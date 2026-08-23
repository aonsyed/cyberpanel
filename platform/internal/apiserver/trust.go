package apiserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type RequestSigner interface { Sign(*CoreRequest) error }
type RequestVerifier interface { Verify(CoreRequest) error }

type Ed25519Signer struct { keyID string; private ed25519.PrivateKey }

func NewEd25519Signer(keyID string, private ed25519.PrivateKey) (*Ed25519Signer, error) {
	if !keyIDPattern.MatchString(keyID) || len(private) != ed25519.PrivateKeySize { return nil, invalid("gateway signing key") }
	return &Ed25519Signer{keyID: keyID, private: append(ed25519.PrivateKey(nil), private...)}, nil
}

func (signer *Ed25519Signer) Sign(request *CoreRequest) error {
	if signer == nil || request == nil { return invalid("core request signer") }
	request.KeyID = signer.keyID; request.Signature = ""
	content, err := request.signedBytes(); if err != nil { return err }
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.private, content))
	return nil
}

type TrustEntry struct { KeyID string `json:"key_id"`; PublicKey string `json:"public_key"`; NotBefore time.Time `json:"not_before"`; NotAfter time.Time `json:"not_after"` }
type TrustDocument struct { Version uint32 `json:"version"`; ActiveKeyID string `json:"active_key_id"`; Entries []TrustEntry `json:"entries"`; UpdatedAt time.Time `json:"updated_at"` }
type SignerDocument struct { Version uint32 `json:"version"`; KeyID string `json:"key_id"`; PrivateKey string `json:"private_key"`; CreatedAt time.Time `json:"created_at"` }

type FileTrustStore struct { path string; clock func() time.Time; mutex sync.RWMutex }

func NewFileTrustStore(path string) (*FileTrustStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path { return nil, invalid("trust store path") }
	return &FileTrustStore{path: path, clock: time.Now}, nil
}

func (store *FileTrustStore) Verify(request CoreRequest) error {
	store.mutex.RLock(); defer store.mutex.RUnlock()
	document, err := loadTrustDocument(store.path); if err != nil { return ErrInvalidSignature }
	now := store.clock().UTC()
	var public ed25519.PublicKey
	for _, entry := range document.Entries {
		if entry.KeyID != request.KeyID || now.Before(entry.NotBefore) || !now.Before(entry.NotAfter) { continue }
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(entry.PublicKey); if decodeErr != nil || len(decoded) != ed25519.PublicKeySize { return ErrInvalidSignature }
		public = ed25519.PublicKey(decoded); break
	}
	if len(public) == 0 { return ErrInvalidSignature }
	signature, err := base64.RawURLEncoding.DecodeString(request.Signature); if err != nil || len(signature) != ed25519.SignatureSize { return ErrInvalidSignature }
	content, err := request.signedBytes(); if err != nil || !ed25519.Verify(public, content, signature) { return ErrInvalidSignature }
	return nil
}

func LoadSigner(path string) (*Ed25519Signer, error) {
	content, err := readSecretFile(path, 1<<20); if err != nil { return nil, err }
	defer clearSecret(content)
	var document SignerDocument
	if err = decodeStrict(content, &document); err != nil || document.Version != 1 { return nil, invalid("signer document") }
	private, err := base64.RawURLEncoding.DecodeString(document.PrivateKey); if err != nil { return nil, invalid("signer private key") }
	defer clearSecret(private)
	return NewEd25519Signer(document.KeyID, ed25519.PrivateKey(private))
}

func loadTrustDocument(path string) (TrustDocument, error) {
	var document TrustDocument
	content, err := readProtectedFile(path, 1<<20); if err != nil { return document, err }
	if err = decodeStrict(content, &document); err != nil || document.Version != 1 || !keyIDPattern.MatchString(document.ActiveKeyID) || len(document.Entries) == 0 || len(document.Entries) > 4 { return document, invalid("trust document") }
	seen := map[string]bool{}
	for _, entry := range document.Entries { if !keyIDPattern.MatchString(entry.KeyID) || seen[entry.KeyID] || !entry.NotAfter.After(entry.NotBefore) { return document, invalid("trust entry") }; seen[entry.KeyID] = true }
	if !seen[document.ActiveKeyID] { return document, invalid("active trust key") }
	return document, nil
}

func readSecretFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 { return nil, errors.New("unsafe secret key path") }
	info, err := os.Lstat(path); if err != nil { return nil, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > maximum { return nil, errors.New("unsafe secret key file") }
	file,err:=os.Open(path);if err!=nil{return nil,err};defer file.Close();opened,err:=file.Stat();if err!=nil||!os.SameFile(info,opened){return nil,errors.New("secret key file changed while opening")};content,err:=io.ReadAll(io.LimitReader(file,maximum+1));if err!=nil||int64(len(content))>maximum{return nil,errors.New("secret key file exceeds configured bound")};return content,nil
}

type TrustPaths struct { SignerPath string; TrustPath string }

func (paths TrustPaths) Validate() error {
	if !filepath.IsAbs(paths.SignerPath) || !filepath.IsAbs(paths.TrustPath) || filepath.Clean(paths.SignerPath) != paths.SignerPath || filepath.Clean(paths.TrustPath) != paths.TrustPath || paths.SignerPath == paths.TrustPath { return invalid("trust paths") }
	return nil
}

// RotateLocalTrust is intentionally used only by the root-only recovery
// surface. It publishes the new public key before switching the gateway's
// private key and keeps the previous key valid for a bounded drain window.
func RotateLocalTrust(paths TrustPaths, now time.Time) (string, error) {
	if err := paths.Validate(); err != nil { return "", err }
	if now.IsZero() { now = time.Now().UTC() } else { now = now.UTC() }
	public, private, err := ed25519.GenerateKey(rand.Reader); if err != nil { return "", err }
	sum := sha256.Sum256(public); keyID := "gw_" + hex.EncodeToString(sum[:])[:32]
	entry := TrustEntry{KeyID: keyID, PublicKey: base64.RawURLEncoding.EncodeToString(public), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(397*24*time.Hour)}
	entries := []TrustEntry{entry}
	if previous, loadErr := loadTrustDocument(paths.TrustPath); loadErr == nil {
		for _, prior := range previous.Entries {
			if prior.KeyID == keyID || !now.Before(prior.NotAfter) { continue }
			if prior.NotAfter.After(now.Add(15*time.Minute)) { prior.NotAfter = now.Add(15*time.Minute) }
			entries = append(entries, prior)
			if len(entries) == 2 { break }
		}
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].KeyID < entries[right].KeyID })
	trust := TrustDocument{Version: 1, ActiveKeyID: keyID, Entries: entries, UpdatedAt: now}
	signer := SignerDocument{Version: 1, KeyID: keyID, PrivateKey: base64.RawURLEncoding.EncodeToString(private), CreatedAt: now}
	if err = secureStateDirectory(filepath.Dir(paths.TrustPath), 0700); err != nil { return "", err }
	if err = secureStateDirectory(filepath.Dir(paths.SignerPath), 0700); err != nil { return "", err }
	if err = writeStateFile(paths.TrustPath, trust, 0640); err != nil { return "", err }
	if err = writeStateFile(paths.SignerPath, signer, 0600); err != nil { return "", fmt.Errorf("trust published but signer switch failed: %w", err) }
	clearSecret(private)
	return keyID, nil
}

type DirectoryNonceStore struct { root string; clock func() time.Time; mutex sync.Mutex; lastSweep time.Time }

func NewDirectoryNonceStore(root string) (*DirectoryNonceStore, error) {
	if err := secureStateDirectory(root, 0700); err != nil { return nil, err }
	return &DirectoryNonceStore{root: root, clock: time.Now}, nil
}

func (store *DirectoryNonceStore) Mark(nonce string, sentAt time.Time) error {
	if store == nil || !idempotencyPattern.MatchString(nonce) { return ErrReplay }
	store.mutex.Lock(); defer store.mutex.Unlock()
	now:=store.clock().UTC();if store.lastSweep.IsZero()||now.Sub(store.lastSweep)>=time.Minute{if err:=store.prune(now);err!=nil{return err};store.lastSweep=now}
	sum := sha256.Sum256([]byte(nonce)); encoded := hex.EncodeToString(sum[:]); directory := filepath.Join(store.root, sentAt.UTC().Format("200601021504"))
	if err := secureStateDirectory(directory, 0700); err != nil { return err }
	path := filepath.Join(directory, encoded)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) { return ErrReplay }
	if err != nil { return err }
	content, _ := json.Marshal(struct{ SentAt time.Time `json:"sent_at"`; SeenAt time.Time `json:"seen_at"` }{sentAt.UTC(), now})
	if _, err = file.Write(content); err == nil { err = file.Sync() }
	closeErr := file.Close(); if err == nil { err = closeErr }
	return err
}

func(store *DirectoryNonceStore)prune(now time.Time)error{entries,err:=os.ReadDir(store.root);if err!=nil{return err};cutoff:=now.Add(-2*time.Minute);for _,entry:=range entries{if !entry.IsDir()||len(entry.Name())!=12{continue};created,parseErr:=time.ParseInLocation("200601021504",entry.Name(),time.UTC);if parseErr==nil&&created.Before(cutoff){if err=os.RemoveAll(filepath.Join(store.root,entry.Name()));err!=nil{return err}}};return nil}
