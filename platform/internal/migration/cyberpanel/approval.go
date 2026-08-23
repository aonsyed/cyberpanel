package cyberpanel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

const (
	sourcePlanSignatureDomain = "cyberpanel-source-plan-v1"
	migrationGrantSignatureDomain = "cyberpanel-migration-session-grant-v1"
)

type LocalApprovalPolicy struct {
	SourceInstallationID string
	Keys map[string]ed25519.PublicKey
	MaximumLifetime time.Duration
	AllowedTargets map[string]struct{}
	AllowedSchemaHashes map[string]struct{}
}

type LocalApprovalVerifier struct {
	policy LocalApprovalPolicy
}

// MigrationGrant is installed on the source by an independent local
// administrator. It contains no target credential: the only target material is
// the public SPKI digest already authenticated by mutual TLS.
type MigrationGrant struct {
	MigrationID migration.ID `json:"migration_id"`
	SourceInstallationID string `json:"source_installation_id"`
	TargetInstallationID string `json:"target_installation_id"`
	ApprovedPlanDigest string `json:"approved_plan_digest"`
	TargetClientSPKI string `json:"target_client_spki"`
	NotBefore time.Time `json:"not_before"`
	ExpiresAt time.Time `json:"expires_at"`
	Nonce string `json:"nonce"`
}

type SignedMigrationGrant struct {
	Grant MigrationGrant `json:"grant"`
	GrantedAt time.Time `json:"granted_at"`
	GrantorKeyID string `json:"grantor_key_id"`
	Signature []byte `json:"signature"`
}

type FileSessionGrantBinder struct {
	grants *os.Root
	sessions *os.Root
	plans PlanStore
	verifier *LocalApprovalVerifier
	clock func() time.Time
	mu sync.Mutex
}

type consumedSessionGrant struct {
	MigrationID migration.ID `json:"migration_id"`
	ApprovedPlanDigest string `json:"approved_plan_digest"`
	GrantDigest string `json:"grant_digest"`
	TargetClientSPKI string `json:"target_client_spki"`
	ConsumedAt time.Time `json:"consumed_at"`
}

func NewLocalApprovalVerifier(policy LocalApprovalPolicy) (*LocalApprovalVerifier, error) {
	if strings.TrimSpace(policy.SourceInstallationID)==""||len(policy.Keys) == 0 || len(policy.AllowedTargets) == 0 || len(policy.AllowedSchemaHashes) == 0 {
		return nil, ErrInvalid
	}
	if policy.MaximumLifetime == 0 {
		policy.MaximumLifetime = 24 * time.Hour
	}
	if policy.MaximumLifetime < time.Minute || policy.MaximumLifetime > 30*24*time.Hour {
		return nil, ErrInvalid
	}
	keys := make(map[string]ed25519.PublicKey, len(policy.Keys))
	for id, key := range policy.Keys {
		if !validKeyID(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	targets := make(map[string]struct{}, len(policy.AllowedTargets))
	for target := range policy.AllowedTargets {
		if strings.TrimSpace(target) == "" {
			return nil, ErrInvalid
		}
		targets[target] = struct{}{}
	}
	hashes := make(map[string]struct{}, len(policy.AllowedSchemaHashes))
	for digest := range policy.AllowedSchemaHashes {
		if !isDigest(digest) {
			return nil, ErrInvalid
		}
		hashes[digest] = struct{}{}
	}
	policy.Keys = keys
	policy.AllowedTargets = targets
	policy.AllowedSchemaHashes = hashes
	return &LocalApprovalVerifier{policy: policy}, nil
}

func (v *LocalApprovalVerifier) VerifyApprovedPlan(ctx context.Context, approved ApprovedPlan, now time.Time) error {
	if v == nil || ctx == nil || now.IsZero() || approved.ApprovedAt.IsZero() || !validKeyID(approved.ApproverKeyID) || len(approved.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := approved.Plan.validate(now.UTC()); err != nil {
		return err
	}
	if approved.Plan.SourceInstallationID!=v.policy.SourceInstallationID{return ErrDenied}
	if approved.ApprovedAt.Before(approved.Plan.NotBefore) || approved.ApprovedAt.After(approved.Plan.ExpiresAt) || approved.Plan.ExpiresAt.Sub(approved.Plan.NotBefore) > v.policy.MaximumLifetime {
		return ErrDenied
	}
	if _, allowed := v.policy.AllowedTargets[approved.Plan.TargetInstallationID]; !allowed {
		return ErrDenied
	}
	if _, allowed := v.policy.AllowedSchemaHashes[approved.Plan.SchemaHash]; !allowed {
		return ErrDenied
	}
	key, trusted := v.policy.Keys[approved.ApproverKeyID]
	if !trusted {
		return ErrDenied
	}
	message, err := approvedPlanMessage(approved)
	if err != nil || !ed25519.Verify(key, message, approved.Signature) {
		return ErrDenied
	}
	return nil
}

func SignApprovedPlan(plan SourcePlan, approvedAt time.Time, keyID string, privateKey ed25519.PrivateKey) (ApprovedPlan, error) {
	if approvedAt.IsZero() || !validKeyID(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return ApprovedPlan{}, ErrInvalid
	}
	if err := plan.validate(approvedAt.UTC()); err != nil {
		return ApprovedPlan{}, err
	}
	approved := ApprovedPlan{Plan: plan, ApprovedAt: approvedAt.UTC(), ApproverKeyID: keyID}
	message, err := approvedPlanMessage(approved)
	if err != nil {
		return ApprovedPlan{}, err
	}
	approved.Signature = ed25519.Sign(privateKey, message)
	return approved, nil
}

func SignMigrationGrant(grant MigrationGrant, grantedAt time.Time, keyID string, privateKey ed25519.PrivateKey) (SignedMigrationGrant, error) {
	if grantedAt.IsZero() || !validKeyID(keyID) || len(privateKey) != ed25519.PrivateKeySize || grant.validateStructure() != nil || grantedAt.After(grant.ExpiresAt) {
		return SignedMigrationGrant{}, ErrInvalid
	}
	signed := SignedMigrationGrant{Grant: grant, GrantedAt: grantedAt.UTC(), GrantorKeyID: keyID}
	message, err := migrationGrantMessage(signed)
	if err != nil {
		return SignedMigrationGrant{}, err
	}
	signed.Signature = ed25519.Sign(privateKey, message)
	return signed, nil
}

func (v *LocalApprovalVerifier) VerifyMigrationGrant(ctx context.Context, signed SignedMigrationGrant, approved ApprovedPlan, peerSPKI string, now time.Time) error {
	if v == nil || ctx == nil || now.IsZero() || signed.GrantedAt.IsZero() || !validKeyID(signed.GrantorKeyID) || len(signed.Signature) != ed25519.SignatureSize || !isDigest(peerSPKI) {
		return ErrInvalid
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := v.VerifyApprovedPlan(ctx, approved, now.UTC()); err != nil {
		return err
	}
	if err := signed.Grant.validateAt(now.UTC()); err != nil {
		return err
	}
	planDigest, err := approvedPlanDigest(approved)
	if err != nil {
		return err
	}
	grant := signed.Grant
	if grant.MigrationID != approved.Plan.MigrationID || grant.SourceInstallationID != approved.Plan.SourceInstallationID || grant.TargetInstallationID != approved.Plan.TargetInstallationID || grant.ApprovedPlanDigest != planDigest || grant.TargetClientSPKI != peerSPKI {
		return ErrDenied
	}
	if grant.NotBefore.Before(approved.Plan.NotBefore) || grant.ExpiresAt.After(approved.Plan.ExpiresAt) || grant.ExpiresAt.Sub(grant.NotBefore) > v.policy.MaximumLifetime || signed.GrantedAt.Before(approved.Plan.NotBefore) || signed.GrantedAt.After(grant.ExpiresAt) {
		return ErrDenied
	}
	key, trusted := v.policy.Keys[signed.GrantorKeyID]
	if !trusted {
		return ErrDenied
	}
	message, err := migrationGrantMessage(signed)
	if err != nil || !ed25519.Verify(key, message, signed.Signature) {
		return ErrDenied
	}
	return nil
}

func OpenFileSessionGrantBinder(grantPath, sessionPath string, plans PlanStore, verifier *LocalApprovalVerifier) (*FileSessionGrantBinder, error) {
	if plans == nil || verifier == nil || grantPath == sessionPath {
		return nil, ErrInvalid
	}
	grants, err := openPrivateRoot(grantPath)
	if err != nil {
		return nil, err
	}
	sessions, err := openPrivateRoot(sessionPath)
	if err != nil {
		grants.Close()
		return nil, err
	}
	return &FileSessionGrantBinder{grants: grants, sessions: sessions, plans: plans, verifier: verifier, clock: time.Now}, nil
}

func (b *FileSessionGrantBinder) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var failures []error
	if b.grants != nil {
		failures = append(failures, b.grants.Close())
		b.grants = nil
	}
	if b.sessions != nil {
		failures = append(failures, b.sessions.Close())
		b.sessions = nil
	}
	return errors.Join(failures...)
}

func (b *FileSessionGrantBinder) AuthorizeSession(ctx context.Context, connection net.Conn, migrationID migration.ID) error {
	if b == nil || b.grants == nil || b.sessions == nil || b.plans == nil || b.verifier == nil || ctx == nil || connection == nil || !migrationID.Valid() {
		return ErrInvalid
	}
	peerSPKI, err := peerSPKIDigest(connection)
	if err != nil {
		return ErrDenied
	}
	approved, err := b.plans.ApprovedPlan(ctx, migrationID)
	if err != nil {
		return err
	}
	var signed SignedMigrationGrant
	if err = readPrivateRootJSON(b.grants, migrationID.String()+".grant.json", &signed); err != nil {
		return err
	}
	if err = b.verifier.VerifyMigrationGrant(ctx, signed, approved, peerSPKI, b.clock().UTC()); err != nil {
		return err
	}
	planDigest, err := approvedPlanDigest(approved)
	if err != nil {
		return err
	}
	grantDigest, err := migrationGrantDigest(signed)
	if err != nil {
		return err
	}
	binding := consumedSessionGrant{MigrationID: migrationID, ApprovedPlanDigest: planDigest, GrantDigest: grantDigest, TargetClientSPKI: peerSPKI, ConsumedAt: b.clock().UTC()}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.consume(binding)
}

func (b *FileSessionGrantBinder) consume(binding consumedSessionGrant) error {
	name := binding.MigrationID.String() + ".session.json"
	var existing consumedSessionGrant
	if err := readPrivateRootJSON(b.sessions, name, &existing); err == nil {
		if sameConsumedSession(existing, binding) {
			return nil
		}
		return ErrDenied
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	randomValue := make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, randomValue); err != nil {
		return err
	}
	temporary := ".session-" + hex.EncodeToString(randomValue)
	file, err := b.sessions.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	keep := true
	defer func() {
		file.Close()
		if keep {
			_ = b.sessions.Remove(temporary)
		}
	}()
	if count, writeErr := file.Write(raw); writeErr != nil {
		err = writeErr
	} else if count != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = file.Chmod(0o400)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = b.sessions.Link(temporary, name); err != nil {
		if readErr := readPrivateRootJSON(b.sessions, name, &existing); readErr != nil || !sameConsumedSession(existing, binding) {
			return errors.Join(err, readErr, ErrDenied)
		}
	}
	if err = b.sessions.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	keep = false
	directory, err := b.sessions.Open(".")
	if err != nil {
		return err
	}
	err = directory.Sync()
	return errors.Join(err, directory.Close())
}

func sameConsumedSession(left, right consumedSessionGrant) bool {
	return left.MigrationID == right.MigrationID && left.ApprovedPlanDigest == right.ApprovedPlanDigest && left.GrantDigest == right.GrantDigest && left.TargetClientSPKI == right.TargetClientSPKI && !left.ConsumedAt.IsZero()
}

func (g MigrationGrant) validateStructure() error {
	if !g.MigrationID.Valid() || strings.TrimSpace(g.SourceInstallationID) == "" || strings.TrimSpace(g.TargetInstallationID) == "" || !isDigest(g.ApprovedPlanDigest) || !isDigest(g.TargetClientSPKI) || g.NotBefore.IsZero() || g.ExpiresAt.IsZero() || !g.ExpiresAt.After(g.NotBefore) || len(g.Nonce) < 16 || len(g.Nonce) > 256 || strings.ContainsAny(g.Nonce, "\r\n\x00") {
		return ErrInvalid
	}
	return nil
}

func (g MigrationGrant) validateAt(now time.Time) error {
	if err := g.validateStructure(); err != nil {
		return err
	}
	if now.Before(g.NotBefore) || !now.Before(g.ExpiresAt) {
		return ErrDenied
	}
	return nil
}

func migrationGrantMessage(signed SignedMigrationGrant) ([]byte, error) {
	signed.Signature = nil
	raw, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	return append([]byte(migrationGrantSignatureDomain+"\x00"), raw...), nil
}

func migrationGrantDigest(signed SignedMigrationGrant) (string, error) {
	message, err := migrationGrantMessage(signed)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write(message)
	_, _ = hash.Write(signed.Signature)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func openPrivateRoot(path string) (*os.Root, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode().Perm()&0o077 != 0 {
		return nil, errors.Join(err, ErrInvalid)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, ErrChanged
	}
	return root, nil
}

func readPrivateRootJSON(root *os.Root, name string, target any) error {
	if root == nil || !safeGrantFileName(name) || target == nil {
		return ErrInvalid
	}
	before, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 || before.Size() < 2 || before.Size() > 1<<20 {
		return ErrInvalid
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o400 {
		return ErrChanged
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	final, err := file.Stat()
	if err != nil || !sameFileState(after, final) {
		return ErrChanged
	}
	return nil
}

func safeGrantFileName(value string) bool {
	return value != "" && filepath.Base(value) == value && !strings.ContainsAny(value, `/\\\x00`) && !strings.Contains(value, "..")
}

func approvedPlanMessage(approved ApprovedPlan) ([]byte, error) {
	approved.Signature = nil
	approved.Plan.SiteSourceIDs = append([]string(nil), approved.Plan.SiteSourceIDs...)
	sortStrings(approved.Plan.SiteSourceIDs)
	raw, err := json.Marshal(approved)
	if err != nil {
		return nil, err
	}
	return append([]byte(sourcePlanSignatureDomain+"\x00"), raw...), nil
}

type FilePlanStore struct {
	root *os.Root
}

func OpenFilePlanStore(rootPath string) (*FilePlanStore, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(rootPath)
	if err != nil || !before.IsDir() || before.Mode().Perm()&0o077 != 0 {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, ErrInvalid
	}
	return &FilePlanStore{root: root}, nil
}

func (s *FilePlanStore) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.Close()
}

func (s *FilePlanStore) ApprovedPlan(ctx context.Context, migrationID migration.ID) (ApprovedPlan, error) {
	if s == nil || s.root == nil || ctx == nil || !migrationID.Valid() {
		return ApprovedPlan{}, ErrInvalid
	}
	select {
	case <-ctx.Done():
		return ApprovedPlan{}, ctx.Err()
	default:
	}
	name := migrationID.String() + ".json"
	before, err := s.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return ApprovedPlan{}, migration.ErrNotFound
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 || before.Size() < 2 || before.Size() > 1<<20 {
		return ApprovedPlan{}, ErrInvalid
	}
	file, err := s.root.Open(name)
	if err != nil {
		return ApprovedPlan{}, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o400 {
		return ApprovedPlan{}, ErrInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var value ApprovedPlan
	if err := decoder.Decode(&value); err != nil {
		return ApprovedPlan{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ApprovedPlan{}, ErrInvalid
	}
	final, err := file.Stat()
	if err != nil || !sameFileState(after, final) || !final.Mode().IsRegular() || final.Mode().Perm() != 0o400 {
		return ApprovedPlan{}, ErrChanged
	}
	if value.Plan.MigrationID != migrationID {
		return ApprovedPlan{}, ErrDenied
	}
	return value, nil
}

func approvedPlanDigest(approved ApprovedPlan) (string, error) {
	message, err := approvedPlanMessage(approved)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(message)
	return hex.EncodeToString(sum[:]), nil
}

func isDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validKeyID(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '-' && character != ':' && character != '.' {
			return false
		}
	}
	return true
}

func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}
