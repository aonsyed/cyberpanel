//go:build linux

package providers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type backupSecretDialer string

func (path backupSecretDialer) DialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", string(path))
}

// Real broker/store/KEK and Linux process identity checks, on private sockets.
// No installed service, production credential or shared repository is changed.
func isolatedRepositoryKeys(t *testing.T) *RepositoryKeys {
	t.Helper()
	root := t.TempDir()
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(root, "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := secrets.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "kek")
	if err = os.WriteFile(keyPath, key, 0400); err != nil {
		t.Fatal(err)
	}
	wipeKey(key)
	kek, err := secrets.NewFileKEK(keyPath, 1, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secrets.NewBroker(store, kek, secrets.LinuxConsumerRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	materialPath := filepath.Join(root, "m.sock")
	managementPath := filepath.Join(root, "g.sock")
	materialListener, err := net.Listen("unix", materialPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { materialListener.Close() })
	managementListener, err := net.Listen("unix", managementPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { managementListener.Close() })
	materialPeer, err := secrets.NewLinuxMaterialPeerAuthorizer(uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	managementPeer, err := secrets.NewLinuxManagementPeerAuthorizer(uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	go (&secrets.MaterialServer{Broker: broker, Authorizer: materialPeer}).Serve(materialListener)
	go (&secrets.ManagementServer{Broker: broker, Authorizer: managementPeer}).Serve(managementListener)
	material, err := secrets.NewMaterialClient(secrets.FramedMaterialTransport{Dialer: backupSecretDialer(materialPath)})
	if err != nil {
		t.Fatal(err)
	}
	management, err := secrets.NewManagementClient(secrets.FramedManagementTransport{Dialer: backupSecretDialer(managementPath)})
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, executable)
	executable.Close()
	if err != nil {
		t.Fatal(err)
	}
	return &RepositoryKeys{Material: material, Management: management, ConsumerReleaseDigest: hex.EncodeToString(hash.Sum(nil))}
}

type encryptedTestSource struct {
	path  string
	reads int
}

func (source *encryptedTestSource) OpenObject(_ context.Context, _ backup.ObjectDescriptor, _ string, offset uint64) (io.ReadCloser, error) {
	source.reads++
	f, err := os.Open(source.path)
	if err == nil {
		_, err = f.Seek(int64(offset), io.SeekStart)
	}
	return f, err
}

type wrongRepositoryKey struct{ RepositoryKeySource }

func (source wrongRepositoryKey) ReadKey(ctx context.Context, spec backup.RepositorySpec, operation secrets.Operation) ([]byte, error) {
	key, err := source.RepositoryKeySource.ReadKey(ctx, spec, operation)
	if err == nil {
		key[0] ^= 0x80
	}
	return key, err
}

func TestEncryptedLocalRepositoryBrokerRoundTrip(t *testing.T) {
	ctx := context.Background()
	keys := isolatedRepositoryKeys(t)
	root := t.TempDir()
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	repository := &LocalRepository{ID: "encrypted", Root: root, rootFD: fd}
	t.Cleanup(func() { repository.Close() })
	for _, p := range []string{".staging", "blobs", "points"} {
		if err = os.Mkdir(filepath.Join(root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	content := []byte("private file and SQL fixture: CREATE TABLE secret;\x00\xff\n")
	sourcePath := filepath.Join(t.TempDir(), "capture")
	if err = os.WriteFile(sourcePath, content, 0600); err != nil {
		t.Fatal(err)
	}
	source := &encryptedTestSource{path: sourcePath}
	provider := LocalProvider{Repositories: map[backup.RepositoryID]*LocalRepository{"encrypted": repository}, Source: source, Keys: keys}
	spec := backup.RepositorySpec{Repository: backup.Repository{ID: "encrypted", Kind: backup.Local, Endpoint: "file://" + root, CredentialRef: "local"}, TenantID: "tenant_fixture", FailureDomain: "local", EncryptionDomain: "domain_fixture", ObjectFormat: LocalEncryptedFormat, MaximumConcurrency: 1}
	if err = keys.EnsureKey(ctx, spec, false); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	if err = keys.EnsureKey(ctx, spec, true); err != nil {
		t.Fatal(err)
	}
	if err = keys.EnsureKey(ctx, spec, true); err != nil {
		t.Fatal("enrollment replay", err)
	}
	owner, resource, keyID := backupKeyIDs(spec)
	for _, mutation := range []string{"purpose", "owner", "resource", "operation", "adapter"} {
		request := secrets.MaterialRequest{SecretID: keyID, OwnerTenantID: owner, ResourceID: resource, Purpose: secrets.PurposeBackupRepository, Operation: secrets.OperationDecrypt, AdapterID: backupKeyAdapter, AdapterVersion: backupKeyAdapterVersion}
		switch mutation {
		case "purpose":
			request.Purpose = secrets.PurposeDatabase
		case "owner":
			request.OwnerTenantID = "wrong_tenant"
		case "resource":
			request.ResourceID = "wrong_resource"
		case "operation":
			request.Operation = secrets.OperationRead
		case "adapter":
			request.AdapterID = "database.mariadb"
		}
		if reply, err := keys.Material.Read(ctx, request); err == nil {
			wipeKey(reply.Material)
			t.Fatal("unauthorized key delivery", mutation)
		}
	}
	object := backup.ObjectDescriptor{Key: "site/files.tar", Digest: hashBytes(content), Size: uint64(len(content)), Mode: 0600}
	manifest := backup.RecoveryPointManifest{RecoveryPointID: "point_encrypted", PolicyID: "policy_fixture", TenantID: spec.TenantID, Scope: "site_fixture", WriteFrontier: 1, SourceGeneration: 1, CreatedAt: time.Now().UTC(), RequiredComponents: []backup.ComponentKind{backup.ComponentFiles}, Artifacts: []backup.ArtifactManifest{{ID: "artifact_fixture", Component: backup.ComponentFiles, ObjectCount: 1, Bytes: object.Size, RootDigest: hashText(object.Key + "\x00" + object.Digest + "\x00"), Tool: "fixture", SchemaVersion: 1, SourceGeneration: 1, Consistency: backup.ConsistencyFuzzy, Objects: []backup.ObjectDescriptor{object}}}}
	manifest.ManifestDigest, err = backup.RecoveryPointDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := provider.StageManifest(ctx, spec, manifest, "capture_fixture")
	if err != nil {
		t.Fatal(err)
	}
	relative, err := provider.StageObject(ctx, spec, stage, object, "capture_fixture")
	if err != nil {
		t.Fatal(err)
	}
	reads := source.reads
	if repeated, err := provider.StageObject(ctx, spec, stage, object, "capture_fixture"); err != nil || repeated != relative || source.reads != reads {
		t.Fatal("encrypted staging replay reread source", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, content) {
		t.Fatal("plaintext stored")
	}
	if _, err = os.Stat(filepath.Join(root, objectPath(object))); !os.IsNotExist(err) {
		t.Fatal("plaintext blob exists")
	}
	receipt, err := provider.Commit(ctx, spec, manifest, stage, "capture_fixture")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err = provider.Verify(ctx, spec, manifest, receipt)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := provider.OpenCommittedObject(ctx, spec, manifest, receipt, object)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := io.ReadAll(opened)
	opened.Close()
	if err != nil || !bytes.Equal(content, restored) {
		t.Fatal("decrypt restore mismatch", err)
	}
	var envelope localObjectEnvelope
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	key, err := keys.ReadKey(ctx, spec, secrets.OperationDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"tenant", "repository", "domain", "mode", "size"} {
		alteredSpec, alteredObject := spec, object
		switch scope {
		case "tenant":
			alteredSpec.TenantID = "other_tenant"
		case "repository":
			alteredSpec.Repository.ID = "other_repository"
		case "domain":
			alteredSpec.EncryptionDomain = "other_domain"
		case "mode":
			alteredObject.Mode = 0644
		case "size":
			alteredObject.Size++
		}
		aad, _ := encryptedObjectBinding(alteredSpec, alteredObject)
		if plaintext, err := secrets.OpenAEADEnvelope(key, envelope.Nonce, envelope.Ciphertext, aad); err == nil {
			wipeKey(plaintext)
			t.Fatal("unauthenticated object identity", scope)
		}
	}
	wipeKey(key)
	wrong := provider
	wrong.Keys = wrongRepositoryKey{keys}
	if reader, err := wrong.OpenCommittedObject(ctx, spec, manifest, receipt, object); err == nil {
		reader.Close()
		t.Fatal("wrong key accepted")
	}
	for _, mutation := range []string{"tamper", "truncate"} {
		var envelope localObjectEnvelope
		if err = json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		if mutation == "tamper" {
			envelope.Ciphertext[0] ^= 1
		} else {
			envelope.Ciphertext = envelope.Ciphertext[:len(envelope.Ciphertext)-1]
		}
		changed, _ := json.Marshal(envelope)
		if err = os.WriteFile(filepath.Join(root, relative), changed, 0600); err != nil {
			t.Fatal(err)
		}
		if reader, err := provider.OpenCommittedObject(ctx, spec, manifest, receipt, object); err == nil {
			reader.Close()
			t.Fatal("accepted", mutation)
		}
	}
	if err = os.WriteFile(filepath.Join(root, relative), raw, 0600); err != nil {
		t.Fatal(err)
	}
	other := object
	other.Key = "site/another.tar"
	otherPath := encryptedObjectPath(spec, other)
	if err = os.WriteFile(filepath.Join(root, otherPath), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if reader, err := provider.openEncryptedObject(ctx, spec, repository, other); err == nil {
		reader.Close()
		t.Fatal("cross-object substitution accepted")
	}
	missing := provider
	missing.Keys = nil
	if _, err = missing.StageObject(ctx, spec, stage, object, "capture_fixture"); err == nil {
		t.Fatal("missing key plaintext fallback")
	}
	oversize := object
	oversize.Size = MaximumEncryptedObjectBytes + 1
	before := source.reads
	if _, err = provider.StageObject(ctx, spec, stage, oversize, "capture_fixture"); !errors.Is(err, ErrEncryptedObjectTooLarge) || source.reads != before {
		t.Fatal("size limit not before source read", err)
	}
	oversizeManifest := manifest
	oversizeManifest.RecoveryPointID = "point_oversized"
	oversizeManifest.Artifacts = append([]backup.ArtifactManifest(nil), manifest.Artifacts...)
	oversizeManifest.Artifacts[0].Objects = []backup.ObjectDescriptor{oversize}
	oversizeManifest.Artifacts[0].Bytes = oversize.Size
	oversizeManifest.ManifestDigest, err = backup.RecoveryPointDigest(oversizeManifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.StageManifest(ctx, spec, oversizeManifest, "oversize_capture"); !errors.Is(err, ErrEncryptedObjectTooLarge) {
		t.Fatal("oversized manifest not rejected before staging", err)
	}
	if _, err = os.Stat(filepath.Join(root, ".staging", stageToken(spec.Repository.ID, oversizeManifest.RecoveryPointID, "oversize_capture"))); !os.IsNotExist(err) {
		t.Fatal("oversized manifest created staging")
	}
	legacy := spec
	legacy.ObjectFormat = ""
	if _, err = provider.OpenCommittedObject(ctx, legacy, manifest, receipt, object); err == nil {
		t.Fatal("v2 marker accepted as legacy plaintext")
	}
	manifest.RecoveryPointID = "point_legacy"
	manifest.ManifestDigest, err = backup.RecoveryPointDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.StageManifest(ctx, legacy, manifest, "legacy_capture"); err == nil {
		t.Fatal("implicit plaintext capture allowed")
	}
	// Construct the retained v1 disk fixture through the old implementation;
	// public new-capture operations intentionally reject its absent format.
	stage, err = provider.plainStageManifest(ctx, legacy, manifest, "legacy_capture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.plainStageObject(ctx, legacy, stage, object, "legacy_capture"); err != nil {
		t.Fatal(err)
	}
	receipt, err = provider.plainCommit(ctx, legacy, manifest, stage, "legacy_capture")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err = provider.Verify(ctx, legacy, manifest, receipt)
	if err != nil {
		t.Fatal(err)
	}
	opened, err = provider.OpenCommittedObject(ctx, legacy, manifest, receipt, object)
	if err != nil {
		t.Fatal(err)
	}
	restored, err = io.ReadAll(opened)
	opened.Close()
	if err != nil || !bytes.Equal(restored, content) {
		t.Fatal("legacy raw point changed", err)
	}
	t.Log("real broker enrollment + purpose/owner/resource/operation/adapter denial; encrypted bytes verified/decrypted; wrong key, tamper, truncation, substitution and downgrade rejected; legacy-v1 raw point readable")
}
