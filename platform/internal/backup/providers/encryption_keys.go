package providers

import (
	"context"
	"crypto/rand"
	"errors"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"runtime"
)

const LocalEncryptedFormat = "aes256gcm-v1"
const LocalPlaintextFormat = "plaintext-v1"
const backupKeyAdapter = "backup.local"
const backupKeyAdapterVersion = "aes256gcm-v1"

type RepositoryKeySource interface {
	ReadKey(context.Context, backup.RepositorySpec, secrets.Operation) ([]byte, error)
	EnsureKey(context.Context, backup.RepositorySpec, bool) error
}

// RepositoryKeys uses the existing broker's exact audience and one-use delivery
// grants. Keys are never sent through the tenant API or persisted by panel-core.
type RepositoryKeys struct {
	Material              *secrets.MaterialClient
	Management            *secrets.ManagementClient
	ConsumerReleaseDigest string
}

func backupKeyIDs(spec backup.RepositorySpec) (secrets.ID, secrets.ID, secrets.ID) {
	owner, _ := secrets.NewID("tenant_" + hashText(spec.TenantID)[:48])
	resource, _ := secrets.NewID("backup_" + hashText(spec.TenantID + "\x00" + string(spec.Repository.ID) + "\x00" + spec.EncryptionDomain)[:48])
	key, _ := secrets.NewID("backup_key_" + hashText(string(resource))[:48])
	return owner, resource, key
}

func (source *RepositoryKeys) ReadKey(ctx context.Context, spec backup.RepositorySpec, operation secrets.Operation) ([]byte, error) {
	if source == nil || source.Material == nil || validateSpec(spec, backup.Local) != nil || spec.ObjectFormat != LocalEncryptedFormat || (operation != secrets.OperationEncrypt && operation != secrets.OperationDecrypt) {
		return nil, ErrCredential
	}
	owner, resource, key := backupKeyIDs(spec)
	reply, err := source.Material.Read(ctx, secrets.MaterialRequest{SecretID: key, OwnerTenantID: owner, Purpose: secrets.PurposeBackupRepository, Operation: operation, AdapterID: backupKeyAdapter, AdapterVersion: backupKeyAdapterVersion, ResourceID: resource})
	if err != nil {
		return nil, err
	}
	if reply.SecretVersion != 1 || len(reply.Material) != 32 {
		wipeKey(reply.Material)
		return nil, ErrCredential
	}
	return reply.Material, nil
}

func (source *RepositoryKeys) EnsureKey(ctx context.Context, spec backup.RepositorySpec, allowCreate bool) error {
	key, err := source.ReadKey(ctx, spec, secrets.OperationEncrypt)
	wipeKey(key)
	if err == nil {
		return nil
	}
	if !allowCreate || !errors.Is(err, secrets.ErrNotFound) || source.Management == nil || !digest(source.ConsumerReleaseDigest) {
		return err
	}
	owner, resource, id := backupKeyIDs(spec)
	key = make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return err
	}
	defer wipeKey(key)
	_, err = source.Management.Put(ctx, secrets.PutRequest{ID: id, OwnerTenantID: owner, Purpose: secrets.PurposeBackupRepository, Audience: secrets.AudienceBinding{AdapterID: backupKeyAdapter, AdapterVersion: backupKeyAdapterVersion, Account: string(spec.Repository.ID), Origin: spec.Repository.Endpoint, ResourceKind: "backup_repository", ResourceID: resource, ResourceGeneration: 1, Operations: []secrets.Operation{secrets.OperationEncrypt, secrets.OperationDecrypt}, ConsumerReleaseDigest: source.ConsumerReleaseDigest}, Plaintext: key})
	// A lost reply or simultaneous create may have committed exactly this scope.
	// Re-read through the full audience authority; never replace existing keys.
	if err != nil && !errors.Is(err, secrets.ErrConflict) && !errors.Is(err, secrets.ErrRollback) {
		return err
	}
	key, err = source.ReadKey(ctx, spec, secrets.OperationEncrypt)
	wipeKey(key)
	return err
}

func wipeKey(value []byte) {
	for i := range value {
		value[i] = 0
	}
	runtime.KeepAlive(value)
}
func localObjectFormat(spec backup.RepositorySpec) (string, error) {
	switch spec.ObjectFormat {
	case "", LocalPlaintextFormat:
		return LocalPlaintextFormat, nil
	case LocalEncryptedFormat:
		return LocalEncryptedFormat, nil
	default:
		return "", ErrInvalid
	}
}

func validCommitStorageFormat(marker commitMarker, spec backup.RepositorySpec) bool {
	if marker.Version == 1 && marker.ObjectFormat == "" && marker.EncryptionDomain == "" && marker.KeyVersion == 0 {
		return spec.ObjectFormat == "" || spec.ObjectFormat == LocalPlaintextFormat
	}
	return spec.Repository.Kind == backup.Local && spec.ObjectFormat == LocalEncryptedFormat && marker.Version == 2 && marker.ObjectFormat == LocalEncryptedFormat && marker.EncryptionDomain == spec.EncryptionDomain && marker.KeyVersion == 1
}
