//go:build linux

package certificates

import (
	"context"
	"encoding/pem"
	"sync"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// MigrationPrivateKeyAudience admits only the managed-material parser for one
// tenant's migration certificate. It is not an ACME account or a signing key.
func MigrationPrivateKeyAudience(tenant, resource, release string) (secrets.ID, secrets.AudienceBinding, error) {
	if !validMaterialIdentifier(tenant) || !validMaterialIdentifier(resource) { return "", secrets.AudienceBinding{}, ErrMaterialInvalid }
	audience := secrets.AudienceBinding{AdapterID: CertificateSecretAdapterID, AdapterVersion: CertificateSecretAdapterVersion,
		Account: "certificate-migration-import", Origin: "local://panel-core/certificates/migration", ResourceKind: "migration_certificate_key",
		ResourceID: certificateResourceID(resource), ResourceGeneration: 1, Operations: []secrets.Operation{secrets.OperationRead}, ConsumerReleaseDigest: release}
	if audience.Validate() != nil { return "", secrets.AudienceBinding{}, ErrMaterialInvalid }
	return certificateTenantID(tenant), audience, nil
}

func ValidateMigrationPrivateKey(content []byte) error {
	if len(content) == 0 || len(content) > 128<<10 { return ErrMaterialInvalid }
	key, err := parseManagedCertificateSigner(content)
	if err != nil { return ErrMaterialInvalid }
	wipeParsedMaterialPrivateKey(key)
	return nil
}

// OpenMigrationMaterial never gives a generic key reader to migration command
// consumers. Its single consumption combines public chain bytes with the exact
// enrolled key and returns them only through MaterialService's parser contract.
// The encrypted original remains replayable until migration cancellation; the
// managed material gets a separately purpose-bound key in the existing store.
func (runtime *SecretMaterialRuntime) OpenMigrationMaterial(metadata secrets.Metadata, tenant, resource string, chain []byte) (OneUseCertificateMaterial, error) {
	if runtime == nil || runtime.Material == nil || metadata.Validate() != nil || metadata.State != secrets.StateActive || metadata.Version != 1 || metadata.Purpose != secrets.PurposeTLSKey || len(chain) == 0 || len(chain) > MaximumMaterialPEMBytes-(128<<10) { return nil, ErrMaterialInvalid }
	owner, audience, err := MigrationPrivateKeyAudience(tenant, resource, runtime.ConsumerReleaseDigest)
	if err != nil || metadata.OwnerTenantID != owner || metadata.Audience.AdapterID != audience.AdapterID || metadata.Audience.AdapterVersion != audience.AdapterVersion || metadata.Audience.Account != audience.Account || metadata.Audience.Origin != audience.Origin || metadata.Audience.ResourceKind != audience.ResourceKind || metadata.Audience.ResourceID != audience.ResourceID || metadata.Audience.ResourceGeneration != 1 || metadata.Audience.ConsumerReleaseDigest != audience.ConsumerReleaseDigest || len(metadata.Audience.Operations) != 1 || metadata.Audience.Operations[0] != secrets.OperationRead { return nil, ErrMaterialUnauthorized }
	return &migrationMaterial{runtime: runtime, metadata: metadata, chain: append([]byte(nil), chain...)}, nil
}

type migrationMaterial struct {
	runtime *SecretMaterialRuntime
	metadata secrets.Metadata
	chain []byte
	used bool
	mu sync.Mutex
}

func (material *migrationMaterial) Consume(ctx context.Context, maximum int64) ([]byte, error) {
	material.mu.Lock(); defer material.mu.Unlock()
	if material.used || maximum < 1 || maximum > MaximumMaterialPEMBytes { return nil, ErrMaterialInvalid }
	material.used = true
	defer wipeCertificateBytes(material.chain)
	metadata := material.metadata
	response, err := material.runtime.Material.Read(ctx, secrets.MaterialRequest{SecretID: metadata.ID, OwnerTenantID: metadata.OwnerTenantID,
		Purpose: secrets.PurposeTLSKey, Operation: secrets.OperationRead, AdapterID: CertificateSecretAdapterID,
		AdapterVersion: CertificateSecretAdapterVersion, ResourceID: metadata.Audience.ResourceID})
	defer wipeCertificateBytes(response.Material)
	if err != nil { return nil, materialSecretError(err) }
	if response.SecretVersion != metadata.Version || response.BindingDigest != metadata.BindingDigest || ValidateMigrationPrivateKey(response.Material) != nil || int64(len(material.chain)+len(response.Material)+1) > maximum { return nil, ErrMaterialInvalid }
	content := make([]byte, 0, len(material.chain)+len(response.Material)+1)
	content = append(content, material.chain...); content = append(content, '\n'); content = append(content, response.Material...)
	return content, nil
}

func (material *migrationMaterial) Destroy(context.Context) error {
	material.mu.Lock(); defer material.mu.Unlock()
	material.used = true; wipeCertificateBytes(material.chain); material.chain = nil
	return nil
}

// MigrationDeploymentMaterial uses only a sealed, already-validated managed
// generation. The deployment broker resolves its purpose-bound private key.
func MigrationDeploymentMaterial(generation ManagedCertificateGeneration) (CertificateMaterial, error) {
	if verifySealedManagedCertificateGeneration(generation) != nil || generation.State == MaterialStateRetired { return CertificateMaterial{}, ErrMaterialInvalid }
	var chain []byte
	for _, item := range generation.Chain { chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: item.DER})...) }
	material, err := certificateMaterialFromPEM(chain)
	if err != nil || material.FingerprintSHA256 != generation.LeafFingerprintSHA256 { return CertificateMaterial{}, ErrMaterialInvalid }
	material.PrivateKeyRef = generation.PrivateKeyReference.ID
	return material, nil
}
