//go:build linux

package maildelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const cyberMailMaximumProtectedMaterialBytes = 64 << 10

type CyberMailLocalRuntimeV1 struct {
	Registry *ProviderRegistryV1
}

type CyberMailLocalRuntimeV1Options struct {
	Repository            *SQLiteRepository
	Material              *secrets.MaterialClient
	Management            *secrets.ManagementClient
	HelloName             string
	ConsumerReleaseDigest string
	Now                   func() time.Time
}

func NewCyberMailLocalRuntimeV1(options CyberMailLocalRuntimeV1Options) (*CyberMailLocalRuntimeV1, error) {
	if options.Repository == nil || options.Material == nil || options.Management == nil || !validHostname(options.HelloName) ||
		!validDigest(options.ConsumerReleaseDigest) {
		return nil, ErrInvalid
	}
	source := &cyberMailProtectedSecretSource{repository: options.Repository, material: options.Material}
	activator := &cyberMailProtectedCredentialActivator{repository: options.Repository, source: source,
		management: options.Management, consumerReleaseDigest: strings.ToLower(options.ConsumerReleaseDigest),
		activated: make(map[cyberMailActivationKey]EncryptedCredentialReference)}
	relay, err := NewCyberMailSMTPRelay(CyberMailSMTPRelayOptions{HelloName: options.HelloName, Secrets: source,
		Observer: cyberMailUnsupportedQueueObserver{}, Now: options.Now})
	if err != nil {
		return nil, err
	}
	adapter, err := NewCyberMailAdapterV1(CyberMailAdapterV1Options{Credentials: source, Bindings: options.Repository,
		Relay: relay, CredentialActivator: activator, Now: options.Now})
	if err != nil {
		return nil, err
	}
	registry, err := NewProviderRegistryV1(adapter)
	if err != nil {
		return nil, err
	}
	return &CyberMailLocalRuntimeV1{Registry: registry}, nil
}

type cyberMailSecretBytes []byte

func (value *cyberMailSecretBytes) UnmarshalJSON(encoded []byte) error {
	var plaintext string
	if json.Unmarshal(encoded, &plaintext) != nil || len(plaintext) == 0 || len(plaintext) > 4096 {
		return ErrInvalid
	}
	*value = append((*value)[:0], plaintext...)
	return nil
}

func (value cyberMailSecretBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(value))
}

type cyberMailProtectedMaterial struct {
	Email               string               `json:"email"`
	APIKey              cyberMailSecretBytes `json:"api_key"`
	SMTPCredentialID    string               `json:"smtp_credential_id"`
	SMTPUsername        string               `json:"smtp_username"`
	SMTPPassword        cyberMailSecretBytes `json:"smtp_password"`
}

func (material *cyberMailProtectedMaterial) clear() {
	if material == nil {
		return
	}
	clearBytes(material.APIKey)
	clearBytes(material.SMTPPassword)
	material.APIKey = nil
	material.SMTPPassword = nil
}

type cyberMailProtectedSecretSource struct {
	repository *SQLiteRepository
	material   *secrets.MaterialClient
}

func (source *cyberMailProtectedSecretSource) ResolveCyberMailCredential(ctx context.Context, binding ProviderBinding, version uint64) (CyberMailCredential, error) {
	if source == nil || source.repository == nil || source.material == nil || validateCyberMailBinding(binding) != nil ||
		version != binding.Credential.Version {
		return CyberMailCredential{}, ErrInvalid
	}
	material, cleanup, err := source.read(ctx, binding, binding.Credential)
	if err != nil {
		return CyberMailCredential{}, err
	}
	credential := CyberMailCredential{TenantID: binding.TenantID, BindingID: binding.ID, CredentialVersion: version,
		AccountEmail: material.Email, APIKey: append([]byte(nil), material.APIKey...), SMTPCredentialID: material.SMTPCredentialID,
		SMTPUsername: material.SMTPUsername, Cleanup: cleanup}
	if credential.validate(binding, version) != nil {
		credential.clear()
		return CyberMailCredential{}, ErrInvalid
	}
	return credential, nil
}

func (source *cyberMailProtectedSecretSource) ResolveSMTPAuthSecret(ctx context.Context, reference EncryptedCredentialReference) (SMTPAuthSecret, error) {
	if source == nil || source.repository == nil || source.material == nil || reference.Validate() != nil {
		return SMTPAuthSecret{}, ErrInvalid
	}
	binding, err := source.repository.ResolveCyberMailCredentialBinding(ctx, reference)
	if err != nil {
		return SMTPAuthSecret{}, err
	}
	material, cleanup, err := source.read(ctx, binding, reference)
	if err != nil {
		return SMTPAuthSecret{}, err
	}
	secret := SMTPAuthSecret{Username: []byte(material.SMTPUsername), Password: append([]byte(nil), material.SMTPPassword...)}
	secret.Cleanup = func() {
		clearBytes(secret.Username)
		clearBytes(secret.Password)
		cleanup()
	}
	if secret.Validate() != nil {
		secret.Cleanup()
		return SMTPAuthSecret{}, ErrInvalid
	}
	return secret, nil
}

func (source *cyberMailProtectedSecretSource) read(ctx context.Context, binding ProviderBinding, reference EncryptedCredentialReference) (*cyberMailProtectedMaterial, func(), error) {
	secretID, err := secrets.NewID(reference.Reference)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	response, err := source.material.Read(ctx, secrets.MaterialRequest{SecretID: secretID,
		OwnerTenantID: cyberMailScopedSecretID("tenant", string(binding.TenantID)), Purpose: secrets.PurposeMailRelay,
		Operation: secrets.OperationAuthenticate, AdapterID: CyberMailAdapterKind, AdapterVersion: CyberMailAdapterVersionV1,
		ResourceID: cyberMailScopedSecretID("resource", string(binding.ID))})
	if err != nil {
		return nil, nil, errors.Join(ErrUnavailable, err)
	}
	if len(response.Material) == 0 || len(response.Material) > cyberMailMaximumProtectedMaterialBytes ||
		response.SecretVersion != reference.Version || response.BindingDigest != reference.EncryptionContextDigest {
		clearBytes(response.Material)
		return nil, nil, ErrIntegrity
	}
	var material cyberMailProtectedMaterial
	if decodeStrict(response.Material, &material) != nil {
		clearBytes(response.Material)
		material.clear()
		return nil, nil, ErrInvalid
	}
	clearBytes(response.Material)
	credential := CyberMailCredential{TenantID: binding.TenantID, BindingID: binding.ID, CredentialVersion: reference.Version,
		AccountEmail: material.Email, APIKey: material.APIKey, SMTPCredentialID: material.SMTPCredentialID,
		SMTPUsername: material.SMTPUsername, Cleanup: func() {}}
	probe := SMTPAuthSecret{Username: []byte(material.SMTPUsername), Password: material.SMTPPassword, Cleanup: func() {}}
	if credential.validate(binding, reference.Version) != nil || probe.Validate() != nil {
		clearBytes(probe.Username)
		material.clear()
		return nil, nil, ErrInvalid
	}
	clearBytes(probe.Username)
	var once sync.Once
	cleanup := func() { once.Do(material.clear) }
	return &material, cleanup, nil
}

type cyberMailActivationKey struct {
	TenantID TenantID
	BindingID BindingID
	Version uint64
}

type cyberMailProtectedCredentialActivator struct {
	repository            *SQLiteRepository
	source                *cyberMailProtectedSecretSource
	management            *secrets.ManagementClient
	consumerReleaseDigest string
	mutex                 sync.Mutex
	activated             map[cyberMailActivationKey]EncryptedCredentialReference
}

func (activator *cyberMailProtectedCredentialActivator) ActivateCyberMailRotatedCredential(ctx context.Context, rotated CyberMailRotatedCredential) (string, error) {
	if activator == nil || activator.repository == nil || activator.source == nil || activator.management == nil ||
		!validID(string(rotated.TenantID)) || !validID(string(rotated.BindingID)) || rotated.OldVersion == 0 ||
		rotated.NewVersion != rotated.OldVersion+1 || len(rotated.SMTPPassword) == 0 || len(rotated.SMTPPassword) > 4096 {
		return "", ErrInvalid
	}
	binding, err := activator.repository.LoadBinding(ctx, rotated.TenantID, rotated.BindingID)
	if err != nil {
		return "", err
	}
	if validateCyberMailBinding(binding) != nil || binding.Credential.Version != rotated.OldVersion {
		return "", ErrConflict
	}
	material, cleanup, err := activator.source.read(ctx, binding, binding.Credential)
	if err != nil {
		return "", err
	}
	defer cleanup()
	if material.SMTPCredentialID != rotated.SMTPCredentialID || material.SMTPUsername != rotated.SMTPUsername {
		return "", ErrConflict
	}
	clearBytes(material.SMTPPassword)
	material.SMTPPassword = append(material.SMTPPassword[:0], rotated.SMTPPassword...)
	encoded, err := json.Marshal(material)
	if err != nil || len(encoded) == 0 || len(encoded) > cyberMailMaximumProtectedMaterialBytes {
		clearBytes(encoded)
		return "", ErrInvalid
	}
	defer clearBytes(encoded)
	secretID, err := secrets.NewID(binding.Credential.Reference)
	if err != nil {
		return "", ErrInvalid
	}
	metadata, err := activator.management.Put(ctx, secrets.PutRequest{ID: secretID,
		OwnerTenantID: cyberMailScopedSecretID("tenant", string(binding.TenantID)), Purpose: secrets.PurposeMailRelay,
		Audience: cyberMailSecretAudience(binding, activator.consumerReleaseDigest), Plaintext: encoded,
		ExpectedVersion: rotated.OldVersion, ExpectedBindingDigest: binding.Credential.EncryptionContextDigest})
	if err != nil {
		return "", errors.Join(ErrAmbiguous, err)
	}
	if metadata.ID != secretID || metadata.Version != rotated.NewVersion || !validDigest(metadata.BindingDigest) {
		return "", ErrIntegrity
	}
	reference := binding.Credential
	reference.Version = metadata.Version
	reference.EncryptionContextDigest = metadata.BindingDigest
	key := cyberMailActivationKey{TenantID: rotated.TenantID, BindingID: rotated.BindingID, Version: rotated.NewVersion}
	activator.mutex.Lock()
	activator.activated[key] = reference
	activator.mutex.Unlock()
	return cyberMailEvidenceDigest("smtp.activate", string(rotated.TenantID), string(rotated.BindingID),
		metadata.BindingDigest, metadata.CiphertextDigest, string(metadata.ID)), nil
}

func (activator *cyberMailProtectedCredentialActivator) take(tenantID TenantID, bindingID BindingID, version uint64) (EncryptedCredentialReference, error) {
	key := cyberMailActivationKey{TenantID: tenantID, BindingID: bindingID, Version: version}
	activator.mutex.Lock()
	reference, ok := activator.activated[key]
	delete(activator.activated, key)
	activator.mutex.Unlock()
	if !ok || reference.Validate() != nil || reference.Version != version {
		return EncryptedCredentialReference{}, ErrAmbiguous
	}
	return reference, nil
}

func (adapter *CyberMailAdapterV1) ActivatedCyberMailCredentialReference(tenantID TenantID, bindingID BindingID, version uint64) (EncryptedCredentialReference, error) {
	activator, ok := adapter.credentialActivator.(*cyberMailProtectedCredentialActivator)
	if !ok || activator == nil {
		return EncryptedCredentialReference{}, ErrUnsupported
	}
	return activator.take(tenantID, bindingID, version)
}

type cyberMailUnsupportedQueueObserver struct{}

func (cyberMailUnsupportedQueueObserver) QuerySMTPIdempotency(context.Context, SMTPRelayOrigin, TenantID, string) (QueryResult, error) {
	return QueryResult{}, errors.Join(ErrUnsupported, ErrUnavailable)
}

func cyberMailSecretAudience(binding ProviderBinding, releaseDigest string) secrets.AudienceBinding {
	return secrets.AudienceBinding{AdapterID: CyberMailAdapterKind, AdapterVersion: CyberMailAdapterVersionV1,
		Account: CyberMailAdapterKind, Origin: CyberMailAPIBaseURL, ResourceKind: "mail_relay",
		ResourceID: cyberMailScopedSecretID("resource", string(binding.ID)), ResourceGeneration: 1,
		Operations: []secrets.Operation{secrets.OperationAuthenticate, secrets.OperationRotate}, ConsumerReleaseDigest: releaseDigest}
}

func cyberMailScopedSecretID(namespace, value string) secrets.ID {
	if identifier, err := secrets.NewID(value); err == nil {
		return identifier
	}
	digest := sha256.Sum256([]byte(namespace + "\x00" + value))
	return secrets.ID(namespace + "_" + hex.EncodeToString(digest[:])[:48])
}

var _ CyberMailCredentialResolver = (*cyberMailProtectedSecretSource)(nil)
var _ SMTPSecretResolver = (*cyberMailProtectedSecretSource)(nil)
var _ CyberMailCredentialActivator = (*cyberMailProtectedCredentialActivator)(nil)
var _ SMTPQueueObserver = cyberMailUnsupportedQueueObserver{}
