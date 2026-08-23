package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// SecretConsumerProfile is installed only for a concrete provider worker.
// The immutable account, origin, adapter identity, and executable digest are
// copied into the broker audience so panel-core cannot retarget a credential.
type SecretConsumerProfile struct {
	AdapterID             string
	AdapterVersion        string
	Account               string
	Origin                string
	ConsumerReleaseDigest string
	Operations            []secrets.Operation
}

func (profile SecretConsumerProfile) validate() error {
	if strings.TrimSpace(profile.AdapterID) == "" || strings.TrimSpace(profile.AdapterVersion) == "" || strings.TrimSpace(profile.Account) == "" || strings.TrimSpace(profile.Origin) == "" || !validDigest(profile.ConsumerReleaseDigest) || len(profile.Operations) == 0 {
		return ErrInvalid
	}
	seen := map[secrets.Operation]bool{}
	for _, operation := range profile.Operations {
		if seen[operation] {
			return ErrInvalid
		}
		seen[operation] = true
	}
	return nil
}

type BrokerSecretManager struct {
	Management *secrets.ManagementClient
	Profiles   map[ProviderKind]SecretConsumerProfile
}

func NewBrokerSecretManager(client *secrets.ManagementClient, profiles map[ProviderKind]SecretConsumerProfile) (*BrokerSecretManager, error) {
	if client == nil || len(profiles) == 0 {
		return nil, ErrInvalid
	}
	copyProfiles := make(map[ProviderKind]SecretConsumerProfile, len(profiles))
	for kind, profile := range profiles {
		if !kind.Valid() || profile.validate() != nil {
			return nil, ErrInvalid
		}
		profile.Operations = append([]secrets.Operation(nil), profile.Operations...)
		copyProfiles[kind] = profile
	}
	return &BrokerSecretManager{Management:client, Profiles:copyProfiles}, nil
}

func (manager *BrokerSecretManager) StoreProviderSecret(ctx context.Context, request BindingRequest, material []byte) (SecretRef, uint64, string, error) {
	if manager == nil || manager.Management == nil || ctx == nil || len(material) == 0 {
		wipeIntegrationSecret(material)
		return "", 0, "", ErrInvalid
	}
	profile, audience, owner, secretID, purpose, err := manager.enrollment(request.ID, request.TenantID, request.Kind, request.Purpose, request.Endpoint)
	if err != nil {
		wipeIntegrationSecret(material)
		return "", 0, "", err
	}
	_ = profile
	metadata, err := manager.Management.Put(ctx, secrets.PutRequest{ID:secretID, OwnerTenantID:owner, Purpose:purpose, Audience:audience, Plaintext:material})
	if err != nil {
		return "", 0, "", err
	}
	return SecretRef(metadata.ID.String()), metadata.Version, metadata.BindingDigest, nil
}

func (manager *BrokerSecretManager) RotateProviderSecret(ctx context.Context, binding ProviderBinding, material []byte) (uint64, string, error) {
	if manager == nil || manager.Management == nil || ctx == nil || len(material) == 0 || binding.SecretVersion == 0 || !validDigest(binding.SecretBindingDigest) {
		wipeIntegrationSecret(material)
		return 0, "", ErrInvalid
	}
	_, audience, owner, secretID, purpose, err := manager.enrollment(binding.ID, binding.TenantID, binding.Kind, binding.Purpose, binding.Endpoint)
	if err != nil || SecretRef(secretID.String()) != binding.SecretRef {
		wipeIntegrationSecret(material)
		return 0, "", ErrIntegrity
	}
	metadata, err := manager.Management.Put(ctx, secrets.PutRequest{ID:secretID, OwnerTenantID:owner, Purpose:purpose, Audience:audience, Plaintext:material, ExpectedVersion:binding.SecretVersion, ExpectedBindingDigest:binding.SecretBindingDigest})
	if err != nil {
		return 0, "", err
	}
	return metadata.Version, metadata.BindingDigest, nil
}

func (manager *BrokerSecretManager) RevokeProviderSecret(ctx context.Context, binding ProviderBinding) error {
	if manager == nil || manager.Management == nil || ctx == nil || binding.SecretVersion == 0 || !validDigest(binding.SecretBindingDigest) {
		return ErrInvalid
	}
	_, audience, owner, secretID, purpose, err := manager.enrollment(binding.ID, binding.TenantID, binding.Kind, binding.Purpose, binding.Endpoint)
	if err != nil || SecretRef(secretID.String()) != binding.SecretRef {
		return ErrIntegrity
	}
	_, err = manager.Management.Revoke(ctx, secrets.RevokeRequest{ID:secretID, OwnerTenantID:owner, Purpose:purpose, Audience:audience, ExpectedVersion:binding.SecretVersion, ExpectedBindingDigest:binding.SecretBindingDigest})
	return err
}

func (manager *BrokerSecretManager) enrollment(bindingID BindingID, tenant TenantID, kind ProviderKind, purpose CredentialPurpose, endpoint EndpointPolicy) (SecretConsumerProfile, secrets.AudienceBinding, secrets.ID, secrets.ID, secrets.Purpose, error) {
	profile, ok := manager.Profiles[kind]
	if !ok || profile.validate() != nil || !purposeMatches(kind, purpose) || endpoint.Validate() != nil || endpoint.URL != profile.Origin {
		return SecretConsumerProfile{}, secrets.AudienceBinding{}, "", "", "", ErrUnsupported
	}
	ownerRaw := string(tenant)
	if ownerRaw == "" {
		ownerRaw = "installation"
	}
	owner := integrationSecretID("owner", ownerRaw)
	resource := integrationSecretID("binding", string(bindingID))
	secretID := integrationSecretID("integration", string(bindingID))
	secretPurpose, err := integrationSecretPurpose(purpose)
	if err != nil {
		return SecretConsumerProfile{}, secrets.AudienceBinding{}, "", "", "", err
	}
	account:=profile.Account;if account=="binding"{account=string(bindingID)}
	audience := secrets.AudienceBinding{AdapterID:profile.AdapterID, AdapterVersion:profile.AdapterVersion, Account:account, Origin:profile.Origin, ResourceKind:"integration_binding", ResourceID:resource, ResourceGeneration:1, Operations:append([]secrets.Operation(nil),profile.Operations...), ConsumerReleaseDigest:profile.ConsumerReleaseDigest}
	if audience.Validate() != nil {
		return SecretConsumerProfile{}, secrets.AudienceBinding{}, "", "", "", ErrInvalid
	}
	return profile, audience, owner, secretID, secretPurpose, nil
}

func integrationSecretPurpose(purpose CredentialPurpose) (secrets.Purpose, error) {
	switch purpose {
	case PurposeDNS:
		return secrets.PurposeDNSProvider, nil
	case PurposeBackup:
		return secrets.PurposeBackupRepository, nil
	case PurposeMailRelay:
		return secrets.PurposeMailRelay, nil
	case PurposeRegistry:
		return secrets.PurposeRegistry, nil
	case PurposeSecurity, PurposeNotification:
		return secrets.PurposeAuthentication, nil
	default:
		return "", ErrUnsupported
	}
}

func integrationSecretID(namespace, value string) secrets.ID {
	if identifier, err := secrets.NewID(strings.ToLower(value)); err == nil {
		return identifier
	}
	sum := sha256.Sum256([]byte(namespace + "\x00" + value))
	return secrets.ID(namespace + "_" + hex.EncodeToString(sum[:])[:48])
}

func wipeIntegrationSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ SecretManager = (*BrokerSecretManager)(nil)
