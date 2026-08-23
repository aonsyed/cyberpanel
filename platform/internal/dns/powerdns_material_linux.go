//go:build linux

package dns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	PowerDNSDatabaseMaterialAdapterID = "dns.powerdns.database"
	PowerDNSTSIGMaterialAdapterID = "dns.powerdns.tsig"
	PowerDNSMaterialAdapterVersion = "linux-powerdns-v1"
)

// PowerDNSMaterialResolver is the concrete purpose-bound bridge from the
// privileged daemon adapter to panel-secretd. It never reads credential files
// and never accepts caller-selected socket paths or secret operations.
type PowerDNSMaterialResolver struct {
	client *secrets.MaterialClient
	installationOwner secrets.ID
}

func NewLocalPowerDNSMaterialResolver(installationOwner secrets.ID) (*PowerDNSMaterialResolver, error) {
	client, err := secrets.NewLocalMaterialClient()
	if err != nil {
		return nil, err
	}
	return NewPowerDNSMaterialResolver(client, installationOwner)
}

func OpenLocalLinuxPowerDNSHost(platform LinuxPowerDNSPlatform, ownership PowerDNSOwnership, installationOwner secrets.ID, controlDatabaseFingerprint string) (*LinuxPowerDNSHost, error) {
	resolver, err := NewLocalPowerDNSMaterialResolver(installationOwner)
	if err != nil {
		return nil, err
	}
	return OpenLinuxPowerDNSHost(platform, ownership, resolver, controlDatabaseFingerprint)
}

func NewPowerDNSMaterialResolver(client *secrets.MaterialClient, installationOwner secrets.ID) (*PowerDNSMaterialResolver, error) {
	if client == nil || !installationOwner.Valid() {
		return nil, ErrInvalidDNS
	}
	return &PowerDNSMaterialResolver{client: client, installationOwner: installationOwner}, nil
}

func (resolver *PowerDNSMaterialResolver) ResolvePowerDNSDatabaseCredential(ctx context.Context, binding PowerDNSDatabaseBinding) ([]byte, error) {
	if resolver == nil || resolver.client == nil || binding.Purpose != PowerDNSAuthoritativePurpose || !safePowerDNSOpaque(binding.ID, 128) || !safePowerDNSOpaque(binding.CredentialRef, 256) || !powerDNSSHA256(binding.Fingerprint) || binding.Fingerprint != binding.ExpectedFingerprint() {
		return nil, ErrPowerDNSConfigCredential
	}
	return resolver.read(ctx, powerDNSMaterialID("pdnsdb", binding.CredentialRef), resolver.installationOwner, secrets.PurposeDatabase, secrets.OperationAuthenticate, PowerDNSDatabaseMaterialAdapterID, powerDNSMaterialID("pdnsbinding", binding.Fingerprint), powerDNSMaximumCredentialBytes, true, ErrPowerDNSConfigCredential)
}

func (resolver *PowerDNSMaterialResolver) ResolvePowerDNSAuthoritativeCredential(ctx context.Context, identity PowerDNSAuthoritativeDatabaseIdentity) ([]byte, error) {
	if resolver == nil || resolver.client == nil || identity.Purpose != PowerDNSAuthoritativePurpose || !validPowerDNSIdentityValue(identity.CredentialRef, 2048) || !powerDNSSHA256(identity.Fingerprint) {
		return nil, ErrPowerDNSAuthoritativeCredential
	}
	return resolver.read(ctx, powerDNSMaterialID("pdnsdb", identity.CredentialRef), resolver.installationOwner, secrets.PurposeDatabase, secrets.OperationAuthenticate, PowerDNSDatabaseMaterialAdapterID, powerDNSMaterialID("pdnsbinding", identity.Fingerprint), powerDNSMaximumCredentialBytes, true, ErrPowerDNSAuthoritativeCredential)
}

func (resolver *PowerDNSMaterialResolver) ResolvePowerDNSTSIGSecret(ctx context.Context, tenant string, secretRef string) ([]byte, error) {
	if resolver == nil || resolver.client == nil || !validPowerDNSIdentityValue(tenant, 512) || !validPowerDNSIdentityValue(secretRef, 2048) {
		return nil, ErrPowerDNSTSIGSecret
	}
	owner := powerDNSMaterialID("pdnstenant", tenant)
	audience := powerDNSMaterialID("pdnstsigbinding", tenant, secretRef)
	return resolver.read(ctx, powerDNSMaterialID("pdnstsig", secretRef), owner, secrets.PurposeDNSProvider, secrets.OperationRead, PowerDNSTSIGMaterialAdapterID, audience, 256, false, ErrPowerDNSTSIGSecret)
}

func (resolver *PowerDNSMaterialResolver) read(ctx context.Context, secretID secrets.ID, owner secrets.ID, purpose secrets.Purpose, operation secrets.Operation, adapterID string, resourceID secrets.ID, maximum int, textOnly bool, failure error) ([]byte, error) {
	if ctx == nil || !secretID.Valid() || !owner.Valid() || !resourceID.Valid() || maximum < 1 {
		return nil, failure
	}
	response, err := resolver.client.Read(ctx, secrets.MaterialRequest{
		SecretID: secretID,
		OwnerTenantID: owner,
		Purpose: purpose,
		Operation: operation,
		AdapterID: adapterID,
		AdapterVersion: PowerDNSMaterialAdapterVersion,
		ResourceID: resourceID,
	})
	if err != nil || len(response.Material) == 0 || len(response.Material) > maximum || textOnly && bytes.IndexAny(response.Material, "\x00\r\n") >= 0 {
		wipePowerDNSSecret(response.Material)
		return nil, failure
	}
	return response.Material, nil
}

func powerDNSMaterialID(prefix string, values ...string) secrets.ID {
	hash := sha256.New()
	_, _ = hash.Write([]byte(prefix))
	for _, value := range values {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	identifier, _ := secrets.NewID(prefix + "_" + hex.EncodeToString(hash.Sum(nil))[:48])
	return identifier
}

var _ PowerDNSCredentialResolver = (*PowerDNSMaterialResolver)(nil)
var _ PowerDNSAuthoritativeCredentialResolver = (*PowerDNSMaterialResolver)(nil)
var _ PowerDNSTSIGSecretResolver = (*PowerDNSMaterialResolver)(nil)
