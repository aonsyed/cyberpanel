//go:build linux

package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	LinuxAccessSecretAdapterID      = "access.linux"
	LinuxAccessSecretAdapterVersion = "linux-access-v1"
)

type LinuxAccessSecretSource struct {
	client            *secrets.MaterialClient
	management        *secrets.ManagementClient
	installationOwner secrets.ID
}

func NewLinuxAccessSecretSource(client *secrets.MaterialClient, owner secrets.ID) (*LinuxAccessSecretSource, error) {
	if client == nil || !owner.Valid() {
		return nil, ErrInvalidState
	}
	return &LinuxAccessSecretSource{client: client, installationOwner: owner}, nil
}
func NewLinuxAccessSecretSourceWithManagement(client *secrets.MaterialClient, management *secrets.ManagementClient, owner secrets.ID) (*LinuxAccessSecretSource, error) {
	if client == nil || management == nil || !owner.Valid() {
		return nil, ErrInvalidState
	}
	return &LinuxAccessSecretSource{client: client, management: management, installationOwner: owner}, nil
}
func accessSecretID(prefix, value string) secrets.ID {
	sum := sha256.Sum256([]byte(prefix + "\x00" + value))
	id, _ := secrets.NewID(prefix + "_" + hex.EncodeToString(sum[:])[:48])
	return id
}
func (source *LinuxAccessSecretSource) Read(ctx context.Context, reference string, purpose secrets.Purpose, operation secrets.Operation, resource string) ([]byte, error) {
	if source == nil || source.client == nil || !validID(reference) || !validID(resource) {
		return nil, ErrInvalidID
	}
	response, err := source.client.Read(ctx, secrets.MaterialRequest{SecretID: accessSecretID("accesssecret", reference), OwnerTenantID: source.installationOwner, Purpose: purpose, Operation: operation, AdapterID: LinuxAccessSecretAdapterID, AdapterVersion: LinuxAccessSecretAdapterVersion, ResourceID: accessSecretID("accessaudience", resource)})
	if err != nil {
		return nil, err
	}
	return response.Material, nil
}
func (source *LinuxAccessSecretSource) ReadMigrationHash(ctx context.Context, reference, tenant, resource string) ([]byte, error) {
	if source == nil || source.client == nil || !validID(reference) || !validID(tenant) || !validID(resource) {
		return nil, ErrInvalidID
	}
	response, err := source.client.Read(ctx, secrets.MaterialRequest{SecretID: AccessSecretRecordID(reference), OwnerTenantID: AccessTenantOwnerID(tenant), Purpose: secrets.PurposeAuthentication, Operation: secrets.OperationAuthenticate, AdapterID: LinuxAccessSecretAdapterID, AdapterVersion: LinuxAccessSecretAdapterVersion, ResourceID: AccessSecretAudienceID(resource)})
	if err != nil {
		return nil, err
	}
	if ValidateUnixCryptHash(response.Material) != nil {
		wipeAccess(response.Material)
		return nil, ErrIntegrity
	}
	return response.Material, nil
}
func AccessSecretRecordID(reference string) secrets.ID {
	return accessSecretID("accesssecret", reference)
}
func AccessSecretAudienceID(resource string) secrets.ID {
	return accessSecretID("accessaudience", resource)
}
func AccessTenantOwnerID(tenant string) secrets.ID { return accessSecretID("tenant", tenant) }
