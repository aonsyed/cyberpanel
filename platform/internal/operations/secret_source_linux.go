//go:build linux

package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	OperationsSecretAdapterID = "operations.managed-service"
	OperationsSecretAdapterVersion = "linux-managed-service-v1"
)

type LinuxManagedServiceSecretSource interface {
	ManagedCredential(context.Context, SecretRef, ManagedService) ([]byte, error)
}

type LinuxOperationsSecretBrokerSource struct {
	client *secrets.MaterialClient
	installationOwner secrets.ID
}

func NewLinuxOperationsSecretBrokerSource(client *secrets.MaterialClient, installationOwner secrets.ID) (*LinuxOperationsSecretBrokerSource, error) {
	if client == nil || !installationOwner.Valid() { return nil, ErrInvalidResource }
	return &LinuxOperationsSecretBrokerSource{client:client, installationOwner:installationOwner}, nil
}

func (source *LinuxOperationsSecretBrokerSource) ManagedCredential(ctx context.Context, reference SecretRef, service ManagedService) ([]byte, error) {
	if source == nil || source.client == nil || reference.IsZero() || service.ID.IsZero() { return nil, ErrInvalidResource }
	owner := source.installationOwner
	if service.TenantID.String() != "" { owner = OperationsTenantOwnerID(service.TenantID.String()) }
	response, err := source.client.Read(ctx, secrets.MaterialRequest{
		SecretID:OperationsSecretRecordID(reference.String()), OwnerTenantID:owner, Purpose:secrets.PurposeAuthentication,
		Operation:secrets.OperationAuthenticate, AdapterID:OperationsSecretAdapterID, AdapterVersion:OperationsSecretAdapterVersion,
		ResourceID:OperationsManagedAudienceID(service.ID.String()),
	})
	if err != nil { return nil, err }
	if len(response.Material) == 0 || len(response.Material) > 65536 { wipeOperationsBytes(response.Material); return nil, ErrInvalidResource }
	return response.Material, nil
}

func operationsSecretID(prefix, value string) secrets.ID {
	digest := sha256.Sum256([]byte(prefix+"\x00"+value)); identifier, _ := secrets.NewID(prefix+"_"+hex.EncodeToString(digest[:])[:48]); return identifier
}
func OperationsSecretRecordID(reference string)secrets.ID{return operationsSecretID("opssecret",reference)}
func OperationsTenantOwnerID(tenantID string)secrets.ID{return operationsSecretID("tenant",tenantID)}
func OperationsManagedAudienceID(resourceID string)secrets.ID{return operationsSecretID("managed",resourceID)}

func wipeOperationsBytes(values ...[]byte) { for _, value := range values { for index := range value { value[index] = 0 } } }

var _ LinuxManagedServiceSecretSource = (*LinuxOperationsSecretBrokerSource)(nil)
