package database

import (
	"context"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

// MigrationRestore is a closed, create-only dump protocol. The peer supplies
// bounded bytes, never a pathname, SQL command, executable or CLI argument.
type MigrationRestoreRequest struct {
	Action string `json:"action"`
	ID ResourceID `json:"id"`
	TenantID site.TenantID `json:"tenant_id"`
	SiteID site.SiteID `json:"site_id"`
	DatabaseID ResourceID `json:"database_id"`
	PrincipalID ResourceID `json:"principal_id"`
	GrantSetID ResourceID `json:"grant_set_id"`
	SourceName SQLIdentifier `json:"source_name"`
	InputDigest string `json:"input_digest"`
	DumpDigest string `json:"dump_digest"`
	DumpBytes uint64 `json:"dump_bytes"`
	Offset uint64 `json:"offset,omitempty"`
	Data []byte `json:"data,omitempty"`
}

type MigrationRestoreReceipt struct {
	ID ResourceID `json:"id"`
	InputDigest string `json:"input_digest"`
	State string `json:"state"`
	Bytes uint64 `json:"bytes"`
	ProofDigest string `json:"proof_digest,omitempty"`
	Process *TransferProcessReceipt `json:"process,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type MigrationRestoreExecutor interface {
	RestoreMigrationDatabase(context.Context, MigrationRestoreRequest) (MigrationRestoreReceipt, error)
}

func (value MigrationRestoreRequest) validate() error {
	if value.ID.IsZero() || value.TenantID.String()=="" || value.SiteID.String()=="" || value.DatabaseID.IsZero() || value.PrincipalID.IsZero() || value.GrantSetID.IsZero() || value.SourceName.IsZero() || !validSHA256(value.InputDigest) || !validSHA256(value.DumpDigest) || value.DumpBytes==0 || value.DumpBytes>64<<30 { return ErrInvalidCommand }
	switch value.Action {
	case "begin", "apply", "observe", "discard":
		if value.Offset!=0 || len(value.Data)!=0 { return ErrInvalidCommand }
	case "chunk":
		if len(value.Data)==0 || len(value.Data)>256<<10 || value.Offset>value.DumpBytes || uint64(len(value.Data))>value.DumpBytes-value.Offset { return ErrInvalidCommand }
	default: return ErrInvalidCommand
	}
	return nil
}

func (value MigrationRestoreReceipt) matches(request MigrationRestoreRequest) bool {
	if value.ID!=request.ID || value.InputDigest!=request.InputDigest || value.Bytes>request.DumpBytes || value.ObservedAt.IsZero() { return false }
	switch value.State {
	case "uploading", "ambiguous", "discarded": return value.ProofDigest=="" && value.Process==nil
	case "applied": return value.Bytes==request.DumpBytes && validSHA256(value.ProofDigest) && value.Process!=nil && value.Process.ExitCode==0 && !value.Process.Partial && value.Process.InputVerified
	default: return false
	}
}

func (client *BrokerClient) RestoreMigrationDatabase(ctx context.Context, value MigrationRestoreRequest) (MigrationRestoreReceipt, error) {
	request, err := client.requestWithMaximum(ctx, BrokerMigrationRestore, 2*time.Minute)
	if err!=nil { return MigrationRestoreReceipt{}, err }
	request.MigrationRestore=&value
	if err=request.validate(client.now().UTC()); err!=nil { return MigrationRestoreReceipt{}, err }
	response, err := client.transport.RoundTrip(ctx,request)
	if err!=nil { return MigrationRestoreReceipt{}, err }
	if err=response.validate(request); err!=nil { return MigrationRestoreReceipt{}, err }
	if response.FailureCode!="" { return MigrationRestoreReceipt{}, brokerFailure(response.FailureCode) }
	return *response.MigrationRestore,nil
}
