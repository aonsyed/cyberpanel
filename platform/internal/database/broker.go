package database

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

const (
	DatabaseBrokerProtocolVersion uint32 = 1
	DatabaseBrokerMaximumFrame          = 1 << 20
	databaseBrokerMaximumResponseFrame  = 66 << 20
)

type BrokerOperation string

const (
	BrokerObserveOrApply BrokerOperation = "observe_or_apply"
	BrokerCompensate     BrokerOperation = "compensate"
	BrokerWorkspaceMetadata BrokerOperation = "workspace_metadata"
	BrokerWorkspaceQuery    BrokerOperation = "workspace_query"
	BrokerWorkspaceExport   BrokerOperation = "workspace_export"
	BrokerWorkspaceExportRead BrokerOperation = "workspace_export_read"
	BrokerInstanceStatus    BrokerOperation = "instance_status"
	BrokerMariaDBHA         BrokerOperation = "mariadb_ha"
	BrokerMigrationRestore BrokerOperation = "migration_restore"
)

type MariaDBHAAction string

const (
	MariaDBHAObserve    MariaDBHAAction = "observe"
	MariaDBHAFreeze     MariaDBHAAction = "freeze"
	MariaDBHAPromote    MariaDBHAAction = "promote"
	MariaDBHADemote     MariaDBHAAction = "demote"
	MariaDBHASignPermit MariaDBHAAction = "sign_permit"
	MariaDBHACheckpoint MariaDBHAAction = "checkpoint"
	MariaDBHACatchUp MariaDBHAAction = "catch_up"
	MariaDBHARejoin MariaDBHAAction = "rejoin"
	MariaDBHAWriterCertificate MariaDBHAAction = "writer_certificate"
	MariaDBHAWriterFenceEvidence MariaDBHAAction = "writer_fence_evidence"
	MariaDBHAWriterCandidateEvidence MariaDBHAAction = "writer_candidate_evidence"
)

// MariaDBHARequest is the closed privileged surface used by the local HA
// adapters. It carries topology state, fencing coordinates, and write permits;
// it never accepts SQL, an executable, a service name, or a filesystem path.
type MariaDBHARequest struct {
	Action       MariaDBHAAction   `json:"action"`
	Cluster      ha.DatabaseCluster `json:"cluster,omitempty"`
	NodeID       ha.NodeID          `json:"node_id,omitempty"`
	FencingToken uint64             `json:"fencing_token,omitempty"`
	Lease        *ha.WriterLease    `json:"lease,omitempty"`
	Permit       *ha.WritePermit    `json:"permit,omitempty"`
	Channel *ha.ReplicationChannel `json:"channel,omitempty"`
	Checkpoint *ha.ReplicationCheckpoint `json:"checkpoint,omitempty"`
	SourceGeneration uint64 `json:"source_generation,omitempty"`
	AuthorityEpoch uint64 `json:"authority_epoch,omitempty"`
	WriterAuthority json.RawMessage `json:"writer_authority,omitempty"`
}

type MariaDBHAResult struct {
	Cluster  *ha.DatabaseCluster `json:"cluster,omitempty"`
	Receipt  string              `json:"receipt,omitempty"`
	Frontier uint64              `json:"frontier,omitempty"`
	Permit   *ha.WritePermit     `json:"permit,omitempty"`
	Checkpoint *ha.ReplicationCheckpoint `json:"checkpoint,omitempty"`
	Replication *ha.ReplicationReceipt `json:"replication,omitempty"`
	WriterCertificate *DatabaseWriterCertificate `json:"writer_certificate,omitempty"`
	WriterFenceEvidence *DatabaseWriterFenceEvidence `json:"writer_fence_evidence,omitempty"`
}

type WorkspaceBrokerRequest struct {
	Access    WorkspaceAccess `json:"access"`
	Statement string          `json:"statement,omitempty"`
}

type BrokerRequest struct {
	Version      uint32               `json:"version"`
	RequestID    string               `json:"request_id"`
	Operation    BrokerOperation      `json:"operation"`
	Deadline     time.Time            `json:"deadline"`
	Effect       *EffectRequest       `json:"effect,omitempty"`
	Compensation *CompensationRequest `json:"compensation,omitempty"`
	Workspace    *WorkspaceBrokerRequest `json:"workspace,omitempty"`
	InstanceID   ResourceID              `json:"instance_id,omitempty"`
	MariaDBHA    *MariaDBHARequest    `json:"mariadb_ha,omitempty"`
	MigrationRestore *MigrationRestoreRequest `json:"migration_restore,omitempty"`
	WorkspaceExport *WorkspaceExportRequest `json:"workspace_export,omitempty"`
	WorkspaceExportRead *WorkspaceExportReadRequest `json:"workspace_export_read,omitempty"`
}

type BrokerResponse struct {
	Version      uint32                `json:"version"`
	RequestID    string                `json:"request_id"`
	Operation    BrokerOperation       `json:"operation"`
	Effect       *EffectReceipt        `json:"effect,omitempty"`
	Compensation *CompensationReceipt  `json:"compensation,omitempty"`
	Metadata     *WorkspaceMetadataResult `json:"metadata,omitempty"`
	Query        *WorkspaceQueryResult `json:"query,omitempty"`
	InstanceStatus *MariaDBInstanceStatus `json:"instance_status,omitempty"`
	MariaDBHA    *MariaDBHAResult      `json:"mariadb_ha,omitempty"`
	MigrationRestore *MigrationRestoreReceipt `json:"migration_restore,omitempty"`
	Export *TransferProcessReceipt `json:"export,omitempty"`
	ExportChunk *WorkspaceExportChunk `json:"export_chunk,omitempty"`
	FailureCode  string                `json:"failure_code,omitempty"`
}

func (request BrokerRequest) validate(now time.Time) error {
	if request.Operation!=BrokerWorkspaceExportRead && request.WorkspaceExportRead!=nil{return ErrInvalidCommand}
	if request.Operation!=BrokerWorkspaceExport && request.WorkspaceExport!=nil{return ErrInvalidCommand}
	if request.Operation != BrokerMigrationRestore && request.MigrationRestore != nil { return ErrInvalidCommand }
	if request.Operation != BrokerInstanceStatus && !request.InstanceID.IsZero() { return ErrInvalidCommand }
	if request.Version != DatabaseBrokerProtocolVersion || !validBrokerRequestID(request.RequestID) || request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.After(now.Add(2*time.Minute)) {
		return ErrInvalidCommand
	}
	switch request.Operation {
	case BrokerWorkspaceExportRead:
		if request.Effect!=nil || request.Compensation!=nil || request.Workspace!=nil || request.MariaDBHA!=nil || request.WorkspaceExportRead==nil || request.WorkspaceExportRead.validate(now)!=nil{return ErrInvalidCommand}
	case BrokerWorkspaceExport:
		if request.Effect!=nil || request.Compensation!=nil || request.Workspace!=nil || request.MariaDBHA!=nil || request.WorkspaceExport==nil || request.WorkspaceExport.validate(now)!=nil{return ErrInvalidCommand}
	case BrokerMigrationRestore:
		if request.Effect!=nil || request.Compensation!=nil || request.Workspace!=nil || request.MariaDBHA!=nil || request.MigrationRestore==nil || request.MigrationRestore.validate()!=nil { return ErrInvalidCommand }
	case BrokerObserveOrApply:
		if request.Effect == nil || request.Compensation != nil || request.Workspace != nil || request.MariaDBHA != nil || validateEffectRequest(*request.Effect) != nil {
			return ErrInvalidCommand
		}
	case BrokerCompensate:
		if request.Effect != nil || request.Compensation == nil || request.Workspace != nil || request.MariaDBHA != nil || !validCompensationRequest(*request.Compensation) {
			return ErrInvalidCommand
		}
	case BrokerWorkspaceMetadata:
		if request.Effect != nil || request.Compensation != nil || request.Workspace == nil || request.MariaDBHA != nil || request.Workspace.Statement != "" || request.Workspace.Access.validate(now) != nil {
			return ErrInvalidCommand
		}
	case BrokerWorkspaceQuery:
		if request.Effect != nil || request.Compensation != nil || request.Workspace == nil || request.MariaDBHA != nil || request.Workspace.Access.validate(now) != nil {
			return ErrInvalidCommand
		}
		if normalized, _, err := ParseWorkspaceStatement(request.Workspace.Statement); err != nil || normalized != request.Workspace.Statement {
			return ErrInvalidCommand
		}
	case BrokerInstanceStatus:
		if request.Effect != nil || request.Compensation != nil || request.Workspace != nil || request.InstanceID.IsZero() || request.MariaDBHA != nil || request.MigrationRestore != nil {
			return ErrInvalidCommand
		}
	case BrokerMariaDBHA:
		if request.Effect != nil || request.Compensation != nil || request.Workspace != nil || request.MariaDBHA == nil || validateMariaDBHARequest(*request.MariaDBHA, now) != nil {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

func (response BrokerResponse) validate(request BrokerRequest) error {
	if request.Operation!=BrokerWorkspaceExportRead && response.ExportChunk!=nil{return ErrInvalidReceipt}
	if request.Operation!=BrokerWorkspaceExport && response.Export!=nil{return ErrInvalidReceipt}
	if request.Operation != BrokerMigrationRestore && response.MigrationRestore != nil { return ErrInvalidReceipt }
	if request.Operation != BrokerInstanceStatus && response.InstanceStatus != nil { return ErrInvalidReceipt }
	if response.Version != DatabaseBrokerProtocolVersion || response.RequestID != request.RequestID || response.Operation != request.Operation {
		return ErrInvalidReceipt
	}
	if response.FailureCode != "" {
		if response.ExportChunk!=nil{return ErrInvalidReceipt}
		if response.Export!=nil{return ErrInvalidReceipt}
		if response.Effect != nil || response.Compensation != nil || response.Metadata != nil || response.Query != nil || response.InstanceStatus != nil || response.MariaDBHA != nil || response.MigrationRestore != nil || !validBrokerFailure(response.FailureCode) {
			return ErrInvalidReceipt
		}
		return nil
	}
	switch request.Operation {
	case BrokerWorkspaceExportRead:
		if response.Effect!=nil || response.Compensation!=nil || response.Metadata!=nil || response.Query!=nil || response.MariaDBHA!=nil || response.ExportChunk==nil || request.WorkspaceExportRead==nil || !response.ExportChunk.matches(*request.WorkspaceExportRead){return ErrInvalidReceipt};return nil
	case BrokerWorkspaceExport:
		if response.Effect!=nil || response.Compensation!=nil || response.Metadata!=nil || response.Query!=nil || response.MariaDBHA!=nil || response.Export==nil || request.WorkspaceExport==nil || !request.WorkspaceExport.matches(*response.Export){return ErrInvalidReceipt};return nil
	case BrokerMigrationRestore:
		if response.Effect!=nil || response.Compensation!=nil || response.Metadata!=nil || response.Query!=nil || response.MariaDBHA!=nil || response.MigrationRestore==nil || request.MigrationRestore==nil || !response.MigrationRestore.matches(*request.MigrationRestore) { return ErrInvalidReceipt }; return nil
	case BrokerObserveOrApply:
		if response.Metadata != nil || response.Query != nil || response.MariaDBHA != nil { return ErrInvalidReceipt }
		return validateBrokerEffectResponse(request, response)
	case BrokerCompensate:
		if response.Metadata != nil || response.Query != nil || response.MariaDBHA != nil { return ErrInvalidReceipt }
		return validateBrokerCompensationResponse(request, response)
	case BrokerWorkspaceMetadata:
		if response.Effect != nil || response.Compensation != nil || response.Metadata == nil || response.Query != nil || response.MariaDBHA != nil || request.Workspace == nil {
			return ErrInvalidReceipt
		}
		return validateWorkspaceMetadata(*response.Metadata, request.Workspace.Access)
	case BrokerWorkspaceQuery:
		if response.Effect != nil || response.Compensation != nil || response.Metadata != nil || response.Query == nil || response.MariaDBHA != nil || request.Workspace == nil {
			return ErrInvalidReceipt
		}
		_, kind, err := ParseWorkspaceStatement(request.Workspace.Statement)
		if err != nil || response.Query.Kind != kind { return ErrInvalidReceipt }
		return validateWorkspaceResult(*response.Query, request.Workspace.Access)
	case BrokerInstanceStatus:
		if response.Effect != nil || response.Compensation != nil || response.Metadata != nil || response.Query != nil || response.InstanceStatus == nil || response.MariaDBHA != nil || response.MigrationRestore != nil {
			return ErrInvalidReceipt
		}
		return response.InstanceStatus.validate(request.InstanceID)
	case BrokerMariaDBHA:
		if response.Effect != nil || response.Compensation != nil || response.Metadata != nil || response.Query != nil || response.MariaDBHA == nil || request.MariaDBHA == nil {
			return ErrInvalidReceipt
		}
		return validateMariaDBHAResult(*request.MariaDBHA, *response.MariaDBHA)
	default:
		return ErrInvalidReceipt
	}
}

func validateMariaDBHARequest(request MariaDBHARequest, now time.Time) error {
	if request.Action == MariaDBHAWriterCertificate || request.Action == MariaDBHAWriterFenceEvidence || request.Action == MariaDBHAWriterCandidateEvidence {
		if request.NodeID != "" || request.FencingToken != 0 || request.Lease != nil || request.Permit != nil || request.Channel != nil || request.Checkpoint != nil || request.SourceGeneration != 0 || request.AuthorityEpoch != 0 || !sameWriterValue(request.Cluster, ha.DatabaseCluster{}) {
			return ErrInvalidCommand
		}
		if request.Action == MariaDBHAWriterFenceEvidence {
			_, err := decodeDatabaseWriterFenceAuthority(request.WriterAuthority)
			return err
		}
		_, err := decodeDatabaseWriterCandidateAuthority(request.WriterAuthority)
		return err
	}
	if len(request.WriterAuthority) != 0 {
		return ErrInvalidCommand
	}
	if request.Action==MariaDBHACheckpoint || request.Action==MariaDBHACatchUp || request.Action==MariaDBHARejoin { return validateMariaDBReplicationRequest(request) }
	if request.Channel!=nil || request.Checkpoint!=nil || request.SourceGeneration!=0 || request.AuthorityEpoch!=0 { return ErrInvalidCommand }
	const localResource = ha.ID("mariadb-local")
	const localNode = ha.NodeID("local")
	if request.Action == MariaDBHASignPermit {
		if request.Cluster.ID != "" || request.Cluster.GroupID != "" || request.Cluster.Topology != "" || len(request.Cluster.Members) != 0 || request.Cluster.Generation != 0 || request.NodeID != "" || request.FencingToken != 0 || request.Lease != nil || request.Permit == nil {
			return ErrInvalidCommand
		}
		permit := *request.Permit
		if permit.ResourceID != string(localResource) || permit.NodeID == "" || permit.LeaseID == "" || permit.FencingToken == 0 || permit.AuthorityEpoch == 0 || len(permit.WritePaths) == 0 || permit.Signature != "" || permit.IssuedAt.IsZero() || !permit.ExpiresAt.After(permit.IssuedAt) || !now.Before(permit.ExpiresAt) {
			return ErrInvalidCommand
		}
		return nil
	}
	if request.Cluster.Validate() != nil || request.Cluster.ID != localResource || request.Cluster.Topology != ha.DatabasePrimaryReplica || request.Permit != nil {
		return ErrInvalidCommand
	}
	switch request.Action {
	case MariaDBHAObserve:
		if request.NodeID != "" || request.FencingToken != 0 || request.Lease != nil { return ErrInvalidCommand }
	case MariaDBHAFreeze, MariaDBHADemote:
		if request.NodeID != localNode || request.FencingToken == 0 || request.Lease != nil { return ErrInvalidCommand }
	case MariaDBHAPromote:
		if request.NodeID == "" || request.FencingToken == 0 || request.Lease == nil { return ErrInvalidCommand }
		lease := *request.Lease
		if lease.Validate(now) != nil || lease.State != ha.LeaseActive || lease.ResourceID != string(localResource) || lease.HolderNodeID != request.NodeID || lease.FencingToken != request.FencingToken || lease.GroupID != request.Cluster.GroupID {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

func validateMariaDBHAResult(request MariaDBHARequest, result MariaDBHAResult) error {
	if request.Action == MariaDBHAWriterCertificate || request.Action == MariaDBHAWriterFenceEvidence || request.Action == MariaDBHAWriterCandidateEvidence {
		if result.Cluster != nil || result.Receipt != "" || result.Frontier != 0 || result.Permit != nil || result.Checkpoint != nil || result.Replication != nil {
			return ErrInvalidReceipt
		}
		if request.Action == MariaDBHAWriterCertificate {
			authority, err := decodeDatabaseWriterCandidateAuthority(request.WriterAuthority)
			if err != nil || result.WriterCertificate == nil || result.WriterFenceEvidence != nil {
				return ErrInvalidReceipt
			}
			receipt, err := decodeDatabaseSourceFenceReceipt(authority.SourceFenceReceipt)
			value := *result.WriterCertificate
			if err != nil || !validDatabaseWriterCertificate(value, time.Now().UTC()) || !sameWriterValue(value.Channel, authority.Channel) || !sameWriterValue(value.Checkpoint, authority.Checkpoint) || !sameWriterValue(value.Lease, authority.Lease) || value.ClusterID != authority.Cluster.ID || value.ClusterGeneration != authority.Cluster.Generation || value.TopologyDigest != authority.TopologyDigest || value.DeploymentEpoch != authority.DeploymentEpoch || value.DeploymentDigest != authority.DeploymentDigest || value.AuthorityEpoch != authority.AuthorityEpoch || value.OldWriter != authority.SourceNodeID || value.Candidate != authority.CandidateNodeID || value.FenceEffectID != receipt.EffectID || value.FenceDigest != writerDigestBytes(authority.SourceFenceReceipt) {
				return ErrInvalidReceipt
			}
			return nil
		}
		if result.WriterFenceEvidence == nil || result.WriterCertificate != nil || !validDatabaseWriterFenceEvidence(*result.WriterFenceEvidence) {
			return ErrInvalidReceipt
		}
		value := *result.WriterFenceEvidence
		if request.Action == MariaDBHAWriterFenceEvidence {
			authority, err := decodeDatabaseWriterFenceAuthority(request.WriterAuthority)
			receipt, receiptErr := decodeDatabaseSourceFenceReceipt(value.SourceFenceReceipt)
			if err != nil || receiptErr != nil || value.NodeID != authority.SourceNodeID || !sameWriterValue(value.Channel, authority.Channel) || !sameWriterValue(value.Checkpoint, authority.Checkpoint) || value.AuthorityEpoch != authority.AuthorityEpoch || value.DeploymentEpoch != authority.DeploymentEpoch || value.DeploymentDigest != authority.DeploymentDigest || value.FencingToken != authority.FencingToken || !sourceFenceReceiptMatchesAuthority(receipt, authority) {
				return ErrInvalidReceipt
			}
			return nil
		}
		authority, err := decodeDatabaseWriterCandidateAuthority(request.WriterAuthority)
		if err != nil || value.NodeID != authority.CandidateNodeID || !sameWriterValue(value.Channel, authority.Channel) || !sameWriterValue(value.Checkpoint, authority.Checkpoint) || value.AuthorityEpoch != authority.AuthorityEpoch || value.DeploymentEpoch != authority.DeploymentEpoch || value.DeploymentDigest != authority.DeploymentDigest || value.FencingToken != authority.FencingToken || !bytes.Equal(value.SourceFenceReceipt, authority.SourceFenceReceipt) {
			return ErrInvalidReceipt
		}
		return nil
	}
	if result.WriterCertificate!=nil||result.WriterFenceEvidence!=nil{return ErrInvalidReceipt}
	if request.Action==MariaDBHACheckpoint || request.Action==MariaDBHACatchUp || request.Action==MariaDBHARejoin { return validateMariaDBReplicationResult(request,result) }
	if result.Checkpoint!=nil || result.Replication!=nil { return ErrInvalidReceipt }
	switch request.Action {
	case MariaDBHAObserve:
		if result.Cluster == nil || result.Receipt != "" || result.Frontier != 0 || result.Permit != nil || result.Cluster.Validate() != nil || result.Cluster.ID != request.Cluster.ID || result.Cluster.GroupID != request.Cluster.GroupID {
			return ErrInvalidReceipt
		}
	case MariaDBHAFreeze, MariaDBHADemote:
		if result.Cluster != nil || result.Receipt == "" || result.Frontier != 0 || result.Permit != nil { return ErrInvalidReceipt }
	case MariaDBHAPromote:
		if result.Cluster != nil || result.Receipt == "" || result.Frontier == 0 || result.Permit != nil { return ErrInvalidReceipt }
	case MariaDBHASignPermit:
		if result.Cluster != nil || result.Receipt != "" || result.Frontier != 0 || result.Permit == nil { return ErrInvalidReceipt }
		actual, expected := *result.Permit, *request.Permit
		signature := actual.Signature
		actual.Signature = ""
		if !sameWritePermit(actual, expected) || signature == "" { return ErrInvalidReceipt }
	default:
		return ErrInvalidReceipt
	}
	return nil
}

func sameWritePermit(left, right ha.WritePermit) bool {
	if left.ResourceID != right.ResourceID || left.NodeID != right.NodeID || left.LeaseID != right.LeaseID || left.FencingToken != right.FencingToken || left.AuthorityEpoch != right.AuthorityEpoch || !left.IssuedAt.Equal(right.IssuedAt) || !left.ExpiresAt.Equal(right.ExpiresAt) || left.Signature != right.Signature || len(left.WritePaths) != len(right.WritePaths) {
		return false
	}
	for index := range left.WritePaths { if left.WritePaths[index] != right.WritePaths[index] { return false } }
	return true
}

func validateBrokerEffectResponse(request BrokerRequest, response BrokerResponse) error {
	if response.Effect == nil || response.Compensation != nil || request.Effect == nil || !effectReceiptMatches(*request.Effect, *response.Effect) {
		return ErrInvalidReceipt
	}
	return nil
}

func validateBrokerCompensationResponse(request BrokerRequest, response BrokerResponse) error {
	if response.Effect != nil || response.Compensation == nil || request.Compensation == nil || !compensationReceiptMatches(*request.Compensation, *response.Compensation) {
		return ErrInvalidReceipt
	}
	return nil
}

func validCompensationRequest(request CompensationRequest) bool {
	return request.EffectID != "" && validSHA256(request.RequestDigest) && !request.Scope.ID.IsZero() && !request.CompensationToken.IsZero() && request.FailureCode != ""
}

func validBrokerRequestID(value string) bool {
	if len(value) != 36 || value[:4] != "req-" { return false }
	_, err := hex.DecodeString(value[4:])
	return err == nil
}

func validBrokerFailure(value string) bool {
	switch value {
	case "invalid_request", "unauthorized", "not_found", "conflict", "deadline", "unavailable", "internal", "ambiguous", "transfer_limit":
		return true
	default:
		return false
	}
}

type DatabaseBrokerTransport interface {
	RoundTrip(context.Context, BrokerRequest) (BrokerResponse, error)
}

type BrokerClient struct {
	ReplicationEpoch func(context.Context,ha.ChannelID)(uint64,error)
	transport DatabaseBrokerTransport
	now       func() time.Time
}

var _ MariaDBExecutor = (*BrokerClient)(nil)
var _ ha.DatabaseReplicationExecutor = (*BrokerClient)(nil)
var _ ha.WritePermitSigner = (*BrokerClient)(nil)

func NewBrokerClient(transport DatabaseBrokerTransport) (*BrokerClient, error) {
	if transport == nil { return nil, ErrInvalidCommand }
	return &BrokerClient{transport: transport, now: time.Now}, nil
}

func (client *BrokerClient) ObserveOrApply(ctx context.Context, effect EffectRequest) (EffectReceipt, error) {
	request, err := client.request(ctx, BrokerObserveOrApply)
	if err != nil { return EffectReceipt{}, err }
	request.Effect = &effect
	if err = request.validate(client.now().UTC()); err != nil { return EffectReceipt{}, err }
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil { return EffectReceipt{}, err }
	if err = response.validate(request); err != nil { return EffectReceipt{}, err }
	if response.FailureCode != "" { return EffectReceipt{}, brokerFailure(response.FailureCode) }
	return *response.Effect, nil
}

func (client *BrokerClient) Compensate(ctx context.Context, compensation CompensationRequest) (CompensationReceipt, error) {
	request, err := client.request(ctx, BrokerCompensate)
	if err != nil { return CompensationReceipt{}, err }
	request.Compensation = &compensation
	if err = request.validate(client.now().UTC()); err != nil { return CompensationReceipt{}, err }
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil { return CompensationReceipt{}, err }
	if err = response.validate(request); err != nil { return CompensationReceipt{}, err }
	if response.FailureCode != "" { return CompensationReceipt{}, brokerFailure(response.FailureCode) }
	return *response.Compensation, nil
}

func (client *BrokerClient) Status(ctx context.Context, instanceID ResourceID) (MariaDBInstanceStatus, error) {
	if instanceID.IsZero() {
		return MariaDBInstanceStatus{}, ErrInvalidCommand
	}
	request, err := client.request(ctx, BrokerInstanceStatus)
	if err != nil {
		return MariaDBInstanceStatus{}, err
	}
	request.InstanceID = instanceID
	if err = request.validate(client.now().UTC()); err != nil {
		return MariaDBInstanceStatus{}, err
	}
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil {
		return MariaDBInstanceStatus{}, err
	}
	if err = response.validate(request); err != nil {
		return MariaDBInstanceStatus{}, err
	}
	if response.FailureCode != "" {
		return MariaDBInstanceStatus{}, brokerFailure(response.FailureCode)
	}
	return *response.InstanceStatus, nil
}

func (client *BrokerClient) BrowseWorkspaceMetadata(ctx context.Context, access WorkspaceAccess) (WorkspaceMetadataResult, error) {
	if client == nil || client.transport == nil || ctx == nil || access.validate(client.now().UTC()) != nil {
		return WorkspaceMetadataResult{}, ErrInvalidCommand
	}
	bounded, cancel := workspaceContext(ctx, access, client.now().UTC())
	defer cancel()
	request, err := client.requestWithMaximum(bounded, BrokerWorkspaceMetadata, 2*time.Minute)
	if err != nil { return WorkspaceMetadataResult{}, err }
	request.Workspace = &WorkspaceBrokerRequest{Access: access}
	if err = request.validate(client.now().UTC()); err != nil { return WorkspaceMetadataResult{}, err }
	response, err := client.transport.RoundTrip(bounded, request)
	if err != nil { return WorkspaceMetadataResult{}, err }
	if err = response.validate(request); err != nil { return WorkspaceMetadataResult{}, err }
	if response.FailureCode != "" { return WorkspaceMetadataResult{}, brokerFailure(response.FailureCode) }
	return *response.Metadata, nil
}

func (client *BrokerClient) ExecuteWorkspaceStatement(ctx context.Context, access WorkspaceAccess, statement string) (WorkspaceQueryResult, error) {
	if client == nil || client.transport == nil || ctx == nil || access.validate(client.now().UTC()) != nil {
		return WorkspaceQueryResult{}, ErrInvalidCommand
	}
	normalized, _, err := ParseWorkspaceStatement(statement)
	if err != nil || normalized != statement { return WorkspaceQueryResult{}, ErrInvalidCommand }
	bounded, cancel := workspaceContext(ctx, access, client.now().UTC())
	defer cancel()
	request, err := client.requestWithMaximum(bounded, BrokerWorkspaceQuery, 2*time.Minute)
	if err != nil { return WorkspaceQueryResult{}, err }
	request.Workspace = &WorkspaceBrokerRequest{Access: access, Statement: statement}
	if err = request.validate(client.now().UTC()); err != nil { return WorkspaceQueryResult{}, err }
	response, err := client.transport.RoundTrip(bounded, request)
	if err != nil { return WorkspaceQueryResult{}, err }
	if err = response.validate(request); err != nil { return WorkspaceQueryResult{}, err }
	if response.FailureCode != "" { return WorkspaceQueryResult{}, brokerFailure(response.FailureCode) }
	return *response.Query, nil
}

func (client *BrokerClient) ObserveCluster(ctx context.Context, cluster ha.DatabaseCluster) (ha.DatabaseCluster, error) {
	result, err := client.mariaDBHA(ctx, MariaDBHARequest{Action:MariaDBHAObserve, Cluster:cluster})
	if err != nil { return ha.DatabaseCluster{}, err }
	return *result.Cluster, nil
}

func (client *BrokerClient) FreezeDatabaseWrites(ctx context.Context, cluster ha.DatabaseCluster, node ha.NodeID, fencingToken uint64) (string, error) {
	result, err := client.mariaDBHA(ctx, MariaDBHARequest{Action:MariaDBHAFreeze, Cluster:cluster, NodeID:node, FencingToken:fencingToken})
	if err != nil { return "", err }
	return result.Receipt, nil
}

func (client *BrokerClient) PromoteDatabaseWriter(ctx context.Context, cluster ha.DatabaseCluster, node ha.NodeID, lease ha.WriterLease) (string, uint64, error) {
	result, err := client.mariaDBHA(ctx, MariaDBHARequest{Action:MariaDBHAPromote, Cluster:cluster, NodeID:node, FencingToken:lease.FencingToken, Lease:&lease})
	if err != nil { return "", 0, err }
	return result.Receipt, result.Frontier, nil
}

func (client *BrokerClient) DemoteDatabaseWriter(ctx context.Context, cluster ha.DatabaseCluster, node ha.NodeID, fencingToken uint64) (string, error) {
	result, err := client.mariaDBHA(ctx, MariaDBHARequest{Action:MariaDBHADemote, Cluster:cluster, NodeID:node, FencingToken:fencingToken})
	if err != nil { return "", err }
	return result.Receipt, nil
}

func (client *BrokerClient) SignWritePermit(ctx context.Context, permit ha.WritePermit) (ha.WritePermit, error) {
	result, err := client.mariaDBHA(ctx, MariaDBHARequest{Action:MariaDBHASignPermit, Permit:&permit})
	if err != nil { return ha.WritePermit{}, err }
	return *result.Permit, nil
}

func (client *BrokerClient) CreateDatabaseCheckpoint(ctx context.Context, channel ha.ReplicationChannel, generation uint64) (ha.ReplicationCheckpoint, error) {
	result,err:=client.mariaDBHA(ctx,MariaDBHARequest{Action:MariaDBHACheckpoint,Channel:&channel,SourceGeneration:generation})
	if err!=nil{return ha.ReplicationCheckpoint{},err};return *result.Checkpoint,nil
}

func (client *BrokerClient) CatchUpReplica(ctx context.Context, channel ha.ReplicationChannel, checkpoint ha.ReplicationCheckpoint) (ha.ReplicationReceipt, error) {
	result,err:=client.mariaDBHA(ctx,MariaDBHARequest{Action:MariaDBHACatchUp,Channel:&channel,Checkpoint:&checkpoint})
	if err!=nil{return ha.ReplicationReceipt{},err};return *result.Replication,nil
}

func (client *BrokerClient) RejoinDatabaseMember(ctx context.Context, cluster ha.DatabaseCluster, node ha.NodeID, checkpoint ha.ReplicationCheckpoint) (string, error) {
	result,err:=client.mariaDBHA(ctx,MariaDBHARequest{Action:MariaDBHARejoin,Cluster:cluster,NodeID:node,Checkpoint:&checkpoint})
	if err!=nil{return "",err};return result.Receipt,nil
}

func (client *BrokerClient) mariaDBHA(ctx context.Context, value MariaDBHARequest) (MariaDBHAResult, error) {
	if value.Action==MariaDBHACheckpoint||value.Action==MariaDBHACatchUp||value.Action==MariaDBHARejoin{
		if client==nil||client.ReplicationEpoch==nil{return MariaDBHAResult{},ErrUnauthorized}
		var channel ha.ChannelID;if value.Channel!=nil{channel=value.Channel.ID}else if value.Checkpoint!=nil{channel=value.Checkpoint.ChannelID}
		epoch,epochErr:=client.ReplicationEpoch(ctx,channel);if epochErr!=nil||epoch==0{return MariaDBHAResult{},ErrUnauthorized};value.AuthorityEpoch=epoch
	}
	maximum:=30*time.Second;if value.AuthorityEpoch!=0{maximum=2*time.Minute}
	request, err := client.requestWithMaximum(ctx, BrokerMariaDBHA,maximum)
	if err != nil { return MariaDBHAResult{}, err }
	request.MariaDBHA = &value
	if err = request.validate(client.now().UTC()); err != nil { return MariaDBHAResult{}, err }
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil { return MariaDBHAResult{}, err }
	if err = response.validate(request); err != nil { return MariaDBHAResult{}, err }
	if response.FailureCode != "" { return MariaDBHAResult{}, brokerFailure(response.FailureCode) }
	return *response.MariaDBHA, nil
}

func (client *BrokerClient) request(ctx context.Context, operation BrokerOperation) (BrokerRequest, error) {
	return client.requestWithMaximum(ctx, operation, 30*time.Second)
}

func (client *BrokerClient) requestWithMaximum(ctx context.Context, operation BrokerOperation, maximum time.Duration) (BrokerRequest, error) {
	if client == nil || client.transport == nil || ctx == nil { return BrokerRequest{}, ErrInvalidCommand }
	identifier := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, identifier); err != nil { return BrokerRequest{}, err }
	now := client.now().UTC()
	deadline := now.Add(maximum)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) { deadline = value.UTC() }
	return BrokerRequest{Version: DatabaseBrokerProtocolVersion, RequestID: "req-" + hex.EncodeToString(identifier), Operation: operation, Deadline: deadline}, nil
}

type DatabaseBrokerDialer interface {
	DialContext(context.Context) (net.Conn, error)
}

type FramedDatabaseBrokerTransport struct{ Dialer DatabaseBrokerDialer }

func (transport FramedDatabaseBrokerTransport) RoundTrip(ctx context.Context, request BrokerRequest) (BrokerResponse, error) {
	if transport.Dialer == nil { return BrokerResponse{}, ErrInvalidCommand }
	connection, err := transport.Dialer.DialContext(ctx)
	if err != nil { return BrokerResponse{}, err }
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	deadline := request.Deadline
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) { deadline = value }
	if err = connection.SetDeadline(deadline); err != nil { return BrokerResponse{}, err }
	if err = writeDatabaseBrokerFrame(connection, request); err != nil { return BrokerResponse{}, err }
	var response BrokerResponse
	if err = readDatabaseBrokerFrameLimit(connection, &response, databaseBrokerMaximumResponseFrame); err != nil { return BrokerResponse{}, err }
	return response, nil
}

type DatabaseBrokerAuthorizer interface{ Authorize(net.Conn) error }

type DatabaseBrokerServer struct {
	Authorizer        DatabaseBrokerAuthorizer
	Executor          MariaDBExecutor
	Admission         rebootcontrol.ExecutionAdmission
	MaximumConcurrent uint32
	Now               func() time.Time
	once              sync.Once
	semaphore         chan struct{}
}

func (server *DatabaseBrokerServer) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.Authorizer == nil || server.Executor == nil { return ErrInvalidCommand }
	server.once.Do(func() {
		maximum := server.MaximumConcurrent
		if maximum == 0 { maximum = 64 }
		if maximum > 1024 { maximum = 1024 }
		server.semaphore = make(chan struct{}, maximum)
	})
	for {
		connection, err := listener.Accept()
		if err != nil { return err }
		select {
		case server.semaphore <- struct{}{}:
			go func() { defer func() { <-server.semaphore; _ = connection.Close() }(); server.serve(connection) }()
		default:
			_ = connection.Close()
		}
	}
}

func (server *DatabaseBrokerServer) serve(connection net.Conn) {
	if server.Authorizer.Authorize(connection) != nil { return }
	now := time.Now().UTC()
	if server.Now != nil { now = server.Now().UTC() }
	_ = connection.SetReadDeadline(now.Add(15 * time.Second))
	var request BrokerRequest
	if readDatabaseBrokerFrame(connection, &request) != nil || request.validate(now) != nil {
		_ = writeDatabaseBrokerFrame(connection, BrokerResponse{Version: DatabaseBrokerProtocolVersion, RequestID: request.RequestID, Operation: request.Operation, FailureCode: "invalid_request"})
		return
	}
	_ = connection.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
	defer cancel()
	go func() {
		var probe [1]byte
		_, _ = connection.Read(probe[:])
		cancel()
	}()
	// Metadata and fixed SHOW/DESCRIBE grammar cannot carry an effect payload.
	// SELECT/EXPLAIN remain conservatively gated: expressions may invoke stored
	// functions, so a leading SELECT alone is not a read-only guarantee.
	mutation:=request.Operation!=BrokerWorkspaceMetadata && request.Operation!=BrokerInstanceStatus && request.Operation!=BrokerWorkspaceExportRead
	if request.Operation==BrokerWorkspaceQuery {
		_,kind,_:=ParseWorkspaceStatement(request.Workspace.Statement)
		mutation=kind!=WorkspaceStatementShow && kind!=WorkspaceStatementDescribe
	}
	if request.Operation==BrokerMigrationRestore && request.MigrationRestore.Action=="observe" { mutation=false }
	if request.Operation==BrokerMariaDBHA && request.MariaDBHA.Action==MariaDBHAObserve { mutation=false }
	var lease rebootcontrol.ExecutionLease
	if mutation {
		if server.Admission==nil{return}
		binding:=rebootcontrol.ExecutionBinding{Boundary:"database",Method:string(request.Operation),Caller:"authenticated-panel-core"}
		switch request.Operation {
		case BrokerWorkspaceExport:
			binding.RequestDigest=rebootcontrol.ExecutionDigest(request.WorkspaceExport);binding.EffectID="workspace-export:"+binding.RequestDigest;binding.Resource=rebootcontrol.ExecutionResource(request.WorkspaceExport.Access)
		case BrokerObserveOrApply:
			binding.EffectID=request.Effect.EffectID;binding.RequestDigest=rebootcontrol.ExecutionDigest(request.Effect);binding.Resource=rebootcontrol.ExecutionResource(request.Effect.Scope)
		case BrokerCompensate:
			binding.EffectID=request.Compensation.EffectID;binding.RequestDigest=rebootcontrol.ExecutionDigest(request.Compensation);binding.Resource=rebootcontrol.ExecutionResource(request.Compensation.Scope)
		case BrokerWorkspaceQuery:
			binding.EffectID=request.RequestID;binding.RequestDigest=rebootcontrol.ExecutionDigest(request.Workspace);binding.Resource=rebootcontrol.ExecutionResource(request.Workspace.Access)
		case BrokerMigrationRestore:
			restore:=request.MigrationRestore
			binding.EffectID="migration-restore:"+restore.ID.String()+":"+restore.Action+":"+fmt.Sprint(restore.Offset)
			binding.RequestDigest=rebootcontrol.ExecutionDigest(restore)
			binding.Resource=rebootcontrol.ExecutionResource(struct{Tenant,Site,Database,Principal,Restore string}{restore.TenantID.String(),restore.SiteID.String(),restore.DatabaseID.String(),restore.PrincipalID.String(),restore.ID.String()})
		case BrokerMariaDBHA:
			haRequest:=request.MariaDBHA
			binding.RequestDigest=rebootcontrol.ExecutionDigest(haRequest)
			binding.EffectID="mariadb-ha:"+binding.RequestDigest
			channel,checkpoint,leaseID:="","",""
			if haRequest.Channel!=nil{channel=string(haRequest.Channel.ID)}
			if haRequest.Checkpoint!=nil{checkpoint=string(haRequest.Checkpoint.ID)}
			if haRequest.Lease!=nil{leaseID=string(haRequest.Lease.ID)}
			binding.Resource=rebootcontrol.ExecutionResource(struct{Action MariaDBHAAction;Cluster string;Node ha.NodeID;Channel,Checkpoint,Lease string;Fence,Epoch uint64}{haRequest.Action,string(haRequest.Cluster.ID),haRequest.NodeID,channel,checkpoint,leaseID,haRequest.FencingToken,haRequest.AuthorityEpoch})
		}
		var admissionErr error;lease,admissionErr=server.Admission.AdmitExecution(ctx,binding);if admissionErr!=nil{return}
		if len(lease.Cached)!=0 {
			var cached BrokerResponse
			if json.Unmarshal(lease.Cached,&cached)==nil { cached.RequestID=request.RequestID;if cached.validate(request)==nil{_=writeDatabaseBrokerFrameLimit(connection,cached,databaseBrokerMaximumResponseFrame)} };return
		}
		defer func(){_=rebootcontrol.SettleExecution(server.Admission,lease,false,nil)}()
	}
	response := BrokerResponse{Version: DatabaseBrokerProtocolVersion, RequestID: request.RequestID, Operation: request.Operation}
	var err error
	switch request.Operation {
	case BrokerWorkspaceExportRead:
		reader,ok:=server.Executor.(WorkspaceExportReader)
		if !ok{err=ErrInvalidCommand;break}
		var chunk WorkspaceExportChunk
		chunk,err=reader.ReadWorkspaceExport(ctx,*request.WorkspaceExportRead)
		if err==nil && chunk.matches(*request.WorkspaceExportRead){response.ExportChunk=&chunk}
	case BrokerWorkspaceExport:
		exporter,ok:=server.Executor.(WorkspaceExportExecutor)
		if !ok{err=ErrInvalidCommand;break}
		var receipt TransferProcessReceipt
		receipt,err=exporter.ExportWorkspaceDatabase(ctx,*request.WorkspaceExport)
		if err==nil && request.WorkspaceExport.matches(receipt){response.Export=&receipt}
	case BrokerObserveOrApply:
		var receipt EffectReceipt
		receipt, err = server.Executor.ObserveOrApply(ctx, *request.Effect)
		if effectReceiptMatches(*request.Effect, receipt) { response.Effect = &receipt }
	case BrokerMigrationRestore:
		restore, ok := server.Executor.(MigrationRestoreExecutor)
		if !ok { err=ErrInvalidCommand; break }
		var receipt MigrationRestoreReceipt
		receipt,err=restore.RestoreMigrationDatabase(ctx,*request.MigrationRestore)
		if err==nil && receipt.matches(*request.MigrationRestore) { response.MigrationRestore=&receipt }
	case BrokerCompensate:
		var receipt CompensationReceipt
		receipt, err = server.Executor.Compensate(ctx, *request.Compensation)
		if compensationReceiptMatches(*request.Compensation, receipt) { response.Compensation = &receipt }
	case BrokerInstanceStatus:
		observer, ok := server.Executor.(interface {
			Status(context.Context, ResourceID) (MariaDBInstanceStatus, error)
		})
		if !ok {
			err = ErrInvalidCommand
			break
		}
		var status MariaDBInstanceStatus
		status, err = observer.Status(ctx, request.InstanceID)
		if err == nil && status.validate(request.InstanceID) == nil {
			response.InstanceStatus = &status
		}
	case BrokerWorkspaceMetadata:
		workspace, ok := server.Executor.(WorkspaceExecutor)
		if !ok { err = ErrInvalidCommand; break }
		var result WorkspaceMetadataResult
		result, err = workspace.BrowseWorkspaceMetadata(ctx, request.Workspace.Access)
		if err == nil && validateWorkspaceMetadata(result, request.Workspace.Access) == nil { response.Metadata = &result }
	case BrokerWorkspaceQuery:
		workspace, ok := server.Executor.(WorkspaceExecutor)
		if !ok { err = ErrInvalidCommand; break }
		var result WorkspaceQueryResult
		result, err = workspace.ExecuteWorkspaceStatement(ctx, request.Workspace.Access, request.Workspace.Statement)
		if err == nil && validateWorkspaceResult(result, request.Workspace.Access) == nil { response.Query = &result }
	case BrokerMariaDBHA:
		result := MariaDBHAResult{}
		if request.MariaDBHA.AuthorityEpoch!=0{ctx=context.WithValue(ctx,replicationEpochContextKey{},request.MariaDBHA.AuthorityEpoch)}
		executor, ok := server.Executor.(ha.DatabaseReplicationExecutor)
		if !ok { err = ErrInvalidCommand; break }
		switch request.MariaDBHA.Action {
		case MariaDBHAWriterCertificate:
			issuer,issuerOK:=server.Executor.(interface{IssueDatabaseWriterCertificate(context.Context,json.RawMessage)(DatabaseWriterCertificate,error)})
			if !issuerOK{err=ErrUnauthorized;break}
			var certificate DatabaseWriterCertificate
			certificate,err=issuer.IssueDatabaseWriterCertificate(ctx,request.MariaDBHA.WriterAuthority)
			if err==nil{result.WriterCertificate=&certificate}
		case MariaDBHAWriterFenceEvidence:
			observer,observerOK:=server.Executor.(interface{ObserveDatabaseWriterFence(context.Context,json.RawMessage)(DatabaseWriterFenceEvidence,error)})
			if !observerOK{err=ErrUnauthorized;break}
			var evidence DatabaseWriterFenceEvidence
			evidence,err=observer.ObserveDatabaseWriterFence(ctx,request.MariaDBHA.WriterAuthority)
			if err==nil{result.WriterFenceEvidence=&evidence}
		case MariaDBHAWriterCandidateEvidence:
			observer,observerOK:=server.Executor.(interface{ObserveDatabaseWriterCandidate(context.Context,json.RawMessage)(DatabaseWriterFenceEvidence,error)})
			if !observerOK{err=ErrUnauthorized;break}
			var evidence DatabaseWriterFenceEvidence
			evidence,err=observer.ObserveDatabaseWriterCandidate(ctx,request.MariaDBHA.WriterAuthority)
			if err==nil{result.WriterFenceEvidence=&evidence}
		case MariaDBHACheckpoint:
			var checkpoint ha.ReplicationCheckpoint
			checkpoint,err=executor.CreateDatabaseCheckpoint(ctx,*request.MariaDBHA.Channel,request.MariaDBHA.SourceGeneration)
			if err==nil{result.Checkpoint=&checkpoint}
		case MariaDBHACatchUp:
			var receipt ha.ReplicationReceipt
			receipt,err=executor.CatchUpReplica(ctx,*request.MariaDBHA.Channel,*request.MariaDBHA.Checkpoint)
			if err==nil{result.Replication=&receipt}
		case MariaDBHARejoin:
			result.Receipt,err=executor.RejoinDatabaseMember(ctx,request.MariaDBHA.Cluster,request.MariaDBHA.NodeID,*request.MariaDBHA.Checkpoint)
		case MariaDBHAObserve:
			var cluster ha.DatabaseCluster
			cluster, err = executor.ObserveCluster(ctx, request.MariaDBHA.Cluster)
			if err == nil { result.Cluster = &cluster }
		case MariaDBHAFreeze:
			result.Receipt, err = executor.FreezeDatabaseWrites(ctx, request.MariaDBHA.Cluster, request.MariaDBHA.NodeID, request.MariaDBHA.FencingToken)
		case MariaDBHAPromote:
			result.Receipt, result.Frontier, err = executor.PromoteDatabaseWriter(ctx, request.MariaDBHA.Cluster, request.MariaDBHA.NodeID, *request.MariaDBHA.Lease)
		case MariaDBHADemote:
			result.Receipt, err = executor.DemoteDatabaseWriter(ctx, request.MariaDBHA.Cluster, request.MariaDBHA.NodeID, request.MariaDBHA.FencingToken)
		case MariaDBHASignPermit:
			signer, signerOK := server.Executor.(ha.WritePermitSigner)
			if !signerOK { err = ErrInvalidCommand; break }
			var permit ha.WritePermit
			permit, err = signer.SignWritePermit(ctx, *request.MariaDBHA.Permit)
			if err == nil { result.Permit = &permit }
		default:
			err = ErrInvalidCommand
		}
		if err == nil && validateMariaDBHAResult(*request.MariaDBHA, result) == nil { response.MariaDBHA = &result }
	}
	if response.Effect == nil && response.Compensation == nil && response.Metadata == nil && response.Query == nil && response.InstanceStatus == nil && response.MariaDBHA == nil && response.MigrationRestore == nil && response.Export==nil && response.ExportChunk==nil {
		response.FailureCode = classifyBrokerFailure(err)
	}
	if response.validate(request)!=nil{return}
	if mutation {
		terminal:=err==nil && response.Query!=nil
		if response.Export!=nil{terminal=err==nil}
		if response.Effect!=nil{terminal=response.Effect.Outcome==EffectConfirmed || response.Effect.Outcome==EffectRejected && !response.Effect.MutationObserved}
		if response.Compensation!=nil{terminal=response.Compensation.Outcome==EffectConfirmed}
		if response.MigrationRestore!=nil || response.MariaDBHA!=nil { terminal=err==nil }
		if rebootcontrol.SettleExecution(server.Admission,lease,terminal,response)!=nil{return}
	}
	_ = writeDatabaseBrokerFrameLimit(connection, response, databaseBrokerMaximumResponseFrame)
}

func writeDatabaseBrokerFrame(writer io.Writer, value any) error {
	return writeDatabaseBrokerFrameLimit(writer, value, DatabaseBrokerMaximumFrame)
}

func writeDatabaseBrokerFrameLimit(writer io.Writer, value any, maximum int) error {
	content, err := json.Marshal(value)
	if err != nil || len(content) == 0 || len(content) > maximum { return ErrInvalidCommand }
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(content)))
	if err = writeDatabaseBrokerBytes(writer, header[:]); err != nil { return err }
	return writeDatabaseBrokerBytes(writer, content)
}

func writeDatabaseBrokerBytes(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil { return err }
		if written <= 0 || written > len(content) { return io.ErrShortWrite }
		content = content[written:]
	}
	return nil
}

func readDatabaseBrokerFrame(reader io.Reader, target any) error {
	return readDatabaseBrokerFrameLimit(reader, target, DatabaseBrokerMaximumFrame)
}

func readDatabaseBrokerFrameLimit(reader io.Reader, target any, maximum uint32) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil { return err }
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maximum { return ErrInvalidCommand }
	content := make([]byte, size)
	if _, err := io.ReadFull(reader, content); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return ErrInvalidCommand }
	if decoder.Decode(&struct{}{}) != io.EOF { return ErrInvalidCommand }
	return nil
}

func classifyBrokerFailure(err error) string {
	switch {
	case errors.Is(err, ErrTransferLimit): return "transfer_limit"
	case errors.Is(err, ErrTransferCancelled): return "deadline"
	case errors.Is(err, ErrTransferStale): return "conflict"
	case errors.Is(err, ErrTransferInvalid), errors.Is(err, ErrTransferUnsafeSQL): return "invalid_request"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled): return "deadline"
	case errors.Is(err, ErrUnauthorized): return "unauthorized"
	case errors.Is(err, ErrNotFound): return "not_found"
	case errors.Is(err, ErrConflict), errors.Is(err, ErrIdempotency): return "conflict"
	case errors.Is(err, ErrInvalidCommand), errors.Is(err, ErrInvalidResource): return "invalid_request"
	case errors.Is(err, ErrAmbiguous): return "ambiguous"
	case errors.Is(err, ErrUnavailable): return "unavailable"
	case err == nil: return "internal"
	default: return "internal"
	}
}

func brokerFailure(code string) error {
	switch code {
	case "transfer_limit": return ErrTransferLimit
	case "invalid_request": return ErrInvalidCommand
	case "unauthorized": return ErrUnauthorized
	case "not_found": return ErrNotFound
	case "conflict": return ErrConflict
	case "deadline": return context.DeadlineExceeded
	case "ambiguous": return ErrAmbiguous
	case "unavailable": return ErrUnavailable
	case "internal": return errors.New("database broker unavailable")
	default: return ErrInvalidReceipt
	}
}

var _ WorkspaceExecutor = (*BrokerClient)(nil)
