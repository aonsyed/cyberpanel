package database

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
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
	BrokerMariaDBHA         BrokerOperation = "mariadb_ha"
)

type MariaDBHAAction string

const (
	MariaDBHAObserve    MariaDBHAAction = "observe"
	MariaDBHAFreeze     MariaDBHAAction = "freeze"
	MariaDBHAPromote    MariaDBHAAction = "promote"
	MariaDBHADemote     MariaDBHAAction = "demote"
	MariaDBHASignPermit MariaDBHAAction = "sign_permit"
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
}

type MariaDBHAResult struct {
	Cluster  *ha.DatabaseCluster `json:"cluster,omitempty"`
	Receipt  string              `json:"receipt,omitempty"`
	Frontier uint64              `json:"frontier,omitempty"`
	Permit   *ha.WritePermit     `json:"permit,omitempty"`
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
	MariaDBHA    *MariaDBHARequest    `json:"mariadb_ha,omitempty"`
}

type BrokerResponse struct {
	Version      uint32                `json:"version"`
	RequestID    string                `json:"request_id"`
	Operation    BrokerOperation       `json:"operation"`
	Effect       *EffectReceipt        `json:"effect,omitempty"`
	Compensation *CompensationReceipt  `json:"compensation,omitempty"`
	Metadata     *WorkspaceMetadataResult `json:"metadata,omitempty"`
	Query        *WorkspaceQueryResult `json:"query,omitempty"`
	MariaDBHA    *MariaDBHAResult      `json:"mariadb_ha,omitempty"`
	FailureCode  string                `json:"failure_code,omitempty"`
}

func (request BrokerRequest) validate(now time.Time) error {
	if request.Version != DatabaseBrokerProtocolVersion || !validBrokerRequestID(request.RequestID) || request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.After(now.Add(2*time.Minute)) {
		return ErrInvalidCommand
	}
	switch request.Operation {
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
	if response.Version != DatabaseBrokerProtocolVersion || response.RequestID != request.RequestID || response.Operation != request.Operation {
		return ErrInvalidReceipt
	}
	if response.FailureCode != "" {
		if response.Effect != nil || response.Compensation != nil || response.Metadata != nil || response.Query != nil || response.MariaDBHA != nil || !validBrokerFailure(response.FailureCode) {
			return ErrInvalidReceipt
		}
		return nil
	}
	switch request.Operation {
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
	const localResource = ha.ID("mariadb-local")
	const localNode = ha.NodeID("local")
	if request.Action == MariaDBHASignPermit {
		if request.Cluster.ID != "" || request.Cluster.GroupID != "" || request.Cluster.Topology != "" || len(request.Cluster.Members) != 0 || request.Cluster.Generation != 0 || request.NodeID != "" || request.FencingToken != 0 || request.Lease != nil || request.Permit == nil {
			return ErrInvalidCommand
		}
		permit := *request.Permit
		if permit.ResourceID != string(localResource) || permit.NodeID != localNode || permit.LeaseID == "" || permit.FencingToken == 0 || permit.AuthorityEpoch == 0 || len(permit.WritePaths) == 0 || permit.Signature != "" || permit.IssuedAt.IsZero() || !permit.ExpiresAt.After(permit.IssuedAt) || !now.Before(permit.ExpiresAt) {
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
		if request.NodeID != localNode || request.FencingToken == 0 || request.Lease == nil { return ErrInvalidCommand }
		lease := *request.Lease
		if lease.Validate(now) != nil || lease.State != ha.LeaseActive || lease.ResourceID != string(localResource) || lease.HolderNodeID != localNode || lease.FencingToken != request.FencingToken || lease.GroupID != request.Cluster.GroupID {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

func validateMariaDBHAResult(request MariaDBHARequest, result MariaDBHAResult) error {
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
	case "invalid_request", "unauthorized", "not_found", "conflict", "deadline", "unavailable", "internal", "ambiguous":
		return true
	default:
		return false
	}
}

type DatabaseBrokerTransport interface {
	RoundTrip(context.Context, BrokerRequest) (BrokerResponse, error)
}

type BrokerClient struct {
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

func (*BrokerClient) CreateDatabaseCheckpoint(context.Context, ha.ReplicationChannel, uint64) (ha.ReplicationCheckpoint, error) {
	return ha.ReplicationCheckpoint{}, ha.ErrUnsupported
}

func (*BrokerClient) CatchUpReplica(context.Context, ha.ReplicationChannel, ha.ReplicationCheckpoint) (ha.ReplicationReceipt, error) {
	return ha.ReplicationReceipt{}, ha.ErrUnsupported
}

func (*BrokerClient) RejoinDatabaseMember(context.Context, ha.DatabaseCluster, ha.NodeID, ha.ReplicationCheckpoint) (string, error) {
	return "", ha.ErrUnsupported
}

func (client *BrokerClient) mariaDBHA(ctx context.Context, value MariaDBHARequest) (MariaDBHAResult, error) {
	request, err := client.request(ctx, BrokerMariaDBHA)
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
	response := BrokerResponse{Version: DatabaseBrokerProtocolVersion, RequestID: request.RequestID, Operation: request.Operation}
	var err error
	switch request.Operation {
	case BrokerObserveOrApply:
		var receipt EffectReceipt
		receipt, err = server.Executor.ObserveOrApply(ctx, *request.Effect)
		if effectReceiptMatches(*request.Effect, receipt) { response.Effect = &receipt }
	case BrokerCompensate:
		var receipt CompensationReceipt
		receipt, err = server.Executor.Compensate(ctx, *request.Compensation)
		if compensationReceiptMatches(*request.Compensation, receipt) { response.Compensation = &receipt }
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
		executor, ok := server.Executor.(ha.DatabaseReplicationExecutor)
		if !ok { err = ErrInvalidCommand; break }
		switch request.MariaDBHA.Action {
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
	if response.Effect == nil && response.Compensation == nil && response.Metadata == nil && response.Query == nil && response.MariaDBHA == nil {
		response.FailureCode = classifyBrokerFailure(err)
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
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled): return "deadline"
	case errors.Is(err, ErrUnauthorized): return "unauthorized"
	case errors.Is(err, ErrNotFound): return "not_found"
	case errors.Is(err, ErrConflict), errors.Is(err, ErrIdempotency): return "conflict"
	case errors.Is(err, ErrInvalidCommand), errors.Is(err, ErrInvalidResource): return "invalid_request"
	case errors.Is(err, ErrAmbiguous): return "ambiguous"
	case err == nil: return "internal"
	default: return "internal"
	}
}

func brokerFailure(code string) error {
	switch code {
	case "invalid_request": return ErrInvalidCommand
	case "unauthorized": return ErrUnauthorized
	case "not_found": return ErrNotFound
	case "conflict": return ErrConflict
	case "deadline": return context.DeadlineExceeded
	case "ambiguous": return ErrAmbiguous
	case "unavailable", "internal": return errors.New("database broker unavailable")
	default: return ErrInvalidReceipt
	}
}

var _ WorkspaceExecutor = (*BrokerClient)(nil)
