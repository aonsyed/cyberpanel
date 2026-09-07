package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

const centralFederationProtocolVersion uint32 = 1

type Authorizer interface {
	Authorize(context.Context, Operator, string, federation.ID, string, string) error
}

type IntentSigner interface {
	IntentKeyID(context.Context) (string, error)
	SignIntent(context.Context, string, []byte) ([]byte, error)
	RevocationKeyID(context.Context) (string, error)
	SignRevocation(context.Context, string, []byte) ([]byte, error)
}

type ReceiptVerifier interface {
	VerifyNodeReceipt(context.Context, federation.ID, string, []byte, []byte) error
}

type EventVerifier interface {
	VerifyNodeEvent(context.Context, federation.ID, string, []byte, []byte) error
}

type NodeEvidenceVerifier interface {
	ReceiptVerifier
	EventVerifier
}

type IDGenerator interface {
	New(context.Context, string) (federation.ID, error)
}

type Audit interface {
	Record(context.Context, string, Operator, federation.ID, string, string, string) error
}

type Service struct {
	store           *Store
	authorizer      Authorizer
	signer          IntentSigner
	receiptVerifier ReceiptVerifier
	eventVerifier   EventVerifier
	ids             IDGenerator
	audit           Audit
	peerID          federation.ID
	clock           func() time.Time
}

func NewService(store *Store, authorizer Authorizer, signer IntentSigner, ids IDGenerator, audit Audit, peerID federation.ID) (*Service, error) {
	if store == nil || authorizer == nil || signer == nil || ids == nil || audit == nil || !peerID.Valid() {
		return nil, ErrInvalid
	}
	return &Service{store: store, authorizer: authorizer, signer: signer, ids: ids, audit: audit, peerID: peerID, clock: time.Now}, nil
}

func (s *Service) WithReceiptVerifier(verifier ReceiptVerifier) *Service {
	if s != nil {
		s.receiptVerifier = verifier
	}
	return s
}

func (s *Service) WithEventVerifier(verifier EventVerifier) *Service {
	if s != nil {
		s.eventVerifier = verifier
	}
	return s
}

func (s *Service) WithEvidenceVerifier(verifier NodeEvidenceVerifier) *Service {
	if s != nil {
		s.receiptVerifier = verifier
		s.eventVerifier = verifier
	}
	return s
}

func (s *Service) CreateIntent(ctx context.Context, operator Operator, request IntentRequest) (federation.Intent, error) {
	if s == nil || ctx == nil || !request.NodeID.Valid() || !request.GrantID.Valid() || request.CommandType == "" || !validSHA256(request.SchemaHash) || request.TenantID == "" || request.ResourceKind == "" || request.ResourceID == "" || request.IdempotencyKey == "" || len(request.IdempotencyKey) > 256 || strings.ContainsAny(request.IdempotencyKey, "\x00\r\n") || !validRisk(request.Risk) || operator.PrincipalID == "" || operator.TenantID == "" || operator.SessionID == "" || operator.AuthzEpoch == 0 || operator.Assurance == "" {
		return federation.Intent{}, ErrInvalid
	}
	node, err := s.store.Node(ctx, request.NodeID)
	if err != nil {
		return federation.Intent{}, err
	}
	if node.State == NodeRevoked || node.State == NodeRevoking {
		return federation.Intent{}, ErrForbidden
	}
	if err = s.authorizer.Authorize(ctx, operator, "node.intent.create", node.ID, request.ResourceKind, request.ResourceID); err != nil {
		return federation.Intent{}, err
	}
	capability, ok := findCapability(node.Capabilities, request.CommandType)
	if !ok || !capability.RemoteEligible || capability.SchemaHash != request.SchemaHash || capability.Version == 0 || !validRisk(capability.MinimumRisk) {
		return federation.Intent{}, ErrForbidden
	}
	if !riskAtLeast(request.Risk, capability.MinimumRisk) {
		request.Risk = capability.MinimumRisk
	}
	now := s.clock().UTC()
	grant, err := s.store.Grant(ctx, request.GrantID)
	if err != nil {
		return federation.Intent{}, err
	}
	if err = grant.Validate(now); err != nil || grant.PeerID != s.peerID || grant.NodeID != node.ID || grant.AuthorityEpoch != node.AuthorityEpoch || !riskAllows(grant.MaximumRisk, request.Risk) || !grantAllows(grant, request) {
		return federation.Intent{}, ErrForbidden
	}
	if (request.Risk == federation.RiskHigh || request.Risk == federation.RiskCritical) && request.Approval == nil {
		return federation.Intent{}, ErrForbidden
	}
	canonical, err := canonicalPayload(request.Payload)
	if err != nil {
		return federation.Intent{}, err
	}
	actor := federation.Actor{PrincipalID: operator.PrincipalID, TenantID: operator.TenantID, SessionID: operator.SessionID, AuthzEpoch: operator.AuthzEpoch, Assurance: operator.Assurance}
	admissionDigest, err := intentAdmissionDigest(s.peerID, node, request, capability, actor, canonical)
	if err != nil {
		return federation.Intent{}, err
	}
	id, err := s.ids.New(ctx, "intent")
	if err != nil {
		return federation.Intent{}, err
	}
	effectID := "fed-" + digest([]byte("cyberpanel-central-effect-v1\x00" + node.ID.String() + "\x00" + request.IdempotencyKey + "\x00" + admissionDigest))
	intent := federation.Intent{
		ID:                 id,
		PeerID:             s.peerID,
		NodeID:             node.ID,
		GrantID:            request.GrantID,
		AuthorityEpoch:     node.AuthorityEpoch,
		ProtocolVersion:    capability.Version,
		CommandType:        request.CommandType,
		SchemaHash:         request.SchemaHash,
		Payload:            canonical,
		PayloadDigest:      digest(canonical),
		TenantID:           request.TenantID,
		ResourceKind:       request.ResourceKind,
		ResourceID:         request.ResourceID,
		ExpectedGeneration: request.ExpectedGeneration,
		IdempotencyKey:     request.IdempotencyKey,
		EffectID:           effectID,
		Risk:               request.Risk,
		ActorChain:         []federation.Actor{actor},
		Approval:           request.Approval,
		IssuedAt:           now,
		ExpiresAt:          now.Add(15 * time.Minute),
	}
	key, err := s.signer.IntentKeyID(ctx)
	if err != nil {
		return federation.Intent{}, err
	}
	intent.SigningKeyID = key
	intent.Signature, err = s.signer.SignIntent(ctx, key, intent.SigStructure())
	if err != nil {
		return federation.Intent{}, err
	}
	if err = intent.Validate(now); err != nil {
		return federation.Intent{}, err
	}
	priority := uint8(2)
	if intent.Risk == federation.RiskHigh {
		priority = 3
	}
	if intent.Risk == federation.RiskCritical {
		priority = 4
	}
	stored, created, err := s.store.QueueIntent(ctx, node.OwnerTenantID, intent, priority, admissionDigest)
	if err != nil {
		return federation.Intent{}, err
	}
	if !created {
		return stored, nil
	}
	_ = s.audit.Record(ctx, "federation.intent.queued", operator, node.ID, request.ResourceKind, request.ResourceID, intent.EffectID)
	return intent, nil
}

func (s *Service) HandleReceipt(ctx context.Context, nodeID federation.ID, receipt federation.Receipt) error {
	_, err := s.AdmitReceipt(ctx, nodeID, receipt)
	return err
}

func (s *Service) AdmitReceipt(ctx context.Context, nodeID federation.ID, receipt federation.Receipt) (bool, error) {
	if s == nil || ctx == nil || s.receiptVerifier == nil || nodeID != receipt.NodeID || !validReceipt(receipt) {
		return false, ErrInvalid
	}
	if err := s.receiptVerifier.VerifyNodeReceipt(ctx, nodeID, receipt.SignatureKeyID, receipt.SigStructure(), receipt.Signature); err != nil {
		return false, ErrForbidden
	}
	return s.store.Receipt(ctx, receipt)
}

func (s *Service) HandleEvents(ctx context.Context, nodeID federation.ID, events []federation.NodeEvent) error {
	_, err := s.AdmitEvents(ctx, nodeID, events)
	return err
}

func (s *Service) AdmitEvents(ctx context.Context, nodeID federation.ID, events []federation.NodeEvent) (EventApplyResult, error) {
	if s == nil || ctx == nil || s.eventVerifier == nil || !nodeID.Valid() || len(events) == 0 || len(events) > 1000 {
		return EventApplyResult{}, ErrInvalid
	}
	now := s.clock().UTC()
	receipts := make([]federation.Receipt, 0)
	for index, event := range events {
		if event.NodeID != nodeID || !event.ID.Valid() || event.Sequence == 0 || index > 0 && event.Sequence <= events[index-1].Sequence || event.Priority < federation.PriorityTelemetry || event.Priority > federation.PriorityRevocation || event.Kind == "" || len(event.Kind) > 128 || len(event.Payload) == 0 || len(event.Payload) > federation.MaxFrameBytes || digest(event.Payload) != event.PayloadDigest || event.OccurredAt.IsZero() || event.OccurredAt.After(now.Add(5*time.Minute)) || event.SignatureKeyID == "" || len(event.SignatureKeyID) > 256 || len(event.Signature) == 0 || (event.ResourceKind == "") != (event.ResourceID == "") {
			return EventApplyResult{}, ErrInvalid
		}
		if err := s.eventVerifier.VerifyNodeEvent(ctx, nodeID, event.SignatureKeyID, event.SigStructure(), event.Signature); err != nil {
			return EventApplyResult{}, ErrForbidden
		}
		if event.Kind == "federation.receipt.v1" {
			var receipt federation.Receipt
			if s.receiptVerifier == nil || decodeControlPayload(event.Payload, &receipt) != nil || receipt.NodeID != nodeID || receipt.IntentID.String() != event.ResourceID || event.ResourceKind != "federated_intent" || receipt.LocalGeneration != event.Generation || !receipt.UpdatedAt.UTC().Equal(event.OccurredAt.UTC()) || !validReceipt(receipt) {
				return EventApplyResult{}, ErrInvalid
			}
			if err := s.receiptVerifier.VerifyNodeReceipt(ctx, nodeID, receipt.SignatureKeyID, receipt.SigStructure(), receipt.Signature); err != nil {
				return EventApplyResult{}, ErrForbidden
			}
			receipts = append(receipts, receipt)
		}
	}
	for _, receipt := range receipts {
		if _, err := s.store.Receipt(ctx, receipt); err != nil {
			return EventApplyResult{}, err
		}
	}
	return s.store.ApplyEvents(ctx, nodeID, events)
}

func (s *Service) Disconnect(ctx context.Context, nodeID federation.ID) error {
	if s == nil || ctx == nil || !nodeID.Valid() {
		return ErrInvalid
	}
	return s.store.MarkNodeStale(ctx, nodeID)
}

func (s *Service) RevokeNode(ctx context.Context, operator Operator, nodeID federation.ID, reason string) (federation.Revocation, error) {
	node, err := s.store.Node(ctx, nodeID)
	if err != nil {
		return federation.Revocation{}, err
	}
	if err = s.authorizer.Authorize(ctx, operator, "node.revoke", node.ID, "node", node.ID.String()); err != nil {
		return federation.Revocation{}, err
	}
	revocation := federation.Revocation{PeerID: s.peerID, NodeID: node.ID, NewAuthorityEpoch: node.AuthorityEpoch + 1, Reason: reason, IssuedAt: s.clock().UTC()}
	key, err := s.signer.RevocationKeyID(ctx)
	if err != nil {
		return federation.Revocation{}, err
	}
	revocation.SigningKeyID = key
	revocation.Signature, err = s.signer.SignRevocation(ctx, key, revocationStructure(revocation))
	if err != nil {
		return federation.Revocation{}, err
	}
	if err = s.store.PutRevocation(ctx, revocation); err != nil {
		return federation.Revocation{}, err
	}
	node.AuthorityEpoch = revocation.NewAuthorityEpoch
	node.State = NodeRevoking
	node.UpdatedAt = s.clock().UTC()
	if err = s.store.PutNode(ctx, node); err != nil {
		return federation.Revocation{}, err
	}
	_ = s.audit.Record(ctx, "federation.node.revocation_queued", operator, node.ID, "node", node.ID.String(), reason)
	return revocation, nil
}

func (s *Service) CreateSaga(ctx context.Context, operator Operator, saga Saga) (Saga, error) {
	if !saga.ID.Valid() || !saga.OwnerTenantID.Valid() || saga.Kind == "" || len(saga.Steps) == 0 {
		return Saga{}, ErrInvalid
	}
	if err := s.authorizer.Authorize(ctx, operator, "saga.create", saga.ID, "saga", saga.ID.String()); err != nil {
		return Saga{}, err
	}
	ids := map[string]bool{}
	for _, step := range saga.Steps {
		if step.ID == "" || !step.NodeID.Valid() || ids[step.ID] {
			return Saga{}, ErrInvalid
		}
		ids[step.ID] = true
	}
	for _, step := range saga.Steps {
		for _, dependency := range step.Dependencies {
			if !ids[dependency] {
				return Saga{}, ErrInvalid
			}
		}
	}
	saga.State = SagaPending
	saga.Current = 0
	saga.CreatedAt = s.clock().UTC()
	saga.UpdatedAt = saga.CreatedAt
	if err := s.store.PutSaga(ctx, saga); err != nil {
		return Saga{}, err
	}
	return saga, nil
}

func (s *Service) AdvanceSaga(ctx context.Context, id federation.ID, operator Operator) (Saga, error) {
	saga, err := s.store.Saga(ctx, id)
	if err != nil {
		return Saga{}, err
	}
	if err = s.authorizer.Authorize(ctx, operator, "saga.advance", saga.ID, "saga", saga.ID.String()); err != nil {
		return Saga{}, err
	}
	if saga.State == SagaApplied || saga.State == SagaFailed {
		return saga, nil
	}
	saga.State = SagaRunning
	for index := range saga.Steps {
		step := &saga.Steps[index]
		if step.Status == federation.IntentApplied {
			continue
		}
		if !dependenciesApplied(saga.Steps, *step) {
			continue
		}
		if step.IntentID == "" {
			saga.State = SagaPaused
			saga.ErrorCode = "SAGA_STEP_INTENT_REQUIRED"
			break
		}
		saga.Current = uint32(index)
		saga.UpdatedAt = s.clock().UTC()
		return saga, s.store.PutSaga(ctx, saga)
	}
	all := true
	for _, step := range saga.Steps {
		if step.Status != federation.IntentApplied {
			all = false
			break
		}
	}
	if all {
		saga.State = SagaApplied
	}
	saga.UpdatedAt = s.clock().UTC()
	return saga, s.store.PutSaga(ctx, saga)
}

func (s *Service) ApplySagaReceipt(ctx context.Context, sagaID federation.ID, receipt federation.Receipt) (Saga, error) {
	saga, err := s.store.Saga(ctx, sagaID)
	if err != nil {
		return Saga{}, err
	}
	found := false
	for index := range saga.Steps {
		if saga.Steps[index].IntentID == receipt.IntentID {
			saga.Steps[index].Status = receipt.Status
			saga.Steps[index].Receipt = &receipt
			found = true
			break
		}
	}
	if !found {
		return saga, ErrNotFound
	}
	if receipt.Status == federation.IntentRejected {
		saga.State = SagaCompensating
		saga.ErrorCode = receipt.ErrorCode
	} else if receipt.Status == federation.IntentAmbiguous {
		saga.State = SagaPaused
		saga.ErrorCode = "SAGA_STEP_AMBIGUOUS"
	}
	saga.UpdatedAt = s.clock().UTC()
	return saga, s.store.PutSaga(ctx, saga)
}

type NodeSession struct {
	service                *Service
	store                  *Store
	session                federation.Session
	nodeID                 federation.ID
	certificateFingerprint [sha256.Size]byte
	protocolVersion        uint32
	authorityEpoch         uint64
	capabilityDigest       string
	sendEvery              time.Duration
	helloTimeout           time.Duration
	receiveTimeout         time.Duration
}

type helloAcknowledgement struct {
	Accepted          bool          `json:"accepted"`
	NodeID            federation.ID `json:"nodeId"`
	PeerID            federation.ID `json:"peerId"`
	ProtocolVersion   uint32        `json:"protocolVersion"`
	CapabilityDigest string        `json:"capabilityDigest"`
	AuthorityEpoch    uint64        `json:"authorityEpoch"`
	RevocationPending bool          `json:"revocationPending"`
}

type heartbeat struct {
	At                time.Time     `json:"at"`
	NodeID            federation.ID `json:"nodeId"`
	PeerID            federation.ID `json:"peerId"`
	AuthorityEpoch    uint64        `json:"authorityEpoch"`
	CapabilityDigest string        `json:"capabilityDigest"`
}

type revocationAcknowledgement struct {
	NodeID          federation.ID `json:"nodeId"`
	AuthorityEpoch uint64        `json:"authorityEpoch"`
	AppliedAt       time.Time     `json:"appliedAt"`
}

type eventAcknowledgement struct {
	Through uint64 `json:"through"`
}

type resyncRequest = federation.ProjectionSnapshotRequest

func (n *NodeSession) Run(ctx context.Context) error {
	if n == nil || ctx == nil || n.service == nil || n.store == nil || n.session == nil {
		return ErrInvalid
	}
	if err := n.negotiate(ctx); err != nil {
		return err
	}
	defer func() { _ = n.service.Disconnect(context.Background(), n.nodeID) }()
	if err := n.flush(ctx); err != nil {
		return err
	}
	interval := n.sendEvery
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	incoming := make(chan federation.Frame, 1)
	failures := make(chan error, 1)
	go func() {
		for {
			timeout := n.receiveTimeout
			if timeout <= 0 || timeout > 5*time.Minute {
				timeout = 45 * time.Second
			}
			receiveContext, cancel := context.WithTimeout(ctx, timeout)
			frame, err := n.session.Receive(receiveContext)
			cancel()
			if err != nil {
				select {
				case failures <- err:
				case <-ctx.Done():
				}
				return
			}
			select {
			case incoming <- frame:
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failures:
			return err
		case frame := <-incoming:
			if err := n.handle(ctx, frame); err != nil {
				return err
			}
		case <-ticker.C:
			if err := n.flush(ctx); err != nil {
				return err
			}
		}
	}
}

func (n *NodeSession) negotiate(ctx context.Context) error {
	timeout := n.helloTimeout
	if timeout <= 0 || timeout > time.Minute {
		timeout = 15 * time.Second
	}
	helloContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	frame, err := n.session.Receive(helloContext)
	if err != nil {
		return err
	}
	if frame.Type != federation.FrameHello {
		return ErrForbidden
	}
	var capabilities federation.CapabilitySet
	if err = decodeControlPayload(frame.Payload, &capabilities); err != nil || !validHelloCapabilities(capabilities, n.service.clock().UTC()) {
		return ErrInvalid
	}
	node, err := n.store.Node(ctx, capabilities.NodeID)
	if err != nil {
		return err
	}
	if node.State == NodeRevoked || !certificateFingerprintMatches(node.CertificateFingerprint, n.certificateFingerprint) {
		return ErrForbidden
	}
	revocationPending := node.State == NodeRevoking && capabilities.AuthorityEpoch < node.AuthorityEpoch
	if (node.State == NodeRevoking && !revocationPending) || (node.State != NodeRevoking && capabilities.AuthorityEpoch != node.AuthorityEpoch) {
		return ErrStale
	}
	node.Capabilities = capabilities
	if !revocationPending && node.State != NodeDegraded {
		node.State = NodeOnline
	}
	node.LastSeenAt = n.service.clock().UTC()
	node.UpdatedAt = node.LastSeenAt
	if err = n.store.PutNode(ctx, node); err != nil {
		return err
	}
	n.nodeID = node.ID
	n.protocolVersion = capabilities.ProtocolVersion
	n.authorityEpoch = capabilities.AuthorityEpoch
	n.capabilityDigest = capabilities.Digest
	acknowledgement := helloAcknowledgement{Accepted: true, NodeID: node.ID, PeerID: n.service.peerID, ProtocolVersion: capabilities.ProtocolVersion, CapabilityDigest: capabilities.Digest, AuthorityEpoch: node.AuthorityEpoch, RevocationPending: revocationPending}
	return sendFrame(ctx, n.session, federation.FrameHelloAck, acknowledgement)
}

func (n *NodeSession) flush(ctx context.Context) error {
	node, err := n.store.Node(ctx, n.nodeID)
	if err != nil {
		return err
	}
	if !certificateFingerprintMatches(node.CertificateFingerprint, n.certificateFingerprint) || node.State == NodeRevoked {
		return ErrForbidden
	}
	revocations, err := n.store.QueuedRevocations(ctx, n.nodeID, 20)
	if err != nil {
		return err
	}
	for _, value := range revocations {
		if err = n.store.MarkRevocationSent(ctx, n.nodeID, value.NewAuthorityEpoch); err != nil {
			return err
		}
		if err = sendFrame(ctx, n.session, federation.FrameRevocation, value); err != nil {
			return err
		}
	}
	if len(revocations) > 0 {
		return nil
	}
	node, err = n.store.Node(ctx, n.nodeID)
	if err != nil {
		return err
	}
	if !certificateFingerprintMatches(node.CertificateFingerprint, n.certificateFingerprint) {
		return ErrForbidden
	}
	if node.State == NodeRevoking || node.State == NodeRevoked {
		return nil
	}
	if pending, found, pendingErr := n.store.PendingProjectionSnapshot(ctx, n.nodeID, n.service.peerID, node.AuthorityEpoch); pendingErr != nil {
		return pendingErr
	} else if found {
		return sendFrame(ctx, n.session, federation.FrameSnapshotRequest, pending)
	}
	if node.State == NodeDegraded {
		request, beginErr := n.store.BeginProjectionSnapshot(ctx,n.nodeID,n.service.peerID,node.AuthorityEpoch,node.ProjectionSequence+1)
		if beginErr != nil { return beginErr }
		return sendFrame(ctx,n.session,federation.FrameSnapshotRequest,request)
	}
	intents, err := n.store.QueuedIntents(ctx, n.nodeID, 50)
	if err != nil {
		return err
	}
	for _, intent := range intents {
		if err = n.store.MarkIntentSent(ctx, intent.ID); err != nil {
			return err
		}
		if err = sendFrame(ctx, n.session, federation.FrameIntent, intent); err != nil {
			return err
		}
	}
	return nil
}

func (n *NodeSession) handle(ctx context.Context, frame federation.Frame) error {
	node, err := n.store.Node(ctx, n.nodeID)
	if err != nil {
		return err
	}
	if !certificateFingerprintMatches(node.CertificateFingerprint, n.certificateFingerprint) || node.State == NodeRevoked || node.State == NodeRevoking && frame.Type != federation.FrameRevocationAck {
		return ErrForbidden
	}
	switch frame.Type {
	case federation.FrameReceipt:
		var receipt federation.Receipt
		if err := decodeControlPayload(frame.Payload, &receipt); err != nil {
			return err
		}
		return n.service.HandleReceipt(ctx, n.nodeID, receipt)
	case federation.FrameRevocationAck:
		var acknowledgement revocationAcknowledgement
		if err := decodeControlPayload(frame.Payload, &acknowledgement); err != nil {
			return err
		}
		if acknowledgement.NodeID != n.nodeID || acknowledgement.AuthorityEpoch == 0 || acknowledgement.AppliedAt.IsZero() || acknowledgement.AppliedAt.After(n.service.clock().UTC().Add(5*time.Minute)) {
			return ErrInvalid
		}
		return n.store.AckRevocation(ctx, n.nodeID, acknowledgement.AuthorityEpoch)
	case federation.FrameEventBatch:
		if pending, found, pendingErr := n.store.PendingProjectionSnapshot(ctx, n.nodeID, n.service.peerID, node.AuthorityEpoch); pendingErr != nil {
			return pendingErr
		} else if found {
			return sendFrame(ctx, n.session, federation.FrameSnapshotRequest, pending)
		}
		var events []federation.NodeEvent
		if err := decodeControlPayload(frame.Payload, &events); err != nil {
			return err
		}
		result, err := n.service.AdmitEvents(ctx, n.nodeID, events)
		if err != nil {
			return err
		}
		if result.Resync {
			request, beginErr := n.store.BeginProjectionSnapshot(ctx, n.nodeID, n.service.peerID, n.authorityEpoch, result.ReceivedSequence)
			if beginErr != nil { return beginErr }
			return sendFrame(ctx, n.session, federation.FrameSnapshotRequest, request)
		}
		if result.AckThrough == 0 {
			return ErrInvalid
		}
		return sendFrame(ctx, n.session, federation.FrameEventAck, eventAcknowledgement{Through: result.AckThrough})
	case federation.FrameSnapshotChunk:
		var chunk federation.ProjectionSnapshotChunk
		if err := decodeControlPayload(frame.Payload, &chunk); err != nil { return err }
		if chunk.NodeID != n.nodeID || chunk.PeerID != n.service.peerID || chunk.AuthorityEpoch != n.authorityEpoch || n.service.eventVerifier == nil || chunk.SignatureKeyID == "" || len(chunk.SignatureKeyID)>256 || len(chunk.Signature)!=64 { return ErrForbidden }
		if err := n.service.eventVerifier.VerifyNodeEvent(ctx,n.nodeID,chunk.SignatureKeyID,chunk.SigStructure(),chunk.Signature); err != nil { return ErrForbidden }
		request, complete, err := n.store.ReceiveProjectionSnapshot(ctx, chunk, hex.EncodeToString(n.certificateFingerprint[:]))
		if err != nil { return err }
		if complete { return sendFrame(ctx,n.session,federation.FrameEventAck,eventAcknowledgement{Through:chunk.Watermark}) }
		return sendFrame(ctx,n.session,federation.FrameSnapshotRequest,request)
	case federation.FrameHeartbeat:
		var value heartbeat
		if err := decodeControlPayload(frame.Payload, &value); err != nil {
			return err
		}
		if value.At.IsZero() || value.At.After(n.service.clock().UTC().Add(5*time.Minute)) || value.NodeID != n.nodeID || value.PeerID != n.service.peerID || value.AuthorityEpoch != n.authorityEpoch || value.CapabilityDigest != n.capabilityDigest {
			return ErrForbidden
		}
		node, err := n.store.Node(ctx, n.nodeID)
		if err != nil {
			return err
		}
		if node.State == NodeRevoked || !certificateFingerprintMatches(node.CertificateFingerprint, n.certificateFingerprint) || node.AuthorityEpoch != value.AuthorityEpoch || node.Capabilities.Digest != value.CapabilityDigest {
			return ErrForbidden
		}
		if node.State != NodeRevoking && node.State != NodeDegraded {
			node.State = NodeOnline
		}
		node.LastSeenAt = n.service.clock().UTC()
		node.UpdatedAt = node.LastSeenAt
		return n.store.PutNode(ctx, node)
	default:
		return ErrInvalid
	}
}

func sendFrame(ctx context.Context, session federation.Session, kind federation.FrameType, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return session.Send(ctx, federation.Frame{Version: 1, Type: kind, Payload: raw})
}

func decodeControlPayload(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > federation.MaxFrameBytes || target == nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func validHelloCapabilities(capabilities federation.CapabilitySet, now time.Time) bool {
	if !capabilities.NodeID.Valid() || capabilities.ProtocolVersion != centralFederationProtocolVersion || capabilities.AuthorityEpoch == 0 || capabilities.GeneratedAt.IsZero() || capabilities.GeneratedAt.After(now.Add(5*time.Minute)) || len(capabilities.Capabilities) > 4096 || !validSHA256(capabilities.Digest) || capabilities.Digest != capabilities.CanonicalDigest() {
		return false
	}
	seen := make(map[string]struct{}, len(capabilities.Capabilities))
	for _, capability := range capabilities.Capabilities {
		if capability.CommandType == "" || len(capability.CommandType) > 256 || capability.Version == 0 || !validSHA256(capability.SchemaHash) || !validRisk(capability.MinimumRisk) || len(capability.Resources) > 1024 {
			return false
		}
		if _, exists := seen[capability.CommandType]; exists {
			return false
		}
		seen[capability.CommandType] = struct{}{}
	}
	return true
}

func validReceipt(receipt federation.Receipt) bool {
	if !receipt.IntentID.Valid() || !receipt.NodeID.Valid() || receipt.EffectID == "" || receipt.IdempotencyKey == "" || receipt.SignatureKeyID == "" || len(receipt.SignatureKeyID) > 256 || len(receipt.Signature) == 0 || receipt.UpdatedAt.IsZero() || len(receipt.ErrorCode) > 128 || len(receipt.ErrorMessage) > 1024 || strings.ContainsAny(receipt.ErrorCode, "\x00\r\n") || receipt.ResultDigest != "" && !validSHA256(receipt.ResultDigest) {
		return false
	}
	terminal := receipt.Status == federation.IntentApplied || receipt.Status == federation.IntentRejected || receipt.Status == federation.IntentExpired
	if receipt.Terminal != terminal {
		return false
	}
	switch receipt.Status {
	case federation.IntentAccepted, federation.IntentRunning, federation.IntentApplied, federation.IntentRejected, federation.IntentAmbiguous, federation.IntentExpired:
		return true
	default:
		return false
	}
}

func intentAdmissionDigest(peerID federation.ID, node Node, request IntentRequest, capability federation.Capability, actor federation.Actor, canonical []byte) (string, error) {
	value := struct {
		Domain              string               `json:"domain"`
		PeerID              federation.ID        `json:"peerId"`
		NodeID              federation.ID        `json:"nodeId"`
		GrantID             federation.ID        `json:"grantId"`
		AuthorityEpoch      uint64               `json:"authorityEpoch"`
		CapabilityVersion   uint32               `json:"capabilityVersion"`
		CommandType         string               `json:"commandType"`
		SchemaHash          string               `json:"schemaHash"`
		PayloadDigest       string               `json:"payloadDigest"`
		TenantID            string               `json:"tenantId"`
		ResourceKind        string               `json:"resourceKind"`
		ResourceID          string               `json:"resourceId"`
		ExpectedGeneration uint64               `json:"expectedGeneration"`
		IdempotencyKey      string               `json:"idempotencyKey"`
		Risk                federation.Risk      `json:"risk"`
		Actor               federation.Actor     `json:"actor"`
		Approval            *federation.Approval `json:"approval,omitempty"`
	}{
		Domain: "cyberpanel-central-intent-admission-v1", PeerID: peerID, NodeID: node.ID, GrantID: request.GrantID, AuthorityEpoch: node.AuthorityEpoch, CapabilityVersion: capability.Version, CommandType: request.CommandType, SchemaHash: request.SchemaHash, PayloadDigest: digest(canonical), TenantID: request.TenantID, ResourceKind: request.ResourceKind, ResourceID: request.ResourceID, ExpectedGeneration: request.ExpectedGeneration, IdempotencyKey: request.IdempotencyKey, Risk: request.Risk, Actor: actor, Approval: request.Approval,
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}

func grantAllows(grant federation.MutationGrant, request IntentRequest) bool {
	for _, selector := range grant.Selectors {
		if selector.LabelSelector != "" {
			continue
		}
		if selector.Kind != "*" && selector.Kind != request.ResourceKind {
			continue
		}
		if selector.TenantID != "*" && selector.TenantID != request.TenantID {
			continue
		}
		if selector.ResourceID != "*" && selector.ResourceID != request.ResourceID {
			continue
		}
		for _, operation := range selector.Operations {
			if operation == "*" || operation == request.CommandType {
				return true
			}
		}
	}
	return false
}

func findCapability(set federation.CapabilitySet, kind string) (federation.Capability, bool) {
	for _, value := range set.Capabilities {
		if value.CommandType == kind {
			return value, true
		}
	}
	return federation.Capability{}, false
}

func validRisk(value federation.Risk) bool {
	switch value {
	case federation.RiskLow, federation.RiskModerate, federation.RiskHigh, federation.RiskCritical:
		return true
	default:
		return false
	}
}

func riskAtLeast(value, minimum federation.Risk) bool {
	rank := map[federation.Risk]int{federation.RiskLow: 1, federation.RiskModerate: 2, federation.RiskHigh: 3, federation.RiskCritical: 4}
	return rank[value] >= rank[minimum]
}

func riskAllows(maximum, requested federation.Risk) bool {
	rank := map[federation.Risk]int{federation.RiskLow: 1, federation.RiskModerate: 2, federation.RiskHigh: 3, federation.RiskCritical: 4}
	return rank[requested] > 0 && rank[requested] <= rank[maximum]
}

func canonicalPayload(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > federation.MaxFrameBytes {
		return nil, ErrInvalid
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	return json.Marshal(value)
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func dependenciesApplied(steps []SagaStep, step SagaStep) bool {
	for _, dependency := range step.Dependencies {
		found := false
		for _, candidate := range steps {
			if candidate.ID == dependency {
				found = candidate.Status == federation.IntentApplied
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func revocationStructure(value federation.Revocation) []byte {
	copy := value
	copy.Signature = nil
	raw, _ := json.Marshal(struct {
		Domain string                `json:"domain"`
		Value  federation.Revocation `json:"value"`
	}{"cyberpanel-federation-revocation-v1", copy})
	return raw
}
