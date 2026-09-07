package ha

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

const (
	FederatedMariaDBGateFreezeCommand        = "ha.mariadb.writer_gate.freeze"
	FederatedMariaDBGateActivateCommand      = "ha.mariadb.writer_gate.activate"
	FederatedMariaDBGateRevokeCommand        = "ha.mariadb.writer_gate.revoke"
	FederatedMariaDBPromotionFreezeCommand   = "ha.mariadb.promotion.freeze"
	FederatedMariaDBPromotionActivateCommand = "ha.mariadb.promotion.activate"
	FederatedMariaDBPromotionDemoteCommand   = "ha.mariadb.promotion.demote"
	FederatedMariaDBPromotionProbeCommand    = "ha.mariadb.promotion.probe"
	FederatedOLSListenerApplyCommand         = "ha.webengine.ols_lse_listener.apply"
	FederatedHAApprovalPolicyVersion         = "cyberpanel.ha.federated-dispatch.v1"
)

const federatedHAProtocolVersion uint32 = 1

// FederatedHAIntentSender binds a closed draft to the current central grant,
// capability and authority epoch, signs it, and submits it through the
// production federation queue. Observe must read the durable receipt for the
// same intent/effect; it must never resubmit the effect. Receipt verification
// uses the node key already trusted by the central federation runtime.
type FederatedHAIntentSender interface {
	BindAndSend(context.Context, federation.Intent) (federation.Intent, federation.Receipt, error)
	Observe(context.Context, federation.Intent) (federation.Receipt, error)
	VerifyNodeReceipt(context.Context, federation.ID, string, []byte, []byte) error
}

type FederatedMariaDBWriterGatePayload struct {
	ResourceID    string       `json:"resource_id"`
	NodeID        NodeID       `json:"node_id"`
	FencingToken  uint64       `json:"fencing_token"`
	WritePaths    []string     `json:"write_paths,omitempty"`
	Lease         *WriterLease `json:"lease,omitempty"`
	Permit        *WritePermit `json:"permit,omitempty"`
}

type FederatedMariaDBPromotionPayload struct {
	Promotion     Promotion    `json:"promotion"`
	Lease         *WriterLease `json:"lease,omitempty"`
	FencingToken  uint64       `json:"fencing_token,omitempty"`
}

type FederatedOLSListenerPayload struct {
	TargetNodeID NodeID        `json:"target_node_id"`
	Change       TrafficChange `json:"change"`
}

// FederatedHACommandCapabilities is the exact capability set required by this
// bridge. A node that does not advertise the matching command and schema hash
// is rejected by the existing federation agent before local execution.
func FederatedHACommandCapabilities() []federation.Capability {
	commands := []string{
		FederatedMariaDBGateFreezeCommand,
		FederatedMariaDBGateActivateCommand,
		FederatedMariaDBGateRevokeCommand,
		FederatedMariaDBPromotionFreezeCommand,
		FederatedMariaDBPromotionActivateCommand,
		FederatedMariaDBPromotionDemoteCommand,
		FederatedMariaDBPromotionProbeCommand,
		FederatedOLSListenerApplyCommand,
	}
	capabilities := make([]federation.Capability, 0, len(commands))
	for _, command := range commands {
		capabilities = append(capabilities, federation.Capability{
			CommandType: command,
			SchemaHash: federatedHACommandSchemaHash(command),
			Version: federatedHAProtocolVersion,
			RemoteEligible: true,
			MinimumRisk: federation.RiskCritical,
			Resources: []string{LocalMariaDBResourceID},
		})
	}
	return capabilities
}

type FederatedHADispatcher struct {
	Sender FederatedHAIntentSender
	Now    func() time.Time
}

func (dispatcher *FederatedHADispatcher) dispatch(ctx context.Context, node NodeID, command, resource string, expectedGeneration uint64, payload any) (federation.Receipt, error) {
	if dispatcher == nil || dispatcher.Sender == nil || ctx == nil || command == "" || resource == "" || expectedGeneration == 0 {
		return federation.Receipt{}, ErrUnsupported
	}
	target, err := federation.NewID(string(node))
	if err != nil || target.String() != string(node) {
		return federation.Receipt{}, errors.Join(ErrUnsupported, err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) == 0 || len(encoded) > federation.MaxFrameBytes {
		return federation.Receipt{}, errors.Join(ErrInvalid, err)
	}
	// Match the central intent encoder before binding payload and approval digests.
	var canonical any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err = decoder.Decode(&canonical); err != nil { return federation.Receipt{}, ErrInvalid }
	encoded, err = json.Marshal(canonical)
	if err != nil { return federation.Receipt{}, ErrInvalid }
	payloadDigest := federatedHADigest(encoded)
	effectDigest := federatedHADigest([]byte("cyberpanel-ha-federated-effect-v1\x00" + command + "\x00" + target.String() + "\x00" + resource + "\x00" + payloadDigest))
	draft := federation.Intent{
		ID: federation.ID("ha_intent_" + effectDigest[:48]),
		NodeID: target,
		ProtocolVersion: federatedHAProtocolVersion,
		CommandType: command,
		SchemaHash: federatedHACommandSchemaHash(command),
		Payload: encoded,
		PayloadDigest: payloadDigest,
		TenantID: "system",
		ResourceKind: "ha",
		ResourceID: resource,
		ExpectedGeneration: expectedGeneration,
		IdempotencyKey: "ha_idempotency_" + effectDigest[:48],
		EffectID: "ha_effect_" + effectDigest[:48],
		Risk: federation.RiskCritical,
	}
	bound, receipt, sendErr := dispatcher.Sender.BindAndSend(ctx, draft)
	if err = validateBoundFederatedHAIntent(draft, bound, dispatcher.current()); err != nil {
		return federation.Receipt{}, err
	}
	if receiptErr := dispatcher.validateReceipt(ctx, bound, receipt); receiptErr == nil && receipt.Terminal {
		return dispatcher.terminalReceipt(receipt)
	}
	// The production federation store owns replay. A transport error or a
	// non-terminal/ambiguous receipt is reconciled by observation only.
	observed, observeErr := dispatcher.Sender.Observe(ctx, bound)
	if err = dispatcher.validateReceipt(ctx, bound, observed); err != nil {
		return federation.Receipt{}, errors.Join(ErrReconciliationRequired, sendErr, observeErr, err)
	}
	if observeErr != nil || !observed.Terminal {
		return observed, errors.Join(ErrReconciliationRequired, sendErr, observeErr)
	}
	return dispatcher.terminalReceipt(observed)
}

func (dispatcher *FederatedHADispatcher) validateReceipt(ctx context.Context, intent federation.Intent, receipt federation.Receipt) error {
	if receipt.IntentID != intent.ID || receipt.NodeID != intent.NodeID || receipt.EffectID != intent.EffectID || receipt.IdempotencyKey != intent.IdempotencyKey || receipt.Status == "" || receipt.UpdatedAt.IsZero() || receipt.SignatureKeyID == "" || len(receipt.Signature) == 0 {
		return ErrInvalid
	}
	if receipt.UpdatedAt.After(dispatcher.current().Add(time.Minute)) {
		return ErrInvalid
	}
	if err := dispatcher.Sender.VerifyNodeReceipt(ctx, receipt.NodeID, receipt.SignatureKeyID, receipt.SigStructure(), receipt.Signature); err != nil {
		return errors.Join(ErrForbidden, err)
	}
	return nil
}

func (dispatcher *FederatedHADispatcher) terminalReceipt(receipt federation.Receipt) (federation.Receipt, error) {
	switch receipt.Status {
	case federation.IntentApplied:
		if !receipt.Terminal || !validDigest(receipt.ResultDigest) {
			return receipt, ErrInvalid
		}
		return receipt, nil
	case federation.IntentRejected, federation.IntentExpired:
		return receipt, federatedHAReceiptError(receipt)
	default:
		return receipt, ErrReconciliationRequired
	}
}

func (dispatcher *FederatedHADispatcher) current() time.Time {
	if dispatcher != nil && dispatcher.Now != nil {
		return dispatcher.Now().UTC()
	}
	return time.Now().UTC()
}

type OwningNodeWriterGate struct {
	LocalNode NodeID
	Local     WriterGate
	Remote    *FederatedHADispatcher
}

func NewOwningNodeWriterGate(localNode NodeID, local WriterGate, remote *FederatedHADispatcher) (*OwningNodeWriterGate, error) {
	if !validID(string(localNode)) || local == nil {
		return nil, ErrInvalid
	}
	return &OwningNodeWriterGate{LocalNode: localNode, Local: local, Remote: remote}, nil
}

func (gate *OwningNodeWriterGate) FreezeResourceWrites(ctx context.Context, resource string, node NodeID, fencingToken uint64, paths []string) (string, error) {
	if gate == nil || gate.Local == nil {
		return "", ErrInvalid
	}
	if node == gate.LocalNode {
		return gate.Local.FreezeResourceWrites(ctx, resource, node, fencingToken, paths)
	}
	ordered := append([]string(nil), paths...)
	sort.Strings(ordered)
	receipt, err := gate.Remote.dispatch(ctx, node, FederatedMariaDBGateFreezeCommand, resource, fencingToken, FederatedMariaDBWriterGatePayload{ResourceID: resource, NodeID: node, FencingToken: fencingToken, WritePaths: ordered})
	return federatedHAReceiptEvidence(receipt, err)
}

func (gate *OwningNodeWriterGate) ActivateResourceWrites(ctx context.Context, lease WriterLease) (WritePermit, error) {
	if gate == nil || gate.Local == nil {
		return WritePermit{}, ErrInvalid
	}
	if lease.HolderNodeID == gate.LocalNode {
		return gate.Local.ActivateResourceWrites(ctx, lease)
	}
	receipt, err := gate.Remote.dispatch(ctx, lease.HolderNodeID, FederatedMariaDBGateActivateCommand, lease.ResourceID, lease.Generation, FederatedMariaDBWriterGatePayload{ResourceID: lease.ResourceID, NodeID: lease.HolderNodeID, FencingToken: lease.FencingToken, Lease: &lease})
	evidence, err := federatedHAReceiptEvidence(receipt, err)
	if err != nil {
		return WritePermit{}, err
	}
	if receipt.ResultDigest != FederatedHAWritePermitDigest(lease) {
		return WritePermit{}, ErrLeaseLost
	}
	paths := append([]string(nil), lease.EnforcedWritePaths...)
	sort.Strings(paths)
	permit := WritePermit{ResourceID: lease.ResourceID, NodeID: lease.HolderNodeID, LeaseID: lease.ID, FencingToken: lease.FencingToken, AuthorityEpoch: lease.AuthorityEpoch, WritePaths: paths, IssuedAt: receipt.UpdatedAt.UTC(), ExpiresAt: lease.ExpiresAt, Signature: evidence}
	if !validPromotionPermit(permit, lease, gate.Remote.current()) {
		return WritePermit{}, ErrLeaseLost
	}
	return permit, nil
}

func (gate *OwningNodeWriterGate) RevokeWritePermit(ctx context.Context, permit WritePermit) error {
	if gate == nil || gate.Local == nil {
		return ErrInvalid
	}
	if permit.NodeID == gate.LocalNode {
		return gate.Local.RevokeWritePermit(ctx, permit)
	}
	_, err := gate.Remote.dispatch(ctx, permit.NodeID, FederatedMariaDBGateRevokeCommand, permit.ResourceID, permit.FencingToken, FederatedMariaDBWriterGatePayload{ResourceID: permit.ResourceID, NodeID: permit.NodeID, FencingToken: permit.FencingToken, Permit: &permit})
	return err
}

type OwningNodePromotionExecutor struct {
	LocalNode NodeID
	Local     PromotionExecutor
	Remote    *FederatedHADispatcher
}

func NewOwningNodePromotionExecutor(localNode NodeID, local PromotionExecutor, remote *FederatedHADispatcher) (*OwningNodePromotionExecutor, error) {
	if !validID(string(localNode)) || local == nil {
		return nil, ErrInvalid
	}
	return &OwningNodePromotionExecutor{LocalNode: localNode, Local: local, Remote: remote}, nil
}

func (executor *OwningNodePromotionExecutor) FreezeWorkloadWrites(ctx context.Context, promotion Promotion, fencingToken uint64) (string, error) {
	if executor == nil || executor.Local == nil {
		return "", ErrInvalid
	}
	if promotion.PreviousWriter == executor.LocalNode {
		return executor.Local.FreezeWorkloadWrites(ctx, promotion, fencingToken)
	}
	receipt, err := executor.Remote.dispatch(ctx, promotion.PreviousWriter, FederatedMariaDBPromotionFreezeCommand, promotion.ResourceID, promotion.Generation, FederatedMariaDBPromotionPayload{Promotion: promotion, FencingToken: fencingToken})
	return federatedHAReceiptEvidence(receipt, err)
}

func (executor *OwningNodePromotionExecutor) ActivateCandidateServices(ctx context.Context, promotion Promotion, lease WriterLease) (string, uint64, error) {
	if executor == nil || executor.Local == nil {
		return "", 0, ErrInvalid
	}
	if promotion.Candidate == executor.LocalNode {
		return executor.Local.ActivateCandidateServices(ctx, promotion, lease)
	}
	receipt, err := executor.Remote.dispatch(ctx, promotion.Candidate, FederatedMariaDBPromotionActivateCommand, promotion.ResourceID, promotion.Generation, FederatedMariaDBPromotionPayload{Promotion: promotion, Lease: &lease})
	evidence, err := federatedHAReceiptEvidence(receipt, err)
	if err != nil || receipt.LocalGeneration == 0 {
		return evidence, receipt.LocalGeneration, errors.Join(err, ErrIrreversibleFrontier)
	}
	return evidence, receipt.LocalGeneration, nil
}

func (executor *OwningNodePromotionExecutor) DemotePreviousServices(ctx context.Context, promotion Promotion, fencingToken uint64) (string, error) {
	if executor == nil || executor.Local == nil {
		return "", ErrInvalid
	}
	if promotion.PreviousWriter == executor.LocalNode {
		return executor.Local.DemotePreviousServices(ctx, promotion, fencingToken)
	}
	receipt, err := executor.Remote.dispatch(ctx, promotion.PreviousWriter, FederatedMariaDBPromotionDemoteCommand, promotion.ResourceID, promotion.Generation, FederatedMariaDBPromotionPayload{Promotion: promotion, FencingToken: fencingToken})
	return federatedHAReceiptEvidence(receipt, err)
}

func (executor *OwningNodePromotionExecutor) ProbeCandidate(ctx context.Context, promotion Promotion) (string, error) {
	if executor == nil || executor.Local == nil {
		return "", ErrInvalid
	}
	if promotion.Candidate == executor.LocalNode {
		return executor.Local.ProbeCandidate(ctx, promotion)
	}
	receipt, err := executor.Remote.dispatch(ctx, promotion.Candidate, FederatedMariaDBPromotionProbeCommand, promotion.ResourceID, promotion.Generation, FederatedMariaDBPromotionPayload{Promotion: promotion})
	return federatedHAReceiptEvidence(receipt, err)
}

func (executor *OwningNodePromotionExecutor) ProbeExternalTraffic(ctx context.Context, promotion Promotion, receipt TrafficReceipt) (string, error) {
	if executor == nil || executor.Local == nil {
		return "", ErrInvalid
	}
	return executor.Local.ProbeExternalTraffic(ctx, promotion, receipt)
}

func (executor *OwningNodePromotionExecutor) RestorePreviousServices(ctx context.Context, promotion Promotion, fencingToken uint64) (string, error) {
	if executor == nil || executor.Local == nil {
		return "", ErrInvalid
	}
	if promotion.PreviousWriter != executor.LocalNode {
		return "", ErrUnsupported
	}
	return executor.Local.RestorePreviousServices(ctx, promotion, fencingToken)
}

func (executor *OwningNodePromotionExecutor) KeepPreviousFenced(ctx context.Context, promotion Promotion, until time.Time) error {
	if executor == nil || executor.Local == nil {
		return ErrInvalid
	}
	if promotion.PreviousWriter != executor.LocalNode {
		return ErrUnsupported
	}
	return executor.Local.KeepPreviousFenced(ctx, promotion, until)
}

type OwningNodeTrafficProvider struct {
	LocalNode NodeID
	Local     TrafficProvider
	Remote    *FederatedHADispatcher
}

func NewOwningNodeTrafficProvider(localNode NodeID, local TrafficProvider, remote *FederatedHADispatcher) (*OwningNodeTrafficProvider, error) {
	if !validID(string(localNode)) || local == nil {
		return nil, ErrInvalid
	}
	return &OwningNodeTrafficProvider{LocalNode: localNode, Local: local, Remote: remote}, nil
}

func (provider *OwningNodeTrafficProvider) Observe(ctx context.Context, policy TrafficPolicy) (TrafficObservation, error) {
	if provider == nil || provider.Local == nil {
		return TrafficObservation{}, ErrInvalid
	}
	return provider.Local.Observe(ctx, policy)
}

func (provider *OwningNodeTrafficProvider) ApplyConditional(ctx context.Context, change TrafficChange) (TrafficReceipt, error) {
	if provider == nil || provider.Local == nil {
		return TrafficReceipt{}, ErrInvalid
	}
	remoteNodes, err := changedRemoteTrafficNodes(change, provider.LocalNode)
	if err != nil {
		return TrafficReceipt{}, err
	}
	if len(remoteNodes) == 0 {
		return provider.Local.ApplyConditional(ctx, change)
	}
	activation, deactivation := orderRemoteTrafficNodes(change, remoteNodes)
	remoteReceipts := make([]federation.Receipt, 0, len(remoteNodes))
	for _, node := range activation {
		receipt, dispatchErr := provider.applyRemote(ctx, change, node)
		if dispatchErr != nil {
			return TrafficReceipt{}, dispatchErr
		}
		remoteReceipts = append(remoteReceipts, receipt)
	}
	localReceipt, err := provider.Local.ApplyConditional(ctx, change)
	if err != nil {
		return localReceipt, errors.Join(ErrProviderAmbiguous, err)
	}
	for _, node := range deactivation {
		receipt, dispatchErr := provider.applyRemote(ctx, change, node)
		if dispatchErr != nil {
			return localReceipt, dispatchErr
		}
		remoteReceipts = append(remoteReceipts, receipt)
	}
	evidence, err := json.Marshal(struct {
		Local  string               `json:"local_receipt"`
		Remote []federation.Receipt `json:"remote_receipts"`
	}{Local: localReceipt.ProviderReceipt, Remote: remoteReceipts})
	if err != nil {
		return TrafficReceipt{}, err
	}
	localReceipt.ProviderReceipt = string(evidence)
	return localReceipt, nil
}

func (provider *OwningNodeTrafficProvider) applyRemote(ctx context.Context, change TrafficChange, node NodeID) (federation.Receipt, error) {
	child := change
	child.EffectID = federatedHATrafficEffectID(change.EffectID, node)
	receipt, err := provider.Remote.dispatch(ctx, node, FederatedOLSListenerApplyCommand, change.Policy.Resource, change.Policy.Generation, FederatedOLSListenerPayload{TargetNodeID: node, Change: child})
	if err != nil {
		return receipt, errors.Join(ErrProviderAmbiguous, err)
	}
	if receipt.ResultDigest != change.Desired.Digest {
		return receipt, ErrProviderAmbiguous
	}
	return receipt, nil
}

func (provider *OwningNodeTrafficProvider) ApplyObserve(ctx context.Context, change TrafficChange) (TrafficReceipt, error) {
	if provider == nil || provider.Local == nil {
		return TrafficReceipt{}, ErrInvalid
	}
	remote, err := changedRemoteTrafficNodes(change, provider.LocalNode)
	if err != nil {
		return TrafficReceipt{}, err
	}
	if len(remote) != 0 {
		return TrafficReceipt{}, ErrUnsupported
	}
	return provider.Local.ApplyObserve(ctx, change)
}

func (provider *OwningNodeTrafficProvider) CompensateConditional(ctx context.Context, change TrafficChange, receipt TrafficReceipt) (TrafficReceipt, error) {
	if provider == nil || provider.Local == nil {
		return TrafficReceipt{}, ErrInvalid
	}
	remote, err := changedRemoteTrafficNodes(change, provider.LocalNode)
	if err != nil {
		return TrafficReceipt{}, err
	}
	if len(remote) != 0 {
		return TrafficReceipt{}, ErrUnsupported
	}
	return provider.Local.CompensateConditional(ctx, change, receipt)
}

func changedRemoteTrafficNodes(change TrafficChange, local NodeID) ([]NodeID, error) {
	if change.EffectID == "" || change.Policy.ID == "" || change.Before.PolicyID != change.Policy.ID || change.Desired.PolicyID != change.Policy.ID || len(change.Before.Endpoints) == 0 || len(change.Before.Endpoints) != len(change.Desired.Endpoints) {
		return nil, ErrInvalid
	}
	changed := map[NodeID]struct{}{}
	for index := range change.Before.Endpoints {
		before, desired := change.Before.Endpoints[index], change.Desired.Endpoints[index]
		if before.NodeID != desired.NodeID || before.Address != desired.Address || before.Port != desired.Port || before.NodeID == "" {
			return nil, ErrInvalid
		}
		if before.Weight != desired.Weight || before.Healthy != desired.Healthy {
			if before.NodeID != local {
				changed[before.NodeID] = struct{}{}
			}
		}
	}
	result := make([]NodeID, 0, len(changed))
	for node := range changed {
		result = append(result, node)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result, nil
}

func orderRemoteTrafficNodes(change TrafficChange, nodes []NodeID) ([]NodeID, []NodeID) {
	delta := map[NodeID]int64{}
	for index := range change.Before.Endpoints {
		delta[change.Before.Endpoints[index].NodeID] += int64(change.Desired.Endpoints[index].Weight) - int64(change.Before.Endpoints[index].Weight)
	}
	activation := make([]NodeID, 0, len(nodes))
	deactivation := make([]NodeID, 0, len(nodes))
	for _, node := range nodes {
		if delta[node] > 0 {
			activation = append(activation, node)
		} else {
			deactivation = append(deactivation, node)
		}
	}
	return activation, deactivation
}

func validateBoundFederatedHAIntent(draft, bound federation.Intent, now time.Time) error {
	if bound.NodeID != draft.NodeID || bound.ProtocolVersion != draft.ProtocolVersion || bound.CommandType != draft.CommandType || bound.SchemaHash != draft.SchemaHash || bound.PayloadDigest != draft.PayloadDigest || string(bound.Payload) != string(draft.Payload) || bound.TenantID != draft.TenantID || bound.ResourceKind != draft.ResourceKind || bound.ResourceID != draft.ResourceID || bound.ExpectedGeneration != draft.ExpectedGeneration || bound.IdempotencyKey != draft.IdempotencyKey || bound.Risk != draft.Risk {
		return ErrForbidden
	}
	// An expired submitted intent may still have a durable terminal receipt.
	// Validate its original envelope without extending its execution authority.
	if !bound.ID.Valid() || !bound.PeerID.Valid() || !bound.GrantID.Valid() || bound.AuthorityEpoch == 0 || bound.EffectID == "" || len(bound.ActorChain) != 1 || bound.Approval == nil || bound.IssuedAt.After(now.Add(time.Minute)) || bound.Validate(bound.IssuedAt) != nil {
		return ErrForbidden
	}
	return nil
}

// FederatedHAApprovalPlanDigest is the closed transaction bound by the
// independent approval source. Central may assign the intent and effect IDs,
// so this digest covers the immutable requested semantics and fixed grant.
func FederatedHAApprovalPlanDigest(draft federation.Intent, tenant string, grant federation.ID) (string, error) {
	if !draft.NodeID.Valid() || !grant.Valid() || tenant == "" || draft.TenantID != tenant || draft.ProtocolVersion == 0 || draft.CommandType == "" || !validDigest(draft.SchemaHash) || len(draft.Payload) == 0 || len(draft.Payload) > federation.MaxFrameBytes || draft.PayloadDigest != federatedHADigest(draft.Payload) || draft.ResourceKind != "ha" || draft.ResourceID == "" || draft.ExpectedGeneration == 0 || draft.IdempotencyKey == "" || draft.Risk != federation.RiskHigh && draft.Risk != federation.RiskCritical {
		return "", ErrInvalid
	}
	payload, err := json.Marshal(struct {
		Domain              string        `json:"domain"`
		NodeID              federation.ID `json:"node_id"`
		GrantID             federation.ID `json:"grant_id"`
		ProtocolVersion     uint32        `json:"protocol_version"`
		CommandType         string        `json:"command_type"`
		SchemaHash          string        `json:"schema_hash"`
		PayloadDigest       string        `json:"payload_digest"`
		TenantID            string        `json:"tenant_id"`
		ResourceKind        string        `json:"resource_kind"`
		ResourceID          string        `json:"resource_id"`
		ExpectedGeneration uint64        `json:"expected_generation"`
		IdempotencyKey      string        `json:"idempotency_key"`
		Risk                federation.Risk `json:"risk"`
	}{FederatedHAApprovalPolicyVersion, draft.NodeID, grant, draft.ProtocolVersion, draft.CommandType, draft.SchemaHash, draft.PayloadDigest, tenant, draft.ResourceKind, draft.ResourceID, draft.ExpectedGeneration, draft.IdempotencyKey, draft.Risk})
	if err != nil {
		return "", err
	}
	return federatedHADigest(payload), nil
}

func federatedHAReceiptError(receipt federation.Receipt) error {
	code := strings.ToUpper(strings.TrimSpace(receipt.ErrorCode))
	switch {
	case receipt.Status == federation.IntentExpired, strings.Contains(code, "EXPIRED"):
		return ErrExpired
	case strings.Contains(code, "CAPABILITY"):
		return ErrUnsupported
	case strings.Contains(code, "STALE"):
		return ErrStaleGeneration
	case strings.Contains(code, "GRANT"), strings.Contains(code, "AUTHORITY"), strings.Contains(code, "SIGNATURE"), strings.Contains(code, "POLICY"):
		return ErrForbidden
	default:
		return ErrConflict
	}
}

func federatedHAReceiptEvidence(receipt federation.Receipt, err error) (string, error) {
	if err != nil {
		return "", err
	}
	encoded, encodeErr := json.Marshal(receipt)
	if encodeErr != nil || len(encoded) == 0 || len(encoded) > maximumPromotionReceiptBytes {
		return "", errors.Join(ErrInvalid, encodeErr)
	}
	return string(encoded), nil
}

func federatedHACommandSchemaHash(command string) string {
	return federatedHADigest([]byte("cyberpanel-ha-federated-schema-v1\x00" + command))
}

// FederatedHAWritePermitDigest is the result digest an owning node returns
// after its local gate has issued and verified the permit. The signed node
// receipt therefore binds the reconstructed permit without transporting a
// second receipt type alongside federation.Receipt.
func FederatedHAWritePermitDigest(lease WriterLease) string {
	paths := append([]string(nil), lease.EnforcedWritePaths...)
	sort.Strings(paths)
	payload, _ := json.Marshal(struct {
		Domain         string        `json:"domain"`
		ResourceID     string        `json:"resource_id"`
		NodeID         NodeID        `json:"node_id"`
		LeaseID        WriterLeaseID `json:"lease_id"`
		FencingToken   uint64        `json:"fencing_token"`
		AuthorityEpoch uint64        `json:"authority_epoch"`
		WritePaths     []string      `json:"write_paths"`
		ExpiresAt      time.Time     `json:"expires_at"`
	}{"cyberpanel-ha-federated-write-permit-v1", lease.ResourceID, lease.HolderNodeID, lease.ID, lease.FencingToken, lease.AuthorityEpoch, paths, lease.ExpiresAt.UTC()})
	return federatedHADigest(payload)
}

func federatedHATrafficEffectID(parent string, node NodeID) string {
	sum := sha256.Sum256([]byte("cyberpanel-ha-federated-traffic-effect-v1\x00" + parent + "\x00" + string(node)))
	return "traffic_remote_" + hex.EncodeToString(sum[:])[:48]
}

func federatedHADigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

var _ WriterGate = (*OwningNodeWriterGate)(nil)
var _ PromotionExecutor = (*OwningNodePromotionExecutor)(nil)
var _ TrafficProvider = (*OwningNodeTrafficProvider)(nil)
