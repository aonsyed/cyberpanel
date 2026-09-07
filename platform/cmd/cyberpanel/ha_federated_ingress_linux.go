//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

const haFederationIngressPath = "/etc/cyberpanel/ha/federated-ingress.json"

type haIngressTrust struct {
	TenantID string `json:"tenant_id"`
	NodeID federation.ID `json:"node_id"`
	PeerID federation.ID `json:"peer_id"`
	GroupID ha.NodeGroupID `json:"group_id"`
	GrantKeys map[string][]byte `json:"grant_keys"`
	ApprovalKeys map[string][]byte `json:"approval_keys"`
	GrantIDs []federation.ID `json:"grant_ids"`
}

type haIngressPayload struct {
	kind string
	raw json.RawMessage
	gate ha.FederatedMariaDBWriterGatePayload
	promotion ha.FederatedMariaDBPromotionPayload
	traffic ha.FederatedOLSListenerPayload
	activationToken uint64
}

type federatedHAIngress struct {
	db *sql.DB
	store *federation.Store
	repository ha.SQLRepository
	gate ha.WriterGate
	promotion ha.PromotionExecutor
	traffic *localOLSListenerTrafficProvider
	nodeID, peerID federation.ID
	now func() time.Time
}

func init() {
	federationIngressFactory = func(ctx context.Context, db *sql.DB, node, peer federation.ID, providers *localMariaDBHAProviders, now func() time.Time) (federationRuntimeIngress, error) {
		ingress, err := newFederatedHAIngress(ctx, db, node, peer, providers, now)
		if ingress == nil { return nil, err }
		return ingress, err
	}
}

func newFederatedHAIngress(ctx context.Context, db *sql.DB, node, peer federation.ID, providers *localMariaDBHAProviders, now func() time.Time) (*federatedHAIngress, error) {
	if _, err := readHAFederationProtectedFile(haFederationIngressPath, false); errors.Is(err, os.ErrNotExist) { return nil, nil } else if err != nil { return nil, err }
	if ctx == nil || db == nil || providers == nil || !node.Valid() || !peer.Valid() { return nil, ha.ErrInvalid }
	gate, gateOK := providers.gate.(*ha.OwningNodeWriterGate)
	promotion, promotionOK := providers.promotion.(*ha.OwningNodePromotionExecutor)
	traffic, trafficOK := providers.traffic.(*ha.OwningNodeTrafficProvider)
	if !gateOK || !promotionOK || !trafficOK || gate.Local == nil || promotion.Local == nil || traffic.Local == nil { return nil, ha.ErrUnsupported }
	localTraffic, ok := traffic.Local.(*localOLSListenerTrafficProvider)
	if !ok { return nil, ha.ErrUnsupported }
	store, err := federation.NewStore(db)
	if err != nil { return nil, err }
	if now == nil { now = time.Now }
	ingress := &federatedHAIngress{db: db, store: store, repository: ha.SQLRepository{DB: db}, gate: gate.Local, promotion: promotion.Local, traffic: localTraffic, nodeID: node, peerID: peer, now: now}
	if _, err = ingress.trust(ctx); err != nil { return nil, err }
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ha_federated_ingress_effects_v1 (
	 effect_id TEXT PRIMARY KEY, intent_id TEXT NOT NULL UNIQUE,
	 request_digest TEXT NOT NULL, intent_json BLOB NOT NULL,
	 result_json BLOB, claimed_at TIMESTAMP NOT NULL
	);
	CREATE TABLE IF NOT EXISTS ha_federated_ingress_fences_v1 (
	 resource_id TEXT PRIMARY KEY, authority_epoch INTEGER NOT NULL,
	 fencing_token INTEGER NOT NULL, blocked_token INTEGER NOT NULL
	)`)
	if err != nil { return nil, err }
	return ingress, nil
}

func (ingress *federatedHAIngress) Capabilities() []federation.Capability { return ha.FederatedHACommandCapabilities() }

func (ingress *federatedHAIngress) Capability(command string) (federation.Capability, bool) {
	for _, capability := range ingress.Capabilities() { if capability.CommandType == command { return capability, true } }
	return federation.Capability{}, false
}

func (ingress *federatedHAIngress) Decode(command, schema string, raw json.RawMessage) (any, error) {
	capability, ok := ingress.Capability(command)
	if !ok || schema != capability.SchemaHash || len(raw) == 0 || len(raw) > 1<<20 { return nil, ha.ErrUnsupported }
	payload := &haIngressPayload{kind: command, raw: append(json.RawMessage(nil), raw...)}
	var target any
	switch command {
	case ha.FederatedMariaDBGateFreezeCommand, ha.FederatedMariaDBGateActivateCommand, ha.FederatedMariaDBGateRevokeCommand: target = &payload.gate
	case ha.FederatedMariaDBPromotionFreezeCommand, ha.FederatedMariaDBPromotionActivateCommand, ha.FederatedMariaDBPromotionDemoteCommand, ha.FederatedMariaDBPromotionProbeCommand: target = &payload.promotion
	case ha.FederatedOLSListenerApplyCommand: target = &payload.traffic
	default: return nil, ha.ErrUnsupported
	}
	if decodeHAFederationJSON(raw, target) != nil { return nil, ha.ErrInvalid }
	return payload, nil
}

func (ingress *federatedHAIngress) trust(ctx context.Context) (haIngressTrust, error) {
	var trust haIngressTrust
	if ingress == nil || ctx == nil { return trust, ha.ErrInvalid }
	raw, err := readHAFederationProtectedFile(haFederationIngressPath, false)
	if err != nil || decodeHAFederationJSON(raw, &trust) != nil { return trust, ha.ErrForbidden }
	node, _, peer, err := ingress.store.State(ctx)
	if err != nil || node != ingress.nodeID || peer != ingress.peerID || trust.NodeID != node || trust.PeerID != peer || trust.TenantID != "system" || trust.GroupID == "" || len(trust.GrantIDs) == 0 || len(trust.GrantIDs) > 128 || len(trust.GrantKeys) == 0 || len(trust.GrantKeys) > 16 || len(trust.ApprovalKeys) == 0 || len(trust.ApprovalKeys) > 16 { return trust, ha.ErrForbidden }
	for _, keys := range []map[string][]byte{trust.GrantKeys, trust.ApprovalKeys} { for id, key := range keys { if !federation.ID(id).Valid() || len(key) != ed25519.PublicKeySize { return trust, ha.ErrForbidden } } }
	for _, id := range trust.GrantIDs { if !id.Valid() { return trust, ha.ErrForbidden } }
	return trust, nil
}

func (ingress *federatedHAIngress) VerifyGrant(ctx context.Context, grant federation.MutationGrant) error {
	trust, err := ingress.trust(ctx)
	if err != nil { return err }
	_, epoch, _, err := ingress.store.State(ctx)
	if err != nil || grant.Validate(ingress.now().UTC()) != nil || grant.NodeID != trust.NodeID || grant.PeerID != trust.PeerID || grant.AuthorityEpoch != epoch || grant.IssuedAt.After(ingress.now().UTC()) || grant.MaximumRisk != federation.RiskCritical { return ha.ErrForbidden }
	allowed := false
	for _, id := range trust.GrantIDs { if id == grant.ID { allowed = true } }
	if !allowed { return ha.ErrForbidden }
	message, err := ha.FederatedHAGrantSignaturePayload(grant)
	key := trust.GrantKeys[grant.SignatureKeyID]
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(key), message, grant.Signature) { return ha.ErrForbidden }
	for _, selector := range grant.Selectors {
		if selector.TenantID != trust.TenantID || selector.Kind != "ha" || selector.ResourceID != ha.LocalMariaDBResourceID || selector.LabelSelector != "" || len(selector.Operations) == 0 { return ha.ErrForbidden }
		for _, command := range selector.Operations { if _, ok := ingress.Capability(command); !ok { return ha.ErrForbidden } }
	}
	return nil
}

func (ingress *federatedHAIngress) VerifyApproval(ctx context.Context, intent federation.Intent) error {
	trust, err := ingress.trust(ctx)
	if err != nil { return err }
	if intent.TenantID != trust.TenantID || intent.NodeID != trust.NodeID || intent.PeerID != trust.PeerID || intent.Approval == nil || !ingress.now().UTC().Before(intent.Approval.ExpiresAt) { return ha.ErrForbidden }
	plan, err := ha.FederatedHAApprovalPlanDigest(intent, trust.TenantID, intent.GrantID)
	if err != nil || intent.Approval.PlanDigest != plan { return ha.ErrForbidden }
	message, err := ha.FederatedHAApprovalSignaturePayload(*intent.Approval)
	key := trust.ApprovalKeys[intent.Approval.SigningKeyID]
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(key), message, intent.Approval.Signature) { return ha.ErrForbidden }
	return nil
}

func (ingress *federatedHAIngress) AuthorizeFederated(ctx context.Context, intent federation.Intent, grant federation.MutationGrant, decoded any) error {
	payload, ok := decoded.(*haIngressPayload)
	if !ok || payload == nil || payload.kind != intent.CommandType || !bytes.Equal(payload.raw, intent.Payload) || intent.ResourceKind != "ha" || intent.ResourceID != ha.LocalMariaDBResourceID || intent.ExpectedGeneration == 0 || intent.Risk != federation.RiskCritical || len(intent.ActorChain) != 1 || intent.ActorChain[0].TenantID != intent.TenantID || intent.ActorChain[0].PrincipalID == "" || intent.ActorChain[0].AuthzEpoch == 0 || intent.ActorChain[0].Assurance != "phishing_resistant" && intent.ActorChain[0].Assurance != "hardware_bound" { return ha.ErrForbidden }
	if err := ingress.VerifyGrant(ctx, grant); err != nil { return err }
	if grant.ID != intent.GrantID || grant.AuthorityEpoch != intent.AuthorityEpoch { return ha.ErrForbidden }
	if err := ingress.VerifyApproval(ctx, intent); err != nil { return err }
	allowed := false
	for _, selector := range grant.Selectors { for _, command := range selector.Operations { if command == intent.CommandType { allowed = true } } }
	if !allowed { return ha.ErrForbidden }
	trust, err := ingress.trust(ctx)
	if err != nil { return err }
	member, err := ingress.repository.LoadNode(ctx, ha.NodeID(ingress.nodeID))
	if err != nil || member.GroupID != trust.GroupID || member.State == ha.NodeRetired || member.State == ha.NodeJoining { return ha.ErrForbidden }
	cluster, err := ingress.repository.LoadDatabaseCluster(ctx, ha.ID(intent.ResourceID))
	if err != nil || cluster.Validate() != nil || cluster.GroupID != trust.GroupID || cluster.Topology != ha.DatabasePrimaryReplica { return ha.ErrForbidden }
	// The domain and executor use a fixed owning-node alias. No remote member
	// can be relabeled into that alias, and an existing alias collision is denied.
	localMembers := 0
	for _, member := range cluster.Members { if member.NodeID == "local" { localMembers++ }; if ingress.nodeID != "local" && member.NodeID == ha.NodeID(ingress.nodeID) { return ha.ErrForbidden } }
	if localMembers != 1 { return ha.ErrForbidden }
	switch payload.kind {
	case ha.FederatedMariaDBGateFreezeCommand:
		p := payload.gate
		if p.ResourceID != intent.ResourceID || p.NodeID != ha.NodeID(ingress.nodeID) || p.FencingToken != intent.ExpectedGeneration || p.FencingToken == 0 || p.Lease != nil || p.Permit != nil || !haIngressWritePaths(p.WritePaths) { return ha.ErrForbidden }
	case ha.FederatedMariaDBGateActivateCommand:
		p := payload.gate
		if p.Lease == nil || p.Permit != nil || len(p.WritePaths) != 0 || p.ResourceID != intent.ResourceID || p.NodeID != ha.NodeID(ingress.nodeID) || p.Lease.Generation != intent.ExpectedGeneration || p.Lease.FencingToken != p.FencingToken { return ha.ErrForbidden }
		if err = ingress.validateLease(*p.Lease, trust); err != nil { return err }
		if err = ingress.requireLeaseFences(ctx, *p.Lease, trust); err != nil { return err }
	case ha.FederatedMariaDBGateRevokeCommand:
		p := payload.gate
		if p.Permit == nil || p.Lease != nil || len(p.WritePaths) != 0 || p.NodeID != ha.NodeID(ingress.nodeID) || p.ResourceID != intent.ResourceID || p.FencingToken != intent.ExpectedGeneration || p.FencingToken == 0 || p.Permit.NodeID != p.NodeID || p.Permit.ResourceID != p.ResourceID || p.Permit.FencingToken != p.FencingToken || p.Permit.Signature == "" || !haIngressWritePaths(p.Permit.WritePaths) { return ha.ErrForbidden }
	case ha.FederatedMariaDBPromotionFreezeCommand, ha.FederatedMariaDBPromotionDemoteCommand, ha.FederatedMariaDBPromotionActivateCommand, ha.FederatedMariaDBPromotionProbeCommand:
		p := payload.promotion
		if p.Promotion.ID == "" || p.Promotion.ResourceID != intent.ResourceID || p.Promotion.GroupID != trust.GroupID || p.Promotion.Generation != intent.ExpectedGeneration || p.Promotion.Candidate == p.Promotion.PreviousWriter || p.Promotion.CheckpointFrontier == 0 { return ha.ErrForbidden }
		if ingress.nodeID != "local" && (p.Promotion.Candidate == "local" || p.Promotion.PreviousWriter == "local") { return ha.ErrForbidden }
		stored, loadErr := ingress.repository.LoadPromotion(ctx, p.Promotion.ID)
		if loadErr != nil || !haIngressSameJSON(stored, p.Promotion) { return ha.ErrForbidden }
		if payload.kind == ha.FederatedMariaDBPromotionFreezeCommand || payload.kind == ha.FederatedMariaDBPromotionDemoteCommand {
			if p.Promotion.PreviousWriter != ha.NodeID(ingress.nodeID) || p.FencingToken == 0 || p.Lease != nil { return ha.ErrForbidden }
		} else {
			if p.Promotion.Candidate != ha.NodeID(ingress.nodeID) || p.FencingToken != 0 { return ha.ErrForbidden }
			if payload.kind == ha.FederatedMariaDBPromotionActivateCommand {
				if p.Lease == nil || p.Lease.ID != p.Promotion.LeaseID || ingress.validateLease(*p.Lease, trust) != nil { return ha.ErrForbidden }
				if err = ingress.requireLeaseFences(ctx, *p.Lease, trust); err != nil { return err }
			} else if p.Lease != nil { return ha.ErrForbidden }
		}
	case ha.FederatedOLSListenerApplyCommand:
		p := payload.traffic
		if p.TargetNodeID != ha.NodeID(ingress.nodeID) || p.Change.Policy.Resource != intent.ResourceID || p.Change.Policy.GroupID != trust.GroupID || p.Change.Policy.Generation != intent.ExpectedGeneration || p.Change.EffectID == "" || p.Change.Policy.Kind != ha.LocalOLSListenerTrafficKind || p.Change.Policy.ProviderBindingID != ha.LocalOLSListenerProviderBinding || p.Change.Policy.ProviderMode != ha.TrafficAtomicCAS { return ha.ErrForbidden }
		stored, loadErr := ingress.repository.LoadTrafficPolicy(ctx, p.Change.Policy.ID)
		if loadErr != nil || !haIngressSameJSON(stored, p.Change.Policy) { return ha.ErrForbidden }
		mapped, mappingErr := ingress.localTrafficChange(p.Change)
		if mappingErr != nil { return mappingErr }
		activating, mappingErr := desiredLocalListenerState(mapped.Desired.Endpoints)
		if mappingErr != nil { return mappingErr }
		if activating {
			lease, leaseErr := ingress.repository.ActiveWriterLeaseByResource(ctx, intent.ResourceID)
			if leaseErr != nil || ingress.validateLease(lease, trust) != nil { return ha.ErrLeaseLost }
			if err = ingress.requireLeaseFences(ctx, lease, trust); err != nil { return err }
			payload.activationToken = lease.FencingToken
		}
		if err != nil { return err }
	default: return ha.ErrUnsupported
	}
	return nil
}

func (ingress *federatedHAIngress) validateLease(lease ha.WriterLease, trust haIngressTrust) error {
	if lease.Validate(ingress.now().UTC()) != nil || lease.State != ha.LeaseActive || lease.HolderNodeID != ha.NodeID(ingress.nodeID) || lease.ResourceID != ha.LocalMariaDBResourceID || lease.GroupID != trust.GroupID || !haIngressWritePaths(lease.EnforcedWritePaths) { return ha.ErrLeaseLost }
	return nil
}

func (ingress *federatedHAIngress) requireLeaseFences(ctx context.Context, lease ha.WriterLease, trust haIngressTrust) error {
	// The approved wire lease must already be admitted to the local HA domain.
	// Federation transport does not mint a lease or replace quorum/fence admission.
	stored, err := ingress.repository.LoadLease(ctx, lease.ID)
	if err != nil || !haIngressSameJSON(stored, lease) { return ha.ErrLeaseLost }
	group, err := ingress.repository.LoadNodeGroup(ctx, trust.GroupID)
	if err != nil || len(group.RequiredFenceClasses) == 0 { return ha.ErrFenceFailed }
	rows, err := ingress.db.QueryContext(ctx, `SELECT promotion_json FROM ha_promotions WHERE group_id=? AND resource_id=? AND state NOT IN ('committed','rolled_back','failed') LIMIT 2`, trust.GroupID, lease.ResourceID)
	if err != nil { return err }
	var promotion ha.Promotion
	count := 0
	for rows.Next() {
		var raw []byte
		count++
		if count > 1 || rows.Scan(&raw) != nil || json.Unmarshal(raw, &promotion) != nil { rows.Close(); return ha.ErrFenceFailed }
	}
	err = rows.Err()
	rows.Close()
	if err != nil { return err }
	// The coordinator records LeaseID on the promotion after gate activation;
	// an empty value at that one boundary is not a different lease authority.
	if count != 1 || promotion.LeaseID != "" && promotion.LeaseID != lease.ID || promotion.Candidate != lease.HolderNodeID || promotion.PreviousWriter == promotion.Candidate || !federation.ID(promotion.PreviousWriter).Valid() || len(promotion.FenceIDs) == 0 { return ha.ErrFenceFailed }
	classes := map[ha.FenceClass]bool{}
	for _, id := range promotion.FenceIDs {
		fence, fenceErr := ingress.repository.LoadFence(ctx, id)
		if fenceErr != nil || fence.GroupID != trust.GroupID || fence.TargetNodeID != promotion.PreviousWriter || fence.State != ha.FenceProven || fence.Validate(ingress.now().UTC()) != nil || fence.FencingToken != lease.FencingToken || fence.AuthorityEpoch != lease.AuthorityEpoch || !haIngressSamePaths(fence.ProtectedWritePaths, lease.EnforcedWritePaths) { return ha.ErrFenceFailed }
		classes[fence.Class] = true
	}
	for _, class := range group.RequiredFenceClasses { if !classes[class] { return ha.ErrFenceFailed } }
	return nil
}

func (ingress *federatedHAIngress) SubmitFederated(ctx context.Context, command federation.FederatedCommand) (federation.LocalResult, error) {
	ambiguous := federation.LocalResult{Status: federation.IntentAmbiguous, ErrorCode: "HA_EFFECT_UNRESOLVED"}
	if ingress == nil || ctx == nil || command.Origin != federation.OriginFederation || !command.IntentID.Valid() || command.EffectID == "" { return ambiguous, ha.ErrForbidden }
	unlock, lockErr := lockHAFederatedEffects(ctx)
	if lockErr != nil { return ambiguous, lockErr }
	defer unlock()
	// Reload the exact intent already accepted by Agent. This prevents a caller
	// from constructing an unvalidated flattened gateway command.
	var raw []byte
	if err := ingress.db.QueryRowContext(ctx, `SELECT intent_json FROM federation_intents WHERE id=? AND effect_id=?`, command.IntentID, command.EffectID).Scan(&raw); err != nil { return ambiguous, err }
	var intent federation.Intent
	if decodeHAFederationJSON(raw, &intent) != nil || intent.Validate(ingress.now().UTC()) != nil || intent.PeerID != command.PeerID || intent.TenantID != command.TenantID || intent.ResourceKind != command.ResourceKind || intent.ResourceID != command.ResourceID || intent.ExpectedGeneration != command.ExpectedGeneration || intent.IdempotencyKey != command.IdempotencyKey || intent.Risk != command.Risk || !haIngressSameJSON(intent.ActorChain, command.ActorChain) || !haIngressSameJSON(intent.Approval, command.Approval) { return ambiguous, ha.ErrForbidden }
	payload, err := ingress.Decode(intent.CommandType, intent.SchemaHash, intent.Payload)
	if err != nil { return ambiguous, err }
	passed, ok := command.Payload.(*haIngressPayload)
	if !ok || passed == nil || passed.kind != intent.CommandType || !bytes.Equal(passed.raw, intent.Payload) { return ambiguous, ha.ErrForbidden }
	grant, err := ingress.store.Grant(ctx, intent.GrantID)
	if err != nil { return ambiguous, err }
	if err = ingress.AuthorizeFederated(ctx, intent, grant, payload); err != nil { return ambiguous, err }
	digest := haSenderDigest(intent.SigStructure())
	tx, err := ingress.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return ambiguous, err }
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ha_federated_ingress_effects_v1(effect_id,intent_id,request_digest,intent_json,claimed_at) VALUES(?,?,?,?,?)`, intent.EffectID, intent.ID, digest, raw, ingress.now().UTC())
	if err != nil { return ambiguous, err }
	count, err := result.RowsAffected()
	if err != nil { return ambiguous, err }
	if count != 1 {
		if err = tx.Rollback(); err != nil { return ambiguous, err }
		var existing string
		if ingress.db.QueryRowContext(ctx, `SELECT request_digest FROM ha_federated_ingress_effects_v1 WHERE effect_id=? AND intent_id=?`, intent.EffectID, intent.ID).Scan(&existing) != nil || existing != digest { return ambiguous, ha.ErrConflict }
		return ingress.ObserveEffect(ctx, intent.EffectID)
	}
	if err = ingress.advanceFence(ctx, tx, intent, payload.(*haIngressPayload)); err != nil { return ambiguous, err }
	if err = tx.Commit(); err != nil { return ambiguous, err }
	applied, err := ingress.execute(ctx, intent, payload.(*haIngressPayload))
	if err != nil { return ambiguous, err }
	encoded, err := json.Marshal(applied)
	if err != nil { return ambiguous, err }
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	result, err = ingress.db.ExecContext(saveCtx, `UPDATE ha_federated_ingress_effects_v1 SET result_json=? WHERE effect_id=? AND request_digest=? AND result_json IS NULL`, encoded, intent.EffectID, digest)
	if err != nil { return ambiguous, err }
	count, err = result.RowsAffected()
	if err != nil || count != 1 { return ambiguous, ha.ErrReconciliationRequired }
	return applied, nil
}

func (ingress *federatedHAIngress) advanceFence(ctx context.Context, tx *sql.Tx, intent federation.Intent, payload *haIngressPayload) error {
	var token uint64
	blocks, activates := false, false
	switch payload.kind {
	case ha.FederatedMariaDBGateFreezeCommand, ha.FederatedMariaDBGateRevokeCommand: token, blocks = payload.gate.FencingToken, true
	case ha.FederatedMariaDBGateActivateCommand: token, activates = payload.gate.FencingToken, true
	case ha.FederatedMariaDBPromotionFreezeCommand, ha.FederatedMariaDBPromotionDemoteCommand: token, blocks = payload.promotion.FencingToken, true
	case ha.FederatedMariaDBPromotionActivateCommand: token, activates = payload.promotion.Lease.FencingToken, true
	case ha.FederatedOLSListenerApplyCommand:
		if payload.activationToken == 0 { return nil }
		token, activates = payload.activationToken, true
	default: return nil // probes are read-only; listener mutation uses generation CAS
	}
	if token == 0 { return ha.ErrFenceFailed }
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ha_federated_ingress_fences_v1(resource_id,authority_epoch,fencing_token,blocked_token) VALUES(?,0,0,0)`, intent.ResourceID); err != nil { return err }
	var epoch, current, blocked uint64
	if err := tx.QueryRowContext(ctx, `SELECT authority_epoch,fencing_token,blocked_token FROM ha_federated_ingress_fences_v1 WHERE resource_id=?`, intent.ResourceID).Scan(&epoch, &current, &blocked); err != nil { return err }
	if intent.AuthorityEpoch < epoch || token < current || activates && token <= blocked { return ha.ErrFenceFailed }
	if blocks { blocked = token }
	_, err := tx.ExecContext(ctx, `UPDATE ha_federated_ingress_fences_v1 SET authority_epoch=?,fencing_token=?,blocked_token=? WHERE resource_id=?`, intent.AuthorityEpoch, token, blocked, intent.ResourceID)
	return err
}

func (ingress *federatedHAIngress) execute(ctx context.Context, intent federation.Intent, payload *haIngressPayload) (federation.LocalResult, error) {
	result := federation.LocalResult{OperationID: intent.EffectID, Generation: intent.ExpectedGeneration, Status: federation.IntentApplied, Terminal: true}
	var evidence string
	var err error
	switch payload.kind {
	case ha.FederatedMariaDBGateFreezeCommand:
		evidence, err = ingress.gate.FreezeResourceWrites(ctx, intent.ResourceID, "local", payload.gate.FencingToken, payload.gate.WritePaths)
	case ha.FederatedMariaDBGateActivateCommand:
		lease := *payload.gate.Lease
		lease.HolderNodeID = "local"
		var permit ha.WritePermit
		permit, err = ingress.gate.ActivateResourceWrites(ctx, lease)
		if err == nil && permit.Signature != "" { evidence = permit.Signature; result.ResultDigest = ha.FederatedHAWritePermitDigest(*payload.gate.Lease) }
	case ha.FederatedMariaDBGateRevokeCommand:
		permit := *payload.gate.Permit
		permit.NodeID = "local"
		err = ingress.gate.RevokeWritePermit(ctx, permit)
		if err == nil {
			localGate, ok := ingress.gate.(*ha.LocalMariaDBWriterGate)
			if !ok { return federation.LocalResult{}, ha.ErrUnsupported }
			cluster, loadErr := ingress.repository.LoadDatabaseCluster(ctx, ha.ID(intent.ResourceID))
			if loadErr != nil { return federation.LocalResult{}, loadErr }
			observed, observeErr := localGate.Executor.ObserveCluster(ctx, cluster)
			if observeErr != nil { return federation.LocalResult{}, observeErr }
			for _, member := range observed.Members { if member.NodeID == "local" && member.ReadOnly { raw, _ := json.Marshal(observed); evidence = string(raw) } }
		}
	case ha.FederatedMariaDBPromotionFreezeCommand, ha.FederatedMariaDBPromotionDemoteCommand, ha.FederatedMariaDBPromotionActivateCommand, ha.FederatedMariaDBPromotionProbeCommand:
		promotion := payload.promotion.Promotion
		if promotion.PreviousWriter == ha.NodeID(ingress.nodeID) { promotion.PreviousWriter = "local" }
		if promotion.Candidate == ha.NodeID(ingress.nodeID) { promotion.Candidate = "local" }
		switch payload.kind {
		case ha.FederatedMariaDBPromotionFreezeCommand: evidence, err = ingress.promotion.FreezeWorkloadWrites(ctx, promotion, payload.promotion.FencingToken)
		case ha.FederatedMariaDBPromotionDemoteCommand: evidence, err = ingress.promotion.DemotePreviousServices(ctx, promotion, payload.promotion.FencingToken)
		case ha.FederatedMariaDBPromotionActivateCommand:
			lease := *payload.promotion.Lease
			lease.HolderNodeID = "local"
			evidence, result.Generation, err = ingress.promotion.ActivateCandidateServices(ctx, promotion, lease)
		case ha.FederatedMariaDBPromotionProbeCommand: evidence, err = ingress.promotion.ProbeCandidate(ctx, promotion)
		}
	case ha.FederatedOLSListenerApplyCommand:
		change, mappingErr := ingress.localTrafficChange(payload.traffic.Change)
		if mappingErr != nil { return federation.LocalResult{}, mappingErr }
		var receipt ha.TrafficReceipt
		receipt, err = ingress.traffic.ApplyConditional(ctx, change)
		if err == nil && receipt.OutputDigest == change.Desired.Digest && receipt.EffectID == change.EffectID { evidence = receipt.ProviderReceipt; result.ResultDigest = payload.traffic.Change.Desired.Digest }
	default: return federation.LocalResult{}, ha.ErrUnsupported
	}
	if err != nil || evidence == "" || result.Generation == 0 { return federation.LocalResult{}, errors.Join(ha.ErrReconciliationRequired, err) }
	if result.ResultDigest == "" { result.ResultDigest = haSenderDigest([]byte(evidence)) }
	return result, nil
}

func (ingress *federatedHAIngress) ObserveEffect(ctx context.Context, effect string) (federation.LocalResult, error) {
	ambiguous := federation.LocalResult{Status: federation.IntentAmbiguous, ErrorCode: "HA_EFFECT_UNRESOLVED"}
	if ingress == nil || ctx == nil || effect == "" { return ambiguous, ha.ErrInvalid }
	var raw []byte
	if err := ingress.db.QueryRowContext(ctx, `SELECT result_json FROM ha_federated_ingress_effects_v1 WHERE effect_id=?`, effect).Scan(&raw); err != nil { return ambiguous, errors.Join(ha.ErrReconciliationRequired, err) }
	if len(raw) == 0 { return ambiguous, ha.ErrReconciliationRequired }
	var result federation.LocalResult
	if decodeHAFederationJSON(raw, &result) != nil || result.OperationID != effect || result.Status != federation.IntentApplied || !result.Terminal || result.Generation == 0 || !haSenderValidDigest(result.ResultDigest) { return ambiguous, ha.ErrReconciliationRequired }
	return result, nil
}

func (ingress *federatedHAIngress) localTrafficChange(original ha.TrafficChange) (ha.TrafficChange, error) {
	if original.Before.Digest != trafficEndpointDigest(original.Before.Endpoints) || original.Desired.Digest != trafficEndpointDigest(original.Desired.Endpoints) { return ha.TrafficChange{}, ha.ErrForbidden }
	change := original
	change.Policy.Endpoints = append([]ha.TrafficEndpoint(nil), original.Policy.Endpoints...)
	change.Before.Endpoints = append([]ha.TrafficEndpoint(nil), original.Before.Endpoints...)
	change.Desired.Endpoints = append([]ha.TrafficEndpoint(nil), original.Desired.Endpoints...)
	for _, endpoints := range [][]ha.TrafficEndpoint{change.Policy.Endpoints, change.Before.Endpoints, change.Desired.Endpoints} {
		localPorts := map[uint16]bool{}
		for index := range endpoints {
			endpoint := &endpoints[index]
			if ingress.nodeID != "local" && endpoint.NodeID == "local" { return ha.TrafficChange{}, ha.ErrForbidden }
			if endpoint.NodeID != ha.NodeID(ingress.nodeID) { continue }
			if localPorts[endpoint.Port] || endpoint.Port != 80 && endpoint.Port != 443 { return ha.TrafficChange{}, ha.ErrForbidden }
			localPorts[endpoint.Port] = true
			endpoint.NodeID = "local"
		}
		if len(localPorts) != 2 { return ha.TrafficChange{}, ha.ErrForbidden }
	}
	change.Before.Digest = trafficEndpointDigest(change.Before.Endpoints)
	change.Desired.Digest = trafficEndpointDigest(change.Desired.Endpoints)
	change.Policy.DesiredDigest = change.Desired.Digest
	if change.Policy.ObservedDigest != "" { change.Policy.ObservedDigest = change.Before.Digest }
	return change, nil
}

func haIngressSameJSON(left, right any) bool { a, errA := json.Marshal(left); b, errB := json.Marshal(right); return errA == nil && errB == nil && bytes.Equal(a, b) }
func haIngressSamePaths(left, right []string) bool { a, b := append([]string(nil), left...), append([]string(nil), right...); sort.Strings(a); sort.Strings(b); return haIngressSameJSON(a, b) }
func haIngressWritePaths(paths []string) bool {
	if len(paths) == 0 || len(paths) > 16 { return false }
	seen := map[string]bool{}
	for _, path := range paths { if path == "" || len(path) > 256 || seen[path] { return false }; seen[path] = true }
	return true
}

// Serialize the fenced transition across runner recomposition and processes.
// The durable claim is committed while this lock is held and before execution.
// A later worker cannot pass a newer fence while an earlier effect still runs.
func lockHAFederatedEffects(ctx context.Context) (func(), error) {
	const path = "/var/lib/cyberpanel/control/ha-federated-effects.lock"
	for _, parent := range []string{"/var", "/var/lib", "/var/lib/cyberpanel", "/var/lib/cyberpanel/control"} {
		info, err := os.Lstat(parent)
		if err != nil { return nil, err }
		uid := haApprovalFileUID(info)
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || uid != 0 && uid != uint32(os.Geteuid()) { return nil, ha.ErrForbidden }
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil { return nil, err }
	info, err := file.Stat()
	if err != nil { file.Close(); return nil, err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 { file.Close(); return nil, ha.ErrForbidden }
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil { return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil }
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) { file.Close(); return nil, err }
		timer := time.NewTimer(50*time.Millisecond)
		select { case <-ctx.Done(): timer.Stop(); file.Close(); return nil, ctx.Err(); case <-timer.C: }
	}
}

var _ federation.SchemaRegistry = (*federatedHAIngress)(nil)
var _ federation.AuthorityVerifier = (*federatedHAIngress)(nil)
var _ federation.LocalPolicy = (*federatedHAIngress)(nil)
var _ federation.CommandGateway = (*federatedHAIngress)(nil)
