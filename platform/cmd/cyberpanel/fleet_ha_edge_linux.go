//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type fleetHAEdge struct {
	repository *ha.SQLRepository
	groups     ha.GroupService
	verifier   ha.EnrollmentVerifier
	failover   ha.FailoverCoordinator
	now        func() time.Time
}

func newFleetHAEdge(repository *ha.SQLRepository, now func() time.Time) (*fleetHAEdge, error) {
	if repository == nil || repository.DB == nil {
		return nil, errors.New("fleet edge requires high-availability authority")
	}
	if now == nil {
		now = time.Now
	}
	edge := &fleetHAEdge{repository:repository, now:now}
	edge.groups = ha.GroupService{Store:*repository, Now:now}
	edge.verifier = ha.EnrollmentVerifier{Now:now}
	edge.failover = ha.FailoverCoordinator{Store:*repository, Now:now}
	return edge, nil
}

func (edge *fleetHAEdge) ListNodes(ctx context.Context, call apiserver.EdgeCall, page apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.FleetNodeProjection], error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "" {
		return apiserver.EdgePage[apiserver.FleetNodeProjection]{}, ha.ErrInvalid
	}
	values, next, total, err := edge.repository.ListAllNodes(ctx, page.Cursor, page.Limit)
	if err != nil {
		return apiserver.EdgePage[apiserver.FleetNodeProjection]{}, err
	}
	items := make([]apiserver.FleetNodeProjection, 0, len(values))
	for _, value := range values {
		items = append(items, fleetNodeProjection(value))
	}
	return apiserver.EdgePage[apiserver.FleetNodeProjection]{Items:items, NextCursor:next, Total:total}, nil
}

func (edge *fleetHAEdge) GetNode(ctx context.Context, call apiserver.EdgeCall) (apiserver.FleetNodeProjection, error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" {
		return apiserver.FleetNodeProjection{}, ha.ErrInvalid
	}
	node, err := edge.repository.LoadNode(ctx, ha.NodeID(call.ResourceID))
	if err != nil {
		return apiserver.FleetNodeProjection{}, err
	}
	return fleetNodeProjection(node), nil
}

func (edge *fleetHAEdge) TopologyStatus(ctx context.Context, call apiserver.EdgeCall) (apiserver.HATopologyStatusProjection, error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" {
		return apiserver.HATopologyStatusProjection{}, ha.ErrInvalid
	}
	selected, err := edge.repository.LoadNode(ctx, ha.NodeID(call.ResourceID))
	if err != nil {
		return apiserver.HATopologyStatusProjection{}, err
	}
	group, err := edge.repository.LoadNodeGroup(ctx, selected.GroupID)
	if err != nil {
		return apiserver.HATopologyStatusProjection{}, err
	}
	if err = group.Validate(); err != nil {
		return apiserver.HATopologyStatusProjection{}, err
	}
	nodes, err := edge.repository.ListNodes(ctx, group.ID)
	if err != nil {
		return apiserver.HATopologyStatusProjection{}, err
	}
	nodeProjections := make([]apiserver.FleetNodeProjection, 0, len(nodes))
	for _, node := range nodes {
		if err = node.Validate(); err != nil {
			return apiserver.HATopologyStatusProjection{}, err
		}
		nodeProjections = append(nodeProjections, fleetNodeProjection(node))
	}
	leases, err := edge.repository.ListActiveWriterLeases(ctx, group.ID)
	if err != nil {
		return apiserver.HATopologyStatusProjection{}, err
	}
	now := edge.now().UTC()
	authorities := make([]apiserver.HAWriterAuthorityProjection, 0, len(leases))
	for _, lease := range leases {
		paths := append([]string(nil), lease.EnforcedWritePaths...)
		sort.Strings(paths)
		authorities = append(authorities, apiserver.HAWriterAuthorityProjection{
			LeaseID:string(lease.ID), ResourceID:lease.ResourceID, HolderNodeID:string(lease.HolderNodeID), State:string(lease.State),
			EnforcedWritePaths:paths, Generation:lease.Generation, ExpiresAt:lease.ExpiresAt, Current:now.Before(lease.ExpiresAt),
		})
	}
	fenceClasses := make([]string, len(group.RequiredFenceClasses))
	for index, class := range group.RequiredFenceClasses {
		fenceClasses[index] = string(class)
	}
	sort.Strings(fenceClasses)
	return apiserver.HATopologyStatusProjection{
		ID:string(group.ID), SelectedNodeID:string(selected.ID), Name:group.Name, State:group.State, CoordinatorID:group.CoordinatorID,
		MinimumManagers:group.MinimumManagers, AutomaticFailoverConfigured:group.AutomaticFailover, RequiredFenceClasses:fenceClasses,
		Nodes:nodeProjections, WriterAuthorities:authorities, Generation:group.Generation, UpdatedAt:group.UpdatedAt,
	}, nil
}

func (edge *fleetHAEdge) NodeHealth(ctx context.Context, call apiserver.EdgeCall) (apiserver.HANodeHealthProjection, error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" {
		return apiserver.HANodeHealthProjection{}, ha.ErrInvalid
	}
	node, err := edge.repository.LoadNode(ctx, ha.NodeID(call.ResourceID))
	if err != nil {
		return apiserver.HANodeHealthProjection{}, err
	}
	observed, err := edge.repository.ListHealthObservations(ctx, node.ID)
	if err != nil {
		return apiserver.HANodeHealthProjection{}, err
	}
	now := edge.now().UTC()
	status := string(ha.HealthUnknown)
	firstFreshState, firstFreshBootID, firstFreshCapability := "", "", ""
	asymmetric := false
	var fresh, stale uint64
	observations := make([]apiserver.HAHealthObservationProjection, 0, len(observed))
	for _, observation := range observed {
		observer, loadErr := edge.repository.LoadNode(ctx, observation.ObserverNodeID)
		if loadErr != nil || observer.GroupID != node.GroupID {
			return apiserver.HANodeHealthProjection{}, ha.ErrInvalid
		}
		isFresh := now.Before(observation.ValidUntil)
		if isFresh {
			fresh++
			if firstFreshState == "" {
				firstFreshState = string(observation.State)
				firstFreshBootID = observation.BootID
				firstFreshCapability = observation.CapabilityDigest
			} else if firstFreshState != string(observation.State) || firstFreshBootID != observation.BootID || firstFreshCapability != observation.CapabilityDigest {
				asymmetric = true
			}
		} else {
			stale++
		}
		checks := make(map[string]bool, len(observation.Checks))
		for key, value := range observation.Checks {
			checks[key] = value
		}
		observations = append(observations, apiserver.HAHealthObservationProjection{
			ObserverNodeID:string(observation.ObserverNodeID), State:string(observation.State), Checks:checks, Latency:observation.Latency,
			BootID:observation.BootID, CapabilityDigest:observation.CapabilityDigest, ObservedAt:observation.ObservedAt,
			ValidUntil:observation.ValidUntil, Sequence:observation.Sequence, Fresh:isFresh,
		})
	}
	if asymmetric {
		status = "asymmetric"
	} else if firstFreshState != "" {
		status = firstFreshState
	}
	return apiserver.HANodeHealthProjection{
		ID:string(node.ID), NodeState:string(node.State), Status:status, Asymmetric:asymmetric,
		FreshObservations:fresh, StaleObservations:stale, Observations:observations, Generation:node.Generation,
	}, nil
}

func (edge *fleetHAEdge) EnrollNode(ctx context.Context, call apiserver.EdgeCall, payload apiserver.FleetEnrollPayload, token []byte) (apiserver.EdgeMutation[apiserver.FleetNodeProjection], error) {
	defer wipeFleetToken(token)
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "" || call.CommandID == "" || len(token) == 0 || strings.TrimSpace(payload.CentralFingerprint) == "" {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, ha.ErrInvalid
	}
	enrollment, err := edge.verifier.Verify(token, payload.CentralFingerprint)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, err
	}
	node, _, err := edge.repository.AdmitEnrollment(ctx, enrollment, call.CommandID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, err
	}
	projection := fleetNodeProjection(node)
	return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{OperationID:call.CommandID, State:string(node.State), Generation:node.Generation, Resource:projection}, nil
}

func (edge *fleetHAEdge) RevokeNode(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.FleetNodeProjection], error) {
	if edge == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" || call.ExpectedGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, ha.ErrInvalid
	}
	node, err := edge.groups.SetNodeState(ctx, ha.NodeID(call.ResourceID), call.ExpectedGeneration, ha.NodeRetired)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, err
	}
	projection := fleetNodeProjection(node)
	return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{OperationID:call.CommandID, State:string(node.State), Generation:node.Generation, Resource:projection}, nil
}

func (edge *fleetHAEdge) DrainNode(ctx context.Context, call apiserver.EdgeCall, payload apiserver.HANodeDrainPayload) (apiserver.EdgeMutation[apiserver.FleetNodeProjection], error) {
	if edge == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" || call.ExpectedGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, ha.ErrInvalid
	}
	node, err := edge.groups.BeginDrain(ctx, ha.NodeID(call.ResourceID), call.ExpectedGeneration, payload.Deadline, payload.Force)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, err
	}
	projection := fleetNodeProjection(node)
	return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{OperationID:call.CommandID, State:string(node.State), Generation:node.Generation, Resource:projection}, nil
}

func (edge *fleetHAEdge) PlanPromotion(ctx context.Context, call apiserver.EdgeCall, payload apiserver.HAPromotionPlanPayload) (apiserver.EdgeMutation[apiserver.HAPromotionProjection], error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" || call.CommandID == "" || call.ExpectedGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrInvalid
	}
	resourceID := call.ResourceID
	expectedLeaseGeneration := call.ExpectedGeneration
	selectedWriter := ha.NodeID("")
	if payload.ProtectedResourceID != "" {
		resourceID = payload.ProtectedResourceID
		expectedLeaseGeneration = payload.WriterLeaseGeneration
		selectedWriter = ha.NodeID(call.ResourceID)
	}
	if existing, err := edge.repository.PromotionByCommand(ctx, ha.CommandID(call.CommandID)); err == nil {
		if existing.ResourceID != resourceID || selectedWriter != "" && existing.PreviousWriter != selectedWriter || existing.Candidate != ha.NodeID(payload.CandidateNodeID) || existing.MaximumDataLoss != payload.MaximumDataLoss || existing.ExpectedGeneration != expectedLeaseGeneration {
			return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrConflict
		}
		return promotionMutation(existing, promotionPlanDigest(existing)), nil
	} else if !errors.Is(err, ha.ErrNotFound) {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	now := edge.now().UTC()
	var writer ha.NodeMember
	if selectedWriter != "" {
		var err error
		writer, err = edge.repository.LoadNode(ctx, selectedWriter)
		if err != nil {
			return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
		}
		if writer.Generation != call.ExpectedGeneration {
			return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrStaleGeneration
		}
	}
	candidate, err := edge.repository.LoadNode(ctx, ha.NodeID(payload.CandidateNodeID))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if candidate.State != ha.NodeReady {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrUnsafePromotion
	}
	lease, err := edge.repository.ActiveWriterLeaseByResource(ctx, resourceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if lease.Generation != expectedLeaseGeneration || lease.GroupID != candidate.GroupID || selectedWriter != "" && (lease.HolderNodeID != selectedWriter || writer.GroupID != lease.GroupID) || lease.HolderNodeID == candidate.ID {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrStaleGeneration
	}
	if err = lease.Validate(now); err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	channel, err := edge.repository.ChannelForResourceTarget(ctx, candidate.GroupID, resourceID, lease.HolderNodeID, candidate.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	checkpoint, err := edge.repository.LatestCheckpoint(ctx, channel.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if err = checkpoint.Validate(); err != nil || checkpoint.SourceGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrCheckpointStale
	}
	traffic, err := edge.repository.TrafficPolicyByResource(ctx, candidate.GroupID, resourceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if !promotionTrafficCovers(traffic, lease.HolderNodeID, candidate.ID) {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrUnsafePromotion
	}
	potentialLoss := checkpoint.LagDuration > 0 || checkpoint.LagBytes > 0
	blocked := checkpoint.LagDuration > payload.MaximumDataLoss || payload.MaximumDataLoss == 0 && checkpoint.LagBytes > 0
	promotion := ha.Promotion{
		ID:ha.PromotionID(fleetEffectID("promotion", call.CommandID, resourceID)), CommandID:ha.CommandID(call.CommandID), GroupID:candidate.GroupID,
		ResourceID:resourceID, PreviousWriter:lease.HolderNodeID, Candidate:candidate.ID, ExpectedGeneration:expectedLeaseGeneration,
		CheckpointID:checkpoint.ID, CheckpointFrontier:checkpoint.WriteFrontier, MaximumDataLoss:payload.MaximumDataLoss, LeaseID:lease.ID,
		TrafficPolicyID:traffic.ID, Automatic:false, PotentialDataLoss:potentialLoss, State:ha.PromotionPlanned,
		WriteFrontier:checkpoint.WriteFrontier, Generation:1, CreatedAt:now, UpdatedAt:now,
	}
	if blocked {
		promotion.State = ha.PromotionFailed
		promotion.Failure = "latest verified checkpoint exceeds the requested maximum data loss"
	}
	if err = edge.repository.CreatePromotion(ctx, promotion); err != nil {
		existing, loadErr := edge.repository.PromotionByCommand(ctx, promotion.CommandID)
		if loadErr != nil || existing.ID != promotion.ID || existing.ResourceID != promotion.ResourceID || existing.PreviousWriter != promotion.PreviousWriter || existing.Candidate != promotion.Candidate || existing.ExpectedGeneration != promotion.ExpectedGeneration || existing.MaximumDataLoss != promotion.MaximumDataLoss {
			return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
		}
		promotion = existing
	}
	return promotionMutation(promotion, promotionPlanDigest(promotion)), nil
}

func (edge *fleetHAEdge) ExecutePromotion(ctx context.Context, call apiserver.EdgeCall, payload apiserver.HAPromotionExecutePayload) (apiserver.EdgeMutation[apiserver.HAPromotionProjection], error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" || call.CommandID == "" || call.ExpectedGeneration == 0 || call.Assurance < identity.AssurancePhishingResistant || payload.PromotionID == "" || payload.WriterLeaseGeneration == 0 || payload.PlanDigest == "" {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrInvalid
	}
	selectedWriter, err := edge.repository.LoadNode(ctx, ha.NodeID(call.ResourceID))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if selectedWriter.Generation != call.ExpectedGeneration {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrStaleGeneration
	}
	promotion, err := edge.repository.LoadPromotion(ctx, ha.PromotionID(payload.PromotionID))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if promotion.PreviousWriter != selectedWriter.ID || promotion.GroupID != selectedWriter.GroupID {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrConflict
	}
	var quorum ha.QuorumObservation
	if err = json.Unmarshal([]byte(payload.QuorumEvidence), &quorum); err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrInvalid
	}
	bindings, err := parsePromotionFenceBindings(payload.FenceProviderBindings)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	runID := ha.FailoverRunID(fleetEffectID("failover", string(promotion.ID), promotion.ResourceID))
	request := ha.PromotionExecutionRequest{
		PromotionID:promotion.ID, RunID:runID, ExpectedLeaseGeneration:payload.WriterLeaseGeneration,
		Approval:ha.PromotionApprovalEvidence{
			CommandID:ha.CommandID(call.CommandID), ActorID:call.PrincipalID, CredentialID:call.CredentialID,
			SessionID:call.SessionID, AuthzEpoch:call.AuthzEpoch, PlanDigest:payload.PlanDigest,
			PhishingResistant:call.Assurance >= identity.AssurancePhishingResistant, ApprovedAt:edge.now().UTC(),
		},
		Quorum:quorum, FenceProviderBindings:bindings,
	}
	promotion, run, executeErr := edge.failover.Execute(ctx, request)
	if executeErr != nil && !errors.Is(executeErr, ha.ErrReconciliationRequired) {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, executeErr
	}
	return promotionExecutionMutation(promotion, run), nil
}

func fleetNodeProjection(node ha.NodeMember) apiserver.FleetNodeProjection {
	roles := make([]string, len(node.Roles))
	for index := range node.Roles {
		roles[index] = string(node.Roles[index])
	}
	sort.Strings(roles)
	name := strings.TrimSpace(node.Labels["name"])
	if name == "" {
		name = string(node.ID)
	}
	version := strings.TrimSpace(node.Labels["product_version"])
	if version == "" && len(node.Capabilities.VersionDigest) >= 12 {
		version = node.Capabilities.VersionDigest[:12]
	}
	return apiserver.FleetNodeProjection{ID:string(node.ID), Name:name, State:string(node.State), Roles:roles, Architecture:node.Capabilities.Architecture, Version:version, FailureDomain:node.FailureDomain, LastSeenAt:node.Capabilities.ObservedAt, Generation:node.Generation}
}

func promotionMutation(promotion ha.Promotion, digest string) apiserver.EdgeMutation[apiserver.HAPromotionProjection] {
	state := string(promotion.State)
	if promotion.State == ha.PromotionFailed && promotion.Failure != "" {
		state = "blocked"
	} else if promotion.PotentialDataLoss {
		state = "requires_approval"
	}
	projection := apiserver.HAPromotionProjection{
		ID:string(promotion.ID), ResourceID:promotion.ResourceID, PreviousWriterNodeID:string(promotion.PreviousWriter), CandidateNodeID:string(promotion.Candidate),
		WriterLeaseGeneration:promotion.ExpectedGeneration, MaximumDataLoss:promotion.MaximumDataLoss, PotentialDataLoss:promotion.PotentialDataLoss,
		PlanDigest:digest, State:state, Failure:promotion.Failure, Generation:promotion.Generation,
	}
	return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{OperationID:string(promotion.CommandID), State:state, Generation:promotion.Generation, Resource:projection}
}

func promotionPlanDigest(promotion ha.Promotion) string {
	digest, _ := ha.PromotionPlanDigest(promotion)
	return digest
}

func promotionExecutionMutation(promotion ha.Promotion, run ha.FailoverRun) apiserver.EdgeMutation[apiserver.HAPromotionProjection] {
	effects := make([]apiserver.HAPromotionEffectProjection, len(run.Effects))
	for index, receipt := range run.Effects {
		effects[index] = apiserver.HAPromotionEffectProjection{
			Sequence:receipt.Sequence, EffectID:receipt.EffectID, Kind:receipt.Kind, Outcome:string(receipt.Outcome),
			ReceiptDigest:receipt.ReceiptDigest, Frontier:receipt.Frontier, Irreversible:receipt.Irreversible,
			Failure:receipt.Failure, StartedAt:receipt.StartedAt, CompletedAt:receipt.CompletedAt,
		}
	}
	projection := apiserver.HAPromotionProjection{
		ID:string(promotion.ID), ResourceID:promotion.ResourceID, PreviousWriterNodeID:string(promotion.PreviousWriter), CandidateNodeID:string(promotion.Candidate),
		WriterLeaseGeneration:promotion.ExpectedGeneration, MaximumDataLoss:promotion.MaximumDataLoss, PotentialDataLoss:promotion.PotentialDataLoss,
		PlanDigest:run.PlanDigest, State:string(run.State), RunID:string(run.ID), Step:run.Step, Effects:effects,
		ReconciliationRequired:run.ReconciliationRequired, ReconciliationReason:run.ReconciliationReason,
		Failure:run.Failure, Generation:promotion.Generation,
	}
	return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{OperationID:string(run.Approval.CommandID), State:string(run.State), Generation:promotion.Generation, Resource:projection}
}

func parsePromotionFenceBindings(value string) (map[ha.FenceClass]string, error) {
	result := map[ha.FenceClass]string{}
	for _, line := range strings.Split(strings.TrimSpace(value), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			return nil, ha.ErrInvalid
		}
		class := ha.FenceClass(strings.TrimSpace(parts[0]))
		switch class {
		case ha.FencePower, ha.FenceStorage, ha.FenceDatabase, ha.FenceMandatoryLease, ha.FenceAdministrative:
		default:
			return nil, ha.ErrInvalid
		}
		if _, duplicate := result[class]; duplicate {
			return nil, ha.ErrConflict
		}
		result[class] = strings.TrimSpace(parts[1])
	}
	return result, nil
}

func promotionTrafficCovers(policy ha.TrafficPolicy, previous, candidate ha.NodeID) bool {
	if policy.ID == "" || policy.Resource == "" || policy.Generation == 0 || policy.ProviderBindingID == "" {
		return false
	}
	previousFound, candidateFound := false, false
	for _, endpoint := range policy.Endpoints {
		if endpoint.NodeID == previous {
			previousFound = true
		}
		if endpoint.NodeID == candidate {
			candidateFound = true
		}
	}
	return previousFound && candidateFound
}

func fleetEffectID(kind, commandID, resourceID string) string {
	sum := sha256.Sum256([]byte("cyberpanel-fleet-edge-v1\x00" + kind + "\x00" + commandID + "\x00" + resourceID))
	return kind + "_" + hex.EncodeToString(sum[:])[:48]
}

func wipeFleetToken(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ apiserver.FleetEdgeService = (*fleetHAEdge)(nil)
var _ apiserver.HAEdgeService = (*fleetHAEdge)(nil)
