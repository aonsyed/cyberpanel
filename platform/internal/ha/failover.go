package ha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const promotionLeaseLifetime = 2 * time.Minute
const maximumPromotionReceiptBytes = 64 << 10

type PromotionExecutionRequest struct {
	PromotionID             PromotionID                `json:"promotion_id"`
	RunID                   FailoverRunID              `json:"run_id"`
	ExpectedLeaseGeneration uint64                     `json:"expected_lease_generation"`
	Approval                PromotionApprovalEvidence `json:"approval"`
	Quorum                  QuorumObservation         `json:"quorum"`
	FenceProviderBindings   map[FenceClass]string      `json:"fence_provider_bindings,omitempty"`
}

func (request PromotionExecutionRequest) Validate(now time.Time) error {
	if !validID(string(request.PromotionID)) || !validID(string(request.RunID)) || request.ExpectedLeaseGeneration == 0 || len(request.FenceProviderBindings) > 5 {
		return ErrInvalid
	}
	if !validID(string(request.Approval.CommandID)) || !validID(request.Approval.ActorID) || !validID(request.Approval.CredentialID) || request.Approval.SessionID != "" && !validID(request.Approval.SessionID) || request.Approval.AuthzEpoch == 0 || !validDigest(request.Approval.PlanDigest) || !request.Approval.PhishingResistant || request.Approval.ApprovedAt.IsZero() || request.Approval.ApprovedAt.After(now.Add(time.Minute)) || now.Sub(request.Approval.ApprovedAt) > 5*time.Minute {
		return ErrDataLossApproval
	}
	if err := request.Quorum.Validate(now); err != nil {
		return err
	}
	for class, binding := range request.FenceProviderBindings {
		if !validFenceClass(class) || !validID(binding) {
			return ErrInvalid
		}
	}
	return nil
}

type FailoverCoordinator struct {
	Store          Store
	Health         HealthAuthority
	Leases         LeaseAuthority
	Gate           WriterGate
	FenceProviders map[FenceClass]FenceProvider
	ManualFence    ManualFenceConfirmer
	Traffic        TrafficProvider
	Executor       PromotionExecutor
	Database       DatabaseReplicationExecutor
	Backup         BackupConsistency
	Now            func() time.Time
}

func (coordinator FailoverCoordinator) now() time.Time {
	if coordinator.Now != nil {
		return coordinator.Now().UTC()
	}
	return time.Now().UTC()
}

// Execute runs an already persisted, manual, zero-lag promotion plan. It never
// derives authority from reachability and never probes health. Each mutating
// provider call is durably admitted before invocation and completed with its
// exact bounded receipt before the next effect starts.
func (coordinator FailoverCoordinator) Execute(ctx context.Context, request PromotionExecutionRequest) (Promotion, FailoverRun, error) {
	if coordinator.Store == nil || ctx == nil || !validID(string(request.PromotionID)) || !validID(string(request.RunID)) {
		return Promotion{}, FailoverRun{}, ErrInvalid
	}
	promotion, err := coordinator.Store.LoadPromotion(ctx, request.PromotionID)
	if err != nil {
		return Promotion{}, FailoverRun{}, err
	}
	if existing, loadErr := coordinator.Store.LoadFailoverRun(ctx, request.RunID); loadErr == nil {
		if existing.PromotionID != promotion.ID || existing.PlanDigest != request.Approval.PlanDigest {
			return Promotion{}, FailoverRun{}, ErrConflict
		}
		if existing.State == PromotionCommitted {
			return promotion, existing, nil
		}
		if existing.State == PromotionFailed {
			return promotion, existing, ErrConflict
		}
		if existing.State == PromotionReconciliation || existing.ReconciliationRequired {
			return promotion, existing, ErrReconciliationRequired
		}
		if promotion.State == PromotionCommitted {
			existing.State = PromotionReconciliation
			existing.Step = "commit_receipt"
			existing.ReconciliationRequired = true
			existing.ReconciliationReason = "promotion committed but the terminal run receipt is incomplete"
			existing.UpdatedAt = coordinator.now()
			_ = coordinator.Store.UpdateFailoverRun(ctx, existing)
			return promotion, existing, ErrReconciliationRequired
		}
		return coordinator.reconcile(ctx, promotion, existing, -1, "interrupted_execution", ErrReconciliationRequired)
	} else if !errors.Is(loadErr, ErrNotFound) {
		return Promotion{}, FailoverRun{}, loadErr
	}
	now := coordinator.now()
	if err = request.Validate(now); err != nil {
		return Promotion{}, FailoverRun{}, err
	}
	planDigest, err := PromotionPlanDigest(promotion)
	if err != nil {
		return Promotion{}, FailoverRun{}, err
	}
	if request.Approval.PlanDigest != planDigest || promotion.State != PromotionPlanned || promotion.Automatic || promotion.PotentialDataLoss {
		return Promotion{}, FailoverRun{}, ErrUnsafePromotion
	}
	authority, err := coordinator.promotionAuthority(ctx, promotion, now)
	if err != nil {
		return Promotion{}, FailoverRun{}, err
	}
	if request.ExpectedLeaseGeneration != promotion.ExpectedGeneration || authority.Generation != request.ExpectedLeaseGeneration || promotion.LeaseID != authority.ID {
		return Promotion{}, FailoverRun{}, ErrStaleGeneration
	}
	checkpoint, err := coordinator.Store.LoadCheckpoint(ctx, promotion.CheckpointID)
	if err != nil {
		return Promotion{}, FailoverRun{}, err
	}
	if err = checkpoint.Validate(); err != nil || checkpoint.WriteFrontier != promotion.CheckpointFrontier || checkpoint.LagBytes != 0 || checkpoint.LagDuration != 0 {
		return Promotion{}, FailoverRun{}, ErrCheckpointStale
	}
	group, err := coordinator.Store.LoadNodeGroup(ctx, promotion.GroupID)
	if err != nil {
		return Promotion{}, FailoverRun{}, err
	}
	if err = group.Validate(); err != nil || request.Quorum.GroupID != group.ID {
		return Promotion{}, FailoverRun{}, ErrNoQuorum
	}
	policy, err := coordinator.Store.LoadTrafficPolicy(ctx, promotion.TrafficPolicyID)
	if err != nil {
		return Promotion{}, FailoverRun{}, err
	}
	if !trafficPolicyCoversPromotion(policy, promotion) {
		return Promotion{}, FailoverRun{}, ErrUnsafePromotion
	}
	if err = coordinator.requireExecutionPrimitives(group, promotion, request); err != nil {
		return Promotion{}, FailoverRun{}, err
	}

	run := FailoverRun{
		ID: request.RunID, PromotionID: promotion.ID, PlanDigest: planDigest, Approval: request.Approval,
		HealthQuorumDigest: request.Quorum.Digest, State: PromotionChecking, Step: "preflight", Attempt: 1,
		StartedAt: now, UpdatedAt: now,
	}
	if err = coordinator.Store.CreateFailoverRun(ctx, run); err != nil {
		return Promotion{}, FailoverRun{}, err
	}
	if err = coordinator.setPromotionState(ctx, &promotion, PromotionChecking); err != nil {
		return coordinator.stopBeforeEffect(ctx, promotion, run, "preflight", err)
	}

	nextToken := authority.FencingToken + 1
	if nextToken == 0 {
		return coordinator.stopBeforeEffect(ctx, promotion, run, "fencing_token", ErrConflict)
	}
	paths := append([]string(nil), authority.EnforcedWritePaths...)
	sort.Strings(paths)
	fencePlans := coordinator.fencePlans(group, promotion, request, paths, nextToken, authority.AuthorityEpoch)
	fenceReceipts := make([]FenceReceipt, 0, len(fencePlans))
	if err = coordinator.setPromotionState(ctx, &promotion, PromotionFencing); err != nil {
		return coordinator.stopBeforeEffect(ctx, promotion, run, "fence_previous_writer", err)
	}
	for _, plan := range fencePlans {
		index, beginErr := coordinator.beginEffect(ctx, &run, PromotionFencing, "fence."+string(plan.Class), true)
		if beginErr != nil {
			return promotion, run, beginErr
		}
		receipt, effectErr := coordinator.applyFence(ctx, plan, request.Quorum, promotion, planDigest)
		if effectErr != nil {
			if receipt.FenceID != "" || receipt.ProviderReceipt != "" {
				attachPromotionEffectReceipt(&run, index, receipt)
			}
			return coordinator.reconcile(ctx, promotion, run, index, "fence_previous_writer", effectErr)
		}
		evidence, evidenceErr := promotionReceiptJSON(receipt)
		if evidenceErr != nil {
			return coordinator.reconcile(ctx, promotion, run, index, "fence_receipt", evidenceErr)
		}
		if effectErr = coordinator.completeEffect(ctx, &run, index, evidence, 0, true); effectErr != nil {
			return coordinator.reconcile(ctx, promotion, run, index, "fence_receipt", effectErr)
		}
		fenceReceipts = append(fenceReceipts, receipt)
	}
	if err = validateFenceCoverage(fenceReceipts, paths, coordinator.now()); err != nil {
		return coordinator.reconcile(ctx, promotion, run, -1, "fence_coverage", err)
	}
	if err = coordinator.validatePersistedFenceReceipts(ctx, fencePlans, fenceReceipts, coordinator.now()); err != nil {
		return coordinator.reconcile(ctx, promotion, run, -1, "fence_receipt", err)
	}
	run.FenceProofDigest, err = digestFenceReceipts(fenceReceipts)
	if err != nil {
		return coordinator.reconcile(ctx, promotion, run, -1, "fence_digest", err)
	}
	if err = coordinator.Store.UpdateFailoverRun(ctx, run); err != nil {
		return coordinator.reconcile(ctx, promotion, run, -1, "fence_receipt", err)
	}
	currentAuthority, authorityErr := coordinator.promotionAuthority(ctx, promotion, coordinator.now())
	if authorityErr != nil || currentAuthority.ID != authority.ID || currentAuthority.Generation != authority.Generation || currentAuthority.FencingToken != authority.FencingToken || currentAuthority.AuthorityEpoch != authority.AuthorityEpoch || !currentAuthority.ExpiresAt.Equal(authority.ExpiresAt) {
		return coordinator.reconcile(ctx, promotion, run, -1, "current_writer_lease", errors.Join(ErrStaleGeneration, authorityErr))
	}
	promotion.FenceIDs = make([]FenceID, len(fenceReceipts))
	for index := range fenceReceipts {
		promotion.FenceIDs[index] = fenceReceipts[index].FenceID
	}
	if err = coordinator.setPromotionState(ctx, &promotion, PromotionFenced); err != nil {
		return coordinator.reconcile(ctx, promotion, run, -1, "persist_fenced_state", err)
	}

	if err = coordinator.setPromotionState(ctx, &promotion, PromotionPromoting); err != nil {
		return coordinator.reconcile(ctx, promotion, run, -1, "writer_transition", err)
	}
	gateIndex, beginErr := coordinator.beginEffect(ctx, &run, PromotionPromoting, "writer.freeze_gate", true)
	if beginErr != nil {
		return promotion, run, beginErr
	}
	gateReceipt, effectErr := coordinator.Gate.FreezeResourceWrites(ctx, promotion.ResourceID, promotion.PreviousWriter, nextToken, paths)
	if effectErr != nil || gateReceipt == "" {
		attachPromotionEffectReceipt(&run, gateIndex, gateReceipt)
		return coordinator.reconcile(ctx, promotion, run, gateIndex, "freeze_writer_gate", errors.Join(effectErr, emptyReceiptError(gateReceipt)))
	}
	if err = coordinator.completeEffect(ctx, &run, gateIndex, gateReceipt, checkpoint.WriteFrontier, true); err != nil {
		return coordinator.reconcile(ctx, promotion, run, gateIndex, "freeze_writer_gate", err)
	}

	freezeIndex, beginErr := coordinator.beginEffect(ctx, &run, PromotionPromoting, "writer.freeze_workload", true)
	if beginErr != nil {
		return promotion, run, beginErr
	}
	workloadReceipt, effectErr := coordinator.Executor.FreezeWorkloadWrites(ctx, promotion, nextToken)
	if effectErr != nil || workloadReceipt == "" {
		attachPromotionEffectReceipt(&run, freezeIndex, workloadReceipt)
		return coordinator.reconcile(ctx, promotion, run, freezeIndex, "freeze_workload_writer", errors.Join(effectErr, emptyReceiptError(workloadReceipt)))
	}
	if err = coordinator.completeEffect(ctx, &run, freezeIndex, workloadReceipt, checkpoint.WriteFrontier, true); err != nil {
		return coordinator.reconcile(ctx, promotion, run, freezeIndex, "freeze_workload_writer", err)
	}

	revokeIndex, beginErr := coordinator.beginEffect(ctx, &run, PromotionPromoting, "writer.revoke_previous_lease", true)
	if beginErr != nil {
		return promotion, run, beginErr
	}
	if effectErr = coordinator.Leases.RevokeWriterLease(ctx, authority.ID, authority.FencingToken, authority.AuthorityEpoch); effectErr != nil {
		return coordinator.reconcile(ctx, promotion, run, revokeIndex, "revoke_previous_lease", effectErr)
	}
	observedRevocation, effectErr := coordinator.Leases.ObserveWriterLease(ctx, authority.ID)
	if effectErr != nil || observedRevocation.ID != authority.ID || observedRevocation.State != LeaseRevoked && observedRevocation.State != LeaseExpired && observedRevocation.State != LeaseLost {
		if observedRevocation.ID != "" {
			attachPromotionEffectReceipt(&run, revokeIndex, observedRevocation)
		}
		return coordinator.reconcile(ctx, promotion, run, revokeIndex, "observe_previous_lease", errors.Join(effectErr, ErrLeaseLost))
	}
	revoked := authority
	revoked.State = observedRevocation.State
	revoked.Generation++
	if err = coordinator.Store.UpdateLease(ctx, revoked, authority.Generation); err != nil {
		return coordinator.reconcile(ctx, promotion, run, revokeIndex, "persist_previous_lease", err)
	}
	revocationReceipt, evidenceErr := promotionReceiptJSON(observedRevocation)
	if evidenceErr != nil {
		return coordinator.reconcile(ctx, promotion, run, revokeIndex, "previous_lease_receipt", evidenceErr)
	}
	if err = coordinator.completeEffect(ctx, &run, revokeIndex, revocationReceipt, checkpoint.WriteFrontier, true); err != nil {
		return coordinator.reconcile(ctx, promotion, run, revokeIndex, "previous_lease_receipt", err)
	}

	leaseNow := coordinator.now()
	proposedLease := WriterLease{
		ID: WriterLeaseID(promotionEffectID("lease", string(promotion.ID), string(request.RunID))), GroupID: promotion.GroupID,
		ResourceID: promotion.ResourceID, HolderNodeID: promotion.Candidate, EnforcedWritePaths: paths,
		FencingToken: nextToken, AuthorityEpoch: authority.AuthorityEpoch, QuorumDigest: request.Quorum.Digest,
		IssuedAt: leaseNow, RenewAfter: leaseNow.Add(promotionLeaseLifetime / 2), ExpiresAt: leaseNow.Add(promotionLeaseLifetime),
		State: LeasePending, Generation: 1,
	}
	leaseIndex, beginErr := coordinator.beginEffect(ctx, &run, PromotionPromoting, "writer.acquire_candidate_lease", true)
	if beginErr != nil {
		return promotion, run, beginErr
	}
	activeLease, effectErr := coordinator.Leases.AcquireWriterLease(ctx, proposedLease, request.Quorum)
	if effectErr != nil || !samePromotionLease(activeLease, proposedLease) || activeLease.State != LeaseActive || activeLease.Validate(coordinator.now()) != nil {
		if activeLease.ID != "" {
			attachPromotionEffectReceipt(&run, leaseIndex, activeLease)
		}
		return coordinator.reconcile(ctx, promotion, run, leaseIndex, "acquire_candidate_lease", errors.Join(effectErr, ErrLeaseLost))
	}
	if err = coordinator.Store.CreateLease(ctx, activeLease); err != nil {
		return coordinator.reconcile(ctx, promotion, run, leaseIndex, "persist_candidate_lease", err)
	}
	leaseReceipt, evidenceErr := promotionReceiptJSON(activeLease)
	if evidenceErr != nil {
		return coordinator.reconcile(ctx, promotion, run, leaseIndex, "candidate_lease_receipt", evidenceErr)
	}
	if err = coordinator.completeEffect(ctx, &run, leaseIndex, leaseReceipt, checkpoint.WriteFrontier, true); err != nil {
		return coordinator.reconcile(ctx, promotion, run, leaseIndex, "candidate_lease_receipt", err)
	}

	permitIndex, beginErr := coordinator.beginEffect(ctx, &run, PromotionPromoting, "writer.activate_gate", true)
	if beginErr != nil {
		return promotion, run, beginErr
	}
	permit, effectErr := coordinator.Gate.ActivateResourceWrites(ctx, activeLease)
	if effectErr != nil || !validPromotionPermit(permit, activeLease, coordinator.now()) {
		if permit.LeaseID != "" {
			attachPromotionEffectReceipt(&run, permitIndex, permit)
		}
		return coordinator.reconcile(ctx, promotion, run, permitIndex, "activate_candidate_gate", errors.Join(effectErr, ErrLeaseLost))
	}
	permitReceipt, evidenceErr := promotionReceiptJSON(permit)
	if evidenceErr != nil {
		return coordinator.reconcile(ctx, promotion, run, permitIndex, "candidate_gate_receipt", evidenceErr)
	}
	if err = coordinator.completeEffect(ctx, &run, permitIndex, permitReceipt, checkpoint.WriteFrontier, true); err != nil {
		return coordinator.reconcile(ctx, promotion, run, permitIndex, "candidate_gate_receipt", err)
	}
	promotion.LeaseID = activeLease.ID
	promotion.Irreversible = true
	if err = coordinator.persistPromotion(ctx, &promotion); err != nil {
		return coordinator.reconcile(ctx, promotion, run, permitIndex, "persist_writer_frontier", err)
	}

	activateIndex, beginErr := coordinator.beginEffect(ctx, &run, PromotionPromoting, "writer.activate_candidate", true)
	if beginErr != nil {
		return promotion, run, beginErr
	}
	activationReceipt, frontier, effectErr := coordinator.Executor.ActivateCandidateServices(ctx, promotion, activeLease)
	if effectErr != nil || activationReceipt == "" || frontier < checkpoint.WriteFrontier {
		attachPromotionEffectReceipt(&run, activateIndex, activationReceipt)
		run.Effects[activateIndex].Frontier = frontier
		return coordinator.reconcile(ctx, promotion, run, activateIndex, "activate_candidate", errors.Join(effectErr, emptyReceiptError(activationReceipt), ErrIrreversibleFrontier))
	}
	if err = coordinator.completeEffect(ctx, &run, activateIndex, activationReceipt, frontier, true); err != nil {
		return coordinator.reconcile(ctx, promotion, run, activateIndex, "candidate_activation_receipt", err)
	}
	if frontier > promotion.WriteFrontier {
		promotion.WriteFrontier = frontier
	}
	promotion.Irreversible = true
	if err = coordinator.persistPromotion(ctx, &promotion); err != nil {
		return coordinator.reconcile(ctx, promotion, run, activateIndex, "persist_writer_frontier", err)
	}

	before, observeErr := coordinator.Traffic.Observe(ctx, policy)
	if observeErr != nil || !validTrafficObservation(before, policy) {
		return coordinator.reconcile(ctx, promotion, run, -1, "observe_traffic", errors.Join(observeErr, ErrProviderAmbiguous))
	}
	desired := buildTrafficDesired(policy, before, promotion.Candidate, promotion.PreviousWriter, coordinator.now())
	change := TrafficChange{Policy: policy, EffectID: promotionEffectID("traffic", string(promotion.ID), string(request.RunID)), Before: before, Desired: desired}
	if err = coordinator.setPromotionState(ctx, &promotion, PromotionRouting); err != nil {
		return coordinator.reconcile(ctx, promotion, run, -1, "traffic_transition", err)
	}
	run.TrafficBeforeDigest = before.Digest
	trafficIndex, beginErr := coordinator.beginEffect(ctx, &run, PromotionRouting, "traffic.cutover", true)
	if beginErr != nil {
		return promotion, run, beginErr
	}
	var trafficReceipt TrafficReceipt
	if policy.ProviderMode == TrafficAtomicCAS {
		trafficReceipt, effectErr = coordinator.Traffic.ApplyConditional(ctx, change)
	} else {
		trafficReceipt, effectErr = coordinator.Traffic.ApplyObserve(ctx, change)
	}
	if effectErr != nil || trafficReceipt.PolicyID != policy.ID || trafficReceipt.EffectID != change.EffectID || trafficReceipt.BeforeDigest != before.Digest || trafficReceipt.OutputDigest != desired.Digest || validateTrafficReceipt(trafficReceipt) != nil {
		if trafficReceipt.EffectID != "" || trafficReceipt.ProviderReceipt != "" {
			attachPromotionEffectReceipt(&run, trafficIndex, trafficReceipt)
		}
		return coordinator.reconcile(ctx, promotion, run, trafficIndex, "traffic_cutover", errors.Join(effectErr, ErrProviderAmbiguous))
	}
	run.TrafficAfterDigest = trafficReceipt.OutputDigest
	run.ProviderRevision = trafficReceipt.Revision
	trafficEvidence, evidenceErr := promotionReceiptJSON(trafficReceipt)
	if evidenceErr != nil {
		return coordinator.reconcile(ctx, promotion, run, trafficIndex, "traffic_receipt", evidenceErr)
	}
	if err = coordinator.completeEffect(ctx, &run, trafficIndex, trafficEvidence, promotion.WriteFrontier, true); err != nil {
		return coordinator.reconcile(ctx, promotion, run, trafficIndex, "traffic_receipt", err)
	}

	demoteIndex, beginErr := coordinator.beginEffect(ctx, &run, PromotionRouting, "writer.demote_previous", true)
	if beginErr != nil {
		return promotion, run, beginErr
	}
	demotionReceipt, effectErr := coordinator.Executor.DemotePreviousServices(ctx, promotion, activeLease.FencingToken)
	if effectErr != nil || demotionReceipt == "" {
		attachPromotionEffectReceipt(&run, demoteIndex, demotionReceipt)
		return coordinator.reconcile(ctx, promotion, run, demoteIndex, "demote_previous_writer", errors.Join(effectErr, emptyReceiptError(demotionReceipt)))
	}
	if err = coordinator.completeEffect(ctx, &run, demoteIndex, demotionReceipt, promotion.WriteFrontier, true); err != nil {
		return coordinator.reconcile(ctx, promotion, run, demoteIndex, "demote_previous_writer", err)
	}

	if err = coordinator.setPromotionState(ctx, &promotion, PromotionCommitted); err != nil {
		return coordinator.reconcile(ctx, promotion, run, -1, "commit_promotion", err)
	}
	run.State = PromotionCommitted
	run.Step = "committed"
	run.Failure = ""
	run.CompletedAt = coordinator.now()
	run.UpdatedAt = run.CompletedAt
	if err = coordinator.Store.UpdateFailoverRun(ctx, run); err != nil {
		run.State = PromotionReconciliation
		run.Step = "commit_receipt"
		run.ReconciliationRequired = true
		run.ReconciliationReason = err.Error()
		run.Failure = err.Error()
		run.UpdatedAt = coordinator.now()
		_ = coordinator.Store.UpdateFailoverRun(ctx, run)
		return promotion, run, errors.Join(ErrReconciliationRequired, err)
	}
	return promotion, run, nil
}

func (coordinator FailoverCoordinator) requireExecutionPrimitives(group NodeGroup, promotion Promotion, request PromotionExecutionRequest) error {
	missing := make([]string, 0, 8)
	if coordinator.Leases == nil {
		missing = append(missing, "quorum-backed writer lease authority")
	}
	if coordinator.Gate == nil {
		missing = append(missing, "mandatory writer gate")
	}
	if coordinator.Executor == nil {
		missing = append(missing, "node service promotion executor")
	}
	if coordinator.Traffic == nil {
		missing = append(missing, "traffic provider")
	}
	for _, class := range group.RequiredFenceClasses {
		if class == FenceAdministrative {
			if coordinator.ManualFence == nil {
				missing = append(missing, "administrative fence confirmer")
			}
			if len(promotion.Approvals) == 0 {
				missing = append(missing, "independently signed administrative fence approval")
			}
			continue
		}
		provider := coordinator.FenceProviders[class]
		if provider == nil || provider.Class() != class {
			missing = append(missing, string(class)+" fence provider")
		}
		if request.FenceProviderBindings[class] == "" {
			missing = append(missing, string(class)+" fence provider binding")
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return fmt.Errorf("%w: %s", ErrUnsupported, strings.Join(missing, ", "))
	}
	return nil
}

func (coordinator FailoverCoordinator) fencePlans(group NodeGroup, promotion Promotion, request PromotionExecutionRequest, paths []string, token, authorityEpoch uint64) []Fence {
	classes := append([]FenceClass(nil), group.RequiredFenceClasses...)
	sort.Slice(classes, func(left, right int) bool { return classes[left] < classes[right] })
	plans := make([]Fence, 0, len(classes))
	for _, class := range classes {
		plans = append(plans, Fence{
			ID: FenceID(promotionEffectID("fence-"+string(class), string(promotion.ID), string(request.RunID))),
			GroupID: promotion.GroupID, TargetNodeID: promotion.PreviousWriter, Class: class,
			ProtectedWritePaths: append([]string(nil), paths...), ProviderBindingID: request.FenceProviderBindings[class],
			FencingToken: token, AuthorityEpoch: authorityEpoch, Challenge: request.Approval.PlanDigest,
			State: FencePlanned, Generation: 1,
		})
	}
	return plans
}

func (coordinator FailoverCoordinator) applyFence(ctx context.Context, plan Fence, quorum QuorumObservation, promotion Promotion, approvalDigest string) (FenceReceipt, error) {
	if plan.State != FencePlanned {
		return FenceReceipt{}, ErrConflict
	}
	if err := coordinator.Store.SaveFence(ctx, plan, 0); err != nil {
		return FenceReceipt{}, err
	}
	request := FenceRequest{Fence: plan, Quorum: quorum, ApprovalDigest: approvalDigest}
	var receipt FenceReceipt
	var err error
	if plan.Class == FenceAdministrative {
		receipt, err = coordinator.ManualFence.VerifyAdministrativeFence(ctx, plan, promotion.Approvals)
	} else {
		provider := coordinator.FenceProviders[plan.Class]
		receipt, err = provider.Fence(ctx, request)
		if err == nil {
			receipt, err = provider.Observe(ctx, request, receipt)
		}
	}
	if err != nil {
		return receipt, err
	}
	if err = validateFenceReceiptAgainstPlan(plan, receipt, coordinator.now()); err != nil {
		return receipt, err
	}
	previous := plan.Generation
	plan.State = FenceProven
	plan.ProofDigest = receipt.ProofDigest
	plan.ProviderReceipt = receipt.ProviderReceipt
	plan.AppliedAt = receipt.AppliedAt
	plan.ValidUntil = receipt.ValidUntil
	plan.Generation++
	if err = coordinator.Store.SaveFence(ctx, plan, previous); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func (coordinator FailoverCoordinator) promotionAuthority(ctx context.Context, promotion Promotion, now time.Time) (WriterLease, error) {
	authority, err := coordinator.Store.ActiveWriterLeaseByResource(ctx, promotion.ResourceID)
	if errors.Is(err, ErrNotFound) {
		return WriterLease{}, ErrLeaseLost
	}
	if err != nil {
		return WriterLease{}, err
	}
	if authority.Generation != promotion.ExpectedGeneration {
		return WriterLease{}, ErrStaleGeneration
	}
	if authority.GroupID != promotion.GroupID || authority.ResourceID != promotion.ResourceID || authority.HolderNodeID != promotion.PreviousWriter {
		return WriterLease{}, ErrSplitBrainRisk
	}
	if authority.State != LeaseActive || !now.Before(authority.ExpiresAt) {
		return WriterLease{}, ErrLeaseLost
	}
	if err = authority.Validate(now); err != nil {
		return WriterLease{}, err
	}
	return authority, nil
}

func (coordinator FailoverCoordinator) validatePersistedFenceReceipts(ctx context.Context, plans []Fence, receipts []FenceReceipt, now time.Time) error {
	if len(plans) == 0 || len(plans) != len(receipts) {
		return ErrFenceRequired
	}
	planByID := make(map[FenceID]Fence, len(plans))
	for _, plan := range plans {
		if _, exists := planByID[plan.ID]; exists {
			return ErrConflict
		}
		planByID[plan.ID] = plan
	}
	seen := make(map[FenceID]struct{}, len(receipts))
	for _, receipt := range receipts {
		plan, exists := planByID[receipt.FenceID]
		if !exists {
			return ErrFenceFailed
		}
		if _, duplicate := seen[receipt.FenceID]; duplicate {
			return ErrFenceFailed
		}
		seen[receipt.FenceID] = struct{}{}
		if err := validateFenceReceiptAgainstPlan(plan, receipt, now); err != nil {
			return err
		}
		stored, err := coordinator.Store.LoadFence(ctx, receipt.FenceID)
		if err != nil {
			return err
		}
		if stored.State != FenceProven || stored.Generation != plan.Generation+1 || stored.GroupID != plan.GroupID || stored.TargetNodeID != plan.TargetNodeID || stored.Class != plan.Class || stored.FencingToken != plan.FencingToken || stored.AuthorityEpoch != plan.AuthorityEpoch || stored.ProofDigest != receipt.ProofDigest || stored.ProviderReceipt != receipt.ProviderReceipt || !stored.AppliedAt.Equal(receipt.AppliedAt) || !stored.ValidUntil.Equal(receipt.ValidUntil) || !sameProtectedWritePaths(stored.ProtectedWritePaths, receipt.ProtectedWritePaths) {
			return ErrFenceFailed
		}
		if err = stored.Validate(now); err != nil {
			return err
		}
	}
	return nil
}

func validateFenceReceiptAgainstPlan(plan Fence, receipt FenceReceipt, now time.Time) error {
	if receipt.FenceID != plan.ID || receipt.TargetNodeID != plan.TargetNodeID || receipt.Class != plan.Class || receipt.FencingToken != plan.FencingToken || !validDigest(receipt.ProofDigest) || receipt.ProviderReceipt == "" || receipt.AppliedAt.IsZero() || receipt.AppliedAt.After(now) || !receipt.ValidUntil.After(receipt.AppliedAt) || !now.Before(receipt.ValidUntil) || !sameProtectedWritePaths(plan.ProtectedWritePaths, receipt.ProtectedWritePaths) {
		return ErrFenceFailed
	}
	return nil
}

func sameProtectedWritePaths(left, right []string) bool {
	if len(left) == 0 || len(left) != len(right) {
		return false
	}
	values := make(map[string]struct{}, len(left))
	for _, value := range left {
		if value == "" {
			return false
		}
		if _, duplicate := values[value]; duplicate {
			return false
		}
		values[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := values[value]; !exists {
			return false
		}
		delete(values, value)
	}
	return len(values) == 0
}

func (coordinator FailoverCoordinator) setPromotionState(ctx context.Context, promotion *Promotion, state PromotionState) error {
	promotion.State = state
	return coordinator.persistPromotion(ctx, promotion)
}

func (coordinator FailoverCoordinator) persistPromotion(ctx context.Context, promotion *Promotion) error {
	previous := promotion.Generation
	next := *promotion
	next.Generation++
	next.UpdatedAt = coordinator.now()
	if err := coordinator.Store.UpdatePromotion(ctx, next, previous); err != nil {
		return err
	}
	*promotion = next
	return nil
}

func (coordinator FailoverCoordinator) beginEffect(ctx context.Context, run *FailoverRun, state PromotionState, kind string, irreversible bool) (int, error) {
	now := coordinator.now()
	sequence := uint32(len(run.Effects) + 1)
	run.Effects = append(run.Effects, PromotionEffectReceipt{
		Sequence: sequence, EffectID: promotionEffectID(kind, string(run.ID), fmt.Sprint(sequence)), Kind: kind,
		Outcome: PromotionEffectPending, Irreversible: irreversible, StartedAt: now,
	})
	run.State = state
	run.Step = kind
	run.UpdatedAt = now
	if err := coordinator.Store.UpdateFailoverRun(ctx, *run); err != nil {
		run.State = PromotionReconciliation
		run.Step = "persist_effect_intent"
		run.ReconciliationRequired = true
		run.ReconciliationReason = err.Error()
		return -1, errors.Join(ErrReconciliationRequired, err)
	}
	return len(run.Effects) - 1, nil
}

func (coordinator FailoverCoordinator) completeEffect(ctx context.Context, run *FailoverRun, index int, receipt string, frontier uint64, irreversible bool) error {
	if index < 0 || index >= len(run.Effects) || run.Effects[index].Outcome != PromotionEffectPending || receipt == "" || len(receipt) > maximumPromotionReceiptBytes {
		return ErrInvalid
	}
	sum := sha256.Sum256([]byte(receipt))
	run.Effects[index].Outcome = PromotionEffectConfirmed
	run.Effects[index].Receipt = receipt
	run.Effects[index].ReceiptDigest = hex.EncodeToString(sum[:])
	run.Effects[index].Frontier = frontier
	run.Effects[index].Irreversible = irreversible
	run.Effects[index].CompletedAt = coordinator.now()
	run.UpdatedAt = run.Effects[index].CompletedAt
	return coordinator.Store.UpdateFailoverRun(ctx, *run)
}

func (coordinator FailoverCoordinator) stopBeforeEffect(ctx context.Context, promotion Promotion, run FailoverRun, step string, cause error) (Promotion, FailoverRun, error) {
	promotion.State = PromotionFailed
	promotion.Failure = cause.Error()
	_ = coordinator.persistPromotion(ctx, &promotion)
	run.State = PromotionFailed
	run.Step = step
	run.Failure = cause.Error()
	run.UpdatedAt = coordinator.now()
	run.CompletedAt = run.UpdatedAt
	_ = coordinator.Store.UpdateFailoverRun(ctx, run)
	return promotion, run, cause
}

func (coordinator FailoverCoordinator) reconcile(ctx context.Context, promotion Promotion, run FailoverRun, effectIndex int, step string, cause error) (Promotion, FailoverRun, error) {
	now := coordinator.now()
	if effectIndex >= 0 && effectIndex < len(run.Effects) {
		run.Effects[effectIndex].Outcome = PromotionEffectAmbiguous
		run.Effects[effectIndex].Failure = cause.Error()
		run.Effects[effectIndex].CompletedAt = now
	}
	run.State = PromotionReconciliation
	run.Step = step
	run.Failure = cause.Error()
	run.ReconciliationRequired = true
	run.ReconciliationReason = cause.Error()
	run.UpdatedAt = now
	runErr := coordinator.Store.UpdateFailoverRun(ctx, run)
	previous := promotion.Generation
	promotion.State = PromotionReconciliation
	promotion.Failure = cause.Error()
	promotion.Generation++
	promotion.UpdatedAt = now
	promotionErr := coordinator.Store.UpdatePromotion(ctx, promotion, previous)
	return promotion, run, errors.Join(ErrReconciliationRequired, cause, runErr, promotionErr)
}

func PromotionPlanDigest(promotion Promotion) (string, error) {
	value := promotion
	value.Approvals = nil
	payload, err := json.Marshal(struct {
		Domain string    `json:"domain"`
		Plan   Promotion `json:"plan"`
	}{Domain: "cyberpanel-ha-promotion-plan-v1", Plan: value})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func promotionEffectID(kind string, values ...string) string {
	sum := sha256.Sum256([]byte("cyberpanel-ha-promotion-effect-v1\x00" + kind + "\x00" + strings.Join(values, "\x00")))
	prefix := strings.ReplaceAll(kind, ".", "-")
	if len(prefix) > 32 {
		prefix = prefix[:32]
	}
	return prefix + "_" + hex.EncodeToString(sum[:])[:48]
}

func promotionReceiptJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if len(payload) == 0 || len(payload) > maximumPromotionReceiptBytes {
		return "", ErrInvalid
	}
	return string(payload), nil
}

func attachPromotionEffectReceipt(run *FailoverRun, index int, value any) {
	if run == nil || index < 0 || index >= len(run.Effects) {
		return
	}
	var receipt string
	if text, ok := value.(string); ok {
		receipt = text
	} else {
		receipt, _ = promotionReceiptJSON(value)
	}
	if receipt == "" || len(receipt) > maximumPromotionReceiptBytes {
		return
	}
	sum := sha256.Sum256([]byte(receipt))
	run.Effects[index].Receipt = receipt
	run.Effects[index].ReceiptDigest = hex.EncodeToString(sum[:])
}

func digestFenceReceipts(receipts []FenceReceipt) (string, error) {
	payload, err := json.Marshal(receipts)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func trafficPolicyCoversPromotion(policy TrafficPolicy, promotion Promotion) bool {
	if policy.ID != promotion.TrafficPolicyID || policy.GroupID != promotion.GroupID || policy.Resource != promotion.ResourceID || policy.ProviderBindingID == "" || policy.Generation == 0 || policy.ProviderMode != TrafficAtomicCAS && policy.ProviderMode != TrafficObserveApply {
		return false
	}
	previous, candidate := false, false
	for _, endpoint := range policy.Endpoints {
		previous = previous || endpoint.NodeID == promotion.PreviousWriter
		candidate = candidate || endpoint.NodeID == promotion.Candidate
	}
	return previous && candidate
}

func validTrafficObservation(observation TrafficObservation, policy TrafficPolicy) bool {
	return observation.PolicyID == policy.ID && observation.Revision != "" && validDigest(observation.Digest) && !observation.ObservedAt.IsZero()
}

func buildTrafficDesired(policy TrafficPolicy, before TrafficObservation, writer, old NodeID, observedAt time.Time) TrafficObservation {
	endpoints := append([]TrafficEndpoint(nil), before.Endpoints...)
	for index := range endpoints {
		if endpoints[index].NodeID == writer {
			endpoints[index].Weight = 100
			endpoints[index].Healthy = true
		} else if endpoints[index].NodeID == old {
			endpoints[index].Weight = 0
		}
	}
	payload, _ := json.Marshal(endpoints)
	sum := sha256.Sum256(payload)
	return TrafficObservation{PolicyID: policy.ID, Endpoints: endpoints, Digest: hex.EncodeToString(sum[:]), ObservedAt: observedAt}
}

func validateTrafficReceipt(receipt TrafficReceipt) error {
	if !validID(string(receipt.PolicyID)) || !validID(receipt.EffectID) || !validDigest(receipt.BeforeDigest) || !validDigest(receipt.OutputDigest) || receipt.ProviderReceipt == "" || receipt.AppliedAt.IsZero() {
		return fmt.Errorf("%w: traffic receipt", ErrInvalid)
	}
	return nil
}

func samePromotionLease(actual, proposed WriterLease) bool {
	return actual.ID == proposed.ID && actual.GroupID == proposed.GroupID && actual.ResourceID == proposed.ResourceID && actual.HolderNodeID == proposed.HolderNodeID && actual.FencingToken == proposed.FencingToken && actual.AuthorityEpoch == proposed.AuthorityEpoch && actual.QuorumDigest == proposed.QuorumDigest && sameProtectedWritePaths(actual.EnforcedWritePaths, proposed.EnforcedWritePaths)
}

func validPromotionPermit(permit WritePermit, lease WriterLease, now time.Time) bool {
	return permit.ResourceID == lease.ResourceID && permit.NodeID == lease.HolderNodeID && permit.LeaseID == lease.ID && permit.FencingToken == lease.FencingToken && permit.AuthorityEpoch == lease.AuthorityEpoch && permit.Signature != "" && now.Before(permit.ExpiresAt) && sameProtectedWritePaths(permit.WritePaths, lease.EnforcedWritePaths)
}

func emptyReceiptError(receipt string) error {
	if receipt == "" {
		return ErrProviderAmbiguous
	}
	return nil
}
