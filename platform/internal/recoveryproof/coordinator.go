package recoveryproof

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

type CoordinatorLimits struct {
	MaximumRestoreBytes  int64
	MaximumRestoreInodes int64
	MaximumRunDuration   time.Duration
	FenceDuration        time.Duration
	MaximumEvidence      int
	MaximumResources     int
}

func DefaultCoordinatorLimits() CoordinatorLimits {
	return CoordinatorLimits{
		MaximumRestoreBytes:  1 << 40,
		MaximumRestoreInodes: 10000000,
		MaximumRunDuration:   12 * time.Hour,
		FenceDuration:        12 * time.Hour,
		MaximumEvidence:      512,
		MaximumResources:     512,
	}
}

func (l CoordinatorLimits) validate() error {
	if l.MaximumRestoreBytes <= 0 || l.MaximumRestoreBytes > 16<<40 ||
		l.MaximumRestoreInodes <= 0 || l.MaximumRestoreInodes > 1000000000 ||
		l.MaximumRunDuration < time.Minute || l.MaximumRunDuration > 24*time.Hour ||
		l.FenceDuration < l.MaximumRunDuration || l.FenceDuration > 24*time.Hour ||
		l.MaximumEvidence < 16 || l.MaximumEvidence > 512 ||
		l.MaximumResources < 1 || l.MaximumResources > 512 {
		return fmt.Errorf("%w: coordinator limits", ErrInvalid)
	}
	return nil
}

type Coordinator struct {
	Repository  *SQLiteRepository
	Capacity    CapacityAdmission
	Maintenance MaintenanceAdmission
	Backups     BackupCatalog
	Isolation   IsolationManager
	Restore     RestoreEngine
	Probes      ProbeSuite
	Signer      Signer
	Authorizer  Authorizer
	Auditor     Auditor
	Alerts      AlertSink
	Now         func() time.Time
	Limits      CoordinatorLimits
}

type RunRequest struct {
	Actor              Actor
	DrillID            DrillID
	ExpectedGeneration uint64
	LeaseID            string
}

type checkpointCandidate struct {
	At         time.Time
	EvidenceID EvidenceID
}

func (c Coordinator) CreatePlan(
	ctx context.Context,
	actor Actor,
	plan DrillPlan,
) (DrillPlan, ScheduleState, error) {
	if _, err := c.dependencies(); err != nil {
		return DrillPlan{}, ScheduleState{}, err
	}
	sealed, err := SealPlan(plan)
	if err != nil {
		return DrillPlan{}, ScheduleState{}, err
	}
	if actor.TenantID != sealed.TenantID {
		return DrillPlan{}, ScheduleState{}, ErrUnauthorized
	}
	if err := c.authorizeAndAudit(ctx, actor, ActionPlanCreate, sealed, nil, c.now()); err != nil {
		return DrillPlan{}, ScheduleState{}, err
	}
	return c.Repository.CreatePlan(ctx, sealed)
}

func (c Coordinator) CreateOccurrence(
	ctx context.Context,
	actor Actor,
	request OccurrenceRequest,
) (Drill, ScheduleState, error) {
	if _, err := c.dependencies(); err != nil {
		return Drill{}, ScheduleState{}, err
	}
	if actor.TenantID != request.TenantID {
		return Drill{}, ScheduleState{}, ErrUnauthorized
	}
	plan, err := c.Repository.GetPlan(ctx, request.TenantID, request.PlanID)
	if err != nil {
		return Drill{}, ScheduleState{}, err
	}
	if err := c.authorizeAndAudit(ctx, actor, ActionDrillRun, plan, nil, c.now()); err != nil {
		return Drill{}, ScheduleState{}, err
	}
	return c.Repository.CreateOccurrence(ctx, request)
}

func (c Coordinator) Run(ctx context.Context, request RunRequest) (ProofManifest, error) {
	limits, err := c.dependencies()
	if err != nil {
		return ProofManifest{}, err
	}
	if request.ExpectedGeneration == 0 || !validLocalID(request.LeaseID) ||
		!validLocalID(string(request.Actor.TenantID)) || !validLocalID(string(request.Actor.PrincipalID)) ||
		!validLocalID(string(request.DrillID)) {
		return ProofManifest{}, fmt.Errorf("%w: run request", ErrInvalid)
	}
	drill, err := c.Repository.GetDrill(ctx, request.Actor.TenantID, request.DrillID)
	if err != nil {
		return ProofManifest{}, err
	}
	if drill.Generation != request.ExpectedGeneration || drill.State != StatePlanned {
		return ProofManifest{}, ErrStaleGeneration
	}
	plan, err := c.Repository.GetPlan(ctx, drill.TenantID, drill.PlanID)
	if err != nil {
		return ProofManifest{}, err
	}
	if plan.Digest != drill.PlanDigest || drill.RecoveryPoint.Consistency != plan.Consistency ||
		!sameComponents(drill.RecoveryPoint.Components, plan.Components) {
		return ProofManifest{}, ErrIntegrity
	}
	startedAt := c.now()
	if err := c.authorizeAndAudit(ctx, request.Actor, ActionDrillRun, plan, &drill, startedAt); err != nil {
		return ProofManifest{}, err
	}

	observation, observeErr := c.Backups.InspectRecoveryPoint(ctx, drill.TenantID, drill.RecoveryPoint)
	backupObservedAt := c.now()
	observationValid := observeErr == nil && validRecoveryObservation(
		observation,
		drill,
		backupObservedAt,
		limits,
	)
	evidence := boundedEvidence(nil, observation.Evidence, limits.MaximumEvidence)
	if observeErr != nil || !observationValid {
		completed := c.now()
		timing, _ := NewPhaseTiming(PhaseAdmission, startedAt, completed)
		return c.finishTerminal(
			ctx,
			request.Actor,
			plan,
			drill,
			StateUncertain,
			appendFinding(nil, "recovery_point_uncertain", SeverityCritical, ""),
			evidence,
			[]PhaseTiming{timing},
			nil,
			MeasuredDuration{},
			MeasuredDuration{},
			time.Time{},
			completed,
		)
	}
	checkpoint := checkpointCandidate{At: observation.ObservedCheckpoint, EvidenceID: observation.CheckpointEvidence}

	capacity, capacityErr := c.Capacity.Admit(ctx, CapacityRequest{
		TenantID:       drill.TenantID,
		PlanID:         plan.ID,
		DrillID:        drill.ID,
		Components:     append([]Component(nil), plan.Components...),
		IsolationClass: plan.Destination.IsolationClass,
		MaximumBytes:   limits.MaximumRestoreBytes,
		MaximumInodes:  limits.MaximumRestoreInodes,
	})
	maintenance, maintenanceErr := c.Maintenance.Admit(ctx, MaintenanceRequest{
		TenantID:    drill.TenantID,
		PlanID:      plan.ID,
		DrillID:     drill.ID,
		ScheduledAt: drill.ScheduledAt,
		MaximumRun:  limits.MaximumRunDuration,
	})
	admissionCompleted := c.now()
	admissionTiming, timingErr := NewPhaseTiming(PhaseAdmission, startedAt, admissionCompleted)
	if timingErr != nil {
		return ProofManifest{}, timingErr
	}
	if capacityErr != nil || maintenanceErr != nil ||
		!validCapacityDecision(capacity, drill, admissionCompleted) ||
		!validMaintenanceDecision(maintenance, drill, admissionCompleted) {
		outcome := StateFailed
		code := "admission_denied"
		if capacityErr != nil || maintenanceErr != nil || capacity.Uncertain || maintenance.Uncertain {
			outcome = StateUncertain
			code = "admission_uncertain"
		}
		return c.finishTerminal(
			ctx,
			request.Actor,
			plan,
			drill,
			outcome,
			appendFinding(nil, code, SeverityCritical, ""),
			evidence,
			[]PhaseTiming{admissionTiming},
			nil,
			measureRPO(startedAt, checkpoint),
			MeasuredDuration{},
			checkpoint.At,
			admissionCompleted,
		)
	}
	leaseExpires := minimumTime(
		admissionCompleted.Add(limits.FenceDuration),
		capacity.ExpiresAt,
		maintenance.EndsAt,
	)
	if !leaseExpires.After(admissionCompleted) {
		return c.finishTerminal(
			ctx,
			request.Actor,
			plan,
			drill,
			StateUncertain,
			appendFinding(nil, "admission_expired", SeverityCritical, ""),
			evidence,
			[]PhaseTiming{admissionTiming},
			nil,
			measureRPO(startedAt, checkpoint),
			MeasuredDuration{},
			checkpoint.At,
			admissionCompleted,
		)
	}
	admitted := drill
	admitted.State = StateAdmitted
	admitted.Generation++
	admitted.Fence = Fence{Token: drill.Fence.Token + 1, LeaseID: request.LeaseID, ExpiresAt: leaseExpires}
	admitted.PhaseTimings = append(admitted.PhaseTimings, admissionTiming)
	admitted.Evidence = evidence
	admitted.ActualRPO = measureRPO(startedAt, checkpoint)
	admitted.ObservedCheckpoint = checkpoint.At
	admitted.UpdatedAt = admissionCompleted
	admitted, _, err = c.Repository.TransitionCAS(ctx, TransitionRequest{
		Current: drill,
		Next:    admitted,
		Receipt: transitionReceipt(drill, admitted, ReceiptAdmission, "admitted", nil,
			append(evidenceDigests(evidence), capacity.Digest, maintenance.Digest), admissionCompleted),
		Now: admissionCompleted,
	})
	if err != nil {
		return ProofManifest{}, err
	}

	allocationStarted := c.now()
	allocation, allocationErr := c.Isolation.Allocate(ctx, AllocationRequest{
		TenantID: drill.TenantID,
		DrillID:  drill.ID,
		Fence:    admitted.Fence,
		Policy:   plan.Destination,
		Capacity: capacity,
		Effects:  StrictEffectProhibitions(),
	})
	allocationObservedAt := c.now()
	allocationValid := validAllocation(allocation, admitted, allocationStarted, allocationObservedAt, limits)
	if allocationErr != nil || !allocationValid {
		if allocation.Destination.Validate(admitted.TenantID, admitted.ID) == nil &&
			!allocation.Destination.CreatedAt.Before(allocationStarted) {
			cleaning, transitionErr := c.moveToCleaning(
				ctx,
				admitted,
				allocation.Destination,
				allocation.Resources,
				allocation.Evidence,
				"allocation_uncertain",
				allocationStarted,
				allocationObservedAt,
			)
			if transitionErr != nil {
				return ProofManifest{}, transitionErr
			}
			return c.cleanupAndFinish(ctx, request.Actor, plan, cleaning, StateUncertain,
				allocation.Resources, validateResourceIdentities(allocation.Resources) != nil, limits)
		}
		allocationCompleted := allocationObservedAt
		allocationTiming, _ := NewPhaseTiming(PhaseAllocation, allocationStarted, allocationCompleted)
		return c.finishTerminal(
			ctx,
			request.Actor,
			plan,
			admitted,
			StateUncertain,
			appendFinding(admitted.Findings, "allocation_uncertain", SeverityCritical, ""),
			boundedEvidence(admitted.Evidence, allocation.Evidence, limits.MaximumEvidence),
			append(admitted.PhaseTimings, allocationTiming),
			nil,
			admitted.ActualRPO,
			MeasuredDuration{},
			admitted.ObservedCheckpoint,
			allocationCompleted,
		)
	}
	allocationTiming, _ := NewPhaseTiming(PhaseAllocation, allocation.StartedAt, allocation.CompletedAt)
	allocationPhaseReceipt := transitionReceipt(admitted, admitted, ReceiptAllocation,
		"allocation_completed", allocation.Resources, evidenceDigests(allocation.Evidence),
		allocationObservedAt)
	if _, err := c.Repository.RecordReceiptCAS(
		ctx,
		admitted,
		allocationPhaseReceipt,
		allocationObservedAt,
	); err != nil {
		return ProofManifest{}, err
	}
	restoring := admitted
	restoring.State = StateRestoring
	restoring.Generation++
	restoring.Destination = &allocation.Destination
	restoring.PhaseTimings = append(restoring.PhaseTimings, allocationTiming)
	if wouldOverflowEvidence(restoring.Evidence, allocation.Evidence, limits.MaximumEvidence) {
		restoring.Findings = appendFinding(restoring.Findings, "evidence_limit", SeverityCritical, "")
	}
	restoring.Evidence = boundedEvidence(restoring.Evidence, allocation.Evidence, limits.MaximumEvidence)
	restoring.UpdatedAt = allocationObservedAt
	restoring, _, err = c.Repository.TransitionCAS(ctx, TransitionRequest{
		Current: admitted,
		Next:    restoring,
		Receipt: transitionReceipt(admitted, restoring, ReceiptAllocation, "allocated",
			allocation.Resources, evidenceDigests(allocation.Evidence), allocationObservedAt),
		Now: allocationObservedAt,
	})
	if err != nil {
		return ProofManifest{}, err
	}

	restoreResult, restoreErr := c.Restore.RestoreIsolated(ctx, RestoreRequest{
		TenantID:      restoring.TenantID,
		DrillID:       restoring.ID,
		Fence:         restoring.Fence,
		RecoveryPoint: restoring.RecoveryPoint,
		Destination:   *restoring.Destination,
		Components:    append([]Component(nil), plan.Components...),
		Consistency:   plan.Consistency,
		Effects:       StrictEffectProhibitions(),
	})
	restoreObservedAt := c.now()
	if restoreErr != nil || !validRestoreResult(restoreResult, restoring, plan, restoreObservedAt, limits) {
		cleaning, transitionErr := c.moveToCleaning(
			ctx,
			restoring,
			*restoring.Destination,
			restoreResult.Resources,
			restoreResult.Evidence,
			"restore_uncertain",
			firstNonZero(restoreResult.StartedAt, c.now()),
			restoreObservedAt,
		)
		if transitionErr != nil {
			return ProofManifest{}, transitionErr
		}
		resources := mergeResources(allocation.Resources, restoreResult.Resources, limits.MaximumResources)
		return c.cleanupAndFinish(ctx, request.Actor, plan, cleaning, StateUncertain, resources,
			validateResourceIdentities(restoreResult.Resources) != nil, limits)
	}
	checkpoint = conservativeCheckpoint(checkpoint, checkpointCandidate{
		At: restoreResult.ObservedCheckpoint, EvidenceID: restoreResult.CheckpointEvidence,
	})
	restoreTiming, _ := NewPhaseTiming(PhaseRestore, restoreResult.StartedAt, restoreResult.CompletedAt)
	restorePhaseReceipt := transitionReceipt(restoring, restoring, ReceiptRestore,
		"restore_completed", restoreResult.Resources, evidenceDigests(restoreResult.Evidence),
		restoreObservedAt)
	if _, err := c.Repository.RecordReceiptCAS(
		ctx,
		restoring,
		restorePhaseReceipt,
		restoreObservedAt,
	); err != nil {
		return ProofManifest{}, err
	}
	verifying := restoring
	verifying.State = StateVerifying
	verifying.Generation++
	verifying.PhaseTimings = append(verifying.PhaseTimings, restoreTiming)
	if wouldOverflowEvidence(verifying.Evidence, restoreResult.Evidence, limits.MaximumEvidence) {
		verifying.Findings = appendFinding(verifying.Findings, "evidence_limit", SeverityCritical, "")
	}
	verifying.Evidence = boundedEvidence(verifying.Evidence, restoreResult.Evidence, limits.MaximumEvidence)
	verifying.ObservedCheckpoint = checkpoint.At
	verifying.ActualRPO = measureRPO(startedAt, checkpoint)
	verifying.UpdatedAt = restoreObservedAt
	verifying, _, err = c.Repository.TransitionCAS(ctx, TransitionRequest{
		Current: restoring,
		Next:    verifying,
		Receipt: transitionReceipt(restoring, verifying, ReceiptRestore, "restored",
			restoreResult.Resources, evidenceDigests(restoreResult.Evidence), restoreObservedAt),
		Now: restoreObservedAt,
	})
	if err != nil {
		return ProofManifest{}, err
	}

	verificationStarted := c.now()
	checks := make([]CheckResult, 0, len(plan.Checklist))
	findings := append([]Finding(nil), verifying.Findings...)
	verificationEvidence := append([]EvidenceReference(nil), verifying.Evidence...)
	verificationOutcome := StateProved
	if findingCodeExists(findings, "evidence_limit") {
		verificationOutcome = StateUncertain
	}
	var applicationCompleted time.Time
	var applicationEvidence EvidenceID
	for _, kind := range plan.Checklist {
		probeStarted := c.now()
		probe, probeErr := c.Probes.Probe(ctx, ProbeRequest{
			TenantID:      verifying.TenantID,
			DrillID:       verifying.ID,
			Fence:         verifying.Fence,
			Kind:          kind,
			Destination:   *verifying.Destination,
			RecoveryPoint: verifying.RecoveryPoint,
			ReadOnly:      true,
			Effects:       StrictEffectProhibitions(),
		})
		probeObservedAt := c.now()
		if probeErr != nil || !validProbeResult(probe, kind, probeObservedAt, limits) {
			completed := probeObservedAt
			checks = append(checks, CheckResult{
				Kind: kind, Status: CheckUncertain, StartedAt: probeStarted, CompletedAt: completed,
			})
			findings = appendFinding(findings, "probe_uncertain", SeverityCritical, kind)
			verificationOutcome = StateUncertain
			continue
		}
		ids := evidenceIDs(probe.Evidence)
		checks = append(checks, CheckResult{
			Kind: kind, Status: probe.Status, StartedAt: probe.StartedAt,
			CompletedAt: probe.CompletedAt, EvidenceIDs: ids,
		})
		if wouldOverflowEvidence(verificationEvidence, probe.Evidence, limits.MaximumEvidence) {
			verificationOutcome = StateUncertain
			findings = appendFinding(findings, "evidence_limit", SeverityCritical, kind)
		}
		verificationEvidence = boundedEvidence(verificationEvidence, probe.Evidence, limits.MaximumEvidence)
		if len(findings)+len(probe.Findings) > 256 {
			verificationOutcome = StateUncertain
		}
		findings = boundedFindings(findings, probe.Findings)
		checkpoint = conservativeCheckpoint(checkpoint, checkpointCandidate{
			At: probe.ObservedCheckpoint, EvidenceID: probe.CheckpointEvidence,
		})
		if probe.Status == CheckFailed && verificationOutcome != StateUncertain {
			verificationOutcome = StateFailed
		} else if probe.Status == CheckUncertain {
			verificationOutcome = StateUncertain
		}
		if kind == CheckApplication && probe.Status == CheckPassed && len(ids) != 0 {
			applicationCompleted = probe.CompletedAt
			applicationEvidence = ids[0]
		}
	}
	verificationCompleted := c.now()
	verificationTiming, _ := NewPhaseTiming(PhaseVerification, verificationStarted, verificationCompleted)
	actualRPO := measureRPO(startedAt, checkpoint)
	actualRTO := MeasuredDuration{}
	if !applicationCompleted.IsZero() && !restoreResult.StartedAt.IsZero() &&
		!applicationCompleted.Before(restoreResult.StartedAt) {
		actualRTO = MeasuredDuration{
			Known: true, Value: applicationCompleted.Sub(restoreResult.StartedAt),
			BasisEvidenceID: applicationEvidence,
		}
	}
	if !actualRPO.Known || !actualRTO.Known {
		verificationOutcome = StateUncertain
		findings = appendFinding(findings, "measurement_unavailable", SeverityCritical, "")
	} else if actualRPO.Value > plan.RPOTarget && verificationOutcome != StateUncertain {
		verificationOutcome = StateFailed
		findings = appendFinding(findings, "rpo_target_missed", SeverityCritical, "")
	}
	cleaning := verifying
	cleaning.State = StateCleaning
	cleaning.Generation++
	cleaning.Checks = checks
	cleaning.Findings = findings
	cleaning.Evidence = verificationEvidence
	cleaning.ObservedCheckpoint = checkpoint.At
	cleaning.ActualRPO = actualRPO
	cleaning.ActualRTO = actualRTO
	cleaning.PhaseTimings = append(cleaning.PhaseTimings, verificationTiming)
	cleaning.UpdatedAt = verificationCompleted
	verificationPhaseReceipt := transitionReceipt(verifying, verifying, ReceiptVerification,
		"verification_completed", nil, evidenceDigests(verificationEvidence), verificationCompleted)
	if _, err := c.Repository.RecordReceiptCAS(
		ctx,
		verifying,
		verificationPhaseReceipt,
		verificationCompleted,
	); err != nil {
		return ProofManifest{}, err
	}
	cleaning, _, err = c.Repository.TransitionCAS(ctx, TransitionRequest{
		Current: verifying,
		Next:    cleaning,
		Receipt: transitionReceipt(verifying, cleaning, ReceiptVerification, "verified",
			nil, evidenceDigests(verificationEvidence), verificationCompleted),
		Now: verificationCompleted,
	})
	if err != nil {
		return ProofManifest{}, err
	}
	resources := mergeResources(allocation.Resources, restoreResult.Resources, limits.MaximumResources)
	return c.cleanupAndFinish(ctx, request.Actor, plan, cleaning, verificationOutcome, resources, false, limits)
}

func (c Coordinator) cleanupAndFinish(
	ctx context.Context,
	actor Actor,
	plan DrillPlan,
	cleaning Drill,
	desiredOutcome DrillState,
	resources []ExactResourceReceipt,
	resourceAmbiguous bool,
	limits CoordinatorLimits,
) (ProofManifest, error) {
	if cleaning.State != StateCleaning || cleaning.Destination == nil {
		return ProofManifest{}, fmt.Errorf("%w: cleanup state", ErrInvalid)
	}
	cleanupStarted := c.now()
	if resourceAmbiguous || len(resources) > limits.MaximumResources ||
		validateResourceIdentities(resources) != nil ||
		validateResourceOwnership(resources, cleaning.TenantID, cleaning.ID) != nil {
		cleaning.Findings = appendFinding(cleaning.Findings, "resource_set_ambiguous", SeverityCritical, "")
		cleanupCompleted := c.now()
		cleanupTiming, _ := NewPhaseTiming(PhaseCleanup, cleanupStarted, cleanupCompleted)
		cleaning.PhaseTimings = append(cleaning.PhaseTimings, cleanupTiming)
		receiptResources := boundedAnyResources(resources, limits.MaximumResources)
		receipt := transitionReceipt(cleaning, cleaning, ReceiptCleanup, "resource_set_ambiguous",
			receiptResources, nil, cleanupCompleted)
		if _, err := c.Repository.RecordReceiptCAS(ctx, cleaning, receipt, cleanupCompleted); err != nil {
			return ProofManifest{}, err
		}
		return c.finishTerminal(ctx, actor, plan, cleaning, StateUncertain,
			cleaning.Findings, cleaning.Evidence, cleaning.PhaseTimings, cleaning.Checks,
			cleaning.ActualRPO, cleaning.ActualRTO, cleaning.ObservedCheckpoint, cleanupCompleted)
	}
	observation, observeErr := c.Isolation.Observe(
		ctx,
		cleaning.TenantID,
		cleaning.ID,
		*cleaning.Destination,
	)
	observationObservedAt := c.now()
	owned := observeErr == nil && validDestinationObservation(
		observation,
		cleaning,
		observationObservedAt,
		limits,
	)
	cleanupEvidence := observation.Evidence
	cleanupResources := resources
	statusCode := "cleanup_ownership_uncertain"
	if owned {
		result, cleanupErr := c.Isolation.CleanupExact(ctx, CleanupRequest{
			TenantID:    cleaning.TenantID,
			DrillID:     cleaning.ID,
			Fence:       cleaning.Fence,
			Destination: *cleaning.Destination,
			Resources:   append([]ExactResourceReceipt(nil), resources...),
			Effects:     StrictEffectProhibitions(),
		})
		cleanupObservedAt := c.now()
		if wouldOverflowEvidence(cleanupEvidence, result.Evidence, limits.MaximumEvidence) {
			desiredOutcome = StateUncertain
			cleaning.Findings = appendFinding(cleaning.Findings, "evidence_limit", SeverityCritical, "")
		}
		cleanupEvidence = boundedEvidence(cleanupEvidence, result.Evidence, limits.MaximumEvidence)
		if cleanupErr == nil && validCleanupResult(result, resources, cleanupObservedAt, limits) {
			statusCode = "cleanup_completed"
			cleanupResources = result.Resources
		} else {
			statusCode = "cleanup_uncertain"
			desiredOutcome = StateUncertain
			if len(result.Resources) != 0 {
				cleanupResources = boundedAnyResources(result.Resources, limits.MaximumResources)
			}
		}
	} else {
		desiredOutcome = StateUncertain
	}
	cleanupCompleted := c.now()
	cleanupTiming, _ := NewPhaseTiming(PhaseCleanup, cleanupStarted, cleanupCompleted)
	if statusCode != "cleanup_completed" {
		cleaning.Findings = appendFinding(cleaning.Findings, statusCode, SeverityCritical, "")
	}
	if wouldOverflowEvidence(cleaning.Evidence, cleanupEvidence, limits.MaximumEvidence) {
		desiredOutcome = StateUncertain
		cleaning.Findings = appendFinding(cleaning.Findings, "evidence_limit", SeverityCritical, "")
	}
	cleaning.Evidence = boundedEvidence(cleaning.Evidence, cleanupEvidence, limits.MaximumEvidence)
	cleaning.PhaseTimings = append(cleaning.PhaseTimings, cleanupTiming)
	receipt := transitionReceipt(cleaning, cleaning, ReceiptCleanup, statusCode,
		cleanupResources, evidenceDigests(cleanupEvidence), cleanupCompleted)
	receipt.DrillGeneration = cleaning.Generation
	receipt.FenceToken = cleaning.Fence.Token
	if _, err := c.Repository.RecordReceiptCAS(ctx, cleaning, receipt, cleanupCompleted); err != nil {
		return ProofManifest{}, err
	}
	return c.finishTerminal(
		ctx,
		actor,
		plan,
		cleaning,
		desiredOutcome,
		cleaning.Findings,
		cleaning.Evidence,
		cleaning.PhaseTimings,
		cleaning.Checks,
		cleaning.ActualRPO,
		cleaning.ActualRTO,
		cleaning.ObservedCheckpoint,
		cleanupCompleted,
	)
}

func (c Coordinator) moveToCleaning(
	ctx context.Context,
	current Drill,
	destination IsolatedDestination,
	resources []ExactResourceReceipt,
	evidence []EvidenceReference,
	statusCode string,
	startedAt time.Time,
	completedAt time.Time,
) (Drill, error) {
	timing, err := NewPhaseTiming(phaseForCurrent(current.State), startedAt, completedAt)
	if err != nil {
		return Drill{}, err
	}
	next := current
	next.State = StateCleaning
	next.Generation++
	next.Destination = &destination
	next.Findings = appendFinding(next.Findings, statusCode, SeverityCritical, "")
	next.Evidence = boundedEvidence(next.Evidence, evidence, 512)
	next.PhaseTimings = append(next.PhaseTimings, timing)
	next.UpdatedAt = completedAt
	phaseReceipt := transitionReceipt(current, current, receiptForCurrent(current.State), statusCode,
		boundedAnyResources(resources, 512), evidenceDigests(evidence), completedAt)
	if _, err := c.Repository.RecordReceiptCAS(ctx, current, phaseReceipt, completedAt); err != nil {
		return Drill{}, err
	}
	next, _, err = c.Repository.TransitionCAS(ctx, TransitionRequest{
		Current: current,
		Next:    next,
		Receipt: transitionReceipt(current, next, receiptForCurrent(current.State), statusCode,
			boundedAnyResources(resources, 512), evidenceDigests(evidence), completedAt),
		Now: completedAt,
	})
	return next, err
}

func (c Coordinator) finishTerminal(
	ctx context.Context,
	actor Actor,
	plan DrillPlan,
	current Drill,
	outcome DrillState,
	findings []Finding,
	evidence []EvidenceReference,
	timings []PhaseTiming,
	checks []CheckResult,
	actualRPO MeasuredDuration,
	actualRTO MeasuredDuration,
	checkpoint time.Time,
	now time.Time,
) (ProofManifest, error) {
	if !outcome.terminal() || !transitionAllowed(current.State, outcome) {
		return ProofManifest{}, fmt.Errorf("%w: terminal outcome", ErrInvalid)
	}
	now = canonicalTime(now)
	checks = completeChecklist(checks, now)
	findings = normalizedFindings(findings)
	evidence = normalizedEvidence(evidence)
	if actualRPO.Known && !evidenceIDPresent(evidence, actualRPO.BasisEvidenceID) {
		actualRPO = MeasuredDuration{}
		outcome = StateUncertain
		findings = appendFinding(findings, "rpo_evidence_missing", SeverityCritical, "")
	}
	if actualRTO.Known && !evidenceIDPresent(evidence, actualRTO.BasisEvidenceID) {
		actualRTO = MeasuredDuration{}
		outcome = StateUncertain
		findings = appendFinding(findings, "rto_evidence_missing", SeverityCritical, "")
	}
	requiredEvidenceRetention := now.Add(plan.Retention.EvidenceRetention)
	for _, item := range evidence {
		if item.RetainUntil.Before(requiredEvidenceRetention) {
			outcome = StateUncertain
			findings = appendFinding(findings, "evidence_retention_short", SeverityCritical, "")
			break
		}
	}
	findings = normalizedFindings(findings)
	if outcome == StateProved {
		for _, check := range checks {
			if check.Status != CheckPassed {
				outcome = StateFailed
				findings = appendFinding(findings, "checklist_failed", SeverityCritical, check.Kind)
				break
			}
		}
		if !actualRPO.Known || !actualRTO.Known {
			outcome = StateUncertain
			findings = appendFinding(findings, "measurement_unavailable", SeverityCritical, "")
		}
	}
	proof := ProofManifest{
		ID:                 "proof:" + current.OccurrenceKey[:32],
		TenantID:           current.TenantID,
		DrillID:            current.ID,
		DrillDigest:        current.Digest,
		PlanID:             plan.ID,
		PlanDigest:         plan.Digest,
		RecoveryPoint:      current.RecoveryPoint,
		Checklist:          checks,
		PhaseTimings:       timings,
		ObservedCheckpoint: checkpoint,
		ActualRPO:          actualRPO,
		ActualRTO:          actualRTO,
		Findings:           findings,
		Evidence:           evidence,
		Outcome:            outcome,
		CreatedAt:          now,
		RetainUntil:        now.Add(plan.Retention.ProofRetention),
	}
	if current.Destination != nil {
		proof.DestinationDigest = current.Destination.Digest
	}
	signed, err := SignProof(ctx, proof, c.Signer)
	if err != nil {
		return ProofManifest{}, err
	}
	proofDigest, err := ProofDigest(signed)
	if err != nil {
		return ProofManifest{}, err
	}
	next := current
	next.State = outcome
	next.Generation++
	next.Checks = checks
	next.Findings = findings
	next.Evidence = evidence
	next.PhaseTimings = timings
	next.ObservedCheckpoint = checkpoint
	next.ActualRPO = actualRPO
	next.ActualRTO = actualRTO
	next.ProofDigest = proofDigest
	next.UpdatedAt = now
	next, _, err = c.Repository.TransitionCAS(ctx, TransitionRequest{
		Current: current,
		Next:    next,
		Receipt: transitionReceipt(current, next, ReceiptProof, "proof_recorded",
			nil, []string{proofDigest}, now),
		Proof: &signed,
		Now:   now,
	})
	if err != nil {
		return ProofManifest{}, err
	}
	if outcome != StateProved {
		alertErr := c.notify(ctx, AlertFailed, plan, &next, "proof_"+string(outcome), proofDigest, now)
		if outcome == StateUncertain {
			return signed, errors.Join(ErrUncertain, alertErr)
		}
		return signed, errors.Join(ErrProofFailed, alertErr)
	}
	return signed, nil
}

func (c Coordinator) EmitDueAlerts(ctx context.Context, limit int) error {
	if _, err := c.dependencies(); err != nil {
		return err
	}
	due, err := c.Repository.ListDuePlans(ctx, c.now(), limit)
	if err != nil {
		return err
	}
	for _, item := range due {
		kind := AlertStale
		reason := "proof_stale"
		if item.Missed {
			kind = AlertMissed
			reason = "occurrence_missed"
		}
		if err := c.notify(ctx, kind, item.Plan, nil, reason, item.Schedule.Digest, c.now()); err != nil {
			return err
		}
	}
	return nil
}

func (c Coordinator) ListDrills(
	ctx context.Context,
	actor Actor,
	cursor *DrillCursor,
	limit int,
) (DrillPage, error) {
	return c.listAuthorized(ctx, actor, cursor, limit, ActionProofRead)
}

func (c Coordinator) GetProof(
	ctx context.Context,
	actor Actor,
	drillID DrillID,
) (ProofManifest, error) {
	if _, err := c.dependencies(); err != nil {
		return ProofManifest{}, err
	}
	drill, err := c.Repository.GetDrill(ctx, actor.TenantID, drillID)
	if err != nil {
		return ProofManifest{}, err
	}
	plan, err := c.Repository.GetPlan(ctx, actor.TenantID, drill.PlanID)
	if err != nil {
		return ProofManifest{}, err
	}
	if err := c.authorizeAndAudit(ctx, actor, ActionProofRead, plan, &drill, c.now()); err != nil {
		return ProofManifest{}, err
	}
	return c.Repository.GetProof(ctx, actor.TenantID, drillID)
}

func (c Coordinator) ExportDrills(
	ctx context.Context,
	actor Actor,
	cursor *DrillCursor,
	limit int,
) (ExportBundle, error) {
	if limit > MaximumListItems {
		return ExportBundle{}, ErrLimit
	}
	page, err := c.listAuthorized(ctx, actor, cursor, limit, ActionProofExport)
	if err != nil {
		return ExportBundle{}, err
	}
	return SignProjectionExport(ctx, actor.TenantID, c.now(), page.Items, page.NextCursor, c.Signer)
}

func (c Coordinator) listAuthorized(
	ctx context.Context,
	actor Actor,
	cursor *DrillCursor,
	limit int,
	action Action,
) (DrillPage, error) {
	if _, err := c.dependencies(); err != nil {
		return DrillPage{}, err
	}
	page, err := c.Repository.ListDrills(ctx, actor.TenantID, cursor, limit)
	if err != nil {
		return DrillPage{}, err
	}
	for _, projection := range page.Items {
		drill, err := c.Repository.GetDrill(ctx, actor.TenantID, projection.DrillID)
		if err != nil {
			return DrillPage{}, err
		}
		plan, err := c.Repository.GetPlan(ctx, actor.TenantID, drill.PlanID)
		if err != nil {
			return DrillPage{}, err
		}
		if err := c.authorizeAndAudit(ctx, actor, action, plan, &drill, c.now()); err != nil {
			return DrillPage{}, err
		}
	}
	return page, nil
}

func (c Coordinator) dependencies() (CoordinatorLimits, error) {
	if c.Repository == nil || c.Capacity == nil || c.Maintenance == nil ||
		c.Backups == nil || c.Isolation == nil || c.Restore == nil || c.Probes == nil ||
		c.Signer == nil || c.Authorizer == nil || c.Auditor == nil || c.Alerts == nil || c.Now == nil {
		return CoordinatorLimits{}, fmt.Errorf("%w: coordinator dependencies", ErrInvalid)
	}
	limits := c.Limits
	if limits == (CoordinatorLimits{}) {
		limits = DefaultCoordinatorLimits()
	}
	if err := limits.validate(); err != nil {
		return CoordinatorLimits{}, err
	}
	if c.now().IsZero() {
		return CoordinatorLimits{}, fmt.Errorf("%w: coordinator clock", ErrInvalid)
	}
	return limits, nil
}

func (c Coordinator) now() time.Time { return canonicalTime(c.Now()) }

func (c Coordinator) authorizeAndAudit(
	ctx context.Context,
	actor Actor,
	action Action,
	plan DrillPlan,
	drill *Drill,
	now time.Time,
) error {
	if actor.TenantID != plan.TenantID || !validLocalID(string(actor.PrincipalID)) {
		return ErrUnauthorized
	}
	decisionErr := c.Authorizer.Authorize(ctx, actor, action, plan, drill)
	outcome := "authorized"
	reason := "policy_allowed"
	if decisionErr != nil {
		outcome = "denied"
		reason = "policy_denied"
	}
	event := AuditEvent{
		TenantID: actor.TenantID, PrincipalID: actor.PrincipalID, Action: action,
		PlanID: plan.ID, Outcome: outcome, ReasonCode: reason, OccurredAt: now,
	}
	if drill != nil {
		event.DrillID = drill.ID
		event.Generation = drill.Generation
		event.FenceToken = drill.Fence.Token
	}
	event.ID = deterministicID("audit", event)
	if err := c.Auditor.Record(ctx, event); err != nil {
		return fmt.Errorf("recoveryproof: record authorization audit: %w", err)
	}
	if decisionErr != nil {
		return ErrUnauthorized
	}
	return nil
}

func (c Coordinator) notify(
	ctx context.Context,
	kind AlertKind,
	plan DrillPlan,
	drill *Drill,
	reason string,
	evidenceDigest string,
	now time.Time,
) error {
	alert := Alert{
		TenantID: plan.TenantID, PlanID: plan.ID, Kind: kind, ReasonCode: reason,
		EvidenceDigest: evidenceDigest, ObservedAt: now,
	}
	if drill != nil {
		alert.DrillID = drill.ID
	}
	alert.ID = deterministicID("alert", struct {
		TenantID      TenantID
		PlanID        PlanID
		DrillID       DrillID
		Kind          AlertKind
		ReasonCode    string
		EvidenceDigest string
	}{alert.TenantID, alert.PlanID, alert.DrillID, alert.Kind, alert.ReasonCode, alert.EvidenceDigest})
	if err := c.Alerts.Notify(ctx, alert); err != nil {
		return fmt.Errorf("recoveryproof: send alert: %w", err)
	}
	return nil
}

func validRecoveryObservation(
	value RecoveryPointObservation,
	drill Drill,
	observedAt time.Time,
	limits CoordinatorLimits,
) bool {
	valueDigest, valueErr := canonicalDigest(value.RecoveryPoint)
	expectedDigest, expectedErr := canonicalDigest(drill.RecoveryPoint)
	return valueErr == nil && expectedErr == nil && valueDigest == expectedDigest &&
		value.ArtifactIntegrity && value.OwnershipVerified && !value.ObservedAt.IsZero() &&
		!value.ObservedAt.After(observedAt) &&
		len(value.Evidence) <= limits.MaximumEvidence && validateEvidence(value.Evidence) == nil &&
		checkpointBindingValid(value.ObservedCheckpoint, value.CheckpointEvidence, value.Evidence) &&
		(value.ObservedCheckpoint.IsZero() || !value.ObservedCheckpoint.After(value.ObservedAt))
}

func validCapacityDecision(value CapacityDecision, drill Drill, now time.Time) bool {
	if value.TenantID != drill.TenantID || value.DrillID != drill.ID ||
		!value.Admitted || value.Uncertain || !validReason(value.ReasonCode) ||
		value.ReservedBytes <= 0 || value.ReservedInodes <= 0 ||
		!validLocalID(value.ReservationID) || value.Generation == 0 ||
		!validDigest(value.Digest) || !value.ExpiresAt.After(now) {
		return false
	}
	return true
}

func validMaintenanceDecision(value MaintenanceDecision, drill Drill, now time.Time) bool {
	return value.TenantID == drill.TenantID && value.DrillID == drill.ID &&
		value.Admitted && !value.Uncertain && validReason(value.ReasonCode) &&
		validLocalID(value.WindowID) && value.Generation > 0 && validDigest(value.Digest) &&
		!value.StartsAt.IsZero() && !now.Before(value.StartsAt) && value.EndsAt.After(now) &&
		value.EndsAt.After(value.StartsAt)
}

func validAllocation(
	value AllocationResult,
	drill Drill,
	startedAt time.Time,
	observedAt time.Time,
	limits CoordinatorLimits,
) bool {
	return value.Destination.Validate(drill.TenantID, drill.ID) == nil &&
		!value.Destination.CreatedAt.Before(startedAt) && !value.StartedAt.Before(startedAt) &&
		!value.CompletedAt.Before(value.StartedAt) && !value.CompletedAt.After(observedAt) &&
		len(value.Resources) <= limits.MaximumResources &&
		validateResources(value.Resources, false) == nil &&
		validateResourceOwnership(value.Resources, drill.TenantID, drill.ID) == nil &&
		len(value.Evidence) <= limits.MaximumEvidence &&
		validateEvidence(value.Evidence) == nil
}

func validRestoreResult(
	value RestoreResult,
	drill Drill,
	plan DrillPlan,
	observedAt time.Time,
	limits CoordinatorLimits,
) bool {
	return validLocalID(value.OperationID) && value.RecoveryDigest == drill.RecoveryPoint.Point.Digest &&
		drill.Destination != nil && value.DestinationDigest == drill.Destination.Digest &&
		sameComponents(value.Components, plan.Components) && !value.StartedAt.IsZero() &&
		!value.CompletedAt.Before(value.StartedAt) && !value.CompletedAt.After(observedAt) &&
		len(value.Resources) <= limits.MaximumResources &&
		validateResources(value.Resources, false) == nil &&
		validateResourceOwnership(value.Resources, drill.TenantID, drill.ID) == nil &&
		len(value.Evidence) <= limits.MaximumEvidence &&
		validateEvidence(value.Evidence) == nil &&
		checkpointBindingValid(value.ObservedCheckpoint, value.CheckpointEvidence, value.Evidence) &&
		(value.ObservedCheckpoint.IsZero() || !value.ObservedCheckpoint.After(value.CompletedAt))
}

func validProbeResult(
	value ProbeResult,
	kind CheckKind,
	observedAt time.Time,
	limits CoordinatorLimits,
) bool {
	if value.Kind != kind || value.StartedAt.IsZero() || value.CompletedAt.Before(value.StartedAt) ||
		value.CompletedAt.After(observedAt) ||
		len(value.Evidence) == 0 || len(value.Evidence) > limits.MaximumEvidence ||
		validateEvidence(value.Evidence) != nil || validateFindings(value.Findings) != nil ||
		len(value.Findings) > 256 || !findingsBoundToEvidence(value.Findings, value.Evidence) {
		return false
	}
	switch value.Status {
	case CheckPassed, CheckFailed, CheckUncertain:
	default:
		return false
	}
	return checkpointBindingValid(value.ObservedCheckpoint, value.CheckpointEvidence, value.Evidence) &&
		(value.ObservedCheckpoint.IsZero() || !value.ObservedCheckpoint.After(value.CompletedAt))
}

func findingsBoundToEvidence(findings []Finding, evidence []EvidenceReference) bool {
	ids := make(map[EvidenceID]struct{}, len(evidence))
	for _, item := range evidence {
		ids[item.ID] = struct{}{}
	}
	for _, finding := range findings {
		for _, evidenceID := range finding.EvidenceIDs {
			if _, found := ids[evidenceID]; !found {
				return false
			}
		}
	}
	return true
}

func checkpointBindingValid(
	checkpoint time.Time,
	evidenceID EvidenceID,
	evidence []EvidenceReference,
) bool {
	if checkpoint.IsZero() {
		return evidenceID == ""
	}
	if !validLocalID(string(evidenceID)) {
		return false
	}
	for _, item := range evidence {
		if item.ID == evidenceID {
			return true
		}
	}
	return false
}

func validDestinationObservation(
	value DestinationObservation,
	drill Drill,
	observedAt time.Time,
	limits CoordinatorLimits,
) bool {
	if drill.Destination == nil {
		return false
	}
	return value.Destination.NamespaceID == drill.Destination.NamespaceID &&
		value.Destination.Generation == drill.Destination.Generation &&
		value.Destination.Digest == drill.Destination.Digest && value.OwnedByDrill &&
		value.NonRouted && value.ProductionEndpointCount == 0 && !value.ObservedAt.IsZero() &&
		!value.ObservedAt.After(observedAt) &&
		len(value.Evidence) <= limits.MaximumEvidence && validateEvidence(value.Evidence) == nil
}

func validCleanupResult(
	value CleanupResult,
	expected []ExactResourceReceipt,
	observedAt time.Time,
	limits CoordinatorLimits,
) bool {
	if !value.Complete || value.Ambiguous || value.StartedAt.IsZero() ||
		value.CompletedAt.Before(value.StartedAt) || value.CompletedAt.After(observedAt) ||
		len(value.Resources) != len(expected) ||
		len(value.Resources) > limits.MaximumResources || len(value.Evidence) > limits.MaximumEvidence ||
		validateEvidence(value.Evidence) != nil || validateResources(value.Resources, true) != nil {
		return false
	}
	actual := append([]ExactResourceReceipt(nil), value.Resources...)
	want := append([]ExactResourceReceipt(nil), expected...)
	sortResources(actual)
	sortResources(want)
	for index := range actual {
		if actual[index].DescriptorID != want[index].DescriptorID ||
			actual[index].ObjectID != want[index].ObjectID ||
			actual[index].TenantID != want[index].TenantID || actual[index].DrillID != want[index].DrillID ||
			actual[index].Generation != want[index].Generation || actual[index].Digest != want[index].Digest {
			return false
		}
	}
	return true
}

func validateResources(resources []ExactResourceReceipt, cleaned bool) error {
	seen := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		if !validLocalID(resource.DescriptorID) || !validLocalID(resource.ObjectID) ||
			resource.Generation == 0 || !validDigest(resource.Digest) {
			return ErrInvalid
		}
		key := resource.DescriptorID + ":" + resource.ObjectID
		if _, duplicate := seen[key]; duplicate {
			return ErrConflict
		}
		seen[key] = struct{}{}
		if cleaned {
			if resource.Status != ResourceDeleted && resource.Status != ResourceAbsent {
				return ErrUncertain
			}
		} else if resource.Status != ResourceCreated && resource.Status != ResourceVerified {
			return ErrInvalid
		}
	}
	return nil
}

func transitionReceipt(
	current Drill,
	next Drill,
	kind ReceiptKind,
	status string,
	resources []ExactResourceReceipt,
	evidenceDigests []string,
	now time.Time,
) Receipt {
	exactResources := boundedOwnedResources(resources, current.TenantID, current.ID, 512)
	sortResources(exactResources)
	return Receipt{
		ID:              ReceiptID(deterministicID("receipt", struct {
			Drill DrillID
			Kind ReceiptKind
			Generation uint64
		}{current.ID, kind, next.Generation})),
		TenantID:        current.TenantID,
		DrillID:         current.ID,
		Kind:            kind,
		FromState:       current.State,
		ToState:         next.State,
		DrillGeneration: next.Generation,
		FenceToken:      next.Fence.Token,
		StatusCode:      status,
		EvidenceDigests: normalizedDigests(evidenceDigests),
		Resources:       exactResources,
		CreatedAt:       canonicalTime(now),
	}
}

func deterministicID(prefix string, value any) string {
	digest, err := canonicalDigest(value)
	if err != nil {
		return prefix + ":invalid"
	}
	return prefix + ":" + digest[:32]
}

func appendFinding(values []Finding, code string, severity Severity, check CheckKind) []Finding {
	if len(values) >= 256 {
		return values
	}
	return append(values, Finding{Code: code, Severity: severity, Check: check, Count: 1})
}

func findingCodeExists(values []Finding, code string) bool {
	for _, finding := range values {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func boundedFindings(existing, additions []Finding) []Finding {
	result := append([]Finding(nil), existing...)
	for _, finding := range additions {
		if len(result) >= 255 {
			return appendFinding(result, "finding_limit", SeverityCritical, "")
		}
		result = append(result, finding)
	}
	return result
}

func boundedEvidence(existing, additions []EvidenceReference, maximum int) []EvidenceReference {
	result := make([]EvidenceReference, 0, minimumInt(len(existing)+len(additions), maximum))
	seen := make(map[EvidenceID]struct{}, len(result))
	for _, item := range append(append([]EvidenceReference(nil), existing...), additions...) {
		if len(result) >= maximum {
			break
		}
		if validateEvidence([]EvidenceReference{item}) != nil {
			continue
		}
		if _, duplicate := seen[item.ID]; duplicate {
			continue
		}
		seen[item.ID] = struct{}{}
		result = append(result, item)
	}
	return result
}

func normalizedFindings(values []Finding) []Finding {
	aggregated := make(map[string]Finding, len(values))
	for _, finding := range values {
		key := finding.Code + ":" + string(finding.Severity) + ":" + string(finding.Check)
		current, exists := aggregated[key]
		if !exists {
			current = Finding{Code: finding.Code, Severity: finding.Severity, Check: finding.Check}
		}
		if ^uint64(0)-current.Count < finding.Count {
			current.Count = ^uint64(0)
		} else {
			current.Count += finding.Count
		}
		seenEvidence := make(map[EvidenceID]struct{}, len(current.EvidenceIDs))
		for _, id := range current.EvidenceIDs {
			seenEvidence[id] = struct{}{}
		}
		for _, id := range finding.EvidenceIDs {
			if _, duplicate := seenEvidence[id]; !duplicate && len(current.EvidenceIDs) < 32 {
				seenEvidence[id] = struct{}{}
				current.EvidenceIDs = append(current.EvidenceIDs, id)
			}
		}
		sort.Slice(current.EvidenceIDs, func(i, j int) bool {
			return current.EvidenceIDs[i] < current.EvidenceIDs[j]
		})
		aggregated[key] = current
	}
	keys := make([]string, 0, len(aggregated))
	for key := range aggregated {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Finding, 0, len(keys))
	for _, key := range keys {
		result = append(result, aggregated[key])
	}
	return result
}

func normalizedEvidence(values []EvidenceReference) []EvidenceReference {
	result := boundedEvidence(nil, values, 512)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func evidenceDigests(values []EvidenceReference) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Digest)
	}
	return normalizedDigests(result)
}

func normalizedDigests(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !validDigest(value) {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func evidenceIDs(values []EvidenceReference) []EvidenceID {
	result := make([]EvidenceID, 0, len(values))
	for _, value := range values {
		result = append(result, value.ID)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func evidenceIDPresent(values []EvidenceReference, id EvidenceID) bool {
	for _, value := range values {
		if value.ID == id {
			return true
		}
	}
	return false
}

func completeChecklist(existing []CheckResult, now time.Time) []CheckResult {
	byKind := make(map[CheckKind]CheckResult, len(existing))
	for _, check := range existing {
		byKind[check.Kind] = check
	}
	result := make([]CheckResult, 0, len(requiredChecks))
	for _, kind := range requiredChecks {
		check, ok := byKind[kind]
		if !ok {
			check = CheckResult{
				Kind: kind, Status: CheckUncertain, StartedAt: now, CompletedAt: now,
			}
		}
		result = append(result, check)
	}
	return result
}

func measureRPO(reference time.Time, checkpoint checkpointCandidate) MeasuredDuration {
	if reference.IsZero() || checkpoint.At.IsZero() || checkpoint.At.After(reference) ||
		!validLocalID(string(checkpoint.EvidenceID)) {
		return MeasuredDuration{}
	}
	return MeasuredDuration{
		Known: true, Value: reference.Sub(checkpoint.At), BasisEvidenceID: checkpoint.EvidenceID,
	}
}

func conservativeCheckpoint(a, b checkpointCandidate) checkpointCandidate {
	if b.At.IsZero() || !validLocalID(string(b.EvidenceID)) {
		return a
	}
	if a.At.IsZero() || b.At.Before(a.At) {
		return b
	}
	return a
}

func mergeResources(a, b []ExactResourceReceipt, maximum int) []ExactResourceReceipt {
	result := boundedAnyResources(a, maximum+1)
	seen := make(map[string]int, len(result))
	for index, item := range result {
		seen[item.DescriptorID+":"+item.ObjectID] = index
	}
	for _, item := range b {
		if !validResourceIdentity(item) {
			continue
		}
		if len(result) > maximum {
			break
		}
		key := item.DescriptorID + ":" + item.ObjectID
		if previousIndex, duplicate := seen[key]; duplicate {
			previous := result[previousIndex]
			if previous.TenantID != item.TenantID || previous.DrillID != item.DrillID ||
				previous.Generation != item.Generation || previous.Digest != item.Digest {
				result = append(result, item)
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, item)
	}
	return result
}

func boundedAnyResources(values []ExactResourceReceipt, maximum int) []ExactResourceReceipt {
	result := make([]ExactResourceReceipt, 0, minimumInt(len(values), maximum))
	for _, value := range values {
		if len(result) >= maximum {
			break
		}
		if validResourceIdentity(value) {
			result = append(result, value)
		}
	}
	return result
}

func boundedOwnedResources(
	values []ExactResourceReceipt,
	tenantID TenantID,
	drillID DrillID,
	maximum int,
) []ExactResourceReceipt {
	result := make([]ExactResourceReceipt, 0, minimumInt(len(values), maximum))
	for _, value := range values {
		if len(result) >= maximum {
			break
		}
		if validResourceIdentity(value) && value.TenantID == tenantID && value.DrillID == drillID {
			result = append(result, value)
		}
	}
	return result
}

func validResourceIdentity(resource ExactResourceReceipt) bool {
	if !validLocalID(resource.DescriptorID) || !validLocalID(resource.ObjectID) ||
		!validLocalID(string(resource.TenantID)) || !validLocalID(string(resource.DrillID)) ||
		resource.Generation == 0 || !validDigest(resource.Digest) {
		return false
	}
	switch resource.Status {
	case ResourceCreated, ResourceVerified, ResourceDeleted, ResourceAbsent, ResourceAmbiguous:
		return true
	default:
		return false
	}
}

func validateResourceOwnership(
	resources []ExactResourceReceipt,
	tenantID TenantID,
	drillID DrillID,
) error {
	for _, resource := range resources {
		if resource.TenantID != tenantID || resource.DrillID != drillID {
			return ErrProhibited
		}
	}
	return nil
}

func validateResourceIdentities(resources []ExactResourceReceipt) error {
	seen := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		if !validResourceIdentity(resource) {
			return ErrInvalid
		}
		key := resource.DescriptorID + ":" + resource.ObjectID
		if _, duplicate := seen[key]; duplicate {
			return ErrConflict
		}
		seen[key] = struct{}{}
	}
	return nil
}

func wouldOverflowEvidence(existing, additions []EvidenceReference, maximum int) bool {
	seen := make(map[EvidenceID]string, len(existing))
	count := 0
	for _, item := range append(append([]EvidenceReference(nil), existing...), additions...) {
		if validateEvidence([]EvidenceReference{item}) != nil {
			return true
		}
		itemDigest, err := canonicalDigest(item)
		if err != nil {
			return true
		}
		if previousDigest, duplicate := seen[item.ID]; duplicate {
			if previousDigest != itemDigest {
				return true
			}
			continue
		}
		seen[item.ID] = itemDigest
		count++
		if count > maximum {
			return true
		}
	}
	return false
}

func minimumInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sortResources(values []ExactResourceReceipt) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].DescriptorID == values[j].DescriptorID {
			return values[i].ObjectID < values[j].ObjectID
		}
		return values[i].DescriptorID < values[j].DescriptorID
	})
}

func sameComponents(a, b []Component) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func minimumTime(values ...time.Time) time.Time {
	var result time.Time
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		if result.IsZero() || value.Before(result) {
			result = value
		}
	}
	return canonicalTime(result)
}

func firstNonZero(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return canonicalTime(value)
		}
	}
	return time.Time{}
}

func phaseForCurrent(state DrillState) Phase {
	if state == StateAdmitted {
		return PhaseAllocation
	}
	return PhaseRestore
}

func receiptForCurrent(state DrillState) ReceiptKind {
	if state == StateAdmitted {
		return ReceiptAllocation
	}
	return ReceiptRestore
}
