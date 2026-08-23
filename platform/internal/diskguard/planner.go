package diskguard

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

type PlanRequest struct {
	PlanID         string               `json:"plan_id"`
	IdempotencyKey string               `json:"idempotency_key"`
	Policy         WatermarkPolicy      `json:"policy"`
	Observation    FilesystemObservation `json:"observation"`
	Artifacts      []ArtifactDescriptor `json:"artifacts"`
	Now            time.Time            `json:"now"`
}

type Planner struct{}

func (Planner) Build(request PlanRequest) (Plan, error) {
	if !validID(request.PlanID) || !validID(request.IdempotencyKey) || request.Policy.Validate() != nil || request.Observation.Validate() != nil || request.Policy.FilesystemID != request.Observation.FilesystemID || request.Now.IsZero() || len(request.Artifacts) > int(request.Policy.MaximumCandidates) {
		return Plan{}, ErrInvalid
	}
	now := request.Now.UTC()
	descriptors := append([]ArtifactDescriptor(nil), request.Artifacts...)
	seenDescriptors, seenObjects := map[string]struct{}{}, map[string]struct{}{}
	for index := range descriptors {
		descriptors[index].CreatedAt, descriptors[index].RetainUntil = descriptors[index].CreatedAt.UTC(), descriptors[index].RetainUntil.UTC()
		if descriptors[index].Validate() != nil || descriptors[index].FilesystemID != request.Policy.FilesystemID {
			return Plan{}, ErrInvalid
		}
		if _, exists := seenDescriptors[descriptors[index].DescriptorID]; exists {
			return Plan{}, ErrConflict
		}
		if _, exists := seenObjects[descriptors[index].ObjectID]; exists {
			return Plan{}, ErrConflict
		}
		seenDescriptors[descriptors[index].DescriptorID], seenObjects[descriptors[index].ObjectID] = struct{}{}, struct{}{}
	}
	sort.Slice(descriptors, func(left, right int) bool { return descriptorSortKey(descriptors[left]) < descriptorSortKey(descriptors[right]) })
	inputDigest, err := digestValue(struct {
		Domain string `json:"domain"`
		PlanID string `json:"plan_id"`
		IdempotencyKey string `json:"idempotency_key"`
		PolicyDigest string `json:"policy_digest"`
		ObservationDigest string `json:"observation_digest"`
		Artifacts []ArtifactDescriptor `json:"artifacts"`
		Now time.Time `json:"now"`
	}{"diskguard-plan-input-v1",request.PlanID,request.IdempotencyKey,request.Policy.Digest,request.Observation.Digest,descriptors,now})
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{ID:request.PlanID,IdempotencyKey:request.IdempotencyKey,InputDigest:inputDigest,FilesystemID:request.Policy.FilesystemID,PolicyID:request.Policy.ID,PolicyGeneration:request.Policy.Generation,PolicyDigest:request.Policy.Digest,ObservationID:request.Observation.ID,ObservationGeneration:request.Observation.Generation,ObservationDigest:request.Observation.Digest,State:PlanPlanned,Generation:1,CreatedAt:now,UpdatedAt:now}
	reasons := map[ReasonCode]struct{}{}
	if now.Before(request.Observation.ObservedAt.UTC()) || now.Sub(request.Observation.ObservedAt.UTC()) > request.Policy.MaximumObservationAge {
		plan.Level = PressureUnknown
		reasons[ReasonObservationStale] = struct{}{}
		plan.Actions = []PlanAction{controlAction(plan.ID, 1, ActionBlockHeavyWork, plan.FilesystemID, ReasonHeavyWorkBlocked)}
		reasons[ReasonHeavyWorkBlocked] = struct{}{}
		plan.Reasons = sortedReasons(reasons)
		return SealPlan(plan)
	}
	if basisPointsExceeded(request.Observation.UncertaintyBytes, request.Observation.TotalBytes, request.Policy.MaximumUncertaintyBasisPoints) || basisPointsExceeded(request.Observation.UncertaintyInodes, request.Observation.TotalInodes, request.Policy.MaximumUncertaintyBasisPoints) {
		plan.Level = PressureUnknown
		reasons[ReasonObservationUncertain] = struct{}{}
		plan.Actions = []PlanAction{controlAction(plan.ID, 1, ActionBlockHeavyWork, plan.FilesystemID, ReasonHeavyWorkBlocked)}
		reasons[ReasonHeavyWorkBlocked] = struct{}{}
		plan.Reasons = sortedReasons(reasons)
		return SealPlan(plan)
	}
	reserveBytes, reserveInodes, err := request.Policy.Reserves.totals()
	if err != nil || reserveBytes >= request.Observation.TotalBytes || reserveInodes >= request.Observation.TotalInodes {
		return Plan{}, ErrInvalid
	}
	reliableFreeBytes := saturatingSubtract(request.Observation.FreeBytes, request.Observation.UncertaintyBytes)
	reliableFreeInodes := saturatingSubtract(request.Observation.FreeInodes, request.Observation.UncertaintyInodes)
	usableBytes, usableInodes := saturatingSubtract(reliableFreeBytes, reserveBytes), saturatingSubtract(reliableFreeInodes, reserveInodes)
	plan.ProjectedUsableBytes, plan.ProjectedUsableInodes = usableBytes, usableInodes
	if reliableFreeBytes <= reserveBytes || reliableFreeInodes <= reserveInodes {
		reasons[ReasonReserveEncroached] = struct{}{}
	}
	plan.Level = pressureLevel(request.Policy, usableBytes, usableInodes, reasons)
	if plan.Level == PressureNormal {
		plan.State = PlanCompleted
		plan.Reasons = []ReasonCode{ReasonNoPressure}
		return SealPlan(plan)
	}
	maximumClassRank := 1
	switch plan.Level {
	case PressureHigh:
		maximumClassRank = 3
	case PressureCritical, PressureEmergency:
		maximumClassRank = 4
	}
	eligible := make([]ArtifactDescriptor, 0, len(descriptors))
	for _, descriptor := range descriptors {
		rank := artifactReclaimRank(descriptor.Class)
		if descriptor.Protection == ProtectionEligible && descriptor.Retention != RetentionLegalHold && !descriptor.RetainUntil.After(now) && rank >= 0 && rank <= maximumClassRank {
			eligible = append(eligible, descriptor)
		}
	}
	sort.Slice(eligible, func(left, right int) bool {
		leftRank, rightRank := artifactReclaimRank(eligible[left].Class), artifactReclaimRank(eligible[right].Class)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if !eligible[left].RetainUntil.Equal(eligible[right].RetainUntil) {
			return eligible[left].RetainUntil.Before(eligible[right].RetainUntil)
		}
		if !eligible[left].CreatedAt.Equal(eligible[right].CreatedAt) {
			return eligible[left].CreatedAt.Before(eligible[right].CreatedAt)
		}
		return descriptorSortKey(eligible[left]) < descriptorSortKey(eligible[right])
	})
	deleteLimit := int(request.Policy.MaximumActions) - 1
	var reclaimedBytes, reclaimedInodes uint64
	for _, descriptor := range eligible {
		if len(plan.Actions) >= deleteLimit || targetsSatisfied(usableBytes, usableInodes, reclaimedBytes, reclaimedInodes, request.Policy) {
			break
		}
		if descriptor.Bytes > request.Policy.MaximumReclaimBytes-reclaimedBytes {
			continue
		}
		reason := artifactReason(descriptor.Class)
		action := PlanAction{Sequence:uint16(len(plan.Actions)+1),ID:actionID(plan.ID,uint16(len(plan.Actions)+1),descriptor.ObjectID),Kind:ActionExpireObject,DescriptorID:descriptor.DescriptorID,ObjectID:descriptor.ObjectID,FilesystemID:descriptor.FilesystemID,TenantID:descriptor.TenantID,Class:descriptor.Class,Protection:descriptor.Protection,Retention:descriptor.Retention,ExpectedGeneration:descriptor.Generation,ExpectedDigest:descriptor.Digest,ExpectedBytes:descriptor.Bytes,ExpectedInodes:descriptor.Inodes,Reason:reason,Destructive:true,RequiresApproval:plan.Level==PressureEmergency}
		plan.Actions = append(plan.Actions, action)
		reasons[reason] = struct{}{}
		reclaimedBytes, reclaimedInodes = saturatingAdd(reclaimedBytes, descriptor.Bytes), saturatingAdd(reclaimedInodes, descriptor.Inodes)
	}
	plan.ProjectedUsableBytes, plan.ProjectedUsableInodes = saturatingAdd(usableBytes, reclaimedBytes), saturatingAdd(usableInodes, reclaimedInodes)
	controlKind, controlReason := ActionThrottleHeavyWork, ReasonHeavyWorkThrottled
	if plan.Level == PressureCritical || plan.Level == PressureEmergency {
		controlKind, controlReason = ActionBlockHeavyWork, ReasonHeavyWorkBlocked
	}
	plan.Actions = append(plan.Actions, controlAction(plan.ID, uint16(len(plan.Actions)+1), controlKind, plan.FilesystemID, controlReason))
	reasons[controlReason] = struct{}{}
	if !targetsSatisfied(usableBytes, usableInodes, reclaimedBytes, reclaimedInodes, request.Policy) {
		reasons[ReasonInsufficientReclaimable] = struct{}{}
	}
	if plan.Level == PressureEmergency && len(plan.Actions) > 1 {
		plan.RequiresApproval, plan.RequiresStepUp = true, true
		reasons[ReasonEmergencyApproval] = struct{}{}
	}
	plan.Reasons = sortedReasons(reasons)
	return SealPlan(plan)
}

func pressureLevel(policy WatermarkPolicy, bytes, inodes uint64, reasons map[ReasonCode]struct{}) PressureLevel {
	level := PressureNormal
	if bytes <= policy.Low.MinimumUsableBytes || inodes <= policy.Low.MinimumUsableInodes {
		level = PressureLow
		if bytes <= policy.Low.MinimumUsableBytes { reasons[ReasonLowBytes] = struct{}{} }
		if inodes <= policy.Low.MinimumUsableInodes { reasons[ReasonLowInodes] = struct{}{} }
	}
	if bytes <= policy.High.MinimumUsableBytes || inodes <= policy.High.MinimumUsableInodes {
		level = PressureHigh
		delete(reasons, ReasonLowBytes); delete(reasons, ReasonLowInodes)
		if bytes <= policy.High.MinimumUsableBytes { reasons[ReasonHighBytes] = struct{}{} }
		if inodes <= policy.High.MinimumUsableInodes { reasons[ReasonHighInodes] = struct{}{} }
	}
	if bytes <= policy.Critical.MinimumUsableBytes || inodes <= policy.Critical.MinimumUsableInodes {
		level = PressureCritical
		delete(reasons, ReasonHighBytes); delete(reasons, ReasonHighInodes)
		if bytes <= policy.Critical.MinimumUsableBytes { reasons[ReasonCriticalBytes] = struct{}{} }
		if inodes <= policy.Critical.MinimumUsableInodes { reasons[ReasonCriticalInodes] = struct{}{} }
	}
	if bytes <= policy.Emergency.MinimumUsableBytes || inodes <= policy.Emergency.MinimumUsableInodes {
		level = PressureEmergency
		delete(reasons, ReasonCriticalBytes); delete(reasons, ReasonCriticalInodes)
		if bytes <= policy.Emergency.MinimumUsableBytes { reasons[ReasonEmergencyBytes] = struct{}{} }
		if inodes <= policy.Emergency.MinimumUsableInodes { reasons[ReasonEmergencyInodes] = struct{}{} }
	}
	return level
}

func targetsSatisfied(bytes, inodes, reclaimedBytes, reclaimedInodes uint64, policy WatermarkPolicy) bool {
	return saturatingAdd(bytes, reclaimedBytes) >= policy.RecoveryTargetBytes && saturatingAdd(inodes, reclaimedInodes) >= policy.RecoveryTargetInodes
}

func artifactReclaimRank(class ArtifactClass) int {
	switch class {
	case ArtifactCache:
		return 0
	case ArtifactTemporary:
		return 1
	case ArtifactLog:
		return 2
	case ArtifactGeneral:
		return 3
	case ArtifactBackup:
		return 4
	default:
		return -1
	}
}

func artifactReason(class ArtifactClass) ReasonCode {
	switch class {
	case ArtifactCache:
		return ReasonExpiredCache
	case ArtifactTemporary:
		return ReasonExpiredTemporary
	case ArtifactLog:
		return ReasonExpiredLog
	case ArtifactGeneral:
		return ReasonExpiredArtifact
	default:
		return ReasonExpiredBackup
	}
}

func controlAction(planID string, sequence uint16, kind ActionKind, filesystemID string, reason ReasonCode) PlanAction {
	return PlanAction{Sequence:sequence,ID:actionID(planID,sequence,string(kind)),Kind:kind,FilesystemID:filesystemID,Reason:reason}
}

func actionID(planID string, sequence uint16, target string) string {
	sum := sha256.Sum256([]byte("diskguard-action-v1\x00"+planID+"\x00"+target+"\x00"+time.Duration(sequence).String()))
	return "dgact-" + hex.EncodeToString(sum[:])[:48]
}

func descriptorSortKey(descriptor ArtifactDescriptor) string {
	return descriptor.TenantID + "\x00" + descriptor.DescriptorID + "\x00" + descriptor.ObjectID
}

func basisPointsExceeded(uncertainty, total uint64, maximum uint16) bool {
	allowed := total/10000*uint64(maximum) + total%10000*uint64(maximum)/10000
	return uncertainty > allowed
}
