package diagnosticsrepair

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

type CanonicalResource struct {
	Scope                    Scope  `json:"scope"`
	Managed                  bool   `json:"managed"`
	OwnerID                  string `json:"owner_id"`
	ServiceID                string `json:"service_id"`
	Generation               uint64 `json:"generation"`
	Digest                   string `json:"digest"`
	OwnershipModeDigest      string `json:"ownership_mode_digest,omitempty"`
	CertificateBindingDigest string `json:"certificate_binding_digest,omitempty"`
}

func (resource CanonicalResource) Validate() error {
	if resource.Scope.Validate() != nil || !resource.Managed || !identifierPattern.MatchString(resource.OwnerID) ||
		!identifierPattern.MatchString(resource.ServiceID) || resource.Generation == 0 || resource.Generation > maxGeneration ||
		!validDigest(resource.Digest) || resource.OwnershipModeDigest != "" && !validDigest(resource.OwnershipModeDigest) ||
		resource.CertificateBindingDigest != "" && !validDigest(resource.CertificateBindingDigest) { return ErrInvalid }
	return nil
}

type CanonicalSource interface { ResolveCanonical(context.Context, Scope, DiagnosticKind) (CanonicalResource, error) }

type EffectKind string

const (
	EffectReconcileGeneration EffectKind = "reconcile_canonical_generation"
	EffectValidateConfig      EffectKind = "validate_config"
	EffectRestoreOwnership    EffectKind = "restore_ownership_mode"
	EffectReloadService       EffectKind = "reload_exact_service"
	EffectRestartService      EffectKind = "restart_exact_service"
	EffectRepairCertificate   EffectKind = "repair_certificate_binding"
)

func (kind EffectKind) Valid() bool {
	switch kind {
	case EffectReconcileGeneration, EffectValidateConfig, EffectRestoreOwnership, EffectReloadService,
		EffectRestartService, EffectRepairCertificate:
		return true
	default: return false
	}
}

func (kind EffectKind) mutable() bool { return kind != EffectValidateConfig }

type Impact string

const (
	ImpactNone     Impact = "none"
	ImpactService  Impact = "service"
	ImpactWorkload Impact = "hosted_workload"
)

type PreconditionKind string

const (
	PreconditionFindingOpen      PreconditionKind = "finding_open"
	PreconditionObservedGeneration PreconditionKind = "observed_generation"
	PreconditionCanonicalOwner   PreconditionKind = "canonical_owner"
	PreconditionSnapshotProven   PreconditionKind = "snapshot_proven"
	PreconditionMaintenance      PreconditionKind = "maintenance_active"
)

type Precondition struct {
	Kind           PreconditionKind `json:"kind"`
	ExpectedDigest string           `json:"expected_digest"`
}

type CompensationKind string

const (
	CompensationNone               CompensationKind = "none"
	CompensationRestoreSnapshot    CompensationKind = "restore_snapshot"
	CompensationReloadPrevious     CompensationKind = "reload_previous_generation"
	CompensationRestartPrevious    CompensationKind = "restart_previous_generation"
	CompensationRestoreCertificate CompensationKind = "restore_certificate_binding"
)

type Compensation struct {
	Kind           CompensationKind `json:"kind"`
	Required       bool             `json:"required"`
	ReferenceDigest string          `json:"reference_digest,omitempty"`
}

type RepairStep struct {
	ID                    string            `json:"id"`
	Order                 uint32            `json:"order"`
	FindingIDs            []string          `json:"finding_ids"`
	DependsOn             []string          `json:"depends_on"`
	Effect                EffectKind        `json:"effect"`
	Scope                 Scope             `json:"scope"`
	Diagnostic            DiagnosticKind    `json:"diagnostic"`
	ServiceID             string            `json:"service_id"`
	CanonicalGeneration   uint64            `json:"canonical_generation"`
	CanonicalDigest       string            `json:"canonical_digest"`
	OwnershipModeDigest   string            `json:"ownership_mode_digest,omitempty"`
	CertificateBindingDigest string         `json:"certificate_binding_digest,omitempty"`
	ObservedGeneration    uint64            `json:"observed_generation"`
	Preconditions         []Precondition    `json:"preconditions"`
	SnapshotRequired      bool              `json:"snapshot_required"`
	Impact                Impact            `json:"impact"`
	MaintenanceRequired   bool              `json:"maintenance_required"`
	StepUpRequired        bool              `json:"step_up_required"`
	ApprovalRequired      bool              `json:"approval_required"`
	Compensation          Compensation      `json:"compensation"`
	Digest                string            `json:"digest"`
}

type SnapshotPolicy struct {
	Required          bool          `json:"required"`
	ResourceIDs       []string      `json:"resource_ids"`
	Retention         time.Duration `json:"retention"`
	ProofRequired     bool          `json:"proof_required"`
}

type RecoveryPolicy struct {
	ReverseOrder       bool     `json:"reverse_order"`
	RequireProof       bool     `json:"require_proof"`
	AmbiguousStateCodes []string `json:"ambiguous_state_codes"`
}

type IrreversibleFrontier struct {
	Declared bool   `json:"declared"`
	StepID   string `json:"step_id,omitempty"`
	Reason   string `json:"reason"`
}

type PlanState string

const (
	PlanPreview    PlanState = "preview"
	PlanApproved   PlanState = "approved"
	PlanExecuting  PlanState = "executing"
	PlanSucceeded  PlanState = "succeeded"
	PlanRolledBack PlanState = "rolled_back"
	PlanFailed     PlanState = "failed"
	PlanUncertain  PlanState = "uncertain"
)

func (state PlanState) Valid() bool {
	switch state {
	case PlanPreview, PlanApproved, PlanExecuting, PlanSucceeded, PlanRolledBack, PlanFailed, PlanUncertain: return true
	default: return false
	}
}

type RepairPlan struct {
	ID                    string               `json:"id"`
	RunID                 string               `json:"run_id"`
	RunDigest             string               `json:"run_digest"`
	Scope                 Scope                `json:"scope"`
	OwnerID               string               `json:"owner_id"`
	ControllerID          string               `json:"controller_id"`
	RegistryDigest        string               `json:"registry_digest"`
	State                 PlanState            `json:"state"`
	Generation            uint64               `json:"generation"`
	Fence                 uint64               `json:"fence"`
	Steps                 []RepairStep         `json:"steps"`
	Snapshot              SnapshotPolicy       `json:"snapshot"`
	Recovery              RecoveryPolicy       `json:"recovery"`
	Irreversible          IrreversibleFrontier `json:"irreversible_frontier"`
	DefinitionDigest      string               `json:"definition_digest"`
	MaintenanceRequired   bool                 `json:"maintenance_required"`
	StepUpRequired        bool                 `json:"step_up_required"`
	ApprovalRequired      bool                 `json:"approval_required"`
	CreatedAt             time.Time            `json:"created_at"`
	UpdatedAt             time.Time            `json:"updated_at"`
	LastReceiptDigest     string               `json:"last_receipt_digest,omitempty"`
	SnapshotReference     string               `json:"snapshot_reference,omitempty"`
	SnapshotEvidence      string               `json:"snapshot_evidence,omitempty"`
	ExecutedSteps         []StepExecution      `json:"executed_steps,omitempty"`
	CompensatedSteps      []StepExecution      `json:"compensated_steps,omitempty"`
	AmbiguousEvidence     string               `json:"ambiguous_evidence,omitempty"`
	RecoverySteps         []string             `json:"recovery_steps,omitempty"`
	Digest                string               `json:"digest"`
}

type StepExecution struct {
	StepID       string `json:"step_id"`
	ReceiptDigest string `json:"receipt_digest"`
	EvidenceDigest string `json:"evidence_digest"`
}

type PlanRequest struct {
	ID          string
	Run         DiagnosticRun
	FindingIDs  []string
	OwnerID     string
	ControllerID string
	CreatedAt   time.Time
	SnapshotRetention time.Duration
}

type Planner struct {
	registry  *Registry
	canonical CanonicalSource
	clock     Clock
}

func NewPlanner(registry *Registry, canonical CanonicalSource, clock Clock) (*Planner, error) {
	if registry == nil || canonical == nil || clock == nil { return nil, ErrInvalid }
	return &Planner{registry, canonical, clock}, nil
}

func (planner *Planner) Preview(ctx context.Context, request PlanRequest) (RepairPlan, error) {
	if planner == nil || !identifierPattern.MatchString(request.ID) || !identifierPattern.MatchString(request.OwnerID) || !identifierPattern.MatchString(request.ControllerID) ||
		!validTime(request.CreatedAt) || request.SnapshotRetention < time.Hour || request.SnapshotRetention > 90*24*time.Hour ||
		len(request.FindingIDs) == 0 || len(request.FindingIDs) > 512 { return RepairPlan{}, ErrInvalid }
	run, err := CanonicalRun(request.Run)
	if err != nil || run.RegistryDigest != planner.registry.Digest() || run.State == RunHealthy { return RepairPlan{}, ErrInvalid }
	now := planner.clock.Now().UTC()
	if !validTime(now) || absoluteDuration(now.Sub(request.CreatedAt.UTC())) > 5*time.Minute { return RepairPlan{}, ErrInvalid }
	requested := append([]string(nil), request.FindingIDs...)
	sort.Strings(requested)
	for index, findingID := range requested {
		if !validDigest(findingID) || index > 0 && requested[index-1] == findingID { return RepairPlan{}, ErrInvalid }
	}
	findings := indexFindings(run)
	drafts := make([]stepDraft, 0)
	resources := make(map[string]struct{})
	for _, findingID := range requested {
		finding, found := findings[findingID]
		if !found || !finding.RepairEligible || finding.OwnerID != request.OwnerID { return RepairPlan{}, ErrConflict }
		observation, found := observationFor(run, finding.Kind)
		if !found || now.After(observation.FreshUntil) || observation.State == ProbeUnsupported || observation.State == ProbeUncertain { return RepairPlan{}, ErrStale }
		canonical, resolveErr := planner.canonical.ResolveCanonical(ctx, finding.Scope, finding.Kind)
		if resolveErr != nil { return RepairPlan{}, ErrIntegrity }
		if !canonical.Managed { return RepairPlan{}, ErrUnmanaged }
		if canonical.Validate() != nil || canonical.Scope != finding.Scope || canonical.OwnerID != request.OwnerID ||
			canonical.OwnerID != finding.OwnerID || canonical.ServiceID != finding.ServiceID { return RepairPlan{}, ErrConflict }
		effects := effectsForFinding(finding.Code)
		if len(effects) == 0 { return RepairPlan{}, ErrUnsupported }
		for _, effect := range effects {
			if effect == EffectRestoreOwnership && !validDigest(canonical.OwnershipModeDigest) ||
				effect == EffectRepairCertificate && !validDigest(canonical.CertificateBindingDigest) { return RepairPlan{}, ErrIntegrity }
			drafts = append(drafts, stepDraft{finding: finding, canonical: canonical, effect: effect})
		}
		resources[finding.Scope.ResourceID] = struct{}{}
	}
	steps, err := canonicalSteps(drafts)
	if err != nil { return RepairPlan{}, err }
	resourceIDs := make([]string, 0, len(resources))
	for resourceID := range resources { resourceIDs = append(resourceIDs, resourceID) }
	sort.Strings(resourceIDs)
	plan := RepairPlan{ID: request.ID, RunID: run.ID, RunDigest: run.Digest, Scope: run.Scope, OwnerID: request.OwnerID, ControllerID: request.ControllerID,
		RegistryDigest: run.RegistryDigest, State: PlanPreview, Generation: 1, Fence: 1, Steps: steps,
		Snapshot: SnapshotPolicy{Required: hasMutableStep(steps), ResourceIDs: resourceIDs,
			Retention: request.SnapshotRetention, ProofRequired: true},
		Recovery: RecoveryPolicy{ReverseOrder: true, RequireProof: true,
			AmbiguousStateCodes: []string{"inspect_canonical_generation", "inspect_effect_receipt", "preserve_snapshot"}},
		Irreversible: IrreversibleFrontier{Declared: false, Reason: "none"},
		MaintenanceRequired: anyMaintenance(steps), StepUpRequired: hasMutableStep(steps), ApprovalRequired: hasMutableStep(steps),
		CreatedAt: request.CreatedAt.UTC(), UpdatedAt: request.CreatedAt.UTC()}
	return CanonicalPlan(plan)
}

type stepDraft struct {
	finding   Finding
	canonical CanonicalResource
	effect    EffectKind
}

func canonicalSteps(drafts []stepDraft) ([]RepairStep, error) {
	sort.Slice(drafts, func(i, j int) bool {
		left, right := effectRank(drafts[i].effect), effectRank(drafts[j].effect)
		if left != right { return left < right }
		if drafts[i].finding.Scope.key() != drafts[j].finding.Scope.key() { return drafts[i].finding.Scope.key() < drafts[j].finding.Scope.key() }
		if drafts[i].effect != drafts[j].effect { return drafts[i].effect < drafts[j].effect }
		return drafts[i].finding.ID < drafts[j].finding.ID
	})
	steps := make([]RepairStep, 0, len(drafts))
	byKey := make(map[string]int)
	for _, draft := range drafts {
		key := draft.finding.Scope.key() + "/" + string(draft.finding.Kind) + "/" + string(draft.effect) + "/" +
			draft.canonical.Digest + "/" + uintString(draft.finding.ObservedGeneration)
		if index, exists := byKey[key]; exists {
			steps[index].FindingIDs = append(steps[index].FindingIDs, draft.finding.ID)
			steps[index].Preconditions = append(steps[index].Preconditions,
				Precondition{PreconditionFindingOpen, draft.finding.Digest})
			continue
		}
		step := RepairStep{Effect: draft.effect, Scope: draft.finding.Scope, Diagnostic: draft.finding.Kind,
			ServiceID: draft.canonical.ServiceID, CanonicalGeneration: draft.canonical.Generation,
			CanonicalDigest: draft.canonical.Digest, OwnershipModeDigest: draft.canonical.OwnershipModeDigest,
			CertificateBindingDigest: draft.canonical.CertificateBindingDigest, ObservedGeneration: draft.finding.ObservedGeneration,
			FindingIDs: []string{draft.finding.ID}, SnapshotRequired: draft.effect.mutable(), Impact: impactFor(draft.effect),
			MaintenanceRequired: draft.effect.mutable(), StepUpRequired: draft.effect.mutable(), ApprovalRequired: draft.effect.mutable(),
			Compensation: compensationFor(draft.effect)}
		step.Preconditions = []Precondition{
			{PreconditionFindingOpen, draft.finding.Digest},
			{PreconditionObservedGeneration, digestParts("observed-generation", uintString(draft.finding.ObservedGeneration))},
			{PreconditionCanonicalOwner, digestParts("canonical-owner", draft.canonical.OwnerID, draft.canonical.Digest)},
		}
		if step.SnapshotRequired { step.Preconditions = append(step.Preconditions, Precondition{PreconditionSnapshotProven, draft.canonical.Digest}) }
		if step.MaintenanceRequired { step.Preconditions = append(step.Preconditions, Precondition{PreconditionMaintenance, draft.canonical.Digest}) }
		byKey[key] = len(steps)
		steps = append(steps, step)
	}
	for index := range steps {
		sort.Strings(steps[index].FindingIDs)
		steps[index].Order = uint32(index + 1)
		steps[index].ID = digestParts("repair-step", steps[index].Scope.key(), string(steps[index].Effect),
			steps[index].CanonicalDigest, uintString(uint64(steps[index].Order)))
		if index > 0 { steps[index].DependsOn = []string{steps[index-1].ID} }
		if steps[index].Compensation.Required { steps[index].Compensation.ReferenceDigest = steps[index].CanonicalDigest }
		steps[index].Digest = ""
		digest, err := digestJSON(steps[index])
		if err != nil { return nil, err }
		steps[index].Digest = digest
	}
	return steps, nil
}

func effectsForFinding(code FindingCode) []EffectKind {
	switch code {
	case FindingCanonicalDrift, FindingDNSMismatch, FindingFirewallPolicy:
		return []EffectKind{EffectReconcileGeneration, EffectValidateConfig, EffectReloadService}
	case FindingConfigInvalid:
		return []EffectKind{EffectReconcileGeneration, EffectValidateConfig, EffectReloadService}
	case FindingOwnershipMode:
		return []EffectKind{EffectRestoreOwnership}
	case FindingServiceDegraded:
		return []EffectKind{EffectReloadService}
	case FindingServiceDown, FindingMailDelivery, FindingFTPUnavailable:
		return []EffectKind{EffectRestartService}
	case FindingCertificateBinding:
		return []EffectKind{EffectRepairCertificate, EffectValidateConfig, EffectReloadService}
	default:
		return nil
	}
}

func effectRank(effect EffectKind) int {
	switch effect {
	case EffectReconcileGeneration: return 10
	case EffectRestoreOwnership: return 20
	case EffectRepairCertificate: return 30
	case EffectValidateConfig: return 40
	case EffectReloadService: return 50
	case EffectRestartService: return 60
	default: return 100
	}
}

func impactFor(effect EffectKind) Impact {
	switch effect {
	case EffectValidateConfig: return ImpactNone
	case EffectReloadService, EffectRestoreOwnership, EffectRepairCertificate: return ImpactService
	default: return ImpactWorkload
	}
}

func compensationFor(effect EffectKind) Compensation {
	switch effect {
	case EffectValidateConfig: return Compensation{Kind: CompensationNone, Required: false}
	case EffectReloadService: return Compensation{Kind: CompensationReloadPrevious, Required: true}
	case EffectRestartService: return Compensation{Kind: CompensationRestartPrevious, Required: true}
	case EffectRepairCertificate: return Compensation{Kind: CompensationRestoreCertificate, Required: true}
	default: return Compensation{Kind: CompensationRestoreSnapshot, Required: true}
	}
}

func indexFindings(run DiagnosticRun) map[string]Finding {
	findings := make(map[string]Finding)
	for _, observation := range run.Observations { for _, finding := range observation.Findings { findings[finding.ID] = finding } }
	return findings
}

func observationFor(run DiagnosticRun, kind DiagnosticKind) (ProbeObservation, bool) {
	index := sort.Search(len(run.Observations), func(index int) bool { return run.Observations[index].Kind >= kind })
	if index == len(run.Observations) || run.Observations[index].Kind != kind { return ProbeObservation{}, false }
	return run.Observations[index], true
}

func hasMutableStep(steps []RepairStep) bool { for _, step := range steps { if step.Effect.mutable() { return true } }; return false }

func anyMaintenance(steps []RepairStep) bool { for _, step := range steps { if step.MaintenanceRequired { return true } }; return false }

func CanonicalPlan(plan RepairPlan) (RepairPlan, error) {
	if !identifierPattern.MatchString(plan.ID) || !identifierPattern.MatchString(plan.RunID) || !validDigest(plan.RunDigest) ||
		plan.Scope.Validate() != nil || !identifierPattern.MatchString(plan.OwnerID) || !identifierPattern.MatchString(plan.ControllerID) || !validDigest(plan.RegistryDigest) || !plan.State.Valid() ||
		plan.Generation == 0 || plan.Generation > maxGeneration || plan.Fence == 0 || plan.Fence > maxGeneration || len(plan.Steps) == 0 || len(plan.Steps) > 512 ||
		!validTime(plan.CreatedAt) || !validTime(plan.UpdatedAt) || plan.UpdatedAt.Before(plan.CreatedAt) || plan.Irreversible.Declared ||
		plan.Irreversible.StepID != "" || plan.Irreversible.Reason != "none" || plan.LastReceiptDigest != "" && !validDigest(plan.LastReceiptDigest) ||
		plan.AmbiguousEvidence != "" && !validDigest(plan.AmbiguousEvidence) || len(plan.RecoverySteps) > 32 { return RepairPlan{}, ErrInvalid }
	if plan.SnapshotReference != "" && !identifierPattern.MatchString(plan.SnapshotReference) || plan.SnapshotEvidence != "" && !validDigest(plan.SnapshotEvidence) ||
		(plan.SnapshotReference == "") != (plan.SnapshotEvidence == "") || len(plan.ExecutedSteps) > len(plan.Steps) || len(plan.CompensatedSteps) > len(plan.ExecutedSteps) { return RepairPlan{}, ErrInvalid }
	plan.CreatedAt, plan.UpdatedAt = plan.CreatedAt.UTC(), plan.UpdatedAt.UTC()
	for index, recoveryStep := range plan.RecoverySteps {
		if !identifierPattern.MatchString(recoveryStep) || index > 0 && plan.RecoverySteps[index-1] >= recoveryStep { return RepairPlan{}, ErrInvalid }
	}
	for index, execution := range plan.ExecutedSteps {
		if index >= len(plan.Steps) || execution.StepID != plan.Steps[index].ID || !validDigest(execution.ReceiptDigest) || !validDigest(execution.EvidenceDigest) { return RepairPlan{}, ErrInvalid }
	}
	for index, execution := range plan.CompensatedSteps {
		expected := plan.ExecutedSteps[len(plan.ExecutedSteps)-1-index].StepID
		if execution.StepID != expected || !validDigest(execution.ReceiptDigest) || !validDigest(execution.EvidenceDigest) { return RepairPlan{}, ErrInvalid }
	}
	resourceSet := make(map[string]struct{})
	for index, step := range plan.Steps {
		if step.Order != uint32(index+1) || !validDigest(step.ID) || !validDigest(step.Digest) || !step.Effect.Valid() || step.Scope.Validate() != nil ||
			step.Scope != plan.Scope || !step.Diagnostic.Valid() || !identifierPattern.MatchString(step.ServiceID) || step.CanonicalGeneration == 0 ||
			step.CanonicalGeneration > maxGeneration || !validDigest(step.CanonicalDigest) ||
			step.OwnershipModeDigest != "" && !validDigest(step.OwnershipModeDigest) ||
			step.CertificateBindingDigest != "" && !validDigest(step.CertificateBindingDigest) ||
			step.ObservedGeneration > maxGeneration || len(step.FindingIDs) == 0 || len(step.Preconditions) == 0 ||
			step.Impact != impactFor(step.Effect) || step.SnapshotRequired != step.Effect.mutable() ||
			step.MaintenanceRequired != step.Effect.mutable() || step.StepUpRequired != step.Effect.mutable() ||
			step.ApprovalRequired != step.Effect.mutable() ||
			index == 0 && len(step.DependsOn) != 0 || index > 0 && (len(step.DependsOn) != 1 || step.DependsOn[0] != plan.Steps[index-1].ID) {
			return RepairPlan{}, ErrInvalid
		}
		if step.ID != digestParts("repair-step", step.Scope.key(), string(step.Effect), step.CanonicalDigest, uintString(uint64(step.Order))) { return RepairPlan{}, ErrIntegrity }
		resourceSet[step.Scope.ResourceID] = struct{}{}
		for findingIndex, findingID := range step.FindingIDs {
			if !validDigest(findingID) || findingIndex > 0 && step.FindingIDs[findingIndex-1] >= findingID { return RepairPlan{}, ErrInvalid }
		}
		findingPreconditions, observedPreconditions, ownerPreconditions, snapshotPreconditions, maintenancePreconditions := 0, 0, 0, 0, 0
		seenFindingPreconditions := make(map[string]struct{}, len(step.FindingIDs))
		for _, precondition := range step.Preconditions {
			if precondition.Kind != PreconditionFindingOpen && precondition.Kind != PreconditionObservedGeneration &&
				precondition.Kind != PreconditionCanonicalOwner && precondition.Kind != PreconditionSnapshotProven &&
				precondition.Kind != PreconditionMaintenance || !validDigest(precondition.ExpectedDigest) { return RepairPlan{}, ErrInvalid }
			switch precondition.Kind {
			case PreconditionFindingOpen:
				findingID := digestParts("finding", precondition.ExpectedDigest)
				position := sort.SearchStrings(step.FindingIDs, findingID)
				if position == len(step.FindingIDs) || step.FindingIDs[position] != findingID { return RepairPlan{}, ErrIntegrity }
				if _, duplicate := seenFindingPreconditions[findingID]; duplicate { return RepairPlan{}, ErrInvalid }
				seenFindingPreconditions[findingID] = struct{}{}
				findingPreconditions++
			case PreconditionObservedGeneration:
				if precondition.ExpectedDigest != digestParts("observed-generation", uintString(step.ObservedGeneration)) { return RepairPlan{}, ErrIntegrity }
				observedPreconditions++
			case PreconditionCanonicalOwner:
				if precondition.ExpectedDigest != digestParts("canonical-owner", plan.OwnerID, step.CanonicalDigest) { return RepairPlan{}, ErrIntegrity }
				ownerPreconditions++
			case PreconditionSnapshotProven:
				if precondition.ExpectedDigest != step.CanonicalDigest { return RepairPlan{}, ErrIntegrity }
				snapshotPreconditions++
			case PreconditionMaintenance:
				if precondition.ExpectedDigest != step.CanonicalDigest { return RepairPlan{}, ErrIntegrity }
				maintenancePreconditions++
			}
		}
		if findingPreconditions != len(step.FindingIDs) || observedPreconditions != 1 || ownerPreconditions != 1 ||
			snapshotPreconditions != int(boolUint(step.SnapshotRequired)) || maintenancePreconditions != int(boolUint(step.MaintenanceRequired)) { return RepairPlan{}, ErrInvalid }
		expectedCompensation := compensationFor(step.Effect)
		if step.Compensation.Kind != expectedCompensation.Kind || step.Compensation.Required != expectedCompensation.Required ||
			step.Compensation.Required && step.Compensation.ReferenceDigest != step.CanonicalDigest ||
			!step.Compensation.Required && step.Compensation.ReferenceDigest != "" { return RepairPlan{}, ErrInvalid }
		if step.Effect == EffectRestoreOwnership && !validDigest(step.OwnershipModeDigest) ||
			step.Effect == EffectRepairCertificate && !validDigest(step.CertificateBindingDigest) { return RepairPlan{}, ErrInvalid }
		claimed := step.Digest
		step.Digest = ""
		digest, err := digestJSON(step)
		if err != nil || claimed != digest { return RepairPlan{}, ErrIntegrity }
	}
	if plan.Snapshot.Required != hasMutableStep(plan.Steps) || !plan.Snapshot.ProofRequired || plan.Snapshot.Retention < time.Hour ||
		plan.Snapshot.Retention > 90*24*time.Hour || len(plan.Snapshot.ResourceIDs) != len(resourceSet) || !plan.Recovery.ReverseOrder || !plan.Recovery.RequireProof ||
		plan.MaintenanceRequired != anyMaintenance(plan.Steps) || plan.StepUpRequired != hasMutableStep(plan.Steps) ||
		plan.ApprovalRequired != hasMutableStep(plan.Steps) { return RepairPlan{}, ErrInvalid }
	for index, resourceID := range plan.Snapshot.ResourceIDs {
		if !identifierPattern.MatchString(resourceID) || index > 0 && plan.Snapshot.ResourceIDs[index-1] >= resourceID { return RepairPlan{}, ErrInvalid }
		if _, found := resourceSet[resourceID]; !found { return RepairPlan{}, ErrIntegrity }
	}
	if len(plan.Recovery.AmbiguousStateCodes) == 0 || len(plan.Recovery.AmbiguousStateCodes) > 16 { return RepairPlan{}, ErrInvalid }
	for index, code := range plan.Recovery.AmbiguousStateCodes {
		if !identifierPattern.MatchString(code) || index > 0 && plan.Recovery.AmbiguousStateCodes[index-1] >= code { return RepairPlan{}, ErrInvalid }
	}
	if plan.State == PlanPreview || plan.State == PlanApproved {
		if plan.SnapshotReference != "" || len(plan.ExecutedSteps) != 0 || len(plan.CompensatedSteps) != 0 || plan.AmbiguousEvidence != "" { return RepairPlan{}, ErrIntegrity }
	}
	if plan.State == PlanSucceeded && (len(plan.ExecutedSteps) != len(plan.Steps) || len(plan.CompensatedSteps) != 0 ||
		plan.Snapshot.Required && plan.SnapshotReference == "" || plan.AmbiguousEvidence != "") { return RepairPlan{}, ErrIntegrity }
	if plan.State == PlanRolledBack && (len(plan.ExecutedSteps) == 0 || len(plan.CompensatedSteps) != len(plan.ExecutedSteps) ||
		plan.SnapshotReference == "" || plan.AmbiguousEvidence != "") { return RepairPlan{}, ErrIntegrity }
	if plan.State == PlanUncertain && (!validDigest(plan.AmbiguousEvidence) || len(plan.RecoverySteps) == 0) { return RepairPlan{}, ErrIntegrity }
	definition := struct {
		ID                  string               `json:"id"`
		RunID               string               `json:"run_id"`
		RunDigest           string               `json:"run_digest"`
		Scope               Scope                `json:"scope"`
		OwnerID             string               `json:"owner_id"`
		RegistryDigest      string               `json:"registry_digest"`
		Steps               []RepairStep         `json:"steps"`
		Snapshot            SnapshotPolicy       `json:"snapshot"`
		Recovery            RecoveryPolicy       `json:"recovery"`
		Irreversible        IrreversibleFrontier `json:"irreversible_frontier"`
		MaintenanceRequired bool                 `json:"maintenance_required"`
		StepUpRequired      bool                 `json:"step_up_required"`
		ApprovalRequired    bool                 `json:"approval_required"`
		CreatedAt           time.Time            `json:"created_at"`
	}{plan.ID, plan.RunID, plan.RunDigest, plan.Scope, plan.OwnerID, plan.RegistryDigest, plan.Steps,
		plan.Snapshot, plan.Recovery, plan.Irreversible, plan.MaintenanceRequired, plan.StepUpRequired,
		plan.ApprovalRequired, plan.CreatedAt}
	definitionDigest, err := digestJSON(definition)
	if err != nil || plan.DefinitionDigest != "" && plan.DefinitionDigest != definitionDigest { return RepairPlan{}, ErrIntegrity }
	plan.DefinitionDigest = definitionDigest
	claimed := plan.Digest
	plan.Digest = ""
	digest, err := digestJSON(plan)
	if err != nil || claimed != "" && claimed != digest { return RepairPlan{}, ErrIntegrity }
	plan.Digest = digest
	return plan, nil
}

type StepProof struct {
	Order      uint32     `json:"order"`
	Effect     EffectKind `json:"effect"`
	Impact     Impact     `json:"impact"`
	StepDigest string     `json:"step_digest"`
}

type PlanProofManifest struct {
	PlanID       string      `json:"plan_id"`
	RunID        string      `json:"run_id"`
	State        PlanState   `json:"state"`
	Generation   uint64      `json:"generation"`
	StepUp       bool        `json:"step_up_required"`
	Maintenance  bool        `json:"maintenance_required"`
	Steps        []StepProof `json:"steps"`
	UpdatedAt    time.Time   `json:"updated_at"`
	Digest       string      `json:"digest"`
}

func ExportPlan(plan RepairPlan, maximumBytes int) (PlanProofManifest, []byte, error) {
	plan, err := CanonicalPlan(plan)
	if err != nil || maximumBytes < 1024 || maximumBytes > 16<<20 { return PlanProofManifest{}, nil, ErrInvalid }
	proof := PlanProofManifest{PlanID: plan.ID, RunID: plan.RunID, State: plan.State, Generation: plan.Generation,
		StepUp: plan.StepUpRequired, Maintenance: plan.MaintenanceRequired, UpdatedAt: plan.UpdatedAt}
	for _, step := range plan.Steps { proof.Steps = append(proof.Steps, StepProof{step.Order, step.Effect, step.Impact, step.Digest}) }
	proof.Digest, err = digestJSON(proof)
	if err != nil { return PlanProofManifest{}, nil, err }
	raw, err := json.Marshal(proof)
	if err != nil || len(raw) > maximumBytes { return PlanProofManifest{}, nil, ErrCapacity }
	return proof, raw, nil
}
