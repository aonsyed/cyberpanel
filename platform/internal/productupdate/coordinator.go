package productupdate

import (
	"context"
	"sort"
	"time"
)

type UpdateAction string

const (
	ActionVerify    UpdateAction = "verify"
	ActionFence     UpdateAction = "fence"
	ActionStage     UpdateAction = "stage"
	ActionPreflight UpdateAction = "preflight"
	ActionSwitch    UpdateAction = "switch"
	ActionProbe     UpdateAction = "probe"
	ActionFinalize  UpdateAction = "finalize"
	ActionCommit    UpdateAction = "commit"
	ActionRollback  UpdateAction = "rollback"
	ActionFail      UpdateAction = "fail"
)

type Approval struct {
	ID             string    `json:"id"`
	Approver       string    `json:"approver"`
	DecisionDigest string    `json:"decision_digest"`
	ApprovedAt     time.Time `json:"approved_at"`
}

type UpdateAuthorization struct {
	ID             string       `json:"id"`
	Issuer         string       `json:"issuer"`
	Subject        string       `json:"subject"`
	NodeID         string       `json:"node_id"`
	ManifestDigest string       `json:"manifest_digest"`
	Action         UpdateAction `json:"action"`
	HighAssurance  bool         `json:"high_assurance"`
	StepUp         bool         `json:"step_up"`
	ScopeDigest    string       `json:"scope_digest"`
	IssuedAt       time.Time    `json:"issued_at"`
	ExpiresAt      time.Time    `json:"expires_at"`
	ProofDigest    string       `json:"proof_digest"`
	Approval       Approval     `json:"approval"`
	Digest         string       `json:"digest"`
}

func CanonicalAuthorization(authorization UpdateAuthorization, manifest ReleaseManifest, nodeID string, action UpdateAction, now time.Time) (UpdateAuthorization, error) {
	if !identifierPattern.MatchString(authorization.ID) || !identifierPattern.MatchString(authorization.Issuer) ||
		!identifierPattern.MatchString(authorization.Subject) || authorization.NodeID != nodeID ||
		authorization.ManifestDigest != manifest.Digest || authorization.Action != action || !authorization.HighAssurance || !authorization.StepUp ||
		!validDigest(authorization.ScopeDigest) || !validDigest(authorization.ProofDigest) || !validTime(authorization.IssuedAt) ||
		!validTime(authorization.ExpiresAt) || !authorization.ExpiresAt.After(authorization.IssuedAt) || now.Before(authorization.IssuedAt) ||
		!now.Before(authorization.ExpiresAt) || !identifierPattern.MatchString(authorization.Approval.ID) ||
		!identifierPattern.MatchString(authorization.Approval.Approver) || !validDigest(authorization.Approval.DecisionDigest) ||
		!validTime(authorization.Approval.ApprovedAt) || authorization.Approval.ApprovedAt.Before(authorization.IssuedAt) ||
		authorization.Approval.ApprovedAt.After(authorization.ExpiresAt) {
		return UpdateAuthorization{}, ErrUnauthorized
	}
	if authorization.ScopeDigest != digestParts("product-update-scope", manifest.Digest, nodeID, string(action)) { return UpdateAuthorization{}, ErrUnauthorized }
	authorization.IssuedAt, authorization.ExpiresAt = authorization.IssuedAt.UTC(), authorization.ExpiresAt.UTC()
	authorization.Approval.ApprovedAt = authorization.Approval.ApprovedAt.UTC()
	claimed := authorization.Digest
	authorization.Digest = ""
	digest, err := digestJSON(authorization)
	if err != nil || claimed != digest { return UpdateAuthorization{}, ErrIntegrity }
	authorization.Digest = digest
	return authorization, nil
}

type AuthorizationVerifier interface {
	VerifyUpdateAuthorization(context.Context, UpdateAuthorization) error
}

type MaintenanceRequest struct {
	ManifestID      string        `json:"manifest_id"`
	ManifestDigest  string        `json:"manifest_digest"`
	NodeID          string        `json:"node_id"`
	Action          UpdateAction  `json:"action"`
	Rollout         RolloutClass  `json:"rollout"`
	Fence           uint64        `json:"fence"`
	RequestedAt     time.Time     `json:"requested_at"`
	ExpectedDuration time.Duration `json:"expected_duration"`
	Digest          string        `json:"digest"`
}

type MaintenanceAdmission struct {
	Allowed          bool      `json:"allowed"`
	OccurrenceID     string    `json:"occurrence_id"`
	OccurrenceDigest string    `json:"occurrence_digest"`
	EndsAt           time.Time `json:"ends_at"`
	EvidenceDigest   string    `json:"evidence_digest"`
	Digest           string    `json:"digest"`
}

type MaintenanceGate interface {
	AdmitProductUpdate(context.Context, MaintenanceRequest) (MaintenanceAdmission, error)
}

type AuditRecord struct {
	ID                  string       `json:"id"`
	ManifestID          string       `json:"manifest_id"`
	NodeID               string       `json:"node_id"`
	Action               UpdateAction `json:"action"`
	Generation           uint64       `json:"generation"`
	Fence                uint64       `json:"fence"`
	AuthorizationDigest  string       `json:"authorization_digest"`
	MaintenanceEvidence  string       `json:"maintenance_evidence,omitempty"`
	IntentDigest         string       `json:"intent_digest"`
	At                   time.Time    `json:"at"`
	Digest               string       `json:"digest"`
}

type AuditSink interface { RecordProductUpdate(context.Context, AuditRecord) error }

type InventorySource interface { InstalledInventory(context.Context, string) (InstalledInventory, error) }

type Clock interface { Now() time.Time }

type ActiveRelease struct {
	ID       string `json:"id"`
	Digest   string `json:"digest"`
	Evidence string `json:"evidence"`
}

func (release ActiveRelease) Validate() error {
	if !identifierPattern.MatchString(release.ID) || !validDigest(release.Digest) || !validDigest(release.Evidence) { return ErrIntegrity }
	return nil
}

type EffectReceipt struct {
	ID              string    `json:"id"`
	OperationDigest string    `json:"operation_digest"`
	EvidenceDigest  string    `json:"evidence_digest"`
	Completed       bool      `json:"completed"`
	At              time.Time `json:"at"`
	Digest          string    `json:"digest"`
}

func canonicalEffect(receipt EffectReceipt, operationDigest string) (EffectReceipt, error) {
	if !identifierPattern.MatchString(receipt.ID) || receipt.OperationDigest != operationDigest || !validDigest(receipt.EvidenceDigest) ||
		!receipt.Completed || !validTime(receipt.At) { return EffectReceipt{}, ErrIntegrity }
	receipt.At = receipt.At.UTC()
	claimed := receipt.Digest
	receipt.Digest = ""
	digest, err := digestJSON(receipt)
	if err != nil || claimed != digest { return EffectReceipt{}, ErrIntegrity }
	receipt.Digest = digest
	return receipt, nil
}

type MigrationOperation struct {
	ManifestID     string        `json:"manifest_id"`
	ManifestDigest string        `json:"manifest_digest"`
	NodeID         string        `json:"node_id"`
	Step           MigrationStep `json:"step"`
	ReleaseRoot    ReleaseRoot   `json:"release_root"`
	Fence          uint64        `json:"fence"`
	IdempotencyKey string        `json:"idempotency_key"`
	Digest         string        `json:"digest"`
}

type MigrationAssessment struct {
	OperationDigest string `json:"operation_digest"`
	Reversible      bool   `json:"reversible"`
	EvidenceDigest  string `json:"evidence_digest"`
	Digest          string `json:"digest"`
}

type BackupOperation struct {
	Migration      MigrationOperation `json:"migration"`
	Online         bool               `json:"online"`
	IdempotencyKey string             `json:"idempotency_key"`
	Digest         string             `json:"digest"`
}

type MigrationRollbackOperation struct {
	Migration          MigrationOperation `json:"migration"`
	BackupEvidence     string             `json:"backup_evidence"`
	RollbackProof      string             `json:"rollback_proof"`
	IdempotencyKey     string             `json:"idempotency_key"`
	Digest             string             `json:"digest"`
}

type MigrationExecutor interface {
	PreflightMigration(context.Context, MigrationOperation) (MigrationAssessment, error)
	OnlineBackup(context.Context, BackupOperation) (EffectReceipt, error)
	ApplyMigration(context.Context, MigrationOperation) (EffectReceipt, error)
	RollbackMigration(context.Context, MigrationRollbackOperation) (EffectReceipt, error)
}

type RollbackInspection struct {
	ManifestID     string        `json:"manifest_id"`
	NodeID         string        `json:"node_id"`
	Current        ActiveRelease `json:"current"`
	Target         ReleaseRoot   `json:"target"`
	RollbackClass  RollbackClass `json:"rollback_class"`
	Fence          uint64        `json:"fence"`
	Digest         string        `json:"digest"`
}

type RollbackProof struct {
	InspectionDigest string `json:"inspection_digest"`
	Valid            bool   `json:"valid"`
	PreviousID       string `json:"previous_id"`
	PreviousDigest   string `json:"previous_digest"`
	EvidenceDigest   string `json:"evidence_digest"`
	Digest           string `json:"digest"`
}

type SwitchOperation struct {
	ManifestID     string        `json:"manifest_id"`
	ManifestDigest string        `json:"manifest_digest"`
	NodeID         string        `json:"node_id"`
	Previous       ActiveRelease `json:"previous"`
	Target         ReleaseRoot   `json:"target"`
	Fence          uint64        `json:"fence"`
	IdempotencyKey string        `json:"idempotency_key"`
	Digest         string        `json:"digest"`
}

type FinalizeOperation struct {
	Disposition       FinalizeDisposition `json:"disposition"`
	ManifestID       string `json:"manifest_id"`
	ManifestDigest   string `json:"manifest_digest"`
	NodeID           string `json:"node_id"`
	ActiveReleaseID  string `json:"active_release_id"`
	ActiveDigest     string `json:"active_digest"`
	PreviousID       string `json:"previous_id"`
	PreviousDigest   string `json:"previous_digest"`
	Fence            uint64 `json:"fence"`
	IdempotencyKey   string `json:"idempotency_key"`
	Digest           string `json:"digest"`
}

type FinalizeDisposition string

const (
	FinalizeCommit   FinalizeDisposition = "commit"
	FinalizeRollback FinalizeDisposition = "rollback"
)

type PlatformExecutor interface {
	CurrentRelease(context.Context, string) (ActiveRelease, error)
	InspectRollback(context.Context, RollbackInspection) (RollbackProof, error)
	AtomicSwitch(context.Context, SwitchOperation) (EffectReceipt, error)
	CommitSwitch(context.Context, FinalizeOperation) (EffectReceipt, error)
	AtomicRollback(context.Context, FinalizeOperation) (EffectReceipt, error)
}

type HealthSnapshot struct {
	ID                          string    `json:"id"`
	NodeID                      string    `json:"node_id"`
	ActiveReleaseDigest         string    `json:"active_release_digest"`
	ControlPlaneHealthy         bool      `json:"control_plane_healthy"`
	HostedWorkloadNonRegression bool      `json:"hosted_workload_non_regression"`
	ObservedAt                  time.Time `json:"observed_at"`
	EvidenceDigest              string    `json:"evidence_digest"`
	Digest                      string    `json:"digest"`
}

type ProbeOperation struct {
	ManifestID           string `json:"manifest_id"`
	NodeID                string `json:"node_id"`
	ExpectedReleaseDigest string `json:"expected_release_digest"`
	BaselineDigest       string `json:"baseline_digest"`
	Fence                uint64 `json:"fence"`
	Digest               string `json:"digest"`
}

type HealthProber interface {
	CaptureBaseline(context.Context, string) (HealthSnapshot, error)
	ProbeRelease(context.Context, ProbeOperation) (HealthSnapshot, error)
}

type Command struct {
	ManifestID       string
	NodeID           string
	ExpectedGeneration uint64
	Fence            uint64
	ControllerID     string
	IdempotencyKey   string
	At               time.Time
	ExpectedDuration time.Duration
	Authorization    UpdateAuthorization
}

type Coordinator struct {
	repository    *Repository
	verifier      *Verifier
	stager        *Stager
	inventory     InventorySource
	authorization AuthorizationVerifier
	maintenance   MaintenanceGate
	audit         AuditSink
	migrations    MigrationExecutor
	platform      PlatformExecutor
	health        HealthProber
	clock         Clock
}

func NewCoordinator(repository *Repository, verifier *Verifier, stager *Stager, inventory InventorySource,
	authorization AuthorizationVerifier, maintenance MaintenanceGate, audit AuditSink, migrations MigrationExecutor,
	platform PlatformExecutor, health HealthProber, clock Clock) (*Coordinator, error) {
	if repository == nil || verifier == nil || stager == nil || inventory == nil || authorization == nil ||
		maintenance == nil || audit == nil || migrations == nil || platform == nil || health == nil || clock == nil { return nil, ErrInvalid }
	return &Coordinator{repository, verifier, stager, inventory, authorization, maintenance, audit, migrations, platform, health, clock}, nil
}

func (coordinator *Coordinator) Discover(ctx context.Context, manifest ReleaseManifest, nodeID, controllerID, idempotencyKey string, at time.Time) (UpdateState, Receipt, error) {
	if !coordinator.current(at) { return UpdateState{}, Receipt{}, ErrInvalid }
	return coordinator.repository.CreateDiscovered(ctx, manifest, nodeID, controllerID, idempotencyKey, at)
}

func (coordinator *Coordinator) Version(ctx context.Context, nodeID string) (VersionProjection, error) {
	if !identifierPattern.MatchString(nodeID) { return VersionProjection{}, ErrInvalid }
	inventory, err := coordinator.inventory.InstalledInventory(ctx, nodeID)
	if err != nil { return VersionProjection{}, ErrIntegrity }
	return RedactedVersion(inventory)
}

func (coordinator *Coordinator) Inspect(ctx context.Context, manifestID, nodeID string) (UpdateProjection, error) {
	manifest, state, err := coordinator.repository.Get(ctx, manifestID, nodeID)
	if err != nil { return UpdateProjection{}, err }
	return RedactedUpdate(manifest, state)
}

func (coordinator *Coordinator) List(ctx context.Context, phase Phase, afterManifest, afterNode string, limit int) ([]UpdateProjection, error) {
	states, err := coordinator.repository.List(ctx, phase, afterManifest, afterNode, limit)
	if err != nil { return nil, err }
	projections := make([]UpdateProjection, 0, len(states))
	for _, state := range states {
		manifest, err := loadManifest(ctx, coordinator.repository.db, state.ManifestID)
		if err != nil { return nil, err }
		projection, err := RedactedUpdate(manifest, state)
		if err != nil { return nil, err }
		projections = append(projections, projection)
	}
	return projections, nil
}

func (coordinator *Coordinator) Takeover(ctx context.Context, command Command, toController string) (UpdateState, Receipt, error) {
	if !identifierPattern.MatchString(toController) || command.ExpectedGeneration >= maxGeneration || command.Fence >= maxGeneration || !coordinator.current(command.At) { return UpdateState{}, Receipt{}, ErrInvalid }
	if replayState, replayReceipt, found, replayErr := coordinator.repository.replay(ctx, command.ManifestID, command.NodeID, command.IdempotencyKey); replayErr != nil {
		return UpdateState{}, Receipt{}, replayErr
	} else if found {
		if replayReceipt.From != replayReceipt.To || replayReceipt.Generation != command.ExpectedGeneration+1 || replayReceipt.Fence != command.Fence+1 || replayState.Fence < replayReceipt.Fence {
			return UpdateState{}, Receipt{}, ErrIntegrity
		}
		return replayState, replayReceipt, nil
	}
	manifest, state, err := coordinator.repository.Get(ctx, command.ManifestID, command.NodeID)
	if err != nil { return UpdateState{}, Receipt{}, err }
	if state.Generation != command.ExpectedGeneration || state.Fence != command.Fence || state.ControllerID != command.ControllerID {
		return UpdateState{}, Receipt{}, ErrConflict
	}
	authorization, err := CanonicalAuthorization(command.Authorization, manifest, command.NodeID, ActionFence, coordinator.clock.Now().UTC())
	if err != nil { return UpdateState{}, Receipt{}, err }
	intent := digestParts("fence", manifest.Digest, state.ControllerID, toController, fmtUint(state.Fence))
	if authorization.Approval.DecisionDigest != intent { return UpdateState{}, Receipt{}, ErrUnauthorized }
	if err := coordinator.authorization.VerifyUpdateAuthorization(ctx, authorization); err != nil { return UpdateState{}, Receipt{}, ErrUnauthorized }
	if err := coordinator.recordAudit(ctx, state, authorization, ActionFence, "", intent, command.At); err != nil { return UpdateState{}, Receipt{}, err }
	return coordinator.repository.fence(ctx, command.ManifestID, command.NodeID, command.ControllerID, toController,
		command.IdempotencyKey, command.ExpectedGeneration, command.Fence, command.At)
}

func (coordinator *Coordinator) FailBeforeSwitch(ctx context.Context, command Command, evidenceDigest string) (UpdateState, Receipt, error) {
	if !validDigest(evidenceDigest) || !coordinator.current(command.At) { return UpdateState{}, Receipt{}, ErrInvalid }
	if state, receipt, found, err := coordinator.replay(ctx, command, "", PhaseFailed); found || err != nil { return state, receipt, err }
	manifest, state, err := coordinator.repository.Get(ctx, command.ManifestID, command.NodeID)
	if err != nil { return UpdateState{}, Receipt{}, err }
	if state.Phase != PhaseDiscovered && state.Phase != PhaseVerified && state.Phase != PhaseStaged ||
		state.Generation != command.ExpectedGeneration || state.Fence != command.Fence || state.ControllerID != command.ControllerID {
		return UpdateState{}, Receipt{}, ErrConflict
	}
	authorization, err := CanonicalAuthorization(command.Authorization, manifest, command.NodeID, ActionFail, coordinator.clock.Now().UTC())
	if err != nil { return UpdateState{}, Receipt{}, err }
	if err := coordinator.authorization.VerifyUpdateAuthorization(ctx, authorization); err != nil { return UpdateState{}, Receipt{}, ErrUnauthorized }
	if err := coordinator.recordAudit(ctx, state, authorization, ActionFail, "", evidenceDigest, command.At); err != nil { return UpdateState{}, Receipt{}, err }
	return coordinator.repository.transition(ctx, transitionFor(command, state, PhaseFailed, ReasonRejected, evidenceDigest))
}

func (coordinator *Coordinator) Verify(ctx context.Context, command Command) (UpdateState, Receipt, error) {
	if state, receipt, found, err := coordinator.replay(ctx, command, PhaseDiscovered, PhaseVerified); found || err != nil { return state, receipt, err }
	manifest, state, authorization, err := coordinator.loadAuthorized(ctx, command, PhaseDiscovered, ActionVerify)
	if err != nil { return UpdateState{}, Receipt{}, err }
	inventory, err := coordinator.inventory.InstalledInventory(ctx, command.NodeID)
	if err != nil { return UpdateState{}, Receipt{}, ErrIntegrity }
	sequence, digest, err := coordinator.repository.AcceptedSequence(ctx, command.NodeID, manifest.Platform)
	if err != nil { return UpdateState{}, Receipt{}, err }
	manifest, inventory, err = coordinator.verifier.Verify(manifest, inventory, coordinator.clock.Now().UTC(), sequence, digest)
	if err != nil { return UpdateState{}, Receipt{}, err }
	evidence := digestParts("verified", manifest.Digest, inventory.Digest, authorization.Digest, fmtUint(sequence))
	if err := coordinator.recordAudit(ctx, state, authorization, ActionVerify, "", evidence, command.At); err != nil { return UpdateState{}, Receipt{}, err }
	return coordinator.repository.transition(ctx, transitionFor(command, state, PhaseVerified, ReasonVerified, evidence))
}

func (coordinator *Coordinator) Stage(ctx context.Context, command Command, source ArtifactSource) (UpdateState, Receipt, error) {
	if state, receipt, found, err := coordinator.replay(ctx, command, PhaseVerified, PhaseStaged); found || err != nil { return state, receipt, err }
	manifest, state, authorization, err := coordinator.loadAuthorized(ctx, command, PhaseVerified, ActionStage)
	if err != nil { return UpdateState{}, Receipt{}, err }
	intent := digestParts("stage", manifest.Digest, authorization.Digest, fmtUint(command.Fence))
	if err := coordinator.recordAudit(ctx, state, authorization, ActionStage, "", intent, command.At); err != nil { return UpdateState{}, Receipt{}, err }
	release, err := coordinator.stager.stage(ctx, manifest, source)
	if err != nil { return UpdateState{}, Receipt{}, err }
	transition := transitionFor(command, state, PhaseStaged, ReasonStaged, release.EvidenceDigest)
	transition.StagedRootID, transition.StagedRootDigest = release.Root.ID, release.Root.Digest
	return coordinator.repository.transition(ctx, transition)
}

func (coordinator *Coordinator) Preflight(ctx context.Context, command Command) (UpdateState, Receipt, error) {
	if state, receipt, found, err := coordinator.replay(ctx, command, PhaseStaged, PhasePreflighted, PhaseUncertain); found || err != nil { return state, receipt, err }
	manifest, state, authorization, err := coordinator.loadAuthorized(ctx, command, PhaseStaged, ActionPreflight)
	if err != nil { return UpdateState{}, Receipt{}, err }
	admission, err := coordinator.admit(ctx, command, manifest, ActionPreflight)
	if err != nil { return UpdateState{}, Receipt{}, err }
	root, err := coordinator.stager.resolve(state.StagedRootID, state.StagedRootDigest)
	if err != nil { return UpdateState{}, Receipt{}, err }
	inventory, err := coordinator.inventory.InstalledInventory(ctx, command.NodeID)
	if err != nil { return UpdateState{}, Receipt{}, ErrIntegrity }
	inventory, err = CanonicalInventory(inventory)
	if err != nil { return UpdateState{}, Receipt{}, err }
	if len(manifest.Migrations) > 0 && manifest.Migrations[0].FromSchema != inventory.SchemaVersion { return UpdateState{}, Receipt{}, ErrIncompatible }
	active, err := coordinator.platform.CurrentRelease(ctx, command.NodeID)
	if err != nil || active.Validate() != nil { return UpdateState{}, Receipt{}, ErrIntegrity }
	baseline, err := coordinator.health.CaptureBaseline(ctx, command.NodeID)
	if err != nil || validateHealth(baseline, command.NodeID, active.Digest, false) != nil { return UpdateState{}, Receipt{}, ErrIntegrity }
	inspection := RollbackInspection{ManifestID: manifest.ID, NodeID: command.NodeID, Current: active,
		Target: root, RollbackClass: manifest.Rollback, Fence: command.Fence}
	inspection.Digest, _ = digestJSON(inspection)
	proof := RollbackProof{}
	proofValid := false
	proofEvidence := digestParts("rollback-not-declared", manifest.Digest)
	if manifest.Rollback != RollbackNone {
		proof, err = coordinator.platform.InspectRollback(ctx, inspection)
		if err != nil || validateRollbackProof(proof, inspection, manifest) != nil { return UpdateState{}, Receipt{}, ErrRollback }
		proofValid, proofEvidence = true, proof.EvidenceDigest
	}
	intent := digestParts("preflight", manifest.Digest, root.Digest, active.Digest, baseline.Digest,
		admission.EvidenceDigest, authorization.Digest, proofEvidence)
	if err := coordinator.recordAudit(ctx, state, authorization, ActionPreflight, admission.EvidenceDigest, intent, command.At); err != nil {
		return UpdateState{}, Receipt{}, err
	}
	assessments := make(map[string]string, len(manifest.Migrations))
	backups := make(map[string]string, len(manifest.Migrations))
	operations := make([]MigrationOperation, 0, len(manifest.Migrations))
	for _, step := range manifest.Migrations {
		operation := migrationOperation(manifest, command, root, step)
		assessment, assessErr := coordinator.migrations.PreflightMigration(ctx, operation)
		if assessErr != nil || validateAssessment(assessment, operation, !step.ForwardOnly) != nil {
			return coordinator.externalUncertain(ctx, command, state, authorization, ActionPreflight,
				digestParts("migration-preflight-uncertain", operation.Digest), []string{"inspect_migration_preflight"})
		}
		if manifest.Rollback == RollbackFull && !assessment.Reversible { proofValid = false }
		assessments[step.ID] = assessment.Digest
		operations = append(operations, operation)
	}
	for _, operation := range operations {
		if !operation.Step.BackupRequired { continue }
		backup := BackupOperation{Migration: operation, Online: true, IdempotencyKey: digestParts(command.IdempotencyKey, "backup", operation.Step.ID)}
		backup.Digest, _ = digestJSON(backup)
		receipt, backupErr := coordinator.migrations.OnlineBackup(ctx, backup)
		if backupErr != nil {
			return coordinator.externalUncertain(ctx, command, state, authorization, ActionPreflight,
				digestParts("backup-uncertain", backup.Digest), []string{"inspect_online_backup", "do_not_switch_release"})
		}
		receipt, backupErr = canonicalEffect(receipt, backup.Digest)
		if backupErr != nil { return coordinator.externalUncertain(ctx, command, state, authorization, ActionPreflight,
			digestParts("backup-receipt-invalid", backup.Digest), []string{"inspect_online_backup", "do_not_switch_release"}) }
		backups[operation.Step.ID] = receipt.EvidenceDigest
	}
	applied := make(map[string]string, len(operations))
	for _, operation := range operations {
		receipt, applyErr := coordinator.migrations.ApplyMigration(ctx, operation)
		if applyErr != nil {
			return coordinator.externalUncertain(ctx, command, state, authorization, ActionPreflight,
				digestParts("migration-apply-uncertain", operation.Digest), []string{"inspect_schema_version", "preserve_online_backup"})
		}
		receipt, applyErr = canonicalEffect(receipt, operation.Digest)
		if applyErr != nil { return coordinator.externalUncertain(ctx, command, state, authorization, ActionPreflight,
			digestParts("migration-receipt-invalid", operation.Digest), []string{"inspect_schema_version", "preserve_online_backup"}) }
		applied[operation.Step.ID] = receipt.Digest
	}
	postMigrationDigest := inventory.Digest
	if len(operations) > 0 {
		postInventory, observeErr := coordinator.inventory.InstalledInventory(ctx, command.NodeID)
		if observeErr != nil { return coordinator.externalUncertain(ctx, command, state, authorization, ActionPreflight,
			digestParts("schema-observation-uncertain", manifest.Digest), []string{"inspect_schema_version", "preserve_online_backup"}) }
		postInventory, observeErr = CanonicalInventory(postInventory)
		expectedSchema := operations[len(operations)-1].Step.ToSchema
		if observeErr != nil || postInventory.SchemaVersion != expectedSchema || postInventory.ObservedAt.Before(inventory.ObservedAt) {
			return coordinator.externalUncertain(ctx, command, state, authorization, ActionPreflight,
				digestParts("schema-version-mismatch", manifest.Digest, fmtUint(expectedSchema)), []string{"inspect_schema_version", "preserve_online_backup"})
		}
		postMigrationDigest = postInventory.Digest
	}
	if manifest.Rollback == RollbackBinaryOnly && len(operations) != 0 || manifest.Rollback == RollbackFull && !allBackedUp(operations, backups) { proofValid = false }
	migrationEvidence := digestStringSlices("migration-evidence", []string{postMigrationDigest}, sortedValues(assessments), sortedValues(backups), sortedValues(applied))
	rollbackEvidence := digestParts("rollback-proof", proofEvidence, proof.Digest, migrationEvidence)
	transition := transitionFor(command, state, PhasePreflighted, ReasonPreflighted,
		digestParts(intent, migrationEvidence, rollbackEvidence))
	transition.PreviousReleaseID, transition.PreviousReleaseDigest = active.ID, active.Digest
	transition.BaselineDigest, transition.MigrationEvidence = baseline.Digest, migrationEvidence
	transition.MigrationProofs = migrationProofs(operations, assessments, backups, applied)
	transition.RollbackProven, transition.RollbackEvidence = proofValid, rollbackEvidence
	return coordinator.repository.transition(ctx, transition)
}

func (coordinator *Coordinator) Switch(ctx context.Context, command Command) (UpdateState, Receipt, error) {
	if state, receipt, found, err := coordinator.replay(ctx, command, PhasePreflighted, PhaseSwitched, PhaseUncertain); found || err != nil { return state, receipt, err }
	manifest, state, authorization, err := coordinator.loadAuthorized(ctx, command, PhasePreflighted, ActionSwitch)
	if err != nil { return UpdateState{}, Receipt{}, err }
	admission, err := coordinator.admit(ctx, command, manifest, ActionSwitch)
	if err != nil { return UpdateState{}, Receipt{}, err }
	root, err := coordinator.stager.resolve(state.StagedRootID, state.StagedRootDigest)
	if err != nil { return UpdateState{}, Receipt{}, err }
	active, err := coordinator.platform.CurrentRelease(ctx, command.NodeID)
	if err != nil || active.Validate() != nil || active.ID != state.PreviousReleaseID || active.Digest != state.PreviousReleaseDigest {
		return UpdateState{}, Receipt{}, ErrConflict
	}
	operation := SwitchOperation{ManifestID: manifest.ID, ManifestDigest: manifest.Digest, NodeID: command.NodeID,
		Previous: active, Target: root, Fence: command.Fence, IdempotencyKey: command.IdempotencyKey}
	operation.Digest, _ = digestJSON(operation)
	if err := coordinator.recordAudit(ctx, state, authorization, ActionSwitch, admission.EvidenceDigest, operation.Digest, command.At); err != nil {
		return UpdateState{}, Receipt{}, err
	}
	effect, err := coordinator.platform.AtomicSwitch(ctx, operation)
	if err != nil {
		return coordinator.externalUncertain(ctx, command, state, authorization, ActionSwitch,
			digestParts("switch-uncertain", operation.Digest), []string{"inspect_active_release", "retain_staged_release"})
	}
	effect, err = canonicalEffect(effect, operation.Digest)
	if err != nil { return coordinator.externalUncertain(ctx, command, state, authorization, ActionSwitch,
		digestParts("switch-receipt-invalid", operation.Digest), []string{"inspect_active_release", "retain_staged_release"}) }
	return coordinator.repository.transition(ctx, transitionFor(command, state, PhaseSwitched, ReasonSwitched, effect.Digest))
}

func (coordinator *Coordinator) BeginProbe(ctx context.Context, command Command) (UpdateState, Receipt, error) {
	if state, receipt, found, err := coordinator.replay(ctx, command, PhaseSwitched, PhaseProbing); found || err != nil { return state, receipt, err }
	_, state, authorization, err := coordinator.loadAuthorized(ctx, command, PhaseSwitched, ActionProbe)
	if err != nil { return UpdateState{}, Receipt{}, err }
	evidence := digestParts("begin-probe", state.StagedRootDigest, state.BaselineDigest, fmtUint(state.Fence))
	if err := coordinator.recordAudit(ctx, state, authorization, ActionProbe, "", evidence, command.At); err != nil { return UpdateState{}, Receipt{}, err }
	return coordinator.repository.transition(ctx, transitionFor(command, state, PhaseProbing, ReasonSwitched, evidence))
}

func (coordinator *Coordinator) CompleteProbe(ctx context.Context, command Command) (UpdateState, Receipt, error) {
	if state, receipt, found, err := coordinator.replay(ctx, command, PhaseProbing, PhaseCommitted, PhaseRolledBack, PhaseUncertain); found || err != nil { return state, receipt, err }
	manifest, state, authorization, err := coordinator.loadAuthorized(ctx, command, PhaseProbing, ActionFinalize)
	if err != nil { return UpdateState{}, Receipt{}, err }
	probe := ProbeOperation{ManifestID: manifest.ID, NodeID: command.NodeID, ExpectedReleaseDigest: state.StagedRootDigest,
		BaselineDigest: state.BaselineDigest, Fence: command.Fence}
	probe.Digest, _ = digestJSON(probe)
	snapshot, err := coordinator.health.ProbeRelease(ctx, probe)
	if err != nil || validateHealth(snapshot, command.NodeID, state.StagedRootDigest, true) != nil {
		return coordinator.rollback(ctx, command, manifest, state, authorization, snapshot)
	}
	operation := finalizeOperation(manifest, state, command, FinalizeCommit)
	if err := coordinator.recordAudit(ctx, state, authorization, ActionCommit, "", operation.Digest, command.At); err != nil { return UpdateState{}, Receipt{}, err }
	effect, err := coordinator.platform.CommitSwitch(ctx, operation)
	if err != nil {
		return coordinator.externalUncertain(ctx, command, state, authorization, ActionCommit,
			digestParts("commit-uncertain", operation.Digest), []string{"inspect_active_release", "inspect_commit_marker"})
	}
	effect, err = canonicalEffect(effect, operation.Digest)
	if err != nil { return coordinator.externalUncertain(ctx, command, state, authorization, ActionCommit,
		digestParts("commit-receipt-invalid", operation.Digest), []string{"inspect_active_release", "inspect_commit_marker"}) }
	evidence := digestParts("committed", snapshot.Digest, effect.Digest)
	return coordinator.repository.transition(ctx, transitionFor(command, state, PhaseCommitted, ReasonHealthy, evidence))
}

func (coordinator *Coordinator) rollback(ctx context.Context, command Command, manifest ReleaseManifest, state UpdateState, authorization UpdateAuthorization, failedSnapshot HealthSnapshot) (UpdateState, Receipt, error) {
	failureEvidence := digestParts("health-regression", state.BaselineDigest, failedSnapshot.EvidenceDigest)
	if !state.RollbackProven || manifest.Rollback == RollbackNone {
		return coordinator.externalUncertain(ctx, command, state, authorization, ActionRollback, failureEvidence,
			[]string{"preserve_recovery_evidence", "manual_recovery_required", "do_not_claim_rollback"})
	}
	operation := finalizeOperation(manifest, state, command, FinalizeRollback)
	if err := coordinator.recordAudit(ctx, state, authorization, ActionRollback, "", operation.Digest, command.At); err != nil { return UpdateState{}, Receipt{}, err }
	effect, err := coordinator.platform.AtomicRollback(ctx, operation)
	if err != nil {
		return coordinator.externalUncertain(ctx, command, state, authorization, ActionRollback,
			digestParts("binary-rollback-uncertain", operation.Digest), []string{"inspect_active_release", "preserve_recovery_evidence"})
	}
	effect, err = canonicalEffect(effect, operation.Digest)
	if err != nil { return coordinator.externalUncertain(ctx, command, state, authorization, ActionRollback,
		digestParts("rollback-receipt-invalid", operation.Digest), []string{"inspect_active_release", "preserve_recovery_evidence"}) }
	migrationReceipts := make([]string, 0, len(manifest.Migrations))
	if manifest.Rollback == RollbackFull {
		root, resolveErr := coordinator.stager.resolve(state.StagedRootID, state.StagedRootDigest)
		if resolveErr != nil { return UpdateState{}, Receipt{}, resolveErr }
		for index := len(manifest.Migrations) - 1; index >= 0; index-- {
			migration := migrationOperation(manifest, command, root, manifest.Migrations[index])
			migrationProof, found := findMigrationProof(state.MigrationProofs, migration.Step.ID)
			if !found || migrationProof.OperationDigest != migration.Digest || !validDigest(migrationProof.BackupEvidence) {
				return coordinator.externalUncertain(ctx, command, state, authorization, ActionRollback,
					digestParts("migration-proof-missing", migration.Digest), []string{"preserve_online_backup", "manual_schema_recovery"})
			}
			rollback := MigrationRollbackOperation{Migration: migration, BackupEvidence: migrationProof.BackupEvidence,
				RollbackProof: state.RollbackEvidence, IdempotencyKey: digestParts(command.IdempotencyKey, "rollback", migration.Step.ID)}
			rollback.Digest, _ = digestJSON(rollback)
			receipt, rollbackErr := coordinator.migrations.RollbackMigration(ctx, rollback)
			if rollbackErr != nil {
				return coordinator.externalUncertain(ctx, command, state, authorization, ActionRollback,
					digestParts("schema-rollback-uncertain", rollback.Digest), []string{"inspect_schema_version", "preserve_online_backup"})
			}
			receipt, rollbackErr = canonicalEffect(receipt, rollback.Digest)
			if rollbackErr != nil { return coordinator.externalUncertain(ctx, command, state, authorization, ActionRollback,
				digestParts("schema-rollback-receipt-invalid", rollback.Digest), []string{"inspect_schema_version", "preserve_online_backup"}) }
			migrationReceipts = append(migrationReceipts, receipt.Digest)
		}
		if len(manifest.Migrations) > 0 {
			inventory, inventoryErr := coordinator.inventory.InstalledInventory(ctx, command.NodeID)
			if inventoryErr != nil { return coordinator.externalUncertain(ctx, command, state, authorization, ActionRollback,
				digestParts("rollback-schema-observation-uncertain", manifest.Digest), []string{"inspect_schema_version", "preserve_online_backup"}) }
			inventory, inventoryErr = CanonicalInventory(inventory)
			if inventoryErr != nil || inventory.SchemaVersion != manifest.Migrations[0].FromSchema {
				return coordinator.externalUncertain(ctx, command, state, authorization, ActionRollback,
					digestParts("rollback-schema-version-mismatch", manifest.Digest), []string{"inspect_schema_version", "preserve_online_backup"})
			}
			migrationReceipts = append(migrationReceipts, inventory.Digest)
		}
	}
	probe := ProbeOperation{ManifestID: manifest.ID, NodeID: command.NodeID, ExpectedReleaseDigest: state.PreviousReleaseDigest,
		BaselineDigest: state.BaselineDigest, Fence: command.Fence}
	probe.Digest, _ = digestJSON(probe)
	snapshot, probeErr := coordinator.health.ProbeRelease(ctx, probe)
	if probeErr != nil || validateHealth(snapshot, command.NodeID, state.PreviousReleaseDigest, true) != nil {
		return coordinator.externalUncertain(ctx, command, state, authorization, ActionRollback,
			digestParts("rollback-probe-uncertain", probe.Digest), []string{"inspect_control_plane", "inspect_hosted_workloads"})
	}
	evidence := digestStringSlices("rolled-back", []string{failureEvidence, effect.Digest, snapshot.Digest}, migrationReceipts)
	return coordinator.repository.transition(ctx, transitionFor(command, state, PhaseRolledBack, ReasonRolledBack, evidence))
}

func (coordinator *Coordinator) loadExpected(ctx context.Context, command Command, phase Phase) (ReleaseManifest, UpdateState, error) {
	if !identifierPattern.MatchString(command.ManifestID) || !identifierPattern.MatchString(command.NodeID) ||
		!identifierPattern.MatchString(command.ControllerID) || !identifierPattern.MatchString(command.IdempotencyKey) ||
		command.ExpectedGeneration == 0 || command.Fence == 0 || !validTime(command.At) || command.ExpectedDuration < 0 || command.ExpectedDuration > 24*time.Hour {
		return ReleaseManifest{}, UpdateState{}, ErrInvalid
	}
	if !coordinator.current(command.At) { return ReleaseManifest{}, UpdateState{}, ErrInvalid }
	manifest, state, err := coordinator.repository.Get(ctx, command.ManifestID, command.NodeID)
	if err != nil { return ReleaseManifest{}, UpdateState{}, err }
	if state.Phase != phase || state.Generation != command.ExpectedGeneration || state.Fence != command.Fence || state.ControllerID != command.ControllerID {
		return ReleaseManifest{}, UpdateState{}, ErrConflict
	}
	return manifest, state, nil
}

func (coordinator *Coordinator) loadAuthorized(ctx context.Context, command Command, phase Phase, action UpdateAction) (ReleaseManifest, UpdateState, UpdateAuthorization, error) {
	manifest, state, err := coordinator.loadExpected(ctx, command, phase)
	if err != nil { return ReleaseManifest{}, UpdateState{}, UpdateAuthorization{}, err }
	now := coordinator.clock.Now().UTC()
	if action == ActionStage || action == ActionPreflight || action == ActionSwitch {
		if err := coordinator.verifier.verifyAuthenticity(manifest, now); err != nil { return ReleaseManifest{}, UpdateState{}, UpdateAuthorization{}, err }
		if action != ActionStage && !manifest.ExpiresAt.After(now.Add(command.ExpectedDuration)) { return ReleaseManifest{}, UpdateState{}, UpdateAuthorization{}, ErrExpired }
	}
	authorization, err := CanonicalAuthorization(command.Authorization, manifest, command.NodeID, action, now)
	if err != nil { return ReleaseManifest{}, UpdateState{}, UpdateAuthorization{}, err }
	if err := coordinator.authorization.VerifyUpdateAuthorization(ctx, authorization); err != nil {
		return ReleaseManifest{}, UpdateState{}, UpdateAuthorization{}, ErrUnauthorized
	}
	return manifest, state, authorization, nil
}

func (coordinator *Coordinator) admit(ctx context.Context, command Command, manifest ReleaseManifest, action UpdateAction) (MaintenanceAdmission, error) {
	if command.ExpectedDuration <= 0 { return MaintenanceAdmission{}, ErrInvalid }
	request := MaintenanceRequest{ManifestID: manifest.ID, ManifestDigest: manifest.Digest, NodeID: command.NodeID,
		Action: action, Rollout: manifest.Rollout, Fence: command.Fence, RequestedAt: command.At.UTC(), ExpectedDuration: command.ExpectedDuration}
	request.Digest, _ = digestJSON(request)
	admission, err := coordinator.maintenance.AdmitProductUpdate(ctx, request)
	if err != nil || !admission.Allowed || !identifierPattern.MatchString(admission.OccurrenceID) ||
		!validDigest(admission.OccurrenceDigest) || !validDigest(admission.EvidenceDigest) || !validTime(admission.EndsAt) ||
		admission.EndsAt.Before(command.At.Add(command.ExpectedDuration)) { return MaintenanceAdmission{}, ErrConflict }
	admission.EndsAt = admission.EndsAt.UTC()
	claimed := admission.Digest
	admission.Digest = ""
	digest, err := digestJSON(admission)
	if err != nil || claimed != digest { return MaintenanceAdmission{}, ErrIntegrity }
	admission.Digest = digest
	return admission, nil
}

func (coordinator *Coordinator) recordAudit(ctx context.Context, state UpdateState, authorization UpdateAuthorization, action UpdateAction, maintenanceEvidence, intent string, at time.Time) error {
	record := AuditRecord{ManifestID: state.ManifestID, NodeID: state.NodeID, Action: action, Generation: state.Generation,
		Fence: state.Fence, AuthorizationDigest: authorization.Digest, MaintenanceEvidence: maintenanceEvidence,
		IntentDigest: intent, At: at.UTC()}
	record.ID = digestParts("product-update-audit", state.ManifestID, state.NodeID, string(action), fmtUint(state.Generation), fmtUint(state.Fence), intent)
	record.Digest, _ = digestJSON(record)
	if err := coordinator.audit.RecordProductUpdate(ctx, record); err != nil { return ErrIntegrity }
	return nil
}

func (coordinator *Coordinator) externalUncertain(ctx context.Context, command Command, state UpdateState, authorization UpdateAuthorization,
	action UpdateAction, evidence string, steps []string) (UpdateState, Receipt, error) {
	if !validDigest(evidence) { evidence = digestParts("redacted-external-uncertain", state.ManifestDigest, string(action)) }
	transition := transitionFor(command, state, PhaseUncertain, ReasonExternalUncertain, evidence)
	transition.RecoveryEvidence, transition.RecoverySteps = evidence, steps
	next, receipt, err := coordinator.repository.transition(ctx, transition)
	if err != nil { return UpdateState{}, Receipt{}, err }
	return next, receipt, ErrIntegrity
}

func transitionFor(command Command, state UpdateState, to Phase, reason ReasonCode, evidence string) Transition {
	return Transition{ManifestID: command.ManifestID, NodeID: command.NodeID, ExpectedGeneration: command.ExpectedGeneration,
		Fence: command.Fence, ControllerID: command.ControllerID, IdempotencyKey: command.IdempotencyKey,
		From: state.Phase, To: to, Reason: reason, EvidenceDigest: evidence, At: command.At.UTC()}
}

func migrationOperation(manifest ReleaseManifest, command Command, root ReleaseRoot, step MigrationStep) MigrationOperation {
	operation := MigrationOperation{ManifestID: manifest.ID, ManifestDigest: manifest.Digest, NodeID: command.NodeID,
		Step: step, ReleaseRoot: root, Fence: command.Fence,
		IdempotencyKey: digestParts("migration", manifest.ID, command.NodeID, step.ID, fmtUint(command.Fence))}
	operation.Digest, _ = digestJSON(operation)
	return operation
}

func validateAssessment(assessment MigrationAssessment, operation MigrationOperation, requireReversible bool) error {
	if assessment.OperationDigest != operation.Digest || !validDigest(assessment.EvidenceDigest) || requireReversible && !assessment.Reversible { return ErrRollback }
	claimed := assessment.Digest
	assessment.Digest = ""
	digest, err := digestJSON(assessment)
	if err != nil || claimed != digest { return ErrIntegrity }
	return nil
}

func validateRollbackProof(proof RollbackProof, inspection RollbackInspection, manifest ReleaseManifest) error {
	if proof.InspectionDigest != inspection.Digest || !proof.Valid || proof.PreviousID != inspection.Current.ID ||
		proof.PreviousDigest != inspection.Current.Digest || !validDigest(proof.EvidenceDigest) || manifest.Rollback == RollbackNone { return ErrRollback }
	claimed := proof.Digest
	proof.Digest = ""
	digest, err := digestJSON(proof)
	if err != nil || claimed != digest { return ErrIntegrity }
	return nil
}

func validateHealth(snapshot HealthSnapshot, nodeID, releaseDigest string, requireHealthy bool) error {
	if !identifierPattern.MatchString(snapshot.ID) || snapshot.NodeID != nodeID || snapshot.ActiveReleaseDigest != releaseDigest ||
		!validTime(snapshot.ObservedAt) || !validDigest(snapshot.EvidenceDigest) { return ErrIntegrity }
	snapshot.ObservedAt = snapshot.ObservedAt.UTC()
	claimed := snapshot.Digest
	snapshot.Digest = ""
	digest, err := digestJSON(snapshot)
	if err != nil || claimed != digest { return ErrIntegrity }
	if requireHealthy && (!snapshot.ControlPlaneHealthy || !snapshot.HostedWorkloadNonRegression) { return ErrIncompatible }
	return nil
}

func finalizeOperation(manifest ReleaseManifest, state UpdateState, command Command, disposition FinalizeDisposition) FinalizeOperation {
	operation := FinalizeOperation{Disposition: disposition, ManifestID: manifest.ID, ManifestDigest: manifest.Digest, NodeID: command.NodeID,
		PreviousID: state.PreviousReleaseID, PreviousDigest: state.PreviousReleaseDigest, Fence: command.Fence,
		IdempotencyKey: command.IdempotencyKey}
	operation.ActiveReleaseID, operation.ActiveDigest = state.StagedRootID, state.StagedRootDigest
	operation.Digest, _ = digestJSON(operation)
	return operation
}

func allBackedUp(operations []MigrationOperation, backups map[string]string) bool {
	for _, operation := range operations {
		if !operation.Step.BackupRequired || !validDigest(backups[operation.Step.ID]) { return false }
	}
	return true
}

func sortedValues(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values { keys = append(keys, key) }
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys { result = append(result, values[key]) }
	return result
}

func migrationProofs(operations []MigrationOperation, assessments, backups, applied map[string]string) []MigrationProof {
	proofs := make([]MigrationProof, 0, len(operations))
	for _, operation := range operations {
		proofs = append(proofs, MigrationProof{StepID: operation.Step.ID, OperationDigest: operation.Digest,
			AssessmentDigest: assessments[operation.Step.ID], BackupEvidence: backups[operation.Step.ID],
			ApplyReceiptDigest: applied[operation.Step.ID]})
	}
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].StepID < proofs[j].StepID })
	return proofs
}

func findMigrationProof(proofs []MigrationProof, stepID string) (MigrationProof, bool) {
	index := sort.Search(len(proofs), func(index int) bool { return proofs[index].StepID >= stepID })
	if index == len(proofs) || proofs[index].StepID != stepID { return MigrationProof{}, false }
	return proofs[index], true
}

func digestStringSlices(domain string, groups ...[]string) string {
	parts := []string{domain}
	for _, group := range groups { parts = append(parts, group...) }
	return digestParts(parts...)
}

func (coordinator *Coordinator) replay(ctx context.Context, command Command, from Phase, allowed ...Phase) (UpdateState, Receipt, bool, error) {
	if !identifierPattern.MatchString(command.ManifestID) || !identifierPattern.MatchString(command.NodeID) ||
		!identifierPattern.MatchString(command.IdempotencyKey) || command.ExpectedGeneration == 0 || command.ExpectedGeneration >= maxGeneration ||
		command.Fence == 0 || command.Fence > maxGeneration { return UpdateState{}, Receipt{}, false, ErrInvalid }
	state, receipt, found, err := coordinator.repository.replay(ctx, command.ManifestID, command.NodeID, command.IdempotencyKey)
	if err != nil || !found { return state, receipt, found, err }
	if from != "" && receipt.From != from || receipt.Generation != command.ExpectedGeneration+1 || receipt.Fence != command.Fence {
		return UpdateState{}, Receipt{}, false, ErrIntegrity
	}
	matched := false
	for _, phase := range allowed { if receipt.To == phase { matched = true; break } }
	if !matched { return UpdateState{}, Receipt{}, false, ErrIntegrity }
	if receipt.To == PhaseUncertain { return state, receipt, true, ErrIntegrity }
	return state, receipt, true, nil
}

func (coordinator *Coordinator) current(at time.Time) bool {
	now := coordinator.clock.Now().UTC()
	if !validTime(now) || !validTime(at) { return false }
	delta := now.Sub(at.UTC())
	if delta < 0 { delta = -delta }
	return delta <= 5*time.Minute
}
