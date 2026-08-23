package database

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

type TuningAuthorizationAction string

const (
	AuthorizeTuningObserve   TuningAuthorizationAction = "tuning.observe"
	AuthorizeTuningRecommend TuningAuthorizationAction = "tuning.recommend"
	AuthorizeTuningPlan      TuningAuthorizationAction = "tuning.plan"
	AuthorizeTuningExecute   TuningAuthorizationAction = "tuning.execute"
)

type TuningAuthorizationRequest struct {
	Actor      TuningActorID              `json:"actor"`
	InstanceID ResourceID                 `json:"instance_id"`
	PlanID     ResourceID                 `json:"plan_id,omitempty"`
	Action     TuningAuthorizationAction `json:"action"`
}

func (request TuningAuthorizationRequest) Validate() error {
	if !validTuningID(string(request.Actor)) || request.InstanceID.IsZero() { return ErrTuningInvalid }
	switch request.Action {
	case AuthorizeTuningObserve, AuthorizeTuningRecommend:
		if !request.PlanID.IsZero() { return ErrTuningInvalid }
	case AuthorizeTuningPlan, AuthorizeTuningExecute:
		if request.PlanID.IsZero() { return ErrTuningInvalid }
	default:
		return ErrTuningInvalid
	}
	return nil
}

type TuningAuthorizer interface {
	AuthorizeDatabaseTuning(context.Context, TuningAuthorizationRequest) error
}

type TuningStepUpRequest struct {
	Actor        TuningActorID             `json:"actor"`
	InstanceID  ResourceID                `json:"instance_id"`
	PlanID      ResourceID                `json:"plan_id"`
	Action      TuningAuthorizationAction `json:"action"`
	AssertionRef ResourceID               `json:"assertion_ref"`
	Revision     uint64                   `json:"revision"`
}

func (request TuningStepUpRequest) Validate() error {
	if !validTuningID(string(request.Actor)) || request.InstanceID.IsZero() || request.PlanID.IsZero() || request.AssertionRef.IsZero() || request.Revision == 0 ||
		request.Action != AuthorizeTuningPlan && request.Action != AuthorizeTuningExecute { return ErrTuningInvalid }
	return nil
}

type TuningStepUpVerifier interface {
	VerifyDatabaseTuningStepUp(context.Context, TuningStepUpRequest) error
}

type TuningAuditRecord struct {
	Actor          TuningActorID              `json:"actor"`
	InstanceID     ResourceID                 `json:"instance_id"`
	PlanID         ResourceID                 `json:"plan_id,omitempty"`
	Action         TuningAuthorizationAction `json:"action"`
	Outcome        string                     `json:"outcome"`
	ResourceDigest string                     `json:"resource_digest,omitempty"`
	EvidenceDigest string                     `json:"evidence_digest,omitempty"`
	Generation     uint64                     `json:"generation,omitempty"`
	OccurredAt     time.Time                  `json:"occurred_at"`
	Digest         string                     `json:"digest"`
}

func (record TuningAuditRecord) Validate() error {
	if (TuningAuthorizationRequest{Actor: record.Actor, InstanceID: record.InstanceID, PlanID: record.PlanID, Action: record.Action}).Validate() != nil ||
		!validReasonCode(record.Outcome) || record.ResourceDigest != "" && !validSHA256(record.ResourceDigest) || record.EvidenceDigest != "" && !validSHA256(record.EvidenceDigest) ||
		record.OccurredAt.IsZero() || !validSHA256(record.Digest) || tuningAuditDigest(record) != record.Digest { return ErrTuningInvalid }
	return nil
}

func tuningAuditDigest(record TuningAuditRecord) string {
	record.Digest = ""
	encoded, _ := json.Marshal(record)
	return tuningDigest(encoded)
}

type TuningAuditSink interface {
	RecordDatabaseTuning(context.Context, TuningAuditRecord) error
}

type TuningStateRepository interface {
	BootstrapTuning(context.Context) error
	SaveObservation(context.Context, TuningObservation) error
	LoadObservation(context.Context, ResourceID) (TuningObservation, error)
	AdmitPlan(context.Context, TuningPlan, time.Time) (TuningReceipt, error)
	LoadPlan(context.Context, ResourceID) (TuningPlan, error)
	LatestReceipt(context.Context, ResourceID) (TuningReceipt, error)
	AppendReceipt(context.Context, TuningReceipt, uint64) error
}

type TuningPreflightRequest struct {
	InstanceID               ResourceID     `json:"instance_id"`
	ExpectedServerVersion    MariaDBVersion `json:"expected_server_version"`
	ExpectedConfigGeneration uint64         `json:"expected_config_generation"`
	MaximumRows              uint32         `json:"maximum_rows"`
	MaximumBytes             uint32         `json:"maximum_bytes"`
	Timeout                  time.Duration  `json:"timeout"`
}

type TuningPreflight struct {
	InstanceID       ResourceID               `json:"instance_id"`
	ServerVersion    MariaDBVersion           `json:"server_version"`
	ServerIDDigest   string                   `json:"server_id_digest"`
	ConfigGeneration uint64                   `json:"config_generation"`
	Variables        []ObservedTuningVariable `json:"variables"`
	FreeMemoryBytes  uint64                   `json:"free_memory_bytes"`
	FreeDiskBytes    uint64                   `json:"free_disk_bytes"`
	Health           Health                   `json:"health"`
	Replication      ReplicationSnapshot      `json:"replication"`
	ObservedAt       time.Time                `json:"observed_at"`
	Digest           string                   `json:"digest"`
}

func (preflight TuningPreflight) Validate() error {
	if preflight.InstanceID.IsZero() || preflight.ServerVersion.Major == 0 || !validSHA256(preflight.ServerIDDigest) || preflight.ConfigGeneration == 0 ||
		len(preflight.Variables) == 0 || len(preflight.Variables) > MaximumTuningVariables || !validHealth(preflight.Health) || validateReplication(preflight.Replication) != nil ||
		preflight.ObservedAt.IsZero() || !validSHA256(preflight.Digest) || tuningPreflightDigest(preflight) != preflight.Digest { return ErrTuningInvalid }
	last := TuningVariable("")
	for _, variable := range preflight.Variables {
		if variable.Variable <= last || validateTuningValue(variable.Variable, variable.Value) != nil || !validReasonCode(variable.Source) { return ErrTuningInvalid }
		last = variable.Variable
	}
	return nil
}

func tuningPreflightDigest(preflight TuningPreflight) string {
	preflight.Digest = ""
	encoded, _ := json.Marshal(preflight)
	return tuningDigest(encoded)
}

type TuningProof struct {
	Code      string `json:"code"`
	Confirmed bool   `json:"confirmed"`
	Digest    string `json:"digest"`
}

func (proof TuningProof) Validate() error {
	if !validReasonCode(proof.Code) || !validSHA256(proof.Digest) { return ErrTuningInvalid }
	return nil
}

type StagedTuningConfig struct {
	PlanID              ResourceID `json:"plan_id"`
	Token               ResourceID `json:"token"`
	PreviousConfigDigest string     `json:"previous_config_digest"`
	CandidateConfigDigest string    `json:"candidate_config_digest"`
	PreviousGeneration  uint64     `json:"previous_generation"`
	CandidateGeneration uint64     `json:"candidate_generation"`
	Proof               TuningProof `json:"proof"`
}

func (staged StagedTuningConfig) Validate() error {
	if staged.PlanID.IsZero() || staged.Token.IsZero() || !validSHA256(staged.PreviousConfigDigest) || !validSHA256(staged.CandidateConfigDigest) ||
		staged.PreviousGeneration == 0 || staged.CandidateGeneration != staged.PreviousGeneration+1 || staged.Proof.Validate() != nil || !staged.Proof.Confirmed { return ErrTuningInvalid }
	return nil
}

type TuningConfigAdapter interface {
	ValidateTuningCandidate(context.Context, ResourceID, MariaDBVersion, CandidateTuningConfig) (TuningProof, error)
	StageTuningCandidate(context.Context, ResourceID, uint64, CandidateTuningConfig) (StagedTuningConfig, error)
	CommitTuningCandidate(context.Context, StagedTuningConfig) (TuningProof, error)
	RestoreTuningConfig(context.Context, StagedTuningConfig) (TuningProof, error)
}

type DynamicTuningRequest struct {
	PlanID          ResourceID       `json:"plan_id"`
	InstanceID      ResourceID       `json:"instance_id"`
	ServerVersion   MariaDBVersion   `json:"server_version"`
	ConfigGeneration uint64          `json:"config_generation"`
	Changes         []TuningChange   `json:"changes"`
}

type TuningProbeRequest struct {
	PlanID             ResourceID       `json:"plan_id"`
	InstanceID         ResourceID       `json:"instance_id"`
	ServerVersion      MariaDBVersion   `json:"server_version"`
	ConfigGeneration   uint64           `json:"config_generation"`
	MaximumRows        uint32           `json:"maximum_rows"`
	MaximumBytes       uint32           `json:"maximum_bytes"`
	Timeout            time.Duration    `json:"timeout"`
}

type TuningProbe struct {
	InstanceID                 ResourceID          `json:"instance_id"`
	ServerVersion              MariaDBVersion      `json:"server_version"`
	ConfigGeneration           uint64              `json:"config_generation"`
	Health                     Health              `json:"health"`
	WorkloadP95Latency         time.Duration       `json:"workload_p95_latency"`
	WorkloadErrorBasisPoints   uint16              `json:"workload_error_basis_points"`
	Replication                ReplicationSnapshot `json:"replication"`
	HealthDigest               string              `json:"health_digest"`
	WorkloadDigest             string              `json:"workload_digest"`
	ReplicationDigest          string              `json:"replication_digest"`
	ObservedAt                 time.Time           `json:"observed_at"`
	Digest                     string              `json:"digest"`
}

func (probe TuningProbe) Validate() error {
	if probe.InstanceID.IsZero() || probe.ServerVersion.Major == 0 || probe.ConfigGeneration == 0 || !validHealth(probe.Health) || probe.WorkloadP95Latency < 0 ||
		probe.WorkloadP95Latency > time.Minute || probe.WorkloadErrorBasisPoints > 10000 || validateReplication(probe.Replication) != nil || !validSHA256(probe.HealthDigest) ||
		!validSHA256(probe.WorkloadDigest) || !validSHA256(probe.ReplicationDigest) || probe.ObservedAt.IsZero() || !validSHA256(probe.Digest) || tuningProbeDigest(probe) != probe.Digest { return ErrTuningInvalid }
	return nil
}

func tuningProbeDigest(probe TuningProbe) string {
	probe.Digest = ""
	encoded, _ := json.Marshal(probe)
	return tuningDigest(encoded)
}

type MariaDBTuningControl interface {
	PreflightTuning(context.Context, TuningPreflightRequest) (TuningPreflight, error)
	ApplyDynamicTuning(context.Context, DynamicTuningRequest) (TuningProof, error)
	RestoreDynamicTuning(context.Context, DynamicTuningRequest) (TuningProof, error)
	ProbeTuning(context.Context, TuningProbeRequest) (TuningProbe, error)
}

type TuningDeploymentRequest struct {
	PlanID              ResourceID         `json:"plan_id"`
	InstanceID          ResourceID         `json:"instance_id"`
	Mode                ApplicationMode    `json:"mode"`
	ServerVersion       MariaDBVersion     `json:"server_version"`
	ConfigGeneration    uint64             `json:"config_generation"`
	MaintenanceWindowRef ResourceID        `json:"maintenance_window_ref"`
	RecoveryPointRef    ResourceID         `json:"recovery_point_ref"`
}

type TuningDeployment interface {
	ActivateTuning(context.Context, TuningDeploymentRequest) (TuningProof, error)
	RecoverTuning(context.Context, TuningDeploymentRequest) (TuningProof, error)
}

type TuningCoordinator struct {
	repository TuningStateRepository
	collector  TuningCollector
	authorizer TuningAuthorizer
	stepUp     TuningStepUpVerifier
	audit      TuningAuditSink
	mariaDB    MariaDBTuningControl
	config     TuningConfigAdapter
	deployment TuningDeployment
	now        func() time.Time
}

func NewTuningCoordinator(repository TuningStateRepository, collector TuningCollector, authorizer TuningAuthorizer, stepUp TuningStepUpVerifier, audit TuningAuditSink,
	mariaDB MariaDBTuningControl, config TuningConfigAdapter, deployment TuningDeployment, now func() time.Time) (TuningCoordinator, error) {
	if repository == nil || collector.source == nil || authorizer == nil || stepUp == nil || audit == nil || mariaDB == nil || config == nil || deployment == nil { return TuningCoordinator{}, ErrTuningInvalid }
	if now == nil { now = time.Now }
	return TuningCoordinator{repository: repository, collector: collector, authorizer: authorizer, stepUp: stepUp, audit: audit, mariaDB: mariaDB, config: config, deployment: deployment, now: now}, nil
}

func (coordinator TuningCoordinator) Bootstrap(ctx context.Context) error { return coordinator.repository.BootstrapTuning(ctx) }

func (coordinator TuningCoordinator) Observe(ctx context.Context, actor TuningActorID, request TuningObservationRequest) (TuningObservation, error) {
	authorization := TuningAuthorizationRequest{Actor: actor, InstanceID: request.InstanceID, Action: AuthorizeTuningObserve}
	if err := coordinator.authorize(ctx, authorization); err != nil { return TuningObservation{}, err }
	observation, err := coordinator.collector.Collect(ctx, request)
	if err != nil { coordinator.recordAudit(ctx, authorization, "observation_failed", "", "", 0); return TuningObservation{}, err }
	if err = coordinator.repository.SaveObservation(ctx, observation); err != nil { return TuningObservation{}, err }
	if err = coordinator.recordAudit(ctx, authorization, "observation_recorded", observation.Digest, observation.Snapshot.Server.ServerIDDigest, observation.ConfigGeneration); err != nil { return TuningObservation{}, err }
	return observation, nil
}

func (coordinator TuningCoordinator) Recommend(ctx context.Context, actor TuningActorID, observationID ResourceID, capacity InstanceCapacity) ([]TuningRecommendation, error) {
	observation, err := coordinator.repository.LoadObservation(ctx, observationID)
	if err != nil { return nil, err }
	authorization := TuningAuthorizationRequest{Actor: actor, InstanceID: observation.InstanceID, Action: AuthorizeTuningRecommend}
	if err = coordinator.authorize(ctx, authorization); err != nil { return nil, err }
	recommendations, err := RecommendTuning(observation, capacity, coordinator.now().UTC())
	if err != nil { coordinator.recordAudit(ctx, authorization, "recommendation_failed", observation.Digest, "", 0); return nil, err }
	setDigest, err := RecommendationSetDigest(recommendations)
	if err != nil { return nil, err }
	if err = coordinator.recordAudit(ctx, authorization, "recommendation_created", setDigest, observation.Digest, uint64(len(recommendations))); err != nil { return nil, err }
	return recommendations, nil
}

func (coordinator TuningCoordinator) CreatePlan(ctx context.Context, actor TuningActorID, request TuningPlanRequest, stepUp TuningStepUpRequest,
	observationID ResourceID, recommendations []TuningRecommendation, capacity InstanceCapacity) (TuningPlan, TuningReceipt, error) {
	observation, err := coordinator.repository.LoadObservation(ctx, observationID)
	if err != nil { return TuningPlan{}, TuningReceipt{}, err }
	authorization := TuningAuthorizationRequest{Actor: actor, InstanceID: observation.InstanceID, PlanID: request.PlanID, Action: AuthorizeTuningPlan}
	if err = coordinator.authorize(ctx, authorization); err != nil { return TuningPlan{}, TuningReceipt{}, err }
	if request.Actor != actor || stepUp.Validate() != nil || stepUp.Actor != actor || stepUp.InstanceID != observation.InstanceID || stepUp.PlanID != request.PlanID || stepUp.Action != AuthorizeTuningPlan {
		return TuningPlan{}, TuningReceipt{}, ErrTuningInvalid
	}
	if err = coordinator.stepUp.VerifyDatabaseTuningStepUp(ctx, stepUp); err != nil { coordinator.recordAudit(ctx, authorization, "step_up_denied", "", "", 0); return TuningPlan{}, TuningReceipt{}, ErrUnauthorized }
	plan, err := BuildTuningPlan(request, observation, recommendations, capacity, coordinator.now().UTC())
	if err != nil { return TuningPlan{}, TuningReceipt{}, err }
	receipt, err := coordinator.repository.AdmitPlan(ctx, plan, coordinator.now().UTC())
	if err != nil { return TuningPlan{}, TuningReceipt{}, err }
	if err = coordinator.recordAudit(ctx, authorization, "plan_admitted", plan.Digest, observation.Digest, receipt.Generation); err != nil { return TuningPlan{}, TuningReceipt{}, err }
	return plan, receipt, nil
}

type ExecuteTuningRequest struct {
	Actor                     TuningActorID
	PlanID                    ResourceID
	PlanDigest                string
	ExpectedReceiptGeneration uint64
	StepUp                    TuningStepUpRequest
	StepTimeout               time.Duration
}

func (coordinator TuningCoordinator) Execute(ctx context.Context, request ExecuteTuningRequest) (TuningReceipt, error) {
	if !validTuningID(string(request.Actor)) || request.PlanID.IsZero() || !validSHA256(request.PlanDigest) || request.ExpectedReceiptGeneration == 0 ||
		request.StepTimeout < time.Second || request.StepTimeout > MaximumTuningCollectTime { return TuningReceipt{}, ErrTuningInvalid }
	overallTimeout := request.StepTimeout * 12
	if overallTimeout > 5*time.Minute { overallTimeout = 5 * time.Minute }
	boundedOverall, cancelOverall := context.WithTimeout(ctx, overallTimeout)
	defer cancelOverall()
	ctx = boundedOverall
	plan, err := coordinator.repository.LoadPlan(ctx, request.PlanID)
	if err != nil { return TuningReceipt{}, err }
	authorization := TuningAuthorizationRequest{Actor: request.Actor, InstanceID: plan.InstanceID, PlanID: plan.ID, Action: AuthorizeTuningExecute}
	if plan.Digest != request.PlanDigest || plan.Validate() != nil { return TuningReceipt{}, ErrTuningInvalid }
	if err = coordinator.authorize(ctx, authorization); err != nil { return TuningReceipt{}, err }
	if request.StepUp.Validate() != nil || request.StepUp.Actor != request.Actor || request.StepUp.InstanceID != plan.InstanceID || request.StepUp.PlanID != plan.ID || request.StepUp.Action != AuthorizeTuningExecute {
		return TuningReceipt{}, ErrTuningInvalid
	}
	if err = coordinator.stepUp.VerifyDatabaseTuningStepUp(ctx, request.StepUp); err != nil { coordinator.recordAudit(ctx, authorization, "step_up_denied", plan.Digest, "", request.ExpectedReceiptGeneration); return TuningReceipt{}, ErrUnauthorized }
	receipt, err := coordinator.repository.LatestReceipt(ctx, plan.ID)
	if err != nil { return TuningReceipt{}, err }
	if receipt.Generation != request.ExpectedReceiptGeneration || receipt.Status != TuningAccepted { return TuningReceipt{}, ErrTuningConflict }
	observation, err := coordinator.repository.LoadObservation(ctx, plan.Preconditions.ObservationID)
	if err != nil || observation.Digest != plan.Preconditions.ObservationDigest { return coordinator.failWithoutMutation(ctx, authorization, receipt, "observation_missing") }
	now := coordinator.now().UTC()
	if now.Before(plan.Preconditions.EvidenceCapturedAt) || now.Sub(plan.Preconditions.EvidenceCapturedAt) > plan.Preconditions.MaximumEvidenceAge { return coordinator.failWithoutMutation(ctx, authorization, receipt, "evidence_stale") }
	if _, err = TuningCapabilitiesFor(plan.Preconditions.ServerVersion); err != nil { return coordinator.failWithoutMutation(ctx, authorization, receipt, "version_unsupported") }
	preflightRequest := TuningPreflightRequest{InstanceID: plan.InstanceID, ExpectedServerVersion: plan.Preconditions.ServerVersion, ExpectedConfigGeneration: plan.Preconditions.ConfigGeneration,
		MaximumRows: MaximumTuningVariables + 32, MaximumBytes: 256 << 10, Timeout: request.StepTimeout}
	bounded, cancel := context.WithTimeout(ctx, request.StepTimeout)
	preflight, err := coordinator.mariaDB.PreflightTuning(bounded, preflightRequest)
	cancel()
	if err != nil || preflight.Validate() != nil || !preflightMatches(plan, observation, preflight, now) { return coordinator.failWithoutMutation(ctx, authorization, receipt, "preflight_failed") }
	candidate, err := RenderTuningCandidate(plan)
	if err != nil || candidate.Digest() != plan.CandidateConfigDigest { return coordinator.failWithoutMutation(ctx, authorization, receipt, "candidate_invalid") }
	bounded, cancel = context.WithTimeout(ctx, request.StepTimeout)
	validation, err := coordinator.config.ValidateTuningCandidate(bounded, plan.InstanceID, plan.Preconditions.ServerVersion, candidate)
	cancel()
	if err != nil || validation.Validate() != nil || !validation.Confirmed { return coordinator.failWithoutMutation(ctx, authorization, receipt, "syntax_invalid") }
	receipt = nextTuningReceipt(receipt, TuningValidated, now)
	receipt.ValidationDigest = validation.Digest
	receipt = sealTuningReceipt(receipt)
	if err = coordinator.repository.AppendReceipt(ctx, receipt, receipt.Generation-1); err != nil { return TuningReceipt{}, err }
	bounded, cancel = context.WithTimeout(ctx, request.StepTimeout)
	staged, stageErr := coordinator.config.StageTuningCandidate(bounded, plan.InstanceID, plan.Preconditions.ConfigGeneration, candidate)
	cancel()
	if stageErr != nil || staged.Validate() != nil || staged.PlanID != plan.ID || staged.CandidateConfigDigest != plan.CandidateConfigDigest {
		return coordinator.markAmbiguous(ctx, authorization, receipt, "stage_ambiguous")
	}
	previousReceipt := receipt
	receipt = nextTuningReceipt(previousReceipt, TuningStaged, coordinator.now().UTC())
	receipt.StageDigest = staged.Proof.Digest
	receipt.StageToken = staged.Token
	receipt.PreviousConfigDigest = staged.PreviousConfigDigest
	receipt.PreviousConfigGeneration = staged.PreviousGeneration
	receipt.CandidateConfigGeneration = staged.CandidateGeneration
	receipt = sealTuningReceipt(receipt)
	if err = coordinator.repository.AppendReceipt(ctx, receipt, previousReceipt.Generation); err != nil {
		previousReceipt.StageDigest, previousReceipt.StageToken = staged.Proof.Digest, staged.Token
		previousReceipt.PreviousConfigDigest, previousReceipt.PreviousConfigGeneration = staged.PreviousConfigDigest, staged.PreviousGeneration
		previousReceipt.CandidateConfigGeneration = staged.CandidateGeneration
		return coordinator.markAmbiguous(ctx, authorization, previousReceipt, "stage_receipt_failed")
	}
	previousReceipt = receipt
	receipt = nextTuningReceipt(previousReceipt, TuningApplying, coordinator.now().UTC())
	receipt.MutationPossible = true
	receipt = sealTuningReceipt(receipt)
	if err = coordinator.repository.AppendReceipt(ctx, receipt, previousReceipt.Generation); err != nil { return coordinator.markAmbiguous(ctx, authorization, previousReceipt, "apply_receipt_failed") }
	mode := highestApplicationMode(plan.Changes)
	bounded, cancel = context.WithTimeout(ctx, request.StepTimeout)
	configCommit, applyErr := coordinator.config.CommitTuningCandidate(bounded, staged)
	cancel()
	if applyErr != nil || configCommit.Validate() != nil || !configCommit.Confirmed {
		return coordinator.compensate(ctx, authorization, plan, receipt, staged, mode, request.StepTimeout, "config_commit_failed")
	}
	receipt.ConfigCommitDigest = configCommit.Digest
	if mode == ApplicationDynamic {
		bounded, cancel = context.WithTimeout(ctx, request.StepTimeout)
		effect, effectErr := coordinator.mariaDB.ApplyDynamicTuning(bounded, dynamicRequest(plan, staged.CandidateGeneration, false))
		cancel()
		if effectErr != nil || effect.Validate() != nil || !effect.Confirmed { return coordinator.compensate(ctx, authorization, plan, receipt, staged, mode, request.StepTimeout, "dynamic_apply_failed") }
		receipt.MariaDBEffectDigest = effect.Digest
	} else {
		deploymentRequest := deploymentRequest(plan, staged.CandidateGeneration, mode)
		bounded, cancel = context.WithTimeout(ctx, request.StepTimeout)
		deploymentProof, deploymentErr := coordinator.deployment.ActivateTuning(bounded, deploymentRequest)
		cancel()
		if deploymentErr != nil || deploymentProof.Validate() != nil || !deploymentProof.Confirmed { return coordinator.compensate(ctx, authorization, plan, receipt, staged, mode, request.StepTimeout, "deployment_failed") }
		receipt.DeploymentDigest = deploymentProof.Digest
	}
	previousReceipt = receipt
	receipt = nextTuningReceipt(previousReceipt, TuningVerifying, coordinator.now().UTC())
	receipt.MutationPossible = true
	receipt = sealTuningReceipt(receipt)
	if err = coordinator.repository.AppendReceipt(ctx, receipt, previousReceipt.Generation); err != nil { return coordinator.markAmbiguous(ctx, authorization, previousReceipt, "receipt_write_failed") }
	bounded, cancel = context.WithTimeout(ctx, request.StepTimeout)
	probe, probeErr := coordinator.mariaDB.ProbeTuning(bounded, TuningProbeRequest{PlanID: plan.ID, InstanceID: plan.InstanceID, ServerVersion: plan.Preconditions.ServerVersion,
		ConfigGeneration: staged.CandidateGeneration, MaximumRows: MaximumTuningVariables + 32, MaximumBytes: 256 << 10, Timeout: request.StepTimeout})
	cancel()
	if probeErr != nil || probe.Validate() != nil || !probeAcceptable(plan, staged.CandidateGeneration, probe, coordinator.now().UTC()) {
		return coordinator.compensate(ctx, authorization, plan, receipt, staged, mode, request.StepTimeout, "probe_failed")
	}
	previousReceipt = receipt
	receipt = nextTuningReceipt(previousReceipt, TuningCommitted, coordinator.now().UTC())
	receipt.HealthProbeDigest, receipt.WorkloadProbeDigest, receipt.ReplicationProbeDigest = probe.HealthDigest, probe.WorkloadDigest, probe.ReplicationDigest
	receipt.MutationPossible = true
	receipt = sealTuningReceipt(receipt)
	if err = coordinator.repository.AppendReceipt(ctx, receipt, previousReceipt.Generation); err != nil { return coordinator.markAmbiguous(ctx, authorization, previousReceipt, "commit_receipt_failed") }
	if err = coordinator.recordAudit(ctx, authorization, "tuning_committed", plan.Digest, receipt.Digest, receipt.Generation); err != nil { return receipt, err }
	return receipt, nil
}

func preflightMatches(plan TuningPlan, observation TuningObservation, preflight TuningPreflight, now time.Time) bool {
	if preflight.InstanceID != plan.InstanceID || compareVersion(preflight.ServerVersion, plan.Preconditions.ServerVersion) != 0 || preflight.ServerIDDigest != observation.Snapshot.Server.ServerIDDigest ||
		preflight.ConfigGeneration != plan.Preconditions.ConfigGeneration || preflight.FreeMemoryBytes < plan.Preconditions.MinimumFreeMemoryBytes || preflight.FreeDiskBytes < plan.Preconditions.MinimumFreeDiskBytes ||
		preflight.Health != HealthHealthy && preflight.Health != HealthDegraded || preflight.ObservedAt.After(now.Add(time.Minute)) || now.Sub(preflight.ObservedAt) > time.Minute ||
		!replicationMatches(plan.Preconditions.Replication, preflight.Replication) { return false }
	values := make(map[TuningVariable]TuningValue, len(preflight.Variables))
	for _, variable := range preflight.Variables { values[variable.Variable] = variable.Value }
	for _, change := range plan.Changes {
		value, exists := values[change.Variable]
		if !exists || !value.equal(change.Current) { return false }
	}
	return true
}

func replicationMatches(expected ReplicationPrecondition, observed ReplicationSnapshot) bool {
	if expected.Role != observed.Role || expected.GTIDSetDigest != observed.GTIDSetDigest { return false }
	return expected.Role != ReplicationReplica || observed.IOThreadRunning && observed.SQLThreadRunning && observed.LagUpperBound <= expected.MaximumLag
}

func probeAcceptable(plan TuningPlan, configGeneration uint64, probe TuningProbe, now time.Time) bool {
	return probe.InstanceID == plan.InstanceID && compareVersion(probe.ServerVersion, plan.Preconditions.ServerVersion) == 0 && probe.ConfigGeneration == configGeneration &&
		probe.Health == HealthHealthy && probe.WorkloadP95Latency <= plan.Preconditions.MaximumProbeLatency && probe.WorkloadErrorBasisPoints <= plan.Preconditions.MaximumProbeErrorBasisPoints &&
		replicationMatches(plan.Preconditions.Replication, probe.Replication) && !probe.ObservedAt.After(now.Add(time.Minute)) && now.Sub(probe.ObservedAt) <= time.Minute
}

func dynamicRequest(plan TuningPlan, configGeneration uint64, restore bool) DynamicTuningRequest {
	changes := append([]TuningChange(nil), plan.Changes...)
	if restore {
		for index := range changes { changes[index].Current, changes[index].Target = changes[index].Target, changes[index].Current }
	}
	return DynamicTuningRequest{PlanID: plan.ID, InstanceID: plan.InstanceID, ServerVersion: plan.Preconditions.ServerVersion, ConfigGeneration: configGeneration, Changes: changes}
}

func deploymentRequest(plan TuningPlan, configGeneration uint64, mode ApplicationMode) TuningDeploymentRequest {
	return TuningDeploymentRequest{PlanID: plan.ID, InstanceID: plan.InstanceID, Mode: mode, ServerVersion: plan.Preconditions.ServerVersion, ConfigGeneration: configGeneration,
		MaintenanceWindowRef: plan.MaintenanceWindowRef, RecoveryPointRef: plan.RecoveryPointRef}
}

func highestApplicationMode(changes []TuningChange) ApplicationMode {
	mode := ApplicationDynamic
	for _, change := range changes {
		if change.Mode == ApplicationRestart { return ApplicationRestart }
		if change.Mode == ApplicationReload { mode = ApplicationReload }
	}
	return mode
}

func (coordinator TuningCoordinator) compensate(ctx context.Context, authorization TuningAuthorizationRequest, plan TuningPlan, receipt TuningReceipt, staged StagedTuningConfig,
	mode ApplicationMode, timeout time.Duration, failureCode string) (TuningReceipt, error) {
	proofs := make([]string, 0, 3)
	proven := true
	if mode == ApplicationDynamic {
		bounded, cancel := context.WithTimeout(ctx, timeout)
		proof, err := coordinator.mariaDB.RestoreDynamicTuning(bounded, dynamicRequest(plan, staged.PreviousGeneration, true))
		cancel()
		if err != nil || proof.Validate() != nil || !proof.Confirmed { proven = false } else { proofs = append(proofs, proof.Digest) }
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	restoreProof, err := coordinator.config.RestoreTuningConfig(bounded, staged)
	cancel()
	if err != nil || restoreProof.Validate() != nil || !restoreProof.Confirmed { proven = false } else { proofs = append(proofs, restoreProof.Digest) }
	if mode != ApplicationDynamic {
		bounded, cancel = context.WithTimeout(ctx, timeout)
		recoveryProof, recoveryErr := coordinator.deployment.RecoverTuning(bounded, deploymentRequest(plan, staged.PreviousGeneration, mode))
		cancel()
		if recoveryErr != nil || recoveryProof.Validate() != nil || !recoveryProof.Confirmed { proven = false } else { proofs = append(proofs, recoveryProof.Digest) }
	}
	bounded, cancel = context.WithTimeout(ctx, timeout)
	probe, probeErr := coordinator.mariaDB.ProbeTuning(bounded, TuningProbeRequest{PlanID: plan.ID, InstanceID: plan.InstanceID, ServerVersion: plan.Preconditions.ServerVersion,
		ConfigGeneration: staged.PreviousGeneration, MaximumRows: MaximumTuningVariables + 32, MaximumBytes: 256 << 10, Timeout: timeout})
	cancel()
	if probeErr != nil || probe.Validate() != nil || !probeAcceptable(plan, staged.PreviousGeneration, probe, coordinator.now().UTC()) {
		proven = false
	} else {
		proofs = append(proofs, probe.Digest)
	}
	sort.Strings(proofs)
	encoded, _ := json.Marshal(proofs)
	receipt = nextTuningReceipt(receipt, TuningCompensated, coordinator.now().UTC())
	receipt.CompensationDigest = tuningDigest(encoded)
	if probeErr == nil && probe.Validate() == nil {
		receipt.HealthProbeDigest, receipt.WorkloadProbeDigest, receipt.ReplicationProbeDigest = probe.HealthDigest, probe.WorkloadDigest, probe.ReplicationDigest
	}
	receipt.FailureCode = failureCode
	receipt.MutationPossible = true
	if !proven { receipt.Status = TuningAmbiguous }
	receipt = sealTuningReceipt(receipt)
	if appendErr := coordinator.repository.AppendReceipt(ctx, receipt, receipt.Generation-1); appendErr != nil { return receipt, ErrAmbiguous }
	outcome := "tuning_compensated"
	if receipt.Status == TuningAmbiguous { outcome = "tuning_ambiguous" }
	coordinator.recordAudit(ctx, authorization, outcome, plan.Digest, receipt.Digest, receipt.Generation)
	if receipt.Status == TuningAmbiguous { return receipt, ErrAmbiguous }
	return receipt, ErrTuningCompensated
}

func (coordinator TuningCoordinator) failWithoutMutation(ctx context.Context, authorization TuningAuthorizationRequest, receipt TuningReceipt, code string) (TuningReceipt, error) {
	receipt = nextTuningReceipt(receipt, TuningFailed, coordinator.now().UTC())
	receipt.FailureCode = code
	receipt.MutationPossible = false
	receipt = sealTuningReceipt(receipt)
	if err := coordinator.repository.AppendReceipt(ctx, receipt, receipt.Generation-1); err != nil { return TuningReceipt{}, err }
	coordinator.recordAudit(ctx, authorization, "tuning_failed", receipt.PlanDigest, receipt.Digest, receipt.Generation)
	return receipt, ErrTuningStale
}

func (coordinator TuningCoordinator) markAmbiguous(ctx context.Context, authorization TuningAuthorizationRequest, receipt TuningReceipt, code string) (TuningReceipt, error) {
	receipt = nextTuningReceipt(receipt, TuningAmbiguous, coordinator.now().UTC())
	receipt.FailureCode = code
	receipt.MutationPossible = true
	receipt = sealTuningReceipt(receipt)
	if err := coordinator.repository.AppendReceipt(ctx, receipt, receipt.Generation-1); err != nil { return receipt, ErrAmbiguous }
	coordinator.recordAudit(ctx, authorization, "tuning_ambiguous", receipt.PlanDigest, receipt.Digest, receipt.Generation)
	return receipt, ErrAmbiguous
}

func nextTuningReceipt(previous TuningReceipt, status TuningExecutionStatus, occurredAt time.Time) TuningReceipt {
	previous.Generation++
	previous.Status = status
	previous.OccurredAt = occurredAt.UTC()
	previous.FailureCode = ""
	previous.Digest = ""
	return previous
}

func (coordinator TuningCoordinator) authorize(ctx context.Context, request TuningAuthorizationRequest) error {
	if request.Validate() != nil { return ErrTuningInvalid }
	if err := coordinator.authorizer.AuthorizeDatabaseTuning(ctx, request); err != nil {
		coordinator.recordAudit(ctx, request, "authorization_denied", "", "", 0)
		return ErrUnauthorized
	}
	return nil
}

func (coordinator TuningCoordinator) recordAudit(ctx context.Context, request TuningAuthorizationRequest, outcome, resourceDigest, evidenceDigest string, generation uint64) error {
	record := TuningAuditRecord{Actor: request.Actor, InstanceID: request.InstanceID, PlanID: request.PlanID, Action: request.Action, Outcome: outcome,
		ResourceDigest: resourceDigest, EvidenceDigest: evidenceDigest, Generation: generation, OccurredAt: coordinator.now().UTC()}
	record.Digest = tuningAuditDigest(record)
	if record.Validate() != nil { return ErrTuningInvalid }
	return coordinator.audit.RecordDatabaseTuning(ctx, record)
}

func IsTuningTerminal(status TuningExecutionStatus) bool {
	return status == TuningCommitted || status == TuningCompensated || status == TuningFailed || status == TuningAmbiguous
}
