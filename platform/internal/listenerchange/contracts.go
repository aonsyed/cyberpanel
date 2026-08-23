package listenerchange

import (
	"context"
	"slices"
	"time"
)

type ExecutionState string

const (
	StatePreviewed           ExecutionState = "previewed"
	StateStaged              ExecutionState = "staged"
	StateValidated           ExecutionState = "validated"
	StateFirewallOpened      ExecutionState = "firewall_opened"
	StateShadowActive        ExecutionState = "shadow_active"
	StateExternallyConfirmed ExecutionState = "externally_confirmed"
	StateOldDrained          ExecutionState = "old_drained"
	StateRollingBack         ExecutionState = "rolling_back"
	StateCommitted           ExecutionState = "committed"
	StateRolledBack          ExecutionState = "rolled_back"
	StateUncertain           ExecutionState = "uncertain"
)

var stableStates = []ExecutionState{
	StateCommitted, StateExternallyConfirmed, StateFirewallOpened, StateOldDrained,
	StatePreviewed, StateRolledBack, StateRollingBack, StateShadowActive,
	StateStaged, StateUncertain, StateValidated,
}

func (state ExecutionState) terminal() bool {
	return state == StateCommitted || state == StateRolledBack || state == StateUncertain
}

func (state ExecutionState) releasesScope() bool {
	return state == StateCommitted || state == StateRolledBack
}

type Execution struct {
	PlanID                    PlanID        `json:"plan_id"`
	Scope                     Scope         `json:"scope"`
	State                     ExecutionState `json:"state"`
	Revision                  uint64        `json:"revision"`
	Attempt                   uint32        `json:"attempt"`
	FenceToken                string        `json:"fence_token,omitempty"`
	LeaseHolder               string        `json:"lease_holder,omitempty"`
	LeaseUntil                time.Time     `json:"lease_until,omitempty"`
	Boot                      BootIdentity  `json:"boot"`
	RollbackHandle            string        `json:"rollback_handle,omitempty"`
	RollbackDeadline          time.Time     `json:"rollback_deadline"`
	PortsReserved             bool          `json:"ports_reserved"`
	ConfigurationStaged       bool          `json:"configuration_staged"`
	ConfigurationValidated    bool          `json:"configuration_validated"`
	FirewallOpened            bool          `json:"firewall_opened"`
	RollbackArmed             bool          `json:"rollback_armed"`
	ShadowActive              bool          `json:"shadow_active"`
	LocalValidated            bool          `json:"local_validated"`
	ExternallyConfirmed       bool          `json:"externally_confirmed"`
	OldDrained                bool          `json:"old_drained"`
	OldFirewallClosed         bool          `json:"old_firewall_closed"`
	RollbackFinalized         bool          `json:"rollback_finalized"`
	ConfirmedAdministrative   *AdministrativePathEvidence `json:"confirmed_administrative,omitempty"`
	ObservedConfigurationGeneration uint64  `json:"observed_configuration_generation"`
	ObservedFirewallGeneration uint64       `json:"observed_firewall_generation"`
	FailureCode               string        `json:"failure_code,omitempty"`
	UpdatedAt                 time.Time     `json:"updated_at"`
}

func (execution Execution) Validate(plan ChangePlan) error {
	if execution.PlanID != plan.ID || execution.Scope != plan.Scope || !slices.Contains(stableStates, execution.State) || execution.Revision == 0 || execution.Attempt == 0 && (execution.State != StatePreviewed || execution.FenceToken != "") || execution.State != StateUncertain && execution.Boot.MachineID != plan.Boot.MachineID || execution.Boot.Validate(execution.UpdatedAt) != nil || !validUTC(execution.RollbackDeadline) || !execution.RollbackDeadline.Equal(plan.Rollback.Deadline) || execution.ObservedConfigurationGeneration < plan.BeforeConfigurationGeneration || execution.ObservedConfigurationGeneration > plan.BeforeConfigurationGeneration+2 || execution.ObservedFirewallGeneration < plan.BeforeFirewallGeneration || execution.ObservedFirewallGeneration > plan.BeforeFirewallGeneration+4 || !validUTC(execution.UpdatedAt) {
		return ErrInvalid
	}
	if execution.State == StateCommitted && (!execution.OldDrained || !execution.OldFirewallClosed || !execution.RollbackFinalized || execution.ObservedConfigurationGeneration != plan.AfterConfigurationGeneration || execution.ObservedFirewallGeneration != plan.AfterFirewallGeneration) {
		return ErrIncomplete
	}
	if execution.State == StateExternallyConfirmed && !execution.ExternallyConfirmed || execution.State == StateOldDrained && !execution.OldDrained {
		return ErrIncomplete
	}
	if execution.RollbackArmed && !validID(execution.RollbackHandle) {
		return ErrInvalid
	}
	if (execution.FenceToken == "") != (execution.LeaseHolder == "") || (execution.FenceToken == "") != execution.LeaseUntil.IsZero() {
		return ErrInvalid
	}
	return nil
}

type OperationPhase string
type OperationOutcome string

const (
	PhaseReservePorts      OperationPhase = "reserve_ports"
	PhaseStage             OperationPhase = "stage"
	PhaseValidate          OperationPhase = "validate"
	PhaseOpenFirewall      OperationPhase = "open_firewall"
	PhaseArmRollback       OperationPhase = "arm_rollback"
	PhaseActivateShadow    OperationPhase = "activate_shadow"
	PhaseProbeLocal        OperationPhase = "probe_local"
	PhaseConfirmExternal   OperationPhase = "confirm_external"
	PhaseDrainOld          OperationPhase = "drain_old"
	PhaseCloseOldFirewall  OperationPhase = "close_old_firewall"
	PhaseCommitRollback    OperationPhase = "commit_rollback_lease"
	PhaseFinalizeRollback  OperationPhase = "finalize_rollback"
	PhaseCommit            OperationPhase = "commit"
	PhaseRestoreOld        OperationPhase = "restore_old"
	PhaseStopShadow        OperationPhase = "stop_shadow"
	PhaseReopenOldFirewall OperationPhase = "reopen_old_firewall"
	PhaseCloseNewFirewall  OperationPhase = "close_new_firewall"
	PhaseDiscardStage      OperationPhase = "discard_stage"
	PhaseReleasePorts      OperationPhase = "release_ports"
	PhaseRollbackComplete  OperationPhase = "rollback_complete"

	OutcomeSucceeded  OperationOutcome = "succeeded"
	OutcomeNotApplied OperationOutcome = "not_applied"
	OutcomeAmbiguous  OperationOutcome = "ambiguous"
)

type OperationReceipt struct {
	ID                              string           `json:"id"`
	PlanID                          PlanID           `json:"plan_id"`
	Scope                           Scope            `json:"scope"`
	Phase                           OperationPhase   `json:"phase"`
	Outcome                         OperationOutcome `json:"outcome"`
	IdempotencyKey                  string           `json:"idempotency_key"`
	Attempt                         uint32           `json:"attempt"`
	FenceToken                      string           `json:"fence_token"`
	Boot                            BootIdentity     `json:"boot"`
	ExpectedConfigurationGeneration uint64          `json:"expected_configuration_generation"`
	ObservedConfigurationGeneration uint64          `json:"observed_configuration_generation"`
	ExpectedFirewallGeneration      uint64           `json:"expected_firewall_generation"`
	ObservedFirewallGeneration      uint64           `json:"observed_firewall_generation"`
	ExpectedDigest                  string           `json:"expected_digest"`
	ObservedDigest                  string           `json:"observed_digest"`
	FailureCode                     string           `json:"failure_code,omitempty"`
	ObservedAt                      time.Time         `json:"observed_at"`
	Digest                          string           `json:"digest"`
}

func (receipt OperationReceipt) Validate(plan ChangePlan) error {
	if !validID(receipt.ID) || receipt.PlanID != plan.ID || receipt.Scope != plan.Scope || receipt.Phase == "" || receipt.Outcome != OutcomeSucceeded && receipt.Outcome != OutcomeNotApplied && receipt.Outcome != OutcomeAmbiguous || !validID(receipt.IdempotencyKey) || receipt.Attempt == 0 || !validID(receipt.FenceToken) || receipt.Boot.MachineID != plan.Boot.MachineID || receipt.ExpectedConfigurationGeneration < plan.BeforeConfigurationGeneration || receipt.ExpectedConfigurationGeneration > plan.BeforeConfigurationGeneration+2 || receipt.ObservedConfigurationGeneration < plan.BeforeConfigurationGeneration || receipt.ObservedConfigurationGeneration > plan.BeforeConfigurationGeneration+2 || receipt.ExpectedFirewallGeneration < plan.BeforeFirewallGeneration || receipt.ExpectedFirewallGeneration > plan.BeforeFirewallGeneration+4 || receipt.ObservedFirewallGeneration < plan.BeforeFirewallGeneration || receipt.ObservedFirewallGeneration > plan.BeforeFirewallGeneration+4 || !validDigest(receipt.ExpectedDigest) || !validDigest(receipt.ObservedDigest) || receipt.FailureCode != "" && !validCode(receipt.FailureCode) || !validUTC(receipt.ObservedAt) || !validDigest(receipt.Digest) {
		return ErrInvalid
	}
	copy := receipt
	copy.Digest = ""
	expected, err := digestValue("operation-receipt", copy)
	if err != nil || expected != receipt.Digest {
		return ErrInvalid
	}
	return nil
}

func (receipt OperationReceipt) ExpectedDigestValue() (string, error) {
	copy := receipt
	copy.Digest = ""
	return digestValue("operation-receipt", copy)
}

type OperationContext struct {
	PlanID         PlanID       `json:"plan_id"`
	Scope          Scope        `json:"scope"`
	Attempt        uint32       `json:"attempt"`
	FenceToken     string       `json:"fence_token"`
	IdempotencyKey string       `json:"idempotency_key"`
	Boot           BootIdentity `json:"boot"`
	Deadline       time.Time    `json:"deadline"`
	ExpectedDigest string       `json:"expected_digest"`
}

type PortReservationRequest struct {
	Operation OperationContext `json:"operation"`
	Current   ListenerSet      `json:"current"`
	Target    ListenerSet      `json:"target"`
}

type ListenerConfigurationRequest struct {
	Operation                       OperationContext     `json:"operation"`
	Current                         ListenerSet          `json:"current"`
	Target                          ListenerSet          `json:"target"`
	CurrentOrigin                   string               `json:"current_origin"`
	TargetOrigin                    string               `json:"target_origin"`
	CurrentCertificate              CertificateDependency `json:"current_certificate"`
	TargetCertificate               CertificateDependency `json:"target_certificate"`
	ExpectedConfigurationGeneration uint64               `json:"expected_configuration_generation"`
	TargetConfigurationGeneration   uint64               `json:"target_configuration_generation"`
}

type FirewallChangeRequest struct {
	Operation          OperationContext `json:"operation"`
	Tuples             []FirewallTuple  `json:"tuples"`
	ExpectedGeneration uint64           `json:"expected_generation"`
	TargetGeneration   uint64           `json:"target_generation"`
}

type RollbackLeaseRequest struct {
	Operation OperationContext `json:"operation"`
	PlanDigest string           `json:"plan_digest"`
	Current   ListenerSet      `json:"current"`
	Target    ListenerSet      `json:"target"`
	Deadline  time.Time        `json:"deadline"`
	Persistent bool            `json:"persistent"`
}

type RollbackLeaseResult struct {
	Receipt OperationReceipt `json:"receipt"`
	Handle  string           `json:"handle"`
}

type LocalProbeObservation struct {
	Receipt                    OperationReceipt `json:"receipt"`
	ObservedListeners          ListenerSet      `json:"observed_listeners"`
	ObservedOrigin             string           `json:"observed_origin"`
	CertificateFingerprint     string           `json:"certificate_fingerprint"`
	ConfigurationGeneration    uint64           `json:"configuration_generation"`
	AdministrativeObserverID   string           `json:"administrative_observer_id"`
}

type DrainObservation struct {
	Receipt      OperationReceipt `json:"receipt"`
	OldActive    bool             `json:"old_active"`
	TargetActive bool             `json:"target_active"`
}

type ListenerActivationObservation struct {
	Receipt       OperationReceipt `json:"receipt"`
	CurrentActive bool             `json:"current_active"`
	TargetActive  bool             `json:"target_active"`
}

type ExternalObservation struct {
	Receipt       OperationReceipt `json:"receipt"`
	ChallengeID   string           `json:"challenge_id"`
	BindingDigest string           `json:"binding_digest"`
	NonceDigest   string           `json:"nonce_digest"`
	ObserverIDs   []string         `json:"observer_ids"`
	Listeners     ListenerSet      `json:"listeners"`
	Origin        string           `json:"origin"`
	IndependentlyObserved bool     `json:"independently_observed"`
	ObservedAt    time.Time        `json:"observed_at"`
}

func (observation ExternalObservation) Validate(plan ChangePlan, now time.Time) error {
	if !plan.ExternalConfirmationRequired || plan.Challenge == nil || observation.Receipt.Validate(plan) != nil || observation.Receipt.Phase != PhaseConfirmExternal || observation.Receipt.Outcome != OutcomeSucceeded || observation.ChallengeID != plan.Challenge.ID || observation.BindingDigest != plan.Challenge.BindingDigest || observation.NonceDigest != plan.Challenge.NonceDigest || len(observation.ObserverIDs) < int(plan.ConfirmationPolicy.MinimumObservers) || len(observation.ObserverIDs) > 3 || observation.Listeners.Validate() != nil || !slices.Equal(observation.Listeners.Panel, plan.Target.Panel) || !slices.Equal(observation.Listeners.SSH, plan.Target.SSH) || observation.Origin != plan.TargetOrigin || !observation.IndependentlyObserved || !validUTC(observation.ObservedAt) || !observation.Receipt.ObservedAt.Equal(observation.ObservedAt) || observation.ObservedAt.After(now) || now.Sub(observation.ObservedAt) > plan.ConfirmationPolicy.MaximumAge {
		return ErrStale
	}
	for index, observer := range observation.ObserverIDs {
		if !validID(observer) || index > 0 && observation.ObserverIDs[index-1] >= observer {
			return ErrStale
		}
	}
	expected, err := digestValue("external-observation", struct {
		ChallengeID string `json:"challenge_id"`
		BindingDigest string `json:"binding_digest"`
		NonceDigest string `json:"nonce_digest"`
		ObserverIDs []string `json:"observer_ids"`
		Listeners ListenerSet `json:"listeners"`
		Origin string `json:"origin"`
		IndependentlyObserved bool `json:"independently_observed"`
		ObservedAt time.Time `json:"observed_at"`
	}{observation.ChallengeID, observation.BindingDigest, observation.NonceDigest, observation.ObserverIDs, observation.Listeners, observation.Origin, observation.IndependentlyObserved, observation.ObservedAt})
	if err != nil || expected != observation.Receipt.ObservedDigest {
		return ErrStale
	}
	return nil
}

type AuthorizationAction string

const (
	ActionPreview AuthorizationAction = "preview_listener_change"
	ActionExecute AuthorizationAction = "execute_listener_change"
	ActionRollback AuthorizationAction = "rollback_listener_change"
)

type Authorizer interface {
	Authorize(context.Context, Actor, Scope, AuthorizationAction) error
}

type StepUpVerifier interface {
	VerifyRecent(context.Context, Actor, Scope, time.Time, time.Duration) error
}

type RiskApprover interface {
	Approve(context.Context, Actor, Scope, []RiskReason, string) error
}

type BootObserver interface {
	ObserveBoot(context.Context, Scope, time.Time) (BootIdentity, error)
}

type PortBroker interface {
	Reserve(context.Context, PortReservationRequest) (OperationReceipt, error)
	Release(context.Context, PortReservationRequest) (OperationReceipt, error)
}

type ListenerBroker interface {
	Stage(context.Context, ListenerConfigurationRequest) (OperationReceipt, error)
	Validate(context.Context, ListenerConfigurationRequest) (OperationReceipt, error)
	ActivateShadow(context.Context, ListenerConfigurationRequest) (ListenerActivationObservation, error)
	ProbeLocal(context.Context, ListenerConfigurationRequest) (LocalProbeObservation, error)
	DrainOld(context.Context, ListenerConfigurationRequest) (DrainObservation, error)
	RestoreOld(context.Context, ListenerConfigurationRequest) (ListenerActivationObservation, error)
	StopShadow(context.Context, ListenerConfigurationRequest) (ListenerActivationObservation, error)
	DiscardStage(context.Context, ListenerConfigurationRequest) (OperationReceipt, error)
}

type CanonicalFirewall interface {
	OpenExact(context.Context, FirewallChangeRequest) (OperationReceipt, error)
	CloseExact(context.Context, FirewallChangeRequest) (OperationReceipt, error)
}

type PersistentRollback interface {
	Arm(context.Context, RollbackLeaseRequest) (RollbackLeaseResult, error)
	Finalize(context.Context, RollbackLeaseRequest, string) (OperationReceipt, error)
}

type ExternalConfirmer interface {
	Issue(context.Context, Scope, string, ExternalConfirmationPolicy, time.Time) (ConfirmationChallenge, error)
	Observe(context.Context, OperationContext, ChangePlan) (ExternalObservation, error)
}

type AuditEvent struct {
	ID          string              `json:"id"`
	Scope       Scope               `json:"scope"`
	PlanID      PlanID              `json:"plan_id,omitempty"`
	Actor       PrincipalID         `json:"actor"`
	Action      AuthorizationAction `json:"action"`
	Phase       OperationPhase      `json:"phase,omitempty"`
	State       ExecutionState      `json:"state,omitempty"`
	Attempt     uint32              `json:"attempt,omitempty"`
	FenceToken string              `json:"fence_token,omitempty"`
	Outcome     OperationOutcome    `json:"outcome,omitempty"`
	ReasonCode  string              `json:"reason_code,omitempty"`
	Digest      string              `json:"digest"`
	At          time.Time           `json:"at"`
}

type AuditSink interface {
	Append(context.Context, AuditEvent) error
}

type Status struct {
	PlanID           PlanID             `json:"plan_id"`
	State            ExecutionState     `json:"state"`
	Revision         uint64             `json:"revision"`
	Attempt          uint32             `json:"attempt"`
	ObservedConfigurationGeneration uint64 `json:"observed_configuration_generation"`
	ObservedFirewallGeneration uint64       `json:"observed_firewall_generation"`
	RollbackDeadline time.Time          `json:"rollback_deadline"`
	Risks            []RiskReason       `json:"risks"`
	Receipts         []RedactedReceipt  `json:"receipts"`
	FailureCode      string             `json:"failure_code,omitempty"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

type RedactedReceipt struct {
	Phase       OperationPhase   `json:"phase"`
	Outcome     OperationOutcome `json:"outcome"`
	FailureCode string           `json:"failure_code,omitempty"`
	ObservedAt  time.Time        `json:"observed_at"`
}
