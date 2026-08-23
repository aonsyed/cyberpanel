package nodeidentity

import (
	"context"
	"encoding/json"
	"slices"
	"time"
)

type CapabilityObservation struct {
	Scope                    Scope     `json:"scope"`
	Generation               uint64    `json:"generation"`
	SetHostname              bool      `json:"set_hostname"`
	SetAddresses             bool      `json:"set_addresses"`
	SetTimezone              bool      `json:"set_timezone"`
	SetAdministrativeContact bool      `json:"set_administrative_contact"`
	SetPanelOrigin           bool      `json:"set_panel_origin"`
	StageCertificate         bool      `json:"stage_certificate"`
	StageListeners           bool      `json:"stage_listeners"`
	ManageDNS                bool      `json:"manage_dns"`
	DNSConfigured            bool      `json:"dns_configured"`
	ManageMail               bool      `json:"manage_mail"`
	MailConfigured           bool      `json:"mail_configured"`
	MakeBeforeBreakAddresses bool      `json:"make_before_break_addresses"`
	MakeBeforeBreakCertificate bool    `json:"make_before_break_certificate"`
	MakeBeforeBreakListeners bool      `json:"make_before_break_listeners"`
	RollbackHost             bool      `json:"rollback_host"`
	RollbackCertificate      bool      `json:"rollback_certificate"`
	RollbackListeners        bool      `json:"rollback_listeners"`
	RollbackDNS              bool      `json:"rollback_dns"`
	RollbackMail             bool      `json:"rollback_mail"`
	ObserveDependencies      bool      `json:"observe_dependencies"`
	HostnameRequiresReboot   bool      `json:"hostname_requires_reboot"`
	RebootNode               bool      `json:"reboot_node"`
	ObservedAt               time.Time `json:"observed_at"`
	ValidUntil               time.Time `json:"valid_until"`
	Digest                   string    `json:"digest"`
}

func (capabilities CapabilityObservation) Validate(now time.Time) error {
	if capabilities.Scope.Validate() != nil || capabilities.Generation == 0 || !validUTC(now) || !validUTC(capabilities.ObservedAt) || !validUTC(capabilities.ValidUntil) || capabilities.ObservedAt.After(now) || now.Sub(capabilities.ObservedAt) > MaximumEvidenceAge || !capabilities.ValidUntil.After(now) || capabilities.ValidUntil.After(capabilities.ObservedAt.Add(MaximumEvidenceAge)) || !capabilities.SetHostname || !capabilities.SetAddresses || !capabilities.SetTimezone || !capabilities.SetAdministrativeContact || !capabilities.SetPanelOrigin || !capabilities.StageCertificate || !capabilities.StageListeners || !capabilities.ObserveDependencies || !validDigest(capabilities.Digest) {
		return ErrUnsupported
	}
	expected, err := capabilities.expectedDigest()
	if err != nil || expected != capabilities.Digest {
		return ErrStale
	}
	return nil
}

func (capabilities CapabilityObservation) expectedDigest() (string, error) {
	copy := capabilities
	copy.ObservedAt, copy.ValidUntil, copy.Digest = time.Time{}, time.Time{}, ""
	return digestValue("capabilities", copy)
}

func (capabilities CapabilityObservation) ExpectedDigest() (string, error) {
	return capabilities.expectedDigest()
}

type ImpactKind string

const (
	ImpactCertificate ImpactKind = "certificate"
	ImpactListeners   ImpactKind = "listeners"
	ImpactDNS         ImpactKind = "dns"
	ImpactMail        ImpactKind = "mail"
)

type RollbackCertainty string

const (
	RollbackReversible   RollbackCertainty = "reversible"
	RollbackIrreversible RollbackCertainty = "irreversible"
	RollbackAmbiguous    RollbackCertainty = "ambiguous"
)

func (certainty RollbackCertainty) valid() bool {
	return certainty == RollbackReversible || certainty == RollbackIrreversible || certainty == RollbackAmbiguous
}

type ChangeImpact struct {
	Kind            ImpactKind       `json:"kind"`
	Affected        bool             `json:"affected"`
	Required        bool             `json:"required"`
	MakeBeforeBreak bool             `json:"make_before_break"`
	Rollback        RollbackCertainty `json:"rollback"`
}

type RebootRequirement string

const (
	RebootNone     RebootRequirement = "none"
	RebootRequired RebootRequirement = "required"
)

type PlanRequirements struct {
	MaintenanceRequired bool              `json:"maintenance_required"`
	Reboot              RebootRequirement `json:"reboot"`
	LockoutRisk         bool              `json:"lockout_risk"`
	OverallRollback     RollbackCertainty `json:"overall_rollback"`
}

type WarningCode string

const (
	WarningLockout      WarningCode = "administrative_lockout"
	WarningCertificate  WarningCode = "certificate_reissue"
	WarningDNS          WarningCode = "dns_cutover"
	WarningMail         WarningCode = "mail_identity_change"
	WarningMaintenance  WarningCode = "maintenance_required"
	WarningReboot       WarningCode = "reboot_required"
	WarningIrreversible WarningCode = "irreversible_change"
	WarningAmbiguous    WarningCode = "ambiguous_rollback"
)

type PlanWarning struct {
	Code    WarningCode `json:"code"`
	Message string      `json:"message"`
}

func warningFor(code WarningCode) PlanWarning {
	switch code {
	case WarningLockout:
		return PlanWarning{code, "Address or panel-origin changes can lock administrators out."}
	case WarningCertificate:
		return PlanWarning{code, "The panel certificate must be staged and verified for the new origin."}
	case WarningDNS:
		return PlanWarning{code, "Authoritative DNS must remain coherent throughout the address cutover."}
	case WarningMail:
		return PlanWarning{code, "Mail identity and dependent configuration require a coordinated change."}
	case WarningMaintenance:
		return PlanWarning{code, "Dependent configuration activation requires a maintenance window."}
	case WarningReboot:
		return PlanWarning{code, "This host requires a reboot to finish the hostname transition."}
	case WarningIrreversible:
		return PlanWarning{code, "At least one activated dependency cannot be reliably rolled back."}
	case WarningAmbiguous:
		return PlanWarning{code, "Rollback outcome cannot be established conclusively by observation."}
	default:
		return PlanWarning{}
	}
}

type EffectKind string

const (
	EffectHostname    EffectKind = "hostname"
	EffectAddresses   EffectKind = "addresses"
	EffectTimezone    EffectKind = "timezone"
	EffectContact     EffectKind = "administrative_contact"
	EffectPanelOrigin EffectKind = "panel_origin"
	EffectCertificate EffectKind = "certificate"
	EffectListeners   EffectKind = "listeners"
	EffectDNS         EffectKind = "dns"
	EffectMail        EffectKind = "mail"
	EffectReboot      EffectKind = "reboot"
)

type EffectIntent struct {
	Kind             EffectKind `json:"kind"`
	BeforeDigest     string     `json:"before_digest"`
	AfterDigest      string     `json:"after_digest"`
	Reversible       bool       `json:"reversible"`
	MakeBeforeBreak  bool       `json:"make_before_break"`
}

func (effect EffectIntent) Validate() error {
	if !validEffect(effect.Kind) || !validDigest(effect.BeforeDigest) || !validDigest(effect.AfterDigest) || effect.BeforeDigest == effect.AfterDigest || effect.MakeBeforeBreak && (effect.Kind != EffectAddresses && effect.Kind != EffectCertificate && effect.Kind != EffectListeners) {
		return ErrInvalid
	}
	return nil
}

type PlanRequest struct {
	ExpectedDesiredRevision  uint64        `json:"expected_desired_revision"`
	ExpectedObservedRevision uint64        `json:"expected_observed_revision"`
	ExpectedBeforeGeneration uint64        `json:"expected_before_generation"`
	ExpectedAfterGeneration  uint64        `json:"expected_after_generation"`
	After                    IdentitySpec  `json:"after"`
	Evidence                 DNSAddressEvidence `json:"evidence"`
	Capabilities             CapabilityObservation `json:"capabilities"`
	AcknowledgedWarnings     []WarningCode `json:"acknowledged_warnings"`
	MaintenanceApproved      bool          `json:"maintenance_approved"`
	RebootApproved           bool          `json:"reboot_approved"`
	IrreversibleApproved     bool          `json:"irreversible_approved"`
}

type ChangePlan struct {
	ID                       PlanID                `json:"id"`
	Scope                    Scope                 `json:"scope"`
	BeforeDesiredRevision    uint64                `json:"before_desired_revision"`
	BeforeObservedRevision   uint64                `json:"before_observed_revision"`
	BeforeGeneration         uint64                `json:"before_generation"`
	AfterGeneration          uint64                `json:"after_generation"`
	BeforeDesiredDigest      string                `json:"before_desired_digest"`
	BeforeObservationDigest  string                `json:"before_observation_digest"`
	Before                   IdentitySpec          `json:"before"`
	After                    IdentitySpec          `json:"after"`
	Evidence                 DNSAddressEvidence    `json:"evidence"`
	Capabilities             CapabilityObservation `json:"capabilities"`
	Impacts                  []ChangeImpact         `json:"impacts"`
	Requirements             PlanRequirements       `json:"requirements"`
	Warnings                 []PlanWarning           `json:"warnings"`
	AcknowledgedWarnings     []WarningCode           `json:"acknowledged_warnings"`
	MaintenanceApproved      bool                    `json:"maintenance_approved"`
	RebootApproved           bool                    `json:"reboot_approved"`
	IrreversibleApproved     bool                    `json:"irreversible_approved"`
	Effects                  []EffectIntent          `json:"effects"`
	CreatedBy                PrincipalID             `json:"created_by"`
	CreatedAt                time.Time               `json:"created_at"`
	Digest                   string                  `json:"digest"`
}

func BuildPlan(current DesiredIdentity, observed ObservedIdentity, request PlanRequest, actor PrincipalID, now time.Time) (ChangePlan, error) {
	if current.Validate() != nil || request.After.Validate() != nil || !validID(string(actor)) || !validUTC(now) {
		return ChangePlan{}, ErrInvalid
	}
	if observed.Validate(current.Spec, now) != nil || request.Evidence.Validate(request.After, now) != nil {
		return ChangePlan{}, ErrStale
	}
	if err := request.Capabilities.Validate(now); err != nil {
		return ChangePlan{}, err
	}
	if current.Scope != observed.Scope || current.Scope != request.Evidence.Scope || current.Scope != request.Capabilities.Scope || current.Revision != request.ExpectedDesiredRevision || observed.Revision != request.ExpectedObservedRevision || current.Generation != request.ExpectedBeforeGeneration || observed.AppliedGeneration != current.Generation || current.Generation == ^uint64(0) || request.ExpectedAfterGeneration != current.Generation+1 || !observed.CoreMatches(current.Spec) {
		return ChangePlan{}, ErrStale
	}
	beforeDigest, _ := current.Spec.Digest()
	afterDigest, _ := request.After.Digest()
	if beforeDigest == afterDigest {
		return ChangePlan{}, ErrConflict
	}
	impacts, requirements, effects, err := deriveChange(current.Spec, request.After, request.Capabilities)
	if err != nil {
		return ChangePlan{}, err
	}
	warnings := deriveWarnings(impacts, requirements)
	warningCodes := make([]WarningCode, 0, len(warnings))
	for _, warning := range warnings {
		warningCodes = append(warningCodes, warning.Code)
	}
	if !slices.Equal(warningCodes, request.AcknowledgedWarnings) || request.MaintenanceApproved != requirements.MaintenanceRequired || request.RebootApproved != (requirements.Reboot == RebootRequired) || request.IrreversibleApproved != (requirements.OverallRollback != RollbackReversible) {
		return ChangePlan{}, ErrIncomplete
	}
	plan := ChangePlan{
		Scope: current.Scope, BeforeDesiredRevision: current.Revision, BeforeObservedRevision: observed.Revision,
		BeforeGeneration: current.Generation, AfterGeneration: current.Generation + 1,
		BeforeDesiredDigest: current.Digest, BeforeObservationDigest: observed.Digest,
		Before: current.Spec, After: request.After, Evidence: request.Evidence, Capabilities: request.Capabilities,
		Impacts: impacts, Requirements: requirements, Warnings: warnings,
		AcknowledgedWarnings: append([]WarningCode(nil), request.AcknowledgedWarnings...),
		MaintenanceApproved: request.MaintenanceApproved, RebootApproved: request.RebootApproved, IrreversibleApproved: request.IrreversibleApproved,
		Effects: effects,
		CreatedBy: actor, CreatedAt: now,
	}
	digest, err := plan.expectedDigest()
	if err != nil {
		return ChangePlan{}, err
	}
	plan.Digest = digest
	plan.ID = PlanID("identity-plan-" + digest[:40])
	if plan.ValidateAt(now) != nil {
		return ChangePlan{}, ErrInvalid
	}
	return plan, nil
}

func (plan ChangePlan) ValidateAt(now time.Time) error {
	if !validID(string(plan.ID)) || plan.Scope.Validate() != nil || plan.BeforeDesiredRevision == 0 || plan.BeforeObservedRevision == 0 || plan.BeforeGeneration == 0 || plan.BeforeGeneration == ^uint64(0) || plan.AfterGeneration != plan.BeforeGeneration+1 || !validDigest(plan.BeforeDesiredDigest) || !validDigest(plan.BeforeObservationDigest) || plan.Before.Validate() != nil || plan.After.Validate() != nil || plan.Evidence.Scope != plan.Scope || plan.Evidence.Validate(plan.After, now) != nil || plan.Capabilities.Scope != plan.Scope || plan.Capabilities.Validate(now) != nil || !validID(string(plan.CreatedBy)) || !validUTC(plan.CreatedAt) || plan.CreatedAt.After(now) || !validDigest(plan.Digest) {
		return ErrInvalid
	}
	beforeSpecDigest, _ := plan.Before.Digest()
	afterSpecDigest, _ := plan.After.Digest()
	if beforeSpecDigest == afterSpecDigest || len(plan.Effects) == 0 {
		return ErrInvalid
	}
	impacts, requirements, effects, err := deriveChange(plan.Before, plan.After, plan.Capabilities)
	if err != nil || !slices.Equal(plan.Impacts, impacts) || plan.Requirements != requirements || !slices.Equal(plan.Effects, effects) || !slices.Equal(plan.Warnings, deriveWarnings(impacts, requirements)) {
		return ErrInvalid
	}
	warningCodes := make([]WarningCode, 0, len(plan.Warnings))
	for _, warning := range plan.Warnings {
		if warning != warningFor(warning.Code) {
			return ErrInvalid
		}
		warningCodes = append(warningCodes, warning.Code)
	}
	if !slices.Equal(warningCodes, plan.AcknowledgedWarnings) || plan.MaintenanceApproved != plan.Requirements.MaintenanceRequired || plan.RebootApproved != (plan.Requirements.Reboot == RebootRequired) || plan.IrreversibleApproved != (plan.Requirements.OverallRollback != RollbackReversible) {
		return ErrInvalid
	}
	expected, err := plan.expectedDigest()
	if err != nil || expected != plan.Digest || plan.ID != PlanID("identity-plan-"+expected[:40]) {
		return ErrInvalid
	}
	return nil
}

func (plan ChangePlan) expectedDigest() (string, error) {
	copy := plan
	copy.ID, copy.Digest = "", ""
	return digestValue("plan", copy)
}

func deriveChange(before, after IdentitySpec, capabilities CapabilityObservation) ([]ChangeImpact, PlanRequirements, []EffectIntent, error) {
	hostChanged := before.Hostname != after.Hostname || before.FQDN != after.FQDN
	addressesChanged := !slices.Equal(before.DeclaredAddresses, after.DeclaredAddresses)
	timezoneChanged := before.Timezone != after.Timezone
	contactChanged := before.AdministrativeContact != after.AdministrativeContact
	originChanged := before.PanelOrigin != after.PanelOrigin
	certificateChanged := hostChanged || originChanged
	listenersChanged := addressesChanged || originChanged
	dnsChanged := hostChanged || addressesChanged
	mailChanged := capabilities.MailConfigured && hostChanged
	rebootRequired := hostChanged && capabilities.HostnameRequiresReboot
	if hostChanged && !capabilities.SetHostname || addressesChanged && !capabilities.SetAddresses || timezoneChanged && !capabilities.SetTimezone || contactChanged && !capabilities.SetAdministrativeContact || originChanged && !capabilities.SetPanelOrigin || certificateChanged && !capabilities.StageCertificate || listenersChanged && !capabilities.StageListeners || dnsChanged && capabilities.DNSConfigured && !capabilities.ManageDNS || mailChanged && !capabilities.ManageMail || rebootRequired && !capabilities.RebootNode {
		return nil, PlanRequirements{}, nil, ErrUnsupported
	}
	dnsImpact := dnsChanged
	impacts := []ChangeImpact{
		{ImpactCertificate, certificateChanged, certificateChanged, certificateChanged && capabilities.MakeBeforeBreakCertificate, certainty(certificateChanged, capabilities.RollbackCertificate, capabilities.ObserveDependencies)},
		{ImpactListeners, listenersChanged, listenersChanged, listenersChanged && capabilities.MakeBeforeBreakListeners, certainty(listenersChanged, capabilities.RollbackListeners, capabilities.ObserveDependencies)},
		{ImpactDNS, dnsImpact, dnsImpact && capabilities.DNSConfigured, dnsImpact && addressesChanged && capabilities.MakeBeforeBreakAddresses, certainty(dnsImpact && capabilities.DNSConfigured, capabilities.RollbackDNS, capabilities.ObserveDependencies)},
		{ImpactMail, mailChanged, mailChanged, false, certainty(mailChanged, capabilities.RollbackMail, capabilities.ObserveDependencies)},
	}
	overall := RollbackReversible
	for _, impact := range impacts {
		if impact.Rollback == RollbackAmbiguous {
			overall = RollbackAmbiguous
		}
		if impact.Rollback == RollbackIrreversible {
			overall = RollbackIrreversible
		}
	}
	if (hostChanged || addressesChanged || timezoneChanged || contactChanged || originChanged) && !capabilities.RollbackHost {
		overall = RollbackIrreversible
	}
	lockout := originChanged || addressesChanged
	requirements := PlanRequirements{MaintenanceRequired: certificateChanged || listenersChanged || dnsChanged || mailChanged, Reboot: RebootNone, LockoutRisk: lockout, OverallRollback: overall}
	if rebootRequired {
		requirements.Reboot = RebootRequired
	}
	effects := make([]EffectIntent, 0, 9)
	appendEffect := func(changed bool, kind EffectKind, beforeValue, afterValue any, reversible, makeBeforeBreak bool) {
		if !changed {
			return
		}
		beforeDigest, _ := digestValue("effect-before", beforeValue)
		afterDigest, _ := digestValue("effect-after", afterValue)
		effects = append(effects, EffectIntent{kind, beforeDigest, afterDigest, reversible, makeBeforeBreak})
	}
	appendEffect(hostChanged, EffectHostname, []string{before.Hostname, before.FQDN}, []string{after.Hostname, after.FQDN}, capabilities.RollbackHost, false)
	appendEffect(addressesChanged, EffectAddresses, before.DeclaredAddresses, after.DeclaredAddresses, capabilities.RollbackHost, capabilities.MakeBeforeBreakAddresses)
	appendEffect(timezoneChanged, EffectTimezone, before.Timezone, after.Timezone, capabilities.RollbackHost, false)
	appendEffect(contactChanged, EffectContact, before.AdministrativeContact, after.AdministrativeContact, capabilities.RollbackHost, false)
	appendEffect(originChanged, EffectPanelOrigin, before.PanelOrigin, after.PanelOrigin, capabilities.RollbackHost, false)
	appendEffect(certificateChanged, EffectCertificate, before.PanelOrigin, after.PanelOrigin, capabilities.RollbackCertificate, capabilities.MakeBeforeBreakCertificate)
	appendEffect(listenersChanged, EffectListeners, struct{ Addresses any; Origin string }{before.DeclaredAddresses, before.PanelOrigin}, struct{ Addresses any; Origin string }{after.DeclaredAddresses, after.PanelOrigin}, capabilities.RollbackListeners, capabilities.MakeBeforeBreakListeners)
	appendEffect(dnsChanged && capabilities.DNSConfigured, EffectDNS, struct{ FQDN string; Addresses any }{before.FQDN, before.DeclaredAddresses}, struct{ FQDN string; Addresses any }{after.FQDN, after.DeclaredAddresses}, capabilities.RollbackDNS, capabilities.MakeBeforeBreakAddresses)
	appendEffect(mailChanged, EffectMail, before.FQDN, after.FQDN, capabilities.RollbackMail, false)
	appendEffect(rebootRequired, EffectReboot, false, true, true, false)
	return impacts, requirements, effects, nil
}

func certainty(affected, reversible, observable bool) RollbackCertainty {
	if !affected || reversible {
		return RollbackReversible
	}
	if !observable {
		return RollbackAmbiguous
	}
	return RollbackIrreversible
}

func deriveWarnings(impacts []ChangeImpact, requirements PlanRequirements) []PlanWarning {
	codes := make([]WarningCode, 0, 8)
	if requirements.LockoutRisk {
		codes = append(codes, WarningLockout)
	}
	for _, impact := range impacts {
		if !impact.Affected {
			continue
		}
		switch impact.Kind {
		case ImpactCertificate:
			codes = append(codes, WarningCertificate)
		case ImpactDNS:
			codes = append(codes, WarningDNS)
		case ImpactMail:
			codes = append(codes, WarningMail)
		}
	}
	if requirements.MaintenanceRequired {
		codes = append(codes, WarningMaintenance)
	}
	if requirements.Reboot == RebootRequired {
		codes = append(codes, WarningReboot)
	}
	if requirements.OverallRollback == RollbackIrreversible {
		codes = append(codes, WarningIrreversible)
	}
	if requirements.OverallRollback == RollbackAmbiguous {
		codes = append(codes, WarningAmbiguous)
	}
	slices.Sort(codes)
	warnings := make([]PlanWarning, 0, len(codes))
	for _, code := range codes {
		warnings = append(warnings, warningFor(code))
	}
	return warnings
}

func validEffect(kind EffectKind) bool {
	switch kind {
	case EffectHostname, EffectAddresses, EffectTimezone, EffectContact, EffectPanelOrigin, EffectCertificate, EffectListeners, EffectDNS, EffectMail, EffectReboot:
		return true
	default:
		return false
	}
}

type ExecutionPhase string

const (
	PhaseStage      ExecutionPhase = "stage"
	PhasePreflight  ExecutionPhase = "preflight"
	PhaseActivate   ExecutionPhase = "activate"
	PhaseProbe      ExecutionPhase = "probe"
	PhaseCommit     ExecutionPhase = "commit"
	PhaseCompensate ExecutionPhase = "compensate"
)

type ExecutionState string

const (
	ExecutionQueued       ExecutionState = "queued"
	ExecutionStaged       ExecutionState = "staged"
	ExecutionPreflighted  ExecutionState = "preflighted"
	ExecutionActivated    ExecutionState = "activated"
	ExecutionProbed       ExecutionState = "probed"
	ExecutionCompensating ExecutionState = "compensating"
	ExecutionCompleted    ExecutionState = "completed"
	ExecutionFailed       ExecutionState = "failed"
	ExecutionCompensated  ExecutionState = "compensated"
	ExecutionAmbiguous    ExecutionState = "ambiguous"
	ExecutionIrreversible ExecutionState = "irreversible"
)

type Execution struct {
	PlanID               PlanID        `json:"plan_id"`
	State                ExecutionState `json:"state"`
	Revision             uint64        `json:"revision"`
	Attempt              uint32        `json:"attempt"`
	Fence                uint64        `json:"fence"`
	LeaseToken           string        `json:"lease_token,omitempty"`
	LeaseUntil           time.Time     `json:"lease_until,omitempty"`
	Activated            bool          `json:"activated"`
	IrreversibleCrossed  bool          `json:"irreversible_crossed"`
	Ambiguous            bool          `json:"ambiguous"`
	LastErrorCode        string        `json:"last_error_code,omitempty"`
	UpdatedAt            time.Time     `json:"updated_at"`
}

func (execution Execution) Validate() error {
	if !validID(string(execution.PlanID)) || execution.Revision == 0 || execution.Attempt > 1_000_000 || !validUTC(execution.UpdatedAt) || !validExecutionState(execution.State) || execution.Ambiguous != (execution.State == ExecutionAmbiguous) || execution.IrreversibleCrossed && !execution.Activated || (execution.State == ExecutionActivated || execution.State == ExecutionProbed || execution.State == ExecutionCompleted || execution.State == ExecutionIrreversible) && !execution.Activated || execution.State == ExecutionIrreversible && !execution.IrreversibleCrossed {
		return ErrInvalid
	}
	leased := execution.LeaseToken != ""
	if leased != !execution.LeaseUntil.IsZero() || leased && (!validID(execution.LeaseToken) || !validUTC(execution.LeaseUntil) || execution.Fence == 0) || terminalState(execution.State) && leased {
		return ErrInvalid
	}
	if execution.LastErrorCode != "" && !validErrorCode(execution.LastErrorCode) {
		return ErrInvalid
	}
	return nil
}

type ExecutionLease struct {
	Execution Execution `json:"execution"`
	Token     string    `json:"token"`
	Fence     uint64    `json:"fence"`
	Until     time.Time `json:"until"`
}

type ReceiptOutcome string

const (
	OutcomeSucceeded ReceiptOutcome = "succeeded"
	OutcomeNotApplied ReceiptOutcome = "not_applied"
	OutcomeAmbiguous ReceiptOutcome = "ambiguous"
)

type StageResult struct {
	StagedEffects []EffectKind `json:"staged_effects"`
	StagedDigest  string       `json:"staged_digest"`
}

type PreflightResult struct {
	Checked []ImpactKind `json:"checked"`
	Digest  string       `json:"digest"`
}

type ActivationResult struct {
	ActivationID       string            `json:"activation_id"`
	ActivatedGeneration uint64           `json:"activated_generation"`
	MakeBeforeBreak    bool              `json:"make_before_break"`
	Rollback           RollbackCertainty `json:"rollback"`
	Digest             string            `json:"digest"`
}

type ProbeResult struct {
	Observed            *ObservedIdentity `json:"observed,omitempty"`
	HostnameVerified    bool              `json:"hostname_verified"`
	PanelOriginVerified bool              `json:"panel_origin_verified"`
	CertificateVerified bool              `json:"certificate_verified"`
	ListenersVerified   bool              `json:"listeners_verified"`
}

type CompensationResult struct {
	RestoredGeneration uint64            `json:"restored_generation"`
	Certainty          RollbackCertainty `json:"certainty"`
	Digest             string            `json:"digest"`
}

type CommitResult struct {
	DesiredDigest  string `json:"desired_digest"`
	ObservedDigest string `json:"observed_digest"`
}

type ExecutionReceipt struct {
	PlanID          PlanID              `json:"plan_id"`
	PlanDigest      string              `json:"plan_digest"`
	Phase           ExecutionPhase      `json:"phase"`
	Fence           uint64              `json:"fence"`
	Attempt         uint32              `json:"attempt"`
	Outcome         ReceiptOutcome      `json:"outcome"`
	Stage           *StageResult        `json:"stage,omitempty"`
	Preflight       *PreflightResult    `json:"preflight,omitempty"`
	Activation      *ActivationResult   `json:"activation,omitempty"`
	Probe           *ProbeResult        `json:"probe,omitempty"`
	Compensation    *CompensationResult `json:"compensation,omitempty"`
	Commit          *CommitResult       `json:"commit,omitempty"`
	ErrorCode       string              `json:"error_code,omitempty"`
	StartedAt       time.Time           `json:"started_at"`
	FinishedAt      time.Time           `json:"finished_at"`
	Digest          string              `json:"digest"`
}

func (receipt ExecutionReceipt) Validate(plan ChangePlan, now time.Time) error {
	if receipt.PlanID != plan.ID || receipt.PlanDigest != plan.Digest || receipt.Fence == 0 || receipt.Attempt == 0 || receipt.Outcome != OutcomeSucceeded && receipt.Outcome != OutcomeNotApplied && receipt.Outcome != OutcomeAmbiguous || !validUTC(receipt.StartedAt) || !validUTC(receipt.FinishedAt) || receipt.FinishedAt.Before(receipt.StartedAt) || receipt.FinishedAt.After(now) || !validDigest(receipt.Digest) {
		return ErrInvalid
	}
	if receipt.Outcome == OutcomeSucceeded && receipt.ErrorCode != "" || receipt.Outcome != OutcomeSucceeded && !validErrorCode(receipt.ErrorCode) {
		return ErrInvalid
	}
	set := 0
	for _, present := range []bool{receipt.Stage != nil, receipt.Preflight != nil, receipt.Activation != nil, receipt.Probe != nil, receipt.Compensation != nil, receipt.Commit != nil} {
		if present {
			set++
		}
	}
	if set != 1 || receipt.phasePayloadValid(plan) != nil {
		return ErrInvalid
	}
	expected, err := receipt.expectedDigest()
	if err != nil || expected != receipt.Digest {
		return ErrInvalid
	}
	return nil
}

func (receipt ExecutionReceipt) phasePayloadValid(plan ChangePlan) error {
	switch receipt.Phase {
	case PhaseStage:
		if receipt.Stage == nil || receipt.Outcome == OutcomeSucceeded && (!slices.Equal(receipt.Stage.StagedEffects, effectKinds(plan.Effects)) || !validDigest(receipt.Stage.StagedDigest)) {
			return ErrInvalid
		}
	case PhasePreflight:
		if receipt.Preflight == nil || receipt.Outcome == OutcomeSucceeded && (!slices.Equal(receipt.Preflight.Checked, affectedImpacts(plan.Impacts)) || !validDigest(receipt.Preflight.Digest)) {
			return ErrInvalid
		}
	case PhaseActivate:
		if receipt.Activation == nil || receipt.Outcome == OutcomeSucceeded && (!validID(receipt.Activation.ActivationID) || receipt.Activation.ActivatedGeneration != plan.AfterGeneration || receipt.Activation.MakeBeforeBreak != makeBeforeBreak(plan) || !rollbackHonest(plan.Requirements.OverallRollback, receipt.Activation.Rollback) || !validDigest(receipt.Activation.Digest)) {
			return ErrInvalid
		}
	case PhaseProbe:
		if receipt.Probe == nil || receipt.Outcome == OutcomeSucceeded && (receipt.Probe.Observed == nil || receipt.Probe.Observed.Scope != plan.Scope || receipt.Probe.Observed.Revision != plan.BeforeObservedRevision+1 || receipt.Probe.Observed.AppliedGeneration != plan.AfterGeneration || receipt.Probe.Observed.Validate(plan.After, receipt.FinishedAt) != nil || !receipt.Probe.Observed.AllMatched() || !receipt.Probe.HostnameVerified || !receipt.Probe.PanelOriginVerified || !receipt.Probe.CertificateVerified || !receipt.Probe.ListenersVerified) {
			return ErrInvalid
		}
	case PhaseCompensate:
		if receipt.Compensation == nil || receipt.Outcome == OutcomeSucceeded && (receipt.Compensation.RestoredGeneration != plan.BeforeGeneration || receipt.Compensation.Certainty != RollbackReversible || !validDigest(receipt.Compensation.Digest)) {
			return ErrInvalid
		}
	case PhaseCommit:
		if receipt.Commit == nil || receipt.Outcome != OutcomeSucceeded || !validDigest(receipt.Commit.DesiredDigest) || !validDigest(receipt.Commit.ObservedDigest) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (receipt ExecutionReceipt) expectedDigest() (string, error) {
	copy := receipt
	copy.Digest = ""
	return digestValue("receipt", copy)
}

type StageRequest struct {
	PlanID      PlanID        `json:"plan_id"`
	PlanDigest  string        `json:"plan_digest"`
	IdempotencyKey string     `json:"idempotency_key"`
	Before      IdentitySpec  `json:"before"`
	After       IdentitySpec  `json:"after"`
	Effects     []EffectIntent `json:"effects"`
	Fence       uint64        `json:"fence"`
	LeaseUntil  time.Time     `json:"lease_until"`
}

type PreflightRequest struct {
	PlanID      PlanID         `json:"plan_id"`
	PlanDigest  string         `json:"plan_digest"`
	IdempotencyKey string      `json:"idempotency_key"`
	Impacts     []ChangeImpact `json:"impacts"`
	Staged      StageResult    `json:"staged"`
	Fence       uint64         `json:"fence"`
	LeaseUntil  time.Time      `json:"lease_until"`
}

type ActivateRequest struct {
	PlanID         PlanID         `json:"plan_id"`
	PlanDigest     string         `json:"plan_digest"`
	IdempotencyKey string         `json:"idempotency_key"`
	Effects        []EffectIntent `json:"effects"`
	MakeBeforeBreak bool          `json:"make_before_break"`
	Fence          uint64         `json:"fence"`
	LeaseUntil     time.Time      `json:"lease_until"`
}

type ProbeRequest struct {
	PlanID        PlanID       `json:"plan_id"`
	PlanDigest    string       `json:"plan_digest"`
	IdempotencyKey string      `json:"idempotency_key"`
	Scope         Scope        `json:"scope"`
	After         IdentitySpec `json:"after"`
	AfterGeneration uint64     `json:"after_generation"`
	ObservedRevision uint64    `json:"observed_revision"`
	Fence         uint64       `json:"fence"`
	LeaseUntil    time.Time    `json:"lease_until"`
}

type CompensateRequest struct {
	PlanID       PlanID              `json:"plan_id"`
	PlanDigest   string              `json:"plan_digest"`
	IdempotencyKey string            `json:"idempotency_key"`
	Before       IdentitySpec        `json:"before"`
	Receipts     []ExecutionReceipt  `json:"receipts"`
	Fence        uint64              `json:"fence"`
	LeaseUntil   time.Time           `json:"lease_until"`
}

// Executor accepts only closed, typed host-identity effects. Implementations
// must make IdempotencyKey one-use/idempotent and reject a fence below the
// highest fence observed for a plan and phase.
type Executor interface {
	Stage(context.Context, StageRequest) (StageResult, ReceiptOutcome, error)
	Preflight(context.Context, PreflightRequest) (PreflightResult, ReceiptOutcome, error)
	Activate(context.Context, ActivateRequest) (ActivationResult, ReceiptOutcome, error)
	Probe(context.Context, ProbeRequest) (ProbeResult, ReceiptOutcome, error)
	Compensate(context.Context, CompensateRequest) (CompensationResult, ReceiptOutcome, error)
}

func effectKinds(effects []EffectIntent) []EffectKind {
	values := make([]EffectKind, 0, len(effects))
	for _, effect := range effects {
		values = append(values, effect.Kind)
	}
	return values
}

func affectedImpacts(impacts []ChangeImpact) []ImpactKind {
	values := make([]ImpactKind, 0, len(impacts))
	for _, impact := range impacts {
		if impact.Affected {
			values = append(values, impact.Kind)
		}
	}
	return values
}

func validExecutionState(state ExecutionState) bool {
	switch state {
	case ExecutionQueued, ExecutionStaged, ExecutionPreflighted, ExecutionActivated, ExecutionProbed, ExecutionCompensating, ExecutionCompleted, ExecutionFailed, ExecutionCompensated, ExecutionAmbiguous, ExecutionIrreversible:
		return true
	default:
		return false
	}
}

func terminalState(state ExecutionState) bool {
	return state == ExecutionCompleted || state == ExecutionFailed || state == ExecutionCompensated || state == ExecutionAmbiguous || state == ExecutionIrreversible
}

func phaseForState(state ExecutionState) ExecutionPhase {
	switch state {
	case ExecutionQueued:
		return PhaseStage
	case ExecutionStaged:
		return PhasePreflight
	case ExecutionPreflighted:
		return PhaseActivate
	case ExecutionActivated:
		return PhaseProbe
	case ExecutionProbed:
		return PhaseCommit
	case ExecutionCompensating:
		return PhaseCompensate
	default:
		return ""
	}
}

func makeBeforeBreak(plan ChangePlan) bool {
	for _, impact := range plan.Impacts {
		if impact.Affected && impact.Required && (impact.Kind == ImpactCertificate || impact.Kind == ImpactListeners || impact.Kind == ImpactDNS) && !impact.MakeBeforeBreak {
			return false
		}
	}
	return true
}

func rollbackHonest(planned, observed RollbackCertainty) bool {
	return planned.valid() && observed == planned
}

func validErrorCode(code string) bool {
	switch code {
	case "executor_failure", "stale", "unsupported", "preflight_failed", "probe_failed", "compensation_failed", "audit_unavailable", "lease_expired", "conflict":
		return true
	default:
		return false
	}
}

func marshalDigest(domain string, value any) string {
	encoded, _ := json.Marshal(value)
	digest, _ := digestValue(domain, json.RawMessage(encoded))
	return digest
}
