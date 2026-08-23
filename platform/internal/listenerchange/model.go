package listenerchange

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalid          = errors.New("invalid listener change value")
	ErrUnauthorized     = errors.New("listener change authorization denied")
	ErrStepUpRequired   = errors.New("recent listener change step-up required")
	ErrRiskApproval     = errors.New("listener lockout risk not approved")
	ErrNotFound         = errors.New("listener change resource not found")
	ErrConflict         = errors.New("listener change conflict")
	ErrStale            = errors.New("stale listener change generation or evidence")
	ErrIncomplete       = errors.New("listener change is incomplete")
	ErrUncertain        = errors.New("listener change outcome is uncertain")
	ErrAuditUnavailable = errors.New("listener change audit unavailable")
)

const (
	MaximumEvidenceAge   = 5 * time.Minute
	MaximumStepUpAge     = 10 * time.Minute
	MinimumRollbackLease = 2 * time.Minute
	MaximumRollbackLease = 30 * time.Minute
	MaximumWorkLease     = 2 * time.Minute
	MaximumListeners     = 32
	MaximumStatusReceipts = 16
	maximumGeneration    = uint64(1<<63 - 1)
)

type TenantID string
type NodeID string
type PrincipalID string
type PlanID string

type Scope struct {
	TenantID TenantID `json:"tenant_id"`
	NodeID   NodeID   `json:"node_id"`
}

func (scope Scope) Validate() error {
	if !validID(string(scope.TenantID)) || !validID(string(scope.NodeID)) {
		return ErrInvalid
	}
	return nil
}

type Actor struct {
	TenantID    TenantID    `json:"tenant_id"`
	PrincipalID PrincipalID `json:"principal_id"`
	SessionID   string      `json:"session_id"`
}

func (actor Actor) Validate() error {
	if !validID(string(actor.TenantID)) || !validID(string(actor.PrincipalID)) || !validID(actor.SessionID) {
		return ErrInvalid
	}
	return nil
}

type ListenerKind string
type Protocol string

const (
	ListenerPanel ListenerKind = "panel"
	ListenerSSH   ListenerKind = "ssh"
	ProtocolTCP   Protocol     = "tcp"
)

type Listener struct {
	Kind     ListenerKind `json:"kind"`
	Protocol Protocol     `json:"protocol"`
	Address  netip.Addr   `json:"address"`
	Port     uint16       `json:"port"`
}

func (listener Listener) Validate() error {
	if listener.Kind != ListenerPanel && listener.Kind != ListenerSSH || listener.Protocol != ProtocolTCP || !listener.Address.IsValid() || listener.Address.Is4In6() || listener.Address.Zone() != "" || listener.Address.IsMulticast() || listener.Port == 0 {
		return ErrInvalid
	}
	return nil
}

func compareListener(left, right Listener) int {
	if left.Kind < right.Kind {
		return -1
	}
	if left.Kind > right.Kind {
		return 1
	}
	if left.Protocol < right.Protocol {
		return -1
	}
	if left.Protocol > right.Protocol {
		return 1
	}
	if compared := left.Address.Compare(right.Address); compared != 0 {
		return compared
	}
	if left.Port < right.Port {
		return -1
	}
	if left.Port > right.Port {
		return 1
	}
	return 0
}

type ListenerSet struct {
	Panel []Listener `json:"panel"`
	SSH   []Listener `json:"ssh"`
}

func (listeners ListenerSet) Validate() error {
	if len(listeners.Panel) == 0 || len(listeners.SSH) == 0 || len(listeners.Panel)+len(listeners.SSH) > MaximumListeners || !sortedListeners(listeners.Panel, ListenerPanel) || !sortedListeners(listeners.SSH, ListenerSSH) || duplicateEndpoint(listeners.Panel, listeners.SSH) {
		return ErrInvalid
	}
	return nil
}

func duplicateEndpoint(panel, ssh []Listener) bool {
	for _, left := range panel {
		for _, right := range ssh {
			if left.Protocol == right.Protocol && left.Address == right.Address && left.Port == right.Port {
				return true
			}
		}
	}
	return false
}

func (listeners ListenerSet) all() []Listener {
	values := append(append([]Listener(nil), listeners.Panel...), listeners.SSH...)
	slices.SortFunc(values, compareListener)
	return values
}

func (listeners ListenerSet) Digest() (string, error) {
	if listeners.Validate() != nil {
		return "", ErrInvalid
	}
	return digestValue("listener-set", listeners)
}

type BootIdentity struct {
	BootID     string    `json:"boot_id"`
	MachineID  string    `json:"machine_id"`
	ObservedAt time.Time `json:"observed_at"`
	Digest     string    `json:"digest"`
}

func (boot BootIdentity) Validate(now time.Time) error {
	if !validID(boot.BootID) || !validID(boot.MachineID) || !validUTC(now) || !validUTC(boot.ObservedAt) || boot.ObservedAt.After(now) || now.Sub(boot.ObservedAt) > MaximumEvidenceAge || !validDigest(boot.Digest) {
		return ErrStale
	}
	copy := boot
	copy.Digest = ""
	expected, err := digestValue("boot", copy)
	if err != nil || expected != boot.Digest {
		return ErrStale
	}
	return nil
}

func (boot BootIdentity) ExpectedDigest() (string, error) {
	copy := boot
	copy.Digest = ""
	return digestValue("boot", copy)
}

type CertificateDependency struct {
	Origin      string    `json:"origin"`
	DNSNames    []string  `json:"dns_names"`
	Fingerprint string    `json:"fingerprint"`
	Generation  uint64    `json:"generation"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	ObservedAt  time.Time `json:"observed_at"`
	ValidUntil  time.Time `json:"valid_until"`
	Digest      string    `json:"digest"`
}

func (certificate CertificateDependency) Validate(now time.Time) error {
	origin, host, err := canonicalOrigin(certificate.Origin)
	if err != nil || origin != certificate.Origin || certificate.Generation == 0 || certificate.Generation > maximumGeneration || !sortedHostnames(certificate.DNSNames) || !slices.Contains(certificate.DNSNames, host) || !validDigest(certificate.Fingerprint) || !validUTC(now) || !validUTC(certificate.NotBefore) || !validUTC(certificate.NotAfter) || !certificate.NotAfter.After(now) || certificate.NotBefore.After(now) || !validUTC(certificate.ObservedAt) || !validUTC(certificate.ValidUntil) || certificate.ObservedAt.After(now) || now.Sub(certificate.ObservedAt) > MaximumEvidenceAge || !certificate.ValidUntil.After(now) || certificate.ValidUntil.After(certificate.ObservedAt.Add(MaximumEvidenceAge)) || !validDigest(certificate.Digest) {
		return ErrStale
	}
	copy := certificate
	copy.Digest = ""
	expected, err := digestValue("certificate", copy)
	if err != nil || expected != certificate.Digest {
		return ErrStale
	}
	return nil
}

func (certificate CertificateDependency) ExpectedDigest() (string, error) {
	copy := certificate
	copy.Digest = ""
	return digestValue("certificate", copy)
}

type AdministrativePathEvidence struct {
	Listeners  []Listener `json:"listeners"`
	ObserverID string     `json:"observer_id"`
	ObservedAt time.Time  `json:"observed_at"`
	ValidUntil time.Time  `json:"valid_until"`
	Digest     string     `json:"digest"`
}

func (evidence AdministrativePathEvidence) Validate(current ListenerSet, now time.Time) error {
	if len(evidence.Listeners) == 0 || !sortedListeners(evidence.Listeners, ListenerSSH) || !validID(evidence.ObserverID) || !validUTC(now) || !validUTC(evidence.ObservedAt) || !validUTC(evidence.ValidUntil) || evidence.ObservedAt.After(now) || now.Sub(evidence.ObservedAt) > MaximumEvidenceAge || !evidence.ValidUntil.After(now) || evidence.ValidUntil.After(evidence.ObservedAt.Add(MaximumEvidenceAge)) || !validDigest(evidence.Digest) {
		return ErrStale
	}
	for _, listener := range evidence.Listeners {
		if !slices.Contains(current.SSH, listener) {
			return ErrStale
		}
	}
	copy := evidence
	copy.Digest = ""
	expected, err := digestValue("administrative-evidence", copy)
	if err != nil || expected != evidence.Digest {
		return ErrStale
	}
	return nil
}

func (evidence AdministrativePathEvidence) ExpectedDigest() (string, error) {
	copy := evidence
	copy.Digest = ""
	return digestValue("administrative-evidence", copy)
}

type CurrentState struct {
	Scope                 Scope                      `json:"scope"`
	Revision              uint64                     `json:"revision"`
	ConfigurationGeneration uint64                   `json:"configuration_generation"`
	FirewallGeneration    uint64                     `json:"firewall_generation"`
	Listeners             ListenerSet                `json:"listeners"`
	PanelOrigin           string                     `json:"panel_origin"`
	Certificate           CertificateDependency      `json:"certificate"`
	ConfirmedAdministrative AdministrativePathEvidence `json:"confirmed_administrative"`
	Boot                  BootIdentity               `json:"boot"`
	ObservedAt            time.Time                  `json:"observed_at"`
	Digest                string                     `json:"digest"`
}

func (current CurrentState) Validate(now time.Time) error {
	origin, _, originErr := canonicalOrigin(current.PanelOrigin)
	if current.Scope.Validate() != nil || current.Revision == 0 || current.Revision > maximumGeneration || current.ConfigurationGeneration == 0 || current.ConfigurationGeneration > maximumGeneration || current.FirewallGeneration == 0 || current.FirewallGeneration > maximumGeneration || current.Listeners.Validate() != nil || originErr != nil || origin != current.PanelOrigin || current.Certificate.Origin != current.PanelOrigin || current.Certificate.Validate(now) != nil || current.ConfirmedAdministrative.Validate(current.Listeners, now) != nil || current.Boot.Validate(now) != nil || !validUTC(current.ObservedAt) || current.ObservedAt.After(now) || now.Sub(current.ObservedAt) > MaximumEvidenceAge || !validDigest(current.Digest) {
		return ErrStale
	}
	copy := current
	copy.Digest = ""
	expected, err := digestValue("current-state", copy)
	if err != nil || expected != current.Digest {
		return ErrStale
	}
	return nil
}

func (current CurrentState) ExpectedDigest() (string, error) {
	copy := current
	copy.Digest = ""
	return digestValue("current-state", copy)
}

type ConfirmationMode string

const (
	ConfirmationAlways ConfirmationMode = "always"
	ConfirmationOnRisk ConfirmationMode = "on_risk"
	ConfirmationNever  ConfirmationMode = "never"
)

type ExternalConfirmationPolicy struct {
	Mode             ConfirmationMode `json:"mode"`
	MinimumObservers uint8            `json:"minimum_observers"`
	MaximumAge       time.Duration    `json:"maximum_age"`
}

func (policy ExternalConfirmationPolicy) Validate() error {
	if policy.Mode != ConfirmationAlways && policy.Mode != ConfirmationOnRisk && policy.Mode != ConfirmationNever || policy.MinimumObservers == 0 || policy.MinimumObservers > 3 || policy.MaximumAge < 30*time.Second || policy.MaximumAge > MaximumEvidenceAge {
		return ErrInvalid
	}
	return nil
}

type ConfirmationChallenge struct {
	ID            string    `json:"id"`
	BindingDigest string    `json:"binding_digest"`
	NonceDigest   string    `json:"nonce_digest"`
	ExpiresAt     time.Time `json:"expires_at"`
	AuthorityID   string    `json:"authority_id"`
}

func (challenge ConfirmationChallenge) Validate(binding string, now time.Time, maximumAge time.Duration) error {
	if !validID(challenge.ID) || challenge.BindingDigest != binding || !validDigest(challenge.NonceDigest) || !validUTC(now) || !validUTC(challenge.ExpiresAt) || !challenge.ExpiresAt.After(now) || challenge.ExpiresAt.After(now.Add(maximumAge)) || !validID(challenge.AuthorityID) {
		return ErrStale
	}
	return nil
}

type RollbackPolicy struct {
	LeaseDuration time.Duration `json:"lease_duration"`
	Deadline      time.Time     `json:"deadline"`
	Persistent    bool          `json:"persistent"`
}

func (policy RollbackPolicy) Validate(createdAt time.Time) error {
	if policy.LeaseDuration < MinimumRollbackLease || policy.LeaseDuration > MaximumRollbackLease || !validUTC(policy.Deadline) || !policy.Deadline.Equal(createdAt.Add(policy.LeaseDuration)) || !policy.Persistent {
		return ErrInvalid
	}
	return nil
}

type RiskReason string

const (
	RiskPanelAddressChanged RiskReason = "panel_address_changed"
	RiskPanelPortChanged    RiskReason = "panel_port_changed"
	RiskPanelOriginChanged  RiskReason = "panel_origin_changed"
	RiskSSHAddressChanged   RiskReason = "ssh_address_changed"
	RiskSSHPortChanged      RiskReason = "ssh_port_changed"
	RiskFirewallChanged     RiskReason = "firewall_rules_changed"
	RiskCertificateChanged  RiskReason = "certificate_changed"
	RiskLastAdminMigration  RiskReason = "last_admin_path_migration"
	RiskExternalRequired    RiskReason = "external_confirmation_required"
)

var stableRisks = []RiskReason{
	RiskCertificateChanged, RiskExternalRequired, RiskFirewallChanged, RiskLastAdminMigration,
	RiskPanelAddressChanged, RiskPanelOriginChanged, RiskPanelPortChanged,
	RiskSSHAddressChanged, RiskSSHPortChanged,
}

type FirewallTuple struct {
	Purpose  ListenerKind `json:"purpose"`
	Protocol Protocol     `json:"protocol"`
	Address  netip.Addr   `json:"address"`
	Port     uint16       `json:"port"`
}

func (tuple FirewallTuple) Validate() error {
	return Listener{Kind: tuple.Purpose, Protocol: tuple.Protocol, Address: tuple.Address, Port: tuple.Port}.Validate()
}

type PlanRequest struct {
	ExpectedRevision               uint64                     `json:"expected_revision"`
	ExpectedConfigurationGeneration uint64                   `json:"expected_configuration_generation"`
	ExpectedFirewallGeneration     uint64                     `json:"expected_firewall_generation"`
	Target                         ListenerSet                `json:"target"`
	TargetOrigin                   string                     `json:"target_origin"`
	TargetCertificate              CertificateDependency      `json:"target_certificate"`
	ConfirmationPolicy             ExternalConfirmationPolicy `json:"confirmation_policy"`
	Challenge                      *ConfirmationChallenge      `json:"challenge,omitempty"`
	RollbackLease                  time.Duration              `json:"rollback_lease"`
	ApprovedRisks                  []RiskReason                `json:"approved_risks"`
}

type ChangePlan struct {
	ID                         PlanID                     `json:"id"`
	Scope                      Scope                      `json:"scope"`
	BeforeRevision             uint64                     `json:"before_revision"`
	BeforeConfigurationGeneration uint64                 `json:"before_configuration_generation"`
	AfterConfigurationGeneration uint64                  `json:"after_configuration_generation"`
	BeforeFirewallGeneration   uint64                     `json:"before_firewall_generation"`
	OpenFirewallGeneration     uint64                     `json:"open_firewall_generation"`
	AfterFirewallGeneration    uint64                     `json:"after_firewall_generation"`
	BeforeDigest               string                    `json:"before_digest"`
	Current                    ListenerSet                `json:"current"`
	Target                     ListenerSet                `json:"target"`
	CurrentOrigin              string                     `json:"current_origin"`
	TargetOrigin               string                     `json:"target_origin"`
	CurrentCertificate         CertificateDependency      `json:"current_certificate"`
	TargetCertificate          CertificateDependency      `json:"target_certificate"`
	ConfirmedAdministrative    AdministrativePathEvidence `json:"confirmed_administrative"`
	OpenFirewall               []FirewallTuple            `json:"open_firewall"`
	CloseFirewall              []FirewallTuple            `json:"close_firewall"`
	ConfirmationPolicy         ExternalConfirmationPolicy `json:"confirmation_policy"`
	ExternalConfirmationRequired bool                     `json:"external_confirmation_required"`
	Challenge                  *ConfirmationChallenge      `json:"challenge,omitempty"`
	Rollback                   RollbackPolicy              `json:"rollback"`
	Boot                       BootIdentity                `json:"boot"`
	Risks                      []RiskReason                `json:"risks"`
	ApprovedRisks              []RiskReason                `json:"approved_risks"`
	CreatedBy                  PrincipalID                 `json:"created_by"`
	CreatedAt                  time.Time                   `json:"created_at"`
	Digest                     string                      `json:"digest"`
}

func BuildPlan(current CurrentState, request PlanRequest, actor PrincipalID, now time.Time) (ChangePlan, error) {
	if current.Validate(now) != nil || request.Target.Validate() != nil || request.ConfirmationPolicy.Validate() != nil || !validID(string(actor)) || !validUTC(now) {
		return ChangePlan{}, ErrInvalid
	}
	targetOrigin, _, err := canonicalOrigin(request.TargetOrigin)
	if err != nil || targetOrigin != request.TargetOrigin || request.TargetCertificate.Origin != request.TargetOrigin || request.TargetCertificate.Validate(now) != nil {
		return ChangePlan{}, ErrStale
	}
	if request.ExpectedRevision != current.Revision || request.ExpectedConfigurationGeneration != current.ConfigurationGeneration || request.ExpectedFirewallGeneration != current.FirewallGeneration || current.Revision >= maximumGeneration || current.ConfigurationGeneration > maximumGeneration-2 || current.FirewallGeneration > maximumGeneration-4 {
		return ChangePlan{}, ErrStale
	}
	currentDigest, _ := current.Listeners.Digest()
	targetDigest, _ := request.Target.Digest()
	if currentDigest == targetDigest && current.PanelOrigin == request.TargetOrigin && current.Certificate.Digest == request.TargetCertificate.Digest {
		return ChangePlan{}, ErrConflict
	}
	open := firewallDifference(request.Target, current.Listeners)
	closeValues := firewallDifference(current.Listeners, request.Target)
	risks := deriveRisks(current, request, open, closeValues)
	required := confirmationRequired(current.Listeners, request.Target, request.ConfirmationPolicy, risks)
	if sshChanged(current.Listeners, request.Target) && !required {
		return ChangePlan{}, ErrRiskApproval
	}
	binding, err := confirmationBinding(current, request, risks)
	if err != nil {
		return ChangePlan{}, err
	}
	if required {
		if request.Challenge == nil || request.Challenge.Validate(binding, now, request.ConfirmationPolicy.MaximumAge) != nil {
			return ChangePlan{}, ErrIncomplete
		}
	} else if request.Challenge != nil {
		return ChangePlan{}, ErrInvalid
	}
	if !slices.Equal(risks, request.ApprovedRisks) {
		return ChangePlan{}, ErrRiskApproval
	}
	openGeneration := current.FirewallGeneration
	if len(open) != 0 {
		openGeneration++
	}
	afterFirewall := openGeneration
	if len(closeValues) != 0 {
		afterFirewall++
	}
	plan := ChangePlan{
		Scope: current.Scope, BeforeRevision: current.Revision,
		BeforeConfigurationGeneration: current.ConfigurationGeneration, AfterConfigurationGeneration: current.ConfigurationGeneration + 1,
		BeforeFirewallGeneration: current.FirewallGeneration, OpenFirewallGeneration: openGeneration, AfterFirewallGeneration: afterFirewall,
		BeforeDigest: current.Digest, Current: current.Listeners, Target: request.Target,
		CurrentOrigin: current.PanelOrigin, TargetOrigin: request.TargetOrigin,
		CurrentCertificate: current.Certificate, TargetCertificate: request.TargetCertificate,
		ConfirmedAdministrative: current.ConfirmedAdministrative,
		OpenFirewall: open, CloseFirewall: closeValues,
		ConfirmationPolicy: request.ConfirmationPolicy, ExternalConfirmationRequired: required, Challenge: request.Challenge,
		Rollback: RollbackPolicy{LeaseDuration: request.RollbackLease, Deadline: now.Add(request.RollbackLease), Persistent: true},
		Boot: current.Boot, Risks: risks, ApprovedRisks: append([]RiskReason(nil), request.ApprovedRisks...),
		CreatedBy: actor, CreatedAt: now,
	}
	digest, err := plan.expectedDigest()
	if err != nil {
		return ChangePlan{}, err
	}
	plan.Digest = digest
	plan.ID = PlanID("listener-plan-" + digest[:40])
	if plan.ValidateAt(now) != nil {
		return ChangePlan{}, ErrInvalid
	}
	return plan, nil
}

func (plan ChangePlan) ValidateAt(now time.Time) error {
	if !validID(string(plan.ID)) || plan.Scope.Validate() != nil || plan.BeforeRevision == 0 || plan.BeforeRevision >= maximumGeneration || plan.BeforeConfigurationGeneration == 0 || plan.BeforeConfigurationGeneration > maximumGeneration-2 || plan.AfterConfigurationGeneration != plan.BeforeConfigurationGeneration+1 || plan.BeforeFirewallGeneration == 0 || plan.BeforeFirewallGeneration > maximumGeneration-4 || plan.OpenFirewallGeneration < plan.BeforeFirewallGeneration || plan.AfterFirewallGeneration < plan.OpenFirewallGeneration || plan.AfterFirewallGeneration > plan.BeforeFirewallGeneration+2 || !validDigest(plan.BeforeDigest) || plan.Current.Validate() != nil || plan.Target.Validate() != nil || plan.CurrentCertificate.Origin != plan.CurrentOrigin || plan.TargetCertificate.Origin != plan.TargetOrigin || plan.CurrentCertificate.Validate(plan.CreatedAt) != nil || plan.TargetCertificate.Validate(now) != nil || plan.ConfirmedAdministrative.Validate(plan.Current, plan.CreatedAt) != nil || plan.ConfirmationPolicy.Validate() != nil || plan.Rollback.Validate(plan.CreatedAt) != nil || plan.Boot.Validate(plan.CreatedAt) != nil || !slices.Equal(plan.Risks, plan.ApprovedRisks) || !sortedRisks(plan.Risks) || !validID(string(plan.CreatedBy)) || !validUTC(plan.CreatedAt) || plan.CreatedAt.After(now) || !validDigest(plan.Digest) {
		return ErrInvalid
	}
	expectedOpen := firewallDifference(plan.Target, plan.Current)
	expectedClose := firewallDifference(plan.Current, plan.Target)
	if !slices.Equal(plan.OpenFirewall, expectedOpen) || !slices.Equal(plan.CloseFirewall, expectedClose) || plan.OpenFirewallGeneration != plan.BeforeFirewallGeneration+boolGeneration(len(expectedOpen) != 0) || plan.AfterFirewallGeneration != plan.OpenFirewallGeneration+boolGeneration(len(expectedClose) != 0) {
		return ErrInvalid
	}
	request := PlanRequest{Target: plan.Target, TargetOrigin: plan.TargetOrigin, TargetCertificate: plan.TargetCertificate, ConfirmationPolicy: plan.ConfirmationPolicy}
	expectedRisks := deriveRisks(CurrentState{Listeners: plan.Current, PanelOrigin: plan.CurrentOrigin, Certificate: plan.CurrentCertificate}, request, expectedOpen, expectedClose)
	if !slices.Equal(plan.Risks, expectedRisks) || plan.ExternalConfirmationRequired != confirmationRequired(plan.Current, plan.Target, plan.ConfirmationPolicy, plan.Risks) || sshChanged(plan.Current, plan.Target) && !plan.ExternalConfirmationRequired {
		return ErrInvalid
	}
	binding, err := plan.confirmationBinding()
	if plan.ExternalConfirmationRequired {
		if plan.Challenge == nil || err != nil || plan.Challenge.Validate(binding, plan.CreatedAt, plan.ConfirmationPolicy.MaximumAge) != nil {
			return ErrInvalid
		}
	} else if plan.Challenge != nil {
		return ErrInvalid
	}
	expected, err := plan.expectedDigest()
	if err != nil || expected != plan.Digest || plan.ID != PlanID("listener-plan-"+expected[:40]) {
		return ErrInvalid
	}
	return nil
}

func (plan ChangePlan) expectedDigest() (string, error) {
	copy := plan
	copy.ID, copy.Digest = "", ""
	return digestValue("plan", copy)
}

func (plan ChangePlan) confirmationBinding() (string, error) {
	return digestValue("confirmation-binding", struct {
		Scope Scope `json:"scope"`
		BeforeRevision uint64 `json:"before_revision"`
		BeforeConfigurationGeneration uint64 `json:"before_configuration_generation"`
		BeforeFirewallGeneration uint64 `json:"before_firewall_generation"`
		BootDigest string `json:"boot_digest"`
		Current ListenerSet `json:"current"`
		Target ListenerSet `json:"target"`
		Origin string `json:"origin"`
		Certificate string `json:"certificate"`
		Risks []RiskReason `json:"risks"`
	}{plan.Scope, plan.BeforeRevision, plan.BeforeConfigurationGeneration, plan.BeforeFirewallGeneration, plan.Boot.Digest, plan.Current, plan.Target, plan.TargetOrigin, plan.TargetCertificate.Digest, plan.Risks})
}

func confirmationBinding(current CurrentState, request PlanRequest, risks []RiskReason) (string, error) {
	return digestValue("confirmation-binding", struct {
		Scope Scope `json:"scope"`
		BeforeRevision uint64 `json:"before_revision"`
		BeforeConfigurationGeneration uint64 `json:"before_configuration_generation"`
		BeforeFirewallGeneration uint64 `json:"before_firewall_generation"`
		BootDigest string `json:"boot_digest"`
		Current ListenerSet `json:"current"`
		Target ListenerSet `json:"target"`
		Origin string `json:"origin"`
		Certificate string `json:"certificate"`
		Risks []RiskReason `json:"risks"`
	}{current.Scope, current.Revision, current.ConfigurationGeneration, current.FirewallGeneration, current.Boot.Digest, current.Listeners, request.Target, request.TargetOrigin, request.TargetCertificate.Digest, risks})
}

func deriveRisks(current CurrentState, request PlanRequest, open, closeValues []FirewallTuple) []RiskReason {
	values := make([]RiskReason, 0, len(stableRisks))
	panelAddress, panelPort := listenerAddressAndPortChanged(current.Listeners.Panel, request.Target.Panel)
	sshAddress, sshPort := listenerAddressAndPortChanged(current.Listeners.SSH, request.Target.SSH)
	add := func(condition bool, risk RiskReason) {
		if condition {
			values = append(values, risk)
		}
	}
	add(panelAddress, RiskPanelAddressChanged)
	add(panelPort, RiskPanelPortChanged)
	add(current.PanelOrigin != request.TargetOrigin, RiskPanelOriginChanged)
	add(sshAddress, RiskSSHAddressChanged)
	add(sshPort, RiskSSHPortChanged)
	add(len(open)+len(closeValues) != 0, RiskFirewallChanged)
	add(current.Certificate.Digest != request.TargetCertificate.Digest, RiskCertificateChanged)
	add(sshChanged(current.Listeners, request.Target), RiskLastAdminMigration)
	preliminaryRequired := request.ConfirmationPolicy.Mode == ConfirmationAlways || request.ConfirmationPolicy.Mode == ConfirmationOnRisk && len(values) != 0 || sshChanged(current.Listeners, request.Target)
	add(preliminaryRequired, RiskExternalRequired)
	slices.Sort(values)
	return values
}

func confirmationRequired(current, target ListenerSet, policy ExternalConfirmationPolicy, risks []RiskReason) bool {
	return sshChanged(current, target) || policy.Mode == ConfirmationAlways || policy.Mode == ConfirmationOnRisk && len(risks) != 0
}

func sshChanged(current, target ListenerSet) bool {
	return !slices.Equal(current.SSH, target.SSH)
}

func listenerAddressAndPortChanged(current, target []Listener) (bool, bool) {
	currentAddresses, targetAddresses := make([]netip.Addr, 0, len(current)), make([]netip.Addr, 0, len(target))
	currentPorts, targetPorts := make([]uint16, 0, len(current)), make([]uint16, 0, len(target))
	for _, listener := range current {
		currentAddresses = append(currentAddresses, listener.Address)
		currentPorts = append(currentPorts, listener.Port)
	}
	for _, listener := range target {
		targetAddresses = append(targetAddresses, listener.Address)
		targetPorts = append(targetPorts, listener.Port)
	}
	slices.SortFunc(currentAddresses, func(left, right netip.Addr) int { return left.Compare(right) })
	slices.SortFunc(targetAddresses, func(left, right netip.Addr) int { return left.Compare(right) })
	slices.Sort(currentPorts)
	slices.Sort(targetPorts)
	return !slices.Equal(slices.Compact(currentAddresses), slices.Compact(targetAddresses)), !slices.Equal(slices.Compact(currentPorts), slices.Compact(targetPorts))
}

func firewallDifference(left, right ListenerSet) []FirewallTuple {
	rightValues := right.all()
	values := make([]FirewallTuple, 0, len(left.Panel)+len(left.SSH))
	for _, listener := range left.all() {
		if !slices.Contains(rightValues, listener) {
			values = append(values, FirewallTuple{Purpose: listener.Kind, Protocol: listener.Protocol, Address: listener.Address, Port: listener.Port})
		}
	}
	return values
}

func sortedListeners(values []Listener, kind ListenerKind) bool {
	for index, listener := range values {
		if listener.Validate() != nil || listener.Kind != kind || index > 0 && compareListener(values[index-1], listener) >= 0 {
			return false
		}
	}
	return true
}

func sortedRisks(values []RiskReason) bool {
	for index, value := range values {
		if !slices.Contains(stableRisks, value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func sortedHostnames(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for index, value := range values {
		if !validHostname(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func canonicalOrigin(value string) (string, string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		return "", "", ErrInvalid
	}
	_, addressErr := netip.ParseAddr(parsed.Hostname())
	if addressErr == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !validHostname(parsed.Hostname()) || strings.ToLower(parsed.Host) != parsed.Host || !validPort(parsed.Port()) {
		return "", "", ErrInvalid
	}
	return "https://" + parsed.Host, parsed.Hostname(), nil
}

func validHostname(value string) bool {
	if len(value) < 4 || len(value) > 253 || strings.ToLower(value) != value || strings.HasSuffix(value, ".") || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !alphaNumeric(label[0]) || !alphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := range label {
			if !alphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func validPort(value string) bool {
	if value == "" {
		return true
	}
	port, err := strconv.ParseUint(value, 10, 16)
	return err == nil && port > 0 && strconv.FormatUint(port, 10) == value
}

func validID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !alphaNumeric(value[0]) || !alphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := range value {
		if !alphaNumeric(value[index]) && value[index] != '-' && value[index] != '_' && value[index] != '.' && value[index] != ':' {
			return false
		}
	}
	return true
}

func validCode(value string) bool {
	if len(value) < 3 || len(value) > 96 {
		return false
	}
	for index := range value {
		if value[index] < 'a' || value[index] > 'z' {
			if value[index] < '0' || value[index] > '9' {
				if value[index] != '_' && value[index] != '-' {
					return false
				}
			}
		}
	}
	return true
}

func alphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for index := range value {
		if value[index] < '0' || value[index] > '9' && value[index] < 'a' || value[index] > 'f' {
			return false
		}
	return true
}

func validUTC(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func boolGeneration(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func digestValue(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("cyberpanel:listener-change:"+domain+":v1\x00"), encoded...))
	return hex.EncodeToString(sum[:]), nil
}
