package onboarding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/mail"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalid          = errors.New("invalid onboarding value")
	ErrUnauthorized     = errors.New("onboarding authorization denied")
	ErrStepUpRequired   = errors.New("recent onboarding step-up required")
	ErrNotFound         = errors.New("onboarding resource not found")
	ErrConflict         = errors.New("onboarding resource conflict")
	ErrStale            = errors.New("stale onboarding revision or observation")
	ErrUnsupported      = errors.New("unsupported onboarding capability or platform")
	ErrIncomplete       = errors.New("onboarding is incomplete")
	ErrIrreversible     = errors.New("onboarding irreversible frontier not authorized")
	ErrAuditUnavailable = errors.New("onboarding audit unavailable")
)

const (
	MaximumObservationAge = 5 * time.Minute
	MaximumStepUpAge      = 10 * time.Minute
	MaximumIntentLease    = 2 * time.Minute
)

type WizardID string
type TenantID string
type NodeID string
type PrincipalID string
type SecretRef string

type Scope struct {
	TenantID TenantID    `json:"tenant_id"`
	NodeID   NodeID      `json:"node_id"`
	OwnerID  PrincipalID `json:"owner_id"`
}

func (scope Scope) Validate() error {
	if !validID(string(scope.TenantID)) || !validID(string(scope.NodeID)) || !validID(string(scope.OwnerID)) {
		return ErrInvalid
	}
	return nil
}

type Actor struct {
	PrincipalID PrincipalID `json:"principal_id"`
	TenantID    TenantID    `json:"tenant_id"`
	SessionID   string      `json:"session_id"`
}

func (actor Actor) Validate() error {
	if !validID(string(actor.PrincipalID)) || !validID(string(actor.TenantID)) || !validID(actor.SessionID) {
		return ErrInvalid
	}
	return nil
}

type Step string

const (
	StepHostname           Step = "hostname"
	StepPublicAddresses    Step = "public_addresses"
	StepOwnerContact       Step = "owner_contact"
	StepTimezone           Step = "timezone"
	StepWebEngine          Step = "web_engine"
	StepServiceProfile     Step = "service_profile"
	StepAuthoritativeDNS   Step = "authoritative_dns"
	StepFirewallListeners  Step = "firewall_listeners"
	StepRecoveryEnrollment Step = "recovery_enrollment"
	StepFinalClaim         Step = "final_claim"
)

var configurationSteps = []Step{
	StepHostname, StepPublicAddresses, StepOwnerContact, StepTimezone,
	StepWebEngine, StepServiceProfile, StepAuthoritativeDNS,
	StepFirewallListeners, StepRecoveryEnrollment,
}

func (step Step) valid() bool {
	for _, candidate := range append(append([]Step(nil), configurationSteps...), StepFinalClaim) {
		if candidate == step {
			return true
		}
	}
	return false
}

func stepIndex(step Step) int {
	for index, candidate := range configurationSteps {
		if candidate == step {
			return index
		}
	}
	if step == StepFinalClaim {
		return len(configurationSteps)
	}
	return -1
}

type WizardState string

const (
	StateCollecting   WizardState = "collecting"
	StateReview       WizardState = "review"
	StateReady        WizardState = "ready"
	StateApplying     WizardState = "applying"
	StateCompensating WizardState = "compensating"
	StateCompensated  WizardState = "compensated"
	StateCompleted    WizardState = "completed"
)

func (state WizardState) valid() bool {
	switch state {
	case StateCollecting, StateReview, StateReady, StateApplying, StateCompensating, StateCompensated, StateCompleted:
		return true
	default:
		return false
	}
}

type Wizard struct {
	ID                    WizardID   `json:"id"`
	Scope                 Scope      `json:"scope"`
	State                 WizardState `json:"state"`
	Revision              uint64     `json:"revision"`
	PlanGeneration        uint64     `json:"plan_generation"`
	CurrentStep           Step       `json:"current_step"`
	IrreversibleStep      Step       `json:"irreversible_step"`
	IrreversibleCrossed   bool       `json:"irreversible_crossed"`
	IrreversibleCrossedAt time.Time  `json:"irreversible_crossed_at,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

func (wizard Wizard) Validate() error {
	if !validID(string(wizard.ID)) || wizard.Scope.Validate() != nil || !wizard.State.valid() || wizard.Revision == 0 || !wizard.CurrentStep.valid() || wizard.IrreversibleStep != StepFinalClaim || wizard.CreatedAt.Location() != time.UTC || wizard.UpdatedAt.Location() != time.UTC || wizard.UpdatedAt.Before(wizard.CreatedAt) {
		return ErrInvalid
	}
	if wizard.IrreversibleCrossed != !wizard.IrreversibleCrossedAt.IsZero() || !wizard.IrreversibleCrossedAt.IsZero() && (wizard.IrreversibleCrossedAt.Location() != time.UTC || wizard.IrreversibleCrossedAt.Before(wizard.CreatedAt) || wizard.IrreversibleCrossedAt.After(wizard.UpdatedAt)) {
		return ErrInvalid
	}
	if wizard.State == StateCollecting && wizard.PlanGeneration != 0 || wizard.State != StateCollecting && wizard.PlanGeneration == 0 || wizard.State != StateCollecting && wizard.CurrentStep != StepFinalClaim || wizard.State == StateCompleted && !wizard.IrreversibleCrossed || wizard.IrreversibleCrossed && wizard.State != StateApplying && wizard.State != StateCompleted {
		return ErrInvalid
	}
	return nil
}

type WebEngine string

const (
	EngineOpenLiteSpeed       WebEngine = "openlitespeed"
	EngineLiteSpeedEnterprise WebEngine = "litespeed_enterprise"
)

type ServiceProfile string

const (
	ProfileWeb    ServiceProfile = "web"
	ProfileWebDNS ServiceProfile = "web_dns"
	ProfileFull   ServiceProfile = "full"
)

type Listener string

const (
	ListenerSSH        Listener = "ssh"
	ListenerHTTP       Listener = "http"
	ListenerHTTPS      Listener = "https"
	ListenerDNSTCP     Listener = "dns_tcp"
	ListenerDNSUDP     Listener = "dns_udp"
	ListenerSMTP       Listener = "smtp"
	ListenerSubmission Listener = "submission"
	ListenerIMAPTLS    Listener = "imap_tls"
)

func (listener Listener) valid() bool {
	switch listener {
	case ListenerSSH, ListenerHTTP, ListenerHTTPS, ListenerDNSTCP, ListenerDNSUDP, ListenerSMTP, ListenerSubmission, ListenerIMAPTLS:
		return true
	default:
		return false
	}
}

type HostnameAnswer struct {
	Hostname string `json:"hostname"`
}

type PublicAddressesAnswer struct {
	Addresses []netip.Addr `json:"addresses"`
}

type OwnerContactAnswer struct {
	DisplayName           string    `json:"display_name"`
	Email                 string    `json:"email"`
	PasswordCredentialRef SecretRef `json:"password_credential_ref"`
}

type TimezoneAnswer struct {
	Timezone string `json:"timezone"`
}

type WebEngineAnswer struct {
	Engine WebEngine `json:"engine"`
}

type ServiceProfileAnswer struct {
	Profile ServiceProfile `json:"profile"`
}

type AuthoritativeDNSAnswer struct {
	Enabled     bool     `json:"enabled"`
	Nameservers []string `json:"nameservers"`
}

type FirewallListenersAnswer struct {
	Listeners   []Listener     `json:"listeners"`
	AdminSources []netip.Prefix `json:"admin_sources"`
}

type RecoveryEnrollmentAnswer struct {
	AuthorityCredentialRef SecretRef `json:"authority_credential_ref"`
	RecoveryContact        string    `json:"recovery_contact"`
	Confirmed              bool      `json:"confirmed"`
}

type FinalClaimAnswer struct {
	PlanGeneration      uint64        `json:"plan_generation"`
	PlanDigest          string        `json:"plan_digest"`
	AcknowledgedWarnings []WarningCode `json:"acknowledged_warnings"`
	AcceptIrreversible  bool          `json:"accept_irreversible"`
}

type StepAnswer struct {
	Hostname           *HostnameAnswer           `json:"hostname,omitempty"`
	PublicAddresses    *PublicAddressesAnswer    `json:"public_addresses,omitempty"`
	OwnerContact       *OwnerContactAnswer       `json:"owner_contact,omitempty"`
	Timezone           *TimezoneAnswer           `json:"timezone,omitempty"`
	WebEngine          *WebEngineAnswer          `json:"web_engine,omitempty"`
	ServiceProfile     *ServiceProfileAnswer     `json:"service_profile,omitempty"`
	AuthoritativeDNS   *AuthoritativeDNSAnswer   `json:"authoritative_dns,omitempty"`
	FirewallListeners  *FirewallListenersAnswer  `json:"firewall_listeners,omitempty"`
	RecoveryEnrollment *RecoveryEnrollmentAnswer `json:"recovery_enrollment,omitempty"`
	FinalClaim         *FinalClaimAnswer          `json:"final_claim,omitempty"`
}

func (answer StepAnswer) Step() (Step, error) {
	values := []struct {
		step Step
		set  bool
	}{
		{StepHostname, answer.Hostname != nil}, {StepPublicAddresses, answer.PublicAddresses != nil},
		{StepOwnerContact, answer.OwnerContact != nil}, {StepTimezone, answer.Timezone != nil},
		{StepWebEngine, answer.WebEngine != nil}, {StepServiceProfile, answer.ServiceProfile != nil},
		{StepAuthoritativeDNS, answer.AuthoritativeDNS != nil}, {StepFirewallListeners, answer.FirewallListeners != nil},
		{StepRecoveryEnrollment, answer.RecoveryEnrollment != nil}, {StepFinalClaim, answer.FinalClaim != nil},
	}
	selected := Step("")
	for _, value := range values {
		if value.set {
			if selected != "" {
				return "", ErrInvalid
			}
			selected = value.step
		}
	}
	if selected == "" {
		return "", ErrInvalid
	}
	return selected, nil
}

func (answer StepAnswer) Validate() error {
	step, err := answer.Step()
	if err != nil {
		return err
	}
	switch step {
	case StepHostname:
		if !validHostname(answer.Hostname.Hostname) {
			return ErrInvalid
		}
	case StepPublicAddresses:
		if len(answer.PublicAddresses.Addresses) == 0 || len(answer.PublicAddresses.Addresses) > 16 || !sortedAddresses(answer.PublicAddresses.Addresses) {
			return ErrInvalid
		}
		for _, address := range answer.PublicAddresses.Addresses {
			if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.Zone() != "" {
				return ErrInvalid
			}
		}
	case StepOwnerContact:
		if !validHumanName(answer.OwnerContact.DisplayName) || !validEmail(answer.OwnerContact.Email) || !validSecretRef(answer.OwnerContact.PasswordCredentialRef) {
			return ErrInvalid
		}
	case StepTimezone:
		if answer.Timezone.Timezone == "" || answer.Timezone.Timezone == "Local" || strings.TrimSpace(answer.Timezone.Timezone) != answer.Timezone.Timezone {
			return ErrInvalid
		}
		if _, err = time.LoadLocation(answer.Timezone.Timezone); err != nil {
			return ErrInvalid
		}
	case StepWebEngine:
		if answer.WebEngine.Engine != EngineOpenLiteSpeed && answer.WebEngine.Engine != EngineLiteSpeedEnterprise {
			return ErrInvalid
		}
	case StepServiceProfile:
		if answer.ServiceProfile.Profile != ProfileWeb && answer.ServiceProfile.Profile != ProfileWebDNS && answer.ServiceProfile.Profile != ProfileFull {
			return ErrInvalid
		}
	case StepAuthoritativeDNS:
		if !answer.AuthoritativeDNS.Enabled && len(answer.AuthoritativeDNS.Nameservers) != 0 || answer.AuthoritativeDNS.Enabled && (len(answer.AuthoritativeDNS.Nameservers) < 2 || len(answer.AuthoritativeDNS.Nameservers) > 8 || !sortedStrings(answer.AuthoritativeDNS.Nameservers)) {
			return ErrInvalid
		}
		for _, nameserver := range answer.AuthoritativeDNS.Nameservers {
			if !validHostname(nameserver) {
				return ErrInvalid
			}
		}
	case StepFirewallListeners:
		if len(answer.FirewallListeners.Listeners) == 0 || len(answer.FirewallListeners.Listeners) > 8 || !sortedListeners(answer.FirewallListeners.Listeners) || len(answer.FirewallListeners.AdminSources) > 32 || !sortedPrefixes(answer.FirewallListeners.AdminSources) {
			return ErrInvalid
		}
		seenSSH := false
		for _, listener := range answer.FirewallListeners.Listeners {
			if !listener.valid() {
				return ErrInvalid
			}
			seenSSH = seenSSH || listener == ListenerSSH
		}
		if !seenSSH {
			return ErrInvalid
		}
		for _, prefix := range answer.FirewallListeners.AdminSources {
			if !prefix.IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Bits() == 0 {
				return ErrInvalid
			}
		}
	case StepRecoveryEnrollment:
		if !validSecretRef(answer.RecoveryEnrollment.AuthorityCredentialRef) || !validEmail(answer.RecoveryEnrollment.RecoveryContact) || !answer.RecoveryEnrollment.Confirmed {
			return ErrInvalid
		}
	case StepFinalClaim:
		if answer.FinalClaim.PlanGeneration == 0 || !validDigest(answer.FinalClaim.PlanDigest) || !answer.FinalClaim.AcceptIrreversible || !sortedWarnings(answer.FinalClaim.AcknowledgedWarnings) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type AnswerRecord struct {
	WizardID WizardID    `json:"wizard_id"`
	Step     Step        `json:"step"`
	Revision uint64      `json:"revision"`
	Answer   StepAnswer  `json:"answer"`
	Digest   string      `json:"digest"`
	ActorID  PrincipalID `json:"actor_id"`
	CreatedAt time.Time  `json:"created_at"`
}

func NewAnswerRecord(wizardID WizardID, revision uint64, answer StepAnswer, actor PrincipalID, at time.Time) (AnswerRecord, error) {
	step, err := answer.Step()
	if !validID(string(wizardID)) || revision == 0 || err != nil || answer.Validate() != nil || !validID(string(actor)) || at.Location() != time.UTC {
		return AnswerRecord{}, ErrInvalid
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		return AnswerRecord{}, err
	}
	sum := sha256.Sum256(append([]byte("cyberpanel:onboarding:answer:v1\x00"), encoded...))
	return AnswerRecord{WizardID: wizardID, Step: step, Revision: revision, Answer: answer, Digest: hex.EncodeToString(sum[:]), ActorID: actor, CreatedAt: at}, nil
}

func (record AnswerRecord) Validate() error {
	step, err := record.Answer.Step()
	if !validID(string(record.WizardID)) || record.Revision == 0 || err != nil || step != record.Step || record.Answer.Validate() != nil || !validDigest(record.Digest) || !validID(string(record.ActorID)) || record.CreatedAt.Location() != time.UTC {
		return ErrInvalid
	}
	encoded, err := json.Marshal(record.Answer)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(append([]byte("cyberpanel:onboarding:answer:v1\x00"), encoded...))
	if record.Digest != hex.EncodeToString(sum[:]) {
		return ErrInvalid
	}
	return nil
}

type Distribution string
type Architecture string

const (
	DistributionUbuntu Distribution = "ubuntu"
	DistributionAlma   Distribution = "almalinux"
	ArchitectureAMD64  Architecture = "amd64"
	ArchitectureARM64  Architecture = "arm64"
)

type PlatformTuple struct {
	Distribution Distribution `json:"distribution"`
	Release      string       `json:"release"`
	Architecture Architecture `json:"architecture"`
}

func (tuple PlatformTuple) Validate() error {
	architectureOK := tuple.Architecture == ArchitectureAMD64 || tuple.Architecture == ArchitectureARM64
	ubuntuOK := tuple.Distribution == DistributionUbuntu && (tuple.Release == "22.04" || tuple.Release == "24.04")
	almaOK := tuple.Distribution == DistributionAlma && tuple.Release == "9"
	if !architectureOK || !ubuntuOK && !almaOK {
		return ErrUnsupported
	}
	return nil
}

type Capabilities struct {
	OpenLiteSpeed       bool `json:"openlitespeed"`
	LiteSpeedEnterprise bool `json:"litespeed_enterprise"`
	Database            bool `json:"database"`
	AuthoritativeDNS    bool `json:"authoritative_dns"`
	Mail                bool `json:"mail"`
	Firewall            bool `json:"firewall"`
	IPv6                bool `json:"ipv6"`
	RecoveryAuthority   bool `json:"recovery_authority"`
	NodeClaim           bool `json:"node_claim"`
}

type PrerequisiteObservation struct {
	NodeID       NodeID       `json:"node_id"`
	Generation   uint64       `json:"generation"`
	Tuple        PlatformTuple `json:"tuple"`
	Capabilities Capabilities `json:"capabilities"`
	ObservedAt   time.Time    `json:"observed_at"`
	ValidUntil   time.Time    `json:"valid_until"`
	Digest       string       `json:"digest"`
}

func (observation PrerequisiteObservation) Validate(nodeID NodeID, now time.Time) error {
	if observation.Tuple.Validate() != nil {
		return ErrUnsupported
	}
	capabilities := observation.Capabilities
	if !capabilities.OpenLiteSpeed && !capabilities.LiteSpeedEnterprise || !capabilities.Database || !capabilities.Firewall || !capabilities.RecoveryAuthority || !capabilities.NodeClaim {
		return ErrUnsupported
	}
	if now.IsZero() || now.Location() != time.UTC || observation.NodeID != nodeID || observation.Generation == 0 || observation.ObservedAt.Location() != time.UTC || observation.ValidUntil.Location() != time.UTC || observation.ObservedAt.After(now) || now.Sub(observation.ObservedAt) > MaximumObservationAge || !observation.ValidUntil.After(now) || observation.ValidUntil.After(observation.ObservedAt.Add(MaximumObservationAge)) || !validDigest(observation.Digest) {
		return ErrStale
	}
	expected, err := observation.ExpectedDigest()
	if err != nil || observation.Digest != expected {
		return ErrStale
	}
	return nil
}

func (observation PrerequisiteObservation) ExpectedDigest() (string, error) {
	type unsigned struct {
		NodeID NodeID `json:"node_id"`; Generation uint64 `json:"generation"`; Tuple PlatformTuple `json:"tuple"`; Capabilities Capabilities `json:"capabilities"`
	}
	encoded, err := json.Marshal(unsigned{observation.NodeID, observation.Generation, observation.Tuple, observation.Capabilities})
	if err != nil {
		return "", err
	}
	return domainDigest("prerequisites", encoded), nil
}

func validateAnswerCapability(answer StepAnswer, observation PrerequisiteObservation) error {
	step, err := answer.Step()
	if err != nil || answer.Validate() != nil {
		return ErrInvalid
	}
	capabilities := observation.Capabilities
	switch step {
	case StepPublicAddresses:
		for _, address := range answer.PublicAddresses.Addresses {
			if address.Is6() && !capabilities.IPv6 {
				return ErrUnsupported
			}
		}
	case StepWebEngine:
		if answer.WebEngine.Engine == EngineOpenLiteSpeed && !capabilities.OpenLiteSpeed || answer.WebEngine.Engine == EngineLiteSpeedEnterprise && !capabilities.LiteSpeedEnterprise {
			return ErrUnsupported
		}
	case StepServiceProfile:
		if !capabilities.Database || answer.ServiceProfile.Profile != ProfileWeb && (!capabilities.AuthoritativeDNS || answer.ServiceProfile.Profile == ProfileFull && !capabilities.Mail) {
			return ErrUnsupported
		}
	case StepAuthoritativeDNS:
		if answer.AuthoritativeDNS.Enabled && !capabilities.AuthoritativeDNS {
			return ErrUnsupported
		}
	case StepFirewallListeners:
		if !capabilities.Firewall {
			return ErrUnsupported
		}
	case StepRecoveryEnrollment:
		if !capabilities.RecoveryAuthority {
			return ErrUnsupported
		}
	case StepFinalClaim:
		if !capabilities.NodeClaim {
			return ErrUnsupported
		}
	}
	return nil
}

func validID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !alphaNumeric(value[0]) || !alphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := range value {
		if alphaNumeric(value[index]) || value[index] == '-' || value[index] == '_' || value[index] == '.' || value[index] == ':' {
			continue
		}
		return false
	}
	return true
}

func validSecretRef(reference SecretRef) bool {
	value := string(reference)
	return validID(value) && !strings.Contains(value, "..") && !strings.ContainsAny(value, "/\\")
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for index := range value {
		if value[index] < '0' || value[index] > '9' && value[index] < 'a' || value[index] > 'f' {
			return false
		}
	}
	return true
}

func alphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
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

func validHumanName(value string) bool {
	if len(value) < 2 || len(value) > 128 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validEmail(value string) bool {
	parsed, err := mail.ParseAddress(value)
	separator := strings.LastIndexByte(value, '@')
	return err == nil && separator > 0 && separator < len(value)-1 && parsed.Name == "" && parsed.Address == value && len(value) <= 254 && strings.ToLower(value[separator+1:]) == value[separator+1:]
}

func sortedAddresses(values []netip.Addr) bool {
	for index, value := range values {
		if index > 0 && values[index-1].Compare(value) >= 0 {
			return false
		}
	}
	return true
}

func sortedPrefixes(values []netip.Prefix) bool {
	for index, value := range values {
		if value != value.Masked() || index > 0 && (values[index-1].Addr().Compare(value.Addr()) > 0 || values[index-1].Addr() == value.Addr() && values[index-1].Bits() >= value.Bits()) {
			return false
		}
	}
	return true
}

func sortedStrings(values []string) bool {
	return sort.StringsAreSorted(values) && uniqueStrings(values)
}

func sortedListeners(values []Listener) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] >= values[index] {
			return false
		}
	}
	return true
}

func uniqueStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return false
		}
	}
	return true
}
