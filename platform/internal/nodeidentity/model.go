package nodeidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/mail"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalid          = errors.New("invalid node identity value")
	ErrUnauthorized     = errors.New("node identity authorization denied")
	ErrStepUpRequired   = errors.New("recent node identity step-up required")
	ErrNotFound         = errors.New("node identity resource not found")
	ErrConflict         = errors.New("node identity conflict")
	ErrStale            = errors.New("stale node identity generation or evidence")
	ErrUnsupported      = errors.New("unsupported node identity change")
	ErrIncomplete       = errors.New("node identity operation incomplete")
	ErrAuditUnavailable = errors.New("node identity audit unavailable")
)

const (
	MaximumEvidenceAge = 5 * time.Minute
	MaximumStepUpAge   = 10 * time.Minute
	MaximumLease       = 2 * time.Minute
	HistoryLimit       = 64
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

type AdministrativeContact struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (contact AdministrativeContact) Validate() error {
	if !validText(contact.Name, 2, 128) || !validEmail(contact.Email) {
		return ErrInvalid
	}
	return nil
}

// IdentitySpec intentionally contains no credential or credential reference.
type IdentitySpec struct {
	Hostname              string                `json:"hostname"`
	FQDN                  string                `json:"fqdn"`
	DeclaredAddresses     []netip.Addr          `json:"declared_addresses"`
	Timezone              string                `json:"timezone"`
	AdministrativeContact AdministrativeContact `json:"administrative_contact"`
	PanelURL              string                `json:"panel_url"`
	PanelOrigin           string                `json:"panel_origin"`
}

func (spec IdentitySpec) Validate() error {
	if !validHostLabel(spec.Hostname) || !validFQDN(spec.FQDN) || strings.Split(spec.FQDN, ".")[0] != spec.Hostname || !validPublicAddresses(spec.DeclaredAddresses) || !validTimezone(spec.Timezone) || spec.AdministrativeContact.Validate() != nil {
		return ErrInvalid
	}
	origin, normalizedURL, err := validatePanelURL(spec.PanelURL, spec.FQDN)
	if err != nil || spec.PanelOrigin != origin || spec.PanelURL != normalizedURL {
		return ErrInvalid
	}
	return nil
}

func (spec IdentitySpec) Digest() (string, error) {
	if spec.Validate() != nil {
		return "", ErrInvalid
	}
	return digestValue("identity-spec", spec)
}

type DesiredIdentity struct {
	Scope      Scope        `json:"scope"`
	Revision   uint64       `json:"revision"`
	Generation uint64       `json:"generation"`
	Spec       IdentitySpec `json:"spec"`
	SpecDigest string       `json:"spec_digest"`
	UpdatedBy  PrincipalID  `json:"updated_by"`
	UpdatedAt  time.Time    `json:"updated_at"`
	Digest     string       `json:"digest"`
}

func NewDesiredIdentity(scope Scope, revision, generation uint64, spec IdentitySpec, actor PrincipalID, at time.Time) (DesiredIdentity, error) {
	specDigest, err := spec.Digest()
	if scope.Validate() != nil || revision == 0 || generation == 0 || err != nil || !validID(string(actor)) || !validUTC(at) {
		return DesiredIdentity{}, ErrInvalid
	}
	desired := DesiredIdentity{Scope: scope, Revision: revision, Generation: generation, Spec: spec, SpecDigest: specDigest, UpdatedBy: actor, UpdatedAt: at}
	desired.Digest, err = desired.expectedDigest()
	if err != nil {
		return DesiredIdentity{}, err
	}
	return desired, nil
}

func (desired DesiredIdentity) Validate() error {
	if desired.Scope.Validate() != nil || desired.Revision == 0 || desired.Generation == 0 || desired.Spec.Validate() != nil || !validDigest(desired.SpecDigest) || !validID(string(desired.UpdatedBy)) || !validUTC(desired.UpdatedAt) || !validDigest(desired.Digest) {
		return ErrInvalid
	}
	specDigest, err := desired.Spec.Digest()
	if err != nil || specDigest != desired.SpecDigest {
		return ErrInvalid
	}
	expected, err := desired.expectedDigest()
	if err != nil || expected != desired.Digest {
		return ErrInvalid
	}
	return nil
}

func (desired DesiredIdentity) expectedDigest() (string, error) {
	copy := desired
	copy.Digest = ""
	return digestValue("desired", copy)
}

type ObservationStatus string

const (
	StatusMatch     ObservationStatus = "match"
	StatusMismatch  ObservationStatus = "mismatch"
	StatusUnknown   ObservationStatus = "unknown"
	StatusAmbiguous ObservationStatus = "ambiguous"
)

func (status ObservationStatus) valid() bool {
	return status == StatusMatch || status == StatusMismatch || status == StatusUnknown || status == StatusAmbiguous
}

type ListenerProtocol string

const (
	ProtocolTCP ListenerProtocol = "tcp"
	ProtocolUDP ListenerProtocol = "udp"
)

type ListenerObservation struct {
	Protocol  ListenerProtocol `json:"protocol"`
	Address   netip.Addr       `json:"address"`
	Port      uint16           `json:"port"`
	Status    ObservationStatus `json:"status"`
	ObservedAt time.Time       `json:"observed_at"`
}

func (listener ListenerObservation) Validate() error {
	if listener.Protocol != ProtocolTCP && listener.Protocol != ProtocolUDP || !listener.Address.IsValid() || listener.Address.Is4In6() || listener.Port == 0 || !listener.Status.valid() || !validUTC(listener.ObservedAt) {
		return ErrInvalid
	}
	return nil
}

type CertificateObservation struct {
	Status      ObservationStatus `json:"status"`
	Origin      string            `json:"origin,omitempty"`
	DNSNames    []string          `json:"dns_names,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	NotBefore   time.Time         `json:"not_before,omitempty"`
	NotAfter    time.Time         `json:"not_after,omitempty"`
	ObservedAt  time.Time         `json:"observed_at"`
}

func (certificate CertificateObservation) Validate() error {
	if !certificate.Status.valid() || !validUTC(certificate.ObservedAt) {
		return ErrInvalid
	}
	if certificate.Status == StatusUnknown || certificate.Status == StatusAmbiguous {
		if certificate.Origin != "" || len(certificate.DNSNames) != 0 || certificate.Fingerprint != "" || !certificate.NotBefore.IsZero() || !certificate.NotAfter.IsZero() {
			return ErrInvalid
		}
		return nil
	}
	parsedOrigin, err := url.Parse(certificate.Origin)
	if err != nil || parsedOrigin.Scheme != "https" || parsedOrigin.Host == "" || parsedOrigin.User != nil || parsedOrigin.Path != "" || parsedOrigin.RawQuery != "" || parsedOrigin.Fragment != "" || !validFQDN(parsedOrigin.Hostname()) || !validPort(parsedOrigin.Port()) || !sortedFQDNs(certificate.DNSNames) || !validDigest(certificate.Fingerprint) || !validUTC(certificate.NotBefore) || !validUTC(certificate.NotAfter) || !certificate.NotAfter.After(certificate.NotBefore) {
		return ErrInvalid
	}
	return nil
}

type MailObservation struct {
	Configured bool              `json:"configured"`
	Hostname   string            `json:"hostname,omitempty"`
	Status     ObservationStatus `json:"status"`
	Generation uint64            `json:"generation"`
	ObservedAt time.Time         `json:"observed_at"`
}

func (mailState MailObservation) Validate() error {
	if !mailState.Status.valid() || !validUTC(mailState.ObservedAt) || mailState.Generation == 0 || mailState.Configured != (mailState.Hostname != "") || mailState.Configured && !validFQDN(mailState.Hostname) {
		return ErrInvalid
	}
	return nil
}

type ObservedValues struct {
	Hostname              string                 `json:"hostname,omitempty"`
	FQDN                  string                 `json:"fqdn,omitempty"`
	PublicAddresses       []netip.Addr           `json:"public_addresses"`
	Timezone              string                 `json:"timezone,omitempty"`
	AdministrativeContact *AdministrativeContact `json:"administrative_contact,omitempty"`
	PanelOrigin           string                 `json:"panel_origin,omitempty"`
}

func (values ObservedValues) Validate() error {
	if !safeObservedText(values.Hostname, 63) || !safeObservedText(values.FQDN, 253) || !safeObservedText(values.Timezone, 128) || !safeObservedText(values.PanelOrigin, 512) || !validPublicAddresses(values.PublicAddresses) {
		return ErrInvalid
	}
	if values.AdministrativeContact != nil && values.AdministrativeContact.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type DriftDimension string

const (
	DriftHostname    DriftDimension = "hostname"
	DriftFQDN        DriftDimension = "fqdn"
	DriftAddresses   DriftDimension = "public_addresses"
	DriftTimezone    DriftDimension = "timezone"
	DriftContact     DriftDimension = "administrative_contact"
	DriftPanelOrigin DriftDimension = "panel_origin"
	DriftCertificate DriftDimension = "certificate"
	DriftListeners   DriftDimension = "listeners"
	DriftDNS         DriftDimension = "dns"
	DriftMail        DriftDimension = "mail"
)

var driftDimensions = []DriftDimension{
	DriftHostname, DriftFQDN, DriftAddresses, DriftTimezone, DriftContact,
	DriftPanelOrigin, DriftCertificate, DriftListeners, DriftDNS, DriftMail,
}

type Drift struct {
	Dimension DriftDimension    `json:"dimension"`
	Status    ObservationStatus `json:"status"`
	Expected  string            `json:"expected_digest"`
	Observed  string            `json:"observed_digest,omitempty"`
}

func (drift Drift) Validate() error {
	if !slices.Contains(driftDimensions, drift.Dimension) || !drift.Status.valid() || !validDigest(drift.Expected) || drift.Status == StatusUnknown && drift.Observed != "" || drift.Status != StatusUnknown && !validDigest(drift.Observed) {
		return ErrInvalid
	}
	return nil
}

type DNSAddressEvidence struct {
	Scope         Scope        `json:"scope"`
	Generation    uint64       `json:"generation"`
	FQDN          string       `json:"fqdn"`
	IPv4          []netip.Addr `json:"ipv4"`
	IPv6          []netip.Addr `json:"ipv6"`
	Authoritative bool         `json:"authoritative"`
	ObservedAt    time.Time    `json:"observed_at"`
	ValidUntil    time.Time    `json:"valid_until"`
	Digest        string       `json:"digest"`
}

func (evidence DNSAddressEvidence) Validate(spec IdentitySpec, now time.Time) error {
	if spec.Validate() != nil || evidence.validateShape(now) != nil || evidence.FQDN != spec.FQDN || !evidence.Authoritative {
		return ErrStale
	}
	addresses := append(append([]netip.Addr(nil), evidence.IPv4...), evidence.IPv6...)
	slices.SortFunc(addresses, func(left, right netip.Addr) int { return left.Compare(right) })
	if !slices.Equal(addresses, spec.DeclaredAddresses) {
		return ErrStale
	}
	expected, err := evidence.expectedDigest()
	if err != nil || expected != evidence.Digest {
		return ErrStale
	}
	return nil
}

func (evidence DNSAddressEvidence) expectedDigest() (string, error) {
	copy := evidence
	copy.ObservedAt, copy.ValidUntil, copy.Digest = time.Time{}, time.Time{}, ""
	return digestValue("dns-evidence", copy)
}

func (evidence DNSAddressEvidence) ExpectedDigest() (string, error) {
	return evidence.expectedDigest()
}

func (evidence DNSAddressEvidence) validateShape(now time.Time) error {
	if evidence.Scope.Validate() != nil || evidence.Generation == 0 || !validFQDN(evidence.FQDN) || !validUTC(now) || !validUTC(evidence.ObservedAt) || !validUTC(evidence.ValidUntil) || evidence.ObservedAt.After(now) || now.Sub(evidence.ObservedAt) > MaximumEvidenceAge || !evidence.ValidUntil.After(now) || evidence.ValidUntil.After(evidence.ObservedAt.Add(MaximumEvidenceAge)) || !validPublicFamilies(evidence.IPv4, evidence.IPv6) || !validDigest(evidence.Digest) {
		return ErrStale
	}
	expected, err := evidence.expectedDigest()
	if err != nil || expected != evidence.Digest {
		return ErrStale
	}
	return nil
}

type ObservedIdentity struct {
	Scope             Scope                    `json:"scope"`
	Revision          uint64                   `json:"revision"`
	AppliedGeneration uint64                   `json:"applied_generation"`
	Values            ObservedValues           `json:"values"`
	Certificate       CertificateObservation   `json:"certificate"`
	Listeners         []ListenerObservation    `json:"listeners"`
	DNS               DNSAddressEvidence       `json:"dns"`
	Mail              MailObservation          `json:"mail"`
	Drift             []Drift                  `json:"drift"`
	ObservedAt        time.Time                `json:"observed_at"`
	ValidUntil        time.Time                `json:"valid_until"`
	Digest            string                   `json:"digest"`
}

func NewObservedIdentity(scope Scope, revision, appliedGeneration uint64, desired IdentitySpec, values ObservedValues, certificate CertificateObservation, listeners []ListenerObservation, dns DNSAddressEvidence, mailState MailObservation, observedAt, validUntil time.Time) (ObservedIdentity, error) {
	observed := ObservedIdentity{Scope: scope, Revision: revision, AppliedGeneration: appliedGeneration, Values: values, Certificate: certificate, Listeners: append([]ListenerObservation(nil), listeners...), DNS: dns, Mail: mailState, ObservedAt: observedAt, ValidUntil: validUntil}
	observed.Drift = calculateDrift(desired, observed)
	digest, err := observed.expectedDigest()
	if err != nil {
		return ObservedIdentity{}, err
	}
	observed.Digest = digest
	if observed.Validate(desired, observedAt) != nil {
		return ObservedIdentity{}, ErrInvalid
	}
	return observed, nil
}

func (observed ObservedIdentity) Validate(desired IdentitySpec, now time.Time) error {
	if desired.Validate() != nil || observed.Scope.Validate() != nil || observed.Revision == 0 || observed.AppliedGeneration == 0 || observed.Values.Validate() != nil || observed.Certificate.Validate() != nil || observed.Mail.Validate() != nil || observed.DNS.validateShape(now) != nil || observed.DNS.Scope != observed.Scope || !validUTC(now) || !validUTC(observed.ObservedAt) || !validUTC(observed.ValidUntil) || observed.ObservedAt.After(now) || now.Sub(observed.ObservedAt) > MaximumEvidenceAge || !observed.ValidUntil.After(now) || observed.ValidUntil.After(observed.ObservedAt.Add(MaximumEvidenceAge)) || observed.Certificate.ObservedAt.After(observed.ObservedAt) || observed.Mail.ObservedAt.After(observed.ObservedAt) || observed.DNS.ObservedAt.After(observed.ObservedAt) || !sortedListeners(observed.Listeners) || len(observed.Drift) != len(driftDimensions) || !validDigest(observed.Digest) {
		return ErrStale
	}
	for index, listener := range observed.Listeners {
		if listener.Validate() != nil || listener.ObservedAt.After(observed.ObservedAt) || index > 0 && compareListener(observed.Listeners[index-1], listener) >= 0 {
			return ErrInvalid
		}
	}
	expectedDrift := calculateDrift(desired, observed)
	for index, drift := range observed.Drift {
		if drift.Validate() != nil || drift.Dimension != driftDimensions[index] || drift != expectedDrift[index] {
			return ErrInvalid
		}
	}
	expected, err := observed.expectedDigest()
	if err != nil || expected != observed.Digest {
		return ErrStale
	}
	return nil
}

func (observed ObservedIdentity) expectedDigest() (string, error) {
	copy := observed
	copy.ObservedAt, copy.ValidUntil, copy.Digest = time.Time{}, time.Time{}, ""
	return digestValue("observed", copy)
}

func (observed ObservedIdentity) CoreMatches(desired IdentitySpec) bool {
	if desired.Validate() != nil {
		return false
	}
	computed := calculateDrift(desired, observed)
	for _, drift := range computed[:6] {
		if drift.Status != StatusMatch {
			return false
		}
	}
	return true
}

func (observed ObservedIdentity) AllMatched() bool {
	if len(observed.Drift) != len(driftDimensions) {
		return false
	}
	for _, drift := range observed.Drift {
		if drift.Status != StatusMatch {
			return false
		}
	}
	return true
}

func calculateDrift(desired IdentitySpec, observed ObservedIdentity) []Drift {
	values := observed.Values
	comparisons := []struct {
		dimension DriftDimension
		expected  any
		actual    any
		known     bool
		status    ObservationStatus
	}{
		{DriftHostname, desired.Hostname, values.Hostname, values.Hostname != "", ""},
		{DriftFQDN, desired.FQDN, values.FQDN, values.FQDN != "", ""},
		{DriftAddresses, desired.DeclaredAddresses, values.PublicAddresses, true, ""},
		{DriftTimezone, desired.Timezone, values.Timezone, values.Timezone != "", ""},
		{DriftContact, desired.AdministrativeContact, values.AdministrativeContact, values.AdministrativeContact != nil, ""},
		{DriftPanelOrigin, desired.PanelOrigin, values.PanelOrigin, values.PanelOrigin != "", ""},
		{DriftCertificate, desired.PanelOrigin, observed.Certificate.Origin, observed.Certificate.Status != StatusUnknown, certificateStatus(desired, observed.Certificate)},
		{DriftListeners, struct{ Port uint16; Addresses []netip.Addr }{panelPort(desired.PanelOrigin), desired.DeclaredAddresses}, observed.Listeners, len(observed.Listeners) != 0, panelListenerStatus(desired, observed.Listeners)},
		{DriftDNS, desired.DeclaredAddresses, append(append([]netip.Addr(nil), observed.DNS.IPv4...), observed.DNS.IPv6...), observed.DNS.Generation != 0, dnsStatus(desired, observed.DNS)},
		{DriftMail, desired.FQDN, observed.Mail.Hostname, !observed.Mail.Configured || observed.Mail.Hostname != "", mailStatus(desired, observed.Mail)},
	}
	drifts := make([]Drift, 0, len(comparisons))
	for _, comparison := range comparisons {
		expected, _ := digestValue("drift-expected", comparison.expected)
		status := comparison.status
		observedDigest := ""
		if !comparison.known {
			status = StatusUnknown
		} else {
			observedDigest, _ = digestValue("drift-observed", comparison.actual)
			if status == "" {
				status = StatusMismatch
				expectedActual, _ := json.Marshal(comparison.expected)
				actual, _ := json.Marshal(comparison.actual)
				if string(expectedActual) == string(actual) {
					status = StatusMatch
				}
			}
		}
		drifts = append(drifts, Drift{Dimension: comparison.dimension, Status: status, Expected: expected, Observed: observedDigest})
	}
	return drifts
}

func certificateStatus(desired IdentitySpec, certificate CertificateObservation) ObservationStatus {
	if certificate.Status == StatusUnknown || certificate.Status == StatusAmbiguous {
		return certificate.Status
	}
	if certificate.Status != StatusMatch || certificate.Origin != desired.PanelOrigin || !slices.Contains(certificate.DNSNames, desired.FQDN) || certificate.NotBefore.After(certificate.ObservedAt) || !certificate.NotAfter.After(certificate.ObservedAt) {
		return StatusMismatch
	}
	return StatusMatch
}

func panelListenerStatus(desired IdentitySpec, listeners []ListenerObservation) ObservationStatus {
	matched := make(map[netip.Addr]bool, len(desired.DeclaredAddresses))
	for _, listener := range listeners {
		if listener.Status == StatusAmbiguous {
			return StatusAmbiguous
		}
		if listener.Protocol == ProtocolTCP && listener.Port == panelPort(desired.PanelOrigin) && listener.Status == StatusMatch && slices.Contains(desired.DeclaredAddresses, listener.Address) {
			matched[listener.Address] = true
		}
	}
	if len(matched) == len(desired.DeclaredAddresses) {
		return StatusMatch
	}
	return StatusMismatch
}

func dnsStatus(desired IdentitySpec, evidence DNSAddressEvidence) ObservationStatus {
	if evidence.Generation == 0 {
		return StatusUnknown
	}
	addresses := append(append([]netip.Addr(nil), evidence.IPv4...), evidence.IPv6...)
	slices.SortFunc(addresses, func(left, right netip.Addr) int { return left.Compare(right) })
	if evidence.FQDN == desired.FQDN && evidence.Authoritative && slices.Equal(addresses, desired.DeclaredAddresses) {
		return StatusMatch
	}
	return StatusMismatch
}

func mailStatus(desired IdentitySpec, observed MailObservation) ObservationStatus {
	if !observed.Configured {
		return StatusMatch
	}
	if observed.Status == StatusAmbiguous || observed.Status == StatusUnknown {
		return observed.Status
	}
	if observed.Hostname == desired.FQDN && observed.Status == StatusMatch {
		return StatusMatch
	}
	return StatusMismatch
}

func validPanelOrigin(origin, fqdn string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != fqdn || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" {
		return false
	}
	return validPort(parsed.Port())
}

func validatePanelURL(value, fqdn string) (string, string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != fqdn || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path != "" && parsed.Path != "/" || strings.ToLower(parsed.Host) != parsed.Host || !validPort(parsed.Port()) {
		return "", "", ErrInvalid
	}
	origin := "https://" + parsed.Host
	normalized := origin
	if parsed.Path == "/" {
		normalized += "/"
	}
	return origin, normalized, nil
}

func panelPort(origin string) uint16 {
	parsed, err := url.Parse(origin)
	if err != nil {
		return 0
	}
	if parsed.Port() == "" {
		return 443
	}
	value, _ := strconv.ParseUint(parsed.Port(), 10, 16)
	return uint16(value)
}

func validPort(value string) bool {
	if value == "" {
		return true
	}
	port, err := strconv.ParseUint(value, 10, 16)
	return err == nil && port > 0 && strconv.FormatUint(port, 10) == value
}

func validHostLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 || strings.ToLower(value) != value || !alphaNumeric(value[0]) || !alphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := range value {
		if !alphaNumeric(value[index]) && value[index] != '-' {
			return false
		}
	}
	return true
}

func validFQDN(value string) bool {
	if len(value) < 4 || len(value) > 253 || strings.HasSuffix(value, ".") || strings.ToLower(value) != value || !strings.Contains(value, ".") {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil && address.IsValid() {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validHostLabel(label) {
			return false
		}
	}
	return true
}

func sortedFQDNs(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for index, value := range values {
		if !validFQDN(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validPublicFamilies(ipv4, ipv6 []netip.Addr) bool {
	if len(ipv4)+len(ipv6) == 0 || len(ipv4)+len(ipv6) > 32 || !sortedAddresses(ipv4) || !sortedAddresses(ipv6) {
		return false
	}
	for _, address := range ipv4 {
		if !address.Is4() || !publicAddress(address) {
			return false
		}
	}
	for _, address := range ipv6 {
		if !address.Is6() || address.Is4In6() || !publicAddress(address) {
			return false
		}
	}
	return true
}

func validPublicAddresses(values []netip.Addr) bool {
	if len(values) == 0 || len(values) > 32 || !sortedAddresses(values) {
		return false
	}
	for _, address := range values {
		if !publicAddress(address) {
			return false
		}
	}
	return true
}

func publicAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Is4In6() || address.Zone() != "" || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func sortedAddresses(values []netip.Addr) bool {
	for index, value := range values {
		if index > 0 && values[index-1].Compare(value) >= 0 {
			return false
		}
	}
	return true
}

func sortedListeners(values []ListenerObservation) bool {
	for _, value := range values {
		if value.Validate() != nil {
			return false
		}
	}
	return true
}

func compareListener(left, right ListenerObservation) int {
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

func validTimezone(value string) bool {
	if value == "" || value == "Local" || strings.TrimSpace(value) != value {
		return false
	}
	_, err := time.LoadLocation(value)
	return err == nil
}

func validEmail(value string) bool {
	parsed, err := mail.ParseAddress(value)
	separator := strings.LastIndexByte(value, '@')
	return err == nil && separator > 0 && separator < len(value)-1 && parsed.Name == "" && parsed.Address == value && len(value) <= 254 && strings.ToLower(value[separator+1:]) == value[separator+1:]
}

func validText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func safeObservedText(value string, maximum int) bool {
	return value == "" || validText(value, 1, maximum)
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
	}
	return true
}

func validUTC(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func digestValue(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("cyberpanel:node-identity:"+domain+":v1\x00"), encoded...))
	return hex.EncodeToString(sum[:]), nil
}
