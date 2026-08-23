// Package diagnosticsrepair provides dependency-aware read-only diagnostics and
// a separately authorized typed repair lifecycle. It never emits shell or config text.
package diagnosticsrepair

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid      = errors.New("invalid diagnostics-repair resource")
	ErrNotFound     = errors.New("diagnostics-repair resource not found")
	ErrConflict     = errors.New("diagnostics-repair generation, fence, or owner conflict")
	ErrIntegrity    = errors.New("diagnostics-repair integrity failure")
	ErrUnauthorized = errors.New("diagnostics-repair authorization rejected")
	ErrUnsupported  = errors.New("diagnostics-repair operation unsupported")
	ErrUnmanaged    = errors.New("diagnostics-repair resource is unmanaged")
	ErrStale        = errors.New("diagnostics-repair observation is stale")
	ErrCapacity     = errors.New("diagnostics-repair bound exceeded")
	ErrUnproven     = errors.New("diagnostics-repair recovery is unproven")
)

const (
	MaxPageSize   = 500
	maxGeneration = uint64(1<<63 - 1)
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type Scope struct {
	TenantID   string `json:"tenant_id,omitempty"`
	NodeID     string `json:"node_id"`
	ResourceID string `json:"resource_id"`
}

func (scope Scope) Validate() error {
	if scope.TenantID != "" && !identifierPattern.MatchString(scope.TenantID) ||
		!identifierPattern.MatchString(scope.NodeID) || !identifierPattern.MatchString(scope.ResourceID) { return ErrInvalid }
	return nil
}

func (scope Scope) key() string { return scope.TenantID + "/" + scope.NodeID + "/" + scope.ResourceID }

type DiagnosticKind string

const (
	DiagnosticControl      DiagnosticKind = "control"
	DiagnosticOLS          DiagnosticKind = "ols_lse"
	DiagnosticPHP          DiagnosticKind = "php"
	DiagnosticDNS          DiagnosticKind = "dns"
	DiagnosticMail         DiagnosticKind = "mail"
	DiagnosticFTP          DiagnosticKind = "ftp"
	DiagnosticDatabase     DiagnosticKind = "database"
	DiagnosticFirewall     DiagnosticKind = "firewall"
	DiagnosticCertificates DiagnosticKind = "certificates"
)

func (kind DiagnosticKind) Valid() bool {
	switch kind {
	case DiagnosticControl, DiagnosticOLS, DiagnosticPHP, DiagnosticDNS, DiagnosticMail, DiagnosticFTP,
		DiagnosticDatabase, DiagnosticFirewall, DiagnosticCertificates:
		return true
	default: return false
	}
}

type DiagnosticDefinition struct {
	Kind          DiagnosticKind   `json:"kind"`
	Dependencies  []DiagnosticKind `json:"dependencies"`
	ServiceID     string           `json:"service_id"`
	Freshness     time.Duration    `json:"freshness"`
	MaximumFindings uint16         `json:"maximum_findings"`
}

type Registry struct {
	definitions map[DiagnosticKind]DiagnosticDefinition
	order       []DiagnosticKind
	digest      string
}

func NewRegistry(definitions []DiagnosticDefinition) (*Registry, error) {
	if len(definitions) != 9 { return nil, ErrInvalid }
	registry := &Registry{definitions: make(map[DiagnosticKind]DiagnosticDefinition, len(definitions))}
	canonical := append([]DiagnosticDefinition(nil), definitions...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Kind < canonical[j].Kind })
	for _, definition := range canonical {
		if !definition.Kind.Valid() || !identifierPattern.MatchString(definition.ServiceID) || definition.Freshness < time.Second ||
			definition.Freshness > 24*time.Hour || definition.MaximumFindings == 0 || definition.MaximumFindings > 256 { return nil, ErrInvalid }
		if _, exists := registry.definitions[definition.Kind]; exists { return nil, ErrInvalid }
		definition.Dependencies = append([]DiagnosticKind(nil), definition.Dependencies...)
		sort.Slice(definition.Dependencies, func(i, j int) bool { return definition.Dependencies[i] < definition.Dependencies[j] })
		for index, dependency := range definition.Dependencies {
			if !dependency.Valid() || dependency == definition.Kind || index > 0 && definition.Dependencies[index-1] == dependency { return nil, ErrInvalid }
		}
		registry.definitions[definition.Kind] = definition
	}
	for _, required := range allDiagnosticKinds() { if _, found := registry.definitions[required]; !found { return nil, ErrInvalid } }
	order, err := topologicalOrder(registry.definitions)
	if err != nil { return nil, err }
	registry.order = order
	serialized := make([]DiagnosticDefinition, 0, len(canonical))
	for _, kind := range order { serialized = append(serialized, registry.definitions[kind]) }
	registry.digest, err = digestJSON(serialized)
	if err != nil { return nil, err }
	return registry, nil
}

func DefaultRegistry() (*Registry, error) {
	return NewRegistry([]DiagnosticDefinition{
		{DiagnosticControl, nil, "control", 2 * time.Minute, 64},
		{DiagnosticOLS, []DiagnosticKind{DiagnosticControl}, "openlitespeed", 2 * time.Minute, 64},
		{DiagnosticPHP, []DiagnosticKind{DiagnosticControl, DiagnosticOLS}, "php", 2 * time.Minute, 64},
		{DiagnosticDNS, []DiagnosticKind{DiagnosticControl}, "dns", 5 * time.Minute, 64},
		{DiagnosticMail, []DiagnosticKind{DiagnosticControl, DiagnosticDNS}, "mail", 2 * time.Minute, 64},
		{DiagnosticFTP, []DiagnosticKind{DiagnosticControl, DiagnosticFirewall}, "ftp", 2 * time.Minute, 64},
		{DiagnosticDatabase, []DiagnosticKind{DiagnosticControl}, "database", 2 * time.Minute, 64},
		{DiagnosticFirewall, []DiagnosticKind{DiagnosticControl}, "firewall", 2 * time.Minute, 64},
		{DiagnosticCertificates, []DiagnosticKind{DiagnosticControl, DiagnosticDNS, DiagnosticOLS}, "certificates", 5 * time.Minute, 64},
	})
}

func allDiagnosticKinds() []DiagnosticKind {
	return []DiagnosticKind{DiagnosticControl, DiagnosticOLS, DiagnosticPHP, DiagnosticDNS, DiagnosticMail,
		DiagnosticFTP, DiagnosticDatabase, DiagnosticFirewall, DiagnosticCertificates}
}

func topologicalOrder(definitions map[DiagnosticKind]DiagnosticDefinition) ([]DiagnosticKind, error) {
	visiting, visited := make(map[DiagnosticKind]bool), make(map[DiagnosticKind]bool)
	order := make([]DiagnosticKind, 0, len(definitions))
	var visit func(DiagnosticKind) error
	visit = func(kind DiagnosticKind) error {
		if visiting[kind] { return ErrInvalid }
		if visited[kind] { return nil }
		visiting[kind] = true
		definition := definitions[kind]
		for _, dependency := range definition.Dependencies {
			if _, found := definitions[dependency]; !found { return ErrInvalid }
			if err := visit(dependency); err != nil { return err }
		}
		visiting[kind], visited[kind] = false, true
		order = append(order, kind)
		return nil
	}
	for _, kind := range allDiagnosticKinds() { if err := visit(kind); err != nil { return nil, err } }
	return order, nil
}

func (registry *Registry) Definition(kind DiagnosticKind) (DiagnosticDefinition, bool) {
	if registry == nil { return DiagnosticDefinition{}, false }
	definition, found := registry.definitions[kind]
	if !found { return DiagnosticDefinition{}, false }
	definition.Dependencies = append([]DiagnosticKind(nil), definition.Dependencies...)
	return definition, true
}

func (registry *Registry) Order() []DiagnosticKind {
	if registry == nil { return nil }
	return append([]DiagnosticKind(nil), registry.order...)
}

func (registry *Registry) Digest() string { if registry == nil { return "" }; return registry.digest }

type ProbeState string

const (
	ProbeHealthy     ProbeState = "healthy"
	ProbeFindings    ProbeState = "findings"
	ProbeUnsupported ProbeState = "unsupported"
	ProbeUncertain   ProbeState = "uncertain"
)

func (state ProbeState) Valid() bool { return state == ProbeHealthy || state == ProbeFindings || state == ProbeUnsupported || state == ProbeUncertain }

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

func (severity Severity) Valid() bool { return severity == SeverityInfo || severity == SeverityWarning || severity == SeverityCritical }

type FindingCode string

const (
	FindingCanonicalDrift     FindingCode = "canonical_generation_drift"
	FindingConfigInvalid      FindingCode = "config_invalid"
	FindingOwnershipMode      FindingCode = "ownership_mode_drift"
	FindingServiceDegraded    FindingCode = "service_degraded"
	FindingServiceDown        FindingCode = "service_down"
	FindingDNSMismatch        FindingCode = "dns_mismatch"
	FindingMailDelivery       FindingCode = "mail_delivery_failure"
	FindingFTPUnavailable     FindingCode = "ftp_unavailable"
	FindingDatabaseIntegrity  FindingCode = "database_integrity"
	FindingFirewallPolicy     FindingCode = "firewall_policy_drift"
	FindingCertificateBinding FindingCode = "certificate_binding_mismatch"
	FindingCertificateExpiry  FindingCode = "certificate_expiry"
	FindingDependencyUnknown  FindingCode = "dependency_health_unknown"
	FindingProbeUnsupported   FindingCode = "probe_unsupported"
	FindingProbeUncertain     FindingCode = "probe_uncertain"
	FindingStaleObservation   FindingCode = "stale_observation"
	FindingOwnerConflict      FindingCode = "exact_owner_conflict"
	FindingUnmanagedResource  FindingCode = "unmanaged_resource"
)

func (code FindingCode) Valid() bool {
	switch code {
	case FindingCanonicalDrift, FindingConfigInvalid, FindingOwnershipMode, FindingServiceDegraded, FindingServiceDown,
		FindingDNSMismatch, FindingMailDelivery, FindingFTPUnavailable, FindingDatabaseIntegrity, FindingFirewallPolicy,
		FindingCertificateBinding, FindingCertificateExpiry, FindingDependencyUnknown, FindingProbeUnsupported,
		FindingProbeUncertain, FindingStaleObservation, FindingOwnerConflict, FindingUnmanagedResource:
		return true
	default: return false
	}
}

type EvidenceCode string

const (
	EvidenceObservedGeneration EvidenceCode = "observed_generation"
	EvidenceCanonicalDigest    EvidenceCode = "canonical_digest"
	EvidenceConfigValidation   EvidenceCode = "config_validation"
	EvidenceOwnership          EvidenceCode = "ownership_mode"
	EvidenceServiceHealth      EvidenceCode = "service_health"
	EvidenceDNSAnswer          EvidenceCode = "dns_answer"
	EvidenceMailPath           EvidenceCode = "mail_path"
	EvidenceFTPHealth          EvidenceCode = "ftp_health"
	EvidenceDatabaseProof      EvidenceCode = "database_proof"
	EvidenceFirewallPolicy     EvidenceCode = "firewall_policy"
	EvidenceCertificateBinding EvidenceCode = "certificate_binding"
	EvidenceCertificateExpiry  EvidenceCode = "certificate_expiry"
	EvidenceDependency         EvidenceCode = "dependency"
	EvidenceUnsupported        EvidenceCode = "unsupported"
	EvidenceAmbiguous          EvidenceCode = "ambiguous"
	EvidenceStale              EvidenceCode = "stale"
)

func (code EvidenceCode) Valid() bool {
	switch code {
	case EvidenceObservedGeneration, EvidenceCanonicalDigest, EvidenceConfigValidation, EvidenceOwnership,
		EvidenceServiceHealth, EvidenceDNSAnswer, EvidenceMailPath, EvidenceFTPHealth, EvidenceDatabaseProof,
		EvidenceFirewallPolicy, EvidenceCertificateBinding, EvidenceCertificateExpiry, EvidenceDependency,
		EvidenceUnsupported, EvidenceAmbiguous, EvidenceStale:
		return true
	default: return false
	}
}

type Evidence struct {
	Code       EvidenceCode `json:"code"`
	Digest     string       `json:"digest"`
	ObservedAt time.Time    `json:"observed_at"`
}

type Finding struct {
	ID                 string         `json:"id"`
	Kind               DiagnosticKind `json:"kind"`
	Scope              Scope          `json:"scope"`
	Code               FindingCode    `json:"code"`
	Severity           Severity       `json:"severity"`
	ObservedGeneration uint64         `json:"observed_generation"`
	ServiceID          string         `json:"service_id"`
	OwnerID            string         `json:"owner_id,omitempty"`
	RepairEligible     bool           `json:"repair_eligible"`
	Evidence           []Evidence     `json:"evidence"`
	Digest             string         `json:"digest"`
}

func canonicalFinding(finding Finding, maximum int) (Finding, error) {
	if !finding.Kind.Valid() || finding.Scope.Validate() != nil || !finding.Code.Valid() || !finding.Severity.Valid() ||
		!identifierPattern.MatchString(finding.ServiceID) || finding.OwnerID != "" && !identifierPattern.MatchString(finding.OwnerID) ||
		finding.ObservedGeneration > maxGeneration || finding.RepairEligible && finding.OwnerID == "" ||
		len(finding.Evidence) == 0 || len(finding.Evidence) > maximum { return Finding{}, ErrInvalid }
	finding.Evidence = append([]Evidence(nil), finding.Evidence...)
	sort.Slice(finding.Evidence, func(i, j int) bool {
		if finding.Evidence[i].Code == finding.Evidence[j].Code { return finding.Evidence[i].Digest < finding.Evidence[j].Digest }
		return finding.Evidence[i].Code < finding.Evidence[j].Code
	})
	for index, evidence := range finding.Evidence {
		if !evidence.Code.Valid() || !validDigest(evidence.Digest) || !validTime(evidence.ObservedAt) ||
			index > 0 && finding.Evidence[index-1].Code == evidence.Code && finding.Evidence[index-1].Digest == evidence.Digest { return Finding{}, ErrInvalid }
		finding.Evidence[index].ObservedAt = evidence.ObservedAt.UTC()
	}
	finding.ID = ""
	finding.Digest = ""
	digest, err := digestJSON(finding)
	if err != nil { return Finding{}, err }
	finding.ID, finding.Digest = digestParts("finding", digest), digest
	return finding, nil
}

type ProbeObservation struct {
	Kind               DiagnosticKind `json:"kind"`
	Scope              Scope          `json:"scope"`
	State              ProbeState     `json:"state"`
	ObservedGeneration uint64         `json:"observed_generation"`
	ObservedAt         time.Time      `json:"observed_at"`
	FreshUntil         time.Time      `json:"fresh_until"`
	Findings           []Finding      `json:"findings"`
	EvidenceDigest     string         `json:"evidence_digest"`
	Digest             string         `json:"digest"`
}

func canonicalObservation(observation ProbeObservation, definition DiagnosticDefinition, now time.Time) (ProbeObservation, error) {
	if observation.Kind != definition.Kind || observation.Scope.Validate() != nil || !observation.State.Valid() ||
		!validTime(observation.ObservedAt) || !validTime(observation.FreshUntil) || observation.FreshUntil.Before(observation.ObservedAt) ||
		observation.FreshUntil.After(observation.ObservedAt.Add(definition.Freshness)) || !validDigest(observation.EvidenceDigest) ||
		len(observation.Findings) > int(definition.MaximumFindings) { return ProbeObservation{}, ErrInvalid }
	observation.ObservedAt, observation.FreshUntil = observation.ObservedAt.UTC(), observation.FreshUntil.UTC()
	if now.After(observation.FreshUntil) { return ProbeObservation{}, ErrStale }
	findings := make([]Finding, 0, len(observation.Findings))
	for _, finding := range observation.Findings {
		if finding.Kind != observation.Kind || finding.Scope != observation.Scope ||
			finding.ObservedGeneration != observation.ObservedGeneration { return ProbeObservation{}, ErrIntegrity }
		canonical, err := canonicalFinding(finding, 32)
		if err != nil { return ProbeObservation{}, err }
		findings = append(findings, canonical)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	for index := 1; index < len(findings); index++ { if findings[index-1].ID == findings[index].ID { return ProbeObservation{}, ErrInvalid } }
	observation.Findings = findings
	if observation.State == ProbeHealthy && len(findings) != 0 || observation.State == ProbeFindings && len(findings) == 0 ||
		(observation.State == ProbeUnsupported || observation.State == ProbeUncertain) && len(findings) != 1 { return ProbeObservation{}, ErrInvalid }
	if observation.State == ProbeUnsupported && findings[0].Code != FindingProbeUnsupported ||
		observation.State == ProbeUncertain && findings[0].Code != FindingProbeUncertain && findings[0].Code != FindingDependencyUnknown && findings[0].Code != FindingStaleObservation {
		return ProbeObservation{}, ErrInvalid
	}
	if (observation.State == ProbeUnsupported || observation.State == ProbeUncertain) && findings[0].RepairEligible { return ProbeObservation{}, ErrInvalid }
	claimed := observation.Digest
	observation.Digest = ""
	digest, err := digestJSON(observation)
	if err != nil || claimed != "" && claimed != digest { return ProbeObservation{}, ErrIntegrity }
	observation.Digest = digest
	return observation, nil
}

type RunState string

const (
	RunHealthy     RunState = "healthy"
	RunFindings    RunState = "findings"
	RunUnsupported RunState = "unsupported"
	RunUncertain   RunState = "uncertain"
)

type DiagnosticRun struct {
	ID             string             `json:"id"`
	Scope          Scope              `json:"scope"`
	RegistryDigest string             `json:"registry_digest"`
	RequestedAt    time.Time          `json:"requested_at"`
	CompletedAt    time.Time          `json:"completed_at"`
	State          RunState           `json:"state"`
	Observations   []ProbeObservation `json:"observations"`
	Digest         string             `json:"digest"`
}

func CanonicalRun(run DiagnosticRun) (DiagnosticRun, error) {
	if !identifierPattern.MatchString(run.ID) || run.Scope.Validate() != nil || !validDigest(run.RegistryDigest) ||
		!validTime(run.RequestedAt) || !validTime(run.CompletedAt) || run.CompletedAt.Before(run.RequestedAt) ||
		run.State != RunHealthy && run.State != RunFindings && run.State != RunUnsupported && run.State != RunUncertain ||
		len(run.Observations) == 0 || len(run.Observations) > 9 { return DiagnosticRun{}, ErrInvalid }
	run.RequestedAt, run.CompletedAt = run.RequestedAt.UTC(), run.CompletedAt.UTC()
	run.Observations = append([]ProbeObservation(nil), run.Observations...)
	sort.Slice(run.Observations, func(i, j int) bool { return run.Observations[i].Kind < run.Observations[j].Kind })
	for index, observation := range run.Observations {
		if !observation.Kind.Valid() || observation.Scope != run.Scope || !validDigest(observation.Digest) ||
			index > 0 && run.Observations[index-1].Kind == observation.Kind || !observation.State.Valid() ||
			observation.ObservedGeneration > maxGeneration || !validTime(observation.ObservedAt) || !validTime(observation.FreshUntil) ||
			observation.FreshUntil.Before(observation.ObservedAt) || observation.FreshUntil.Sub(observation.ObservedAt) > 24*time.Hour ||
			run.CompletedAt.Before(observation.ObservedAt) || !validDigest(observation.EvidenceDigest) ||
			len(observation.Findings) > 256 { return DiagnosticRun{}, ErrInvalid }
		observation.ObservedAt, observation.FreshUntil = observation.ObservedAt.UTC(), observation.FreshUntil.UTC()
		for findingIndex, finding := range observation.Findings {
			if finding.Kind != observation.Kind || finding.Scope != observation.Scope ||
				findingIndex > 0 && observation.Findings[findingIndex-1].ID >= finding.ID { return DiagnosticRun{}, ErrInvalid }
			canonical, canonicalErr := canonicalFinding(finding, 32)
			if canonicalErr != nil || canonical.ID != finding.ID || canonical.Digest != finding.Digest { return DiagnosticRun{}, ErrIntegrity }
		}
		if observation.State == ProbeHealthy && len(observation.Findings) != 0 ||
			observation.State == ProbeFindings && len(observation.Findings) == 0 ||
			(observation.State == ProbeUnsupported || observation.State == ProbeUncertain) && len(observation.Findings) != 1 { return DiagnosticRun{}, ErrInvalid }
		if observation.State == ProbeUnsupported && observation.Findings[0].Code != FindingProbeUnsupported ||
			observation.State == ProbeUncertain && observation.Findings[0].Code != FindingProbeUncertain &&
				observation.Findings[0].Code != FindingDependencyUnknown && observation.Findings[0].Code != FindingStaleObservation {
			return DiagnosticRun{}, ErrInvalid
		}
		claimedObservation := observation.Digest
		observation.Digest = ""
		observationDigest, observationErr := digestJSON(observation)
		if observationErr != nil || claimedObservation != observationDigest { return DiagnosticRun{}, ErrIntegrity }
		observation.Digest = claimedObservation
		run.Observations[index] = observation
	}
	if run.State != stateForObservations(run.Observations) { return DiagnosticRun{}, ErrIntegrity }
	claimed := run.Digest
	run.Digest = ""
	digest, err := digestJSON(run)
	if err != nil || claimed != "" && claimed != digest { return DiagnosticRun{}, ErrIntegrity }
	run.Digest = digest
	return run, nil
}

func stateForObservations(observations []ProbeObservation) RunState {
	state := RunHealthy
	for _, observation := range observations {
		switch observation.State {
		case ProbeUncertain:
			state = RunUncertain
		case ProbeUnsupported:
			if state != RunUncertain { state = RunUnsupported }
		case ProbeFindings:
			if state == RunHealthy { state = RunFindings }
		}
	}
	return state
}

func digestJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil { return "", err }
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func digestParts(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts { fmt.Fprintf(hash, "%d:%s\n", len(part), part) }
	return hex.EncodeToString(hash.Sum(nil))
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) { return false }
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validTime(value time.Time) bool { return !value.IsZero() && value.Year() >= 2000 && value.Year() <= 9999 }

func uintString(value uint64) string {
	if value == 0 { return "0" }
	buffer := make([]byte, 20)
	index := len(buffer)
	for value > 0 { index--; buffer[index] = byte('0' + value%10); value /= 10 }
	return string(buffer[index:])
}
