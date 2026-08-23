package dns

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrDNSDiagnosticUnavailable = errors.New("DNS diagnostic query unavailable")
var ErrDNSDiagnosticOutputLimit = errors.New("DNS diagnostic output limit exceeded")

const (
	maxDiagnosticResolvers   = 4
	maxDiagnosticAuthorities = 4
	maxDiagnosticTransfers   = 16
	maxDiagnosticNameservers = 8
	maxDiagnosticAnswers     = 128
	maxDiagnosticEvidence    = 128
	defaultDiagnosticTimeout = 3 * time.Second
	defaultDiagnosticOverall = 45 * time.Second
	maximumDiagnosticTimeout = 10 * time.Second
	maximumDiagnosticOverall = 2 * time.Minute
)

type DiagnosticState string

const (
	DiagnosticHealthy       DiagnosticState = "healthy"
	DiagnosticDegraded      DiagnosticState = "degraded"
	DiagnosticFailed        DiagnosticState = "failed"
	DiagnosticUnsupported   DiagnosticState = "unsupported"
	DiagnosticIndeterminate DiagnosticState = "indeterminate"
)

type DiagnosticKind string

const (
	DiagnosticLocalAuthority DiagnosticKind = "local_authority"
	DiagnosticDelegation     DiagnosticKind = "public_delegation"
	DiagnosticSerial         DiagnosticKind = "soa_serial_convergence"
	DiagnosticDNSSEC         DiagnosticKind = "dnssec_continuity"
	DiagnosticTransfer       DiagnosticKind = "transfer_health"
	DiagnosticPropagation    DiagnosticKind = "public_propagation"
)

type DiagnosticRequest struct {
	Zone               ZoneSpec           `json:"zone"`
	ExpectedGeneration uint64             `json:"expected_generation"`
	LocalAuthorities   []netip.Addr        `json:"local_authorities"`
	PublicResolvers    []netip.Addr        `json:"public_resolvers"`
	TransferPeers      []TransferPeerSpec  `json:"transfer_peers,omitempty"`
}

type DiagnosticEvidence struct {
	Resolver   string    `json:"resolver"`
	Name       string    `json:"name"`
	Kind       RRKind    `json:"kind"`
	Status     string    `json:"status,omitempty"`
	Flags      []string  `json:"flags,omitempty"`
	Values     []string  `json:"values,omitempty"`
	ErrorCode  string    `json:"error_code,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type DiagnosticFinding struct {
	Kind           DiagnosticKind       `json:"kind"`
	State          DiagnosticState      `json:"state"`
	Code           string               `json:"code"`
	Evidence       []DiagnosticEvidence `json:"evidence"`
	EvidenceDigest string               `json:"evidence_digest"`
	ObservedAt     time.Time            `json:"observed_at"`
}

type DiagnosticReport struct {
	ZoneID             ZoneID              `json:"zone_id"`
	TenantID           string              `json:"tenant_id"`
	ZoneName           string              `json:"zone_name"`
	ExpectedGeneration uint64              `json:"expected_generation"`
	State              DiagnosticState     `json:"state"`
	Findings           []DiagnosticFinding `json:"findings"`
	EvidenceDigest     string              `json:"evidence_digest"`
	ObservedAt         time.Time           `json:"observed_at"`
}

type diagnosticQuery struct {
	Server        netip.Addr
	Name          DNSName
	Kind          RRKind
	Authoritative bool
	DNSSEC        bool
}

type diagnosticRecord struct {
	Owner DNSName
	Kind  RRKind
	Value string
}

type diagnosticAnswer struct {
	Status        string
	Authoritative bool
	Authenticated bool
	Records       []diagnosticRecord
	ObservedAt    time.Time
}

type DiagnosticRunner interface {
	Run(context.Context, diagnosticQuery) ([]byte, error)
}

type DiagnosticResolver interface {
	Resolve(context.Context, diagnosticQuery) (diagnosticAnswer, error)
}

type DiagnosticService struct {
	Resolver       DiagnosticResolver
	PerCheckTimeout time.Duration
	OverallTimeout  time.Duration
	Now             func() time.Time
}

type diagnosticResult struct {
	query  diagnosticQuery
	answer diagnosticAnswer
	err    error
}

func (service DiagnosticService) Diagnose(ctx context.Context, request DiagnosticRequest) (DiagnosticReport, error) {
	report := DiagnosticReport{ZoneID: request.Zone.ID, TenantID: request.Zone.TenantID, ZoneName: request.Zone.Name.String(), ExpectedGeneration: request.ExpectedGeneration}
	if ctx == nil || service.Resolver == nil || validateDiagnosticRequest(request) != nil {
		return report, ErrInvalidDNS
	}
	if request.Zone.Generation != request.ExpectedGeneration {
		return report, ErrDNSConflict
	}
	perCheck, overall := diagnosticDeadlines(service.PerCheckTimeout, service.OverallTimeout)
	overallContext, cancel := context.WithTimeout(ctx, overall)
	defer cancel()

	localQueries := make([]diagnosticQuery, 0, len(request.LocalAuthorities)*5)
	for _, server := range request.LocalAuthorities {
		for _, kind := range []RRKind{RR_SOA, RR_NS, RR_A, RR_AAAA, RR_DNSKEY} {
			localQueries = append(localQueries, diagnosticQuery{Server: server, Name: request.Zone.Name, Kind: kind, Authoritative: true, DNSSEC: kind == RR_DNSKEY})
		}
	}
	publicQueries := make([]diagnosticQuery, 0, len(request.PublicResolvers)*6)
	for _, server := range request.PublicResolvers {
		for _, kind := range []RRKind{RR_SOA, RR_NS, RR_A, RR_AAAA, RR_DNSKEY, RR_DS} {
			publicQueries = append(publicQueries, diagnosticQuery{Server: server, Name: request.Zone.Name, Kind: kind, DNSSEC: kind == RR_DNSKEY || kind == RR_DS})
		}
	}
	local := service.resolveMany(overallContext, perCheck, localQueries)
	public := service.resolveMany(overallContext, perCheck, publicQueries)

	nameservers, nameserversTruncated := diagnosticNameservers(request.Zone, local, public)
	glueQueries := make([]diagnosticQuery, 0, len(request.PublicResolvers)*len(nameservers)*2)
	for _, server := range request.PublicResolvers {
		for _, name := range nameservers {
			for _, kind := range []RRKind{RR_A, RR_AAAA} {
				glueQueries = append(glueQueries, diagnosticQuery{Server: server, Name: name, Kind: kind})
			}
		}
	}
	glue := service.resolveMany(overallContext, perCheck, glueQueries)

	transferQueries := diagnosticTransferQueries(request)
	transfers := service.resolveMany(overallContext, perCheck, transferQueries)
	now := diagnosticNow(service.Now)
	findings := []DiagnosticFinding{
		evaluateLocalAuthority(request, local, now),
		evaluateDelegation(request, local, public, glue, nameservers, nameserversTruncated, now),
		evaluateSerial(request, local, public, now),
		evaluateDNSSEC(request, local, public, now),
		evaluateTransfers(request, local, transfers, now),
		evaluatePropagation(request, public, now),
	}
	for index := range findings {
		findings[index].EvidenceDigest = digestDiagnosticEvidence(findings[index].Evidence)
	}
	report.Findings = findings
	report.State = aggregateDiagnosticState(findings)
	report.EvidenceDigest = digestDiagnosticReport(report)
	report.ObservedAt = now
	return report, nil
}

func validateDiagnosticRequest(request DiagnosticRequest) error {
	if request.ExpectedGeneration == 0 || len(request.LocalAuthorities) == 0 || len(request.LocalAuthorities) > maxDiagnosticAuthorities || len(request.PublicResolvers) == 0 || len(request.PublicResolvers) > maxDiagnosticResolvers || len(request.TransferPeers) > maxDiagnosticTransfers || len(request.Zone.PrimaryAddresses) > maxDiagnosticTransfers {
		return ErrInvalidDNS
	}
	if validateZoneSpec(request.Zone, nil, request.TransferPeers) != nil || !validDiagnosticZoneName(request.Zone.Name) {
		return ErrInvalidDNS
	}
	if !uniqueDiagnosticAddresses(request.LocalAuthorities, false) || !uniqueDiagnosticAddresses(request.PublicResolvers, true) {
		return ErrInvalidDNS
	}
	return nil
}

func validDiagnosticZoneName(zone DNSName) bool {
	value := zone.String()
	if value == "" || value == "@" || strings.Contains(value, "*") || strings.Contains(value, "_") {
		return false
	}
	parsed, err := ParseName(value)
	return err == nil && parsed.String() == value
}

func uniqueDiagnosticAddresses(addresses []netip.Addr, public bool) bool {
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || public && (address.IsPrivate() || address.IsLoopback()) {
			return false
		}
		if _, exists := seen[address]; exists {
			return false
		}
		seen[address] = struct{}{}
	}
	return true
}

func diagnosticDeadlines(perCheck, overall time.Duration) (time.Duration, time.Duration) {
	if perCheck <= 0 || perCheck > maximumDiagnosticTimeout {
		perCheck = defaultDiagnosticTimeout
	}
	if overall <= 0 || overall > maximumDiagnosticOverall {
		overall = defaultDiagnosticOverall
	}
	return perCheck, overall
}

func diagnosticNow(now func() time.Time) time.Time {
	if now == nil {
		return time.Now().UTC()
	}
	return now().UTC()
}

func (service DiagnosticService) resolveMany(ctx context.Context, timeout time.Duration, queries []diagnosticQuery) []diagnosticResult {
	results := make([]diagnosticResult, len(queries))
	for index, query := range queries {
		results[index].query = query
		if ctx.Err() != nil {
			results[index].err = ctx.Err()
			results[index].answer.ObservedAt = diagnosticNow(service.Now)
			continue
		}
		queryContext, cancel := context.WithTimeout(ctx, timeout)
		results[index].answer, results[index].err = service.Resolver.Resolve(queryContext, query)
		cancel()
		if results[index].answer.ObservedAt.IsZero() {
			results[index].answer.ObservedAt = diagnosticNow(service.Now)
		}
	}
	return results
}

func diagnosticNameservers(zone ZoneSpec, groups ...[]diagnosticResult) ([]DNSName, bool) {
	byName := map[string]DNSName{}
	for _, group := range groups {
		for _, result := range group {
			if result.err != nil || result.query.Kind != RR_NS || result.answer.Status != "NOERROR" {
				continue
			}
			for _, value := range diagnosticValues(result.answer, zone.Name, RR_NS) {
				name, err := ParseName(value)
				if err == nil && name.String() != "@" && (name.String() == zone.Name.String() || strings.HasSuffix(name.String(), "."+zone.Name.String())) {
					byName[name.String()] = name
				}
			}
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	truncated := len(names) > maxDiagnosticNameservers
	if truncated {
		names = names[:maxDiagnosticNameservers]
	}
	result := make([]DNSName, 0, len(names))
	for _, name := range names {
		result = append(result, byName[name])
	}
	return result, truncated
}

func diagnosticTransferQueries(request DiagnosticRequest) []diagnosticQuery {
	addresses := map[netip.Addr]struct{}{}
	if request.Zone.Mode == ZoneSecondary {
		for _, address := range request.Zone.PrimaryAddresses {
			addresses[address.Unmap()] = struct{}{}
		}
	}
	for _, peer := range request.TransferPeers {
		addresses[peer.Address.Unmap()] = struct{}{}
	}
	ordered := make([]netip.Addr, 0, len(addresses))
	for address := range addresses {
		ordered = append(ordered, address)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Compare(ordered[right]) < 0 })
	queries := make([]diagnosticQuery, 0, len(ordered))
	for _, address := range ordered {
		queries = append(queries, diagnosticQuery{Server: address, Name: request.Zone.Name, Kind: RR_SOA, Authoritative: true})
	}
	return queries
}

func evaluateLocalAuthority(request DiagnosticRequest, results []diagnosticResult, now time.Time) DiagnosticFinding {
	good := 0
	for _, server := range request.LocalAuthorities {
		soa, soaOK := findDiagnosticResult(results, server, request.Zone.Name, RR_SOA)
		ns, nsOK := findDiagnosticResult(results, server, request.Zone.Name, RR_NS)
		a, aOK := findDiagnosticResult(results, server, request.Zone.Name, RR_A)
		aaaa, aaaaOK := findDiagnosticResult(results, server, request.Zone.Name, RR_AAAA)
		if soaOK && nsOK && aOK && aaaaOK && diagnosticAuthoritativeAnswer(soa, RR_SOA) && diagnosticAuthoritativeAnswer(ns, RR_NS) && diagnosticAuthoritativeResponse(a) && diagnosticAuthoritativeResponse(aaaa) {
			good++
		}
	}
	state, code := DiagnosticFailed, "local_authority_unavailable"
	if good == len(request.LocalAuthorities) {
		consistent := true
		for _, kind := range []RRKind{RR_SOA, RR_NS, RR_A, RR_AAAA} {
			sets := successfulAuthoritativeSets(results, request.LocalAuthorities, request.Zone.Name, kind)
			consistent = consistent && len(sets) == len(request.LocalAuthorities) && allDiagnosticSetsEqual(sets)
		}
		if consistent {
			state, code = DiagnosticHealthy, "local_authority_consistent"
		} else {
			state, code = DiagnosticDegraded, "local_authority_divergent"
		}
	} else if good > 0 {
		state, code = DiagnosticDegraded, "local_authority_partial"
	}
	return newDiagnosticFinding(DiagnosticLocalAuthority, state, code, results, now)
}

func evaluateDelegation(request DiagnosticRequest, local, public, glue []diagnosticResult, nameservers []DNSName, nameserversTruncated bool, now time.Time) DiagnosticFinding {
	localNSSets := successfulAuthoritativeSets(local, request.LocalAuthorities, request.Zone.Name, RR_NS)
	localNS := []string{}
	if len(localNSSets) == len(request.LocalAuthorities) && allDiagnosticSetsEqual(localNSSets) {
		localNS = localNSSets[0]
	}
	publicSets := successfulResolverSets(public, request.PublicResolvers, request.Zone.Name, RR_NS)
	state, code := DiagnosticIndeterminate, "delegation_insufficient_resolvers"
	if len(publicSets) >= 2 {
		if len(publicSets) != len(request.PublicResolvers) {
			state, code = DiagnosticDegraded, "delegation_partial"
		} else if allDiagnosticSetsEmpty(publicSets) {
			state, code = DiagnosticFailed, "delegation_missing"
		} else if nameserversTruncated {
			state, code = DiagnosticDegraded, "delegation_nameserver_limit"
		} else if !allDiagnosticSetsEqual(publicSets) || len(localNS) == 0 || !sameDiagnosticSet(localNS, publicSets[0]) {
			state, code = DiagnosticDegraded, "delegation_divergent"
		} else if !diagnosticGlueConverged(glue, request.PublicResolvers, nameservers) {
			state, code = DiagnosticDegraded, "delegation_glue_incomplete"
		} else {
			state, code = DiagnosticHealthy, "delegation_and_glue_consistent"
		}
	}
	evidence := append(append(diagnosticEvidence(local), diagnosticEvidence(public)...), diagnosticEvidence(glue)...)
	return finishDiagnosticFinding(DiagnosticDelegation, state, code, evidence, now)
}

func evaluateSerial(request DiagnosticRequest, local, public []diagnosticResult, now time.Time) DiagnosticFinding {
	localSerials := diagnosticSerials(local, request.Zone.Name, true)
	publicSerials := diagnosticSerials(public, request.Zone.Name, false)
	state, code := DiagnosticIndeterminate, "serial_insufficient_observations"
	if len(localSerials) == 0 {
		state, code = DiagnosticFailed, "local_serial_unavailable"
	} else if len(localSerials) != len(request.LocalAuthorities) {
		state, code = DiagnosticDegraded, "local_serial_partial"
	} else if !allUint64Equal(localSerials) {
		state, code = DiagnosticFailed, "local_serial_divergent"
	} else if len(publicSerials) >= 2 {
		if len(publicSerials) == len(request.PublicResolvers) && allUint64Equal(publicSerials) && publicSerials[0] == localSerials[0] {
			state, code = DiagnosticHealthy, "serials_converged"
		} else {
			state, code = DiagnosticDegraded, "serials_divergent"
		}
	}
	evidence := append(diagnosticEvidence(local), diagnosticEvidence(public)...)
	return finishDiagnosticFinding(DiagnosticSerial, state, code, evidence, now)
}

func evaluateDNSSEC(request DiagnosticRequest, local, public []diagnosticResult, now time.Time) DiagnosticFinding {
	localKeySets := successfulAuthoritativeSets(local, request.LocalAuthorities, request.Zone.Name, RR_DNSKEY)
	localComplete := len(localKeySets) == len(request.LocalAuthorities)
	localConsistent := localComplete && allDiagnosticSetsEqual(localKeySets)
	localKeys := []string{}
	if localConsistent {
		localKeys = localKeySets[0]
	}
	valid, complete, unsigned := 0, 0, 0
	for _, resolver := range request.PublicResolvers {
		keyResult, keyOK := findDiagnosticResult(public, resolver, request.Zone.Name, RR_DNSKEY)
		dsResult, dsOK := findDiagnosticResult(public, resolver, request.Zone.Name, RR_DS)
		if !keyOK || !dsOK || !diagnosticSuccessful(keyResult) || !diagnosticSuccessful(dsResult) {
			continue
		}
		complete++
		keys := diagnosticValues(keyResult.answer, request.Zone.Name, RR_DNSKEY)
		ds := diagnosticValues(dsResult.answer, request.Zone.Name, RR_DS)
		if len(keys) == 0 && len(ds) == 0 {
			unsigned++
			continue
		}
		if keyResult.answer.Authenticated && dsResult.answer.Authenticated && dnssecContinuity(request.Zone.Name, localKeys, keys, ds) {
			valid++
		}
	}
	state, code := DiagnosticIndeterminate, "dnssec_insufficient_resolvers"
	if complete >= 2 {
		switch {
		case !localComplete:
			state, code = DiagnosticIndeterminate, "dnssec_local_unobservable"
		case !localConsistent:
			state, code = DiagnosticFailed, "dnssec_local_keys_divergent"
		case complete != len(request.PublicResolvers):
			state, code = DiagnosticDegraded, "dnssec_resolver_partial"
		case valid >= 2 && valid == complete && complete == len(request.PublicResolvers):
			state, code = DiagnosticHealthy, "dnssec_chain_continuous"
		case len(localKeys) == 0 && unsigned == complete:
			state, code = DiagnosticUnsupported, "dnssec_not_published"
		case valid > 0:
			state, code = DiagnosticDegraded, "dnssec_validation_divergent"
		case len(localKeys) > 0 && unsigned == complete:
			state, code = DiagnosticDegraded, "dnssec_ds_not_published"
		default:
			state, code = DiagnosticFailed, "dnssec_chain_broken"
		}
	}
	evidence := append(diagnosticEvidenceForKind(local, RR_DNSKEY), diagnosticEvidenceForKinds(public, RR_DNSKEY, RR_DS)...)
	return finishDiagnosticFinding(DiagnosticDNSSEC, state, code, evidence, now)
}

func evaluateTransfers(request DiagnosticRequest, local, transfers []diagnosticResult, now time.Time) DiagnosticFinding {
	if len(transfers) == 0 {
		return finishDiagnosticFinding(DiagnosticTransfer, DiagnosticUnsupported, "transfers_not_configured", nil, now)
	}
	localSerials := diagnosticSerials(local, request.Zone.Name, true)
	if len(localSerials) != len(request.LocalAuthorities) || !allUint64Equal(localSerials) {
		return newDiagnosticFinding(DiagnosticTransfer, DiagnosticIndeterminate, "transfer_baseline_unavailable", transfers, now)
	}
	matching := 0
	for _, result := range transfers {
		serial, ok := diagnosticSerial(result, true)
		if ok && serial == localSerials[0] {
			matching++
		}
	}
	state, code := DiagnosticFailed, "transfer_peers_unreachable"
	if matching == len(transfers) {
		state, code = DiagnosticHealthy, "transfer_serials_converged"
	} else if matching > 0 {
		state, code = DiagnosticDegraded, "transfer_serials_partial"
	} else if len(diagnosticSerials(transfers, request.Zone.Name, true)) > 0 {
		state, code = DiagnosticDegraded, "transfer_serials_divergent"
	}
	return newDiagnosticFinding(DiagnosticTransfer, state, code, transfers, now)
}

func evaluatePropagation(request DiagnosticRequest, public []diagnosticResult, now time.Time) DiagnosticFinding {
	fingerprints := make([]string, 0, len(request.PublicResolvers))
	for _, resolver := range request.PublicResolvers {
		values := []string{}
		complete := true
		for _, kind := range []RRKind{RR_SOA, RR_NS, RR_A, RR_AAAA} {
			result, ok := findDiagnosticResult(public, resolver, request.Zone.Name, kind)
			if !ok || !diagnosticSuccessful(result) || kind == RR_SOA && len(diagnosticValues(result.answer, request.Zone.Name, kind)) == 0 || kind == RR_NS && len(diagnosticValues(result.answer, request.Zone.Name, kind)) == 0 {
				complete = false
				break
			}
			for _, value := range diagnosticValues(result.answer, request.Zone.Name, kind) {
				values = append(values, string(kind)+"="+value)
			}
		}
		if complete {
			sort.Strings(values)
			fingerprints = append(fingerprints, strings.Join(values, "\x00"))
		}
	}
	state, code := DiagnosticIndeterminate, "propagation_insufficient_resolvers"
	if len(fingerprints) >= 2 {
		if len(fingerprints) == len(request.PublicResolvers) && allStringsEqual(fingerprints) {
			state, code = DiagnosticHealthy, "propagation_converged"
		} else {
			state, code = DiagnosticDegraded, "propagation_divergent"
		}
	} else if len(fingerprints) == 0 && len(request.PublicResolvers) >= 2 {
		state, code = DiagnosticFailed, "propagation_unobservable"
	}
	return newDiagnosticFinding(DiagnosticPropagation, state, code, public, now)
}

func newDiagnosticFinding(kind DiagnosticKind, state DiagnosticState, code string, results []diagnosticResult, now time.Time) DiagnosticFinding {
	return finishDiagnosticFinding(kind, state, code, diagnosticEvidence(results), now)
}

func finishDiagnosticFinding(kind DiagnosticKind, state DiagnosticState, code string, evidence []DiagnosticEvidence, now time.Time) DiagnosticFinding {
	if len(evidence) > maxDiagnosticEvidence {
		evidence = evidence[:maxDiagnosticEvidence]
	}
	return DiagnosticFinding{Kind: kind, State: state, Code: code, Evidence: evidence, ObservedAt: now}
}

func diagnosticEvidence(results []diagnosticResult) []DiagnosticEvidence {
	evidence := make([]DiagnosticEvidence, 0, len(results))
	for _, result := range results {
		item := DiagnosticEvidence{Resolver: result.query.Server.String(), Name: result.query.Name.String(), Kind: result.query.Kind, ObservedAt: result.answer.ObservedAt}
		if result.err != nil {
			item.ErrorCode = diagnosticErrorCode(result.err)
		} else {
			item.Status = result.answer.Status
			if result.answer.Authoritative {
				item.Flags = append(item.Flags, "aa")
			}
			if result.answer.Authenticated {
				item.Flags = append(item.Flags, "ad")
			}
			item.Values = diagnosticValues(result.answer, result.query.Name, result.query.Kind)
		}
		evidence = append(evidence, item)
	}
	sort.Slice(evidence, func(left, right int) bool {
		return diagnosticEvidenceKey(evidence[left]) < diagnosticEvidenceKey(evidence[right])
	})
	return evidence
}

func diagnosticEvidenceForKind(results []diagnosticResult, kind RRKind) []DiagnosticEvidence {
	return diagnosticEvidenceForKinds(results, kind)
}

func diagnosticEvidenceForKinds(results []diagnosticResult, kinds ...RRKind) []DiagnosticEvidence {
	allowed := map[RRKind]struct{}{}
	for _, kind := range kinds {
		allowed[kind] = struct{}{}
	}
	filtered := make([]diagnosticResult, 0, len(results))
	for _, result := range results {
		if _, ok := allowed[result.query.Kind]; ok {
			filtered = append(filtered, result)
		}
	}
	return diagnosticEvidence(filtered)
}

func diagnosticErrorCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrDNSDiagnosticOutputLimit):
		return "output_limit"
	case errors.Is(err, ErrInvalidDNS):
		return "invalid_answer"
	default:
		return "unavailable"
	}
}

func findDiagnosticResult(results []diagnosticResult, server netip.Addr, name DNSName, kind RRKind) (diagnosticResult, bool) {
	server = server.Unmap()
	for _, result := range results {
		if result.query.Server.Unmap() == server && result.query.Name.String() == name.String() && result.query.Kind == kind {
			return result, true
		}
	}
	return diagnosticResult{}, false
}

func diagnosticSuccessful(result diagnosticResult) bool {
	return result.err == nil && result.answer.Status == "NOERROR"
}

func diagnosticAuthoritativeResponse(result diagnosticResult) bool {
	return diagnosticSuccessful(result) && result.answer.Authoritative
}

func diagnosticAuthoritativeAnswer(result diagnosticResult, kind RRKind) bool {
	return diagnosticAuthoritativeResponse(result) && len(diagnosticValues(result.answer, result.query.Name, kind)) > 0
}

func diagnosticValues(answer diagnosticAnswer, owner DNSName, kind RRKind) []string {
	values := make([]string, 0)
	seen := map[string]struct{}{}
	for _, record := range answer.Records {
		if record.Owner.String() != owner.String() || record.Kind != kind {
			continue
		}
		if _, exists := seen[record.Value]; exists {
			continue
		}
		seen[record.Value] = struct{}{}
		values = append(values, record.Value)
	}
	sort.Strings(values)
	return values
}

func successfulResolverSets(results []diagnosticResult, resolvers []netip.Addr, name DNSName, kind RRKind) [][]string {
	sets := make([][]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		result, ok := findDiagnosticResult(results, resolver, name, kind)
		if ok && diagnosticSuccessful(result) {
			sets = append(sets, diagnosticValues(result.answer, name, kind))
		}
	}
	return sets
}

func successfulAuthoritativeSets(results []diagnosticResult, resolvers []netip.Addr, name DNSName, kind RRKind) [][]string {
	sets := make([][]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		result, ok := findDiagnosticResult(results, resolver, name, kind)
		if ok && diagnosticAuthoritativeResponse(result) {
			sets = append(sets, diagnosticValues(result.answer, name, kind))
		}
	}
	return sets
}

func diagnosticGlueConverged(results []diagnosticResult, resolvers []netip.Addr, nameservers []DNSName) bool {
	for _, name := range nameservers {
		observations := 0
		for _, resolver := range resolvers {
			addresses := []string{}
			for _, kind := range []RRKind{RR_A, RR_AAAA} {
				result, ok := findDiagnosticResult(results, resolver, name, kind)
				if ok && diagnosticSuccessful(result) {
					addresses = append(addresses, diagnosticValues(result.answer, name, kind)...)
				}
			}
			if len(addresses) > 0 {
				observations++
			}
		}
		if observations < 2 || observations != len(resolvers) {
			return false
		}
	}
	return true
}

func diagnosticSerials(results []diagnosticResult, name DNSName, authoritative bool) []uint64 {
	serials := make([]uint64, 0, len(results))
	for _, result := range results {
		if result.query.Name.String() != name.String() || result.query.Kind != RR_SOA {
			continue
		}
		serial, ok := diagnosticSerial(result, authoritative)
		if ok {
			serials = append(serials, serial)
		}
	}
	return serials
}

func diagnosticSerial(result diagnosticResult, authoritative bool) (uint64, bool) {
	if !diagnosticSuccessful(result) || authoritative && !result.answer.Authoritative {
		return 0, false
	}
	values := diagnosticValues(result.answer, result.query.Name, RR_SOA)
	if len(values) != 1 {
		return 0, false
	}
	fields := strings.Fields(values[0])
	if len(fields) != 7 {
		return 0, false
	}
	serial, err := strconv.ParseUint(fields[2], 10, 32)
	return serial, err == nil
}

func dnssecContinuity(zone DNSName, localKeys, publicKeys, dsRecords []string) bool {
	if len(localKeys) == 0 || len(publicKeys) == 0 || len(dsRecords) == 0 || !sameDiagnosticSet(localKeys, publicKeys) {
		return false
	}
	for _, key := range publicKeys {
		for _, record := range dsRecords {
			if dnskeyMatchesDS(zone, key, record) {
				return true
			}
		}
	}
	return false
}

func dnskeyMatchesDS(zone DNSName, key, record string) bool {
	keyFields := strings.Fields(key)
	dsFields := strings.Fields(record)
	if len(keyFields) != 4 || len(dsFields) != 4 || strconv.FormatUint(uint64(diagnosticDNSKEYTag(key)), 10) != dsFields[0] || keyFields[2] != dsFields[1] {
		return false
	}
	flags, firstErr := strconv.ParseUint(keyFields[0], 10, 16)
	protocol, secondErr := strconv.ParseUint(keyFields[1], 10, 8)
	algorithm, thirdErr := strconv.ParseUint(keyFields[2], 10, 8)
	digestType, fourthErr := strconv.ParseUint(dsFields[2], 10, 8)
	public, fifthErr := base64.StdEncoding.DecodeString(keyFields[3])
	if firstErr != nil || secondErr != nil || thirdErr != nil || fourthErr != nil || fifthErr != nil || len(public) == 0 {
		return false
	}
	wire := make([]byte, 0, len(zone.String())+len(public)+8)
	for _, label := range strings.Split(zone.String(), ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0, byte(flags>>8), byte(flags), byte(protocol), byte(algorithm))
	wire = append(wire, public...)
	var digest []byte
	switch digestType {
	case 1:
		sum := sha1.Sum(wire)
		digest = sum[:]
	case 2:
		sum := sha256.Sum256(wire)
		digest = sum[:]
	case 4:
		sum := sha512.Sum384(wire)
		digest = sum[:]
	default:
		return false
	}
	return strings.EqualFold(hex.EncodeToString(digest), dsFields[3])
}

func diagnosticDNSKEYTag(value string) uint16 {
	fields := strings.Fields(value)
	if len(fields) != 4 {
		return 0
	}
	flags, firstErr := strconv.ParseUint(fields[0], 10, 16)
	protocol, secondErr := strconv.ParseUint(fields[1], 10, 8)
	algorithm, thirdErr := strconv.ParseUint(fields[2], 10, 8)
	public, fourthErr := base64.StdEncoding.DecodeString(fields[3])
	if firstErr != nil || secondErr != nil || thirdErr != nil || fourthErr != nil || len(public) == 0 {
		return 0
	}
	wire := []byte{byte(flags >> 8), byte(flags), byte(protocol), byte(algorithm)}
	wire = append(wire, public...)
	var accumulator uint32
	for index, octet := range wire {
		if index&1 == 0 {
			accumulator += uint32(octet) << 8
		} else {
			accumulator += uint32(octet)
		}
	}
	accumulator += (accumulator >> 16) & 0xffff
	return uint16(accumulator & 0xffff)
}

func sameDiagnosticSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func allDiagnosticSetsEqual(sets [][]string) bool {
	if len(sets) == 0 {
		return false
	}
	for _, set := range sets[1:] {
		if !sameDiagnosticSet(sets[0], set) {
			return false
		}
	}
	return true
}

func allDiagnosticSetsEmpty(sets [][]string) bool {
	for _, set := range sets {
		if len(set) != 0 {
			return false
		}
	}
	return true
}

func allUint64Equal(values []uint64) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values[1:] {
		if value != values[0] {
			return false
		}
	}
	return true
}

func allStringsEqual(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values[1:] {
		if value != values[0] {
			return false
		}
	}
	return true
}

func aggregateDiagnosticState(findings []DiagnosticFinding) DiagnosticState {
	state := DiagnosticHealthy
	for _, finding := range findings {
		switch finding.State {
		case DiagnosticFailed:
			return DiagnosticFailed
		case DiagnosticDegraded:
			state = DiagnosticDegraded
		case DiagnosticIndeterminate:
			if state == DiagnosticHealthy {
				state = DiagnosticIndeterminate
			}
		}
	}
	return state
}

func digestDiagnosticEvidence(evidence []DiagnosticEvidence) string {
	keys := make([]string, 0, len(evidence))
	for _, item := range evidence {
		keys = append(keys, diagnosticEvidenceKey(item))
	}
	sort.Strings(keys)
	return digestDiagnosticStrings(keys)
}

func diagnosticEvidenceKey(item DiagnosticEvidence) string {
	flags := append([]string(nil), item.Flags...)
	values := append([]string(nil), item.Values...)
	sort.Strings(flags)
	sort.Strings(values)
	return strings.Join([]string{item.Resolver, item.Name, string(item.Kind), item.Status, strings.Join(flags, ","), strings.Join(values, "\x1f"), item.ErrorCode}, "\x00")
}

func digestDiagnosticReport(report DiagnosticReport) string {
	values := []string{string(report.ZoneID), report.TenantID, report.ZoneName, strconv.FormatUint(report.ExpectedGeneration, 10)}
	for _, finding := range report.Findings {
		values = append(values, string(finding.Kind)+"\x00"+string(finding.State)+"\x00"+finding.Code+"\x00"+finding.EvidenceDigest)
	}
	return digestDiagnosticStrings(values)
}

func digestDiagnosticStrings(values []string) string {
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}
