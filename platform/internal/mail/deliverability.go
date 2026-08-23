package mail

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxDeliverabilityResolvers   = 4
	maxDeliverabilityAddresses   = 8
	maxDeliverabilitySignals     = 8
	maxDeliverabilityValues      = 64
	maxDeliverabilityEvidence    = 128
	defaultDeliverabilityCheck   = 4 * time.Second
	defaultDeliverabilityOverall = 50 * time.Second
	maximumDeliverabilityCheck   = 10 * time.Second
	maximumDeliverabilityOverall = 2 * time.Minute
)

type DeliverabilityState string

const (
	DeliverabilityHealthy       DeliverabilityState = "healthy"
	DeliverabilityDegraded      DeliverabilityState = "degraded"
	DeliverabilityFailed        DeliverabilityState = "failed"
	DeliverabilityUnsupported   DeliverabilityState = "unsupported"
	DeliverabilityIndeterminate DeliverabilityState = "indeterminate"
)

type DeliverabilityFindingKind string

const (
	DeliverabilityForwardReverse DeliverabilityFindingKind = "forward_reverse_dns"
	DeliverabilityMXHELO         DeliverabilityFindingKind = "mx_helo_identity"
	DeliverabilitySPF            DeliverabilityFindingKind = "spf_record"
	DeliverabilityDKIM           DeliverabilityFindingKind = "dkim_record"
	DeliverabilityDMARC          DeliverabilityFindingKind = "dmarc_record"
	DeliverabilityTLS            DeliverabilityFindingKind = "tls_presentation"
	DeliverabilityRelayPolicy    DeliverabilityFindingKind = "authenticated_relay_policy"
	DeliverabilityReachability   DeliverabilityFindingKind = "public_port_reachability"
	DeliverabilityEnrichmentKind DeliverabilityFindingKind = "external_signals"
)

type DeliverabilityRequest struct {
	Domain            Domain       `json:"domain"`
	Hostname          string       `json:"hostname"`
	PublicResolvers   []netip.Addr `json:"public_resolvers"`
	EnrichmentSignals []string     `json:"enrichment_signals,omitempty"`
}

type DeliverabilityEvidence struct {
	Source     string    `json:"source"`
	Check      string    `json:"check"`
	Target     string    `json:"target"`
	Values     []string  `json:"values,omitempty"`
	ErrorCode  string    `json:"error_code,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type DeliverabilityFinding struct {
	Kind           DeliverabilityFindingKind `json:"kind"`
	State          DeliverabilityState       `json:"state"`
	Code           string                    `json:"code"`
	Evidence       []DeliverabilityEvidence  `json:"evidence"`
	EvidenceDigest string                    `json:"evidence_digest"`
	ObservedAt     time.Time                 `json:"observed_at"`
}

type DeliverabilityReport struct {
	DomainID       DomainID                `json:"domain_id"`
	TenantID       string                  `json:"tenant_id"`
	Domain         string                  `json:"domain"`
	Hostname       string                  `json:"hostname"`
	State          DeliverabilityState     `json:"state"`
	Findings       []DeliverabilityFinding `json:"findings"`
	EvidenceDigest string                  `json:"evidence_digest"`
	ObservedAt     time.Time               `json:"observed_at"`
}

type DeliverabilityEnrichmentRequest struct {
	Name      string       `json:"name"`
	Domain    string       `json:"domain"`
	Hostname  string       `json:"hostname"`
	Addresses []netip.Addr `json:"addresses"`
}

type DeliverabilitySignal struct {
	Name       string              `json:"name"`
	State      DeliverabilityState `json:"state"`
	Code       string              `json:"code"`
	Values     []string            `json:"values,omitempty"`
	ObservedAt time.Time           `json:"observed_at"`
}

type Enrichment interface {
	Check(context.Context, DeliverabilityEnrichmentRequest) (DeliverabilitySignal, error)
}

type DeliverabilityLocalPolicyRequest struct {
	Hostname string `json:"hostname"`
}

type DeliverabilityLocalPolicyEvidence struct {
	Hostname              string       `json:"hostname"`
	SASLEnabled           bool         `json:"sasl_enabled"`
	RecipientRestrictions []string     `json:"recipient_restrictions"`
	RelayRestrictions     []string     `json:"relay_restrictions"`
	TrustedNetworks       []netip.Prefix `json:"trusted_networks"`
	Proven                bool         `json:"proven"`
	Safe                  bool         `json:"safe"`
	ObservedAt            time.Time    `json:"observed_at"`
}

type LocalPolicyProbe interface {
	Probe(context.Context, DeliverabilityLocalPolicyRequest) (DeliverabilityLocalPolicyEvidence, error)
}

type deliverabilityDNSKind string

const (
	deliverabilityA    deliverabilityDNSKind = "A"
	deliverabilityAAAA deliverabilityDNSKind = "AAAA"
	deliverabilityMX   deliverabilityDNSKind = "MX"
	deliverabilityPTR  deliverabilityDNSKind = "PTR"
	deliverabilityTXT  deliverabilityDNSKind = "TXT"
)

type deliverabilityDNSQuery struct {
	Resolver netip.Addr
	Name     string
	Kind     deliverabilityDNSKind
}

type deliverabilityDNSAnswer struct {
	Status     string
	Values     []string
	ObservedAt time.Time
}

type Resolver interface {
	Resolve(context.Context, deliverabilityDNSQuery) (deliverabilityDNSAnswer, error)
}

type DeliverabilityProtocol string

const (
	DeliverabilitySMTP       DeliverabilityProtocol = "smtp"
	DeliverabilitySubmission DeliverabilityProtocol = "submission_starttls"
	DeliverabilitySMTPS      DeliverabilityProtocol = "smtp_implicit_tls"
	DeliverabilityIMAPS      DeliverabilityProtocol = "imap_implicit_tls"
)

type deliverabilityProtocolEndpoint struct {
	Protocol   DeliverabilityProtocol
	Address    netip.Addr
	ServerName string
}

type deliverabilityProtocolEvidence struct {
	Reachable         bool
	TLSPresented      bool
	TLSVersion        uint16
	CertificateDigest string
	CertificateExpiry time.Time
	GreetingName      string
	Capabilities      []string
	ObservedAt        time.Time
}

type ProtocolProbe interface {
	Probe(context.Context, deliverabilityProtocolEndpoint) (deliverabilityProtocolEvidence, error)
}

type DeliverabilityService struct {
	Resolver        Resolver
	ProtocolProbe   ProtocolProbe
	LocalPolicy     LocalPolicyProbe
	Enrichment      Enrichment
	PerCheckTimeout time.Duration
	OverallTimeout  time.Duration
	Now             func() time.Time
}

type deliverabilityDNSResult struct {
	query  deliverabilityDNSQuery
	answer deliverabilityDNSAnswer
	err    error
}

type deliverabilityProtocolResult struct {
	endpoint deliverabilityProtocolEndpoint
	evidence deliverabilityProtocolEvidence
	err      error
}

type deliverabilitySignalResult struct {
	name   string
	signal DeliverabilitySignal
	err    error
}

func (service DeliverabilityService) Diagnose(ctx context.Context, request DeliverabilityRequest) (DeliverabilityReport, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(request.Domain.Name), "."))
	hostname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(request.Hostname), "."))
	report := DeliverabilityReport{DomainID: request.Domain.ID, TenantID: request.Domain.Tenant, Domain: domain, Hostname: hostname}
	if ctx == nil || service.Resolver == nil || service.ProtocolProbe == nil || service.LocalPolicy == nil || validateDeliverabilityRequest(request, domain, hostname) != nil {
		return report, ErrInvalidCommand
	}
	perCheck, overall := deliverabilityDeadlines(service.PerCheckTimeout, service.OverallTimeout)
	overallContext, cancel := context.WithTimeout(ctx, overall)
	defer cancel()

	dnsQueries := make([]deliverabilityDNSQuery, 0, len(request.PublicResolvers)*5)
	for _, resolver := range request.PublicResolvers {
		for _, query := range []struct {
			name string
			kind deliverabilityDNSKind
		}{{hostname, deliverabilityA}, {hostname, deliverabilityAAAA}, {domain, deliverabilityMX}, {domain, deliverabilityTXT}, {"_dmarc." + domain, deliverabilityTXT}} {
			dnsQueries = append(dnsQueries, deliverabilityDNSQuery{Resolver: resolver.Unmap(), Name: query.name, Kind: query.kind})
		}
		if request.Domain.DKIM.Enabled {
			dnsQueries = append(dnsQueries, deliverabilityDNSQuery{Resolver: resolver.Unmap(), Name: strings.ToLower(request.Domain.DKIM.Selector) + "._domainkey." + domain, Kind: deliverabilityTXT})
		}
	}
	dnsResults := service.resolveDNS(overallContext, perCheck, dnsQueries)
	addresses, addressConsensus := deliverabilityForwardAddresses(request.PublicResolvers, hostname, dnsResults)
	reverseQueries := make([]deliverabilityDNSQuery, 0, len(addresses)*len(request.PublicResolvers))
	for _, resolver := range request.PublicResolvers {
		for _, address := range addresses {
			reverseQueries = append(reverseQueries, deliverabilityDNSQuery{Resolver: resolver.Unmap(), Name: deliverabilityReverseName(address), Kind: deliverabilityPTR})
		}
	}
	reverseResults := service.resolveDNS(overallContext, perCheck, reverseQueries)
	dnsResults = append(dnsResults, reverseResults...)

	protocolEndpoints := make([]deliverabilityProtocolEndpoint, 0, len(addresses)*4)
	for _, address := range addresses {
		if !deliverabilityPublicAddress(address) {
			continue
		}
		for _, protocol := range []DeliverabilityProtocol{DeliverabilitySMTP, DeliverabilitySubmission, DeliverabilitySMTPS, DeliverabilityIMAPS} {
			protocolEndpoints = append(protocolEndpoints, deliverabilityProtocolEndpoint{Protocol: protocol, Address: address, ServerName: hostname})
		}
	}
	protocolResults := service.probeProtocols(overallContext, perCheck, protocolEndpoints)

	policyContext, policyCancel := context.WithTimeout(overallContext, perCheck)
	policy, policyErr := service.LocalPolicy.Probe(policyContext, DeliverabilityLocalPolicyRequest{Hostname: hostname})
	policyCancel()
	if policy.ObservedAt.IsZero() {
		policy.ObservedAt = deliverabilityNow(service.Now)
	}

	signalResults := service.enrich(overallContext, perCheck, request, domain, hostname, addresses)
	now := deliverabilityNow(service.Now)
	findings := []DeliverabilityFinding{
		evaluateDeliverabilityForwardReverse(request, hostname, addresses, addressConsensus, dnsResults, now),
		evaluateDeliverabilityMXHELO(request, domain, hostname, addresses, dnsResults, protocolResults, now),
		evaluateDeliverabilitySPF(request, domain, dnsResults, now),
		evaluateDeliverabilityDKIM(request, domain, dnsResults, now),
		evaluateDeliverabilityDMARC(request, domain, dnsResults, now),
		evaluateDeliverabilityTLS(addresses, protocolResults, now),
		evaluateDeliverabilityRelay(policy, policyErr, now),
		evaluateDeliverabilityReachability(addresses, protocolResults, now),
		evaluateDeliverabilityEnrichment(request, service.Enrichment, signalResults, now),
	}
	for index := range findings {
		findings[index].EvidenceDigest = digestDeliverabilityEvidence(findings[index].Evidence)
	}
	report.Findings = findings
	report.State = aggregateDeliverabilityState(findings)
	report.EvidenceDigest = digestDeliverabilityReport(report)
	report.ObservedAt = now
	return report, nil
}

func validateDeliverabilityRequest(request DeliverabilityRequest, domain, hostname string) error {
	if request.Domain.ID == "" || !validOpaque(request.Domain.Tenant) || request.Domain.Policy == "" || !validHostname(domain) || request.Domain.Name != domain || !validHostname(hostname) || len(request.PublicResolvers) == 0 || len(request.PublicResolvers) > maxDeliverabilityResolvers || len(request.EnrichmentSignals) > maxDeliverabilitySignals {
		return ErrInvalidCommand
	}
	if request.Domain.DKIM.Enabled && (!validDKIMSelector(request.Domain.DKIM.Selector) || len(request.Domain.DKIM.PublicKey) < 32 || len(request.Domain.DKIM.PublicKey) > 16384) {
		return ErrInvalidCommand
	}
	seenResolvers := map[netip.Addr]struct{}{}
	for _, resolver := range request.PublicResolvers {
		resolver = resolver.Unmap()
		if !deliverabilityPublicAddress(resolver) {
			return ErrInvalidCommand
		}
		if _, exists := seenResolvers[resolver]; exists {
			return ErrInvalidCommand
		}
		seenResolvers[resolver] = struct{}{}
	}
	seenSignals := map[string]struct{}{}
	for _, name := range request.EnrichmentSignals {
		if !validDeliverabilitySignalName(name) {
			return ErrInvalidCommand
		}
		if _, exists := seenSignals[name]; exists {
			return ErrInvalidCommand
		}
		seenSignals[name] = struct{}{}
	}
	return nil
}

func validDeliverabilitySignalName(value string) bool {
	if len(value) < 1 || len(value) > 64 || strings.ToLower(value) != value {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character == '.' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z') {
			return false
		}
	}
	return true
}

func deliverabilityPublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsValid() && address.Zone() == "" && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsMulticast() && !address.IsUnspecified()
}

func deliverabilityReverseName(address netip.Addr) string {
	address = address.Unmap()
	if address.Is4() {
		octets := address.As4()
		return strconv.Itoa(int(octets[3])) + "." + strconv.Itoa(int(octets[2])) + "." + strconv.Itoa(int(octets[1])) + "." + strconv.Itoa(int(octets[0])) + ".in-addr.arpa"
	}
	octets := address.As16()
	const hexadecimal = "0123456789abcdef"
	var out strings.Builder
	for index := len(octets) - 1; index >= 0; index-- {
		out.WriteByte(hexadecimal[octets[index]&0x0f])
		out.WriteByte('.')
		out.WriteByte(hexadecimal[octets[index]>>4])
		out.WriteByte('.')
	}
	out.WriteString("ip6.arpa")
	return out.String()
}

func deliverabilityDeadlines(perCheck, overall time.Duration) (time.Duration, time.Duration) {
	if perCheck <= 0 || perCheck > maximumDeliverabilityCheck {
		perCheck = defaultDeliverabilityCheck
	}
	if overall <= 0 || overall > maximumDeliverabilityOverall {
		overall = defaultDeliverabilityOverall
	}
	return perCheck, overall
}

func deliverabilityNow(now func() time.Time) time.Time {
	if now == nil {
		return time.Now().UTC()
	}
	return now().UTC()
}

func (service DeliverabilityService) resolveDNS(ctx context.Context, timeout time.Duration, queries []deliverabilityDNSQuery) []deliverabilityDNSResult {
	results := make([]deliverabilityDNSResult, len(queries))
	for index, query := range queries {
		results[index].query = query
		if ctx.Err() != nil {
			results[index].err = ctx.Err()
			results[index].answer.ObservedAt = deliverabilityNow(service.Now)
			continue
		}
		queryContext, cancel := context.WithTimeout(ctx, timeout)
		results[index].answer, results[index].err = service.Resolver.Resolve(queryContext, query)
		cancel()
		if results[index].answer.ObservedAt.IsZero() {
			results[index].answer.ObservedAt = deliverabilityNow(service.Now)
		}
	}
	return results
}

func (service DeliverabilityService) probeProtocols(ctx context.Context, timeout time.Duration, endpoints []deliverabilityProtocolEndpoint) []deliverabilityProtocolResult {
	results := make([]deliverabilityProtocolResult, len(endpoints))
	for index, endpoint := range endpoints {
		results[index].endpoint = endpoint
		if ctx.Err() != nil {
			results[index].err = ctx.Err()
			results[index].evidence.ObservedAt = deliverabilityNow(service.Now)
			continue
		}
		probeContext, cancel := context.WithTimeout(ctx, timeout)
		results[index].evidence, results[index].err = service.ProtocolProbe.Probe(probeContext, endpoint)
		cancel()
		if results[index].evidence.ObservedAt.IsZero() {
			results[index].evidence.ObservedAt = deliverabilityNow(service.Now)
		}
	}
	return results
}

func (service DeliverabilityService) enrich(ctx context.Context, timeout time.Duration, request DeliverabilityRequest, domain, hostname string, addresses []netip.Addr) []deliverabilitySignalResult {
	if service.Enrichment == nil {
		return nil
	}
	results := make([]deliverabilitySignalResult, len(request.EnrichmentSignals))
	for index, name := range request.EnrichmentSignals {
		results[index].name = name
		if ctx.Err() != nil {
			results[index].err = ctx.Err()
			continue
		}
		checkContext, cancel := context.WithTimeout(ctx, timeout)
		results[index].signal, results[index].err = service.Enrichment.Check(checkContext, DeliverabilityEnrichmentRequest{Name: name, Domain: domain, Hostname: hostname, Addresses: append([]netip.Addr(nil), addresses...)})
		cancel()
		if results[index].err == nil && !validDeliverabilitySignal(results[index].signal, name) {
			results[index].signal = DeliverabilitySignal{}
			results[index].err = ErrInvalidReceipt
		}
	}
	return results
}

func validDeliverabilitySignal(signal DeliverabilitySignal, expected string) bool {
	if signal.Name != expected || !validDeliverabilityState(signal.State) || !validDeliverabilitySignalName(signal.Code) || signal.ObservedAt.IsZero() || len(signal.Values) > 16 {
		return false
	}
	for _, value := range signal.Values {
		if len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	return true
}

func validDeliverabilityState(state DeliverabilityState) bool {
	switch state {
	case DeliverabilityHealthy, DeliverabilityDegraded, DeliverabilityFailed, DeliverabilityUnsupported, DeliverabilityIndeterminate:
		return true
	default:
		return false
	}
}

func deliverabilityForwardAddresses(resolvers []netip.Addr, hostname string, results []deliverabilityDNSResult) ([]netip.Addr, bool) {
	sets := make([][]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		values := []string{}
		complete := true
		for _, kind := range []deliverabilityDNSKind{deliverabilityA, deliverabilityAAAA} {
			result, ok := findDeliverabilityDNS(results, resolver, hostname, kind)
			if !ok || !deliverabilityDNSSuccess(result) {
				complete = false
				break
			}
			values = append(values, result.answer.Values...)
		}
		if complete {
			sort.Strings(values)
			sets = append(sets, compactDeliverabilityStrings(values))
		}
	}
	consensus := len(sets) >= 2 && len(sets) == len(resolvers) && allDeliverabilitySetsEqual(sets) && len(sets[0]) > 0
	if !consensus {
		return nil, false
	}
	addresses := make([]netip.Addr, 0, len(sets[0]))
	for _, value := range sets[0] {
		address, err := netip.ParseAddr(value)
		if err != nil || !deliverabilityPublicAddress(address) {
			return nil, false
		}
		addresses = append(addresses, address.Unmap())
	}
	if len(addresses) > maxDeliverabilityAddresses {
		return nil, false
	}
	sort.Slice(addresses, func(left, right int) bool { return addresses[left].Compare(addresses[right]) < 0 })
	return addresses, true
}

func evaluateDeliverabilityForwardReverse(request DeliverabilityRequest, hostname string, addresses []netip.Addr, consensus bool, results []deliverabilityDNSResult, now time.Time) DeliverabilityFinding {
	state, code := DeliverabilityIndeterminate, "forward_dns_insufficient_resolvers"
	if len(request.PublicResolvers) >= 2 {
		if !consensus {
			state, code = DeliverabilityFailed, "forward_dns_not_public_or_divergent"
		} else if deliverabilityReverseAgrees(request.PublicResolvers, hostname, addresses, results) {
			state, code = DeliverabilityHealthy, "forward_reverse_agree"
		} else {
			state, code = DeliverabilityDegraded, "reverse_dns_missing_or_divergent"
		}
	}
	return newDeliverabilityFinding(DeliverabilityForwardReverse, state, code, dnsDeliverabilityEvidence(results, deliverabilityA, deliverabilityAAAA, deliverabilityPTR), now)
}

func deliverabilityReverseAgrees(resolvers []netip.Addr, hostname string, addresses []netip.Addr, results []deliverabilityDNSResult) bool {
	if len(resolvers) < 2 || len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		sets := make([][]string, 0, len(resolvers))
		name := deliverabilityReverseName(address)
		for _, resolver := range resolvers {
			result, ok := findDeliverabilityDNS(results, resolver, name, deliverabilityPTR)
			if !ok || !deliverabilityDNSSuccess(result) || len(result.answer.Values) == 0 {
				return false
			}
			sets = append(sets, result.answer.Values)
		}
		if !allDeliverabilitySetsEqual(sets) || !containsDeliverabilityString(sets[0], hostname) {
			return false
		}
	}
	return true
}

func evaluateDeliverabilityMXHELO(request DeliverabilityRequest, domain, hostname string, addresses []netip.Addr, dnsResults []deliverabilityDNSResult, protocolResults []deliverabilityProtocolResult, now time.Time) DeliverabilityFinding {
	mxSets := deliverabilityResolverSets(request.PublicResolvers, domain, deliverabilityMX, dnsResults)
	mxHealthy := len(mxSets) >= 2 && len(mxSets) == len(request.PublicResolvers) && allDeliverabilitySetsEqual(mxSets) && mxContainsHostname(mxSets[0], hostname)
	heloHealthy := len(addresses) > 0
	heloObserved := false
	for _, address := range addresses {
		result, ok := findDeliverabilityProtocol(protocolResults, address, DeliverabilitySMTP)
		if !ok || result.err != nil || !result.evidence.Reachable {
			heloHealthy = false
			continue
		}
		heloObserved = true
		if result.evidence.GreetingName != hostname {
			heloHealthy = false
		}
	}
	state, code := DeliverabilityIndeterminate, "mx_helo_insufficient_evidence"
	if len(request.PublicResolvers) >= 2 {
		switch {
		case mxHealthy && heloHealthy && heloObserved:
			state, code = DeliverabilityHealthy, "mx_and_helo_match"
		case len(mxSets) == 0 || len(mxSets[0]) == 0 || !heloObserved:
			state, code = DeliverabilityFailed, "mx_or_helo_unavailable"
		default:
			state, code = DeliverabilityDegraded, "mx_or_helo_mismatch"
		}
	}
	evidence := append(dnsDeliverabilityEvidence(dnsResults, deliverabilityMX), protocolDeliverabilityEvidence(protocolResults, DeliverabilitySMTP)...)
	return newDeliverabilityFinding(DeliverabilityMXHELO, state, code, evidence, now)
}

func evaluateDeliverabilitySPF(request DeliverabilityRequest, domain string, results []deliverabilityDNSResult, now time.Time) DeliverabilityFinding {
	return evaluateDeliverabilityTXT(request.PublicResolvers, domain, "v=spf1", DeliverabilitySPF, "spf", results, validSPFRecord, now)
}

func evaluateDeliverabilityDKIM(request DeliverabilityRequest, domain string, results []deliverabilityDNSResult, now time.Time) DeliverabilityFinding {
	if !request.Domain.DKIM.Enabled {
		return newDeliverabilityFinding(DeliverabilityDKIM, DeliverabilityUnsupported, "dkim_not_configured", nil, now)
	}
	name := strings.ToLower(request.Domain.DKIM.Selector) + "._domainkey." + domain
	validator := func(value string) bool { return validDKIMRecord(value, request.Domain.DKIM.PublicKey) }
	return evaluateDeliverabilityTXT(request.PublicResolvers, name, "v=dkim1", DeliverabilityDKIM, "dkim", results, validator, now)
}

func evaluateDeliverabilityDMARC(request DeliverabilityRequest, domain string, results []deliverabilityDNSResult, now time.Time) DeliverabilityFinding {
	validator := func(value string) bool {
		valid, _ := validDMARCRecord(value)
		return valid
	}
	finding := evaluateDeliverabilityTXT(request.PublicResolvers, "_dmarc."+domain, "v=dmarc1", DeliverabilityDMARC, "dmarc", results, validator, now)
	if finding.State == DeliverabilityHealthy {
		sets := deliverabilityResolverSets(request.PublicResolvers, "_dmarc."+domain, deliverabilityTXT, results)
		for _, value := range prefixedDeliverabilityValues(sets[0], "v=dmarc1") {
			_, enforcing := validDMARCRecord(value)
			if !enforcing {
				finding.State, finding.Code = DeliverabilityDegraded, "dmarc_monitoring_only"
			}
		}
	}
	return finding
}

func evaluateDeliverabilityTXT(resolvers []netip.Addr, name, prefix string, kind DeliverabilityFindingKind, label string, results []deliverabilityDNSResult, validator func(string) bool, now time.Time) DeliverabilityFinding {
	sets := deliverabilityResolverSets(resolvers, name, deliverabilityTXT, results)
	state, code := DeliverabilityIndeterminate, label+"_insufficient_resolvers"
	if len(resolvers) >= 2 {
		if len(sets) != len(resolvers) {
			state, code = DeliverabilityIndeterminate, label+"_unobservable"
		} else if !allDeliverabilitySetsEqual(sets) {
			state, code = DeliverabilityDegraded, label+"_divergent"
		} else {
			records := prefixedDeliverabilityValues(sets[0], prefix)
			if len(records) == 0 {
				state, code = DeliverabilityFailed, label+"_missing"
			} else if len(records) != 1 || !validator(records[0]) {
				state, code = DeliverabilityFailed, label+"_invalid"
			} else {
				state, code = DeliverabilityHealthy, label+"_valid"
			}
		}
	}
	return newDeliverabilityFinding(kind, state, code, dnsDeliverabilityEvidenceForName(results, name, deliverabilityTXT), now)
}

func validSPFRecord(value string) bool {
	if len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	fields := strings.Fields(strings.ToLower(value))
	if len(fields) < 2 || fields[0] != "v=spf1" || len(fields) > 64 {
		return false
	}
	last := fields[len(fields)-1]
	if last != "-all" && last != "~all" && last != "?all" {
		return false
	}
	for _, field := range fields[1 : len(fields)-1] {
		if len(field) > 255 || strings.TrimLeft(field, "+-~?") == "all" {
			return false
		}
	}
	return true
}

func validDKIMRecord(value, configured string) bool {
	tags, ok := deliverabilityTagMap(value, 16)
	if !ok || !strings.EqualFold(tags["v"], "DKIM1") || tags["p"] == "" || tags["k"] != "" && !strings.EqualFold(tags["k"], "rsa") {
		return false
	}
	public, err := base64.StdEncoding.DecodeString(tags["p"])
	if err != nil || len(public) < 256 || len(public) > 8192 {
		return false
	}
	configuredValue := strings.TrimSpace(configured)
	if tagsValue, parsed := deliverabilityTagMap(configuredValue, 8); parsed && tagsValue["p"] != "" {
		configuredValue = tagsValue["p"]
	}
	return configuredValue == tags["p"]
}

func validDMARCRecord(value string) (bool, bool) {
	tags, ok := deliverabilityTagMap(value, 32)
	if !ok || !strings.EqualFold(tags["v"], "DMARC1") {
		return false, false
	}
	policy := strings.ToLower(tags["p"])
	if policy != "none" && policy != "quarantine" && policy != "reject" {
		return false, false
	}
	return true, policy == "quarantine" || policy == "reject"
}

func deliverabilityTagMap(value string, limit int) (map[string]string, bool) {
	if len(value) == 0 || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
		return nil, false
	}
	tags := map[string]string{}
	parts := strings.Split(value, ";")
	if len(parts) > limit {
		return nil, false
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, "=", 2)
		if len(fields) != 2 {
			return nil, false
		}
		key := strings.ToLower(strings.TrimSpace(fields[0]))
		entry := strings.TrimSpace(fields[1])
		if key == "" || len(key) > 32 || len(entry) > 2048 {
			return nil, false
		}
		if _, exists := tags[key]; exists {
			return nil, false
		}
		tags[key] = entry
	}
	return tags, true
}

func evaluateDeliverabilityTLS(addresses []netip.Addr, results []deliverabilityProtocolResult, now time.Time) DeliverabilityFinding {
	total, valid := 0, 0
	for _, address := range addresses {
		for _, protocol := range []DeliverabilityProtocol{DeliverabilitySubmission, DeliverabilitySMTPS, DeliverabilityIMAPS} {
			total++
			result, ok := findDeliverabilityProtocol(results, address, protocol)
			if ok && result.err == nil && result.evidence.TLSPresented && result.evidence.TLSVersion >= 0x0303 && len(result.evidence.CertificateDigest) == 64 && result.evidence.CertificateExpiry.After(now) {
				valid++
			}
		}
	}
	state, code := DeliverabilityIndeterminate, "tls_unobservable"
	if total > 0 {
		switch {
		case valid == total:
			state, code = DeliverabilityHealthy, "tls_presentations_valid"
		case valid == 0:
			state, code = DeliverabilityFailed, "tls_presentations_failed"
		default:
			state, code = DeliverabilityDegraded, "tls_presentations_partial"
		}
	}
	return newDeliverabilityFinding(DeliverabilityTLS, state, code, protocolDeliverabilityEvidence(results, DeliverabilitySubmission, DeliverabilitySMTPS, DeliverabilityIMAPS), now)
}

func evaluateDeliverabilityRelay(policy DeliverabilityLocalPolicyEvidence, err error, now time.Time) DeliverabilityFinding {
	evidence := policyDeliverabilityEvidence(policy, err)
	if err != nil || !policy.Proven {
		return newDeliverabilityFinding(DeliverabilityRelayPolicy, DeliverabilityIndeterminate, "relay_policy_unproven", evidence, now)
	}
	if !policy.Safe {
		return newDeliverabilityFinding(DeliverabilityRelayPolicy, DeliverabilityFailed, "relay_policy_unsafe", evidence, now)
	}
	return newDeliverabilityFinding(DeliverabilityRelayPolicy, DeliverabilityHealthy, "authenticated_relay_enforced", evidence, now)
}

func evaluateDeliverabilityReachability(addresses []netip.Addr, results []deliverabilityProtocolResult, now time.Time) DeliverabilityFinding {
	total, reachable := len(addresses)*4, 0
	for _, result := range results {
		if result.evidence.Reachable {
			reachable++
		}
	}
	state, code := DeliverabilityIndeterminate, "ports_unobservable"
	if total > 0 {
		switch {
		case reachable == total:
			state, code = DeliverabilityHealthy, "public_ports_reachable"
		case reachable == 0:
			state, code = DeliverabilityFailed, "public_ports_unreachable"
		default:
			state, code = DeliverabilityDegraded, "public_ports_partially_reachable"
		}
	}
	return newDeliverabilityFinding(DeliverabilityReachability, state, code, protocolDeliverabilityEvidence(results, DeliverabilitySMTP, DeliverabilitySubmission, DeliverabilitySMTPS, DeliverabilityIMAPS), now)
}

func evaluateDeliverabilityEnrichment(request DeliverabilityRequest, enrichment Enrichment, results []deliverabilitySignalResult, now time.Time) DeliverabilityFinding {
	if enrichment == nil || len(request.EnrichmentSignals) == 0 {
		return newDeliverabilityFinding(DeliverabilityEnrichmentKind, DeliverabilityUnsupported, "enrichment_not_configured", nil, now)
	}
	state, code := DeliverabilityHealthy, "enrichment_clear"
	complete := 0
	for _, result := range results {
		if result.err != nil {
			state, code = DeliverabilityIndeterminate, "enrichment_unproven"
			continue
		}
		complete++
		switch result.signal.State {
		case DeliverabilityFailed:
			state, code = DeliverabilityFailed, "enrichment_failure"
		case DeliverabilityDegraded:
			if state != DeliverabilityFailed {
				state, code = DeliverabilityDegraded, "enrichment_warning"
			}
		case DeliverabilityIndeterminate:
			if state == DeliverabilityHealthy {
				state, code = DeliverabilityIndeterminate, "enrichment_unproven"
			}
		case DeliverabilityUnsupported:
			if state == DeliverabilityHealthy {
				state, code = DeliverabilityUnsupported, "enrichment_unsupported"
			}
		}
	}
	if complete != len(request.EnrichmentSignals) && state == DeliverabilityHealthy {
		state, code = DeliverabilityIndeterminate, "enrichment_unproven"
	}
	return newDeliverabilityFinding(DeliverabilityEnrichmentKind, state, code, signalDeliverabilityEvidence(results, now), now)
}

func deliverabilityResolverSets(resolvers []netip.Addr, name string, kind deliverabilityDNSKind, results []deliverabilityDNSResult) [][]string {
	sets := make([][]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		result, ok := findDeliverabilityDNS(results, resolver, name, kind)
		if ok && deliverabilityDNSSuccess(result) {
			sets = append(sets, result.answer.Values)
		}
	}
	return sets
}

func findDeliverabilityDNS(results []deliverabilityDNSResult, resolver netip.Addr, name string, kind deliverabilityDNSKind) (deliverabilityDNSResult, bool) {
	for _, result := range results {
		if result.query.Resolver.Unmap() == resolver.Unmap() && result.query.Name == name && result.query.Kind == kind {
			return result, true
		}
	}
	return deliverabilityDNSResult{}, false
}

func deliverabilityDNSSuccess(result deliverabilityDNSResult) bool {
	return result.err == nil && result.answer.Status == "NOERROR"
}

func findDeliverabilityProtocol(results []deliverabilityProtocolResult, address netip.Addr, protocol DeliverabilityProtocol) (deliverabilityProtocolResult, bool) {
	for _, result := range results {
		if result.endpoint.Address.Unmap() == address.Unmap() && result.endpoint.Protocol == protocol {
			return result, true
		}
	}
	return deliverabilityProtocolResult{}, false
}

func prefixedDeliverabilityValues(values []string, prefix string) []string {
	result := []string{}
	prefix = strings.ToLower(prefix)
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), prefix) {
			result = append(result, value)
		}
	}
	return result
}

func mxContainsHostname(values []string, hostname string) bool {
	for _, value := range values {
		fields := strings.Fields(value)
		if len(fields) == 2 && fields[1] == hostname {
			return true
		}
	}
	return false
}

func containsDeliverabilityString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func compactDeliverabilityStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func allDeliverabilitySetsEqual(sets [][]string) bool {
	if len(sets) == 0 {
		return false
	}
	for _, set := range sets {
		if len(set) != len(sets[0]) {
			return false
		}
		for index := range set {
			if set[index] != sets[0][index] {
				return false
			}
		}
	}
	return true
}

func newDeliverabilityFinding(kind DeliverabilityFindingKind, state DeliverabilityState, code string, evidence []DeliverabilityEvidence, now time.Time) DeliverabilityFinding {
	if len(evidence) > maxDeliverabilityEvidence {
		evidence = evidence[:maxDeliverabilityEvidence]
	}
	return DeliverabilityFinding{Kind: kind, State: state, Code: code, Evidence: evidence, ObservedAt: now}
}

func dnsDeliverabilityEvidence(results []deliverabilityDNSResult, kinds ...deliverabilityDNSKind) []DeliverabilityEvidence {
	allowed := map[deliverabilityDNSKind]bool{}
	for _, kind := range kinds {
		allowed[kind] = true
	}
	evidence := []DeliverabilityEvidence{}
	for _, result := range results {
		if !allowed[result.query.Kind] {
			continue
		}
		item := DeliverabilityEvidence{Source: "dns:" + result.query.Resolver.String(), Check: string(result.query.Kind), Target: result.query.Name, ObservedAt: result.answer.ObservedAt}
		if result.err != nil {
			item.ErrorCode = deliverabilityErrorCode(result.err)
		} else {
			item.Values = append([]string{result.answer.Status}, result.answer.Values...)
		}
		evidence = append(evidence, item)
	}
	return sortDeliverabilityEvidence(evidence)
}

func dnsDeliverabilityEvidenceForName(results []deliverabilityDNSResult, name string, kind deliverabilityDNSKind) []DeliverabilityEvidence {
	filtered := []deliverabilityDNSResult{}
	for _, result := range results {
		if result.query.Name == name && result.query.Kind == kind {
			filtered = append(filtered, result)
		}
	}
	return dnsDeliverabilityEvidence(filtered, kind)
}

func protocolDeliverabilityEvidence(results []deliverabilityProtocolResult, protocols ...DeliverabilityProtocol) []DeliverabilityEvidence {
	allowed := map[DeliverabilityProtocol]bool{}
	for _, protocol := range protocols {
		allowed[protocol] = true
	}
	evidence := []DeliverabilityEvidence{}
	for _, result := range results {
		if !allowed[result.endpoint.Protocol] {
			continue
		}
		item := DeliverabilityEvidence{Source: "protocol", Check: string(result.endpoint.Protocol), Target: result.endpoint.Address.String(), ObservedAt: result.evidence.ObservedAt}
		item.Values = []string{"reachable=" + strconv.FormatBool(result.evidence.Reachable)}
		if result.evidence.TLSPresented {
			item.Values = append(item.Values, "tls_version="+strconv.FormatUint(uint64(result.evidence.TLSVersion), 10), "certificate_sha256="+result.evidence.CertificateDigest, "certificate_expiry="+result.evidence.CertificateExpiry.UTC().Format(time.RFC3339))
		}
		if result.evidence.GreetingName != "" {
			item.Values = append(item.Values, "greeting="+result.evidence.GreetingName)
		}
		for _, capability := range result.evidence.Capabilities {
			item.Values = append(item.Values, "capability="+capability)
		}
		if result.err != nil {
			item.ErrorCode = deliverabilityErrorCode(result.err)
		}
		evidence = append(evidence, item)
	}
	return sortDeliverabilityEvidence(evidence)
}

func policyDeliverabilityEvidence(policy DeliverabilityLocalPolicyEvidence, err error) []DeliverabilityEvidence {
	item := DeliverabilityEvidence{Source: "local_postfix", Check: "relay_policy", Target: policy.Hostname, ObservedAt: policy.ObservedAt, Values: []string{"proven=" + strconv.FormatBool(policy.Proven), "safe=" + strconv.FormatBool(policy.Safe), "sasl_enabled=" + strconv.FormatBool(policy.SASLEnabled)}}
	item.Values = append(item.Values, policy.RecipientRestrictions...)
	item.Values = append(item.Values, policy.RelayRestrictions...)
	for _, network := range policy.TrustedNetworks {
		item.Values = append(item.Values, network.String())
	}
	if err != nil {
		item.ErrorCode = deliverabilityErrorCode(err)
	}
	return sortDeliverabilityEvidence([]DeliverabilityEvidence{item})
}

func signalDeliverabilityEvidence(results []deliverabilitySignalResult, now time.Time) []DeliverabilityEvidence {
	evidence := make([]DeliverabilityEvidence, 0, len(results))
	for _, result := range results {
		item := DeliverabilityEvidence{Source: "enrichment", Check: result.name, Target: result.name, ObservedAt: result.signal.ObservedAt}
		if item.ObservedAt.IsZero() {
			item.ObservedAt = now
		}
		if result.err != nil {
			item.ErrorCode = deliverabilityErrorCode(result.err)
		} else {
			item.Values = append([]string{string(result.signal.State), result.signal.Code}, result.signal.Values...)
		}
		evidence = append(evidence, item)
	}
	return sortDeliverabilityEvidence(evidence)
}

func sortDeliverabilityEvidence(evidence []DeliverabilityEvidence) []DeliverabilityEvidence {
	for index := range evidence {
		if len(evidence[index].Values) > maxDeliverabilityValues {
			evidence[index].Values = evidence[index].Values[:maxDeliverabilityValues]
		}
		sort.Strings(evidence[index].Values)
	}
	sort.Slice(evidence, func(left, right int) bool { return deliverabilityEvidenceKey(evidence[left]) < deliverabilityEvidenceKey(evidence[right]) })
	return evidence
}

func deliverabilityErrorCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrInvalidReceipt):
		return "invalid_response"
	case errors.Is(err, ErrInvalidCommand):
		return "invalid_request"
	default:
		return "unavailable"
	}
}

func aggregateDeliverabilityState(findings []DeliverabilityFinding) DeliverabilityState {
	state := DeliverabilityHealthy
	for _, finding := range findings {
		switch finding.State {
		case DeliverabilityFailed:
			return DeliverabilityFailed
		case DeliverabilityDegraded:
			state = DeliverabilityDegraded
		case DeliverabilityIndeterminate:
			if state == DeliverabilityHealthy {
				state = DeliverabilityIndeterminate
			}
		}
	}
	return state
}

func digestDeliverabilityEvidence(evidence []DeliverabilityEvidence) string {
	keys := make([]string, 0, len(evidence))
	for _, item := range evidence {
		keys = append(keys, deliverabilityEvidenceKey(item))
	}
	sort.Strings(keys)
	return digestDeliverabilityStrings(keys)
}

func deliverabilityEvidenceKey(item DeliverabilityEvidence) string {
	values := append([]string(nil), item.Values...)
	sort.Strings(values)
	return strings.Join([]string{item.Source, item.Check, item.Target, strings.Join(values, "\x1f"), item.ErrorCode}, "\x00")
}

func digestDeliverabilityReport(report DeliverabilityReport) string {
	values := []string{string(report.DomainID), report.TenantID, report.Domain, report.Hostname}
	for _, finding := range report.Findings {
		values = append(values, string(finding.Kind)+"\x00"+string(finding.State)+"\x00"+finding.Code+"\x00"+finding.EvidenceDigest)
	}
	return digestDeliverabilityStrings(values)
}

func digestDeliverabilityStrings(values []string) string {
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}
