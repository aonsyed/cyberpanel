package mailtelemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const (
	MaximumAbuseEvents = 5_000
	MaximumAbuseSources = 512
	MaximumAbuseGroups = 1_024
	MaximumAbuseFindings = 256
	MaximumFindingEvents = 32
	MaximumBanLifetime = 24 * time.Hour
	MaximumApprovalLifetime = 15 * time.Minute
)

type AbusePattern string

const (
	PatternBruteForce AbusePattern = "brute_force"
	PatternPasswordSpray AbusePattern = "password_spray"
	PatternDictionary AbusePattern = "dictionary"
	PatternFlood AbusePattern = "flood"
	PatternSuccessAfterFailure AbusePattern = "success_after_failure"
)

func (pattern AbusePattern) valid() bool {
	return pattern == PatternBruteForce || pattern == PatternPasswordSpray || pattern == PatternDictionary || pattern == PatternFlood || pattern == PatternSuccessAfterFailure
}

type AbuseConfig struct {
	Window time.Duration
	FloodWindow time.Duration
	BruteForceFailures uint16
	SprayFailures uint16
	SprayDistinctMailboxes uint16
	DictionaryRejections uint16
	DictionaryDistinctTargets uint16
	FloodEvents uint16
	SuccessAfterFailures uint16
	BanLifetime time.Duration
	ProposerID string
}

func DefaultAbuseConfig() AbuseConfig {
	return AbuseConfig{Window: 15*time.Minute, FloodWindow: time.Minute, BruteForceFailures: 10, SprayFailures: 20, SprayDistinctMailboxes: 8, DictionaryRejections: 30, DictionaryDistinctTargets: 20, FloodEvents: 120, SuccessAfterFailures: 5, BanLifetime: 4*time.Hour, ProposerID: "mail-abuse-detector"}
}

func (config AbuseConfig) valid() bool {
	return config.Window >= time.Minute && config.Window <= time.Hour && config.FloodWindow >= 10*time.Second && config.FloodWindow <= 5*time.Minute && config.FloodWindow <= config.Window && config.BruteForceFailures >= 3 && config.BruteForceFailures <= 1_000 && config.SprayFailures >= config.BruteForceFailures && config.SprayFailures <= 2_000 && config.SprayDistinctMailboxes >= 3 && config.SprayDistinctMailboxes <= 512 && config.DictionaryRejections >= 5 && config.DictionaryRejections <= 2_000 && config.DictionaryDistinctTargets >= 3 && config.DictionaryDistinctTargets <= 512 && config.FloodEvents >= 10 && config.FloodEvents <= 5_000 && config.SuccessAfterFailures >= 2 && config.SuccessAfterFailures <= config.BruteForceFailures && config.BanLifetime >= 5*time.Minute && config.BanLifetime <= MaximumBanLifetime && validID(config.ProposerID)
}

type AbuseFinding struct {
	ID string `json:"id"`
	TenantID TenantID `json:"tenant_id"`
	DomainID DomainID `json:"domain_id,omitempty"`
	MailboxID MailboxID `json:"mailbox_id,omitempty"`
	Source RemoteIdentity `json:"source"`
	Pattern AbusePattern `json:"pattern"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd time.Time `json:"window_end"`
	Observed uint32 `json:"observed"`
	DistinctTargets uint16 `json:"distinct_targets"`
	EventIDs []EventID `json:"event_ids"`
	EvidenceDigest string `json:"evidence_digest"`
	MissingData bool `json:"missing_data"`
	SampleExpired bool `json:"sample_expired"`
	ActionEligible bool `json:"action_eligible"`
	DetectedAt time.Time `json:"detected_at"`
}

func (finding AbuseFinding) valid() bool {
	if !validID(finding.ID) || !validID(string(finding.TenantID)) || finding.DomainID != "" && !validID(string(finding.DomainID)) || finding.MailboxID != "" && !validID(string(finding.MailboxID)) || !finding.Source.valid() || !finding.Pattern.valid() || finding.WindowStart.IsZero() || !finding.WindowEnd.After(finding.WindowStart) || finding.WindowEnd.Sub(finding.WindowStart) > time.Hour || finding.Observed == 0 || finding.DistinctTargets == 0 || len(finding.EventIDs) == 0 || len(finding.EventIDs) > MaximumFindingEvents || !validDigest(finding.EvidenceDigest) || finding.DetectedAt.Before(finding.WindowEnd.Add(-time.Minute)) || finding.ActionEligible && (finding.MissingData || finding.SampleExpired || finding.Source.ProtectedRef == "") { return false }
	for index, id := range finding.EventIDs { if !validID(string(id)) || index > 0 && finding.EventIDs[index-1] >= id { return false } }
	return true
}

type AbuseAction string

const (
	AbuseBan AbuseAction = "ban"
	AbuseAllowlist AbuseAction = "allowlist"
	AbuseReleaseBan AbuseAction = "release_ban"
)

func (action AbuseAction) valid() bool { return action == AbuseBan || action == AbuseAllowlist || action == AbuseReleaseBan }

type AbuseIntentState string

const (
	IntentProposed AbuseIntentState = "proposed"
	IntentSubmitting AbuseIntentState = "submitting"
	IntentApplied AbuseIntentState = "applied"
	IntentFailed AbuseIntentState = "failed"
	IntentRejected AbuseIntentState = "rejected"
	IntentExpired AbuseIntentState = "expired"
)

func (state AbuseIntentState) valid() bool { return state == IntentProposed || state == IntentSubmitting || state == IntentApplied || state == IntentFailed || state == IntentRejected || state == IntentExpired }

type AbuseApproval struct {
	ID string `json:"id"`
	ReviewerID string `json:"reviewer_id"`
	ApprovedDigest string `json:"approved_digest"`
	EvidenceRef string `json:"evidence_ref"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AbuseIntent struct {
	ID string `json:"id"`
	TenantID TenantID `json:"tenant_id"`
	DomainID DomainID `json:"domain_id,omitempty"`
	MailboxID MailboxID `json:"mailbox_id,omitempty"`
	Action AbuseAction `json:"action"`
	Source RemoteIdentity `json:"source"`
	FindingIDs []string `json:"finding_ids"`
	EvidenceDigest string `json:"evidence_digest"`
	ProposedBy string `json:"proposed_by"`
	ReasonCode string `json:"reason_code"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	BodyDigest string `json:"body_digest"`
	Approval *AbuseApproval `json:"approval,omitempty"`
	State AbuseIntentState `json:"state"`
	FailureCode string `json:"failure_code,omitempty"`
	OwnerReceiptID string `json:"owner_receipt_id,omitempty"`
	Revision uint64 `json:"revision"`
}

type abuseIntentBody struct {
	ID string `json:"id"`
	TenantID TenantID `json:"tenant_id"`
	DomainID DomainID `json:"domain_id,omitempty"`
	MailboxID MailboxID `json:"mailbox_id,omitempty"`
	Action AbuseAction `json:"action"`
	Source RemoteIdentity `json:"source"`
	FindingIDs []string `json:"finding_ids"`
	EvidenceDigest string `json:"evidence_digest"`
	ProposedBy string `json:"proposed_by"`
	ReasonCode string `json:"reason_code"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func intentDigest(intent AbuseIntent) (string, error) {
	body := abuseIntentBody{intent.ID, intent.TenantID, intent.DomainID, intent.MailboxID, intent.Action, intent.Source, intent.FindingIDs, intent.EvidenceDigest, intent.ProposedBy, intent.ReasonCode, intent.CreatedAt, intent.ExpiresAt}
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > 64<<10 { return "", ErrLimit }
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (approval AbuseApproval) valid(intent AbuseIntent, now time.Time) bool {
	return validID(approval.ID) && validID(approval.ReviewerID) && approval.ReviewerID != intent.ProposedBy && approval.ApprovedDigest == intent.BodyDigest && validID(approval.EvidenceRef) && !approval.IssuedAt.IsZero() && approval.ExpiresAt.After(approval.IssuedAt) && approval.ExpiresAt.Sub(approval.IssuedAt) <= MaximumApprovalLifetime && !now.Before(approval.IssuedAt.Add(-time.Minute)) && now.Before(approval.ExpiresAt)
}

func sameApproval(left *AbuseApproval, right AbuseApproval) bool {
	return left != nil && left.ID == right.ID && left.ReviewerID == right.ReviewerID && left.ApprovedDigest == right.ApprovedDigest && left.EvidenceRef == right.EvidenceRef && left.IssuedAt.Equal(right.IssuedAt) && left.ExpiresAt.Equal(right.ExpiresAt)
}

func (intent AbuseIntent) valid() bool {
	if !validID(intent.ID) || !validID(string(intent.TenantID)) || intent.DomainID != "" && !validID(string(intent.DomainID)) || intent.MailboxID != "" && !validID(string(intent.MailboxID)) || !intent.Action.valid() || !intent.Source.valid() || intent.Source.ProtectedRef == "" || len(intent.FindingIDs) == 0 || len(intent.FindingIDs) > 16 || !validDigest(intent.EvidenceDigest) || !validID(intent.ProposedBy) || !validID(intent.ReasonCode) || intent.CreatedAt.IsZero() || !intent.ExpiresAt.After(intent.CreatedAt) || intent.ExpiresAt.Sub(intent.CreatedAt) > MaximumBanLifetime || !validDigest(intent.BodyDigest) || !intent.State.valid() || len(intent.FailureCode) > 128 || intent.Revision == 0 || intent.Revision > MaximumRevision { return false }
	for index, id := range intent.FindingIDs { if !validID(id) || index > 0 && intent.FindingIDs[index-1] >= id { return false } }
	digest, err := intentDigest(intent)
	if err != nil || digest != intent.BodyDigest { return false }
	if intent.Approval != nil && !intent.Approval.valid(intent, intent.Approval.IssuedAt) { return false }
	if intent.State == IntentProposed { return intent.Approval == nil && intent.OwnerReceiptID == "" && intent.FailureCode == "" }
	if intent.State == IntentSubmitting || intent.State == IntentApplied { return intent.Approval != nil && intent.Approval.valid(intent, intent.Approval.IssuedAt) && intent.FailureCode == "" && (intent.State != IntentApplied || validID(intent.OwnerReceiptID)) }
	return intent.OwnerReceiptID == ""
}

type AbuseAnalysis struct {
	TenantID TenantID `json:"tenant_id"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd time.Time `json:"window_end"`
	Events uint32 `json:"events"`
	Sources uint16 `json:"sources"`
	Findings []AbuseFinding `json:"findings"`
	Intents []AbuseIntent `json:"intents"`
	Missing []ParseGap `json:"missing"`
}

type abuseGroup struct {
	tenant TenantID
	domain DomainID
	mailbox MailboxID
	source RemoteIdentity
	events []Event
}

func abuseGroupKey(event Event, mailbox bool) string {
	key := string(event.TenantID)+"\x00"+string(event.DomainID)+"\x00"+event.RemoteSource.Pseudonym
	if mailbox { key += "\x00"+string(event.MailboxID) }
	return key
}

func findingDigest(events []Event) (string, []EventID) {
	ids := make([]EventID, 0, len(events))
	for _, event := range events { ids = append(ids, event.ID) }
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	hash := sha256.New()
	for _, id := range ids { hash.Write([]byte{0}); hash.Write([]byte(id)) }
	visible := ids
	if len(visible) > MaximumFindingEvents { visible = visible[:MaximumFindingEvents] }
	return hex.EncodeToString(hash.Sum(nil)), append([]EventID(nil), visible...)
}

func buildFinding(pattern AbusePattern, group abuseGroup, events []Event, distinct uint16, missing, recent bool, now time.Time) AbuseFinding {
	digest, ids := findingDigest(events)
	start, end := events[0].OccurredAt.UTC(), events[len(events)-1].OccurredAt.UTC()
	if !end.After(start) { end = start.Add(time.Nanosecond) }
	finding := AbuseFinding{TenantID: group.tenant, DomainID: group.domain, MailboxID: group.mailbox, Source: group.source, Pattern: pattern, WindowStart: start, WindowEnd: end, Observed: uint32(len(events)), DistinctTargets: distinct, EventIDs: ids, EvidenceDigest: digest, MissingData: missing, SampleExpired: !recent, ActionEligible: !missing && recent && group.source.ProtectedRef != "", DetectedAt: now.UTC()}
	finding.ID = "finding-"+digestParts(string(pattern), string(group.tenant), string(group.domain), string(group.mailbox), group.source.Pseudonym, digest)[:24]
	return finding
}

func relevantMissing(gaps []ParseGap, tenant TenantID, start, end time.Time) bool {
	for _, gap := range gaps { if gap.valid() && (gap.TenantID == "" || gap.TenantID == tenant) && !gap.LastAt.Before(start) && gap.FirstAt.Before(end) { return true } }
	return false
}

func AnalyzeAbuse(events []Event, gaps []ParseGap, config AbuseConfig, now time.Time) (AbuseAnalysis, error) {
	if !config.valid() || now.IsZero() || len(events) == 0 || len(events) > MaximumAbuseEvents || len(gaps) > 256 { return AbuseAnalysis{}, ErrInvalid }
	ordered := append([]Event(nil), events...)
	sort.Slice(ordered, func(left, right int) bool { if ordered[left].OccurredAt.Equal(ordered[right].OccurredAt) { return ordered[left].ID < ordered[right].ID }; return ordered[left].OccurredAt.Before(ordered[right].OccurredAt) })
	tenant := ordered[0].TenantID
	windowStart, observedEnd := ordered[0].OccurredAt.UTC(), ordered[len(ordered)-1].OccurredAt.UTC()
	windowEnd := observedEnd.Add(time.Nanosecond)
	if !validID(string(tenant)) || observedEnd.Sub(windowStart) > config.Window || now.Before(observedEnd.Add(-time.Minute)) { return AbuseAnalysis{}, ErrInvalid }
	recent := now.Sub(observedEnd) <= config.Window
	for _, gap := range gaps { if !gap.valid() || gap.TenantID != "" && gap.TenantID != tenant { return AbuseAnalysis{}, ErrIntegrity } }
	sources := make(map[string]RemoteIdentity)
	seenEvents := make(map[EventID]struct{}, len(ordered))
	mailboxGroups, sourceGroups := make(map[string]*abuseGroup), make(map[string]*abuseGroup)
	for _, event := range ordered {
		if event.Validate() != nil || event.TenantID != tenant || event.OccurredAt.Before(windowStart) || event.OccurredAt.After(windowEnd) { return AbuseAnalysis{}, ErrIntegrity }
		if _, duplicate := seenEvents[event.ID]; duplicate { return AbuseAnalysis{}, ErrConflict }
		seenEvents[event.ID] = struct{}{}
		if event.RemoteSource == nil || event.Direction != DirectionInbound && event.Direction != DirectionUnknown { continue }
		if existing, ok := sources[event.RemoteSource.Pseudonym]; ok && existing.ProtectedRef != event.RemoteSource.ProtectedRef { return AbuseAnalysis{}, ErrIntegrity }
		sources[event.RemoteSource.Pseudonym] = *event.RemoteSource
		if len(sources) > MaximumAbuseSources { return AbuseAnalysis{}, ErrLimit }
		for _, mailboxScope := range []bool{false, true} {
			key := abuseGroupKey(event, mailboxScope)
			groups := sourceGroups
			if mailboxScope { groups = mailboxGroups }
			group := groups[key]
			if group == nil {
				mailbox := MailboxID("")
				if mailboxScope { mailbox = event.MailboxID }
				group = &abuseGroup{tenant: event.TenantID, domain: event.DomainID, mailbox: mailbox, source: *event.RemoteSource}
				groups[key] = group
			}
			group.events = append(group.events, event)
		}
		if len(mailboxGroups)+len(sourceGroups) > MaximumAbuseGroups { return AbuseAnalysis{}, ErrLimit }
	}
	missing := relevantMissing(gaps, tenant, windowStart, windowEnd)
	findings := make([]AbuseFinding, 0, 32)
	appendFinding := func(finding AbuseFinding) error {
		if !finding.valid() { return ErrIntegrity }
		if len(findings) == MaximumAbuseFindings { return ErrLimit }
		findings = append(findings, finding)
		return nil
	}
	mailboxKeys := sortedGroupKeys(mailboxGroups)
	for _, key := range mailboxKeys {
		group := mailboxGroups[key]
		failures := filterEvents(group.events, func(event Event) bool { return event.Category == CategoryAuth && (event.Result == ResultFailed || event.Result == ResultRejected) })
		if len(failures) >= int(config.BruteForceFailures) { if err := appendFinding(buildFinding(PatternBruteForce, *group, failures, 1, missing, recent, now)); err != nil { return AbuseAnalysis{}, err } }
		if len(failures) >= int(config.SuccessAfterFailures) {
			priorFailures := make([]Event, 0, len(failures))
			for _, event := range group.events {
				if event.Category == CategoryAuth && (event.Result == ResultFailed || event.Result == ResultRejected) { priorFailures = append(priorFailures, event); continue }
				if event.Category == CategoryAuth && (event.Result == ResultPassed || event.Result == ResultAccepted) && len(priorFailures) >= int(config.SuccessAfterFailures) {
					evidence := append(append([]Event(nil), priorFailures...), event)
					if err := appendFinding(buildFinding(PatternSuccessAfterFailure, *group, evidence, 1, missing, recent, now)); err != nil { return AbuseAnalysis{}, err }
					break
				}
			}
		}
		flood := maximumFlood(group.events, config.FloodWindow)
		if len(flood) >= int(config.FloodEvents) { if err := appendFinding(buildFinding(PatternFlood, *group, flood, 1, missing, recent, now)); err != nil { return AbuseAnalysis{}, err } }
	}
	for _, key := range sortedGroupKeys(sourceGroups) {
		group := sourceGroups[key]
		authFailures := filterEvents(group.events, func(event Event) bool { return event.Category == CategoryAuth && (event.Result == ResultFailed || event.Result == ResultRejected) })
		distinctMailboxes := distinctTargets(authFailures)
		if len(authFailures) >= int(config.SprayFailures) && distinctMailboxes >= config.SprayDistinctMailboxes { if err := appendFinding(buildFinding(PatternPasswordSpray, *group, authFailures, distinctMailboxes, missing, recent, now)); err != nil { return AbuseAnalysis{}, err } }
		rejections := filterEvents(group.events, func(event Event) bool { return event.Category == CategoryRejection })
		distinctRecipients := distinctTargets(rejections)
		if len(rejections) >= int(config.DictionaryRejections) && distinctRecipients >= config.DictionaryDistinctTargets { if err := appendFinding(buildFinding(PatternDictionary, *group, rejections, distinctRecipients, missing, recent, now)); err != nil { return AbuseAnalysis{}, err } }
	}
	sort.Slice(findings, func(left, right int) bool { return findings[left].ID < findings[right].ID })
	type intentGroup struct { finding AbuseFinding; ids []string; digests []string; patterns []string }
	intentGroups := make(map[string]*intentGroup)
	for _, finding := range findings {
		if !finding.ActionEligible { continue }
		key := string(finding.TenantID)+"\x00"+string(finding.DomainID)+"\x00"+string(finding.MailboxID)+"\x00"+finding.Source.Pseudonym
		group := intentGroups[key]
		if group == nil { group = &intentGroup{finding: finding}; intentGroups[key] = group }
		group.ids = append(group.ids, finding.ID)
		group.digests = append(group.digests, finding.EvidenceDigest)
		group.patterns = append(group.patterns, string(finding.Pattern))
	}
	intents := make([]AbuseIntent, 0, len(intentGroups))
	groupKeys := make([]string, 0, len(intentGroups))
	for key := range intentGroups { groupKeys = append(groupKeys, key) }
	sort.Strings(groupKeys)
	for _, key := range groupKeys {
		group := intentGroups[key]
		sort.Strings(group.ids); sort.Strings(group.digests); sort.Strings(group.patterns)
		reason := group.patterns[0]
		if len(group.patterns) > 1 { reason = "multiple_patterns" }
		finding := group.finding
		intent := AbuseIntent{TenantID: finding.TenantID, DomainID: finding.DomainID, MailboxID: finding.MailboxID, Action: AbuseBan, Source: finding.Source, FindingIDs: group.ids, EvidenceDigest: digestParts(group.digests...), ProposedBy: config.ProposerID, ReasonCode: reason, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(config.BanLifetime), State: IntentProposed, Revision: 1}
		intent.ID = "intent-"+digestParts(key, intent.EvidenceDigest, string(intent.Action), repositoryTime(intent.ExpiresAt))[:24]
		intent.BodyDigest, _ = intentDigest(intent)
		if !intent.valid() { return AbuseAnalysis{}, ErrIntegrity }
		intents = append(intents, intent)
	}
	return AbuseAnalysis{TenantID: tenant, WindowStart: windowStart, WindowEnd: windowEnd, Events: uint32(len(ordered)), Sources: uint16(len(sources)), Findings: findings, Intents: intents, Missing: append([]ParseGap(nil), gaps...)}, nil
}

func sortedGroupKeys(groups map[string]*abuseGroup) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups { keys = append(keys, key) }
	sort.Strings(keys)
	return keys
}

func filterEvents(events []Event, include func(Event) bool) []Event {
	result := make([]Event, 0, len(events))
	for _, event := range events { if include(event) { result = append(result, event) } }
	return result
}

func distinctTargets(events []Event) uint16 {
	targets := make(map[string]struct{})
	for _, event := range events {
		target := string(event.MailboxID)
		if target == "" && event.Recipient != nil { target = event.Recipient.Value }
		if target != "" { targets[target] = struct{}{} }
	}
	if len(targets) > 65535 { return 65535 }
	return uint16(len(targets))
}

func maximumFlood(events []Event, window time.Duration) []Event {
	candidates := filterEvents(events, func(event Event) bool { return event.Category == CategoryAuth || event.Category == CategoryDelivery || event.Category == CategoryRejection || event.Category == CategoryDeferral || event.Category == CategoryBounce })
	bestStart, bestEnd, left := 0, 0, 0
	for right := range candidates {
		for left < right && candidates[right].OccurredAt.Sub(candidates[left].OccurredAt) > window { left++ }
		if right-left+1 > bestEnd-bestStart { bestStart, bestEnd = left, right+1 }
	}
	return append([]Event(nil), candidates[bestStart:bestEnd]...)
}

type FirewallMutationRequest struct {
	RequestID string
	TenantID TenantID
	DomainID DomainID
	MailboxID MailboxID
	Action AbuseAction
	ProtectedSourceRef string
	SourcePseudonym string
	ReasonCode string
	EvidenceDigest string
	RequestedBy string
	ApprovedBy string
	ExpiresAt time.Time
}

type FirewallMutationReceipt struct {
	RequestID string
	OwnerReceiptID string
	AlreadyApplied bool
	AppliedUntil time.Time
	EvidenceDigest string
	CompletedAt time.Time
}

// FirewallAuthority is the sole mutation seam. Implementations resolve the
// protected source and own all firewall generations, leases, and rule changes.
type FirewallAuthority interface {
	RequestMailAbuseMutation(context.Context, FirewallMutationRequest) (FirewallMutationReceipt, error)
}

type AbuseAuthorizer interface { AuthorizeMailAbuseIntent(context.Context, Actor, AbuseIntent, bool) error }
type AbuseApprovalVerifier interface { VerifyMailAbuseApproval(context.Context, AbuseIntent, AbuseApproval) error }
type AbuseAuditor interface { RecordMailAbuseAudit(context.Context, AbuseAuditRecord) error }

type AbuseAuditRecord struct {
	IntentID string
	TenantID TenantID
	Action AbuseAction
	ActorID string
	ReviewerID string
	BodyDigest string
	Outcome string
	ReceiptDigest string
	At time.Time
}

type FalsePositiveEvidence struct {
	ID string `json:"id"`
	TenantID TenantID `json:"tenant_id"`
	OriginalIntentID string `json:"original_intent_id"`
	RecoveryIntentID string `json:"recovery_intent_id"`
	ReportedBy string `json:"reported_by"`
	ReasonDigest string `json:"reason_digest"`
	OriginalEvidenceDigest string `json:"original_evidence_digest"`
	CreatedAt time.Time `json:"created_at"`
	Digest string `json:"digest"`
}

func (evidence FalsePositiveEvidence) valid() bool {
	if !validID(evidence.ID) || !validID(string(evidence.TenantID)) || !validID(evidence.OriginalIntentID) || !validID(evidence.RecoveryIntentID) || !validID(evidence.ReportedBy) || !validDigest(evidence.ReasonDigest) || !validDigest(evidence.OriginalEvidenceDigest) || evidence.CreatedAt.IsZero() || !validDigest(evidence.Digest) { return false }
	copyEvidence := evidence
	copyEvidence.Digest = ""
	encoded, err := json.Marshal(copyEvidence)
	digest := sha256.Sum256(encoded)
	return err == nil && evidence.Digest == hex.EncodeToString(digest[:])
}

type AbuseCoordinator struct {
	repository *SQLiteRepository
	authorizer AbuseAuthorizer
	approvals AbuseApprovalVerifier
	firewall FirewallAuthority
	auditor AbuseAuditor
	now func() time.Time
}

func NewAbuseCoordinator(repository *SQLiteRepository, authorizer AbuseAuthorizer, approvals AbuseApprovalVerifier, firewall FirewallAuthority, auditor AbuseAuditor) (*AbuseCoordinator, error) {
	if repository == nil || authorizer == nil || approvals == nil || firewall == nil || auditor == nil { return nil, ErrInvalid }
	return &AbuseCoordinator{repository: repository, authorizer: authorizer, approvals: approvals, firewall: firewall, auditor: auditor, now: time.Now}, nil
}

func (coordinator *AbuseCoordinator) PersistAnalysis(ctx context.Context, analysis AbuseAnalysis) error {
	if coordinator == nil || ctx == nil || !validID(string(analysis.TenantID)) || analysis.WindowStart.IsZero() || !analysis.WindowEnd.After(analysis.WindowStart) || analysis.WindowEnd.Sub(analysis.WindowStart) > time.Hour || analysis.Events == 0 || analysis.Events > MaximumAbuseEvents || analysis.Sources > MaximumAbuseSources || len(analysis.Findings) > MaximumAbuseFindings || len(analysis.Intents) > MaximumAbuseFindings || len(analysis.Missing) > 256 { return ErrInvalid }
	for _, gap := range analysis.Missing { if !gap.valid() || gap.TenantID != "" && gap.TenantID != analysis.TenantID { return ErrIntegrity } }
	findingIDs := make(map[string]struct{}, len(analysis.Findings))
	for _, finding := range analysis.Findings {
		if !finding.valid() || finding.TenantID != analysis.TenantID { return ErrIntegrity }
		if _, duplicate := findingIDs[finding.ID]; duplicate { return ErrConflict }
		findingIDs[finding.ID] = struct{}{}
		if err := coordinator.repository.putAbuseFinding(ctx, finding); err != nil { return err }
	}
	for _, intent := range analysis.Intents {
		if !intent.valid() || intent.TenantID != analysis.TenantID { return ErrIntegrity }
		for _, findingID := range intent.FindingIDs { if _, exists := findingIDs[findingID]; !exists { return ErrIntegrity } }
		if err := coordinator.repository.putAbuseIntent(ctx, intent, 0); err != nil { return err }
	}
	return nil
}

func (coordinator *AbuseCoordinator) InspectIntent(ctx context.Context, actor Actor, tenant TenantID, intentID string) (AbuseIntent, error) {
	if coordinator == nil || ctx == nil || !actor.valid() || !validID(string(tenant)) || !validID(intentID) { return AbuseIntent{}, ErrInvalid }
	if actor.TenantID != tenant { return AbuseIntent{}, ErrNotFound }
	intent, err := coordinator.repository.loadAbuseIntent(ctx, tenant, intentID)
	if errors.Is(err, sql.ErrNoRows) { return AbuseIntent{}, ErrNotFound }
	if err != nil { return AbuseIntent{}, err }
	if coordinator.authorizer.AuthorizeMailAbuseIntent(ctx, actor, intent, false) != nil { return AbuseIntent{}, ErrNotFound }
	return intent, nil
}

func (coordinator *AbuseCoordinator) ApproveAndSubmit(ctx context.Context, reviewer Actor, tenant TenantID, intentID string, expectedRevision uint64, approval AbuseApproval) (AbuseIntent, error) {
	if coordinator == nil || ctx == nil || !reviewer.valid() || !validID(string(tenant)) || !validID(intentID) || expectedRevision == 0 { return AbuseIntent{}, ErrInvalid }
	if reviewer.TenantID != tenant { return AbuseIntent{}, ErrNotFound }
	intent, err := coordinator.repository.loadAbuseIntent(ctx, tenant, intentID)
	if errors.Is(err, sql.ErrNoRows) { return AbuseIntent{}, ErrNotFound }
	if err != nil { return AbuseIntent{}, err }
	now := coordinator.now().UTC()
	if intent.Revision != expectedRevision || !now.Before(intent.ExpiresAt) { return AbuseIntent{}, ErrConflict }
	if intent.State == IntentProposed {
		if !approval.valid(intent, now) || approval.ReviewerID != reviewer.SubjectID || coordinator.approvals.VerifyMailAbuseApproval(ctx, intent, approval) != nil || coordinator.authorizer.AuthorizeMailAbuseIntent(ctx, reviewer, intent, true) != nil { return AbuseIntent{}, ErrUnauthorized }
		intent.Approval, intent.State, intent.Revision = &approval, IntentSubmitting, intent.Revision+1
		if err = coordinator.repository.putAbuseIntent(ctx, intent, expectedRevision); err != nil { return AbuseIntent{}, err }
	} else if intent.State == IntentSubmitting {
		if !sameApproval(intent.Approval, approval) || approval.ReviewerID != reviewer.SubjectID || coordinator.authorizer.AuthorizeMailAbuseIntent(ctx, reviewer, intent, true) != nil { return AbuseIntent{}, ErrUnauthorized }
	} else { return AbuseIntent{}, ErrConflict }
	audit := AbuseAuditRecord{IntentID: intent.ID, TenantID: tenant, Action: intent.Action, ActorID: intent.ProposedBy, ReviewerID: reviewer.SubjectID, BodyDigest: intent.BodyDigest, Outcome: "authorized", At: now}
	if err = coordinator.auditor.RecordMailAbuseAudit(ctx, audit); err != nil { return coordinator.failIntent(ctx, intent, "audit_unavailable", err) }
	request := FirewallMutationRequest{RequestID: intent.ID, TenantID: intent.TenantID, DomainID: intent.DomainID, MailboxID: intent.MailboxID, Action: intent.Action, ProtectedSourceRef: intent.Source.ProtectedRef, SourcePseudonym: intent.Source.Pseudonym, ReasonCode: intent.ReasonCode, EvidenceDigest: intent.EvidenceDigest, RequestedBy: intent.ProposedBy, ApprovedBy: reviewer.SubjectID, ExpiresAt: intent.ExpiresAt}
	receipt, err := coordinator.firewall.RequestMailAbuseMutation(ctx, request)
	if err != nil { return intent, err }
	if receipt.RequestID != intent.ID || !validID(receipt.OwnerReceiptID) || receipt.AppliedUntil.After(intent.ExpiresAt) || receipt.AppliedUntil.Before(now) || !validDigest(receipt.EvidenceDigest) || receipt.CompletedAt.Before(intent.CreatedAt.Add(-time.Minute)) || receipt.CompletedAt.After(coordinator.now().UTC().Add(time.Minute)) || !receipt.AlreadyApplied && receipt.CompletedAt.Before(now.Add(-time.Minute)) { return intent, ErrIntegrity }
	intent.State, intent.OwnerReceiptID, intent.Revision = IntentApplied, receipt.OwnerReceiptID, intent.Revision+1
	if err = coordinator.repository.completeAbuseIntent(ctx, intent, receipt, intent.Revision-1); err != nil { return AbuseIntent{}, err }
	audit.Outcome, audit.ReceiptDigest, audit.At = "applied", receipt.EvidenceDigest, coordinator.now().UTC()
	if err = coordinator.auditor.RecordMailAbuseAudit(ctx, audit); err != nil { return AbuseIntent{}, err }
	return intent, nil
}

func (coordinator *AbuseCoordinator) failIntent(ctx context.Context, intent AbuseIntent, code string, cause error) (AbuseIntent, error) {
	intent.State, intent.FailureCode, intent.Revision = IntentFailed, code, intent.Revision+1
	_ = coordinator.repository.putAbuseIntent(ctx, intent, intent.Revision-1)
	return intent, cause
}

func (coordinator *AbuseCoordinator) ProposeFalsePositiveRecovery(ctx context.Context, reporter Actor, tenant TenantID, originalIntentID, recoveryIntentID string, reasonDigest string, allowUntil time.Time) (AbuseIntent, FalsePositiveEvidence, error) {
	if coordinator == nil || ctx == nil || !reporter.valid() || !validID(string(tenant)) || !validID(originalIntentID) || !validID(recoveryIntentID) || !validDigest(reasonDigest) || allowUntil.IsZero() { return AbuseIntent{}, FalsePositiveEvidence{}, ErrInvalid }
	if reporter.TenantID != tenant { return AbuseIntent{}, FalsePositiveEvidence{}, ErrNotFound }
	original, err := coordinator.repository.loadAbuseIntent(ctx, tenant, originalIntentID)
	if errors.Is(err, sql.ErrNoRows) { return AbuseIntent{}, FalsePositiveEvidence{}, ErrNotFound }
	if err != nil { return AbuseIntent{}, FalsePositiveEvidence{}, err }
	now := coordinator.now().UTC()
	if original.Action != AbuseBan || original.State != IntentApplied || !allowUntil.After(now) || allowUntil.Sub(now) > MaximumBanLifetime { return AbuseIntent{}, FalsePositiveEvidence{}, ErrConflict }
	recovery := AbuseIntent{ID: recoveryIntentID, TenantID: tenant, DomainID: original.DomainID, MailboxID: original.MailboxID, Action: AbuseAllowlist, Source: original.Source, FindingIDs: append([]string(nil), original.FindingIDs...), EvidenceDigest: digestParts(original.EvidenceDigest, reasonDigest), ProposedBy: reporter.SubjectID, ReasonCode: "false_positive_recovery", CreatedAt: now, ExpiresAt: allowUntil.UTC(), State: IntentProposed, Revision: 1}
	recovery.BodyDigest, _ = intentDigest(recovery)
	evidence := FalsePositiveEvidence{ID: "recovery-"+digestParts(originalIntentID, recoveryIntentID, reasonDigest)[:24], TenantID: tenant, OriginalIntentID: originalIntentID, RecoveryIntentID: recoveryIntentID, ReportedBy: reporter.SubjectID, ReasonDigest: reasonDigest, OriginalEvidenceDigest: original.EvidenceDigest, CreatedAt: now}
	evidenceRaw, _ := json.Marshal(evidence)
	evidenceDigest := sha256.Sum256(evidenceRaw)
	evidence.Digest = hex.EncodeToString(evidenceDigest[:])
	if !recovery.valid() || !evidence.valid() { return AbuseIntent{}, FalsePositiveEvidence{}, ErrIntegrity }
	if coordinator.authorizer.AuthorizeMailAbuseIntent(ctx, reporter, recovery, true) != nil { return AbuseIntent{}, FalsePositiveEvidence{}, ErrUnauthorized }
	if err = coordinator.repository.putRecoveryAndIntent(ctx, evidence, recovery); err != nil { return AbuseIntent{}, FalsePositiveEvidence{}, err }
	return recovery, evidence, nil
}

func (repository *SQLiteRepository) putAbuseFinding(ctx context.Context, finding AbuseFinding) error {
	if repository == nil || ctx == nil || !finding.valid() { return ErrInvalid }
	document, err := encodeDocument(finding, 128<<10)
	if err != nil { return err }
	result, err := repository.db.ExecContext(ctx, `INSERT OR IGNORE INTO mail_abuse_findings_v1(finding_id,tenant_id,source_pseudonym,pattern,detected_at,document) VALUES(?,?,?,?,?,?)`, finding.ID, finding.TenantID, finding.Source.Pseudonym, finding.Pattern, repositoryTime(finding.DetectedAt), document)
	if err != nil { return err }
	rows, err := result.RowsAffected()
	if err != nil { return err }
	if rows == 0 { var existing []byte; if repository.db.QueryRowContext(ctx, `SELECT document FROM mail_abuse_findings_v1 WHERE finding_id=?`, finding.ID).Scan(&existing) != nil || !bytes.Equal(existing, document) { return ErrIntegrity } }
	return nil
}

func (repository *SQLiteRepository) putAbuseIntent(ctx context.Context, intent AbuseIntent, expectedRevision uint64) error {
	if repository == nil || ctx == nil || !intent.valid() || intent.Revision != expectedRevision+1 { return ErrInvalid }
	document, err := encodeDocument(intent, 128<<10)
	if err != nil { return err }
	if expectedRevision == 0 {
		result, insertErr := repository.db.ExecContext(ctx, `INSERT OR IGNORE INTO mail_abuse_intents_v1(intent_id,tenant_id,revision,state,expires_at,document) VALUES(?,?,?,?,?,?)`, intent.ID, intent.TenantID, intent.Revision, intent.State, repositoryTime(intent.ExpiresAt), document)
		if insertErr != nil { return insertErr }
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil { return rowsErr }
		if rows == 0 {
			var existing []byte
			if repository.db.QueryRowContext(ctx, `SELECT document FROM mail_abuse_intents_v1 WHERE intent_id=? AND tenant_id=?`, intent.ID, intent.TenantID).Scan(&existing) != nil || !bytes.Equal(existing, document) { return ErrConflict }
		}
		return nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE mail_abuse_intents_v1 SET revision=?,state=?,expires_at=?,document=? WHERE intent_id=? AND tenant_id=? AND revision=?`, intent.Revision, intent.State, repositoryTime(intent.ExpiresAt), document, intent.ID, intent.TenantID, expectedRevision)
	if err != nil { return err }
	return changedExactlyOne(result)
}

func (repository *SQLiteRepository) loadAbuseIntent(ctx context.Context, tenant TenantID, intentID string) (AbuseIntent, error) {
	var revision uint64
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT revision,document FROM mail_abuse_intents_v1 WHERE tenant_id=? AND intent_id=?`, tenant, intentID).Scan(&revision, &document)
	if err != nil { return AbuseIntent{}, err }
	var intent AbuseIntent
	if decodeDocument(document, 128<<10, &intent) != nil || !intent.valid() || intent.TenantID != tenant || intent.ID != intentID || intent.Revision != revision { return AbuseIntent{}, ErrIntegrity }
	return intent, nil
}

func (repository *SQLiteRepository) completeAbuseIntent(ctx context.Context, intent AbuseIntent, receipt FirewallMutationReceipt, expectedRevision uint64) error {
	document, err := encodeDocument(intent, 128<<10)
	if err != nil { return err }
	receiptDocument, err := encodeDocument(receipt, 32<<10)
	if err != nil { return err }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `UPDATE mail_abuse_intents_v1 SET revision=?,state=?,document=? WHERE intent_id=? AND tenant_id=? AND revision=?`, intent.Revision, intent.State, document, intent.ID, intent.TenantID, expectedRevision)
	if err != nil || changedExactlyOne(result) != nil { return ErrConflict }
	if _, err = transaction.ExecContext(ctx, `INSERT INTO mail_abuse_authority_receipts_v1(intent_id,owner_receipt_id,evidence_digest,document,completed_at) VALUES(?,?,?,?,?)`, intent.ID, receipt.OwnerReceiptID, receipt.EvidenceDigest, receiptDocument, repositoryTime(receipt.CompletedAt)); err != nil { return err }
	return transaction.Commit()
}

func (repository *SQLiteRepository) putRecoveryAndIntent(ctx context.Context, evidence FalsePositiveEvidence, intent AbuseIntent) error {
	evidenceDocument, err := encodeDocument(evidence, 32<<10)
	if err != nil { return err }
	intentDocument, err := encodeDocument(intent, 128<<10)
	if err != nil { return err }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	if _, err = transaction.ExecContext(ctx, `INSERT INTO mail_abuse_intents_v1(intent_id,tenant_id,revision,state,expires_at,document) VALUES(?,?,?,?,?,?)`, intent.ID, intent.TenantID, intent.Revision, intent.State, repositoryTime(intent.ExpiresAt), intentDocument); err != nil { return ErrConflict }
	if _, err = transaction.ExecContext(ctx, `INSERT INTO mail_abuse_recoveries_v1(recovery_id,tenant_id,original_intent_id,recovery_intent_id,reason_digest,document,created_at) VALUES(?,?,?,?,?,?,?)`, evidence.ID, evidence.TenantID, evidence.OriginalIntentID, evidence.RecoveryIntentID, evidence.ReasonDigest, evidenceDocument, repositoryTime(evidence.CreatedAt)); err != nil { return err }
	return transaction.Commit()
}
