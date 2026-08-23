package sshactivity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"sort"
	"time"
)

const MaximumCursorLifetime = 24 * time.Hour

type CursorSigner interface {
	ActiveSSHCursorKey(context.Context) (string, error)
	SignSSHCursor(context.Context, string, []byte) ([]byte, error)
	VerifySSHCursor(context.Context, string, []byte, []byte) error
}

type CursorState struct {
	Version       uint8    `json:"version"`
	SourceID      SourceID `json:"source_id"`
	Boot          BootIdentity `json:"boot"`
	JournalCursor string   `json:"journal_cursor"`
	QueryDigest   string   `json:"query_digest"`
	IssuedUnixNS  int64    `json:"issued_unix_ns"`
	ExpiresUnixNS int64    `json:"expires_unix_ns"`
}

type cursorEnvelope struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type CursorCodec struct {
	signer CursorSigner
	now    func() time.Time
}

func NewCursorCodec(signer CursorSigner) (*CursorCodec, error) {
	if signer == nil {
		return nil, ErrInvalid
	}
	return &CursorCodec{signer: signer, now: time.Now}, nil
}

func strictJSON(encoded []byte, maximum int, target any) error {
	if len(encoded) == 0 || len(encoded) > maximum {
		return ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrIntegrity
	}
	return nil
}

func validJournalCursor(value string) bool {
	if value == "" || len(value) > MaximumCursorBytes {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func (state CursorState) valid(now time.Time) bool {
	if state.Version != 1 || !validOpaque(string(state.SourceID)) || !state.Boot.valid() || !validJournalCursor(state.JournalCursor) || !validDigest(state.QueryDigest) || state.IssuedUnixNS <= 0 || state.ExpiresUnixNS <= state.IssuedUnixNS {
		return false
	}
	issued := time.Unix(0, state.IssuedUnixNS)
	expires := time.Unix(0, state.ExpiresUnixNS)
	return expires.Sub(issued) <= MaximumCursorLifetime && !now.Before(issued.Add(-time.Minute)) && now.Before(expires)
}

func (codec *CursorCodec) Encode(ctx context.Context, state CursorState, lifetime time.Duration) (string, error) {
	if codec == nil || codec.signer == nil || ctx == nil || lifetime <= 0 || lifetime > MaximumCursorLifetime {
		return "", ErrInvalid
	}
	now := codec.now().UTC()
	state.Version = 1
	state.IssuedUnixNS = now.UnixNano()
	state.ExpiresUnixNS = now.Add(lifetime).UnixNano()
	if !state.valid(now) {
		return "", ErrInvalid
	}
	payload, err := json.Marshal(state)
	if err != nil || len(payload) > MaximumCursorBytes {
		return "", ErrLimit
	}
	keyID, err := codec.signer.ActiveSSHCursorKey(ctx)
	if err != nil {
		return "", err
	}
	if !validOpaque(keyID) {
		return "", ErrIntegrity
	}
	signature, err := codec.signer.SignSSHCursor(ctx, keyID, payload)
	if err != nil {
		return "", err
	}
	if len(signature) < 16 || len(signature) > 512 {
		return "", ErrIntegrity
	}
	envelope, err := json.Marshal(cursorEnvelope{
		KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil || len(envelope) > MaximumCursorBytes {
		return "", ErrLimit
	}
	token := base64.RawURLEncoding.EncodeToString(envelope)
	if len(token) > MaximumCursorBytes {
		return "", ErrLimit
	}
	return token, nil
}

func (codec *CursorCodec) Decode(ctx context.Context, token string) (CursorState, error) {
	if codec == nil || codec.signer == nil || ctx == nil || token == "" || len(token) > MaximumCursorBytes {
		return CursorState{}, ErrInvalid
	}
	envelopeBytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(envelopeBytes) > MaximumCursorBytes {
		return CursorState{}, ErrIntegrity
	}
	var envelope cursorEnvelope
	if strictJSON(envelopeBytes, MaximumCursorBytes, &envelope) != nil || !validOpaque(envelope.KeyID) {
		return CursorState{}, ErrIntegrity
	}
	payload, payloadErr := base64.RawURLEncoding.DecodeString(envelope.Payload)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if payloadErr != nil || signatureErr != nil || len(payload) > MaximumCursorBytes || len(signature) < 16 || len(signature) > 512 {
		return CursorState{}, ErrIntegrity
	}
	if codec.signer.VerifySSHCursor(ctx, envelope.KeyID, payload, signature) != nil {
		return CursorState{}, ErrIntegrity
	}
	var state CursorState
	if strictJSON(payload, MaximumCursorBytes, &state) != nil || !state.valid(codec.now().UTC()) {
		return CursorState{}, ErrIntegrity
	}
	return state, nil
}

func authenticationQueryDigest(query AuthenticationQuery) (string, error) {
	if query.Validate() != nil {
		return "", ErrInvalid
	}
	source := ""
	if query.Source != nil {
		source = query.Source.String()
	}
	binding := struct {
		StartNS      int64                 `json:"start_ns"`
		EndNS        int64                 `json:"end_ns"`
		Source       string                `json:"source"`
		UserName     string                `json:"user_name"`
		Outcome      AuthenticationOutcome `json:"outcome"`
		Limit        uint32                `json:"limit"`
		ScanLimit    uint32                `json:"scan_limit"`
		MaximumBytes int64                 `json:"maximum_bytes"`
		DurationNS   int64                 `json:"duration_ns"`
	}{query.Start.UTC().UnixNano(), query.End.UTC().UnixNano(), source, query.UserName, query.Outcome, query.Limit, query.ScanLimit, query.MaximumBytes, int64(query.Duration)}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

type RiskReason string

const (
	RiskSpray           RiskReason = "spray"
	RiskBruteForce      RiskReason = "brute_force"
	RiskImpossibleChurn RiskReason = "impossible_churn"
	RiskDisabledAccount RiskReason = "disabled_account"
	RiskUnknownKey      RiskReason = "unknown_key"
	RiskPrivilegedTarget RiskReason = "privileged_target"
)

type RiskSeverity string

const (
	SeverityLow      RiskSeverity = "low"
	SeverityMedium   RiskSeverity = "medium"
	SeverityHigh     RiskSeverity = "high"
	SeverityCritical RiskSeverity = "critical"
)

type UncertaintyCode string

const (
	UncertaintyEvidenceGap     UncertaintyCode = "evidence_gap"
	UncertaintyBoundedWindow   UncertaintyCode = "bounded_window"
	UncertaintyIdentityMissing UncertaintyCode = "identity_missing"
	UncertaintyClock           UncertaintyCode = "clock_uncertain"
)

type AttributionConclusion string

const AttributionUndetermined AttributionConclusion = "undetermined_indicator_only"

type RiskFinding struct {
	ID             string                  `json:"id"`
	Reason         RiskReason              `json:"reason"`
	Severity       RiskSeverity            `json:"severity"`
	Source         netip.Addr              `json:"source,omitempty"`
	UserID         UserID                  `json:"user_id,omitempty"`
	WindowStart    time.Time               `json:"window_start"`
	WindowEnd      time.Time               `json:"window_end"`
	Count          uint32                  `json:"count"`
	Distinct       uint32                  `json:"distinct"`
	RelatedCursors []string                `json:"related_cursors"`
	EvidenceDigest string                  `json:"evidence_digest"`
	Uncertainty    []UncertaintyCode       `json:"uncertainty,omitempty"`
	Attribution    AttributionConclusion   `json:"attribution"`
}

func (finding RiskFinding) valid() bool {
	if !validOpaque(finding.ID) || finding.Attribution != AttributionUndetermined || finding.Count == 0 || finding.WindowStart.IsZero() || finding.WindowEnd.Before(finding.WindowStart) || !validDigest(finding.EvidenceDigest) || len(finding.RelatedCursors) > MaximumRelatedCursors {
		return false
	}
	switch finding.Reason {
	case RiskSpray, RiskBruteForce, RiskImpossibleChurn, RiskDisabledAccount, RiskUnknownKey, RiskPrivilegedTarget:
	default:
		return false
	}
	switch finding.Severity {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

type RiskPolicy struct {
	SprayFailures       uint32
	SprayDistinctUsers  uint32
	BruteForceFailures  uint32
	ChurnSuccesses      uint32
	ChurnDistinctSources uint32
	ChurnWindow         time.Duration
}

func DefaultRiskPolicy() RiskPolicy {
	return RiskPolicy{SprayFailures: 10, SprayDistinctUsers: 5, BruteForceFailures: 8, ChurnSuccesses: 3, ChurnDistinctSources: 3, ChurnWindow: 10 * time.Minute}
}

func (policy RiskPolicy) valid() bool {
	return policy.SprayFailures >= 2 && policy.SprayFailures <= MaximumEvents && policy.SprayDistinctUsers >= 2 && policy.SprayDistinctUsers <= policy.SprayFailures &&
		policy.BruteForceFailures >= 2 && policy.BruteForceFailures <= MaximumEvents && policy.ChurnSuccesses >= 2 && policy.ChurnSuccesses <= MaximumEvents &&
		policy.ChurnDistinctSources >= 2 && policy.ChurnDistinctSources <= policy.ChurnSuccesses && policy.ChurnWindow >= time.Minute && policy.ChurnWindow <= 24*time.Hour
}

type SourceAggregate struct {
	Source        netip.Addr   `json:"source"`
	Successes     uint32       `json:"successes"`
	Failures      uint32       `json:"failures"`
	DistinctUsers uint32       `json:"distinct_users"`
	FirstAt       time.Time    `json:"first_at"`
	LastAt        time.Time    `json:"last_at"`
	Reasons       []RiskReason `json:"reasons,omitempty"`
}

type AnalysisResult struct {
	Findings    []RiskFinding    `json:"findings"`
	Sources     []SourceAggregate `json:"sources"`
	Gaps        []ObservationGap  `json:"gaps,omitempty"`
	Digest      string            `json:"digest"`
	Attribution AttributionConclusion `json:"attribution"`
}

type eventGroup struct {
	events []AuthenticationEvent
	users  map[UserID]struct{}
}

func related(events []AuthenticationEvent) ([]string, string, []UncertaintyCode) {
	cursors := make([]string, 0, len(events))
	parts := make([]string, 0, len(events)*2)
	for _, event := range events {
		parts = append(parts, string(event.ID), event.Evidence.RecordDigest)
		if len(cursors) < MaximumRelatedCursors {
			cursors = append(cursors, event.Cursor)
		}
	}
	uncertainty := []UncertaintyCode(nil)
	if len(events) > MaximumRelatedCursors {
		uncertainty = append(uncertainty, UncertaintyBoundedWindow)
	}
	return cursors, digestParts(parts...), uncertainty
}

func gapUncertainty(gaps []ObservationGap) []UncertaintyCode {
	set := map[UncertaintyCode]struct{}{}
	for _, gap := range gaps {
		switch gap.Code {
		case GapClockUncertain:
			set[UncertaintyClock] = struct{}{}
		case GapIdentityUnknown:
			set[UncertaintyIdentityMissing] = struct{}{}
		default:
			set[UncertaintyEvidenceGap] = struct{}{}
		}
	}
	result := make([]UncertaintyCode, 0, len(set))
	for code := range set {
		result = append(result, code)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func makeFinding(reason RiskReason, severity RiskSeverity, source netip.Addr, user UserID, events []AuthenticationEvent, distinct uint32, uncertainty []UncertaintyCode) RiskFinding {
	cursors, evidenceDigest, bounded := related(events)
	uncertainty = append(append([]UncertaintyCode(nil), uncertainty...), bounded...)
	sort.Slice(uncertainty, func(left, right int) bool { return uncertainty[left] < uncertainty[right] })
	start, end := events[0].At, events[len(events)-1].At
	id := "risk-" + digestParts(string(reason), source.String(), string(user), start.UTC().Format(time.RFC3339Nano), evidenceDigest)[:24]
	return RiskFinding{ID: id, Reason: reason, Severity: severity, Source: source, UserID: user, WindowStart: start, WindowEnd: end, Count: uint32(len(events)), Distinct: distinct, RelatedCursors: cursors, EvidenceDigest: evidenceDigest, Uncertainty: uncertainty, Attribution: AttributionUndetermined}
}

func AnalyzeActivity(events []AuthenticationEvent, gaps []ObservationGap, policy RiskPolicy, maximumSources uint16) (AnalysisResult, error) {
	if len(events) > MaximumEvents || len(gaps) > MaximumRepositoryPage || !policy.valid() || maximumSources == 0 || maximumSources > MaximumRiskFindings {
		return AnalysisResult{}, ErrInvalid
	}
	for _, event := range events {
		if !event.valid() {
			return AnalysisResult{}, ErrIntegrity
		}
	}
	for _, gap := range gaps {
		if !gap.valid() {
			return AnalysisResult{}, ErrIntegrity
		}
	}
	events = stableEvents(events)
	uncertainty := gapUncertainty(gaps)
	failuresBySource := map[netip.Addr]*eventGroup{}
	failuresByTarget := map[string]*eventGroup{}
	successByUser := map[UserID][]AuthenticationEvent{}
	flagged := map[string][]AuthenticationEvent{}
	for _, event := range events {
		if event.Outcome == OutcomeFailed {
			group := failuresBySource[event.Source.Address]
			if group == nil {
				group = &eventGroup{users: map[UserID]struct{}{}}
				failuresBySource[event.Source.Address] = group
			}
			group.events = append(group.events, event)
			group.users[event.User.ID] = struct{}{}
			key := event.Source.Address.String() + "\x00" + string(event.User.ID)
			target := failuresByTarget[key]
			if target == nil {
				target = &eventGroup{users: map[UserID]struct{}{event.User.ID: {}}}
				failuresByTarget[key] = target
			}
			target.events = append(target.events, event)
		} else {
			successByUser[event.User.ID] = append(successByUser[event.User.ID], event)
		}
		if event.User.Disabled {
			key := "disabled\x00" + string(event.User.ID) + "\x00" + event.Source.Address.String()
			flagged[key] = append(flagged[key], event)
		}
		if event.Key != nil && !event.Key.Known {
			key := "unknown-key\x00" + string(event.Key.ID) + "\x00" + event.Source.Address.String()
			flagged[key] = append(flagged[key], event)
		}
		if event.User.Privileged {
			key := "privileged\x00" + event.Source.Address.String() + "\x00" + string(event.User.ID)
			flagged[key] = append(flagged[key], event)
		}
	}
	findings := make([]RiskFinding, 0)
	for source, group := range failuresBySource {
		if uint32(len(group.events)) >= policy.SprayFailures && uint32(len(group.users)) >= policy.SprayDistinctUsers {
			findings = append(findings, makeFinding(RiskSpray, SeverityHigh, source, "", group.events, uint32(len(group.users)), uncertainty))
		}
	}
	for _, group := range failuresByTarget {
		if uint32(len(group.events)) >= policy.BruteForceFailures {
			findings = append(findings, makeFinding(RiskBruteForce, SeverityHigh, group.events[0].Source.Address, group.events[0].User.ID, group.events, 1, uncertainty))
		}
	}
	for user, successes := range successByUser {
		for left := 0; left < len(successes); left++ {
			right := left
			sources := map[netip.Addr]struct{}{}
			for right < len(successes) && successes[right].At.Sub(successes[left].At) <= policy.ChurnWindow {
				sources[successes[right].Source.Address] = struct{}{}
				right++
			}
			if uint32(right-left) >= policy.ChurnSuccesses && uint32(len(sources)) >= policy.ChurnDistinctSources {
				findings = append(findings, makeFinding(RiskImpossibleChurn, SeverityMedium, netip.Addr{}, user, successes[left:right], uint32(len(sources)), uncertainty))
				break
			}
		}
	}
	keys := make([]string, 0, len(flagged))
	for key := range flagged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := flagged[key]
		reason, severity := RiskPrivilegedTarget, SeverityMedium
		if len(key) >= 8 && key[:8] == "disabled" {
			reason, severity = RiskDisabledAccount, SeverityHigh
		} else if len(key) >= 11 && key[:11] == "unknown-key" {
			reason, severity = RiskUnknownKey, SeverityMedium
		}
		findings = append(findings, makeFinding(reason, severity, group[0].Source.Address, group[0].User.ID, group, 1, uncertainty))
	}
	if len(findings) > MaximumRiskFindings {
		return AnalysisResult{}, ErrLimit
	}
	sort.Slice(findings, func(left, right int) bool {
		if findings[left].Reason != findings[right].Reason {
			return findings[left].Reason < findings[right].Reason
		}
		return findings[left].ID < findings[right].ID
	})
	sources, err := aggregateSources(events, findings, maximumSources)
	if err != nil {
		return AnalysisResult{}, err
	}
	encoded, err := json.Marshal(struct {
		Findings []RiskFinding `json:"findings"`
		Sources []SourceAggregate `json:"sources"`
		Gaps []ObservationGap `json:"gaps"`
	}{findings, sources, gaps})
	if err != nil || len(encoded) > MaximumRiskJSON {
		return AnalysisResult{}, ErrLimit
	}
	digest := sha256.Sum256(encoded)
	return AnalysisResult{Findings: findings, Sources: sources, Gaps: append([]ObservationGap(nil), gaps...), Digest: hex.EncodeToString(digest[:]), Attribution: AttributionUndetermined}, nil
}

func aggregateSources(events []AuthenticationEvent, findings []RiskFinding, limit uint16) ([]SourceAggregate, error) {
	type aggregate struct {
		value SourceAggregate
		users map[UserID]struct{}
		reasons map[RiskReason]struct{}
	}
	values := map[netip.Addr]*aggregate{}
	for _, event := range events {
		item := values[event.Source.Address]
		if item == nil {
			if len(values) == int(limit) {
				return nil, ErrLimit
			}
			item = &aggregate{value: SourceAggregate{Source: event.Source.Address, FirstAt: event.At}, users: map[UserID]struct{}{}, reasons: map[RiskReason]struct{}{}}
			values[event.Source.Address] = item
		}
		if event.Outcome == OutcomeSucceeded {
			item.value.Successes++
		} else {
			item.value.Failures++
		}
		item.users[event.User.ID] = struct{}{}
		if event.At.After(item.value.LastAt) {
			item.value.LastAt = event.At
		}
	}
	for _, finding := range findings {
		if finding.Source.IsValid() {
			if item := values[finding.Source]; item != nil {
				item.reasons[finding.Reason] = struct{}{}
			}
		}
	}
	result := make([]SourceAggregate, 0, len(values))
	for _, item := range values {
		item.value.DistinctUsers = uint32(len(item.users))
		for reason := range item.reasons {
			item.value.Reasons = append(item.value.Reasons, reason)
		}
		sort.Slice(item.value.Reasons, func(left, right int) bool { return item.value.Reasons[left] < item.value.Reasons[right] })
		result = append(result, item.value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Source.Less(result[right].Source) })
	return result, nil
}
