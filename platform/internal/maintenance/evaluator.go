package maintenance

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const defaultMaximumWindows = 128

type EvaluatorConfig struct {
	MaximumWindows int
	OverrideVerifier OverrideVerifier
	AuditSink        AuditSink
}

type Evaluator struct {
	repository       *Repository
	maximumWindows   int
	overrideVerifier OverrideVerifier
	auditSink        AuditSink
}

func NewEvaluator(repository *Repository, config EvaluatorConfig) (*Evaluator, error) {
	if repository == nil || repository.db == nil {
		return nil, ErrInvalid
	}
	if config.MaximumWindows == 0 {
		config.MaximumWindows = defaultMaximumWindows
	}
	if config.MaximumWindows < 1 || config.MaximumWindows > MaxPageSize {
		return nil, ErrInvalid
	}
	return &Evaluator{repository: repository, maximumWindows: config.MaximumWindows,
		overrideVerifier: config.OverrideVerifier, auditSink: config.AuditSink}, nil
}

type evaluatedWindow struct {
	window     Window
	candidate  span
	phase      OccurrencePhase
	occurrence Occurrence
}

func (evaluator *Evaluator) Admit(ctx context.Context, request AdmissionRequest) (Decision, error) {
	if err := request.Validate(); err != nil {
		return Decision{}, err
	}
	windows, err := evaluator.repository.listEnabled(ctx, request.Target.TenantID, evaluator.maximumWindows)
	if err != nil {
		return Decision{}, err
	}
	relevant := make([]Window, 0, len(windows))
	for _, window := range windows {
		if scopeMatches(window.Scope, request.Target) && classIncluded(window.OperationClasses, request.OperationClass) {
			relevant = append(relevant, window)
		}
	}
	evaluated, err := evaluator.evaluateEvidence(ctx, relevant, request.At)
	if err != nil {
		return Decision{}, err
	}
	evidence := evidenceFromEvaluated(evaluated)
	decision, selected, err := evaluator.ordinaryDecision(request, relevant, evaluated, evidence)
	if err != nil {
		return Decision{}, err
	}
	if decision.Kind == DecisionAllow {
		if selected != nil {
			if err := evaluator.repository.ensureOccurrence(ctx, selected.occurrence); err != nil {
				return Decision{}, err
			}
		}
		return decision, nil
	}
	if request.Override == nil {
		return decision, nil
	}
	return evaluator.tryOverride(ctx, request, relevant, decision)
}

func (evaluator *Evaluator) ordinaryDecision(request AdmissionRequest, windows []Window, evaluated []evaluatedWindow, evidence []Evidence) (Decision, *evaluatedWindow, error) {
	active := make([]evaluatedWindow, 0)
	for _, item := range evaluated {
		if item.phase == PhaseActive || item.phase == PhaseEnding {
			active = append(active, item)
		}
	}
	governing := mostSpecific(active)
	if len(governing) > 0 {
		if governing[0].window.Effect == EffectDeny {
			decision, err := buildDecision(request, DecisionDeny, "window_denied", &governing[0], time.Time{}, evidence)
			return decision, nil, err
		}
		for _, item := range bestFittingAllows(governing) {
			if item.phase == PhaseActive && !request.At.Add(request.ExpectedDuration).After(item.candidate.endsAt) {
				selected := item
				decision, err := buildDecision(request, DecisionAllow, "window_active", &selected, time.Time{}, evidence)
				return decision, &selected, err
			}
		}
		next, future, err := evaluator.nextEligible(request, windows)
		if err != nil {
			return Decision{}, nil, err
		}
		if future != nil {
			evidence = appendEvidence(evidence, evidenceFor(*future))
			decision, err := buildDecision(request, DecisionDefer, "window_would_overrun", &governing[0], next, evidence)
			return decision, nil, err
		}
		decision, err := buildDecision(request, DecisionDeny, "window_would_overrun", &governing[0], time.Time{}, evidence)
		return decision, nil, err
	}

	missed := make([]evaluatedWindow, 0)
	for _, item := range evaluated {
		if item.phase == PhaseMissed && item.window.Missed == MissedDeny {
			missed = append(missed, item)
		}
	}
	missed = mostSpecific(missed)
	if len(missed) > 0 {
		decision, err := buildDecision(request, DecisionDeny, "window_missed", &missed[0], time.Time{}, evidence)
		return decision, nil, err
	}

	next, future, err := evaluator.nextEligible(request, windows)
	if err != nil {
		return Decision{}, nil, err
	}
	if future != nil {
		evidence = appendEvidence(evidence, evidenceFor(*future))
		reason := "window_planned"
		for _, item := range evaluated {
			if item.phase == PhaseMissed && item.window.Missed == MissedDefer {
				reason = "window_missed_defer"
				break
			}
		}
		if future.phase == PhaseDraining {
			reason = "window_draining"
		}
		decision, err := buildDecision(request, DecisionDefer, reason, future, next, evidence)
		return decision, nil, err
	}
	terminal := make([]evaluatedWindow, 0)
	for _, item := range evaluated {
		if item.phase == PhaseCompleted || item.phase == PhaseMissed {
			terminal = append(terminal, item)
		}
	}
	terminal = mostSpecific(terminal)
	if len(terminal) > 0 {
		reason := "window_completed"
		if terminal[0].phase == PhaseMissed {
			reason = "window_missed"
		}
		decision, err := buildDecision(request, DecisionDeny, reason, &terminal[0], time.Time{}, evidence)
		return decision, nil, err
	}
	decision, err := buildDecision(request, DecisionDeny, "no_eligible_window", nil, time.Time{}, evidence)
	return decision, nil, err
}

func (evaluator *Evaluator) evaluateEvidence(ctx context.Context, windows []Window, at time.Time) ([]evaluatedWindow, error) {
	result := make([]evaluatedWindow, 0, len(windows))
	for _, window := range windows {
		position, err := resolveSchedule(window, at)
		if err != nil {
			return nil, err
		}
		candidates := make([]span, 0, 2)
		if position.current != nil {
			candidates = append(candidates, *position.current)
		} else {
			if position.previous != nil {
				candidates = append(candidates, *position.previous)
			}
			if position.next != nil {
				candidates = append(candidates, *position.next)
			}
		}
		for _, candidate := range candidates {
			occurrence, err := buildOccurrence(window, candidate)
			if err != nil {
				return nil, err
			}
			materialized, err := evaluator.repository.occurrenceExists(ctx, occurrence.ID)
			if err != nil {
				return nil, err
			}
			result = append(result, evaluatedWindow{window: window, candidate: candidate,
				phase: phaseAt(window, candidate, at, materialized), occurrence: occurrence})
		}
	}
	return result, nil
}

func (evaluator *Evaluator) nextEligible(request AdmissionRequest, windows []Window) (time.Time, *evaluatedWindow, error) {
	cursor := request.At
	maximumTransitions := len(windows)*8 + 8
	for step := 0; step < maximumTransitions; step++ {
		nextTransition := time.Time{}
		for _, window := range windows {
			position, err := resolveSchedule(window, cursor)
			if err != nil {
				return time.Time{}, nil, err
			}
			points := make([]time.Time, 0, 2)
			if position.current != nil {
				points = append(points, position.current.endsAt)
			}
			if position.next != nil {
				points = append(points, position.next.startsAt)
			}
			for _, point := range points {
				if point.After(cursor) && (nextTransition.IsZero() || point.Before(nextTransition)) {
					nextTransition = point
				}
			}
		}
		if nextTransition.IsZero() {
			return time.Time{}, nil, nil
		}
		candidates, err := governingAt(windows, nextTransition)
		if err != nil {
			return time.Time{}, nil, err
		}
		if len(candidates) > 0 && candidates[0].window.Effect != EffectDeny {
			for _, candidate := range bestFittingAllows(candidates) {
				if candidate.phase == PhaseActive && !nextTransition.Add(request.ExpectedDuration).After(candidate.candidate.endsAt) {
					selected := candidate
					selected.phase = phaseAt(selected.window, selected.candidate, request.At, false)
					return nextTransition, &selected, nil
				}
			}
		}
		cursor = nextTransition
	}
	return time.Time{}, nil, nil
}

func governingAt(windows []Window, at time.Time) ([]evaluatedWindow, error) {
	active := make([]evaluatedWindow, 0)
	for _, window := range windows {
		position, err := resolveSchedule(window, at)
		if err != nil {
			return nil, err
		}
		if position.current == nil {
			continue
		}
		occurrence, err := buildOccurrence(window, *position.current)
		if err != nil {
			return nil, err
		}
		active = append(active, evaluatedWindow{window: window, candidate: *position.current,
			phase: phaseAt(window, *position.current, at, false), occurrence: occurrence})
	}
	return mostSpecific(active), nil
}

func mostSpecific(items []evaluatedWindow) []evaluatedWindow {
	if len(items) == 0 {
		return nil
	}
	maximum := uint8(0)
	for _, item := range items {
		if item.window.Scope.Specificity() > maximum {
			maximum = item.window.Scope.Specificity()
		}
	}
	result := make([]evaluatedWindow, 0, len(items))
	for _, item := range items {
		if item.window.Scope.Specificity() == maximum {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].window.Effect != result[right].window.Effect {
			return result[left].window.Effect == EffectDeny
		}
		return result[left].window.ID < result[right].window.ID
	})
	return result
}

func bestFittingAllows(items []evaluatedWindow) []evaluatedWindow {
	result := make([]evaluatedWindow, 0, len(items))
	for _, item := range items {
		if item.window.Effect == EffectAllow {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if !result[left].candidate.endsAt.Equal(result[right].candidate.endsAt) {
			return result[left].candidate.endsAt.After(result[right].candidate.endsAt)
		}
		return result[left].window.ID < result[right].window.ID
	})
	return result
}

func (evaluator *Evaluator) tryOverride(ctx context.Context, request AdmissionRequest, windows []Window, ordinary Decision) (Decision, error) {
	denied, err := buildDecision(request, DecisionDeny, "override_invalid", nil, time.Time{}, ordinary.Evidence)
	if err != nil {
		return Decision{}, err
	}
	if request.OperationClass != OperationSecurity && request.OperationClass != OperationRecovery || !overrideAllowed(windows) {
		denied.Reason = "override_forbidden"
		return redigestDecision(denied)
	}
	authorization, err := CanonicalOverride(*request.Override)
	if err != nil {
		return denied, nil
	}
	targetDigest, err := request.Target.Digest()
	if err != nil {
		return Decision{}, err
	}
	if authorization.TenantID != request.Target.TenantID || authorization.TargetDigest != targetDigest || authorization.OperationClass != request.OperationClass || request.At.Before(authorization.NotBefore) || !request.At.Before(authorization.ExpiresAt) || request.At.Before(authorization.IssuedAt) || request.At.Add(request.ExpectedDuration).After(authorization.ExpiresAt) {
		return denied, nil
	}
	if evaluator.overrideVerifier == nil {
		denied.Reason = "override_unverifiable"
		return redigestDecision(denied)
	}
	authorization.Proof = append([]byte(nil), authorization.Proof...)
	if err := evaluator.overrideVerifier.VerifyMaintenanceOverride(ctx, authorization); err != nil {
		return denied, nil
	}
	if evaluator.auditSink == nil {
		denied.Reason = "override_audit_required"
		redigested, digestErr := redigestDecision(denied)
		if digestErr != nil {
			return Decision{}, digestErr
		}
		return redigested, ErrAuditRequired
	}
	record, err := buildAuditRecord(request, authorization, ordinary)
	if err != nil {
		return Decision{}, err
	}
	if err := evaluator.auditSink.RecordMaintenanceOverride(ctx, record); err != nil {
		denied.Reason = "override_audit_failed"
		redigested, digestErr := redigestDecision(denied)
		if digestErr != nil {
			return Decision{}, digestErr
		}
		return redigested, err
	}
	allowed, err := buildDecision(request, DecisionAllow, "emergency_override", nil, time.Time{}, ordinary.Evidence)
	if err != nil {
		return Decision{}, err
	}
	allowed.OverrideID = authorization.ID
	return redigestDecision(allowed)
}

func overrideAllowed(windows []Window) bool {
	if len(windows) == 0 {
		return false
	}
	maximum := uint8(0)
	for _, window := range windows {
		if window.Scope.Specificity() > maximum {
			maximum = window.Scope.Specificity()
		}
	}
	found := false
	for _, window := range windows {
		if window.Scope.Specificity() != maximum {
			continue
		}
		found = true
		if window.EmergencyOverride != OverrideHighAssurance {
			return false
		}
	}
	return found
}

func buildDecision(request AdmissionRequest, kind DecisionKind, reason string, selected *evaluatedWindow, next time.Time, evidence []Evidence) (Decision, error) {
	evidence = canonicalEvidence(evidence)
	raw, err := json.Marshal(evidence)
	if err != nil {
		return Decision{}, err
	}
	decision := Decision{Kind: kind, Reason: reason, RequestID: request.ID, EvaluatedAt: request.At,
		NextEligibleAt: next, Evidence: evidence, EvidenceDigest: digestBytes(raw)}
	if selected != nil {
		decision.Phase = selected.phase
		decision.WindowID = selected.window.ID
		decision.OccurrenceID = selected.occurrence.ID
	}
	return decision, nil
}

func redigestDecision(decision Decision) (Decision, error) {
	decision.Evidence = canonicalEvidence(decision.Evidence)
	raw, err := json.Marshal(decision.Evidence)
	if err != nil {
		return Decision{}, err
	}
	decision.EvidenceDigest = digestBytes(raw)
	return decision, nil
}

func buildAuditRecord(request AdmissionRequest, authorization OverrideAuthorization, ordinary Decision) (OverrideAuditRecord, error) {
	input := strings.Join([]string{authorization.ID, request.ID, string(ordinary.Kind), ordinary.Reason, ordinary.EvidenceDigest}, "\x00")
	record := OverrideAuditRecord{ID: "mwaudit_" + digestBytes([]byte(input))[:48], AuthorizationID: authorization.ID,
		AuthorizationDigest: authorization.Digest, RequestID: request.ID, TenantID: request.Target.TenantID,
		OperationClass: request.OperationClass, At: request.At, PriorDecision: ordinary.Kind,
		PriorReason: ordinary.Reason, EvidenceDigest: ordinary.EvidenceDigest}
	raw, err := json.Marshal(record)
	if err != nil {
		return OverrideAuditRecord{}, err
	}
	record.Digest = digestBytes(raw)
	return record, nil
}

func phaseAt(window Window, candidate span, at time.Time, materialized bool) OccurrencePhase {
	if at.Before(candidate.startsAt) {
		if window.Drain.BeforeStart > 0 && !at.Before(candidate.startsAt.Add(-window.Drain.BeforeStart)) {
			return PhaseDraining
		}
		return PhasePlanned
	}
	if at.Before(candidate.endsAt) {
		if window.Drain.BeforeEnd > 0 && !at.Before(candidate.endsAt.Add(-window.Drain.BeforeEnd)) {
			return PhaseEnding
		}
		return PhaseActive
	}
	if materialized {
		return PhaseCompleted
	}
	return PhaseMissed
}

func scopeMatches(scope Scope, target Target) bool {
	if scope.TenantID != target.TenantID {
		return false
	}
	switch scope.Kind {
	case ScopeTenant:
		return true
	case ScopeNode:
		return scope.NodeID == target.NodeID
	case ScopeResource:
		return (scope.NodeID == "" || scope.NodeID == target.NodeID) && scope.ResourceKind == target.ResourceKind && scope.ResourceID == target.ResourceID
	default:
		return false
	}
}

func classIncluded(classes []OperationClass, class OperationClass) bool {
	index := sort.Search(len(classes), func(index int) bool { return classes[index] >= class })
	return index < len(classes) && classes[index] == class
}

func evidenceFromEvaluated(items []evaluatedWindow) []Evidence {
	evidence := make([]Evidence, 0, len(items))
	for _, item := range items {
		evidence = append(evidence, evidenceFor(item))
	}
	return canonicalEvidence(evidence)
}

func evidenceFor(item evaluatedWindow) Evidence {
	return Evidence{WindowID: item.window.ID, WindowGeneration: item.window.Generation,
		Specificity: item.window.Scope.Specificity(), Effect: item.window.Effect, Phase: item.phase,
		OccurrenceID: item.occurrence.ID, StartsAt: item.candidate.startsAt, EndsAt: item.candidate.endsAt}
}

func appendEvidence(evidence []Evidence, item Evidence) []Evidence {
	for _, existing := range evidence {
		if existing.WindowID == item.WindowID && existing.OccurrenceID == item.OccurrenceID {
			return evidence
		}
	}
	return append(evidence, item)
}

func canonicalEvidence(evidence []Evidence) []Evidence {
	result := append([]Evidence(nil), evidence...)
	sort.Slice(result, func(left, right int) bool {
		if result[left].Specificity != result[right].Specificity {
			return result[left].Specificity > result[right].Specificity
		}
		if result[left].Effect != result[right].Effect {
			return result[left].Effect == EffectDeny
		}
		if result[left].WindowID != result[right].WindowID {
			return result[left].WindowID < result[right].WindowID
		}
		return result[left].OccurrenceID < result[right].OccurrenceID
	})
	return result
}
