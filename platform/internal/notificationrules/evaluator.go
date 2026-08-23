package notificationrules

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

const mandatoryCriticalRuleID = "system-critical-local-inbox"

type EvaluationInput struct {
	Event          Event
	Rules          []Rule
	DeliveryStates []DeliveryState
	DedupStates    []DedupState
	Now            time.Time
}

func hashParts(prefix string, values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte(strconv.Itoa(len(value))))
		hash.Write([]byte{':'})
		hash.Write([]byte(value))
	}
	return prefix + hex.EncodeToString(hash.Sum(nil))[:48]
}

func eventDedupDigest(event Event) string {
	dedupValue := event.DedupKey
	if dedupValue == "" {
		dedupValue = event.ResourceKind + "\x00" + event.ResourceID
		if event.ResourceKind == "" {
			dedupValue = event.ID
		}
	}
	digest := sha256.Sum256([]byte(event.TenantID + "\x00" + string(event.Source) + "\x00" + string(event.Kind) + "\x00" + dedupValue))
	return hex.EncodeToString(digest[:])
}

func planID(event Event, ruleID string, revision uint64, stage uint16, destination Destination) string {
	return hashParts("nr_", event.TenantID, event.ID, ruleID, strconv.FormatUint(revision, 10), strconv.FormatUint(uint64(stage), 10), string(destination.Kind), destination.ID)
}

func containsValue[T comparable](values []T, target T) bool {
	for _, value := range values {
		if value == target { return true }
	}
	return false
}

func matches(rule Rule, event Event) bool {
	predicate := rule.Match
	if len(predicate.Sources) != 0 && !containsValue(predicate.Sources, event.Source) { return false }
	if len(predicate.Kinds) != 0 && !containsValue(predicate.Kinds, event.Kind) { return false }
	if len(predicate.ResourceKinds) != 0 && !containsValue(predicate.ResourceKinds, event.ResourceKind) { return false }
	for _, label := range predicate.Labels {
		value, exists := event.Labels[label.Key]
		switch label.Operator {
		case LabelEquals:
			if !exists || value != label.Value { return false }
		case LabelNotEquals:
			if exists && value == label.Value { return false }
		case LabelExists:
			if !exists { return false }
		case LabelNotExists:
			if exists { return false }
		default:
			return false
		}
	}
	return true
}

func quietAt(windows []QuietWindow, local time.Time) bool {
	minute := uint16(local.Hour()*60 + local.Minute())
	weekday := local.Weekday()
	for _, window := range windows {
		for _, startDay := range window.Weekdays {
			if window.StartMinute < window.EndMinute {
				if weekday == startDay && minute >= window.StartMinute && minute < window.EndMinute { return true }
				continue
			}
			if weekday == startDay && minute >= window.StartMinute { return true }
			if weekday == time.Weekday((int(startDay)+1)%7) && minute < window.EndMinute { return true }
		}
	}
	return false
}

func quietEnd(rule Rule, now time.Time) (time.Time, bool, error) {
	if len(rule.QuietHours) == 0 || rule.QuietBypassAt <= SeverityInfo {
		return time.Time{}, false, nil
	}
	location, err := time.LoadLocation(rule.Timezone)
	if err != nil { return time.Time{}, false, ErrInvalid }
	local := now.In(location)
	if !quietAt(rule.QuietHours, local) { return time.Time{}, false, nil }
	candidate := time.Date(local.Year(), local.Month(), local.Day(), local.Hour(), local.Minute(), 0, 0, location).Add(time.Minute)
	for checked := 0; checked < 14*24*60; checked++ {
		if !quietAt(rule.QuietHours, candidate) { return candidate.UTC(), true, nil }
		candidate = candidate.Add(time.Minute)
	}
	return time.Time{}, false, ErrInvalid
}

func dedupStateKey(ruleID string, stage uint16, destination Destination, digest string) string {
	return strings.Join([]string{ruleID, strconv.FormatUint(uint64(stage), 10), string(destination.Kind), destination.ID, digest}, "\x00")
}

func deliveryDecision(state DeliveryState, now time.Time, retryPolicy RetryPolicy) (RouteAction, ReasonCode, time.Time, bool) {
	switch state.Status {
	case DeliveryDelivered:
		return RouteSuppress, ReasonAlreadyDelivered, time.Time{}, true
	case DeliverySuppressed:
		return RouteSuppress, ReasonDeliverySuppressed, time.Time{}, true
	case DeliveryFailed:
		return RouteSuppress, ReasonDeliveryFailed, time.Time{}, true
	case DeliveryQueued, DeliveryRetry:
		if state.Status == DeliveryRetry && state.Attempts >= retryPolicy.normalized().MaximumAttempts {
			return RouteSuppress, ReasonRetryExhausted, time.Time{}, true
		}
		if state.NextAttemptAt.After(now) {
			return RouteDefer, ReasonDeliveryDeferred, state.NextAttemptAt, true
		}
	}
	return "", "", time.Time{}, false
}

func NextRetryAt(rule Rule, completedAttempts uint32, now time.Time) (time.Time, error) {
	if rule.ValidateConfiguration() != nil || completedAttempts == 0 || now.IsZero() {
		return time.Time{}, ErrInvalid
	}
	policy := rule.RetryPolicy.normalized()
	if completedAttempts >= policy.MaximumAttempts { return time.Time{}, ErrLimit }
	delay := policy.InitialBackoff
	for attempt := uint32(1); attempt < completedAttempts && delay < policy.MaximumBackoff; attempt++ {
		if delay > policy.MaximumBackoff/2 { delay = policy.MaximumBackoff; break }
		delay *= 2
	}
	if delay > policy.MaximumBackoff { delay = policy.MaximumBackoff }
	next := now.UTC().Add(delay)
	if !next.After(now) { return time.Time{}, ErrInvalid }
	return next, nil
}

func AdvanceDedupState(rule Rule, event Event, plan RoutePlan, existing *DedupState, deliveredAt time.Time) (DedupState, error) {
	if rule.ValidateStored() != nil || event.Validate() != nil || deliveredAt.IsZero() || deliveredAt.Before(event.OccurredAt) || plan.Action != RouteSend || plan.TenantID != event.TenantID || plan.EventID != event.ID || plan.RuleID != rule.ID || plan.RuleRevision != rule.Revision || plan.DedupDigest != eventDedupDigest(event) || plan.Destination.Validate() != nil || int(plan.Stage) >= len(rule.Escalation) || plan.ID != planID(event, rule.ID, rule.Revision, plan.Stage, plan.Destination) {
		return DedupState{}, ErrInvalid
	}
	if !containsValue(rule.Escalation[plan.Stage].Destinations, plan.Destination) { return DedupState{}, ErrInvalid }
	state := DedupState{
		TenantID: event.TenantID, RuleID: rule.ID, Stage: plan.Stage, DestinationKind: plan.Destination.Kind,
		DestinationID: plan.Destination.ID, DedupDigest: plan.DedupDigest, LastEventID: event.ID,
		LastDeliveredAt: deliveredAt.UTC(),
	}
	if existing != nil {
		if existing.ValidateStored() != nil || existing.TenantID != state.TenantID || existing.RuleID != state.RuleID || existing.Stage != state.Stage || existing.DestinationKind != state.DestinationKind || existing.DestinationID != state.DestinationID || existing.DedupDigest != state.DedupDigest {
			return DedupState{}, ErrInvalid
		}
	}
	if rule.RateLimit != (RateLimit{}) {
		state.RateWindowStarted = deliveredAt.UTC()
		state.RateCount = 1
		if existing != nil && !existing.RateWindowStarted.IsZero() {
			windowEnd := existing.RateWindowStarted.Add(rule.RateLimit.Window)
			if !windowEnd.After(existing.RateWindowStarted) { return DedupState{}, ErrInvalid }
			if windowEnd.After(deliveredAt) {
				if existing.RateCount >= rule.RateLimit.Maximum { return DedupState{}, ErrLimit }
				state.RateWindowStarted = existing.RateWindowStarted
				state.RateCount = existing.RateCount + 1
			}
		}
	}
	return state, nil
}

type deferral struct {
	reason ReasonCode
	at     time.Time
	rank   uint8
}

func latestDeferral(values ...deferral) (deferral, bool) {
	var selected deferral
	found := false
	for _, value := range values {
		if value.at.IsZero() { continue }
		if !found || value.at.After(selected.at) || value.at.Equal(selected.at) && value.rank < selected.rank {
			selected, found = value, true
		}
	}
	return selected, found
}

func protectedCriticalSource(source EventSource) bool {
	return source == SourceBackup || source == SourceSecurity || source == SourceCertificate || source == SourceHealth
}

func appendPlan(plans []RoutePlan, plan RoutePlan) ([]RoutePlan, error) {
	if len(plans) >= MaximumRoutePlans { return nil, ErrLimit }
	return append(plans, plan), nil
}

func Evaluate(input EvaluationInput) ([]RoutePlan, error) {
	if err := input.Event.Validate(); err != nil || input.Now.IsZero() || input.Now.Before(input.Event.OccurredAt) || len(input.Rules) > MaximumRulesPerTenant || len(input.DeliveryStates) > MaximumRoutePlans || len(input.DedupStates) > MaximumRoutePlans {
		return nil, ErrInvalid
	}
	now := input.Now.UTC()
	rules := append([]Rule(nil), input.Rules...)
	ruleIDs := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ValidateStored() != nil || rule.TenantID != input.Event.TenantID {
			return nil, ErrInvalid
		}
		if _, duplicate := ruleIDs[rule.ID]; duplicate { return nil, ErrInvalid }
		ruleIDs[rule.ID] = struct{}{}
	}
	stableRules(rules)
	deliveryStates := make(map[string]DeliveryState, len(input.DeliveryStates))
	for _, state := range input.DeliveryStates {
		if state.ValidateStored() != nil || state.TenantID != input.Event.TenantID {
			return nil, ErrInvalid
		}
		if _, duplicate := deliveryStates[state.ID]; duplicate { return nil, ErrInvalid }
		deliveryStates[state.ID] = state
	}
	dedupStates := make(map[string]DedupState, len(input.DedupStates))
	for _, state := range input.DedupStates {
		if state.ValidateStored() != nil || state.TenantID != input.Event.TenantID {
			return nil, ErrInvalid
		}
		key := dedupStateKey(state.RuleID, state.Stage, Destination{Kind: state.DestinationKind, ID: state.DestinationID}, state.DedupDigest)
		if _, duplicate := dedupStates[key]; duplicate { return nil, ErrInvalid }
		dedupStates[key] = state
	}
	dedupDigest := eventDedupDigest(input.Event)
	plans := make([]RoutePlan, 0)
	var err error
	for _, rule := range rules {
		if !rule.Enabled || !matches(rule, input.Event) { continue }
		quietUntil, inQuietHours, quietErr := quietEnd(rule, now)
		if quietErr != nil { return nil, quietErr }
		for stageIndex, configuredStage := range rule.Escalation {
			stage := configuredStage
			destinations := append([]Destination(nil), stage.Destinations...)
			sort.Slice(destinations, func(left, right int) bool {
				if destinations[left].Kind != destinations[right].Kind { return destinations[left].Kind < destinations[right].Kind }
				if destinations[left].ID != destinations[right].ID { return destinations[left].ID < destinations[right].ID }
				return destinations[left].RecipientRef < destinations[right].RecipientRef
			})
			dueAt := input.Event.OccurredAt.UTC().Add(stage.After)
			if stage.After > 0 && !dueAt.After(input.Event.OccurredAt) { return nil, ErrInvalid }
			for _, destination := range destinations {
				plan := RoutePlan{
					ID: planID(input.Event, rule.ID, rule.Revision, uint16(stageIndex), destination), TenantID: input.Event.TenantID,
					EventID: input.Event.ID, RuleID: rule.ID, RuleRevision: rule.Revision, Stage: uint16(stageIndex), Destination: destination,
					Action: RouteSend, ReasonCode: ReasonReady, DedupDigest: dedupDigest, EvaluatedAt: now,
				}
				switch {
				case input.Event.Severity < rule.MinimumSeverity:
					plan.Action, plan.ReasonCode = RouteSuppress, ReasonSeverityBelowRule
				case input.Event.Severity < stage.MinimumSeverity:
					plan.Action, plan.ReasonCode = RouteSuppress, ReasonSeverityBelowStage
				case dueAt.After(now):
					plan.Action, plan.ReasonCode, plan.NextAttemptAt = RouteDefer, ReasonEscalationPending, dueAt
				default:
					if state, exists := deliveryStates[plan.ID]; exists {
						if state.EventID != input.Event.ID || state.RuleID != rule.ID { return nil, ErrInvalid }
						if action, reason, next, decided := deliveryDecision(state, now, rule.RetryPolicy); decided {
							plan.Action, plan.ReasonCode, plan.NextAttemptAt = action, reason, next
							break
						}
					}
					if destination.Kind == DestinationLocalInbox { break }
					state, hasDedupState := dedupStates[dedupStateKey(rule.ID, uint16(stageIndex), destination, dedupDigest)]
					if hasDedupState && rule.DedupWindow > 0 {
						dedupUntil := state.LastDeliveredAt.Add(rule.DedupWindow)
						if !dedupUntil.After(state.LastDeliveredAt) { return nil, ErrInvalid }
						if dedupUntil.After(now) {
							plan.Action, plan.ReasonCode = RouteSuppress, ReasonDeduplicated
							break
						}
					}
					deferrals := make([]deferral, 0, 2)
					if inQuietHours && input.Event.Severity < rule.QuietBypassAt {
						deferrals = append(deferrals, deferral{reason: ReasonQuietHours, at: quietUntil, rank: 1})
					}
					if hasDedupState && rule.RateLimit != (RateLimit{}) && !state.RateWindowStarted.IsZero() {
						windowEnd := state.RateWindowStarted.Add(rule.RateLimit.Window)
						if !windowEnd.After(state.RateWindowStarted) { return nil, ErrInvalid }
						if windowEnd.After(now) && state.RateCount >= rule.RateLimit.Maximum {
							deferrals = append(deferrals, deferral{reason: ReasonRateLimited, at: windowEnd, rank: 2})
						}
					}
					if deferred, found := latestDeferral(deferrals...); found {
						plan.Action, plan.ReasonCode, plan.NextAttemptAt = RouteDefer, deferred.reason, deferred.at
					}
				}
				plans, err = appendPlan(plans, plan)
				if err != nil { return nil, err }
			}
		}
	}
	if input.Event.Severity == SeverityCritical && protectedCriticalSource(input.Event.Source) {
		covered := false
		for _, plan := range plans {
			if plan.Destination.Kind == DestinationLocalInbox && (plan.Action == RouteSend || plan.ReasonCode == ReasonAlreadyDelivered || plan.ReasonCode == ReasonDeliveryDeferred) {
				covered = true
				break
			}
		}
		if !covered {
			destination := Destination{ID: "mandatory", Kind: DestinationLocalInbox, RecipientRef: "tenant-owners"}
			mandatory := RoutePlan{
				ID: planID(input.Event, mandatoryCriticalRuleID, 1, 0, destination), TenantID: input.Event.TenantID, EventID: input.Event.ID,
				RuleID: mandatoryCriticalRuleID, RuleRevision: 1, Stage: 0, Destination: destination,
				Action: RouteSend, ReasonCode: ReasonMandatoryLocalInbox, DedupDigest: dedupDigest, EvaluatedAt: now,
			}
			if state, exists := deliveryStates[mandatory.ID]; exists {
				if state.EventID != input.Event.ID || state.RuleID != mandatoryCriticalRuleID { return nil, ErrInvalid }
				if action, reason, next, decided := deliveryDecision(state, now, DefaultRetryPolicy()); decided {
					mandatory.Action, mandatory.ReasonCode, mandatory.NextAttemptAt = action, reason, next
				}
			}
			plans, err = appendPlan(plans, mandatory)
			if err != nil { return nil, err }
			copy(plans[1:], plans[:len(plans)-1])
			plans[0] = mandatory
		}
	}
	return plans, nil
}
