package alerts

import (
	"context"
	"time"
)

const (
	defaultRulesPerSample = 128
	defaultSamplesPerBatch = 256
	defaultPendingDelivery = 128
)

type EvaluatorConfig struct {
	RulesPerSample int
	SamplesPerBatch int
	PendingDelivery int
	Clock            func() time.Time
}

// Evaluator advances persisted rule state synchronously. It owns no collector,
// notification transport, scheduler, or background goroutine.
type Evaluator struct {
	repository       *Repository
	sink             Sink
	rulesPerSample   int
	samplesPerBatch  int
	pendingDelivery  int
	clock            func() time.Time
}

func NewEvaluator(repository *Repository, sink Sink, config EvaluatorConfig) (*Evaluator, error) {
	if repository == nil || repository.db == nil || sink == nil {
		return nil, ErrInvalid
	}
	if config.RulesPerSample == 0 {
		config.RulesPerSample = defaultRulesPerSample
	}
	if config.SamplesPerBatch == 0 {
		config.SamplesPerBatch = defaultSamplesPerBatch
	}
	if config.PendingDelivery == 0 {
		config.PendingDelivery = defaultPendingDelivery
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.RulesPerSample < 1 || config.RulesPerSample > MaxPageSize ||
		config.SamplesPerBatch < 1 || config.SamplesPerBatch > MaxPageSize ||
		config.PendingDelivery < 1 || config.PendingDelivery > MaxPageSize {
		return nil, ErrInvalid
	}
	return &Evaluator{repository: repository, sink: sink, rulesPerSample: config.RulesPerSample,
		samplesPerBatch: config.SamplesPerBatch, pendingDelivery: config.PendingDelivery, clock: config.Clock}, nil
}

type EvaluationResult struct {
	RuleID    string
	State     State
	Event     *AlertEvent
	Delivered bool
}

// EvaluateRule evaluates one canonical sample against one explicitly selected
// rule. A committed event remains in the outbox when its sink returns an error.
func (evaluator *Evaluator) EvaluateRule(ctx context.Context, ruleID string, sample Sample) (EvaluationResult, error) {
	canonical, err := CanonicalSample(sample)
	if err != nil {
		return EvaluationResult{}, err
	}
	now, err := evaluator.now()
	if err != nil {
		return EvaluationResult{}, err
	}
	event, pending, err := evaluator.repository.advance(ctx, ruleID, canonical, now)
	if err != nil {
		return EvaluationResult{}, err
	}
	result := EvaluationResult{RuleID: ruleID, Event: event}
	result.State, err = evaluator.repository.LoadState(ctx, ruleID)
	if err != nil {
		return result, err
	}
	if event != nil && pending {
		if err := evaluator.sink.Emit(ctx, cloneEvent(*event)); err != nil {
			return result, err
		}
		completedAt, err := evaluator.now()
		if err != nil {
			return result, err
		}
		if err := evaluator.repository.MarkEventDelivered(ctx, event.ID, event.Digest, completedAt); err != nil {
			return result, err
		}
		result.Delivered = true
	} else if event != nil {
		result.Delivered = true
	}
	return result, nil
}

// EvaluateSample finds enabled rules with an exact tenant/resource/signal
// match. The configured cap turns unbounded fan-out into ErrCapacity.
func (evaluator *Evaluator) EvaluateSample(ctx context.Context, sample Sample) ([]EvaluationResult, error) {
	canonical, err := CanonicalSample(sample)
	if err != nil {
		return nil, err
	}
	rules, err := evaluator.repository.matchRules(ctx, canonical, evaluator.rulesPerSample)
	if err != nil {
		return nil, err
	}
	results := make([]EvaluationResult, 0, len(rules))
	for _, rule := range rules {
		result, err := evaluator.EvaluateRule(ctx, rule.ID, canonical)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (evaluator *Evaluator) EvaluateBatch(ctx context.Context, samples []Sample) ([]EvaluationResult, error) {
	if len(samples) == 0 || len(samples) > evaluator.samplesPerBatch {
		return nil, ErrCapacity
	}
	results := make([]EvaluationResult, 0)
	for _, sample := range samples {
		sampleResults, err := evaluator.EvaluateSample(ctx, sample)
		results = append(results, sampleResults...)
		if err != nil {
			return results, err
		}
	}
	return results, nil
}

type DueEvaluation struct {
	Evaluated  int
	NextCursor string
}

// EvaluateDue records missing input as unknown. It never manufactures a
// healthy value or a recovery event from absence.
func (evaluator *Evaluator) EvaluateDue(ctx context.Context, tenantID string, at time.Time, limit int, cursor string) (DueEvaluation, error) {
	if limit < 1 || limit > evaluator.rulesPerSample {
		return DueEvaluation{}, ErrInvalid
	}
	page, err := evaluator.repository.ListDue(ctx, tenantID, at, limit, cursor)
	if err != nil {
		return DueEvaluation{}, err
	}
	result := DueEvaluation{NextCursor: page.NextCursor}
	for _, item := range page.Items {
		sample, err := CanonicalSample(Sample{Kind: item.Rule.Kind, Scope: item.Rule.Scope,
			Status: SampleUnknown, SourceID: "alerts.due", ObservedAt: at})
		if err != nil {
			return result, err
		}
		if _, _, err := evaluator.repository.advance(ctx, item.Rule.ID, sample, at); err != nil {
			return result, err
		}
		result.Evaluated++
	}
	return result, nil
}

type DeliveryResult struct {
	Delivered  int
	NextCursor string
}

// DeliverPending retries a bounded page. Event IDs and digests let a sink make
// the unavoidable emit/ack boundary idempotent.
func (evaluator *Evaluator) DeliverPending(ctx context.Context, limit int, cursor string) (DeliveryResult, error) {
	if limit < 1 || limit > evaluator.pendingDelivery {
		return DeliveryResult{}, ErrInvalid
	}
	page, err := evaluator.repository.ListPendingEvents(ctx, limit, cursor)
	if err != nil {
		return DeliveryResult{}, err
	}
	result := DeliveryResult{NextCursor: page.NextCursor}
	for _, event := range page.Events {
		if err := evaluator.sink.Emit(ctx, cloneEvent(event)); err != nil {
			return result, err
		}
		completedAt, err := evaluator.now()
		if err != nil {
			return result, err
		}
		if err := evaluator.repository.MarkEventDelivered(ctx, event.ID, event.Digest, completedAt); err != nil {
			return result, err
		}
		result.Delivered++
	}
	return result, nil
}

func (evaluator *Evaluator) now() (time.Time, error) {
	now := evaluator.clock()
	if !validTimestamp(now) {
		return time.Time{}, ErrInvalid
	}
	return now, nil
}

func advanceState(rule Rule, state State, sample Sample, now time.Time) (State, *AlertEvent, error) {
	if err := rule.Validate(); err != nil {
		return State{}, nil, err
	}
	if err := state.Validate(); err != nil {
		return State{}, nil, err
	}
	if canonical, err := CanonicalSample(sample); err != nil || canonical != sample {
		if err != nil {
			return State{}, nil, err
		}
		return State{}, nil, ErrInvalid
	}
	if state.RuleID != rule.ID || state.RuleGeneration != rule.Generation {
		return State{}, nil, ErrConflict
	}
	if rule.Kind != sample.Kind || rule.Scope != sample.Scope {
		return State{}, nil, ErrScope
	}
	if state.Generation == maxGeneration {
		return State{}, nil, ErrCapacity
	}

	next := state
	next.Generation++
	next.LastStatus = sample.Status
	next.LastSampleDigest = sample.Digest
	next.LastObservedAt = sample.ObservedAt
	next.NextDueAt = sample.ObservedAt.Add(rule.Window)
	next.UpdatedAt = now
	if sample.Status == SampleUnknown {
		next.Condition = ConditionUnknown
		next.ConsecutiveBad = 0
		next.ConsecutiveGood = 0
		next.LastValue = nil
		return validatedTransition(next, nil)
	}

	value := sample.Value
	next.LastValue = &value
	triggered := thresholdTriggered(rule, value)
	if !state.Active {
		next.ConsecutiveGood = 0
		if !triggered {
			next.Condition = ConditionHealthy
			next.ConsecutiveBad = 0
			return validatedTransition(next, nil)
		}
		next.Condition = ConditionUnhealthy
		next.ConsecutiveBad = incrementUntil(next.ConsecutiveBad, rule.ConsecutiveSamples)
		if next.ConsecutiveBad < rule.ConsecutiveSamples || sample.ObservedAt.Before(state.CooldownUntil) {
			return validatedTransition(next, nil)
		}
		next.Active = true
		next.LastFiredAt = sample.ObservedAt
		next.CooldownUntil = sample.ObservedAt.Add(rule.Cooldown)
		event, err := buildEvent(EventFiring, rule, next, sample, now)
		if err != nil {
			return State{}, nil, err
		}
		return validatedTransition(next, &event)
	}

	next.ConsecutiveBad = 0
	if !thresholdRecovered(rule, value) {
		next.Condition = ConditionUnhealthy
		next.ConsecutiveGood = 0
		return validatedTransition(next, nil)
	}
	next.Condition = ConditionHealthy
	next.ConsecutiveGood = incrementUntil(next.ConsecutiveGood, rule.ConsecutiveSamples)
	if rule.Recovery == RecoveryManual || next.ConsecutiveGood < rule.ConsecutiveSamples {
		return validatedTransition(next, nil)
	}
	next.Active = false
	next.LastRecoveredAt = sample.ObservedAt
	next.CooldownUntil = laterTime(next.CooldownUntil, sample.ObservedAt.Add(rule.Cooldown))
	event, err := buildEvent(EventRecovery, rule, next, sample, now)
	if err != nil {
		return State{}, nil, err
	}
	return validatedTransition(next, &event)
}

func thresholdTriggered(rule Rule, value float64) bool {
	switch rule.Comparator {
	case ComparatorGreaterThan:
		return value > rule.Threshold
	case ComparatorGreaterThanOrEqual:
		return value >= rule.Threshold
	case ComparatorLessThan:
		return value < rule.Threshold
	case ComparatorLessThanOrEqual:
		return value <= rule.Threshold
	case ComparatorEqual:
		return value == rule.Threshold
	case ComparatorNotEqual:
		return value != rule.Threshold
	default:
		return false
	}
}

func thresholdRecovered(rule Rule, value float64) bool {
	switch rule.Comparator {
	case ComparatorGreaterThan:
		return value <= rule.Threshold-rule.Hysteresis
	case ComparatorGreaterThanOrEqual:
		return value < rule.Threshold-rule.Hysteresis
	case ComparatorLessThan:
		return value >= rule.Threshold+rule.Hysteresis
	case ComparatorLessThanOrEqual:
		return value > rule.Threshold+rule.Hysteresis
	case ComparatorEqual:
		return value != rule.Threshold
	case ComparatorNotEqual:
		return value == rule.Threshold
	default:
		return false
	}
}

func validatedTransition(state State, event *AlertEvent) (State, *AlertEvent, error) {
	if err := state.Validate(); err != nil {
		return State{}, nil, err
	}
	if event != nil {
		if err := event.Validate(); err != nil {
			return State{}, nil, err
		}
	}
	return state, event, nil
}

func incrementUntil(current, limit uint16) uint16 {
	if current < limit {
		return current + 1
	}
	return limit
}

func laterTime(left, right time.Time) time.Time {
	if left.After(right) {
		return left
	}
	return right
}

func cloneEvent(event AlertEvent) AlertEvent {
	event.NotificationRouteRefs = append([]string(nil), event.NotificationRouteRefs...)
	if event.Value != nil {
		value := *event.Value
		event.Value = &value
	}
	return event
}
