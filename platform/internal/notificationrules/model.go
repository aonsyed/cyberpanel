package notificationrules

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid      = errors.New("notification rules: invalid value")
	ErrUnauthorized = errors.New("notification rules: unauthorized")
	ErrNotFound     = errors.New("notification rules: not found")
	ErrConflict     = errors.New("notification rules: revision conflict")
	ErrLimit        = errors.New("notification rules: limit exceeded")
	ErrIntegrity    = errors.New("notification rules: integrity failure")
)

const (
	MaximumRulesPerTenant        = 128
	MaximumMatchValues           = 32
	MaximumLabelPredicates       = 16
	MaximumQuietWindows          = 14
	MaximumEscalationStages      = 8
	MaximumDestinationsPerStage  = 8
	MaximumRoutePlans            = MaximumRulesPerTenant * MaximumEscalationStages * MaximumDestinationsPerStage
	MaximumPageSize              = 128
	MaximumDeliveryStatesPerTenant = 65536
	MaximumDedupStatesPerTenant  = 65536
	MaximumRuleJSONBytes         = 64 << 10
	MaximumStateJSONBytes        = 16 << 10
	MaximumDedupWindow           = 30 * 24 * time.Hour
	MaximumRateWindow            = 24 * time.Hour
	MaximumEscalationDelay       = 30 * 24 * time.Hour
	MaximumDeliveryAttempts      = 1000
)

var (
	opaquePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	labelKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	labelValuePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	timezonePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
)

type EventSource string

const (
	SourceOperation   EventSource = "operation"
	SourceHealth      EventSource = "health"
	SourceQuota       EventSource = "quota"
	SourceBackup      EventSource = "backup"
	SourceSecurity    EventSource = "security"
	SourceCertificate EventSource = "certificate"
	SourceProvider    EventSource = "provider"
	SourceMail        EventSource = "mail"
	SourceUpdate      EventSource = "update"
	SourceMigration   EventSource = "migration"
)

func (source EventSource) Valid() bool {
	switch source {
	case SourceOperation, SourceHealth, SourceQuota, SourceBackup, SourceSecurity, SourceCertificate, SourceProvider, SourceMail, SourceUpdate, SourceMigration:
		return true
	default:
		return false
	}
}

type EventKind string

const (
	KindOperationFailed       EventKind = "operation.failed"
	KindOperationStalled      EventKind = "operation.stalled"
	KindOperationCompleted    EventKind = "operation.completed"
	KindHealthDegraded        EventKind = "health.degraded"
	KindHealthRecovered       EventKind = "health.recovered"
	KindQuotaWarning          EventKind = "quota.warning"
	KindQuotaExceeded         EventKind = "quota.exceeded"
	KindBackupFailed          EventKind = "backup.failed"
	KindBackupRPOBreached     EventKind = "backup.rpo_breached"
	KindBackupProofFailed     EventKind = "backup.restore_proof_failed"
	KindSecurityFinding       EventKind = "security.finding"
	KindSecurityAuditGap      EventKind = "security.audit_gap"
	KindSecurityCredential    EventKind = "security.credential"
	KindSecurityAuthorization EventKind = "security.authorization"
	KindCertificateExpiring   EventKind = "certificate.expiring"
	KindCertificateFailed     EventKind = "certificate.renewal_failed"
	KindProviderDegraded      EventKind = "provider.degraded"
	KindProviderRecovered     EventKind = "provider.recovered"
	KindMailQueuePressure     EventKind = "mail.queue_pressure"
	KindMailDeliveryFailed    EventKind = "mail.delivery_failed"
	KindUpdateAvailable       EventKind = "update.available"
	KindUpdateFailed          EventKind = "update.failed"
	KindMigrationWaiting      EventKind = "migration.waiting"
	KindMigrationFailed       EventKind = "migration.failed"
	KindMigrationCompleted    EventKind = "migration.completed"
)

var eventKindSources = map[EventKind]EventSource{
	KindOperationFailed: SourceOperation, KindOperationStalled: SourceOperation, KindOperationCompleted: SourceOperation,
	KindHealthDegraded: SourceHealth, KindHealthRecovered: SourceHealth,
	KindQuotaWarning: SourceQuota, KindQuotaExceeded: SourceQuota,
	KindBackupFailed: SourceBackup, KindBackupRPOBreached: SourceBackup, KindBackupProofFailed: SourceBackup,
	KindSecurityFinding: SourceSecurity, KindSecurityAuditGap: SourceSecurity, KindSecurityCredential: SourceSecurity, KindSecurityAuthorization: SourceSecurity,
	KindCertificateExpiring: SourceCertificate, KindCertificateFailed: SourceCertificate,
	KindProviderDegraded: SourceProvider, KindProviderRecovered: SourceProvider,
	KindMailQueuePressure: SourceMail, KindMailDeliveryFailed: SourceMail,
	KindUpdateAvailable: SourceUpdate, KindUpdateFailed: SourceUpdate,
	KindMigrationWaiting: SourceMigration, KindMigrationFailed: SourceMigration, KindMigrationCompleted: SourceMigration,
}

func (kind EventKind) Source() (EventSource, bool) {
	source, found := eventKindSources[kind]
	return source, found
}

type Severity uint8

const (
	SeverityInfo Severity = iota + 1
	SeverityWarning
	SeverityError
	SeverityCritical
)

func (severity Severity) Valid() bool { return severity >= SeverityInfo && severity <= SeverityCritical }

type DestinationKind string

const (
	DestinationLocalInbox   DestinationKind = "local_inbox"
	DestinationSMTP         DestinationKind = "smtp"
	DestinationSignedWebhook DestinationKind = "signed_webhook"
)

func (kind DestinationKind) Valid() bool {
	return kind == DestinationLocalInbox || kind == DestinationSMTP || kind == DestinationSignedWebhook
}

type Destination struct {
	ID           string          `json:"id"`
	Kind         DestinationKind `json:"kind"`
	RecipientRef string          `json:"recipient_ref"`
	BindingRef   string          `json:"binding_ref,omitempty"`
}

func (destination Destination) Validate() error {
	if !opaquePattern.MatchString(destination.ID) || !destination.Kind.Valid() || !opaquePattern.MatchString(destination.RecipientRef) {
		return ErrInvalid
	}
	if destination.Kind == DestinationLocalInbox {
		if destination.BindingRef != "" {
			return ErrInvalid
		}
		return nil
	}
	if !opaquePattern.MatchString(destination.BindingRef) {
		return ErrInvalid
	}
	return nil
}

type LabelOperator string

const (
	LabelEquals    LabelOperator = "equals"
	LabelNotEquals LabelOperator = "not_equals"
	LabelExists    LabelOperator = "exists"
	LabelNotExists LabelOperator = "not_exists"
)

type LabelPredicate struct {
	Key      string        `json:"key"`
	Operator LabelOperator `json:"operator"`
	Value    string        `json:"value,omitempty"`
}

func sensitiveLabelKey(key string) bool {
	normalized := strings.ReplaceAll(strings.ToLower(key), "-", "_")
	for _, fragment := range []string{"password", "passwd", "passphrase", "secret", "token", "credential", "authorization", "cookie", "private_key", "api_key", "apikey"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func (predicate LabelPredicate) Validate() error {
	if !labelKeyPattern.MatchString(predicate.Key) || sensitiveLabelKey(predicate.Key) {
		return ErrInvalid
	}
	switch predicate.Operator {
	case LabelEquals, LabelNotEquals:
		if !labelValuePattern.MatchString(predicate.Value) {
			return ErrInvalid
		}
	case LabelExists, LabelNotExists:
		if predicate.Value != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type MatchPredicate struct {
	Sources       []EventSource   `json:"sources,omitempty"`
	Kinds         []EventKind     `json:"kinds,omitempty"`
	ResourceKinds []string        `json:"resource_kinds,omitempty"`
	Labels        []LabelPredicate `json:"labels,omitempty"`
}

func uniqueStrings[T ~string](values []T, maximum int, valid func(T) bool) bool {
	if len(values) > maximum {
		return false
	}
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if !valid(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func (predicate MatchPredicate) Validate() error {
	if !uniqueStrings(predicate.Sources, MaximumMatchValues, func(value EventSource) bool { return value.Valid() }) || !uniqueStrings(predicate.Kinds, MaximumMatchValues, func(value EventKind) bool { _, ok := value.Source(); return ok }) || !uniqueStrings(predicate.ResourceKinds, MaximumMatchValues, func(value string) bool { return opaquePattern.MatchString(value) }) || len(predicate.Labels) > MaximumLabelPredicates {
		return ErrInvalid
	}
	sourceSet := make(map[EventSource]struct{}, len(predicate.Sources))
	for _, source := range predicate.Sources {
		sourceSet[source] = struct{}{}
	}
	if len(sourceSet) != 0 {
		for _, kind := range predicate.Kinds {
			source, _ := kind.Source()
			if _, included := sourceSet[source]; !included {
				return ErrInvalid
			}
		}
	}
	labelKeys := make(map[string]struct{}, len(predicate.Labels))
	for _, label := range predicate.Labels {
		if err := label.Validate(); err != nil {
			return err
		}
		key := label.Key + "\x00" + string(label.Operator)
		if _, duplicate := labelKeys[key]; duplicate {
			return ErrInvalid
		}
		labelKeys[key] = struct{}{}
	}
	return nil
}

type QuietWindow struct {
	Weekdays   []time.Weekday `json:"weekdays"`
	StartMinute uint16        `json:"start_minute"`
	EndMinute   uint16        `json:"end_minute"`
}

func (window QuietWindow) Validate() error {
	if len(window.Weekdays) == 0 || len(window.Weekdays) > 7 || window.StartMinute >= 1440 || window.EndMinute >= 1440 || window.StartMinute == window.EndMinute {
		return ErrInvalid
	}
	seen := make(map[time.Weekday]struct{}, len(window.Weekdays))
	for _, weekday := range window.Weekdays {
		if weekday < time.Sunday || weekday > time.Saturday {
			return ErrInvalid
		}
		if _, duplicate := seen[weekday]; duplicate {
			return ErrInvalid
		}
		seen[weekday] = struct{}{}
	}
	return nil
}

type RateLimit struct {
	Maximum uint32        `json:"maximum"`
	Window  time.Duration `json:"window"`
}

type RetryPolicy struct {
	MaximumAttempts uint32        `json:"maximum_attempts"`
	InitialBackoff  time.Duration `json:"initial_backoff"`
	MaximumBackoff  time.Duration `json:"maximum_backoff"`
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaximumAttempts: 8, InitialBackoff: time.Minute, MaximumBackoff: time.Hour}
}

func (policy RetryPolicy) normalized() RetryPolicy {
	if policy == (RetryPolicy{}) { return DefaultRetryPolicy() }
	return policy
}

func (policy RetryPolicy) Validate() error {
	policy = policy.normalized()
	if policy.MaximumAttempts == 0 || policy.MaximumAttempts > 100 || policy.InitialBackoff < time.Second || policy.InitialBackoff > time.Hour || policy.MaximumBackoff < policy.InitialBackoff || policy.MaximumBackoff > 24*time.Hour {
		return ErrInvalid
	}
	return nil
}

func (limit RateLimit) Validate() error {
	if limit == (RateLimit{}) {
		return nil
	}
	if limit.Maximum == 0 || limit.Maximum > 10000 || limit.Window < time.Minute || limit.Window > MaximumRateWindow {
		return ErrInvalid
	}
	return nil
}

type EscalationStage struct {
	After           time.Duration `json:"after"`
	MinimumSeverity Severity      `json:"minimum_severity"`
	Destinations    []Destination `json:"destinations"`
}

func (stage EscalationStage) Validate() error {
	if stage.After < 0 || stage.After > MaximumEscalationDelay || !stage.MinimumSeverity.Valid() || len(stage.Destinations) == 0 || len(stage.Destinations) > MaximumDestinationsPerStage {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(stage.Destinations))
	for _, destination := range stage.Destinations {
		if err := destination.Validate(); err != nil {
			return err
		}
		key := string(destination.Kind) + "\x00" + destination.ID
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalid
		}
		seen[key] = struct{}{}
	}
	return nil
}

type Rule struct {
	TenantID       string            `json:"tenant_id"`
	ID             string            `json:"id"`
	Revision       uint64            `json:"revision"`
	Enabled        bool              `json:"enabled"`
	Priority       int32             `json:"priority"`
	Match          MatchPredicate    `json:"match"`
	MinimumSeverity Severity         `json:"minimum_severity"`
	Timezone       string            `json:"timezone"`
	QuietHours     []QuietWindow     `json:"quiet_hours,omitempty"`
	QuietBypassAt  Severity          `json:"quiet_bypass_at"`
	DedupWindow    time.Duration     `json:"dedup_window"`
	RateLimit      RateLimit         `json:"rate_limit"`
	RetryPolicy    RetryPolicy       `json:"retry_policy"`
	Escalation     []EscalationStage `json:"escalation"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

func (rule Rule) ValidateConfiguration() error {
	if !opaquePattern.MatchString(rule.TenantID) || !opaquePattern.MatchString(rule.ID) || rule.Priority < -100000 || rule.Priority > 100000 || rule.Match.Validate() != nil || !rule.MinimumSeverity.Valid() || !timezonePattern.MatchString(rule.Timezone) || rule.Timezone == "Local" || rule.QuietBypassAt < SeverityWarning || !rule.QuietBypassAt.Valid() || len(rule.QuietHours) > MaximumQuietWindows || rule.DedupWindow < 0 || rule.DedupWindow > MaximumDedupWindow || rule.RateLimit.Validate() != nil || rule.RetryPolicy.Validate() != nil || len(rule.Escalation) == 0 || len(rule.Escalation) > MaximumEscalationStages {
		return ErrInvalid
	}
	if _, err := time.LoadLocation(rule.Timezone); err != nil {
		return ErrInvalid
	}
	quietMinutes := make([]bool, 7*1440)
	for _, window := range rule.QuietHours {
		if err := window.Validate(); err != nil {
			return err
		}
		for _, weekday := range window.Weekdays {
			start := int(weekday)*1440 + int(window.StartMinute)
			end := int(weekday)*1440 + int(window.EndMinute)
			if window.StartMinute < window.EndMinute {
				for minute := start; minute < end; minute++ { quietMinutes[minute] = true }
				continue
			}
			for minute := start; minute < (int(weekday)+1)*1440; minute++ { quietMinutes[minute] = true }
			nextDay := (int(weekday)+1)%7
			for minute := nextDay*1440; minute < nextDay*1440+int(window.EndMinute); minute++ { quietMinutes[minute] = true }
		}
	}
	openMinute := false
	for _, quiet := range quietMinutes { if !quiet { openMinute = true; break } }
	if !openMinute {
		return ErrInvalid
	}
	previous := time.Duration(-1)
	totalDestinations := 0
	for index, stage := range rule.Escalation {
		if err := stage.Validate(); err != nil || index == 0 && stage.After != 0 || stage.After <= previous {
			return ErrInvalid
		}
		previous = stage.After
		totalDestinations += len(stage.Destinations)
	}
	if totalDestinations > MaximumRoutePlans {
		return ErrLimit
	}
	return nil
}

func (rule Rule) ValidateStored() error {
	if err := rule.ValidateConfiguration(); err != nil {
		return err
	}
	if rule.Revision == 0 || rule.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type Event struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	Source       EventSource       `json:"source"`
	Kind         EventKind         `json:"kind"`
	Severity     Severity          `json:"severity"`
	ResourceKind string            `json:"resource_kind,omitempty"`
	ResourceID   string            `json:"resource_id,omitempty"`
	DedupKey     string            `json:"dedup_key,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	OccurredAt   time.Time         `json:"occurred_at"`
}

func (event Event) Validate() error {
	source, kindValid := event.Kind.Source()
	if !opaquePattern.MatchString(event.ID) || !opaquePattern.MatchString(event.TenantID) || !event.Source.Valid() || !kindValid || source != event.Source || !event.Severity.Valid() || event.OccurredAt.IsZero() || len(event.Labels) > MaximumLabelPredicates || event.DedupKey != "" && !labelValuePattern.MatchString(event.DedupKey) {
		return ErrInvalid
	}
	if event.ResourceKind == "" && event.ResourceID != "" || event.ResourceKind != "" && (!opaquePattern.MatchString(event.ResourceKind) || !opaquePattern.MatchString(event.ResourceID)) {
		return ErrInvalid
	}
	for key, value := range event.Labels {
		if !labelKeyPattern.MatchString(key) || sensitiveLabelKey(key) || !labelValuePattern.MatchString(value) {
			return ErrInvalid
		}
	}
	return nil
}

type RouteAction string

const (
	RouteSend     RouteAction = "send"
	RouteDefer    RouteAction = "defer"
	RouteSuppress RouteAction = "suppress"
)

type ReasonCode string

const (
	ReasonReady                 ReasonCode = "route_ready"
	ReasonMandatoryLocalInbox   ReasonCode = "mandatory_critical_local_inbox"
	ReasonSeverityBelowRule     ReasonCode = "severity_below_rule_threshold"
	ReasonSeverityBelowStage    ReasonCode = "severity_below_stage_threshold"
	ReasonEscalationPending     ReasonCode = "escalation_stage_pending"
	ReasonQuietHours            ReasonCode = "quiet_hours"
	ReasonDeduplicated          ReasonCode = "deduplicated"
	ReasonRateLimited           ReasonCode = "rate_limited"
	ReasonAlreadyDelivered      ReasonCode = "already_delivered"
	ReasonDeliveryDeferred      ReasonCode = "delivery_state_deferred"
	ReasonDeliverySuppressed    ReasonCode = "delivery_state_suppressed"
	ReasonRetryExhausted        ReasonCode = "retry_exhausted"
	ReasonDeliveryFailed       ReasonCode = "delivery_failed"
)

func (reason ReasonCode) Valid() bool {
	switch reason {
	case ReasonReady, ReasonMandatoryLocalInbox, ReasonSeverityBelowRule, ReasonSeverityBelowStage, ReasonEscalationPending, ReasonQuietHours, ReasonDeduplicated, ReasonRateLimited, ReasonAlreadyDelivered, ReasonDeliveryDeferred, ReasonDeliverySuppressed, ReasonRetryExhausted, ReasonDeliveryFailed:
		return true
	default:
		return false
	}
}

type RoutePlan struct {
	ID            string      `json:"id"`
	TenantID      string      `json:"tenant_id"`
	EventID       string      `json:"event_id"`
	RuleID        string      `json:"rule_id"`
	RuleRevision  uint64      `json:"rule_revision"`
	Stage         uint16      `json:"stage"`
	Destination   Destination `json:"destination"`
	Action        RouteAction `json:"action"`
	ReasonCode    ReasonCode  `json:"reason_code"`
	DedupDigest   string      `json:"dedup_digest"`
	EvaluatedAt   time.Time   `json:"evaluated_at"`
	NextAttemptAt time.Time   `json:"next_attempt_at,omitempty"`
}

type DeliveryStatus string

const (
	DeliveryQueued     DeliveryStatus = "queued"
	DeliveryRetry      DeliveryStatus = "retry"
	DeliveryDelivered  DeliveryStatus = "delivered"
	DeliverySuppressed DeliveryStatus = "suppressed"
	DeliveryFailed     DeliveryStatus = "failed"
)

type DeliveryState struct {
	TenantID      string         `json:"tenant_id"`
	ID            string         `json:"id"`
	RuleID        string         `json:"rule_id"`
	EventID       string         `json:"event_id"`
	Status        DeliveryStatus `json:"status"`
	Revision      uint64         `json:"revision"`
	Attempts      uint32         `json:"attempts"`
	ReasonCode    ReasonCode     `json:"reason_code"`
	FailureCode   string         `json:"failure_code,omitempty"`
	NextAttemptAt time.Time      `json:"next_attempt_at,omitempty"`
	DeliveredAt   time.Time      `json:"delivered_at,omitempty"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

func (state DeliveryState) ValidateStored() error {
	if !opaquePattern.MatchString(state.TenantID) || !opaquePattern.MatchString(state.ID) || !opaquePattern.MatchString(state.RuleID) || !opaquePattern.MatchString(state.EventID) || state.Revision == 0 || state.Attempts > MaximumDeliveryAttempts || !state.ReasonCode.Valid() || state.UpdatedAt.IsZero() || state.FailureCode != "" && !opaquePattern.MatchString(state.FailureCode) {
		return ErrInvalid
	}
	switch state.Status {
	case DeliveryQueued, DeliveryRetry:
		if state.NextAttemptAt.IsZero() || !state.DeliveredAt.IsZero() || state.Status == DeliveryQueued && state.FailureCode != "" || state.Status == DeliveryRetry && state.FailureCode == "" { return ErrInvalid }
	case DeliveryDelivered:
		if state.DeliveredAt.IsZero() || state.DeliveredAt.After(state.UpdatedAt) || !state.NextAttemptAt.IsZero() || state.FailureCode != "" { return ErrInvalid }
	case DeliverySuppressed:
		if !state.NextAttemptAt.IsZero() || !state.DeliveredAt.IsZero() || state.FailureCode != "" { return ErrInvalid }
	case DeliveryFailed:
		if !state.NextAttemptAt.IsZero() || !state.DeliveredAt.IsZero() || state.FailureCode == "" { return ErrInvalid }
	default:
		return ErrInvalid
	}
	return nil
}

type DedupState struct {
	TenantID         string    `json:"tenant_id"`
	RuleID           string    `json:"rule_id"`
	Stage            uint16    `json:"stage"`
	DestinationKind  DestinationKind `json:"destination_kind"`
	DestinationID    string    `json:"destination_id"`
	DedupDigest      string    `json:"dedup_digest"`
	Revision         uint64    `json:"revision"`
	LastEventID      string    `json:"last_event_id"`
	LastDeliveredAt  time.Time `json:"last_delivered_at"`
	RateWindowStarted time.Time `json:"rate_window_started,omitempty"`
	RateCount        uint32    `json:"rate_count"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (state DedupState) ValidateStored() error {
	if !opaquePattern.MatchString(state.TenantID) || !opaquePattern.MatchString(state.RuleID) || state.Stage >= MaximumEscalationStages || !state.DestinationKind.Valid() || !opaquePattern.MatchString(state.DestinationID) || len(state.DedupDigest) != 64 || !opaquePattern.MatchString(state.LastEventID) || state.Revision == 0 || state.RateCount > 1000000 || state.LastDeliveredAt.IsZero() || state.UpdatedAt.IsZero() || state.LastDeliveredAt.After(state.UpdatedAt) {
		return ErrInvalid
	}
	for _, value := range state.DedupDigest {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') { return ErrInvalid }
	}
	if state.RateCount != 0 && state.RateWindowStarted.IsZero() || state.RateWindowStarted.After(state.UpdatedAt) {
		return ErrInvalid
	}
	return nil
}

type RulePageRequest struct {
	AfterID string
	Limit   uint16
}

type RulePage struct {
	Rules       []Rule
	NextAfterID string
}

type DeliveryCursor struct {
	NextAttemptAt time.Time
	ID            string
}

type DeliveryPageRequest struct {
	Before time.Time
	After  DeliveryCursor
	Limit  uint16
}

type DeliveryPage struct {
	States []DeliveryState
	Next   DeliveryCursor
}

type Repository interface {
	GetRule(context.Context, string, string) (Rule, error)
	ListRules(context.Context, string, RulePageRequest) (RulePage, error)
	UpsertRule(context.Context, Rule, uint64) (Rule, error)
	DeleteRule(context.Context, string, string, uint64) error
	GetDelivery(context.Context, string, string) (DeliveryState, error)
	ListDueDeliveries(context.Context, string, DeliveryPageRequest) (DeliveryPage, error)
	UpsertDelivery(context.Context, DeliveryState, uint64) (DeliveryState, error)
	DeleteDelivery(context.Context, string, string, uint64) error
	GetDedup(context.Context, DedupState) (DedupState, error)
	UpsertDedup(context.Context, DedupState, uint64) (DedupState, error)
	DeleteDedup(context.Context, DedupState, uint64) error
}

type Actor struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	RequestID   string `json:"request_id"`
}

func (actor Actor) Validate() error {
	if !opaquePattern.MatchString(actor.PrincipalID) || !opaquePattern.MatchString(actor.TenantID) || !opaquePattern.MatchString(actor.RequestID) { return ErrInvalid }
	return nil
}

type AuthorizationAction string

const (
	AuthorizeRuleRead       AuthorizationAction = "notification.rule.read"
	AuthorizeRuleWrite      AuthorizationAction = "notification.rule.write"
	AuthorizeEvaluate       AuthorizationAction = "notification.route.evaluate"
	AuthorizeDeliveryRead   AuthorizationAction = "notification.delivery.read"
	AuthorizeDeliveryWrite  AuthorizationAction = "notification.delivery.write"
)

type Authorizer interface {
	Authorize(context.Context, Actor, AuthorizationAction, string, string) error
}

type AuditRecord struct {
	Action           AuthorizationAction `json:"action"`
	Actor            Actor               `json:"actor"`
	TenantID         string              `json:"tenant_id"`
	ResourceID       string              `json:"resource_id"`
	ExpectedRevision uint64              `json:"expected_revision"`
	ResultRevision   uint64              `json:"result_revision"`
	Outcome          string              `json:"outcome"`
	Digest           string              `json:"digest"`
	OccurredAt       time.Time           `json:"occurred_at"`
}

type Auditor interface {
	RecordNotificationPolicy(context.Context, AuditRecord) error
}

func stableRules(rules []Rule) {
	sort.Slice(rules, func(left, right int) bool {
		if rules[left].Priority != rules[right].Priority { return rules[left].Priority > rules[right].Priority }
		return rules[left].ID < rules[right].ID
	})
}
