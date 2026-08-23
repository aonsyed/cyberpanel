package apiserver

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/alerts"
	"github.com/aonsyed/cyberpanel/platform/internal/capacity"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
	"github.com/aonsyed/cyberpanel/platform/internal/logworkspace"
	"github.com/aonsyed/cyberpanel/platform/internal/serviceregistry"
)

type ObservabilityMetricProjection struct {
	Name           string                 `json:"name"`
	Label          string                 `json:"label"`
	Value          float64                `json:"value,omitempty"`
	Unit           capacity.Unit          `json:"unit,omitempty"`
	Available      bool                   `json:"available"`
	Complete       bool                   `json:"complete"`
	MissingReason  string                 `json:"missing_reason,omitempty"`
	ObservedAt     time.Time              `json:"observed_at,omitempty"`
	SampleInterval time.Duration          `json:"sample_interval,omitempty"`
	Retention      capacity.RetentionPolicy `json:"retention"`
}

type UsageLimitProjection struct {
	ScopeKind    string    `json:"scope_kind"`
	ScopeID      string    `json:"scope_id"`
	Dimension    string    `json:"dimension"`
	Used         uint64    `json:"used,omitempty"`
	Limit        uint64    `json:"limit,omitempty"`
	Unit         string    `json:"unit"`
	Available    bool      `json:"available"`
	LimitState   string    `json:"limit_state"`
	MissingReason string   `json:"missing_reason,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

type ServiceHealthProjection struct {
	ID                        string                      `json:"id"`
	Name                      string                      `json:"name"`
	Configured                bool                        `json:"configured"`
	Install                   serviceregistry.InstallState `json:"install"`
	Enable                    serviceregistry.EnableState  `json:"enable"`
	Active                    serviceregistry.ActiveState  `json:"active"`
	Configuration             serviceregistry.ConfigState  `json:"configuration"`
	DependenciesReady         bool                        `json:"dependencies_ready"`
	ExpectedListenersOwned    bool                        `json:"expected_listeners_owned"`
	InternallyHealthy         bool                        `json:"internally_healthy"`
	ExternallyFunctional      bool                        `json:"externally_functional"`
	DesiredGenerationObserved bool                        `json:"desired_generation_observed"`
	Health                    serviceregistry.HealthState  `json:"health"`
	Drift                     serviceregistry.DriftState   `json:"drift"`
	Generation                uint64                      `json:"generation"`
	EvidenceDigest            string                      `json:"evidence_digest,omitempty"`
	MissingReason             string                      `json:"missing_reason,omitempty"`
	ObservedAt                time.Time                   `json:"observed_at,omitempty"`
}

type AlertRuleStatusProjection struct {
	ID         string           `json:"id"`
	Kind       alerts.SignalKind `json:"kind"`
	Severity   alerts.Severity   `json:"severity"`
	Condition  alerts.Condition  `json:"condition"`
	Active     bool             `json:"active"`
	Enabled    bool             `json:"enabled"`
	Generation uint64           `json:"generation"`
	UpdatedAt  time.Time        `json:"updated_at"`
	Rule       alerts.Rule       `json:"rule"`
	State      alerts.State      `json:"state"`
}

type LogRecordProjection struct {
	SourceID   logworkspace.SourceID `json:"source_id"`
	Generation uint64                `json:"generation"`
	Sequence   uint64                `json:"sequence"`
	Offset     int64                 `json:"offset"`
	ObservedAt time.Time             `json:"observed_at"`
	Text       string                `json:"text"`
	Redacted   bool                  `json:"redacted"`
}

type LogConditionProjection struct {
	Code       logworkspace.ConditionCode `json:"code"`
	SourceID   logworkspace.SourceID      `json:"source_id"`
	Generation uint64                     `json:"generation"`
	At         time.Time                  `json:"at"`
}

type LogSourceProjection struct {
	ID                    logworkspace.SourceID       `json:"id"`
	Category              logworkspace.SourceCategory `json:"category"`
	Scope                 logworkspace.SourceScope    `json:"scope"`
	Backend               logworkspace.BackendKind    `json:"backend"`
	Unit                  logworkspace.ServiceUnitID  `json:"unit,omitempty"`
	Protected             bool                        `json:"protected"`
	Generation            uint64                      `json:"generation"`
	RetentionAuthority    string                      `json:"retention_authority"`
	RedactionPolicy       string                      `json:"redaction_policy"`
	CursorLifetimeSeconds uint32                      `json:"cursor_lifetime_seconds"`
	MaximumLines          uint32                      `json:"maximum_lines"`
	MaximumBytes          int64                       `json:"maximum_bytes"`
}

type LogProjectionPage struct {
	Records    []LogRecordProjection    `json:"records"`
	Conditions []LogConditionProjection `json:"conditions"`
	Summary    logworkspace.ProjectionSummary `json:"summary"`
}

type CapacityForecastProjection struct {
	Available     bool                      `json:"available"`
	MissingReason string                    `json:"missing_reason,omitempty"`
	Forecast      *capacity.CapacityForecast `json:"forecast,omitempty"`
}

type UsageExportResult struct {
	State             string               `json:"state"`
	Export            capacity.UsageExport `json:"export"`
	MissingDimensions []string             `json:"missing_dimensions,omitempty"`
}

type LogExportResult struct {
	Job           logworkspace.ExportJob      `json:"job"`
	Manifest      logworkspace.ExportManifest `json:"manifest"`
	ContentBase64 string                      `json:"content_base64"`
}

type ObservabilityDashboard struct {
	Node        DashboardNodeProjection       `json:"node"`
	Metrics     []ObservabilityMetricProjection `json:"metrics"`
	Usage       []UsageLimitProjection        `json:"usage"`
	Services    []ServiceHealthProjection     `json:"services"`
	Alerts      []integrations.InboxItem      `json:"alerts"`
	Warnings    []string                      `json:"warnings"`
	GeneratedAt time.Time                     `json:"generated_at"`
}

type MetricQueryPayload struct {
	ResourceKind       string               `json:"resource_kind"`
	ResourceID         string               `json:"resource_id"`
	Metric             capacity.MetricName  `json:"metric"`
	SourceTier         capacity.Tier        `json:"source_tier"`
	From               time.Time            `json:"from"`
	Until              time.Time            `json:"until"`
	IntervalSeconds    uint32               `json:"interval_seconds"`
	Aggregation        capacity.Aggregation `json:"aggregation"`
	MaximumSourcePoints uint32              `json:"maximum_source_points,omitempty"`
}

type ForecastQueryPayload struct {
	Query           MetricQueryPayload `json:"query"`
	HorizonSeconds  uint32             `json:"horizon_seconds"`
	MinimumSamples  uint16             `json:"minimum_samples,omitempty"`
	MinimumCoverage float64            `json:"minimum_coverage,omitempty"`
	CapacityLimit   *float64           `json:"capacity_limit,omitempty"`
}

type UsageExportPayload struct {
	PeriodStart time.Time `json:"period_start,omitempty"`
	PeriodEnd   time.Time `json:"period_end,omitempty"`
}

type UsageExportStatusPayload struct {
	Export capacity.UsageExport `json:"export"`
}

type LogQueryPayload struct {
	Mode             string    `json:"mode,omitempty"`
	Cursor           string    `json:"cursor,omitempty"`
	Since            time.Time `json:"since,omitempty"`
	Until            time.Time `json:"until,omitempty"`
	TailLines        uint32    `json:"tail_lines,omitempty"`
	Literal          string    `json:"literal,omitempty"`
	Regex            string    `json:"regex,omitempty"`
	CaseSensitive    bool      `json:"case_sensitive,omitempty"`
	Lines            uint32    `json:"lines,omitempty"`
	Bytes            int64     `json:"bytes,omitempty"`
	DurationSeconds  uint16    `json:"duration_seconds,omitempty"`
	RegexTimeoutSeconds uint16 `json:"regex_timeout_seconds,omitempty"`
}

type LogExportPayload struct {
	Query LogQueryPayload `json:"query"`
}

type AlertThreshold float64

func (value *AlertThreshold) UnmarshalJSON(raw []byte) error {
	encoded := strings.TrimSpace(string(raw))
	if len(encoded) >= 2 && encoded[0] == '"' {
		unquoted, err := strconv.Unquote(encoded)
		if err != nil { return invalid("alert threshold") }
		encoded = unquoted
	}
	parsed, err := strconv.ParseFloat(encoded, 64)
	if err != nil { return invalid("alert threshold") }
	*value = AlertThreshold(parsed)
	return nil
}

type AlertRulePayload struct {
	ID                    string                `json:"id,omitempty"`
	Kind                  alerts.SignalKind     `json:"kind"`
	ResourceKind          string                `json:"resource_kind"`
	ResourceID            string                `json:"resource_id"`
	Comparator            alerts.Comparator     `json:"comparator"`
	Threshold             AlertThreshold        `json:"threshold"`
	WindowSeconds         uint32                `json:"window_seconds,omitempty"`
	Severity              alerts.Severity       `json:"severity"`
	Hysteresis            float64               `json:"hysteresis,omitempty"`
	ConsecutiveSamples    uint16                `json:"consecutive_samples,omitempty"`
	CooldownSeconds       uint32                `json:"cooldown_seconds,omitempty"`
	Recovery              alerts.RecoveryPolicy `json:"recovery,omitempty"`
	NotificationRouteRefs []string              `json:"notification_route_refs,omitempty"`
	Enabled               bool                  `json:"enabled"`
}

type ObservabilityEdgeService interface {
	ObservabilityDashboard(context.Context, EdgeCall) (ObservabilityDashboard, error)
	QueryMetric(context.Context, EdgeCall, MetricQueryPayload) (capacity.MetricSeries, error)
	ForecastCapacity(context.Context, EdgeCall, ForecastQueryPayload) (CapacityForecastProjection, error)
	ListUsage(context.Context, EdgeCall) (EdgePage[UsageLimitProjection], error)
	GetSiteUsage(context.Context, EdgeCall) (EdgePage[UsageLimitProjection], error)
	CreateUsageExport(context.Context, EdgeCall, UsageExportPayload) (UsageExportResult, error)
	UsageExportStatus(context.Context, EdgeCall, UsageExportStatusPayload) (UsageExportResult, error)
	ListLogSources(context.Context, EdgeCall, EdgePagePayload) (EdgePage[LogSourceProjection], error)
	QueryLogs(context.Context, EdgeCall, LogQueryPayload) (LogProjectionPage, error)
	CreateLogExport(context.Context, EdgeCall, LogExportPayload) (LogExportResult, error)
	LogExportStatus(context.Context, EdgeCall) (logworkspace.ExportJob, error)
	ListAlertRules(context.Context, EdgeCall, EdgePagePayload) (EdgePage[AlertRuleStatusProjection], error)
	GetAlertStatus(context.Context, EdgeCall) (AlertRuleStatusProjection, error)
	CreateAlertRule(context.Context, EdgeCall, AlertRulePayload) (EdgeMutation[AlertRuleStatusProjection], error)
	UpdateAlertRule(context.Context, EdgeCall, AlertRulePayload) (EdgeMutation[AlertRuleStatusProjection], error)
	ListAlertInbox(context.Context, EdgeCall, EdgePagePayload) (EdgePage[integrations.InboxItem], error)
	AcknowledgeAlert(context.Context, EdgeCall) (EdgeMutation[integrations.InboxItem], error)
	ListServiceHealth(context.Context, EdgeCall, EdgePagePayload) (EdgePage[ServiceHealthProjection], error)
}

type ObservabilityEdgeCapabilities struct {
	Dashboard, Metrics, Usage, UsageExport, Logs, LogExport, AlertRules, AlertInbox, ServiceHealth bool
}

type ObservabilityEdgeCapabilityProvider interface {
	ObservabilityCapabilities() ObservabilityEdgeCapabilities
}

func registerObservabilityContracts(registry *Registry) error {
	password, mfa := identity.AssurancePassword, identity.AssuranceMFA
	definitions := []Operation{
		consoleOperation("observability.dashboard.get", "operations:observe", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantOrInstallationListScope),
		consoleOperation("observability.metric.query", "operations:observe", password, false, func() any { return &MetricQueryPayload{} }, validateMetricQuery, edgeTenantOrInstallationListScope),
		consoleOperation("observability.capacity.forecast", "operations:observe", password, false, func() any { return &ForecastQueryPayload{} }, validateForecastQuery, edgeTenantOrInstallationListScope),
		consoleOperation("observability.usage.list", "operations:observe", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantListScope),
		consoleOperation("observability.site_usage.get", "operations:observe", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantResourceReadScope),
		consoleOperation("observability.usage_export.create", "operations:observe", mfa, true, func() any { return &UsageExportPayload{} }, validateUsageExport, edgeTenantCreateScope),
		consoleOperation("observability.usage_export.status", "operations:observe", password, false, func() any { return &UsageExportStatusPayload{} }, nil, edgeTenantListScope),
		consoleOperation("observability.log_source.list", "operations:observe", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantOrInstallationListScope),
		consoleOperation("observability.log.query", "operations:observe", password, false, func() any { return &LogQueryPayload{} }, validateLogQuery, edgeTenantOrInstallationResourceReadScope),
		consoleOperation("observability.log_export.create", "operations:observe", mfa, true, func() any { return &LogExportPayload{} }, validateLogExport, edgeTenantOrInstallationExistingMutationScope),
		consoleOperation("observability.log_export.status", "operations:observe", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantOrInstallationResourceReadScope),
		consoleOperation("observability.alert_rule.list", "operations:observe", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantOrInstallationListScope),
		consoleOperation("observability.alert_status.get", "operations:observe", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantOrInstallationResourceReadScope),
		consoleOperation("observability.alert_rule.create", "operations:manage", mfa, true, func() any { return &AlertRulePayload{} }, validateAlertRule, edgeTenantOrInstallationCreateScope),
		consoleOperation("observability.alert_rule.update", "operations:manage", mfa, true, func() any { return &AlertRulePayload{} }, validateAlertRule, edgeTenantOrInstallationExistingMutationScope),
		{Name: "observability.alert_inbox.list", Auth: AuthRequired, SelfService: true, Assurance: password, NewPayload: func() any { return &EdgePagePayload{} }, ValidatePayload: validateEdgePage, ResolveScope: edgeTenantListScope},
		{Name: "observability.alert.acknowledge", Auth: AuthRequired, SelfService: true, Assurance: password, Mutating: true, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: edgeTenantExistingMutationScope},
		consoleOperation("observability.service_health.list", "operations:observe", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantOrInstallationListScope),
	}
	for _, definition := range definitions {
		if err := register(registry, definition); err != nil { return err }
	}
	return nil
}

func validateMetricQuery(value any) error {
	payload := value.(*MetricQueryPayload)
	if payload.SourceTier == "" { payload.SourceTier = capacity.TierRaw }
	if payload.Aggregation == "" { payload.Aggregation = capacity.AggregationMean }
	if payload.MaximumSourcePoints == 0 { payload.MaximumSourcePoints = 10000 }
	if !validEdgeID(payload.ResourceKind) || !validEdgeID(payload.ResourceID) || !validEdgeID(string(payload.Metric)) || payload.From.IsZero() || !payload.Until.After(payload.From) || payload.IntervalSeconds == 0 || payload.IntervalSeconds > 365*24*60*60 || payload.MaximumSourcePoints > 50000 { return invalid("metric query") }
	interval := time.Duration(payload.IntervalSeconds) * time.Second
	if payload.Until.Sub(payload.From)%interval != 0 || payload.From.UTC().UnixNano()%interval.Nanoseconds() != 0 || payload.Until.Sub(payload.From)/interval > 2000 { return invalid("metric interval") }
	if payload.SourceTier != capacity.TierRaw && payload.SourceTier != capacity.TierHour && payload.SourceTier != capacity.TierDay { return invalid("metric tier") }
	switch payload.Aggregation { case capacity.AggregationMinimum, capacity.AggregationMaximum, capacity.AggregationMean, capacity.AggregationSum, capacity.AggregationCount, capacity.AggregationP95: default: return invalid("metric aggregation") }
	return nil
}

func validateForecastQuery(value any) error {
	payload := value.(*ForecastQueryPayload)
	if err := validateMetricQuery(&payload.Query); err != nil { return err }
	if payload.HorizonSeconds < payload.Query.IntervalSeconds || payload.HorizonSeconds > 365*24*60*60 || payload.MinimumSamples != 0 && payload.MinimumSamples < 24 || payload.MinimumSamples > 2000 || math.IsNaN(payload.MinimumCoverage) || math.IsInf(payload.MinimumCoverage, 0) || payload.MinimumCoverage != 0 && payload.MinimumCoverage < .8 || payload.MinimumCoverage > 1 { return invalid("capacity forecast") }
	if payload.CapacityLimit != nil && (*payload.CapacityLimit <= 0 || math.IsNaN(*payload.CapacityLimit) || math.IsInf(*payload.CapacityLimit, 0)) { return invalid("capacity limit") }
	return nil
}

func validateUsageExport(value any) error {
	payload := value.(*UsageExportPayload)
	if payload.PeriodStart.IsZero() != payload.PeriodEnd.IsZero() || !payload.PeriodStart.IsZero() && (!payload.PeriodEnd.After(payload.PeriodStart) || payload.PeriodEnd.Sub(payload.PeriodStart) > 366*24*time.Hour) { return invalid("usage export period") }
	return nil
}

func validateLogQuery(value any) error {
	payload := value.(*LogQueryPayload)
	if payload.Mode == "" { payload.Mode = "tail" }
	if payload.Lines == 0 { payload.Lines = 100 }
	if payload.Bytes == 0 { payload.Bytes = 512 << 10 }
	if payload.DurationSeconds == 0 { payload.DurationSeconds = 5 }
	if payload.Lines > logworkspace.MaximumLines || payload.Bytes > logworkspace.MaximumBytes || payload.Bytes < 1 || payload.DurationSeconds > uint16(logworkspace.MaximumDuration/time.Second) || len(payload.Cursor) > logworkspace.MaximumOpaqueBytes || len(payload.Literal) > logworkspace.MaximumSearchLiteral || len(payload.Regex) > logworkspace.MaximumRegexBytes { return invalid("log query bounds") }
	switch payload.Mode {
	case "tail":
		if payload.TailLines == 0 { payload.TailLines = payload.Lines }
		if payload.TailLines > logworkspace.MaximumTailLines || payload.Cursor != "" || payload.Literal != "" || payload.Regex != "" { return invalid("log tail") }
	case "cursor":
		if payload.Cursor == "" || payload.TailLines != 0 || payload.Literal != "" || payload.Regex != "" { return invalid("log cursor") }
	case "time":
		if payload.Since.IsZero() || !payload.Until.After(payload.Since) || payload.Cursor != "" || payload.TailLines != 0 || payload.Literal != "" || payload.Regex != "" { return invalid("log time query") }
	case "search":
		if payload.Literal == "" || payload.Cursor != "" || payload.TailLines != 0 || !payload.Since.IsZero() && !payload.Until.IsZero() && !payload.Until.After(payload.Since) { return invalid("log search") }
		if payload.Regex != "" && payload.RegexTimeoutSeconds == 0 { payload.RegexTimeoutSeconds = 2 }
		if payload.RegexTimeoutSeconds > uint16(logworkspace.MaximumRegexDuration/time.Second) { return invalid("log regex timeout") }
	default:
		return invalid("log projection")
	}
	return nil
}

func validateLogExport(value any) error {
	payload := value.(*LogExportPayload)
	if payload.Query.Lines == 0 { payload.Query.Lines = 5000 }
	if payload.Query.Bytes == 0 { payload.Query.Bytes = 4 << 20 }
	if payload.Query.DurationSeconds == 0 { payload.Query.DurationSeconds = 30 }
	return validateLogQuery(&payload.Query)
}

func validateAlertRule(value any) error {
	payload := value.(*AlertRulePayload)
	if payload.WindowSeconds == 0 { payload.WindowSeconds = 60 }
	if payload.ConsecutiveSamples == 0 { payload.ConsecutiveSamples = 1 }
	if payload.CooldownSeconds == 0 { payload.CooldownSeconds = 300 }
	if payload.Recovery == "" { payload.Recovery = alerts.RecoveryAutomatic }
	threshold := float64(payload.Threshold)
	if payload.ID != "" && !validEdgeID(payload.ID) || !validEdgeID(payload.ResourceKind) || !validEdgeID(payload.ResourceID) || !payload.Kind.Valid() || !payload.Comparator.Valid() || !payload.Severity.Valid() || payload.Recovery != alerts.RecoveryAutomatic && payload.Recovery != alerts.RecoveryManual || payload.WindowSeconds > 30*24*60*60 || payload.ConsecutiveSamples > 1000 || payload.CooldownSeconds > 30*24*60*60 || len(payload.NotificationRouteRefs) > 128 || math.IsNaN(threshold) || math.IsInf(threshold, 0) || math.IsNaN(payload.Hysteresis) || math.IsInf(payload.Hysteresis, 0) || payload.Hysteresis < 0 { return invalid("alert rule") }
	for _, reference := range payload.NotificationRouteRefs { if !validEdgeID(reference) { return invalid("alert route") } }
	return nil
}

func bindObservabilityContracts(registry *Registry, services DomainServices) error {
	edge, ok := services.DashboardEdge.(ObservabilityEdgeService)
	if !ok || edge == nil { return nil }
	capabilities := ObservabilityEdgeCapabilities{Dashboard:true, Metrics:true, Usage:true, UsageExport:true, Logs:true, LogExport:true, AlertRules:true, AlertInbox:true, ServiceHealth:true}
	if provider, available := edge.(ObservabilityEdgeCapabilityProvider); available { capabilities = provider.ObservabilityCapabilities() }
	type binding struct { name string; available bool; handler OperationHandler }
	bindings := []binding{
		{"observability.dashboard.get", capabilities.Dashboard, func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) { result, err := edge.ObservabilityDashboard(ctx, edgeCall(inv)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.metric.query", capabilities.Metrics, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.QueryMetric(ctx, edgeCall(inv), *value.(*MetricQueryPayload)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.capacity.forecast", capabilities.Metrics, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.ForecastCapacity(ctx, edgeCall(inv), *value.(*ForecastQueryPayload)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.usage.list", capabilities.Usage, func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) { result, err := edge.ListUsage(ctx, edgeCall(inv)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.site_usage.get", capabilities.Usage, func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) { result, err := edge.GetSiteUsage(ctx, edgeCall(inv)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.usage_export.create", capabilities.UsageExport, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.CreateUsageExport(ctx, edgeCall(inv), *value.(*UsageExportPayload)); return observabilityResult(http.StatusCreated, result, err) }},
		{"observability.usage_export.status", capabilities.UsageExport, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.UsageExportStatus(ctx, edgeCall(inv), *value.(*UsageExportStatusPayload)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.log_source.list", capabilities.Logs, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.ListLogSources(ctx, edgeCall(inv), *value.(*EdgePagePayload)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.log.query", capabilities.Logs, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.QueryLogs(ctx, edgeCall(inv), *value.(*LogQueryPayload)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.log_export.create", capabilities.LogExport, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.CreateLogExport(ctx, edgeCall(inv), *value.(*LogExportPayload)); return observabilityResult(http.StatusCreated, result, err) }},
		{"observability.log_export.status", capabilities.LogExport, func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) { result, err := edge.LogExportStatus(ctx, edgeCall(inv)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.alert_rule.list", capabilities.AlertRules, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.ListAlertRules(ctx, edgeCall(inv), *value.(*EdgePagePayload)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.alert_status.get", capabilities.AlertRules, func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) { result, err := edge.GetAlertStatus(ctx, edgeCall(inv)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.alert_rule.create", capabilities.AlertRules, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.CreateAlertRule(ctx, edgeCall(inv), *value.(*AlertRulePayload)); if err != nil { return OperationResult{}, mapObservabilityError(err) }; return edgeOperationResult(http.StatusCreated, result), nil }},
		{"observability.alert_rule.update", capabilities.AlertRules, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.UpdateAlertRule(ctx, edgeCall(inv), *value.(*AlertRulePayload)); if err != nil { return OperationResult{}, mapObservabilityError(err) }; return edgeOperationResult(http.StatusOK, result), nil }},
		{"observability.alert_inbox.list", capabilities.AlertInbox, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.ListAlertInbox(ctx, edgeCall(inv), *value.(*EdgePagePayload)); return observabilityResult(http.StatusOK, result, err) }},
		{"observability.alert.acknowledge", capabilities.AlertInbox, func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) { result, err := edge.AcknowledgeAlert(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapObservabilityError(err) }; return edgeOperationResult(http.StatusOK, result), nil }},
		{"observability.service_health.list", capabilities.ServiceHealth, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) { result, err := edge.ListServiceHealth(ctx, edgeCall(inv), *value.(*EdgePagePayload)); return observabilityResult(http.StatusOK, result, err) }},
	}
	for _, current := range bindings {
		if err := bindIf(registry, current.name, current.available, current.handler); err != nil { return err }
	}
	return nil
}

func observabilityResult(status int, value any, err error) (OperationResult, error) {
	if err != nil { return OperationResult{}, mapObservabilityError(err) }
	return OperationResult{Status:status, Value:value}, nil
}

func mapObservabilityError(err error) error {
	if err == nil { return nil }
	switch {
	case errors.Is(err, capacity.ErrInvalid), errors.Is(err, alerts.ErrInvalid), errors.Is(err, logworkspace.ErrInvalid), errors.Is(err, serviceregistry.ErrInvalid), errors.Is(err, integrations.ErrInvalid), errors.Is(err, identity.ErrInvalid): return ErrInvalidRequest
	case errors.Is(err, logworkspace.ErrUnauthorized), errors.Is(err, serviceregistry.ErrUnauthorized), errors.Is(err, integrations.ErrUnauthorized), errors.Is(err, integrations.ErrPolicyDenied), errors.Is(err, identity.ErrForbidden): return ErrForbidden
	case errors.Is(err, capacity.ErrNotFound), errors.Is(err, alerts.ErrNotFound), errors.Is(err, logworkspace.ErrNotFound), errors.Is(err, serviceregistry.ErrNotFound), errors.Is(err, integrations.ErrNotFound), errors.Is(err, identity.ErrNotFound): return ErrNotFound
	case errors.Is(err, capacity.ErrConflict), errors.Is(err, capacity.ErrStaleSample), errors.Is(err, alerts.ErrConflict), errors.Is(err, alerts.ErrStale), errors.Is(err, alerts.ErrScope), errors.Is(err, logworkspace.ErrConflict), errors.Is(err, logworkspace.ErrGap), errors.Is(err, serviceregistry.ErrConflict), errors.Is(err, serviceregistry.ErrStale), errors.Is(err, integrations.ErrConflict), errors.Is(err, integrations.ErrStaleGeneration), errors.Is(err, identity.ErrConflict), errors.Is(err, identity.ErrStaleGeneration): return ErrConflict
	case errors.Is(err, capacity.ErrCardinality), errors.Is(err, capacity.ErrLimit), errors.Is(err, alerts.ErrCapacity), errors.Is(err, logworkspace.ErrLimit): return ErrResponseTooLarge
	case errors.Is(err, capacity.ErrInsufficientEvidence), errors.Is(err, serviceregistry.ErrUnsupported), errors.Is(err, serviceregistry.ErrAmbiguous), errors.Is(err, logworkspace.ErrProtected): return ErrOperationUnavailable
	case errors.Is(err, capacity.ErrIntegrity), errors.Is(err, alerts.ErrIntegrity), errors.Is(err, logworkspace.ErrIntegrity), errors.Is(err, integrations.ErrIntegrity): return ErrUnavailable
	default:
		if strings.Contains(strings.ToLower(err.Error()), "not found") { return ErrNotFound }
		return err
	}
}
