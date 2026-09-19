//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/alerts"
	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/artifactguard"
	"github.com/aonsyed/cyberpanel/platform/internal/capacity"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
	"github.com/aonsyed/cyberpanel/platform/internal/logworkspace"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/serviceregistry"
)

const observabilityInstallationTenant = "installation"

type dashboardEdge struct {
	db              *sql.DB
	now             func() time.Time
	metrics         capacity.Service
	identity        *identity.Store
	alertRepository *alerts.Repository
	inbox           integrations.InboxService
	logRegistry     *logworkspace.Registry
	logReader       logworkspace.Reader
	logRepository   *logworkspace.SQLiteRepository
	serviceRegistry *serviceregistry.Registry
	serviceStore    *serviceregistry.SQLiteRepository
	serviceObserver *serviceregistry.LinuxObserver
	serviceHealthMu sync.Mutex
	signer          *observabilitySigner
}

func newDashboardEdge(db *sql.DB, now func() time.Time, serviceCommands apiserver.OperationsCommandService) (*dashboardEdge, error) {
	if db == nil || now == nil || serviceCommands == nil {
		return nil, errors.New("dashboard authority is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	metricRepository := capacity.SQLiteRepository{DB: db}
	if err := metricRepository.Initialize(ctx); err != nil {
		return nil, err
	}
	identityStore, err := identity.NewStore(db)
	if err != nil {
		return nil, err
	}
	alertRepository, err := alerts.NewRepository(db)
	if err != nil {
		return nil, err
	}
	if err = alertRepository.Bootstrap(ctx); err != nil {
		return nil, err
	}
	logRepository, err := logworkspace.NewSQLiteRepository(db)
	if err != nil {
		return nil, err
	}
	if err = logRepository.Bootstrap(ctx); err != nil {
		return nil, err
	}
	signer, err := newObservabilitySigner()
	if err != nil {
		return nil, err
	}
	logRegistry, err := logworkspace.NewRegistry(nil, defaultJournalSources())
	if err != nil {
		return nil, err
	}
	cursors, err := logworkspace.NewCursorCodec(signer)
	if err != nil {
		return nil, err
	}
	logReader, err := logworkspace.NewLinuxReader(logRegistry, nil, cursors, runtimeLogAuthorizer{}, runtimeLogRedactor{now: now}, runtimeLogTimestamp{})
	if err != nil {
		return nil, err
	}
	serviceProber, err := newOperationsServiceHealthProber(serviceCommands, now)
	if err != nil {
		return nil, err
	}
	serviceRegistry, serviceStore, serviceObserver, err := newObservedServiceRegistry(ctx, db, serviceProber, serviceRegistryClock{now: now})
	if err != nil {
		return nil, err
	}
	return &dashboardEdge{
		db: db, now: now, metrics: capacity.Service{Store: metricRepository}, identity: identityStore,
		alertRepository: alertRepository, inbox: integrations.InboxService{Store: integrations.SQLRepository{DB: db}, Now: now},
		logRegistry: logRegistry, logReader: logReader, logRepository: logRepository,
		serviceRegistry: serviceRegistry, serviceStore: serviceStore, serviceObserver: serviceObserver, signer: signer,
	}, nil
}

func (edge *dashboardEdge) ObservabilityCapabilities() apiserver.ObservabilityEdgeCapabilities {
	ready := edge != nil
	return apiserver.ObservabilityEdgeCapabilities{
		Dashboard: ready, Metrics: ready, Usage: ready, UsageExport: ready && edge.signer != nil,
		Logs: ready && edge.logRegistry != nil && edge.logReader != nil,
		LogExport: ready && edge.logReader != nil && edge.logRepository != nil,
		AlertRules: ready && edge.alertRepository != nil, AlertInbox: ready,
		ServiceHealth: ready && edge.serviceRegistry != nil && edge.serviceStore != nil && edge.serviceObserver != nil,
	}
}

func (edge *dashboardEdge) Summary(ctx context.Context, call apiserver.EdgeCall) (apiserver.DashboardSummary, error) {
	if edge == nil || edge.db == nil || ctx == nil {
		return apiserver.DashboardSummary{}, errors.New("dashboard authority is required")
	}
	services, serviceErr := edge.serviceHealthPage(ctx, apiserver.EdgePagePayload{Limit: serviceregistry.MaxServices})
	return edge.dashboardSummary(ctx, call, services.Items, serviceErr)
}

func (edge *dashboardEdge) dashboardSummary(ctx context.Context, call apiserver.EdgeCall, services []apiserver.ServiceHealthProjection, serviceErr error) (apiserver.DashboardSummary, error) {
	if edge == nil || edge.db == nil || ctx == nil {
		return apiserver.DashboardSummary{}, errors.New("dashboard authority is required")
	}
	now := edge.now().UTC()
	node := dashboardNode(now)
	warnings := make([]string, 0, 4)
	counts := apiserver.DashboardCountProjection{}
	if call.TenantID != "" {
		tenantID, err := identity.NewID(call.TenantID)
		if err != nil {
			return apiserver.DashboardSummary{}, err
		}
		usage, err := edge.identity.Usage(ctx, tenantID)
		if err != nil {
			return apiserver.DashboardSummary{}, err
		}
		if usage.UpdatedAt.IsZero() {
			warnings = append(warnings, "Tenant usage projection has not been published; counts are unavailable.")
		} else {
			counts.Sites, counts.Databases, counts.Mailboxes = usage.Sites, usage.Databases, usage.Mailboxes
		}
	} else {
		warnings = append(warnings, "Installation aggregate counts are omitted; select a tenant to read its materialized usage projection.")
	}
	if serviceErr != nil {
		warnings = append(warnings, "Managed-service health projection is unavailable.")
	} else {
		node.Health = aggregateNodeHealth(services)
	}
	return apiserver.DashboardSummary{Node: node, Counts: counts, Warnings: warnings, GeneratedAt: now}, nil
}

func (edge *dashboardEdge) ObservabilityDashboard(ctx context.Context, call apiserver.EdgeCall) (apiserver.ObservabilityDashboard, error) {
	if edge == nil || edge.db == nil || ctx == nil {
		return apiserver.ObservabilityDashboard{}, errors.New("dashboard authority is required")
	}
	services, serviceErr := edge.serviceHealthPage(ctx, apiserver.EdgePagePayload{Limit: serviceregistry.MaxServices})
	summary, err := edge.dashboardSummary(ctx, call, services.Items, serviceErr)
	if err != nil {
		return apiserver.ObservabilityDashboard{}, err
	}
	dashboard := apiserver.ObservabilityDashboard{Node: summary.Node, Warnings: append([]string(nil), summary.Warnings...), GeneratedAt: summary.GeneratedAt}
	for _, spec := range dashboardMetricSpecs() {
		metric := edge.latestMetric(ctx, observabilityInstallationTenant, "node", "local", spec.name, spec.label)
		dashboard.Metrics = append(dashboard.Metrics, metric)
		if !metric.Available {
			dashboard.Warnings = append(dashboard.Warnings, spec.label+" is unavailable: "+metric.MissingReason+".")
		}
	}
	if call.TenantID != "" {
		usage, usageErr := edge.ListUsage(ctx, call)
		if usageErr != nil {
			dashboard.Warnings = append(dashboard.Warnings, "Tenant usage and limits are unavailable.")
		} else {
			dashboard.Usage = usage.Items
		}
		alertsPage, alertErr := edge.ListAlertInbox(ctx, call, apiserver.EdgePagePayload{Limit: 8})
		if alertErr != nil {
			dashboard.Warnings = append(dashboard.Warnings, "Alert inbox projection is unavailable.")
		} else {
			dashboard.Alerts = alertsPage.Items
		}
	}
	if serviceErr == nil {
		dashboard.Services = services.Items
	} else {
		dashboard.Warnings = append(dashboard.Warnings, "Managed-service observations are unavailable.")
	}
	return dashboard, nil
}

func dashboardNode(now time.Time) apiserver.DashboardNodeProjection {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "localhost"
	}
	return apiserver.DashboardNodeProjection{ID: "local", Hostname: strings.TrimSpace(hostname), Health: "unknown", Version: "greenfield", Architecture: runtime.GOARCH, OperatingSystem: readOSReleaseName(), UpdatedAt: now}
}

type dashboardMetricSpec struct {
	name  capacity.MetricName
	label string
}

func dashboardMetricSpecs() []dashboardMetricSpec {
	return []dashboardMetricSpec{
		{name: "cpu.utilization", label: "CPU utilization"},
		{name: "load.1m", label: "Load (1 minute)"},
		{name: "memory.utilization", label: "Memory utilization"},
		{name: "filesystem.utilization", label: "Disk utilization"},
		{name: "filesystem.inode_utilization", label: "Inode utilization"},
		{name: "network.bytes_per_second", label: "Network throughput"},
	}
}

func (edge *dashboardEdge) latestMetric(ctx context.Context, tenantID, resourceKind, resourceID string, metric capacity.MetricName, label string) apiserver.ObservabilityMetricProjection {
	result := apiserver.ObservabilityMetricProjection{Name: string(metric), Label: label, Available: false, MissingReason: "collector_has_not_published_samples", Retention: capacity.DefaultRetentionPolicy()}
	until := edge.now().UTC().Truncate(5 * time.Minute)
	series, err := edge.metrics.Query(ctx, capacity.QueryRequest{
		Scope: capacity.MetricScope{TenantID: tenantID, ResourceKind: resourceKind, ResourceID: resourceID},
		Metric: metric, SourceTier: capacity.TierRaw, From: until.Add(-30 * time.Minute), Until: until,
		Interval: 5 * time.Minute, Aggregation: capacity.AggregationMean, MaximumSourcePoints: 2000,
	})
	if err != nil {
		if !errors.Is(err, capacity.ErrNotFound) {
			result.MissingReason = "metric_projection_unavailable"
		}
		return result
	}
	result.Unit, result.SampleInterval = series.Unit, series.RawSampleInterval
	for index := len(series.Points) - 1; index >= 0; index-- {
		point := series.Points[index]
		if point.Available {
			result.Value, result.Available, result.Complete, result.ObservedAt = point.Value, true, point.Complete, point.Until
			if !point.Complete {
				result.MissingReason = "partial_coverage"
			} else {
				result.MissingReason = ""
			}
			return result
		}
	}
	return result
}

func (edge *dashboardEdge) QueryMetric(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MetricQueryPayload) (capacity.MetricSeries, error) {
	return edge.metrics.Query(ctx, capacity.QueryRequest{
		Scope: capacity.MetricScope{TenantID: observabilityTenant(call), ResourceKind: payload.ResourceKind, ResourceID: payload.ResourceID},
		Metric: payload.Metric, SourceTier: payload.SourceTier, From: payload.From, Until: payload.Until,
		Interval: time.Duration(payload.IntervalSeconds) * time.Second, Aggregation: payload.Aggregation,
		MaximumSourcePoints: payload.MaximumSourcePoints,
	})
}

func (edge *dashboardEdge) ForecastCapacity(ctx context.Context, call apiserver.EdgeCall, payload apiserver.ForecastQueryPayload) (apiserver.CapacityForecastProjection, error) {
	query := capacity.QueryRequest{
		Scope: capacity.MetricScope{TenantID: observabilityTenant(call), ResourceKind: payload.Query.ResourceKind, ResourceID: payload.Query.ResourceID},
		Metric: payload.Query.Metric, SourceTier: payload.Query.SourceTier, From: payload.Query.From, Until: payload.Query.Until,
		Interval: time.Duration(payload.Query.IntervalSeconds) * time.Second, Aggregation: payload.Query.Aggregation,
		MaximumSourcePoints: payload.Query.MaximumSourcePoints,
	}
	forecast, err := edge.metrics.Forecast(ctx, capacity.ForecastRequest{Query: query, Horizon: time.Duration(payload.HorizonSeconds) * time.Second, MinimumSamples: payload.MinimumSamples, MinimumCoverage: payload.MinimumCoverage, CapacityLimit: payload.CapacityLimit})
	if errors.Is(err, capacity.ErrInsufficientEvidence) {
		return apiserver.CapacityForecastProjection{Available: false, MissingReason: "insufficient_measured_evidence"}, nil
	}
	if err != nil {
		return apiserver.CapacityForecastProjection{}, err
	}
	return apiserver.CapacityForecastProjection{Available: true, Forecast: &forecast}, nil
}

func observabilityTenant(call apiserver.EdgeCall) string {
	if call.TenantID != "" {
		return call.TenantID
	}
	return observabilityInstallationTenant
}

func readOSReleaseName() string {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil || len(raw) > 64<<10 {
		return runtime.GOOS
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			value := strings.TrimSpace(strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\""))
			if value != "" && len(value) <= 256 {
				return value
			}
		}
	}
	return runtime.GOOS
}

type usageDefinition struct {
	dimension string
	used      func(identity.Usage) uint64
	limit     func(identity.ResourceQuota) uint64
	unit      string
}

func usageDefinitions() []usageDefinition {
	return []usageDefinition{
		{dimension: "sites", used: func(value identity.Usage) uint64 { return value.Sites }, limit: func(value identity.ResourceQuota) uint64 { return value.Sites }, unit: "count"},
		{dimension: "domains", used: func(value identity.Usage) uint64 { return value.Domains }, limit: func(value identity.ResourceQuota) uint64 { return value.Domains }, unit: "count"},
		{dimension: "databases", used: func(value identity.Usage) uint64 { return value.Databases }, limit: func(value identity.ResourceQuota) uint64 { return value.Databases }, unit: "count"},
		{dimension: "mailboxes", used: func(value identity.Usage) uint64 { return value.Mailboxes }, limit: func(value identity.ResourceQuota) uint64 { return value.Mailboxes }, unit: "count"},
		{dimension: "ftp_accounts", used: func(value identity.Usage) uint64 { return value.FTPAccounts }, limit: func(value identity.ResourceQuota) uint64 { return value.FTPAccounts }, unit: "count"},
		{dimension: "storage", used: func(value identity.Usage) uint64 { return value.DiskBytes }, limit: func(value identity.ResourceQuota) uint64 { return value.DiskBytes }, unit: "bytes"},
		{dimension: "inodes", used: func(value identity.Usage) uint64 { return value.Inodes }, limit: func(value identity.ResourceQuota) uint64 { return value.Inodes }, unit: "count"},
		{dimension: "traffic", used: func(value identity.Usage) uint64 { return value.MonthlyTransfer }, limit: func(value identity.ResourceQuota) uint64 { return value.MonthlyTransfer }, unit: "bytes"},
	}
}

func (edge *dashboardEdge) ListUsage(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgePage[apiserver.UsageLimitProjection], error) {
	tenantID, err := identity.NewID(call.TenantID)
	if err != nil {
		return apiserver.EdgePage[apiserver.UsageLimitProjection]{}, err
	}
	tenant, err := edge.identity.Tenant(ctx, tenantID)
	if err != nil {
		return apiserver.EdgePage[apiserver.UsageLimitProjection]{}, err
	}
	usage, err := edge.identity.Usage(ctx, tenantID)
	if err != nil {
		return apiserver.EdgePage[apiserver.UsageLimitProjection]{}, err
	}
	var plan identity.Plan
	if tenant.PlanID.Valid() {
		plan, err = edge.identity.Plan(ctx, tenant.PlanID)
		if err != nil {
			return apiserver.EdgePage[apiserver.UsageLimitProjection]{}, err
		}
	}
	definitions := usageDefinitions()
	items := make([]apiserver.UsageLimitProjection, 0, len(definitions))
	for _, definition := range definitions {
		available := !usage.UpdatedAt.IsZero()
		used, limit := definition.used(usage), definition.limit(plan.Quota)
		state, missing := usageLimitState(available, tenant.PlanID.Valid(), used, limit)
		items = append(items, apiserver.UsageLimitProjection{
			ScopeKind: "tenant", ScopeID: call.TenantID, Dimension: definition.dimension,
			Used: used, Limit: limit, Unit: definition.unit, Available: available,
			LimitState: state, MissingReason: missing, UpdatedAt: usage.UpdatedAt,
		})
	}
	return apiserver.EdgePage[apiserver.UsageLimitProjection]{Items: items, Total: uint64(len(items))}, nil
}

func usageLimitState(available, planAvailable bool, used, limit uint64) (string, string) {
	if !available {
		return "unknown", "usage_projection_not_published"
	}
	if !planAvailable {
		return "unknown", "plan_limit_not_configured"
	}
	if used > limit {
		return "exceeded", ""
	}
	if used == limit {
		return "at_limit", ""
	}
	return "within_limit", ""
}

func (edge *dashboardEdge) GetSiteUsage(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgePage[apiserver.UsageLimitProjection], error) {
	if call.TenantID == "" || call.ResourceID == "" {
		return apiserver.EdgePage[apiserver.UsageLimitProjection]{}, capacity.ErrInvalid
	}
	specs := []struct {
		dimension string
		metric    capacity.MetricName
		label     string
	}{
		{dimension: "storage", metric: "storage.bytes", label: "Storage"},
		{dimension: "traffic", metric: "traffic.bytes", label: "Traffic"},
		{dimension: "inodes", metric: "inode.count", label: "Inodes"},
		{dimension: "cpu", metric: "cpu.core_seconds", label: "CPU"},
	}
	items := make([]apiserver.UsageLimitProjection, 0, len(specs))
	for _, spec := range specs {
		metric := edge.latestMetric(ctx, call.TenantID, "site", call.ResourceID, spec.metric, spec.label)
		used := uint64(0)
		available := metric.Available && metric.Value >= 0 && metric.Value < math.Exp2(64)
		missingReason := metric.MissingReason
		if available {
			used = uint64(math.Round(metric.Value))
		} else if metric.Available {
			missingReason = "metric_value_out_of_range"
		}
		items = append(items, apiserver.UsageLimitProjection{
			ScopeKind: "site", ScopeID: call.ResourceID, Dimension: spec.dimension,
			Used: used, Unit: string(metric.Unit), Available: available, LimitState: "not_configured",
			MissingReason: missingReason, UpdatedAt: metric.ObservedAt,
		})
	}
	return apiserver.EdgePage[apiserver.UsageLimitProjection]{Items: items, Total: uint64(len(items))}, nil
}

func (edge *dashboardEdge) CreateUsageExport(ctx context.Context, call apiserver.EdgeCall, payload apiserver.UsageExportPayload) (apiserver.UsageExportResult, error) {
	tenantID, err := identity.NewID(call.TenantID)
	if err != nil {
		return apiserver.UsageExportResult{}, err
	}
	periodStart, periodEnd := payload.PeriodStart.UTC(), payload.PeriodEnd.UTC()
	if periodStart.IsZero() {
		periodEnd = edge.now().UTC().Truncate(24 * time.Hour)
		periodStart = time.Date(periodEnd.Year(), periodEnd.Month(), 1, 0, 0, 0, 0, time.UTC)
		if !periodEnd.After(periodStart) {
			periodStart = periodStart.AddDate(0, -1, 0)
		}
	}
	tenant, err := edge.identity.Tenant(ctx, tenantID)
	if err != nil {
		return apiserver.UsageExportResult{}, err
	}
	usage, err := edge.identity.Usage(ctx, tenantID)
	if err != nil {
		return apiserver.UsageExportResult{}, err
	}
	var plan identity.Plan
	if tenant.PlanID.Valid() {
		plan, err = edge.identity.Plan(ctx, tenant.PlanID)
		if err != nil {
			return apiserver.UsageExportResult{}, err
		}
	}
	rows := make([]capacity.UsageRow, 0, 4)
	missing := make([]string, 0, 8)
	if tenant.PlanID.Valid() {
		rows = append(rows, usageExportRow(call.TenantID, capacity.UsagePlan, "tenant", call.TenantID, "plan.assignment", capacity.UnitCount, periodStart, periodEnd, 1, digestEvidence(plan)))
	} else {
		missing = append(missing, "plan")
	}
	if usage.UpdatedAt.IsZero() {
		missing = append(missing, "storage", "traffic", "mail")
	} else {
		if usage.DiskBytes > math.MaxInt64 || usage.MonthlyTransfer > math.MaxInt64 || usage.Mailboxes > math.MaxInt64 {
			return apiserver.UsageExportResult{}, capacity.ErrLimit
		}
		rows = append(rows,
			usageExportRow(call.TenantID, capacity.UsageStorage, "tenant", call.TenantID, "storage.bytes", capacity.UnitBytes, periodStart, periodEnd, usage.DiskBytes, digestEvidence(usage)),
			usageExportRow(call.TenantID, capacity.UsageTraffic, "tenant", call.TenantID, "traffic.bytes", capacity.UnitBytes, periodStart, periodEnd, usage.MonthlyTransfer, digestEvidence(usage)),
			usageExportRow(call.TenantID, capacity.UsageMail, "tenant", call.TenantID, "mail.mailboxes", capacity.UnitCount, periodStart, periodEnd, usage.Mailboxes, digestEvidence(usage)),
		)
	}
	missing = append(missing, "cpu", "backup", "provider", "campaign")
	if len(rows) == 0 {
		return apiserver.UsageExportResult{}, capacity.ErrInsufficientEvidence
	}
	export, err := capacity.BuildUsageExport(ctx, capacity.UsageExportRequest{ExportID: call.CommandID, PeriodStart: periodStart, PeriodEnd: periodEnd, GeneratedAt: edge.now().UTC(), Rows: rows}, edge.signer)
	if err != nil {
		return apiserver.UsageExportResult{}, err
	}
	return apiserver.UsageExportResult{State: "succeeded", Export: export, MissingDimensions: missing}, nil
}

func usageExportRow(tenantID string, dimension capacity.UsageDimension, resourceKind, resourceID string, metric capacity.MetricName, unit capacity.Unit, start, end time.Time, quantity uint64, digest string) capacity.UsageRow {
	return capacity.UsageRow{TenantID: tenantID, Dimension: dimension, ResourceKind: resourceKind, ResourceID: resourceID, Metric: metric, Unit: unit, IntervalStart: start, IntervalEnd: end, Quantity: int64(quantity), SourceDigest: digest}
}

func digestEvidence(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		raw = []byte("unavailable")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (edge *dashboardEdge) UsageExportStatus(ctx context.Context, call apiserver.EdgeCall, payload apiserver.UsageExportStatusPayload) (apiserver.UsageExportResult, error) {
	if payload.Export.ExportID == "" || call.TenantID == "" {
		return apiserver.UsageExportResult{}, capacity.ErrInvalid
	}
	if err := payload.Export.VerifyDigest(); err != nil {
		return apiserver.UsageExportResult{}, err
	}
	for _, row := range payload.Export.Rows {
		if row.TenantID != call.TenantID {
			return apiserver.UsageExportResult{}, capacity.ErrNotFound
		}
	}
	if err := edge.signer.VerifyUsageExport(ctx, payload.Export); err != nil {
		return apiserver.UsageExportResult{}, err
	}
	return apiserver.UsageExportResult{State: "verified", Export: payload.Export}, nil
}

func (edge *dashboardEdge) ListLogSources(_ context.Context, call apiserver.EdgeCall, payload apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.LogSourceProjection], error) {
	limit := payload.Limit
	if limit == 0 {
		limit = 100
	}
	page, err := edge.logRegistry.List(logworkspace.SourceID(payload.Cursor), limit)
	if err != nil {
		return apiserver.EdgePage[apiserver.LogSourceProjection]{}, err
	}
	items := make([]apiserver.LogSourceProjection, 0, len(page.Sources))
	for _, source := range page.Sources {
		if logSourceVisible(call, source) {
			items = append(items, apiserver.LogSourceProjection{
				ID: source.ID, Category: source.Category, Scope: source.Scope, Backend: source.Backend, Unit: source.Unit,
				Protected: source.Protected, Generation: source.Generation, RetentionAuthority: "systemd_journal",
				RedactionPolicy: artifactguard.ScannerVersion, CursorLifetimeSeconds: 15 * 60,
				MaximumLines: logworkspace.MaximumLines, MaximumBytes: logworkspace.MaximumBytes,
			})
		}
	}
	return apiserver.EdgePage[apiserver.LogSourceProjection]{Items: items, NextCursor: string(page.NextID)}, nil
}

func logSourceVisible(call apiserver.EdgeCall, source logworkspace.Source) bool {
	if source.Scope.TenantID == "" {
		return call.TenantID == ""
	}
	return call.TenantID != "" && source.Scope.TenantID == call.TenantID
}

func (edge *dashboardEdge) QueryLogs(ctx context.Context, call apiserver.EdgeCall, payload apiserver.LogQueryPayload) (apiserver.LogProjectionPage, error) {
	query, err := edge.logQuery(call, payload)
	if err != nil {
		return apiserver.LogProjectionPage{}, err
	}
	sink := &projectionLogSink{}
	summary, err := edge.logReader.Stream(ctx, logActor(call), query, sink)
	if err != nil {
		return apiserver.LogProjectionPage{}, err
	}
	if sink.summary != summary {
		return apiserver.LogProjectionPage{}, logworkspace.ErrIntegrity
	}
	return apiserver.LogProjectionPage{Records: sink.records, Conditions: sink.conditions, Summary: summary}, nil
}

func (edge *dashboardEdge) logQuery(call apiserver.EdgeCall, payload apiserver.LogQueryPayload) (logworkspace.Query, error) {
	source, err := edge.logRegistry.Resolve(logworkspace.SourceID(call.ResourceID))
	if err != nil {
		return logworkspace.Query{}, err
	}
	if !logSourceVisible(call, source) {
		return logworkspace.Query{}, logworkspace.ErrUnauthorized
	}
	mode := payload.Mode
	if mode == "" {
		mode = "tail"
	}
	lines, bytesLimit, duration := payload.Lines, payload.Bytes, time.Duration(payload.DurationSeconds)*time.Second
	if lines == 0 {
		lines = 100
	}
	if bytesLimit == 0 {
		bytesLimit = 512 << 10
	}
	if duration == 0 {
		duration = 5 * time.Second
	}
	query := logworkspace.Query{SourceID: source.ID, Limits: logworkspace.QueryLimits{Lines: lines, Bytes: bytesLimit, Duration: duration}}
	switch mode {
	case "tail":
		query.Projection, query.TailLines = logworkspace.ProjectionTail, payload.TailLines
		if query.TailLines == 0 {
			query.TailLines = lines
		}
	case "cursor":
		query.Projection, query.Cursor = logworkspace.ProjectionCursor, payload.Cursor
	case "time":
		query.Projection, query.Since, query.Until = logworkspace.ProjectionTime, payload.Since.UTC(), payload.Until.UTC()
	case "search":
		query.Projection, query.Since, query.Until = logworkspace.ProjectionSearch, payload.Since.UTC(), payload.Until.UTC()
		query.Search = logworkspace.SearchSpec{Literal: payload.Literal, Regex: payload.Regex, CaseSensitive: payload.CaseSensitive, RegexTimeout: time.Duration(payload.RegexTimeoutSeconds) * time.Second}
	default:
		return logworkspace.Query{}, logworkspace.ErrInvalid
	}
	if err = query.Validate(); err != nil {
		return logworkspace.Query{}, err
	}
	return query, nil
}

type projectionLogSink struct {
	records    []apiserver.LogRecordProjection
	conditions []apiserver.LogConditionProjection
	summary    logworkspace.ProjectionSummary
}

func (sink *projectionLogSink) WriteRecord(_ context.Context, record logworkspace.LogRecord) error {
	if len(sink.records) >= int(logworkspace.MaximumLines) {
		return logworkspace.ErrLimit
	}
	sink.records = append(sink.records, apiserver.LogRecordProjection{SourceID: record.SourceID, Generation: record.Generation, Sequence: record.Sequence, Offset: record.Offset, ObservedAt: record.ObservedAt, Text: string(record.Text), Redacted: record.Redacted})
	return nil
}

func (sink *projectionLogSink) WriteCondition(_ context.Context, condition logworkspace.StreamCondition) error {
	if len(sink.conditions) >= 32 {
		return logworkspace.ErrLimit
	}
	sink.conditions = append(sink.conditions, apiserver.LogConditionProjection{Code: condition.Code, SourceID: condition.SourceID, Generation: condition.Generation, At: condition.At})
	return nil
}

func (sink *projectionLogSink) Close(_ context.Context, summary logworkspace.ProjectionSummary) error {
	sink.summary = summary
	return nil
}

func (edge *dashboardEdge) CreateLogExport(ctx context.Context, call apiserver.EdgeCall, payload apiserver.LogExportPayload) (apiserver.LogExportResult, error) {
	query, err := edge.logQuery(call, payload.Query)
	if err != nil {
		return apiserver.LogExportResult{}, err
	}
	job := logworkspace.ExportJob{TenantID: observabilityTenant(call), ID: call.CommandID, SourceID: query.SourceID, SourceGeneration: call.ExpectedGeneration, Query: query, State: logworkspace.ExportQueued}
	if job.SourceGeneration == 0 {
		source, resolveErr := edge.logRegistry.Resolve(query.SourceID)
		if resolveErr != nil {
			return apiserver.LogExportResult{}, resolveErr
		}
		job.SourceGeneration = source.Generation
	}
	job, err = edge.logRepository.UpsertExportJob(ctx, job, 0)
	if err != nil {
		return apiserver.LogExportResult{}, err
	}
	artifacts := &memoryLogArtifactSink{}
	exporter, err := logworkspace.NewExportService(edge.logReader, edge.logRepository, artifacts)
	if err != nil {
		return apiserver.LogExportResult{}, err
	}
	exportActor := logActor(call)
	exportActor.TenantID = job.TenantID
	if _, err = exporter.Run(ctx, exportActor, job.TenantID, job.ID, job.Revision); err != nil {
		return apiserver.LogExportResult{}, err
	}
	job, err = edge.logRepository.GetExportJob(ctx, job.TenantID, job.ID)
	if err != nil {
		return apiserver.LogExportResult{}, err
	}
	if artifacts.writer == nil || artifacts.writer.manifest.JobID != job.ID {
		return apiserver.LogExportResult{}, logworkspace.ErrIntegrity
	}
	return apiserver.LogExportResult{Job: job, Manifest: artifacts.writer.manifest, ContentBase64: base64.StdEncoding.EncodeToString(artifacts.writer.content.Bytes())}, nil
}

func (edge *dashboardEdge) LogExportStatus(ctx context.Context, call apiserver.EdgeCall) (logworkspace.ExportJob, error) {
	return edge.logRepository.GetExportJob(ctx, observabilityTenant(call), call.ResourceID)
}

type memoryLogArtifactSink struct {
	writer *memoryLogArtifactWriter
}

func (sink *memoryLogArtifactSink) BeginLogArtifact(_ context.Context, job logworkspace.ExportJob) (logworkspace.ArtifactWriter, error) {
	if sink.writer != nil {
		return nil, logworkspace.ErrConflict
	}
	sink.writer = &memoryLogArtifactWriter{job: job}
	return sink.writer, nil
}

type memoryLogArtifactWriter struct {
	job       logworkspace.ExportJob
	content   bytes.Buffer
	manifest  logworkspace.ExportManifest
	committed bool
}

func (writer *memoryLogArtifactWriter) WriteLogChunk(_ context.Context, value []byte) error {
	if writer.committed || int64(writer.content.Len()+len(value)) > logworkspace.MaximumBytes {
		return logworkspace.ErrLimit
	}
	_, err := writer.content.Write(value)
	return err
}

func (writer *memoryLogArtifactWriter) CommitLogArtifact(_ context.Context, manifest logworkspace.ExportManifest) (logworkspace.ArtifactReceipt, error) {
	if writer.committed || manifest.JobID != writer.job.ID || manifest.SourceID != writer.job.SourceID || manifest.Bytes != int64(writer.content.Len()) {
		return logworkspace.ArtifactReceipt{}, logworkspace.ErrIntegrity
	}
	sum := sha256.Sum256(writer.content.Bytes())
	if manifest.ContentDigest != hex.EncodeToString(sum[:]) {
		return logworkspace.ArtifactReceipt{}, logworkspace.ErrIntegrity
	}
	writer.manifest, writer.committed = manifest, true
	return logworkspace.ArtifactReceipt{ArtifactID: "artifact_" + writer.job.ID, ContentDigest: manifest.ContentDigest, Bytes: manifest.Bytes}, nil
}

func (writer *memoryLogArtifactWriter) AbortLogArtifact(_ context.Context) error {
	writer.content.Reset()
	writer.manifest, writer.committed = logworkspace.ExportManifest{}, false
	return nil
}

func logActor(call apiserver.EdgeCall) logworkspace.Actor {
	sessionID := call.SessionID
	if sessionID == "" {
		sessionID = call.CredentialID
	}
	return logworkspace.Actor{SubjectID: call.PrincipalID, TenantID: call.TenantID, SessionID: sessionID, AuthzEpoch: call.AuthzEpoch}
}

type runtimeLogAuthorizer struct{}

func (runtimeLogAuthorizer) AuthorizeLogRead(_ context.Context, actor logworkspace.Actor, source logworkspace.Source, _ logworkspace.Query) error {
	installationActor := actor.TenantID == "" || actor.TenantID == observabilityInstallationTenant
	if source.Scope.TenantID == "" && !installationActor || source.Scope.TenantID != "" && source.Scope.TenantID != actor.TenantID {
		return logworkspace.ErrUnauthorized
	}
	return nil
}

type runtimeLogRedactor struct {
	now func() time.Time
}

func (redactor runtimeLogRedactor) RedactLogRecord(ctx context.Context, _ logworkspace.Source, raw []byte) ([]byte, bool, error) {
	limits := artifactguard.DefaultScanLimits()
	limits.MaximumInputBytes, limits.MaximumOutputBytes = logworkspace.MaximumRecordBytes, logworkspace.MaximumRecordBytes
	limits.MaximumLineBytes, limits.MaximumTokenBytes = logworkspace.MaximumRecordBytes, 64<<10
	var output bytes.Buffer
	manifest, err := (artifactguard.StreamingRedactor{Limits: limits}).Redact(ctx, bytes.NewReader(raw), &output, redactor.now().UTC())
	if err != nil {
		return nil, false, logworkspace.ErrLimit
	}
	return output.Bytes(), len(manifest.Findings) > 0 || !bytes.Equal(raw, output.Bytes()), nil
}

type runtimeLogTimestamp struct{}

func (runtimeLogTimestamp) Timestamp(context.Context, logworkspace.Source, []byte) (time.Time, error) {
	return time.Time{}, logworkspace.ErrIntegrity
}

func defaultJournalSources() []logworkspace.Source {
	definitions := []struct {
		id       logworkspace.SourceID
		category logworkspace.SourceCategory
		unit     logworkspace.ServiceUnitID
		protected bool
	}{
		{id: "panel-core", category: logworkspace.CategoryPanel, unit: "panel-core.service"},
		{id: "panel-gateway", category: logworkspace.CategoryPanel, unit: "panel-gateway.service"},
		{id: "panel-execd", category: logworkspace.CategoryOperation, unit: "panel-execd.service"},
		{id: "web-engine", category: logworkspace.CategoryEngine, unit: "lsws.service"},
		{id: "mariadb", category: logworkspace.CategoryDatabase, unit: "mariadb.service"},
		{id: "powerdns", category: logworkspace.CategoryDNS, unit: "pdns.service"},
		{id: "postfix", category: logworkspace.CategoryMail, unit: "postfix.service"},
		{id: "dovecot", category: logworkspace.CategoryMail, unit: "dovecot.service"},
		{id: "rspamd", category: logworkspace.CategoryMail, unit: "rspamd.service"},
		{id: "clamav", category: logworkspace.CategoryScanner, unit: "clamav-daemon.service", protected: true},
		{id: "ftps", category: logworkspace.CategoryFTP, unit: "pure-ftpd.service"},
		{id: "containers", category: logworkspace.CategoryContainer, unit: "docker.service"},
	}
	sources := make([]logworkspace.Source, 0, len(definitions))
	for _, definition := range definitions {
		sources = append(sources, logworkspace.Source{ID: definition.id, Category: definition.category, Backend: logworkspace.BackendJournal, Unit: definition.unit, Protected: definition.protected, Generation: 1})
	}
	return sources
}

func (edge *dashboardEdge) ListAlertRules(ctx context.Context, call apiserver.EdgeCall, payload apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.AlertRuleStatusProjection], error) {
	limit := int(payload.Limit)
	if limit == 0 {
		limit = 100
	}
	page, err := edge.alertRepository.ListRules(ctx, observabilityTenant(call), limit, payload.Cursor)
	if err != nil {
		return apiserver.EdgePage[apiserver.AlertRuleStatusProjection]{}, err
	}
	items := make([]apiserver.AlertRuleStatusProjection, 0, len(page.Rules))
	for _, rule := range page.Rules {
		state, stateErr := edge.alertRepository.LoadState(ctx, rule.ID)
		if stateErr != nil {
			return apiserver.EdgePage[apiserver.AlertRuleStatusProjection]{}, stateErr
		}
		items = append(items, alertRuleStatus(rule, state))
	}
	return apiserver.EdgePage[apiserver.AlertRuleStatusProjection]{Items: items, NextCursor: page.NextCursor}, nil
}

func (edge *dashboardEdge) GetAlertStatus(ctx context.Context, call apiserver.EdgeCall) (apiserver.AlertRuleStatusProjection, error) {
	rule, err := edge.alertRepository.LoadRule(ctx, call.ResourceID)
	if err != nil {
		return apiserver.AlertRuleStatusProjection{}, err
	}
	if rule.Scope.TenantID != observabilityTenant(call) {
		return apiserver.AlertRuleStatusProjection{}, alerts.ErrNotFound
	}
	state, err := edge.alertRepository.LoadState(ctx, rule.ID)
	if err != nil {
		return apiserver.AlertRuleStatusProjection{}, err
	}
	return alertRuleStatus(rule, state), nil
}

func (edge *dashboardEdge) CreateAlertRule(ctx context.Context, call apiserver.EdgeCall, payload apiserver.AlertRulePayload) (apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection], error) {
	id := payload.ID
	if id == "" {
		sum := sha256.Sum256([]byte(call.CommandID))
		id = "alert_" + hex.EncodeToString(sum[:])[:40]
	}
	now := edge.now().UTC()
	rule := alertRuleFromPayload(payload, id, observabilityTenant(call), 1, now, now)
	if err := edge.alertRepository.PutRule(ctx, rule, 0); err != nil {
		return apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection]{}, err
	}
	persistedRule, err := edge.alertRepository.LoadRule(ctx, id)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection]{}, err
	}
	rule = persistedRule
	state, err := edge.alertRepository.LoadState(ctx, id)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection]{}, err
	}
	resource := alertRuleStatus(rule, state)
	return apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection]{OperationID: call.CommandID, State: "applied", Generation: rule.Generation, Resource: resource}, nil
}

func (edge *dashboardEdge) UpdateAlertRule(ctx context.Context, call apiserver.EdgeCall, payload apiserver.AlertRulePayload) (apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection], error) {
	previous, err := edge.alertRepository.LoadRule(ctx, call.ResourceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection]{}, err
	}
	if previous.Scope.TenantID != observabilityTenant(call) || payload.ID != "" && payload.ID != previous.ID || call.ExpectedGeneration != previous.Generation {
		return apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection]{}, alerts.ErrConflict
	}
	rule := alertRuleFromPayload(payload, previous.ID, previous.Scope.TenantID, previous.Generation+1, previous.CreatedAt, edge.now().UTC())
	if err = edge.alertRepository.PutRule(ctx, rule, previous.Generation); err != nil {
		return apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection]{}, err
	}
	rule, err = edge.alertRepository.LoadRule(ctx, rule.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection]{}, err
	}
	state, err := edge.alertRepository.LoadState(ctx, rule.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection]{}, err
	}
	resource := alertRuleStatus(rule, state)
	return apiserver.EdgeMutation[apiserver.AlertRuleStatusProjection]{OperationID: call.CommandID, State: "applied", Generation: rule.Generation, Resource: resource}, nil
}

func alertRuleFromPayload(payload apiserver.AlertRulePayload, id, tenantID string, generation uint64, createdAt, updatedAt time.Time) alerts.Rule {
	return alerts.Rule{
		ID: id, Kind: payload.Kind, Scope: alerts.Scope{TenantID: tenantID, ResourceKind: payload.ResourceKind, ResourceID: payload.ResourceID},
		Comparator: payload.Comparator, Threshold: float64(payload.Threshold), Window: time.Duration(payload.WindowSeconds) * time.Second,
		Severity: payload.Severity, Hysteresis: payload.Hysteresis, ConsecutiveSamples: payload.ConsecutiveSamples,
		Cooldown: time.Duration(payload.CooldownSeconds) * time.Second, Recovery: payload.Recovery,
		NotificationRouteRefs: append([]string(nil), payload.NotificationRouteRefs...), Enabled: payload.Enabled,
		Generation: generation, CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}

func alertRuleStatus(rule alerts.Rule, state alerts.State) apiserver.AlertRuleStatusProjection {
	return apiserver.AlertRuleStatusProjection{ID: rule.ID, Kind: rule.Kind, Severity: rule.Severity, Condition: state.Condition, Active: state.Active, Enabled: rule.Enabled, Generation: rule.Generation, UpdatedAt: rule.UpdatedAt, Rule: rule, State: state}
}

func (edge *dashboardEdge) ListAlertInbox(ctx context.Context, call apiserver.EdgeCall, payload apiserver.EdgePagePayload) (apiserver.EdgePage[integrations.InboxItem], error) {
	if call.TenantID == "" || call.PrincipalID == "" {
		return apiserver.EdgePage[integrations.InboxItem]{}, integrations.ErrInvalid
	}
	limit := payload.Limit
	if limit == 0 {
		limit = 100
	}
	items, next, err := edge.inbox.List(ctx, integrations.TenantID(call.TenantID), call.PrincipalID, limit, payload.Cursor)
	if err != nil {
		return apiserver.EdgePage[integrations.InboxItem]{}, err
	}
	return apiserver.EdgePage[integrations.InboxItem]{Items: items, NextCursor: next}, nil
}

func (edge *dashboardEdge) AcknowledgeAlert(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[integrations.InboxItem], error) {
	item, err := edge.inbox.Acknowledge(ctx, integrations.TenantID(call.TenantID), call.PrincipalID, integrations.ID(call.ResourceID), call.ExpectedGeneration)
	if err != nil {
		return apiserver.EdgeMutation[integrations.InboxItem]{}, err
	}
	return apiserver.EdgeMutation[integrations.InboxItem]{OperationID: call.CommandID, State: "acknowledged", Generation: item.Generation, Resource: item}, nil
}

func (edge *dashboardEdge) ListServiceHealth(ctx context.Context, _ apiserver.EdgeCall, payload apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.ServiceHealthProjection], error) {
	return edge.serviceHealthPage(ctx, payload)
}

func (edge *dashboardEdge) serviceHealthPage(ctx context.Context, payload apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.ServiceHealthProjection], error) {
	if edge.serviceRegistry == nil || edge.serviceStore == nil {
		return apiserver.EdgePage[apiserver.ServiceHealthProjection]{}, serviceregistry.ErrUnsupported
	}
	limit := int(payload.Limit)
	if limit == 0 || limit > serviceregistry.MaxServices {
		limit = serviceregistry.MaxServices
	}
	definitions := edge.serviceRegistry.Definitions()
	items := make([]apiserver.ServiceHealthProjection, 0, limit)
	next := ""
	for _, definition := range definitions {
		if string(definition.ID) <= payload.Cursor {
			continue
		}
		if len(items) == limit {
			next = string(items[len(items)-1].ID)
			break
		}
		item := apiserver.ServiceHealthProjection{ID: string(definition.ID), Name: definition.DisplayName, Install: serviceregistry.InstallUnknown, Enable: serviceregistry.EnableUnknown, Active: serviceregistry.ActiveUnknown, Configuration: serviceregistry.ConfigUnknown, Health: serviceregistry.HealthUnknown, Drift: serviceregistry.DriftUnknown, MissingReason: "collector_has_not_published_observation"}
		if desired, err := edge.serviceStore.Desired(ctx, "local", definition.ID); err == nil {
			item.Configured, item.Generation = true, desired.Generation
		} else if !errors.Is(err, serviceregistry.ErrNotFound) {
			return apiserver.EdgePage[apiserver.ServiceHealthProjection]{}, err
		}
		observation, err := edge.serviceStore.Observed(ctx, "local", definition.ID)
		if errors.Is(err, serviceregistry.ErrNotFound) {
			items = append(items, item)
			continue
		}
		if err != nil {
			return apiserver.EdgePage[apiserver.ServiceHealthProjection]{}, err
		}
		item.Install, item.Enable, item.Active, item.Configuration = observation.Install, observation.Enable, observation.Active, observation.Config
		item.DependenciesReady, item.ExpectedListenersOwned = observation.DependenciesReady, observation.ExpectedListenersOwned
		item.InternallyHealthy, item.ExternallyFunctional = observation.InternallyHealthy, observation.ExternallyFunctional
		item.DesiredGenerationObserved, item.Health, item.Drift = observation.DesiredGenerationObserved, observation.Health, observation.Drift
		item.Generation, item.EvidenceDigest, item.ObservedAt, item.MissingReason = observation.Generation, observation.EvidenceDigest, observation.ObservedAt, ""
		observationAge := edge.now().UTC().Sub(observation.ObservedAt)
		if observation.ObservedAt.IsZero() || observationAge > 5*time.Minute || observationAge < -time.Minute {
			item.Health, item.MissingReason = serviceregistry.HealthIndeterminate, "stale_observation"
		}
		items = append(items, item)
	}
	return apiserver.EdgePage[apiserver.ServiceHealthProjection]{Items: items, NextCursor: next, Total: uint64(len(definitions))}, nil
}

func aggregateNodeHealth(services []apiserver.ServiceHealthProjection) string {
	if len(services) == 0 {
		return "unknown"
	}
	available := false
	result := "healthy"
	for _, service := range services {
		switch service.Health {
		case serviceregistry.HealthFailed:
			return "failed"
		case serviceregistry.HealthDegraded, serviceregistry.HealthIndeterminate:
			result, available = "degraded", true
		case serviceregistry.HealthHealthy:
			available = true
		}
	}
	if !available {
		return "unknown"
	}
	return result
}

type serviceRegistryClock struct {
	now func() time.Time
}

func (clock serviceRegistryClock) Now() time.Time { return clock.now().UTC() }

type operationsServiceHealthProber struct {
	commands  apiserver.OperationsCommandService
	node      operations.ResourceID
	principal operations.ResourceID
	now       func() time.Time
}

func newOperationsServiceHealthProber(commands apiserver.OperationsCommandService, now func() time.Time) (*operationsServiceHealthProber, error) {
	if commands == nil || now == nil {
		return nil, errors.New("service health prober dependencies are required")
	}
	node, nodeErr := operations.NewResourceID("local")
	principal, principalErr := operations.NewResourceID("service-health-observer")
	if nodeErr != nil || principalErr != nil {
		return nil, errors.Join(nodeErr, principalErr)
	}
	return &operationsServiceHealthProber{commands: commands, node: node, principal: principal, now: now}, nil
}

func serviceRegistryOperationName(id serviceregistry.ServiceID) (operations.ServiceName, bool) {
	switch id {
	case serviceregistry.ServiceOpenLiteSpeed:
		return operations.ServiceWebOpenLiteSpeed, true
	case serviceregistry.ServiceLiteSpeed:
		return operations.ServiceWebEnterprise, true
	case serviceregistry.ServiceMariaDB:
		return operations.ServiceMariaDB, true
	case serviceregistry.ServicePostfix:
		return operations.ServicePostfix, true
	case serviceregistry.ServiceDovecot:
		return operations.ServiceDovecot, true
	case serviceregistry.ServicePowerDNS:
		return operations.ServicePowerDNS, true
	case serviceregistry.ServiceFTPS:
		return operations.ServicePureFTPd, true
	case serviceregistry.ServiceRedis:
		return operations.ServiceRedis, true
	case serviceregistry.ServiceSearch:
		return operations.ServiceElasticsearch, true
	case serviceregistry.ServicePanelCore:
		return operations.ServicePanel, true
	default:
		return "", false
	}
}

func (prober *operationsServiceHealthProber) Probe(ctx context.Context, probe serviceregistry.BoundHealthProbe) (serviceregistry.HealthEvidence, error) {
	observedAt := prober.now().UTC()
	service, supported := serviceRegistryOperationName(probe.ServiceID)
	if !supported {
		return serviceregistry.SealHealthEvidence(serviceregistry.HealthEvidence{State: serviceregistry.HealthUnsupported, ObservedAt: observedAt})
	}
	commandID := accessEdgeID("service-health-", string(probe.ServiceID), probe.Process.BootID, probe.Process.InvocationID, observedAt.Format(time.RFC3339Nano))
	receipt, err := prober.commands.Handle(ctx, operations.DiagnoseService{
		Header: operations.CommandHeader{
			CommandID: commandID,
			NodeID:    prober.node,
			Actor: operations.Actor{
				PrincipalID:  prober.principal,
				Capabilities: []operations.Capability{operations.CapabilityNodeOperations},
			},
			RequestedAt: observedAt,
			Deadline:    observedAt.Add(15 * time.Second),
		},
		Service: service,
		Depth:   operations.DiagnosticDependency,
		Since:   observedAt.Add(-5 * time.Minute),
	})
	if err != nil {
		return serviceregistry.HealthEvidence{}, err
	}
	diagnostics := receipt.Effect.Result.Diagnostics
	if receipt.Status != operations.OperationApplied || receipt.Effect.Outcome != operations.EffectConfirmed || diagnostics == nil || diagnostics.Service != service || receipt.Effect.CompletedAt.IsZero() || len(diagnostics.Checks) == 0 {
		return serviceregistry.HealthEvidence{}, serviceregistry.ErrAmbiguous
	}
	state := serviceregistry.HealthDegraded
	internal := diagnostics.ActiveState == "active"
	if !internal {
		state = serviceregistry.HealthFailed
	}
	for _, check := range diagnostics.Checks {
		if check.EvidenceDigest == "" {
			return serviceregistry.HealthEvidence{}, serviceregistry.ErrAmbiguous
		}
		switch check.Outcome {
		case operations.CheckPass:
		case operations.CheckWarn:
			internal = false
		case operations.CheckFail:
			internal = false
			state = serviceregistry.HealthFailed
		default:
			return serviceregistry.HealthEvidence{}, serviceregistry.ErrAmbiguous
		}
	}
	return serviceregistry.SealHealthEvidence(serviceregistry.HealthEvidence{
		State:             state,
		InternallyHealthy: internal,
		ObservedAt:        receipt.Effect.CompletedAt,
	})
}

func (edge *dashboardEdge) collectServiceHealth(ctx context.Context) {
	if edge == nil || edge.serviceRegistry == nil || edge.serviceStore == nil || edge.serviceObserver == nil || ctx == nil {
		return
	}
	edge.serviceHealthMu.Lock()
	defer edge.serviceHealthMu.Unlock()
	for _, definition := range edge.serviceRegistry.Definitions() {
		if ctx.Err() != nil {
			return
		}
		expectedGeneration := uint64(0)
		if current, err := edge.serviceStore.Observed(ctx, "local", definition.ID); err == nil {
			expectedGeneration = current.Generation
		} else if !errors.Is(err, serviceregistry.ErrNotFound) {
			continue
		}
		if expectedGeneration >= serviceregistry.MaxGeneration {
			continue
		}
		var desired *serviceregistry.DesiredState
		configGeneration := uint64(0)
		if current, err := edge.serviceStore.Desired(ctx, "local", definition.ID); err == nil {
			desired = &current
			configGeneration = current.ConfigGeneration
		} else if !errors.Is(err, serviceregistry.ErrNotFound) {
			continue
		}
		observation, _ := edge.serviceObserver.Observe(ctx, "local", definition.ID, expectedGeneration+1, configGeneration, desired)
		if validationErr := serviceregistry.ValidateObservation(observation); validationErr != nil {
			continue
		}
		_ = edge.serviceStore.PutObserved(ctx, observation, expectedGeneration)
	}
}

func (edge *dashboardEdge) RunServiceHealthCollector(ctx context.Context, interval time.Duration) {
	if edge == nil || edge.serviceObserver == nil || ctx == nil || interval <= 0 {
		return
	}
	edge.collectServiceHealth(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			edge.collectServiceHealth(ctx)
		}
	}
}

func newCachedServiceRegistry(ctx context.Context, db *sql.DB) (*serviceregistry.Registry, *serviceregistry.SQLiteRepository, error) {
	support, ok := localServiceSupport()
	if !ok {
		return nil, nil, nil
	}
	return newCachedServiceRegistryForSupport(ctx, db, support)
}

func newCachedServiceRegistryForSupport(ctx context.Context, db *sql.DB, support serviceregistry.SupportContext) (*serviceregistry.Registry, *serviceregistry.SQLiteRepository, error) {
	registry, err := serviceregistry.NewRegistry(support)
	if err != nil {
		return nil, nil, err
	}
	repository, err := serviceregistry.NewSQLiteRepository(db, registry)
	if err != nil {
		return nil, nil, err
	}
	if err = repository.Init(ctx); err != nil {
		return nil, nil, err
	}
	return registry, repository, nil
}

func newObservedServiceRegistry(ctx context.Context, db *sql.DB, prober serviceregistry.HealthProber, clock serviceregistry.Clock) (*serviceregistry.Registry, *serviceregistry.SQLiteRepository, *serviceregistry.LinuxObserver, error) {
	support, ok := localServiceSupport()
	if !ok {
		return nil, nil, nil, nil
	}
	registry, repository, err := newCachedServiceRegistryForSupport(ctx, db, support)
	if err != nil {
		return nil, nil, nil, err
	}
	profile := serviceregistry.LinuxProfile(support.OSFamily + "-" + support.OSVersion)
	runner, err := serviceregistry.NewBoundedExecRunner(profile, registry)
	if err != nil {
		return nil, nil, nil, err
	}
	observer, err := serviceregistry.NewLinuxObserver(profile, registry, runner, prober, clock)
	if err != nil {
		return nil, nil, nil, err
	}
	return registry, repository, observer, nil
}

func localServiceSupport() (serviceregistry.SupportContext, bool) {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil || len(raw) > 64<<10 {
		return serviceregistry.SupportContext{}, false
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			values[key] = strings.Trim(strings.TrimSpace(value), "\"")
		}
	}
	family, version := values["ID"], values["VERSION_ID"]
	if family == "almalinux" {
		version, _, _ = strings.Cut(version, ".")
	}
	support := serviceregistry.SupportContext{OSFamily: family, OSVersion: version, Architecture: runtime.GOARCH, ReleaseChannel: "stable"}
	if family == "ubuntu" && (version == "22.04" || version == "24.04") || family == "almalinux" && (version == "8" || version == "9") {
		return support, runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
	}
	return serviceregistry.SupportContext{}, false
}

type observabilitySigner struct {
	keyID   string
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func newObservabilitySigner() (*observabilitySigner, error) {
	authority, err := loadAuditSigner(auditCredentialPath)
	if err != nil {
		return nil, err
	}
	return &observabilitySigner{keyID: authority.KeyID, private: append(ed25519.PrivateKey(nil), authority.Private...), public: append(ed25519.PublicKey(nil), authority.PublicKeys[authority.KeyID]...)}, nil
}

func (signer *observabilitySigner) KeyID() string { return signer.keyID }

func (signer *observabilitySigner) Algorithm() capacity.SignatureAlgorithm { return capacity.SignatureEd25519 }

func (signer *observabilitySigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if signer == nil || len(signer.private) != ed25519.PrivateKeySize {
		return nil, capacity.ErrInvalid
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return ed25519.Sign(signer.private, message), nil
	}
}

func (signer *observabilitySigner) VerifyUsageExport(ctx context.Context, export capacity.UsageExport) error {
	if signer == nil || export.KeyID != signer.keyID || export.Algorithm != capacity.SignatureEd25519 {
		return capacity.ErrIntegrity
	}
	digest, err := hex.DecodeString(export.Digest)
	if err != nil || len(digest) != sha256.Size {
		return capacity.ErrIntegrity
	}
	signature, err := base64.RawStdEncoding.DecodeString(export.Signature)
	if err != nil {
		return capacity.ErrIntegrity
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	message := append([]byte("capacity.usage_export.v1\x00"), digest...)
	if !ed25519.Verify(signer.public, message, signature) {
		return capacity.ErrIntegrity
	}
	return nil
}

func (signer *observabilitySigner) ActiveCursorKey(context.Context) (string, error) {
	if signer == nil || signer.keyID == "" {
		return "", logworkspace.ErrInvalid
	}
	return signer.keyID, nil
}

func (signer *observabilitySigner) SignCursor(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	if signer == nil || keyID != signer.keyID {
		return nil, logworkspace.ErrUnauthorized
	}
	return signer.Sign(ctx, message)
}

func (signer *observabilitySigner) VerifyCursor(ctx context.Context, keyID string, message, signature []byte) error {
	if signer == nil || keyID != signer.keyID {
		return logworkspace.ErrUnauthorized
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if !ed25519.Verify(signer.public, message, signature) {
		return logworkspace.ErrIntegrity
	}
	return nil
}

var _ apiserver.DashboardEdgeService = (*dashboardEdge)(nil)
var _ apiserver.ObservabilityEdgeService = (*dashboardEdge)(nil)
var _ apiserver.ObservabilityEdgeCapabilityProvider = (*dashboardEdge)(nil)
var _ capacity.Signer = (*observabilitySigner)(nil)
var _ logworkspace.CursorSigner = (*observabilitySigner)(nil)
