package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

const (
	InstallationTenantID       = "installation"
	defaultProjectionHorizon   = 90 * 24 * time.Hour
	maximumProjectionHorizon   = 366 * 24 * time.Hour
	defaultProjectionLimit     = 16
	maximumProjectionLimit     = 64
	defaultServiceWindowLimit  = 128
	maximumConflictProjections = 128
)

type WindowServiceConfig struct {
	MaximumWindows       int
	ProjectionHorizon    time.Duration
	ProjectionLimit      int
	Now                  func() time.Time
}

// WindowService is the bounded repository adapter for the maintenance-window
// API. It projects only the package's absolute and weekly schedules; it is not
// a general calendar or job scheduler.
type WindowService struct {
	repository        *Repository
	evaluator         *Evaluator
	maximumWindows    int
	projectionHorizon time.Duration
	projectionLimit   int
	now               func() time.Time
}

func NewWindowService(repository *Repository, evaluator *Evaluator, config WindowServiceConfig) (*WindowService, error) {
	if repository == nil || repository.db == nil || evaluator == nil || evaluator.repository != repository {
		return nil, ErrInvalid
	}
	if config.MaximumWindows == 0 {
		config.MaximumWindows = defaultServiceWindowLimit
	}
	if config.ProjectionHorizon == 0 {
		config.ProjectionHorizon = defaultProjectionHorizon
	}
	if config.ProjectionLimit == 0 {
		config.ProjectionLimit = defaultProjectionLimit
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaximumWindows < 1 || config.MaximumWindows > MaxPageSize ||
		config.ProjectionHorizon < time.Minute || config.ProjectionHorizon > maximumProjectionHorizon ||
		config.ProjectionLimit < 1 || config.ProjectionLimit > maximumProjectionLimit {
		return nil, ErrInvalid
	}
	return &WindowService{repository: repository, evaluator: evaluator, maximumWindows: config.MaximumWindows,
		projectionHorizon: config.ProjectionHorizon, projectionLimit: config.ProjectionLimit, now: config.Now}, nil
}

type WindowScopeSpec struct {
	Kind         ScopeKind `json:"kind"`
	NodeID       string    `json:"node_id,omitempty"`
	ResourceKind string    `json:"resource_kind,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
}

type WindowScheduleSpec struct {
	Kind                ScheduleKind `json:"kind"`
	StartsAt            time.Time    `json:"starts_at,omitempty"`
	EndsAt              time.Time    `json:"ends_at,omitempty"`
	Weekdays            []Weekday   `json:"weekdays,omitempty"`
	LocalStartMinute    uint16       `json:"local_start_minute,omitempty"`
	DurationSeconds     uint32       `json:"duration_seconds,omitempty"`
	EffectiveFrom       string       `json:"effective_from,omitempty"`
	EffectiveUntil      string       `json:"effective_until,omitempty"`
	Fold                 FoldPolicy   `json:"fold,omitempty"`
	Gap                  GapPolicy    `json:"gap,omitempty"`
}

type WindowDrainSpec struct {
	Mode               DrainMode `json:"mode"`
	BeforeStartSeconds uint32    `json:"before_start_seconds,omitempty"`
	BeforeEndSeconds   uint32    `json:"before_end_seconds,omitempty"`
}

// WindowSpec contains only caller-controlled policy. Identity, tenant,
// generation, state, and timestamps remain server-owned.
type WindowSpec struct {
	Scope                  WindowScopeSpec         `json:"scope"`
	TimeZone               string                  `json:"time_zone"`
	Schedule               WindowScheduleSpec      `json:"schedule"`
	MaximumDurationSeconds uint32                  `json:"maximum_duration_seconds"`
	Effect                 WindowEffect            `json:"effect"`
	OperationClasses       []OperationClass        `json:"operation_classes"`
	Drain                  WindowDrainSpec         `json:"drain"`
	Missed                 MissedWindowPolicy      `json:"missed"`
	EmergencyOverride      EmergencyOverridePolicy `json:"emergency_override"`
}

func CanonicalWindowSpec(spec WindowSpec) (WindowSpec, error) {
	stamp := time.Unix(946684800, 0).UTC()
	window, err := windowFromSpec("mwin_validation", InstallationTenantID, 1, stamp, stamp, spec)
	if err != nil {
		return WindowSpec{}, err
	}
	return specFromWindow(window), nil
}

type ApprovalRequirements struct {
	ConfigurationAssurance string                  `json:"configuration_assurance"`
	ExecutionApproval      string                  `json:"execution_approval"`
	EmergencyOverride      EmergencyOverridePolicy `json:"emergency_override"`
}

type OccurrenceProjection struct {
	ID               string            `json:"id"`
	Digest           string            `json:"digest"`
	WindowID         string            `json:"window_id"`
	WindowGeneration uint64            `json:"window_generation"`
	Scope            WindowScopeSpec   `json:"scope"`
	StartsAt         time.Time         `json:"starts_at"`
	EndsAt           time.Time         `json:"ends_at"`
	Effect           WindowEffect      `json:"effect"`
	OperationClasses []OperationClass  `json:"operation_classes"`
	Phase            OccurrencePhase   `json:"phase"`
	Materialized     bool              `json:"materialized"`
}

type ConflictProjection struct {
	Kind                 string           `json:"kind"`
	OtherWindowID        string           `json:"other_window_id"`
	OtherOccurrenceID    string           `json:"other_occurrence_id"`
	BlockingWindowID     string           `json:"blocking_window_id,omitempty"`
	StartsAt             time.Time        `json:"starts_at"`
	EndsAt               time.Time        `json:"ends_at"`
	OperationClasses     []OperationClass `json:"operation_classes"`
}

type WindowProjection struct {
	ID                      string                  `json:"id"`
	Type                    string                  `json:"type"`
	TenantID                string                  `json:"tenant_id"`
	Scope                   WindowScopeSpec         `json:"scope"`
	TimeZone                string                  `json:"time_zone"`
	Schedule                WindowScheduleSpec      `json:"schedule"`
	MaximumDurationSeconds  uint32                  `json:"maximum_duration_seconds"`
	Effect                  WindowEffect            `json:"effect"`
	OperationClasses        []OperationClass        `json:"operation_classes"`
	Drain                   WindowDrainSpec         `json:"drain"`
	Missed                  MissedWindowPolicy      `json:"missed"`
	EmergencyOverride       EmergencyOverridePolicy `json:"emergency_override"`
	Approval                ApprovalRequirements    `json:"approval"`
	State                   string                  `json:"state"`
	Occurrences             []OccurrenceProjection  `json:"occurrences"`
	NextOccurrenceAt        *time.Time              `json:"next_occurrence_at,omitempty"`
	ProjectionFrom          time.Time               `json:"projection_from"`
	ProjectionThrough       time.Time               `json:"projection_through"`
	ProjectionTruncated     bool                    `json:"projection_truncated"`
	Conflicts               []ConflictProjection    `json:"conflicts"`
	ConflictState           string                  `json:"conflict_state"`
	ConflictTruncated       bool                    `json:"conflict_truncated"`
	Generation              uint64                  `json:"generation"`
	CreatedAt               time.Time               `json:"created_at"`
	UpdatedAt               time.Time               `json:"updated_at"`
}

type WindowListRequest struct {
	TenantID       string
	Limit          int
	Cursor         string
	At             time.Time
	Horizon        time.Duration
	OccurrenceLimit int
}

type WindowProjectionPage struct {
	Items      []WindowProjection `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
	Total      uint64             `json:"total"`
}

type CreateWindowRequest struct {
	TenantID  string
	CommandID string
	Spec      WindowSpec
}

type UpdateWindowRequest struct {
	TenantID          string
	WindowID          string
	ExpectedGeneration uint64
	Spec              WindowSpec
}

type CancelWindowRequest struct {
	TenantID          string
	WindowID          string
	ExpectedGeneration uint64
}

func (service *WindowService) ListWindows(ctx context.Context, request WindowListRequest) (WindowProjectionPage, error) {
	if service == nil || service.repository == nil || ctx == nil || !identifierPattern.MatchString(request.TenantID) ||
		request.Limit < 1 || request.Limit > service.maximumWindows || request.Cursor != "" && !identifierPattern.MatchString(request.Cursor) {
		return WindowProjectionPage{}, ErrInvalid
	}
	at, until, occurrenceLimit, err := service.projectionRange(request.At, request.Horizon, request.OccurrenceLimit)
	if err != nil {
		return WindowProjectionPage{}, err
	}
	windows, err := service.loadCatalog(ctx, request.TenantID)
	if err != nil {
		return WindowProjectionPage{}, err
	}
	projected, err := service.projectCatalog(ctx, windows, at, until, occurrenceLimit)
	if err != nil {
		return WindowProjectionPage{}, err
	}
	start := sort.Search(len(projected), func(index int) bool { return projected[index].ID > request.Cursor })
	end := start + request.Limit
	if end > len(projected) {
		end = len(projected)
	}
	page := WindowProjectionPage{Items: append([]WindowProjection(nil), projected[start:end]...), Total: uint64(len(projected))}
	if end < len(projected) && end > start {
		page.NextCursor = projected[end-1].ID
	}
	return page, nil
}

func (service *WindowService) CreateWindow(ctx context.Context, request CreateWindowRequest) (WindowProjection, error) {
	if service == nil || service.repository == nil || ctx == nil || !identifierPattern.MatchString(request.TenantID) || !identifierPattern.MatchString(request.CommandID) {
		return WindowProjection{}, ErrInvalid
	}
	canonical, err := CanonicalWindowSpec(request.Spec)
	if err != nil {
		return WindowProjection{}, err
	}
	id := "mwin_" + digestBytes([]byte(request.CommandID))[:48]
	prior, err := service.repository.LoadWindow(ctx, id)
	if err == nil {
		if prior.Scope.TenantID != request.TenantID || !prior.Enabled || !sameWindowSpec(specFromWindow(prior), canonical) {
			return WindowProjection{}, ErrConflict
		}
		return service.projectWindow(ctx, id)
	}
	if !errors.Is(err, ErrNotFound) {
		return WindowProjection{}, err
	}
	windows, err := service.loadCatalog(ctx, request.TenantID)
	if err != nil {
		return WindowProjection{}, err
	}
	if len(windows) >= service.maximumWindows {
		return WindowProjection{}, ErrCapacity
	}
	now := service.currentTime()
	window, err := windowFromSpec(id, request.TenantID, 1, now, now, canonical)
	if err != nil {
		return WindowProjection{}, err
	}
	windows = append(windows, window)
	projected, err := service.projectCatalog(ctx, windows, now, now.Add(service.projectionHorizon), service.projectionLimit)
	if err != nil {
		return WindowProjection{}, err
	}
	result, err := findWindowProjection(projected, id)
	if err != nil {
		return WindowProjection{}, err
	}
	if err = service.repository.CreateWindow(ctx, window); err != nil {
		return WindowProjection{}, err
	}
	return result, nil
}

func (service *WindowService) UpdateWindow(ctx context.Context, request UpdateWindowRequest) (WindowProjection, error) {
	if service == nil || service.repository == nil || ctx == nil || !identifierPattern.MatchString(request.TenantID) ||
		!identifierPattern.MatchString(request.WindowID) || request.ExpectedGeneration == 0 || request.ExpectedGeneration >= maxGeneration {
		return WindowProjection{}, ErrInvalid
	}
	prior, err := service.repository.LoadWindow(ctx, request.WindowID)
	if err != nil {
		return WindowProjection{}, err
	}
	if prior.Scope.TenantID != request.TenantID || prior.Generation != request.ExpectedGeneration || !prior.Enabled {
		return WindowProjection{}, ErrConflict
	}
	canonical, err := CanonicalWindowSpec(request.Spec)
	if err != nil {
		return WindowProjection{}, err
	}
	now := service.currentTime()
	next, err := windowFromSpec(prior.ID, request.TenantID, prior.Generation+1, prior.CreatedAt, now, canonical)
	if err != nil {
		return WindowProjection{}, err
	}
	if next.Scope != prior.Scope {
		return WindowProjection{}, ErrInvalid
	}
	windows, err := service.loadCatalog(ctx, request.TenantID)
	if err != nil {
		return WindowProjection{}, err
	}
	if !replaceWindow(windows, next) {
		return WindowProjection{}, ErrNotFound
	}
	projected, err := service.projectCatalog(ctx, windows, now, now.Add(service.projectionHorizon), service.projectionLimit)
	if err != nil {
		return WindowProjection{}, err
	}
	result, err := findWindowProjection(projected, next.ID)
	if err != nil {
		return WindowProjection{}, err
	}
	if err = service.repository.UpdateWindow(ctx, next, request.ExpectedGeneration); err != nil {
		return WindowProjection{}, err
	}
	return result, nil
}

func (service *WindowService) CancelWindow(ctx context.Context, request CancelWindowRequest) (WindowProjection, error) {
	if service == nil || service.repository == nil || ctx == nil || !identifierPattern.MatchString(request.TenantID) ||
		!identifierPattern.MatchString(request.WindowID) || request.ExpectedGeneration == 0 || request.ExpectedGeneration >= maxGeneration {
		return WindowProjection{}, ErrInvalid
	}
	prior, err := service.repository.LoadWindow(ctx, request.WindowID)
	if err != nil {
		return WindowProjection{}, err
	}
	if prior.Scope.TenantID != request.TenantID || prior.Generation != request.ExpectedGeneration || !prior.Enabled {
		return WindowProjection{}, ErrConflict
	}
	now := service.currentTime()
	canceled := prior
	canceled.Enabled = false
	canceled.Generation++
	canceled.UpdatedAt = now
	windows, err := service.loadCatalog(ctx, request.TenantID)
	if err != nil {
		return WindowProjection{}, err
	}
	if !replaceWindow(windows, canceled) {
		return WindowProjection{}, ErrNotFound
	}
	projected, err := service.projectCatalog(ctx, windows, now, now.Add(service.projectionHorizon), service.projectionLimit)
	if err != nil {
		return WindowProjection{}, err
	}
	result, err := findWindowProjection(projected, canceled.ID)
	if err != nil {
		return WindowProjection{}, err
	}
	if _, err = service.repository.DisableWindow(ctx, prior.ID, request.ExpectedGeneration, now); err != nil {
		return WindowProjection{}, err
	}
	return result, nil
}

func (service *WindowService) projectWindow(ctx context.Context, id string) (WindowProjection, error) {
	window, err := service.repository.LoadWindow(ctx, id)
	if err != nil {
		return WindowProjection{}, err
	}
	windows, err := service.loadCatalog(ctx, window.Scope.TenantID)
	if err != nil {
		return WindowProjection{}, err
	}
	now := service.currentTime()
	projected, err := service.projectCatalog(ctx, windows, now, now.Add(service.projectionHorizon), service.projectionLimit)
	if err != nil {
		return WindowProjection{}, err
	}
	return findWindowProjection(projected, id)
}

func (service *WindowService) loadCatalog(ctx context.Context, tenantID string) ([]Window, error) {
	page, err := service.repository.ListWindows(ctx, tenantID, service.maximumWindows, "")
	if err != nil {
		return nil, err
	}
	if page.NextCursor != "" {
		return nil, ErrCapacity
	}
	return page.Windows, nil
}

func (service *WindowService) projectionRange(at time.Time, horizon time.Duration, limit int) (time.Time, time.Time, int, error) {
	if at.IsZero() {
		at = service.currentTime()
	} else {
		at = at.UTC()
	}
	if horizon == 0 {
		horizon = service.projectionHorizon
	}
	if limit == 0 {
		limit = service.projectionLimit
	}
	if !validTimestamp(at) || horizon < time.Minute || horizon > maximumProjectionHorizon || limit < 1 || limit > maximumProjectionLimit {
		return time.Time{}, time.Time{}, 0, ErrInvalid
	}
	until := at.Add(horizon).UTC()
	if !validTimestamp(until) || !until.After(at) {
		return time.Time{}, time.Time{}, 0, ErrInvalid
	}
	return at, until, limit, nil
}

func (service *WindowService) currentTime() time.Time {
	return service.now().UTC()
}

func (service *WindowService) projectCatalog(ctx context.Context, windows []Window, at, until time.Time, occurrenceLimit int) ([]WindowProjection, error) {
	ordered := append([]Window(nil), windows...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].ID < ordered[right].ID })
	projected := make([]WindowProjection, 0, len(ordered))
	for _, window := range ordered {
		occurrences, truncated, err := service.projectOccurrences(ctx, window, at, until, occurrenceLimit)
		if err != nil {
			return nil, err
		}
		spec := specFromWindow(window)
		state := "active"
		if !window.Enabled {
			state = "canceled"
		}
		projection := WindowProjection{ID: window.ID, Type: state, TenantID: window.Scope.TenantID, Scope: spec.Scope,
			TimeZone: spec.TimeZone, Schedule: spec.Schedule, MaximumDurationSeconds: spec.MaximumDurationSeconds,
			Effect: spec.Effect, OperationClasses: append([]OperationClass(nil), spec.OperationClasses...), Drain: spec.Drain,
			Missed: spec.Missed, EmergencyOverride: spec.EmergencyOverride, Approval: approvalRequirements(window), State: state,
			Occurrences: occurrences, ProjectionFrom: at, ProjectionThrough: until, ProjectionTruncated: truncated,
			Conflicts: []ConflictProjection{}, ConflictState: "clear", Generation: window.Generation,
			CreatedAt: window.CreatedAt, UpdatedAt: window.UpdatedAt}
		if len(occurrences) > 0 {
			next := occurrences[0].StartsAt
			projection.NextOccurrenceAt = &next
		}
		projected = append(projected, projection)
	}
	applyConflicts(ordered, projected)
	return projected, nil
}

func (service *WindowService) projectOccurrences(ctx context.Context, window Window, at, until time.Time, limit int) ([]OccurrenceProjection, bool, error) {
	if !window.Enabled {
		return []OccurrenceProjection{}, false, nil
	}
	spans, err := projectedSpans(window, at, until)
	if err != nil {
		return nil, false, err
	}
	truncated := len(spans) > limit
	if truncated {
		spans = spans[:limit]
	}
	result := make([]OccurrenceProjection, 0, len(spans))
	for _, candidate := range spans {
		occurrence, err := buildOccurrence(window, candidate)
		if err != nil {
			return nil, false, err
		}
		materialized, err := service.repository.occurrenceExists(ctx, occurrence.ID)
		if err != nil {
			return nil, false, err
		}
		result = append(result, OccurrenceProjection{ID: occurrence.ID, Digest: occurrence.Digest,
			WindowID: occurrence.WindowID, WindowGeneration: occurrence.WindowGeneration, Scope: scopeSpec(occurrence.Scope),
			StartsAt: occurrence.StartsAt, EndsAt: occurrence.EndsAt, Effect: window.Effect,
			OperationClasses: append([]OperationClass(nil), window.OperationClasses...),
			Phase: phaseAt(window, candidate, at, materialized), Materialized: materialized})
	}
	return result, truncated, nil
}

func projectedSpans(window Window, from, until time.Time) ([]span, error) {
	if window.Validate() != nil || !validTimestamp(from) || !validTimestamp(until) || !until.After(from) || until.Sub(from) > maximumProjectionHorizon {
		return nil, ErrInvalid
	}
	if window.Schedule.Kind == ScheduleAbsolute {
		candidate := span{startsAt: window.Schedule.StartAt, endsAt: window.Schedule.EndAt}
		if candidate.endsAt.After(from) && candidate.startsAt.Before(until) {
			return []span{candidate}, nil
		}
		return []span{}, nil
	}
	location, err := normalizedLocation(window.TimeZone)
	if err != nil {
		return nil, err
	}
	localFrom := from.In(location)
	localUntil := until.In(location)
	date := addCivilDays(civilDate{year: localFrom.Year(), month: localFrom.Month(), day: localFrom.Day()}, -7)
	last := addCivilDays(civilDate{year: localUntil.Year(), month: localUntil.Month(), day: localUntil.Day()}, 1)
	spans := make([]span, 0, 64)
	for steps := 0; compareCivil(date, last) <= 0; steps++ {
		if steps > 376 {
			return nil, ErrCapacity
		}
		if recurrenceIncludesDate(window.Schedule.Recurrence, date) {
			start, exists, resolveErr := resolveLocalMinute(location, date, window.Schedule.Recurrence.LocalStartMinute,
				window.Schedule.Recurrence.Fold, window.Schedule.Recurrence.Gap)
			if resolveErr != nil {
				return nil, resolveErr
			}
			if exists {
				candidate := span{startsAt: start, endsAt: start.Add(window.Schedule.Recurrence.Duration).UTC()}
				if candidate.endsAt.After(from) && candidate.startsAt.Before(until) {
					spans = append(spans, candidate)
				}
			}
		}
		date = addCivilDays(date, 1)
	}
	sort.Slice(spans, func(left, right int) bool {
		if !spans[left].startsAt.Equal(spans[right].startsAt) {
			return spans[left].startsAt.Before(spans[right].startsAt)
		}
		return spans[left].endsAt.Before(spans[right].endsAt)
	})
	return deduplicateSpans(spans), nil
}

func applyConflicts(windows []Window, projected []WindowProjection) {
	for index := range windows {
		if !windows[index].Enabled {
			continue
		}
		for left := 0; left < len(projected[index].Occurrences); left++ {
			for right := left + 1; right < len(projected[index].Occurrences); right++ {
				appendConflict(&projected[index], windows[index], projected[index].Occurrences[left], windows[index], projected[index].Occurrences[right], windows[index].OperationClasses)
			}
		}
		for other := index + 1; other < len(windows); other++ {
			if !windows[other].Enabled || !scopesOverlap(windows[index].Scope, windows[other].Scope) {
				continue
			}
			classes := sharedOperationClasses(windows[index].OperationClasses, windows[other].OperationClasses)
			if len(classes) == 0 {
				continue
			}
			for _, left := range projected[index].Occurrences {
				for _, right := range projected[other].Occurrences {
					appendConflict(&projected[index], windows[index], left, windows[other], right, classes)
					appendConflict(&projected[other], windows[other], right, windows[index], left, classes)
				}
			}
		}
	}
	for index := range projected {
		sort.Slice(projected[index].Conflicts, func(left, right int) bool {
			first, second := projected[index].Conflicts[left], projected[index].Conflicts[right]
			if !first.StartsAt.Equal(second.StartsAt) {
				return first.StartsAt.Before(second.StartsAt)
			}
			if first.Kind != second.Kind {
				return first.Kind < second.Kind
			}
			if first.OtherWindowID != second.OtherWindowID {
				return first.OtherWindowID < second.OtherWindowID
			}
			return first.OtherOccurrenceID < second.OtherOccurrenceID
		})
		for _, conflict := range projected[index].Conflicts {
			if conflict.Kind == "blackout" {
				projected[index].ConflictState = "blackout"
				break
			}
			projected[index].ConflictState = "overlap"
		}
	}
}

func appendConflict(target *WindowProjection, own Window, ownOccurrence OccurrenceProjection, other Window,
	otherOccurrence OccurrenceProjection, classes []OperationClass) {
	startsAt := ownOccurrence.StartsAt
	if otherOccurrence.StartsAt.After(startsAt) {
		startsAt = otherOccurrence.StartsAt
	}
	endsAt := ownOccurrence.EndsAt
	if otherOccurrence.EndsAt.Before(endsAt) {
		endsAt = otherOccurrence.EndsAt
	}
	if !startsAt.Before(endsAt) {
		return
	}
	if len(target.Conflicts) >= maximumConflictProjections {
		target.ConflictTruncated = true
		return
	}
	kind := "overlap"
	blocking := ""
	if own.Effect == EffectDeny || other.Effect == EffectDeny {
		kind = "blackout"
		if own.Effect == EffectDeny {
			blocking = own.ID
		}
		if other.Effect == EffectDeny && (blocking == "" || other.ID < blocking) {
			blocking = other.ID
		}
	}
	target.Conflicts = append(target.Conflicts, ConflictProjection{Kind: kind, OtherWindowID: other.ID,
		OtherOccurrenceID: otherOccurrence.ID, BlockingWindowID: blocking, StartsAt: startsAt, EndsAt: endsAt,
		OperationClasses: append([]OperationClass(nil), classes...)})
}

func scopesOverlap(left, right Scope) bool {
	if left.TenantID != right.TenantID {
		return false
	}
	if left.Kind == ScopeTenant || right.Kind == ScopeTenant {
		return true
	}
	if left.Kind == ScopeNode && right.Kind == ScopeNode {
		return left.NodeID == right.NodeID
	}
	if left.Kind == ScopeResource && right.Kind == ScopeResource {
		return left.ResourceKind == right.ResourceKind && left.ResourceID == right.ResourceID &&
			(left.NodeID == "" || right.NodeID == "" || left.NodeID == right.NodeID)
	}
	node, resource := left, right
	if node.Kind == ScopeResource {
		node, resource = right, left
	}
	return node.Kind == ScopeNode && resource.Kind == ScopeResource && (resource.NodeID == "" || resource.NodeID == node.NodeID)
}

func sharedOperationClasses(left, right []OperationClass) []OperationClass {
	result := make([]OperationClass, 0)
	for leftIndex, rightIndex := 0, 0; leftIndex < len(left) && rightIndex < len(right); {
		switch {
		case left[leftIndex] < right[rightIndex]:
			leftIndex++
		case right[rightIndex] < left[leftIndex]:
			rightIndex++
		default:
			result = append(result, left[leftIndex])
			leftIndex++
			rightIndex++
		}
	}
	return result
}

func approvalRequirements(window Window) ApprovalRequirements {
	execution := "policy"
	for _, class := range window.OperationClasses {
		switch class {
		case OperationDisruptive, OperationUpgrade, OperationRestore, OperationSecurity, OperationRecovery:
			execution = "independent"
		}
	}
	return ApprovalRequirements{ConfigurationAssurance: "phishing_resistant", ExecutionApproval: execution,
		EmergencyOverride: window.EmergencyOverride}
}

func windowFromSpec(id, tenantID string, generation uint64, createdAt, updatedAt time.Time, spec WindowSpec) (Window, error) {
	spec.Scope.NodeID = strings.TrimSpace(spec.Scope.NodeID)
	spec.Scope.ResourceKind = strings.TrimSpace(spec.Scope.ResourceKind)
	spec.Scope.ResourceID = strings.TrimSpace(spec.Scope.ResourceID)
	spec.TimeZone = strings.TrimSpace(spec.TimeZone)
	spec.Schedule.EffectiveFrom = strings.TrimSpace(spec.Schedule.EffectiveFrom)
	spec.Schedule.EffectiveUntil = strings.TrimSpace(spec.Schedule.EffectiveUntil)
	schedule := Schedule{Kind: spec.Schedule.Kind}
	switch spec.Schedule.Kind {
	case ScheduleAbsolute:
		if len(spec.Schedule.Weekdays) != 0 || spec.Schedule.LocalStartMinute != 0 || spec.Schedule.DurationSeconds != 0 ||
			spec.Schedule.EffectiveFrom != "" || spec.Schedule.EffectiveUntil != "" || spec.Schedule.Fold != "" || spec.Schedule.Gap != "" {
			return Window{}, ErrInvalid
		}
		schedule.StartAt = spec.Schedule.StartsAt.UTC()
		schedule.EndAt = spec.Schedule.EndsAt.UTC()
	case ScheduleWeekly:
		if !spec.Schedule.StartsAt.IsZero() || !spec.Schedule.EndsAt.IsZero() {
			return Window{}, ErrInvalid
		}
		schedule.Recurrence = Recurrence{Weekdays: append([]Weekday(nil), spec.Schedule.Weekdays...),
			LocalStartMinute: spec.Schedule.LocalStartMinute, Duration: time.Duration(spec.Schedule.DurationSeconds) * time.Second,
			EffectiveFrom: spec.Schedule.EffectiveFrom, EffectiveUntil: spec.Schedule.EffectiveUntil,
			Fold: spec.Schedule.Fold, Gap: spec.Schedule.Gap}
	default:
		return Window{}, ErrInvalid
	}
	window := Window{ID: id, Scope: Scope{Kind: spec.Scope.Kind, TenantID: tenantID, NodeID: spec.Scope.NodeID,
		ResourceKind: spec.Scope.ResourceKind, ResourceID: spec.Scope.ResourceID}, TimeZone: spec.TimeZone,
		Schedule: schedule, MaximumDuration: time.Duration(spec.MaximumDurationSeconds) * time.Second, Effect: spec.Effect,
		OperationClasses: append([]OperationClass(nil), spec.OperationClasses...), Drain: DrainPolicy{Mode: spec.Drain.Mode,
			BeforeStart: time.Duration(spec.Drain.BeforeStartSeconds) * time.Second,
			BeforeEnd: time.Duration(spec.Drain.BeforeEndSeconds) * time.Second}, Missed: spec.Missed,
		EmergencyOverride: spec.EmergencyOverride, Enabled: true, Generation: generation,
		CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC()}
	return CanonicalWindow(window)
}

func specFromWindow(window Window) WindowSpec {
	spec := WindowSpec{Scope: scopeSpec(window.Scope), TimeZone: window.TimeZone,
		MaximumDurationSeconds: uint32(window.MaximumDuration / time.Second), Effect: window.Effect,
		OperationClasses: append([]OperationClass(nil), window.OperationClasses...),
		Drain: WindowDrainSpec{Mode: window.Drain.Mode, BeforeStartSeconds: uint32(window.Drain.BeforeStart / time.Second),
			BeforeEndSeconds: uint32(window.Drain.BeforeEnd / time.Second)}, Missed: window.Missed,
		EmergencyOverride: window.EmergencyOverride}
	if window.Schedule.Kind == ScheduleAbsolute {
		spec.Schedule = WindowScheduleSpec{Kind: ScheduleAbsolute, StartsAt: window.Schedule.StartAt, EndsAt: window.Schedule.EndAt}
	} else {
		recurrence := window.Schedule.Recurrence
		spec.Schedule = WindowScheduleSpec{Kind: ScheduleWeekly, Weekdays: append([]Weekday(nil), recurrence.Weekdays...),
			LocalStartMinute: recurrence.LocalStartMinute, DurationSeconds: uint32(recurrence.Duration / time.Second),
			EffectiveFrom: recurrence.EffectiveFrom, EffectiveUntil: recurrence.EffectiveUntil,
			Fold: recurrence.Fold, Gap: recurrence.Gap}
	}
	return spec
}

func scopeSpec(scope Scope) WindowScopeSpec {
	return WindowScopeSpec{Kind: scope.Kind, NodeID: scope.NodeID, ResourceKind: scope.ResourceKind, ResourceID: scope.ResourceID}
}

func sameWindowSpec(left, right WindowSpec) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftRaw) == string(rightRaw)
}

func replaceWindow(windows []Window, replacement Window) bool {
	for index := range windows {
		if windows[index].ID == replacement.ID {
			windows[index] = replacement
			return true
		}
	}
	return false
}

func findWindowProjection(projected []WindowProjection, id string) (WindowProjection, error) {
	index := sort.Search(len(projected), func(index int) bool { return projected[index].ID >= id })
	if index >= len(projected) || projected[index].ID != id {
		return WindowProjection{}, ErrNotFound
	}
	return projected[index], nil
}
