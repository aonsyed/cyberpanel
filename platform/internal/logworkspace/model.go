package logworkspace

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalid      = errors.New("log workspace: invalid input")
	ErrUnauthorized = errors.New("log workspace: unauthorized")
	ErrNotFound     = errors.New("log workspace: not found")
	ErrConflict     = errors.New("log workspace: revision conflict")
	ErrLimit        = errors.New("log workspace: bounded limit exceeded")
	ErrIntegrity    = errors.New("log workspace: integrity check failed")
	ErrGap          = errors.New("log workspace: source gap")
	ErrProtected    = errors.New("log workspace: protected source")
)

const (
	MaximumSources            = 512
	MaximumPageSize           = 100
	MaximumLines        uint32 = 10_000
	MaximumTailLines    uint32 = 5_000
	MaximumBytes        int64  = 16 << 20
	MaximumRecordBytes         = 256 << 10
	MaximumSearchLiteral       = 4 << 10
	MaximumRegexBytes          = 2 << 10
	MaximumRegexInstructions   = 2_048
	MaximumDuration            = 30 * time.Second
	MaximumRegexDuration       = 10 * time.Second
	MaximumCursorLifetime      = 24 * time.Hour
	MaximumOpaqueBytes         = 4 << 10
	MaximumSourceJSONBytes     = 32 << 10
	MaximumExportJSONBytes     = 64 << 10
	MaximumReceiptJSONBytes    = 64 << 10
	MaximumExportsPerTenant    = 256
	MaximumGeneration   uint64 = 1<<63 - 1
)

var (
	opaquePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)
	segmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$`)
)

type SourceID string
type RootID string
type ServiceUnitID string
type RotationProfileID string

type SourceCategory string

const (
	CategoryPanel     SourceCategory = "panel"
	CategoryEngine    SourceCategory = "engine"
	CategorySite      SourceCategory = "site"
	CategoryDatabase  SourceCategory = "database"
	CategoryDNS       SourceCategory = "dns"
	CategoryMail      SourceCategory = "mail"
	CategoryFTP       SourceCategory = "ftp"
	CategoryWAF       SourceCategory = "waf"
	CategoryScanner   SourceCategory = "scanner"
	CategoryContainer SourceCategory = "container"
	CategoryOperation SourceCategory = "operation"
)

func (category SourceCategory) valid() bool {
	switch category {
	case CategoryPanel, CategoryEngine, CategorySite, CategoryDatabase, CategoryDNS,
		CategoryMail, CategoryFTP, CategoryWAF, CategoryScanner, CategoryContainer, CategoryOperation:
		return true
	default:
		return false
	}
}

type BackendKind string

const (
	BackendJournal BackendKind = "journal"
	BackendFile    BackendKind = "file"
)

// OwnedFileIdentity is installed by trusted local management. Read requests carry
// only SourceID; they can never substitute a host path.
type OwnedFileIdentity struct {
	Root       RootID   `json:"root"`
	Segments   []string `json:"segments"`
	OwnerUID   uint32   `json:"owner_uid"`
	OwnerGID   uint32   `json:"owner_gid"`
	Device     uint64   `json:"device"`
	Inode      uint64   `json:"inode"`
	Generation uint64   `json:"generation"`
}

func (identity OwnedFileIdentity) validate(roots map[RootID]struct{}) error {
	if _, ok := roots[identity.Root]; !ok || identity.Device == 0 || identity.Inode == 0 || identity.Generation == 0 || identity.Generation > MaximumGeneration || len(identity.Segments) == 0 || len(identity.Segments) > 16 {
		return ErrInvalid
	}
	for _, segment := range identity.Segments {
		if segment == "." || segment == ".." || !segmentPattern.MatchString(segment) {
			return ErrInvalid
		}
	}
	return nil
}

type SourceScope struct {
	TenantID string `json:"tenant_id,omitempty"`
	SiteID   string `json:"site_id,omitempty"`
}

func (scope SourceScope) valid() bool {
	return (scope.TenantID == "" || opaquePattern.MatchString(scope.TenantID)) &&
		(scope.SiteID == "" || opaquePattern.MatchString(scope.SiteID))
}

type Source struct {
	ID              SourceID             `json:"id"`
	Category        SourceCategory       `json:"category"`
	Scope           SourceScope          `json:"scope"`
	Backend         BackendKind          `json:"backend"`
	Unit            ServiceUnitID        `json:"unit,omitempty"`
	File            *OwnedFileIdentity   `json:"file,omitempty"`
	RotationProfile RotationProfileID    `json:"rotation_profile,omitempty"`
	Protected       bool                 `json:"protected"`
	Generation      uint64               `json:"generation"`
}

var fixedJournalUnits = map[SourceCategory]map[ServiceUnitID]struct{}{
	CategoryPanel:     {"panel-core.service": {}, "panel-gateway.service": {}, "panel-authd.service": {}, "panel-secretd.service": {}},
	CategoryEngine:    {"lsws.service": {}, "openlitespeed.service": {}},
	CategoryDatabase:  {"mariadb.service": {}, "mysql.service": {}, "postgresql.service": {}, "redis.service": {}, "memcached.service": {}},
	CategoryDNS:       {"pdns.service": {}, "named.service": {}},
	CategoryMail:      {"postfix.service": {}, "dovecot.service": {}, "rspamd.service": {}, "opendkim.service": {}, "redis-server@cyberpanel-mail.service": {}, "redis@cyberpanel-mail.service": {}},
	CategoryFTP:       {"pure-ftpd.service": {}},
	CategoryScanner:   {"clamav-daemon.service": {}, "clamd@scan.service": {}, "clamd@cyberpanel.service": {}},
	CategoryContainer: {"podman.service": {}, "docker.service": {}},
	CategoryOperation: {"panel-execd.service": {}, "panel-providerd.service": {}},
}

var fixedRotationProfiles = map[RotationProfileID]struct{}{
	"panel": {}, "engine": {}, "site": {}, "database": {}, "dns": {}, "mail": {},
	"ftp": {}, "waf": {}, "scanner": {}, "container": {}, "operation": {},
}

func (source Source) validate(roots map[RootID]struct{}) error {
	if !opaquePattern.MatchString(string(source.ID)) || !source.Category.valid() || !source.Scope.valid() || source.Generation == 0 || source.Generation > MaximumGeneration {
		return ErrInvalid
	}
	if source.RotationProfile != "" {
		if _, allowed := fixedRotationProfiles[source.RotationProfile]; !allowed {
			return ErrInvalid
		}
		if string(source.RotationProfile) != string(source.Category) {
			return ErrInvalid
		}
	}
	if (source.Category == CategoryWAF || source.Category == CategoryScanner) && !source.Protected {
		return ErrInvalid
	}
	switch source.Backend {
	case BackendJournal:
		units, ok := fixedJournalUnits[source.Category]
		_, allowed := units[source.Unit]
		if !ok || !allowed || source.File != nil || source.RotationProfile != "" {
			return ErrInvalid
		}
	case BackendFile:
		if source.Unit != "" || source.File == nil || source.File.Generation != source.Generation || source.File.validate(roots) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func cloneSource(source Source) Source {
	if source.File != nil {
		copyIdentity := *source.File
		copyIdentity.Segments = append([]string(nil), source.File.Segments...)
		source.File = &copyIdentity
	}
	return source
}

// Registry is the closed, installer-owned source allowlist.
type Registry struct {
	mu      sync.RWMutex
	roots   map[RootID]struct{}
	sources map[SourceID]Source
}

func NewRegistry(approvedRoots []RootID, sources []Source) (*Registry, error) {
	if len(approvedRoots) > MaximumSources || len(sources) == 0 || len(sources) > MaximumSources {
		return nil, ErrInvalid
	}
	roots := make(map[RootID]struct{}, len(approvedRoots))
	for _, root := range approvedRoots {
		if !opaquePattern.MatchString(string(root)) {
			return nil, ErrInvalid
		}
		if _, exists := roots[root]; exists {
			return nil, ErrConflict
		}
		roots[root] = struct{}{}
	}
	registry := &Registry{roots: roots, sources: make(map[SourceID]Source, len(sources))}
	for _, source := range sources {
		if source.validate(roots) != nil {
			return nil, ErrInvalid
		}
		if _, exists := registry.sources[source.ID]; exists {
			return nil, ErrConflict
		}
		registry.sources[source.ID] = cloneSource(source)
	}
	return registry, nil
}

func (registry *Registry) Resolve(id SourceID) (Source, error) {
	if registry == nil || !opaquePattern.MatchString(string(id)) {
		return Source{}, ErrInvalid
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	source, ok := registry.sources[id]
	if !ok {
		return Source{}, ErrNotFound
	}
	return cloneSource(source), nil
}

type SourcePage struct {
	Sources []Source
	NextID  SourceID
}

func (registry *Registry) List(after SourceID, limit uint16) (SourcePage, error) {
	if registry == nil || limit == 0 || limit > MaximumPageSize || after != "" && !opaquePattern.MatchString(string(after)) {
		return SourcePage{}, ErrInvalid
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	ids := make([]string, 0, len(registry.sources))
	for id := range registry.sources {
		if string(id) > string(after) {
			ids = append(ids, string(id))
		}
	}
	sort.Strings(ids)
	page := SourcePage{Sources: make([]Source, 0, limit)}
	for index, id := range ids {
		if index == int(limit) {
			page.NextID = page.Sources[len(page.Sources)-1].ID
			break
		}
		page.Sources = append(page.Sources, cloneSource(registry.sources[SourceID(id)]))
	}
	return page, nil
}

func (registry *Registry) CompareAndSwapGeneration(id SourceID, expected, next uint64) error {
	if registry == nil || expected == 0 || next <= expected || next > MaximumGeneration {
		return ErrInvalid
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	source, ok := registry.sources[id]
	if !ok {
		return ErrNotFound
	}
	if source.Generation != expected {
		return ErrConflict
	}
	source.Generation = next
	if source.File != nil {
		source.File.Generation = next
	}
	registry.sources[id] = source
	return nil
}

type ProjectionKind string

const (
	ProjectionCursor ProjectionKind = "cursor"
	ProjectionTime   ProjectionKind = "time"
	ProjectionTail   ProjectionKind = "tail"
	ProjectionSearch ProjectionKind = "search"
)

type SearchSpec struct {
	Literal       string        `json:"literal"`
	Regex         string        `json:"regex,omitempty"`
	CaseSensitive bool          `json:"case_sensitive"`
	RegexTimeout  time.Duration `json:"regex_timeout"`
}

type QueryLimits struct {
	Lines    uint32        `json:"lines"`
	Bytes    int64         `json:"bytes"`
	Duration time.Duration `json:"duration"`
}

type Query struct {
	SourceID  SourceID       `json:"source_id"`
	Projection ProjectionKind `json:"projection"`
	Cursor     string         `json:"cursor,omitempty"`
	Since      time.Time      `json:"since,omitempty"`
	Until      time.Time      `json:"until,omitempty"`
	TailLines  uint32         `json:"tail_lines,omitempty"`
	Search     SearchSpec     `json:"search"`
	Limits     QueryLimits    `json:"limits"`
}

func (query Query) Validate() error {
	if !opaquePattern.MatchString(string(query.SourceID)) || query.Limits.Lines == 0 || query.Limits.Lines > MaximumLines || query.Limits.Bytes <= 0 || query.Limits.Bytes > MaximumBytes || query.Limits.Duration <= 0 || query.Limits.Duration > MaximumDuration || len(query.Cursor) > MaximumOpaqueBytes {
		return ErrInvalid
	}
	if !query.Since.IsZero() && !query.Until.IsZero() && !query.Since.Before(query.Until) {
		return ErrInvalid
	}
	switch query.Projection {
	case ProjectionCursor:
		if query.Cursor == "" || !query.Since.IsZero() || !query.Until.IsZero() || query.TailLines != 0 || query.Search != (SearchSpec{}) {
			return ErrInvalid
		}
	case ProjectionTime:
		if query.Cursor != "" || query.Since.IsZero() || query.Until.IsZero() || query.TailLines != 0 || query.Search != (SearchSpec{}) {
			return ErrInvalid
		}
	case ProjectionTail:
		if query.Cursor != "" || query.TailLines == 0 || query.TailLines > MaximumTailLines || !query.Since.IsZero() || !query.Until.IsZero() || query.Search != (SearchSpec{}) {
			return ErrInvalid
		}
	case ProjectionSearch:
		if query.Cursor != "" || query.TailLines != 0 || query.Search.Literal == "" || len(query.Search.Literal) > MaximumSearchLiteral || len(query.Search.Regex) > MaximumRegexBytes || query.Search.Regex == "" && query.Search.RegexTimeout != 0 || query.Search.Regex != "" && (query.Search.RegexTimeout <= 0 || query.Search.RegexTimeout > MaximumRegexDuration) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type Actor struct {
	SubjectID  string
	TenantID   string
	SessionID  string
	AuthzEpoch uint64
}

func (actor Actor) valid() bool {
	return opaquePattern.MatchString(actor.SubjectID) && opaquePattern.MatchString(actor.SessionID) && actor.AuthzEpoch > 0 && (actor.TenantID == "" || opaquePattern.MatchString(actor.TenantID))
}

type ReadAuthorizer interface {
	AuthorizeLogRead(context.Context, Actor, Source, Query) error
}

type Redactor interface {
	RedactLogRecord(context.Context, Source, []byte) (redacted []byte, changed bool, err error)
}

type TimestampExtractor interface {
	Timestamp(context.Context, Source, []byte) (time.Time, error)
}

type ConditionCode string

const (
	ConditionMissing       ConditionCode = "source_missing"
	ConditionRotatedGap    ConditionCode = "rotated_gap"
	ConditionTruncated     ConditionCode = "bounded_truncation"
	ConditionSearchTimeout ConditionCode = "search_timeout"
)

type StreamCondition struct {
	Code       ConditionCode
	SourceID   SourceID
	Generation uint64
	At         time.Time
}

type LogRecord struct {
	SourceID   SourceID
	Generation uint64
	Sequence   uint64
	Offset     int64
	ObservedAt time.Time
	Text       []byte
	Redacted   bool
}

type ProjectionSummary struct {
	SourceID   SourceID
	Generation uint64
	Lines      uint32
	Bytes      int64
	NextCursor string
	Truncated  bool
}

type RecordSink interface {
	WriteRecord(context.Context, LogRecord) error
	WriteCondition(context.Context, StreamCondition) error
	Close(context.Context, ProjectionSummary) error
}

type Reader interface {
	Stream(context.Context, Actor, Query, RecordSink) (ProjectionSummary, error)
}

func literalMatch(value, literal string, caseSensitive bool) bool {
	if caseSensitive {
		return strings.Contains(value, literal)
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(literal))
}
