package mailtelemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid      = errors.New("mail telemetry: invalid input")
	ErrUnauthorized = errors.New("mail telemetry: unauthorized")
	ErrNotFound     = errors.New("mail telemetry: not found")
	ErrConflict     = errors.New("mail telemetry: revision conflict")
	ErrLimit        = errors.New("mail telemetry: bounded limit exceeded")
	ErrIntegrity    = errors.New("mail telemetry: integrity check failed")
	ErrGap          = errors.New("mail telemetry: source gap")
	ErrProtected    = errors.New("mail telemetry: protected access required")
)

const (
	MaximumPageSize          = 250
	MaximumSearchWindow      = 366 * 24 * time.Hour
	MaximumIngestDuration    = 30 * time.Second
	MaximumIngestLines       = 10_000
	MaximumIngestBytes int64 = 32 << 20
	MaximumRecordBytes       = 256 << 10
	MaximumMetadataItems     = 24
	MaximumMetadataValue     = 512
	MaximumPolicyCategories  = 16
	MaximumCursorBytes       = 4096
	MaximumExportRows        = 100_000
	MaximumExportBytes int64 = 512 << 20
	MaximumRevision   uint64 = 1<<63 - 1
)

var (
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)
	metadataPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

type TenantID string
type DomainID string
type MailboxID string
type PolicyID string
type EventID string
type ExportID string
type SourceID string

func validID(value string) bool { return idPattern.MatchString(value) }

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestParts(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte{0})
		hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type SourceKind string

const (
	SourcePostfix        SourceKind = "postfix"
	SourceDovecot        SourceKind = "dovecot"
	SourceRspamd         SourceKind = "rspamd"
	SourceClamAV         SourceKind = "clamav"
	SourceDKIM           SourceKind = "dkim"
	SourcePolicy         SourceKind = "policy"
	SourceDelivery       SourceKind = "delivery"
	SourceAuthentication SourceKind = "authentication"
)

func (kind SourceKind) Valid() bool {
	switch kind {
	case SourcePostfix, SourceDovecot, SourceRspamd, SourceClamAV, SourceDKIM, SourcePolicy, SourceDelivery, SourceAuthentication:
		return true
	default:
		return false
	}
}

type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
	DirectionInternal Direction = "internal"
	DirectionUnknown  Direction = "unknown"
)

func (direction Direction) Valid() bool {
	return direction == DirectionInbound || direction == DirectionOutbound || direction == DirectionInternal || direction == DirectionUnknown
}

type Category string

const (
	CategoryDelivery  Category = "delivery"
	CategoryRejection Category = "rejection"
	CategoryDeferral  Category = "deferral"
	CategoryBounce    Category = "bounce"
	CategorySpam      Category = "spam"
	CategoryMalware   Category = "malware"
	CategoryQuota     Category = "quota"
	CategoryAuth      Category = "authentication"
	CategoryPolicy    Category = "policy"
	CategorySigning   Category = "signing"
)

func (category Category) Valid() bool {
	switch category {
	case CategoryDelivery, CategoryRejection, CategoryDeferral, CategoryBounce, CategorySpam, CategoryMalware, CategoryQuota, CategoryAuth, CategoryPolicy, CategorySigning:
		return true
	default:
		return false
	}
}

type Result string

const (
	ResultAccepted    Result = "accepted"
	ResultDelivered   Result = "delivered"
	ResultRejected    Result = "rejected"
	ResultDeferred    Result = "deferred"
	ResultBounced     Result = "bounced"
	ResultDetected    Result = "detected"
	ResultClean       Result = "clean"
	ResultQuarantined Result = "quarantined"
	ResultPassed      Result = "passed"
	ResultFailed      Result = "failed"
	ResultUnknown     Result = "unknown"
)

func (result Result) Valid() bool {
	switch result {
	case ResultAccepted, ResultDelivered, ResultRejected, ResultDeferred, ResultBounced, ResultDetected, ResultClean, ResultQuarantined, ResultPassed, ResultFailed, ResultUnknown:
		return true
	default:
		return false
	}
}

type EvidenceClass string

const (
	EvidenceOrdinary        EvidenceClass = "ordinary"
	EvidenceSecurity        EvidenceClass = "security"
	EvidenceAudit           EvidenceClass = "audit"
	EvidenceProviderReceipt EvidenceClass = "provider_receipt"
	EvidenceIncident        EvidenceClass = "incident"
)

func (class EvidenceClass) Valid() bool {
	return class == EvidenceOrdinary || class == EvidenceSecurity || class == EvidenceAudit || class == EvidenceProviderReceipt || class == EvidenceIncident
}

type DataClass string

const (
	DataEnvelope   DataClass = "envelope"
	DataResult     DataClass = "result"
	DataTiming     DataClass = "timing"
	DataQueue      DataClass = "queue"
	DataDiagnostic DataClass = "diagnostic"
	DataProvider   DataClass = "provider"
	DataSecurity   DataClass = "security"
)

func (class DataClass) Valid() bool {
	switch class {
	case DataEnvelope, DataResult, DataTiming, DataQueue, DataDiagnostic, DataProvider, DataSecurity:
		return true
	default:
		return false
	}
}

type IdentityKind string

const (
	IdentityPseudonym    IdentityKind = "pseudonym"
	IdentityProtectedRef IdentityKind = "protected_reference"
)

type AddressIdentity struct {
	Kind  IdentityKind `json:"kind"`
	Value string       `json:"value"`
}

func (identity AddressIdentity) valid() bool {
	return (identity.Kind == IdentityPseudonym && validDigest(identity.Value)) || (identity.Kind == IdentityProtectedRef && validID(identity.Value))
}

type Metadata struct {
	Key   string    `json:"key"`
	Value string    `json:"value"`
	Class DataClass `json:"class"`
}

type Provenance struct {
	Parser          string `json:"parser"`
	ParserVersion   uint16 `json:"parser_version"`
	Provider        string `json:"provider,omitempty"`
	ProviderReceiptDigest string `json:"provider_receipt_digest,omitempty"`
	SignatureDigest string `json:"signature_digest,omitempty"`
	SignatureKeyID  string `json:"signature_key_id,omitempty"`
	RecordDigest    string `json:"record_digest"`
}

func (provenance Provenance) valid() bool {
	if !validID(provenance.Parser) || provenance.ParserVersion == 0 || !validDigest(provenance.RecordDigest) || provenance.Provider != "" && !validID(provenance.Provider) || provenance.ProviderReceiptDigest != "" && !validDigest(provenance.ProviderReceiptDigest) || provenance.SignatureDigest != "" && !validDigest(provenance.SignatureDigest) || provenance.SignatureKeyID != "" && !validID(provenance.SignatureKeyID) {
		return false
	}
	return (provenance.SignatureDigest == "") == (provenance.SignatureKeyID == "")
}

type Event struct {
	ID               EventID           `json:"id"`
	TenantID         TenantID          `json:"tenant_id"`
	DomainID         DomainID          `json:"domain_id,omitempty"`
	MailboxID        MailboxID         `json:"mailbox_id,omitempty"`
	PolicyID         PolicyID          `json:"policy_id,omitempty"`
	PolicyRevision   uint64            `json:"policy_revision,omitempty"`
	RetainUntil      time.Time         `json:"retain_until,omitempty"`
	Source           SourceKind        `json:"source"`
	SourceID         SourceID          `json:"source_id"`
	SourceGeneration uint64            `json:"source_generation"`
	SourceCursor     string            `json:"source_cursor"`
	OccurredAt       time.Time         `json:"occurred_at"`
	ObservedAt       time.Time         `json:"observed_at"`
	Direction        Direction         `json:"direction"`
	Category         Category          `json:"category"`
	Result           Result            `json:"result"`
	Evidence         EvidenceClass     `json:"evidence"`
	QueueIdentity    string            `json:"queue_identity,omitempty"`
	MessageIdentity  string            `json:"message_identity,omitempty"`
	Sender           *AddressIdentity  `json:"sender,omitempty"`
	Recipient        *AddressIdentity  `json:"recipient,omitempty"`
	DiagnosticCode   string            `json:"diagnostic_code,omitempty"`
	DurationMicros   uint64            `json:"duration_micros,omitempty"`
	Bytes            uint64            `json:"bytes,omitempty"`
	Metadata         []Metadata        `json:"metadata,omitempty"`
	Provenance       Provenance        `json:"provenance"`
}

func (event Event) Validate() error {
	if !validID(string(event.ID)) || !validID(string(event.TenantID)) || event.DomainID != "" && !validID(string(event.DomainID)) || event.MailboxID != "" && !validID(string(event.MailboxID)) || !event.Source.Valid() || !validID(string(event.SourceID)) || event.SourceGeneration == 0 || event.SourceGeneration > MaximumRevision || event.SourceCursor == "" || len(event.SourceCursor) > MaximumCursorBytes || event.OccurredAt.IsZero() || event.ObservedAt.Before(event.OccurredAt.Add(-time.Minute)) || !event.Direction.Valid() || !event.Category.Valid() || !event.Result.Valid() || !event.Evidence.Valid() || len(event.Metadata) > MaximumMetadataItems || len(event.DiagnosticCode) > 128 || !event.Provenance.valid() {
		return ErrInvalid
	}
	if event.QueueIdentity != "" && !validDigest(event.QueueIdentity) || event.MessageIdentity != "" && !validDigest(event.MessageIdentity) || event.Sender != nil && !event.Sender.valid() || event.Recipient != nil && !event.Recipient.valid() {
		return ErrInvalid
	}
	if (event.PolicyID == "") != (event.PolicyRevision == 0) || event.PolicyID != "" && !validID(string(event.PolicyID)) || event.PolicyRevision > MaximumRevision || !event.RetainUntil.IsZero() && !event.RetainUntil.After(event.OccurredAt) {
		return ErrInvalid
	}
	if event.Evidence == EvidenceOrdinary && (event.PolicyID == "" || event.RetainUntil.IsZero()) { return ErrInvalid }
	seen := make(map[string]struct{}, len(event.Metadata))
	for _, item := range event.Metadata {
		if !metadataPattern.MatchString(item.Key) || item.Value == "" || len(item.Value) > MaximumMetadataValue || !item.Class.Valid() {
			return ErrInvalid
		}
		if _, exists := seen[item.Key]; exists {
			return ErrConflict
		}
		seen[item.Key] = struct{}{}
	}
	return nil
}

type GapCode string

const (
	GapParse       GapCode = "parse"
	GapRotated     GapCode = "rotated"
	GapTruncated   GapCode = "truncated"
	GapCheckpoint  GapCode = "checkpoint"
	GapCorrelation GapCode = "correlation"
	GapSource      GapCode = "source"
)

func (code GapCode) valid() bool {
	return code == GapParse || code == GapRotated || code == GapTruncated || code == GapCheckpoint || code == GapCorrelation || code == GapSource
}

type ParseGap struct {
	ID               string     `json:"id"`
	TenantID         TenantID   `json:"tenant_id,omitempty"`
	SourceID         SourceID   `json:"source_id"`
	SourceGeneration uint64     `json:"source_generation"`
	SourceCursor     string     `json:"source_cursor,omitempty"`
	Code             GapCode    `json:"code"`
	Count            uint64     `json:"count"`
	FirstAt          time.Time  `json:"first_at"`
	LastAt           time.Time  `json:"last_at"`
	EvidenceDigest   string     `json:"evidence_digest"`
}

func (gap ParseGap) valid() bool {
	return validID(gap.ID) && (gap.TenantID == "" || validID(string(gap.TenantID))) && validID(string(gap.SourceID)) && gap.SourceGeneration > 0 && gap.SourceGeneration <= MaximumRevision && len(gap.SourceCursor) <= MaximumCursorBytes && gap.Code.valid() && gap.Count > 0 && !gap.FirstAt.IsZero() && !gap.LastAt.Before(gap.FirstAt) && validDigest(gap.EvidenceDigest)
}

type RetentionPolicy struct {
	Ordinary      time.Duration `json:"ordinary"`
	Provider      time.Duration `json:"provider"`
	SecurityFloor time.Duration `json:"security_floor"`
	AuditFloor    time.Duration `json:"audit_floor"`
	PurgeHourUTC  uint8         `json:"purge_hour_utc"`
	StorageBytes  int64         `json:"storage_bytes"`
}

type TransferPolicy struct {
	ExportAllowed         bool     `json:"export_allowed"`
	BackupHistory         bool     `json:"backup_history"`
	MigrationHistory      bool     `json:"migration_history"`
	AllowedExportFormats  []string `json:"allowed_export_formats"`
	RequireStepUp         bool     `json:"require_step_up"`
	RequireAudit          bool     `json:"require_audit"`
}

type RedactionPolicy struct {
	PseudonymizeAddresses bool `json:"pseudonymize_addresses"`
	ProtectedAccess       bool `json:"protected_access"`
	IncludeDiagnostics    bool `json:"include_diagnostics"`
}

type EvidenceFloor struct {
	RetainSecurity        bool          `json:"retain_security"`
	RetainAudit           bool          `json:"retain_audit"`
	RetainProviderReceipt bool          `json:"retain_provider_receipt"`
	SecurityRetention     time.Duration `json:"security_retention"`
	AuditRetention        time.Duration `json:"audit_retention"`
}

func (floor EvidenceFloor) valid() bool {
	return floor.RetainSecurity && floor.RetainAudit && floor.RetainProviderReceipt && floor.SecurityRetention >= 24*time.Hour && floor.AuditRetention >= 30*24*time.Hour
}

func (floor EvidenceFloor) atLeast(previous EvidenceFloor) bool {
	return floor.valid() && floor.SecurityRetention >= previous.SecurityRetention && floor.AuditRetention >= previous.AuditRetention
}

type Policy struct {
	ID              PolicyID        `json:"id"`
	TenantID        TenantID        `json:"tenant_id"`
	DomainID        DomainID        `json:"domain_id,omitempty"`
	MailboxID       MailboxID       `json:"mailbox_id,omitempty"`
	Enabled         bool            `json:"enabled"`
	Categories      []Category      `json:"categories"`
	MetadataClasses []DataClass     `json:"metadata_classes"`
	Retention       RetentionPolicy `json:"retention"`
	Transfer        TransferPolicy  `json:"transfer"`
	Redaction       RedactionPolicy `json:"redaction"`
	EvidenceFloor   EvidenceFloor   `json:"evidence_floor"`
	Revision        uint64          `json:"revision"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func DefaultPolicy(id PolicyID, tenant TenantID, domain DomainID, mailbox MailboxID, now time.Time) (Policy, error) {
	policy := Policy{
		ID: id, TenantID: tenant, DomainID: domain, MailboxID: mailbox, Enabled: true,
		Categories: []Category{CategoryAuth, CategoryBounce, CategoryDeferral, CategoryDelivery, CategoryMalware, CategoryPolicy, CategoryQuota, CategoryRejection, CategorySigning, CategorySpam},
		MetadataClasses: []DataClass{DataDiagnostic, DataEnvelope, DataProvider, DataQueue, DataResult, DataSecurity, DataTiming},
		Retention: RetentionPolicy{Ordinary: 30*24*time.Hour, Provider: 180*24*time.Hour, SecurityFloor: 90*24*time.Hour, AuditFloor: 365*24*time.Hour, PurgeHourUTC: 3, StorageBytes: 1 << 30},
		Transfer: TransferPolicy{RequireStepUp: true, RequireAudit: true},
		Redaction: RedactionPolicy{PseudonymizeAddresses: true, IncludeDiagnostics: true},
		EvidenceFloor: EvidenceFloor{RetainSecurity: true, RetainAudit: true, RetainProviderReceipt: true, SecurityRetention: 90*24*time.Hour, AuditRetention: 365*24*time.Hour},
		Revision: 1, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	if policy.Validate() != nil { return Policy{}, ErrInvalid }
	return policy, nil
}

func uniqueSorted[T ~string](values []T, maximum int, valid func(T) bool) bool {
	if len(values) == 0 || len(values) > maximum {
		return false
	}
	for index, value := range values {
		if !valid(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func (policy Policy) Validate() error {
	if !validID(string(policy.ID)) || !validID(string(policy.TenantID)) || policy.DomainID != "" && !validID(string(policy.DomainID)) || policy.MailboxID != "" && !validID(string(policy.MailboxID)) || policy.Revision == 0 || policy.Revision > MaximumRevision || policy.CreatedAt.IsZero() || policy.UpdatedAt.Before(policy.CreatedAt) || !policy.EvidenceFloor.valid() {
		return ErrInvalid
	}
	if !uniqueSorted(policy.Categories, MaximumPolicyCategories, func(value Category) bool { return value.Valid() }) || !uniqueSorted(policy.MetadataClasses, MaximumPolicyCategories, func(value DataClass) bool { return value.Valid() }) {
		return ErrInvalid
	}
	retention := policy.Retention
	if retention.Ordinary < time.Hour || retention.Ordinary > 10*365*24*time.Hour || retention.Provider < retention.Ordinary || retention.SecurityFloor < policy.EvidenceFloor.SecurityRetention || retention.AuditFloor < policy.EvidenceFloor.AuditRetention || retention.PurgeHourUTC > 23 || retention.StorageBytes < 1<<20 || retention.StorageBytes > 1<<50 {
		return ErrInvalid
	}
	if !policy.Redaction.PseudonymizeAddresses || policy.Redaction.ProtectedAccess && !policy.Transfer.RequireStepUp || !policy.Transfer.RequireAudit || len(policy.Transfer.AllowedExportFormats) > 8 {
		return ErrInvalid
	}
	if policy.Transfer.ExportAllowed {
		if !policy.Transfer.RequireStepUp || !uniqueSorted(policy.Transfer.AllowedExportFormats, 8, func(value string) bool { return value == "jsonl-v1" }) {
			return ErrInvalid
		}
	} else if len(policy.Transfer.AllowedExportFormats) != 0 {
		return ErrInvalid
	}
	return nil
}

func (policy Policy) permits(category Category, class DataClass) bool {
	if !policy.Enabled {
		return false
	}
	categoryIndex := sort.Search(len(policy.Categories), func(index int) bool { return policy.Categories[index] >= category })
	classIndex := sort.Search(len(policy.MetadataClasses), func(index int) bool { return policy.MetadataClasses[index] >= class })
	return categoryIndex < len(policy.Categories) && policy.Categories[categoryIndex] == category && classIndex < len(policy.MetadataClasses) && policy.MetadataClasses[classIndex] == class
}

type Actor struct {
	SubjectID  string   `json:"subject_id"`
	TenantID   TenantID `json:"tenant_id"`
	SessionID  string   `json:"session_id"`
	AuthzEpoch uint64   `json:"authz_epoch"`
	StepUpAt   time.Time `json:"step_up_at,omitempty"`
}

func (actor Actor) valid() bool {
	return validID(actor.SubjectID) && validID(string(actor.TenantID)) && validID(actor.SessionID) && actor.AuthzEpoch > 0
}

type Authorizer interface {
	AuthorizePolicy(context.Context, Actor, TenantID, DomainID, MailboxID, bool) error
	AuthorizeTelemetry(context.Context, Actor, TenantID, DomainID, MailboxID, bool) error
	AuthorizeExport(context.Context, Actor, Policy, string) error
}

type AuditRecord struct {
	Action         string
	Actor          Actor
	TenantID       TenantID
	ResourceID     string
	At             time.Time
	RequestDigest  string
	Outcome        string
	EvidenceDigest string
}

type Auditor interface { RecordMailTelemetryAudit(context.Context, AuditRecord) error }

type EventQuery struct {
	TenantID  TenantID
	DomainID  DomainID
	MailboxID MailboxID
	Categories []Category
	Start     time.Time
	End       time.Time
	AfterAt   time.Time
	AfterID   EventID
	Limit     uint16
}

func (query EventQuery) validate(actor Actor) error {
	if !actor.valid() || query.TenantID != actor.TenantID || !validID(string(query.TenantID)) || query.DomainID != "" && !validID(string(query.DomainID)) || query.MailboxID != "" && !validID(string(query.MailboxID)) || query.Start.IsZero() || !query.End.After(query.Start) || query.End.Sub(query.Start) > MaximumSearchWindow || query.Limit == 0 || query.Limit > MaximumPageSize || len(query.Categories) > MaximumPolicyCategories || query.AfterID != "" && (query.AfterAt.IsZero() || !validID(string(query.AfterID))) {
		return ErrInvalid
	}
	for index, category := range query.Categories {
		if !category.Valid() || index > 0 && query.Categories[index-1] >= category {
			return ErrInvalid
		}
	}
	return nil
}

type EventPage struct {
	Events      []Event
	NextAt      time.Time
	NextEventID EventID
	Missing     []ParseGap
}

type Counter struct {
	Count       uint64 `json:"count"`
	Denominator uint64 `json:"denominator"`
}

type Statistics struct {
	TenantID     TenantID  `json:"tenant_id"`
	DomainID     DomainID  `json:"domain_id,omitempty"`
	MailboxID    MailboxID `json:"mailbox_id,omitempty"`
	WindowStart  time.Time `json:"window_start"`
	WindowEnd    time.Time `json:"window_end"`
	Inbound      uint64    `json:"inbound"`
	Outbound     uint64    `json:"outbound"`
	Internal     uint64    `json:"internal"`
	Delivery     Counter   `json:"delivery"`
	Rejection    Counter   `json:"rejection"`
	Deferral     Counter   `json:"deferral"`
	Bounce       Counter   `json:"bounce"`
	Spam         Counter   `json:"spam"`
	Malware      Counter   `json:"malware"`
	Quota        Counter   `json:"quota"`
	Auth         Counter   `json:"authentication"`
	SampledEvents uint64   `json:"sampled_events"`
	Missing       []ParseGap `json:"missing"`
}

type CursorCheckpoint struct {
	SourceID         SourceID  `json:"source_id"`
	SourceGeneration uint64    `json:"source_generation"`
	JournalCursor    string    `json:"journal_cursor,omitempty"`
	FileOffset       int64     `json:"file_offset,omitempty"`
	Device           uint64    `json:"device,omitempty"`
	Inode            uint64    `json:"inode,omitempty"`
	LastRecordDigest string    `json:"last_record_digest"`
	LastOccurredAt   time.Time `json:"last_occurred_at"`
	Revision         uint64    `json:"revision"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (checkpoint CursorCheckpoint) valid() bool {
	journal := checkpoint.JournalCursor != "" && len(checkpoint.JournalCursor) <= MaximumCursorBytes && checkpoint.FileOffset == 0 && checkpoint.Device == 0 && checkpoint.Inode == 0
	file := checkpoint.JournalCursor == "" && checkpoint.FileOffset >= 0 && checkpoint.Device > 0 && checkpoint.Inode > 0
	return validID(string(checkpoint.SourceID)) && checkpoint.SourceGeneration > 0 && checkpoint.SourceGeneration <= MaximumRevision && (journal || file) && validDigest(checkpoint.LastRecordDigest) && !checkpoint.LastOccurredAt.IsZero() && checkpoint.Revision > 0 && checkpoint.Revision <= MaximumRevision && !checkpoint.UpdatedAt.Before(checkpoint.LastOccurredAt)
}
