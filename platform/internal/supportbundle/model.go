package supportbundle

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid   = errors.New("support bundle: invalid value")
	ErrLimit     = errors.New("support bundle: limit exceeded")
	ErrSecret    = errors.New("support bundle: secret detected")
	ErrIntegrity = errors.New("support bundle: integrity failure")
	ErrConflict  = errors.New("support bundle: artifact conflict")
)

const (
	SchemaVersion = "cyberpanel.support-bundle.v1"

	DefaultMaximumEntries           = 8
	DefaultMaximumEntryBytes        = 1 << 20
	DefaultMaximumUncompressedBytes = 6 << 20
	DefaultMaximumCompressedBytes   = 3 << 20
	DefaultMaximumRecords           = 5000
	DefaultMaximumDuration          = 30 * time.Second
	DefaultExpiry                   = 24 * time.Hour

	AbsoluteMaximumEntries           = 32
	AbsoluteMaximumEntryBytes        = 4 << 20
	AbsoluteMaximumUncompressedBytes = 24 << 20
	AbsoluteMaximumCompressedBytes   = 12 << 20
	AbsoluteMaximumRecords           = 20000
	AbsoluteMaximumDuration          = 2 * time.Minute
	AbsoluteMaximumExpiry            = 7 * 24 * time.Hour
	MaximumRecordFieldBytes          = 16 << 10
	MaximumFingerprintCount          = 2048
	MaximumFingerprintBytes          = 256 << 10
)

type Limits struct {
	MaximumEntries           uint16        `json:"maximum_entries"`
	MaximumEntryBytes        int64         `json:"maximum_entry_bytes"`
	MaximumUncompressedBytes int64         `json:"maximum_uncompressed_bytes"`
	MaximumCompressedBytes   int64         `json:"maximum_compressed_bytes"`
	MaximumRecords           uint32        `json:"maximum_records"`
	MaximumDuration          time.Duration `json:"maximum_duration"`
}

func DefaultLimits() Limits {
	return Limits{
		MaximumEntries: DefaultMaximumEntries, MaximumEntryBytes: DefaultMaximumEntryBytes,
		MaximumUncompressedBytes: DefaultMaximumUncompressedBytes, MaximumCompressedBytes: DefaultMaximumCompressedBytes,
		MaximumRecords: DefaultMaximumRecords, MaximumDuration: DefaultMaximumDuration,
	}
}

func (limits Limits) normalized() (Limits, error) {
	defaults := DefaultLimits()
	if limits.MaximumEntries == 0 {
		limits.MaximumEntries = defaults.MaximumEntries
	}
	if limits.MaximumEntryBytes == 0 {
		limits.MaximumEntryBytes = defaults.MaximumEntryBytes
	}
	if limits.MaximumUncompressedBytes == 0 {
		limits.MaximumUncompressedBytes = defaults.MaximumUncompressedBytes
	}
	if limits.MaximumCompressedBytes == 0 {
		limits.MaximumCompressedBytes = defaults.MaximumCompressedBytes
	}
	if limits.MaximumRecords == 0 {
		limits.MaximumRecords = defaults.MaximumRecords
	}
	if limits.MaximumDuration == 0 {
		limits.MaximumDuration = defaults.MaximumDuration
	}
	if limits.MaximumEntries < 2 || limits.MaximumEntries > AbsoluteMaximumEntries || limits.MaximumEntryBytes < 1024 || limits.MaximumEntryBytes > AbsoluteMaximumEntryBytes || limits.MaximumUncompressedBytes < limits.MaximumEntryBytes || limits.MaximumUncompressedBytes > AbsoluteMaximumUncompressedBytes || limits.MaximumCompressedBytes < 1024 || limits.MaximumCompressedBytes > AbsoluteMaximumCompressedBytes || limits.MaximumRecords == 0 || limits.MaximumRecords > AbsoluteMaximumRecords || limits.MaximumDuration <= 0 || limits.MaximumDuration > AbsoluteMaximumDuration {
		return Limits{}, ErrLimit
	}
	return limits, nil
}

type ScopeKind string

const (
	ScopeInstallation ScopeKind = "installation"
	ScopeTenant       ScopeKind = "tenant"
	ScopeSite         ScopeKind = "site"
)

type Scope struct {
	Kind ScopeKind `json:"kind"`
	ID   string    `json:"id,omitempty"`
}

var opaquePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

func (scope Scope) Validate() error {
	switch scope.Kind {
	case ScopeInstallation:
		if scope.ID != "" {
			return ErrInvalid
		}
	case ScopeTenant, ScopeSite:
		if !opaquePattern.MatchString(scope.ID) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type CollectionRequest struct {
	Scopes         []Scope
	MaximumRecords uint32
	Deadline       time.Time
}

type VersionRecord struct {
	Component     string    `json:"component"`
	Version       string    `json:"version"`
	Build         string    `json:"build,omitempty"`
	Compatibility string    `json:"compatibility,omitempty"`
	ObservedAt    time.Time `json:"observed_at"`
}

type FunctionalHealthRecord struct {
	Component  string    `json:"component"`
	Check      string    `json:"check"`
	Status     string    `json:"status"`
	ReasonCode string    `json:"reason_code,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type ValidationFinding struct {
	Code         string    `json:"code"`
	Severity     string    `json:"severity"`
	Scope        string    `json:"scope"`
	ResourceKind string    `json:"resource_kind,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
	Summary      string    `json:"summary"`
	ObservedAt   time.Time `json:"observed_at"`
}

type FailedOperationReceipt struct {
	OperationID   string    `json:"operation_id"`
	OperationKind string    `json:"operation_kind"`
	ResourceKind  string    `json:"resource_kind,omitempty"`
	ResourceID    string    `json:"resource_id,omitempty"`
	FailureCode   string    `json:"failure_code"`
	ReceiptDigest string    `json:"receipt_digest,omitempty"`
	FailedAt      time.Time `json:"failed_at"`
}

type ResourceCondition struct {
	ResourceKind string    `json:"resource_kind"`
	ResourceID   string    `json:"resource_id"`
	Type         string    `json:"type"`
	Status       string    `json:"status"`
	ReasonCode   string    `json:"reason_code,omitempty"`
	Summary      string    `json:"summary,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}

type AuditContinuityStatus struct {
	Continuous          bool      `json:"continuous"`
	VerifiedThrough     uint64    `json:"verified_through"`
	HeadDigest          string    `json:"head_digest"`
	CheckpointReference string    `json:"checkpoint_reference"`
	CheckpointDigest    string    `json:"checkpoint_digest"`
	CheckpointKeyID     string    `json:"checkpoint_key_id"`
	CheckedAt           time.Time `json:"checked_at"`
}

type VersionCollector interface {
	CollectVersions(context.Context, CollectionRequest) ([]VersionRecord, error)
}

type FunctionalHealthCollector interface {
	CollectFunctionalHealth(context.Context, CollectionRequest) ([]FunctionalHealthRecord, error)
}

type ValidationFindingCollector interface {
	CollectValidationFindings(context.Context, CollectionRequest) ([]ValidationFinding, error)
}

type FailedOperationReceiptCollector interface {
	CollectRecentFailedOperationReceipts(context.Context, CollectionRequest) ([]FailedOperationReceipt, error)
}

type ResourceConditionCollector interface {
	CollectResourceConditions(context.Context, CollectionRequest) ([]ResourceCondition, error)
}

type AuditContinuityCollector interface {
	CollectAuditContinuity(context.Context, CollectionRequest) (AuditContinuityStatus, error)
}

type Collectors struct {
	Versions          VersionCollector
	FunctionalHealth  FunctionalHealthCollector
	Validation        ValidationFindingCollector
	FailedOperations  FailedOperationReceiptCollector
	ResourceConditions ResourceConditionCollector
	AuditContinuity   AuditContinuityCollector
}

type SecretFingerprint struct {
	ID          string
	Fingerprint string
}

type SecretFingerprintSource interface {
	SupportBundleSecretFingerprints(context.Context) ([]SecretFingerprint, error)
}

type Signature struct {
	KeyID string `json:"key_id"`
	Value string `json:"value"`
}

type Signer interface {
	SignSupportBundle(context.Context, string, []byte) (Signature, error)
}

type BuildRequest struct {
	Scopes    []Scope
	Limits    Limits
	ExpiresIn time.Duration
}

type Omission struct {
	Entry  string `json:"entry"`
	Reason string `json:"reason"`
}

type Truncation struct {
	Entry    string `json:"entry"`
	Included uint32 `json:"included"`
	Omitted  uint32 `json:"omitted"`
	Reason   string `json:"reason"`
}

type EntryMetadata struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
	Records uint32 `json:"records"`
}

type Manifest struct {
	Schema                   string          `json:"schema"`
	Scopes                   []Scope         `json:"scopes"`
	Omissions                []Omission      `json:"omissions"`
	Truncations              []Truncation    `json:"truncations"`
	Entries                  []EntryMetadata `json:"entries"`
	AuditCheckpointReference string          `json:"audit_checkpoint_reference,omitempty"`
	AuditCheckpointDigest    string          `json:"audit_checkpoint_digest,omitempty"`
	AuditContinuityVerified  bool            `json:"audit_continuity_verified"`
	BundleDigest             string          `json:"bundle_digest"`
	CreatedAt                time.Time       `json:"created_at"`
	ExpiresAt                time.Time       `json:"expires_at"`
	SignerKeyID              string          `json:"signer_key_id"`
	Signature                string          `json:"signature"`
}

type Bundle struct {
	Manifest      Manifest
	Content       []byte
	ArchiveSHA256 string
}

type ArtifactID string

func (id ArtifactID) Validate() error {
	if !strings.HasPrefix(string(id), "sb_") || len(id) != 51 || !opaquePattern.MatchString(string(id)) {
		return ErrInvalid
	}
	return nil
}

type ArtifactReceipt struct {
	ID            ArtifactID `json:"id"`
	ArchiveSHA256 string     `json:"archive_sha256"`
	BundleDigest  string     `json:"bundle_digest"`
	Bytes         int64      `json:"bytes"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
}

type ArtifactStore interface {
	StoreSupportBundle(context.Context, Bundle) (ArtifactReceipt, error)
}

func normalizeScopes(scopes []Scope) ([]Scope, error) {
	if len(scopes) == 0 || len(scopes) > 128 {
		return nil, ErrInvalid
	}
	values := append([]Scope(nil), scopes...)
	for _, scope := range values {
		if err := scope.Validate(); err != nil {
			return nil, err
		}
	}
	sort.Slice(values, func(left, right int) bool {
		if values[left].Kind != values[right].Kind {
			return values[left].Kind < values[right].Kind
		}
		return values[left].ID < values[right].ID
	})
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return nil, fmt.Errorf("%w: duplicate scope", ErrInvalid)
		}
	}
	return values, nil
}

func boundedFields(values ...string) bool {
	for _, value := range values {
		if len(value) > MaximumRecordFieldBytes || strings.IndexByte(value, 0) >= 0 {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
