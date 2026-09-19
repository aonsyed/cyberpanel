// Package artifactguard protects product logs and support artifacts throughout
// redaction, encrypted storage, retention, and audience-bound download.
package artifactguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid          = errors.New("artifactguard: invalid value")
	ErrNotFound         = errors.New("artifactguard: not found")
	ErrConflict         = errors.New("artifactguard: conflict")
	ErrStaleGeneration  = errors.New("artifactguard: stale generation")
	ErrUnauthorized     = errors.New("artifactguard: unauthorized")
	ErrStepUpRequired   = errors.New("artifactguard: step-up required")
	ErrLegalHold        = errors.New("artifactguard: legal hold prevents operation")
	ErrRetentionActive  = errors.New("artifactguard: retention prevents operation")
	ErrIntegrity        = errors.New("artifactguard: integrity verification failed")
	ErrTruncated        = errors.New("artifactguard: bounded input was truncated")
	ErrLimit            = errors.New("artifactguard: configured limit exceeded")
	ErrExpired          = errors.New("artifactguard: grant expired")
	ErrConsumed         = errors.New("artifactguard: grant already consumed")
	ErrAmbiguous        = errors.New("artifactguard: operation outcome is ambiguous")
	ErrUnsupportedState = errors.New("artifactguard: unsupported state transition")
)

type TenantID string
type NodeID string
type ArtifactID string
type ObjectID string
type PrincipalID string
type GrantID string
type HoldID string
type ReceiptID string

type Purpose string

const (
	PurposeProductLog        Purpose = "product_log"
	PurposeSupportBundle     Purpose = "support_bundle"
	PurposeDiagnostic       Purpose = "diagnostic"
	PurposeSecurityEvidence Purpose = "security_evidence"
	PurposeOperationEvidence Purpose = "operation_evidence"
)

func (v Purpose) valid() bool {
	switch v {
	case PurposeProductLog, PurposeSupportBundle, PurposeDiagnostic,
		PurposeSecurityEvidence, PurposeOperationEvidence:
		return true
	default:
		return false
	}
}

type DataClass string

const (
	DataClassOperational       DataClass = "operational"
	DataClassConfidential      DataClass = "confidential"
	DataClassSecuritySensitive DataClass = "security_sensitive"
	DataClassRegulated         DataClass = "regulated"
)

func (v DataClass) valid() bool {
	switch v {
	case DataClassOperational, DataClassConfidential, DataClassSecuritySensitive, DataClassRegulated:
		return true
	default:
		return false
	}
}

type SourceKind string

const (
	SourceProductService    SourceKind = "product_service"
	SourceNodeAgent         SourceKind = "node_agent"
	SourceSupportSession    SourceKind = "support_session"
	SourceOperatorUpload    SourceKind = "operator_upload"
	SourceSecurityCollector SourceKind = "security_collector"
)

func (v SourceKind) valid() bool {
	switch v {
	case SourceProductService, SourceNodeAgent, SourceSupportSession,
		SourceOperatorUpload, SourceSecurityCollector:
		return true
	default:
		return false
	}
}

type RetentionClass string

const (
	RetentionTransient RetentionClass = "transient"
	RetentionStandard  RetentionClass = "standard"
	RetentionExtended  RetentionClass = "extended"
	RetentionEvidence  RetentionClass = "evidence"
)

func (v RetentionClass) valid() bool {
	switch v {
	case RetentionTransient, RetentionStandard, RetentionExtended, RetentionEvidence:
		return true
	default:
		return false
	}
}

type RetentionState string

const (
	RetentionStateActive  RetentionState = "active"
	RetentionStateExpired RetentionState = "expired"
	RetentionStateHeld    RetentionState = "held"
)

func (v RetentionState) valid() bool {
	switch v {
	case RetentionStateActive, RetentionStateExpired, RetentionStateHeld:
		return true
	default:
		return false
	}
}

type IntegrityState string

const (
	IntegrityPending     IntegrityState = "pending"
	IntegrityVerified    IntegrityState = "verified"
	IntegrityFailed      IntegrityState = "failed"
	IntegrityQuarantined IntegrityState = "quarantined"
)

func (v IntegrityState) valid() bool {
	switch v {
	case IntegrityPending, IntegrityVerified, IntegrityFailed, IntegrityQuarantined:
		return true
	default:
		return false
	}
}

type LifecycleState string

const (
	LifecycleStaging   LifecycleState = "staging"
	LifecycleAvailable LifecycleState = "available"
	LifecycleDeleting  LifecycleState = "deleting"
	LifecycleDeleted   LifecycleState = "deleted"
	LifecycleAmbiguous LifecycleState = "ambiguous"
)

func (v LifecycleState) valid() bool {
	switch v {
	case LifecycleStaging, LifecycleAvailable, LifecycleDeleting, LifecycleDeleted, LifecycleAmbiguous:
		return true
	default:
		return false
	}
}

type FindingCode string

const (
	FindingStructuredSecretKey FindingCode = "structured_secret_key"
	FindingCredential          FindingCode = "credential_assignment"
	FindingPrivateKey          FindingCode = "private_key"
	FindingJWT                 FindingCode = "jwt"
	FindingCookie              FindingCode = "cookie"
	FindingURLUserInfo         FindingCode = "url_userinfo"
	FindingLineTooLong         FindingCode = "line_too_long"
	FindingTokenTooLong        FindingCode = "token_too_long"
	FindingStructuredLimit     FindingCode = "structured_limit"
	FindingInputTruncated      FindingCode = "input_truncated"
	FindingFindingLimit        FindingCode = "finding_limit"
)

func (v FindingCode) valid() bool {
	switch v {
	case FindingStructuredSecretKey, FindingCredential, FindingPrivateKey, FindingJWT,
		FindingCookie, FindingURLUserInfo, FindingLineTooLong, FindingTokenTooLong,
		FindingStructuredLimit, FindingInputTruncated, FindingFindingLimit:
		return true
	default:
		return false
	}
}

type FindingCount struct {
	Code  FindingCode `json:"code"`
	Count uint64      `json:"count"`
}

type RedactionManifest struct {
	ScannerVersion string         `json:"scanner_version"`
	InputDigest    string         `json:"input_digest"`
	OutputDigest   string         `json:"output_digest"`
	InputBytes     int64          `json:"input_bytes"`
	OutputBytes    int64          `json:"output_bytes"`
	Lines          uint64         `json:"lines"`
	Findings       []FindingCount `json:"findings"`
	Truncated      bool           `json:"truncated"`
	CompletedAt    time.Time      `json:"completed_at"`
}

func (m RedactionManifest) Validate() error {
	if !validLocalID(m.ScannerVersion) || !validDigest(m.InputDigest) ||
		!validDigest(m.OutputDigest) || m.InputBytes < 0 || m.OutputBytes < 0 ||
		m.CompletedAt.IsZero() {
		return fmt.Errorf("%w: redaction manifest", ErrInvalid)
	}
	last := ""
	for _, finding := range m.Findings {
		if !finding.Code.valid() || finding.Count == 0 || string(finding.Code) <= last {
			return fmt.Errorf("%w: redaction finding counts", ErrInvalid)
		}
		last = string(finding.Code)
	}
	return nil
}

type ArtifactSource struct {
	Kind       SourceKind `json:"kind"`
	ID         string     `json:"id"`
	Generation uint64     `json:"generation"`
}

type Retention struct {
	Class       RetentionClass `json:"class"`
	State       RetentionState `json:"state"`
	RetainUntil time.Time      `json:"retain_until"`
	LegalHoldID HoldID         `json:"legal_hold_id,omitempty"`
}

type EncryptionDescriptor struct {
	Algorithm    string `json:"algorithm"`
	KeyReference string `json:"key_reference"`
	KeyVersion   uint64 `json:"key_version"`
	ChunkBytes   uint32 `json:"chunk_bytes"`
}

type Artifact struct {
	ID               ArtifactID           `json:"id"`
	TenantID         TenantID             `json:"tenant_id"`
	NodeID           NodeID               `json:"node_id"`
	ObjectID         ObjectID             `json:"object_id"`
	ObjectGeneration uint64               `json:"object_generation"`
	ObjectDigest     string               `json:"object_digest,omitempty"`
	Purpose          Purpose              `json:"purpose"`
	DataClass        DataClass            `json:"data_class"`
	Source           ArtifactSource       `json:"source"`
	ContentDigest    string               `json:"content_digest"`
	ContentSize      int64                `json:"content_size"`
	Encryption       EncryptionDescriptor `json:"encryption"`
	Redaction        RedactionManifest    `json:"redaction"`
	Retention        Retention            `json:"retention"`
	Integrity        IntegrityState       `json:"integrity"`
	Lifecycle        LifecycleState       `json:"lifecycle"`
	Generation       uint64               `json:"generation"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
	Digest           string               `json:"digest"`
}

func (a Artifact) Validate() error {
	if !validLocalID(string(a.ID)) || !validLocalID(string(a.TenantID)) ||
		!validLocalID(string(a.NodeID)) || !validLocalID(string(a.ObjectID)) ||
		!a.Purpose.valid() || !a.DataClass.valid() || !a.Source.Kind.valid() ||
		!validLocalID(a.Source.ID) || a.Source.Generation == 0 ||
		!a.Retention.Class.valid() || !a.Retention.State.valid() ||
		!a.Integrity.valid() || !a.Lifecycle.valid() || a.Generation == 0 ||
		a.CreatedAt.IsZero() || a.UpdatedAt.Before(a.CreatedAt) {
		return fmt.Errorf("%w: artifact metadata", ErrInvalid)
	}
	if a.Retention.RetainUntil.IsZero() {
		return fmt.Errorf("%w: retention deadline", ErrInvalid)
	}
	if a.Retention.State == RetentionStateHeld {
		if !validLocalID(string(a.Retention.LegalHoldID)) {
			return fmt.Errorf("%w: held artifact without hold", ErrInvalid)
		}
	} else if a.Retention.LegalHoldID != "" {
		return fmt.Errorf("%w: hold identifier on unheld artifact", ErrInvalid)
	}
	if a.Encryption.Algorithm != "AES-256-GCM-CHUNKED" ||
		!validLocalID(a.Encryption.KeyReference) || a.Encryption.KeyVersion == 0 ||
		a.Encryption.ChunkBytes < MinimumChunkBytes || a.Encryption.ChunkBytes > MaximumChunkBytes {
		return fmt.Errorf("%w: encryption descriptor", ErrInvalid)
	}
	if a.Lifecycle != LifecycleStaging {
		if a.ContentSize < 0 || !validDigest(a.ContentDigest) ||
			a.ObjectGeneration == 0 || !validDigest(a.ObjectDigest) {
			return fmt.Errorf("%w: finalized artifact content", ErrInvalid)
		}
		if err := a.Redaction.Validate(); err != nil {
			return err
		}
		if a.Redaction.Truncated || a.Redaction.OutputDigest != a.ContentDigest ||
			a.Redaction.OutputBytes != a.ContentSize {
			return fmt.Errorf("%w: incomplete redaction", ErrInvalid)
		}
	}
	if a.Lifecycle == LifecycleAvailable && a.Integrity != IntegrityVerified {
		return fmt.Errorf("%w: available artifact is not verified", ErrInvalid)
	}
	if a.Digest != "" {
		digest, err := artifactDigest(a)
		if err != nil || digest != a.Digest {
			return fmt.Errorf("%w: artifact digest", ErrIntegrity)
		}
	}
	return nil
}

func SealArtifact(a Artifact) (Artifact, error) {
	a.CreatedAt = canonicalTime(a.CreatedAt)
	a.UpdatedAt = canonicalTime(a.UpdatedAt)
	a.Retention.RetainUntil = canonicalTime(a.Retention.RetainUntil)
	a.Redaction.CompletedAt = canonicalTime(a.Redaction.CompletedAt)
	a.Digest = ""
	if err := a.Validate(); err != nil {
		return Artifact{}, err
	}
	digest, err := artifactDigest(a)
	if err != nil {
		return Artifact{}, err
	}
	a.Digest = digest
	return a, nil
}

func artifactDigest(a Artifact) (string, error) {
	a.Digest = ""
	return canonicalDigest(a)
}

func ArtifactTransitionAllowed(from, to LifecycleState) bool {
	switch from {
	case LifecycleStaging:
		return to == LifecycleAvailable || to == LifecycleAmbiguous
	case LifecycleAvailable:
		return to == LifecycleDeleting || to == LifecycleAmbiguous
	case LifecycleDeleting:
		return to == LifecycleDeleted || to == LifecycleAmbiguous
	case LifecycleAmbiguous:
		return to == LifecycleAvailable || to == LifecycleDeleting || to == LifecycleDeleted
	default:
		return false
	}
}

func ArtifactIdentityEqual(a, b Artifact) bool {
	return a.ID == b.ID && a.TenantID == b.TenantID && a.NodeID == b.NodeID &&
		a.ObjectID == b.ObjectID && a.Purpose == b.Purpose && a.DataClass == b.DataClass &&
		a.Source == b.Source && a.Encryption.KeyReference == b.Encryption.KeyReference &&
		a.Encryption.KeyVersion == b.Encryption.KeyVersion &&
		a.Encryption.Algorithm == b.Encryption.Algorithm &&
		a.Encryption.ChunkBytes == b.Encryption.ChunkBytes &&
		a.ContentDigest == b.ContentDigest && a.ContentSize == b.ContentSize &&
		a.Retention.Class == b.Retention.Class &&
		a.Retention.RetainUntil.Equal(b.Retention.RetainUntil) && redactionEqual(a.Redaction, b.Redaction)
}

func redactionEqual(a, b RedactionManifest) bool {
	aDigest, aErr := canonicalDigest(a)
	bDigest, bErr := canonicalDigest(b)
	return aErr == nil && bErr == nil && aDigest == bDigest
}

type HoldState string

const (
	HoldActive   HoldState = "active"
	HoldReleased HoldState = "released"
)

type LegalHold struct {
	ID         HoldID     `json:"id"`
	ArtifactID ArtifactID `json:"artifact_id"`
	TenantID   TenantID   `json:"tenant_id"`
	ReasonCode string     `json:"reason_code"`
	State      HoldState  `json:"state"`
	Generation uint64     `json:"generation"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ReleasedAt time.Time  `json:"released_at,omitempty"`
	Digest     string     `json:"digest"`
}

func SealLegalHold(h LegalHold) (LegalHold, error) {
	if !validLocalID(string(h.ID)) || !validLocalID(string(h.ArtifactID)) ||
		!validLocalID(string(h.TenantID)) || !validReasonCode(h.ReasonCode) ||
		(h.State != HoldActive && h.State != HoldReleased) || h.Generation == 0 ||
		h.CreatedAt.IsZero() || h.UpdatedAt.Before(h.CreatedAt) {
		return LegalHold{}, fmt.Errorf("%w: legal hold", ErrInvalid)
	}
	if h.State == HoldReleased && h.ReleasedAt.IsZero() {
		return LegalHold{}, fmt.Errorf("%w: released hold timestamp", ErrInvalid)
	}
	if h.State == HoldActive && !h.ReleasedAt.IsZero() {
		return LegalHold{}, fmt.Errorf("%w: active hold release timestamp", ErrInvalid)
	}
	h.CreatedAt = canonicalTime(h.CreatedAt)
	h.UpdatedAt = canonicalTime(h.UpdatedAt)
	h.ReleasedAt = canonicalTime(h.ReleasedAt)
	h.Digest = ""
	digest, err := canonicalDigest(h)
	if err != nil {
		return LegalHold{}, err
	}
	h.Digest = digest
	return h, nil
}

type GrantOperation string

const (
	GrantRead   GrantOperation = "read"
	GrantExport GrantOperation = "export"
)

func (v GrantOperation) valid() bool { return v == GrantRead || v == GrantExport }

type GrantState string

const (
	GrantIssued   GrantState = "issued"
	GrantConsumed GrantState = "consumed"
	GrantExpired  GrantState = "expired"
	GrantRevoked  GrantState = "revoked"
)

type DownloadMetadata struct {
	Filename      string `json:"filename"`
	MediaType     string `json:"media_type"`
	ContentLength int64  `json:"content_length"`
	ContentDigest string `json:"content_digest"`
}

func (m DownloadMetadata) Validate() error {
	if !safeFilename(m.Filename) || len(m.MediaType) > 128 || m.ContentLength < 0 ||
		!validDigest(m.ContentDigest) {
		return fmt.Errorf("%w: download metadata", ErrInvalid)
	}
	mediaType, _, err := mime.ParseMediaType(m.MediaType)
	if err != nil || mediaType == "" {
		return fmt.Errorf("%w: media type", ErrInvalid)
	}
	return nil
}

func (m DownloadMetadata) ContentDisposition() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	value := mime.FormatMediaType("attachment", map[string]string{"filename": m.Filename})
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("%w: content disposition", ErrInvalid)
	}
	return value, nil
}

type DownloadGrant struct {
	ID                GrantID          `json:"id"`
	ArtifactID        ArtifactID       `json:"artifact_id"`
	ArtifactDigest    string           `json:"artifact_digest"`
	TenantID          TenantID         `json:"tenant_id"`
	AudiencePrincipal PrincipalID      `json:"audience_principal"`
	Operation         GrantOperation   `json:"operation"`
	Metadata          DownloadMetadata `json:"metadata"`
	OneUse            bool             `json:"one_use"`
	State             GrantState       `json:"state"`
	Generation        uint64           `json:"generation"`
	IssuedAt          time.Time        `json:"issued_at"`
	ExpiresAt         time.Time        `json:"expires_at"`
	ConsumedAt        time.Time        `json:"consumed_at,omitempty"`
	Digest            string           `json:"digest"`
}

func SealDownloadGrant(g DownloadGrant) (DownloadGrant, error) {
	if !validLocalID(string(g.ID)) || !validLocalID(string(g.ArtifactID)) ||
		!validDigest(g.ArtifactDigest) || !validLocalID(string(g.TenantID)) ||
		!validLocalID(string(g.AudiencePrincipal)) || !g.Operation.valid() || !g.OneUse ||
		g.Generation == 0 || g.IssuedAt.IsZero() || !g.ExpiresAt.After(g.IssuedAt) ||
		g.ExpiresAt.Sub(g.IssuedAt) > MaximumGrantLifetime {
		return DownloadGrant{}, fmt.Errorf("%w: download grant", ErrInvalid)
	}
	if err := g.Metadata.Validate(); err != nil {
		return DownloadGrant{}, err
	}
	switch g.State {
	case GrantIssued:
		if !g.ConsumedAt.IsZero() {
			return DownloadGrant{}, fmt.Errorf("%w: issued grant consumption", ErrInvalid)
		}
	case GrantConsumed:
		if g.ConsumedAt.IsZero() || g.ConsumedAt.Before(g.IssuedAt) {
			return DownloadGrant{}, fmt.Errorf("%w: consumed grant timestamp", ErrInvalid)
		}
	case GrantExpired, GrantRevoked:
	default:
		return DownloadGrant{}, fmt.Errorf("%w: grant state", ErrInvalid)
	}
	g.IssuedAt = canonicalTime(g.IssuedAt)
	g.ExpiresAt = canonicalTime(g.ExpiresAt)
	g.ConsumedAt = canonicalTime(g.ConsumedAt)
	g.Digest = ""
	digest, err := canonicalDigest(g)
	if err != nil {
		return DownloadGrant{}, err
	}
	g.Digest = digest
	return g, nil
}

type DeletionStatus string

const (
	DeletionCompleted     DeletionStatus = "deleted"
	DeletionAlreadyAbsent DeletionStatus = "already_absent"
	DeletionAmbiguous     DeletionStatus = "ambiguous"
)

type DeletionReceipt struct {
	ID               ReceiptID      `json:"id"`
	ArtifactID       ArtifactID     `json:"artifact_id"`
	TenantID         TenantID       `json:"tenant_id"`
	ObjectID         ObjectID       `json:"object_id"`
	ArtifactGeneration uint64       `json:"artifact_generation"`
	ObjectGeneration uint64         `json:"object_generation"`
	ObjectDigest     string         `json:"object_digest"`
	Status           DeletionStatus `json:"status"`
	Actor            PrincipalID    `json:"actor"`
	AuditID          string         `json:"audit_id"`
	CompletedAt      time.Time      `json:"completed_at"`
	Digest           string         `json:"digest"`
}

func SealDeletionReceipt(r DeletionReceipt) (DeletionReceipt, error) {
	if !validLocalID(string(r.ID)) || !validLocalID(string(r.ArtifactID)) ||
		!validLocalID(string(r.TenantID)) || !validLocalID(string(r.ObjectID)) ||
		r.ArtifactGeneration == 0 || r.ObjectGeneration == 0 || !validDigest(r.ObjectDigest) ||
		!validLocalID(string(r.Actor)) || !validLocalID(r.AuditID) || r.CompletedAt.IsZero() {
		return DeletionReceipt{}, fmt.Errorf("%w: deletion receipt", ErrInvalid)
	}
	switch r.Status {
	case DeletionCompleted, DeletionAlreadyAbsent, DeletionAmbiguous:
	default:
		return DeletionReceipt{}, fmt.Errorf("%w: deletion status", ErrInvalid)
	}
	r.CompletedAt = canonicalTime(r.CompletedAt)
	r.Digest = ""
	digest, err := canonicalDigest(r)
	if err != nil {
		return DeletionReceipt{}, err
	}
	r.Digest = digest
	return r, nil
}

type Action string

const (
	ActionRead   Action = "artifact.read"
	ActionExport Action = "artifact.export"
	ActionDelete Action = "artifact.delete"
)

type Actor struct {
	TenantID   TenantID    `json:"tenant_id"`
	PrincipalID PrincipalID `json:"principal_id"`
}

type StepUpEvidence struct {
	ID          string      `json:"id"`
	TenantID    TenantID    `json:"tenant_id"`
	PrincipalID PrincipalID `json:"principal_id"`
	Action      Action      `json:"action"`
	ArtifactID  ArtifactID  `json:"artifact_id"`
	ExpiresAt   time.Time   `json:"expires_at"`
	Digest      string      `json:"digest"`
}

type AuditEvent struct {
	ID                 string      `json:"id"`
	TenantID           TenantID    `json:"tenant_id"`
	PrincipalID        PrincipalID `json:"principal_id"`
	ArtifactID         ArtifactID  `json:"artifact_id"`
	ArtifactGeneration uint64      `json:"artifact_generation"`
	ArtifactDigest     string      `json:"artifact_digest"`
	Action             Action      `json:"action"`
	Outcome            string      `json:"outcome"`
	ReasonCode         string      `json:"reason_code"`
	OccurredAt         time.Time   `json:"occurred_at"`
}

const (
	MinimumChunkBytes   = 4 << 10
	MaximumChunkBytes   = 1 << 20
	MaximumGrantLifetime = 15 * time.Minute
)

var (
	localIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	reasonCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

func validLocalID(value string) bool { return localIDPattern.MatchString(value) }

func validReasonCode(value string) bool { return reasonCodePattern.MatchString(value) }

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func canonicalDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: canonical encoding: %v", ErrInvalid, err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Round(0)
}

func sortedFindingCounts(counts map[FindingCode]uint64) []FindingCount {
	codes := make([]string, 0, len(counts))
	for code, count := range counts {
		if count != 0 {
			codes = append(codes, string(code))
		}
	}
	sort.Strings(codes)
	result := make([]FindingCount, 0, len(codes))
	for _, code := range codes {
		result = append(result, FindingCount{Code: FindingCode(code), Count: counts[FindingCode(code)]})
	}
	return result
}

func safeFilename(value string) bool {
	if value == "" || len(value) > 180 || value == "." || value == ".." ||
		strings.HasPrefix(value, ".") || strings.ContainsAny(value, `/\\\r\n"`) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
