package emailmarketing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	maxIdentifierBytes = 128
	maxNameBytes       = 256
	maxPurposeBytes    = 512
	maxTagCount        = 64
)

type TenantID string
type ListID string
type SubscriberID string
type TagID string
type ActorID string
type BatchID string

type Lifecycle string

const (
	LifecycleActive   Lifecycle = "active"
	LifecycleArchived Lifecycle = "archived"
	LifecycleDeleted  Lifecycle = "deleted"
)

type AddressIdentity struct {
	Normalized string
	Digest     string
}

// NormalizeAddress deliberately applies one stable policy: ASCII addresses are
// lower-cased, while provider-specific rewrites such as plus stripping are never
// performed. The digest is suitable for equality and tombstones, not recovery.
func NormalizeAddress(value string) (AddressIdentity, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 254 || strings.Count(value, "@") != 1 {
		return AddressIdentity{}, errors.New("emailmarketing: invalid address")
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return AddressIdentity{}, errors.New("emailmarketing: address must be printable ASCII")
		}
	}
	parts := strings.SplitN(strings.ToLower(value), "@", 2)
	local, domain := parts[0], parts[1]
	if len(local) == 0 || len(local) > 64 || len(domain) == 0 || len(domain) > 253 ||
		strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return AddressIdentity{}, errors.New("emailmarketing: invalid address")
	}
	for _, r := range local {
		if !isLocalAddressRune(r) {
			return AddressIdentity{}, errors.New("emailmarketing: invalid local part")
		}
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return AddressIdentity{}, errors.New("emailmarketing: invalid domain")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return AddressIdentity{}, errors.New("emailmarketing: invalid domain")
			}
		}
	}
	normalized := local + "@" + domain
	sum := sha256.Sum256([]byte(normalized))
	return AddressIdentity{Normalized: normalized, Digest: hex.EncodeToString(sum[:])}, nil
}

func isLocalAddressRune(r rune) bool {
	if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
		return true
	}
	return strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", r)
}

type List struct {
	TenantID   TenantID
	ID         ListID
	Name       string
	Purpose    string
	Lifecycle  Lifecycle
	Generation uint64
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ArchivedAt *time.Time
}

type Tag struct {
	TenantID   TenantID
	ID         TagID
	Name       string
	Lifecycle  Lifecycle
	Generation uint64
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ArchivedAt *time.Time
}

type VerificationProvenance string

const (
	VerificationUnverified  VerificationProvenance = "unverified"
	VerificationSelfAsserted VerificationProvenance = "self_asserted"
	VerificationDoubleOptIn VerificationProvenance = "double_opt_in"
	VerificationProvider    VerificationProvenance = "provider"
	VerificationMigrated    VerificationProvenance = "migrated"
)

type EvidenceCertainty string

const (
	CertaintyExact    EvidenceCertainty = "exact"
	CertaintyInferred EvidenceCertainty = "inferred"
	CertaintyUnknown  EvidenceCertainty = "unknown"
)

type Verification struct {
	Provenance    VerificationProvenance
	Certainty     EvidenceCertainty
	VerifiedAt    *time.Time
	EvidenceDigest string
	ProviderRef   string
}

type Subscriber struct {
	TenantID     TenantID
	ID           SubscriberID
	Address      AddressIdentity
	Verification Verification
	TagIDs       []TagID
	Lifecycle    Lifecycle
	Generation   uint64
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ArchivedAt   *time.Time
	DeleteAfter  *time.Time
}

type MembershipStatus string

const (
	MembershipSubscribed   MembershipStatus = "subscribed"
	MembershipUnsubscribed MembershipStatus = "unsubscribed"
	MembershipArchived     MembershipStatus = "archived"
)

type Membership struct {
	TenantID    TenantID
	ListID      ListID
	SubscriberID SubscriberID
	Status      MembershipStatus
	Generation  uint64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ConsentSource string

const (
	ConsentWebForm   ConsentSource = "web_form"
	ConsentDoubleOpt ConsentSource = "double_opt_in"
	ConsentAdmin     ConsentSource = "admin"
	ConsentCSV       ConsentSource = "csv_import"
	ConsentAPI       ConsentSource = "api"
	ConsentProvider  ConsentSource = "provider_attestation"
	ConsentMigrated  ConsentSource = "migrated"
)

type ConsentRecord struct {
	ID             string
	TenantID       TenantID
	ListID         ListID
	SubscriberID   SubscriberID
	Source         ConsentSource
	Purpose        string
	Affirmative    bool
	CapturedAt     time.Time
	RecordedAt     time.Time
	EvidenceDigest string
	EvidenceRef    string
	Verification   Verification
	ActorID        ActorID
}

type SuppressionScope string

const (
	SuppressionGlobal SuppressionScope = "global"
	SuppressionTenant SuppressionScope = "tenant"
)

type SuppressionReason string

const (
	SuppressionUnsubscribe SuppressionReason = "unsubscribe"
	SuppressionComplaint   SuppressionReason = "complaint"
	SuppressionHardBounce  SuppressionReason = "hard_bounce"
	SuppressionPolicy      SuppressionReason = "policy"
	SuppressionManual      SuppressionReason = "manual"
)

type SuppressionAction string

const (
	SuppressionAdded    SuppressionAction = "added"
	SuppressionReleased SuppressionAction = "released"
)

type SuppressionRecord struct {
	ID               string
	Scope            SuppressionScope
	TenantID         TenantID
	ListID           ListID
	SubscriberID     SubscriberID
	AddressDigest    string
	Reason           SuppressionReason
	Action           SuppressionAction
	OccurredAt       time.Time
	EvidenceDigest   string
	ActorID          ActorID
	PriorRecordID    string
	ConsentRecordID  string
}

type ResubscribeProof struct {
	Consent            ConsentRecord
	StepUpReceipt      string
	AdjudicationDigest string
	ProviderClearance  string
}

// ValidateResubscribe is intentionally conservative. It requires fresh,
// affirmative, exact evidence and additional adjudication for high-risk causes.
func ValidateResubscribe(suppression SuppressionRecord, proof ResubscribeProof) error {
	consent := proof.Consent
	if suppression.Action != SuppressionAdded || (suppression.Scope == SuppressionTenant && consent.TenantID != suppression.TenantID) ||
		consent.SubscriberID != suppression.SubscriberID || !consent.Affirmative ||
		!consent.CapturedAt.After(suppression.OccurredAt) || consent.EvidenceDigest == "" ||
		consent.Verification.Certainty != CertaintyExact {
		return errors.New("emailmarketing: fresh exact affirmative consent required")
	}
	switch suppression.Reason {
	case SuppressionUnsubscribe:
		if consent.Verification.Provenance != VerificationDoubleOptIn {
			return errors.New("emailmarketing: double opt-in required after unsubscribe")
		}
	case SuppressionManual:
		if proof.StepUpReceipt == "" {
			return errors.New("emailmarketing: step-up required for manual suppression release")
		}
	case SuppressionHardBounce:
		if proof.StepUpReceipt == "" || proof.ProviderClearance == "" {
			return errors.New("emailmarketing: provider clearance required after hard bounce")
		}
	case SuppressionComplaint, SuppressionPolicy:
		if proof.StepUpReceipt == "" || proof.AdjudicationDigest == "" {
			return errors.New("emailmarketing: explicit policy adjudication required")
		}
	default:
		return errors.New("emailmarketing: unknown suppression reason")
	}
	return nil
}

type RetentionPolicy struct {
	ConsentRetainUntil    time.Time
	SuppressionRetainUntil time.Time
	TombstoneRetainUntil  time.Time
	EraseAddressAfter     time.Time
	LegalHold             bool
}

type Tombstone struct {
	TenantID      TenantID
	SubscriberID  SubscriberID
	AddressDigest string
	ErasedAt      time.Time
	RetainUntil   time.Time
	Reason        string
}

func DigestEvidence(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizeTags(tags []TagID) ([]TagID, error) {
	if len(tags) > maxTagCount {
		return nil, errors.New("emailmarketing: too many tags")
	}
	seen := make(map[TagID]struct{}, len(tags))
	result := make([]TagID, 0, len(tags))
	for _, id := range tags {
		if err := validateIdentifier(string(id)); err != nil {
			return nil, fmt.Errorf("emailmarketing: invalid tag: %w", err)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func validateIdentifier(value string) error {
	if value == "" || len(value) > maxIdentifierBytes {
		return errors.New("identifier length is invalid")
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') &&
			r != '-' && r != '_' && r != '.' && r != ':' {
			return errors.New("identifier contains a forbidden character")
		}
	}
	return nil
}

func validateLifecycle(value Lifecycle) error {
	switch value {
	case LifecycleActive, LifecycleArchived, LifecycleDeleted:
		return nil
	default:
		return errors.New("emailmarketing: invalid lifecycle")
	}
}
