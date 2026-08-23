package webmaildata

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"

	maildata "github.com/aonsyed/cyberpanel/platform/internal/mail"
)

var (
	ErrInvalid      = errors.New("webmail data: invalid input")
	ErrUnauthorized = errors.New("webmail data: unauthorized")
	ErrStepUp       = errors.New("webmail data: step-up required")
	ErrNotFound     = errors.New("webmail data: not found")
	ErrConflict     = errors.New("webmail data: revision conflict")
	ErrLimit        = errors.New("webmail data: limit exceeded")
	ErrDuplicate    = errors.New("webmail data: duplicate contact")
	ErrRetained     = errors.New("webmail data: retained tombstone")
	ErrIntegrity    = errors.New("webmail data: integrity failure")
	ErrActivation   = errors.New("webmail data: sieve activation failed")
)

const (
	MaximumRevision            = uint64(1<<63 - 1)
	MaximumPageSize            = 250
	MaximumContactAddresses    = 32
	MaximumContactPhones       = 32
	MaximumContactMetadata     = 64
	MaximumGroupsPerMailbox    = 500
	MaximumGroupMembers        = 2_000
	MaximumDistributionTargets = 500
	MaximumIdentities          = 32
	MaximumSignatureBytes      = 64 << 10
	MaximumSieveRules          = 256
	MaximumSieveConditions     = 32
	MaximumSieveActions        = 16
	MaximumSieveRedirects      = 5
	MaximumSieveTextBytes      = 256 << 10
	MaximumBackupObjects       = 100_000
	MaximumBackupBytes         = int64(512 << 20)
)

var (
	opaquePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	phonePattern    = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	metadataPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

type Scope struct {
	TenantID  string `json:"tenant_id"`
	UserID    string `json:"user_id"`
	MailboxID string `json:"mailbox_id"`
}

func (scope Scope) Valid() bool {
	return opaquePattern.MatchString(scope.TenantID) && opaquePattern.MatchString(scope.UserID) && opaquePattern.MatchString(scope.MailboxID)
}

type Lifecycle string

const (
	LifecycleActive  Lifecycle = "active"
	LifecycleDeleted Lifecycle = "deleted"
)

type ProvenanceKind string

const (
	ProvenanceManual   ProvenanceKind = "manual"
	ProvenanceCSV      ProvenanceKind = "csv"
	ProvenanceVCard    ProvenanceKind = "vcard"
	ProvenanceMigrated ProvenanceKind = "migrated"
	ProvenanceSynced   ProvenanceKind = "synced"
)

type Provenance struct {
	Kind         ProvenanceKind `json:"kind"`
	SourceDigest string         `json:"source_digest,omitempty"`
	ImportedAt   *time.Time     `json:"imported_at,omitempty"`
}

type LabeledAddress struct {
	Label      string `json:"label"`
	Address    string `json:"address"`
	Normalized string `json:"normalized"`
	Primary    bool   `json:"primary,omitempty"`
}

type LabeledPhone struct {
	Label      string `json:"label"`
	Number     string `json:"number"`
	Normalized string `json:"normalized"`
	Primary    bool   `json:"primary,omitempty"`
}

type MetadataField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Contact struct {
	Scope       Scope            `json:"scope"`
	ID          string           `json:"id"`
	DisplayName string           `json:"display_name"`
	GivenName   string           `json:"given_name,omitempty"`
	FamilyName  string           `json:"family_name,omitempty"`
	Organization string          `json:"organization,omitempty"`
	Notes       string           `json:"notes,omitempty"`
	Addresses   []LabeledAddress `json:"addresses,omitempty"`
	Phones      []LabeledPhone   `json:"phones,omitempty"`
	Metadata    []MetadataField  `json:"metadata,omitempty"`
	Provenance  Provenance       `json:"provenance"`
	Lifecycle   Lifecycle        `json:"lifecycle"`
	Revision    uint64           `json:"revision"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

func NormalizeContact(value Contact) (Contact, error) {
	if !value.Scope.Valid() || !opaquePattern.MatchString(value.ID) || value.Revision == 0 || value.Revision > MaximumRevision ||
		value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) || value.Lifecycle != LifecycleActive && value.Lifecycle != LifecycleDeleted {
		return Contact{}, ErrInvalid
	}
	value.DisplayName = cleanText(value.DisplayName, 512)
	value.GivenName = cleanText(value.GivenName, 256)
	value.FamilyName = cleanText(value.FamilyName, 256)
	value.Organization = cleanText(value.Organization, 512)
	value.Notes = cleanMultiline(value.Notes, 32<<10)
	if value.DisplayName == "" || len(value.Addresses) > MaximumContactAddresses || len(value.Phones) > MaximumContactPhones || len(value.Metadata) > MaximumContactMetadata {
		return Contact{}, ErrInvalid
	}
	primaryAddress := false
	seenAddress := map[string]bool{}
	for index := range value.Addresses {
		address, err := normalizeAddress(value.Addresses[index].Address)
		if err != nil || seenAddress[address] {
			return Contact{}, ErrInvalid
		}
		seenAddress[address] = true
		value.Addresses[index].Address = strings.TrimSpace(value.Addresses[index].Address)
		value.Addresses[index].Normalized = address
		value.Addresses[index].Label = cleanLabel(value.Addresses[index].Label)
		if value.Addresses[index].Primary {
			if primaryAddress { return Contact{}, ErrInvalid }
			primaryAddress = true
		}
	}
	primaryPhone := false
	seenPhone := map[string]bool{}
	for index := range value.Phones {
		number := normalizePhone(value.Phones[index].Number)
		if !phonePattern.MatchString(number) || seenPhone[number] {
			return Contact{}, ErrInvalid
		}
		seenPhone[number] = true
		value.Phones[index].Normalized = number
		value.Phones[index].Label = cleanLabel(value.Phones[index].Label)
		if value.Phones[index].Primary {
			if primaryPhone { return Contact{}, ErrInvalid }
			primaryPhone = true
		}
	}
	seenMetadata := map[string]bool{}
	for index := range value.Metadata {
		value.Metadata[index].Key = strings.ToLower(strings.TrimSpace(value.Metadata[index].Key))
		value.Metadata[index].Value = cleanText(value.Metadata[index].Value, 4<<10)
		if !metadataPattern.MatchString(value.Metadata[index].Key) || seenMetadata[value.Metadata[index].Key] || value.Metadata[index].Value == "" {
			return Contact{}, ErrInvalid
		}
		seenMetadata[value.Metadata[index].Key] = true
	}
	sort.Slice(value.Addresses, func(i, j int) bool { return value.Addresses[i].Normalized < value.Addresses[j].Normalized })
	sort.Slice(value.Phones, func(i, j int) bool { return value.Phones[i].Normalized < value.Phones[j].Normalized })
	sort.Slice(value.Metadata, func(i, j int) bool { return value.Metadata[i].Key < value.Metadata[j].Key })
	if !validProvenance(value.Provenance) { return Contact{}, ErrInvalid }
	if value.Provenance.ImportedAt != nil { importedAt := value.Provenance.ImportedAt.UTC().Truncate(time.Second); value.Provenance.ImportedAt = &importedAt }
	value.CreatedAt = value.CreatedAt.UTC().Truncate(time.Second)
	value.UpdatedAt = value.UpdatedAt.UTC().Truncate(time.Second)
	return value, nil
}

type GroupKind string

const (
	GroupContacts     GroupKind = "contacts"
	GroupDistribution GroupKind = "distribution"
)

type ContactGroup struct {
	Scope      Scope      `json:"scope"`
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Kind       GroupKind  `json:"kind"`
	ContactIDs []string   `json:"contact_ids,omitempty"`
	Recipients []string   `json:"recipients,omitempty"`
	Lifecycle  Lifecycle  `json:"lifecycle"`
	Revision   uint64     `json:"revision"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func NormalizeGroup(value ContactGroup) (ContactGroup, error) {
	if !value.Scope.Valid() || !opaquePattern.MatchString(value.ID) || value.Revision == 0 || value.Revision > MaximumRevision || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) || value.Lifecycle != LifecycleActive && value.Lifecycle != LifecycleDeleted {
		return ContactGroup{}, ErrInvalid
	}
	value.Name = cleanText(value.Name, 256)
	if value.Name == "" || value.Kind != GroupContacts && value.Kind != GroupDistribution || len(value.ContactIDs) > MaximumGroupMembers || len(value.Recipients) > MaximumDistributionTargets {
		return ContactGroup{}, ErrInvalid
	}
	if value.Kind == GroupContacts && len(value.Recipients) != 0 { return ContactGroup{}, ErrInvalid }
	seen := map[string]bool{}
	for _, id := range value.ContactIDs {
		if !opaquePattern.MatchString(id) || seen[id] { return ContactGroup{}, ErrInvalid }
		seen[id] = true
	}
	sort.Strings(value.ContactIDs)
	seen = map[string]bool{}
	for index := range value.Recipients {
		address, err := normalizeAddress(value.Recipients[index])
		if err != nil || seen[address] { return ContactGroup{}, ErrInvalid }
		seen[address] = true
		value.Recipients[index] = address
	}
	sort.Strings(value.Recipients)
	if len(value.ContactIDs)+len(value.Recipients) > MaximumGroupMembers { return ContactGroup{}, ErrLimit }
	value.CreatedAt = value.CreatedAt.UTC().Truncate(time.Second)
	value.UpdatedAt = value.UpdatedAt.UTC().Truncate(time.Second)
	return value, nil
}

type Identity struct {
	ID          string `json:"id"`
	Address     string `json:"address"`
	DisplayName string `json:"display_name"`
	ReplyTo     string `json:"reply_to,omitempty"`
	Signature   string `json:"signature,omitempty"`
	Default     bool   `json:"default,omitempty"`
}

type RemoteImagePolicy string

const (
	RemoteImagesBlock RemoteImagePolicy = "block"
	RemoteImagesAsk   RemoteImagePolicy = "ask"
	RemoteImagesProxy RemoteImagePolicy = "proxy"
)

type WebmailPreferences struct {
	Scope               Scope             `json:"scope"`
	Identities          []Identity        `json:"identities"`
	Timezone            string            `json:"timezone"`
	ComposeHTML         bool              `json:"compose_html"`
	ComposeFont         string            `json:"compose_font,omitempty"`
	RequestReadReceipt  bool              `json:"request_read_receipt"`
	DesktopNotifications bool             `json:"desktop_notifications"`
	SoundNotifications  bool              `json:"sound_notifications"`
	RemoteImages        RemoteImagePolicy `json:"remote_images"`
	HideQuotedText      bool              `json:"hide_quoted_text"`
	SendTelemetry       bool              `json:"send_telemetry"`
	Revision            uint64            `json:"revision"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

func NormalizePreferences(value WebmailPreferences) (WebmailPreferences, error) {
	if !value.Scope.Valid() || value.Revision == 0 || value.Revision > MaximumRevision || value.UpdatedAt.IsZero() || len(value.Identities) == 0 || len(value.Identities) > MaximumIdentities {
		return WebmailPreferences{}, ErrInvalid
	}
	location, err := time.LoadLocation(value.Timezone)
	if err != nil || len(value.Timezone) > 64 { return WebmailPreferences{}, ErrInvalid }
	value.Timezone = location.String()
	value.ComposeFont = cleanText(value.ComposeFont, 128)
	if value.RemoteImages != RemoteImagesBlock && value.RemoteImages != RemoteImagesAsk && value.RemoteImages != RemoteImagesProxy { return WebmailPreferences{}, ErrInvalid }
	seen := map[string]bool{}
	defaultCount := 0
	for index := range value.Identities {
		identity := &value.Identities[index]
		if !opaquePattern.MatchString(identity.ID) || seen[identity.ID] { return WebmailPreferences{}, ErrInvalid }
		seen[identity.ID] = true
		identity.Address, err = normalizeAddress(identity.Address)
		if err != nil { return WebmailPreferences{}, ErrInvalid }
		if identity.ReplyTo != "" { identity.ReplyTo, err = normalizeAddress(identity.ReplyTo); if err != nil { return WebmailPreferences{}, ErrInvalid } }
		identity.DisplayName = cleanText(identity.DisplayName, 256)
		identity.Signature = cleanMultiline(identity.Signature, MaximumSignatureBytes)
		if identity.DisplayName == "" || len(identity.Signature) > MaximumSignatureBytes { return WebmailPreferences{}, ErrInvalid }
		if identity.Default { defaultCount++ }
	}
	if defaultCount != 1 { return WebmailPreferences{}, ErrInvalid }
	sort.Slice(value.Identities, func(i, j int) bool { return value.Identities[i].ID < value.Identities[j].ID })
	value.UpdatedAt = value.UpdatedAt.UTC().Truncate(time.Second)
	return value, nil
}

type CanonicalVacationReference struct {
	RuleID     maildata.AutoresponderID `json:"rule_id"`
	Generation uint64                   `json:"generation"`
}

func (value CanonicalVacationReference) Valid() bool {
	return opaquePattern.MatchString(string(value.RuleID)) && value.Generation > 0 && value.Generation <= maildata.AutoresponderMaximumGeneration
}

type FieldMask []string

func (mask FieldMask) Valid(allowed map[string]bool) bool {
	if len(mask) == 0 || len(mask) > 64 { return false }
	seen := map[string]bool{}
	for _, field := range mask {
		if !allowed[field] || seen[field] { return false }
		seen[field] = true
	}
	return true
}

type ContactQuery struct {
	Scope  Scope
	Search string
	Cursor string
	Limit  int
}

type ContactPage struct {
	Contacts  []Contact
	NextCursor string
}

type DuplicatePolicy string

const (
	DuplicateReject DuplicatePolicy = "reject"
	DuplicateSkip   DuplicatePolicy = "skip"
	DuplicateMerge  DuplicatePolicy = "merge"
)

func normalizeAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || len(value) > 254 || strings.ContainsAny(value, "\r\n\x00") { return "", ErrInvalid }
	parts := strings.Split(strings.ToLower(value), "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" { return "", ErrInvalid }
	return parts[0] + "@" + parts[1], nil
}

func normalizePhone(value string) string {
	value = strings.TrimSpace(value)
	var result strings.Builder
	for index, char := range value {
		if char >= '0' && char <= '9' || char == '+' && index == 0 { result.WriteRune(char) }
	}
	return result.String()
}

func cleanLabel(value string) string { return cleanText(value, 64) }

func cleanText(value string, maximum int) string {
	value = strings.Join(strings.Fields(strings.Map(func(char rune) rune {
		if char == 0 || char == '\r' || char == '\n' || char < 0x20 && char != '\t' { return -1 }
		return char
	}, value)), " ")
	if len(value) > maximum { return "" }
	return value
}

func cleanMultiline(value string, maximum int) string {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\r", "\n")
	value = strings.Map(func(char rune) rune { if char == 0 || char < 0x20 && char != '\n' && char != '\t' { return -1 }; return char }, value)
	value = strings.TrimSpace(value)
	if len(value) > maximum { return "" }
	return value
}

func validProvenance(value Provenance) bool {
	switch value.Kind { case ProvenanceManual, ProvenanceCSV, ProvenanceVCard, ProvenanceMigrated, ProvenanceSynced: default: return false }
	if value.SourceDigest != "" { if len(value.SourceDigest) != 64 { return false }; if _, err := hex.DecodeString(value.SourceDigest); err != nil { return false } }
	return value.ImportedAt == nil || !value.ImportedAt.IsZero()
}

func addressDigest(value string) string { sum := sha256.Sum256([]byte(value)); return hex.EncodeToString(sum[:]) }
