package webmail

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
)

var (
	ErrInvalid           = errors.New("webmail: invalid request")
	ErrNotFound          = errors.New("webmail: not found")
	ErrUnauthorized      = errors.New("webmail: unauthorized")
	ErrConflict          = errors.New("webmail: conflict")
	ErrLimit             = errors.New("webmail: limit exceeded")
	ErrGrantInvalid      = errors.New("webmail: grant invalid or already used")
	ErrCursorInvalid     = errors.New("webmail: cursor invalid or already used")
	ErrStaleUIDValidity  = errors.New("webmail: stale uidvalidity")
	ErrPartial           = errors.New("webmail: bounded operation returned partial data")
	ErrAmbiguous         = errors.New("webmail: ambiguous server response")
	ErrProtocol          = errors.New("webmail: invalid imap response")
	ErrUnavailable       = errors.New("webmail: imap unavailable")
	ErrIneligibleFolder  = errors.New("webmail: folder is protected")
)

const (
	MaximumPageSize       = 100
	MaximumSearchTerms    = 8
	MaximumSearchText     = 256
	MaximumFolderNameRunes = 255
	MaximumGrantLifetime  = 2 * time.Minute
	MaximumCursorLifetime = 10 * time.Minute
	MaximumGrantsPerTenant = 4096
	MaximumReceiptsPerTenant = 4096
	MaximumCursorsPerTenant  = 4096
)

var opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Principal struct {
	UserID    string
	SessionID string
}

func (principal Principal) valid() bool {
	return opaqueIDPattern.MatchString(principal.UserID) && opaqueIDPattern.MatchString(principal.SessionID)
}

type AuthorizedMailAccount struct {
	TenantID          string
	MailboxID         string
	DisplayLabel      string
	AddressLabel      string
	AuthorizationEpoch uint64
	Enabled           bool
}

func (account AuthorizedMailAccount) valid() bool {
	return opaqueIDPattern.MatchString(account.TenantID) && opaqueIDPattern.MatchString(account.MailboxID) &&
		account.AuthorizationEpoch > 0 && account.Enabled && len(account.DisplayLabel) <= 256 && len(account.AddressLabel) <= 320
}

type AccountPage struct {
	Accounts   []AuthorizedMailAccount
	NextCursor string
}

type MailboxContext struct {
	Principal          Principal
	TenantID           string
	MailboxID          string
	Audience           string
	AuthorizationEpoch uint64
	Grant              string
	RequestID          string
}

func (mailbox MailboxContext) valid() bool {
	return mailbox.Principal.valid() && opaqueIDPattern.MatchString(mailbox.TenantID) &&
		opaqueIDPattern.MatchString(mailbox.MailboxID) && opaqueIDPattern.MatchString(mailbox.Audience) &&
		mailbox.AuthorizationEpoch > 0 && len(mailbox.Grant) >= 32 && len(mailbox.Grant) <= 256 &&
		opaqueIDPattern.MatchString(mailbox.RequestID)
}

type GrantClaims struct {
	TenantID           string
	UserID             string
	SessionID          string
	MailboxID          string
	Audience           string
	AuthorizationEpoch uint64
	IssuedAt           time.Time
	ExpiresAt          time.Time
}

func (claims GrantClaims) valid(now time.Time) bool {
	return opaqueIDPattern.MatchString(claims.TenantID) && opaqueIDPattern.MatchString(claims.UserID) &&
		opaqueIDPattern.MatchString(claims.SessionID) && opaqueIDPattern.MatchString(claims.MailboxID) &&
		opaqueIDPattern.MatchString(claims.Audience) && claims.AuthorizationEpoch > 0 &&
		!claims.IssuedAt.IsZero() && claims.ExpiresAt.After(claims.IssuedAt) &&
		claims.ExpiresAt.Sub(claims.IssuedAt) <= MaximumGrantLifetime && claims.ExpiresAt.After(now)
}

type IssuedGrant struct {
	Token     string
	ExpiresAt time.Time
}

type MessageSort string

const (
	SortNewest MessageSort = "newest"
	SortOldest MessageSort = "oldest"
)

func (sort MessageSort) valid() bool { return sort == SortNewest || sort == SortOldest }

type Preferences struct {
	TenantID   string
	UserID     string
	MailboxID  string
	Revision   uint64
	PageSize   uint16
	Sort       MessageSort
	Threaded   bool
	UpdatedAt  time.Time
}

func (preferences Preferences) valid() bool {
	return opaqueIDPattern.MatchString(preferences.TenantID) && opaqueIDPattern.MatchString(preferences.UserID) &&
		opaqueIDPattern.MatchString(preferences.MailboxID) && preferences.Revision > 0 &&
		preferences.PageSize > 0 && preferences.PageSize <= MaximumPageSize && preferences.Sort.valid() && !preferences.UpdatedAt.IsZero()
}

type CursorKind string

const (
	CursorAccounts CursorKind = "accounts"
	CursorFolders  CursorKind = "folders"
	CursorMessages CursorKind = "messages"
	CursorSearch   CursorKind = "search"
)

type CursorState struct {
	Kind                CursorKind
	TenantID            string
	UserID              string
	SessionID           string
	MailboxID           string
	AuthorizationEpoch  uint64
	FolderName          string
	UIDValidity         uint32
	LastUID             uint32
	LastAccountID       string
	LastFolderName      string
	Sort                MessageSort
	QueryDigest         string
	ExpiresAt           time.Time
}

func (cursor CursorState) valid(now time.Time) bool {
	if cursor.Kind != CursorAccounts && cursor.Kind != CursorFolders && cursor.Kind != CursorMessages && cursor.Kind != CursorSearch {
		return false
	}
	if !opaqueIDPattern.MatchString(cursor.TenantID) || !opaqueIDPattern.MatchString(cursor.UserID) ||
		!opaqueIDPattern.MatchString(cursor.SessionID) || cursor.AuthorizationEpoch == 0 || cursor.ExpiresAt.After(now.Add(MaximumCursorLifetime)) || !cursor.ExpiresAt.After(now) {
		return false
	}
	if cursor.Kind == CursorAccounts {
		return cursor.MailboxID == "" && (cursor.LastAccountID == "" || opaqueIDPattern.MatchString(cursor.LastAccountID))
	}
	if !opaqueIDPattern.MatchString(cursor.MailboxID) {
		return false
	}
	if cursor.Kind == CursorFolders {
		return cursor.LastFolderName != "" && validMailboxName(cursor.LastFolderName)
	}
	return validMailboxName(cursor.FolderName) && cursor.UIDValidity > 0 && cursor.LastUID > 0 && cursor.Sort.valid() && len(cursor.QueryDigest) == 64
}

type OperationReceipt struct {
	RequestID      string
	TenantID       string
	UserDigest     string
	MailboxDigest  string
	Operation      string
	Outcome        string
	ItemCount      uint16
	Partial        bool
	OccurredAt     time.Time
}

func (receipt OperationReceipt) valid() bool {
	return opaqueIDPattern.MatchString(receipt.RequestID) && opaqueIDPattern.MatchString(receipt.TenantID) &&
		len(receipt.UserDigest) == 64 && len(receipt.MailboxDigest) == 64 && opaqueIDPattern.MatchString(receipt.Operation) &&
		(receipt.Outcome == "succeeded" || receipt.Outcome == "failed" || receipt.Outcome == "denied") && !receipt.OccurredAt.IsZero()
}

type SpecialUse string

const (
	SpecialInbox   SpecialUse = "inbox"
	SpecialArchive SpecialUse = "archive"
	SpecialDrafts  SpecialUse = "drafts"
	SpecialJunk    SpecialUse = "junk"
	SpecialSent    SpecialUse = "sent"
	SpecialTrash   SpecialUse = "trash"
	SpecialFlagged SpecialUse = "flagged"
	SpecialAll     SpecialUse = "all"
)

type Quota struct {
	UsedBytes uint64
	LimitBytes uint64
}

type Folder struct {
	Name          string
	Parent        string
	Delimiter     rune
	Subscribed    bool
	HasChildren   bool
	SpecialUse    SpecialUse
	Messages      uint32
	Unseen        uint32
	UIDNext       uint32
	UIDValidity   uint32
	HighestModSeq uint64
	Quota         Quota
}

type FolderPageRequest struct {
	Limit  uint16
	Cursor string
	afterName string
}

type FolderPage struct {
	Folders    []Folder
	NextCursor string
	Partial    bool
	more       bool
}

type FolderMutation string

const (
	FolderCreate      FolderMutation = "create"
	FolderRename      FolderMutation = "rename"
	FolderSubscribe   FolderMutation = "subscribe"
	FolderUnsubscribe FolderMutation = "unsubscribe"
	FolderEmpty       FolderMutation = "empty"
	FolderDelete      FolderMutation = "delete"
)

type FolderMutationRequest struct {
	Operation FolderMutation
	Name      string
	NewName   string
}

func (request FolderMutationRequest) valid() bool {
	if !validMailboxName(request.Name) {
		return false
	}
	switch request.Operation {
	case FolderCreate, FolderSubscribe, FolderUnsubscribe, FolderEmpty, FolderDelete:
		return request.NewName == ""
	case FolderRename:
		return validMailboxName(request.NewName) && request.Name != request.NewName
	default:
		return false
	}
}

type Address struct {
	Name    string
	Mailbox string
	Host    string
}

type MessageIdentity struct {
	Folder      string
	UIDValidity uint32
	UID         uint32
}

type MessageSummary struct {
	Identity      MessageIdentity
	ModSeq        uint64
	ThreadID      string
	Flags         []string
	Sender        Address
	Subject       string
	Date          time.Time
	Size          uint64
	HasAttachment bool
}

type MessagePageRequest struct {
	Folder string
	Limit  uint16
	Cursor string
	Sort   MessageSort
	Threaded bool
	expectedUIDValidity uint32
	afterUID uint32
}

type MessagePage struct {
	Folder       string
	UIDValidity  uint32
	HighestModSeq uint64
	Messages     []MessageSummary
	NextCursor   string
	Partial      bool
	more         bool
	lastUID      uint32
}

type SearchCriteria struct {
	Text      string
	From      string
	Subject   string
	Since     time.Time
	Before    time.Time
	Seen      *bool
	Flagged   *bool
	HasAttachment *bool
}

func (criteria SearchCriteria) valid() bool {
	values := []string{criteria.Text, criteria.From, criteria.Subject}
	terms := 0
	for _, value := range values {
		if value != "" {
			terms++
		}
		if len(value) > MaximumSearchText || strings.IndexFunc(value, unicode.IsControl) >= 0 || strings.ToValidUTF8(value, "") != value {
			return false
		}
	}
	if !criteria.Since.IsZero() {
		terms++
	}
	if !criteria.Before.IsZero() {
		terms++
	}
	if criteria.Seen != nil {
		terms++
	}
	if criteria.Flagged != nil {
		terms++
	}
	if criteria.HasAttachment != nil {
		terms++
	}
	return terms > 0 && terms <= MaximumSearchTerms && (criteria.Before.IsZero() || criteria.Since.IsZero() || criteria.Before.After(criteria.Since))
}

type SearchRequest struct {
	Folder   string
	Criteria SearchCriteria
	Limit    uint16
	Cursor   string
	Sort     MessageSort
	expectedUIDValidity uint32
	afterUID uint32
}

type SearchPage struct {
	Folder       string
	UIDValidity  uint32
	HighestModSeq uint64
	Identities   []MessageIdentity
	NextCursor   string
	Partial      bool
	more         bool
	lastUID      uint32
}

func validMailboxName(name string) bool {
	return name != "" && len([]rune(name)) <= MaximumFolderNameRunes && len(name) <= 1024 &&
		strings.IndexFunc(name, unicode.IsControl) < 0 && strings.ToValidUTF8(name, "") == name
}

type Authorizer interface {
	ListMailAccounts(context.Context, Principal, string) ([]AuthorizedMailAccount, error)
	AuthorizeMailbox(context.Context, Principal, string, string) (AuthorizedMailAccount, error)
}

type AuditEvent struct {
	Operation      string
	Outcome        string
	TenantID       string
	UserDigest     string
	SessionDigest  string
	MailboxDigest  string
	RequestID      string
	OccurredAt     time.Time
}

type Auditor interface {
	RecordWebmailSecurity(context.Context, AuditEvent) error
}

type Repository interface {
	Bootstrap(context.Context) error
	StoreGrant(context.Context, string, GrantClaims) error
	SwitchGrant(context.Context, Principal, string, string, uint64, string, GrantClaims, time.Time) (uint64, error)
	ConsumeGrant(context.Context, string, GrantClaims, time.Time) error
	RevokeGrants(context.Context, Principal, string, string, uint64, time.Time) (uint64, error)
	GetPreferences(context.Context, string, string, string) (Preferences, error)
	PutPreferences(context.Context, Preferences, uint64) (Preferences, error)
	StoreCursor(context.Context, string, CursorState) error
	ConsumeCursor(context.Context, string, CursorState, time.Time) (CursorState, error)
	StoreReceipt(context.Context, OperationReceipt) error
}

type Backend interface {
	ListFolders(context.Context, string, FolderPageRequest) (FolderPage, error)
	MutateFolder(context.Context, string, FolderMutationRequest) error
	ListMessages(context.Context, string, MessagePageRequest) (MessagePage, error)
	Search(context.Context, string, SearchRequest) (SearchPage, error)
}
