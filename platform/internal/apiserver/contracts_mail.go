package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	securewebmail "github.com/aonsyed/cyberpanel/platform/internal/webmail"
)

type MailPagePayload struct {
	Limit  uint16 `json:"limit"`
	Cursor string `json:"cursor,omitempty"`
}
type MailPageResult struct {
	Items      []mail.ResourceEnvelope `json:"items"`
	NextCursor string                  `json:"next_cursor,omitempty"`
}
type MailDomainPayload struct {
	Domain mail.Domain `json:"domain"`
}
type MailMailboxPayload struct {
	Mailbox mail.Mailbox `json:"mailbox"`
}
type MailAliasPayload struct {
	Alias mail.Alias `json:"alias"`
}
type MailPolicyPayload struct {
	Policy mail.Policy `json:"policy"`
}
type MailDKIMPreparePayload struct {
	OverlapSeconds                  uint32 `json:"overlap_seconds,omitempty"`
	CurrentSecretVersion            uint64 `json:"current_secret_version,omitempty"`
	CurrentSecretBindingDigest      string `json:"current_secret_binding_digest,omitempty"`
	CurrentSecretResourceGeneration uint64 `json:"current_secret_resource_generation,omitempty"`
}
type MailDKIMActivatePayload struct {
	ConfirmPrevious bool `json:"confirm_previous,omitempty"`
}
type MailQueueFlushPayload struct {
	Limit  uint16 `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}
type MailQueueFlushResult struct {
	Items      []mail.OperationReceipt `json:"items"`
	NextCursor string                  `json:"next_cursor,omitempty"`
}
type EmptyPayload struct{}

type WebmailAccountPagePayload struct {
	Limit  uint16 `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}
type WebmailAccountSwitchPayload struct {
	PreviousMailboxID string `json:"previous_mailbox_id"`
	TargetMailboxID   string `json:"target_mailbox_id"`
}
type WebmailEpochPayload struct {
	AuthorizationEpoch uint64 `json:"authorization_epoch"`
}
type WebmailFolderPagePayload struct {
	WebmailEpochPayload
	Limit  uint16 `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}
type WebmailFolderMutationPayload struct {
	WebmailEpochPayload
	Operation securewebmail.FolderMutation `json:"operation"`
	Name      string                       `json:"name"`
	NewName   string                       `json:"new_name,omitempty"`
}
type WebmailMessageIdentity struct {
	Folder      string `json:"folder"`
	UIDValidity uint32 `json:"uid_validity"`
	UID         uint32 `json:"uid"`
}
type WebmailMessagePagePayload struct {
	WebmailEpochPayload
	Folder   string                    `json:"folder"`
	Limit    uint16                    `json:"limit,omitempty"`
	Cursor   string                    `json:"cursor,omitempty"`
	Sort     securewebmail.MessageSort `json:"sort,omitempty"`
	Threaded bool                      `json:"threaded,omitempty"`
}
type WebmailSearchCriteria struct {
	Text          string    `json:"text,omitempty"`
	From          string    `json:"from,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Since         time.Time `json:"since,omitempty"`
	Before        time.Time `json:"before,omitempty"`
	Seen          *bool     `json:"seen,omitempty"`
	Flagged       *bool     `json:"flagged,omitempty"`
	HasAttachment *bool     `json:"has_attachment,omitempty"`
}
type WebmailSearchPayload struct {
	WebmailEpochPayload
	Folder   string                    `json:"folder"`
	Criteria WebmailSearchCriteria     `json:"criteria"`
	Limit    uint16                    `json:"limit,omitempty"`
	Cursor   string                    `json:"cursor,omitempty"`
	Sort     securewebmail.MessageSort `json:"sort,omitempty"`
}
type WebmailReadPayload struct {
	WebmailEpochPayload
	Identity          WebmailMessageIdentity          `json:"identity"`
	RemoteImagePolicy securewebmail.RemoteImagePolicy `json:"remote_image_policy,omitempty"`
}
type WebmailRemoteImagePayload struct {
	WebmailEpochPayload
	Identity       WebmailMessageIdentity `json:"identity"`
	ReferenceID    string                 `json:"reference_id"`
	URL            string                 `json:"url"`
	ExpectedDigest string                 `json:"expected_digest"`
	MaximumBytes   uint64                 `json:"maximum_bytes,omitempty"`
}
type WebmailAttachmentIssuePayload struct {
	WebmailEpochPayload
	Identity     WebmailMessageIdentity `json:"identity"`
	PartID       string                 `json:"part_id"`
	Filename     string                 `json:"filename"`
	ContentType  string                 `json:"content_type"`
	MaximumBytes uint64                 `json:"maximum_bytes"`
	Preview      bool                   `json:"preview,omitempty"`
}
type WebmailAttachmentLeasePayload struct {
	DownloadID string `json:"download_id"`
}
type WebmailAttachmentReadPayload struct {
	DownloadID string `json:"download_id"`
	Offset     uint64 `json:"offset"`
	Length     uint32 `json:"length"`
}
type WebmailAttachmentUploadPayload struct {
	WebmailEpochPayload
	Filename      string    `json:"filename"`
	ContentType   string    `json:"content_type"`
	MaximumBytes  uint64    `json:"maximum_bytes"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	ContentBase64 string    `json:"content_base64"`
}
type WebmailAttachmentDeletePayload struct {
	WebmailEpochPayload
	UploadID string `json:"upload_id"`
}
type WebmailComposeAddress struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}
type WebmailComposePayload struct {
	ID            string                    `json:"id"`
	Mode          securewebmail.ComposeMode `json:"mode"`
	From          WebmailComposeAddress     `json:"from"`
	To            []WebmailComposeAddress   `json:"to"`
	CC            []WebmailComposeAddress   `json:"cc,omitempty"`
	BCC           []WebmailComposeAddress   `json:"bcc,omitempty"`
	ReplyTo       []WebmailComposeAddress   `json:"reply_to,omitempty"`
	Subject       string                    `json:"subject,omitempty"`
	PlainText     string                    `json:"plain_text,omitempty"`
	SanitizedHTML string                    `json:"sanitized_html,omitempty"`
	InReplyTo     string                    `json:"in_reply_to,omitempty"`
	References    []string                  `json:"references,omitempty"`
	AttachmentIDs []string                  `json:"attachment_ids,omitempty"`
	SendAt        time.Time                 `json:"send_at,omitempty"`
}
type WebmailDraftSavePayload struct {
	WebmailEpochPayload
	Message WebmailComposePayload `json:"message"`
}
type WebmailDraftPayload struct {
	WebmailEpochPayload
	DraftID string `json:"draft_id"`
}
type WebmailSendPayload struct {
	WebmailEpochPayload
	Message WebmailComposePayload `json:"message"`
}
type WebmailMessageActionPayload struct {
	WebmailEpochPayload
	Action       securewebmail.MessageAction `json:"action"`
	Messages     []WebmailMessageIdentity    `json:"messages"`
	TargetFolder string                      `json:"target_folder,omitempty"`
}

type WebmailAccountProjection struct {
	ID                 string `json:"id"`
	DisplayLabel       string `json:"display_label"`
	Address            string `json:"address"`
	AuthorizationEpoch uint64 `json:"authorization_epoch"`
}
type WebmailAccountPageResult struct {
	Items      []WebmailAccountProjection `json:"items"`
	NextCursor string                     `json:"next_cursor,omitempty"`
}
type WebmailFolderProjection struct {
	Name          string                   `json:"name"`
	Parent        string                   `json:"parent,omitempty"`
	Delimiter     string                   `json:"delimiter,omitempty"`
	Subscribed    bool                     `json:"subscribed"`
	HasChildren   bool                     `json:"has_children"`
	Role          securewebmail.SpecialUse `json:"role,omitempty"`
	Messages      uint32                   `json:"messages"`
	Unseen        uint32                   `json:"unseen"`
	UIDNext       uint32                   `json:"uid_next"`
	UIDValidity   uint32                   `json:"uid_validity"`
	HighestModSeq uint64                   `json:"highest_mod_seq"`
	Quota         securewebmail.Quota      `json:"quota"`
}
type WebmailFolderPageResult struct {
	Items      []WebmailFolderProjection `json:"items"`
	NextCursor string                    `json:"next_cursor,omitempty"`
	Partial    bool                      `json:"partial,omitempty"`
}
type WebmailAddressProjection struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}
type WebmailMessageSummaryProjection struct {
	Identity      WebmailMessageIdentity   `json:"identity"`
	ModSeq        uint64                   `json:"mod_seq"`
	ThreadID      string                   `json:"thread_id"`
	Flags         []string                 `json:"flags"`
	Sender        WebmailAddressProjection `json:"sender"`
	Subject       string                   `json:"subject"`
	Date          time.Time                `json:"date"`
	Size          uint64                   `json:"size"`
	HasAttachment bool                     `json:"has_attachment"`
}
type WebmailMessagePageResult struct {
	Folder        string                            `json:"folder"`
	UIDValidity   uint32                            `json:"uid_validity"`
	HighestModSeq uint64                            `json:"highest_mod_seq"`
	Items         []WebmailMessageSummaryProjection `json:"items"`
	NextCursor    string                            `json:"next_cursor,omitempty"`
	Partial       bool                              `json:"partial,omitempty"`
}
type WebmailSearchPageResult struct {
	Folder        string                   `json:"folder"`
	UIDValidity   uint32                   `json:"uid_validity"`
	HighestModSeq uint64                   `json:"highest_mod_seq"`
	Items         []WebmailMessageIdentity `json:"items"`
	NextCursor    string                   `json:"next_cursor,omitempty"`
	Partial       bool                     `json:"partial,omitempty"`
}
type WebmailRemoteImageProjection struct {
	ID      string `json:"id"`
	URL     string `json:"url"`
	Digest  string `json:"digest"`
	Blocked bool   `json:"blocked"`
}
type WebmailRenderedMessageResult struct {
	Identity       WebmailMessageIdentity         `json:"identity"`
	PlainText      string                         `json:"plain_text,omitempty"`
	SanitizedHTML  string                         `json:"sanitized_html,omitempty"`
	CSP            string                         `json:"csp"`
	ReferrerPolicy string                         `json:"referrer_policy"`
	RemoteImages   []WebmailRemoteImageProjection `json:"remote_images"`
	Attachments    []WebmailAttachmentReference   `json:"attachments"`
}
type WebmailAttachmentReference struct {
	PartID      string `json:"part_id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        uint64 `json:"size"`
}
type WebmailRemoteImageResult struct {
	ContentType    string `json:"content_type"`
	ContentBase64  string `json:"content_base64"`
	Size           uint64 `json:"size"`
	CacheControl   string `json:"cache_control"`
	ReferrerPolicy string `json:"referrer_policy"`
}
type WebmailAttachmentLeaseResult struct {
	ID           string    `json:"id"`
	Filename     string    `json:"filename"`
	ContentType  string    `json:"content_type"`
	Disposition  string    `json:"disposition"`
	Size         uint64    `json:"size"`
	Digest       string    `json:"digest"`
	MalwareState string    `json:"malware_state"`
	ExpiresAt    time.Time `json:"expires_at"`
	DownloadURL  string    `json:"download_url"`
}
type WebmailAttachmentReadResult struct {
	DownloadID    string `json:"download_id"`
	Offset        uint64 `json:"offset"`
	ContentBase64 string `json:"content_base64"`
}
type WebmailBlobResult struct {
	ID          string    `json:"id"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	Size        uint64    `json:"size"`
	Digest      string    `json:"digest"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type WebmailDraftResult struct {
	Revision  uint64                `json:"revision"`
	Message   WebmailComposePayload `json:"message"`
	UpdatedAt time.Time             `json:"updated_at"`
}
type WebmailSendResult struct {
	State            string `json:"state"`
	SubmissionID     string `json:"submission_id,omitempty"`
	MayHaveSubmitted bool   `json:"may_have_submitted,omitempty"`
}

func registerMailContracts(registry *Registry) error {
	manage := identity.MustPermission("mail:manage")
	definitions := []Operation{
		{Name: "mail.mailbox.password.enroll", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, MaximumBodyBytes: 4096, NewPayload: func() any { return &MailboxPasswordPayload{} }, ValidatePayload: validateMailboxPassword, ResolveScope: mailExistingScope},
		{Name: "mail.domain.list", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &MailPagePayload{} }, ValidatePayload: validateMailPage, ResolveScope: mailListScope},
		{Name: "mail.domain.get", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailGetScope},
		{Name: "mail.domain.create", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailDomainPayload{} }, ValidatePayload: validateMailDomain, ResolveScope: mailCreateScope},
		{Name: "mail.domain.update", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailDomainPayload{} }, ValidatePayload: validateMailDomain, ResolveScope: mailExistingScope},
		{Name: "mail.domain.delete", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailExistingScope},
		{Name: "mail.domain.dkim.prepare", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailDKIMPreparePayload{} }, ValidatePayload: validateMailDKIMPrepare, ResolveScope: mailExistingScope},
		{Name: "mail.domain.dkim.status", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailGetScope},
		{Name: "mail.domain.dkim.activate", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailDKIMActivatePayload{} }, ResolveScope: mailExistingScope},
		{Name: "mail.mailbox.list", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &MailPagePayload{} }, ValidatePayload: validateMailPage, ResolveScope: mailListScope},
		{Name: "mail.mailbox.get", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailGetScope},
		{Name: "mail.mailbox.create", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailMailboxPayload{} }, ValidatePayload: validateMailMailbox, ResolveScope: mailCreateScope},
		{Name: "mail.mailbox.update", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailMailboxPayload{} }, ValidatePayload: validateMailMailbox, ResolveScope: mailExistingScope},
		{Name: "mail.mailbox.delete", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailExistingScope},
		{Name: "mail.alias.list", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &MailPagePayload{} }, ValidatePayload: validateMailPage, ResolveScope: mailListScope},
		{Name: "mail.alias.get", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailGetScope},
		{Name: "mail.alias.create", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailAliasPayload{} }, ValidatePayload: validateMailAlias, ResolveScope: mailCreateScope},
		{Name: "mail.alias.update", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailAliasPayload{} }, ValidatePayload: validateMailAlias, ResolveScope: mailExistingScope},
		{Name: "mail.alias.delete", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailExistingScope},
		{Name: "mail.policy.list", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &MailPagePayload{} }, ValidatePayload: validateMailPage, ResolveScope: mailListScope},
		{Name: "mail.policy.get", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailGetScope},
		{Name: "mail.policy.create", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailPolicyPayload{} }, ValidatePayload: validateMailPolicy, ResolveScope: mailCreateScope},
		{Name: "mail.policy.update", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailPolicyPayload{} }, ValidatePayload: validateMailPolicy, ResolveScope: mailExistingScope},
		{Name: "mail.policy.delete", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailExistingScope},
		{Name: "mail.queue.list", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &MailPagePayload{} }, ValidatePayload: validateMailPage, ResolveScope: mailListScope},
		{Name: "mail.queue.get", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailGetScope},
		{Name: "mail.queue.inspect", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailGetScope},
		{Name: "mail.queue.retry", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailExistingScope},
		{Name: "mail.queue.flush", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &MailQueueFlushPayload{} }, ValidatePayload: validateMailQueueFlush, ResolveScope: mailListScope},
		{Name: "mail.queue.cancel", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailExistingScope},
		{Name: "mail.queue.delete", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailExistingScope},
		{Name: "webmail.account.list", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &WebmailAccountPagePayload{} }, ValidatePayload: validateWebmailAccounts, ResolveScope: mailListScope},
		{Name: "webmail.mailbox.list", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &WebmailAccountPagePayload{} }, ValidatePayload: validateWebmailAccounts, ResolveScope: mailListScope},
		{Name: "webmail.account.switch", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &WebmailAccountSwitchPayload{} }, ValidatePayload: validateWebmailAccountSwitch, ResolveScope: tenantScope},
		{Name: "webmail.folder.list", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &WebmailFolderPagePayload{} }, ValidatePayload: validateWebmailFolderPage, ResolveScope: webmailScope},
		{Name: "webmail.folder.mutate", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &WebmailFolderMutationPayload{} }, ValidatePayload: validateWebmailFolderMutation, ResolveScope: webmailScope},
		{Name: "webmail.message.list", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &WebmailMessagePagePayload{} }, ValidatePayload: validateWebmailMessagePage, ResolveScope: webmailScope},
		{Name: "webmail.message.search", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &WebmailSearchPayload{} }, ValidatePayload: validateSecureWebmailSearch, ResolveScope: webmailScope},
		{Name: "webmail.message.read", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, MaximumResponseBytes: 4 << 20, NewPayload: func() any { return &WebmailReadPayload{} }, ValidatePayload: validateSecureWebmailRead, ResolveScope: webmailScope},
		{Name: "webmail.message.get", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, MaximumResponseBytes: 4 << 20, NewPayload: func() any { return &WebmailReadPayload{} }, ValidatePayload: validateSecureWebmailRead, ResolveScope: webmailScope},
		{Name: "webmail.remote_image.fetch", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, MaximumResponseBytes: 8 << 20, NewPayload: func() any { return &WebmailRemoteImagePayload{} }, ValidatePayload: validateWebmailRemoteImage, ResolveScope: webmailScope},
		{Name: "webmail.attachment.issue", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &WebmailAttachmentIssuePayload{} }, ValidatePayload: validateWebmailAttachmentIssue, ResolveScope: webmailScope},
		{Name: "webmail.attachment.get", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &WebmailAttachmentLeasePayload{} }, ValidatePayload: validateWebmailAttachmentLease, ResolveScope: webmailScope},
		{Name: "webmail.attachment.read", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, MaximumResponseBytes: 2 << 20, NewPayload: func() any { return &WebmailAttachmentReadPayload{} }, ValidatePayload: validateWebmailAttachmentRead, ResolveScope: webmailScope},
		{Name: "webmail.attachment.close", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &WebmailAttachmentLeasePayload{} }, ValidatePayload: validateWebmailAttachmentLease, ResolveScope: webmailScope},
		{Name: "webmail.attachment.upload", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, Mutating: true, MaximumBodyBytes: 12 << 20, NewPayload: func() any { return &WebmailAttachmentUploadPayload{} }, ValidatePayload: validateWebmailAttachmentUpload, ResolveScope: webmailScope},
		{Name: "webmail.attachment.delete", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &WebmailAttachmentDeletePayload{} }, ValidatePayload: validateWebmailAttachmentDelete, ResolveScope: webmailScope},
		{Name: "webmail.draft.save", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &WebmailDraftSavePayload{} }, ValidatePayload: validateWebmailDraftSave, ResolveScope: webmailScope},
		{Name: "webmail.draft.get", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, NewPayload: func() any { return &WebmailDraftPayload{} }, ValidatePayload: validateSecureWebmailDraft, ResolveScope: webmailScope},
		{Name: "webmail.draft.delete", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &WebmailDraftPayload{} }, ValidatePayload: validateSecureWebmailDraft, ResolveScope: webmailScope},
		{Name: "webmail.message.send", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &WebmailSendPayload{} }, ValidatePayload: validateSecureWebmailSend, ResolveScope: webmailScope},
		{Name: "webmail.message.action", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &WebmailMessageActionPayload{} }, ValidatePayload: validateWebmailMessageAction, ResolveScope: webmailScope},
	}
	for _, definition := range definitions {
		if err := register(registry, definition); err != nil {
			return err
		}
	}
	return nil
}

func validateMailPage(value any) error {
	payload := value.(*MailPagePayload)
	if payload.Limit > 500 || len(payload.Cursor) > 1024 {
		return invalid("mail page")
	}
	return nil
}
func validateMailQueueFlush(value any) error {
	payload := value.(*MailQueueFlushPayload)
	if payload.Limit == 0 {
		payload.Limit = 500
	}
	if payload.Limit > 1000 || len(payload.Cursor) > 1024 {
		return invalid("mail queue page")
	}
	return nil
}
func validateMailDomain(value any) error {
	domain := value.(*MailDomainPayload).Domain
	if !safeMailOpaque(string(domain.ID)) || !validMailHostname(domain.Name) || !safeMailOpaque(string(domain.Policy)) || len(domain.DKIM.PublicKey) > 16<<10 || domain.StaticRoutes {
		return invalid("mail domain")
	}
	if domain.DKIM.Enabled && (!safeMailLabel(domain.DKIM.Selector, 63) || !safeMailOpaque(domain.DKIM.PrivateKeyRef)) {
		return invalid("mail DKIM")
	}
	if domain.Relay.Host != "" && (!validMailHostname(domain.Relay.Host) || domain.Relay.Port == 0 || !safeMailOpaque(domain.Relay.CredentialRef)) {
		return invalid("mail relay")
	}
	return nil
}
func validateMailDKIMPrepare(value any) error {
	payload := value.(*MailDKIMPreparePayload)
	if payload.OverlapSeconds == 0 {
		payload.OverlapSeconds = uint32(mail.DKIMDefaultOverlap / time.Second)
	}
	overlap := time.Duration(payload.OverlapSeconds) * time.Second
	if overlap < mail.DKIMMinimumOverlap || overlap > mail.DKIMMaximumOverlap {
		return invalid("mail DKIM overlap")
	}
	payload.CurrentSecretBindingDigest = strings.ToLower(strings.TrimSpace(payload.CurrentSecretBindingDigest))
	present := payload.CurrentSecretVersion != 0 || payload.CurrentSecretBindingDigest != "" || payload.CurrentSecretResourceGeneration != 0
	if present && (payload.CurrentSecretVersion == 0 || payload.CurrentSecretResourceGeneration == 0 || !validDigestReference(payload.CurrentSecretBindingDigest)) {
		return invalid("mail DKIM current secret")
	}
	return nil
}
func validateMailMailbox(value any) error {
	mailbox := value.(*MailMailboxPayload).Mailbox
	if !safeMailOpaque(string(mailbox.ID)) || !safeMailOpaque(string(mailbox.Domain)) || !safeMailboxLocal(mailbox.Local) || mailbox.QuotaBytes == 0 || mailbox.QuotaBytes > 1<<50 {
		return invalid("mail mailbox")
	}
	return nil
}
func validateMailAlias(value any) error {
	alias := value.(*MailAliasPayload).Alias
	if !safeMailOpaque(string(alias.ID)) || !safeMailOpaque(string(alias.Domain)) || !safeMailAddress(alias.Source) || len(alias.Targets) == 0 || len(alias.Targets) > 1000 {
		return invalid("mail alias")
	}
	for _, target := range alias.Targets {
		if !safeMailAddress(target) {
			return invalid("mail alias targets")
		}
	}
	switch alias.Capability {
	case "", mail.CapabilityPlus, mail.CapabilityPattern:
		if alias.PipeRef != "" {
			return invalid("mail alias pipe")
		}
	case mail.CapabilityPipe:
		if !safeMailOpaque(alias.PipeRef) {
			return invalid("mail alias pipe")
		}
	default:
		return invalid("mail alias capability")
	}
	return nil
}
func validateMailPolicy(value any) error {
	policy := value.(*MailPolicyPayload).Policy
	if !safeMailOpaque(string(policy.ID)) || policy.MaxMailboxBytes == 0 || policy.MaxMailboxBytes > 1<<50 || policy.MaxRecipients == 0 || policy.MaxRecipients > 10000 || math.IsNaN(policy.SpamThreshold) || math.IsInf(policy.SpamThreshold, 0) || policy.SpamThreshold < -100 || policy.SpamThreshold > 100 || policy.RetainDays > 3650 || policy.Log.RetainDays > 3650 {
		return invalid("mail policy")
	}
	return nil
}
func validateWebmailAccounts(value any) error {
	payload := value.(*WebmailAccountPagePayload)
	if payload.Limit == 0 {
		payload.Limit = 50
	}
	if payload.Limit > securewebmail.MaximumPageSize || len(payload.Cursor) > 256 {
		return invalid("webmail account page")
	}
	return nil
}
func validateWebmailAccountSwitch(value any) error {
	payload := value.(*WebmailAccountSwitchPayload)
	if !safeMailOpaque(payload.PreviousMailboxID) || !safeMailOpaque(payload.TargetMailboxID) || payload.PreviousMailboxID == payload.TargetMailboxID {
		return invalid("webmail account switch")
	}
	return nil
}
func validWebmailEpoch(epoch uint64) bool { return epoch > 0 && epoch <= math.MaxInt64 }
func validWebmailFolder(value string) bool {
	if value == "" || len(value) > 1024 || len([]rune(value)) > securewebmail.MaximumFolderNameRunes || strings.ToValidUTF8(value, "") != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
func validWebmailIdentity(value WebmailMessageIdentity) bool {
	return validWebmailFolder(value.Folder) && value.UIDValidity > 0 && value.UID > 0
}
func validWebmailSort(value securewebmail.MessageSort) bool {
	return value == "" || value == securewebmail.SortNewest || value == securewebmail.SortOldest
}
func validateWebmailFolderPage(value any) error {
	payload := value.(*WebmailFolderPagePayload)
	if payload.Limit == 0 {
		payload.Limit = 50
	}
	if !validWebmailEpoch(payload.AuthorizationEpoch) || payload.Limit > securewebmail.MaximumPageSize || len(payload.Cursor) > 256 {
		return invalid("webmail folder page")
	}
	return nil
}
func validateWebmailFolderMutation(value any) error {
	payload := value.(*WebmailFolderMutationPayload)
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !validWebmailFolder(payload.Name) {
		return invalid("webmail folder mutation")
	}
	switch payload.Operation {
	case securewebmail.FolderCreate, securewebmail.FolderSubscribe, securewebmail.FolderUnsubscribe, securewebmail.FolderEmpty, securewebmail.FolderDelete:
		if payload.NewName != "" {
			return invalid("webmail folder mutation")
		}
	case securewebmail.FolderRename:
		if !validWebmailFolder(payload.NewName) || payload.Name == payload.NewName {
			return invalid("webmail folder mutation")
		}
	default:
		return invalid("webmail folder mutation")
	}
	return nil
}
func validateWebmailMessagePage(value any) error {
	payload := value.(*WebmailMessagePagePayload)
	if payload.Limit == 0 {
		payload.Limit = 50
	}
	if payload.Sort == "" {
		payload.Sort = securewebmail.SortNewest
	}
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !validWebmailFolder(payload.Folder) || payload.Limit > securewebmail.MaximumPageSize || len(payload.Cursor) > 256 || !validWebmailSort(payload.Sort) {
		return invalid("webmail message page")
	}
	return nil
}
func validateSecureWebmailSearch(value any) error {
	payload := value.(*WebmailSearchPayload)
	if payload.Limit == 0 {
		payload.Limit = 50
	}
	if payload.Sort == "" {
		payload.Sort = securewebmail.SortNewest
	}
	criteria := payload.Criteria
	terms := 0
	for _, item := range []string{criteria.Text, criteria.From, criteria.Subject} {
		if item != "" {
			terms++
		}
		if len(item) > securewebmail.MaximumSearchText || strings.ContainsAny(item, "\x00\r\n") {
			return invalid("webmail search")
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
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !validWebmailFolder(payload.Folder) || payload.Limit > securewebmail.MaximumPageSize || len(payload.Cursor) > 256 || !validWebmailSort(payload.Sort) || terms == 0 || terms > securewebmail.MaximumSearchTerms || !criteria.Before.IsZero() && !criteria.Since.IsZero() && !criteria.Before.After(criteria.Since) {
		return invalid("webmail search")
	}
	return nil
}
func validateSecureWebmailRead(value any) error {
	payload := value.(*WebmailReadPayload)
	if payload.RemoteImagePolicy == "" {
		payload.RemoteImagePolicy = securewebmail.RemoteImagesBlocked
	}
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !validWebmailIdentity(payload.Identity) || (payload.RemoteImagePolicy != securewebmail.RemoteImagesBlocked && payload.RemoteImagePolicy != securewebmail.RemoteImagesProxy) {
		return invalid("webmail message read")
	}
	return nil
}
func validateWebmailRemoteImage(value any) error {
	payload := value.(*WebmailRemoteImagePayload)
	if payload.MaximumBytes == 0 {
		payload.MaximumBytes = securewebmail.MaximumRemoteImageBytes
	}
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !validWebmailIdentity(payload.Identity) || !safeMailOpaque(payload.ReferenceID) || len(payload.URL) == 0 || len(payload.URL) > 4096 || !validDigestReference(payload.ExpectedDigest) || payload.MaximumBytes > securewebmail.MaximumRemoteImageBytes {
		return invalid("webmail remote image")
	}
	return nil
}
func validWebmailPart(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character == '.' {
			if index == 0 || index == len(value)-1 {
				return false
			}
			continue
		}
		if character < '0' || character > '9' || index == 0 && character == '0' {
			return false
		}
	}
	return !strings.Contains(value, "..")
}
func validateWebmailAttachmentIssue(value any) error {
	payload := value.(*WebmailAttachmentIssuePayload)
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !validWebmailIdentity(payload.Identity) || !validWebmailPart(payload.PartID) || !safeWebmailFilename(payload.Filename) || !safeWebmailContentType(payload.ContentType) || payload.MaximumBytes == 0 || payload.MaximumBytes > securewebmail.MaximumAttachmentBytes {
		return invalid("webmail attachment")
	}
	return nil
}
func validateWebmailAttachmentLease(value any) error {
	if !safeMailOpaque(value.(*WebmailAttachmentLeasePayload).DownloadID) {
		return invalid("webmail attachment lease")
	}
	return nil
}
func validateWebmailAttachmentRead(value any) error {
	payload := value.(*WebmailAttachmentReadPayload)
	if !safeMailOpaque(payload.DownloadID) || payload.Length == 0 || payload.Length > 1<<20 || payload.Offset > securewebmail.MaximumAttachmentBytes {
		return invalid("webmail attachment range")
	}
	return nil
}
func validateWebmailAttachmentUpload(value any) error {
	payload := value.(*WebmailAttachmentUploadPayload)
	now := time.Now().UTC()
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !safeWebmailFilename(payload.Filename) || !safeWebmailContentType(payload.ContentType) || payload.MaximumBytes == 0 || payload.MaximumBytes > 8<<20 || len(payload.ContentBase64) == 0 || len(payload.ContentBase64) > 12<<20 || strings.ContainsAny(payload.ContentBase64, "\r\n\t ") || !payload.ExpiresAt.After(now) || payload.ExpiresAt.After(now.Add(securewebmail.MaximumUploadLifetime)) {
		return invalid("webmail attachment upload")
	}
	return nil
}
func validateWebmailAttachmentDelete(value any) error {
	payload := value.(*WebmailAttachmentDeletePayload)
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !safeMailOpaque(payload.UploadID) {
		return invalid("webmail attachment delete")
	}
	return nil
}
func safeWebmailFilename(value string) bool {
	return value != "" && len(value) <= 255 && strings.ToValidUTF8(value, "") == value && !strings.ContainsAny(value, "\x00\r\n/\\")
}
func safeWebmailContentType(value string) bool {
	return value != "" && len(value) <= 127 && !strings.ContainsAny(value, "\x00\r\n") && strings.Contains(value, "/")
}
func validWebmailCompose(message WebmailComposePayload, requireRecipients bool) bool {
	if !safeMailOpaque(message.ID) || (message.Mode != securewebmail.ComposeNew && message.Mode != securewebmail.ComposeReply && message.Mode != securewebmail.ComposeReplyAll && message.Mode != securewebmail.ComposeForward) || len(message.Subject) > 998 || strings.ContainsAny(message.Subject, "\x00\r\n") || len(message.PlainText) > securewebmail.MaximumRenderedPartBytes || len(message.SanitizedHTML) > securewebmail.MaximumRenderedPartBytes || len(message.AttachmentIDs) > securewebmail.MaximumComposeAttachments || len(message.References) > 64 {
		return false
	}
	recipients := len(message.To) + len(message.CC) + len(message.BCC)
	if requireRecipients && recipients == 0 || recipients > securewebmail.MaximumRecipients {
		return false
	}
	for _, group := range [][]WebmailComposeAddress{message.To, message.CC, message.BCC, message.ReplyTo} {
		for _, address := range group {
			if address.Address == "" || len(address.Address) > 320 || len(address.Name) > 256 || strings.ContainsAny(address.Address+address.Name, "\x00\r\n") {
				return false
			}
		}
	}
	for _, id := range message.AttachmentIDs {
		if !safeMailOpaque(id) {
			return false
		}
	}
	return message.From.Address != "" && len(message.From.Address) <= 320
}
func validateWebmailDraftSave(value any) error {
	payload := value.(*WebmailDraftSavePayload)
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !validWebmailCompose(payload.Message, false) {
		return invalid("webmail draft")
	}
	return nil
}
func validateSecureWebmailDraft(value any) error {
	payload := value.(*WebmailDraftPayload)
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !safeMailOpaque(payload.DraftID) {
		return invalid("webmail draft")
	}
	return nil
}
func validateSecureWebmailSend(value any) error {
	payload := value.(*WebmailSendPayload)
	if !validWebmailEpoch(payload.AuthorizationEpoch) || !validWebmailCompose(payload.Message, true) {
		return invalid("webmail send")
	}
	return nil
}
func validateWebmailMessageAction(value any) error {
	payload := value.(*WebmailMessageActionPayload)
	if !validWebmailEpoch(payload.AuthorizationEpoch) || len(payload.Messages) == 0 || len(payload.Messages) > securewebmail.MaximumMessageBatch {
		return invalid("webmail message action")
	}
	for _, message := range payload.Messages {
		if !validWebmailIdentity(message) {
			return invalid("webmail message action")
		}
	}
	switch payload.Action {
	case securewebmail.ActionMove, securewebmail.ActionCopy, securewebmail.ActionArchive, securewebmail.ActionSpam, securewebmail.ActionNotSpam:
		if !validWebmailFolder(payload.TargetFolder) {
			return invalid("webmail message action")
		}
	case securewebmail.ActionDelete, securewebmail.ActionUndelete, securewebmail.ActionRead, securewebmail.ActionUnread, securewebmail.ActionFlag, securewebmail.ActionUnflag:
		if payload.TargetFolder != "" {
			return invalid("webmail message action")
		}
	default:
		return invalid("webmail message action")
	}
	return nil
}

func mailListScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if request.ResourceID != "" || request.ExpectedGeneration != 0 {
		return identity.Scope{}, invalid("mail list scope")
	}
	return tenantScope(request, value)
}
func mailGetScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !safeMailOpaque(request.ResourceID) || request.ExpectedGeneration != 0 {
		return identity.Scope{}, invalid("mail resource scope")
	}
	return tenantScope(request, value)
}
func mailCreateScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !safeMailOpaque(request.ResourceID) || request.ExpectedGeneration != 0 {
		return identity.Scope{}, invalid("mail create scope")
	}
	return tenantScope(request, value)
}
func mailExistingScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !safeMailOpaque(request.ResourceID) || request.ExpectedGeneration == 0 {
		return identity.Scope{}, invalid("mail resource generation")
	}
	return tenantScope(request, value)
}
func webmailScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !safeMailOpaque(request.ResourceID) {
		return identity.Scope{}, invalid("webmail mailbox scope")
	}
	return tenantScope(request, value)
}

func safeMailOpaque(value string) bool {
	if value == "" || len(value) > 160 {
		return false
	}
	for index := range value {
		character := value[index]
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}
func safeMailToken(value string) bool {
	for index := range value {
		character := value[index]
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
			return false
		}
	}
	return true
}
func validateWebmailSession(session mail.MailSession) error {
	if !safeMailOpaque(session.ID) || len(session.Token) < 64 || len(session.Token) > 4096 || !safeMailToken(session.Token) || session.ExpiresAt.IsZero() || session.ExpiresAt.Before(time.Now().Add(-time.Minute)) || session.ExpiresAt.After(time.Now().Add(31*time.Minute)) {
		return invalid("mail session")
	}
	return nil
}
func validOptionalMailbox(value mail.MailboxID) bool {
	return value == "" || safeMailOpaque(string(value))
}
func mailSession(inv Invocation, session mail.MailSession) mail.MailSession {
	session.TenantID = inv.Request.TenantID
	session.PrincipalID = inv.Actor.PrincipalID.String()
	session.AuthzEpoch = inv.Actor.AuthzEpoch
	return session
}
func boundWebmailSession(ctx context.Context, service *mail.WebmailService, inv Invocation, session mail.MailSession, selected mail.MailboxID) (mail.MailSession, error) {
	bound := mailSession(inv, session)
	verified, err := service.ResolveSession(ctx, bound)
	if err != nil {
		return mail.MailSession{}, mapMailError(err)
	}
	if string(verified.MailboxID) != inv.Request.ResourceID || selected != "" && selected != verified.MailboxID {
		return mail.MailSession{}, ErrForbidden
	}
	return bound, nil
}
func safeMailLabel(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for index := range value {
		character := value[index]
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return true
}
func validMailHostname(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if len(value) < 3 || len(value) > 253 || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !safeMailLabel(label, 63) || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
func safeMailboxLocal(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '.' || value[len(value)-1] == '.' || strings.Contains(value, "..") {
		return false
	}
	for index := range value {
		character := value[index]
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune(".!#$%&'*+-=?^_`{|}~", rune(character))) {
			return false
		}
	}
	return true
}
func safeMailAddress(value mail.Address) bool {
	raw := strings.ToLower(strings.TrimSpace(string(value)))
	if len(raw) > 254 || strings.Count(raw, "@") != 1 {
		return false
	}
	parts := strings.SplitN(raw, "@", 2)
	return safeMailboxLocal(parts[0]) && validMailHostname(parts[1])
}
func safeCompose(message mail.ComposeMessage) bool {
	if len(message.Subject) > 998 || strings.ContainsAny(message.Subject, "\x00\r\n") || len(message.Text) > 1<<20 || len(message.SanitizedHTML) > 1<<20 || strings.Contains(message.Text, "\x00") || strings.Contains(message.SanitizedHTML, "\x00") || len(message.AttachmentBlobRefs) > 100 {
		return false
	}
	total := len(message.To) + len(message.CC) + len(message.BCC)
	if total == 0 || total > 500 {
		return false
	}
	for _, address := range append(append(append([]mail.Address{}, message.To...), message.CC...), message.BCC...) {
		if !safeMailAddress(address) {
			return false
		}
	}
	for _, reference := range message.AttachmentBlobRefs {
		if !safeMailOpaque(reference) {
			return false
		}
	}
	return message.InReplyTo == "" || safeMailOpaque(string(message.InReplyTo))
}

func bindMail(registry *Registry, services DomainServices) error {
	if err := bindMailboxPassword(registry, services.MailboxPasswords); err != nil {
		return err
	}
	if services.MailControl != nil && services.MailControl.Store != nil {
		for name, kind := range map[string]mail.ResourceKind{"mail.domain.list": mail.ResourceDomain, "mail.mailbox.list": mail.ResourceMailbox, "mail.alias.list": mail.ResourceAlias, "mail.policy.list": mail.ResourcePolicy} {
			name, kind := name, kind
			if err := registry.Bind(name, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				page := value.(*MailPagePayload)
				items, next, err := services.MailControl.Store.List(ctx, inv.Request.TenantID, kind, int(page.Limit), page.Cursor)
				if err != nil {
					return OperationResult{}, mapMailError(err)
				}
				return OperationResult{Status: http.StatusOK, Value: MailPageResult{Items: items, NextCursor: next}}, nil
			}); err != nil {
				return err
			}
		}
		for name, kind := range map[string]mail.ResourceKind{"mail.domain.get": mail.ResourceDomain, "mail.mailbox.get": mail.ResourceMailbox, "mail.alias.get": mail.ResourceAlias, "mail.policy.get": mail.ResourcePolicy} {
			name, kind := name, kind
			if err := registry.Bind(name, func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
				resource, found, err := services.MailControl.Store.Load(ctx, inv.Request.TenantID, kind, inv.Request.ResourceID)
				if err != nil {
					return OperationResult{}, mapMailError(err)
				}
				if !found {
					return OperationResult{}, ErrNotFound
				}
				return OperationResult{Status: http.StatusOK, Value: resource, Generation: resource.Generation}, nil
			}); err != nil {
				return err
			}
		}
		bindings := []struct {
			name    string
			kind    mail.ResourceKind
			action  mail.Action
			payload func(any) (any, string)
		}{
			{"mail.domain.create", mail.ResourceDomain, mail.ActionCreate, domainMailResource}, {"mail.domain.update", mail.ResourceDomain, mail.ActionUpdate, domainMailResource}, {"mail.domain.delete", mail.ResourceDomain, mail.ActionDelete, nil},
			{"mail.mailbox.create", mail.ResourceMailbox, mail.ActionCreate, mailboxMailResource}, {"mail.mailbox.update", mail.ResourceMailbox, mail.ActionUpdate, mailboxMailResource}, {"mail.mailbox.delete", mail.ResourceMailbox, mail.ActionDelete, nil},
			{"mail.alias.create", mail.ResourceAlias, mail.ActionCreate, aliasMailResource}, {"mail.alias.update", mail.ResourceAlias, mail.ActionUpdate, aliasMailResource}, {"mail.alias.delete", mail.ResourceAlias, mail.ActionDelete, nil},
			{"mail.policy.create", mail.ResourcePolicy, mail.ActionCreate, policyMailResource}, {"mail.policy.update", mail.ResourcePolicy, mail.ActionUpdate, policyMailResource}, {"mail.policy.delete", mail.ResourcePolicy, mail.ActionDelete, nil},
		}
		for _, binding := range bindings {
			binding := binding
			if err := registry.Bind(binding.name, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				command := newMailCommand(inv, binding.kind, binding.action)
				if binding.payload != nil {
					resource, id := binding.payload(value)
					if id != inv.Request.ResourceID {
						return OperationResult{}, invalid("mail resource identity")
					}
					switch typed := resource.(type) {
					case mail.Domain:
						typed.Tenant = inv.Request.TenantID
						command.Domain = &typed
					case mail.Mailbox:
						command.Mailbox = &typed
					case mail.Alias:
						command.Alias = &typed
					case mail.Policy:
						command.Policy = &typed
					}
				}
				receipt, err := services.MailControl.Handle(ctx, command)
				if err != nil {
					return OperationResult{}, mapMailError(err)
				}
				return OperationResult{Status: http.StatusOK, Value: receipt, Generation: receipt.Request.Generation}, nil
			}); err != nil {
				return err
			}
		}
		if rotation := services.MailControl.DKIMRotation; rotation != nil {
			if err := registry.Bind("mail.domain.dkim.prepare", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				payload := value.(*MailDKIMPreparePayload)
				var proof *mail.DKIMSecretProof
				if payload.CurrentSecretVersion != 0 {
					proof = &mail.DKIMSecretProof{Version: payload.CurrentSecretVersion, BindingDigest: payload.CurrentSecretBindingDigest, ResourceGeneration: payload.CurrentSecretResourceGeneration}
				}
				status, err := rotation.Prepare(ctx, mail.DKIMPrepareRequest{TenantID: inv.Request.TenantID, DomainID: mail.DomainID(inv.Request.ResourceID), ExpectedGeneration: inv.Request.ExpectedGeneration, OperationID: commandID(inv), Overlap: time.Duration(payload.OverlapSeconds) * time.Second, CurrentSecret: proof})
				if err != nil {
					return OperationResult{}, mapMailError(err)
				}
				return OperationResult{Status: http.StatusCreated, Value: status, Generation: status.CurrentGeneration}, nil
			}); err != nil {
				return err
			}
			if err := registry.Bind("mail.domain.dkim.status", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
				status, err := rotation.Status(ctx, inv.Request.TenantID, mail.DomainID(inv.Request.ResourceID))
				if err != nil {
					return OperationResult{}, mapMailError(err)
				}
				return OperationResult{Status: http.StatusOK, Value: status, Generation: status.CurrentGeneration}, nil
			}); err != nil {
				return err
			}
			if err := registry.Bind("mail.domain.dkim.activate", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				status, err := rotation.Activate(ctx, mail.DKIMActivateRequest{TenantID: inv.Request.TenantID, DomainID: mail.DomainID(inv.Request.ResourceID), ExpectedGeneration: inv.Request.ExpectedGeneration, ConfirmPrevious: value.(*MailDKIMActivatePayload).ConfirmPrevious})
				if err != nil {
					return OperationResult{}, mapMailError(err)
				}
				return OperationResult{Status: http.StatusOK, Value: status, Generation: status.CurrentGeneration}, nil
			}); err != nil {
				return err
			}
		}
	}
	if services.MailQueue != nil {
		if err := registry.Bind("mail.queue.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			page := value.(*MailPagePayload)
			if page.Cursor != "" {
				return OperationResult{}, ErrInvalidRequest
			}
			items, evidence, err := services.MailQueue.ListQueue(ctx, uint32(page.Limit))
			if err != nil {
				return OperationResult{}, mapMailError(err)
			}
			return OperationResult{Status: http.StatusOK, Value: map[string]any{"items": items, "evidence_digest": evidence}}, nil
		}); err != nil {
			return err
		}
		for _, name := range []string{"mail.queue.get", "mail.queue.inspect"} {
			name := name
			if err := registry.Bind(name, func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
				items, evidence, err := services.MailQueue.ListQueue(ctx, 10000)
				if err != nil {
					return OperationResult{}, mapMailError(err)
				}
				for _, item := range items {
					if string(item.ID) == inv.Request.ResourceID {
						return OperationResult{Status: http.StatusOK, Value: map[string]any{"item": item, "evidence_digest": evidence}}, nil
					}
				}
				return OperationResult{}, ErrNotFound
			}); err != nil {
				return err
			}
		}
		for name, action := range map[string]mail.MailQueueAction{"mail.queue.retry": mail.QueueRetry, "mail.queue.cancel": mail.QueueDelete, "mail.queue.delete": mail.QueueDelete} {
			name, action := name, action
			if err := registry.Bind(name, func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
				receipt, err := services.MailQueue.Queue(ctx, action, mail.QueueID(inv.Request.ResourceID))
				if err != nil {
					return OperationResult{}, mapMailError(err)
				}
				return OperationResult{Status: http.StatusOK, Value: receipt}, nil
			}); err != nil {
				return err
			}
		}
		if err := registry.Bind("mail.queue.flush", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			receipt, err := services.MailQueue.Queue(ctx, mail.QueueFlush, "")
			if err != nil {
				return OperationResult{}, mapMailError(err)
			}
			return OperationResult{Status: http.StatusOK, Value: receipt}, nil
		}); err != nil {
			return err
		}
	}
	provider, ok := services.WebmailEdge.(interface{ SecureWebmail() *securewebmail.Service })
	if ok && provider.SecureWebmail() != nil {
		return bindSecureWebmail(registry, provider.SecureWebmail())
	}
	return nil
}

func newMailCommand(inv Invocation, kind mail.ResourceKind, action mail.Action) mail.Command {
	sum := sha256.Sum256([]byte(inv.IdempotencyKey))
	commandSum := sha256.Sum256([]byte(inv.Request.TenantID + "\x00" + inv.Actor.PrincipalID.String() + "\x00" + inv.Request.Operation + "\x00" + inv.IdempotencyKey))
	return mail.Command{ID: "mailcmd_" + hex.EncodeToString(commandSum[:])[:48], IdempotencyKey: "api_" + hex.EncodeToString(sum[:]), ActorID: inv.Actor.PrincipalID.String(), TenantID: inv.Request.TenantID, Kind: kind, ResourceID: inv.Request.ResourceID, ExpectedGeneration: inv.Request.ExpectedGeneration, Action: action}
}
func newMailCommandForResource(inv Invocation, kind mail.ResourceKind, action mail.Action, resource string, generation uint64) mail.Command {
	sum := sha256.Sum256([]byte(inv.IdempotencyKey + "\x00" + resource))
	commandSum := sha256.Sum256([]byte(inv.Request.TenantID + "\x00" + inv.Actor.PrincipalID.String() + "\x00" + inv.Request.Operation + "\x00" + inv.IdempotencyKey + "\x00" + resource))
	return mail.Command{ID: "mailcmd_" + hex.EncodeToString(commandSum[:])[:48], IdempotencyKey: "api_" + hex.EncodeToString(sum[:]), ActorID: inv.Actor.PrincipalID.String(), TenantID: inv.Request.TenantID, Kind: kind, ResourceID: resource, ExpectedGeneration: generation, Action: action}
}
func domainMailResource(value any) (any, string) {
	resource := value.(*MailDomainPayload).Domain
	return resource, string(resource.ID)
}
func mailboxMailResource(value any) (any, string) {
	resource := value.(*MailMailboxPayload).Mailbox
	return resource, string(resource.ID)
}
func aliasMailResource(value any) (any, string) {
	resource := value.(*MailAliasPayload).Alias
	return resource, string(resource.ID)
}
func policyMailResource(value any) (any, string) {
	resource := value.(*MailPolicyPayload).Policy
	return resource, string(resource.ID)
}

const webmailDownloadChunkSize = 1 << 20
const webmailDownloadLifetime = 2 * time.Minute
const maximumWebmailDownloads = 128

type webmailDownloadOwner struct{ tenantID, userID, sessionID, mailboxID string }
type webmailDownloadLease struct {
	mutex              sync.Mutex
	owner              webmailDownloadOwner
	result             WebmailAttachmentLeaseResult
	body               io.ReadCloser
	offset, lastOffset uint64
	lastContent        []byte
}
type webmailDownloadStore struct {
	mutex sync.Mutex
	items map[string]*webmailDownloadLease
}

var secureWebmailDownloads = &webmailDownloadStore{items: map[string]*webmailDownloadLease{}}

func secureWebmailPrincipal(inv Invocation) (securewebmail.Principal, error) {
	sessionID := inv.Actor.SessionID.String()
	if sessionID == "" {
		sessionID = inv.Actor.CredentialID.String()
	}
	principal := securewebmail.Principal{UserID: inv.Actor.PrincipalID.String(), SessionID: sessionID}
	if !safeMailOpaque(principal.UserID) || !safeMailOpaque(principal.SessionID) {
		return securewebmail.Principal{}, ErrForbidden
	}
	return principal, nil
}
func secureWebmailMailbox(ctx context.Context, service *securewebmail.Service, inv Invocation, epoch uint64) (securewebmail.MailboxContext, error) {
	principal, err := secureWebmailPrincipal(inv)
	if err != nil {
		return securewebmail.MailboxContext{}, err
	}
	issued, err := service.IssueGrant(ctx, principal, inv.Request.TenantID, inv.Request.ResourceID, inv.Request.RequestID)
	if err != nil {
		return securewebmail.MailboxContext{}, mapSecureWebmailError(err)
	}
	return securewebmail.MailboxContext{Principal: principal, TenantID: inv.Request.TenantID, MailboxID: inv.Request.ResourceID, Audience: "cyberpanel-webmail", AuthorizationEpoch: epoch, Grant: issued.Token, RequestID: inv.Request.RequestID}, nil
}
func secureWebmailOwner(inv Invocation) (webmailDownloadOwner, error) {
	principal, err := secureWebmailPrincipal(inv)
	if err != nil {
		return webmailDownloadOwner{}, err
	}
	return webmailDownloadOwner{tenantID: inv.Request.TenantID, userID: principal.UserID, sessionID: principal.SessionID, mailboxID: inv.Request.ResourceID}, nil
}
func (owner webmailDownloadOwner) valid() bool {
	return safeMailOpaque(owner.tenantID) && safeMailOpaque(owner.userID) && safeMailOpaque(owner.sessionID) && safeMailOpaque(owner.mailboxID)
}

func coreWebmailIdentity(value WebmailMessageIdentity) securewebmail.MessageIdentity {
	return securewebmail.MessageIdentity{Folder: value.Folder, UIDValidity: value.UIDValidity, UID: value.UID}
}
func apiWebmailIdentity(value securewebmail.MessageIdentity) WebmailMessageIdentity {
	return WebmailMessageIdentity{Folder: value.Folder, UIDValidity: value.UIDValidity, UID: value.UID}
}
func coreWebmailAddress(value WebmailComposeAddress) securewebmail.ComposeAddress {
	return securewebmail.ComposeAddress{Name: value.Name, Address: value.Address}
}
func apiWebmailAddress(value securewebmail.ComposeAddress) WebmailComposeAddress {
	return WebmailComposeAddress{Name: value.Name, Address: value.Address}
}
func coreWebmailAddresses(values []WebmailComposeAddress) []securewebmail.ComposeAddress {
	items := make([]securewebmail.ComposeAddress, len(values))
	for index, value := range values {
		items[index] = coreWebmailAddress(value)
	}
	return items
}
func apiWebmailAddresses(values []securewebmail.ComposeAddress) []WebmailComposeAddress {
	items := make([]WebmailComposeAddress, len(values))
	for index, value := range values {
		items[index] = apiWebmailAddress(value)
	}
	return items
}
func coreWebmailCompose(value WebmailComposePayload) securewebmail.ComposeMessage {
	return securewebmail.ComposeMessage{ID: value.ID, Mode: value.Mode, From: coreWebmailAddress(value.From), To: coreWebmailAddresses(value.To), CC: coreWebmailAddresses(value.CC), BCC: coreWebmailAddresses(value.BCC), ReplyTo: coreWebmailAddresses(value.ReplyTo), Subject: value.Subject, PlainText: value.PlainText, SanitizedHTML: value.SanitizedHTML, InReplyTo: value.InReplyTo, References: append([]string(nil), value.References...), AttachmentIDs: append([]string(nil), value.AttachmentIDs...), SendAt: value.SendAt}
}
func apiWebmailCompose(value securewebmail.ComposeMessage) WebmailComposePayload {
	return WebmailComposePayload{ID: value.ID, Mode: value.Mode, From: apiWebmailAddress(value.From), To: apiWebmailAddresses(value.To), CC: apiWebmailAddresses(value.CC), BCC: apiWebmailAddresses(value.BCC), ReplyTo: apiWebmailAddresses(value.ReplyTo), Subject: value.Subject, PlainText: value.PlainText, SanitizedHTML: value.SanitizedHTML, InReplyTo: value.InReplyTo, References: append([]string(nil), value.References...), AttachmentIDs: append([]string(nil), value.AttachmentIDs...), SendAt: value.SendAt}
}
func apiWebmailAccountPage(value securewebmail.AccountPage) WebmailAccountPageResult {
	items := make([]WebmailAccountProjection, len(value.Accounts))
	for index, account := range value.Accounts {
		items[index] = WebmailAccountProjection{ID: account.MailboxID, DisplayLabel: account.DisplayLabel, Address: account.AddressLabel, AuthorizationEpoch: account.AuthorizationEpoch}
	}
	return WebmailAccountPageResult{Items: items, NextCursor: value.NextCursor}
}
func apiWebmailFolderPage(value securewebmail.FolderPage) WebmailFolderPageResult {
	items := make([]WebmailFolderProjection, len(value.Folders))
	for index, folder := range value.Folders {
		delimiter := ""
		if folder.Delimiter != 0 {
			delimiter = string(folder.Delimiter)
		}
		items[index] = WebmailFolderProjection{Name: folder.Name, Parent: folder.Parent, Delimiter: delimiter, Subscribed: folder.Subscribed, HasChildren: folder.HasChildren, Role: folder.SpecialUse, Messages: folder.Messages, Unseen: folder.Unseen, UIDNext: folder.UIDNext, UIDValidity: folder.UIDValidity, HighestModSeq: folder.HighestModSeq, Quota: folder.Quota}
	}
	return WebmailFolderPageResult{Items: items, NextCursor: value.NextCursor, Partial: value.Partial}
}
func apiWebmailAddressProjection(value securewebmail.Address) WebmailAddressProjection {
	address := value.Mailbox
	if value.Host != "" {
		address += "@" + value.Host
	}
	return WebmailAddressProjection{Name: value.Name, Address: address}
}
func apiWebmailFlags(values []string) []string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "\\"))
		if value != "" {
			items = append(items, value)
		}
	}
	return items
}
func apiWebmailMessageSummary(value securewebmail.MessageSummary) WebmailMessageSummaryProjection {
	return WebmailMessageSummaryProjection{Identity: apiWebmailIdentity(value.Identity), ModSeq: value.ModSeq, ThreadID: value.ThreadID, Flags: apiWebmailFlags(value.Flags), Sender: apiWebmailAddressProjection(value.Sender), Subject: value.Subject, Date: value.Date, Size: value.Size, HasAttachment: value.HasAttachment}
}
func apiWebmailMessagePage(value securewebmail.MessagePage) WebmailMessagePageResult {
	items := make([]WebmailMessageSummaryProjection, len(value.Messages))
	for index, message := range value.Messages {
		items[index] = apiWebmailMessageSummary(message)
	}
	return WebmailMessagePageResult{Folder: value.Folder, UIDValidity: value.UIDValidity, HighestModSeq: value.HighestModSeq, Items: items, NextCursor: value.NextCursor, Partial: value.Partial}
}
func apiWebmailSearchPage(value securewebmail.SearchPage) WebmailSearchPageResult {
	items := make([]WebmailMessageIdentity, len(value.Identities))
	for index, message := range value.Identities {
		items[index] = apiWebmailIdentity(message)
	}
	return WebmailSearchPageResult{Folder: value.Folder, UIDValidity: value.UIDValidity, HighestModSeq: value.HighestModSeq, Items: items, NextCursor: value.NextCursor, Partial: value.Partial}
}
func apiWebmailRenderedMessage(value securewebmail.RenderedMessage) WebmailRenderedMessageResult {
	attachments := make([]WebmailAttachmentReference, len(value.Attachments))
	for index, attachment := range value.Attachments {
		attachments[index] = WebmailAttachmentReference{PartID: attachment.PartID, Filename: attachment.Filename, ContentType: attachment.ContentType, Size: attachment.Size}
	}
	images := make([]WebmailRemoteImageProjection, len(value.RemoteImages))
	for index, image := range value.RemoteImages {
		images[index] = WebmailRemoteImageProjection{ID: image.ID, URL: image.URL, Digest: image.URLDigest, Blocked: image.Blocked}
	}
	return WebmailRenderedMessageResult{Identity: apiWebmailIdentity(value.Identity), PlainText: value.PlainText, SanitizedHTML: value.SanitizedHTML, CSP: value.CSP, ReferrerPolicy: value.ReferrerPolicy, RemoteImages: images, Attachments: attachments}
}
func apiWebmailBlob(value securewebmail.BlobInfo) WebmailBlobResult {
	return WebmailBlobResult{ID: value.ID, Filename: value.Filename, ContentType: value.ContentType, Size: value.Size, Digest: value.Digest, ExpiresAt: value.ExpiresAt}
}
func apiWebmailDraft(value securewebmail.Draft) WebmailDraftResult {
	return WebmailDraftResult{Revision: value.Revision, Message: apiWebmailCompose(value.Message), UpdatedAt: value.UpdatedAt}
}

func (store *webmailDownloadStore) pruneLocked(now time.Time) {
	for id, lease := range store.items {
		if !lease.result.ExpiresAt.After(now) {
			delete(store.items, id)
			lease.mutex.Lock()
			clearSecret(lease.lastContent)
			lease.lastContent = nil
			_ = lease.body.Close()
			lease.mutex.Unlock()
		}
	}
}
func (store *webmailDownloadStore) issue(inv Invocation, download securewebmail.AttachmentDownload) (WebmailAttachmentLeaseResult, error) {
	owner, err := secureWebmailOwner(inv)
	if err != nil || !owner.valid() || download.Body == nil || download.Size > securewebmail.MaximumAttachmentBytes || !validDigestReference(download.Digest) || !safeWebmailFilename(download.Filename) || !safeWebmailContentType(download.ContentType) {
		if download.Body != nil {
			_ = download.Body.Close()
		}
		if err != nil {
			return WebmailAttachmentLeaseResult{}, err
		}
		return WebmailAttachmentLeaseResult{}, ErrUnavailable
	}
	disposition := download.Disposition
	if disposition != "inline" {
		disposition = "attachment"
	}
	sum := sha256.Sum256([]byte(effectID(inv) + "\x00" + download.Digest))
	id := "wmd_" + hex.EncodeToString(sum[:])[:48]
	expiresAt := time.Now().UTC().Add(webmailDownloadLifetime)
	result := WebmailAttachmentLeaseResult{ID: id, Filename: download.Filename, ContentType: download.ContentType, Disposition: disposition, Size: download.Size, Digest: download.Digest, MalwareState: download.MalwareState, ExpiresAt: expiresAt, DownloadURL: "/api/v1/webmail/attachments/" + url.PathEscape(id) + "?tenant_id=" + url.QueryEscape(owner.tenantID) + "&mailbox_id=" + url.QueryEscape(owner.mailboxID)}
	lease := &webmailDownloadLease{owner: owner, result: result, body: download.Body}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.pruneLocked(time.Now().UTC())
	if len(store.items) >= maximumWebmailDownloads {
		_ = download.Body.Close()
		return WebmailAttachmentLeaseResult{}, ErrRateLimited
	}
	if _, exists := store.items[id]; exists {
		_ = download.Body.Close()
		return WebmailAttachmentLeaseResult{}, ErrConflict
	}
	store.items[id] = lease
	return result, nil
}
func (store *webmailDownloadStore) get(inv Invocation, id string) (WebmailAttachmentLeaseResult, error) {
	owner, err := secureWebmailOwner(inv)
	if err != nil {
		return WebmailAttachmentLeaseResult{}, err
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.pruneLocked(time.Now().UTC())
	lease, exists := store.items[id]
	if !exists {
		return WebmailAttachmentLeaseResult{}, ErrNotFound
	}
	if lease.owner != owner {
		return WebmailAttachmentLeaseResult{}, ErrForbidden
	}
	return lease.result, nil
}
func (store *webmailDownloadStore) read(ctx context.Context, inv Invocation, payload WebmailAttachmentReadPayload) (WebmailAttachmentReadResult, error) {
	owner, err := secureWebmailOwner(inv)
	if err != nil {
		return WebmailAttachmentReadResult{}, err
	}
	store.mutex.Lock()
	store.pruneLocked(time.Now().UTC())
	lease, exists := store.items[payload.DownloadID]
	if !exists {
		store.mutex.Unlock()
		return WebmailAttachmentReadResult{}, ErrNotFound
	}
	if lease.owner != owner {
		store.mutex.Unlock()
		return WebmailAttachmentReadResult{}, ErrForbidden
	}
	lease.mutex.Lock()
	store.mutex.Unlock()
	defer lease.mutex.Unlock()
	if err = ctx.Err(); err != nil {
		return WebmailAttachmentReadResult{}, err
	}
	if payload.Offset == lease.lastOffset && len(lease.lastContent) == int(payload.Length) {
		content := append([]byte(nil), lease.lastContent...)
		encoded := base64.RawStdEncoding.EncodeToString(content)
		clearSecret(content)
		return WebmailAttachmentReadResult{DownloadID: payload.DownloadID, Offset: payload.Offset, ContentBase64: encoded}, nil
	}
	if payload.Offset != lease.offset || payload.Offset > lease.result.Size || uint64(payload.Length) > lease.result.Size-payload.Offset {
		return WebmailAttachmentReadResult{}, ErrConflict
	}
	content := make([]byte, payload.Length)
	read, readErr := io.ReadFull(lease.body, content)
	if readErr != nil || read != len(content) {
		clearSecret(content)
		return WebmailAttachmentReadResult{}, ErrUnavailable
	}
	clearSecret(lease.lastContent)
	lease.lastOffset = payload.Offset
	lease.lastContent = append(lease.lastContent[:0], content...)
	lease.offset += uint64(read)
	encoded := base64.RawStdEncoding.EncodeToString(content)
	clearSecret(content)
	return WebmailAttachmentReadResult{DownloadID: payload.DownloadID, Offset: payload.Offset, ContentBase64: encoded}, nil
}
func (store *webmailDownloadStore) close(inv Invocation, id string) error {
	owner, err := secureWebmailOwner(inv)
	if err != nil {
		return err
	}
	store.mutex.Lock()
	lease, exists := store.items[id]
	if !exists {
		store.mutex.Unlock()
		return nil
	}
	if lease.owner != owner {
		store.mutex.Unlock()
		return ErrForbidden
	}
	delete(store.items, id)
	store.mutex.Unlock()
	lease.mutex.Lock()
	defer lease.mutex.Unlock()
	clearSecret(lease.lastContent)
	lease.lastContent = nil
	return lease.body.Close()
}

func bindSecureWebmail(registry *Registry, service *securewebmail.Service) error {
	accounts := func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		principal, err := secureWebmailPrincipal(inv)
		if err != nil {
			return OperationResult{}, err
		}
		payload := value.(*WebmailAccountPagePayload)
		page, err := service.ListAccounts(ctx, principal, inv.Request.TenantID, payload.Limit, payload.Cursor)
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: apiWebmailAccountPage(page)}, nil
	}
	if err := registry.Bind("webmail.account.list", accounts); err != nil {
		return err
	}
	if err := registry.Bind("webmail.mailbox.list", accounts); err != nil {
		return err
	}
	if err := registry.Bind("webmail.account.switch", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		principal, err := secureWebmailPrincipal(inv)
		if err != nil {
			return OperationResult{}, err
		}
		payload := value.(*WebmailAccountSwitchPayload)
		issued, err := service.SwitchAccount(ctx, principal, inv.Request.TenantID, payload.PreviousMailboxID, payload.TargetMailboxID, inv.Request.RequestID)
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusCreated, Value: map[string]any{"mailbox_id": payload.TargetMailboxID, "expires_at": issued.ExpiresAt}}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.folder.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailFolderPagePayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		page, err := service.ListFolders(ctx, mailbox, securewebmail.FolderPageRequest{Limit: payload.Limit, Cursor: payload.Cursor})
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: apiWebmailFolderPage(page)}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.folder.mutate", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailFolderMutationPayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		err = service.MutateFolder(ctx, mailbox, securewebmail.FolderMutationRequest{Operation: payload.Operation, Name: payload.Name, NewName: payload.NewName})
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: map[string]string{"status": "updated"}}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.message.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailMessagePagePayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		page, err := service.ListMessages(ctx, mailbox, securewebmail.MessagePageRequest{Folder: payload.Folder, Limit: payload.Limit, Cursor: payload.Cursor, Sort: payload.Sort, Threaded: payload.Threaded})
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: apiWebmailMessagePage(page)}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.message.search", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailSearchPayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		criteria := payload.Criteria
		page, err := service.Search(ctx, mailbox, securewebmail.SearchRequest{Folder: payload.Folder, Criteria: securewebmail.SearchCriteria{Text: criteria.Text, From: criteria.From, Subject: criteria.Subject, Since: criteria.Since, Before: criteria.Before, Seen: criteria.Seen, Flagged: criteria.Flagged, HasAttachment: criteria.HasAttachment}, Limit: payload.Limit, Cursor: payload.Cursor, Sort: payload.Sort})
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: apiWebmailSearchPage(page)}, nil
	}); err != nil {
		return err
	}
	read := func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailReadPayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		message, err := service.ReadMessage(ctx, mailbox, securewebmail.MessageReadRequest{Identity: coreWebmailIdentity(payload.Identity), RemoteImagePolicy: payload.RemoteImagePolicy})
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: apiWebmailRenderedMessage(message)}, nil
	}
	if err := registry.Bind("webmail.message.read", read); err != nil {
		return err
	}
	if err := registry.Bind("webmail.message.get", read); err != nil {
		return err
	}
	if err := registry.Bind("webmail.remote_image.fetch", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailRemoteImagePayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		image, err := service.ProxyRemoteImage(ctx, mailbox, securewebmail.RemoteImageRequest{Identity: coreWebmailIdentity(payload.Identity), ReferenceID: payload.ReferenceID, URL: payload.URL, ExpectedDigest: payload.ExpectedDigest, MaximumBytes: payload.MaximumBytes})
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		if image.Body == nil {
			return OperationResult{}, ErrUnavailable
		}
		if image.Size > payload.MaximumBytes {
			_ = image.Body.Close()
			return OperationResult{}, ErrUnavailable
		}
		content, readErr := io.ReadAll(io.LimitReader(image.Body, int64(payload.MaximumBytes)+1))
		closeErr := image.Body.Close()
		if readErr != nil || closeErr != nil || uint64(len(content)) > payload.MaximumBytes || uint64(len(content)) != image.Size {
			clearSecret(content)
			return OperationResult{}, ErrUnavailable
		}
		encoded := base64.RawStdEncoding.EncodeToString(content)
		clearSecret(content)
		return OperationResult{Status: http.StatusOK, Value: WebmailRemoteImageResult{ContentType: image.ContentType, ContentBase64: encoded, Size: image.Size, CacheControl: image.CacheControl, ReferrerPolicy: image.ReferrerPolicy}}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.attachment.issue", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailAttachmentIssuePayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		download, err := service.DownloadAttachment(ctx, mailbox, securewebmail.AttachmentRequest{Identity: coreWebmailIdentity(payload.Identity), PartID: payload.PartID, Filename: payload.Filename, ContentType: payload.ContentType, Disposition: "attachment", MaximumBytes: payload.MaximumBytes, Preview: payload.Preview})
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		lease, err := secureWebmailDownloads.issue(inv, download)
		if err != nil {
			return OperationResult{}, err
		}
		return OperationResult{Status: http.StatusCreated, Value: lease}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.attachment.get", func(_ context.Context, inv Invocation, value any) (OperationResult, error) {
		lease, err := secureWebmailDownloads.get(inv, value.(*WebmailAttachmentLeasePayload).DownloadID)
		if err != nil {
			return OperationResult{}, err
		}
		return OperationResult{Status: http.StatusOK, Value: lease}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.attachment.read", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		chunk, err := secureWebmailDownloads.read(ctx, inv, *value.(*WebmailAttachmentReadPayload))
		if err != nil {
			return OperationResult{}, err
		}
		return OperationResult{Status: http.StatusOK, Value: chunk}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.attachment.close", func(_ context.Context, inv Invocation, value any) (OperationResult, error) {
		if err := secureWebmailDownloads.close(inv, value.(*WebmailAttachmentLeasePayload).DownloadID); err != nil {
			return OperationResult{}, err
		}
		return OperationResult{Status: http.StatusOK, Value: map[string]string{"status": "closed"}}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.attachment.upload", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailAttachmentUploadPayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(payload.ContentBase64))
		blob, err := service.UploadAttachment(ctx, mailbox, securewebmail.UploadRequest{Filename: payload.Filename, ContentType: payload.ContentType, MaximumBytes: payload.MaximumBytes, ExpiresAt: payload.ExpiresAt}, decoder)
		payload.ContentBase64 = ""
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusCreated, Value: apiWebmailBlob(blob)}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.attachment.delete", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailAttachmentDeletePayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		if err = service.DeleteUpload(ctx, mailbox, payload.UploadID); err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: map[string]string{"status": "deleted"}}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.draft.save", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailDraftSavePayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		draft, err := service.SaveDraft(ctx, mailbox, coreWebmailCompose(payload.Message), inv.Request.ExpectedGeneration)
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: apiWebmailDraft(draft), Generation: draft.Revision}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.draft.get", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailDraftPayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		draft, err := service.GetDraft(ctx, mailbox, payload.DraftID)
		if err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: apiWebmailDraft(draft), Generation: draft.Revision}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.draft.delete", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailDraftPayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		if err = service.DeleteDraft(ctx, mailbox, payload.DraftID, inv.Request.ExpectedGeneration); err != nil {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: map[string]string{"status": "deleted"}}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("webmail.message.send", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailSendPayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		submissionID, err := service.Send(ctx, mailbox, coreWebmailCompose(payload.Message))
		if err != nil {
			if submissionID != "" || errors.Is(err, securewebmail.ErrPartial) {
				return OperationResult{Status: http.StatusAccepted, Value: WebmailSendResult{State: "uncertain", SubmissionID: submissionID, MayHaveSubmitted: true}}, nil
			}
			return OperationResult{}, mapSecureWebmailError(err)
		}
		state := "queued"
		if !payload.Message.SendAt.IsZero() {
			state = "scheduled"
		}
		return OperationResult{Status: http.StatusAccepted, Value: WebmailSendResult{State: state, SubmissionID: submissionID}}, nil
	}); err != nil {
		return err
	}
	return registry.Bind("webmail.message.action", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*WebmailMessageActionPayload)
		mailbox, err := secureWebmailMailbox(ctx, service, inv, payload.AuthorizationEpoch)
		if err != nil {
			return OperationResult{}, err
		}
		messages := make([]securewebmail.MessageIdentity, len(payload.Messages))
		for index, message := range payload.Messages {
			messages[index] = coreWebmailIdentity(message)
		}
		result, err := service.ApplyMessages(ctx, mailbox, securewebmail.MessageActionRequest{Action: payload.Action, Messages: messages, TargetFolder: payload.TargetFolder})
		if err != nil && !(errors.Is(err, securewebmail.ErrPartial) && result.Affected > 0) {
			return OperationResult{}, mapSecureWebmailError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: map[string]any{"action": result.Action, "affected": result.Affected, "uid_validity": result.UIDValidity, "highest_mod_seq": result.HighestModSeq, "partial": err != nil}}, nil
	})
}

func mapMailError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, mail.ErrInvalidCommand):
		return ErrInvalidRequest
	case errors.Is(err, mail.ErrUnauthorized):
		return ErrForbidden
	case errors.Is(err, mail.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, mail.ErrConflict):
		return ErrConflict
	case errors.Is(err, mail.ErrRateLimited):
		return ErrRateLimited
	case errors.Is(err, mail.ErrAmbiguous), errors.Is(err, mail.ErrInvalidReceipt):
		return ErrUnavailable
	default:
		return err
	}
}
func mapSecureWebmailError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, securewebmail.ErrInvalid), errors.Is(err, securewebmail.ErrCursorInvalid):
		return ErrInvalidRequest
	case errors.Is(err, securewebmail.ErrUnauthorized), errors.Is(err, securewebmail.ErrGrantInvalid):
		return ErrForbidden
	case errors.Is(err, securewebmail.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, securewebmail.ErrConflict), errors.Is(err, securewebmail.ErrStaleUIDValidity), errors.Is(err, securewebmail.ErrIneligibleFolder):
		return ErrConflict
	case errors.Is(err, securewebmail.ErrLimit):
		return ErrResponseTooLarge
	case errors.Is(err, securewebmail.ErrPartial), errors.Is(err, securewebmail.ErrAmbiguous), errors.Is(err, securewebmail.ErrProtocol), errors.Is(err, securewebmail.ErrUnavailable):
		return ErrUnavailable
	default:
		return ErrUnavailable
	}
}
