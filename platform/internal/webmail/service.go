package webmail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Service struct {
	repository    Repository
	authorizer    Authorizer
	auditor       Auditor
	backend       Backend
	audience      string
	grantLifetime time.Duration
	now           func() time.Time
	blobs         BlobStore
	scanner       MalwareScanner
	images        RemoteImageProxy
	submitter     Submitter
	scheduler     SubmissionScheduler
	spam          SpamReporter
}

type ContentDependencies struct {
	Blobs     BlobStore
	Scanner   MalwareScanner
	Images    RemoteImageProxy
	Submitter Submitter
	Scheduler SubmissionScheduler
	Spam      SpamReporter
}

func (service *Service) ConfigureContent(dependencies ContentDependencies) error {
	if !service.valid() || dependencies.Blobs == nil || dependencies.Scanner == nil || dependencies.Images == nil || dependencies.Submitter == nil || dependencies.Spam == nil {
		return ErrInvalid
	}
	service.blobs = dependencies.Blobs
	service.scanner = dependencies.Scanner
	service.images = dependencies.Images
	service.submitter = dependencies.Submitter
	service.scheduler = dependencies.Scheduler
	service.spam = dependencies.Spam
	return nil
}

func NewService(repository Repository, authorizer Authorizer, auditor Auditor, backend Backend, audience string, grantLifetime time.Duration) (*Service, error) {
	if repository == nil || authorizer == nil || auditor == nil || backend == nil || !opaqueIDPattern.MatchString(audience) ||
		grantLifetime <= 0 || grantLifetime > MaximumGrantLifetime {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, authorizer: authorizer, auditor: auditor, backend: backend,
		audience: audience, grantLifetime: grantLifetime, now: time.Now}, nil
}

func (service *Service) valid() bool {
	return service != nil && service.repository != nil && service.authorizer != nil && service.auditor != nil &&
		service.backend != nil && opaqueIDPattern.MatchString(service.audience) && service.grantLifetime > 0 &&
		service.grantLifetime <= MaximumGrantLifetime && service.now != nil
}

func (service *Service) Bootstrap(ctx context.Context) error {
	if !service.valid() || ctx == nil {
		return ErrInvalid
	}
	return service.repository.Bootstrap(ctx)
}

func secretToken(prefix string) (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := prefix + base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	for index := range raw {
		raw[index] = 0
	}
	return token, hex.EncodeToString(digest[:]), nil
}

func digestParts(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(strconv.Itoa(len(part))))
		hash.Write([]byte{':'})
		hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (service *Service) audit(ctx context.Context, operation, outcome string, principal Principal, tenantID, mailboxID, requestID string) error {
	if !service.valid() || ctx == nil || !principal.valid() || !opaqueIDPattern.MatchString(tenantID) ||
		!opaqueIDPattern.MatchString(mailboxID) || !opaqueIDPattern.MatchString(operation) ||
		(outcome != "succeeded" && outcome != "failed" && outcome != "denied") || !opaqueIDPattern.MatchString(requestID) {
		return ErrInvalid
	}
	return service.auditor.RecordWebmailSecurity(ctx, AuditEvent{
		Operation: operation, Outcome: outcome, TenantID: tenantID, UserDigest: digestParts(principal.UserID),
		SessionDigest: digestParts(principal.SessionID), MailboxDigest: digestParts(mailboxID),
		RequestID: requestID, OccurredAt: service.now().UTC(),
	})
}

func (service *Service) authorizedAccount(ctx context.Context, principal Principal, tenantID, mailboxID string) (AuthorizedMailAccount, error) {
	if !service.valid() || ctx == nil || !principal.valid() || !opaqueIDPattern.MatchString(tenantID) || !opaqueIDPattern.MatchString(mailboxID) {
		return AuthorizedMailAccount{}, ErrInvalid
	}
	account, err := service.authorizer.AuthorizeMailbox(ctx, principal, tenantID, mailboxID)
	if err != nil || !account.valid() || account.TenantID != tenantID || account.MailboxID != mailboxID {
		return AuthorizedMailAccount{}, ErrNotFound
	}
	return account, nil
}

func accountSnapshotDigest(accounts []AuthorizedMailAccount) string {
	parts := make([]string, 0, len(accounts)*2)
	for _, account := range accounts {
		parts = append(parts, account.MailboxID, strconv.FormatUint(account.AuthorizationEpoch, 10))
	}
	return digestParts(parts...)
}

func (service *Service) ListAccounts(ctx context.Context, principal Principal, tenantID string, limit uint16, cursorToken string) (AccountPage, error) {
	if !service.valid() || ctx == nil || !principal.valid() || !opaqueIDPattern.MatchString(tenantID) || limit == 0 || limit > MaximumPageSize || len(cursorToken) > 256 {
		return AccountPage{}, ErrInvalid
	}
	accounts, err := service.authorizer.ListMailAccounts(ctx, principal, tenantID)
	if err != nil {
		return AccountPage{}, ErrNotFound
	}
	if len(accounts) > 10000 {
		return AccountPage{}, ErrLimit
	}
	for _, account := range accounts {
		if !account.valid() || account.TenantID != tenantID {
			return AccountPage{}, ErrNotFound
		}
	}
	sort.Slice(accounts, func(left, right int) bool { return accounts[left].MailboxID < accounts[right].MailboxID })
	for index := 1; index < len(accounts); index++ {
		if accounts[index-1].MailboxID == accounts[index].MailboxID {
			return AccountPage{}, ErrAmbiguous
		}
	}
	snapshotDigest := accountSnapshotDigest(accounts)
	afterID := ""
	if cursorToken != "" {
		digest := sha256.Sum256([]byte(cursorToken))
		state, consumeErr := service.repository.ConsumeCursor(ctx, hex.EncodeToString(digest[:]), CursorState{
			Kind: CursorAccounts, TenantID: tenantID, UserID: principal.UserID, SessionID: principal.SessionID,
			AuthorizationEpoch: 1,
		}, service.now().UTC())
		if consumeErr != nil || state.QueryDigest != snapshotDigest {
			return AccountPage{}, ErrCursorInvalid
		}
		afterID = state.LastAccountID
	}
	start := sort.Search(len(accounts), func(index int) bool { return accounts[index].MailboxID > afterID })
	end := start + int(limit)
	more := false
	if end < len(accounts) {
		more = true
	} else {
		end = len(accounts)
	}
	page := AccountPage{Accounts: append([]AuthorizedMailAccount(nil), accounts[start:end]...)}
	if more && len(page.Accounts) > 0 {
		token, digest, tokenErr := secretToken("wmc_")
		if tokenErr != nil {
			return AccountPage{}, tokenErr
		}
		state := CursorState{Kind: CursorAccounts, TenantID: tenantID, UserID: principal.UserID,
			SessionID: principal.SessionID, AuthorizationEpoch: 1, LastAccountID: page.Accounts[len(page.Accounts)-1].MailboxID,
			QueryDigest: snapshotDigest, ExpiresAt: service.now().UTC().Add(MaximumCursorLifetime)}
		if err = service.repository.StoreCursor(ctx, digest, state); err != nil {
			return AccountPage{}, err
		}
		page.NextCursor = token
	}
	return page, nil
}

func (service *Service) IssueGrant(ctx context.Context, principal Principal, tenantID, mailboxID, requestID string) (IssuedGrant, error) {
	account, err := service.authorizedAccount(ctx, principal, tenantID, mailboxID)
	if err != nil {
		if err == ErrNotFound && service.valid() && principal.valid() && opaqueIDPattern.MatchString(tenantID) && opaqueIDPattern.MatchString(mailboxID) && opaqueIDPattern.MatchString(requestID) {
			return IssuedGrant{}, errors.Join(err, service.audit(ctx, "grant.issue", "denied", principal, tenantID, mailboxID, requestID))
		}
		return IssuedGrant{}, err
	}
	if !opaqueIDPattern.MatchString(requestID) {
		return IssuedGrant{}, ErrInvalid
	}
	now := service.now().UTC()
	token, digest, err := secretToken("wmg_")
	if err != nil {
		return IssuedGrant{}, err
	}
	claims := GrantClaims{TenantID: tenantID, UserID: principal.UserID, SessionID: principal.SessionID,
		MailboxID: mailboxID, Audience: service.audience, AuthorizationEpoch: account.AuthorizationEpoch,
		IssuedAt: now, ExpiresAt: now.Add(service.grantLifetime)}
	if err = service.repository.StoreGrant(ctx, digest, claims); err != nil {
		return IssuedGrant{}, err
	}
	if err = service.audit(ctx, "grant.issue", "succeeded", principal, tenantID, mailboxID, requestID); err != nil {
		_, revokeErr := service.repository.RevokeGrants(ctx, principal, tenantID, mailboxID, account.AuthorizationEpoch, service.now().UTC())
		return IssuedGrant{}, errors.Join(err, revokeErr)
	}
	return IssuedGrant{Token: token, ExpiresAt: claims.ExpiresAt}, nil
}

func (service *Service) SwitchAccount(ctx context.Context, principal Principal, tenantID, previousMailboxID, targetMailboxID, requestID string) (IssuedGrant, error) {
	if !service.valid() || ctx == nil || !principal.valid() || !opaqueIDPattern.MatchString(tenantID) ||
		!opaqueIDPattern.MatchString(previousMailboxID) || !opaqueIDPattern.MatchString(targetMailboxID) || !opaqueIDPattern.MatchString(requestID) {
		return IssuedGrant{}, ErrInvalid
	}
	previous, err := service.authorizedAccount(ctx, principal, tenantID, previousMailboxID)
	if err != nil {
		return IssuedGrant{}, errors.Join(err, service.audit(ctx, "grant.revoke", "denied", principal, tenantID, previousMailboxID, requestID))
	}
	target, err := service.authorizedAccount(ctx, principal, tenantID, targetMailboxID)
	if err != nil {
		return IssuedGrant{}, errors.Join(err, service.audit(ctx, "grant.issue", "denied", principal, tenantID, targetMailboxID, requestID))
	}
	now := service.now().UTC()
	token, digest, err := secretToken("wmg_")
	if err != nil {
		return IssuedGrant{}, err
	}
	claims := GrantClaims{TenantID: tenantID, UserID: principal.UserID, SessionID: principal.SessionID,
		MailboxID: targetMailboxID, Audience: service.audience, AuthorizationEpoch: target.AuthorizationEpoch,
		IssuedAt: now, ExpiresAt: now.Add(service.grantLifetime)}
	if _, err = service.repository.SwitchGrant(ctx, principal, tenantID, previousMailboxID, previous.AuthorizationEpoch, digest, claims, now); err != nil {
		return IssuedGrant{}, err
	}
	if err = service.audit(ctx, "grant.revoke", "succeeded", principal, tenantID, previousMailboxID, requestID); err != nil {
		_, revokeErr := service.repository.RevokeGrants(ctx, principal, tenantID, targetMailboxID, target.AuthorizationEpoch, service.now().UTC())
		return IssuedGrant{}, errors.Join(err, revokeErr)
	}
	if err = service.audit(ctx, "grant.issue", "succeeded", principal, tenantID, targetMailboxID, requestID); err != nil {
		_, revokeErr := service.repository.RevokeGrants(ctx, principal, tenantID, targetMailboxID, target.AuthorizationEpoch, service.now().UTC())
		return IssuedGrant{}, errors.Join(err, revokeErr)
	}
	return IssuedGrant{Token: token, ExpiresAt: claims.ExpiresAt}, nil
}

func (service *Service) RevokeAccount(ctx context.Context, principal Principal, tenantID, mailboxID, requestID string) (uint64, error) {
	if !service.valid() || ctx == nil || !principal.valid() || !opaqueIDPattern.MatchString(tenantID) ||
		!opaqueIDPattern.MatchString(mailboxID) || !opaqueIDPattern.MatchString(requestID) {
		return 0, ErrInvalid
	}
	account, err := service.authorizedAccount(ctx, principal, tenantID, mailboxID)
	if err != nil {
		return 0, errors.Join(err, service.audit(ctx, "grant.revoke", "denied", principal, tenantID, mailboxID, requestID))
	}
	count, err := service.repository.RevokeGrants(ctx, principal, tenantID, mailboxID, account.AuthorizationEpoch, service.now().UTC())
	if err != nil {
		return 0, errors.Join(err, service.audit(ctx, "grant.revoke", "failed", principal, tenantID, mailboxID, requestID))
	}
	return count, service.audit(ctx, "grant.revoke", "succeeded", principal, tenantID, mailboxID, requestID)
}

func (service *Service) authenticateOperation(ctx context.Context, mailbox MailboxContext, operation string) (AuthorizedMailAccount, error) {
	if !service.valid() || ctx == nil || !mailbox.valid() || mailbox.Audience != service.audience || !opaqueIDPattern.MatchString(operation) {
		return AuthorizedMailAccount{}, ErrInvalid
	}
	account, err := service.authorizedAccount(ctx, mailbox.Principal, mailbox.TenantID, mailbox.MailboxID)
	if err != nil || account.AuthorizationEpoch != mailbox.AuthorizationEpoch {
		auditErr := service.audit(ctx, "grant.use", "denied", mailbox.Principal, mailbox.TenantID, mailbox.MailboxID, mailbox.RequestID)
		return AuthorizedMailAccount{}, errors.Join(ErrNotFound, auditErr)
	}
	digest := sha256.Sum256([]byte(mailbox.Grant))
	claims := GrantClaims{TenantID: mailbox.TenantID, UserID: mailbox.Principal.UserID, SessionID: mailbox.Principal.SessionID,
		MailboxID: mailbox.MailboxID, Audience: mailbox.Audience, AuthorizationEpoch: mailbox.AuthorizationEpoch}
	if err = service.repository.ConsumeGrant(ctx, hex.EncodeToString(digest[:]), claims, service.now().UTC()); err != nil {
		return AuthorizedMailAccount{}, errors.Join(err, service.audit(ctx, "grant.use", "denied", mailbox.Principal, mailbox.TenantID, mailbox.MailboxID, mailbox.RequestID))
	}
	if err = service.audit(ctx, "grant.use", "succeeded", mailbox.Principal, mailbox.TenantID, mailbox.MailboxID, mailbox.RequestID); err != nil {
		return AuthorizedMailAccount{}, err
	}
	return account, nil
}

func (service *Service) receipt(ctx context.Context, mailbox MailboxContext, operation, outcome string, count int, partial bool) error {
	if count < 0 || count > MaximumPageSize {
		return ErrInvalid
	}
	return service.repository.StoreReceipt(ctx, OperationReceipt{RequestID: mailbox.RequestID, TenantID: mailbox.TenantID,
		UserDigest: digestParts(mailbox.Principal.UserID), MailboxDigest: digestParts(mailbox.MailboxID), Operation: operation,
		Outcome: outcome, ItemCount: uint16(count), Partial: partial, OccurredAt: service.now().UTC()})
}

func queryDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (service *Service) consumeCursor(ctx context.Context, mailbox MailboxContext, token string, expected CursorState) (CursorState, error) {
	if token == "" {
		return CursorState{}, nil
	}
	if len(token) > 256 {
		return CursorState{}, ErrCursorInvalid
	}
	digest := sha256.Sum256([]byte(token))
	expected.TenantID = mailbox.TenantID
	expected.UserID = mailbox.Principal.UserID
	expected.SessionID = mailbox.Principal.SessionID
	expected.MailboxID = mailbox.MailboxID
	expected.AuthorizationEpoch = mailbox.AuthorizationEpoch
	return service.repository.ConsumeCursor(ctx, hex.EncodeToString(digest[:]), expected, service.now().UTC())
}

func (service *Service) issueCursor(ctx context.Context, state CursorState) (string, error) {
	token, digest, err := secretToken("wmc_")
	if err != nil {
		return "", err
	}
	state.ExpiresAt = service.now().UTC().Add(MaximumCursorLifetime)
	if err = service.repository.StoreCursor(ctx, digest, state); err != nil {
		return "", err
	}
	return token, nil
}

func (service *Service) ListFolders(ctx context.Context, mailbox MailboxContext, request FolderPageRequest) (FolderPage, error) {
	if _, err := service.authenticateOperation(ctx, mailbox, "folder.list"); err != nil {
		return FolderPage{}, err
	}
	if request.Limit == 0 || request.Limit > MaximumPageSize {
		return FolderPage{}, errors.Join(ErrInvalid, service.receipt(ctx, mailbox, "folder.list", "failed", 0, false))
	}
	state, err := service.consumeCursor(ctx, mailbox, request.Cursor, CursorState{Kind: CursorFolders})
	if err != nil {
		return FolderPage{}, errors.Join(err, service.receipt(ctx, mailbox, "folder.list", "failed", 0, false))
	}
	request.Cursor = ""
	request.afterName = state.LastFolderName
	page, err := service.backend.ListFolders(ctx, mailbox.Grant, request)
	if err != nil {
		return FolderPage{}, errors.Join(err, service.receipt(ctx, mailbox, "folder.list", "failed", 0, errors.Is(err, ErrPartial)))
	}
	if page.more && len(page.Folders) > 0 {
		page.NextCursor, err = service.issueCursor(ctx, CursorState{Kind: CursorFolders, TenantID: mailbox.TenantID,
			UserID: mailbox.Principal.UserID, SessionID: mailbox.Principal.SessionID, MailboxID: mailbox.MailboxID,
			AuthorizationEpoch: mailbox.AuthorizationEpoch, LastFolderName: page.Folders[len(page.Folders)-1].Name})
		if err != nil {
			return FolderPage{}, errors.Join(err, service.receipt(ctx, mailbox, "folder.list", "failed", 0, false))
		}
	}
	return page, service.receipt(ctx, mailbox, "folder.list", "succeeded", len(page.Folders), page.Partial)
}

func (service *Service) MutateFolder(ctx context.Context, mailbox MailboxContext, request FolderMutationRequest) error {
	operation := "folder." + string(request.Operation)
	if _, err := service.authenticateOperation(ctx, mailbox, operation); err != nil {
		return err
	}
	if !request.valid() {
		return errors.Join(ErrInvalid, service.receipt(ctx, mailbox, operation, "failed", 0, false))
	}
	err := service.backend.MutateFolder(ctx, mailbox.Grant, request)
	if err != nil {
		return errors.Join(err, service.receipt(ctx, mailbox, operation, "failed", 0, errors.Is(err, ErrPartial)))
	}
	return service.receipt(ctx, mailbox, operation, "succeeded", 0, false)
}

func (service *Service) messageDefaults(ctx context.Context, mailbox MailboxContext, request MessagePageRequest) (MessagePageRequest, error) {
	if request.Limit != 0 && request.Sort != "" {
		return request, nil
	}
	preferences, err := service.repository.GetPreferences(ctx, mailbox.TenantID, mailbox.Principal.UserID, mailbox.MailboxID)
	if errors.Is(err, ErrNotFound) {
		preferences = Preferences{PageSize: 50, Sort: SortNewest, Threaded: true}
	} else if err != nil {
		return MessagePageRequest{}, err
	}
	if request.Limit == 0 {
		request.Limit = preferences.PageSize
	}
	if request.Sort == "" {
		request.Sort = preferences.Sort
	}
	if !request.Threaded {
		request.Threaded = preferences.Threaded
	}
	return request, nil
}

func (service *Service) ListMessages(ctx context.Context, mailbox MailboxContext, request MessagePageRequest) (MessagePage, error) {
	if _, err := service.authenticateOperation(ctx, mailbox, "message.list"); err != nil {
		return MessagePage{}, err
	}
	request, err := service.messageDefaults(ctx, mailbox, request)
	if err != nil || !validMailboxName(request.Folder) || request.Limit == 0 || request.Limit > MaximumPageSize || !request.Sort.valid() {
		return MessagePage{}, errors.Join(ErrInvalid, err, service.receipt(ctx, mailbox, "message.list", "failed", 0, false))
	}
	digest, err := queryDigest(struct {
		Folder   string
		Sort     MessageSort
		Threaded bool
	}{request.Folder, request.Sort, request.Threaded})
	if err != nil {
		return MessagePage{}, err
	}
	state, err := service.consumeCursor(ctx, mailbox, request.Cursor, CursorState{Kind: CursorMessages})
	if err != nil || state.QueryDigest != "" && state.QueryDigest != digest || state.FolderName != "" && state.FolderName != request.Folder || state.Sort != "" && state.Sort != request.Sort {
		return MessagePage{}, errors.Join(ErrCursorInvalid, err, service.receipt(ctx, mailbox, "message.list", "failed", 0, false))
	}
	request.Cursor = ""
	request.expectedUIDValidity = state.UIDValidity
	request.afterUID = state.LastUID
	page, err := service.backend.ListMessages(ctx, mailbox.Grant, request)
	if err != nil {
		return MessagePage{}, errors.Join(err, service.receipt(ctx, mailbox, "message.list", "failed", 0, errors.Is(err, ErrPartial)))
	}
	if page.more && page.lastUID > 0 {
		page.NextCursor, err = service.issueCursor(ctx, CursorState{Kind: CursorMessages, TenantID: mailbox.TenantID,
			UserID: mailbox.Principal.UserID, SessionID: mailbox.Principal.SessionID, MailboxID: mailbox.MailboxID,
			AuthorizationEpoch: mailbox.AuthorizationEpoch, FolderName: request.Folder, UIDValidity: page.UIDValidity,
			LastUID: page.lastUID, Sort: request.Sort, QueryDigest: digest})
		if err != nil {
			return MessagePage{}, errors.Join(err, service.receipt(ctx, mailbox, "message.list", "failed", 0, false))
		}
	}
	return page, service.receipt(ctx, mailbox, "message.list", "succeeded", len(page.Messages), page.Partial)
}

func (service *Service) Search(ctx context.Context, mailbox MailboxContext, request SearchRequest) (SearchPage, error) {
	if _, err := service.authenticateOperation(ctx, mailbox, "message.search"); err != nil {
		return SearchPage{}, err
	}
	if request.Sort == "" {
		request.Sort = SortNewest
	}
	if !validMailboxName(request.Folder) || !request.Criteria.valid() || request.Limit == 0 || request.Limit > MaximumPageSize || !request.Sort.valid() {
		return SearchPage{}, errors.Join(ErrInvalid, service.receipt(ctx, mailbox, "message.search", "failed", 0, false))
	}
	digest, err := queryDigest(struct {
		Folder   string
		Criteria SearchCriteria
		Sort     MessageSort
	}{request.Folder, request.Criteria, request.Sort})
	if err != nil {
		return SearchPage{}, err
	}
	state, err := service.consumeCursor(ctx, mailbox, request.Cursor, CursorState{Kind: CursorSearch})
	if err != nil || state.QueryDigest != "" && state.QueryDigest != digest || state.FolderName != "" && state.FolderName != request.Folder || state.Sort != "" && state.Sort != request.Sort {
		return SearchPage{}, errors.Join(ErrCursorInvalid, err, service.receipt(ctx, mailbox, "message.search", "failed", 0, false))
	}
	request.Cursor = ""
	request.expectedUIDValidity = state.UIDValidity
	request.afterUID = state.LastUID
	page, err := service.backend.Search(ctx, mailbox.Grant, request)
	if err != nil {
		return SearchPage{}, errors.Join(err, service.receipt(ctx, mailbox, "message.search", "failed", 0, errors.Is(err, ErrPartial)))
	}
	if page.more && page.lastUID > 0 {
		page.NextCursor, err = service.issueCursor(ctx, CursorState{Kind: CursorSearch, TenantID: mailbox.TenantID,
			UserID: mailbox.Principal.UserID, SessionID: mailbox.Principal.SessionID, MailboxID: mailbox.MailboxID,
			AuthorizationEpoch: mailbox.AuthorizationEpoch, FolderName: request.Folder, UIDValidity: page.UIDValidity,
			LastUID: page.lastUID, Sort: request.Sort, QueryDigest: digest})
		if err != nil {
			return SearchPage{}, errors.Join(err, service.receipt(ctx, mailbox, "message.search", "failed", 0, false))
		}
	}
	return page, service.receipt(ctx, mailbox, "message.search", "succeeded", len(page.Identities), page.Partial)
}

func (service *Service) GetPreferences(ctx context.Context, mailbox MailboxContext) (Preferences, error) {
	if _, err := service.authenticateOperation(ctx, mailbox, "preferences.get"); err != nil {
		return Preferences{}, err
	}
	preferences, err := service.repository.GetPreferences(ctx, mailbox.TenantID, mailbox.Principal.UserID, mailbox.MailboxID)
	if err != nil {
		return Preferences{}, errors.Join(err, service.receipt(ctx, mailbox, "preferences.get", "failed", 0, false))
	}
	return preferences, service.receipt(ctx, mailbox, "preferences.get", "succeeded", 0, false)
}

func (service *Service) PutPreferences(ctx context.Context, mailbox MailboxContext, preferences Preferences, expectedRevision uint64) (Preferences, error) {
	if _, err := service.authenticateOperation(ctx, mailbox, "preferences.put"); err != nil {
		return Preferences{}, err
	}
	preferences.TenantID = mailbox.TenantID
	preferences.UserID = mailbox.Principal.UserID
	preferences.MailboxID = mailbox.MailboxID
	stored, err := service.repository.PutPreferences(ctx, preferences, expectedRevision)
	if err != nil {
		return Preferences{}, errors.Join(err, service.receipt(ctx, mailbox, "preferences.put", "failed", 0, false))
	}
	return stored, service.receipt(ctx, mailbox, "preferences.put", "succeeded", 0, false)
}

const messageCSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'none'; style-src 'none'; img-src 'self'; connect-src 'none'; font-src 'none'; media-src 'none'; sandbox allow-popups allow-popups-to-escape-sandbox"

func decodeMIMEBody(header textproto.MIMEHeader, body io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding"))) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		return quotedprintable.NewReader(body)
	default:
		return body
	}
}

type renderedParts struct {
	plain       string
	html        string
	parts       int
	total       uint64
	attachments []AttachmentReference
}

func readRenderedPart(reader io.Reader, state *renderedParts) (string, error) {
	remaining := uint64(MaximumRenderedPartBytes)
	if state.total >= 2*MaximumRenderedPartBytes {
		return "", ErrLimit
	}
	if remaining > 2*MaximumRenderedPartBytes-state.total {
		remaining = 2*MaximumRenderedPartBytes - state.total
	}
	content, err := io.ReadAll(io.LimitReader(reader, int64(remaining)+1))
	if err != nil || uint64(len(content)) > remaining {
		return "", errors.Join(ErrLimit, err)
	}
	state.total += uint64(len(content))
	return strings.ToValidUTF8(string(content), "\uFFFD"), nil
}

func walkMIME(header textproto.MIMEHeader, body io.Reader, depth int, state *renderedParts) error {
	return walkMIMEPart(header, body, depth, "", state)
}

func walkMIMEPart(header textproto.MIMEHeader, body io.Reader, depth int, partID string, state *renderedParts) error {
	if depth > 8 || state.parts >= 128 {
		return ErrLimit
	}
	state.parts++
	contentType, parameters, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || contentType == "" {
		contentType = "text/plain"
		parameters = nil
	}
	disposition, dispositionParameters, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
	filename := dispositionParameters["filename"]
	if filename == "" {
		filename = parameters["name"]
	}
	if strings.EqualFold(disposition, "attachment") || filename != "" {
		// Container attachments need separate IMAP section semantics; never advertise a leaf ID for them.
		if strings.HasPrefix(strings.ToLower(contentType), "multipart/") || strings.EqualFold(contentType, "message/rfc822") {
			return ErrProtocol
		}
		if !safeFilename(filename) {
			filename = "attachment"
		}
		if !safeContentType(contentType) {
			contentType = "application/octet-stream"
		}
		if partID == "" {
			partID = "1"
		}
		size, readErr := io.Copy(io.Discard, io.LimitReader(decodeMIMEBody(header, body), MaximumAttachmentBytes+1))
		if readErr != nil || size > MaximumAttachmentBytes {
			return errors.Join(ErrLimit, readErr)
		}
		state.attachments = append(state.attachments, AttachmentReference{PartID: partID, Filename: filename, ContentType: contentType, Size: uint64(size)})
		return nil
	}
	if strings.HasPrefix(strings.ToLower(contentType), "multipart/") {
		boundary := parameters["boundary"]
		if boundary == "" || len(boundary) > 200 {
			return ErrProtocol
		}
		multipartReader := multipart.NewReader(body, boundary)
		partNumber := 0
		for {
			part, nextErr := multipartReader.NextPart()
			if errors.Is(nextErr, io.EOF) {
				return nil
			}
			if nextErr != nil {
				return ErrProtocol
			}
			partNumber++
			childID := strconv.Itoa(partNumber)
			if partID != "" {
				childID = partID + "." + childID
			}
			if err = walkMIMEPart(part.Header, part, depth+1, childID, state); err != nil {
				part.Close()
				return err
			}
			part.Close()
		}
	}
	decoded := decodeMIMEBody(header, body)
	switch strings.ToLower(contentType) {
	case "text/plain":
		if state.plain == "" {
			state.plain, err = readRenderedPart(decoded, state)
		}
	case "text/html":
		if state.html == "" {
			state.html, err = readRenderedPart(decoded, state)
		}
	}
	return err
}

func parseHTMLAttributes(raw string) map[string]string {
	attributes := make(map[string]string)
	for index := 0; index < len(raw); {
		for index < len(raw) && (raw[index] == ' ' || raw[index] == '\t' || raw[index] == '/') {
			index++
		}
		start := index
		for index < len(raw) && ((raw[index] >= 'a' && raw[index] <= 'z') || (raw[index] >= 'A' && raw[index] <= 'Z') || raw[index] == '-' || raw[index] == ':') {
			index++
		}
		if start == index {
			index++
			continue
		}
		name := strings.ToLower(raw[start:index])
		for index < len(raw) && (raw[index] == ' ' || raw[index] == '\t') {
			index++
		}
		if index >= len(raw) || raw[index] != '=' {
			attributes[name] = ""
			continue
		}
		index++
		for index < len(raw) && (raw[index] == ' ' || raw[index] == '\t') {
			index++
		}
		if index >= len(raw) {
			break
		}
		quote := byte(0)
		if raw[index] == '\'' || raw[index] == '"' {
			quote = raw[index]
			index++
		}
		valueStart := index
		if quote != 0 {
			for index < len(raw) && raw[index] != quote {
				index++
			}
		} else {
			for index < len(raw) && raw[index] != ' ' && raw[index] != '\t' && raw[index] != '/' {
				index++
			}
		}
		if len(attributes) < 32 && index-valueStart <= 4096 {
			attributes[name] = html.UnescapeString(raw[valueStart:index])
		}
		if quote != 0 && index < len(raw) {
			index++
		}
	}
	return attributes
}

func safeLink(raw string) (string, bool) {
	if len(raw) == 0 || len(raw) > 4096 || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil {
		return "", false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "http":
		if parsed.Hostname() == "" {
			return "", false
		}
	case "mailto":
		if parsed.Opaque == "" || strings.ContainsAny(parsed.Opaque, "?&") {
			return "", false
		}
	default:
		return "", false
	}
	return parsed.String(), true
}

func asciiLower(value string) string {
	buffer := []byte(value)
	for index, character := range buffer {
		if character >= 'A' && character <= 'Z' {
			buffer[index] = character + ('a' - 'A')
		}
	}
	return string(buffer)
}

func sanitizeHTMLDocument(input string, policy RemoteImagePolicy) (string, []RemoteImageReference, error) {
	if policy != RemoteImagesBlocked && policy != RemoteImagesProxy || len(input) > MaximumRenderedPartBytes {
		return "", nil, ErrInvalid
	}
	allowed := map[string]bool{"p": true, "br": true, "div": true, "span": true, "strong": true, "b": true,
		"em": true, "i": true, "u": true, "blockquote": true, "pre": true, "code": true, "ul": true,
		"ol": true, "li": true, "table": true, "thead": true, "tbody": true, "tr": true, "td": true,
		"th": true, "hr": true, "a": true, "img": true}
	void := map[string]bool{"br": true, "hr": true, "img": true}
	var output strings.Builder
	images := make([]RemoteImageReference, 0, 8)
	lowerInput := asciiLower(input)
	for index := 0; index < len(input); {
		open := strings.IndexByte(input[index:], '<')
		if open < 0 {
			output.WriteString(html.EscapeString(html.UnescapeString(input[index:])))
			break
		}
		open += index
		output.WriteString(html.EscapeString(html.UnescapeString(input[index:open])))
		close := strings.IndexByte(input[open+1:], '>')
		if close < 0 {
			output.WriteString("&lt;")
			index = open + 1
			continue
		}
		close += open + 1
		raw := strings.TrimSpace(input[open+1 : close])
		closing := strings.HasPrefix(raw, "/")
		if closing {
			raw = strings.TrimSpace(strings.TrimPrefix(raw, "/"))
		}
		nameEnd := strings.IndexAny(raw, " \t/")
		if nameEnd < 0 {
			nameEnd = len(raw)
		}
		name := strings.ToLower(raw[:nameEnd])
		if name == "script" || name == "style" || name == "template" || name == "svg" || name == "math" {
			if !closing {
				lowerRemainder := lowerInput[close+1:]
				endMarker := "</" + name
				end := strings.Index(lowerRemainder, endMarker)
				if end < 0 {
					break
				}
				endClose := strings.IndexByte(input[close+1+end:], '>')
				if endClose < 0 {
					break
				}
				index = close + 1 + end + endClose + 1
				continue
			}
			index = close + 1
			continue
		}
		if !allowed[name] {
			index = close + 1
			continue
		}
		if closing {
			if !void[name] {
				output.WriteString("</" + name + ">")
			}
			index = close + 1
			continue
		}
		attributes := parseHTMLAttributes(raw[nameEnd:])
		output.WriteByte('<')
		output.WriteString(name)
		if name == "a" {
			if href, ok := safeLink(attributes["href"]); ok {
				output.WriteString(` href="` + html.EscapeString(href) + `" target="_blank" rel="noopener noreferrer nofollow"`)
			}
		} else if name == "img" {
			if alt := boundedProjection(attributes["alt"], 512); alt != "" {
				output.WriteString(` alt="` + html.EscapeString(alt) + `"`)
			}
			source := attributes["src"]
			if strings.HasPrefix(strings.ToLower(source), "cid:") && len(source) <= 512 {
				output.WriteString(` data-cid="` + html.EscapeString(source[4:]) + `"`)
			} else if parsed, parseErr := normalizeRemoteImageURL(source); parseErr == nil && len(images) < 64 {
				digest := sha256.Sum256([]byte(parsed.String()))
				digestString := hex.EncodeToString(digest[:])
				id := "img_" + digestString[:32]
				output.WriteString(` data-remote-image-id="` + id + `"`)
				images = append(images, RemoteImageReference{ID: id, URL: parsed.String(), URLDigest: digestString, Blocked: policy == RemoteImagesBlocked})
			}
		}
		output.WriteByte('>')
		index = close + 1
	}
	if output.Len() > MaximumRenderedPartBytes {
		return "", nil, ErrLimit
	}
	return output.String(), images, nil
}

func (service *Service) ReadMessage(ctx context.Context, mailbox MailboxContext, request MessageReadRequest) (RenderedMessage, error) {
	if service.images == nil {
		return RenderedMessage{}, ErrUnavailable
	}
	if _, err := service.authenticateOperation(ctx, mailbox, "message.read"); err != nil {
		return RenderedMessage{}, err
	}
	if !request.Identity.valid() || request.RemoteImagePolicy != RemoteImagesBlocked && request.RemoteImagePolicy != RemoteImagesProxy {
		return RenderedMessage{}, errors.Join(ErrInvalid, service.receipt(ctx, mailbox, "message.read", "failed", 0, false))
	}
	stream, err := service.backend.OpenMessage(ctx, mailbox.Grant, request.Identity, MaximumRawMessageBytes)
	if err != nil {
		return RenderedMessage{}, errors.Join(err, service.receipt(ctx, mailbox, "message.read", "failed", 0, errors.Is(err, ErrPartial)))
	}
	message, err := mail.ReadMessage(bufio.NewReaderSize(stream, 64<<10))
	if err != nil {
		return RenderedMessage{}, errors.Join(ErrProtocol, stream.Close(), service.receipt(ctx, mailbox, "message.read", "failed", 0, false))
	}
	state := &renderedParts{}
	err = walkMIME(textproto.MIMEHeader(message.Header), message.Body, 0, state)
	closeErr := stream.Close()
	if err != nil || closeErr != nil {
		return RenderedMessage{}, errors.Join(err, closeErr, service.receipt(ctx, mailbox, "message.read", "failed", 0, errors.Is(err, ErrPartial)))
	}
	sanitized := ""
	images := []RemoteImageReference(nil)
	if state.html != "" {
		sanitized, images, err = sanitizeHTMLDocument(state.html, request.RemoteImagePolicy)
		if err != nil {
			return RenderedMessage{}, errors.Join(err, service.receipt(ctx, mailbox, "message.read", "failed", 0, false))
		}
	} else if state.plain != "" {
		sanitized = "<pre>" + html.EscapeString(state.plain) + "</pre>"
	}
	result := RenderedMessage{Identity: request.Identity, PlainText: boundedProjection(state.plain, MaximumRenderedPartBytes),
		SanitizedHTML: sanitized, CSP: messageCSP, ReferrerPolicy: "no-referrer", RemoteImages: images, Attachments: state.attachments}
	return result, service.receipt(ctx, mailbox, "message.read", "succeeded", 1, false)
}

func (service *Service) ProxyRemoteImage(ctx context.Context, mailbox MailboxContext, request RemoteImageRequest) (RemoteImage, error) {
	if service.images == nil {
		return RemoteImage{}, ErrUnavailable
	}
	if _, err := service.authenticateOperation(ctx, mailbox, "remote_image.fetch"); err != nil {
		return RemoteImage{}, err
	}
	if !request.Identity.valid() || !opaqueIDPattern.MatchString(request.ReferenceID) {
		return RemoteImage{}, errors.Join(ErrInvalid, service.receipt(ctx, mailbox, "remote_image.fetch", "failed", 0, false))
	}
	messageStream, err := service.backend.OpenMessage(ctx, mailbox.Grant, request.Identity, MaximumRawMessageBytes)
	if err != nil {
		return RemoteImage{}, errors.Join(err, service.receipt(ctx, mailbox, "remote_image.fetch", "failed", 0, errors.Is(err, ErrPartial)))
	}
	message, parseErr := mail.ReadMessage(bufio.NewReaderSize(messageStream, 64<<10))
	if parseErr != nil {
		messageStream.Close()
		return RemoteImage{}, errors.Join(ErrProtocol, service.receipt(ctx, mailbox, "remote_image.fetch", "failed", 0, false))
	}
	state := &renderedParts{}
	parseErr = walkMIME(textproto.MIMEHeader(message.Header), message.Body, 0, state)
	closeErr := messageStream.Close()
	if parseErr != nil || closeErr != nil {
		return RemoteImage{}, errors.Join(parseErr, closeErr, service.receipt(ctx, mailbox, "remote_image.fetch", "failed", 0, errors.Is(parseErr, ErrPartial)))
	}
	_, references, sanitizeErr := sanitizeHTMLDocument(state.html, RemoteImagesProxy)
	if sanitizeErr != nil {
		return RemoteImage{}, errors.Join(sanitizeErr, service.receipt(ctx, mailbox, "remote_image.fetch", "failed", 0, false))
	}
	authorizedReference := false
	for _, reference := range references {
		if reference.ID == request.ReferenceID && reference.URL == request.URL && reference.URLDigest == request.ExpectedDigest {
			authorizedReference = true
			break
		}
	}
	if !authorizedReference {
		return RemoteImage{}, errors.Join(ErrNotFound, service.receipt(ctx, mailbox, "remote_image.fetch", "failed", 0, false))
	}
	request.CachePartition = digestParts(mailbox.TenantID, mailbox.Principal.UserID, mailbox.MailboxID)
	if request.MaximumBytes == 0 {
		request.MaximumBytes = MaximumRemoteImageBytes
	}
	image, err := service.images.Fetch(ctx, request)
	if err != nil {
		return RemoteImage{}, errors.Join(err, service.receipt(ctx, mailbox, "remote_image.fetch", "failed", 0, errors.Is(err, ErrPartial)))
	}
	return image, service.receipt(ctx, mailbox, "remote_image.fetch", "succeeded", 1, false)
}

type deletingReader struct {
	reader io.ReadCloser
	delete func() error
	closed bool
}

type joinedReadCloser struct {
	io.Reader
	io.Closer
}

type countingReader struct {
	reader io.Reader
	count  uint64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	read, err := reader.reader.Read(buffer)
	reader.count += uint64(read)
	return read, err
}

func (reader *deletingReader) Read(buffer []byte) (int, error) { return reader.reader.Read(buffer) }

func (reader *deletingReader) Close() error {
	if reader.closed {
		return nil
	}
	reader.closed = true
	return errors.Join(reader.reader.Close(), reader.delete())
}

func safeFilename(filename string) bool {
	return filename != "" && len(filename) <= 255 && strings.ToValidUTF8(filename, "") == filename &&
		strings.IndexFunc(filename, unicode.IsControl) < 0 && !strings.ContainsAny(filename, `/\`)
}

func safeContentType(contentType string) bool {
	if len(contentType) == 0 || len(contentType) > 127 || strings.ContainsAny(contentType, "\x00\r\n") {
		return false
	}
	parsed, parameters, err := mime.ParseMediaType(contentType)
	return err == nil && parsed != "" && len(parameters) == 0
}

func previewContentType(contentType string) bool {
	switch strings.ToLower(contentType) {
	case "text/plain", "image/png", "image/jpeg", "image/gif", "image/webp", "image/avif":
		return true
	default:
		return false
	}
}

func (service *Service) DownloadAttachment(ctx context.Context, mailbox MailboxContext, request AttachmentRequest) (AttachmentDownload, error) {
	if service.blobs == nil || service.scanner == nil {
		return AttachmentDownload{}, ErrUnavailable
	}
	if _, err := service.authenticateOperation(ctx, mailbox, "attachment.read"); err != nil {
		return AttachmentDownload{}, err
	}
	if !request.Identity.valid() || len(request.PartID) > 128 || !partIDPattern.MatchString(request.PartID) || !safeFilename(request.Filename) ||
		!safeContentType(request.ContentType) || request.MaximumBytes == 0 || request.MaximumBytes > MaximumAttachmentBytes ||
		(request.Disposition != "" && request.Disposition != "attachment" && request.Disposition != "inline") {
		return AttachmentDownload{}, errors.Join(ErrInvalid, service.receipt(ctx, mailbox, "attachment.read", "failed", 0, false))
	}
	source, declaredSize, err := service.backend.OpenPart(ctx, mailbox.Grant, request.Identity, request.PartID, request.MaximumBytes)
	if err != nil {
		return AttachmentDownload{}, errors.Join(err, service.receipt(ctx, mailbox, "attachment.read", "failed", 0, errors.Is(err, ErrPartial)))
	}
	owner := BlobOwner{TenantID: mailbox.TenantID, UserID: mailbox.Principal.UserID, MailboxID: mailbox.MailboxID}
	id, _, err := secretToken("q_")
	if err != nil {
		source.Close()
		return AttachmentDownload{}, err
	}
	blob, putErr := service.blobs.Put(ctx, BlobInfo{ID: id, Owner: owner, Filename: request.Filename,
		ContentType: request.ContentType, ExpiresAt: service.now().UTC().Add(5 * time.Minute)}, source, request.MaximumBytes)
	closeErr := source.Close()
	if putErr != nil || closeErr != nil || blob.Size != declaredSize {
		_ = service.blobs.Delete(ctx, owner, id)
		return AttachmentDownload{}, errors.Join(putErr, closeErr, ErrPartial, service.receipt(ctx, mailbox, "attachment.read", "failed", 0, true))
	}
	scanReader, _, err := service.blobs.Open(ctx, owner, id)
	if err != nil {
		_ = service.blobs.Delete(ctx, owner, id)
		return AttachmentDownload{}, err
	}
	countedScan := &countingReader{reader: io.LimitReader(scanReader, int64(blob.Size))}
	verdict, scanErr := service.scanner.Scan(ctx, countedScan, blob.Size)
	closeErr = scanReader.Close()
	if scanErr != nil || closeErr != nil || verdict != "clean" || countedScan.count != blob.Size {
		_ = service.blobs.Delete(ctx, owner, id)
		return AttachmentDownload{}, errors.Join(ErrUnauthorized, scanErr, closeErr,
			service.receipt(ctx, mailbox, "attachment.read", "failed", 0, false))
	}
	reader, _, err := service.blobs.Open(ctx, owner, id)
	if err != nil {
		_ = service.blobs.Delete(ctx, owner, id)
		return AttachmentDownload{}, err
	}
	disposition := "attachment"
	if request.Preview && previewContentType(request.ContentType) {
		disposition = "inline"
		if strings.HasPrefix(request.ContentType, "image/") {
			prefix := make([]byte, 16)
			read, readErr := io.ReadFull(reader, prefix)
			if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
				reader.Close()
				_ = service.blobs.Delete(ctx, owner, id)
				return AttachmentDownload{}, errors.Join(ErrProtocol, readErr)
			}
			prefix = prefix[:read]
			if !validImageBytes(request.ContentType, prefix) {
				reader.Close()
				_ = service.blobs.Delete(ctx, owner, id)
				return AttachmentDownload{}, ErrUnauthorized
			}
			reader = &joinedReadCloser{Reader: io.MultiReader(bytes.NewReader(prefix), reader), Closer: reader}
		}
	}
	download := AttachmentDownload{Filename: request.Filename, ContentType: request.ContentType, Disposition: disposition,
		Size: blob.Size, Digest: blob.Digest, MalwareState: "clean", CSP: messageCSP, NoSniff: true,
		Body: &deletingReader{reader: reader, delete: func() error { return service.blobs.Delete(context.Background(), owner, id) }}}
	return download, service.receipt(ctx, mailbox, "attachment.read", "succeeded", 1, false)
}

func (service *Service) UploadAttachment(ctx context.Context, mailbox MailboxContext, request UploadRequest, source io.Reader) (BlobInfo, error) {
	if service.blobs == nil || service.scanner == nil {
		return BlobInfo{}, ErrUnavailable
	}
	if _, err := service.authenticateOperation(ctx, mailbox, "attachment.upload"); err != nil {
		return BlobInfo{}, err
	}
	now := service.now().UTC()
	if source == nil || !safeFilename(request.Filename) || !safeContentType(request.ContentType) || request.MaximumBytes == 0 ||
		request.MaximumBytes > MaximumAttachmentBytes || !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(MaximumUploadLifetime)) {
		return BlobInfo{}, errors.Join(ErrInvalid, service.receipt(ctx, mailbox, "attachment.upload", "failed", 0, false))
	}
	id, _, err := secretToken("upl_")
	if err != nil {
		return BlobInfo{}, err
	}
	owner := BlobOwner{TenantID: mailbox.TenantID, UserID: mailbox.Principal.UserID, MailboxID: mailbox.MailboxID}
	blob, err := service.blobs.Put(ctx, BlobInfo{ID: id, Owner: owner, Filename: request.Filename,
		ContentType: request.ContentType, ExpiresAt: request.ExpiresAt.UTC()}, source, request.MaximumBytes)
	if err != nil {
		return BlobInfo{}, errors.Join(err, service.receipt(ctx, mailbox, "attachment.upload", "failed", 0, errors.Is(err, ErrPartial)))
	}
	scanReader, _, err := service.blobs.Open(ctx, owner, id)
	if err != nil {
		_ = service.blobs.Delete(ctx, owner, id)
		return BlobInfo{}, err
	}
	countedScan := &countingReader{reader: io.LimitReader(scanReader, int64(blob.Size))}
	verdict, scanErr := service.scanner.Scan(ctx, countedScan, blob.Size)
	closeErr := scanReader.Close()
	if scanErr != nil || closeErr != nil || verdict != "clean" || countedScan.count != blob.Size {
		_ = service.blobs.Delete(ctx, owner, id)
		return BlobInfo{}, errors.Join(ErrUnauthorized, scanErr, closeErr,
			service.receipt(ctx, mailbox, "attachment.upload", "failed", 0, false))
	}
	if err = service.repository.StoreUpload(ctx, blob); err != nil {
		_ = service.blobs.Delete(ctx, owner, id)
		return BlobInfo{}, errors.Join(err, service.receipt(ctx, mailbox, "attachment.upload", "failed", 0, false))
	}
	return blob, service.receipt(ctx, mailbox, "attachment.upload", "succeeded", 1, false)
}

func (service *Service) DeleteUpload(ctx context.Context, mailbox MailboxContext, uploadID string) error {
	if service.blobs == nil {
		return ErrUnavailable
	}
	if _, err := service.authenticateOperation(ctx, mailbox, "attachment.delete"); err != nil {
		return err
	}
	owner := BlobOwner{TenantID: mailbox.TenantID, UserID: mailbox.Principal.UserID, MailboxID: mailbox.MailboxID}
	if !opaqueIDPattern.MatchString(uploadID) {
		return errors.Join(ErrInvalid, service.receipt(ctx, mailbox, "attachment.delete", "failed", 0, false))
	}
	if _, err := service.repository.GetUploads(ctx, owner, []string{uploadID}, service.now().UTC()); err != nil {
		return errors.Join(err, service.receipt(ctx, mailbox, "attachment.delete", "failed", 0, false))
	}
	if err := service.blobs.Delete(ctx, owner, uploadID); err != nil {
		return errors.Join(err, service.receipt(ctx, mailbox, "attachment.delete", "failed", 0, false))
	}
	if err := service.repository.DeleteUpload(ctx, owner, uploadID); err != nil {
		return errors.Join(ErrPartial, err, service.receipt(ctx, mailbox, "attachment.delete", "failed", 0, true))
	}
	return service.receipt(ctx, mailbox, "attachment.delete", "succeeded", 0, false)
}

func validateComposeAddress(address ComposeAddress) (mail.Address, error) {
	if len(address.Name) > 256 || strings.IndexFunc(address.Name, unicode.IsControl) >= 0 || len(address.Address) > 320 || strings.ContainsAny(address.Address, "\x00\r\n") {
		return mail.Address{}, ErrInvalid
	}
	if strings.ContainsAny(address.Name, `,"\`) {
		return mail.Address{}, ErrInvalid
	}
	parsed, err := mail.ParseAddress(address.Address)
	if err != nil || parsed.Address != address.Address || parsed.Address == "" {
		return mail.Address{}, ErrInvalid
	}
	return mail.Address{Name: address.Name, Address: parsed.Address}, nil
}

func normalizeCompose(message ComposeMessage, account AuthorizedMailAccount, now time.Time, requireRecipients bool) (ComposeMessage, []mail.Address, error) {
	if !opaqueIDPattern.MatchString(message.ID) || len(message.Subject) > 998 || strings.IndexFunc(message.Subject, unicode.IsControl) >= 0 ||
		len(message.PlainText) > MaximumRenderedPartBytes || len(message.SanitizedHTML) > MaximumRenderedPartBytes ||
		len(message.AttachmentIDs) > MaximumComposeAttachments || len(message.References) > 64 ||
		!message.SendAt.IsZero() && (message.SendAt.Before(now) || message.SendAt.After(now.Add(365*24*time.Hour))) {
		return ComposeMessage{}, nil, ErrInvalid
	}
	if message.Mode != ComposeNew && message.Mode != ComposeReply && message.Mode != ComposeReplyAll && message.Mode != ComposeForward {
		return ComposeMessage{}, nil, ErrInvalid
	}
	if message.Mode != ComposeNew && (message.InReplyTo == "" || len(message.InReplyTo) > 255 || strings.ContainsAny(message.InReplyTo, "\x00\r\n <>\t")) {
		return ComposeMessage{}, nil, ErrInvalid
	}
	from, err := validateComposeAddress(message.From)
	if err != nil {
		return ComposeMessage{}, nil, err
	}
	accountAddress, err := mail.ParseAddress(account.AddressLabel)
	if err != nil || !strings.EqualFold(accountAddress.Address, from.Address) {
		return ComposeMessage{}, nil, ErrUnauthorized
	}
	recipients := make([]mail.Address, 0, len(message.To)+len(message.CC)+len(message.BCC))
	seenRecipients := make(map[string]bool)
	for _, group := range [][]ComposeAddress{message.To, message.CC, message.BCC, message.ReplyTo} {
		for _, address := range group {
			_, parseErr := validateComposeAddress(address)
			if parseErr != nil {
				return ComposeMessage{}, nil, parseErr
			}
		}
	}
	for _, address := range append(append(append([]ComposeAddress(nil), message.To...), message.CC...), message.BCC...) {
		parsed, parseErr := validateComposeAddress(address)
		if parseErr != nil {
			return ComposeMessage{}, nil, parseErr
		}
		key := strings.ToLower(parsed.Address)
		if seenRecipients[key] {
			return ComposeMessage{}, nil, ErrInvalid
		}
		seenRecipients[key] = true
		recipients = append(recipients, parsed)
	}
	if requireRecipients && len(recipients) == 0 || len(recipients) > MaximumRecipients {
		return ComposeMessage{}, nil, ErrLimit
	}
	seenAttachments := make(map[string]bool)
	for _, id := range message.AttachmentIDs {
		if !opaqueIDPattern.MatchString(id) || seenAttachments[id] {
			return ComposeMessage{}, nil, ErrInvalid
		}
		seenAttachments[id] = true
	}
	for _, reference := range message.References {
		if len(reference) == 0 || len(reference) > 255 || strings.ContainsAny(reference, "\x00\r\n <>\t") {
			return ComposeMessage{}, nil, ErrInvalid
		}
	}
	if len(strings.Join(message.References, " ")) > 900 {
		return ComposeMessage{}, nil, ErrLimit
	}
	if message.SanitizedHTML != "" {
		sanitized, _, sanitizeErr := sanitizeHTMLDocument(message.SanitizedHTML, RemoteImagesBlocked)
		if sanitizeErr != nil {
			return ComposeMessage{}, nil, sanitizeErr
		}
		message.SanitizedHTML = sanitized
	}
	return message, recipients, nil
}

func formatComposeAddresses(addresses []ComposeAddress) string {
	formatted := make([]string, 0, len(addresses))
	for _, address := range addresses {
		formatted = append(formatted, (&mail.Address{Name: address.Name, Address: address.Address}).String())
	}
	return strings.Join(formatted, ", ")
}

func writeFoldedHeader(writer io.Writer, name, value string) error {
	if name == "" || value == "" || strings.ContainsAny(name+value, "\x00\r\n") {
		return ErrInvalid
	}
	pieces := strings.Split(value, ", ")
	line := name + ": "
	for index, piece := range pieces {
		separator := ""
		if index > 0 {
			separator = ", "
		}
		if len(line)+len(separator)+len(piece) > 78 && line != name+": " {
			if len(line) > 998 {
				return ErrLimit
			}
			if _, err := io.WriteString(writer, line+",\r\n"); err != nil {
				return err
			}
			line = " " + piece
			continue
		}
		line += separator + piece
	}
	if len(line) > 998 {
		return ErrLimit
	}
	_, err := io.WriteString(writer, line+"\r\n")
	return err
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (writer *boundedWriter) Write(content []byte) (int, error) {
	if int64(len(content)) > writer.remaining {
		return 0, ErrLimit
	}
	written, err := writer.writer.Write(content)
	writer.remaining -= int64(written)
	return written, err
}

type mimeLineWriter struct {
	writer io.Writer
	column int
}

func (writer *mimeLineWriter) Write(content []byte) (int, error) {
	consumed := 0
	for len(content) > 0 {
		room := 76 - writer.column
		if room == 0 {
			if _, err := io.WriteString(writer.writer, "\r\n"); err != nil {
				return consumed, err
			}
			writer.column = 0
			room = 76
		}
		count := room
		if count > len(content) {
			count = len(content)
		}
		written, err := writer.writer.Write(content[:count])
		consumed += written
		writer.column += written
		content = content[written:]
		if err != nil {
			return consumed, err
		}
		if written != count {
			return consumed, io.ErrShortWrite
		}
	}
	return consumed, nil
}

func writeTextMIMEPart(writer *multipart.Writer, contentType, content string) error {
	header := make(textproto.MIMEHeader)
	header.Set("Content-Type", contentType+`; charset="utf-8"`)
	header.Set("Content-Transfer-Encoding", "quoted-printable")
	part, err := writer.CreatePart(header)
	if err != nil {
		return err
	}
	encoded := quotedprintable.NewWriter(part)
	if _, err = io.WriteString(encoded, strings.ReplaceAll(content, "\r\n", "\n")); err != nil {
		encoded.Close()
		return err
	}
	return encoded.Close()
}

func writeMIMEMessage(ctx context.Context, destination io.Writer, message ComposeMessage, uploads []BlobInfo, blobs BlobStore) error {
	bounded := &boundedWriter{writer: destination, remaining: MaximumComposeBytes}
	buffered := bufio.NewWriterSize(bounded, 32<<10)
	from, _ := validateComposeAddress(message.From)
	headers := []struct{ name, value string }{
		{"Date", time.Now().UTC().Format(time.RFC1123Z)},
		{"Message-ID", "<" + digestParts(message.ID, from.Address)[:32] + "@cyberpanel.local>"},
		{"From", (&from).String()}, {"To", formatComposeAddresses(message.To)},
		{"Subject", mime.QEncoding.Encode("utf-8", message.Subject)}, {"MIME-Version", "1.0"},
	}
	if len(message.CC) > 0 {
		headers = append(headers, struct{ name, value string }{"Cc", formatComposeAddresses(message.CC)})
	}
	if len(message.ReplyTo) > 0 {
		headers = append(headers, struct{ name, value string }{"Reply-To", formatComposeAddresses(message.ReplyTo)})
	}
	if message.InReplyTo != "" {
		headers = append(headers, struct{ name, value string }{"In-Reply-To", "<" + message.InReplyTo + ">"})
	}
	if len(message.References) > 0 {
		references := make([]string, len(message.References))
		for index, reference := range message.References {
			references[index] = "<" + reference + ">"
		}
		headers = append(headers, struct{ name, value string }{"References", strings.Join(references, " ")})
	}
	outer := multipart.NewWriter(buffered)
	for _, header := range headers {
		if err := writeFoldedHeader(buffered, header.name, header.value); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(buffered, "Content-Type: multipart/mixed; boundary=\""+outer.Boundary()+"\"\r\n\r\n"); err != nil {
		return err
	}
	alternativeBoundary := multipart.NewWriter(io.Discard).Boundary()
	alternativeHeader := make(textproto.MIMEHeader)
	alternativeHeader.Set("Content-Type", `multipart/alternative; boundary="`+alternativeBoundary+`"`)
	alternativePart, err := outer.CreatePart(alternativeHeader)
	if err != nil {
		return err
	}
	alternative := multipart.NewWriter(alternativePart)
	if err = alternative.SetBoundary(alternativeBoundary); err != nil {
		return err
	}
	if err = writeTextMIMEPart(alternative, "text/plain", message.PlainText); err != nil {
		return err
	}
	if message.SanitizedHTML != "" {
		if err = writeTextMIMEPart(alternative, "text/html", message.SanitizedHTML); err != nil {
			return err
		}
	}
	if err = alternative.Close(); err != nil {
		return err
	}
	for _, upload := range uploads {
		if err = ctx.Err(); err != nil {
			return err
		}
		reader, stored, openErr := blobs.Open(ctx, upload.Owner, upload.ID)
		if openErr != nil {
			return openErr
		}
		if stored.Size != upload.Size {
			reader.Close()
			return ErrConflict
		}
		header := make(textproto.MIMEHeader)
		header.Set("Content-Type", mime.FormatMediaType(upload.ContentType, map[string]string{"name": upload.Filename}))
		header.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": upload.Filename}))
		header.Set("Content-Transfer-Encoding", "base64")
		part, createErr := outer.CreatePart(header)
		if createErr != nil {
			reader.Close()
			return createErr
		}
		hash := sha256.New()
		lineWriter := &mimeLineWriter{writer: part}
		encoder := base64.NewEncoder(base64.StdEncoding, lineWriter)
		written, copyErr := io.Copy(encoder, io.TeeReader(io.LimitReader(&contextReader{ctx: ctx, reader: reader}, int64(upload.Size)+1), hash))
		closeEncoderErr := encoder.Close()
		closeReaderErr := reader.Close()
		if copyErr != nil || closeEncoderErr != nil || closeReaderErr != nil || uint64(written) != upload.Size ||
			hex.EncodeToString(hash.Sum(nil)) != upload.Digest {
			return errors.Join(ErrConflict, copyErr, closeEncoderErr, closeReaderErr)
		}
		if _, err = io.WriteString(part, "\r\n"); err != nil {
			return err
		}
	}
	if err = outer.Close(); err != nil {
		return err
	}
	return buffered.Flush()
}

func (service *Service) SaveDraft(ctx context.Context, mailbox MailboxContext, message ComposeMessage, expectedRevision uint64) (Draft, error) {
	account, err := service.authenticateOperation(ctx, mailbox, "draft.save")
	if err != nil {
		return Draft{}, err
	}
	message, _, err = normalizeCompose(message, account, service.now().UTC(), false)
	if err != nil {
		return Draft{}, errors.Join(err, service.receipt(ctx, mailbox, "draft.save", "failed", 0, false))
	}
	if len(message.AttachmentIDs) > 0 {
		if _, err = service.repository.GetUploads(ctx, BlobOwner{TenantID: mailbox.TenantID, UserID: mailbox.Principal.UserID,
			MailboxID: mailbox.MailboxID}, message.AttachmentIDs, service.now().UTC()); err != nil {
			return Draft{}, errors.Join(err, service.receipt(ctx, mailbox, "draft.save", "failed", 0, false))
		}
	}
	draft, err := service.repository.PutDraft(ctx, Draft{TenantID: mailbox.TenantID, UserID: mailbox.Principal.UserID,
		MailboxID: mailbox.MailboxID, Message: message}, expectedRevision)
	if err != nil {
		return Draft{}, errors.Join(err, service.receipt(ctx, mailbox, "draft.save", "failed", 0, false))
	}
	return draft, service.receipt(ctx, mailbox, "draft.save", "succeeded", 1, false)
}

func (service *Service) GetDraft(ctx context.Context, mailbox MailboxContext, draftID string) (Draft, error) {
	if _, err := service.authenticateOperation(ctx, mailbox, "draft.get"); err != nil {
		return Draft{}, err
	}
	owner := BlobOwner{TenantID: mailbox.TenantID, UserID: mailbox.Principal.UserID, MailboxID: mailbox.MailboxID}
	draft, err := service.repository.GetDraft(ctx, owner, draftID)
	if err != nil {
		return Draft{}, errors.Join(err, service.receipt(ctx, mailbox, "draft.get", "failed", 0, false))
	}
	return draft, service.receipt(ctx, mailbox, "draft.get", "succeeded", 1, false)
}

func (service *Service) DeleteDraft(ctx context.Context, mailbox MailboxContext, draftID string, expectedRevision uint64) error {
	if _, err := service.authenticateOperation(ctx, mailbox, "draft.delete"); err != nil {
		return err
	}
	owner := BlobOwner{TenantID: mailbox.TenantID, UserID: mailbox.Principal.UserID, MailboxID: mailbox.MailboxID}
	if err := service.repository.DeleteDraft(ctx, owner, draftID, expectedRevision); err != nil {
		return errors.Join(err, service.receipt(ctx, mailbox, "draft.delete", "failed", 0, false))
	}
	return service.receipt(ctx, mailbox, "draft.delete", "succeeded", 0, false)
}

func (service *Service) Send(ctx context.Context, mailbox MailboxContext, message ComposeMessage) (string, error) {
	if service.blobs == nil || service.submitter == nil {
		return "", ErrUnavailable
	}
	account, err := service.authenticateOperation(ctx, mailbox, "message.send")
	if err != nil {
		return "", err
	}
	now := service.now().UTC()
	message, recipients, err := normalizeCompose(message, account, now, true)
	if err != nil {
		return "", errors.Join(err, service.receipt(ctx, mailbox, "message.send", "failed", 0, false))
	}
	owner := BlobOwner{TenantID: mailbox.TenantID, UserID: mailbox.Principal.UserID, MailboxID: mailbox.MailboxID}
	uploads := []BlobInfo(nil)
	if len(message.AttachmentIDs) > 0 {
		uploads, err = service.repository.GetUploads(ctx, owner, message.AttachmentIDs, now)
		if err != nil {
			return "", errors.Join(err, service.receipt(ctx, mailbox, "message.send", "failed", 0, false))
		}
	}
	var total uint64 = uint64(len(message.PlainText) + len(message.SanitizedHTML) + 1<<20)
	for _, upload := range uploads {
		if upload.Size > MaximumComposeBytes-total {
			return "", errors.Join(ErrLimit, service.receipt(ctx, mailbox, "message.send", "failed", 0, false))
		}
		total += upload.Size
		if !message.SendAt.IsZero() && !upload.ExpiresAt.After(message.SendAt.Add(time.Hour)) {
			return "", errors.Join(ErrConflict, service.receipt(ctx, mailbox, "message.send", "failed", 0, false))
		}
	}
	if !message.SendAt.IsZero() {
		if service.scheduler == nil {
			return "", errors.Join(ErrUnavailable, service.receipt(ctx, mailbox, "message.send", "failed", 0, false))
		}
		id, scheduleErr := service.scheduler.Schedule(ctx, owner, message)
		if scheduleErr != nil || !opaqueIDPattern.MatchString(id) {
			return "", errors.Join(ErrUnavailable, scheduleErr, service.receipt(ctx, mailbox, "message.send", "failed", 0, false))
		}
		return id, service.receipt(ctx, mailbox, "message.send", "succeeded", 1, false)
	}
	envelopeRecipients := make([]string, len(recipients))
	for index, recipient := range recipients {
		envelopeRecipients[index] = recipient.Address
	}
	pipeReader, pipeWriter := io.Pipe()
	composeResult := make(chan error, 1)
	go func() {
		composeErr := writeMIMEMessage(ctx, pipeWriter, message, uploads, service.blobs)
		_ = pipeWriter.CloseWithError(composeErr)
		composeResult <- composeErr
	}()
	queueID, submitErr := service.submitter.Submit(ctx, SubmissionEnvelope{From: message.From.Address, Recipients: envelopeRecipients}, pipeReader, MaximumComposeBytes)
	_ = pipeReader.CloseWithError(submitErr)
	composeErr := <-composeResult
	if submitErr != nil || composeErr != nil || !opaqueIDPattern.MatchString(queueID) {
		return "", errors.Join(ErrUnavailable, submitErr, composeErr, service.receipt(ctx, mailbox, "message.send", "failed", 0, errors.Is(submitErr, ErrPartial)))
	}
	var cleanupErr error
	for _, upload := range uploads {
		cleanupErr = errors.Join(cleanupErr, service.blobs.Delete(ctx, owner, upload.ID), service.repository.DeleteUpload(ctx, owner, upload.ID))
	}
	return queueID, errors.Join(cleanupErr, service.receipt(ctx, mailbox, "message.send", "succeeded", 1, false))
}

func (service *Service) ApplyMessages(ctx context.Context, mailbox MailboxContext, request MessageActionRequest) (MessageActionResult, error) {
	if _, err := service.authenticateOperation(ctx, mailbox, "message.action"); err != nil {
		return MessageActionResult{}, err
	}
	if !request.valid() {
		return MessageActionResult{}, errors.Join(ErrInvalid, service.receipt(ctx, mailbox, "message.action", "failed", 0, false))
	}
	if (request.Action == ActionSpam || request.Action == ActionNotSpam) && service.spam == nil {
		return MessageActionResult{}, errors.Join(ErrUnavailable, service.receipt(ctx, mailbox, "message.action", "failed", 0, false))
	}
	result, err := service.backend.ApplyMessages(ctx, mailbox.Grant, request)
	if err != nil {
		return MessageActionResult{}, errors.Join(err, service.receipt(ctx, mailbox, "message.action", "failed", 0, errors.Is(err, ErrPartial)))
	}
	if request.Action == ActionSpam || request.Action == ActionNotSpam {
		if service.spam == nil {
			return result, errors.Join(ErrPartial, service.receipt(ctx, mailbox, "message.action", "failed", int(result.Affected), true))
		}
		owner := BlobOwner{TenantID: mailbox.TenantID, UserID: mailbox.Principal.UserID, MailboxID: mailbox.MailboxID}
		if err = service.spam.Report(ctx, owner, request.Messages, request.Action == ActionSpam); err != nil {
			return result, errors.Join(ErrPartial, err, service.receipt(ctx, mailbox, "message.action", "failed", int(result.Affected), true))
		}
	}
	return result, service.receipt(ctx, mailbox, "message.action", "succeeded", int(result.Affected), false)
}
