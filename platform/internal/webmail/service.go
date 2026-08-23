package webmail

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"time"
)

type Service struct {
	repository Repository
	authorizer Authorizer
	auditor    Auditor
	backend    Backend
	audience   string
	grantLifetime time.Duration
	now        func() time.Time
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
		Folder string
		Sort MessageSort
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
		Folder string
		Criteria SearchCriteria
		Sort MessageSort
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
