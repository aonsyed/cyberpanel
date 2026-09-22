//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	securewebmail "github.com/aonsyed/cyberpanel/platform/internal/webmail"
	"github.com/aonsyed/cyberpanel/platform/internal/webmaildata"
)

const localManageSieveSocket = "/run/dovecot/cyberpanel-managesieve"

type localManageSieveCredentials struct {
	authority  webmailDataAuthority
	service    *securewebmail.Service
	repository *securewebmail.SQLiteRepository
	directory  secureWebmailDirectory
}

func (provider localManageSieveCredentials) CredentialsForManageSieve(ctx context.Context, scope webmaildata.Scope) (webmaildata.ManageSieveCredentials, error) {
	if ctx == nil || !scope.Valid() || provider.service == nil || provider.repository == nil {
		return webmaildata.ManageSieveCredentials{}, webmaildata.ErrInvalid
	}
	if err := provider.authority.authorize(ctx, scope.UserID, scope, identity.AssuranceMFA); err != nil {
		return webmaildata.ManageSieveCredentials{}, err
	}
	principal := securewebmail.Principal{UserID: scope.UserID, SessionID: "managesieve"}
	binding, err := provider.directory.AuthorizeMailbox(ctx, principal, scope.TenantID, scope.MailboxID)
	if err != nil {
		return webmaildata.ManageSieveCredentials{}, err
	}
	grant, err := provider.service.IssueGrant(ctx, principal, scope.TenantID, scope.MailboxID, "managesieve")
	if err != nil {
		return webmaildata.ManageSieveCredentials{}, err
	}
	digest := sha256.Sum256([]byte(grant.Token))
	claims := securewebmail.GrantClaims{TenantID: scope.TenantID, UserID: scope.UserID, SessionID: principal.SessionID, MailboxID: scope.MailboxID, Audience: "cyberpanel-webmail", AuthorizationEpoch: binding.AuthorizationEpoch}
	if err = provider.repository.ConsumeGrant(ctx, hex.EncodeToString(digest[:]), claims, time.Now().UTC()); err != nil {
		return webmaildata.ManageSieveCredentials{}, err
	}
	return webmaildata.ManageSieveCredentials{Username: binding.AddressLabel, Secret: []byte(grant.Token), OAuthBearer: true}, nil
}

type webmailDataAuthority struct {
	authorizer *identity.Authorizer
	store      *identity.Store
	directory  mail.SQLWebmailDirectory
	now        func() time.Time
}

func (authority webmailDataAuthority) AuthorizeWebmailData(ctx context.Context, request webmaildata.AuthorizationRequest) error {
	return authority.authorize(ctx, request.ActorID, request.Scope, identity.AssurancePassword)
}

func (authority webmailDataAuthority) VerifyWebmailDataStepUp(ctx context.Context, actorID string, scope webmaildata.Scope, proof string) error {
	principalID, err := identity.NewID(actorID)
	if ctx == nil || err != nil || authority.store == nil {
		return webmaildata.ErrStepUp
	}
	credentialID, err := identity.NewID(proof)
	if err != nil {
		return webmaildata.ErrStepUp
	}
	credential, err := authority.store.Credential(ctx, credentialID)
	if err != nil || credential.PrincipalID != principalID || credential.State != identity.CredentialActive {
		return webmaildata.ErrStepUp
	}
	if err = authority.authorize(ctx, actorID, scope, identity.AssuranceMFA); err != nil {
		return webmaildata.ErrStepUp
	}
	return nil
}

func (authority webmailDataAuthority) authorize(ctx context.Context, actorID string, scope webmaildata.Scope, assurance identity.AssuranceLevel) error {
	if ctx == nil || authority.authorizer == nil || authority.now == nil || !scope.Valid() || actorID != scope.UserID {
		return webmaildata.ErrUnauthorized
	}
	principalID, err := identity.NewID(actorID)
	if err != nil {
		return webmaildata.ErrUnauthorized
	}
	tenantID, err := identity.NewID(scope.TenantID)
	if err != nil {
		return webmaildata.ErrUnauthorized
	}
	decision, err := authority.authorizer.Decide(ctx, identity.AuthorizationRequest{
		PrincipalID: principalID,
		Permission:  identity.MustPermission("mail:manage"),
		Scope:       identity.Scope{Kind: identity.ScopeTenant, TenantID: tenantID},
		At:          authority.now().UTC(),
		Assurance:   assurance,
	})
	if err != nil || !decision.Allowed {
		return webmaildata.ErrUnauthorized
	}
	if _, err = authority.directory.ResolveWebmailBinding(ctx, scope.TenantID, mail.MailboxID(scope.MailboxID)); err != nil {
		return webmaildata.ErrUnauthorized
	}
	return nil
}

type webmailDataAudit struct {
	writer *audit.Writer
}

func (sink webmailDataAudit) RecordWebmailData(ctx context.Context, event webmaildata.AuditEvent) error {
	if ctx == nil || sink.writer == nil || !event.Scope.Valid() || event.OperationID == "" || event.ActorID == "" || event.Operation == "" || event.OccurredAt.IsZero() {
		return audit.ErrInvalid
	}
	requestSum := sha256.Sum256([]byte(event.OperationID + "\x00" + event.ActorID + "\x00" + string(event.Operation) + "\x00" + event.Scope.TenantID + "\x00" + event.Scope.UserID + "\x00" + event.Scope.MailboxID + "\x00" + event.ResourceID + "\x00" + strconv.FormatUint(event.Before, 10) + "\x00" + strconv.FormatUint(event.After, 10) + "\x00" + event.Digest))
	eventSum := sha256.Sum256([]byte("webmail-data-v1\x00" + event.OperationID))
	targetID := event.ResourceID
	if targetID == "" {
		targetID = event.Scope.MailboxID
	}
	_, err := sink.writer.Append(ctx, audit.Event{
		ID:      "webmail-data-" + hex.EncodeToString(eventSum[:24]),
		Class:   audit.ClassMutation,
		Action:  "webmail.data." + string(event.Operation),
		Actor:   audit.Actor{PrincipalID: event.ActorID, TenantID: event.Scope.TenantID},
		Target:  audit.Target{Kind: "webmail_data", ID: targetID, TenantID: event.Scope.TenantID, Generation: strconv.FormatUint(event.After, 10)},
		Outcome: audit.OutcomeApplied,

		RequestDigest: hex.EncodeToString(requestSum[:]),
		EffectID:      event.OperationID,
		Attributes: map[string]string{
			"before_revision": strconv.FormatUint(event.Before, 10),
			"after_revision":  strconv.FormatUint(event.After, 10),
			"content_digest":  event.Digest,
			"mailbox_id":      event.Scope.MailboxID,
		},
		OccurredAt: event.OccurredAt.UTC(),
	})
	return err
}

func assembleWebmailDataService(ctx context.Context, database *sql.DB, mailStore mail.SQLControlRepository, identityStore *identity.Store, auditService *audit.Service, hostname string, grants *securewebmail.Service, grantRepository *securewebmail.SQLiteRepository) (*webmaildata.Service, error) {
	repository, err := webmaildata.NewSQLiteRepository(database)
	if err != nil {
		return nil, err
	}
	if err = repository.Bootstrap(ctx); err != nil {
		return nil, err
	}
	authorizer, err := identity.NewAuthorizer(identityStore)
	if err != nil {
		return nil, err
	}
	directory := mail.SQLWebmailDirectory{Store: mailStore, ServerName: hostname}
	authority := webmailDataAuthority{authorizer: authorizer, store: identityStore, directory: directory, now: runtimeClock{}.Now}
	service := &webmaildata.Service{
		Repository: repository,
		Authorizer: authority,
		StepUp:     authority,
		Audit:      webmailDataAudit{writer: auditService.Writer},
		SieveRuntime: &webmaildata.LocalManageSieveAdapter{
			UnixSocket:  localManageSieveSocket,
			Credentials: localManageSieveCredentials{authority: authority, service: grants, repository: grantRepository, directory: secureWebmailDirectory{store: mailStore}},
		},
		Now: runtimeClock{}.Now,
	}
	vacationRepository, err := mail.NewSQLAutoresponderRepository(database)
	if err != nil {
		return nil, err
	}
	if err = vacationRepository.Bootstrap(ctx); err != nil {
		return nil, err
	}
	vacations := &localVacationLifecycle{repository: vacationRepository, store: mailStore, authority: authority, audit: webmailDataAudit{writer: auditService.Writer}, data: service, native: service.SieveRuntime.(*webmaildata.LocalManageSieveAdapter)}
	service.Vacations, service.Autoresponders = vacations, vacations
	return service, nil
}

var _ webmaildata.ManageSieveCredentialProvider = localManageSieveCredentials{}
var _ webmaildata.Authorizer = webmailDataAuthority{}
var _ webmaildata.StepUpVerifier = webmailDataAuthority{}
var _ webmaildata.AuditSink = webmailDataAudit{}
