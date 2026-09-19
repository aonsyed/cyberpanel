package sitepreview

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"
)

type Assurance uint8

const (
	AssuranceSession Assurance = 1
	AssuranceMFA     Assurance = 2
	AssurancePhishingResistant Assurance = 3
)

type Actor struct {
	PrincipalID PrincipalID
	AuthzEpoch  uint64
	Assurance   Assurance
}

func (actor Actor) Validate() error {
	if !validID(string(actor.PrincipalID)) || actor.AuthzEpoch == 0 || actor.Assurance < AssuranceSession || actor.Assurance > AssurancePhishingResistant {
		return ErrInvalid
	}
	return nil
}

type Action string

const (
	ActionIssuePreview      Action = "preview.issue"
	ActionConsumePreview    Action = "preview.consume"
	ActionRevokePreview     Action = "preview.revoke"
	ActionListPreviews      Action = "preview.list"
	ActionQueueScreenshot   Action = "screenshot.queue"
	ActionInspectScreenshot Action = "screenshot.inspect"
	ActionRenderScreenshot  Action = "screenshot.render"
)

type AuthorizationRequest struct {
	Actor       Actor
	TenantID    TenantID
	SiteID      SiteID
	SessionID   SessionID
	Audience    Audience
	Action      Action
	MinimumAssurance Assurance
}

type AuthorizationDecision struct {
	TenantID                   TenantID
	SiteID                     SiteID
	PrincipalID                PrincipalID
	CurrentActorAuthzEpoch     uint64
	CurrentAudienceAuthzEpoch  uint64
	Allowed                    bool
}

type Authorizer interface {
	AuthorizeSitePreview(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
}

type SiteDirectory interface {
	ResolveExactSite(context.Context, TenantID, SiteID) (SiteSnapshot, error)
}

type AuditEvent struct {
	TenantID      TenantID
	ActorID       PrincipalID
	Action        Action
	ResourceKind  string
	ResourceID    string
	SiteID        SiteID
	SiteGeneration uint64
	AuthzEpoch    uint64
	RequestDigest string
	Outcome       string
	OccurredAt    time.Time
}

func (event AuditEvent) Validate() error {
	if !validID(string(event.TenantID)) || !validID(string(event.ActorID)) || !validID(string(event.Action)) || !validID(event.ResourceKind) || !validID(event.ResourceID) ||
		!validID(string(event.SiteID)) || event.SiteGeneration == 0 || event.AuthzEpoch == 0 || !validDigest(event.RequestDigest) || !validID(event.Outcome) || event.OccurredAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type AuditSink interface {
	RecordSitePreview(context.Context, AuditEvent) error
}

type RouteEffectOutcome string

const (
	RouteApplied    RouteEffectOutcome = "applied"
	RouteRolledBack RouteEffectOutcome = "rolled_back"
	RouteAbsent     RouteEffectOutcome = "absent"
	RouteAmbiguous  RouteEffectOutcome = "ambiguous"
)

type RouteEffectReceipt struct {
	Outcome        RouteEffectOutcome
	Lease          RouteLease
	Proof          RouteProof
	EvidenceDigest string
}

func (receipt RouteEffectReceipt) Validate(spec RouteSpec) error {
	if receipt.Lease.Validate() != nil || receipt.Lease.SessionID != spec.SessionID || receipt.Lease.SpecDigest != digestJSON("cyberpanel:sitepreview:route:v1", spec) || !validDigest(receipt.EvidenceDigest) {
		return ErrInvalid
	}
	switch receipt.Outcome {
	case RouteApplied:
		if !receipt.Proof.ValidFor(spec) || receipt.Lease.State != "active" {
			return ErrInvalid
		}
	case RouteRolledBack:
		if receipt.Lease.State != "rolled_back" {
			return ErrInvalid
		}
	case RouteAbsent:
		if receipt.Lease.State != "expired" {
			return ErrInvalid
		}
	case RouteAmbiguous:
		if receipt.Lease.State != "ambiguous" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// RouteRuntime accepts only a fully resolved exact-site route. Implementations
// must render their own OLS/LSE binding and cannot accept config text, paths,
// listener IDs, arbitrary upstreams, or shell commands from the caller.
type RouteRuntime interface {
	InstallExactPreview(context.Context, RouteSpec) (RouteEffectReceipt, error)
	ObserveExactPreview(context.Context, RouteSpec, RouteLease) (RouteEffectReceipt, error)
	ExpireExactPreview(context.Context, RouteSpec, RouteLease) (RouteEffectReceipt, error)
	RollbackExactPreview(context.Context, RouteSpec, RouteLease) (RouteEffectReceipt, error)
}

type IssueRequest struct {
	Actor             Actor
	TenantID          TenantID
	SiteID            SiteID
	ExpectedGeneration uint64
	Audience          Audience
	GrantMode         GrantMode
	RequestedHostname string
	Limits            Limits
	CachePolicy       CachePolicy
}

type IssuedPreview struct {
	Session PreviewSession
	Token   []byte
}

type ConsumeRequest struct {
	Actor              Actor
	TenantID           TenantID
	SiteID             SiteID
	Audience           Audience
	PreviewHostname    string
	Token              []byte
	RequestBytes       uint64
}

type AccessGrant struct {
	SessionID          SessionID
	TenantID           TenantID
	SiteID             SiteID
	SiteGeneration     uint64
	PreviewHostname    string
	HostHeader         string
	SNI                string
	Backend            Backend
	Engine             Engine
	CachePolicy        CachePolicy
	WAFPolicy          WAFPolicy
	RemainingBytes     uint64
	RemainingRequests  uint32
	ExpiresAt          time.Time
}

type RevokeRequest struct {
	Actor              Actor
	TenantID           TenantID
	SiteID             SiteID
	SessionID          SessionID
	ExpectedGeneration uint64
}

type ListSessionsRequest struct {
	Actor    Actor
	TenantID TenantID
	SiteID   SiteID
	After    SessionID
	Limit    uint32
}

type ScreenshotInspection struct {
	Job      ScreenshotJob       `json:"job"`
	Artifact *ScreenshotArtifact `json:"artifact,omitempty"`
}

type Service struct {
	repository    *Repository
	sites         SiteDirectory
	authorizer    Authorizer
	audit         AuditSink
	runtime       RouteRuntime
	previewDomain string
	random        io.Reader
	now           func() time.Time
}

func NewService(repository *Repository, sites SiteDirectory, authorizer Authorizer, audit AuditSink, runtime RouteRuntime, previewDomain string) (*Service, error) {
	previewDomain = strings.ToLower(strings.TrimSuffix(previewDomain, "."))
	if repository == nil || sites == nil || authorizer == nil || audit == nil || runtime == nil || !validHostname(previewDomain) || repository.previewDomain != previewDomain {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, sites: sites, authorizer: authorizer, audit: audit, runtime: runtime, previewDomain: previewDomain, random: rand.Reader, now: time.Now}, nil
}

func (service *Service) Bootstrap(ctx context.Context) error {
	if service == nil {
		return ErrInvalid
	}
	return service.repository.Bootstrap(ctx)
}

func (service *Service) clock() time.Time {
	if service.now == nil {
		return time.Now().UTC()
	}
	return service.now().UTC()
}

func (service *Service) authorize(ctx context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
	return service.authorizer.AuthorizeSitePreview(ctx, request)
}

func (service *Service) Issue(ctx context.Context, request IssueRequest) (IssuedPreview, error) {
	if service == nil || request.Actor.Validate() != nil || !validID(string(request.TenantID)) || !validID(string(request.SiteID)) || request.ExpectedGeneration == 0 ||
		request.Audience.Validate() != nil || (request.GrantMode != GrantOneUse && request.GrantMode != GrantShortLived) || !validHostname(request.RequestedHostname) ||
		request.Limits.Validate(request.GrantMode) != nil || (request.CachePolicy != CacheBypassPrivate && request.CachePolicy != CacheSitePolicy) {
		return IssuedPreview{}, ErrInvalid
	}
	minimum := AssuranceSession
	if request.Audience.Kind == AudienceShare {
		minimum = AssuranceMFA
	}
	decision, err := service.authorize(ctx, AuthorizationRequest{Actor: request.Actor, TenantID: request.TenantID, SiteID: request.SiteID, Audience: request.Audience, Action: ActionIssuePreview, MinimumAssurance: minimum})
	if err != nil || !validDecision(decision, request.Actor, request.TenantID, request.SiteID) || decision.CurrentAudienceAuthzEpoch == 0 || request.Actor.Assurance < minimum {
		return IssuedPreview{}, concealAuthorization(err)
	}
	site, err := service.resolveSite(ctx, request.TenantID, request.SiteID, request.ExpectedGeneration)
	if err != nil || !site.AllowsHostname(request.RequestedHostname) || request.RequestedHostname != site.Backend.ServerName {
		return IssuedPreview{}, concealSite(err)
	}
	now := service.clock()
	token := make([]byte, 32)
	nonce := make([]byte, 24)
	if _, err = io.ReadFull(service.random, token); err != nil {
		return IssuedPreview{}, err
	}
	if _, err = io.ReadFull(service.random, nonce); err != nil {
		clear(token)
		return IssuedPreview{}, err
	}
	label := hex.EncodeToString(nonce)
	clear(nonce)
	hostname := "p-" + label + "." + service.previewDomain
	sessionID := SessionID("prv-" + label)
	session := PreviewSession{ID: sessionID, TenantID: request.TenantID, SiteID: request.SiteID, SiteGeneration: site.Generation, Audience: request.Audience, GrantMode: request.GrantMode,
		PreviewHostname: hostname, RequestedHostname: request.RequestedHostname, Backend: site.Backend, Engine: site.Engine, CachePolicy: request.CachePolicy, WAFPolicy: WAFEnforceSitePolicy,
		PHPGeneration: site.PHPGeneration, TLSGeneration: site.TLSGeneration, CacheGeneration: site.CacheGeneration, WAFGeneration: site.WAFGeneration, AuthzEpoch: decision.CurrentAudienceAuthzEpoch,
		Limits: request.Limits, State: SessionPreparing, Generation: 1, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(request.Limits.AbsoluteTTL)}
	tokenDigest := digestToken(token)
	requestDigest := digestJSON("cyberpanel:sitepreview:issue:v1", struct {
		TenantID TenantID
		SiteID SiteID
		Generation uint64
		Audience Audience
		Mode GrantMode
		RequestedHostname string
		Limits Limits
		Cache CachePolicy
	}{request.TenantID, request.SiteID, request.ExpectedGeneration, request.Audience, request.GrantMode, request.RequestedHostname, request.Limits, request.CachePolicy})
	if err = service.record(ctx, AuditEvent{TenantID: request.TenantID, ActorID: request.Actor.PrincipalID, Action: ActionIssuePreview, ResourceKind: "preview_session", ResourceID: string(sessionID), SiteID: request.SiteID,
		SiteGeneration: site.Generation, AuthzEpoch: decision.CurrentActorAuthzEpoch, RequestDigest: requestDigest, Outcome: "authorized", OccurredAt: now}); err != nil {
		clear(token)
		return IssuedPreview{}, err
	}
	if err = service.repository.CreateSession(ctx, session, TokenGrant{Digest: tokenDigest, Audience: request.Audience, Mode: request.GrantMode, AuthzEpoch: decision.CurrentAudienceAuthzEpoch, ExpiresAt: session.ExpiresAt}); err != nil {
		clear(token)
		return IssuedPreview{}, err
	}
	spec := routeSpec(session)
	effect, runtimeErr := service.runtime.InstallExactPreview(ctx, spec)
	if runtimeErr != nil || effect.Validate(spec) != nil || effect.Outcome != RouteApplied {
		clear(token)
		return IssuedPreview{}, service.handleFailedInstall(ctx, session, spec, requestDigest, effect, runtimeErr)
	}
	session.State, session.Generation = SessionActive, 2
	receipt := service.receipt(session.TenantID, "preview_session", string(session.ID), "route_install", "applied", session.Generation, requestDigest, effect.EvidenceDigest, now)
	if err = service.repository.ActivateSession(ctx, session, 1, effect.Lease, receipt); err != nil {
		rollback, rollbackErr := service.runtime.RollbackExactPreview(ctx, spec, effect.Lease)
		clear(token)
		if rollbackErr != nil || rollback.Validate(spec) != nil || rollback.Outcome != RouteRolledBack {
			closeReceipt := service.receipt(session.TenantID, "preview_session", string(session.ID), "route_install", "activation_ambiguous", 2, requestDigest, "", now)
			_, _ = service.repository.CloseSession(ctx, session.TenantID, session.ID, 1, SessionAmbiguous, now, closeReceipt)
			return IssuedPreview{}, errors.Join(ErrAmbiguous, err, rollbackErr)
		}
		closeReceipt := service.receipt(session.TenantID, "preview_session", string(session.ID), "route_install", "activation_rejected", 2, requestDigest, rollback.EvidenceDigest, now)
		_, _ = service.repository.CloseSession(ctx, session.TenantID, session.ID, 1, SessionExpired, now, closeReceipt)
		return IssuedPreview{}, err
	}
	if err = service.record(ctx, AuditEvent{TenantID: request.TenantID, ActorID: request.Actor.PrincipalID, Action: ActionIssuePreview, ResourceKind: "preview_session", ResourceID: string(sessionID), SiteID: request.SiteID,
		SiteGeneration: site.Generation, AuthzEpoch: decision.CurrentActorAuthzEpoch, RequestDigest: requestDigest, Outcome: "activated", OccurredAt: now}); err != nil {
		clear(token)
		return IssuedPreview{}, errors.Join(ErrAmbiguous, err)
	}
	return IssuedPreview{Session: session, Token: token}, nil
}

func (service *Service) Consume(ctx context.Context, request ConsumeRequest) (AccessGrant, error) {
	if service == nil || request.Actor.Validate() != nil || !validID(string(request.TenantID)) || !validID(string(request.SiteID)) || request.Audience.Validate() != nil ||
		!validHostname(request.PreviewHostname) || !strings.HasSuffix(request.PreviewHostname, "."+service.previewDomain) || len(request.Token) != 32 || request.RequestBytes > MaximumSessionBytes {
		return AccessGrant{}, ErrUnauthorized
	}
	decision, err := service.authorize(ctx, AuthorizationRequest{Actor: request.Actor, TenantID: request.TenantID, SiteID: request.SiteID, Audience: request.Audience, Action: ActionConsumePreview, MinimumAssurance: AssuranceSession})
	if err != nil || !validDecision(decision, request.Actor, request.TenantID, request.SiteID) || decision.CurrentAudienceAuthzEpoch == 0 {
		return AccessGrant{}, concealAuthorization(err)
	}
	session, err := service.repository.ConsumeGrant(ctx, ConsumeGrantRequest{TokenDigest: digestToken(request.Token), Audience: request.Audience, CurrentAuthzEpoch: decision.CurrentAudienceAuthzEpoch,
		PreviewHostname: request.PreviewHostname, RequestBytes: request.RequestBytes, Now: service.clock()})
	if err != nil || session.TenantID != request.TenantID || session.SiteID != request.SiteID {
		return AccessGrant{}, concealAuthorization(err)
	}
	site, err := service.resolveSite(ctx, session.TenantID, session.SiteID, session.SiteGeneration)
	if err != nil || !sessionMatchesSite(session, site) {
		return AccessGrant{}, ErrStaleGeneration
	}
	lease, err := service.repository.LoadRouteLease(ctx, session.TenantID, session.ID)
	if err != nil || lease.State != "active" || !service.clock().Before(lease.ExpiresAt) {
		return AccessGrant{}, ErrExpired
	}
	requestDigest := digestJSON("cyberpanel:sitepreview:consume:v1", struct {
		SessionID SessionID
		Generation uint64
		RequestBytes uint64
	}{session.ID, session.Generation, request.RequestBytes})
	if err = service.record(ctx, AuditEvent{TenantID: session.TenantID, ActorID: request.Actor.PrincipalID, Action: ActionConsumePreview, ResourceKind: "preview_session", ResourceID: string(session.ID), SiteID: session.SiteID,
		SiteGeneration: session.SiteGeneration, AuthzEpoch: session.AuthzEpoch, RequestDigest: requestDigest, Outcome: "admitted", OccurredAt: session.LastUsedAt}); err != nil {
		return AccessGrant{}, err
	}
	return AccessGrant{SessionID: session.ID, TenantID: session.TenantID, SiteID: session.SiteID, SiteGeneration: session.SiteGeneration, PreviewHostname: session.PreviewHostname,
		HostHeader: session.RequestedHostname, SNI: session.RequestedHostname, Backend: session.Backend, Engine: session.Engine, CachePolicy: session.CachePolicy, WAFPolicy: session.WAFPolicy,
		RemainingBytes: session.Limits.MaxBytes - session.ConsumedBytes, RemainingRequests: session.Limits.MaxRequests - session.ConsumedRequests, ExpiresAt: session.ExpiresAt}, nil
}

func (service *Service) Revoke(ctx context.Context, request RevokeRequest) error {
	if service == nil || request.Actor.Validate() != nil || !validID(string(request.TenantID)) || !validID(string(request.SiteID)) || !validID(string(request.SessionID)) || request.ExpectedGeneration == 0 {
		return ErrInvalid
	}
	decision, err := service.authorize(ctx, AuthorizationRequest{Actor: request.Actor, TenantID: request.TenantID, SiteID: request.SiteID, SessionID: request.SessionID, Action: ActionRevokePreview, MinimumAssurance: AssuranceMFA})
	if err != nil || !validDecision(decision, request.Actor, request.TenantID, request.SiteID) || request.Actor.Assurance < AssuranceMFA {
		return concealAuthorization(err)
	}
	session, err := service.repository.LoadSession(ctx, request.TenantID, request.SessionID)
	if err != nil || session.SiteID != request.SiteID {
		return concealSite(err)
	}
	now := service.clock()
	requestDigest := digestJSON("cyberpanel:sitepreview:revoke:v1", request)
	receipt := service.receipt(request.TenantID, "preview_session", string(request.SessionID), "revoke", "revoked", request.ExpectedGeneration+1, requestDigest, "", now)
	session, err = service.repository.RevokeSession(ctx, request.TenantID, request.SessionID, request.ExpectedGeneration, now, receipt)
	if err != nil {
		return err
	}
	lease, err := service.repository.LoadRouteLease(ctx, request.TenantID, request.SessionID)
	if err != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	effect, runtimeErr := service.runtime.ExpireExactPreview(ctx, routeSpec(session), lease)
	if runtimeErr != nil || effect.Validate(routeSpec(session)) != nil || effect.Outcome != RouteAbsent {
		lease.State, lease.Generation, lease.UpdatedAt = "ambiguous", lease.Generation+1, now
		_ = service.repository.SaveRouteLease(ctx, request.TenantID, lease, lease.Generation-1)
		_ = service.record(ctx, AuditEvent{TenantID: request.TenantID, ActorID: request.Actor.PrincipalID, Action: ActionRevokePreview, ResourceKind: "preview_session", ResourceID: string(request.SessionID), SiteID: request.SiteID,
			SiteGeneration: session.SiteGeneration, AuthzEpoch: decision.CurrentActorAuthzEpoch, RequestDigest: requestDigest, Outcome: "ambiguous", OccurredAt: now})
		return errors.Join(ErrAmbiguous, runtimeErr)
	}
	if err = service.repository.SaveRouteLease(ctx, request.TenantID, effect.Lease, lease.Generation); err != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	return service.record(ctx, AuditEvent{TenantID: request.TenantID, ActorID: request.Actor.PrincipalID, Action: ActionRevokePreview, ResourceKind: "preview_session", ResourceID: string(request.SessionID), SiteID: request.SiteID,
		SiteGeneration: session.SiteGeneration, AuthzEpoch: decision.CurrentActorAuthzEpoch, RequestDigest: requestDigest, Outcome: "revoked", OccurredAt: now})
}

func (service *Service) ListSessions(ctx context.Context, request ListSessionsRequest) ([]PreviewSession, SessionID, error) {
	if service == nil || request.Actor.Validate() != nil || !validID(string(request.TenantID)) || !validID(string(request.SiteID)) || request.After != "" && !validID(string(request.After)) || request.Limit == 0 || request.Limit > 500 {
		return nil, "", ErrInvalid
	}
	decision, err := service.authorize(ctx, AuthorizationRequest{Actor: request.Actor, TenantID: request.TenantID, SiteID: request.SiteID, Action: ActionListPreviews, MinimumAssurance: AssuranceSession})
	if err != nil || !validDecision(decision, request.Actor, request.TenantID, request.SiteID) {
		return nil, "", concealAuthorization(err)
	}
	site, err := service.sites.ResolveExactSite(ctx, request.TenantID, request.SiteID)
	if err != nil || site.Validate() != nil || site.TenantID != request.TenantID || site.SiteID != request.SiteID {
		return nil, "", ErrNotFound
	}
	return service.repository.ListSessions(ctx, request.TenantID, request.SiteID, request.After, request.Limit)
}

func (service *ScreenshotService) Inspect(ctx context.Context, actor Actor, tenantID TenantID, siteID SiteID, jobID ScreenshotJobID) (ScreenshotInspection, error) {
	if service == nil || actor.Validate() != nil || !validID(string(tenantID)) || !validID(string(siteID)) || !validID(string(jobID)) {
		return ScreenshotInspection{}, ErrInvalid
	}
	decision, err := service.authorizer.AuthorizeSitePreview(ctx, AuthorizationRequest{Actor: actor, TenantID: tenantID, SiteID: siteID, Action: ActionInspectScreenshot, MinimumAssurance: AssuranceSession})
	if err != nil || !validDecision(decision, actor, tenantID, siteID) {
		return ScreenshotInspection{}, concealAuthorization(err)
	}
	job, artifact, err := service.repository.LoadScreenshotJob(ctx, tenantID, siteID, jobID)
	if err != nil {
		return ScreenshotInspection{}, concealSite(err)
	}
	return ScreenshotInspection{Job: job, Artifact: artifact}, nil
}

func (service *Service) ReconcileExpired(ctx context.Context, limit uint32) (uint32, error) {
	if service == nil || limit == 0 || limit > 500 {
		return 0, ErrInvalid
	}
	now := service.clock()
	candidates, err := service.repository.ExpirationCandidates(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	var reconciled uint32
	for _, session := range candidates {
		closeDigest := digestJSON("cyberpanel:sitepreview:expire:v1", struct {
			SessionID SessionID
			Generation uint64
		}{session.ID, session.Generation})
		closeReceipt := service.receipt(session.TenantID, "preview_session", string(session.ID), "expire", "expired", session.Generation+1, closeDigest, "", now)
		closed, closeErr := service.repository.CloseSession(ctx, session.TenantID, session.ID, session.Generation, SessionExpired, now, closeReceipt)
		if closeErr != nil {
			continue
		}
		lease, loadErr := service.repository.LoadRouteLease(ctx, session.TenantID, session.ID)
		if loadErr != nil {
			continue
		}
		effect, expireErr := service.runtime.ExpireExactPreview(ctx, routeSpec(closed), lease)
		if expireErr != nil || effect.Validate(routeSpec(closed)) != nil || effect.Outcome != RouteAbsent {
			lease.State, lease.Generation, lease.UpdatedAt = "ambiguous", lease.Generation+1, now
			_ = service.repository.SaveRouteLease(ctx, session.TenantID, lease, lease.Generation-1)
			continue
		}
		if saveErr := service.repository.SaveRouteLease(ctx, session.TenantID, effect.Lease, lease.Generation); saveErr == nil {
			reconciled++
		}
	}
	return reconciled, nil
}

func (service *Service) ReconcileRoute(ctx context.Context, tenantID TenantID, sessionID SessionID) (RouteEffectReceipt, error) {
	if service == nil || !validID(string(tenantID)) || !validID(string(sessionID)) {
		return RouteEffectReceipt{}, ErrInvalid
	}
	session, err := service.repository.LoadSession(ctx, tenantID, sessionID)
	if err != nil {
		return RouteEffectReceipt{}, err
	}
	lease, err := service.repository.LoadRouteLease(ctx, tenantID, sessionID)
	if err != nil {
		return RouteEffectReceipt{}, err
	}
	spec := routeSpec(session)
	if session.State != SessionActive {
		effect, expireErr := service.runtime.ExpireExactPreview(ctx, spec, lease)
		if expireErr != nil || effect.Validate(spec) != nil || effect.Outcome != RouteAbsent {
			return service.preserveAmbiguousLease(ctx, tenantID, lease, errors.Join(ErrAmbiguous, expireErr))
		}
		if err = service.repository.SaveRouteLease(ctx, tenantID, effect.Lease, lease.Generation); err != nil {
			return RouteEffectReceipt{}, errors.Join(ErrAmbiguous, err)
		}
		return effect, nil
	}
	site, err := service.resolveSite(ctx, session.TenantID, session.SiteID, session.SiteGeneration)
	if err != nil || !sessionMatchesSite(session, site) {
		return service.preserveAmbiguousLease(ctx, tenantID, lease, ErrStaleGeneration)
	}
	effect, observeErr := service.runtime.ObserveExactPreview(ctx, spec, lease)
	if observeErr != nil || effect.Validate(spec) != nil || effect.Outcome != RouteApplied {
		return service.preserveAmbiguousLease(ctx, tenantID, lease, errors.Join(ErrAmbiguous, observeErr))
	}
	if err = service.repository.SaveRouteLease(ctx, tenantID, effect.Lease, lease.Generation); err != nil {
		return RouteEffectReceipt{}, errors.Join(ErrAmbiguous, err)
	}
	return effect, nil
}

func (service *Service) preserveAmbiguousLease(ctx context.Context, tenantID TenantID, lease RouteLease, cause error) (RouteEffectReceipt, error) {
	previous := lease.Generation
	lease.State, lease.Generation, lease.UpdatedAt = "ambiguous", lease.Generation+1, service.clock()
	if err := service.repository.SaveRouteLease(ctx, tenantID, lease, previous); err != nil {
		return RouteEffectReceipt{}, errors.Join(ErrAmbiguous, cause, err)
	}
	return RouteEffectReceipt{Outcome: RouteAmbiguous, Lease: lease, EvidenceDigest: digestJSON("cyberpanel:sitepreview:ambiguous-route:v1", lease)}, errors.Join(ErrAmbiguous, cause)
}

func (service *Service) handleFailedInstall(ctx context.Context, session PreviewSession, spec RouteSpec, requestDigest string, effect RouteEffectReceipt, runtimeErr error) error {
	target, outcome := SessionExpired, "install_rejected"
	if effect.Lease.Validate() == nil && effect.Lease.SessionID == session.ID {
		rollback, rollbackErr := service.runtime.RollbackExactPreview(ctx, spec, effect.Lease)
		if rollbackErr != nil || rollback.Validate(spec) != nil || rollback.Outcome != RouteRolledBack {
			target, outcome = SessionAmbiguous, "install_ambiguous"
			now := service.clock()
			receipt := service.receipt(session.TenantID, "preview_session", string(session.ID), "route_install", outcome, session.Generation+1, requestDigest, "", now)
			_, _ = service.repository.CloseSession(ctx, session.TenantID, session.ID, session.Generation, target, now, receipt)
			return errors.Join(ErrAmbiguous, runtimeErr, rollbackErr)
		}
	}
	if effect.Outcome == RouteAmbiguous {
		target, outcome = SessionAmbiguous, "install_ambiguous"
	}
	now := service.clock()
	receipt := service.receipt(session.TenantID, "preview_session", string(session.ID), "route_install", outcome, session.Generation+1, requestDigest, "", now)
	if _, closeErr := service.repository.CloseSession(ctx, session.TenantID, session.ID, session.Generation, target, now, receipt); closeErr != nil {
		return errors.Join(ErrAmbiguous, runtimeErr, closeErr)
	}
	if effect.Outcome == RouteAmbiguous {
		return errors.Join(ErrAmbiguous, runtimeErr)
	}
	if runtimeErr != nil {
		return runtimeErr
	}
	return ErrConflict
}

func (service *Service) resolveSite(ctx context.Context, tenantID TenantID, siteID SiteID, expected uint64) (SiteSnapshot, error) {
	site, err := service.sites.ResolveExactSite(ctx, tenantID, siteID)
	if err != nil || site.Validate() != nil || site.TenantID != tenantID || site.SiteID != siteID {
		return SiteSnapshot{}, concealSite(err)
	}
	if site.Generation != expected {
		return SiteSnapshot{}, ErrStaleGeneration
	}
	return site, nil
}

func sessionMatchesSite(session PreviewSession, site SiteSnapshot) bool {
	return site.Validate() == nil && session.TenantID == site.TenantID && session.SiteID == site.SiteID && session.SiteGeneration == site.Generation &&
		site.AllowsHostname(session.RequestedHostname) && session.RequestedHostname == site.Backend.ServerName && session.Backend == site.Backend && session.Engine == site.Engine &&
		session.PHPGeneration == site.PHPGeneration && session.TLSGeneration == site.TLSGeneration && session.CacheGeneration == site.CacheGeneration && session.WAFGeneration == site.WAFGeneration
}

func validDecision(decision AuthorizationDecision, actor Actor, tenantID TenantID, siteID SiteID) bool {
	return decision.Allowed && decision.TenantID == tenantID && decision.SiteID == siteID && decision.PrincipalID == actor.PrincipalID &&
		decision.CurrentActorAuthzEpoch == actor.AuthzEpoch
}

func concealAuthorization(err error) error {
	return ErrUnauthorized
}

func concealSite(err error) error {
	if errors.Is(err, ErrStaleGeneration) {
		return err
	}
	if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnauthorized) {
		return ErrNotFound
	}
	return err
}

func digestToken(token []byte) string {
	sum := sha256.Sum256(append([]byte("cyberpanel:sitepreview:token:v1\x00"), token...))
	return hex.EncodeToString(sum[:])
}

func (service *Service) record(ctx context.Context, event AuditEvent) error {
	if event.Validate() != nil {
		return ErrIntegrity
	}
	return service.audit.RecordSitePreview(ctx, event)
}

func (service *Service) receipt(tenantID TenantID, kind, resourceID, operation, outcome string, generation uint64, requestDigest, resultDigest string, at time.Time) Receipt {
	idDigest := digestJSON("cyberpanel:sitepreview:receipt-id:v1", struct {
		TenantID TenantID
		Kind string
		ResourceID string
		Operation string
		Generation uint64
	}{tenantID, kind, resourceID, operation, generation})
	return Receipt{ID: ReceiptID("rcp-" + idDigest[:48]), TenantID: tenantID, ResourceKind: kind, ResourceID: resourceID, Operation: operation, Outcome: outcome,
		Generation: generation, RequestDigest: requestDigest, ResultDigest: resultDigest, OccurredAt: at}
}
