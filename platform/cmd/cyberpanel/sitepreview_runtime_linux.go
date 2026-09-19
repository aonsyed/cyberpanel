//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/sitepreview"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
)

type sitePreviewSiteStore interface {
	Load(context.Context, site.TenantID, site.SiteID) (site.Site, error)
}

type sitePreviewPlanStore interface {
	CurrentPlan(context.Context) (composer.Plan, error)
}

type sitePreviewDirectory struct {
	sites   sitePreviewSiteStore
	catalog sitePreviewPlanStore
}

func (directory sitePreviewDirectory) ResolveExactSite(ctx context.Context, tenantID sitepreview.TenantID, siteID sitepreview.SiteID) (sitepreview.SiteSnapshot, error) {
	if directory.sites == nil || directory.catalog == nil || ctx == nil {
		return sitepreview.SiteSnapshot{}, sitepreview.ErrNotFound
	}
	tenant, err := site.NewTenantID(string(tenantID))
	if err != nil {
		return sitepreview.SiteSnapshot{}, sitepreview.ErrNotFound
	}
	resource, err := site.NewSiteID(string(siteID))
	if err != nil {
		return sitepreview.SiteSnapshot{}, sitepreview.ErrNotFound
	}
	aggregate, err := directory.sites.Load(ctx, tenant, resource)
	if err != nil || aggregate.Lifecycle() != site.LifecycleActive {
		return sitepreview.SiteSnapshot{}, sitepreview.ErrNotFound
	}
	plan, err := directory.catalog.CurrentPlan(ctx)
	if err != nil || plan.SnapshotGeneration == 0 {
		return sitepreview.SiteSnapshot{}, sitepreview.ErrNotFound
	}
	var input *composer.SiteInput
	for index := range plan.Sites {
		candidate := &plan.Sites[index]
		if candidate.Scope.TenantID == tenant && candidate.Scope.SiteID == resource && !candidate.Withdraw {
			if input != nil {
				return sitepreview.SiteSnapshot{}, sitepreview.ErrIntegrity
			}
			input = candidate
		}
	}
	if input == nil || input.Projection.Generation != aggregate.Generation() || input.Projection.Lifecycle != site.LifecycleActive || input.PoolGeneration == 0 {
		return sitepreview.SiteSnapshot{}, sitepreview.ErrStaleGeneration
	}
	canonical := ""
	allowed := make([]string, 0, len(input.Projection.Bindings))
	for _, binding := range input.Projection.Bindings {
		hostname := binding.Hostname.String()
		switch binding.Kind {
		case site.BindingPrimary:
			if canonical != "" {
				return sitepreview.SiteSnapshot{}, sitepreview.ErrIntegrity
			}
			canonical = hostname
			allowed = append(allowed, hostname)
		case site.BindingAlias, site.BindingChild:
			allowed = append(allowed, hostname)
		}
	}
	sort.Strings(allowed)
	if canonical == "" || len(allowed) == 0 {
		return sitepreview.SiteSnapshot{}, sitepreview.ErrIntegrity
	}
	port := uint16(0)
	for _, listener := range plan.Engine.Listeners {
		if listener.Ref != webengine.ResourceRef("listener/preview-internal") || listener.TLSMode != webengine.TLSModeClear || listener.Port == 0 {
			continue
		}
		for _, address := range listener.Addresses {
			if address == "127.0.0.1" {
				port = listener.Port
			}
		}
	}
	if port == 0 {
		return sitepreview.SiteSnapshot{}, sitepreview.ErrIntegrity
	}
	tlsGeneration := uint64(0)
	if len(input.TLS) == 1 {
		tlsGeneration = input.TLS[0].Generation
	} else if len(input.TLS) == 0 && plan.DefaultTLS != nil {
		tlsGeneration = plan.DefaultTLS.Generation
	}
	engine := sitepreview.Engine("")
	switch plan.Engine.Edition {
	case webengine.EditionOpenLiteSpeed:
		engine = sitepreview.EngineOLS
	case webengine.EditionLiteSpeedEnterprise:
		engine = sitepreview.EngineLSE
	}
	snapshot := sitepreview.SiteSnapshot{TenantID: tenantID, SiteID: siteID, Generation: aggregate.Generation(), Ready: true, Engine: engine,
		CanonicalHost: canonical, AllowedHosts: allowed, PHPGeneration: input.PoolGeneration, TLSGeneration: tlsGeneration,
		CacheGeneration: plan.SnapshotGeneration, WAFGeneration: plan.SnapshotGeneration,
		Backend: sitepreview.Backend{Address: netip.MustParseAddr("127.0.0.1"), Port: port, Protocol: sitepreview.BackendHTTP, ServerName: canonical}}
	if snapshot.Validate() != nil {
		return sitepreview.SiteSnapshot{}, sitepreview.ErrIntegrity
	}
	return snapshot, nil
}

type sitePreviewAuthorizer struct {
	authority *identity.Authorizer
	now       func() time.Time
}

func (authorizer sitePreviewAuthorizer) AuthorizeSitePreview(ctx context.Context, request sitepreview.AuthorizationRequest) (sitepreview.AuthorizationDecision, error) {
	denied := sitepreview.AuthorizationDecision{TenantID: request.TenantID, SiteID: request.SiteID, PrincipalID: request.Actor.PrincipalID}
	if authorizer.authority == nil || authorizer.now == nil || ctx == nil || request.Actor.Validate() != nil || request.Actor.Assurance < request.MinimumAssurance || !sitePreviewAction(request.Action) {
		return denied, sitepreview.ErrUnauthorized
	}
	principalID, principalErr := identity.NewID(string(request.Actor.PrincipalID))
	tenantID, tenantErr := identity.NewID(string(request.TenantID))
	resourceID, resourceErr := identity.NewID(string(request.SiteID))
	if principalErr != nil || tenantErr != nil || resourceErr != nil {
		return denied, sitepreview.ErrUnauthorized
	}
	at := authorizer.now().UTC()
	scope := identity.Scope{Kind: identity.ScopeSite, TenantID: tenantID, ResourceID: resourceID}
	decision, err := authorizer.authority.Decide(ctx, identity.AuthorizationRequest{PrincipalID: principalID, Permission: identity.MustPermission("site:manage"), Scope: scope, At: at, Assurance: identity.AssuranceLevel(request.Actor.Assurance)})
	if err != nil || !decision.Allowed || decision.PrincipalEpoch != request.Actor.AuthzEpoch || decision.TenantEpoch == 0 {
		return denied, sitepreview.ErrUnauthorized
	}
	audienceEpoch := decision.PrincipalEpoch
	switch request.Audience.Kind {
	case "":
	case sitepreview.AudienceShare:
		audienceEpoch = decision.TenantEpoch
	case sitepreview.AudienceViewer:
		audienceID, audienceErr := identity.NewID(string(request.Audience.PrincipalID))
		if audienceErr != nil {
			return denied, sitepreview.ErrUnauthorized
		}
		if audienceID == principalID {
			break
		}
		audience, audienceErr := authorizer.authority.Decide(ctx, identity.AuthorizationRequest{PrincipalID: audienceID, Permission: identity.MustPermission("site:manage"), Scope: scope, At: at, Assurance: identity.AssurancePassword})
		if audienceErr != nil || !audience.Allowed || audience.PrincipalEpoch == 0 {
			return denied, sitepreview.ErrUnauthorized
		}
		audienceEpoch = audience.PrincipalEpoch
	default:
		return denied, sitepreview.ErrUnauthorized
	}
	return sitepreview.AuthorizationDecision{TenantID: request.TenantID, SiteID: request.SiteID, PrincipalID: request.Actor.PrincipalID,
		CurrentActorAuthzEpoch: decision.PrincipalEpoch, CurrentAudienceAuthzEpoch: audienceEpoch, Allowed: true}, nil
}

func sitePreviewAction(action sitepreview.Action) bool {
	switch action {
	case sitepreview.ActionIssuePreview, sitepreview.ActionConsumePreview, sitepreview.ActionRevokePreview, sitepreview.ActionListPreviews,
		sitepreview.ActionQueueScreenshot, sitepreview.ActionInspectScreenshot, sitepreview.ActionRenderScreenshot:
		return true
	default:
		return false
	}
}

type sitePreviewAudit struct{ writer *audit.Writer }

func (sink sitePreviewAudit) RecordSitePreview(ctx context.Context, event sitepreview.AuditEvent) error {
	if sink.writer == nil || ctx == nil || event.Validate() != nil {
		return sitepreview.ErrIntegrity
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	outcome := audit.OutcomeApplied
	switch event.Outcome {
	case "authorized", "admitted":
		outcome = audit.OutcomeAllowed
	case "ambiguous", "activation_ambiguous", "install_ambiguous":
		outcome = audit.OutcomeAmbiguous
	case "denied":
		outcome = audit.OutcomeDenied
	case "rejected", "activation_rejected", "install_rejected":
		outcome = audit.OutcomeRejected
	case "failed", "authorization_revoked", "provider_not_invoked", "site_generation_stale", "renderer_failed", "artifact_store_failed", "renderer_contract_invalid":
		outcome = audit.OutcomeFailed
	}
	_, err = sink.writer.Append(ctx, audit.Event{ID: "sitepreview-" + hex.EncodeToString(sum[:24]), Class: audit.ClassSecurity, Action: string(event.Action),
		Actor:   audit.Actor{PrincipalID: string(event.ActorID), TenantID: string(event.TenantID), AuthzEpoch: event.AuthzEpoch, Origin: "panel-core"},
		Target:  audit.Target{Kind: event.ResourceKind, ID: event.ResourceID, TenantID: string(event.TenantID), Generation: strconv.FormatUint(event.SiteGeneration, 10)},
		Outcome: outcome, RequestDigest: event.RequestDigest, Attributes: map[string]string{"site_id": string(event.SiteID), "site_generation": strconv.FormatUint(event.SiteGeneration, 10)}, OccurredAt: event.OccurredAt.UTC()})
	return err
}

func startSitePreviewWorkers(ctx context.Context, previews *sitepreview.Service, screenshots *sitepreview.ScreenshotService) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = previews.ReconcileExpired(ctx, 100)
			}
		}
	}()
	go func() {
		for {
			_, _, err := screenshots.DispatchOne(ctx, "sitepreview-local", 3*time.Minute)
			if err == nil {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			delay := time.Second
			if !errors.Is(err, sitepreview.ErrNotFound) {
				delay = 5 * time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}
