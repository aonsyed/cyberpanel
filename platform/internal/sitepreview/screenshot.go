package sitepreview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/url"
	"time"
)

type ScreenshotRequest struct {
	Actor              Actor
	JobID              ScreenshotJobID
	TenantID           TenantID
	SiteID             SiteID
	ExpectedGeneration uint64
	DestinationURL     string
	Mode               ScreenshotMode
	Limits             ScreenshotLimits
	Provider           *ProviderPolicy
}

type RenderedArtifact struct {
	Reader    io.ReadCloser
	MediaType string
	Width     uint32
	Height    uint32
	Cleanup   func() error
}

func (artifact RenderedArtifact) Validate(limits ScreenshotLimits) error {
	if artifact.Reader == nil || artifact.Cleanup == nil || artifact.MediaType != "image/png" || artifact.Width != limits.Width || artifact.Height != limits.Height || limits.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type LocalScreenshotRenderer interface {
	RenderIsolated(context.Context, ScreenshotJob, SiteSnapshot) (RenderedArtifact, error)
}

type ArtifactStorageReceipt struct {
	StorageRef string
	ByteSize   uint64
	Digest     string
}

func (receipt ArtifactStorageReceipt) Validate(maximum uint64) error {
	if !validID(receipt.StorageRef) || receipt.ByteSize == 0 || receipt.ByteSize > maximum || !validDigest(receipt.Digest) {
		return ErrInvalid
	}
	return nil
}

type ScreenshotArtifactStore interface {
	PutScreenshot(context.Context, ScreenshotJob, string, io.Reader, uint64) (ArtifactStorageReceipt, error)
	DiscardScreenshot(context.Context, ScreenshotJob, ArtifactStorageReceipt) error
}

// QualifiedScreenshotProvider is an optional integration boundary. This
// package deliberately never invokes it: provider dispatch belongs to an
// external worker that must first prove qualification and re-check the exact
// persisted consent, region and retention policy.
type QualifiedScreenshotProvider interface {
	Qualification(context.Context, string) (ProviderQualification, error)
	SubmitConsentedScreenshot(context.Context, ProviderScreenshotRequest) (ProviderScreenshotReceipt, error)
}

type ProviderQualification struct {
	ProviderID     string
	PolicyVersion  uint64
	DataRegions    []string
	MaximumRetention time.Duration
	URLOnlyEgress  bool
}

type ProviderScreenshotRequest struct {
	JobID          ScreenshotJobID
	TenantID       TenantID
	SiteID         SiteID
	SiteGeneration uint64
	DestinationURL string
	DataRegion     string
	Retention      time.Duration
}

type ProviderScreenshotReceipt struct {
	ProviderID     string
	RemoteJobRef   string
	PolicyVersion  uint64
	AcceptedAt     time.Time
	ReceiptDigest  string
}

type ScreenshotService struct {
	repository *Repository
	sites      SiteDirectory
	authorizer Authorizer
	audit      AuditSink
	renderer   LocalScreenshotRenderer
	artifacts  ScreenshotArtifactStore
	now        func() time.Time
}

func NewScreenshotService(repository *Repository, sites SiteDirectory, authorizer Authorizer, audit AuditSink, renderer LocalScreenshotRenderer, artifacts ScreenshotArtifactStore) (*ScreenshotService, error) {
	if repository == nil || sites == nil || authorizer == nil || audit == nil || renderer == nil || artifacts == nil {
		return nil, ErrInvalid
	}
	return &ScreenshotService{repository: repository, sites: sites, authorizer: authorizer, audit: audit, renderer: renderer, artifacts: artifacts, now: time.Now}, nil
}

func (service *ScreenshotService) clock() time.Time {
	if service.now == nil {
		return time.Now().UTC()
	}
	return service.now().UTC()
}

func (service *ScreenshotService) Queue(ctx context.Context, request ScreenshotRequest) (ScreenshotJob, error) {
	if service == nil || request.Actor.Validate() != nil || !validID(string(request.JobID)) || !validID(string(request.TenantID)) || !validID(string(request.SiteID)) || request.ExpectedGeneration == 0 ||
		request.Limits.Validate() != nil || (request.Mode != ScreenshotLocal && request.Mode != ScreenshotProvider) {
		return ScreenshotJob{}, ErrInvalid
	}
	minimum := AssuranceSession
	if request.Mode == ScreenshotProvider {
		minimum = AssuranceMFA
		if request.Provider == nil || request.Provider.Validate() != nil {
			return ScreenshotJob{}, ErrPolicyDenied
		}
	} else if request.Provider != nil {
		return ScreenshotJob{}, ErrInvalid
	}
	decision, err := service.authorizer.AuthorizeSitePreview(ctx, AuthorizationRequest{Actor: request.Actor, TenantID: request.TenantID, SiteID: request.SiteID, Action: ActionQueueScreenshot, MinimumAssurance: minimum})
	if err != nil || !validDecision(decision, request.Actor, request.TenantID, request.SiteID) || request.Actor.Assurance < minimum {
		return ScreenshotJob{}, concealAuthorization(err)
	}
	site, err := service.sites.ResolveExactSite(ctx, request.TenantID, request.SiteID)
	if err != nil || site.Validate() != nil || site.TenantID != request.TenantID || site.SiteID != request.SiteID {
		return ScreenshotJob{}, concealSite(err)
	}
	if site.Generation != request.ExpectedGeneration {
		return ScreenshotJob{}, ErrStaleGeneration
	}
	destination := Destination{URL: request.DestinationURL, AuthorizedBackend: site.Backend, AllowPublicInternet: false}
	if destination.Validate(site) != nil {
		return ScreenshotJob{}, ErrPolicyDenied
	}
	now := service.clock()
	job := ScreenshotJob{ID: request.JobID, TenantID: request.TenantID, SiteID: request.SiteID, SiteGeneration: site.Generation, ActorID: request.Actor.PrincipalID, AuthzEpoch: decision.CurrentActorAuthzEpoch,
		Mode: request.Mode, Destination: destination, Limits: request.Limits, Provider: request.Provider, State: ScreenshotQueued, Generation: 1, CreatedAt: now, UpdatedAt: now}
	requestDigest := digestJSON("cyberpanel:sitepreview:screenshot-queue:v1", request)
	receipt := screenshotReceipt(job, "screenshot_queue", "queued", requestDigest, "", now)
	if err = service.record(ctx, AuditEvent{TenantID: job.TenantID, ActorID: job.ActorID, Action: ActionQueueScreenshot, ResourceKind: "screenshot_job", ResourceID: string(job.ID), SiteID: job.SiteID,
		SiteGeneration: job.SiteGeneration, AuthzEpoch: decision.CurrentActorAuthzEpoch, RequestDigest: requestDigest, Outcome: "authorized", OccurredAt: now}); err != nil {
		return ScreenshotJob{}, err
	}
	if err = service.repository.CreateScreenshotJob(ctx, job, receipt); err != nil {
		return ScreenshotJob{}, err
	}
	return job, nil
}

func (service *ScreenshotService) DispatchOne(ctx context.Context, workerID string, leaseDuration time.Duration) (ScreenshotJob, *ScreenshotArtifact, error) {
	if service == nil || !validID(workerID) {
		return ScreenshotJob{}, nil, ErrInvalid
	}
	now := service.clock()
	job, err := service.repository.ClaimScreenshotJob(ctx, workerID, now, leaseDuration)
	if err != nil {
		return ScreenshotJob{}, nil, err
	}
	decision, authErr := service.authorizer.AuthorizeSitePreview(ctx, AuthorizationRequest{Actor: Actor{PrincipalID: job.ActorID, AuthzEpoch: job.AuthzEpoch, Assurance: AssuranceSession}, TenantID: job.TenantID, SiteID: job.SiteID, Action: ActionRenderScreenshot, MinimumAssurance: AssuranceSession})
	if authErr != nil || !decision.Allowed || decision.TenantID != job.TenantID || decision.SiteID != job.SiteID || decision.PrincipalID != job.ActorID || decision.CurrentActorAuthzEpoch != job.AuthzEpoch {
		return service.fail(ctx, job, ScreenshotFailed, "authorization_revoked", authErr)
	}
	if job.Mode == ScreenshotProvider {
		return service.fail(ctx, job, ScreenshotExternal, "provider_not_invoked", ErrProviderNotInvoked)
	}
	site, err := service.sites.ResolveExactSite(ctx, job.TenantID, job.SiteID)
	if err != nil || site.Validate() != nil || !exactJobSite(job, site) || job.Destination.Validate(site) != nil {
		return service.fail(ctx, job, ScreenshotStale, "site_generation_stale", ErrStaleGeneration)
	}
	deadline := now.Add(job.Limits.Timeout)
	if job.LeaseUntil.Before(deadline) {
		deadline = job.LeaseUntil
	}
	renderContext, cancel := context.WithDeadline(ctx, deadline)
	rendered, renderErr := service.renderer.RenderIsolated(renderContext, job, site)
	cancel()
	if renderErr != nil {
		return service.fail(ctx, job, ScreenshotFailed, "renderer_failed", renderErr)
	}
	if rendered.Validate(job.Limits) != nil {
		_ = rendered.Reader.Close()
		_ = rendered.Cleanup()
		return service.fail(ctx, job, ScreenshotFailed, "renderer_contract_invalid", ErrIntegrity)
	}
	artifact, storeErr := service.storeArtifact(ctx, job, rendered)
	closeErr := rendered.Reader.Close()
	cleanupErr := rendered.Cleanup()
	if storeErr != nil || closeErr != nil || cleanupErr != nil {
		return service.fail(ctx, job, ScreenshotFailed, "artifact_store_failed", errors.Join(storeErr, closeErr, cleanupErr))
	}
	current, err := service.sites.ResolveExactSite(ctx, job.TenantID, job.SiteID)
	if err != nil || current.Validate() != nil || !exactJobSite(job, current) {
		_ = service.artifacts.DiscardScreenshot(ctx, job, ArtifactStorageReceipt{StorageRef: artifact.StorageRef, ByteSize: artifact.ByteSize, Digest: artifact.Digest})
		return service.fail(ctx, job, ScreenshotStale, "site_changed_after_render", ErrStaleGeneration)
	}
	previous := job.Generation
	job.State, job.Generation, job.UpdatedAt, job.LeaseUntil = ScreenshotSucceeded, job.Generation+1, service.clock(), time.Time{}
	requestDigest := digestJSON("cyberpanel:sitepreview:screenshot-complete:v1", struct {
		JobID ScreenshotJobID
		SiteGeneration uint64
		ArtifactDigest string
	}{job.ID, job.SiteGeneration, artifact.Digest})
	receipt := screenshotReceipt(job, "screenshot_complete", "succeeded", requestDigest, artifact.Digest, job.UpdatedAt)
	if err = service.repository.CompleteScreenshotJob(ctx, job, previous, &artifact, receipt); err != nil {
		return job, &artifact, errors.Join(ErrAmbiguous, err)
	}
	if err = service.record(ctx, AuditEvent{TenantID: job.TenantID, ActorID: job.ActorID, Action: ActionRenderScreenshot, ResourceKind: "screenshot_job", ResourceID: string(job.ID), SiteID: job.SiteID,
		SiteGeneration: job.SiteGeneration, AuthzEpoch: job.AuthzEpoch, RequestDigest: requestDigest, Outcome: "succeeded", OccurredAt: job.UpdatedAt}); err != nil {
		return job, &artifact, errors.Join(ErrAmbiguous, err)
	}
	return job, &artifact, nil
}

func (service *ScreenshotService) storeArtifact(ctx context.Context, job ScreenshotJob, rendered RenderedArtifact) (ScreenshotArtifact, error) {
	state := &streamDigest{hash: sha256.New()}
	limited := &io.LimitedReader{R: rendered.Reader, N: int64(job.Limits.MaximumBytes) + 1}
	stream := io.TeeReader(limited, state)
	storage, err := service.artifacts.PutScreenshot(ctx, job, rendered.MediaType, stream, job.Limits.MaximumBytes)
	if err != nil {
		return ScreenshotArtifact{}, err
	}
	if _, err = io.Copy(io.Discard, stream); err != nil {
		return ScreenshotArtifact{}, err
	}
	if state.count == 0 || state.count > job.Limits.MaximumBytes {
		return ScreenshotArtifact{}, ErrPolicyDenied
	}
	digest := hex.EncodeToString(state.hash.Sum(nil))
	if storage.Validate(job.Limits.MaximumBytes) != nil || storage.ByteSize != state.count || storage.Digest != digest {
		return ScreenshotArtifact{}, ErrIntegrity
	}
	now := service.clock()
	idDigest := digestJSON("cyberpanel:sitepreview:artifact-id:v1", struct {
		JobID ScreenshotJobID
		Digest string
	}{job.ID, digest})
	artifact := ScreenshotArtifact{ID: ArtifactID("art-" + idDigest[:48]), JobID: job.ID, TenantID: job.TenantID, SiteID: job.SiteID, SiteGeneration: job.SiteGeneration,
		MediaType: rendered.MediaType, ByteSize: state.count, PixelWidth: rendered.Width, PixelHeight: rendered.Height, Digest: digest, StorageRef: storage.StorageRef, CreatedAt: now}
	if artifact.Validate() != nil {
		return ScreenshotArtifact{}, ErrIntegrity
	}
	return artifact, nil
}

func (service *ScreenshotService) fail(ctx context.Context, job ScreenshotJob, state ScreenshotState, code string, cause error) (ScreenshotJob, *ScreenshotArtifact, error) {
	if state != ScreenshotFailed && state != ScreenshotStale && state != ScreenshotExternal || !validID(code) {
		return job, nil, errors.Join(ErrIntegrity, cause)
	}
	previous := job.Generation
	job.State, job.Generation, job.UpdatedAt, job.LeaseUntil = state, job.Generation+1, service.clock(), time.Time{}
	requestDigest := digestJSON("cyberpanel:sitepreview:screenshot-failure:v1", struct {
		JobID ScreenshotJobID
		Code string
	}{job.ID, code})
	receipt := screenshotReceipt(job, "screenshot_complete", string(state), requestDigest, "", job.UpdatedAt)
	if err := service.repository.CompleteScreenshotJob(ctx, job, previous, nil, receipt); err != nil {
		return job, nil, errors.Join(ErrAmbiguous, cause, err)
	}
	_ = service.record(ctx, AuditEvent{TenantID: job.TenantID, ActorID: job.ActorID, Action: ActionRenderScreenshot, ResourceKind: "screenshot_job", ResourceID: string(job.ID), SiteID: job.SiteID,
		SiteGeneration: job.SiteGeneration, AuthzEpoch: job.AuthzEpoch, RequestDigest: requestDigest, Outcome: code, OccurredAt: job.UpdatedAt})
	return job, nil, cause
}

func (service *ScreenshotService) record(ctx context.Context, event AuditEvent) error {
	if event.Validate() != nil {
		return ErrIntegrity
	}
	return service.audit.RecordSitePreview(ctx, event)
}

func exactJobSite(job ScreenshotJob, site SiteSnapshot) bool {
	return site.TenantID == job.TenantID && site.SiteID == job.SiteID && site.Generation == job.SiteGeneration && site.Backend == job.Destination.AuthorizedBackend && site.AllowsHostname(destinationHostname(job.Destination.URL))
}

func screenshotReceipt(job ScreenshotJob, operation, outcome, requestDigest, resultDigest string, at time.Time) Receipt {
	idDigest := digestJSON("cyberpanel:sitepreview:screenshot-receipt-id:v1", struct {
		JobID ScreenshotJobID
		Operation string
		Generation uint64
	}{job.ID, operation, job.Generation})
	return Receipt{ID: ReceiptID("rcp-" + idDigest[:48]), TenantID: job.TenantID, ResourceKind: "screenshot_job", ResourceID: string(job.ID), Operation: operation, Outcome: outcome,
		Generation: job.Generation, RequestDigest: requestDigest, ResultDigest: resultDigest, OccurredAt: at}
}

type streamDigest struct {
	hash  hash.Hash
	count uint64
}

func (writer *streamDigest) Write(content []byte) (int, error) {
	written, err := writer.hash.Write(content)
	writer.count += uint64(written)
	return written, err
}

func destinationHostname(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
