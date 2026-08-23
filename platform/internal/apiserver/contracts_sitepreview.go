package apiserver

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/sitepreview"
)

type SitePreviewIssuePayload struct {
	Audience          sitepreview.Audience    `json:"audience"`
	GrantMode         sitepreview.GrantMode   `json:"grant_mode"`
	RequestedHostname string                  `json:"requested_hostname"`
	Limits            sitepreview.Limits      `json:"limits"`
	CachePolicy       sitepreview.CachePolicy `json:"cache_policy"`
}

type SitePreviewConsumePayload struct {
	Audience        sitepreview.Audience `json:"audience"`
	PreviewHostname string               `json:"preview_hostname"`
	Token           string               `json:"token"`
	RequestBytes    uint64               `json:"request_bytes"`
}

type SitePreviewRevokePayload struct{ SessionID sitepreview.SessionID `json:"session_id"` }
type SitePreviewListPayload struct{ Cursor sitepreview.SessionID `json:"cursor,omitempty"`; Limit uint32 `json:"limit,omitempty"` }
type SiteScreenshotRequestPayload struct {
	DestinationURL string                      `json:"destination_url"`
	Mode           sitepreview.ScreenshotMode  `json:"mode"`
	Limits         sitepreview.ScreenshotLimits `json:"limits"`
	Provider       *sitepreview.ProviderPolicy `json:"provider,omitempty"`
}
type SiteScreenshotInspectPayload struct{ JobID sitepreview.ScreenshotJobID `json:"job_id"` }

type SitePreviewSessionView struct {
	ID               sitepreview.SessionID    `json:"id"`
	SiteID           sitepreview.SiteID       `json:"site_id"`
	SiteGeneration   uint64                   `json:"site_generation"`
	Audience         sitepreview.Audience     `json:"audience"`
	GrantMode        sitepreview.GrantMode    `json:"grant_mode"`
	PreviewHostname  string                   `json:"preview_hostname"`
	RequestedHostname string                  `json:"requested_hostname"`
	Limits           sitepreview.Limits       `json:"limits"`
	ConsumedBytes    uint64                   `json:"consumed_bytes"`
	ConsumedRequests uint32                   `json:"consumed_requests"`
	State            sitepreview.SessionState `json:"state"`
	Generation       uint64                   `json:"generation"`
	CreatedAt        time.Time                `json:"created_at"`
	LastUsedAt       time.Time                `json:"last_used_at"`
	ExpiresAt        time.Time                `json:"expires_at"`
	RevokedAt        time.Time                `json:"revoked_at,omitempty"`
}

type SitePreviewIssueResult struct {
	Session SitePreviewSessionView `json:"session"`
	Token   string                 `json:"token"`
}
type SitePreviewListResult struct{ Items []SitePreviewSessionView `json:"items"`; NextCursor sitepreview.SessionID `json:"next_cursor,omitempty"` }
type SitePreviewConsumeResult struct {
	SessionID         sitepreview.SessionID `json:"session_id"`
	SiteGeneration    uint64                `json:"site_generation"`
	RemainingBytes    uint64                `json:"remaining_bytes"`
	RemainingRequests uint32                `json:"remaining_requests"`
	ExpiresAt         time.Time             `json:"expires_at"`
}
type SiteScreenshotArtifactView struct {
	ID             sitepreview.ArtifactID `json:"id"`
	SiteGeneration uint64                 `json:"site_generation"`
	MediaType      string                 `json:"media_type"`
	ByteSize       uint64                 `json:"byte_size"`
	PixelWidth     uint32                 `json:"pixel_width"`
	PixelHeight    uint32                 `json:"pixel_height"`
	Digest         string                 `json:"digest"`
	CreatedAt      time.Time              `json:"created_at"`
}
type SiteScreenshotView struct {
	ID             sitepreview.ScreenshotJobID `json:"id"`
	SiteID         sitepreview.SiteID          `json:"site_id"`
	SiteGeneration uint64                      `json:"site_generation"`
	Mode           sitepreview.ScreenshotMode  `json:"mode"`
	State          sitepreview.ScreenshotState `json:"state"`
	Generation     uint64                      `json:"generation"`
	CreatedAt      time.Time                   `json:"created_at"`
	UpdatedAt      time.Time                   `json:"updated_at"`
	Artifact       *SiteScreenshotArtifactView `json:"artifact,omitempty"`
}

func registerSitePreviewContracts(registry *Registry) error {
	operations := []Operation{
		{Name:"sitepreview.session.issue",Permission:identity.MustPermission("site:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,MaximumBodyBytes:32<<10,NewPayload:func()any{return &SitePreviewIssuePayload{}},ValidatePayload:validateSitePreviewIssue,ResolveScope:siteScope},
		{Name:"sitepreview.session.consume",Permission:identity.MustPermission("site:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,MaximumBodyBytes:16<<10,NewPayload:func()any{return &SitePreviewConsumePayload{}},ValidatePayload:validateSitePreviewConsume,ResolveScope:siteScope},
		{Name:"sitepreview.session.revoke",Permission:identity.MustPermission("site:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &SitePreviewRevokePayload{}},ValidatePayload:validateSitePreviewRevoke,ResolveScope:siteScope},
		{Name:"sitepreview.session.list",Permission:identity.MustPermission("site:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:false,NewPayload:func()any{return &SitePreviewListPayload{}},ValidatePayload:validateSitePreviewList,ResolveScope:siteScope},
		{Name:"sitepreview.screenshot.request",Permission:identity.MustPermission("site:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,MaximumBodyBytes:32<<10,NewPayload:func()any{return &SiteScreenshotRequestPayload{}},ValidatePayload:validateSiteScreenshotRequest,ResolveScope:siteScope},
		{Name:"sitepreview.screenshot.inspect",Permission:identity.MustPermission("site:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:false,NewPayload:func()any{return &SiteScreenshotInspectPayload{}},ValidatePayload:validateSiteScreenshotInspect,ResolveScope:siteScope},
	}
	for _, operation := range operations { if err := register(registry, operation); err != nil { return err } }
	return nil
}

func bindSitePreviewContracts(registry *Registry, services DomainServices) error {
	if services.SitePreviews != nil {
		if err := registry.Bind("sitepreview.session.issue", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload:=value.(*SitePreviewIssuePayload); result,err:=services.SitePreviews.Issue(ctx,sitepreview.IssueRequest{Actor:sitePreviewActor(inv),TenantID:sitepreview.TenantID(inv.Request.TenantID),SiteID:sitepreview.SiteID(inv.Request.ResourceID),ExpectedGeneration:inv.Request.ExpectedGeneration,Audience:payload.Audience,GrantMode:payload.GrantMode,RequestedHostname:payload.RequestedHostname,Limits:payload.Limits,CachePolicy:payload.CachePolicy});if err!=nil{return OperationResult{},mapDomainError(err)}
			token:=base64.RawURLEncoding.EncodeToString(result.Token);clear(result.Token);return OperationResult{Status:http.StatusCreated,Value:SitePreviewIssueResult{Session:sitePreviewSessionView(result.Session),Token:token},Generation:result.Session.Generation,Headers:map[string]string{"Cache-Control":"no-store","Pragma":"no-cache"}},nil
		}); err != nil { return err }
		if err := registry.Bind("sitepreview.session.consume", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload:=value.(*SitePreviewConsumePayload);token,decodeErr:=base64.RawURLEncoding.DecodeString(payload.Token);payload.Token="";if decodeErr!=nil||len(token)!=32{clear(token);return OperationResult{},ErrInvalidRequest};defer clear(token)
			grant,err:=services.SitePreviews.Consume(ctx,sitepreview.ConsumeRequest{Actor:sitePreviewActor(inv),TenantID:sitepreview.TenantID(inv.Request.TenantID),SiteID:sitepreview.SiteID(inv.Request.ResourceID),Audience:payload.Audience,PreviewHostname:payload.PreviewHostname,Token:token,RequestBytes:payload.RequestBytes});if err!=nil{return OperationResult{},mapDomainError(err)}
			return OperationResult{Status:http.StatusOK,Value:SitePreviewConsumeResult{SessionID:grant.SessionID,SiteGeneration:grant.SiteGeneration,RemainingBytes:grant.RemainingBytes,RemainingRequests:grant.RemainingRequests,ExpiresAt:grant.ExpiresAt},Headers:map[string]string{"Cache-Control":"no-store"}},nil
		}); err != nil { return err }
		if err := registry.Bind("sitepreview.session.revoke", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload:=value.(*SitePreviewRevokePayload);err:=services.SitePreviews.Revoke(ctx,sitepreview.RevokeRequest{Actor:sitePreviewActor(inv),TenantID:sitepreview.TenantID(inv.Request.TenantID),SiteID:sitepreview.SiteID(inv.Request.ResourceID),SessionID:payload.SessionID,ExpectedGeneration:inv.Request.ExpectedGeneration});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusNoContent},nil
		}); err != nil { return err }
		if err := registry.Bind("sitepreview.session.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload:=value.(*SitePreviewListPayload);sessions,next,err:=services.SitePreviews.ListSessions(ctx,sitepreview.ListSessionsRequest{Actor:sitePreviewActor(inv),TenantID:sitepreview.TenantID(inv.Request.TenantID),SiteID:sitepreview.SiteID(inv.Request.ResourceID),After:payload.Cursor,Limit:payload.Limit});if err!=nil{return OperationResult{},mapDomainError(err)};items:=make([]SitePreviewSessionView,0,len(sessions));for _,session:=range sessions{items=append(items,sitePreviewSessionView(session))};return OperationResult{Status:http.StatusOK,Value:SitePreviewListResult{Items:items,NextCursor:next}},nil
		}); err != nil { return err }
	}
	if services.SiteScreenshots != nil {
		if err := registry.Bind("sitepreview.screenshot.request", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload:=value.(*SiteScreenshotRequestPayload);jobID:=sitepreview.ScreenshotJobID("shot-"+commandID(inv));job,err:=services.SiteScreenshots.Queue(ctx,sitepreview.ScreenshotRequest{Actor:sitePreviewActor(inv),JobID:jobID,TenantID:sitepreview.TenantID(inv.Request.TenantID),SiteID:sitepreview.SiteID(inv.Request.ResourceID),ExpectedGeneration:inv.Request.ExpectedGeneration,DestinationURL:payload.DestinationURL,Mode:payload.Mode,Limits:payload.Limits,Provider:payload.Provider});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusAccepted,Value:siteScreenshotView(sitepreview.ScreenshotInspection{Job:job}),Generation:job.Generation},nil
		}); err != nil { return err }
		if err := registry.Bind("sitepreview.screenshot.inspect", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			inspection,err:=services.SiteScreenshots.Inspect(ctx,sitePreviewActor(inv),sitepreview.TenantID(inv.Request.TenantID),sitepreview.SiteID(inv.Request.ResourceID),value.(*SiteScreenshotInspectPayload).JobID);if err!=nil{return OperationResult{},mapDomainError(err)};view:=siteScreenshotView(inspection);return OperationResult{Status:http.StatusOK,Value:view,Generation:view.Generation},nil
		}); err != nil { return err }
	}
	return nil
}

func validateSitePreviewIssue(value any) error { payload:=value.(*SitePreviewIssuePayload);if payload.Audience.Validate()!=nil||(payload.GrantMode!=sitepreview.GrantOneUse&&payload.GrantMode!=sitepreview.GrantShortLived)||payload.Limits.Validate(payload.GrantMode)!=nil||(payload.CachePolicy!=sitepreview.CacheBypassPrivate&&payload.CachePolicy!=sitepreview.CacheSitePolicy)||len(payload.RequestedHostname)<3||len(payload.RequestedHostname)>253||strings.TrimSpace(payload.RequestedHostname)!=payload.RequestedHostname{return invalid("site preview issue")};return nil }
func validateSitePreviewConsume(value any) error { payload:=value.(*SitePreviewConsumePayload);if payload.Audience.Validate()!=nil||len(payload.PreviewHostname)<3||len(payload.PreviewHostname)>253||len(payload.Token)!=43||payload.RequestBytes>sitepreview.MaximumSessionBytes{return invalid("site preview consume")};return nil }
func validateSitePreviewRevoke(value any) error { if value.(*SitePreviewRevokePayload).SessionID=="" { return invalid("site preview session") };return nil }
func validateSitePreviewList(value any) error { payload:=value.(*SitePreviewListPayload);if payload.Limit==0{payload.Limit=100};if payload.Limit>500||len(payload.Cursor)>128{return invalid("site preview list")};return nil }
func validateSiteScreenshotRequest(value any) error { payload:=value.(*SiteScreenshotRequestPayload);if len(payload.DestinationURL)<8||len(payload.DestinationURL)>2048||payload.Limits.Validate()!=nil||(payload.Mode!=sitepreview.ScreenshotLocal&&payload.Mode!=sitepreview.ScreenshotProvider)||payload.Mode==sitepreview.ScreenshotLocal&&payload.Provider!=nil||payload.Mode==sitepreview.ScreenshotProvider&&(payload.Provider==nil||payload.Provider.Validate()!=nil){return invalid("site screenshot request")};return nil }
func validateSiteScreenshotInspect(value any) error { if value.(*SiteScreenshotInspectPayload).JobID=="" { return invalid("site screenshot job") };return nil }

func sitePreviewActor(inv Invocation) sitepreview.Actor { return sitepreview.Actor{PrincipalID:sitepreview.PrincipalID(inv.Actor.PrincipalID.String()),AuthzEpoch:inv.Actor.AuthzEpoch,Assurance:sitepreview.Assurance(inv.Actor.Assurance)} }
func sitePreviewSessionView(session sitepreview.PreviewSession) SitePreviewSessionView { return SitePreviewSessionView{ID:session.ID,SiteID:session.SiteID,SiteGeneration:session.SiteGeneration,Audience:session.Audience,GrantMode:session.GrantMode,PreviewHostname:session.PreviewHostname,RequestedHostname:session.RequestedHostname,Limits:session.Limits,ConsumedBytes:session.ConsumedBytes,ConsumedRequests:session.ConsumedRequests,State:session.State,Generation:session.Generation,CreatedAt:session.CreatedAt,LastUsedAt:session.LastUsedAt,ExpiresAt:session.ExpiresAt,RevokedAt:session.RevokedAt} }
func siteScreenshotView(inspection sitepreview.ScreenshotInspection) SiteScreenshotView { job:=inspection.Job;view:=SiteScreenshotView{ID:job.ID,SiteID:job.SiteID,SiteGeneration:job.SiteGeneration,Mode:job.Mode,State:job.State,Generation:job.Generation,CreatedAt:job.CreatedAt,UpdatedAt:job.UpdatedAt};if inspection.Artifact!=nil{artifact:=inspection.Artifact;view.Artifact=&SiteScreenshotArtifactView{ID:artifact.ID,SiteGeneration:artifact.SiteGeneration,MediaType:artifact.MediaType,ByteSize:artifact.ByteSize,PixelWidth:artifact.PixelWidth,PixelHeight:artifact.PixelHeight,Digest:artifact.Digest,CreatedAt:artifact.CreatedAt}};return view }
