//go:build linux

package main

import (
	"context"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/preview"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

type hostingPreviewEdge struct{ sessions *preview.Service }

func newHostingPreviewEdge(sessions *preview.Service) (*hostingPreviewEdge, error) {
	if sessions == nil { return nil, preview.ErrInvalid }
	return &hostingPreviewEdge{sessions:sessions},nil
}

func (edge *hostingPreviewEdge) IssuePreview(ctx context.Context, call apiserver.EdgeCall, payload apiserver.HostingPreviewPayload) (apiserver.HostingPreviewGrant, error) {
	if edge == nil || edge.sessions == nil || call.TenantID == "" || call.ResourceID == "" || call.ExpectedGeneration == 0 || call.PrincipalID == "" || call.CredentialID == "" || call.AuthzEpoch == 0 {
		return apiserver.HostingPreviewGrant{}, preview.ErrInvalid
	}
	tenant, err := site.NewTenantID(call.TenantID)
	if err != nil { return apiserver.HostingPreviewGrant{}, err }
	siteID, err := site.NewSiteID(call.ResourceID)
	if err != nil { return apiserver.HostingPreviewGrant{}, err }
	session, err := edge.sessions.Issue(ctx, preview.IssueRequest{
		CommandID:          call.CommandID,
		TenantID:           tenant,
		SiteID:             siteID,
		ExpectedGeneration: call.ExpectedGeneration,
		ViewerPrincipalID:  call.PrincipalID,
		ViewerCredentialID: call.CredentialID,
		AuthzEpoch:         call.AuthzEpoch,
		TTL:                time.Duration(payload.TTLSeconds) * time.Second,
		RequestBudget:      payload.MaximumRequests,
	})
	if err != nil { return apiserver.HostingPreviewGrant{}, err }
	return apiserver.HostingPreviewGrant{ID:session.ID,URL:"https://"+session.Hostname+"/",Hostname:session.Hostname,RequestBudget:session.RequestBudget,SiteGeneration:session.BindingGeneration,ExpiresAt:session.ExpiresAt},nil
}

var _ apiserver.HostingPreviewEdgeService = (*hostingPreviewEdge)(nil)
