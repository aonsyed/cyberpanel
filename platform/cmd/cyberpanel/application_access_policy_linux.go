//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/accesspolicy"
)

type applicationAccessPolicyBridge struct{ authority *accesspolicy.Authority }

func (bridge applicationAccessPolicyBridge) BindApplicationPolicy(ctx context.Context, tenant apps.TenantID, site apps.SiteID, installation apps.InstallationID, policyID, route string) error {
	if bridge.authority == nil || installation == "" {
		return apps.ErrInvalid
	}
	return bridge.authority.VerifyBinding(ctx, string(tenant), string(site), policyID, route)
}

func (bridge applicationAccessPolicyBridge) EnableApplicationPolicy(ctx context.Context, policyID string) error {
	if bridge.authority == nil {
		return apps.ErrInvalid
	}
	_, err := bridge.authority.SetState(ctx, policyID, true)
	return err
}

func (bridge applicationAccessPolicyBridge) DisableApplicationPolicy(ctx context.Context, policyID string) error {
	if bridge.authority == nil {
		return apps.ErrInvalid
	}
	_, err := bridge.authority.SetState(ctx, policyID, false)
	return err
}

func (bridge applicationAccessPolicyBridge) RevokeApplicationPolicy(ctx context.Context, policyID string) error {
	if bridge.authority == nil || policyID == "" {
		return apps.ErrInvalid
	}
	sum := sha256.Sum256([]byte("cyberpanel:application-access-revoke:v1\x00" + policyID))
	return bridge.authority.Delete(ctx, "app-access-"+hex.EncodeToString(sum[:])[:48], policyID)
}

var _ apps.WebAccessPolicyPort = applicationAccessPolicyBridge{}
