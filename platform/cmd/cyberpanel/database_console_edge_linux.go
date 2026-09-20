//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"time"
)

func (edge *databaseEdge) IssueDatabaseConsole(ctx context.Context, call apiserver.EdgeCall, payload apiserver.DatabaseConsoleIssuePayload) (apiserver.DatabaseConsoleProjection, error) {
	var empty apiserver.DatabaseConsoleProjection
	if edge == nil || edge.repository == nil || edge.coordinator == nil || ctx == nil || call.CommandID == "" || call.ExpectedGeneration == 0 {
		return empty, database.ErrUnauthorized
	}
	tenant, err := site.NewTenantID(call.TenantID)
	if err != nil {
		return empty, database.ErrUnauthorized
	}
	databaseID, err := database.NewResourceID(call.ResourceID)
	if err != nil {
		return empty, database.ErrInvalidResource
	}
	principalID, err := database.NewResourceID(payload.PrincipalID)
	if err != nil {
		return empty, database.ErrInvalidResource
	}
	managed, err := edge.loadDatabase(ctx, databaseID)
	if err != nil {
		return empty, err
	}
	if managed.TenantID != tenant {
		return empty, database.ErrNotFound
	}
	if managed.Generation != call.ExpectedGeneration || managed.Status.Lifecycle != database.LifecycleReady || managed.Status.Reconciliation != database.ReconciliationInSync {
		return empty, database.ErrConflict
	}
	principals, err := edge.repository.ListDatabasePrincipals(ctx, tenant, databaseID)
	if err != nil {
		return empty, err
	}
	var principal *database.DatabasePrincipal
	for i := range principals {
		if principals[i].ID == principalID {
			principal = &principals[i]
			break
		}
	}
	if principal == nil || principal.Disabled || principal.TenantID != tenant || principal.SiteID != managed.SiteID || principal.InstanceID != managed.InstanceID || principal.Status.Lifecycle != database.LifecycleReady || principal.Status.Reconciliation != database.ReconciliationInSync {
		return empty, database.ErrUnauthorized
	}
	sum := sha256.Sum256([]byte("cyberpanel:database-console:v1\x00" + tenant.String() + "\x00" + call.CommandID))
	id, _ := database.NewResourceID("console-" + hex.EncodeToString(sum[:])[:48])
	session := database.DatabaseWorkspaceSession{
		Metadata:   database.Metadata{ID: id, TenantID: tenant, SiteID: managed.SiteID, Generation: 1, Status: database.ResourceStatus{Lifecycle: database.LifecycleProvisioning, Health: database.HealthUnknown, Reconciliation: database.ReconciliationPending}},
		DatabaseID: databaseID, PrincipalID: principalID, SessionSecretRef: principal.CredentialSecretRef,
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
		Limits:    database.SessionLimits{StatementTimeout: 30 * time.Second, MaxRows: 1000, MaxResultBytes: 1 << 20, MaxConnections: 1},
	}
	if existing, err := edge.repository.LoadResource(ctx, database.KindConsoleSession, id); err == nil {
		decoded, err := database.DecodeResource(existing)
		if err != nil {
			return empty, err
		}
		stored, ok := decoded.(*database.DatabaseWorkspaceSession)
		if !ok || stored.TenantID != tenant || stored.SiteID != managed.SiteID || stored.DatabaseID != databaseID || stored.PrincipalID != principalID || stored.SessionSecretRef != principal.CredentialSecretRef || !stored.ExpiresAt.After(time.Now().UTC()) {
			return empty, database.ErrConflict
		}
		session = *stored
		if session.Status.Lifecycle == database.LifecycleReady && session.Status.Reconciliation == database.ReconciliationInSync {
			return projectDatabaseConsole(session), nil
		}
		if session.Status.Lifecycle != database.LifecycleProvisioning || session.Status.Reconciliation != database.ReconciliationPending {
			return empty, database.ErrConflict
		}
	} else if !errors.Is(err, database.ErrNotFound) {
		return empty, err
	}
	receipt, err := edge.coordinator.Handle(ctx, database.OpenConsoleSession{Header: database.CommandHeader{CommandID: call.CommandID, TenantID: tenant, Actor: database.Actor{TenantID: tenant, Capability: database.CapabilityTenantConsole}}, Session: session})
	if err != nil {
		return empty, err
	}
	if receipt.Status != database.OperationApplied {
		return empty, database.ErrInvalidReceipt
	}
	return projectDatabaseConsole(session), nil
}

func projectDatabaseConsole(session database.DatabaseWorkspaceSession) apiserver.DatabaseConsoleProjection {
	return apiserver.DatabaseConsoleProjection{ID: session.ID.String(), SiteID: session.SiteID.String(), Generation: session.Generation, ExpiresAt: session.ExpiresAt}
}
