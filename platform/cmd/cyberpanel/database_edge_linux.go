//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	hostingservice "github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

type databaseEdgeRepository interface {
	ListDatabases(context.Context, site.TenantID, string, uint16) ([]database.Database, string, uint64, error)
	ListDatabaseInstances(context.Context, string, uint16) ([]database.DatabaseInstance, string, uint64, error)
	DatabasePrincipalCount(context.Context, site.TenantID, database.ResourceID) (uint64, error)
	LoadResource(context.Context, database.ResourceKind, database.ResourceID) (database.ResourceEnvelope, error)
}

type databaseEdgeSiteStore interface {
	Load(context.Context, site.TenantID, site.SiteID) (site.Site, error)
}

type databaseEdgeCoordinator interface {
	Handle(context.Context, database.Command) (database.OperationReceipt, error)
}

type databaseEdgeStatus interface {
	Status(context.Context, database.ResourceID) (database.MariaDBInstanceStatus, error)
}

type databaseEdgeSecretManagement interface {
	PutExact(context.Context, secrets.PutRequest) (secrets.Metadata, error)
}

type databaseEdge struct {
	repository    databaseEdgeRepository
	sites         databaseEdgeSiteStore
	coordinator   databaseEdgeCoordinator
	status        databaseEdgeStatus
	management    databaseEdgeSecretManagement
	releaseDigest string
}

func newDatabaseEdge(repository databaseEdgeRepository, sites databaseEdgeSiteStore, coordinator databaseEdgeCoordinator, status databaseEdgeStatus, management databaseEdgeSecretManagement, releaseDigest string) (apiserver.DatabaseEdgeService, error) {
	digest, err := hex.DecodeString(releaseDigest)
	if repository == nil || sites == nil || coordinator == nil || status == nil || management == nil || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != releaseDigest {
		return nil, errors.New("database edge requires repository, coordinator, secret broker, and exact executor digest")
	}
	return &databaseEdge{repository: repository, sites: sites, coordinator: coordinator, status: status, management: management, releaseDigest: releaseDigest}, nil
}

func (edge *databaseEdge) ListDatabases(ctx context.Context, call apiserver.EdgeCall, page apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.DatabaseProjection], error) {
	tenant, err := site.NewTenantID(call.TenantID)
	if err != nil {
		return apiserver.EdgePage[apiserver.DatabaseProjection]{}, database.ErrInvalidResource
	}
	values, next, total, err := edge.repository.ListDatabases(ctx, tenant, page.Cursor, page.Limit)
	if err != nil {
		return apiserver.EdgePage[apiserver.DatabaseProjection]{}, err
	}
	items := make([]apiserver.DatabaseProjection, 0, len(values))
	for _, value := range values {
		principals, countErr := edge.repository.DatabasePrincipalCount(ctx, tenant, value.ID)
		if countErr != nil {
			return apiserver.EdgePage[apiserver.DatabaseProjection]{}, countErr
		}
		items = append(items, apiserver.DatabaseProjection{ID: value.ID.String(), SiteID: value.SiteID.String(), Name: value.Name.String(), Instance: value.InstanceID.String(), Principals: principals, Status: string(value.Status.Lifecycle), Generation: value.Generation})
	}
	return apiserver.EdgePage[apiserver.DatabaseProjection]{Items: items, NextCursor: next, Total: total}, nil
}

func (edge *databaseEdge) CreateManagedDatabase(ctx context.Context, call apiserver.EdgeCall, payload apiserver.DatabaseCreateManagedPayload) (apiserver.EdgeMutation[apiserver.DatabaseProjection], error) {
	if edge == nil || edge.repository == nil || edge.sites == nil || edge.coordinator == nil || ctx == nil || call.CommandID == "" || call.TenantID == "" || call.ResourceID != "" || call.ExpectedGeneration != 0 {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrUnauthorized
	}
	tenantID, err := site.NewTenantID(call.TenantID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrInvalidResource
	}
	siteID, err := site.NewSiteID(payload.SiteID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrInvalidResource
	}
	aggregate, err := edge.sites.Load(ctx, tenantID, siteID)
	if err != nil {
		if errors.Is(err, hostingservice.ErrNotFound) {
			return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrNotFound
		}
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, err
	}
	if aggregate.TenantID() != tenantID || aggregate.ID() != siteID || aggregate.Lifecycle() != site.LifecycleActive {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrConflict
	}
	instanceID, err := database.NewResourceID(payload.InstanceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrInvalidResource
	}
	instance, err := edge.loadDatabaseInstance(ctx, instanceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, err
	}
	if instance.Status.Lifecycle != database.LifecycleReady || instance.Status.Reconciliation != database.ReconciliationInSync {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrConflict
	}
	name, err := database.ParseSQLIdentifier(payload.Name)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrInvalidResource
	}
	charset, err := database.ParseSQLIdentifier(payload.Charset)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrInvalidResource
	}
	collation, err := database.ParseSQLIdentifier(payload.Collation)
	if err != nil || payload.QuotaBytes == 0 || payload.QuotaBytes > 1<<60 {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrInvalidResource
	}
	idDigest := sha256.Sum256([]byte("cyberpanel:managed-database:v1\x00" + tenantID.String() + "\x00" + call.CommandID))
	databaseID, _ := database.NewResourceID("db-" + hex.EncodeToString(idDigest[:])[:48])
	resource := database.Database{
		Metadata: database.Metadata{
			ID: databaseID,
			TenantID: tenantID,
			SiteID: siteID,
			Generation: 1,
			Status: database.ResourceStatus{Lifecycle: database.LifecycleProvisioning, Health: database.HealthUnknown, Reconciliation: database.ReconciliationPending},
		},
		InstanceID: instanceID,
		Name: name,
		Charset: charset,
		Collation: collation,
		QuotaBytes: payload.QuotaBytes,
	}
	receipt, err := edge.coordinator.Handle(ctx, database.CreateDatabase{
		Header: database.CommandHeader{CommandID: call.CommandID, Actor: database.Actor{TenantID: tenantID, Capability: database.CapabilityTenantManage}, TenantID: tenantID},
		Database: resource,
	})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, err
	}
	if receipt.Status != database.OperationApplied {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, database.ErrInvalidReceipt
	}
	stored, err := edge.loadDatabase(ctx, databaseID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, err
	}
	principals, err := edge.repository.DatabasePrincipalCount(ctx, tenantID, databaseID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseProjection]{}, err
	}
	projection := projectDatabase(stored, principals)
	return apiserver.EdgeMutation[apiserver.DatabaseProjection]{OperationID: call.CommandID, State: projection.Status, Generation: projection.Generation, Resource: projection}, nil
}

func (edge *databaseEdge) CreateManagedPrincipal(ctx context.Context, call apiserver.EdgeCall, payload apiserver.DatabasePrincipalCreateManagedPayload, password []byte) (apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection], error) {
	defer wipeDatabaseEdgeMaterial(password)
	if edge == nil || edge.repository == nil || edge.coordinator == nil || edge.management == nil || ctx == nil || call.CommandID == "" || call.TenantID == "" || call.ResourceID == "" || call.ExpectedGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrUnauthorized
	}
	if len(password) < 12 || len(password) > 4096 || bytes.IndexByte(password, 0) >= 0 {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrInvalidResource
	}
	tenantID, err := site.NewTenantID(call.TenantID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrInvalidResource
	}
	databaseID, err := database.NewResourceID(call.ResourceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrInvalidResource
	}
	managedDatabase, err := edge.loadDatabase(ctx, databaseID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, err
	}
	if managedDatabase.TenantID != tenantID {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrNotFound
	}
	if managedDatabase.Generation != call.ExpectedGeneration || managedDatabase.Status.Lifecycle != database.LifecycleReady || managedDatabase.Status.Reconciliation != database.ReconciliationInSync {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrConflict
	}
	instance, err := edge.loadDatabaseInstance(ctx, managedDatabase.InstanceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, err
	}
	if instance.ID != managedDatabase.InstanceID || instance.Status.Lifecycle != database.LifecycleReady || instance.Status.Reconciliation != database.ReconciliationInSync {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrConflict
	}
	name, err := database.ParseSQLIdentifier(payload.Name)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrInvalidResource
	}
	hostScope := database.HostScope(payload.HostScope)
	networkPolicyID := database.ResourceID{}
	switch hostScope {
	case database.HostScopeLoopback:
		if instance.Placement != database.PlacementLocal {
			return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrConflict
		}
	case database.HostScopePolicy:
		policy, policyErr := edge.loadNetworkPolicy(ctx, instance.NetworkPolicyID)
		if policyErr != nil {
			return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, policyErr
		}
		if policy.ID != instance.NetworkPolicyID || policy.InstanceID != instance.ID || policy.Status.Lifecycle != database.LifecycleReady || policy.Status.Reconciliation != database.ReconciliationInSync || len(policy.AllowedCIDRs) == 0 {
			return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrConflict
		}
		networkPolicyID = policy.ID
	default:
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrInvalidResource
	}
	privileges := make([]database.Privilege, len(payload.Privileges))
	for index, value := range payload.Privileges {
		privileges[index] = database.Privilege(value)
	}
	sort.Slice(privileges, func(left, right int) bool { return privileges[left] < privileges[right] })
	principalID, grantSetID, credentialRef, err := managedDatabasePrincipalIDs(tenantID, databaseID, call.CommandID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrInvalidResource
	}
	status := database.ResourceStatus{Lifecycle: database.LifecycleProvisioning, Health: database.HealthUnknown, Reconciliation: database.ReconciliationPending}
	principal := database.DatabasePrincipal{
		Metadata: database.Metadata{ID: principalID, TenantID: tenantID, SiteID: managedDatabase.SiteID, Generation: 1, Status: status},
		InstanceID: instance.ID,
		Name: name,
		HostScope: hostScope,
		NetworkPolicyID: networkPolicyID,
		CredentialSecretRef: credentialRef,
	}
	grantSet := database.GrantSet{
		Metadata: database.Metadata{ID: grantSetID, TenantID: tenantID, SiteID: managedDatabase.SiteID, Generation: 1, Status: status},
		InstanceID: instance.ID,
		DatabaseID: managedDatabase.ID,
		PrincipalID: principal.ID,
		Grants: []database.Grant{{Scope: database.GrantScopeDatabase, Privileges: privileges}},
	}
	if principal.Validate() != nil || grantSet.Validate() != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrInvalidResource
	}
	origin := "local://panel-execd/mariadb"
	if instance.External != nil {
		origin = "mariadb://" + net.JoinHostPort(instance.External.Endpoint.Host, strconv.FormatUint(uint64(instance.External.Endpoint.Port), 10))
	}
	if _, err = edge.management.PutExact(ctx, secrets.PutRequest{
		ID: database.DatabaseSecretRecordID(credentialRef.String()),
		OwnerTenantID: database.DatabaseTenantOwnerID(tenantID.String()),
		Purpose: secrets.PurposeDatabase,
		Audience: secrets.AudienceBinding{
			AdapterID: database.MariaDBSecretAdapterID,
			AdapterVersion: database.MariaDBSecretAdapterVersion,
			Account: name.String(),
			Origin: origin,
			ResourceKind: "database_principal",
			ResourceID: database.DatabaseAudienceID(principalID.String()),
			ResourceGeneration: principal.Generation,
			Operations: []secrets.Operation{secrets.OperationAuthenticate},
			ConsumerReleaseDigest: edge.releaseDigest,
		},
		Plaintext: append([]byte(nil), password...),
	}); err != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, mapDatabaseEdgeSecretError(err)
	}
	header := database.CommandHeader{Actor: database.Actor{TenantID: tenantID, Capability: database.CapabilityTenantManage}, TenantID: tenantID}
	header.CommandID = managedDatabaseSubcommandID("principal", tenantID, databaseID, call.CommandID)
	receipt, err := edge.coordinator.Handle(ctx, database.CreatePrincipal{Header: header, Principal: principal})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, err
	}
	if receipt.Status != database.OperationApplied {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrInvalidReceipt
	}
	header.CommandID = managedDatabaseSubcommandID("grants", tenantID, databaseID, call.CommandID)
	receipt, err = edge.coordinator.Handle(ctx, database.ReplaceGrantSet{Header: header, GrantSet: grantSet})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, err
	}
	if receipt.Status != database.OperationApplied {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, database.ErrInvalidReceipt
	}
	stored, err := edge.loadDatabasePrincipal(ctx, principalID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{}, err
	}
	projection := projectDatabasePrincipal(stored, managedDatabase.ID, privileges)
	return apiserver.EdgeMutation[apiserver.DatabasePrincipalProjection]{OperationID: call.CommandID, State: projection.Status, Generation: projection.Generation, Resource: projection}, nil
}

func (edge *databaseEdge) ListDatabaseInstances(ctx context.Context, call apiserver.EdgeCall, page apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.DatabaseInstanceProjection], error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" {
		return apiserver.EdgePage[apiserver.DatabaseInstanceProjection]{}, database.ErrUnauthorized
	}
	values, next, total, err := edge.repository.ListDatabaseInstances(ctx, page.Cursor, page.Limit)
	if err != nil {
		return apiserver.EdgePage[apiserver.DatabaseInstanceProjection]{}, err
	}
	items := make([]apiserver.DatabaseInstanceProjection, 0, len(values))
	for _, value := range values {
		items = append(items, projectDatabaseInstance(value))
	}
	return apiserver.EdgePage[apiserver.DatabaseInstanceProjection]{Items: items, NextCursor: next, Total: total}, nil
}

func (edge *databaseEdge) InspectDatabaseInstance(ctx context.Context, call apiserver.EdgeCall) (apiserver.DatabaseInstanceProjection, error) {
	if edge == nil || edge.repository == nil || edge.status == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" || call.ExpectedGeneration != 0 {
		return apiserver.DatabaseInstanceProjection{}, database.ErrUnauthorized
	}
	id, err := database.NewResourceID(call.ResourceID)
	if err != nil {
		return apiserver.DatabaseInstanceProjection{}, database.ErrInvalidResource
	}
	instance, err := edge.loadDatabaseInstance(ctx, id)
	if err != nil {
		return apiserver.DatabaseInstanceProjection{}, err
	}
	observed, err := edge.status.Status(ctx, id)
	if err != nil {
		return apiserver.DatabaseInstanceProjection{}, err
	}
	if observed.InstanceID != instance.ID || observed.Placement != instance.Placement || observed.Version != instance.Version || !observed.Reachable ||
		instance.Placement == database.PlacementExternal && !observed.TLSVerified {
		return apiserver.DatabaseInstanceProjection{}, database.ErrConflict
	}
	projection := projectDatabaseInstance(instance)
	projection.Health = string(database.HealthHealthy)
	projection.Reachable = observed.Reachable
	projection.TLSVerified = observed.TLSVerified
	projection.ProofDigest = observed.ProofDigest
	projection.ObservedAt = observed.ObservedAt
	return projection, nil
}

func (edge *databaseEdge) ConfigureDatabaseInstanceNetwork(ctx context.Context, call apiserver.EdgeCall, payload apiserver.DatabaseNetworkConfigureManagedPayload) (apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection], error) {
	if edge == nil || edge.repository == nil || edge.coordinator == nil || ctx == nil || call.CommandID == "" || call.TenantID != "" || call.ResourceID == "" || call.ExpectedGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, database.ErrUnauthorized
	}
	instanceID, err := database.NewResourceID(call.ResourceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, database.ErrInvalidResource
	}
	instance, err := edge.loadDatabaseInstance(ctx, instanceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, err
	}
	if instance.Generation != call.ExpectedGeneration || instance.Status.Lifecycle != database.LifecycleReady || instance.Status.Reconciliation != database.ReconciliationInSync {
		return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, database.ErrConflict
	}
	interfaces := make([]database.NetworkInterface, len(payload.Interfaces))
	for index, value := range payload.Interfaces {
		interfaces[index] = database.NetworkInterface(value)
	}
	sort.Slice(interfaces, func(left, right int) bool { return interfaces[left] < interfaces[right] })
	prefixes := make([]netip.Prefix, len(payload.AllowedCIDRs))
	for index, value := range payload.AllowedCIDRs {
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil || prefix != prefix.Masked() {
			return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, database.ErrInvalidResource
		}
		prefixes[index] = prefix
	}
	sort.Slice(prefixes, func(left, right int) bool { return prefixes[left].String() < prefixes[right].String() })
	approval, err := database.NewResourceID(payload.HighRiskApproval)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, database.ErrInvalidResource
	}
	tlsMode := database.TLSMode(payload.TLSMode)
	verification := database.VerificationLevel(payload.Verification)
	if instance.Placement == database.PlacementExternal {
		if instance.External == nil || tlsMode != instance.External.RequiredTLS || verification != database.VerifyIndependentExternal || len(prefixes) == 0 {
			return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, database.ErrConflict
		}
	}
	generation := uint64(1)
	previous, previousErr := edge.loadNetworkPolicy(ctx, instance.NetworkPolicyID)
	if previousErr == nil {
		if previous.ID != instance.NetworkPolicyID || previous.InstanceID != instance.ID || previous.Status.Lifecycle != database.LifecycleReady || previous.Status.Reconciliation != database.ReconciliationInSync {
			return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, database.ErrConflict
		}
		generation = previous.Generation + 1
	} else if !errors.Is(previousErr, database.ErrNotFound) {
		return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, previousErr
	}
	policy := database.NetworkAccessPolicy{
		Metadata: database.Metadata{
			ID: instance.NetworkPolicyID,
			Generation: generation,
			Status: database.ResourceStatus{Lifecycle: database.LifecycleUpdating, Health: database.HealthUnknown, Reconciliation: database.ReconciliationPending},
		},
		InstanceID: instance.ID,
		Interfaces: interfaces,
		AllowedCIDRs: prefixes,
		TLS: tlsMode,
		Verification: verification,
		HighRiskApproval: approval,
	}
	if policy.Validate() != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, database.ErrInvalidResource
	}
	receipt, err := edge.coordinator.Handle(ctx, database.ReplaceRemoteCIDRs{
		Header: database.CommandHeader{CommandID: call.CommandID, Actor: database.Actor{Capability: database.CapabilityNodeAdmin, ApprovalRef: approval}},
		Policy: policy,
	})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, err
	}
	if receipt.Status != database.OperationApplied {
		return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, database.ErrInvalidReceipt
	}
	stored, err := edge.loadNetworkPolicy(ctx, policy.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{}, err
	}
	projection := projectDatabaseNetworkPolicy(stored)
	return apiserver.EdgeMutation[apiserver.DatabaseNetworkPolicyProjection]{OperationID: call.CommandID, State: projection.Status, Generation: projection.Generation, Resource: projection}, nil
}

func (edge *databaseEdge) EnrollExternalDatabaseInstance(ctx context.Context, call apiserver.EdgeCall, payload apiserver.DatabaseExternalEnrollmentPayload, material apiserver.DatabaseExternalEnrollmentSecrets) (apiserver.EdgeMutation[apiserver.DatabaseInstanceProjection], error) {
	defer wipeDatabaseEdgeMaterial(material.AdministratorPassword, material.ClientCertificatePEM, material.ClientKeyPEM, material.CertificateAuthorityPEM)
	if edge == nil || edge.repository == nil || edge.coordinator == nil || edge.management == nil || ctx == nil || call.CommandID == "" || call.TenantID != "" || call.ResourceID != "" || call.ExpectedGeneration != 0 {
		return apiserver.EdgeMutation[apiserver.DatabaseInstanceProjection]{}, database.ErrUnauthorized
	}
	instance, approval, err := edge.externalInstance(payload)
	if err != nil || validateExternalDatabaseMaterial(instance, payload.AdministratorUsername, material) != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseInstanceProjection]{}, database.ErrInvalidResource
	}
	administratorRef := instance.External.AdminSecretRef
	caRef := instance.External.PinnedCASecretRef
	administratorPayload, err := json.Marshal(struct {
		Username             string `json:"username"`
		Password             []byte `json:"password"`
		ClientCertificatePEM []byte `json:"client_certificate_pem,omitempty"`
		ClientKeyPEM         []byte `json:"client_key_pem,omitempty"`
	}{
		Username: payload.AdministratorUsername,
		Password: material.AdministratorPassword,
		ClientCertificatePEM: material.ClientCertificatePEM,
		ClientKeyPEM: material.ClientKeyPEM,
	})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseInstanceProjection]{}, database.ErrInvalidResource
	}
	defer wipeDatabaseEdgeMaterial(administratorPayload)
	owner, _ := secrets.NewID("installation")
	audience := database.DatabaseAudienceID(instance.External.CredentialAudience.String())
	origin := "mariadb://" + net.JoinHostPort(instance.External.Endpoint.Host, strconv.FormatUint(uint64(instance.External.Endpoint.Port), 10))
	baseAudience := secrets.AudienceBinding{
		AdapterID: database.MariaDBSecretAdapterID,
		AdapterVersion: database.MariaDBSecretAdapterVersion,
		Origin: origin,
		ResourceID: audience,
		ResourceGeneration: instance.Generation,
		ConsumerReleaseDigest: edge.releaseDigest,
	}
	administratorAudience := baseAudience
	administratorAudience.Account = payload.AdministratorUsername
	administratorAudience.ResourceKind = "database_admin"
	administratorAudience.Operations = []secrets.Operation{secrets.OperationAuthenticate}
	if _, err = edge.management.PutExact(ctx, secrets.PutRequest{
		ID: database.DatabaseSecretRecordID(administratorRef.String()),
		OwnerTenantID: owner,
		Purpose: secrets.PurposeDatabase,
		Audience: administratorAudience,
		Plaintext: administratorPayload,
	}); err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseInstanceProjection]{}, mapDatabaseEdgeSecretError(err)
	}
	caAudience := baseAudience
	caAudience.Account = instance.External.ServerName
	caAudience.ResourceKind = "database_ca"
	caAudience.Operations = []secrets.Operation{secrets.OperationRead}
	if _, err = edge.management.PutExact(ctx, secrets.PutRequest{
		ID: database.DatabaseSecretRecordID(caRef.String()),
		OwnerTenantID: owner,
		Purpose: secrets.PurposeDatabase,
		Audience: caAudience,
		Plaintext: append([]byte(nil), material.CertificateAuthorityPEM...),
	}); err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseInstanceProjection]{}, mapDatabaseEdgeSecretError(err)
	}
	_, err = edge.coordinator.Handle(ctx, database.BindExternalInstance{
		Header: database.CommandHeader{CommandID: call.CommandID, Actor: database.Actor{Capability: database.CapabilityNodeAdmin, ApprovalRef: approval}},
		Instance: instance,
	})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseInstanceProjection]{}, err
	}
	stored, err := edge.loadDatabaseInstance(ctx, instance.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.DatabaseInstanceProjection]{}, err
	}
	projection := projectDatabaseInstance(stored)
	return apiserver.EdgeMutation[apiserver.DatabaseInstanceProjection]{OperationID: call.CommandID, State: projection.Status, Generation: projection.Generation, Resource: projection}, nil
}

func (edge *databaseEdge) externalInstance(payload apiserver.DatabaseExternalEnrollmentPayload) (database.DatabaseInstance, database.ResourceID, error) {
	id, err := database.NewResourceID(payload.ID)
	if err != nil {
		return database.DatabaseInstance{}, database.ResourceID{}, err
	}
	networkPolicyID, err := database.NewResourceID(payload.NetworkPolicyID)
	if err != nil {
		return database.DatabaseInstance{}, database.ResourceID{}, err
	}
	approval, err := database.NewResourceID(payload.ApprovalRef)
	if err != nil {
		return database.DatabaseInstance{}, database.ResourceID{}, err
	}
	administratorRef, caRef, err := externalDatabaseSecretReferences(id)
	if err != nil {
		return database.DatabaseInstance{}, database.ResourceID{}, err
	}
	host := strings.TrimSpace(payload.Host)
	instance := database.DatabaseInstance{
		Metadata: database.Metadata{
			ID: id,
			Generation: 1,
			Status: database.ResourceStatus{Lifecycle: database.LifecycleProvisioning, Health: database.HealthUnknown, Reconciliation: database.ReconciliationPending},
		},
		Placement: database.PlacementExternal,
		Version: database.MariaDBVersion{Major: payload.VersionMajor, Minor: payload.VersionMinor, Patch: payload.VersionPatch},
		External: &database.ExternalInstance{
			Endpoint: database.Endpoint{Host: host, Port: payload.Port},
			ServerName: host,
			PinnedCASecretRef: caRef,
			AdminSecretRef: administratorRef,
			CredentialAudience: id,
			RequiredTLS: database.TLSMode(payload.TLSMode),
		},
		NetworkPolicyID: networkPolicyID,
		Capacity: database.InstanceCapacity{StorageBytes: payload.StorageBytes, MemoryBytes: payload.MemoryBytes, MaxConnections: payload.MaxConnections},
	}
	if err = instance.Validate(); err != nil {
		return database.DatabaseInstance{}, database.ResourceID{}, err
	}
	return instance, approval, nil
}

func (edge *databaseEdge) loadDatabaseInstance(ctx context.Context, id database.ResourceID) (database.DatabaseInstance, error) {
	envelope, err := edge.repository.LoadResource(ctx, database.KindDatabaseInstance, id)
	if err != nil {
		return database.DatabaseInstance{}, err
	}
	resource, err := database.DecodeResource(envelope)
	if err != nil {
		return database.DatabaseInstance{}, err
	}
	instance, ok := resource.(*database.DatabaseInstance)
	if !ok {
		return database.DatabaseInstance{}, database.ErrInvalidResource
	}
	return *instance, nil
}

func (edge *databaseEdge) loadDatabase(ctx context.Context, id database.ResourceID) (database.Database, error) {
	envelope, err := edge.repository.LoadResource(ctx, database.KindDatabase, id)
	if err != nil {
		return database.Database{}, err
	}
	resource, err := database.DecodeResource(envelope)
	if err != nil {
		return database.Database{}, err
	}
	value, ok := resource.(*database.Database)
	if !ok {
		return database.Database{}, database.ErrInvalidResource
	}
	return *value, nil
}

func (edge *databaseEdge) loadDatabasePrincipal(ctx context.Context, id database.ResourceID) (database.DatabasePrincipal, error) {
	envelope, err := edge.repository.LoadResource(ctx, database.KindPrincipal, id)
	if err != nil {
		return database.DatabasePrincipal{}, err
	}
	resource, err := database.DecodeResource(envelope)
	if err != nil {
		return database.DatabasePrincipal{}, err
	}
	value, ok := resource.(*database.DatabasePrincipal)
	if !ok {
		return database.DatabasePrincipal{}, database.ErrInvalidResource
	}
	return *value, nil
}

func (edge *databaseEdge) loadNetworkPolicy(ctx context.Context, id database.ResourceID) (database.NetworkAccessPolicy, error) {
	envelope, err := edge.repository.LoadResource(ctx, database.KindNetworkPolicy, id)
	if err != nil {
		return database.NetworkAccessPolicy{}, err
	}
	resource, err := database.DecodeResource(envelope)
	if err != nil {
		return database.NetworkAccessPolicy{}, err
	}
	value, ok := resource.(*database.NetworkAccessPolicy)
	if !ok {
		return database.NetworkAccessPolicy{}, database.ErrInvalidResource
	}
	return *value, nil
}

func managedDatabasePrincipalIDs(tenantID site.TenantID, databaseID database.ResourceID, commandID string) (database.ResourceID, database.ResourceID, database.SecretRef, error) {
	seed := tenantID.String() + "\x00" + databaseID.String() + "\x00" + commandID
	principalDigest := sha256.Sum256([]byte("cyberpanel:managed-database-principal:v1\x00" + seed))
	grantDigest := sha256.Sum256([]byte("cyberpanel:managed-database-grants:v1\x00" + seed))
	credentialDigest := sha256.Sum256([]byte("cyberpanel:managed-database-credential:v1\x00" + seed))
	principalID, err := database.NewResourceID("dbprincipal-" + hex.EncodeToString(principalDigest[:])[:48])
	if err != nil {
		return database.ResourceID{}, database.ResourceID{}, database.SecretRef{}, err
	}
	grantSetID, err := database.NewResourceID("dbgrants-" + hex.EncodeToString(grantDigest[:])[:48])
	if err != nil {
		return database.ResourceID{}, database.ResourceID{}, database.SecretRef{}, err
	}
	credentialRef, err := database.NewSecretRef("dbcredential-" + hex.EncodeToString(credentialDigest[:])[:48])
	return principalID, grantSetID, credentialRef, err
}

func managedDatabaseSubcommandID(kind string, tenantID site.TenantID, databaseID database.ResourceID, commandID string) string {
	digest := sha256.Sum256([]byte("cyberpanel:managed-database-command:v1\x00" + kind + "\x00" + tenantID.String() + "\x00" + databaseID.String() + "\x00" + commandID))
	return "db-" + kind + "-" + hex.EncodeToString(digest[:])[:48]
}

func externalDatabaseSecretReferences(instanceID database.ResourceID) (database.SecretRef, database.SecretRef, error) {
	administratorDigest := sha256.Sum256([]byte("cyberpanel:external-database-administrator:v1\x00" + instanceID.String()))
	caDigest := sha256.Sum256([]byte("cyberpanel:external-database-ca:v1\x00" + instanceID.String()))
	administrator, err := database.NewSecretRef("dbext-admin-" + hex.EncodeToString(administratorDigest[:])[:48])
	if err != nil {
		return database.SecretRef{}, database.SecretRef{}, err
	}
	ca, err := database.NewSecretRef("dbext-ca-" + hex.EncodeToString(caDigest[:])[:48])
	return administrator, ca, err
}

func validateExternalDatabaseMaterial(instance database.DatabaseInstance, username string, material apiserver.DatabaseExternalEnrollmentSecrets) error {
	if instance.Validate() != nil || instance.External == nil {
		return database.ErrInvalidResource
	}
	if _, err := database.ParseSQLIdentifier(username); err != nil {
		return err
	}
	if len(material.AdministratorPassword) == 0 || len(material.AdministratorPassword) > 64<<10 || bytes.IndexByte(material.AdministratorPassword, 0) >= 0 ||
		len(material.CertificateAuthorityPEM) == 0 || len(material.CertificateAuthorityPEM) > 64<<10 ||
		len(material.ClientCertificatePEM) > 64<<10 || len(material.ClientKeyPEM) > 64<<10 {
		return database.ErrInvalidResource
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(material.CertificateAuthorityPEM) {
		return database.ErrInvalidResource
	}
	if instance.External.RequiredTLS == database.TLSMutual {
		if len(material.ClientCertificatePEM) == 0 || len(material.ClientKeyPEM) == 0 {
			return database.ErrInvalidResource
		}
		if _, err := tls.X509KeyPair(material.ClientCertificatePEM, material.ClientKeyPEM); err != nil {
			return database.ErrInvalidResource
		}
	} else if len(material.ClientCertificatePEM) != 0 || len(material.ClientKeyPEM) != 0 {
		return database.ErrInvalidResource
	}
	return nil
}

func projectDatabaseInstance(instance database.DatabaseInstance) apiserver.DatabaseInstanceProjection {
	endpoint := "local"
	serverName := ""
	tlsMode := "local_socket"
	if instance.External != nil {
		endpoint = net.JoinHostPort(instance.External.Endpoint.Host, strconv.FormatUint(uint64(instance.External.Endpoint.Port), 10))
		serverName = instance.External.ServerName
		tlsMode = string(instance.External.RequiredTLS)
	}
	version := fmt.Sprintf("%d.%d.%d", instance.Version.Major, instance.Version.Minor, instance.Version.Patch)
	return apiserver.DatabaseInstanceProjection{
		ID: instance.ID.String(),
		Placement: string(instance.Placement),
		Endpoint: endpoint,
		ServerName: serverName,
		TLS: tlsMode,
		Version: version,
		StorageBytes: instance.Capacity.StorageBytes,
		MemoryBytes: instance.Capacity.MemoryBytes,
		MaxConnections: instance.Capacity.MaxConnections,
		Health: string(instance.Status.Health),
		Status: string(instance.Status.Lifecycle),
		Generation: instance.Generation,
	}
}

func projectDatabase(value database.Database, principals uint64) apiserver.DatabaseProjection {
	return apiserver.DatabaseProjection{
		ID: value.ID.String(),
		SiteID: value.SiteID.String(),
		Name: value.Name.String(),
		Instance: value.InstanceID.String(),
		Principals: principals,
		Status: string(value.Status.Lifecycle),
		Generation: value.Generation,
	}
}

func projectDatabasePrincipal(value database.DatabasePrincipal, databaseID database.ResourceID, privileges []database.Privilege) apiserver.DatabasePrincipalProjection {
	projectedPrivileges := make([]string, len(privileges))
	for index, privilege := range privileges {
		projectedPrivileges[index] = string(privilege)
	}
	return apiserver.DatabasePrincipalProjection{
		ID: value.ID.String(),
		DatabaseID: databaseID.String(),
		Name: value.Name.String(),
		HostScope: string(value.HostScope),
		NetworkPolicyID: value.NetworkPolicyID.String(),
		Privileges: projectedPrivileges,
		Status: string(value.Status.Lifecycle),
		Generation: value.Generation,
	}
}

func projectDatabaseNetworkPolicy(value database.NetworkAccessPolicy) apiserver.DatabaseNetworkPolicyProjection {
	interfaces := make([]string, len(value.Interfaces))
	for index, networkInterface := range value.Interfaces {
		interfaces[index] = string(networkInterface)
	}
	prefixes := make([]string, len(value.AllowedCIDRs))
	for index, prefix := range value.AllowedCIDRs {
		prefixes[index] = prefix.String()
	}
	return apiserver.DatabaseNetworkPolicyProjection{
		ID: value.ID.String(),
		InstanceID: value.InstanceID.String(),
		Interfaces: interfaces,
		AllowedCIDRs: prefixes,
		TLS: string(value.TLS),
		Verification: string(value.Verification),
		Status: string(value.Status.Lifecycle),
		Generation: value.Generation,
	}
}

func mapDatabaseEdgeSecretError(err error) error {
	switch {
	case errors.Is(err, secrets.ErrInvalid):
		return database.ErrInvalidResource
	case errors.Is(err, secrets.ErrForbidden):
		return database.ErrUnauthorized
	case errors.Is(err, secrets.ErrNotFound):
		return database.ErrNotFound
	case errors.Is(err, secrets.ErrConflict), errors.Is(err, secrets.ErrRollback), errors.Is(err, secrets.ErrRevoked), errors.Is(err, secrets.ErrExpired):
		return database.ErrConflict
	default:
		return err
	}
}

func wipeDatabaseEdgeMaterial(values ...[]byte) {
	for _, value := range values {
		for index := range value {
			value[index] = 0
		}
	}
}

var _ apiserver.DatabaseEdgeService = (*databaseEdge)(nil)
