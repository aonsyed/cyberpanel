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
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

type databaseEdgeRepository interface {
	ListDatabases(context.Context, site.TenantID, string, uint16) ([]database.Database, string, uint64, error)
	ListDatabaseInstances(context.Context, string, uint16) ([]database.DatabaseInstance, string, uint64, error)
	DatabasePrincipalCount(context.Context, site.TenantID, database.ResourceID) (uint64, error)
	LoadResource(context.Context, database.ResourceKind, database.ResourceID) (database.ResourceEnvelope, error)
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
	coordinator   databaseEdgeCoordinator
	status        databaseEdgeStatus
	management    databaseEdgeSecretManagement
	releaseDigest string
}

func newDatabaseEdge(repository databaseEdgeRepository, coordinator databaseEdgeCoordinator, status databaseEdgeStatus, management databaseEdgeSecretManagement, releaseDigest string) (apiserver.DatabaseEdgeService, error) {
	digest, err := hex.DecodeString(releaseDigest)
	if repository == nil || coordinator == nil || status == nil || management == nil || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != releaseDigest {
		return nil, errors.New("database edge requires repository, coordinator, secret broker, and exact executor digest")
	}
	return &databaseEdge{repository: repository, coordinator: coordinator, status: status, management: management, releaseDigest: releaseDigest}, nil
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
