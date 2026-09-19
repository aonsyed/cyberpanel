//go:build linux

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	hostingservice "github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	webcatalog "github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/containerproxy"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/enterprise"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
)

const migrationContainerGrantLifetime = 365 * 24 * time.Hour

type migrationContainerTarget struct {
	host         *migrationHostTarget
	applications *containers.ApplicationService
	catalog      *webcatalog.SQLCatalog
	routes       containerproxy.TenantWorkloadRouteBroker
}

type migrationContainerOperation struct {
	plan      containers.MigrationVolumePlan
	meta      containers.CommandMeta
	source    migration.ContainerApplication
	volume    migration.ContainerVolume
	migration migration.Migration
	approved  migration.Plan
	scope     migration.RuntimeScope
}

func newMigrationContainerTarget(host *migrationHostTarget, applications *containers.ApplicationService, catalog *webcatalog.SQLCatalog, activator containerproxy.VerifiedActivator) (*migrationContainerTarget, error) {
	if host == nil || applications == nil || catalog == nil || activator == nil {
		return nil, migration.ErrInvalid
	}
	target := &migrationContainerTarget{host: host, applications: applications, catalog: catalog}
	routes, err := containerproxy.NewTenantRouteAuthority(host.db, catalog, activator, target, target, ols.New(), enterprise.New())
	if err != nil {
		return nil, err
	}
	target.routes = routes
	return target, nil
}

func (target *migrationContainerTarget) operation(ctx context.Context, intent migration.ImportIntent, requireCurrentGeneration bool) (migrationContainerOperation, error) {
	var source migration.ContainerApplication
	if target == nil || target.host == nil || target.applications == nil || intent.Kind != migration.ImportContainer || intent.Disposition != migration.DispositionCreate || migration.StrictCanonicalPayload(intent.Payload, &source) != nil || source.SourceID != intent.SourceID || source.TargetID != "" && source.TargetID != intent.TargetID || source.SiteID == "" || len(source.Descriptor) != 0 || len(source.VolumeData) != 0 || len(source.Volumes) != 1 || len(source.SecretBindings) != 0 || len(source.SecretIDs) != 0 || len(intent.SecretIDs) != 0 {
		return migrationContainerOperation{}, migration.ErrBlocked
	}
	value, err := target.host.repository.Migration(ctx, intent.MigrationID)
	if err != nil {
		return migrationContainerOperation{}, err
	}
	plan, err := target.host.repository.Plan(ctx, value.PlanDigest)
	if err != nil {
		return migrationContainerOperation{}, err
	}
	if plan.ApprovedAt == nil || plan.ApprovalDigest == "" || plan.MigrationID != value.ID || plan.ManifestRoot != value.ManifestRoot || requireCurrentGeneration && value.SourceGeneration != intent.SourceGeneration || value.Fence != intent.Fence {
		return migrationContainerOperation{}, migration.ErrBlocked
	}
	scope, err := target.host.scopes.LoadByMigration(ctx, intent.MigrationID)
	if err != nil {
		return migrationContainerOperation{}, err
	}
	tenantID, err := containers.NewID(scope.TenantID)
	if err != nil {
		return migrationContainerOperation{}, migration.ErrBlocked
	}
	applicationID, err := containers.NewID(intent.TargetID.String())
	if err != nil {
		return migrationContainerOperation{}, migration.ErrBlocked
	}
	migrationID, err := containers.NewID(intent.MigrationID.String())
	if err != nil {
		return migrationContainerOperation{}, migration.ErrBlocked
	}
	recipeID, err := containers.NewID(source.RecipeID)
	if err != nil {
		return migrationContainerOperation{}, migration.ErrBlocked
	}
	var siteID containers.ID
	siteMappings := 0
	containerMappings := 0
	for _, mapping := range plan.Mappings {
		if mapping.SourceKind == string(migration.ImportSite) && mapping.SourceID == source.SiteID && mapping.Disposition == migration.DispositionCreate {
			siteMappings++
			siteID, err = containers.NewID(mapping.TargetID.String())
		}
		if mapping.SourceKind == string(migration.ImportContainer) && mapping.SourceID == intent.SourceID && mapping.TargetID == intent.TargetID && mapping.Disposition == migration.DispositionCreate {
			containerMappings++
		}
	}
	if err != nil || siteMappings != 1 || containerMappings != 1 || !siteID.Valid() {
		return migrationContainerOperation{}, migration.ErrBlocked
	}
	expiresAt := plan.ApprovedAt.UTC().Add(migrationContainerGrantLifetime)
	if !time.Now().UTC().Before(expiresAt) {
		return migrationContainerOperation{}, migration.ErrBlocked
	}
	planningGrantDigest := migrationHostDigest(struct {
		Domain, Approval, Effect string
		Migration, Application   migration.ID
		SourceGeneration, Fence  uint64
	}{"container-migration-grant-v1", plan.ApprovalDigest, intent.EffectID, intent.MigrationID, intent.TargetID, intent.SourceGeneration, intent.Fence})
	meta := containers.CommandMeta{
		CommandID: "migration-container-plan-" + intent.EffectID,
		Grant: containers.Grant{
			TenantID:   tenantID,
			ResourceID: applicationID,
			Operation:  "application.migrate",
			AuthzEpoch: intent.SourceGeneration,
			ExpiresAt:  expiresAt,
			Digest:     planningGrantDigest,
		},
		Fence: containers.FenceToken(intent.Fence),
	}
	volume := source.Volumes[0]
	pieces := make([]containers.MigrationVolumePiece, len(volume.Chunks))
	for index, descriptor := range volume.Chunks {
		pieces[index] = containers.MigrationVolumePiece{Digest: descriptor.Digest, Bytes: descriptor.Size}
	}
	containerPlan, err := target.applications.PlanMigration(ctx, containers.DeployApplicationCommand{
		Meta:           meta,
		ApplicationID:  applicationID,
		SiteID:         siteID,
		RecipeID:       recipeID,
		RecipeVersion:  source.RecipeVersion,
		SecretBindings: map[string]string{},
	}, migrationID, intent.SourceGeneration, volume.SourceName, volume.RecipeVolume, pieces, volume.Size, volume.Digest)
	if err != nil {
		return migrationContainerOperation{}, migrationContainerError(err)
	}
	// The canonical intent authorizes planning, but it is not a privileged
	// broker command identity. Bind all effects to target-resolved recipe and
	// volume digests through the plan's derived effect identity.
	brokerEffect := containerPlan.EffectID()
	meta.CommandID = containerPlan.CommandID()
	meta.Grant.Digest = migrationHostDigest(struct {
		Domain, Approval, BrokerEffect string
		Migration, Application         migration.ID
		SourceGeneration, Fence        uint64
	}{"container-migration-broker-grant-v1", plan.ApprovalDigest, string(brokerEffect), intent.MigrationID, intent.TargetID, intent.SourceGeneration, intent.Fence})
	return migrationContainerOperation{plan: containerPlan, meta: meta, source: source, volume: volume, migration: value, approved: plan, scope: scope}, nil
}

func (target *migrationContainerTarget) Apply(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	operation, err := target.operation(ctx, intent, true)
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	// Validate all staged source pieces before allocating any target resource.
	for _, descriptor := range operation.volume.Chunks {
		if err = target.host.chunks.Verify(ctx, descriptor); err != nil {
			return migrationHostFailure(intent, err)
		}
	}
	if _, err = target.applications.AllocateMigration(ctx, operation.meta, operation.plan); err != nil {
		return migrationHostFailure(intent, migrationContainerError(err))
	}
	receipt, err := target.applications.IngressMigrationVolume(ctx, operation.meta, operation.plan, "begin", 0, nil)
	if err != nil {
		return migrationHostFailure(intent, migrationContainerError(err))
	}
	if receipt.State == "receiving" {
		receipt, err = target.transfer(ctx, operation, receipt)
		if err != nil {
			return migrationHostFailure(intent, err)
		}
		receipt, err = target.applications.IngressMigrationVolume(ctx, operation.meta, operation.plan, "seal", 0, nil)
		if err != nil {
			return migrationHostFailure(intent, migrationContainerError(err))
		}
	}
	// Re-run the idempotent stage transition even when the broker already has a
	// staged object. That closes a crash window between broker creation and the
	// durable application-state completion.
	if receipt.State == "sealed" || receipt.State == "staged" {
		receipt, err = target.applications.StageMigration(ctx, operation.meta, operation.plan)
		if err != nil {
			return migrationHostFailure(intent, migrationContainerError(err))
		}
	}
	if receipt.State == "staged" {
		receipt, err = target.applications.IngressMigrationVolume(ctx, operation.meta, operation.plan, "observe", 0, nil)
		if err != nil {
			return migrationHostFailure(intent, migrationContainerError(err))
		}
	}
	if receipt.State != "staged" || receipt.EvidenceDigest == "" || receipt.Bytes != operation.volume.Size || receipt.Received != operation.volume.Size || receipt.RuntimeObjectID == "" {
		return migrationHostFailure(intent, migration.ErrAmbiguous)
	}
	return migrationHostEffect(intent, receipt.EvidenceDigest, 1, receipt.Bytes, receipt.Files), nil
}

func (target *migrationContainerTarget) transfer(ctx context.Context, operation migrationContainerOperation, receipt containers.MigrationContainerReceipt) (containers.MigrationContainerReceipt, error) {
	written := uint64(0)
	for _, descriptor := range operation.volume.Chunks {
		pieceEnd := written + descriptor.Size
		if receipt.Received >= pieceEnd {
			written = pieceEnd
			continue
		}
		localOffset := uint64(0)
		if receipt.Received > written {
			localOffset = receipt.Received - written
		}
		for localOffset < descriptor.Size {
			length := uint64(containers.MigrationVolumeMaximumChunk)
			if length > descriptor.Size-localOffset {
				length = descriptor.Size - localOffset
			}
			data, err := target.host.chunks.ReadRange(ctx, descriptor.Digest, localOffset, length)
			if err != nil || uint64(len(data)) != length {
				return receipt, errors.Join(migration.ErrConflict, err)
			}
			offset := written + localOffset
			receipt, err = target.applications.IngressMigrationVolume(ctx, operation.meta, operation.plan, "chunk", offset, data)
			if err != nil {
				return receipt, migrationContainerError(err)
			}
			if receipt.State != "receiving" || receipt.Received != offset+length {
				return receipt, migration.ErrAmbiguous
			}
			localOffset += length
		}
		written = pieceEnd
	}
	if receipt.Received != operation.volume.Size {
		return receipt, migration.ErrAmbiguous
	}
	return receipt, nil
}

func (target *migrationContainerTarget) Observe(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	operation, err := target.operation(ctx, intent, true)
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	receipt, err := target.applications.IngressMigrationVolume(ctx, operation.meta, operation.plan, "observe", 0, nil)
	if err != nil || receipt.State != "staged" || receipt.EvidenceDigest == "" || receipt.RuntimeObjectID == "" {
		return migrationHostFailure(intent, errors.Join(migration.ErrAmbiguous, migrationContainerError(err)))
	}
	return migrationHostEffect(intent, receipt.EvidenceDigest, 1, receipt.Bytes, receipt.Files), nil
}

const (
	containerActivationPrepared             = "prepared"
	containerActivationRouteReserved        = "route-reserved"
	containerActivationWorkloadPromoted     = "workload-promoted"
	containerActivationWorkloadRunning      = "workload-running"
	containerActivationRouteActivating      = "route-activating"
	containerActivationRouteActive          = "route-active"
	containerActivationPublicationCommitted = "publication-committed"
	containerActivationPublished            = "published"
	containerActivationCanceled             = "canceled"
)

type migrationContainerActivation struct {
	MigrationID         migration.ID
	PlanDigest          string
	ApprovalDigest      string
	SourceGeneration    uint64
	Fence               uint64
	Intent              migration.ImportIntent
	VolumePlan          containers.MigrationVolumePlan
	RouteSpec           containerproxy.TenantWorkloadRouteSpec
	RouteReference      containerproxy.TenantWorkloadRouteReference
	ListenerPort        uint16
	State               string
	WorkloadReceipt     containers.MigrationContainerReceipt
	RouteReceipt        containerproxy.TenantWorkloadRouteReceipt
	PublicationEvidence string
	UpdatedAt           time.Time
}

func validContainerActivationState(state string) bool {
	switch state {
	case containerActivationPrepared, containerActivationRouteReserved, containerActivationWorkloadPromoted, containerActivationWorkloadRunning, containerActivationRouteActivating, containerActivationRouteActive, containerActivationPublicationCommitted, containerActivationPublished, containerActivationCanceled:
		return true
	default:
		return false
	}
}

func (target *migrationContainerTarget) validateActivationJournal(journal migrationContainerActivation) error {
	if target == nil || target.host == nil || target.routes == nil || !journal.MigrationID.Valid() || len(journal.PlanDigest) != 64 || len(journal.ApprovalDigest) != 64 || journal.SourceGeneration == 0 || journal.Fence == 0 || journal.Intent.MigrationID != journal.MigrationID || journal.Intent.SourceGeneration != journal.SourceGeneration || journal.Intent.Fence != journal.Fence || journal.Intent.Kind != migration.ImportContainer || journal.VolumePlan.Validate() != nil || journal.VolumePlan.MigrationID.String() != journal.MigrationID.String() || journal.VolumePlan.SourceGeneration != journal.SourceGeneration || journal.ListenerPort == 0 || !validContainerActivationState(journal.State) || journal.UpdatedAt.IsZero() {
		return migration.ErrConflict
	}
	reference, err := containerproxy.TenantWorkloadRouteReferenceForSpec(journal.RouteSpec)
	if err != nil || reference != journal.RouteReference || journal.RouteSpec.TenantID != journal.VolumePlan.TenantID || journal.RouteSpec.SiteID != journal.VolumePlan.SiteID || journal.RouteSpec.ListenerRef != webengine.ResourceRef("listener/http") || journal.RouteSpec.Generation != journal.SourceGeneration || journal.RouteSpec.WorkloadID != journal.VolumePlan.WorkloadID || journal.RouteSpec.RecipeDigest != journal.VolumePlan.Recipe.Digest || journal.RouteSpec.ImageDigest != journal.VolumePlan.WorkloadSpec().Image.Digest || journal.RouteSpec.TargetEndpoint != netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), containers.LoopbackExposurePort(journal.VolumePlan.WorkloadID, journal.VolumePlan.Recipe.Workloads[0].RoutePortName)) {
		return migration.ErrConflict
	}
	return nil
}

func (target *migrationContainerTarget) loadActivation(ctx context.Context, migrationID migration.ID) (migrationContainerActivation, error) {
	var journal migrationContainerActivation
	var reservationID, authorityDigest, state string
	var raw []byte
	err := target.host.db.QueryRowContext(ctx, `SELECT reservation_id,authority_digest,state,journal_json FROM panel_migration_container_activations WHERE migration_id=?`, migrationID.String()).Scan(&reservationID, &authorityDigest, &state, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return journal, migration.ErrNotFound
	}
	if err != nil || json.Unmarshal(raw, &journal) != nil || journal.State != state || journal.RouteReference.ReservationID != reservationID || journal.RouteSpec.ActivationAuthorityDigest != authorityDigest || target.validateActivationJournal(journal) != nil {
		return migrationContainerActivation{}, errors.Join(migration.ErrConflict, err)
	}
	return journal, nil
}

func (target *migrationContainerTarget) loadActivationByAuthority(ctx context.Context, authorityDigest string) (migrationContainerActivation, error) {
	var migrationID string
	if err := target.host.db.QueryRowContext(ctx, `SELECT migration_id FROM panel_migration_container_activations WHERE authority_digest=?`, authorityDigest).Scan(&migrationID); err != nil {
		return migrationContainerActivation{}, err
	}
	id, err := migration.NewID(migrationID)
	if err != nil {
		return migrationContainerActivation{}, migration.ErrConflict
	}
	return target.loadActivation(ctx, id)
}

func (target *migrationContainerTarget) loadActivationByReservation(ctx context.Context, reservationID string) (migrationContainerActivation, error) {
	var migrationID string
	if err := target.host.db.QueryRowContext(ctx, `SELECT migration_id FROM panel_migration_container_activations WHERE reservation_id=?`, reservationID).Scan(&migrationID); err != nil {
		return migrationContainerActivation{}, err
	}
	id, err := migration.NewID(migrationID)
	if err != nil {
		return migrationContainerActivation{}, migration.ErrConflict
	}
	return target.loadActivation(ctx, id)
}

func (target *migrationContainerTarget) transitionActivation(ctx context.Context, current *migrationContainerActivation, next string) error {
	if current == nil || !validContainerActivationState(next) {
		return migration.ErrInvalid
	}
	prior := current.State
	current.State = next
	current.UpdatedAt = time.Now().UTC()
	if err := target.validateActivationJournal(*current); err != nil {
		current.State = prior
		return err
	}
	raw, err := json.Marshal(current)
	if err != nil {
		current.State = prior
		return err
	}
	result, err := target.host.db.ExecContext(ctx, `UPDATE panel_migration_container_activations SET state=?,journal_json=?,updated_at=? WHERE migration_id=? AND reservation_id=? AND authority_digest=? AND state=?`, next, raw, current.UpdatedAt, current.MigrationID.String(), current.RouteReference.ReservationID, current.RouteSpec.ActivationAuthorityDigest, prior)
	if err != nil {
		current.State = prior
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		current.State = prior
		return errors.Join(migration.ErrConflict, err)
	}
	return nil
}

func containerActivationAuthority(journal migrationContainerActivation, fence migration.SourceFence) string {
	spec := journal.RouteSpec
	spec.ActivationAuthorityDigest = ""
	return migrationHostDigest(struct {
		Domain                         string
		MigrationID                    migration.ID
		PlanDigest, ApprovalDigest     string
		SourceGeneration, Fence        uint64
		SourceFenceDigest              string
		IntentDigest, VolumePlanDigest string
		RouteSpec                      containerproxy.TenantWorkloadRouteSpec
	}{"container-migration-activation-authority-v1", journal.MigrationID, journal.PlanDigest, journal.ApprovalDigest, journal.SourceGeneration, journal.Fence, fence.Digest, migrationHostDigest(journal.Intent), migrationHostDigest(journal.VolumePlan), spec})
}

func (target *migrationContainerTarget) currentSiteHandoff(ctx context.Context, operation migrationContainerOperation, hostname string) (webcatalog.ProvisioningSiteHandoff, error) {
	tenantID, err := site.NewTenantID(operation.scope.TenantID)
	if err != nil {
		return webcatalog.ProvisioningSiteHandoff{}, err
	}
	siteID, err := site.NewSiteID(operation.plan.SiteID.String())
	if err != nil {
		return webcatalog.ProvisioningSiteHandoff{}, err
	}
	aggregate, err := target.host.sites.Load(ctx, tenantID, siteID)
	if err != nil || aggregate.TenantID() != tenantID || aggregate.ID() != siteID || aggregate.Lifecycle() != site.LifecycleProvisioning {
		return webcatalog.ProvisioningSiteHandoff{}, errors.Join(migration.ErrBlocked, err)
	}
	bindings := aggregate.Bindings()
	if len(bindings) != 1 || bindings[0].Kind != site.BindingPrimary || bindings[0].Hostname.String() != hostname {
		return webcatalog.ProvisioningSiteHandoff{}, migration.ErrBlocked
	}
	return target.catalog.ProvisioningSiteHandoff(ctx, hostingservice.CommandScope{TenantID: tenantID, SiteID: siteID}, hostname, webengine.ResourceRef("listener/http"))
}

func (target *migrationContainerTarget) prepareActivation(ctx context.Context, intent migration.ImportIntent) (migrationContainerActivation, migrationContainerOperation, error) {
	operation, err := target.operation(ctx, intent, true)
	if err != nil {
		return migrationContainerActivation{}, operation, err
	}
	if operation.migration.Phase != migration.PhaseCutoverCommitting {
		return migrationContainerActivation{}, operation, migration.ErrBlocked
	}
	if existing, loadErr := target.loadActivation(ctx, intent.MigrationID); loadErr == nil {
		if migrationHostDigest(existing.Intent) != migrationHostDigest(intent) || migrationHostDigest(existing.VolumePlan) != migrationHostDigest(operation.plan) || existing.PlanDigest != operation.approved.DryRunDigest || existing.ApprovalDigest != operation.approved.ApprovalDigest {
			return migrationContainerActivation{}, operation, migration.ErrConflict
		}
		return existing, operation, nil
	} else if !errors.Is(loadErr, migration.ErrNotFound) {
		return migrationContainerActivation{}, operation, loadErr
	}
	tenantID, err := site.NewTenantID(operation.scope.TenantID)
	if err != nil {
		return migrationContainerActivation{}, operation, err
	}
	siteID, err := site.NewSiteID(operation.plan.SiteID.String())
	if err != nil {
		return migrationContainerActivation{}, operation, err
	}
	aggregate, err := target.host.sites.Load(ctx, tenantID, siteID)
	if err != nil || aggregate.TenantID() != tenantID || aggregate.ID() != siteID || aggregate.Lifecycle() != site.LifecycleProvisioning {
		return migrationContainerActivation{}, operation, errors.Join(migration.ErrBlocked, err)
	}
	bindings := aggregate.Bindings()
	if len(bindings) != 1 || bindings[0].Kind != site.BindingPrimary {
		return migrationContainerActivation{}, operation, migration.ErrBlocked
	}
	hostname := bindings[0].Hostname.String()
	handoff, err := target.currentSiteHandoff(ctx, operation, hostname)
	if err != nil {
		return migrationContainerActivation{}, operation, err
	}
	endpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), containers.LoopbackExposurePort(operation.plan.WorkloadID, operation.plan.Recipe.Workloads[0].RoutePortName))
	domainDigest := migrationHostDigest(struct{ Tenant, Site, Hostname string }{operation.plan.TenantID.String(), operation.plan.SiteID.String(), hostname})
	domainID, err := containers.NewID("domain_" + domainDigest[:32])
	if err != nil {
		return migrationContainerActivation{}, operation, err
	}
	journal := migrationContainerActivation{
		MigrationID: operation.migration.ID, PlanDigest: operation.approved.DryRunDigest, ApprovalDigest: operation.approved.ApprovalDigest,
		SourceGeneration: operation.migration.SourceGeneration, Fence: operation.migration.Fence, Intent: intent, VolumePlan: operation.plan,
		RouteSpec: containerproxy.TenantWorkloadRouteSpec{
			TenantID: operation.plan.TenantID, SiteID: operation.plan.SiteID, DomainID: domainID, Hostname: hostname,
			ListenerRef: webengine.ResourceRef("listener/http"), WorkloadID: operation.plan.WorkloadID, RecipeDigest: operation.plan.Recipe.Digest,
			ImageDigest: operation.plan.WorkloadSpec().Image.Digest, Generation: operation.migration.SourceGeneration, TargetEndpoint: endpoint,
			SiteHandoff: containerproxy.TenantWorkloadSiteHandoff{ProjectionGeneration: handoff.ProjectionGeneration, ProjectionDigest: handoff.ProjectionDigest, ConfigurationGeneration: handoff.ConfigurationGeneration, ConfigurationDigest: handoff.ConfigurationDigest},
		},
		ListenerPort: handoff.ListenerPort, State: containerActivationPrepared, UpdatedAt: time.Now().UTC(),
	}
	fence, err := target.host.currentSourceFence(ctx, operation.migration)
	if err != nil {
		return migrationContainerActivation{}, operation, err
	}
	journal.RouteSpec.ActivationAuthorityDigest = containerActivationAuthority(journal, fence)
	journal.RouteReference, err = containerproxy.TenantWorkloadRouteReferenceForSpec(journal.RouteSpec)
	if err != nil || target.validateActivationJournal(journal) != nil {
		return migrationContainerActivation{}, operation, errors.Join(migration.ErrConflict, err)
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return migrationContainerActivation{}, operation, err
	}
	_, err = target.host.db.ExecContext(ctx, `INSERT INTO panel_migration_container_activations(migration_id,reservation_id,authority_digest,state,journal_json,updated_at) VALUES(?,?,?,?,?,?)`, journal.MigrationID.String(), journal.RouteReference.ReservationID, journal.RouteSpec.ActivationAuthorityDigest, journal.State, raw, journal.UpdatedAt)
	if err != nil {
		existing, loadErr := target.loadActivation(ctx, intent.MigrationID)
		if loadErr == nil && migrationHostDigest(existing.Intent) == migrationHostDigest(intent) && migrationHostDigest(existing.VolumePlan) == migrationHostDigest(operation.plan) {
			return existing, operation, nil
		}
		return migrationContainerActivation{}, operation, errors.Join(migration.ErrConflict, err, loadErr)
	}
	return journal, operation, nil
}

func (target *migrationContainerTarget) validateCurrentFenceAuthority(ctx context.Context, journal migrationContainerActivation) (migrationContainerOperation, error) {
	operation, err := target.operation(ctx, journal.Intent, true)
	if err != nil {
		return operation, err
	}
	if operation.migration.ID != journal.MigrationID || operation.migration.SourceGeneration != journal.SourceGeneration || operation.migration.Fence != journal.Fence || operation.approved.DryRunDigest != journal.PlanDigest || operation.approved.ApprovalDigest != journal.ApprovalDigest || migrationHostDigest(operation.plan) != migrationHostDigest(journal.VolumePlan) {
		return operation, migration.ErrConflict
	}
	fence, err := target.host.currentSourceFence(ctx, operation.migration)
	if err != nil {
		return operation, err
	}
	if containerActivationAuthority(journal, fence) != journal.RouteSpec.ActivationAuthorityDigest {
		return operation, migration.ErrConflict
	}
	return operation, nil
}

func (target *migrationContainerTarget) validateCurrentActivation(ctx context.Context, journal migrationContainerActivation) (migrationContainerOperation, error) {
	operation, err := target.validateCurrentFenceAuthority(ctx, journal)
	if err != nil {
		return operation, err
	}
	handoff, err := target.currentSiteHandoff(ctx, operation, journal.RouteSpec.Hostname)
	if err != nil {
		return operation, err
	}
	wanted := journal.RouteSpec.SiteHandoff
	if wanted != (containerproxy.TenantWorkloadSiteHandoff{ProjectionGeneration: handoff.ProjectionGeneration, ProjectionDigest: handoff.ProjectionDigest, ConfigurationGeneration: handoff.ConfigurationGeneration, ConfigurationDigest: handoff.ConfigurationDigest}) || handoff.ListenerPort != journal.ListenerPort {
		return operation, migration.ErrConflict
	}
	return operation, nil
}

// VerifyCurrentTenantWorkloadRouteAuthority is called by the protected route
// broker immediately before each route mutation. It re-reads both the source
// fence and the exact same-owner provisioning-site reservation.
func (target *migrationContainerTarget) VerifyCurrentTenantWorkloadRouteAuthority(ctx context.Context, reservation containerproxy.TenantWorkloadRouteReservation) error {
	journal, err := target.loadActivationByAuthority(ctx, reservation.Spec.ActivationAuthorityDigest)
	if err != nil || reservation.Spec != journal.RouteSpec || reservation.ID != journal.RouteReference.ReservationID || reservation.Digest != journal.RouteReference.ReservationDigest || reservation.Spec.Generation != journal.RouteReference.ExpectedGeneration {
		return errors.Join(containerproxy.ErrTenantRouteConflict, err)
	}
	if journal.State == containerActivationCanceled || journal.State == containerActivationPublished {
		return containerproxy.ErrTenantRouteClosed
	}
	if _, err = target.validateCurrentFenceAuthority(ctx, journal); err != nil {
		return errors.Join(containerproxy.ErrTenantRouteClosed, err)
	}
	if _, err = target.validateCurrentActivation(ctx, journal); err == nil {
		return nil
	}
	// Finalization atomically replaces the provisioning site input with this
	// exact route. Once that handoff is recorded, the deleted site input cannot
	// be re-read; the exact catalog route and applied generation are its proof.
	state, routeErr := target.catalog.ProxyRouteState(ctx, reservation.RouteRef)
	hostname, hostnameErr := webengine.ParseHostname(reservation.Spec.Hostname)
	wanted := composer.ProxyRouteInput{Ref: reservation.RouteRef, Hostname: hostname, ListenerRef: reservation.Spec.ListenerRef, UpstreamPort: reservation.Spec.TargetEndpoint.Port(), Generation: reservation.Spec.Generation}
	if routeErr != nil || hostnameErr != nil || state.Route != wanted || reservation.ActivatedAt == nil || reservation.ActivationGeneration == 0 || state.SnapshotGeneration != reservation.ActivationGeneration || state.AppliedDigest != reservation.CandidateDigest {
		return errors.Join(containerproxy.ErrTenantRouteClosed, err, routeErr, hostnameErr)
	}
	return nil
}

type migrationContainerHTTPObservation struct {
	Available  bool
	StatusCode int
	BodyDigest string
}

func probeMigrationContainerHTTP(ctx context.Context, address, hostname, path string, required bool) (migrationContainerHTTPObservation, error) {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(call context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(call, "tcp", address)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+hostname+path, nil)
	if err != nil {
		return migrationContainerHTTPObservation{}, err
	}
	request.Host = hostname
	response, err := client.Do(request)
	if err != nil {
		if !required && ctx.Err() == nil {
			return migrationContainerHTTPObservation{}, nil
		}
		return migrationContainerHTTPObservation{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return migrationContainerHTTPObservation{}, errors.Join(migration.ErrBlocked, err)
	}
	return migrationContainerHTTPObservation{Available: true, StatusCode: response.StatusCode, BodyDigest: migrationHostDigest(body)}, nil
}

// ObserveTenantWorkloadRoute proves either the exact non-serving provisioning
// handoff (503) or the exact health response through both the private endpoint
// and the tenant hostname on the fixed listener. Any other live response is an
// occupied, mismatched binding and is never replaced.
func (target *migrationContainerTarget) ObserveTenantWorkloadRoute(ctx context.Context, expectation containerproxy.TenantWorkloadRouteExpectation) (containerproxy.TenantWorkloadRouteObservation, error) {
	journal, err := target.loadActivationByReservation(ctx, expectation.ReservationID)
	if err != nil {
		return containerproxy.TenantWorkloadRouteObservation{}, err
	}
	if expectation.ReservationDigest != journal.RouteReference.ReservationDigest || expectation.TenantID != journal.RouteSpec.TenantID || expectation.SiteID != journal.RouteSpec.SiteID || expectation.DomainID != journal.RouteSpec.DomainID || expectation.Hostname != journal.RouteSpec.Hostname || expectation.ListenerRef != journal.RouteSpec.ListenerRef || expectation.WorkloadID != journal.RouteSpec.WorkloadID || expectation.TargetEndpoint != journal.RouteSpec.TargetEndpoint || (expectation.ConfigurationGeneration == 0) != (expectation.ConfigurationDigest == "") {
		return containerproxy.TenantWorkloadRouteObservation{}, containerproxy.ErrTenantRouteConflict
	}
	runningExpected := journal.State == containerActivationWorkloadRunning || journal.State == containerActivationRouteActivating || journal.State == containerActivationRouteActive || journal.State == containerActivationPublicationCommitted || journal.State == containerActivationPublished
	path := journal.VolumePlan.WorkloadSpec().Health.Path
	direct, err := probeMigrationContainerHTTP(ctx, journal.RouteSpec.TargetEndpoint.String(), journal.RouteSpec.Hostname, path, runningExpected)
	if err != nil {
		return containerproxy.TenantWorkloadRouteObservation{}, err
	}
	publicAddress := net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(journal.ListenerPort), 10))
	public, err := probeMigrationContainerHTTP(ctx, publicAddress, journal.RouteSpec.Hostname, path, true)
	if err != nil {
		return containerproxy.TenantWorkloadRouteObservation{}, err
	}
	occupied, bound := false, false
	if direct.Available {
		if direct.StatusCode < 200 || direct.StatusCode >= 400 {
			return containerproxy.TenantWorkloadRouteObservation{}, containerproxy.ErrTenantRouteConflict
		}
		if public.StatusCode == direct.StatusCode && public.BodyDigest == direct.BodyDigest {
			occupied, bound = true, true
		} else if public.StatusCode != http.StatusServiceUnavailable {
			occupied = true
		}
	} else if public.StatusCode != http.StatusServiceUnavailable {
		occupied = true
	}
	observation := containerproxy.TenantWorkloadRouteObservation{TenantWorkloadRouteExpectation: expectation, Occupied: occupied, Bound: bound, ObservedAt: time.Now().UTC()}
	observation.EvidenceDigest = migrationHostDigest(struct {
		Domain      string
		Expectation containerproxy.TenantWorkloadRouteExpectation
		Direct      migrationContainerHTTPObservation
		Public      migrationContainerHTTPObservation
		Occupied    bool
		Bound       bool
	}{"container-migration-route-observation-v1", expectation, direct, public, occupied, bound})
	return observation, nil
}

func exactContainerRouteReservation(journal migrationContainerActivation, reservation containerproxy.TenantWorkloadRouteReservation) bool {
	return reservation.ID == journal.RouteReference.ReservationID && reservation.Digest == journal.RouteReference.ReservationDigest && reservation.Spec == journal.RouteSpec && reservation.Spec.Generation == journal.RouteReference.ExpectedGeneration && reservation.Receipt.ReservationID == reservation.ID && reservation.Receipt.ReservationDigest == reservation.Digest && reservation.Receipt.ActivationAuthorityDigest == journal.RouteSpec.ActivationAuthorityDigest && reservation.Receipt.EvidenceDigest != ""
}

func (target *migrationContainerTarget) cancelBeforePublication(ctx context.Context, journal *migrationContainerActivation, operation migrationContainerOperation) error {
	if journal == nil || journal.State == containerActivationRouteActivating || journal.State == containerActivationRouteActive || journal.State == containerActivationPublicationCommitted || journal.State == containerActivationPublished {
		return migration.ErrWriteFrontier
	}
	absenceDigest := ""
	reservation, err := target.routes.ObserveTenantWorkloadRoute(ctx, journal.RouteReference)
	if err == nil {
		if !exactContainerRouteReservation(*journal, reservation) || reservation.State != containerproxy.TenantWorkloadRouteReserved || reservation.Receipt.Bound {
			return migration.ErrWriteFrontier
		}
		reservation, err = target.routes.DiscardTenantWorkloadRoute(ctx, journal.RouteReference)
		if err != nil || !exactContainerRouteReservation(*journal, reservation) || reservation.State != containerproxy.TenantWorkloadRouteDiscarded || reservation.Receipt.Bound {
			return errors.Join(migration.ErrWriteFrontier, err)
		}
		absenceDigest = reservation.Receipt.EvidenceDigest
	} else if errors.Is(err, containerproxy.ErrTenantRouteNotFound) || errors.Is(err, sql.ErrNoRows) {
		expectation := containerproxy.TenantWorkloadRouteExpectation{ReservationID: journal.RouteReference.ReservationID, ReservationDigest: journal.RouteReference.ReservationDigest, TenantID: journal.RouteSpec.TenantID, SiteID: journal.RouteSpec.SiteID, DomainID: journal.RouteSpec.DomainID, Hostname: journal.RouteSpec.Hostname, ListenerRef: journal.RouteSpec.ListenerRef, WorkloadID: journal.RouteSpec.WorkloadID, TargetEndpoint: journal.RouteSpec.TargetEndpoint}
		observation, observeErr := target.ObserveTenantWorkloadRoute(ctx, expectation)
		if observeErr != nil || observation.Occupied || observation.Bound {
			return errors.Join(migration.ErrWriteFrontier, observeErr)
		}
		absenceDigest = observation.EvidenceDigest
	} else {
		return errors.Join(migration.ErrAmbiguous, err)
	}
	receipt, err := target.applications.CancelMigrationActivation(ctx, operation.meta, operation.plan, journal.RouteSpec.ActivationAuthorityDigest, absenceDigest)
	if err != nil || receipt.State != "discarded" || receipt.PublicationAbsenceDigest != absenceDigest {
		return errors.Join(migration.ErrAmbiguous, migrationContainerError(err))
	}
	journal.WorkloadReceipt = receipt
	journal.PublicationEvidence = absenceDigest
	return target.transitionActivation(ctx, journal, containerActivationCanceled)
}

func (target *migrationContainerTarget) failActivation(ctx context.Context, journal *migrationContainerActivation, operation migrationContainerOperation, cause error) (string, error) {
	if journal.State == containerActivationRouteActivating || journal.State == containerActivationRouteActive || journal.State == containerActivationPublicationCommitted || journal.State == containerActivationPublished {
		return "", errors.Join(migration.ErrWriteFrontier, migration.ErrAmbiguous, cause)
	}
	compensationErr := target.cancelBeforePublication(context.WithoutCancel(ctx), journal, operation)
	return "", errors.Join(cause, compensationErr)
}

// Activate advances the one-workload journal. Every external step is both
// idempotent and recorded separately, so a restart repeats only an exact
// reservation/promotion/start/activation operation. route-activating is the
// conservative write frontier because the proxy apply may already be live.
func (target *migrationContainerTarget) Activate(ctx context.Context, intent migration.ImportIntent) (string, error) {
	journal, operation, err := target.prepareActivation(ctx, intent)
	if err != nil {
		return "", err
	}
	for {
		switch journal.State {
		case containerActivationPrepared:
			if _, err = target.validateCurrentActivation(ctx, journal); err != nil {
				return target.failActivation(ctx, &journal, operation, err)
			}
			reservation, reserveErr := target.routes.ReserveTenantWorkloadRoute(ctx, journal.RouteSpec)
			if reserveErr != nil || !exactContainerRouteReservation(journal, reservation) || reservation.State != containerproxy.TenantWorkloadRouteReserved || reservation.Receipt.Bound {
				return target.failActivation(ctx, &journal, operation, errors.Join(migration.ErrAmbiguous, reserveErr))
			}
			reservation, reserveErr = target.routes.ObserveTenantWorkloadRoute(ctx, journal.RouteReference)
			if reserveErr != nil || !exactContainerRouteReservation(journal, reservation) || reservation.State != containerproxy.TenantWorkloadRouteReserved || reservation.Receipt.Bound {
				return target.failActivation(ctx, &journal, operation, errors.Join(migration.ErrAmbiguous, reserveErr))
			}
			journal.RouteReceipt = reservation.Receipt
			if err = target.transitionActivation(ctx, &journal, containerActivationRouteReserved); err != nil {
				return target.failActivation(ctx, &journal, operation, err)
			}
		case containerActivationRouteReserved:
			if _, err = target.validateCurrentActivation(ctx, journal); err != nil {
				return target.failActivation(ctx, &journal, operation, err)
			}
			receipt, activateErr := target.applications.ActivateMigration(ctx, operation.meta, operation.plan, "promote", journal.RouteSpec.ActivationAuthorityDigest)
			if activateErr != nil || receipt.State != "promoted" && receipt.State != "running" || receipt.ActivationAuthorityDigest != journal.RouteSpec.ActivationAuthorityDigest {
				return target.failActivation(ctx, &journal, operation, errors.Join(migration.ErrAmbiguous, migrationContainerError(activateErr)))
			}
			journal.WorkloadReceipt = receipt
			next := containerActivationWorkloadPromoted
			if receipt.State == "running" {
				next = containerActivationWorkloadRunning
			}
			if err = target.transitionActivation(ctx, &journal, next); err != nil {
				return target.failActivation(ctx, &journal, operation, err)
			}
		case containerActivationWorkloadPromoted:
			if _, err = target.validateCurrentActivation(ctx, journal); err != nil {
				return target.failActivation(ctx, &journal, operation, err)
			}
			receipt, activateErr := target.applications.ActivateMigration(ctx, operation.meta, operation.plan, "start", journal.RouteSpec.ActivationAuthorityDigest)
			if activateErr != nil || receipt.State != "running" || receipt.Lifecycle != containers.LifecycleRunning || receipt.Health != containers.HealthHealthy || receipt.BoundAddress != "127.0.0.1" || receipt.BoundPort != journal.RouteSpec.TargetEndpoint.Port() {
				return target.failActivation(ctx, &journal, operation, errors.Join(migration.ErrAmbiguous, migrationContainerError(activateErr)))
			}
			journal.WorkloadReceipt = receipt
			if err = target.transitionActivation(ctx, &journal, containerActivationWorkloadRunning); err != nil {
				return target.failActivation(ctx, &journal, operation, err)
			}
		case containerActivationWorkloadRunning:
			if _, err = target.validateCurrentActivation(ctx, journal); err != nil {
				return target.failActivation(ctx, &journal, operation, err)
			}
			receipt, observeErr := target.applications.ActivateMigration(ctx, operation.meta, operation.plan, "observe-active", journal.RouteSpec.ActivationAuthorityDigest)
			if observeErr != nil || receipt.State != "running" || receipt.EvidenceDigest == "" {
				return target.failActivation(ctx, &journal, operation, errors.Join(migration.ErrAmbiguous, migrationContainerError(observeErr)))
			}
			journal.WorkloadReceipt = receipt
			if err = target.transitionActivation(ctx, &journal, containerActivationRouteActivating); err != nil {
				return "", errors.Join(migration.ErrWriteFrontier, migration.ErrAmbiguous, err)
			}
		case containerActivationRouteActivating:
			if _, err = target.validateCurrentFenceAuthority(ctx, journal); err != nil {
				return "", errors.Join(migration.ErrWriteFrontier, migration.ErrAmbiguous, err)
			}
			reservation, activationErr := target.routes.ActivateTenantWorkloadRoute(ctx, containerproxy.TenantWorkloadRouteActivation{TenantWorkloadRouteReference: journal.RouteReference, ActivationAuthorityDigest: journal.RouteSpec.ActivationAuthorityDigest})
			if activationErr != nil || !exactContainerRouteReservation(journal, reservation) || reservation.State != containerproxy.TenantWorkloadRouteActive || !reservation.Receipt.Bound {
				return "", errors.Join(migration.ErrWriteFrontier, migration.ErrAmbiguous, activationErr)
			}
			journal.RouteReceipt = reservation.Receipt
			if err = target.transitionActivation(ctx, &journal, containerActivationRouteActive); err != nil {
				return "", errors.Join(migration.ErrWriteFrontier, migration.ErrAmbiguous, err)
			}
		case containerActivationRouteActive:
			proof, observeErr := target.observeActiveJournal(ctx, &journal, operation)
			if observeErr != nil {
				return "", errors.Join(migration.ErrWriteFrontier, migration.ErrAmbiguous, observeErr)
			}
			if _, commitErr := target.applications.CommitMigration(ctx, operation.meta, operation.plan, journal.RouteSpec.ActivationAuthorityDigest, proof); commitErr != nil {
				return "", errors.Join(migration.ErrWriteFrontier, migration.ErrAmbiguous, migrationContainerError(commitErr))
			}
			journal.PublicationEvidence = proof
			if err = target.transitionActivation(ctx, &journal, containerActivationPublicationCommitted); err != nil {
				return "", errors.Join(migration.ErrWriteFrontier, migration.ErrAmbiguous, err)
			}
			return proof, nil
		case containerActivationPublicationCommitted, containerActivationPublished:
			return target.observeActiveJournal(ctx, &journal, operation)
		case containerActivationCanceled:
			return "", containerproxy.ErrTenantRouteClosed
		default:
			return "", migration.ErrConflict
		}
	}
}

func (target *migrationContainerTarget) observeActiveJournal(ctx context.Context, journal *migrationContainerActivation, operation migrationContainerOperation) (string, error) {
	if journal == nil || journal.State != containerActivationRouteActive && journal.State != containerActivationPublicationCommitted && journal.State != containerActivationPublished {
		return "", migration.ErrConflict
	}
	workload, err := target.applications.ActivateMigration(ctx, operation.meta, operation.plan, "observe-active", journal.RouteSpec.ActivationAuthorityDigest)
	if err != nil || workload.State != "running" || workload.SpecDigest != migrationHostDigest(operation.plan.WorkloadSpec()) || workload.RecipeDigest != operation.plan.Recipe.Digest || workload.ImageDigest != operation.plan.WorkloadSpec().Image.Digest || workload.BoundAddress != "127.0.0.1" || workload.BoundPort != journal.RouteSpec.TargetEndpoint.Port() || workload.Lifecycle != containers.LifecycleRunning || workload.Health != containers.HealthHealthy {
		return "", errors.Join(migration.ErrAmbiguous, migrationContainerError(err))
	}
	reservation, err := target.routes.ObserveTenantWorkloadRoute(ctx, journal.RouteReference)
	if err != nil || !exactContainerRouteReservation(*journal, reservation) || reservation.State != containerproxy.TenantWorkloadRouteActive || !reservation.Receipt.Bound || reservation.Receipt.TargetEndpoint != journal.RouteSpec.TargetEndpoint || reservation.Receipt.ConfigurationGeneration == 0 || reservation.Receipt.ConfigurationDigest == "" || reservation.Receipt.ObservationDigest == "" {
		return "", errors.Join(migration.ErrAmbiguous, err)
	}
	journal.WorkloadReceipt = workload
	journal.RouteReceipt = reservation.Receipt
	proof := migrationHostDigest(struct {
		Domain                                             string
		Migration                                         migration.ID
		Authority, WorkloadEvidence, RouteSpec             string
		Reservation, Configuration, Observation            string
		ConfigurationGeneration                           uint64
	}{"container-migration-publication-v1", journal.MigrationID, journal.RouteSpec.ActivationAuthorityDigest, workload.EvidenceDigest, migrationHostDigest(journal.RouteSpec), reservation.Digest, reservation.Receipt.ConfigurationDigest, reservation.Receipt.ObservationDigest, reservation.Receipt.ConfigurationGeneration})
	return proof, nil
}

func (target *migrationContainerTarget) ObserveActive(ctx context.Context, intent migration.ImportIntent) (string, error) {
	journal, err := target.loadActivation(ctx, intent.MigrationID)
	if err != nil || migrationHostDigest(journal.Intent) != migrationHostDigest(intent) {
		return "", errors.Join(migration.ErrConflict, err)
	}
	operation, err := target.operation(ctx, intent, true)
	if err != nil || migrationHostDigest(operation.plan) != migrationHostDigest(journal.VolumePlan) {
		return "", errors.Join(migration.ErrConflict, err)
	}
	return target.observeActiveJournal(ctx, &journal, operation)
}

func (target *migrationContainerTarget) finalizePublication(ctx context.Context, tx *sql.Tx, migrationID migration.ID) error {
	if tx == nil {
		return migration.ErrInvalid
	}
	var raw []byte
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state,journal_json FROM panel_migration_container_activations WHERE migration_id=?`, migrationID.String()).Scan(&state, &raw); err != nil {
		return err
	}
	var journal migrationContainerActivation
	if json.Unmarshal(raw, &journal) != nil || state != journal.State || target.validateActivationJournal(journal) != nil {
		return migration.ErrConflict
	}
	if state == containerActivationPublished {
		return nil
	}
	if state != containerActivationPublicationCommitted || journal.PublicationEvidence == "" {
		return migration.ErrWriteFrontier
	}
	journal.State = containerActivationPublished
	journal.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_container_activations SET state=?,journal_json=?,updated_at=? WHERE migration_id=? AND state=? AND reservation_id=? AND authority_digest=?`, journal.State, raw, journal.UpdatedAt, migrationID.String(), state, journal.RouteReference.ReservationID, journal.RouteSpec.ActivationAuthorityDigest)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return errors.Join(migration.ErrConflict, err)
	}
	return nil
}

func (target *migrationContainerTarget) Compensate(ctx context.Context, intent migration.ImportIntent, _ migration.ImportEffect) (migration.ImportEffect, error) {
	operation, err := target.operation(ctx, intent, false)
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	if journal, loadErr := target.loadActivation(ctx, intent.MigrationID); loadErr == nil {
		if migrationHostDigest(journal.Intent) != migrationHostDigest(intent) {
			return migrationHostFailure(intent, migration.ErrConflict)
		}
		if journal.State != containerActivationCanceled {
			if cancelErr := target.cancelBeforePublication(ctx, &journal, operation); cancelErr != nil {
				return migrationHostFailure(intent, cancelErr)
			}
		}
		effect := migrationHostEffect(intent, struct {
			State, Absence, Receipt string
		}{containerActivationCanceled, journal.PublicationEvidence, journal.WorkloadReceipt.EvidenceDigest}, 1, 0, 0)
		effect.Status = migration.ImportEffectCompensated
		return effect, nil
	} else if !errors.Is(loadErr, migration.ErrNotFound) {
		return migrationHostFailure(intent, loadErr)
	}
	receipt, err := target.applications.DiscardMigration(ctx, operation.meta, operation.plan)
	if err != nil || receipt.State != "discarded" || receipt.EvidenceDigest == "" || receipt.RuntimeObjectID != "" {
		return migrationHostFailure(intent, errors.Join(migration.ErrAmbiguous, migrationContainerError(err)))
	}
	effect := migrationHostEffect(intent, receipt.EvidenceDigest, 1, 0, 0)
	effect.Status = migration.ImportEffectCompensated
	return effect, nil
}

func migrationContainerError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, containers.ErrInvalid):
		return errors.Join(migration.ErrInvalid, err)
	case errors.Is(err, containers.ErrNotFound):
		return errors.Join(migration.ErrNotFound, err)
	case errors.Is(err, containers.ErrConflict), errors.Is(err, containers.ErrStale):
		return errors.Join(migration.ErrConflict, err)
	case errors.Is(err, containers.ErrForbidden), errors.Is(err, containers.ErrPolicy), errors.Is(err, containers.ErrInUse):
		return errors.Join(migration.ErrBlocked, err)
	case errors.Is(err, containers.ErrAmbiguous):
		return errors.Join(migration.ErrAmbiguous, err)
	default:
		return fmt.Errorf("container migration: %w", err)
	}
}
