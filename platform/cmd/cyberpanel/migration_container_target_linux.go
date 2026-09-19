//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

const migrationContainerGrantLifetime = 365 * 24 * time.Hour

type migrationContainerTarget struct {
	host         *migrationHostTarget
	applications *containers.ApplicationService
}

type migrationContainerOperation struct {
	plan   containers.MigrationVolumePlan
	meta   containers.CommandMeta
	source migration.ContainerApplication
	volume migration.ContainerVolume
}

func newMigrationContainerTarget(host *migrationHostTarget, applications *containers.ApplicationService) (*migrationContainerTarget, error) {
	if host == nil || applications == nil {
		return nil, migration.ErrInvalid
	}
	return &migrationContainerTarget{host: host, applications: applications}, nil
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
	return migrationContainerOperation{plan: containerPlan, meta: meta, source: source, volume: volume}, nil
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

func (target *migrationContainerTarget) Compensate(ctx context.Context, intent migration.ImportIntent, _ migration.ImportEffect) (migration.ImportEffect, error) {
	operation, err := target.operation(ctx, intent, false)
	if err != nil {
		return migrationHostFailure(intent, err)
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
