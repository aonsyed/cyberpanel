package containers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const MigrationVolumeMaximumBytes uint64 = 64 << 30
const MigrationVolumeMaximumChunk = 1 << 20

// MigrationVolumePlan is a signed recipe plus explicit source-to-target volume
// identity. Piece order is byte order, never digest order. No host paths cross
// this boundary. Rootless UID/GID are selected by broker configuration.
type MigrationVolumePlan struct {
	Version          uint32
	SourceGeneration uint64
	MigrationID      ID
	ApplicationID    ID
	TenantID         ID
	SiteID           ID
	WorkloadID       ID
	VolumeID         ID
	NetworkID        ID
	Recipe           ApplicationRecipe
	SourceName       string
	RecipeVolume     string
	Pieces           []MigrationVolumePiece
	Bytes            uint64
	Digest           string
}

type MigrationVolumePiece struct {
	Digest string
	Bytes  uint64
}

type MigrationContainerRequest struct {
	Action   string
	EffectID EffectID
	Grant    Grant
	Plan     MigrationVolumePlan
	Offset   uint64
	Data     []byte
}

type MigrationContainerReceipt struct {
	EffectID        EffectID
	PlanDigest      string
	State           string
	ArchiveDigest   string
	TreeDigest      string
	RuntimeObjectID string
	EvidenceDigest  string
	MigrationID     ID
	ApplicationID   ID
	VolumeID        ID
	WorkloadID      ID
	Received        uint64
	Bytes           uint64
	Files           uint64
	ObservedAt      time.Time
}

type MigrationContainerBroker interface {
	MigrationContainer(context.Context, MigrationContainerRequest) (MigrationContainerReceipt, error)
}

func validMigrationVolumeName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func (plan MigrationVolumePlan) workloadIdentity() (ID, string) {
	spec := plan.Recipe.Workloads[0].Spec
	// CommandID is an internal broker identity, never source-controlled
	// workload input. The signed recipe still fixes image/argv/runtime policy.
	spec.CommandID = ""
	digest := digestValue(struct {
		Domain                       string
		Migration, Application       ID
		Workload, Volume             ID
		SourceGeneration             uint64
		WorkloadDigest, VolumeDigest string
	}{"container-migration-workload-v1", plan.MigrationID, plan.ApplicationID, plan.WorkloadID, plan.VolumeID, plan.SourceGeneration, digestValue(spec), plan.Digest})
	identifier, _ := NewID("cmd_migration_" + digest[:32])
	return identifier, digest
}

func (plan MigrationVolumePlan) EffectID() EffectID {
	_, digest := plan.workloadIdentity()
	return EffectID("migration-" + digest)
}

func (plan MigrationVolumePlan) CommandID() string {
	return "migration-container-" + string(plan.EffectID())
}

func (plan MigrationVolumePlan) Validate() error {
	if plan.Version != 1 || plan.SourceGeneration == 0 || !plan.MigrationID.Valid() || !plan.ApplicationID.Valid() || !plan.TenantID.Valid() || !plan.SiteID.Valid() || !plan.WorkloadID.Valid() || !plan.VolumeID.Valid() || !validMigrationVolumeName(plan.SourceName) || !validMigrationVolumeName(plan.RecipeVolume) || plan.Bytes == 0 || plan.Bytes > MigrationVolumeMaximumBytes || !digestPattern.MatchString("sha256:"+plan.Digest) || len(plan.Pieces) == 0 || len(plan.Pieces) > 65536 {
		return ErrInvalid
	}
	if !plan.Recipe.ID.Valid() || plan.Recipe.Version == "" || len(plan.Recipe.Workloads) != 1 || len(plan.Recipe.Volumes) != 1 || len(plan.Recipe.Networks) > 1 || len(plan.Recipe.Workloads[0].DependsOn) != 0 {
		return ErrPolicy
	}
	workload := plan.Recipe.Workloads[0]
	volume := plan.Recipe.Volumes[0]
	spec := workload.Spec
	commandID, _ := plan.workloadIdentity()
	spec.CommandID = commandID
	if workload.Name == "" || workload.RoutePortName == "" || volume.Name != plan.RecipeVolume || volume.Class != "managed" || volume.QuotaBytes == 0 || volume.QuotaBytes > MigrationVolumeMaximumBytes || volume.InodeLimit == 0 || volume.InodeLimit > 250000 || plan.Bytes > volume.QuotaBytes || spec.User.UID == 0 || spec.User.GID == 0 || spec.Restart != RestartNever || spec.Validate(TierTenantRootless) != nil || spec.Security.SeccompProfile != "runtime/default" || spec.Security.MACProfile != "panel/tenant" || spec.Security.AllowPublicEgress || spec.Security.EgressPolicyID != "" {
		return ErrPolicy
	}
	if len(spec.Volumes) != 1 || spec.Volumes[0].Target != volume.MountTarget || spec.Volumes[0].ReadOnly || (spec.Volumes[0].VolumeID.String() != volume.Name && spec.Volumes[0].VolumeID.String() != "vol_"+volume.Name) {
		return ErrPolicy
	}
	mountTarget := spec.Volumes[0].Target
	if mountTarget == "/run" || strings.HasPrefix(mountTarget, "/run/") || mountTarget == "/etc" || strings.HasPrefix(mountTarget, "/etc/") {
		return ErrPolicy
	}
	if len(spec.Ports) != 1 || spec.Ports[0].Name != workload.RoutePortName || spec.Ports[0].Protocol != ProtocolTCP {
		return ErrPolicy
	}
	// No generic legacy environment/credential translation. Until a recipe slot
	// has an enrolled exact workload audience, secret-bearing recipes are blocked.
	for _, entry := range spec.Environment {
		if entry.SecretRef != "" {
			return ErrPolicy
		}
	}
	if len(spec.Networks) != len(plan.Recipe.Networks) {
		return ErrPolicy
	}
	if len(plan.Recipe.Networks) == 1 {
		network := plan.Recipe.Networks[0]
		if !plan.NetworkID.Valid() || !network.Internal || (spec.Networks[0].NetworkID.String() != network.Name && spec.Networks[0].NetworkID.String() != "net_"+network.Name) {
			return ErrPolicy
		}
		aliases := map[string]bool{}
		for _, alias := range spec.Networks[0].Aliases {
			if !validContainerAlias(alias) || aliases[alias] || len(aliases) >= 16 {
				return ErrPolicy
			}
			aliases[alias] = true
		}
	} else if plan.NetworkID != "" {
		return ErrInvalid
	}
	var total uint64
	for _, piece := range plan.Pieces {
		if piece.Bytes == 0 || piece.Bytes > MigrationVolumeMaximumBytes || !digestPattern.MatchString("sha256:"+piece.Digest) || total > plan.Bytes || piece.Bytes > plan.Bytes-total {
			return ErrInvalid
		}
		total += piece.Bytes
	}
	if total != plan.Bytes {
		return ErrInvalid
	}
	return nil
}

func (plan MigrationVolumePlan) WorkloadSpec() WorkloadSpec {
	spec := plan.Recipe.Workloads[0].Spec
	spec.CommandID, _ = plan.workloadIdentity()
	spec.Volumes = append([]VolumeMount(nil), spec.Volumes...)
	spec.Volumes[0].VolumeID = plan.VolumeID
	spec.Networks = append([]NetworkAttachment(nil), spec.Networks...)
	if len(spec.Networks) == 1 {
		spec.Networks[0].NetworkID = plan.NetworkID
	}
	return spec
}

func (request MigrationContainerRequest) Validate(now time.Time) error {
	if request.Plan.Validate() != nil || request.EffectID != request.Plan.EffectID() || grantFor(request.Grant, "application.migrate", request.Plan.ApplicationID, now) != nil || request.Grant.TenantID != request.Plan.TenantID || request.Grant.AuthzEpoch != request.Plan.SourceGeneration {
		return ErrForbidden
	}
	switch request.Action {
	case "begin", "seal", "observe", "stage", "discard":
		if request.Offset != 0 || len(request.Data) != 0 {
			return ErrInvalid
		}
	case "chunk":
		if len(request.Data) == 0 || len(request.Data) > MigrationVolumeMaximumChunk || request.Offset > request.Plan.Bytes || uint64(len(request.Data)) > request.Plan.Bytes-request.Offset {
			return ErrInvalid
		}
	default:
		return ErrPolicy
	}
	return nil
}

func (client *ContainerBrokerClient) MigrationContainer(ctx context.Context, value MigrationContainerRequest) (MigrationContainerReceipt, error) {
	response, err := client.call(ctx, BrokerWireRequest{Method: BrokerMigrationContainer, MigrationContainer: &value})
	if response.MigrationContainer == nil {
		return MigrationContainerReceipt{}, err
	}
	return *response.MigrationContainer, err
}

// PlanMigration binds deterministic resource IDs to a locally registered
// signed catalog recipe. This method cannot allocate, launch, pull or publish.
func (a *ApplicationService) PlanMigration(ctx context.Context, command DeployApplicationCommand, migrationID ID, sourceGeneration uint64, sourceName, recipeVolume string, pieces []MigrationVolumePiece, size uint64, digest string) (MigrationVolumePlan, error) {
	if command.Meta.Validate("application.migrate", command.ApplicationID, a.clock().UTC()) != nil || command.Meta.ExpectedGeneration != 0 || len(command.SecretBindings) != 0 || sourceGeneration == 0 || command.Meta.Grant.AuthzEpoch != sourceGeneration {
		return MigrationVolumePlan{}, ErrPolicy
	}
	recipe, err := a.repository.Recipe(ctx, command.RecipeID, command.RecipeVersion)
	if err != nil {
		return MigrationVolumePlan{}, err
	}
	if recipe.ID != command.RecipeID || recipe.Version != command.RecipeVersion {
		return MigrationVolumePlan{}, ErrConflict
	}
	if err = a.verifier.Verify(ctx, recipe); err != nil {
		return MigrationVolumePlan{}, err
	}
	plan := MigrationVolumePlan{Version: 1, SourceGeneration: sourceGeneration, MigrationID: migrationID, ApplicationID: command.ApplicationID, TenantID: command.Meta.Grant.TenantID, SiteID: command.SiteID, Recipe: recipe, SourceName: sourceName, RecipeVolume: recipeVolume, Pieces: append([]MigrationVolumePiece(nil), pieces...), Bytes: size, Digest: digest}
	if len(recipe.Workloads) != 1 || len(recipe.Volumes) != 1 || len(recipe.Networks) > 1 {
		return plan, ErrPolicy
	}
	plan.WorkloadID, err = a.allocator.For(ctx, plan.ApplicationID, "workload", recipe.Workloads[0].Name)
	if err != nil {
		return plan, err
	}
	plan.VolumeID, err = a.allocator.For(ctx, plan.ApplicationID, "volume", recipe.Volumes[0].Name)
	if err != nil {
		return plan, err
	}
	if len(recipe.Networks) == 1 {
		plan.NetworkID, err = a.allocator.For(ctx, plan.ApplicationID, "network", recipe.Networks[0].Name)
		if err != nil {
			return plan, err
		}
	}
	return plan, plan.Validate()
}

func (a *ApplicationService) verifyMigrationPlan(ctx context.Context, plan MigrationVolumePlan) error {
	if plan.Validate() != nil {
		return ErrPolicy
	}
	registered, err := a.repository.Recipe(ctx, plan.Recipe.ID, plan.Recipe.Version)
	if err != nil {
		return err
	}
	if digestValue(registered) != digestValue(plan.Recipe) {
		return ErrConflict
	}
	return a.verifier.Verify(ctx, registered)
}

func migrationApplicationMatches(application ContainerApplication, plan MigrationVolumePlan) bool {
	if application.ID != plan.ApplicationID || application.TenantID != plan.TenantID || application.SiteID != plan.SiteID || application.RecipeID != plan.Recipe.ID || application.RecipeVersion != plan.Recipe.Version || application.ActiveGeneration != 1 || (application.CandidateGeneration != 1 && !(application.State == "migration-discarded" && application.CandidateGeneration == 0)) || len(application.VolumeIDs) != 1 || application.VolumeIDs[0] != plan.VolumeID || len(application.WorkloadIDs) != 1 || application.WorkloadIDs[0] != plan.WorkloadID {
		return false
	}
	if plan.NetworkID == "" {
		return len(application.NetworkIDs) == 0
	}
	return len(application.NetworkIDs) == 1 && application.NetworkIDs[0] == plan.NetworkID
}

// AllocateMigration persists ownership before allocating empty managed volumes
// and internal networks. It never calls Deploy/ApplyWorkload or adds a route.
func (a *ApplicationService) AllocateMigration(ctx context.Context, meta CommandMeta, plan MigrationVolumePlan) (ContainerApplication, error) {
	if err := a.verifyMigrationPlan(ctx, plan); err != nil {
		return ContainerApplication{}, err
	}
	if meta.Validate("application.migrate", plan.ApplicationID, a.clock().UTC()) != nil || meta.Grant.TenantID != plan.TenantID || meta.Grant.AuthzEpoch != plan.SourceGeneration || meta.CommandID != plan.CommandID() || meta.ExpectedGeneration != 0 {
		return ContainerApplication{}, ErrPolicy
	}
	now := a.clock().UTC()
	application := ContainerApplication{ID: plan.ApplicationID, TenantID: plan.TenantID, SiteID: plan.SiteID, RecipeID: plan.Recipe.ID, RecipeVersion: plan.Recipe.Version, State: "migration-allocating", ActiveGeneration: 1, CandidateGeneration: 1, VolumeIDs: []ID{plan.VolumeID}, WorkloadIDs: []ID{plan.WorkloadID}, CreatedAt: now, UpdatedAt: now}
	if plan.NetworkID != "" {
		application.NetworkIDs = []ID{plan.NetworkID}
	}
	operation := Operation{EffectID: plan.EffectID(), TenantID: plan.TenantID, ResourceID: plan.ApplicationID, CommandDigest: digestValue(plan), Status: "accepted", CreatedAt: now}
	admitted, err := a.repository.Admit(ctx, operation, application, 0)
	if err != nil {
		return application, err
	}
	if !admitted {
		previous, loadErr := a.repository.Application(ctx, plan.TenantID, plan.ApplicationID)
		if loadErr != nil {
			return application, loadErr
		}
		if !migrationApplicationMatches(previous, plan) || (previous.State != "migration-allocating" && previous.State != "migration-staged") {
			return previous, ErrAmbiguous
		}
		application = previous
	}
	volume := plan.Recipe.Volumes[0]
	var result Result
	if _, result, err = a.containers.EnsureVolume(ctx, EnsureVolumeCommand{Meta: deriveMeta(meta, "volume.ensure", plan.VolumeID, "volume"), VolumeID: plan.VolumeID, Name: volume.Name, Class: volume.Class, Tier: TierTenantRootless, QuotaBytes: volume.QuotaBytes, InodeLimit: volume.InodeLimit}); err != nil {
		return application, err
	}
	if result.Status != "applied" {
		return application, ErrAmbiguous
	}
	if plan.NetworkID != "" {
		network := plan.Recipe.Networks[0]
		if _, result, err = a.containers.EnsureNetwork(ctx, EnsureNetworkCommand{Meta: deriveMeta(meta, "network.ensure", plan.NetworkID, "network"), NetworkID: plan.NetworkID, Name: network.Name, Tier: TierTenantRootless, IPv4: netip.MustParsePrefix("10.0.0.0/24"), Internal: true, DNSPolicy: "internal"}); err != nil {
			return application, err
		}
		if result.Status != "applied" {
			return application, ErrAmbiguous
		}
	}
	return application, nil
}

func (a *ApplicationService) IngressMigrationVolume(ctx context.Context, meta CommandMeta, plan MigrationVolumePlan, action string, offset uint64, data []byte) (MigrationContainerReceipt, error) {
	if err := a.verifyMigrationPlan(ctx, plan); err != nil {
		return MigrationContainerReceipt{}, err
	}
	if meta.Validate("application.migrate", plan.ApplicationID, a.clock().UTC()) != nil || meta.Grant.TenantID != plan.TenantID || meta.Grant.AuthzEpoch != plan.SourceGeneration || meta.CommandID != plan.CommandID() {
		return MigrationContainerReceipt{}, ErrPolicy
	}
	broker, ok := a.containers.broker.(MigrationContainerBroker)
	if !ok {
		return MigrationContainerReceipt{}, ErrPolicy
	}
	request := MigrationContainerRequest{Action: action, EffectID: plan.EffectID(), Grant: meta.Grant, Plan: plan, Offset: offset, Data: append([]byte(nil), data...)}
	if err := request.Validate(a.clock().UTC()); err != nil {
		return MigrationContainerReceipt{}, err
	}
	receipt, err := broker.MigrationContainer(ctx, request)
	if err != nil {
		return receipt, err
	}
	if validateMigrationContainerReceipt(BrokerWireRequest{Method: BrokerMigrationContainer, MigrationContainer: &request}, receipt) != nil {
		return receipt, ErrAmbiguous
	}
	return receipt, nil
}

func (a *ApplicationService) StageMigration(ctx context.Context, meta CommandMeta, plan MigrationVolumePlan) (MigrationContainerReceipt, error) {
	receipt, err := a.IngressMigrationVolume(ctx, meta, plan, "stage", 0, nil)
	if err != nil {
		return receipt, err
	}
	if receipt.State != "staged" {
		return receipt, ErrAmbiguous
	}
	application, err := a.repository.Application(ctx, plan.TenantID, plan.ApplicationID)
	if err != nil {
		return receipt, err
	}
	if !migrationApplicationMatches(application, plan) || (application.State != "migration-allocating" && application.State != "migration-staged") {
		return receipt, ErrAmbiguous
	}
	application.State = "migration-staged"
	application.UpdatedAt = a.clock().UTC()
	err = a.repository.Complete(ctx, plan.EffectID(), "applied", application, receipt)
	return receipt, err
}

func (a *ApplicationService) DiscardMigration(ctx context.Context, meta CommandMeta, plan MigrationVolumePlan) (MigrationContainerReceipt, error) {
	if err := a.verifyMigrationPlan(ctx, plan); err != nil {
		return MigrationContainerReceipt{}, err
	}
	if meta.Validate("application.migrate", plan.ApplicationID, a.clock().UTC()) != nil || meta.Grant.TenantID != plan.TenantID || meta.Grant.AuthzEpoch != plan.SourceGeneration || meta.CommandID != plan.CommandID() {
		return MigrationContainerReceipt{}, ErrPolicy
	}
	application, err := a.repository.Application(ctx, plan.TenantID, plan.ApplicationID)
	if err != nil {
		return MigrationContainerReceipt{}, err
	}
	if !migrationApplicationMatches(application, plan) || (application.State != "migration-allocating" && application.State != "migration-staged" && application.State != "migration-discarding" && application.State != "migration-discarded") {
		return MigrationContainerReceipt{}, fmt.Errorf("%w: migration is no longer pre-public", ErrPolicy)
	}
	effect := EffectID("migration-discard-" + digestValue(plan))
	if application.State != "migration-discarded" {
		proposal := application
		proposal.State = "migration-discarding"
		proposal.UpdatedAt = a.clock().UTC()
		operation := Operation{EffectID: effect, TenantID: plan.TenantID, ResourceID: plan.ApplicationID, CommandDigest: digestValue(struct {
			Domain string
			Plan   MigrationVolumePlan
		}{"container-migration-discard-v1", plan}), Status: "accepted", CreatedAt: a.clock().UTC()}
		admitted, admitErr := a.repository.Admit(ctx, operation, proposal, application.ActiveGeneration)
		if admitErr != nil {
			return MigrationContainerReceipt{}, admitErr
		}
		if admitted {
			application = proposal
		} else {
			application, err = a.repository.Application(ctx, plan.TenantID, plan.ApplicationID)
			if err != nil || !migrationApplicationMatches(application, plan) || (application.State != "migration-discarding" && application.State != "migration-discarded") {
				return MigrationContainerReceipt{}, errors.Join(ErrAmbiguous, err)
			}
		}
	}
	receipt, err := a.IngressMigrationVolume(ctx, meta, plan, "discard", 0, nil)
	if errors.Is(err, ErrNotFound) {
		if _, beginErr := a.IngressMigrationVolume(ctx, meta, plan, "begin", 0, nil); beginErr != nil {
			return receipt, errors.Join(err, beginErr)
		}
		receipt, err = a.IngressMigrationVolume(ctx, meta, plan, "discard", 0, nil)
	}
	if err != nil || receipt.State != "discarded" {
		return receipt, errors.Join(ErrAmbiguous, err)
	}
	if application.State == "migration-discarded" {
		return receipt, nil
	}
	application.State = "migration-discarded"
	application.CandidateGeneration = 0
	application.UpdatedAt = a.clock().UTC()
	return receipt, a.repository.Complete(ctx, effect, "applied", application, receipt)
}

// Route ownership cannot be inferred from a hostname. The normal proxy seam
// currently has no tenant-owned site-binding replacement operation; do not run
// a candidate writer while that prerequisite is missing.
func (a *ApplicationService) ActivateMigration(context.Context, MigrationVolumePlan) (MigrationContainerReceipt, error) {
	return MigrationContainerReceipt{}, fmt.Errorf("%w: exact tenant-owned route activation and durable source-fence transaction are unbound", ErrPolicy)
}
