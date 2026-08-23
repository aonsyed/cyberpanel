//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/productupdate"
)

// productUpdateReleaseSource is a fixed, authenticated release catalog and
// artifact source. It cannot be a caller-selected URL or host path.
type productUpdateReleaseSource interface {
	Manifest(context.Context, string) (productupdate.ReleaseManifest, error)
	productupdate.ArtifactSource
}

// productUpdateAuthorizationSource resolves a protected, signed update
// authorization. The API adapter never manufactures or downgrades this proof.
type productUpdateAuthorizationSource interface {
	AuthorizeProductUpdate(context.Context, productUpdateAuthorizationRequest) (productupdate.UpdateAuthorization, error)
}

type productUpdateAuthorizationRequest struct {
	Call             apiserver.EdgeCall
	Manifest         productupdate.ReleaseManifest
	State            productupdate.UpdateState
	Action           productupdate.UpdateAction
	RequestedAt      time.Time
	ExpectedDuration time.Duration
}

type productUpdateLinuxEdge struct {
	coordinator    *productupdate.Coordinator
	repository     *productupdate.Repository
	inventory      productupdate.InventorySource
	releases       productUpdateReleaseSource
	authorizations productUpdateAuthorizationSource
	capabilities   apiserver.ProductUpdateEdgeCapabilities
	nodeID         string
	controllerID   string
	now            func() time.Time
}

const productUpdateMaximumGeneration = uint64(1<<63 - 1)

func newProductUpdateLinuxEdge(coordinator *productupdate.Coordinator, repository *productupdate.Repository,
	inventory productupdate.InventorySource, releases productUpdateReleaseSource, authorizations productUpdateAuthorizationSource,
	nodeID, controllerID string, now func() time.Time) (*productUpdateLinuxEdge, error) {
	if coordinator == nil || repository == nil || inventory == nil || releases == nil || authorizations == nil ||
		!validProductUpdateRuntimeID(nodeID) || !validProductUpdateRuntimeID(controllerID) {
		return nil, productupdate.ErrInvalid
	}
	if now == nil { now = time.Now }
	return &productUpdateLinuxEdge{coordinator:coordinator, repository:repository, inventory:inventory, releases:releases,
		authorizations:authorizations, capabilities:apiserver.ProductUpdateEdgeCapabilities{List:true, Check:true, Plan:true, Apply:true},
		nodeID:nodeID, controllerID:controllerID, now:now}, nil
}

func (edge *productUpdateLinuxEdge) ProductUpdateCapabilities() apiserver.ProductUpdateEdgeCapabilities {
	if edge == nil { return apiserver.ProductUpdateEdgeCapabilities{} }
	return edge.capabilities
}

func (edge *productUpdateLinuxEdge) ListProductUpdates(ctx context.Context, call apiserver.EdgeCall, payload apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.ProductUpdateProjection], error) {
	if edge == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "" || call.ExpectedGeneration != 0 {
		return apiserver.EdgePage[apiserver.ProductUpdateProjection]{}, productupdate.ErrInvalid
	}
	limit := int(payload.Limit)
	if limit == 0 { limit = 100 }
	if limit < 1 || limit > productupdate.MaxPageSize {
		return apiserver.EdgePage[apiserver.ProductUpdateProjection]{}, productupdate.ErrInvalid
	}
	current, err := edge.current(ctx)
	if err != nil { return apiserver.EdgePage[apiserver.ProductUpdateProjection]{}, err }
	afterManifest, afterNode, err := decodeProductUpdateCursor(payload.Cursor)
	if err != nil { return apiserver.EdgePage[apiserver.ProductUpdateProjection]{}, err }
	page := apiserver.EdgePage[apiserver.ProductUpdateProjection]{Items:make([]apiserver.ProductUpdateProjection, 0, limit)}
	stateLimit := limit
	if payload.Cursor == "" {
		page.Items = append(page.Items, apiserver.ProductUpdateProjection{ID:"current", Type:"current", NodeID:edge.nodeID,
			CurrentVersion:current.version, CurrentChannel:string(current.channel), Phase:"current", CheckStatus:"current",
			PlanStatus:"current", ApplyStatus:"current", RecoveryStatus:"not_required", UpdatedAt:current.observedAt})
		stateLimit--
	}
	if stateLimit == 0 { return page, nil }
	states, err := edge.repository.List(ctx, "", afterManifest, afterNode, stateLimit)
	if err != nil { return apiserver.EdgePage[apiserver.ProductUpdateProjection]{}, err }
	for _, state := range states {
		if state.NodeID != edge.nodeID { continue }
		manifest, stored, loadErr := edge.repository.Get(ctx, state.ManifestID, state.NodeID)
		if loadErr != nil { return apiserver.EdgePage[apiserver.ProductUpdateProjection]{}, loadErr }
		projection, projectErr := productUpdateProjection(current, manifest, stored)
		if projectErr != nil { return apiserver.EdgePage[apiserver.ProductUpdateProjection]{}, projectErr }
		page.Items = append(page.Items, projection)
	}
	if len(states) == stateLimit {
		last := states[len(states)-1]
		page.NextCursor, err = encodeProductUpdateCursor(last.ManifestID, last.NodeID)
		if err != nil { return apiserver.EdgePage[apiserver.ProductUpdateProjection]{}, err }
	}
	return page, nil
}

func (edge *productUpdateLinuxEdge) CheckProductUpdate(ctx context.Context, call apiserver.EdgeCall, payload apiserver.ProductUpdateCheckPayload) (apiserver.EdgeMutation[apiserver.ProductUpdateProjection], error) {
	if err := edge.validateMutation(ctx, call, false); err != nil || !validProductUpdateRuntimeID(payload.ManifestID) {
		if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
		return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, productupdate.ErrInvalid
	}
	manifest, err := edge.releases.Manifest(ctx, payload.ManifestID)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	manifest, err = productupdate.CanonicalManifest(manifest)
	if err != nil || manifest.ID != payload.ManifestID {
		if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
		return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, productupdate.ErrIntegrity
	}
	now := edge.now().UTC()
	state, _, err := edge.coordinator.Discover(ctx, manifest, edge.nodeID, edge.controllerID, productUpdateStepKey(call.IdempotencyKey, "discover"), now)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	manifest, state, err = edge.repository.Get(ctx, manifest.ID, edge.nodeID)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	command, err := edge.command(ctx, call, manifest, state, productupdate.ActionVerify, 1, 1, 0)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	state, _, err = edge.coordinator.Verify(ctx, command)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	return edge.mutation(ctx, call, manifest, state)
}

func (edge *productUpdateLinuxEdge) PlanProductUpdate(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.ProductUpdateProjection], error) {
	if err := edge.validateMutation(ctx, call, true); err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	manifest, state, err := edge.repository.Get(ctx, call.ResourceID, edge.nodeID)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	command, err := edge.command(ctx, call, manifest, state, productupdate.ActionStage, call.ExpectedGeneration, state.Fence, 0)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	// Planning stages only the already verified immutable artifacts. Schema
	// preflight and every external effect remain in Apply, where ambiguity is
	// durably recorded by the coordinator instead of being called a dry run.
	state, _, err = edge.coordinator.Stage(ctx, command, edge.releases)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	return edge.mutation(ctx, call, manifest, state)
}

func (edge *productUpdateLinuxEdge) ApplyProductUpdate(ctx context.Context, call apiserver.EdgeCall, payload apiserver.ProductUpdateApplyPayload) (apiserver.EdgeMutation[apiserver.ProductUpdateProjection], error) {
	if err := edge.validateMutation(ctx, call, true); err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	seconds := payload.ExpectedDurationSeconds
	if seconds == 0 { seconds = 1800 }
	if call.ExpectedGeneration > productUpdateMaximumGeneration-4 || seconds < 60 || seconds > 86400 {
		return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, productupdate.ErrInvalid
	}
	duration := time.Duration(seconds) * time.Second
	manifest, state, err := edge.repository.Get(ctx, call.ResourceID, edge.nodeID)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	type updateStep struct {
		action   productupdate.UpdateAction
		expected uint64
		run      func(context.Context, productupdate.Command) (productupdate.UpdateState, productupdate.Receipt, error)
	}
	steps := []updateStep{
		{productupdate.ActionPreflight, call.ExpectedGeneration, edge.coordinator.Preflight},
		{productupdate.ActionSwitch, call.ExpectedGeneration + 1, edge.coordinator.Switch},
		{productupdate.ActionProbe, call.ExpectedGeneration + 2, edge.coordinator.BeginProbe},
		{productupdate.ActionFinalize, call.ExpectedGeneration + 3, edge.coordinator.CompleteProbe},
	}
	for _, step := range steps {
		command, commandErr := edge.command(ctx, call, manifest, state, step.action, step.expected, state.Fence, duration)
		if commandErr != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, commandErr }
		state, _, err = step.run(ctx, command)
		if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
		manifest, state, err = edge.repository.Get(ctx, call.ResourceID, edge.nodeID)
		if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	}
	return edge.mutation(ctx, call, manifest, state)
}

func (edge *productUpdateLinuxEdge) validateMutation(ctx context.Context, call apiserver.EdgeCall, existing bool) error {
	if edge == nil || ctx == nil || call.TenantID != "" || call.PrincipalID == "" || call.CredentialID == "" || call.IdempotencyKey == "" {
		return productupdate.ErrInvalid
	}
	if existing {
		if !validProductUpdateRuntimeID(call.ResourceID) || call.ExpectedGeneration == 0 { return productupdate.ErrInvalid }
	} else if call.ResourceID != "" || call.ExpectedGeneration != 0 {
		return productupdate.ErrInvalid
	}
	return nil
}

func (edge *productUpdateLinuxEdge) command(ctx context.Context, call apiserver.EdgeCall, manifest productupdate.ReleaseManifest,
	state productupdate.UpdateState, action productupdate.UpdateAction, expectedGeneration, fence uint64, duration time.Duration) (productupdate.Command, error) {
	requestedAt := edge.now().UTC()
	authorization, err := edge.authorizations.AuthorizeProductUpdate(ctx, productUpdateAuthorizationRequest{Call:call, Manifest:manifest,
		State:state, Action:action, RequestedAt:requestedAt, ExpectedDuration:duration})
	if err != nil { return productupdate.Command{}, err }
	if authorization.Subject != call.PrincipalID || authorization.NodeID != edge.nodeID || authorization.ManifestDigest != manifest.Digest || authorization.Action != action {
		return productupdate.Command{}, productupdate.ErrUnauthorized
	}
	return productupdate.Command{ManifestID:manifest.ID, NodeID:edge.nodeID, ExpectedGeneration:expectedGeneration, Fence:fence,
		ControllerID:edge.controllerID, IdempotencyKey:productUpdateStepKey(call.IdempotencyKey, string(action)), At:requestedAt,
		ExpectedDuration:duration, Authorization:authorization}, nil
}

func (edge *productUpdateLinuxEdge) mutation(ctx context.Context, call apiserver.EdgeCall, manifest productupdate.ReleaseManifest,
	state productupdate.UpdateState) (apiserver.EdgeMutation[apiserver.ProductUpdateProjection], error) {
	current, err := edge.current(ctx)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	projection, err := productUpdateProjection(current, manifest, state)
	if err != nil { return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{}, err }
	return apiserver.EdgeMutation[apiserver.ProductUpdateProjection]{OperationID:call.CommandID, State:string(state.Phase), Generation:state.Generation, Resource:projection}, nil
}

type productUpdateCurrent struct {
	version    string
	channel    productupdate.Channel
	observedAt time.Time
}

func (edge *productUpdateLinuxEdge) current(ctx context.Context) (productUpdateCurrent, error) {
	inventory, err := edge.inventory.InstalledInventory(ctx, edge.nodeID)
	if err != nil { return productUpdateCurrent{}, productupdate.ErrIntegrity }
	inventory, err = productupdate.CanonicalInventory(inventory)
	if err != nil { return productUpdateCurrent{}, err }
	return productUpdateCurrent{version:inventory.Runtime.String(), channel:inventory.Platform.Channel, observedAt:inventory.ObservedAt}, nil
}

func productUpdateProjection(current productUpdateCurrent, manifest productupdate.ReleaseManifest, state productupdate.UpdateState) (apiserver.ProductUpdateProjection, error) {
	manifest, err := productupdate.CanonicalManifest(manifest)
	if err != nil || state.ManifestID != manifest.ID || state.ManifestDigest != manifest.Digest {
		if err != nil { return apiserver.ProductUpdateProjection{}, err }
		return apiserver.ProductUpdateProjection{}, productupdate.ErrIntegrity
	}
	typeName, check, plan, apply, recovery := productUpdateStatuses(state.Phase)
	rollbackStatus := "declared_unproven"
	if manifest.Rollback == productupdate.RollbackNone { rollbackStatus = "not_supported" }
	if state.RollbackProven { rollbackStatus = "proven" }
	projection := apiserver.ProductUpdateProjection{ID:manifest.ID, Type:typeName, NodeID:state.NodeID, CurrentVersion:current.version,
		CurrentChannel:string(current.channel), TargetVersion:manifest.ReleaseVersion.String(), TargetChannel:string(manifest.Platform.Channel),
		Phase:string(state.Phase), CheckStatus:check, PlanStatus:plan, ApplyStatus:apply, RollbackClass:string(manifest.Rollback),
		RollbackStatus:rollbackStatus, RollbackProven:state.RollbackProven, IrreversibleStep:manifest.Irreversible.StepID,
		IrreversibleSchemaVersion:manifest.Irreversible.SchemaVersion, RecoveryStatus:recovery, Reason:string(state.Reason),
		Generation:state.Generation, UpdatedAt:state.UpdatedAt}
	if state.RollbackProven { projection.RollbackReleaseID = state.PreviousReleaseID }
	if state.Phase == productupdate.PhaseUncertain {
		projection.RecoveryEvidence = state.RecoveryEvidence
		projection.RecoverySteps = append([]string(nil), state.RecoverySteps...)
	}
	return projection, nil
}

func productUpdateStatuses(phase productupdate.Phase) (string, string, string, string, string) {
	switch phase {
	case productupdate.PhaseDiscovered:
		return "checking", "in_progress", "pending", "pending", "not_required"
	case productupdate.PhaseVerified:
		return "checked", "complete", "pending", "pending", "not_required"
	case productupdate.PhaseStaged:
		return "planned", "complete", "complete", "pending", "not_required"
	case productupdate.PhasePreflighted, productupdate.PhaseSwitched, productupdate.PhaseProbing:
		return "applying", "complete", "complete", "in_progress", "not_required"
	case productupdate.PhaseCommitted:
		return "complete", "complete", "complete", "complete", "not_required"
	case productupdate.PhaseRolledBack:
		return "complete", "complete", "complete", "rolled_back", "rollback_completed"
	case productupdate.PhaseFailed:
		return "failed", "failed", "failed", "failed", "not_required"
	case productupdate.PhaseUncertain:
		return "recovery", "ambiguous", "ambiguous", "ambiguous", "manual_recovery_required"
	default:
		return "unknown", "unknown", "unknown", "unknown", "unknown"
	}
}

type productUpdateCursor struct {
	ManifestID string `json:"manifest_id"`
	NodeID     string `json:"node_id"`
}

func encodeProductUpdateCursor(manifestID, nodeID string) (string, error) {
	if !validProductUpdateRuntimeID(manifestID) || !validProductUpdateRuntimeID(nodeID) { return "", productupdate.ErrInvalid }
	raw, err := json.Marshal(productUpdateCursor{ManifestID:manifestID, NodeID:nodeID})
	if err != nil { return "", err }
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeProductUpdateCursor(value string) (string, string, error) {
	if value == "" { return "", "", nil }
	if len(value) > 1024 { return "", "", productupdate.ErrInvalid }
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil { return "", "", productupdate.ErrInvalid }
	var cursor productUpdateCursor
	if json.Unmarshal(raw, &cursor) != nil || !validProductUpdateRuntimeID(cursor.ManifestID) || !validProductUpdateRuntimeID(cursor.NodeID) {
		return "", "", productupdate.ErrInvalid
	}
	return cursor.ManifestID, cursor.NodeID, nil
}

func productUpdateStepKey(idempotencyKey, step string) string {
	sum := sha256.Sum256([]byte("cyberpanel-product-update-step-v1\x00" + idempotencyKey + "\x00" + step))
	return "api-" + hex.EncodeToString(sum[:])
}

func validProductUpdateRuntimeID(value string) bool {
	if value == "" || len(value) > 128 { return false }
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' { continue }
		if index > 0 && (character == '-' || character == '_' || character == '.' || character == ':') { continue }
		return false
	}
	return true
}

var _ apiserver.ProductUpdateEdgeService = (*productUpdateLinuxEdge)(nil)
var _ apiserver.ProductUpdateEdgeCapabilityProvider = (*productUpdateLinuxEdge)(nil)
