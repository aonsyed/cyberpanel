//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/management"
)

type webEngineEdge struct {
	service *management.Service
	edition webengine.Edition
}

func newWebEngineEdge(service *management.Service, edition webengine.Edition) (*webEngineEdge, error) {
	if service == nil || edition != webengine.EditionOpenLiteSpeed && edition != webengine.EditionLiteSpeedEnterprise {
		return nil, management.ErrInvalid
	}
	return &webEngineEdge{service: service, edition: edition}, nil
}

func (edge *webEngineEdge) WebEngineCapabilities() apiserver.WebEngineEdgeCapabilities {
	if edge == nil || edge.service == nil {
		return apiserver.WebEngineEdgeCapabilities{}
	}
	capabilities := edge.service.Capabilities()
	return apiserver.WebEngineEdgeCapabilities{List: capabilities.Inspect, Tuning: capabilities.Tune}
}

func (edge *webEngineEdge) ListInstallations(ctx context.Context, call apiserver.EdgeCall, page apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.WebEngineProjection], error) {
	if edge == nil || edge.service == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "" || call.ExpectedGeneration != 0 {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{}, management.ErrInvalid
	}
	installation, err := edge.service.Installation(ctx)
	if errors.Is(err, management.ErrNotFound) {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{Items: []apiserver.WebEngineProjection{}}, nil
	}
	if err != nil {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{}, err
	}
	tuning, err := edge.service.CurrentTuning(ctx)
	if err != nil {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{}, err
	}
	if tuning.Generation != installation.Generation {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{}, management.ErrConflict
	}
	if page.Cursor != "" && page.Cursor >= installation.ID {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{Items: []apiserver.WebEngineProjection{}, Total: 1}, nil
	}
	return apiserver.EdgePage[apiserver.WebEngineProjection]{Items: []apiserver.WebEngineProjection{webEngineProjection(installation, tuning)}, Total: 1}, nil
}

func (edge *webEngineEdge) ConfigureTuning(ctx context.Context, call apiserver.EdgeCall, payload apiserver.WebEngineTuningPayload) (apiserver.EdgeMutation[apiserver.WebEngineProjection], error) {
	if edge == nil || edge.service == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "node-webengine" ||
		call.ExpectedGeneration == 0 || call.CommandID == "" || call.PrincipalID == "" || call.CredentialID == "" || call.AuthzEpoch == 0 {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrInvalid
	}
	installation, err := edge.service.Installation(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	if installation.ID != call.ResourceID || installation.Edition != edge.edition || installation.Generation != call.ExpectedGeneration {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrConflict
	}
	tuning, err := edge.service.CurrentTuning(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	if tuning.Generation != call.ExpectedGeneration {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrConflict
	}
	if payload.WorkerProcesses != 0 {
		if edge.edition == webengine.EditionLiteSpeedEnterprise && uint32(payload.WorkerProcesses) != tuning.WorkerProcesses {
			return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrLicense
		}
		tuning.WorkerProcesses = uint32(payload.WorkerProcesses)
	}
	if payload.MaxConnections != 0 {
		tuning.MaxConnections = payload.MaxConnections
		tuning.MaxTLSConnections = payload.MaxConnections
	}
	if payload.KeepAliveSeconds != 0 {
		tuning.KeepAliveTimeout = durationSeconds(payload.KeepAliveSeconds)
	}
	tuning.Generation++
	effectID := webEngineEffectID(call.CommandID, "tuning", call.ResourceID)
	_, err = edge.service.Tune(ctx, effectID, tuning, call.ExpectedGeneration, call.ExpectedGeneration+1, webEngineAuthorizationDigest(call))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	installation, err = edge.service.Installation(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	tuning, err = edge.service.CurrentTuning(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	projection := webEngineProjection(installation, tuning)
	return apiserver.EdgeMutation[apiserver.WebEngineProjection]{
		OperationID: effectID, State: string(installation.State), Generation: installation.Generation, Resource: projection,
	}, nil
}

func (*webEngineEdge) ConfigureLicense(context.Context, apiserver.EdgeCall, apiserver.WebEngineLicensePayload, []byte) (apiserver.EdgeMutation[apiserver.WebEngineProjection], error) {
	return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrUnsupported
}

func (*webEngineEdge) Upgrade(context.Context, apiserver.EdgeCall, apiserver.WebEngineUpgradePayload) (apiserver.EdgeMutation[apiserver.WebEngineProjection], error) {
	return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrUnsupported
}

func (*webEngineEdge) CreatePHPProfile(context.Context, apiserver.EdgeCall, apiserver.WebEnginePHPProfilePayload) (apiserver.EdgeMutation[apiserver.WebEnginePHPProfileProjection], error) {
	return apiserver.EdgeMutation[apiserver.WebEnginePHPProfileProjection]{}, management.ErrUnsupported
}

func webEngineProjection(installation management.Installation, tuning management.GlobalTuning) apiserver.WebEngineProjection {
	licenseState := string(installation.License.State)
	if installation.Edition == webengine.EditionOpenLiteSpeed {
		licenseState = "not_applicable"
	} else if licenseState == "" {
		licenseState = "unknown"
	}
	version := installation.Version
	if version == "" {
		version = "unknown"
	}
	health := "unknown"
	if installation.State == management.StateDegraded {
		health = "degraded"
	} else if installation.State == management.StateActive && webEngineValidDigest(installation.ActiveConfigDigest) {
		health = "healthy"
	}
	return apiserver.WebEngineProjection{
		ID: installation.ID, Edition: string(installation.Edition), Version: version, Channel: string(installation.Channel),
		License: licenseState, LicenseState: licenseState, Workers: tuning.WorkerProcesses, Connections: tuning.MaxConnections,
		Health: health, Generation: installation.Generation, UpdatedAt: installation.UpdatedAt,
	}
}

func webEngineValidDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func webEngineEffectID(values ...string) string {
	return "web-" + webEngineDigest(values...)[:48]
}

func webEngineDigest(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func webEngineAuthorizationDigest(call apiserver.EdgeCall) string {
	return webEngineDigest(call.PrincipalID, call.SessionID, call.CredentialID, call.CommandID,
		strconv.FormatUint(uint64(call.Assurance), 10), strconv.FormatUint(call.AuthzEpoch, 10),
		call.ResourceID, strconv.FormatUint(call.ExpectedGeneration, 10), call.IdempotencyKey)
}

func durationSeconds(value uint32) time.Duration {
	return time.Duration(value) * time.Second
}

var _ apiserver.WebEngineEdgeService = (*webEngineEdge)(nil)
var _ apiserver.WebEngineEdgeCapabilityProvider = (*webEngineEdge)(nil)
