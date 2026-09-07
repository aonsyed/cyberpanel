package operations

import "github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"

// RebootMarkerEffect exposes no caller-controlled filesystem path. Probe is
// always a live observation; arm and clear are checked against durable state.
type RebootMarkerEffect struct {
	Marker *rebootcontrol.RecoveryMarker `json:"marker,omitempty"`
	ExactDigest string `json:"exact_digest,omitempty"`
}

type RebootMarkerResult struct {
	Marker *rebootcontrol.RecoveryMarker `json:"marker,omitempty"`
	Present bool `json:"present"`
	Committed bool `json:"committed"`
	Cleared bool `json:"cleared"`
	ExactDigest string `json:"exact_digest,omitempty"`
}

func NewRebootMarkerArmRequest(marker rebootcontrol.RecoveryMarker) (EffectRequest, error) {
	node, err := NewResourceID(marker.NodeID); if err != nil { return EffectRequest{}, err }
	plan, err := NewResourceID(marker.PlanID); if err != nil { return EffectRequest{}, err }
	return finalizeEffect(EffectRequest{Scope: OperationScope{NodeID: node, Kind: KindControlledReboot, ID: plan}, Kind: EffectRebootMarkerArm, RebootMarker: &RebootMarkerEffect{Marker: &marker}})
}

func NewRebootMarkerProbeRequest(node string) (EffectRequest, error) {
	id, err := NewResourceID(node); if err != nil { return EffectRequest{}, err }
	return finalizeEffect(EffectRequest{Scope: OperationScope{NodeID: id, Kind: KindControlledReboot, ID: id}, Kind: EffectRebootMarkerProbe, RebootMarker: &RebootMarkerEffect{}})
}

func NewRebootMarkerClearRequest(node, digest string) (EffectRequest, error) {
	id, err := NewResourceID(node); if err != nil { return EffectRequest{}, err }
	return finalizeEffect(EffectRequest{Scope: OperationScope{NodeID: id, Kind: KindControlledReboot, ID: id}, Kind: EffectRebootMarkerClear, RebootMarker: &RebootMarkerEffect{ExactDigest: digest}})
}

func validateRebootMarkerEffect(request EffectRequest) error {
	effect := request.RebootMarker
	if effect == nil || request.Scope.NodeID.String() != "local" || request.Scope.TenantID.String()!="" || request.Scope.Kind != KindControlledReboot { return ErrInvalidEffect }
	switch request.Kind {
	case EffectRebootMarkerArm:
		if effect.Marker == nil || effect.Marker.Validate() != nil || effect.Marker.NodeID != request.Scope.NodeID.String() || effect.Marker.PlanID != request.Scope.ID.String() || effect.ExactDigest != "" { return ErrInvalidEffect }
	case EffectRebootMarkerProbe:
		if effect.Marker != nil || effect.ExactDigest != "" || request.Scope.ID != request.Scope.NodeID { return ErrInvalidEffect }
	case EffectRebootMarkerClear:
		if effect.Marker != nil || !validSHA256(effect.ExactDigest) || request.Scope.ID != request.Scope.NodeID { return ErrInvalidEffect }
	default: return ErrInvalidEffect
	}
	return nil
}

func validateRebootMarkerResult(request EffectRequest, result RebootMarkerResult) error {
	if validateRebootMarkerEffect(request) != nil { return ErrInvalidEffect }
	if result.Present {
		if result.Marker == nil || result.Marker.Validate() != nil || result.Marker.NodeID != request.Scope.NodeID.String() || result.Marker.Digest != result.ExactDigest { return ErrInvalidEffect }
	} else if result.Marker != nil { return ErrInvalidEffect }
	switch request.Kind {
	case EffectRebootMarkerArm:
		if !result.Present || !result.Committed || result.Cleared || result.ExactDigest != request.RebootMarker.Marker.Digest { return ErrInvalidEffect }
	case EffectRebootMarkerProbe:
		if result.Committed || result.Cleared || !result.Present && result.ExactDigest != "" { return ErrInvalidEffect }
	case EffectRebootMarkerClear:
		if result.Present || result.Committed || !result.Cleared || result.ExactDigest != request.RebootMarker.ExactDigest { return ErrInvalidEffect }
	default: return ErrInvalidEffect
	}
	return nil
}

// ValidateRebootMarkerReceipt also guards direct in-process HostExecutor use.
func ValidateRebootMarkerReceipt(request EffectRequest, receipt EffectReceipt) error {
	if validateEffectRequest(request) != nil || !effectReceiptMatches(request, receipt) || receipt.Outcome != EffectConfirmed || receipt.Result.RebootMarker == nil { return ErrInvalidEffect }
	return validateRebootMarkerResult(request, *receipt.Result.RebootMarker)
}
