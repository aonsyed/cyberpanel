package extensions

import (
	"context"
	"encoding/json"
	"time"
)

type LifecycleAction string

const (
	ActionInstall   LifecycleAction = "install"
	ActionEnable    LifecycleAction = "enable"
	ActionConfigure LifecycleAction = "configure"
	ActionSuspend   LifecycleAction = "suspend"
	ActionUpdate    LifecycleAction = "update"
	ActionRollback  LifecycleAction = "rollback"
	ActionDisable   LifecycleAction = "disable"
	ActionUninstall LifecycleAction = "uninstall"
	ActionPurge     LifecycleAction = "purge"
)

func validLifecycleAction(action LifecycleAction) bool {
	switch action {
	case ActionInstall, ActionEnable, ActionConfigure, ActionSuspend, ActionUpdate, ActionRollback, ActionDisable, ActionUninstall, ActionPurge:
		return true
	default:
		return false
	}
}

type RuntimeRequest struct {
	CommandID           CommandID           `json:"command_id"`
	RequestDigest       string              `json:"request_digest"`
	Action              LifecycleAction     `json:"action"`
	ExtensionID         ExtensionID         `json:"extension_id"`
	ExpectedGeneration  uint64              `json:"expected_generation"`
	ResultGeneration    uint64              `json:"result_generation"`
	Current             *ExtensionRelease   `json:"current,omitempty"`
	Target              *ExtensionRelease   `json:"target,omitempty"`
	Capabilities        []CapabilityRequest `json:"capabilities"`
	Configuration       json.RawMessage     `json:"configuration"`
	ConfigurationDigest string              `json:"configuration_digest"`
	DataPolicy          DataPolicy          `json:"data_policy"`
}

func (request RuntimeRequest) Validate() error {
	if !validID(string(request.CommandID)) || !validDigest(request.RequestDigest) || !validLifecycleAction(request.Action) ||
		!validID(string(request.ExtensionID)) || request.ResultGeneration != request.ExpectedGeneration+1 || request.ResultGeneration == 0 ||
		validateConfiguration(request.Configuration) != nil || digestBytes(request.Configuration) != request.ConfigurationDigest ||
		request.DataPolicy != DataPreserve && request.DataPolicy != DataDelete {
		return ErrInvalid
	}
	if request.Current != nil && (request.Current.ExtensionID != request.ExtensionID || request.Current.Validate() != nil) {
		return ErrInvalid
	}
	if request.Target != nil && (request.Target.ExtensionID != request.ExtensionID || request.Target.Validate() != nil || !sameCapabilities(request.Capabilities, request.Target.Manifest.Capabilities)) {
		return ErrInvalid
	}
	if request.Target == nil && request.Current != nil && !sameCapabilities(request.Capabilities, request.Current.Manifest.Capabilities) {
		return ErrForbidden
	}
	if request.Action == ActionInstall && request.Current != nil || request.Action != ActionInstall && request.Current == nil ||
		(request.Action == ActionInstall || request.Action == ActionUpdate || request.Action == ActionRollback) && request.Target == nil {
		return ErrInvalid
	}
	return nil
}

type RuntimeOutcome string

const (
	RuntimeApplied RuntimeOutcome = "applied"
)

// RuntimeReceipt is the boundary proof returned by an out-of-process runtime.
// It contains identifiers and evidence digests, never credentials or handles.
type RuntimeReceipt struct {
	CommandID       CommandID         `json:"command_id"`
	RequestDigest   string            `json:"request_digest"`
	Action          LifecycleAction   `json:"action"`
	ExtensionID     ExtensionID       `json:"extension_id"`
	ReleaseDigest   string            `json:"release_digest"`
	Generation      uint64            `json:"generation"`
	Outcome         RuntimeOutcome    `json:"outcome"`
	RuntimeObjectIDs []string          `json:"runtime_object_ids,omitempty"`
	Health          HealthObservation `json:"health"`
	EvidenceDigest  string            `json:"evidence_digest"`
	ObservedAt      time.Time         `json:"observed_at"`
}

func (receipt RuntimeReceipt) Validate(request RuntimeRequest) error {
	if receipt.CommandID != request.CommandID || receipt.RequestDigest != request.RequestDigest || receipt.Action != request.Action ||
		receipt.ExtensionID != request.ExtensionID || receipt.Generation != request.ResultGeneration || receipt.Outcome != RuntimeApplied ||
		!validDigest(receipt.ReleaseDigest) || !validDigest(receipt.EvidenceDigest) || receipt.ObservedAt.IsZero() {
		return ErrIntegrity
	}
	expectedRelease := ""
	if request.Current != nil {
		expectedRelease = request.Current.Digest
	}
	if request.Target != nil {
		expectedRelease = request.Target.Digest
	}
	if request.Action == ActionPurge {
		expectedRelease = request.Current.Digest
	}
	if receipt.ReleaseDigest != expectedRelease || !validHealth(receipt.Health) {
		return ErrIntegrity
	}
	previous := ""
	for _, id := range receipt.RuntimeObjectIDs {
		if !validRuntimeID(id) || id <= previous {
			return ErrIntegrity
		}
		previous = id
	}
	return nil
}

func validHealth(health HealthObservation) bool {
	if health.ObservedAt.IsZero() {
		return false
	}
	switch health.State {
	case HealthUnknown, HealthHealthy, HealthDegraded, HealthUnavailable:
		return true
	default:
		return false
	}
}

type RuntimeObjectKind string

const (
	RuntimeObjectExecution RuntimeObjectKind = "execution"
	RuntimeObjectOwnedData RuntimeObjectKind = "owned_data"
)

type RuntimeObject struct {
	ID            string        `json:"id"`
	ExtensionID   ExtensionID   `json:"extension_id"`
	ReleaseDigest string        `json:"release_digest"`
	Kind          RuntimeObjectKind `json:"kind"`
	Execution     ExecutionKind `json:"execution"`
	DataClasses   []string      `json:"data_classes,omitempty"`
}

func (object RuntimeObject) Validate() error {
	if !validRuntimeID(object.ID) || !validID(string(object.ExtensionID)) || !validDigest(object.ReleaseDigest) ||
		object.Kind != RuntimeObjectExecution && object.Kind != RuntimeObjectOwnedData ||
		object.Execution != ExecutionWASM && object.Execution != ExecutionRootlessOCI ||
		object.Kind == RuntimeObjectExecution && len(object.DataClasses) != 0 || object.Kind == RuntimeObjectOwnedData && len(object.DataClasses) == 0 {
		return ErrInvalid
	}
	previous := ""
	for _, class := range object.DataClasses {
		if !namePattern.MatchString(class) || class <= previous {
			return ErrInvalid
		}
		previous = class
	}
	return nil
}

// Runtime delegates execution. Implementations may host WASM or rootless OCI,
// but the control plane never receives a shell, raw socket, or credential.
type Runtime interface {
	Apply(context.Context, RuntimeRequest) (RuntimeReceipt, error)
	Inventory(context.Context) ([]RuntimeObject, error)
}

type ReceiptOutcome string

const (
	ReceiptApplied   ReceiptOutcome = "applied"
	ReceiptAmbiguous ReceiptOutcome = "ambiguous"
)

type OperationReceipt struct {
	CommandID        CommandID         `json:"command_id"`
	RequestDigest    string            `json:"request_digest"`
	Action           LifecycleAction   `json:"action"`
	ExtensionID      ExtensionID       `json:"extension_id"`
	ReleaseDigest    string            `json:"release_digest"`
	ExpectedGeneration uint64           `json:"expected_generation"`
	ResultGeneration uint64            `json:"result_generation"`
	Outcome          ReceiptOutcome    `json:"outcome"`
	RuntimeEvidence  string            `json:"runtime_evidence,omitempty"`
	Health           HealthObservation `json:"health"`
	RecordedAt       time.Time         `json:"recorded_at"`
	Digest           string            `json:"digest"`
}

func (receipt OperationReceipt) Validate() error {
	if !validID(string(receipt.CommandID)) || !validDigest(receipt.RequestDigest) || !validLifecycleAction(receipt.Action) ||
		!validID(string(receipt.ExtensionID)) || !validDigest(receipt.ReleaseDigest) || receipt.ResultGeneration != receipt.ExpectedGeneration+1 ||
		receipt.ResultGeneration == 0 || receipt.RecordedAt.IsZero() || receipt.Outcome != ReceiptApplied && receipt.Outcome != ReceiptAmbiguous ||
		receipt.Outcome == ReceiptApplied && (!validDigest(receipt.RuntimeEvidence) || !validHealth(receipt.Health)) ||
		receipt.Outcome == ReceiptAmbiguous && receipt.RuntimeEvidence != "" || digestOperationReceipt(receipt) != receipt.Digest {
		return ErrIntegrity
	}
	return nil
}

func digestOperationReceipt(receipt OperationReceipt) string {
	receipt.Digest = ""
	return digestJSON(receipt)
}

type AuditEvent struct {
	ReceiptDigest string
	CommandID     CommandID
	Action        LifecycleAction
	ExtensionID   ExtensionID
	ReleaseDigest string
	Before        uint64
	After         uint64
	Outcome       ReceiptOutcome
	Actor         string
	OccurredAt    time.Time
}

type AuditSink interface {
	RecordExtensionEvent(context.Context, AuditEvent) error
}

type OrphanKind string

const (
	OrphanUnownedRuntime OrphanKind = "unowned_runtime"
	OrphanMissingRuntime OrphanKind = "missing_runtime"
	OrphanStaleRelease   OrphanKind = "stale_release"
	OrphanUndeclaredData OrphanKind = "undeclared_data"
)

type Orphan struct {
	Kind          OrphanKind   `json:"kind"`
	ExtensionID   ExtensionID  `json:"extension_id"`
	RuntimeObject *RuntimeObject `json:"runtime_object,omitempty"`
	Detail        string       `json:"detail"`
}
