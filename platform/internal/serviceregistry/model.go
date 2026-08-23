package serviceregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	MaxServices        = 32
	MaxDependencies    = 16
	MaxConsumers       = 128
	MaxPlanSteps       = 128
	MaxImpacts         = 256
	MaxEvidenceBytes   = 256 << 10
	MaxReceiptCommands = 128
	MaxGeneration      = uint64(1<<63 - 1)
)

var (
	ErrInvalid             = errors.New("invalid service registry input")
	ErrNotFound            = errors.New("service registry record not found")
	ErrConflict            = errors.New("service registry compare-and-swap conflict")
	ErrStale               = errors.New("stale service inventory or plan generation")
	ErrUnsupported         = errors.New("unsupported service action")
	ErrUnauthorized        = errors.New("service action is not authorized")
	ErrMaintenanceRequired = errors.New("maintenance window is required")
	ErrConsumersPresent    = errors.New("service has active consumers")
	ErrAmbiguous           = errors.New("service state is ambiguous")

	safeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,127}$`)
)

type ServiceID string

const (
	ServiceOpenLiteSpeed ServiceID = "openlitespeed"
	ServiceLiteSpeed     ServiceID = "litespeed_enterprise"
	ServicePowerDNS      ServiceID = "powerdns"
	ServiceMariaDB       ServiceID = "mariadb"
	ServicePostfix       ServiceID = "postfix"
	ServiceDovecot       ServiceID = "dovecot"
	ServiceRspamd        ServiceID = "rspamd"
	ServiceClamAV        ServiceID = "clamav"
	ServiceFTPS          ServiceID = "ftps"
	ServicePHP74         ServiceID = "php74"
	ServicePHP80         ServiceID = "php80"
	ServicePHP81         ServiceID = "php81"
	ServicePHP82         ServiceID = "php82"
	ServicePHP83         ServiceID = "php83"
	ServicePHP84         ServiceID = "php84"
	ServiceRedis         ServiceID = "redis"
	ServiceSearch        ServiceID = "search"
	ServiceContainers    ServiceID = "containers"
	ServiceScheduler     ServiceID = "scheduler"
	ServiceNodeAgent     ServiceID = "node_agent"
	ServicePanelCore     ServiceID = "panel_core"
	ServicePanelGateway  ServiceID = "panel_gateway"
)

type Action string

const (
	ActionInspect Action = "inspect"
	ActionStart   Action = "start"
	ActionStop    Action = "stop"
	ActionRestart Action = "restart"
	ActionReload  Action = "reload"
	ActionEnable  Action = "enable"
	ActionDisable Action = "disable"
	ActionInstall Action = "install"
	ActionRemove  Action = "remove"
	ActionRepair  Action = "repair"
)

type OwnershipKind string

const (
	OwnershipPanel    OwnershipKind = "panel"
	OwnershipOS       OwnershipKind = "operating_system"
	OwnershipVendor   OwnershipKind = "vendor"
	OwnershipOperator OwnershipKind = "operator"
)

type Ownership struct {
	Kind          OwnershipKind `json:"kind"`
	Scope         string        `json:"scope"`
	ManagedConfig bool          `json:"managed_config"`
}

type Capabilities struct {
	Lifecycle bool `json:"lifecycle"`
	Reload    bool `json:"reload"`
	Enable    bool `json:"enable"`
	Install   bool `json:"install"`
	Remove    bool `json:"remove"`
	Repair    bool `json:"repair"`
	Stateful  bool `json:"stateful"`
	Critical  bool `json:"critical"`
}

type SupportTuple struct {
	OSFamily           string `json:"os_family"`
	OSVersion          string `json:"os_version"`
	Architecture       string `json:"architecture"`
	ReleaseChannel     string `json:"release_channel"`
	MinVersion         string `json:"min_version,omitempty"`
	MaxVersion         string `json:"max_version,omitempty"`
	QualificationDigest string `json:"qualification_digest"`
}

type ServiceDefinition struct {
	ID               ServiceID       `json:"id"`
	DisplayName      string          `json:"display_name"`
	Capabilities     Capabilities    `json:"capabilities"`
	Dependencies     []ServiceID     `json:"dependencies,omitempty"`
	Consumers        []ServiceID     `json:"consumers,omitempty"`
	Conflicts        []ServiceID     `json:"conflicts,omitempty"`
	Ownership        Ownership       `json:"ownership"`
	ConfigGeneration bool            `json:"config_generation"`
	PackageProfile   string          `json:"package_profile"`
	AllowedActions   []Action        `json:"allowed_actions"`
	Support          []SupportTuple  `json:"support"`
}

type SupportContext struct {
	OSFamily       string `json:"os_family"`
	OSVersion      string `json:"os_version"`
	Architecture   string `json:"architecture"`
	ReleaseChannel string `json:"release_channel"`
}

type InstallState string

const (
	InstallUnknown   InstallState = "unknown"
	InstallAbsent    InstallState = "absent"
	InstallInstalled InstallState = "installed"
)

type EnableState string

const (
	EnableUnknown  EnableState = "unknown"
	EnableDisabled EnableState = "disabled"
	EnableEnabled  EnableState = "enabled"
	EnableStatic   EnableState = "static"
	EnableMasked   EnableState = "masked"
)

type ActiveState string

const (
	ActiveUnknown      ActiveState = "unknown"
	ActiveInactive     ActiveState = "inactive"
	ActiveActivating   ActiveState = "activating"
	ActiveActive       ActiveState = "active"
	ActiveDeactivating ActiveState = "deactivating"
	ActiveFailed       ActiveState = "failed"
)

type HealthState string

const (
	HealthUnknown       HealthState = "unknown"
	HealthHealthy       HealthState = "healthy"
	HealthDegraded      HealthState = "degraded"
	HealthFailed        HealthState = "failed"
	HealthUnsupported   HealthState = "unsupported"
	HealthIndeterminate HealthState = "indeterminate"
)

type DriftState string

const (
	DriftUnknown DriftState = "unknown"
	DriftNone    DriftState = "none"
	DriftPresent DriftState = "present"
)

type ConfigState string

const (
	ConfigUnknown       ConfigState = "unknown"
	ConfigValid         ConfigState = "valid"
	ConfigInvalid       ConfigState = "invalid"
	ConfigUnsupported   ConfigState = "unsupported"
	ConfigIndeterminate ConfigState = "indeterminate"
)

type ProcessIdentity struct {
	BootID        string `json:"boot_id"`
	MainPID       int64  `json:"main_pid"`
	PIDStartTicks uint64 `json:"pid_start_ticks"`
	UID           uint32 `json:"uid"`
	Executable    string `json:"executable"`
	ControlGroup  string `json:"control_group"`
	InvocationID  string `json:"invocation_id"`
}

type DesiredState struct {
	NodeID           string      `json:"node_id"`
	ServiceID        ServiceID   `json:"service_id"`
	Generation       uint64      `json:"generation"`
	ConfigGeneration uint64      `json:"config_generation"`
	Installed        bool        `json:"installed"`
	Enabled          bool        `json:"enabled"`
	Active           ActiveState `json:"active"`
	DefinitionDigest string      `json:"definition_digest"`
	Digest           string      `json:"digest"`
	UpdatedAt        time.Time   `json:"updated_at"`
}

type ServiceObservation struct {
	NodeID                    string          `json:"node_id"`
	ServiceID                 ServiceID       `json:"service_id"`
	Generation                uint64          `json:"generation"`
	ConfigGeneration          uint64          `json:"config_generation"`
	DefinitionDigest          string          `json:"definition_digest"`
	Unit                      string          `json:"unit"`
	LoadState                 string          `json:"load_state"`
	UnitFileState             string          `json:"unit_file_state"`
	SubState                  string          `json:"sub_state"`
	FragmentPath              string          `json:"fragment_path"`
	NeedDaemonReload          bool            `json:"need_daemon_reload"`
	ExecMainStartMonotonic    uint64          `json:"exec_main_start_monotonic"`
	Install                   InstallState    `json:"install"`
	Enable                    EnableState     `json:"enable"`
	Active                    ActiveState     `json:"active"`
	Config                    ConfigState     `json:"config"`
	DependenciesReady         bool            `json:"dependencies_ready"`
	DependencyEvidenceDigest  string          `json:"dependency_evidence_digest"`
	ExpectedListenersOwned    bool            `json:"expected_listeners_owned"`
	InternallyHealthy         bool            `json:"internally_healthy"`
	ExternallyFunctional      bool            `json:"externally_functional"`
	DesiredGenerationObserved bool            `json:"desired_generation_observed"`
	Health                    HealthState     `json:"health"`
	Drift                     DriftState      `json:"drift"`
	Process                   ProcessIdentity `json:"process"`
	EvidenceDigest            string          `json:"evidence_digest"`
	ObservedAt                time.Time       `json:"observed_at"`
}

type ConsumerBinding struct {
	ID          string    `json:"id"`
	ServiceID   ServiceID `json:"service_id,omitempty"`
	Kind        string    `json:"kind"`
	Active      bool      `json:"active"`
	EvidenceRef string    `json:"evidence_ref"`
}

type ConsumerSnapshot struct {
	NodeID         string            `json:"node_id"`
	ServiceID      ServiceID         `json:"service_id"`
	Generation     uint64            `json:"generation"`
	Complete       bool              `json:"complete"`
	Consumers      []ConsumerBinding `json:"consumers"`
	EvidenceDigest string            `json:"evidence_digest"`
	ObservedAt     time.Time         `json:"observed_at"`
}

type Impact struct {
	ServiceID       ServiceID `json:"service_id"`
	ConsumerID      string    `json:"consumer_id,omitempty"`
	Relationship    string    `json:"relationship"`
	Availability    string    `json:"availability"`
	WorkloadRestart bool      `json:"workload_restart"`
	Reason          string    `json:"reason"`
}

type PlanStep struct {
	Index                      int       `json:"index"`
	ServiceID                  ServiceID `json:"service_id"`
	Action                     Action    `json:"action"`
	ExpectedObservedGeneration uint64    `json:"expected_observed_generation"`
	ExpectedConfigGeneration   uint64    `json:"expected_config_generation"`
	Compensate                 Action    `json:"compensate,omitempty"`
	Irreversible               bool      `json:"irreversible"`
	Reason                     string    `json:"reason"`
}

type LifecyclePlan struct {
	ID                         string            `json:"id"`
	NodeID                     string            `json:"node_id"`
	Target                     ServiceID         `json:"target"`
	Action                     Action            `json:"action"`
	Generation                 uint64            `json:"generation"`
	ExpectedDesiredGeneration  uint64            `json:"expected_desired_generation"`
	ExpectedObservedGeneration uint64            `json:"expected_observed_generation"`
	ExpectedConfigGeneration   uint64            `json:"expected_config_generation"`
	RegistryDigest             string            `json:"registry_digest"`
	SupportDigest              string            `json:"support_digest"`
	Steps                      []PlanStep        `json:"steps"`
	Impacts                    []Impact          `json:"impacts"`
	Consumers                  []ConsumerBinding `json:"consumers,omitempty"`
	ConsumerSnapshotGeneration uint64            `json:"consumer_snapshot_generation"`
	ConsumerSnapshotDigest     string            `json:"consumer_snapshot_digest"`
	RequiresStepUp             bool              `json:"requires_step_up"`
	RequiresMaintenance        bool              `json:"requires_maintenance"`
	IrreversibleFrontier       int               `json:"irreversible_frontier"`
	Digest                     string            `json:"digest"`
	CreatedAt                  time.Time         `json:"created_at"`
	ExpiresAt                  time.Time         `json:"expires_at"`
}

type CommandReceipt struct {
	Program      string        `json:"program"`
	ArgvDigest   string        `json:"argv_digest"`
	OutputDigest string        `json:"output_digest"`
	ExitCode     int           `json:"exit_code"`
	TimedOut     bool          `json:"timed_out"`
	Duration     time.Duration `json:"duration"`
}

type ProbeResult struct {
	Kind           string      `json:"kind"`
	State          HealthState `json:"state"`
	EvidenceDigest string      `json:"evidence_digest"`
	ObservedAt     time.Time   `json:"observed_at"`
}

type StepReceipt struct {
	Index              int                `json:"index"`
	ServiceID          ServiceID          `json:"service_id"`
	Action             Action             `json:"action"`
	Before             ServiceObservation `json:"before"`
	After              ServiceObservation `json:"after"`
	Commands           []CommandReceipt   `json:"commands,omitempty"`
	Validation         ProbeResult        `json:"validation"`
	Health             ProbeResult        `json:"health"`
	PackageReceiptRef  string             `json:"package_receipt_ref,omitempty"`
	Compensation       *CommandReceipt    `json:"compensation,omitempty"`
	CompensationResult string             `json:"compensation_result,omitempty"`
	Outcome            string             `json:"outcome"`
	EvidenceDigest     string             `json:"evidence_digest"`
}

type LifecycleReceipt struct {
	ID             string        `json:"id"`
	OperationID    string        `json:"operation_id"`
	PlanID         string        `json:"plan_id"`
	PlanDigest     string        `json:"plan_digest"`
	Outcome        string        `json:"outcome"`
	Steps          []StepReceipt `json:"steps"`
	EvidenceDigest string        `json:"evidence_digest"`
	StartedAt      time.Time     `json:"started_at"`
	CompletedAt    time.Time     `json:"completed_at"`
}

type AuthorizationEvidence struct {
	ActorID             string    `json:"actor_id"`
	DecisionID          string    `json:"decision_id"`
	PlanID              string    `json:"plan_id"`
	PlanDigest          string    `json:"plan_digest"`
	Action              Action    `json:"action"`
	Resource            string    `json:"resource"`
	MFAAt               time.Time `json:"mfa_at"`
	PhishingResistantAt time.Time `json:"phishing_resistant_at"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Digest              string    `json:"digest"`
}

type MaintenanceEvidence struct {
	WindowID  string    `json:"window_id"`
	PlanID    string    `json:"plan_id"`
	PlanDigest string   `json:"plan_digest"`
	NodeID    string    `json:"node_id"`
	Scope     string    `json:"scope"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	ApprovedBy string   `json:"approved_by"`
	Digest    string    `json:"digest"`
}

type AuditEvent struct {
	ID             string    `json:"id"`
	OperationID    string    `json:"operation_id"`
	ActorID        string    `json:"actor_id"`
	Kind           string    `json:"kind"`
	Resource       string    `json:"resource"`
	RequestDigest  string    `json:"request_digest"`
	EvidenceDigest string    `json:"evidence_digest"`
	OccurredAt     time.Time `json:"occurred_at"`
}

func digestValue(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("%w: encode digest input: %v", ErrInvalid, err)
	}
	if len(b) > MaxEvidenceBytes {
		return "", fmt.Errorf("%w: digest input exceeds %d bytes", ErrInvalid, MaxEvidenceBytes)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validID(s string) bool { return safeIDPattern.MatchString(s) }

func validGeneration(generation uint64) bool { return generation > 0 && generation <= MaxGeneration }

func copyAndSortServiceIDs(in []ServiceID) []ServiceID {
	out := append([]ServiceID(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func copyAndSortActions(in []Action) []Action {
	out := append([]Action(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func validateServiceID(id ServiceID) error {
	if !validID(string(id)) {
		return fmt.Errorf("%w: invalid service id", ErrInvalid)
	}
	return nil
}

func ValidateDesiredState(s DesiredState) error {
	if !validID(s.NodeID) || validateServiceID(s.ServiceID) != nil || !validGeneration(s.Generation) || s.ConfigGeneration > MaxGeneration || s.DefinitionDigest == "" || s.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: incomplete desired state", ErrInvalid)
	}
	if s.Active != ActiveActive && s.Active != ActiveInactive {
		return fmt.Errorf("%w: desired active state must be active or inactive", ErrInvalid)
	}
	return nil
}

func SealDesiredState(s DesiredState) (DesiredState, error) {
	if err := ValidateDesiredState(s); err != nil {
		return DesiredState{}, err
	}
	s.Digest = ""
	d, err := digestValue(s)
	if err != nil {
		return DesiredState{}, err
	}
	s.Digest = d
	return s, nil
}

func ValidateObservation(o ServiceObservation) error {
	if !validID(o.NodeID) || validateServiceID(o.ServiceID) != nil || !validGeneration(o.Generation) || o.ConfigGeneration > MaxGeneration || o.DefinitionDigest == "" || o.Unit == "" {
		return fmt.Errorf("%w: incomplete service observation", ErrInvalid)
	}
	if o.ObservedAt.IsZero() || o.EvidenceDigest == "" {
		return fmt.Errorf("%w: observation lacks evidence or timestamp", ErrInvalid)
	}
	sealed, err := SealObservation(o)
	if err != nil || sealed.EvidenceDigest != o.EvidenceDigest {
		return fmt.Errorf("%w: observation evidence digest", ErrInvalid)
	}
	return nil
}

func SealConsumerSnapshot(snapshot ConsumerSnapshot) (ConsumerSnapshot, error) {
	if !validID(snapshot.NodeID) || validateServiceID(snapshot.ServiceID) != nil || !validGeneration(snapshot.Generation) || !snapshot.Complete || len(snapshot.Consumers) > MaxConsumers || snapshot.ObservedAt.IsZero() {
		return ConsumerSnapshot{}, fmt.Errorf("%w: incomplete consumer snapshot", ErrInvalid)
	}
	seenConsumers := make(map[string]bool, len(snapshot.Consumers))
	for _, consumer := range snapshot.Consumers {
		if !validID(consumer.ID) || consumer.Kind == "" || consumer.Kind == "registered_service" || consumer.EvidenceRef == "" {
			return ConsumerSnapshot{}, fmt.Errorf("%w: invalid consumer binding", ErrInvalid)
		}
		if seenConsumers[consumer.ID] {
			return ConsumerSnapshot{}, fmt.Errorf("%w: duplicate consumer binding", ErrInvalid)
		}
		seenConsumers[consumer.ID] = true
	}
	snapshot.Consumers = append([]ConsumerBinding(nil), snapshot.Consumers...)
	sort.Slice(snapshot.Consumers, func(i, j int) bool { return snapshot.Consumers[i].ID < snapshot.Consumers[j].ID })
	snapshot.EvidenceDigest = ""
	d, err := digestValue(snapshot)
	if err != nil {
		return ConsumerSnapshot{}, err
	}
	snapshot.EvidenceDigest = d
	return snapshot, nil
}

func SealObservation(o ServiceObservation) (ServiceObservation, error) {
	if !validID(o.NodeID) || validateServiceID(o.ServiceID) != nil || !validGeneration(o.Generation) || o.ConfigGeneration > MaxGeneration || o.DefinitionDigest == "" || o.Unit == "" || o.ObservedAt.IsZero() {
		return ServiceObservation{}, fmt.Errorf("%w: incomplete service observation", ErrInvalid)
	}
	o.EvidenceDigest = ""
	d, err := digestValue(o)
	if err != nil {
		return ServiceObservation{}, err
	}
	o.EvidenceDigest = d
	return o, nil
}

func ValidatePlan(p LifecyclePlan) error {
	if !validID(p.ID) || !validID(p.NodeID) || validateServiceID(p.Target) != nil || !validGeneration(p.Generation) || p.ExpectedDesiredGeneration > MaxGeneration || !validGeneration(p.ExpectedObservedGeneration) || p.ExpectedConfigGeneration > MaxGeneration {
		return fmt.Errorf("%w: incomplete lifecycle plan", ErrInvalid)
	}
	if p.RegistryDigest == "" || p.SupportDigest == "" || p.Digest == "" || p.CreatedAt.IsZero() || !p.ExpiresAt.After(p.CreatedAt) {
		return fmt.Errorf("%w: lifecycle plan metadata", ErrInvalid)
	}
	if len(p.Steps) == 0 || len(p.Steps) > MaxPlanSteps || len(p.Impacts) > MaxImpacts || len(p.Consumers) > MaxConsumers {
		return fmt.Errorf("%w: lifecycle plan exceeds bounds", ErrInvalid)
	}
	for i, step := range p.Steps {
		if step.Index != i || validateServiceID(step.ServiceID) != nil || !validGeneration(step.ExpectedObservedGeneration) || step.ExpectedConfigGeneration > MaxGeneration {
			return fmt.Errorf("%w: invalid plan step %d", ErrInvalid, i)
		}
	}
	seenConsumers := make(map[string]bool, len(p.Consumers))
	for _, consumer := range p.Consumers {
		if !validID(consumer.ID) || consumer.Kind == "" || consumer.EvidenceRef == "" || seenConsumers[consumer.ID] {
			return fmt.Errorf("%w: invalid plan consumer", ErrInvalid)
		}
		seenConsumers[consumer.ID] = true
	}
	return nil
}

func SealPlan(p LifecyclePlan) (LifecyclePlan, error) {
	p.Digest = ""
	p.Consumers = append([]ConsumerBinding(nil), p.Consumers...)
	sort.Slice(p.Consumers, func(i, j int) bool { return p.Consumers[i].ID < p.Consumers[j].ID })
	d, err := digestValue(p)
	if err != nil {
		return LifecyclePlan{}, err
	}
	p.Digest = d
	if err := ValidatePlan(p); err != nil {
		return LifecyclePlan{}, err
	}
	return p, nil
}

func SealStepReceipt(receipt StepReceipt) (StepReceipt, error) {
	if receipt.Index < 0 || validateServiceID(receipt.ServiceID) != nil || receipt.Action == "" || len(receipt.Commands) > MaxReceiptCommands {
		return StepReceipt{}, fmt.Errorf("%w: invalid step receipt", ErrInvalid)
	}
	if receipt.Outcome != "confirmed" && receipt.Outcome != "failed" && receipt.Outcome != "compensated" && receipt.Outcome != "ambiguous" {
		return StepReceipt{}, fmt.Errorf("%w: invalid step receipt outcome", ErrInvalid)
	}
	if err := ValidateObservation(receipt.Before); err != nil {
		return StepReceipt{}, err
	}
	if err := ValidateObservation(receipt.After); err != nil {
		return StepReceipt{}, err
	}
	if receipt.PackageReceiptRef != "" && !validID(receipt.PackageReceiptRef) {
		return StepReceipt{}, fmt.Errorf("%w: invalid package receipt reference", ErrInvalid)
	}
	receipt.EvidenceDigest = ""
	d, err := digestValue(receipt)
	if err != nil {
		return StepReceipt{}, err
	}
	receipt.EvidenceDigest = d
	return receipt, nil
}

func SealLifecycleReceipt(receipt LifecycleReceipt) (LifecycleReceipt, error) {
	if !validID(receipt.ID) || !validID(receipt.OperationID) || !validID(receipt.PlanID) || receipt.PlanDigest == "" || receipt.Outcome == "" || len(receipt.Steps) == 0 || len(receipt.Steps) > MaxPlanSteps || receipt.StartedAt.IsZero() || receipt.CompletedAt.Before(receipt.StartedAt) {
		return LifecycleReceipt{}, fmt.Errorf("%w: invalid lifecycle receipt", ErrInvalid)
	}
	if receipt.Outcome != "confirmed" && receipt.Outcome != "failed" && receipt.Outcome != "compensated" && receipt.Outcome != "ambiguous" {
		return LifecycleReceipt{}, fmt.Errorf("%w: invalid lifecycle receipt outcome", ErrInvalid)
	}
	for i, step := range receipt.Steps {
		if step.Index != i {
			return LifecycleReceipt{}, fmt.Errorf("%w: non-canonical receipt step order", ErrInvalid)
		}
		sealed, err := SealStepReceipt(step)
		if err != nil || sealed.EvidenceDigest != step.EvidenceDigest {
			return LifecycleReceipt{}, fmt.Errorf("%w: step receipt evidence", ErrInvalid)
		}
	}
	receipt.EvidenceDigest = ""
	d, err := digestValue(receipt)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	receipt.EvidenceDigest = d
	return receipt, nil
}

func ValidateAuthorization(e AuthorizationEvidence, plan LifecyclePlan, now time.Time, phishingResistant bool) error {
	if !validID(e.ActorID) || !validID(e.DecisionID) || e.PlanID != plan.ID || e.PlanDigest != plan.Digest || e.Action != plan.Action || e.Resource != plan.NodeID+":"+string(plan.Target) {
		return fmt.Errorf("%w: authorization binding mismatch", ErrUnauthorized)
	}
	if e.IssuedAt.IsZero() || now.Before(e.IssuedAt) || !now.Before(e.ExpiresAt) {
		return fmt.Errorf("%w: authorization is stale", ErrUnauthorized)
	}
	if plan.RequiresStepUp && (e.MFAAt.IsZero() || now.Before(e.MFAAt) || now.Sub(e.MFAAt) > 15*time.Minute) {
		return fmt.Errorf("%w: recent MFA step-up required", ErrUnauthorized)
	}
	if phishingResistant && (e.PhishingResistantAt.IsZero() || now.Before(e.PhishingResistantAt) || now.Sub(e.PhishingResistantAt) > 15*time.Minute) {
		return fmt.Errorf("%w: phishing-resistant step-up required", ErrUnauthorized)
	}
	sealed := e
	sealed.Digest = ""
	d, err := digestValue(sealed)
	if err != nil || !strings.EqualFold(d, e.Digest) {
		return fmt.Errorf("%w: authorization evidence digest", ErrUnauthorized)
	}
	return nil
}

func SealAuthorizationEvidence(e AuthorizationEvidence) (AuthorizationEvidence, error) {
	if !validID(e.ActorID) || !validID(e.DecisionID) || !validID(e.PlanID) || e.PlanDigest == "" || e.Action == "" || e.Resource == "" || e.IssuedAt.IsZero() || !e.ExpiresAt.After(e.IssuedAt) {
		return AuthorizationEvidence{}, fmt.Errorf("%w: incomplete authorization evidence", ErrInvalid)
	}
	e.Digest = ""
	d, err := digestValue(e)
	if err != nil {
		return AuthorizationEvidence{}, err
	}
	e.Digest = d
	return e, nil
}

func ValidateMaintenance(e MaintenanceEvidence, plan LifecyclePlan, now time.Time) error {
	if !validID(e.WindowID) || !validID(e.ApprovedBy) || e.PlanID != plan.ID || e.PlanDigest != plan.Digest || e.NodeID != plan.NodeID || e.Scope != "service:"+string(plan.Target) || now.Before(e.StartsAt) || !now.Before(e.EndsAt) {
		return fmt.Errorf("%w: window does not cover plan", ErrMaintenanceRequired)
	}
	sealed := e
	sealed.Digest = ""
	d, err := digestValue(sealed)
	if err != nil || !strings.EqualFold(d, e.Digest) {
		return fmt.Errorf("%w: maintenance evidence digest", ErrMaintenanceRequired)
	}
	return nil
}

func SealMaintenanceEvidence(e MaintenanceEvidence) (MaintenanceEvidence, error) {
	if !validID(e.WindowID) || !validID(e.PlanID) || e.PlanDigest == "" || !validID(e.NodeID) || !validID(e.ApprovedBy) || e.Scope == "" || e.StartsAt.IsZero() || !e.EndsAt.After(e.StartsAt) {
		return MaintenanceEvidence{}, fmt.Errorf("%w: incomplete maintenance evidence", ErrInvalid)
	}
	e.Digest = ""
	d, err := digestValue(e)
	if err != nil {
		return MaintenanceEvidence{}, err
	}
	e.Digest = d
	return e, nil
}
