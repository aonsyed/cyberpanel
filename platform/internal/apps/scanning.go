package apps

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type ScanMode string

const (
	ScanUploadEvent ScanMode = "upload_event"
	ScanQuick       ScanMode = "quick"
	ScanFull        ScanMode = "full"
	ScanCustom      ScanMode = "custom"
	ScanScheduled   ScanMode = "scheduled"
	ScanPostRestore ScanMode = "post_restore"
	ScanIntegrity   ScanMode = "integrity_comparison"
)

type ScanState string

const (
	ScanAdmitted   ScanState = "admitted"
	ScanSnapshotting ScanState = "snapshotting"
	ScanQueued     ScanState = "queued"
	ScanRunning    ScanState = "running"
	ScanCompleted  ScanState = "completed"
	ScanFailed     ScanState = "failed"
	ScanCancelled  ScanState = "cancelled"
)

type ScannerKind string

const (
	ScannerLocal    ScannerKind = "local"
	ScannerCommercial ScannerKind = "commercial"
	ScannerExternalAI ScannerKind = "external_ai"
)

type ScanBudget struct {
	MaximumDuration      time.Duration `json:"maximum_duration"`
	MaximumFiles         uint64 `json:"maximum_files"`
	MaximumBytes         uint64 `json:"maximum_bytes"`
	MaximumExpandedBytes uint64 `json:"maximum_expanded_bytes"`
	MaximumArchiveDepth  uint8 `json:"maximum_archive_depth"`
	MaximumMemoryBytes   uint64 `json:"maximum_memory_bytes"`
	MaximumCPUPercent    uint8 `json:"maximum_cpu_percent"`
	MaximumIOBytesPerSecond uint64 `json:"maximum_io_bytes_per_second"`
}

func (budget ScanBudget) Validate() error {
	if budget.MaximumDuration <= 0 || budget.MaximumDuration > 24*time.Hour || budget.MaximumFiles == 0 || budget.MaximumBytes == 0 || budget.MaximumExpandedBytes < budget.MaximumBytes || budget.MaximumArchiveDepth > 16 || budget.MaximumMemoryBytes < 32<<20 || budget.MaximumCPUPercent == 0 || budget.MaximumCPUPercent > 100 || budget.MaximumIOBytesPerSecond == 0 {
		return fmt.Errorf("%w: scan budget", ErrInvalid)
	}
	return nil
}

type DataEgressConsent struct {
	ConsentID   string `json:"consent_id"`
	TenantID    TenantID `json:"tenant_id"`
	Provider    string `json:"provider"`
	Purpose     string `json:"purpose"`
	Region      string `json:"region"`
	Retention   time.Duration `json:"retention"`
	DeletionPolicy string `json:"deletion_policy"`
	GrantedAt   time.Time `json:"granted_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (consent DataEgressConsent) Validate(now time.Time) error {
	if !validID(consent.ConsentID) || !validID(string(consent.TenantID)) || consent.Provider == "" || consent.Purpose == "" || consent.Region == "" || consent.DeletionPolicy == "" || consent.Retention < 0 || consent.GrantedAt.IsZero() || !now.Before(consent.ExpiresAt) {
		return fmt.Errorf("%w: data egress consent", ErrPolicyDenied)
	}
	return nil
}

type ScanPolicy struct {
	InstallationID InstallationID `json:"installation_id"`
	Enabled        bool `json:"enabled"`
	Modes          []ScanMode `json:"modes"`
	Schedule       string `json:"schedule,omitempty"`
	ProviderID     string `json:"provider_id"`
	AutoQuarantine bool `json:"auto_quarantine"`
	AutoQuarantineMinimumConfidence float64 `json:"auto_quarantine_minimum_confidence"`
	IgnoredSignatures []string `json:"ignored_signatures,omitempty"`
	Budget         ScanBudget `json:"budget"`
	Generation     uint64 `json:"generation"`
}

func (policy ScanPolicy) Validate() error {
	if err := requireID("installation", string(policy.InstallationID)); err != nil { return err }
	if policy.ProviderID == "" || !validID(policy.ProviderID) || policy.Generation == 0 || policy.AutoQuarantineMinimumConfidence < 0 || policy.AutoQuarantineMinimumConfidence > 1 || len(policy.Modes) == 0 {
		return fmt.Errorf("%w: scan policy", ErrInvalid)
	}
	if err := policy.Budget.Validate(); err != nil { return err }
	seen := map[ScanMode]struct{}{}
	for _, mode := range policy.Modes {
		switch mode { case ScanUploadEvent, ScanQuick, ScanFull, ScanCustom, ScanScheduled, ScanPostRestore, ScanIntegrity: default: return fmt.Errorf("%w: scan mode", ErrInvalid) }
		if _, exists := seen[mode]; exists { return fmt.Errorf("%w: duplicate scan mode", ErrInvalid) }
		seen[mode] = struct{}{}
	}
	if _, scheduled := seen[ScanScheduled]; scheduled && strings.TrimSpace(policy.Schedule) == "" { return fmt.Errorf("%w: scheduled scan expression", ErrInvalid) }
	return nil
}

type ScanRun struct {
	ID              ScanRunID `json:"id"`
	CommandID       CommandID `json:"command_id"`
	TenantID        TenantID `json:"tenant_id"`
	SiteID          SiteID `json:"site_id"`
	InstallationID  InstallationID `json:"installation_id"`
	Mode            ScanMode `json:"mode"`
	ProviderID      string `json:"provider_id"`
	ProviderKind    ScannerKind `json:"provider_kind"`
	SnapshotID      SnapshotID `json:"snapshot_id"`
	SnapshotDigest  string `json:"snapshot_digest"`
	RulesVersion    string `json:"rules_version"`
	EngineVersion   string `json:"engine_version"`
	ModelVersion    string `json:"model_version,omitempty"`
	PromptDigest    string `json:"prompt_digest,omitempty"`
	CustomPaths     []RelativePath `json:"custom_paths,omitempty"`
	Budget          ScanBudget `json:"budget"`
	State           ScanState `json:"state"`
	FilesScanned    uint64 `json:"files_scanned"`
	BytesScanned    uint64 `json:"bytes_scanned"`
	Findings        uint64 `json:"findings"`
	Progress        uint8 `json:"progress"`
	Failure         string `json:"failure,omitempty"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	CompletedAt     time.Time `json:"completed_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (run ScanRun) Validate() error {
	if err := requireID("scan", string(run.ID)); err != nil { return err }
	if err := requireID("command", string(run.CommandID)); err != nil { return err }
	if err := requireID("tenant", string(run.TenantID)); err != nil { return err }
	if err := requireID("site", string(run.SiteID)); err != nil { return err }
	if err := requireID("installation", string(run.InstallationID)); err != nil { return err }
	if !validID(run.ProviderID) || run.RulesVersion == "" || run.EngineVersion == "" || run.Progress > 100 || run.CreatedAt.IsZero() || run.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: scan run", ErrInvalid)
	}
	switch run.State { case ScanAdmitted,ScanSnapshotting,ScanQueued,ScanRunning,ScanCompleted,ScanFailed,ScanCancelled:default:return fmt.Errorf("%w: scan state",ErrInvalid) }
	if (run.State == ScanRunning || run.State == ScanCompleted) && !validDigest(run.SnapshotDigest) { return fmt.Errorf("%w: scan snapshot", ErrInvalid) }
	if run.SnapshotDigest != "" && !validDigest(run.SnapshotDigest) { return fmt.Errorf("%w: scan snapshot", ErrInvalid) }
	return run.Budget.Validate()
}

type FindingSeverity string

const (
	SeverityInformational FindingSeverity = "informational"
	SeverityLow FindingSeverity = "low"
	SeverityMedium FindingSeverity = "medium"
	SeverityHigh FindingSeverity = "high"
	SeverityCritical FindingSeverity = "critical"
)

type FindingState string

const (
	FindingOpen       FindingState = "open"
	FindingAccepted   FindingState = "accepted"
	FindingRemediated FindingState = "remediated"
	FindingFalsePositive FindingState = "false_positive"
	FindingSuperseded FindingState = "superseded"
)

type Finding struct {
	ID             FindingID `json:"id"`
	ScanRunID      ScanRunID `json:"scan_run_id"`
	TenantID       TenantID `json:"tenant_id"`
	SiteID         SiteID `json:"site_id"`
	InstallationID InstallationID `json:"installation_id"`
	Path           RelativePath `json:"path"`
	Resource       string `json:"resource,omitempty"`
	ContentDigest  string `json:"content_digest"`
	SignatureID    string `json:"signature_id"`
	Reason         string `json:"reason"`
	Severity       FindingSeverity `json:"severity"`
	Confidence     float64 `json:"confidence"`
	EvidenceRef    string `json:"evidence_ref"`
	EvidenceDigest string `json:"evidence_digest"`
	Scanner        string `json:"scanner"`
	ScannerVersion string `json:"scanner_version"`
	State          FindingState `json:"state"`
	SuppressedBy   string `json:"suppressed_by,omitempty"`
	SuppressionReason string `json:"suppression_reason,omitempty"`
	SuppressedUntil time.Time `json:"suppressed_until,omitempty"`
	FirstSeenAt    time.Time `json:"first_seen_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	Generation     uint64 `json:"generation"`
}

func (finding Finding) Validate() error {
	if err := requireID("finding", string(finding.ID)); err != nil { return err }
	if err := requireID("scan", string(finding.ScanRunID)); err != nil { return err }
	if err := requireID("tenant", string(finding.TenantID)); err != nil { return err }
	if err := requireID("site", string(finding.SiteID)); err != nil { return err }
	if err := requireID("installation", string(finding.InstallationID)); err != nil { return err }
	if !validDigest(finding.ContentDigest) || !validDigest(finding.EvidenceDigest) || finding.SignatureID == "" || strings.TrimSpace(finding.Reason) == "" || finding.Confidence < 0 || finding.Confidence > 1 || finding.EvidenceRef == "" || finding.Scanner == "" || finding.ScannerVersion == "" || finding.FirstSeenAt.IsZero() || finding.LastSeenAt.IsZero() || finding.Generation == 0 {
		return fmt.Errorf("%w: finding", ErrInvalid)
	}
	if finding.State == FindingAccepted {
		if !validID(finding.SuppressedBy) || strings.TrimSpace(finding.SuppressionReason) == "" || len(finding.SuppressionReason) > 1024 { return fmt.Errorf("%w: finding suppression", ErrInvalid) }
	} else if finding.SuppressedBy != "" || finding.SuppressionReason != "" || !finding.SuppressedUntil.IsZero() {
		return fmt.Errorf("%w: inactive finding suppression", ErrInvalid)
	}
	switch finding.State { case FindingOpen,FindingAccepted,FindingRemediated,FindingFalsePositive,FindingSuperseded:default:return fmt.Errorf("%w: finding state",ErrInvalid) }
	return nil
}

type RemediationAction string

const (
	RemediationQuarantine RemediationAction = "quarantine"
	RemediationRestoreKnownGood RemediationAction = "restore_known_good"
	RemediationReplaceSignedComponent RemediationAction = "replace_signed_component"
	RemediationRepairConfiguration RemediationAction = "repair_configuration"
	RemediationRevokeCredential RemediationAction = "revoke_credential"
)

type RemediationState string

const (
	RemediationProposed RemediationState = "proposed"
	RemediationApproved RemediationState = "approved"
	RemediationExecuting RemediationState = "executing"
	RemediationVerifying RemediationState = "verifying"
	RemediationCommitted RemediationState = "committed"
	RemediationRolledBack RemediationState = "rolled_back"
	RemediationFailed RemediationState = "failed"
)

type RemediationPlan struct {
	ID               RemediationPlanID `json:"id"`
	CommandID        CommandID `json:"command_id"`
	TenantID         TenantID `json:"tenant_id"`
	SiteID           SiteID `json:"site_id"`
	InstallationID   InstallationID `json:"installation_id"`
	FindingIDs       []FindingID `json:"finding_ids"`
	Action           RemediationAction `json:"action"`
	Paths            []RelativePath `json:"paths,omitempty"`
	ExpectedDigests  map[string]string `json:"expected_digests"`
	Replacement      *ComponentRelease `json:"replacement,omitempty"`
	RecoveryPointID  RecoveryPointID `json:"recovery_point_id"`
	QuarantineRef    string `json:"quarantine_ref,omitempty"`
	ApprovedBy       string `json:"approved_by"`
	ApprovalDigest   string `json:"approval_digest"`
	State            RemediationState `json:"state"`
	PostScanRunID    ScanRunID `json:"post_scan_run_id,omitempty"`
	Failure          string `json:"failure,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Generation       uint64 `json:"generation"`
}

func (plan RemediationPlan) Validate() error {
	if err := requireID("remediation", string(plan.ID)); err != nil { return err }
	if err := requireID("command", string(plan.CommandID)); err != nil { return err }
	if err := requireID("tenant", string(plan.TenantID)); err != nil { return err }
	if err := requireID("site", string(plan.SiteID)); err != nil { return err }
	if err := requireID("installation", string(plan.InstallationID)); err != nil { return err }
	if len(plan.FindingIDs) == 0 || len(plan.ExpectedDigests) == 0 || plan.RecoveryPointID == "" || plan.ApprovedBy == "" || !validDigest(plan.ApprovalDigest) || plan.CreatedAt.IsZero() || plan.UpdatedAt.IsZero() || plan.Generation == 0 {
		return fmt.Errorf("%w: remediation plan", ErrInvalid)
	}
	for path, digest := range plan.ExpectedDigests {
		if _, err := ParseRelativePath(path); err != nil || !validDigest(digest) { return fmt.Errorf("%w: remediation precondition", ErrInvalid) }
	}
	return nil
}

type ScanRequest struct {
	Scope          SiteExecutionScope `json:"scope"`
	InstallationID InstallationID `json:"installation_id"`
	RunID          ScanRunID `json:"run_id"`
	Snapshot       Snapshot `json:"snapshot"`
	Mode           ScanMode `json:"mode"`
	CustomPaths    []RelativePath `json:"custom_paths,omitempty"`
	Budget         ScanBudget `json:"budget"`
	RulesVersion   string `json:"rules_version"`
}

type ScanResult struct {
	RunID        ScanRunID `json:"run_id"`
	Findings     []Finding `json:"findings"`
	FilesScanned uint64 `json:"files_scanned"`
	BytesScanned uint64 `json:"bytes_scanned"`
	ResultDigest string `json:"result_digest"`
	CompletedAt  time.Time `json:"completed_at"`
}

type ScannerProvider interface {
	ID() string
	Kind() ScannerKind
	Scan(context.Context, ScanRequest, *DataEgressConsent) (ScanResult, error)
}

type RemediationExecution struct {
	Scope          SiteExecutionScope `json:"scope"`
	InstallationID InstallationID `json:"installation_id"`
	Plan           RemediationPlan `json:"plan"`
	SnapshotID     SnapshotID `json:"snapshot_id"`
}

type RemediationExecutor interface {
	ApplyRemediation(context.Context, RemediationExecution) (ExecutionReceipt, error)
	RollbackRemediation(context.Context, RemediationExecution) (ExecutionReceipt, error)
}

type ScanStore interface {
	SaveScanPolicy(context.Context, ScanPolicy, uint64) error
	LoadScanPolicy(context.Context, InstallationID) (ScanPolicy, error)
	CreateScan(context.Context, ScanRun) error
	UpdateScan(context.Context, ScanRun) error
	LoadScan(context.Context, ScanRunID) (ScanRun, error)
	SaveFindings(context.Context, ScanRunID, []Finding) error
	ListFindings(context.Context, InstallationID, FindingState, uint16, string) ([]Finding, string, error)
	ListScopedFindings(context.Context, TenantID, InstallationID, FindingState, uint16, string) ([]Finding, string, error)
	LoadFinding(context.Context, FindingID) (Finding, error)
	UpdateFinding(context.Context, Finding, uint64) error
	CreateRemediation(context.Context, RemediationPlan) error
	UpdateRemediation(context.Context, RemediationPlan) error
	LoadRemediation(context.Context, RemediationPlanID) (RemediationPlan, error)
}
