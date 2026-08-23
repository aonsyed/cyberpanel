package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"time"
)

type EffectKind string

const (
	EffectResourceProfile EffectKind = "apply_resource_profile"
	EffectTransferReset EffectKind = "reset_transfer_month"
	EffectTransferSample EffectKind = "record_transfer_sample"
	EffectFirewallPolicy EffectKind = "replace_firewall_policy"
	EffectSSHPolicy EffectKind = "replace_ssh_policy"
	EffectPutSSHKey EffectKind = "put_ssh_key"
	EffectDeleteSSHKey EffectKind = "delete_ssh_key"
	EffectWAFPolicy EffectKind = "replace_waf_policy"
	EffectServicePolicy EffectKind = "set_service_policy"
	EffectServiceControl EffectKind = "control_service"
	EffectServiceDiagnose EffectKind = "diagnose_service"
	EffectServiceRepair EffectKind = "repair_service"
	EffectMetricsQuery EffectKind = "query_metrics"
	EffectLogQuery EffectKind = "query_logs"
	EffectSSHLoginQuery EffectKind = "query_ssh_logins"
	EffectSSHSessionQuery EffectKind = "query_ssh_sessions"
	EffectProcessInvestigate EffectKind = "investigate_process"
	EffectProcessTerminate EffectKind = "terminate_process"
	EffectPackageTransaction EffectKind = "package_transaction"
	EffectManagedService EffectKind = "reconcile_managed_service"
)

type ActivationStrategy string

const (
	ActivationAtomic ActivationStrategy = "atomic_replace"
	ActivationMakeBeforeBreak ActivationStrategy = "make_before_break"
	ActivationCompileProbeSwap ActivationStrategy = "compile_probe_swap"
)

type ResourceProfileEffect struct { Profile ResourceProfile `json:"profile"` }
type TransferResetEffect struct { Account TransferAccount `json:"account"` }
type TransferSampleEffect struct { Account TransferAccount `json:"account"` }
type FirewallPolicyEffect struct { Policy FirewallPolicy `json:"policy"`; Strategy ActivationStrategy `json:"strategy"` }
type SSHPolicyEffect struct { Policy SSHPolicy `json:"policy"`; Strategy ActivationStrategy `json:"strategy"` }
type PutSSHKeyEffect struct { Key SSHKey `json:"key"` }
type DeleteSSHKeyEffect struct { Key SSHKey `json:"key"` }
type WAFPolicyEffect struct { Policy WAFPolicy `json:"policy"`; Strategy ActivationStrategy `json:"strategy"` }
type ServicePolicyEffect struct { Policy ServicePolicy `json:"policy"` }
type ServiceControlEffect struct { Service ServiceName `json:"service"`; Action ServiceAction `json:"action"`; PolicyGeneration uint64 `json:"policy_generation"` }
type ServiceDiagnoseEffect struct { Service ServiceName `json:"service"`; Depth DiagnosticDepth `json:"depth"`; Since time.Time `json:"since"` }
type ServiceRepairEffect struct { Service ServiceName `json:"service"`; Strategy RepairStrategy `json:"strategy"`; DiagnosticProofDigest string `json:"diagnostic_proof_digest"` }
type MetricsQueryEffect struct { Scope EnforcementScope `json:"scope"`; Names []MetricName `json:"names"`; Start time.Time `json:"start"`; End time.Time `json:"end"`; Step time.Duration `json:"step"`; Limit uint32 `json:"limit"` }
type LogQueryEffect struct { Source LogSource `json:"source"`; Service ServiceName `json:"service,omitempty"`; TenantID string `json:"tenant_id,omitempty"`; SiteID string `json:"site_id,omitempty"`; Start time.Time `json:"start"`; End time.Time `json:"end"`; MinimumSeverity uint8 `json:"minimum_severity"`; Cursor string `json:"cursor,omitempty"`; Limit uint32 `json:"limit"` }
type SSHLoginQueryEffect struct { Start time.Time `json:"start"`; End time.Time `json:"end"`; SourceCIDR *netip.Prefix `json:"source_cidr,omitempty"`; Limit uint32 `json:"limit"` }
type SSHSessionQueryEffect struct { IncludeClosedSince time.Time `json:"include_closed_since"`; Limit uint32 `json:"limit"` }
type ProcessInvestigateEffect struct { Process ProcessIdentity `json:"process"`; IncludeFileDescriptors bool `json:"include_file_descriptors"`; IncludeNetworkSockets bool `json:"include_network_sockets"` }
type ProcessTerminateEffect struct { Process ProcessIdentity `json:"process"`; Signal TerminationSignal `json:"signal"`; InvestigationProofDigest string `json:"investigation_proof_digest"`; ReasonCode ResourceID `json:"reason_code"` }
type PackageTransactionEffect struct { Transaction PackageTransaction `json:"transaction"` }
type ManagedRedisDataAction string

const (
	ManagedRedisSnapshot ManagedRedisDataAction = "snapshot"
	ManagedRedisRestore  ManagedRedisDataAction = "restore"
	ManagedRedisPurge    ManagedRedisDataAction = "purge"
)

const managedRedisMaximumArtifactBytes = int64(64 << 30)

type ManagedRedisArtifact struct {
	ID               string    `json:"id"`
	GroupID          string    `json:"group_id"`
	InstanceID       ResourceID `json:"instance_id"`
	Kind             string    `json:"kind"`
	RedisVersion     string    `json:"redis_version"`
	ConfigGeneration uint64    `json:"config_generation"`
	SizeBytes        int64     `json:"size_bytes,omitempty"`
	SHA256           string    `json:"sha256,omitempty"`
	CreatedAt        time.Time `json:"created_at,omitempty"`
}

type ManagedRedisDataEffect struct {
	Action                     ManagedRedisDataAction `json:"action"`
	ExpectedSpecGeneration     uint64                 `json:"expected_spec_generation"`
	ExpectedConfigGeneration   uint64                 `json:"expected_config_generation"`
	ExpectedConsumerGeneration uint64                 `json:"expected_consumer_generation,omitempty"`
	Artifact                   ManagedRedisArtifact   `json:"artifact,omitempty"`
	RecoveryArtifact           ManagedRedisArtifact   `json:"recovery_artifact,omitempty"`
}

type ManagedServiceEffect struct {
	Service   ManagedService          `json:"service"`
	RedisData *ManagedRedisDataEffect `json:"redis_data,omitempty"`
}

type EffectRequest struct {
	EffectID string `json:"effect_id"`
	RequestDigest string `json:"request_digest"`
	Scope OperationScope `json:"scope"`
	Kind EffectKind `json:"kind"`
	ResourceProfile *ResourceProfileEffect `json:"resource_profile,omitempty"`
	TransferReset *TransferResetEffect `json:"transfer_reset,omitempty"`
	TransferSample *TransferSampleEffect `json:"transfer_sample,omitempty"`
	FirewallPolicy *FirewallPolicyEffect `json:"firewall_policy,omitempty"`
	SSHPolicy *SSHPolicyEffect `json:"ssh_policy,omitempty"`
	PutSSHKey *PutSSHKeyEffect `json:"put_ssh_key,omitempty"`
	DeleteSSHKey *DeleteSSHKeyEffect `json:"delete_ssh_key,omitempty"`
	WAFPolicy *WAFPolicyEffect `json:"waf_policy,omitempty"`
	ServicePolicy *ServicePolicyEffect `json:"service_policy,omitempty"`
	ServiceControl *ServiceControlEffect `json:"service_control,omitempty"`
	ServiceDiagnose *ServiceDiagnoseEffect `json:"service_diagnose,omitempty"`
	ServiceRepair *ServiceRepairEffect `json:"service_repair,omitempty"`
	MetricsQuery *MetricsQueryEffect `json:"metrics_query,omitempty"`
	LogQuery *LogQueryEffect `json:"log_query,omitempty"`
	SSHLoginQuery *SSHLoginQueryEffect `json:"ssh_login_query,omitempty"`
	SSHSessionQuery *SSHSessionQueryEffect `json:"ssh_session_query,omitempty"`
	ProcessInvestigate *ProcessInvestigateEffect `json:"process_investigate,omitempty"`
	ProcessTerminate *ProcessTerminateEffect `json:"process_terminate,omitempty"`
	PackageTransaction *PackageTransactionEffect `json:"package_transaction,omitempty"`
	ManagedService *ManagedServiceEffect `json:"managed_service,omitempty"`
}

type EffectOutcome string

const (
	EffectConfirmed EffectOutcome = "confirmed"
	EffectRejected EffectOutcome = "rejected"
	EffectAmbiguous EffectOutcome = "ambiguous"
)

type MetricPoint struct { Name MetricName `json:"name"`; Service ServiceName `json:"service,omitempty"`; At time.Time `json:"at"`; Value float64 `json:"value"`; Unit MetricUnit `json:"unit"`; Available bool `json:"available"`; Status string `json:"status,omitempty"`; UnavailableReason string `json:"unavailable_reason,omitempty"` }
type MetricUnit string
const (
	UnitRatio MetricUnit = "ratio"
	UnitBytes MetricUnit = "bytes"
	UnitCount MetricUnit = "count"
	UnitBytesPerSecond MetricUnit = "bytes_per_second"
)

type MetricsBatch struct { Scope EnforcementScope `json:"scope"`; ObservedAt time.Time `json:"observed_at"`; Points []MetricPoint `json:"points"`; Available bool `json:"available"`; UnavailableReason string `json:"unavailable_reason,omitempty"`; Truncated bool `json:"truncated"` }

type LogEntry struct {
	Cursor string `json:"cursor"`
	At time.Time `json:"at"`
	Source LogSource `json:"source"`
	Severity uint8 `json:"severity"`
	EventCode string `json:"event_code"`
	Message string `json:"message"`
	Process ProcessIdentity `json:"process,omitempty"`
}
type LogBatch struct { ObservedAt time.Time `json:"observed_at"`; Entries []LogEntry `json:"entries"`; NextCursor string `json:"next_cursor,omitempty"`; BytesRead uint64 `json:"bytes_read"`; Available bool `json:"available"`; UnavailableReason string `json:"unavailable_reason,omitempty"`; Truncated bool `json:"truncated"` }

type SSHLoginOutcome string
const (
	SSHLoginAccepted SSHLoginOutcome = "accepted"
	SSHLoginRejected SSHLoginOutcome = "rejected"
	SSHLoginDisconnected SSHLoginOutcome = "disconnected"
)
type SSHLoginRecord struct { At time.Time `json:"at"`; PrincipalID ResourceID `json:"principal_id,omitempty"`; Source netip.Addr `json:"source"`; Authentication SSHAuthentication `json:"authentication"`; Outcome SSHLoginOutcome `json:"outcome"`; SessionID ResourceID `json:"session_id,omitempty"`; ReasonCode string `json:"reason_code,omitempty"` }
type SSHLoginBatch struct { Records []SSHLoginRecord `json:"records"`; Truncated bool `json:"truncated"` }

type SSHSession struct { ID ResourceID `json:"id"`; PrincipalID ResourceID `json:"principal_id"`; Source netip.Addr `json:"source"`; StartedAt time.Time `json:"started_at"`; LastActivityAt time.Time `json:"last_activity_at"`; ClosedAt time.Time `json:"closed_at,omitempty"`; Processes []ProcessIdentity `json:"processes"` }
type SSHSessionBatch struct { Sessions []SSHSession `json:"sessions"`; Truncated bool `json:"truncated"` }

type SocketProtocol string
const (
	SocketTCP SocketProtocol = "tcp"
	SocketUDP SocketProtocol = "udp"
	SocketUnix SocketProtocol = "unix"
)
type ProcessSocket struct { Protocol SocketProtocol `json:"protocol"`; LocalAddress netip.AddrPort `json:"local_address,omitempty"`; RemoteAddress netip.AddrPort `json:"remote_address,omitempty"`; State string `json:"state,omitempty"` }
type ProcessReport struct {
	Identity ProcessIdentity `json:"identity"`
	PrincipalID ResourceID `json:"principal_id,omitempty"`
	SystemUserID uint32 `json:"system_user_id"`
	SystemGroupID uint32 `json:"system_group_id"`
	ExecutablePackage ResourceID `json:"executable_package,omitempty"`
	ExecutableDigest string `json:"executable_digest,omitempty"`
	Parent *ProcessIdentity `json:"parent,omitempty"`
	CPUTime time.Duration `json:"cpu_time"`
	ResidentBytes uint64 `json:"resident_bytes"`
	OpenFileDescriptorCount uint32 `json:"open_file_descriptor_count"`
	Sockets []ProcessSocket `json:"sockets,omitempty"`
	CgroupScope ResourceID `json:"cgroup_scope,omitempty"`
}

type DiagnosticCheck struct { Code string `json:"code"`; Outcome CheckOutcome `json:"outcome"`; EvidenceDigest string `json:"evidence_digest"` }
type CheckOutcome string
const (
	CheckPass CheckOutcome = "pass"
	CheckWarn CheckOutcome = "warn"
	CheckFail CheckOutcome = "fail"
)
type ServiceDiagnostics struct { Service ServiceName `json:"service"`; ActiveState string `json:"active_state"`; SubState string `json:"sub_state"`; RestartCount uint32 `json:"restart_count"`; Checks []DiagnosticCheck `json:"checks"`; SuggestedRepairs []RepairStrategy `json:"suggested_repairs"` }

type PackageChange struct { Name ResourceID `json:"name"`; Architecture ResourceID `json:"architecture"`; FromVersion string `json:"from_version,omitempty"`; ToVersion string `json:"to_version,omitempty"`; Action PackageAction `json:"action"` }
type PackageTransactionResult struct { Changes []PackageChange `json:"changes"`; RebootRequired bool `json:"reboot_required"`; ServicesRestarted []ServiceName `json:"services_restarted"`; RecoveryValidated bool `json:"recovery_validated"` }

type EffectResult struct {
	Metrics *MetricsBatch `json:"metrics,omitempty"`
	Logs *LogBatch `json:"logs,omitempty"`
	SSHLogins *SSHLoginBatch `json:"ssh_logins,omitempty"`
	SSHSessions *SSHSessionBatch `json:"ssh_sessions,omitempty"`
	Process *ProcessReport `json:"process,omitempty"`
	Diagnostics *ServiceDiagnostics `json:"diagnostics,omitempty"`
	Packages *PackageTransactionResult `json:"packages,omitempty"`
	ManagedRedisData *ManagedRedisDataResult `json:"managed_redis_data,omitempty"`
}

type ManagedRedisDataResult struct {
	Action         ManagedRedisDataAction `json:"action"`
	Artifact       *ManagedRedisArtifact  `json:"artifact,omitempty"`
	EvidenceDigest string                 `json:"evidence_digest"`
}

type EffectReceipt struct {
	EffectID string `json:"effect_id"`
	RequestDigest string `json:"request_digest"`
	Outcome EffectOutcome `json:"outcome"`
	MutationObserved bool `json:"mutation_observed"`
	ProofDigest string `json:"proof_digest,omitempty"`
	CompensationToken SecretRef `json:"compensation_token,omitempty"`
	FailureCode string `json:"failure_code,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
	Activation *ActivationEvidence `json:"activation,omitempty"`
	Result EffectResult `json:"result,omitempty"`
}

type ActivationEvidence struct {
	Strategy ActivationStrategy `json:"strategy"`
	CandidateDigest string `json:"candidate_digest"`
	PreviousDigest string `json:"previous_digest,omitempty"`
	StageReceiptDigest string `json:"stage_receipt_digest"`
	ProbeReceiptDigest string `json:"probe_receipt_digest"`
	CommitReceiptDigest string `json:"commit_receipt_digest"`
}

type CompensationRequest struct {
	EffectID string `json:"effect_id"`
	RequestDigest string `json:"request_digest"`
	Scope OperationScope `json:"scope"`
	CompensationToken SecretRef `json:"compensation_token"`
	FailureCode string `json:"failure_code"`
}

type CompensationReceipt struct {
	EffectID string `json:"effect_id"`
	RequestDigest string `json:"request_digest"`
	CompensationToken SecretRef `json:"compensation_token"`
	Outcome EffectOutcome `json:"outcome"`
	ProofDigest string `json:"proof_digest,omitempty"`
	FailureCode string `json:"failure_code,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}

// HostExecutor is implemented only by the root-owned node adapter. Its closed
// request union prevents the control plane from passing shell, filesystem,
// systemd-unit, package-manager, nft, firewalld, or ModSecurity text.
type HostExecutor interface {
	ObserveOrApply(context.Context, EffectRequest) (EffectReceipt, error)
	Compensate(context.Context, CompensationRequest) (CompensationReceipt, error)
}

func finalizeEffect(request EffectRequest) (EffectRequest, error) {
	request.EffectID, request.RequestDigest = "", ""
	if validateEffectShape(request) != nil { return EffectRequest{}, ErrInvalidCommand }
	encoded, err := json.Marshal(request)
	if err != nil { return EffectRequest{}, err }
	digest := sha256.Sum256(encoded)
	request.RequestDigest = hex.EncodeToString(digest[:])
	effectID := sha256.Sum256([]byte("cyberpanel:host-operation:v1\x00"+request.Scope.NodeID.String()+"\x00"+request.Scope.TenantID.String()+"\x00"+string(request.Scope.Kind)+"\x00"+request.Scope.ID.String()+"\x00"+request.RequestDigest))
	request.EffectID = "hostfx-"+hex.EncodeToString(effectID[:])
	return request, nil
}

func validateEffectRequest(request EffectRequest) error {
	want, err := finalizeEffect(request)
	if err != nil || want.EffectID != request.EffectID || want.RequestDigest != request.RequestDigest { return ErrInvalidEffect }
	return nil
}

func validateEffectShape(request EffectRequest) error {
	if request.Scope.NodeID.IsZero() || request.Scope.ID.IsZero() { return ErrInvalidCommand }
	count := 0
	for _, present := range []bool{
		request.ResourceProfile != nil, request.TransferReset != nil, request.TransferSample != nil, request.FirewallPolicy != nil, request.SSHPolicy != nil,
		request.PutSSHKey != nil, request.DeleteSSHKey != nil, request.WAFPolicy != nil, request.ServicePolicy != nil,
		request.ServiceControl != nil, request.ServiceDiagnose != nil, request.ServiceRepair != nil, request.MetricsQuery != nil,
		request.LogQuery != nil, request.SSHLoginQuery != nil, request.SSHSessionQuery != nil, request.ProcessInvestigate != nil,
		request.ProcessTerminate != nil, request.PackageTransaction != nil, request.ManagedService != nil,
	} { if present { count++ } }
	if count != 1 { return ErrInvalidCommand }
	switch request.Kind {
	case EffectResourceProfile:
		if request.ResourceProfile == nil || request.ResourceProfile.Profile.Validate() != nil { return ErrInvalidCommand }
	case EffectTransferReset:
		if request.TransferReset == nil || request.TransferReset.Account.Validate() != nil { return ErrInvalidCommand }
	case EffectTransferSample:
		if request.TransferSample == nil || request.TransferSample.Account.Validate() != nil { return ErrInvalidCommand }
	case EffectFirewallPolicy:
		if request.FirewallPolicy == nil || request.FirewallPolicy.Policy.Validate() != nil || request.FirewallPolicy.Strategy != ActivationMakeBeforeBreak { return ErrInvalidCommand }
	case EffectSSHPolicy:
		if request.SSHPolicy == nil || request.SSHPolicy.Policy.Validate() != nil || request.SSHPolicy.Strategy != ActivationMakeBeforeBreak { return ErrInvalidCommand }
	case EffectPutSSHKey:
		if request.PutSSHKey == nil || request.PutSSHKey.Key.Validate() != nil { return ErrInvalidCommand }
	case EffectDeleteSSHKey:
		if request.DeleteSSHKey == nil || request.DeleteSSHKey.Key.Validate() != nil { return ErrInvalidCommand }
	case EffectWAFPolicy:
		if request.WAFPolicy == nil || request.WAFPolicy.Policy.Validate() != nil || request.WAFPolicy.Strategy != ActivationCompileProbeSwap { return ErrInvalidCommand }
	case EffectServicePolicy:
		if request.ServicePolicy == nil || request.ServicePolicy.Policy.Validate() != nil { return ErrInvalidCommand }
	case EffectServiceControl:
		if request.ServiceControl == nil || !validService(request.ServiceControl.Service) || request.ServiceControl.PolicyGeneration == 0 { return ErrInvalidCommand }
	case EffectServiceDiagnose:
		if request.ServiceDiagnose == nil || !validService(request.ServiceDiagnose.Service) { return ErrInvalidCommand }
	case EffectServiceRepair:
		if request.ServiceRepair == nil || !validService(request.ServiceRepair.Service) || !validSHA256(request.ServiceRepair.DiagnosticProofDigest) { return ErrInvalidCommand }
	case EffectMetricsQuery:
		if request.MetricsQuery == nil || request.MetricsQuery.Scope.Validate() != nil || request.MetricsQuery.Scope.NodeID != request.Scope.NodeID || request.MetricsQuery.Scope.TenantID.String() != request.Scope.TenantID.String() || !request.MetricsQuery.End.After(request.MetricsQuery.Start) || request.MetricsQuery.End.Sub(request.MetricsQuery.Start) > 31*24*time.Hour || request.MetricsQuery.Step < time.Second || request.MetricsQuery.Step > 24*time.Hour || request.MetricsQuery.Limit == 0 || request.MetricsQuery.Limit > 256 || len(request.MetricsQuery.Names) == 0 || len(request.MetricsQuery.Names) > 32 { return ErrInvalidCommand }; for _, name := range request.MetricsQuery.Names { if !validMetric(name) { return ErrInvalidCommand } }
	case EffectLogQuery:
		if request.LogQuery == nil || !validLogSource(request.LogQuery.Source) || !request.LogQuery.End.After(request.LogQuery.Start) || request.LogQuery.End.Sub(request.LogQuery.Start) > 7*24*time.Hour || request.LogQuery.MinimumSeverity > 7 || len(request.LogQuery.Cursor) > 512 || request.LogQuery.Limit == 0 || request.LogQuery.Limit > 2000 || request.LogQuery.TenantID != request.Scope.TenantID.String() || request.LogQuery.SiteID != "" && request.LogQuery.TenantID == "" || request.LogQuery.Source == LogServiceJournal && !validService(request.LogQuery.Service) || request.LogQuery.Source != LogServiceJournal && request.LogQuery.Service != "" { return ErrInvalidCommand }
	case EffectSSHLoginQuery:
		if request.SSHLoginQuery == nil { return ErrInvalidCommand }
	case EffectSSHSessionQuery:
		if request.SSHSessionQuery == nil { return ErrInvalidCommand }
	case EffectProcessInvestigate:
		if request.ProcessInvestigate == nil || validateProcessIdentity(request.ProcessInvestigate.Process) != nil { return ErrInvalidCommand }
	case EffectProcessTerminate:
		if request.ProcessTerminate == nil || validateProcessIdentity(request.ProcessTerminate.Process) != nil || !validSHA256(request.ProcessTerminate.InvestigationProofDigest) { return ErrInvalidCommand }
	case EffectPackageTransaction:
		if request.PackageTransaction == nil || request.PackageTransaction.Transaction.Validate() != nil { return ErrInvalidCommand }
	case EffectManagedService:
		if request.ManagedService == nil || request.ManagedService.Service.Validate() != nil || validateManagedRedisData(request.ManagedService.Service, request.ManagedService.RedisData) != nil { return ErrInvalidCommand }
	default:
		return ErrInvalidCommand
	}
	return nil
}

func effectIsMutation(kind EffectKind) bool {
	switch kind {
	case EffectTransferSample, EffectMetricsQuery, EffectLogQuery, EffectSSHLoginQuery, EffectSSHSessionQuery, EffectProcessInvestigate, EffectServiceDiagnose:
		return false
	default:
		return true
	}
}

func effectReceiptMatches(request EffectRequest, receipt EffectReceipt) bool {
	if receipt.EffectID != request.EffectID || receipt.RequestDigest != request.RequestDigest || receipt.CompletedAt.IsZero() { return false }
	switch receipt.Outcome {
	case EffectConfirmed:
		return validateEffectResult(request, receipt.Result) == nil && validateActivationEvidence(request, receipt.Activation) && validSHA256(receipt.ProofDigest) && receipt.MutationObserved == effectIsMutation(request.Kind) && receipt.CompensationToken.IsZero() && receipt.FailureCode == ""
	case EffectRejected:
		return emptyEffectResult(receipt.Result) && receipt.FailureCode != "" && (!receipt.MutationObserved || !receipt.CompensationToken.IsZero())
	case EffectAmbiguous:
		return emptyEffectResult(receipt.Result)
	default:
		return false
	}
}

func validateActivationEvidence(request EffectRequest, evidence *ActivationEvidence) bool {
	strategy := ActivationStrategy("")
	switch request.Kind {
	case EffectFirewallPolicy:
		strategy = ActivationMakeBeforeBreak
	case EffectSSHPolicy:
		strategy = ActivationMakeBeforeBreak
	case EffectWAFPolicy:
		strategy = ActivationCompileProbeSwap
	default:
		return evidence == nil
	}
	candidateDigest, ok := activationCandidateDigest(request)
	return ok && evidence != nil && evidence.Strategy == strategy && evidence.CandidateDigest == candidateDigest &&
		(evidence.PreviousDigest == "" || validSHA256(evidence.PreviousDigest)) && validSHA256(evidence.StageReceiptDigest) &&
		validSHA256(evidence.ProbeReceiptDigest) && validSHA256(evidence.CommitReceiptDigest)
}

func activationCandidateDigest(request EffectRequest) (string, bool) {
	var candidate any
	switch request.Kind {
	case EffectFirewallPolicy: candidate = request.FirewallPolicy.Policy
	case EffectSSHPolicy: candidate = request.SSHPolicy.Policy
	case EffectWAFPolicy: candidate = request.WAFPolicy.Policy
	default: return "", false
	}
	encoded, err := json.Marshal(candidate); if err != nil { return "", false }
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), true
}

func emptyEffectResult(result EffectResult) bool {
	return result.Metrics == nil && result.Logs == nil && result.SSHLogins == nil && result.SSHSessions == nil && result.Process == nil && result.Diagnostics == nil && result.Packages == nil && result.ManagedRedisData == nil
}

func compensationReceiptMatches(request CompensationRequest, receipt CompensationReceipt) bool {
	if receipt.EffectID != request.EffectID || receipt.RequestDigest != request.RequestDigest || receipt.CompensationToken != request.CompensationToken || receipt.CompletedAt.IsZero() { return false }
	return receipt.Outcome == EffectConfirmed && validSHA256(receipt.ProofDigest) || receipt.Outcome == EffectRejected && receipt.FailureCode != "" || receipt.Outcome == EffectAmbiguous
}

func validateEffectResult(request EffectRequest, result EffectResult) error {
	count := 0
	if result.Metrics != nil { count++ }
	if result.Logs != nil { count++ }
	if result.SSHLogins != nil { count++ }
	if result.SSHSessions != nil { count++ }
	if result.Process != nil { count++ }
	if result.Diagnostics != nil { count++ }
	if result.Packages != nil { count++ }
	if result.ManagedRedisData != nil { count++ }
	expected := false
	switch request.Kind {
	case EffectMetricsQuery: expected = result.Metrics != nil
	case EffectLogQuery: expected = result.Logs != nil
	case EffectSSHLoginQuery: expected = result.SSHLogins != nil
	case EffectSSHSessionQuery: expected = result.SSHSessions != nil
	case EffectProcessInvestigate: expected = result.Process != nil
	case EffectServiceDiagnose: expected = result.Diagnostics != nil
	case EffectPackageTransaction: expected = result.Packages != nil || count == 0
	case EffectManagedService:
		expected = request.ManagedService != nil && request.ManagedService.RedisData != nil && result.ManagedRedisData != nil || request.ManagedService != nil && request.ManagedService.RedisData == nil && count == 0
	default: expected = count == 0
	}
	if !expected || count > 1 { return ErrInvalidEffect }
	if result.Logs != nil {
		query := request.LogQuery
		if query == nil || result.Logs.ObservedAt.IsZero() || uint32(len(result.Logs.Entries)) > query.Limit || len(result.Logs.NextCursor) > 512 || result.Logs.BytesRead > 4<<20 || len(result.Logs.UnavailableReason)>64 || result.Logs.Available == (result.Logs.UnavailableReason != "") { return ErrInvalidEffect }
		resultBytes:=0;for _, entry := range result.Logs.Entries { resultBytes+=len(entry.Cursor)+len(entry.EventCode)+len(entry.Message)+128;if len(entry.Cursor) == 0 || len(entry.Cursor) > 512 || entry.At.Before(query.Start) || entry.At.After(query.End) || entry.Source != query.Source || entry.Severity < query.MinimumSeverity || entry.Severity > 7 || len(entry.EventCode) == 0 || len(entry.EventCode) > 128 || len(entry.Message) > 16384 || strings.ContainsRune(entry.Message, '\x00') { return ErrInvalidEffect } };if resultBytes>2<<20{return ErrInvalidEffect}
	}
	if result.Metrics != nil {
		query := request.MetricsQuery
		if query == nil || result.Metrics.Scope != query.Scope || result.Metrics.ObservedAt.IsZero() || uint32(len(result.Metrics.Points)) > query.Limit || len(result.Metrics.UnavailableReason)>64 || result.Metrics.Available == (result.Metrics.UnavailableReason != "") { return ErrInvalidEffect }
		allowed := make(map[MetricName]struct{}, len(query.Names)); for _, name := range query.Names { allowed[name] = struct{}{} }
		for _, point := range result.Metrics.Points { if _, ok := allowed[point.Name]; !ok || !point.At.Equal(result.Metrics.ObservedAt) || !validMetricUnit(point.Name, point.Unit) || len(point.UnavailableReason)>64 || point.Available == (point.UnavailableReason != "") || point.Name == MetricServiceHealth && !validService(point.Service) || point.Name != MetricServiceHealth && point.Service != "" || len(point.Status) > 64 { return ErrInvalidEffect } }
	}
	if result.SSHLogins != nil {
		query := request.SSHLoginQuery
		if query == nil || uint32(len(result.SSHLogins.Records)) > query.Limit { return ErrInvalidEffect }
		for _, record := range result.SSHLogins.Records {
			if record.At.Before(query.Start) || record.At.After(query.End) || !record.Source.IsValid() || (query.SourceCIDR != nil && !query.SourceCIDR.Contains(record.Source)) ||
				(record.Authentication != SSHKeysOnly && record.Authentication != SSHKeysAndMFA) || (record.Outcome != SSHLoginAccepted && record.Outcome != SSHLoginRejected && record.Outcome != SSHLoginDisconnected) || len(record.ReasonCode) > 128 { return ErrInvalidEffect }
		}
	}
	if result.SSHSessions != nil {
		query := request.SSHSessionQuery
		if query == nil || uint32(len(result.SSHSessions.Sessions)) > query.Limit { return ErrInvalidEffect }
		for _, session := range result.SSHSessions.Sessions { if session.ID.IsZero() || session.PrincipalID.IsZero() || !session.Source.IsValid() || session.StartedAt.IsZero() || session.LastActivityAt.Before(session.StartedAt) || !session.ClosedAt.IsZero() && session.ClosedAt.Before(session.StartedAt) || len(session.Processes) > 4096 { return ErrInvalidEffect }; for _, process := range session.Processes { if validateProcessIdentity(process) != nil { return ErrInvalidEffect } } }
	}
	if result.Process != nil {
		if request.ProcessInvestigate == nil || result.Process.Identity != request.ProcessInvestigate.Process || result.Process.ExecutableDigest != "" && !validSHA256(result.Process.ExecutableDigest) || len(result.Process.Sockets) > 65536 { return ErrInvalidEffect }
		for _, socket := range result.Process.Sockets { if socket.Protocol != SocketTCP && socket.Protocol != SocketUDP && socket.Protocol != SocketUnix { return ErrInvalidEffect }; if socket.Protocol != SocketUnix && !socket.LocalAddress.IsValid() { return ErrInvalidEffect }; if len(socket.State) > 64 { return ErrInvalidEffect } }
	}
	if result.Diagnostics != nil {
		if request.ServiceDiagnose == nil || result.Diagnostics.Service != request.ServiceDiagnose.Service || len(result.Diagnostics.ActiveState) > 64 || len(result.Diagnostics.SubState) > 64 || len(result.Diagnostics.Checks) > 256 || len(result.Diagnostics.SuggestedRepairs) > 16 { return ErrInvalidEffect }
		for _, check := range result.Diagnostics.Checks { if len(check.Code) == 0 || len(check.Code) > 128 || (check.Outcome != CheckPass && check.Outcome != CheckWarn && check.Outcome != CheckFail) || !validSHA256(check.EvidenceDigest) { return ErrInvalidEffect } }
	}
	if result.Packages != nil {
		if request.PackageTransaction == nil || len(result.Packages.Changes) > len(request.PackageTransaction.Transaction.Selections) || len(result.Packages.ServicesRestarted) > 64 { return ErrInvalidEffect }
		for _, change := range result.Packages.Changes { if change.Name.IsZero() || change.Architecture.IsZero() || (change.Action != PackageInstall && change.Action != PackageRemove && change.Action != PackageUpgrade) || len(change.FromVersion) > 128 || len(change.ToVersion) > 128 { return ErrInvalidEffect } }
		for _, service := range result.Packages.ServicesRestarted { if !validService(service) { return ErrInvalidEffect } }
	}
	if result.ManagedRedisData != nil {
		if request.ManagedService == nil || request.ManagedService.RedisData == nil || result.ManagedRedisData.Action != request.ManagedService.RedisData.Action || !validSHA256(result.ManagedRedisData.EvidenceDigest) { return ErrInvalidEffect }
		if result.ManagedRedisData.Action == ManagedRedisSnapshot {
			if result.ManagedRedisData.Artifact == nil || validateManagedRedisArtifact(*result.ManagedRedisData.Artifact, true) != nil || !sameManagedRedisArtifactTarget(*result.ManagedRedisData.Artifact, request.ManagedService.RedisData.Artifact) { return ErrInvalidEffect }
		} else if result.ManagedRedisData.Artifact != nil { return ErrInvalidEffect }
	}
	return nil
}

func validateManagedRedisVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || len(value) > 24 { return false }
	for _, part := range parts {
		if part == "" || len(part) > 5 { return false }
		for index := range part { if part[index] < '0' || part[index] > '9' { return false } }
	}
	return true
}

func validateManagedRedisArtifact(artifact ManagedRedisArtifact, complete bool) error {
	if _, err := safeOpaque(artifact.ID, 128); err != nil { return ErrInvalidCommand }
	if _, err := safeOpaque(artifact.GroupID, 128); err != nil { return ErrInvalidCommand }
	if artifact.InstanceID.IsZero() || artifact.Kind != "rdb" || !validateManagedRedisVersion(artifact.RedisVersion) || artifact.ConfigGeneration == 0 || artifact.ConfigGeneration > uint64(1<<63-1) { return ErrInvalidCommand }
	if complete {
		if artifact.SizeBytes <= 0 || artifact.SizeBytes > managedRedisMaximumArtifactBytes || !validSHA256(artifact.SHA256) || artifact.CreatedAt.IsZero() { return ErrInvalidCommand }
	} else if artifact.SizeBytes != 0 || artifact.SHA256 != "" || !artifact.CreatedAt.IsZero() { return ErrInvalidCommand }
	return nil
}

func sameManagedRedisArtifactTarget(artifact, target ManagedRedisArtifact) bool {
	return artifact.ID == target.ID && artifact.GroupID == target.GroupID && artifact.InstanceID == target.InstanceID && artifact.Kind == target.Kind && artifact.RedisVersion == target.RedisVersion && artifact.ConfigGeneration == target.ConfigGeneration
}

func validateManagedRedisData(service ManagedService, data *ManagedRedisDataEffect) error {
	if data == nil { return nil }
	if service.KindName != ManagedRedis || service.Redis == nil || data.ExpectedSpecGeneration == 0 || data.ExpectedSpecGeneration > uint64(1<<63-1) || data.ExpectedConfigGeneration == 0 || data.ExpectedConfigGeneration > uint64(1<<63-1) { return ErrInvalidCommand }
	switch data.Action {
	case ManagedRedisSnapshot:
		if service.Desired != ServiceRunning || data.ExpectedConsumerGeneration != 0 || validateManagedRedisArtifact(data.Artifact, false) != nil || data.Artifact.InstanceID != service.ID || data.Artifact.ConfigGeneration != data.ExpectedConfigGeneration || data.RecoveryArtifact.ID != "" { return ErrInvalidCommand }
	case ManagedRedisRestore:
		if service.Desired != ServiceRunning || data.ExpectedConsumerGeneration == 0 || validateManagedRedisArtifact(data.Artifact, true) != nil || validateManagedRedisArtifact(data.RecoveryArtifact, true) != nil || data.Artifact.InstanceID != service.ID || data.RecoveryArtifact.InstanceID != service.ID || data.Artifact.ID == data.RecoveryArtifact.ID || data.Artifact.RedisVersion != data.RecoveryArtifact.RedisVersion || data.RecoveryArtifact.ConfigGeneration != data.ExpectedConfigGeneration { return ErrInvalidCommand }
	case ManagedRedisPurge:
		if service.Desired != ServiceStopped || data.ExpectedConsumerGeneration == 0 || data.Artifact.ID != "" || validateManagedRedisArtifact(data.RecoveryArtifact, true) != nil || data.RecoveryArtifact.InstanceID != service.ID || data.RecoveryArtifact.ConfigGeneration != data.ExpectedConfigGeneration { return ErrInvalidCommand }
	default:
		return ErrInvalidCommand
	}
	return nil
}

func validMetricUnit(name MetricName, unit MetricUnit) bool {
	switch name {
	case MetricCPUUsage: return unit == UnitRatio
	case MetricLoad1: return unit == UnitCount
	case MetricMemoryUsage, MetricDiskUsage: return unit == UnitBytes
	case MetricIOBytes, MetricNetworkBytes: return unit == UnitBytes || unit == UnitBytesPerSecond
	case MetricInodeUsage, MetricPHPWorkers, MetricServiceHealth: return unit == UnitCount
	default: return false
	}
}
