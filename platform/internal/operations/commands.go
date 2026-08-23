package operations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

type Capability string

const (
	CapabilityTenantOperations Capability = "tenant.operations.manage"
	CapabilityTenantSecurity Capability = "tenant.security.manage"
	CapabilityTenantObserve Capability = "tenant.operations.observe"
	CapabilityNodeOperations Capability = "node.operations.manage"
	CapabilityNodeSecurity Capability = "node.security.manage"
	CapabilityNodePackages Capability = "node.packages.manage"
	CapabilityProcessTerminate Capability = "node.process.terminate"
)

type Actor struct {
	PrincipalID ResourceID `json:"principal_id"`
	TenantID site.TenantID `json:"tenant_id,omitempty"`
	Capabilities []Capability `json:"capabilities"`
	MFAProofRef ResourceID `json:"mfa_proof_ref,omitempty"`
}

func (actor Actor) Has(capability Capability) bool {
	for _, candidate := range actor.Capabilities { if candidate == capability { return true } }
	return false
}

type CommandHeader struct {
	CommandID string `json:"command_id"`
	NodeID ResourceID `json:"node_id"`
	TenantID site.TenantID `json:"tenant_id,omitempty"`
	SiteID site.SiteID `json:"site_id,omitempty"`
	Actor Actor `json:"actor"`
	RequestedAt time.Time `json:"requested_at"`
	Deadline time.Time `json:"deadline"`
	ApprovalRef ResourceID `json:"approval_ref,omitempty"`
}

type OperationScope struct {
	NodeID ResourceID `json:"node_id"`
	TenantID site.TenantID `json:"tenant_id,omitempty"`
	Kind ResourceKind `json:"kind"`
	ID ResourceID `json:"id"`
}

type Command interface {
	commandHeader() CommandHeader
	commandScope() OperationScope
	commandKind() EffectKind
	sealCommand()
}

type ApplyResourceProfile struct { Header CommandHeader `json:"header"`; Profile ResourceProfile `json:"profile"`; ExpectedGeneration uint64 `json:"expected_generation"` }
func (command ApplyResourceProfile) commandHeader() CommandHeader { return command.Header }
func (command ApplyResourceProfile) commandScope() OperationScope { return resourceScope(command.Header, command.Profile.Kind(), command.Profile.ID) }
func (ApplyResourceProfile) commandKind() EffectKind { return EffectResourceProfile }
func (ApplyResourceProfile) sealCommand() {}

type ResetTransferMonth struct { Header CommandHeader `json:"header"`; Account TransferAccount `json:"account"`; ExpectedGeneration uint64 `json:"expected_generation"` }
func (command ResetTransferMonth) commandHeader() CommandHeader { return command.Header }
func (command ResetTransferMonth) commandScope() OperationScope { return resourceScope(command.Header, command.Account.Kind(), command.Account.ID) }
func (ResetTransferMonth) commandKind() EffectKind { return EffectTransferReset }
func (ResetTransferMonth) sealCommand() {}

// RecordTransferSample advances one canonical monthly counter from a trusted
// host observation. Coordinator rejects counter, period, or epoch regression.
type RecordTransferSample struct { Header CommandHeader `json:"header"`; Account TransferAccount `json:"account"`; ExpectedGeneration uint64 `json:"expected_generation"` }
func (command RecordTransferSample) commandHeader() CommandHeader { return command.Header }
func (command RecordTransferSample) commandScope() OperationScope { return resourceScope(command.Header, command.Account.Kind(), command.Account.ID) }
func (RecordTransferSample) commandKind() EffectKind { return EffectTransferSample }
func (RecordTransferSample) sealCommand() {}

type ReplaceFirewallPolicy struct { Header CommandHeader `json:"header"`; Policy FirewallPolicy `json:"policy"`; ExpectedGeneration uint64 `json:"expected_generation"` }
func (command ReplaceFirewallPolicy) commandHeader() CommandHeader { return command.Header }
func (command ReplaceFirewallPolicy) commandScope() OperationScope { return resourceScope(command.Header, command.Policy.Kind(), command.Policy.ID) }
func (ReplaceFirewallPolicy) commandKind() EffectKind { return EffectFirewallPolicy }
func (ReplaceFirewallPolicy) sealCommand() {}

type ReplaceSSHPolicy struct { Header CommandHeader `json:"header"`; Policy SSHPolicy `json:"policy"`; ExpectedGeneration uint64 `json:"expected_generation"` }
func (command ReplaceSSHPolicy) commandHeader() CommandHeader { return command.Header }
func (command ReplaceSSHPolicy) commandScope() OperationScope { return resourceScope(command.Header, command.Policy.Kind(), command.Policy.ID) }
func (ReplaceSSHPolicy) commandKind() EffectKind { return EffectSSHPolicy }
func (ReplaceSSHPolicy) sealCommand() {}

type PutSSHKey struct { Header CommandHeader `json:"header"`; Key SSHKey `json:"key"`; ExpectedGeneration uint64 `json:"expected_generation"` }
func (command PutSSHKey) commandHeader() CommandHeader { return command.Header }
func (command PutSSHKey) commandScope() OperationScope { return resourceScope(command.Header, command.Key.Kind(), command.Key.ID) }
func (PutSSHKey) commandKind() EffectKind { return EffectPutSSHKey }
func (PutSSHKey) sealCommand() {}

type DeleteSSHKey struct { Header CommandHeader `json:"header"`; KeyID ResourceID `json:"key_id"`; ExpectedGeneration uint64 `json:"expected_generation"` }
func (command DeleteSSHKey) commandHeader() CommandHeader { return command.Header }
func (command DeleteSSHKey) commandScope() OperationScope { return resourceScope(command.Header, KindSSHKey, command.KeyID) }
func (DeleteSSHKey) commandKind() EffectKind { return EffectDeleteSSHKey }
func (DeleteSSHKey) sealCommand() {}

type ReplaceWAFPolicy struct { Header CommandHeader `json:"header"`; Policy WAFPolicy `json:"policy"`; ExpectedGeneration uint64 `json:"expected_generation"` }
func (command ReplaceWAFPolicy) commandHeader() CommandHeader { return command.Header }
func (command ReplaceWAFPolicy) commandScope() OperationScope { return resourceScope(command.Header, command.Policy.Kind(), command.Policy.ID) }
func (ReplaceWAFPolicy) commandKind() EffectKind { return EffectWAFPolicy }
func (ReplaceWAFPolicy) sealCommand() {}

type SetServicePolicy struct { Header CommandHeader `json:"header"`; Policy ServicePolicy `json:"policy"`; ExpectedGeneration uint64 `json:"expected_generation"` }
func (command SetServicePolicy) commandHeader() CommandHeader { return command.Header }
func (command SetServicePolicy) commandScope() OperationScope { return resourceScope(command.Header, command.Policy.Kind(), command.Policy.ID) }
func (SetServicePolicy) commandKind() EffectKind { return EffectServicePolicy }
func (SetServicePolicy) sealCommand() {}

type ServiceAction string

const (
	ServiceStart ServiceAction = "start"
	ServiceStop ServiceAction = "stop"
	ServiceRestart ServiceAction = "restart"
	ServiceReload ServiceAction = "reload"
)

type ControlService struct {
	Header CommandHeader `json:"header"`
	Service ServiceName `json:"service"`
	Action ServiceAction `json:"action"`
	ExpectedPolicyGeneration uint64 `json:"expected_policy_generation"`
}
func (command ControlService) commandHeader() CommandHeader { return command.Header }
func (command ControlService) commandScope() OperationScope { return resourceScope(command.Header, KindServicePolicy, serviceResourceID(command.Service)) }
func (ControlService) commandKind() EffectKind { return EffectServiceControl }
func (ControlService) sealCommand() {}

type DiagnosticDepth string

const (
	DiagnosticSummary DiagnosticDepth = "summary"
	DiagnosticDependency DiagnosticDepth = "dependency"
	DiagnosticDeep DiagnosticDepth = "deep"
)

type DiagnoseService struct { Header CommandHeader `json:"header"`; Service ServiceName `json:"service"`; Depth DiagnosticDepth `json:"depth"`; Since time.Time `json:"since"` }
func (command DiagnoseService) commandHeader() CommandHeader { return command.Header }
func (command DiagnoseService) commandScope() OperationScope { return resourceScope(command.Header, KindServicePolicy, serviceResourceID(command.Service)) }
func (DiagnoseService) commandKind() EffectKind { return EffectServiceDiagnose }
func (DiagnoseService) sealCommand() {}

type RepairStrategy string

const (
	RepairReconcileConfig RepairStrategy = "reconcile_config"
	RepairResetFailed RepairStrategy = "reset_failed"
	RepairReinstallManagedFiles RepairStrategy = "reinstall_managed_files"
	RepairDependencyOrder RepairStrategy = "dependency_order"
)

type RepairService struct { Header CommandHeader `json:"header"`; Service ServiceName `json:"service"`; Strategy RepairStrategy `json:"strategy"`; DiagnosticProofDigest string `json:"diagnostic_proof_digest"` }
func (command RepairService) commandHeader() CommandHeader { return command.Header }
func (command RepairService) commandScope() OperationScope { return resourceScope(command.Header, KindServicePolicy, serviceResourceID(command.Service)) }
func (RepairService) commandKind() EffectKind { return EffectServiceRepair }
func (RepairService) sealCommand() {}

type MetricName string

const (
	MetricCPUUsage MetricName = "cpu_usage"
	MetricMemoryUsage MetricName = "memory_usage"
	MetricIOBytes MetricName = "io_bytes"
	MetricNetworkBytes MetricName = "network_bytes"
	MetricDiskUsage MetricName = "disk_usage"
	MetricInodeUsage MetricName = "inode_usage"
	MetricPHPWorkers MetricName = "php_workers"
	MetricServiceHealth MetricName = "service_health"
)

type QueryMetrics struct {
	Header CommandHeader `json:"header"`
	Scope EnforcementScope `json:"scope"`
	Names []MetricName `json:"names"`
	Start time.Time `json:"start"`
	End time.Time `json:"end"`
	Step time.Duration `json:"step"`
	Limit uint32 `json:"limit"`
}
func (command QueryMetrics) commandHeader() CommandHeader { return command.Header }
func (command QueryMetrics) commandScope() OperationScope { return resourceScope(command.Header, KindResourceProfile, queryResourceID("metrics", command.Header.CommandID)) }
func (QueryMetrics) commandKind() EffectKind { return EffectMetricsQuery }
func (QueryMetrics) sealCommand() {}

type LogSource string

const (
	LogPanel LogSource = "panel"
	LogWebAccess LogSource = "web_access"
	LogWebError LogSource = "web_error"
	LogPHP LogSource = "php"
	LogMariaDB LogSource = "mariadb"
	LogMail LogSource = "mail"
	LogSSH LogSource = "ssh"
	LogFirewall LogSource = "firewall"
	LogWAF LogSource = "waf"
	LogServiceJournal LogSource = "service_journal"
)

type OpenLogStream struct {
	Header CommandHeader `json:"header"`
	Source LogSource `json:"source"`
	Service ServiceName `json:"service,omitempty"`
	Start time.Time `json:"start"`
	End time.Time `json:"end"`
	MinimumSeverity uint8 `json:"minimum_severity"`
	Cursor string `json:"cursor,omitempty"`
	Limit uint32 `json:"limit"`
}
func (command OpenLogStream) commandHeader() CommandHeader { return command.Header }
func (command OpenLogStream) commandScope() OperationScope { return resourceScope(command.Header, KindServicePolicy, queryResourceID("logs", command.Header.CommandID)) }
func (OpenLogStream) commandKind() EffectKind { return EffectLogQuery }
func (OpenLogStream) sealCommand() {}

type QuerySSHLogins struct { Header CommandHeader `json:"header"`; Start time.Time `json:"start"`; End time.Time `json:"end"`; SourceCIDR *netip.Prefix `json:"source_cidr,omitempty"`; Limit uint32 `json:"limit"` }
func (command QuerySSHLogins) commandHeader() CommandHeader { return command.Header }
func (command QuerySSHLogins) commandScope() OperationScope { return resourceScope(command.Header, KindSSHPolicy, queryResourceID("ssh-logins", command.Header.CommandID)) }
func (QuerySSHLogins) commandKind() EffectKind { return EffectSSHLoginQuery }
func (QuerySSHLogins) sealCommand() {}

type QuerySSHSessions struct { Header CommandHeader `json:"header"`; IncludeClosedSince time.Time `json:"include_closed_since"`; Limit uint32 `json:"limit"` }
func (command QuerySSHSessions) commandHeader() CommandHeader { return command.Header }
func (command QuerySSHSessions) commandScope() OperationScope { return resourceScope(command.Header, KindSSHPolicy, queryResourceID("ssh-sessions", command.Header.CommandID)) }
func (QuerySSHSessions) commandKind() EffectKind { return EffectSSHSessionQuery }
func (QuerySSHSessions) sealCommand() {}

type ProcessIdentity struct { PID uint32 `json:"pid"`; StartTimeTicks uint64 `json:"start_time_ticks"`; BootID ResourceID `json:"boot_id"` }

type InvestigateProcess struct { Header CommandHeader `json:"header"`; Process ProcessIdentity `json:"process"`; IncludeFileDescriptors bool `json:"include_file_descriptors"`; IncludeNetworkSockets bool `json:"include_network_sockets"` }
func (command InvestigateProcess) commandHeader() CommandHeader { return command.Header }
func (command InvestigateProcess) commandScope() OperationScope { return resourceScope(command.Header, KindResourceProfile, queryResourceID("process", command.Header.CommandID)) }
func (InvestigateProcess) commandKind() EffectKind { return EffectProcessInvestigate }
func (InvestigateProcess) sealCommand() {}

type TerminationSignal string

const (
	SignalTerminate TerminationSignal = "terminate"
	SignalKill TerminationSignal = "kill"
	SignalHangup TerminationSignal = "hangup"
)

type TerminateProcess struct { Header CommandHeader `json:"header"`; Process ProcessIdentity `json:"process"`; Signal TerminationSignal `json:"signal"`; InvestigationProofDigest string `json:"investigation_proof_digest"`; ReasonCode ResourceID `json:"reason_code"` }
func (command TerminateProcess) commandHeader() CommandHeader { return command.Header }
func (command TerminateProcess) commandScope() OperationScope { return resourceScope(command.Header, KindResourceProfile, queryResourceID("terminate", command.Header.CommandID)) }
func (TerminateProcess) commandKind() EffectKind { return EffectProcessTerminate }
func (TerminateProcess) sealCommand() {}

type RequestPackageTransaction struct { Header CommandHeader `json:"header"`; Transaction PackageTransaction `json:"transaction"` }
func (command RequestPackageTransaction) commandHeader() CommandHeader { return command.Header }
func (command RequestPackageTransaction) commandScope() OperationScope { return resourceScope(command.Header, command.Transaction.Kind(), command.Transaction.ID) }
func (RequestPackageTransaction) commandKind() EffectKind { return EffectPackageTransaction }
func (RequestPackageTransaction) sealCommand() {}

type ReconcileManagedService struct { Header CommandHeader `json:"header"`; Service ManagedService `json:"service"`; ExpectedGeneration uint64 `json:"expected_generation"` }
func (command ReconcileManagedService) commandHeader() CommandHeader { return command.Header }
func (command ReconcileManagedService) commandScope() OperationScope { return resourceScope(command.Header, command.Service.Kind(), command.Service.ID) }
func (ReconcileManagedService) commandKind() EffectKind { return EffectManagedService }
func (ReconcileManagedService) sealCommand() {}

func resourceScope(header CommandHeader, kind ResourceKind, id ResourceID) OperationScope {
	return OperationScope{NodeID: header.NodeID, TenantID: header.TenantID, Kind: kind, ID: id}
}

func serviceResourceID(service ServiceName) ResourceID { id, _ := NewResourceID("service-"+string(service)); return id }
func queryResourceID(prefix, commandID string) ResourceID {
	digest := sha256.Sum256([]byte(prefix+"\x00"+commandID))
	id, _ := NewResourceID(prefix+"-"+hex.EncodeToString(digest[:16]))
	return id
}

func validateCommand(command Command, now time.Time) error {
	if command == nil { return ErrInvalidCommand }
	header := command.commandHeader()
	if len(header.CommandID) < 8 || len(header.CommandID) > 128 || strings.ContainsAny(header.CommandID, "\r\n\x00") || header.NodeID.IsZero() || header.Actor.PrincipalID.IsZero() ||
		header.RequestedAt.IsZero() || header.Deadline.IsZero() || header.Deadline.Before(header.RequestedAt) || header.Deadline.Sub(header.RequestedAt) > 24*time.Hour ||
		(header.Actor.TenantID.String() != "" && header.Actor.TenantID.String() != header.TenantID.String()) || (header.SiteID.String() != "" && header.TenantID.String() == "") { return ErrInvalidCommand }
	scope := command.commandScope()
	if scope.NodeID != header.NodeID || scope.TenantID.String() != header.TenantID.String() || scope.ID.IsZero() { return ErrInvalidCommand }
	if err := validateCommandBody(command); err != nil { return err }
	return authorizeCommand(command)
}

func validateCommandBody(command Command) error {
	switch value := command.(type) {
	case ApplyResourceProfile:
		return validateProposed(value.Profile, value.Header, value.ExpectedGeneration)
	case ResetTransferMonth:
		if validateProposed(value.Account, value.Header, value.ExpectedGeneration) != nil || value.Account.IngressBytes != 0 || value.Account.EgressBytes != 0 { return ErrInvalidCommand }
	case RecordTransferSample:
		return validateProposed(value.Account, value.Header, value.ExpectedGeneration)
	case ReplaceFirewallPolicy:
		return validateProposed(value.Policy, value.Header, value.ExpectedGeneration)
	case ReplaceSSHPolicy:
		return validateProposed(value.Policy, value.Header, value.ExpectedGeneration)
	case PutSSHKey:
		if !value.Key.ExpiresAt.IsZero() && !value.Key.ExpiresAt.After(value.Header.RequestedAt) { return ErrInvalidCommand }
		return validateProposed(value.Key, value.Header, value.ExpectedGeneration)
	case DeleteSSHKey:
		if value.KeyID.IsZero() || value.ExpectedGeneration == 0 { return ErrInvalidCommand }
	case ReplaceWAFPolicy:
		if validateProposed(value.Policy, value.Header, value.ExpectedGeneration) != nil { return ErrInvalidCommand }
		for _, exclusion := range value.Policy.Exclusions { if !exclusion.ExpiresAt.After(value.Header.RequestedAt) { return ErrInvalidCommand } }
	case SetServicePolicy:
		if value.Policy.ID != serviceResourceID(value.Policy.Service) { return ErrInvalidCommand }
		return validateProposed(value.Policy, value.Header, value.ExpectedGeneration)
	case ControlService:
		if !validService(value.Service) || value.ExpectedPolicyGeneration == 0 || (value.Action != ServiceStart && value.Action != ServiceStop && value.Action != ServiceRestart && value.Action != ServiceReload) { return ErrInvalidCommand }
	case DiagnoseService:
		if !validService(value.Service) || (value.Depth != DiagnosticSummary && value.Depth != DiagnosticDependency && value.Depth != DiagnosticDeep) || value.Since.IsZero() { return ErrInvalidCommand }
	case RepairService:
		if !validService(value.Service) || !validSHA256(value.DiagnosticProofDigest) || (value.Strategy != RepairReconcileConfig && value.Strategy != RepairResetFailed && value.Strategy != RepairReinstallManagedFiles && value.Strategy != RepairDependencyOrder) { return ErrInvalidCommand }
	case QueryMetrics:
		if value.Scope.Validate() != nil || value.Scope.NodeID != value.Header.NodeID || value.Scope.TenantID.String() != value.Header.TenantID.String() || value.Scope.SiteID.String() != value.Header.SiteID.String() ||
			!value.End.After(value.Start) || value.End.Sub(value.Start) > 31*24*time.Hour || value.Step < time.Second || value.Limit == 0 || value.Limit > 100000 || len(value.Names) == 0 || len(value.Names) > 32 { return ErrInvalidCommand }
		for _, name := range value.Names { if !validMetric(name) { return ErrInvalidCommand } }
	case OpenLogStream:
		if !validLogSource(value.Source) || !value.End.After(value.Start) || value.End.Sub(value.Start) > 7*24*time.Hour || value.MinimumSeverity > 7 || len(value.Cursor) > 512 || value.Limit == 0 || value.Limit > 10000 || (value.Source == LogServiceJournal && !validService(value.Service)) { return ErrInvalidCommand }
	case QuerySSHLogins:
		if !value.End.After(value.Start) || value.End.Sub(value.Start) > 31*24*time.Hour || value.Limit == 0 || value.Limit > 10000 || value.SourceCIDR != nil && !validPrefix(*value.SourceCIDR) { return ErrInvalidCommand }
	case QuerySSHSessions:
		if value.IncludeClosedSince.IsZero() || value.Limit == 0 || value.Limit > 10000 { return ErrInvalidCommand }
	case InvestigateProcess:
		if validateProcessIdentity(value.Process) != nil { return ErrInvalidCommand }
	case TerminateProcess:
		if validateProcessIdentity(value.Process) != nil || (value.Signal != SignalTerminate && value.Signal != SignalKill && value.Signal != SignalHangup) || !validSHA256(value.InvestigationProofDigest) || value.ReasonCode.IsZero() { return ErrInvalidCommand }
	case RequestPackageTransaction:
		if validateProposed(value.Transaction, value.Header, 0) != nil { return ErrInvalidCommand }
	case ReconcileManagedService:
		return validateProposed(value.Service, value.Header, value.ExpectedGeneration)
	default:
		return ErrInvalidCommand
	}
	return nil
}

func validateProposed(resource Resource, header CommandHeader, expected uint64) error {
	if resource == nil || resource.Validate() != nil { return ErrInvalidCommand }
	metadata := resource.Meta()
	if metadata.NodeID != header.NodeID || metadata.TenantID.String() != header.TenantID.String() || metadata.SiteID.String() != header.SiteID.String() ||
		(expected == 0 && metadata.Generation != 1) || (expected != 0 && metadata.Generation != expected+1) { return ErrInvalidCommand }
	return nil
}

func authorizeCommand(command Command) error {
	header := command.commandHeader()
	nodeScoped := header.TenantID.String() == ""
	switch command.(type) {
	case ReplaceFirewallPolicy, ReplaceSSHPolicy:
		if !nodeScoped || !header.Actor.Has(CapabilityNodeSecurity) || header.Actor.MFAProofRef.IsZero() || header.ApprovalRef.IsZero() { return ErrUnauthorized }
	case SetServicePolicy, ControlService, DiagnoseService, RepairService:
		if !nodeScoped || !header.Actor.Has(CapabilityNodeOperations) { return ErrUnauthorized }
	case ReconcileManagedService:
		if !header.Actor.Has(CapabilityNodeOperations) { return ErrUnauthorized }
	case RequestPackageTransaction:
		if !nodeScoped || !header.Actor.Has(CapabilityNodePackages) || header.Actor.MFAProofRef.IsZero() || header.ApprovalRef.IsZero() { return ErrUnauthorized }
	case TerminateProcess:
		if !nodeScoped || !header.Actor.Has(CapabilityProcessTerminate) || header.Actor.MFAProofRef.IsZero() { return ErrUnauthorized }
	case InvestigateProcess, QuerySSHLogins, QuerySSHSessions:
		if !nodeScoped || !header.Actor.Has(CapabilityNodeOperations) { return ErrUnauthorized }
	case ApplyResourceProfile:
		if !header.Actor.Has(CapabilityNodeOperations) { return ErrUnauthorized }
	case ResetTransferMonth, RecordTransferSample:
		if !header.Actor.Has(CapabilityNodeOperations) { return ErrUnauthorized }
	case PutSSHKey:
		if header.Actor.Has(CapabilityNodeSecurity) { return nil }
		if !header.Actor.Has(CapabilityTenantSecurity) || command.(PutSSHKey).Key.PrincipalID != header.Actor.PrincipalID { return ErrUnauthorized }
	case DeleteSSHKey, ReplaceWAFPolicy:
		if !header.Actor.Has(CapabilityNodeSecurity) && !header.Actor.Has(CapabilityTenantSecurity) { return ErrUnauthorized }
	case QueryMetrics, OpenLogStream:
		if !header.Actor.Has(CapabilityNodeOperations) && !header.Actor.Has(CapabilityTenantObserve) { return ErrUnauthorized }
	default:
		return ErrUnauthorized
	}
	return nil
}

func commandDigest(command Command) string {
	encoded, _ := json.Marshal(command)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validateProcessIdentity(identity ProcessIdentity) error {
	if identity.PID < 2 || identity.StartTimeTicks == 0 || identity.BootID.IsZero() { return ErrInvalidCommand }
	return nil
}

func validMetric(name MetricName) bool {
	switch name { case MetricCPUUsage, MetricMemoryUsage, MetricIOBytes, MetricNetworkBytes, MetricDiskUsage, MetricInodeUsage, MetricPHPWorkers, MetricServiceHealth: return true }
	return false
}

func validLogSource(source LogSource) bool {
	switch source { case LogPanel, LogWebAccess, LogWebError, LogPHP, LogMariaDB, LogMail, LogSSH, LogFirewall, LogWAF, LogServiceJournal: return true }
	return false
}
