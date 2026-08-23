package install

import (
	"context"
	"strings"
	"time"
)

type SystemFacts struct{Tuple PlatformTuple `json:"tuple"`;Hostname string `json:"hostname"`;MachineID string `json:"machine_id"`;BootID string `json:"boot_id"`;MemoryBytes uint64 `json:"memory_bytes"`;DiskFreeBytes uint64 `json:"disk_free_bytes"`;CPUCores uint16 `json:"cpu_cores"`;PID1 string `json:"pid1"`;RootFilesystem string `json:"root_filesystem"`;ExistingPanel bool `json:"existing_panel"`;OccupiedPorts []uint16 `json:"occupied_ports"`;ObservedAt time.Time `json:"observed_at"`}
type PreflightRequest struct{TransactionID string `json:"transaction_id"`;Kind TransactionKind `json:"kind"`;Expected PlatformTuple `json:"expected"`;MinimumMemoryBytes uint64 `json:"minimum_memory_bytes"`;MinimumDiskBytes uint64 `json:"minimum_disk_bytes"`;RequiredPorts []uint16 `json:"required_ports"`;AllowExisting bool `json:"allow_existing"`}
type PreflightReceipt struct{Facts SystemFacts `json:"facts"`;Checks map[string]string `json:"checks"`;Digest string `json:"digest"`;CompletedAt time.Time `json:"completed_at"`}
type PackageReceipt struct{ComponentID ComponentID `json:"component_id"`;Installed map[PackageID]string `json:"installed"`;RepositoryReceipts map[string]string `json:"repository_receipts"`;Digest string `json:"digest"`;CompletedAt time.Time `json:"completed_at"`}
type ArtifactReceipt struct{ArtifactID string `json:"artifact_id"`;StagedPath string `json:"staged_path"`;SHA256 string `json:"sha256"`;Size int64 `json:"size"`;Format ArtifactFormat `json:"format"`;TreeDigest string `json:"tree_digest,omitempty"`;Members []ArtifactMember `json:"members,omitempty"`;CompletedAt time.Time `json:"completed_at"`}
type MutationReceipt struct{Operation string `json:"operation"`;Resource string `json:"resource"`;OutputDigest string `json:"output_digest"`;Receipt string `json:"receipt"`;CompletedAt time.Time `json:"completed_at"`}
type HealthReceipt struct{Service ServiceID `json:"service"`;Check HealthCheckID `json:"check"`;Healthy bool `json:"healthy"`;EvidenceDigest string `json:"evidence_digest"`;ObservedAt time.Time `json:"observed_at"`}
type WatchdogTicket struct{ID string `json:"id"`;TransactionID string `json:"transaction_id"`;PreviousSlot SlotID `json:"previous_slot"`;PreviousReleaseID string `json:"previous_release_id"`;CandidateSlot SlotID `json:"candidate_slot"`;Deadline time.Time `json:"deadline"`;BootID string `json:"boot_id"`;Signature string `json:"signature"`}
type ExportReceipt struct{Path string `json:"path"`;Digest string `json:"digest"`;ManifestDigest string `json:"manifest_digest"`;Bytes uint64 `json:"bytes"`;CompletedAt time.Time `json:"completed_at"`}

// Host is deliberately closed and typed. It exposes no shell, arbitrary
// package, arbitrary path, unit, or command execution surface.
type Host interface{
	Probe(context.Context,WebEdition)(SystemFacts,error)
	Preflight(context.Context,PreflightRequest)(PreflightReceipt,error)
	PrepareTransaction(context.Context,TransactionPlan)(MutationReceipt,error)
	EnsureIdentity(context.Context,IdentityID)(MutationReceipt,error)
	InstallPackages(context.Context,PlatformTuple,ComponentID,[]PackageSelection)(PackageReceipt,error)
	StageArtifact(context.Context,string,ComponentID,Artifact)(ArtifactReceipt,error)
	DeployArtifact(context.Context,string,SlotID,ComponentID,ArtifactReceipt)(MutationReceipt,error)
	InstallEnterpriseLicense(context.Context,EnterpriseLicenseRef)(MutationReceipt,error)
	WriteManagedFiles(context.Context,SlotID,ComponentID,[]ManagedFile)(MutationReceipt,error)
	EnableServices(context.Context,PlatformTuple,[]ServiceSpec)([]MutationReceipt,error)
	ProbeServices(context.Context,PlatformTuple,[]ServiceSpec)([]HealthReceipt,error)
	ActivateSlot(context.Context,SlotID,string)(MutationReceipt,error)
	CurrentSlot(context.Context)(SlotID,string,error)
	Deactivate(context.Context,InstalledState,bool)(MutationReceipt,error)
	Export(context.Context,InstalledState,string)(ExportReceipt,error)
	CleanupTransaction(context.Context,TransactionPlan,bool)error
}

type StateInitializer interface{ApplyStateHook(context.Context,StateHookID,SlotID,string,ComponentDefinition)(MutationReceipt,error);RollbackStateHook(context.Context,StateHookID,SlotID,string,MutationReceipt)error}
type Watchdog interface{Arm(context.Context,WatchdogTicket)(WatchdogTicket,error);Disarm(context.Context,WatchdogTicket,string)error;Observe(context.Context,string)(WatchdogTicket,error)}

type Store interface{
	Admit(context.Context,TransactionPlan)(TransactionPlan,bool,error)
	LoadPlan(context.Context,string)(TransactionPlan,error)
	UpdatePlan(context.Context,TransactionPlan,uint64)error
	SaveInstalled(context.Context,InstalledState,uint64)error
	LoadInstalled(context.Context)(InstalledState,error)
	DeleteInstalled(context.Context,uint64)error
	SaveTombstone(context.Context,UninstallTombstone)error
	LoadTombstone(context.Context,string)(UninstallTombstone,error)
}

type EnterpriseLicenseRef struct{SourcePath string `json:"source_path"`;Kind string `json:"kind"`;Digest string `json:"digest"`}
func (license EnterpriseLicenseRef) Validate()error{if license.SourcePath!="/etc/cyberpanel/installer/input/litespeed-license.key"&&license.SourcePath!="/etc/cyberpanel/installer/input/litespeed-serial.no"{return ErrInvalid};if license.Kind!="license_key"&&license.Kind!="serial"{return ErrInvalid};if license.Kind=="license_key"&&!strings.HasSuffix(license.SourcePath,"license.key")||license.Kind=="serial"&&!strings.HasSuffix(license.SourcePath,"serial.no"){return ErrInvalid};if !validDigest(license.Digest){return ErrIntegrity};return nil}
