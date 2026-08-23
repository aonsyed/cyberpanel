package packagemaint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalid          = errors.New("package maintenance: invalid value")
	ErrNotFound         = errors.New("package maintenance: not found")
	ErrConflict         = errors.New("package maintenance: conflict")
	ErrStaleInventory   = errors.New("package maintenance: stale inventory")
	ErrStalePlan        = errors.New("package maintenance: stale plan")
	ErrUnauthorized     = errors.New("package maintenance: authorization required")
	ErrUnsupported      = errors.New("package maintenance: unsupported operation")
	ErrLocked           = errors.New("package maintenance: package database locked")
	ErrRecoveryRequired = errors.New("package maintenance: recovery required")
	ErrAmbiguous        = errors.New("package maintenance: ambiguous outcome")
)

const (
	MaximumPackages       = 50000
	MaximumRepositories   = 256
	MaximumAdvisories     = 10000
	MaximumHolds          = 10000
	MaximumLocks          = 32
	MaximumChanges        = 4096
	MaximumProvenance     = MaximumPackages + MaximumChanges
	MaximumDependencies   = 8192
	MaximumServiceImpacts = 256
	MaximumOutputBytes    = 8 << 20
)

type Manager string

const (
	ManagerAPT Manager = "apt"
	ManagerDNF Manager = "dnf"
)

type PackageState string

const (
	PackageInstalled PackageState = "installed"
	PackageResidual  PackageState = "residual_config"
)

type SignatureState string

const (
	SignatureVerified SignatureState = "verified"
	SignatureUnknown  SignatureState = "unknown"
	SignatureUnsigned SignatureState = "unsigned"
)

type SecurityClass string

const (
	SecurityNone     SecurityClass = "none"
	SecurityLow      SecurityClass = "low"
	SecurityModerate SecurityClass = "moderate"
	SecurityHigh     SecurityClass = "high"
	SecurityCritical SecurityClass = "critical"
	SecurityUnknown  SecurityClass = "unknown"
)

type Package struct {
	Name               string       `json:"name"`
	Architecture       string       `json:"architecture"`
	Epoch              string       `json:"epoch,omitempty"`
	InstalledVersion   string       `json:"installed_version"`
	CandidateVersion   string       `json:"candidate_version,omitempty"`
	SourcePackage      string       `json:"source_package,omitempty"`
	SourceVersion      string       `json:"source_version,omitempty"`
	RepositoryID       string       `json:"repository_id,omitempty"`
	State              PackageState `json:"state"`
	PendingSecurity    bool         `json:"pending_security"`
	ProvenanceDigest   string       `json:"provenance_digest"`
}

type Repository struct {
	ID               string         `json:"id"`
	Manager          Manager        `json:"manager"`
	Origin           string         `json:"origin"`
	Suite            string         `json:"suite,omitempty"`
	Component        string         `json:"component,omitempty"`
	Enabled          bool           `json:"enabled"`
	MetadataRevision string         `json:"metadata_revision,omitempty"`
	SigningKeyID     string         `json:"signing_key_id,omitempty"`
	Signature        SignatureState `json:"signature"`
	Digest           string         `json:"digest"`
}

type Advisory struct {
	ID               string        `json:"id"`
	Security         SecurityClass `json:"security"`
	PackageNames     []string      `json:"package_names"`
	CVEs             []string      `json:"cves,omitempty"`
	CurrentVersion   string        `json:"current_version,omitempty"`
	CorrectedVersion string        `json:"corrected_version,omitempty"`
	RepositoryID     string        `json:"repository_id,omitempty"`
	PublishedAt      time.Time     `json:"published_at,omitempty"`
}

type Hold struct {
	PackageName string `json:"package_name"`
	Kind        string `json:"kind"`
	Source      string `json:"source"`
}

type Lock struct {
	Kind       string    `json:"kind"`
	Path       string    `json:"path,omitempty"`
	Held       bool      `json:"held"`
	OwnerPID   int       `json:"owner_pid,omitempty"`
	RepairCode string    `json:"repair_code,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type Provenance struct {
	PackageName   string         `json:"package_name"`
	Architecture  string         `json:"architecture"`
	Version       string         `json:"version"`
	RepositoryID  string         `json:"repository_id,omitempty"`
	Vendor        string         `json:"vendor,omitempty"`
	Signature     SignatureState `json:"signature"`
	SigningKeyID  string         `json:"signing_key_id,omitempty"`
	LocalArtifact bool           `json:"local_artifact"`
	Digest        string         `json:"digest"`
}

type InventorySnapshot struct {
	ID             string       `json:"id"`
	NodeID         string       `json:"node_id"`
	Manager        Manager      `json:"manager"`
	Generation     uint64       `json:"generation"`
	ContentDigest  string       `json:"content_digest"`
	Packages       []Package    `json:"packages"`
	Repositories   []Repository `json:"repositories"`
	Advisories     []Advisory   `json:"advisories"`
	Holds          []Hold       `json:"holds"`
	Locks          []Lock       `json:"locks"`
	Provenance     []Provenance `json:"provenance"`
	RebootRequired bool         `json:"reboot_required"`
	CapturedAt     time.Time    `json:"captured_at"`
}

type ChangeAction string

const (
	ChangeInstall   ChangeAction = "install"
	ChangeUpgrade   ChangeAction = "upgrade"
	ChangeRemove    ChangeAction = "remove"
	ChangeReinstall ChangeAction = "reinstall"
)

type PackageChange struct {
	Name             string        `json:"name"`
	Architecture     string        `json:"architecture"`
	Action           ChangeAction  `json:"action"`
	FromVersion      string        `json:"from_version,omitempty"`
	ToVersion        string        `json:"to_version,omitempty"`
	RepositoryID     string        `json:"repository_id,omitempty"`
	ProvenanceDigest string        `json:"provenance_digest,omitempty"`
	Selected         bool          `json:"selected"`
	Security         SecurityClass `json:"security"`
}

type DependencyImpact struct {
	PackageName string       `json:"package_name"`
	RequiredBy  []string     `json:"required_by"`
	Action      ChangeAction `json:"action"`
}

type ServiceAction string

const (
	ServiceReload  ServiceAction = "reload"
	ServiceRestart ServiceAction = "restart"
	ServiceStop    ServiceAction = "stop"
)

type ServiceImpact struct {
	ServiceID string        `json:"service_id"`
	Action    ServiceAction `json:"action"`
	Required  bool          `json:"required"`
	ProbeID   string        `json:"probe_id"`
}

type DiskEstimate struct {
	DownloadBytes uint64 `json:"download_bytes"`
	InstalledDelta int64 `json:"installed_delta"`
	RequiredFree   uint64 `json:"required_free"`
}

type RebootEstimate string

const (
	RebootNone     RebootEstimate = "none"
	RebootPossible RebootEstimate = "possible"
	RebootRequired RebootEstimate = "required"
)

type RecoveryKind string

const (
	RecoveryNone       RecoveryKind = "none"
	RecoveryFilesystem RecoveryKind = "filesystem_snapshot"
	RecoveryProvider   RecoveryKind = "provider_snapshot"
)

type RecoveryEligibility struct {
	Kind         RecoveryKind `json:"kind"`
	Eligible     bool         `json:"eligible"`
	Required     bool         `json:"required"`
	ReasonCode   string       `json:"reason_code"`
	ScopeDigest  string       `json:"scope_digest,omitempty"`
	Instructions []string     `json:"instructions"`
}

type IrreversibleFrontier struct {
	Step                       string `json:"step"`
	ReasonCode                 string `json:"reason_code"`
	RequiresCommitAuthorization bool   `json:"requires_commit_authorization"`
	RecoveryInvalidAfter       bool   `json:"recovery_invalid_after"`
}

type MaintenancePlan struct {
	ID                  string                `json:"id"`
	NodeID              string                `json:"node_id"`
	Manager             Manager               `json:"manager"`
	MaintenanceOccurrenceID string            `json:"maintenance_occurrence_id"`
	InventoryID         string                `json:"inventory_id"`
	InventoryGeneration uint64                `json:"inventory_generation"`
	InventoryDigest     string                `json:"inventory_digest"`
	SolverDigest        string                `json:"solver_digest"`
	Generation          uint64                `json:"generation"`
	Changes             []PackageChange       `json:"changes"`
	Dependencies        []DependencyImpact    `json:"dependencies"`
	Holds               []Hold                `json:"holds"`
	Services            []ServiceImpact       `json:"services"`
	Security            SecurityClass         `json:"security"`
	Disk                DiskEstimate          `json:"disk"`
	Reboot              RebootEstimate        `json:"reboot"`
	Recovery            RecoveryEligibility   `json:"recovery"`
	Frontier            IrreversibleFrontier  `json:"irreversible_frontier"`
	Digest              string                `json:"digest"`
	CreatedAt           time.Time             `json:"created_at"`
	ExpiresAt           time.Time             `json:"expires_at"`
}

type OperationState string

const (
	OperationAdmitted         OperationState = "admitted"
	OperationAuthorized       OperationState = "authorized"
	OperationRunning          OperationState = "running"
	OperationVerifying        OperationState = "verifying"
	OperationSucceeded        OperationState = "succeeded"
	OperationFailed           OperationState = "failed"
	OperationRecoveryRequired OperationState = "recovery_required"
	OperationRecovered        OperationState = "recovered"
)

type Assurance string

const (
	AssurancePassword            Assurance = "password"
	AssuranceMFA                 Assurance = "mfa"
	AssurancePhishingResistant   Assurance = "phishing_resistant"
)

type AuthorizationEvidence struct {
	DecisionID          string    `json:"decision_id"`
	ActorID             string    `json:"actor_id"`
	Scope               string    `json:"scope"`
	Assurance           Assurance `json:"assurance"`
	RequestDigest       string    `json:"request_digest"`
	PolicyDigest        string    `json:"policy_digest"`
	AuthorizationEpoch  uint64    `json:"authorization_epoch"`
	GrantID             string    `json:"grant_id,omitempty"`
	GrantedAt           time.Time `json:"granted_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Digest              string    `json:"digest"`
}

type MaintenanceOperation struct {
	ID                    string                 `json:"id"`
	PlanID                string                 `json:"plan_id"`
	PlanDigest            string                 `json:"plan_digest"`
	PlanGeneration        uint64                 `json:"plan_generation"`
	InventoryGeneration   uint64                 `json:"inventory_generation"`
	InventoryDigest       string                 `json:"inventory_digest"`
	State                 OperationState         `json:"state"`
	Generation            uint64                 `json:"generation"`
	Fence                 uint64                 `json:"fence"`
	AcceptanceAuthorization AuthorizationEvidence `json:"acceptance_authorization"`
	CommitAuthorization   AuthorizationEvidence  `json:"commit_authorization,omitempty"`
	Receipt               ExecutionReceipt       `json:"receipt,omitempty"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	CompletedAt           time.Time              `json:"completed_at,omitempty"`
}

type CommandReceipt struct {
	Executable   string    `json:"executable"`
	ArgvDigest   string    `json:"argv_digest"`
	OutputDigest string    `json:"output_digest"`
	ExitCode     int       `json:"exit_code"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
}

type SnapshotReceipt struct {
	Kind       RecoveryKind `json:"kind"`
	SnapshotID string       `json:"snapshot_id,omitempty"`
	ScopeDigest string      `json:"scope_digest,omitempty"`
	Digest     string       `json:"digest,omitempty"`
	CreatedAt  time.Time    `json:"created_at,omitempty"`
}

type ServiceProbeReceipt struct {
	ServiceID     string    `json:"service_id"`
	ProbeID       string    `json:"probe_id"`
	Healthy       bool      `json:"healthy"`
	EvidenceDigest string    `json:"evidence_digest"`
	ObservedAt    time.Time `json:"observed_at"`
}

type RecoveryReceipt struct {
	Attempted    bool      `json:"attempted"`
	Restored     bool      `json:"restored"`
	SnapshotID   string    `json:"snapshot_id,omitempty"`
	EvidenceDigest string   `json:"evidence_digest,omitempty"`
	Instructions []string  `json:"instructions"`
	ObservedAt   time.Time `json:"observed_at,omitempty"`
}

type ObservedPackage struct {
	Name         string `json:"name"`
	Architecture string `json:"architecture"`
	Version      string `json:"version,omitempty"`
	Present      bool   `json:"present"`
}

type ExecutionOutcome string

const (
	OutcomeConfirmed        ExecutionOutcome = "confirmed"
	OutcomeFailed           ExecutionOutcome = "failed"
	OutcomeRecovered        ExecutionOutcome = "recovered"
	OutcomeRecoveryRequired ExecutionOutcome = "recovery_required"
	OutcomeAmbiguous        ExecutionOutcome = "ambiguous"
)

type ExecutionReceipt struct {
	EffectID             string                `json:"effect_id"`
	PlanID               string                `json:"plan_id"`
	PlanDigest           string                `json:"plan_digest"`
	InventoryGeneration  uint64                `json:"inventory_generation"`
	BeforeInventoryDigest string               `json:"before_inventory_digest"`
	AfterInventoryDigest string                `json:"after_inventory_digest,omitempty"`
	Fence                uint64                `json:"fence"`
	AuthorizationDigest  string                `json:"authorization_digest"`
	Outcome              ExecutionOutcome      `json:"outcome"`
	Commands             []CommandReceipt      `json:"commands"`
	Snapshot             SnapshotReceipt       `json:"snapshot,omitempty"`
	ObservedPackages     []ObservedPackage     `json:"observed_packages,omitempty"`
	ServiceProbes        []ServiceProbeReceipt `json:"service_probes,omitempty"`
	Recovery             RecoveryReceipt       `json:"recovery,omitempty"`
	IrreversibleCrossed  bool                  `json:"irreversible_crossed"`
	EvidenceDigest       string                `json:"evidence_digest"`
	ObservedAt           time.Time             `json:"observed_at"`
}

// RebootBootIdentity is the stable host identity a composed publisher must
// observe before a package effect that can require reboot. The requirement
// envelope assigns the receipt timestamp and a deterministic evidence digest
// so an uncertain publication can be replayed byte-for-byte.
type RebootBootIdentity struct {
	BootID        string `json:"boot_id"`
	KernelRelease string `json:"kernel_release"`
	KernelDigest  string `json:"kernel_digest"`
}

func (identity RebootBootIdentity) Validate() error {
	if !safeID.MatchString(identity.BootID) || !safeID.MatchString(identity.KernelRelease) || !validDigest(identity.KernelDigest) {
		return ErrInvalid
	}
	return nil
}

type RebootBootEvidence struct {
	RebootBootIdentity
	ObservedAt     time.Time `json:"observed_at"`
	EvidenceDigest string    `json:"evidence_digest"`
}

func (evidence RebootBootEvidence) Validate() error {
	if evidence.RebootBootIdentity.Validate() != nil || evidence.ObservedAt.IsZero() || evidence.ObservedAt.Location() != time.UTC ||
		evidence.EvidenceDigest != digestStrings("package-maintenance-boot", evidence.BootID, evidence.KernelRelease, evidence.KernelDigest) {
		return ErrInvalid
	}
	return nil
}

// RebootRequirement is passive, immutable package evidence. It authorizes no
// reboot and contains no schedule; a reboot-control adapter may only persist
// its digest under the same package operation ID.
type RebootRequirement struct {
	ID                      string             `json:"id"`
	NodeID                  string             `json:"node_id"`
	PackageOperationID      string             `json:"package_operation_id"`
	PackagePlanID           string             `json:"package_plan_id"`
	PackagePlanDigest       string             `json:"package_plan_digest"`
	PackageReceiptDigest    string             `json:"package_receipt_digest"`
	MaintenanceOccurrenceID string             `json:"maintenance_occurrence_id"`
	Reboot                  RebootEstimate     `json:"reboot"`
	CurrentBoot             RebootBootEvidence `json:"current_boot"`
	AffectedServices        []ServiceImpact    `json:"affected_services"`
	AffectedPackages        []PackageChange    `json:"affected_packages"`
	ObservedAt              time.Time          `json:"observed_at"`
	Digest                  string             `json:"digest"`
}

func CanonicalRebootRequirement(requirement RebootRequirement) (RebootRequirement, error) {
	requirement.CurrentBoot.ObservedAt = requirement.CurrentBoot.ObservedAt.UTC()
	requirement.ObservedAt = requirement.ObservedAt.UTC()
	requirement.AffectedServices = append([]ServiceImpact(nil), requirement.AffectedServices...)
	sort.Slice(requirement.AffectedServices, func(left, right int) bool {
		return requirement.AffectedServices[left].ServiceID+"\x00"+requirement.AffectedServices[left].ProbeID <
			requirement.AffectedServices[right].ServiceID+"\x00"+requirement.AffectedServices[right].ProbeID
	})
	requirement.AffectedPackages = append([]PackageChange(nil), requirement.AffectedPackages...)
	sort.Slice(requirement.AffectedPackages, func(left, right int) bool {
		return packageChangeKey(requirement.AffectedPackages[left]) < packageChangeKey(requirement.AffectedPackages[right])
	})
	provided := requirement.Digest
	requirement.Digest = ""
	if err := validateRebootRequirement(requirement); err != nil {
		return RebootRequirement{}, err
	}
	digest, err := canonicalDigest(requirement)
	if err != nil {
		return RebootRequirement{}, err
	}
	requirement.Digest = digest
	if provided != "" && provided != digest {
		return RebootRequirement{}, ErrConflict
	}
	return requirement, nil
}

func validateRebootRequirement(requirement RebootRequirement) error {
	if !safeID.MatchString(requirement.ID) || requirement.ID != requirement.PackageOperationID || !safeID.MatchString(requirement.NodeID) ||
		!safeID.MatchString(requirement.PackagePlanID) || !validDigest(requirement.PackagePlanDigest) || !validDigest(requirement.PackageReceiptDigest) ||
		!safeID.MatchString(requirement.MaintenanceOccurrenceID) || requirement.Reboot != RebootRequired || requirement.CurrentBoot.Validate() != nil ||
		len(requirement.AffectedServices) > MaximumServiceImpacts || len(requirement.AffectedPackages) == 0 || len(requirement.AffectedPackages) > MaximumChanges ||
		requirement.ObservedAt.IsZero() || requirement.ObservedAt.Location() != time.UTC || !requirement.ObservedAt.Equal(requirement.CurrentBoot.ObservedAt) {
		return ErrInvalid
	}
	for index, service := range requirement.AffectedServices {
		if !safeID.MatchString(service.ServiceID) || !safeID.MatchString(service.ProbeID) || !validServiceAction(service.Action) ||
			index > 0 && requirement.AffectedServices[index-1].ServiceID+"\x00"+requirement.AffectedServices[index-1].ProbeID >= service.ServiceID+"\x00"+service.ProbeID {
			return ErrInvalid
		}
	}
	for index, change := range requirement.AffectedPackages {
		if validateChange(change) != nil || index > 0 && packageChangeKey(requirement.AffectedPackages[index-1]) >= packageChangeKey(change) {
			return ErrInvalid
		}
	}
	return nil
}

type AuditRecord struct {
	ID           string    `json:"id"`
	OperationID  string    `json:"operation_id"`
	ActorID      string    `json:"actor_id"`
	Action       string    `json:"action"`
	Outcome      string    `json:"outcome"`
	RequestDigest string    `json:"request_digest"`
	EvidenceDigest string   `json:"evidence_digest"`
	ObservedAt   time.Time `json:"observed_at"`
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`)
var safePackage = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)
var safeArchitecture = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$`)
var safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+:~_^-]{0,255}$`)

func (snapshot InventorySnapshot) Validate() error {
	if !safeID.MatchString(snapshot.ID) || !safeID.MatchString(snapshot.NodeID) || !validManager(snapshot.Manager) || snapshot.Generation == 0 || !validDigest(snapshot.ContentDigest) || snapshot.CapturedAt.IsZero() || len(snapshot.Packages) > MaximumPackages || len(snapshot.Repositories) > MaximumRepositories || len(snapshot.Advisories) > MaximumAdvisories || len(snapshot.Holds) > MaximumHolds || len(snapshot.Locks) > MaximumLocks || len(snapshot.Provenance) > MaximumProvenance {
		return ErrInvalid
	}
	packageKeys := make(map[string]struct{}, len(snapshot.Packages))
	for _, value := range snapshot.Packages {
		if validatePackage(value) != nil {
			return ErrInvalid
		}
		key := value.Name + "\x00" + value.Architecture
		if _, duplicate := packageKeys[key]; duplicate {
			return ErrInvalid
		}
		packageKeys[key] = struct{}{}
	}
	repositories := make(map[string]struct{}, len(snapshot.Repositories))
	for _, value := range snapshot.Repositories {
		if validateRepository(value, snapshot.Manager) != nil {
			return ErrInvalid
		}
		if _, duplicate := repositories[value.ID]; duplicate {
			return ErrInvalid
		}
		repositories[value.ID] = struct{}{}
	}
	for _, value := range snapshot.Advisories {
		if validateAdvisory(value) != nil {
			return ErrInvalid
		}
	}
	holds := make(map[string]struct{}, len(snapshot.Holds))
	for _, value := range snapshot.Holds {
		if validateHold(value) != nil {
			return ErrInvalid
		}
		key := value.PackageName + "\x00" + value.Kind + "\x00" + value.Source
		if _, duplicate := holds[key]; duplicate {
			return ErrInvalid
		}
		holds[key] = struct{}{}
	}
	locks := make(map[string]struct{}, len(snapshot.Locks))
	for _, value := range snapshot.Locks {
		if validateLock(value) != nil {
			return ErrInvalid
		}
		key := value.Kind + "\x00" + value.Path + "\x00" + value.RepairCode
		if _, duplicate := locks[key]; duplicate {
			return ErrInvalid
		}
		locks[key] = struct{}{}
	}
	provenanceDigests := make(map[string]Provenance, len(snapshot.Provenance))
	for _, value := range snapshot.Provenance {
		copyOfValue := value
		copyOfValue.Digest = ""
		digest, err := canonicalDigest(copyOfValue)
		if !safePackage.MatchString(value.PackageName) || !safeArchitecture.MatchString(value.Architecture) || !safeVersion.MatchString(value.Version) || value.RepositoryID != "" && !safeID.MatchString(value.RepositoryID) || len(value.Vendor) > 512 || strings.ContainsAny(value.Vendor, "\x00\r\n") || !validSignature(value.Signature) || value.SigningKeyID != "" && !safeID.MatchString(value.SigningKeyID) || value.Signature == SignatureVerified && value.SigningKeyID == "" || !validDigest(value.Digest) || err != nil || digest != value.Digest {
			return ErrInvalid
		}
		if value.RepositoryID != "" {
			if _, exists := repositories[value.RepositoryID]; !exists {
				return ErrInvalid
			}
		}
		if _, duplicate := provenanceDigests[value.Digest]; duplicate {
			return ErrInvalid
		}
		provenanceDigests[value.Digest] = value
	}
	for _, value := range snapshot.Packages {
		installed, exists := provenanceDigests[value.ProvenanceDigest]
		if !exists || installed.PackageName != value.Name || installed.Architecture != value.Architecture || installed.Version != value.InstalledVersion {
			return ErrInvalid
		}
		if value.CandidateVersion != "" {
			if value.RepositoryID == "" || !hasCandidateProvenance(snapshot.Provenance, value) {
				return ErrInvalid
			}
		}
	}
	content := inventoryContent(snapshot)
	digest, err := canonicalDigest(content)
	identity := digestStrings(snapshot.NodeID, string(snapshot.Manager), strconv.FormatUint(snapshot.Generation, 10), digest)
	if err != nil || digest != snapshot.ContentDigest || snapshot.ID != "inv_"+identity[:32] {
		return ErrInvalid
	}
	return nil
}

func hasCandidateProvenance(values []Provenance, candidate Package) bool {
	for _, value := range values {
		if value.PackageName == candidate.Name && value.Architecture == candidate.Architecture && value.Version == candidate.CandidateVersion && value.RepositoryID == candidate.RepositoryID {
			return true
		}
	}
	return false
}

func (plan MaintenancePlan) Validate() error {
	if !safeID.MatchString(plan.ID) || !safeID.MatchString(plan.NodeID) || !validManager(plan.Manager) || !safeID.MatchString(plan.MaintenanceOccurrenceID) || !safeID.MatchString(plan.InventoryID) || plan.InventoryGeneration == 0 || !validDigest(plan.InventoryDigest) || !validDigest(plan.SolverDigest) || plan.Generation == 0 || len(plan.Changes) == 0 || len(plan.Changes) > MaximumChanges || len(plan.Dependencies) > MaximumDependencies || len(plan.Holds) > MaximumHolds || len(plan.Services) > MaximumServiceImpacts || !validSecurity(plan.Security) || !validDigest(plan.Digest) || plan.CreatedAt.IsZero() || !plan.ExpiresAt.After(plan.CreatedAt) || plan.ExpiresAt.Sub(plan.CreatedAt) > 24*time.Hour {
		return ErrInvalid
	}
	changes := make(map[string]struct{}, len(plan.Changes))
	for _, change := range plan.Changes {
		if validateChange(change) != nil {
			return ErrInvalid
		}
		key := change.Name + "\x00" + change.Architecture
		if _, duplicate := changes[key]; duplicate {
			return ErrInvalid
		}
		changes[key] = struct{}{}
	}
	dependencies := make(map[string]struct{}, len(plan.Dependencies))
	for _, impact := range plan.Dependencies {
		if !safePackage.MatchString(impact.PackageName) || !validChangeAction(impact.Action) || len(impact.RequiredBy) > 128 {
			return ErrInvalid
		}
		for _, name := range impact.RequiredBy {
			if !safePackage.MatchString(name) {
				return ErrInvalid
			}
		}
		if _, duplicate := dependencies[impact.PackageName]; duplicate {
			return ErrInvalid
		}
		dependencies[impact.PackageName] = struct{}{}
	}
	for _, hold := range plan.Holds {
		if validateHold(hold) != nil {
			return ErrInvalid
		}
	}
	services := make(map[string]struct{}, len(plan.Services))
	for _, impact := range plan.Services {
		if !safeID.MatchString(impact.ServiceID) || !safeID.MatchString(impact.ProbeID) || !validServiceAction(impact.Action) {
			return ErrInvalid
		}
		key := impact.ServiceID + "\x00" + impact.ProbeID
		if _, duplicate := services[key]; duplicate {
			return ErrInvalid
		}
		services[key] = struct{}{}
	}
	if !validReboot(plan.Reboot) || validateRecovery(plan.Recovery) != nil || !safeID.MatchString(plan.Frontier.Step) || !safeID.MatchString(plan.Frontier.ReasonCode) || !plan.Frontier.RequiresCommitAuthorization {
		return ErrInvalid
	}
	copyOfPlan := plan
	copyOfPlan.Digest = ""
	digest, err := canonicalDigest(copyOfPlan)
	if err != nil || digest != plan.Digest {
		return ErrInvalid
	}
	return nil
}

func (evidence AuthorizationEvidence) Validate(minimum Assurance, now time.Time) error {
	if !safeID.MatchString(evidence.DecisionID) || !safeID.MatchString(evidence.ActorID) || !safeID.MatchString(evidence.Scope) || !validDigest(evidence.RequestDigest) || !validDigest(evidence.PolicyDigest) || evidence.AuthorizationEpoch == 0 || evidence.GrantID != "" && !safeID.MatchString(evidence.GrantID) || evidence.GrantedAt.IsZero() || !evidence.ExpiresAt.After(evidence.GrantedAt) || evidence.ExpiresAt.Sub(evidence.GrantedAt) > 15*time.Minute || now.Before(evidence.GrantedAt.Add(-time.Minute)) || !now.Before(evidence.ExpiresAt) || !validDigest(evidence.Digest) || assuranceRank(evidence.Assurance) < assuranceRank(minimum) {
		return ErrUnauthorized
	}
	copyOfEvidence := evidence
	copyOfEvidence.Digest = ""
	digest, err := canonicalDigest(copyOfEvidence)
	if err != nil || digest != evidence.Digest {
		return ErrUnauthorized
	}
	return nil
}

func SealAuthorizationEvidence(evidence *AuthorizationEvidence) error {
	if evidence == nil {
		return ErrInvalid
	}
	evidence.Digest = ""
	digest, err := canonicalDigest(*evidence)
	if err != nil {
		return err
	}
	evidence.Digest = digest
	return nil
}

func validatePackage(value Package) error {
	if !safePackage.MatchString(value.Name) || !safeArchitecture.MatchString(value.Architecture) || value.Epoch != "" && !safeVersion.MatchString(value.Epoch) || !safeVersion.MatchString(value.InstalledVersion) || value.CandidateVersion != "" && !safeVersion.MatchString(value.CandidateVersion) || value.SourcePackage != "" && !safePackage.MatchString(value.SourcePackage) || value.SourceVersion != "" && !safeVersion.MatchString(value.SourceVersion) || value.RepositoryID != "" && !safeID.MatchString(value.RepositoryID) || value.State != PackageInstalled && value.State != PackageResidual || !validDigest(value.ProvenanceDigest) {
		return ErrInvalid
	}
	return nil
}

func validateRepository(value Repository, manager Manager) error {
	copyOfValue := value
	copyOfValue.Digest = ""
	digest, err := canonicalDigest(copyOfValue)
	if !safeID.MatchString(value.ID) || value.Manager != manager || value.Origin == "" || len(value.Origin) > 2048 || strings.ContainsAny(value.Origin, "\x00\r\n") || len(value.Suite) > 256 || strings.ContainsAny(value.Suite, "\x00\r\n") || len(value.Component) > 256 || strings.ContainsAny(value.Component, "\x00\r\n") || value.MetadataRevision != "" && !validDigest(value.MetadataRevision) || value.SigningKeyID != "" && !safeID.MatchString(value.SigningKeyID) || value.Signature == SignatureVerified && (value.SigningKeyID == "" || value.MetadataRevision == "") || !validSignature(value.Signature) || !validDigest(value.Digest) || err != nil || digest != value.Digest {
		return ErrInvalid
	}
	return nil
}

func validateAdvisory(value Advisory) error {
	if !safeID.MatchString(value.ID) || !validSecurity(value.Security) || len(value.PackageNames) == 0 || len(value.PackageNames) > 256 || len(value.CVEs) > 256 || value.CurrentVersion != "" && !safeVersion.MatchString(value.CurrentVersion) || value.CorrectedVersion != "" && !safeVersion.MatchString(value.CorrectedVersion) || value.RepositoryID != "" && !safeID.MatchString(value.RepositoryID) {
		return ErrInvalid
	}
	for _, name := range value.PackageNames {
		if !safePackage.MatchString(name) {
			return ErrInvalid
		}
	}
	for _, cve := range value.CVEs {
		if !safeID.MatchString(cve) {
			return ErrInvalid
		}
	}
	return nil
}

func validateHold(value Hold) error {
	if !safePackage.MatchString(value.PackageName) || !safeID.MatchString(value.Kind) || !safeID.MatchString(value.Source) {
		return ErrInvalid
	}
	return nil
}

func validateLock(value Lock) error {
	if !safeID.MatchString(value.Kind) || value.OwnerPID < 0 || !value.Held && value.OwnerPID != 0 || value.ObservedAt.IsZero() || value.Path != "" && (len(value.Path) > 512 || !strings.HasPrefix(value.Path, "/") || strings.ContainsAny(value.Path, "\x00\r\n")) || value.RepairCode != "" && !safeID.MatchString(value.RepairCode) {
		return ErrInvalid
	}
	return nil
}

func validateChange(change PackageChange) error {
	if !safePackage.MatchString(change.Name) || !safeArchitecture.MatchString(change.Architecture) || !validChangeAction(change.Action) || !validSecurity(change.Security) {
		return ErrInvalid
	}
	switch change.Action {
	case ChangeInstall:
		if change.FromVersion != "" || !safeVersion.MatchString(change.ToVersion) {
			return ErrInvalid
		}
	case ChangeUpgrade, ChangeReinstall:
		if !safeVersion.MatchString(change.FromVersion) || !safeVersion.MatchString(change.ToVersion) {
			return ErrInvalid
		}
	case ChangeRemove:
		if !safeVersion.MatchString(change.FromVersion) || change.ToVersion != "" {
			return ErrInvalid
		}
	}
	if change.Action != ChangeRemove && (!safeID.MatchString(change.RepositoryID) || !validDigest(change.ProvenanceDigest)) {
		return ErrInvalid
	}
	return nil
}

func validateRecovery(value RecoveryEligibility) error {
	if value.Kind != RecoveryNone && value.Kind != RecoveryFilesystem && value.Kind != RecoveryProvider || !safeID.MatchString(value.ReasonCode) || len(value.Instructions) == 0 || len(value.Instructions) > 32 {
		return ErrInvalid
	}
	if value.Eligible && value.Kind == RecoveryNone || !value.Eligible && value.Required || value.Eligible && !validDigest(value.ScopeDigest) || !value.Eligible && value.ScopeDigest != "" {
		return ErrInvalid
	}
	for _, instruction := range value.Instructions {
		if !safeID.MatchString(instruction) {
			return ErrInvalid
		}
	}
	return nil
}

func validManager(value Manager) bool { return value == ManagerAPT || value == ManagerDNF }
func validSignature(value SignatureState) bool { return value == SignatureVerified || value == SignatureUnknown || value == SignatureUnsigned }
func validSecurity(value SecurityClass) bool { return value == SecurityNone || value == SecurityLow || value == SecurityModerate || value == SecurityHigh || value == SecurityCritical || value == SecurityUnknown }
func validChangeAction(value ChangeAction) bool { return value == ChangeInstall || value == ChangeUpgrade || value == ChangeRemove || value == ChangeReinstall }
func validServiceAction(value ServiceAction) bool { return value == ServiceReload || value == ServiceRestart || value == ServiceStop }
func validReboot(value RebootEstimate) bool { return value == RebootNone || value == RebootPossible || value == RebootRequired }

func assuranceRank(value Assurance) int {
	switch value {
	case AssurancePassword:
		return 1
	case AssuranceMFA:
		return 2
	case AssurancePhishingResistant:
		return 3
	default:
		return 0
	}
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func canonicalDigest(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func digestStrings(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func canonicalizeInventory(snapshot *InventorySnapshot) {
	for index := range snapshot.Advisories {
		sort.Strings(snapshot.Advisories[index].PackageNames)
		sort.Strings(snapshot.Advisories[index].CVEs)
	}
	sort.Slice(snapshot.Packages, func(i, j int) bool { return snapshot.Packages[i].Name+"\x00"+snapshot.Packages[i].Architecture < snapshot.Packages[j].Name+"\x00"+snapshot.Packages[j].Architecture })
	sort.Slice(snapshot.Repositories, func(i, j int) bool { return snapshot.Repositories[i].ID < snapshot.Repositories[j].ID })
	sort.Slice(snapshot.Advisories, func(i, j int) bool { return snapshot.Advisories[i].ID+"\x00"+strings.Join(snapshot.Advisories[i].PackageNames, "\x00")+"\x00"+snapshot.Advisories[i].CorrectedVersion < snapshot.Advisories[j].ID+"\x00"+strings.Join(snapshot.Advisories[j].PackageNames, "\x00")+"\x00"+snapshot.Advisories[j].CorrectedVersion })
	sort.Slice(snapshot.Holds, func(i, j int) bool { return snapshot.Holds[i].PackageName+"\x00"+snapshot.Holds[i].Kind+"\x00"+snapshot.Holds[i].Source < snapshot.Holds[j].PackageName+"\x00"+snapshot.Holds[j].Kind+"\x00"+snapshot.Holds[j].Source })
	sort.Slice(snapshot.Locks, func(i, j int) bool { return snapshot.Locks[i].Kind+"\x00"+snapshot.Locks[i].Path+"\x00"+snapshot.Locks[i].RepairCode < snapshot.Locks[j].Kind+"\x00"+snapshot.Locks[j].Path+"\x00"+snapshot.Locks[j].RepairCode })
	sort.Slice(snapshot.Provenance, func(i, j int) bool { return snapshot.Provenance[i].PackageName+"\x00"+snapshot.Provenance[i].Architecture+"\x00"+snapshot.Provenance[i].Version+"\x00"+snapshot.Provenance[i].RepositoryID+"\x00"+snapshot.Provenance[i].Digest < snapshot.Provenance[j].PackageName+"\x00"+snapshot.Provenance[j].Architecture+"\x00"+snapshot.Provenance[j].Version+"\x00"+snapshot.Provenance[j].RepositoryID+"\x00"+snapshot.Provenance[j].Digest })
}

func inventoryContent(snapshot InventorySnapshot) InventorySnapshot {
	content := snapshot
	content.ID, content.ContentDigest, content.CapturedAt, content.Generation = "", "", time.Time{}, 0
	content.Locks = append([]Lock(nil), snapshot.Locks...)
	for index := range content.Locks {
		content.Locks[index].ObservedAt = time.Time{}
	}
	return content
}
