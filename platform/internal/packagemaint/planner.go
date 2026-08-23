package packagemaint

import (
	"errors"
	"sort"
	"strconv"
	"time"
)

// SolverAttestation is the bounded, immutable result of a native package
// manager dependency-resolution pass. Planner never guesses a dependency
// closure or version ordering.
type SolverAttestation struct {
	ResolverID       string                `json:"resolver_id"`
	InventoryDigest string                `json:"inventory_digest"`
	Changes          []PackageChange       `json:"changes"`
	Dependencies     []DependencyImpact    `json:"dependencies"`
	Services         []ServiceImpact       `json:"services"`
	Disk             DiskEstimate          `json:"disk"`
	Reboot           RebootEstimate        `json:"reboot"`
	Recovery         RecoveryEligibility   `json:"recovery"`
	Frontier         IrreversibleFrontier  `json:"irreversible_frontier"`
	ResolvedAt       time.Time             `json:"resolved_at"`
	TransactionDigest string               `json:"transaction_digest"`
	Digest           string                `json:"digest"`
}

type PlanRequest struct {
	Generation              uint64
	ValidFor                time.Duration
	MaintenanceOccurrenceID string
	Attestation             SolverAttestation
}

// Planner accepts only a complete solver attestation whose exact package
// versions and provenance are present in the referenced inventory.
type Planner struct {
	Now func() time.Time
}

func (planner Planner) Build(snapshot InventorySnapshot, request PlanRequest) (MaintenancePlan, error) {
	if err := snapshot.Validate(); err != nil || request.Generation == 0 || request.ValidFor <= 0 || request.ValidFor > 24*time.Hour || !safeID.MatchString(request.MaintenanceOccurrenceID) {
		return MaintenancePlan{}, ErrInvalid
	}
	for _, lock := range snapshot.Locks {
		if lock.Held {
			return MaintenancePlan{}, ErrLocked
		}
		if lock.RepairCode != "" {
			return MaintenancePlan{}, ErrRecoveryRequired
		}
	}
	now := time.Now().UTC()
	if planner.Now != nil {
		now = planner.Now().UTC()
	}
	if now.Before(snapshot.CapturedAt) {
		return MaintenancePlan{}, ErrInvalid
	}
	attestation := request.Attestation
	if err := validateAttestation(attestation, snapshot.ContentDigest, now); err != nil {
		return MaintenancePlan{}, err
	}
	if attestation.ResolvedAt.Before(snapshot.CapturedAt) {
		return MaintenancePlan{}, ErrStaleInventory
	}
	changes := append([]PackageChange(nil), attestation.Changes...)
	dependencies := cloneDependencies(attestation.Dependencies)
	services := append([]ServiceImpact(nil), attestation.Services...)
	holds := append([]Hold(nil), snapshot.Holds...)
	if err := bindChanges(snapshot, changes, dependencies); err != nil {
		return MaintenancePlan{}, err
	}
	security := classifyChanges(snapshot, changes)
	for index := range changes {
		changes[index].Security = classifyPackage(snapshot, changes[index])
	}
	sort.Slice(changes, func(i, j int) bool {
		return packageChangeKey(changes[i]) < packageChangeKey(changes[j])
	})
	if attestation.Recovery.Eligible {
		scopeDigest, err := PackageScopeDigest(changes)
		if err != nil || scopeDigest != attestation.Recovery.ScopeDigest {
			return MaintenancePlan{}, ErrInvalid
		}
	}
	sort.Slice(dependencies, func(i, j int) bool {
		return dependencies[i].PackageName < dependencies[j].PackageName
	})
	for index := range dependencies {
		sort.Strings(dependencies[index].RequiredBy)
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].ServiceID+"\x00"+services[i].ProbeID < services[j].ServiceID+"\x00"+services[j].ProbeID
	})
	sort.Slice(holds, func(i, j int) bool { return holds[i].PackageName+"\x00"+holds[i].Kind+"\x00"+holds[i].Source < holds[j].PackageName+"\x00"+holds[j].Kind+"\x00"+holds[j].Source })
	plan := MaintenancePlan{
		NodeID:              snapshot.NodeID,
		Manager:             snapshot.Manager,
		MaintenanceOccurrenceID: request.MaintenanceOccurrenceID,
		InventoryID:         snapshot.ID,
		InventoryGeneration: snapshot.Generation,
		InventoryDigest:     snapshot.ContentDigest,
		SolverDigest:        attestation.TransactionDigest,
		Generation:          request.Generation,
		Changes:             changes,
		Dependencies:        dependencies,
		Holds:               holds,
		Services:            services,
		Security:            security,
		Disk:                attestation.Disk,
		Reboot:              attestation.Reboot,
		Recovery:            attestation.Recovery,
		Frontier:            attestation.Frontier,
		CreatedAt:           now,
		ExpiresAt:           now.Add(request.ValidFor),
	}
	identity := digestStrings(snapshot.NodeID, string(snapshot.Manager), strconv.FormatUint(request.Generation, 10), snapshot.ContentDigest, attestation.Digest)
	plan.ID = "plan_" + identity[:32]
	digest, err := canonicalDigest(plan)
	if err != nil {
		return MaintenancePlan{}, err
	}
	plan.Digest = digest
	if err := plan.Validate(); err != nil {
		return MaintenancePlan{}, err
	}
	return plan, nil
}

func validateAttestation(value SolverAttestation, inventoryDigest string, now time.Time) error {
	if !safeID.MatchString(value.ResolverID) || value.InventoryDigest != inventoryDigest || len(value.Changes) == 0 || len(value.Changes) > MaximumChanges || len(value.Dependencies) > MaximumDependencies || len(value.Services) > MaximumServiceImpacts || value.ResolvedAt.IsZero() || value.ResolvedAt.After(now.Add(time.Minute)) || now.Sub(value.ResolvedAt) > 30*time.Minute || !validDigest(value.TransactionDigest) || !validDigest(value.Digest) || !validReboot(value.Reboot) || validateRecovery(value.Recovery) != nil || !safeID.MatchString(value.Frontier.Step) || !safeID.MatchString(value.Frontier.ReasonCode) || !value.Frontier.RequiresCommitAuthorization {
		return ErrInvalid
	}
	for _, change := range value.Changes {
		if validateChange(change) != nil {
			return ErrInvalid
		}
	}
	for _, dependency := range value.Dependencies {
		if !safePackage.MatchString(dependency.PackageName) || !validChangeAction(dependency.Action) || len(dependency.RequiredBy) == 0 || len(dependency.RequiredBy) > 128 {
			return ErrInvalid
		}
		for _, name := range dependency.RequiredBy {
			if !safePackage.MatchString(name) {
				return ErrInvalid
			}
		}
	}
	for _, service := range value.Services {
		if !safeID.MatchString(service.ServiceID) || !safeID.MatchString(service.ProbeID) || !validServiceAction(service.Action) {
			return ErrInvalid
		}
	}
	copyOfValue := value
	copyOfValue.Digest = ""
	digest, err := canonicalDigest(copyOfValue)
	transactionCopy := value
	transactionCopy.ResolvedAt = time.Time{}
	transactionCopy.TransactionDigest = ""
	transactionCopy.Digest = ""
	transactionDigest, transactionErr := canonicalDigest(transactionCopy)
	if err != nil || digest != value.Digest || transactionErr != nil || transactionDigest != value.TransactionDigest {
		return ErrInvalid
	}
	return nil
}

// SealSolverAttestation assigns both the stable transaction digest and the
// timestamped observation digest after a native solver has produced closure.
func SealSolverAttestation(value *SolverAttestation) error {
	if value == nil || value.ResolvedAt.IsZero() {
		return ErrInvalid
	}
	value.TransactionDigest, value.Digest = "", ""
	transactionCopy := *value
	transactionCopy.ResolvedAt = time.Time{}
	transactionDigest, err := canonicalDigest(transactionCopy)
	if err != nil {
		return err
	}
	value.TransactionDigest = transactionDigest
	digest, err := canonicalDigest(*value)
	if err != nil {
		return err
	}
	value.Digest = digest
	return nil
}

func bindChanges(snapshot InventorySnapshot, changes []PackageChange, dependencies []DependencyImpact) error {
	packages := make(map[string]Package, len(snapshot.Packages))
	for _, installed := range snapshot.Packages {
		key := installed.Name + "\x00" + installed.Architecture
		if _, exists := packages[key]; exists {
			return ErrInvalid
		}
		packages[key] = installed
	}
	holds := make(map[string]struct{}, len(snapshot.Holds))
	for _, hold := range snapshot.Holds {
		holds[hold.PackageName] = struct{}{}
	}
	repositories := make(map[string]Repository, len(snapshot.Repositories))
	for _, repository := range snapshot.Repositories {
		repositories[repository.ID] = repository
	}
	provenance := make(map[string]Provenance, len(snapshot.Provenance))
	for _, source := range snapshot.Provenance {
		key := source.PackageName + "\x00" + source.Architecture + "\x00" + source.Version + "\x00" + source.RepositoryID
		provenance[key] = source
	}
	changed := make(map[string]PackageChange, len(changes))
	for _, change := range changes {
		key := change.Name + "\x00" + change.Architecture
		if _, duplicate := changed[key]; duplicate {
			return ErrInvalid
		}
		changed[key] = change
		if _, held := holds[change.Name]; held {
			return ErrConflict
		}
		installed, present := packages[key]
		switch change.Action {
		case ChangeInstall:
			if present {
				return ErrConflict
			}
		case ChangeUpgrade:
			if !present || change.FromVersion != installed.InstalledVersion || change.ToVersion == change.FromVersion || installed.CandidateVersion == "" || change.ToVersion != installed.CandidateVersion {
				return ErrStaleInventory
			}
		case ChangeReinstall:
			if !present || change.FromVersion != installed.InstalledVersion || change.ToVersion != installed.InstalledVersion {
				return ErrStaleInventory
			}
		case ChangeRemove:
			if !present || change.FromVersion != installed.InstalledVersion {
				return ErrStaleInventory
			}
		}
		if change.Action == ChangeRemove {
			continue
		}
		repository, exists := repositories[change.RepositoryID]
		if !exists || !repository.Enabled || repository.Signature != SignatureVerified {
			return ErrUnauthorized
		}
		source, exists := provenance[change.Name+"\x00"+change.Architecture+"\x00"+change.ToVersion+"\x00"+change.RepositoryID]
		if !exists || source.Digest != change.ProvenanceDigest || source.Signature != SignatureVerified || source.SigningKeyID != repository.SigningKeyID || source.LocalArtifact {
			return ErrUnauthorized
		}
	}
	dependencyNames := make(map[string]struct{}, len(dependencies))
	for _, dependency := range dependencies {
		if _, duplicate := dependencyNames[dependency.PackageName]; duplicate {
			return ErrInvalid
		}
		dependencyNames[dependency.PackageName] = struct{}{}
		change, exists := changedPackage(changed, dependency.PackageName)
		if !exists || change.Selected || change.Action != dependency.Action {
			return ErrInvalid
		}
		for _, requiredBy := range dependency.RequiredBy {
			requirer, exists := changedPackage(changed, requiredBy)
			if !exists || !requirer.Selected {
				return ErrInvalid
			}
		}
	}
	for _, change := range changes {
		if !change.Selected {
			if _, exists := dependencyNames[change.Name]; !exists {
				return ErrInvalid
			}
		}
	}
	return nil
}

func validatePlanAgainstInventory(plan MaintenancePlan, snapshot InventorySnapshot) error {
	if plan.Validate() != nil || snapshot.Validate() != nil || plan.NodeID != snapshot.NodeID || plan.Manager != snapshot.Manager || plan.InventoryID != snapshot.ID || plan.InventoryGeneration != snapshot.Generation || plan.InventoryDigest != snapshot.ContentDigest {
		return ErrStaleInventory
	}
	changes := append([]PackageChange(nil), plan.Changes...)
	dependencies := cloneDependencies(plan.Dependencies)
	if err := bindChanges(snapshot, changes, dependencies); err != nil {
		return err
	}
	selected := 0
	for _, change := range changes {
		if change.Selected {
			selected++
		}
		if change.Security != classifyPackage(snapshot, change) {
			return ErrInvalid
		}
	}
	if selected == 0 || plan.Security != classifyChanges(snapshot, changes) {
		return ErrInvalid
	}
	planHolds := append([]Hold(nil), plan.Holds...)
	inventoryHolds := append([]Hold(nil), snapshot.Holds...)
	sort.Slice(planHolds, func(i, j int) bool { return planHolds[i].PackageName+"\x00"+planHolds[i].Kind+"\x00"+planHolds[i].Source < planHolds[j].PackageName+"\x00"+planHolds[j].Kind+"\x00"+planHolds[j].Source })
	sort.Slice(inventoryHolds, func(i, j int) bool { return inventoryHolds[i].PackageName+"\x00"+inventoryHolds[i].Kind+"\x00"+inventoryHolds[i].Source < inventoryHolds[j].PackageName+"\x00"+inventoryHolds[j].Kind+"\x00"+inventoryHolds[j].Source })
	planHoldDigest, _ := canonicalDigest(planHolds)
	inventoryHoldDigest, _ := canonicalDigest(inventoryHolds)
	if planHoldDigest != inventoryHoldDigest {
		return ErrStaleInventory
	}
	if plan.Recovery.Eligible {
		scopeDigest, err := PackageScopeDigest(changes)
		if err != nil || scopeDigest != plan.Recovery.ScopeDigest {
			return ErrInvalid
		}
	}
	return nil
}

func changedPackage(changes map[string]PackageChange, name string) (PackageChange, bool) {
	var found PackageChange
	seen := false
	for _, change := range changes {
		if change.Name != name {
			continue
		}
		if seen {
			return PackageChange{}, false
		}
		found, seen = change, true
	}
	return found, seen
}

func classifyChanges(snapshot InventorySnapshot, changes []PackageChange) SecurityClass {
	result := SecurityNone
	for _, change := range changes {
		result = higherSecurity(result, classifyPackage(snapshot, change))
	}
	return result
}

func classifyPackage(snapshot InventorySnapshot, change PackageChange) SecurityClass {
	result := SecurityNone
	found := false
	for _, advisory := range snapshot.Advisories {
		if advisory.CorrectedVersion != "" && change.ToVersion != advisory.CorrectedVersion {
			continue
		}
		for _, name := range advisory.PackageNames {
			if name == change.Name {
				result = higherSecurity(result, advisory.Security)
				found = true
			}
		}
	}
	if found {
		return result
	}
	for _, installed := range snapshot.Packages {
		if installed.Name == change.Name && installed.PendingSecurity {
			return SecurityUnknown
		}
	}
	return SecurityNone
}

func higherSecurity(left, right SecurityClass) SecurityClass {
	rank := map[SecurityClass]int{SecurityNone: 0, SecurityLow: 1, SecurityModerate: 2, SecurityHigh: 3, SecurityCritical: 4, SecurityUnknown: 5}
	if rank[right] > rank[left] {
		return right
	}
	return left
}

func cloneDependencies(values []DependencyImpact) []DependencyImpact {
	result := make([]DependencyImpact, len(values))
	for index, value := range values {
		result[index] = value
		result[index].RequiredBy = append([]string(nil), value.RequiredBy...)
	}
	return result
}

func packageChangeKey(value PackageChange) string {
	return value.Name + "\x00" + value.Architecture + "\x00" + string(value.Action)
}

func PackageScopeDigest(changes []PackageChange) (string, error) {
	values := append([]PackageChange(nil), changes...)
	if len(values) == 0 || len(values) > MaximumChanges {
		return "", ErrInvalid
	}
	for index := range values {
		values[index].Security = SecurityNone
	}
	sort.Slice(values, func(i, j int) bool { return packageChangeKey(values[i]) < packageChangeKey(values[j]) })
	return canonicalDigest(values)
}

// SealInventory canonicalizes a bounded inventory and assigns its immutable
// content-addressed identity. The caller remains responsible for observation.
func SealInventory(snapshot *InventorySnapshot) error {
	if snapshot == nil || snapshot.Generation == 0 || snapshot.CapturedAt.IsZero() {
		return ErrInvalid
	}
	canonicalizeInventory(snapshot)
	content := inventoryContent(*snapshot)
	digest, err := canonicalDigest(content)
	if err != nil {
		return err
	}
	snapshot.ContentDigest = digest
	identity := digestStrings(snapshot.NodeID, string(snapshot.Manager), strconv.FormatUint(snapshot.Generation, 10), digest)
	snapshot.ID = "inv_" + identity[:32]
	if err := snapshot.Validate(); err != nil {
		return errors.Join(ErrInvalid, err)
	}
	return nil
}
