//go:build linux

package packagemaint

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	aptGetPath    = "/usr/bin/apt-get"
	aptMarkPath   = "/usr/bin/apt-mark"
	dpkgPath      = "/usr/bin/dpkg"
	dpkgQueryPath = "/usr/bin/dpkg-query"
	dnfPath       = "/usr/bin/dnf"
	rpmPath       = "/usr/bin/rpm"
)

type CommandResult struct {
	Executable  string
	Argv        []string
	Output      []byte
	ExitCode    int
	StartedAt   time.Time
	CompletedAt time.Time
}

type Runner interface {
	Run(context.Context, string, []string, int) (CommandResult, error)
}

// LinuxRunner executes no shell and accepts only the command shapes used by
// this package. Output is retained only up to the caller's explicit bound.
type LinuxRunner struct {
	Timeout time.Duration
}

func (runner LinuxRunner) Run(ctx context.Context, executable string, argv []string, maximumOutput int) (CommandResult, error) {
	if !allowedInvocation(executable, argv) || maximumOutput <= 0 || maximumOutput > MaximumOutputBytes {
		return CommandResult{}, ErrUnsupported
	}
	information, err := os.Stat(executable)
	if err != nil || !information.Mode().IsRegular() || information.Mode().Perm()&0022 != 0 {
		return CommandResult{}, ErrUnsupported
	}
	stat, ok := information.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return CommandResult{}, ErrUnsupported
	}
	timeout := runner.Timeout
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 2 * time.Minute
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output := &cappedOutput{maximum: maximumOutput}
	command := exec.Command(executable, append([]string(nil), argv...)...)
	command.Dir = "/"
	command.Env = fixedCommandEnvironment()
	command.Stdout = output
	command.Stderr = output
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	result := CommandResult{Executable: executable, Argv: append([]string(nil), argv...), ExitCode: -1}
	if err := command.Start(); err != nil {
		result.CompletedAt = time.Now().UTC()
		return result, ErrUnsupported
	}
	result.StartedAt = time.Now().UTC()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	var waitErr error
	select {
	case waitErr = <-waited:
	case <-commandContext.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		select {
		case waitErr = <-waited:
		case <-time.After(5 * time.Second):
		}
		result.CompletedAt = time.Now().UTC()
		result.Output = output.Bytes()
		return result, commandContext.Err()
	}
	result.CompletedAt = time.Now().UTC()
	result.Output = output.Bytes()
	if output.Exceeded() {
		return result, ErrInvalid
	}
	if waitErr == nil {
		result.ExitCode = 0
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	return result, ErrUnsupported
}

func fixedCommandEnvironment() []string {
	return []string{
		"DEBIAN_FRONTEND=noninteractive",
		"LANG=C",
		"LC_ALL=C",
		"PAGER=cat",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"SYSTEMD_PAGER=cat",
	}
}

type cappedOutput struct {
	mu       sync.Mutex
	maximum  int
	data     []byte
	exceeded bool
}

func (output *cappedOutput) Write(value []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	remaining := output.maximum - len(output.data)
	if remaining > 0 {
		keep := len(value)
		if keep > remaining {
			keep = remaining
		}
		output.data = append(output.data, value[:keep]...)
	}
	if len(value) > remaining {
		output.exceeded = true
	}
	return len(value), nil
}

func (output *cappedOutput) Bytes() []byte {
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.data...)
}

func (output *cappedOutput) Exceeded() bool {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.exceeded
}

type InventoryRequest struct {
	NodeID     string
	Manager    Manager
	Generation uint64
}

type InventoryProvider interface {
	Snapshot(context.Context, InventoryRequest) (InventorySnapshot, error)
}

type LinuxInventory struct {
	Runner         Runner
	OverallTimeout time.Duration
	Now            func() time.Time
}

func (inventory LinuxInventory) Snapshot(ctx context.Context, request InventoryRequest) (InventorySnapshot, error) {
	if !safeID.MatchString(request.NodeID) || !validManager(request.Manager) || request.Generation == 0 {
		return InventorySnapshot{}, ErrInvalid
	}
	timeout := inventory.OverallTimeout
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	overall, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	runner := inventory.Runner
	if runner == nil {
		runner = LinuxRunner{}
	}
	now := time.Now().UTC()
	if inventory.Now != nil {
		now = inventory.Now().UTC()
	}
	snapshot := InventorySnapshot{NodeID: request.NodeID, Manager: request.Manager, Generation: request.Generation, CapturedAt: now}
	var err error
	if request.Manager == ManagerAPT {
		err = observeAPT(overall, runner, &snapshot, now)
	} else {
		err = observeDNF(overall, runner, &snapshot, now)
	}
	if err != nil {
		return InventorySnapshot{}, err
	}
	snapshot.RebootRequired = fixedRebootMarkerPresent()
	if err := SealInventory(&snapshot); err != nil {
		return InventorySnapshot{}, err
	}
	return snapshot, nil
}

func observeAPT(ctx context.Context, runner Runner, snapshot *InventorySnapshot, now time.Time) error {
	installed, err := runner.Run(ctx, dpkgQueryPath, []string{"-W", "-f=${binary:Package}\t${Architecture}\t${Version}\t${db:Status-Abbrev}\n"}, MaximumOutputBytes)
	if err != nil || installed.ExitCode != 0 {
		return ErrUnsupported
	}
	if lineLimitExceeded(installed.Output, MaximumPackages) {
		return ErrInvalid
	}
	packageIndex := make(map[string]int)
	for _, line := range boundedLines(installed.Output, MaximumPackages) {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return ErrInvalid
		}
		name := strings.Split(fields[0], ":")[0]
		state := PackageInstalled
		if strings.HasPrefix(fields[3], "rc") {
			state = PackageResidual
		} else if !strings.HasPrefix(fields[3], "ii") {
			continue
		}
		provenance, err := newProvenance(name, fields[1], fields[2], "", "", SignatureUnknown, "", false)
		if err != nil {
			return err
		}
		snapshot.Provenance = append(snapshot.Provenance, provenance)
		value := Package{Name: name, Architecture: fields[1], InstalledVersion: fields[2], State: state, ProvenanceDigest: provenance.Digest}
		if validatePackage(value) != nil {
			return ErrInvalid
		}
		key := name + "\x00" + fields[1]
		if _, duplicate := packageIndex[key]; duplicate {
			return ErrInvalid
		}
		packageIndex[key] = len(snapshot.Packages)
		snapshot.Packages = append(snapshot.Packages, value)
	}
	if len(snapshot.Packages) == 0 || len(snapshot.Packages) > MaximumPackages {
		return ErrInvalid
	}
	indexResult, err := runner.Run(ctx, aptGetPath, []string{"indextargets", "--format", "$(IDENTIFIER)\t$(SITE)\t$(RELEASE)\t$(COMPONENT)\t$(TRUSTED)"}, MaximumOutputBytes)
	if err != nil || indexResult.ExitCode != 0 {
		return ErrUnsupported
	}
	if lineLimitExceeded(indexResult.Output, MaximumRepositories) {
		return ErrInvalid
	}
	indexLines := boundedLines(indexResult.Output, MaximumRepositories)
	for _, line := range indexLines {
		fields := strings.Split(line, "\t")
		if len(fields) != 5 {
			return ErrInvalid
		}
	}
	sort.Strings(indexLines)
	metadataDigest := digestStrings(indexLines...)
	signature := SignatureUnknown
	repository := Repository{ID: "apt-resolved", Manager: ManagerAPT, Origin: "apt:index-targets", Enabled: true, MetadataRevision: metadataDigest, Signature: signature}
	repository.Digest, err = digestRepository(repository)
	if err != nil {
		return err
	}
	snapshot.Repositories = append(snapshot.Repositories, repository)
	simulation, err := runner.Run(ctx, aptGetPath, []string{"-s", "-o", "Debug::NoLocking=1", "-o", "APT::Get::Show-Upgraded=true", "upgrade"}, MaximumOutputBytes)
	if err != nil || simulation.ExitCode != 0 {
		if packageLockOutput(simulation.Output) {
			return ErrLocked
		}
		return ErrUnsupported
	}
	if lineLimitExceeded(simulation.Output, MaximumChanges*4) {
		return ErrInvalid
	}
	updatesObserved := 0
	for _, line := range boundedLines(simulation.Output, MaximumChanges*4) {
		name, architecture, oldVersion, newVersion, origin, ok := parseAPTInstallation(line)
		if !ok {
			continue
		}
		updatesObserved++
		if updatesObserved > MaximumChanges {
			return ErrInvalid
		}
		index, exists := packageIndex[name+"\x00"+architecture]
		if !exists {
			index, exists = uniquePackageIndex(snapshot.Packages, name)
		}
		if !exists || snapshot.Packages[index].InstalledVersion != oldVersion {
			return ErrInvalid
		}
		provenance, err := newProvenance(name, architecture, newVersion, repository.ID, origin, signature, "", false)
		if err != nil {
			return err
		}
		snapshot.Provenance = append(snapshot.Provenance, provenance)
		snapshot.Packages[index].CandidateVersion = newVersion
		snapshot.Packages[index].RepositoryID = repository.ID
		if strings.Contains(strings.ToLower(origin), "security") {
			snapshot.Packages[index].PendingSecurity = true
			advisoryID := "apt-security-" + digestStrings(name, newVersion)[:24]
			snapshot.Advisories = append(snapshot.Advisories, Advisory{ID: advisoryID, Security: SecurityUnknown, PackageNames: []string{name}, CurrentVersion: oldVersion, CorrectedVersion: newVersion, RepositoryID: repository.ID})
		}
	}
	holdResult, err := runner.Run(ctx, aptMarkPath, []string{"showhold"}, MaximumOutputBytes)
	if err != nil || holdResult.ExitCode != 0 {
		return ErrUnsupported
	}
	if lineLimitExceeded(holdResult.Output, MaximumHolds) {
		return ErrInvalid
	}
	for _, name := range boundedLines(holdResult.Output, MaximumHolds) {
		if !safePackage.MatchString(name) || len(snapshot.Holds) >= MaximumHolds {
			return ErrInvalid
		}
		snapshot.Holds = append(snapshot.Holds, Hold{PackageName: name, Kind: "version", Source: "apt-mark"})
	}
	audit, auditErr := runner.Run(ctx, dpkgPath, []string{"--audit"}, MaximumOutputBytes)
	if auditErr != nil || audit.ExitCode != 0 || len(strings.TrimSpace(string(audit.Output))) != 0 {
		snapshot.Locks = append(snapshot.Locks, Lock{Kind: "dpkg-state", Held: false, RepairCode: "dpkg-audit", ObservedAt: now})
	}
	if active, found, lockErr := fixedManagerLock(ManagerAPT, now); lockErr != nil {
		return lockErr
	} else if found {
		snapshot.Locks = append(snapshot.Locks, active)
	}
	return nil
}

func observeDNF(ctx context.Context, runner Runner, snapshot *InventorySnapshot, now time.Time) error {
	installed, err := runner.Run(ctx, rpmPath, []string{"-qa", "--qf", "%{NAME}\t%{ARCH}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{SIGPGP:pgpsig}\n"}, MaximumOutputBytes)
	if err != nil || installed.ExitCode != 0 {
		return ErrUnsupported
	}
	if lineLimitExceeded(installed.Output, MaximumPackages) {
		return ErrInvalid
	}
	packageIndex := make(map[string]int)
	for _, line := range boundedLines(installed.Output, MaximumPackages) {
		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			return ErrInvalid
		}
		version := fields[3]
		epoch := fields[2]
		if epoch == "0" || epoch == "(none)" {
			epoch = ""
		}
		if epoch != "" {
			version = epoch + ":" + version
		}
		signature, signingKeyID := SignatureUnknown, ""
		lowerSignature := strings.ToLower(fields[5])
		if marker := strings.Index(lowerSignature, "key id "); marker >= 0 {
			keyFields := strings.Fields(fields[5][marker+len("key id "):])
			if len(keyFields) != 0 && safeID.MatchString(keyFields[0]) {
				signingKeyID = keyFields[0]
			}
		}
		if signingKeyID != "" {
			signature = SignatureVerified
		}
		provenance, err := newProvenance(fields[0], fields[1], version, "", fields[4], signature, signingKeyID, false)
		if err != nil {
			return err
		}
		snapshot.Provenance = append(snapshot.Provenance, provenance)
		value := Package{Name: fields[0], Architecture: fields[1], Epoch: epoch, InstalledVersion: version, State: PackageInstalled, ProvenanceDigest: provenance.Digest}
		if validatePackage(value) != nil {
			return ErrInvalid
		}
		key := value.Name + "\x00" + value.Architecture
		if _, duplicate := packageIndex[key]; duplicate {
			return ErrInvalid
		}
		packageIndex[key] = len(snapshot.Packages)
		snapshot.Packages = append(snapshot.Packages, value)
	}
	if len(snapshot.Packages) == 0 || len(snapshot.Packages) > MaximumPackages {
		return ErrInvalid
	}
	repositories := make(map[string]int)
	repositoryResult, err := runner.Run(ctx, dnfPath, []string{"-q", "--cacheonly", "repolist", "--enabled"}, MaximumOutputBytes)
	if err != nil || repositoryResult.ExitCode != 0 || lineLimitExceeded(repositoryResult.Output, MaximumRepositories+4) {
		return ErrUnsupported
	}
	for _, line := range boundedLines(repositoryResult.Output, MaximumRepositories+4) {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "repo" || strings.HasPrefix(fields[0], "repolist:") {
			continue
		}
		repositoryID := "dnf-" + fields[0]
		if !safeID.MatchString(fields[0]) || !safeID.MatchString(repositoryID) || len(snapshot.Repositories) >= MaximumRepositories {
			return ErrInvalid
		}
		repository := Repository{ID: repositoryID, Manager: ManagerDNF, Origin: "dnf:" + fields[0], Enabled: true, Signature: SignatureUnknown}
		repository.Digest, err = digestRepository(repository)
		if err != nil {
			return err
		}
		if _, duplicate := repositories[repositoryID]; duplicate {
			return ErrInvalid
		}
		repositories[repositoryID] = len(snapshot.Repositories)
		snapshot.Repositories = append(snapshot.Repositories, repository)
	}
	updates, err := runner.Run(ctx, dnfPath, []string{"-q", "--cacheonly", "check-update"}, MaximumOutputBytes)
	if err != nil || updates.ExitCode != 0 && updates.ExitCode != 100 {
		if packageLockOutput(updates.Output) {
			return ErrLocked
		}
		return ErrUnsupported
	}
	if lineLimitExceeded(updates.Output, MaximumChanges*4) {
		return ErrInvalid
	}
	updatesObserved := 0
	for _, line := range boundedLines(updates.Output, MaximumChanges*4) {
		fields := strings.Fields(line)
		if len(fields) != 3 || strings.HasPrefix(fields[0], "Last") {
			continue
		}
		separator := strings.LastIndexByte(fields[0], '.')
		if separator <= 0 {
			continue
		}
		name, architecture := fields[0][:separator], fields[0][separator+1:]
		if !safePackage.MatchString(name) || !safeArchitecture.MatchString(architecture) || !safeVersion.MatchString(fields[1]) || !safeID.MatchString(fields[2]) {
			return ErrInvalid
		}
		index, exists := packageIndex[name+"\x00"+architecture]
		if !exists {
			continue
		}
		updatesObserved++
		if updatesObserved > MaximumChanges {
			return ErrInvalid
		}
		repositoryID := "dnf-" + fields[2]
		if len(repositoryID) > 160 || !safeID.MatchString(repositoryID) {
			return ErrInvalid
		}
		if _, exists := repositories[repositoryID]; !exists {
			if len(snapshot.Repositories) >= MaximumRepositories {
				return ErrInvalid
			}
			repository := Repository{ID: repositoryID, Manager: ManagerDNF, Origin: "dnf:" + fields[2], Enabled: true, Signature: SignatureUnknown}
			repository.Digest, err = digestRepository(repository)
			if err != nil {
				return err
			}
			repositories[repositoryID] = len(snapshot.Repositories)
			snapshot.Repositories = append(snapshot.Repositories, repository)
		}
		provenance, err := newProvenance(name, architecture, fields[1], repositoryID, fields[2], SignatureUnknown, "", false)
		if err != nil {
			return err
		}
		snapshot.Provenance = append(snapshot.Provenance, provenance)
		snapshot.Packages[index].CandidateVersion = fields[1]
		snapshot.Packages[index].RepositoryID = repositoryID
	}
	security, securityErr := runner.Run(ctx, dnfPath, []string{"-q", "--cacheonly", "updateinfo", "list", "--security", "--available"}, MaximumOutputBytes)
	if securityErr != nil || security.ExitCode != 0 {
		return ErrUnsupported
	}
	if lineLimitExceeded(security.Output, MaximumAdvisories) {
		return ErrInvalid
	}
	for _, line := range boundedLines(security.Output, MaximumAdvisories) {
		fields := strings.Fields(line)
		if len(fields) < 3 || !safeID.MatchString(fields[0]) {
			continue
		}
		packageField := fields[len(fields)-1]
		name := packageNameFromNEVRA(packageField, snapshot.Packages)
		if !safePackage.MatchString(name) {
			continue
		}
		snapshot.Advisories = append(snapshot.Advisories, Advisory{ID: fields[0], Security: SecurityUnknown, PackageNames: []string{name}})
		for index := range snapshot.Packages {
			if snapshot.Packages[index].Name == name {
				snapshot.Packages[index].PendingSecurity = true
			}
		}
	}
	holds, holdErr := runner.Run(ctx, dnfPath, []string{"-q", "--cacheonly", "versionlock", "list"}, MaximumOutputBytes)
	if holdErr != nil || holds.ExitCode != 0 {
		return ErrUnsupported
	}
	if lineLimitExceeded(holds.Output, MaximumHolds) {
		return ErrInvalid
	}
	for _, line := range boundedLines(holds.Output, MaximumHolds) {
		name := dnfLockedPackage(line, snapshot.Packages)
		if name == "" {
			continue
		}
		if inventoryHasHold(snapshot.Holds, name, "version", "dnf-versionlock") {
			continue
		}
		if len(snapshot.Holds) >= MaximumHolds {
			return ErrInvalid
		}
		snapshot.Holds = append(snapshot.Holds, Hold{PackageName: name, Kind: "version", Source: "dnf-versionlock"})
	}
	verification, verificationErr := runner.Run(ctx, rpmPath, []string{"--verifydb"}, MaximumOutputBytes)
	if verificationErr != nil || verification.ExitCode != 0 {
		snapshot.Locks = append(snapshot.Locks, Lock{Kind: "rpm-state", Held: false, RepairCode: "rpm-verifydb", ObservedAt: now})
	}
	if active, found, lockErr := fixedManagerLock(ManagerDNF, now); lockErr != nil {
		return lockErr
	} else if found {
		snapshot.Locks = append(snapshot.Locks, active)
	}
	return nil
}

func inventoryHasHold(values []Hold, packageName, kind, source string) bool {
	for _, value := range values {
		if value.PackageName == packageName && value.Kind == kind && value.Source == source {
			return true
		}
	}
	return false
}

type TransactionVerifier interface {
	Resolve(context.Context, InventorySnapshot, MaintenancePlan) (SolverAttestation, error)
}

type ExecutionPolicy interface {
	Allow(context.Context, MaintenancePlan, PackageChange) error
}

type Snapshotter interface {
	Create(context.Context, MaintenancePlan) (SnapshotReceipt, error)
}

type ServiceProber interface {
	Probe(context.Context, ServiceImpact) (ServiceProbeReceipt, error)
}

type Recoverer interface {
	Recover(context.Context, MaintenancePlan, SnapshotReceipt) (RecoveryReceipt, error)
}

type LinuxExecutor struct {
	Inventory      InventoryProvider
	Runner         Runner
	Verifier       TransactionVerifier
	Policy         ExecutionPolicy
	Snapshotter    Snapshotter
	ServiceProber  ServiceProber
	Recoverer      Recoverer
	OverallTimeout time.Duration
	Now            func() time.Time
}

func (executor LinuxExecutor) Apply(ctx context.Context, request ExecutionRequest) (ExecutionReceipt, error) {
	if executor.Inventory == nil || executor.Verifier == nil || executor.Policy == nil || !safeID.MatchString(request.EffectID) || validatePlanAgainstInventory(request.Plan, request.Inventory) != nil || request.ExpectedPlanGeneration != request.Plan.Generation || request.ExpectedInventoryGeneration != request.Plan.InventoryGeneration || request.ExpectedInventoryDigest != request.Plan.InventoryDigest || request.Inventory.Generation != request.ExpectedInventoryGeneration || request.Inventory.ContentDigest != request.ExpectedInventoryDigest || request.Fence == 0 || request.Authorization.Scope != "package-maintenance:commit:"+request.Plan.ID {
		return ExecutionReceipt{}, ErrStalePlan
	}
	now := executor.now()
	authorizationRequest := AuthorizationRequest{Boundary: BoundaryCommit, OperationID: request.EffectID, ActorID: request.Authorization.ActorID, Scope: request.Authorization.Scope, PlanID: request.Plan.ID, PlanDigest: request.Plan.Digest, PlanGeneration: request.Plan.Generation, MinimumAssurance: AssurancePhishingResistant, Irreversible: true}
	authorizationRequestDigest, digestErr := canonicalDigest(authorizationRequest)
	if digestErr != nil || request.Authorization.RequestDigest != authorizationRequestDigest || request.Authorization.Validate(AssurancePhishingResistant, now) != nil {
		return ExecutionReceipt{}, ErrUnauthorized
	}
	if !now.Before(request.Plan.ExpiresAt) {
		return ExecutionReceipt{}, ErrStalePlan
	}
	timeout := executor.OverallTimeout
	if timeout <= 0 || timeout > 2*time.Hour {
		timeout = 30 * time.Minute
	}
	overall, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, found, lockErr := fixedManagerLock(request.Plan.Manager, now); lockErr != nil {
		return ExecutionReceipt{}, lockErr
	} else if found {
		return ExecutionReceipt{}, ErrLocked
	}
	before, err := executor.Inventory.Snapshot(overall, InventoryRequest{NodeID: request.Plan.NodeID, Manager: request.Plan.Manager, Generation: request.ExpectedInventoryGeneration})
	if err != nil {
		return ExecutionReceipt{}, normalizeExecutionError(err)
	}
	if before.ContentDigest != request.ExpectedInventoryDigest || before.Generation != request.ExpectedInventoryGeneration {
		return ExecutionReceipt{}, ErrStaleInventory
	}
	for _, lock := range before.Locks {
		if lock.Held {
			return ExecutionReceipt{}, ErrLocked
		}
		if lock.RepairCode != "" {
			return ExecutionReceipt{}, ErrRecoveryRequired
		}
	}
	if _, found, lockErr := fixedManagerLock(request.Plan.Manager, now); lockErr != nil {
		return ExecutionReceipt{}, lockErr
	} else if found {
		return ExecutionReceipt{}, ErrLocked
	}
	resolved, err := executor.Verifier.Resolve(overall, before, request.Plan)
	if err != nil || validateAttestation(resolved, before.ContentDigest, executor.now()) != nil || resolved.ResolvedAt.Before(before.CapturedAt) || resolved.TransactionDigest != request.Plan.SolverDigest || !attestationMatchesPlan(resolved, request.Plan) {
		return ExecutionReceipt{}, ErrStalePlan
	}
	for _, change := range request.Plan.Changes {
		if err := executor.Policy.Allow(overall, request.Plan, change); err != nil {
			return ExecutionReceipt{}, ErrUnauthorized
		}
	}
	if requiredProbeMissing(request.Plan.Services, executor.ServiceProber) {
		return ExecutionReceipt{}, ErrUnsupported
	}
	var snapshotReceipt SnapshotReceipt
	if request.Plan.Recovery.Eligible {
		if executor.Snapshotter == nil {
			if request.Plan.Recovery.Required {
				return ExecutionReceipt{}, ErrRecoveryRequired
			}
		} else {
			snapshotReceipt, err = executor.Snapshotter.Create(overall, request.Plan)
			if err != nil || !validSnapshotReceipt(snapshotReceipt, request.Plan.Recovery) {
				return ExecutionReceipt{}, ErrRecoveryRequired
			}
		}
	}
	runner := executor.Runner
	if runner == nil {
		runner = LinuxRunner{}
	}
	commands, err := mutationCommands(request.Plan)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	receipt := ExecutionReceipt{
		EffectID:              request.EffectID,
		PlanID:                request.Plan.ID,
		PlanDigest:            request.Plan.Digest,
		InventoryGeneration:   before.Generation,
		BeforeInventoryDigest: before.ContentDigest,
		Fence:                 request.Fence,
		AuthorizationDigest:   request.Authorization.Digest,
		Snapshot:              snapshotReceipt,
	}
	var commandFailure error
	for _, command := range commands {
		result, runErr := runner.Run(overall, command.executable, command.argv, MaximumOutputBytes)
		if !result.StartedAt.IsZero() {
			receipt.IrreversibleCrossed = true
			receipt.Commands = append(receipt.Commands, commandReceipt(result))
		}
		if packageLockOutput(result.Output) {
			commandFailure = ErrLocked
			break
		}
		if runErr != nil || result.ExitCode != 0 {
			commandFailure = ErrConflict
			break
		}
	}
	after, observationErr := executor.Inventory.Snapshot(overall, InventoryRequest{NodeID: request.Plan.NodeID, Manager: request.Plan.Manager, Generation: request.ExpectedInventoryGeneration + 1})
	if observationErr == nil {
		receipt.AfterInventoryDigest = after.ContentDigest
		receipt.ObservedPackages = observedPackages(request.Plan, after)
	}
	if commandFailure == nil && observationErr == nil && exactPackageEffect(before, after, request.Plan.Changes) {
		for _, service := range request.Plan.Services {
			probe, probeErr := executor.ServiceProber.Probe(overall, service)
			if probeErr != nil || !validProbeReceipt(probe, service) {
				commandFailure = ErrConflict
				break
			}
			receipt.ServiceProbes = append(receipt.ServiceProbes, probe)
			if service.Required && !probe.Healthy {
				commandFailure = ErrConflict
				break
			}
		}
	} else if commandFailure == nil {
		commandFailure = ErrAmbiguous
	}
	if commandFailure == nil {
		receipt.Outcome = OutcomeConfirmed
		sealExecutionReceipt(&receipt, executor.now())
		return receipt, nil
	}
	if !receipt.IrreversibleCrossed {
		receipt.Outcome = OutcomeFailed
		sealExecutionReceipt(&receipt, executor.now())
		return receipt, commandFailure
	}
	if observationErr == nil && samePackageState(before, after) {
		receipt.Outcome = OutcomeFailed
		sealExecutionReceipt(&receipt, executor.now())
		return receipt, commandFailure
	}
	if snapshotReceipt.SnapshotID != "" && executor.Recoverer != nil {
		recovery, recoveryErr := executor.Recoverer.Recover(overall, request.Plan, snapshotReceipt)
		if recoveryErr == nil && validRecoveryReceipt(recovery, snapshotReceipt) {
			receipt.Recovery = recovery
		}
		if recoveryErr == nil && validRecoveryReceipt(recovery, snapshotReceipt) && recovery.Restored {
			restored, restoredErr := executor.Inventory.Snapshot(overall, InventoryRequest{NodeID: request.Plan.NodeID, Manager: request.Plan.Manager, Generation: request.ExpectedInventoryGeneration + 1})
			if restoredErr == nil && samePackageState(before, restored) {
				receipt.AfterInventoryDigest = restored.ContentDigest
				receipt.Outcome = OutcomeRecovered
				sealExecutionReceipt(&receipt, executor.now())
				return receipt, commandFailure
			}
		}
		if receipt.Recovery.SnapshotID == "" {
			receipt.Recovery = RecoveryReceipt{Attempted: true, SnapshotID: snapshotReceipt.SnapshotID, EvidenceDigest: digestStrings(request.Plan.ID, snapshotReceipt.SnapshotID, "recovery-failed"), Instructions: append([]string(nil), request.Plan.Recovery.Instructions...), ObservedAt: executor.now()}
		}
	}
	receipt.Recovery.Instructions = append([]string(nil), request.Plan.Recovery.Instructions...)
	if observationErr != nil {
		receipt.Outcome = OutcomeAmbiguous
	} else {
		receipt.Outcome = OutcomeRecoveryRequired
	}
	sealExecutionReceipt(&receipt, executor.now())
	return receipt, ErrRecoveryRequired
}

type mutationCommand struct {
	executable string
	argv       []string
}

func mutationCommands(plan MaintenancePlan) ([]mutationCommand, error) {
	changes := append([]PackageChange(nil), plan.Changes...)
	sort.Slice(changes, func(i, j int) bool { return packageChangeKey(changes[i]) < packageChangeKey(changes[j]) })
	if plan.Manager == ManagerAPT {
		arguments := []string{"-y", "--no-install-recommends"}
		hasRemoval, hasReinstall := false, false
		for _, change := range changes {
			hasRemoval = hasRemoval || change.Action == ChangeRemove
			hasReinstall = hasReinstall || change.Action == ChangeReinstall
		}
		if !hasRemoval {
			arguments = append(arguments, "--no-remove")
		}
		if hasReinstall {
			arguments = append(arguments, "--reinstall")
		}
		arguments = append(arguments, "install")
		for _, change := range changes {
			selector := change.Name + ":" + change.Architecture
			if change.Action == ChangeRemove {
				arguments = append(arguments, selector+"-")
			} else {
				arguments = append(arguments, selector+"="+change.ToVersion)
			}
		}
		if !allowedInvocation(aptGetPath, arguments) {
			return nil, ErrUnsupported
		}
		return []mutationCommand{{executable: aptGetPath, argv: arguments}}, nil
	}
	var install, reinstall, remove []string
	for _, change := range changes {
		identity := change.Name + "-" + change.ToVersion + "." + change.Architecture
		switch change.Action {
		case ChangeInstall, ChangeUpgrade:
			install = append(install, identity)
		case ChangeReinstall:
			reinstall = append(reinstall, identity)
		case ChangeRemove:
			remove = append(remove, change.Name+"-"+change.FromVersion+"."+change.Architecture)
		}
	}
	commands := make([]mutationCommand, 0, 3)
	base := []string{"-y", "--cacheonly", "--setopt=install_weak_deps=False"}
	groups := 0
	for _, values := range [][]string{install, reinstall, remove} {
		if len(values) != 0 {
			groups++
		}
	}
	if groups != 1 {
		return nil, ErrUnsupported
	}
	if len(install) != 0 {
		commands = append(commands, mutationCommand{executable: dnfPath, argv: append(append([]string(nil), base...), append([]string{"install"}, install...)...)})
	}
	if len(reinstall) != 0 {
		commands = append(commands, mutationCommand{executable: dnfPath, argv: append(append([]string(nil), base...), append([]string{"reinstall"}, reinstall...)...)})
	}
	if len(remove) != 0 {
		commands = append(commands, mutationCommand{executable: dnfPath, argv: append(append([]string(nil), base...), append([]string{"remove"}, remove...)...)})
	}
	for _, command := range commands {
		if !allowedInvocation(command.executable, command.argv) {
			return nil, ErrUnsupported
		}
	}
	return commands, nil
}

func allowedInvocation(executable string, argv []string) bool {
	for _, argument := range argv {
		if len(argument) == 0 || len(argument) > 512 || strings.ContainsAny(argument, "\x00\r\n") {
			return false
		}
	}
	switch executable {
	case dpkgQueryPath:
		return len(argv) == 2 && argv[0] == "-W" && argv[1] == "-f=${binary:Package}\t${Architecture}\t${Version}\t${db:Status-Abbrev}\n"
	case dpkgPath:
		return equalStrings(argv, []string{"--audit"})
	case aptMarkPath:
		return equalStrings(argv, []string{"showhold"})
	case rpmPath:
		return equalStrings(argv, []string{"--verifydb"}) || equalStrings(argv, []string{"-qa", "--qf", "%{NAME}\t%{ARCH}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{SIGPGP:pgpsig}\n"})
	case aptGetPath:
		if equalStrings(argv, []string{"indextargets", "--format", "$(IDENTIFIER)\t$(SITE)\t$(RELEASE)\t$(COMPONENT)\t$(TRUSTED)"}) || equalStrings(argv, []string{"-s", "-o", "Debug::NoLocking=1", "-o", "APT::Get::Show-Upgraded=true", "upgrade"}) {
			return true
		}
		return validAPTMutation(argv)
	case dnfPath:
		if equalStrings(argv, []string{"-q", "--cacheonly", "repolist", "--enabled"}) || equalStrings(argv, []string{"-q", "--cacheonly", "check-update"}) || equalStrings(argv, []string{"-q", "--cacheonly", "updateinfo", "list", "--security", "--available"}) || equalStrings(argv, []string{"-q", "--cacheonly", "versionlock", "list"}) {
			return true
		}
		return validDNFMutation(argv)
	default:
		return false
	}
}

func validAPTMutation(argv []string) bool {
	if len(argv) < 4 || argv[0] != "-y" || argv[1] != "--no-install-recommends" {
		return false
	}
	index := 2
	if index < len(argv) && argv[index] == "--no-remove" {
		index++
	}
	if index < len(argv) && argv[index] == "--reinstall" {
		index++
	}
	if index >= len(argv) || argv[index] != "install" || index+1 >= len(argv) {
		return false
	}
	for _, argument := range argv[index+1:] {
		if strings.HasSuffix(argument, "-") {
			if !safeAPTSelector(strings.TrimSuffix(argument, "-")) {
				return false
			}
			continue
		}
		parts := strings.SplitN(argument, "=", 2)
		if len(parts) != 2 || !safeAPTSelector(parts[0]) || !safeVersion.MatchString(parts[1]) {
			return false
		}
	}
	return true
}

func safeAPTSelector(value string) bool {
	parts := strings.Split(value, ":")
	return len(parts) == 2 && safePackage.MatchString(parts[0]) && safeArchitecture.MatchString(parts[1])
}

func validDNFMutation(argv []string) bool {
	if len(argv) < 5 || !equalStrings(argv[:3], []string{"-y", "--cacheonly", "--setopt=install_weak_deps=False"}) || argv[3] != "install" && argv[3] != "reinstall" && argv[3] != "remove" {
		return false
	}
	for _, identity := range argv[4:] {
		if !safeDNFArgument(identity) {
			return false
		}
	}
	return true
}

func safeDNFArgument(value string) bool {
	if len(value) == 0 || len(value) > 448 {
		return false
	}
	first := value[0]
	if !(first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z' || first >= '0' && first <= '9') {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("+.:~_^-", character) {
			continue
		}
		return false
	}
	return true
}

func parseAPTInstallation(line string) (string, string, string, string, string, bool) {
	if !strings.HasPrefix(line, "Inst ") {
		return "", "", "", "", "", false
	}
	rest := strings.TrimPrefix(line, "Inst ")
	space := strings.IndexByte(rest, ' ')
	if space <= 0 {
		return "", "", "", "", "", false
	}
	identity, rest := rest[:space], strings.TrimSpace(rest[space+1:])
	name, architecture := identity, ""
	if separator := strings.LastIndexByte(identity, ':'); separator > 0 {
		name, architecture = identity[:separator], identity[separator+1:]
	}
	oldVersion := ""
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 2 {
			return "", "", "", "", "", false
		}
		oldVersion, rest = rest[1:end], strings.TrimSpace(rest[end+1:])
	}
	if !strings.HasPrefix(rest, "(") {
		return "", "", "", "", "", false
	}
	end := strings.LastIndexByte(rest, ')')
	if end <= 1 {
		return "", "", "", "", "", false
	}
	fields := strings.Fields(rest[1:end])
	if len(fields) < 2 {
		return "", "", "", "", "", false
	}
	newVersion := fields[0]
	if architecture == "" {
		architecture = strings.Trim(fields[len(fields)-1], "[]")
	}
	origin := strings.Join(fields[1:len(fields)-1], "_")
	if origin == "" {
		origin = "apt"
	}
	if !safePackage.MatchString(name) || !safeArchitecture.MatchString(architecture) || !safeVersion.MatchString(oldVersion) || !safeVersion.MatchString(newVersion) || len(origin) > 512 {
		return "", "", "", "", "", false
	}
	return name, architecture, oldVersion, newVersion, origin, true
}

func newProvenance(name, architecture, version, repositoryID, vendor string, signature SignatureState, keyID string, local bool) (Provenance, error) {
	value := Provenance{PackageName: name, Architecture: architecture, Version: version, RepositoryID: repositoryID, Vendor: truncateText(vendor, 512), Signature: signature, SigningKeyID: truncateText(keyID, 160), LocalArtifact: local}
	digest, err := canonicalDigest(value)
	if err != nil {
		return Provenance{}, err
	}
	value.Digest = digest
	return value, nil
}

func digestRepository(value Repository) (string, error) {
	value.Digest = ""
	return canonicalDigest(value)
}

func boundedLines(output []byte, maximum int) []string {
	raw := strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
			if len(lines) == maximum {
				break
			}
		}
	}
	return lines
}

func lineLimitExceeded(output []byte, maximum int) bool {
	if maximum < 1 {
		return true
	}
	lines := 0
	for _, value := range output {
		if value == '\n' {
			lines++
			if lines > maximum {
				return true
			}
		}
	}
	if len(output) != 0 && output[len(output)-1] != '\n' {
		lines++
	}
	return lines > maximum
}

func uniquePackageIndex(packages []Package, name string) (int, bool) {
	index := -1
	for candidate, value := range packages {
		if value.Name != name {
			continue
		}
		if index != -1 {
			return 0, false
		}
		index = candidate
	}
	return index, index >= 0
}

func dnfLockedPackage(line string, packages []Package) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "Loaded") {
		return ""
	}
	best := ""
	for _, value := range packages {
		if (line == value.Name || strings.HasPrefix(line, value.Name+"-")) && len(value.Name) > len(best) {
			best = value.Name
		}
	}
	return best
}

func packageNameFromNEVRA(identity string, packages []Package) string {
	best := ""
	for _, value := range packages {
		if strings.HasPrefix(identity, value.Name+"-") && len(value.Name) > len(best) {
			best = value.Name
		}
	}
	return best
}

func fixedRebootMarkerPresent() bool {
	for _, path := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
		information, err := os.Lstat(path)
		if err == nil && information.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func fixedManagerLock(manager Manager, observedAt time.Time) (Lock, bool, error) {
	paths := []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"}
	if manager == ManagerDNF {
		for _, path := range []string{"/run/dnf.pid", "/var/run/dnf.pid"} {
			value, err := readFixedFile(path, 32)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return Lock{}, false, ErrUnsupported
			}
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(value)))
			if parseErr != nil || pid <= 1 {
				continue
			}
			if information, statErr := os.Lstat("/proc/" + strconv.Itoa(pid)); statErr == nil && information.IsDir() {
				commandName, commandErr := readFixedFile("/proc/"+strconv.Itoa(pid)+"/comm", 64)
				name := strings.TrimSpace(string(commandName))
				if commandErr == nil && (name == "dnf" || name == "dnf5" || name == "rpm") {
					return Lock{Kind: "manager-lock", Path: path, Held: true, OwnerPID: pid, ObservedAt: observedAt}, true, nil
				}
			}
		}
		paths = []string{"/var/lib/rpm/.rpm.lock", "/usr/lib/sysimage/rpm/.rpm.lock"}
	}
	locked, err := readFixedFile("/proc/locks", 1<<20)
	if err != nil {
		return Lock{}, false, ErrUnsupported
	}
	if lineLimitExceeded(locked, 65536) {
		return Lock{}, false, ErrUnsupported
	}
	for _, path := range paths {
		information, statErr := os.Stat(path)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return Lock{}, false, ErrUnsupported
		}
		stat, ok := information.Sys().(*syscall.Stat_t)
		if !ok {
			return Lock{}, false, ErrUnsupported
		}
		for _, line := range boundedLines(locked, 65536) {
			fields := strings.Fields(line)
			if len(fields) < 6 || !lockIdentityMatches(fields[5], uint64(stat.Dev), stat.Ino) {
				continue
			}
			pid, _ := strconv.Atoi(fields[4])
			return Lock{Kind: "manager-lock", Path: path, Held: true, OwnerPID: pid, ObservedAt: observedAt}, true, nil
		}
	}
	return Lock{}, false, nil
}

func lockIdentityMatches(value string, device, inode uint64) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return false
	}
	major, majorErr := strconv.ParseUint(parts[0], 16, 64)
	minor, minorErr := strconv.ParseUint(parts[1], 16, 64)
	observedInode, inodeErr := strconv.ParseUint(parts[2], 10, 64)
	if majorErr != nil || minorErr != nil || inodeErr != nil {
		return false
	}
	linuxMajor := device>>8&0xfff | device>>32&0xfffff000
	linuxMinor := device&0xff | device>>12&0xffffff00
	return major == linuxMajor && minor == linuxMinor && observedInode == inode
}

func readFixedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > maximum {
		return nil, ErrInvalid
	}
	return value, nil
}

func packageLockOutput(output []byte) bool {
	message := strings.ToLower(string(output))
	for _, marker := range []string{"could not get lock", "unable to acquire the dpkg frontend lock", "another app is currently holding", "waiting for process with pid", "existing lock ", "rpmdb is locked"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func commandReceipt(result CommandResult) CommandReceipt {
	argvDigest, _ := canonicalDigest(struct {
		Executable string   `json:"executable"`
		Argv       []string `json:"argv"`
	}{Executable: result.Executable, Argv: result.Argv})
	return CommandReceipt{Executable: result.Executable, ArgvDigest: argvDigest, OutputDigest: digestStrings(string(result.Output)), ExitCode: result.ExitCode, StartedAt: result.StartedAt, CompletedAt: result.CompletedAt}
}

func attestationMatchesPlan(attestation SolverAttestation, plan MaintenancePlan) bool {
	attestationChanges := append([]PackageChange(nil), attestation.Changes...)
	planChangeSet := append([]PackageChange(nil), plan.Changes...)
	for index := range attestationChanges {
		attestationChanges[index].Security = SecurityNone
	}
	for index := range planChangeSet {
		planChangeSet[index].Security = SecurityNone
	}
	sort.Slice(attestationChanges, func(i, j int) bool { return packageChangeKey(attestationChanges[i]) < packageChangeKey(attestationChanges[j]) })
	sort.Slice(planChangeSet, func(i, j int) bool { return packageChangeKey(planChangeSet[i]) < packageChangeKey(planChangeSet[j]) })
	attestationDependencies := cloneDependencies(attestation.Dependencies)
	planDependencySet := cloneDependencies(plan.Dependencies)
	for index := range attestationDependencies {
		sort.Strings(attestationDependencies[index].RequiredBy)
	}
	for index := range planDependencySet {
		sort.Strings(planDependencySet[index].RequiredBy)
	}
	sort.Slice(attestationDependencies, func(i, j int) bool { return attestationDependencies[i].PackageName < attestationDependencies[j].PackageName })
	sort.Slice(planDependencySet, func(i, j int) bool { return planDependencySet[i].PackageName < planDependencySet[j].PackageName })
	attestationServices := append([]ServiceImpact(nil), attestation.Services...)
	planServiceSet := append([]ServiceImpact(nil), plan.Services...)
	sort.Slice(attestationServices, func(i, j int) bool { return attestationServices[i].ServiceID+"\x00"+attestationServices[i].ProbeID < attestationServices[j].ServiceID+"\x00"+attestationServices[j].ProbeID })
	sort.Slice(planServiceSet, func(i, j int) bool { return planServiceSet[i].ServiceID+"\x00"+planServiceSet[i].ProbeID < planServiceSet[j].ServiceID+"\x00"+planServiceSet[j].ProbeID })
	changes, _ := canonicalDigest(attestationChanges)
	planChanges, _ := canonicalDigest(planChangeSet)
	dependencies, _ := canonicalDigest(attestationDependencies)
	planDependencies, _ := canonicalDigest(planDependencySet)
	services, _ := canonicalDigest(attestationServices)
	planServices, _ := canonicalDigest(planServiceSet)
	return changes == planChanges && dependencies == planDependencies && services == planServices && attestation.Disk == plan.Disk && attestation.Reboot == plan.Reboot && recoveryEqual(attestation.Recovery, plan.Recovery) && attestation.Frontier == plan.Frontier
}

func recoveryEqual(left, right RecoveryEligibility) bool {
	leftDigest, _ := canonicalDigest(left)
	rightDigest, _ := canonicalDigest(right)
	return leftDigest == rightDigest
}

func requiredProbeMissing(services []ServiceImpact, prober ServiceProber) bool {
	if prober != nil {
		return false
	}
	for _, service := range services {
		if service.Required {
			return true
		}
	}
	return len(services) != 0
}

func validSnapshotReceipt(value SnapshotReceipt, recovery RecoveryEligibility) bool {
	return value.Kind == recovery.Kind && value.ScopeDigest == recovery.ScopeDigest && safeID.MatchString(value.SnapshotID) && validDigest(value.Digest) && !value.CreatedAt.IsZero()
}

func validProbeReceipt(value ServiceProbeReceipt, expected ServiceImpact) bool {
	return value.ServiceID == expected.ServiceID && value.ProbeID == expected.ProbeID && validDigest(value.EvidenceDigest) && !value.ObservedAt.IsZero()
}

func validRecoveryReceipt(value RecoveryReceipt, snapshot SnapshotReceipt) bool {
	if !value.Attempted || value.SnapshotID != snapshot.SnapshotID || !validDigest(value.EvidenceDigest) || value.ObservedAt.IsZero() || len(value.Instructions) > 32 {
		return false
	}
	for _, instruction := range value.Instructions {
		if !safeID.MatchString(instruction) {
			return false
		}
	}
	return true
}

func observedPackages(plan MaintenancePlan, snapshot InventorySnapshot) []ObservedPackage {
	installed := make(map[string]string, len(snapshot.Packages))
	for _, value := range snapshot.Packages {
		installed[value.Name+"\x00"+value.Architecture] = value.InstalledVersion
	}
	result := make([]ObservedPackage, 0, len(plan.Changes))
	for _, change := range plan.Changes {
		version, present := installed[change.Name+"\x00"+change.Architecture]
		result = append(result, ObservedPackage{Name: change.Name, Architecture: change.Architecture, Version: version, Present: present})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name+"\x00"+result[i].Architecture < result[j].Name+"\x00"+result[j].Architecture })
	return result
}

func exactPackageEffect(before, after InventorySnapshot, changes []PackageChange) bool {
	beforeState := packageState(before)
	afterState := packageState(after)
	allowed := make(map[string]PackageChange, len(changes))
	for _, change := range changes {
		key := change.Name + "\x00" + change.Architecture
		allowed[key] = change
		observed, present := afterState[key]
		if change.Action == ChangeRemove {
			if present {
				return false
			}
		} else if !present || observed.Version != change.ToVersion || observed.State != PackageInstalled {
			return false
		}
	}
	for key, observed := range beforeState {
		if _, changed := allowed[key]; !changed && afterState[key] != observed {
			return false
		}
	}
	for key := range afterState {
		if _, existed := beforeState[key]; !existed {
			if _, changed := allowed[key]; !changed {
				return false
			}
		}
	}
	return true
}

func samePackageState(left, right InventorySnapshot) bool {
	leftDigest, _ := canonicalDigest(packageState(left))
	rightDigest, _ := canonicalDigest(packageState(right))
	return leftDigest == rightDigest
}

type packageStateValue struct {
	Version string       `json:"version"`
	State   PackageState `json:"state"`
}

func packageState(snapshot InventorySnapshot) map[string]packageStateValue {
	result := make(map[string]packageStateValue, len(snapshot.Packages))
	for _, value := range snapshot.Packages {
		result[value.Name+"\x00"+value.Architecture] = packageStateValue{Version: value.InstalledVersion, State: value.State}
	}
	return result
}

func sealExecutionReceipt(receipt *ExecutionReceipt, observedAt time.Time) {
	receipt.ObservedAt = observedAt.UTC()
	receipt.EvidenceDigest = ""
	receipt.EvidenceDigest, _ = canonicalDigest(*receipt)
}

func (executor LinuxExecutor) now() time.Time {
	if executor.Now != nil {
		return executor.Now().UTC()
	}
	return time.Now().UTC()
}

func truncateText(value string, maximum int) string {
	value = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(value), "\x00", ""), "\r", " "), "\n", " ")
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
