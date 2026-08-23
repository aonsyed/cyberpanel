//go:build linux

package serviceregistry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	SystemctlPath        = "/usr/bin/systemctl"
	maxCommandOutput     = 32 << 10
	maxSystemdProperties = 24
	maxProcFileBytes     = 16 << 10
	maxCommandDuration   = 30 * time.Second
	maxProbeDuration     = 15 * time.Second
	maxExecutionDuration = 10 * time.Minute
)

type LinuxProfile string

const (
	LinuxUbuntu2204 LinuxProfile = "ubuntu-22.04"
	LinuxUbuntu2404 LinuxProfile = "ubuntu-24.04"
	LinuxAlma8      LinuxProfile = "almalinux-8"
	LinuxAlma9      LinuxProfile = "almalinux-9"
)

type FixedInvocation struct {
	Program string
	Args    []string
	Timeout time.Duration
}

type InvocationResult struct {
	ExitCode int
	Output   []byte
	TimedOut bool
	Duration time.Duration
}

type Runner interface {
	Run(context.Context, FixedInvocation) (InvocationResult, error)
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	remaining int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	kept := 0
	if b.remaining > 0 {
		keep := len(p)
		if keep > b.remaining {
			keep = b.remaining
		}
		_, _ = b.buffer.Write(p[:keep])
		b.remaining -= keep
		kept = keep
	}
	if kept < original {
		b.truncated = true
	}
	return original, nil
}

type BoundedExecRunner struct {
	allowed map[string]struct{}
}

func invocationKey(program string, args []string) string {
	return program + "\x00" + strings.Join(args, "\x00")
}

func NewBoundedExecRunner(profile LinuxProfile, registry *Registry) (*BoundedExecRunner, error) {
	if registry == nil {
		return nil, fmt.Errorf("%w: nil registry", ErrInvalid)
	}
	bindings, err := bindingsFor(profile)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(bindings)*12)
	if err := validateBindings(registry, bindings); err != nil {
		return nil, err
	}
	if err := validateProfileSupport(profile, registry.support); err != nil {
		return nil, err
	}
	for id, binding := range bindings {
		allowed[invocationKey(SystemctlPath, systemdShowArgs(binding.Unit))] = struct{}{}
		for _, action := range []Action{ActionStart, ActionStop, ActionRestart, ActionReload, ActionEnable, ActionDisable} {
			if registry.actionAllowed(id, action) {
				allowed[invocationKey(SystemctlPath, systemdActionArgs(action, binding.Unit))] = struct{}{}
			}
		}
		if binding.Validator.Program != "" {
			allowed[invocationKey(binding.Validator.Program, binding.Validator.Args)] = struct{}{}
		}
	}
	return &BoundedExecRunner{allowed: allowed}, nil
}

func (r *BoundedExecRunner) Run(ctx context.Context, invocation FixedInvocation) (InvocationResult, error) {
	if invocation.Program == "" || invocation.Program[0] != '/' || invocation.Timeout <= 0 || invocation.Timeout > maxCommandDuration {
		return InvocationResult{}, fmt.Errorf("%w: invalid fixed invocation", ErrInvalid)
	}
	if _, ok := r.allowed[invocationKey(invocation.Program, invocation.Args)]; !ok {
		return InvocationResult{}, fmt.Errorf("%w: invocation is not allowlisted", ErrUnauthorized)
	}
	commandContext, cancel := context.WithTimeout(ctx, invocation.Timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, invocation.Program, invocation.Args...)
	command.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
		"HOME=/",
		"TMPDIR=/tmp",
	}
	command.Dir = "/"
	output := &boundedBuffer{remaining: maxCommandOutput}
	command.Stdout = output
	command.Stderr = output
	started := time.Now()
	err := command.Run()
	result := InvocationResult{ExitCode: 0, Output: append([]byte(nil), output.buffer.Bytes()...), Duration: time.Since(started)}
	if contextErr := commandContext.Err(); contextErr != nil {
		result.TimedOut = contextErr == context.DeadlineExceeded
		result.ExitCode = -1
		return result, contextErr
	}
	if output.truncated {
		return result, fmt.Errorf("%w: command output exceeded %d bytes", ErrAmbiguous, maxCommandOutput)
	}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	result.ExitCode = -1
	return result, fmt.Errorf("execute fixed command: %w", err)
}

type linuxBinding struct {
	Unit            string
	PackageProfile  string
	Validator       FixedInvocation
	ProbeID         string
	Executables     []string
}

func fixed(program string, args ...string) FixedInvocation {
	return FixedInvocation{Program: program, Args: args, Timeout: maxCommandDuration}
}

func bindingsFor(profile LinuxProfile) (map[ServiceID]linuxBinding, error) {
	if profile != LinuxUbuntu2204 && profile != LinuxUbuntu2404 && profile != LinuxAlma8 && profile != LinuxAlma9 {
		return nil, fmt.Errorf("%w: unknown Linux profile", ErrUnsupported)
	}
	ubuntu := profile == LinuxUbuntu2204 || profile == LinuxUbuntu2404
	mariaUnit := "mariadb.service"
	redisUnit := "redis.service"
	clamUnit := "clamd@scan.service"
	unitRoot := "/usr/lib/systemd/system/"
	if ubuntu {
		redisUnit = "redis-server.service"
		clamUnit = "clamav-daemon.service"
		unitRoot = "/lib/systemd/system/"
	}
	bindings := map[ServiceID]linuxBinding{
		ServiceOpenLiteSpeed: {
			Unit: "lsws.service", PackageProfile: "service-openlitespeed", ProbeID: "http-local-openlitespeed",
			Validator: fixed("/usr/local/lsws/bin/openlitespeed", "-t"),
			Executables: []string{"/usr/local/lsws/bin/lshttpd", "/usr/local/lsws/bin/openlitespeed"},
		},
		ServiceLiteSpeed: {
			Unit: "lsws.service", PackageProfile: "service-litespeed-enterprise", ProbeID: "http-local-litespeed",
			Validator: fixed("/usr/local/lsws/bin/litespeed", "-t"),
			Executables: []string{"/usr/local/lsws/bin/lshttpd", "/usr/local/lsws/bin/litespeed"},
		},
		ServicePowerDNS: {
			Unit: "pdns.service", PackageProfile: "service-powerdns", ProbeID: "dns-local-authoritative",
			Validator: fixed("/usr/sbin/pdns_server", "--config-dir=/etc/powerdns", "--config-check"),
			Executables: []string{"/usr/sbin/pdns_server"},
		},
		ServiceMariaDB: {
			Unit: mariaUnit, PackageProfile: "service-mariadb", ProbeID: "mysql-local-presentation",
			Validator: fixed("/usr/bin/my_print_defaults", "mysqld"),
			Executables: []string{"/usr/sbin/mariadbd", "/usr/libexec/mariadbd"},
		},
		ServicePostfix: {
			Unit: "postfix.service", PackageProfile: "service-postfix", ProbeID: "smtp-local-presentation",
			Validator: fixed("/usr/sbin/postfix", "check"),
			Executables: []string{"/usr/lib/postfix/sbin/master", "/usr/libexec/postfix/master"},
		},
		ServiceDovecot: {
			Unit: "dovecot.service", PackageProfile: "service-dovecot", ProbeID: "imap-local-presentation",
			Validator: fixed("/usr/sbin/doveconf", "-n"),
			Executables: []string{"/usr/sbin/dovecot"},
		},
		ServiceRspamd: {
			Unit: "rspamd.service", PackageProfile: "service-rspamd", ProbeID: "rspamd-local-controller",
			Validator: fixed("/usr/bin/rspamadm", "configtest"),
			Executables: []string{"/usr/bin/rspamd", "/usr/sbin/rspamd"},
		},
		ServiceClamAV: {
			Unit: clamUnit, PackageProfile: "service-clamav", ProbeID: "clamav-local-presentation",
			Validator: fixed("/usr/sbin/clamd", "--config-test"),
			Executables: []string{"/usr/sbin/clamd"},
		},
		ServiceFTPS: {
			Unit: "pure-ftpd.service", PackageProfile: "service-ftps", ProbeID: "ftps-local-presentation",
			Validator: fixed("/usr/bin/systemd-analyze", "verify", unitRoot+"pure-ftpd.service"),
			Executables: []string{"/usr/sbin/pure-ftpd"},
		},
		ServiceRedis: {
			Unit: redisUnit, PackageProfile: "service-redis", ProbeID: "redis-local-presentation",
			Validator: fixed("/usr/bin/redis-server", "/etc/redis/redis.conf", "--test-memory", "1"),
			Executables: []string{"/usr/bin/redis-server"},
		},
		ServiceSearch: {
			Unit: "elasticsearch.service", PackageProfile: "service-search", ProbeID: "search-local-health",
			Validator: fixed("/usr/bin/systemd-analyze", "verify", unitRoot+"elasticsearch.service"),
			Executables: []string{"/usr/share/elasticsearch/jdk/bin/java", "/usr/bin/java"},
		},
		ServiceContainers: {
			Unit: "containerd.service", PackageProfile: "service-containers", ProbeID: "containerd-local-health",
			Validator: fixed("/usr/bin/containerd", "config", "dump"),
			Executables: []string{"/usr/bin/containerd"},
		},
		ServicePanelCore: {
			Unit: "cyberpanel-core.service", ProbeID: "panel-core-local-health",
			Validator: fixed("/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/cyberpanel-core.service"),
			Executables: []string{"/usr/local/CyberCP/bin/cyberpanel-core"},
		},
		ServicePanelGateway: {
			Unit: "cyberpanel-gateway.service", ProbeID: "panel-gateway-local-health",
			Validator: fixed("/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/cyberpanel-gateway.service"),
			Executables: []string{"/usr/local/CyberCP/bin/cyberpanel-gateway"},
		},
		ServiceScheduler: {
			Unit: "cyberpanel-scheduler.service", ProbeID: "scheduler-local-health",
			Validator: fixed("/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/cyberpanel-scheduler.service"),
			Executables: []string{"/usr/local/CyberCP/bin/cyberpanel-scheduler"},
		},
		ServiceNodeAgent: {
			Unit: "cyberpanel-node-agent.service", ProbeID: "node-agent-local-health",
			Validator: fixed("/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/cyberpanel-node-agent.service"),
			Executables: []string{"/usr/local/CyberCP/bin/cyberpanel-node-agent"},
		},
	}
	phpVersions := []struct {
		ID      ServiceID
		Version string
	}{
		{ServicePHP74, "74"}, {ServicePHP80, "80"}, {ServicePHP81, "81"},
		{ServicePHP82, "82"}, {ServicePHP83, "83"}, {ServicePHP84, "84"},
	}
	for _, php := range phpVersions {
		root := "/usr/local/lsws/lsphp" + php.Version
		bindings[php.ID] = linuxBinding{
			Unit: "lsphp" + php.Version + ".service", PackageProfile: "service-php" + php.Version, ProbeID: "php-fpm-local-" + php.Version,
			Validator: fixed(root+"/bin/php", "-r", "exit(0);"),
			Executables: []string{root + "/bin/lsphp", root + "/sbin/php-fpm"},
		}
	}
	return bindings, nil
}

func systemdShowArgs(unit string) []string {
	return []string{
		"show",
		"--no-pager",
		"--property=LoadState,UnitFileState,ActiveState,SubState,MainPID,ExecMainStartTimestampMonotonic,ControlGroup,InvocationID,FragmentPath,NeedDaemonReload",
		unit,
	}
}

func systemdActionArgs(action Action, unit string) []string {
	return []string{string(action), unit}
}

type BoundHealthProbe struct {
	ServiceID ServiceID
	ProbeID   string
	Unit      string
	Process   ProcessIdentity
}

type HealthEvidence struct {
	State                HealthState
	ExpectedListenersOwned bool
	InternallyHealthy    bool
	ExternallyFunctional bool
	EvidenceDigest       string
	ObservedAt           time.Time
}

func SealHealthEvidence(e HealthEvidence) (HealthEvidence, error) {
	if e.ObservedAt.IsZero() {
		return HealthEvidence{}, fmt.Errorf("%w: incomplete health evidence", ErrInvalid)
	}
	switch e.State {
	case HealthHealthy, HealthDegraded, HealthFailed, HealthUnsupported, HealthIndeterminate:
	default:
		return HealthEvidence{}, fmt.Errorf("%w: invalid health evidence state", ErrInvalid)
	}
	if e.State == HealthHealthy && (!e.ExpectedListenersOwned || !e.InternallyHealthy || !e.ExternallyFunctional) {
		return HealthEvidence{}, fmt.Errorf("%w: healthy evidence lacks required proofs", ErrInvalid)
	}
	e.EvidenceDigest = ""
	d, err := digestValue(e)
	if err != nil {
		return HealthEvidence{}, err
	}
	e.EvidenceDigest = d
	return e, nil
}

type HealthProber interface {
	Probe(context.Context, BoundHealthProbe) (HealthEvidence, error)
}

type LinuxObserver struct {
	registry *Registry
	bindings map[ServiceID]linuxBinding
	runner   Runner
	prober   HealthProber
	clock    Clock
}

func NewLinuxObserver(profile LinuxProfile, registry *Registry, runner Runner, prober HealthProber, clock Clock) (*LinuxObserver, error) {
	if registry == nil || runner == nil || prober == nil || clock == nil {
		return nil, fmt.Errorf("%w: incomplete Linux observer dependencies", ErrInvalid)
	}
	bindings, err := bindingsFor(profile)
	if err != nil {
		return nil, err
	}
	if err := validateBindings(registry, bindings); err != nil {
		return nil, err
	}
	if err := validateProfileSupport(profile, registry.support); err != nil {
		return nil, err
	}
	return &LinuxObserver{registry: registry, bindings: bindings, runner: runner, prober: prober, clock: clock}, nil
}

func validateProfileSupport(profile LinuxProfile, support SupportContext) error {
	expected := LinuxProfile(support.OSFamily + "-" + support.OSVersion)
	if expected != profile {
		return fmt.Errorf("%w: Linux profile does not match support tuple", ErrUnsupported)
	}
	return nil
}

func validateBindings(registry *Registry, bindings map[ServiceID]linuxBinding) error {
	definitions := registry.Definitions()
	if len(bindings) != len(definitions) {
		return fmt.Errorf("%w: Linux binding set is not closed over registry", ErrInvalid)
	}
	units := make(map[string]ServiceID)
	for _, definition := range definitions {
		binding, ok := bindings[definition.ID]
		if !ok || binding.Unit == "" || binding.ProbeID == "" || len(binding.Executables) == 0 {
			return fmt.Errorf("%w: incomplete Linux binding for %s", ErrInvalid, definition.ID)
		}
		if binding.PackageProfile != definition.PackageProfile {
			return fmt.Errorf("%w: package profile mismatch for %s", ErrInvalid, definition.ID)
		}
		if other, duplicate := units[binding.Unit]; duplicate {
			allowedPair := (definition.ID == ServiceOpenLiteSpeed && other == ServiceLiteSpeed) || (definition.ID == ServiceLiteSpeed && other == ServiceOpenLiteSpeed)
			if !allowedPair {
				return fmt.Errorf("%w: duplicate unit mapping for %s", ErrInvalid, definition.ID)
			}
		}
		units[binding.Unit] = definition.ID
		if binding.Validator.Program != "" && binding.Validator.Program[0] != '/' {
			return fmt.Errorf("%w: non-absolute validator for %s", ErrInvalid, definition.ID)
		}
	}
	return nil
}

func parseSystemdProperties(output []byte) (map[string]string, error) {
	if len(output) == 0 || len(output) > maxCommandOutput {
		return nil, fmt.Errorf("%w: bounded systemd output", ErrAmbiguous)
	}
	allowed := map[string]bool{
		"LoadState": true, "UnitFileState": true, "ActiveState": true, "SubState": true,
		"MainPID": true, "ExecMainStartTimestampMonotonic": true, "ControlGroup": true,
		"InvocationID": true, "FragmentPath": true, "NeedDaemonReload": true,
	}
	properties := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) > maxSystemdProperties {
		return nil, fmt.Errorf("%w: too many systemd properties", ErrAmbiguous)
	}
	for _, line := range lines {
		key, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		if !ok || !allowed[key] {
			return nil, fmt.Errorf("%w: unexpected systemd property", ErrAmbiguous)
		}
		if _, duplicate := properties[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate systemd property", ErrAmbiguous)
		}
		if len(value) > 4096 {
			return nil, fmt.Errorf("%w: oversized systemd property", ErrAmbiguous)
		}
		properties[key] = value
	}
	for _, required := range []string{"LoadState", "UnitFileState", "ActiveState", "SubState", "MainPID", "ExecMainStartTimestampMonotonic", "ControlGroup", "InvocationID", "FragmentPath", "NeedDaemonReload"} {
		if _, ok := properties[required]; !ok {
			return nil, fmt.Errorf("%w: missing systemd property", ErrAmbiguous)
		}
	}
	return properties, nil
}

func readSmallFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: process evidence exceeds bounds", ErrAmbiguous)
	}
	return data, nil
}

func parseStartTicks(stat []byte) (uint64, error) {
	closing := bytes.LastIndexByte(stat, ')')
	if closing < 0 || closing+2 >= len(stat) {
		return 0, fmt.Errorf("%w: malformed process stat", ErrAmbiguous)
	}
	fields := strings.Fields(string(stat[closing+2:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("%w: short process stat", ErrAmbiguous)
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("%w: invalid process start identity", ErrAmbiguous)
	}
	return value, nil
}

func parseUID(status []byte) (uint32, error) {
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) != 4 {
			return 0, fmt.Errorf("%w: malformed process uid", ErrAmbiguous)
		}
		value, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("%w: invalid process uid", ErrAmbiguous)
		}
		return uint32(value), nil
	}
	return 0, fmt.Errorf("%w: process uid missing", ErrAmbiguous)
}

func allowedExecutable(path string, allowed []string) bool {
	for _, exact := range allowed {
		if path == exact {
			return true
		}
	}
	return false
}

func canonicalInvocationID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func processInControlGroup(cgroup, expected string) bool {
	for _, line := range strings.Split(cgroup, "\n") {
		first := strings.IndexByte(line, ':')
		if first < 0 {
			continue
		}
		secondRelative := strings.IndexByte(line[first+1:], ':')
		if secondRelative < 0 {
			continue
		}
		path := line[first+1+secondRelative+1:]
		if path == expected {
			return true
		}
	}
	return false
}

func readProcessIdentity(properties map[string]string, binding linuxBinding) (ProcessIdentity, error) {
	pid, err := strconv.ParseInt(properties["MainPID"], 10, 64)
	if err != nil || pid <= 0 || pid > 1<<30 {
		return ProcessIdentity{}, fmt.Errorf("%w: active unit lacks valid main pid", ErrAmbiguous)
	}
	bootBytes, err := readSmallFile("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("read boot identity: %w", err)
	}
	bootID := strings.TrimSpace(string(bootBytes))
	if len(bootID) != 36 {
		return ProcessIdentity{}, fmt.Errorf("%w: invalid boot identity", ErrAmbiguous)
	}
	procRoot := "/proc/" + strconv.FormatInt(pid, 10)
	statBefore, err := readSmallFile(procRoot+"/stat", maxProcFileBytes)
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("read process identity: %w", err)
	}
	startBefore, err := parseStartTicks(statBefore)
	if err != nil {
		return ProcessIdentity{}, err
	}
	status, err := readSmallFile(procRoot+"/status", maxProcFileBytes)
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("read process owner: %w", err)
	}
	uid, err := parseUID(status)
	if err != nil {
		return ProcessIdentity{}, err
	}
	executable, err := os.Readlink(procRoot + "/exe")
	if err != nil || len(executable) > 4096 || !allowedExecutable(executable, binding.Executables) {
		return ProcessIdentity{}, fmt.Errorf("%w: process executable is not bound to service", ErrAmbiguous)
	}
	cgroupBytes, err := readSmallFile(procRoot+"/cgroup", maxProcFileBytes)
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("read process cgroup: %w", err)
	}
	statAfter, err := readSmallFile(procRoot+"/stat", maxProcFileBytes)
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("reread process identity: %w", err)
	}
	startAfter, err := parseStartTicks(statAfter)
	if err != nil || startAfter != startBefore {
		return ProcessIdentity{}, fmt.Errorf("%w: process identity changed during observation", ErrAmbiguous)
	}
	cgroup := strings.TrimSpace(string(cgroupBytes))
	if properties["ControlGroup"] == "" || !processInControlGroup(cgroup, properties["ControlGroup"]) {
		return ProcessIdentity{}, fmt.Errorf("%w: process does not belong to unit cgroup", ErrAmbiguous)
	}
	if !canonicalInvocationID(properties["InvocationID"]) {
		return ProcessIdentity{}, fmt.Errorf("%w: unit invocation identity missing", ErrAmbiguous)
	}
	return ProcessIdentity{
		BootID:        bootID,
		MainPID:       pid,
		PIDStartTicks: startBefore,
		UID:           uid,
		Executable:    executable,
		ControlGroup:  properties["ControlGroup"],
		InvocationID:  properties["InvocationID"],
	}, nil
}

func enableState(value string) EnableState {
	switch value {
	case "enabled", "enabled-runtime", "linked", "linked-runtime", "alias":
		return EnableEnabled
	case "disabled":
		return EnableDisabled
	case "static", "indirect", "generated", "transient":
		return EnableStatic
	case "masked", "masked-runtime":
		return EnableMasked
	default:
		return EnableUnknown
	}
}

func activeState(value string) ActiveState {
	switch ActiveState(value) {
	case ActiveInactive, ActiveActivating, ActiveActive, ActiveDeactivating, ActiveFailed:
		return ActiveState(value)
	default:
		return ActiveUnknown
	}
}

func commandReceipt(invocation FixedInvocation, result InvocationResult) (CommandReceipt, error) {
	argvDigest, err := digestValue(struct {
		Program string   `json:"program"`
		Args    []string `json:"args"`
	}{invocation.Program, invocation.Args})
	if err != nil {
		return CommandReceipt{}, err
	}
	outputDigest, err := digestValue(struct {
		Output []byte `json:"output"`
	}{result.Output})
	if err != nil {
		return CommandReceipt{}, err
	}
	return CommandReceipt{
		Program:      invocation.Program,
		ArgvDigest:   argvDigest,
		OutputDigest: outputDigest,
		ExitCode:     result.ExitCode,
		TimedOut:     result.TimedOut,
		Duration:     result.Duration,
	}, nil
}

func (o *LinuxObserver) validateConfig(ctx context.Context, id ServiceID) (ConfigState, ProbeResult, *CommandReceipt, error) {
	binding, ok := o.bindings[id]
	if !ok {
		return ConfigUnknown, ProbeResult{}, nil, ErrNotFound
	}
	now := o.clock.Now().UTC()
	if binding.Validator.Program == "" {
		evidence, _ := digestValue(struct {
			Service ServiceID `json:"service"`
			State   string    `json:"state"`
		}{id, "validator_unavailable"})
		return ConfigUnsupported, ProbeResult{Kind: "config", State: HealthUnsupported, EvidenceDigest: evidence, ObservedAt: now}, nil, nil
	}
	validationContext, cancel := context.WithTimeout(ctx, maxCommandDuration)
	defer cancel()
	result, runErr := o.runner.Run(validationContext, binding.Validator)
	receipt, receiptErr := commandReceipt(binding.Validator, result)
	if receiptErr != nil {
		return ConfigIndeterminate, ProbeResult{}, nil, receiptErr
	}
	state := ConfigValid
	health := HealthHealthy
	if runErr != nil || result.TimedOut {
		state = ConfigIndeterminate
		health = HealthIndeterminate
	} else if result.ExitCode != 0 {
		state = ConfigInvalid
		health = HealthFailed
	}
	evidence, err := digestValue(receipt)
	if err != nil {
		return ConfigIndeterminate, ProbeResult{}, &receipt, err
	}
	return state, ProbeResult{Kind: "config", State: health, EvidenceDigest: evidence, ObservedAt: now}, &receipt, runErr
}

func (o *LinuxObserver) observeOne(ctx context.Context, nodeID string, id ServiceID, generation, configGeneration uint64, desired *DesiredState) (ServiceObservation, error) {
	if !validID(nodeID) || !validGeneration(generation) || configGeneration > MaxGeneration {
		return ServiceObservation{}, fmt.Errorf("%w: invalid observation request", ErrInvalid)
	}
	binding, ok := o.bindings[id]
	if !ok {
		return ServiceObservation{}, fmt.Errorf("%w: service %s", ErrNotFound, id)
	}
	invocation := FixedInvocation{Program: SystemctlPath, Args: systemdShowArgs(binding.Unit), Timeout: maxCommandDuration}
	showContext, cancel := context.WithTimeout(ctx, maxCommandDuration)
	result, runErr := o.runner.Run(showContext, invocation)
	cancel()
	if runErr != nil || result.TimedOut {
		return ServiceObservation{}, fmt.Errorf("%w: systemd observation failed for %s", ErrAmbiguous, id)
	}
	properties, err := parseSystemdProperties(result.Output)
	if err != nil {
		return ServiceObservation{}, err
	}
	if result.ExitCode != 0 && properties["LoadState"] != "not-found" {
		return ServiceObservation{}, fmt.Errorf("%w: systemd observation failed for %s", ErrAmbiguous, id)
	}
	needDaemonReload := false
	switch properties["NeedDaemonReload"] {
	case "yes":
		needDaemonReload = true
	case "no":
	default:
		return ServiceObservation{}, fmt.Errorf("%w: invalid daemon-reload state", ErrAmbiguous)
	}
	var execMainStart uint64
	if properties["ExecMainStartTimestampMonotonic"] != "" {
		execMainStart, err = strconv.ParseUint(properties["ExecMainStartTimestampMonotonic"], 10, 64)
		if err != nil {
			return ServiceObservation{}, fmt.Errorf("%w: invalid systemd process start timestamp", ErrAmbiguous)
		}
	}
	if properties["ActiveState"] == "active" && execMainStart == 0 {
		return ServiceObservation{}, fmt.Errorf("%w: active unit lacks systemd start identity", ErrAmbiguous)
	}
	now := o.clock.Now().UTC()
	observation := ServiceObservation{
		NodeID:           nodeID,
		ServiceID:        id,
		Generation:       generation,
		ConfigGeneration: configGeneration,
		DefinitionDigest: o.registry.Digest(),
		Unit:             binding.Unit,
		LoadState:        properties["LoadState"],
		UnitFileState:    properties["UnitFileState"],
		SubState:         properties["SubState"],
		FragmentPath:     properties["FragmentPath"],
		NeedDaemonReload: needDaemonReload,
		ExecMainStartMonotonic: execMainStart,
		Enable:           enableState(properties["UnitFileState"]),
		Active:           activeState(properties["ActiveState"]),
		ObservedAt:       now,
	}
	if properties["LoadState"] == "not-found" {
		observation.Install = InstallAbsent
	} else if properties["LoadState"] == "loaded" {
		observation.Install = InstallInstalled
	} else {
		observation.Install = InstallUnknown
	}
	config, _, _, configErr := o.validateConfig(ctx, id)
	observation.Config = config
	if configErr != nil {
		observation.Config = ConfigIndeterminate
	}
	if observation.Active == ActiveActive {
		process, processErr := readProcessIdentity(properties, binding)
		if processErr != nil {
			observation.Health = HealthIndeterminate
			observation.ObservedAt = o.clock.Now().UTC()
			observation, _ = SealObservation(observation)
			return observation, processErr
		}
		observation.Process = process
		probeContext, probeCancel := context.WithTimeout(ctx, maxProbeDuration)
		health, probeErr := o.prober.Probe(probeContext, BoundHealthProbe{ServiceID: id, ProbeID: binding.ProbeID, Unit: binding.Unit, Process: process})
		probeCancel()
		sealedHealth, sealErr := SealHealthEvidence(health)
		probeNow := o.clock.Now().UTC()
		if probeErr != nil || sealErr != nil || sealedHealth.EvidenceDigest != health.EvidenceDigest || health.ObservedAt.After(probeNow) || probeNow.Sub(health.ObservedAt) > time.Minute {
			observation.Health = HealthIndeterminate
		} else {
			observation.Health = health.State
			observation.ExpectedListenersOwned = health.ExpectedListenersOwned
			observation.InternallyHealthy = health.InternallyHealthy
			observation.ExternallyFunctional = health.ExternallyFunctional
		}
	} else if observation.Active == ActiveInactive && observation.Install == InstallInstalled {
		observation.Health = HealthFailed
	} else if observation.Install == InstallAbsent {
		observation.Health = HealthUnsupported
	} else {
		observation.Health = HealthIndeterminate
	}
	if desired != nil {
		observation.DesiredGenerationObserved = desired.NodeID == nodeID && desired.ServiceID == id && desired.ConfigGeneration == configGeneration && desired.DefinitionDigest == o.registry.Digest()
		matchesDesired := (desired.Installed == (observation.Install == InstallInstalled)) && (desired.Enabled == (observation.Enable == EnableEnabled || observation.Enable == EnableStatic)) && desired.Active == observation.Active
		if matchesDesired && observation.DesiredGenerationObserved && !observation.NeedDaemonReload {
			observation.Drift = DriftNone
		} else {
			observation.Drift = DriftPresent
		}
	} else {
		observation.Drift = DriftUnknown
	}
	observation.ObservedAt = o.clock.Now().UTC()
	observation, err = SealObservation(observation)
	if err != nil {
		return ServiceObservation{}, err
	}
	return observation, nil
}

func (o *LinuxObserver) Observe(ctx context.Context, nodeID string, id ServiceID, generation, configGeneration uint64, desired *DesiredState) (ServiceObservation, error) {
	definition, ok := o.registry.Definition(id)
	if !ok {
		return ServiceObservation{}, fmt.Errorf("%w: service %s", ErrNotFound, id)
	}
	observation, err := o.observeOne(ctx, nodeID, id, generation, configGeneration, desired)
	if err != nil {
		return observation, err
	}
	observation.DependenciesReady = true
	dependencyEvidence := make([]string, 0, len(definition.Dependencies))
	for _, dependency := range definition.Dependencies {
		dependencyObservation, dependencyErr := o.observeOne(ctx, nodeID, dependency, 1, 0, nil)
		if dependencyErr != nil || dependencyObservation.Install != InstallInstalled || dependencyObservation.Active != ActiveActive || !dependencyObservation.InternallyHealthy {
			observation.DependenciesReady = false
		}
		dependencyEvidence = append(dependencyEvidence, dependencyObservation.EvidenceDigest)
	}
	observation.DependencyEvidenceDigest, err = digestValue(dependencyEvidence)
	if err != nil {
		return ServiceObservation{}, err
	}
	observation.ObservedAt = o.clock.Now().UTC()
	observation, err = SealObservation(observation)
	if err != nil {
		return ServiceObservation{}, err
	}
	return observation, nil
}

type LinuxExecutor struct {
	registry *Registry
	bindings map[ServiceID]linuxBinding
	observer *LinuxObserver
	runner   Runner
	packages PackageMaintenance
	clock    Clock
	ids      IDSource
}

func NewLinuxExecutor(profile LinuxProfile, registry *Registry, observer *LinuxObserver, runner Runner, packages PackageMaintenance, clock Clock, ids IDSource) (*LinuxExecutor, error) {
	if registry == nil || observer == nil || runner == nil || packages == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: incomplete Linux executor dependencies", ErrInvalid)
	}
	bindings, err := bindingsFor(profile)
	if err != nil {
		return nil, err
	}
	if err := validateBindings(registry, bindings); err != nil {
		return nil, err
	}
	if err := validateProfileSupport(profile, registry.support); err != nil {
		return nil, err
	}
	return &LinuxExecutor{registry: registry, bindings: bindings, observer: observer, runner: runner, packages: packages, clock: clock, ids: ids}, nil
}

func (e *LinuxExecutor) ambiguousObservation(nodeID string, step PlanStep) ServiceObservation {
	binding := e.bindings[step.ServiceID]
	observation := ServiceObservation{
		NodeID: nodeID, ServiceID: step.ServiceID, Generation: step.ExpectedObservedGeneration,
		ConfigGeneration: step.ExpectedConfigGeneration, DefinitionDigest: e.registry.Digest(), Unit: binding.Unit,
		Install: InstallUnknown, Enable: EnableUnknown, Active: ActiveUnknown, Config: ConfigIndeterminate,
		Health: HealthIndeterminate, Drift: DriftUnknown, ObservedAt: e.clock.Now().UTC(),
	}
	observation, _ = SealObservation(observation)
	return observation
}

func packageActionFor(action Action) (PackageAction, bool) {
	switch action {
	case ActionInstall:
		return PackageInstall, true
	case ActionRemove:
		return PackageRemove, true
	case ActionRepair:
		return PackageRepair, true
	default:
		return "", false
	}
}

func (e *LinuxExecutor) runSystemd(ctx context.Context, action Action, binding linuxBinding) (CommandReceipt, error) {
	invocation := FixedInvocation{Program: SystemctlPath, Args: systemdActionArgs(action, binding.Unit), Timeout: maxCommandDuration}
	result, err := e.runner.Run(ctx, invocation)
	receipt, receiptErr := commandReceipt(invocation, result)
	if receiptErr != nil {
		return CommandReceipt{}, receiptErr
	}
	if err != nil {
		return receipt, err
	}
	if result.TimedOut {
		return receipt, context.DeadlineExceeded
	}
	if result.ExitCode != 0 {
		return receipt, fmt.Errorf("systemd action failed for registered unit")
	}
	return receipt, nil
}

func (e *LinuxExecutor) runCompensation(ctx context.Context, serviceID ServiceID, action Action, binding linuxBinding) (*CommandReceipt, *CommandReceipt, error) {
	var validationReceipt *CommandReceipt
	if action == ActionStart || action == ActionRestart || action == ActionReload {
		config, _, command, validationErr := e.observer.validateConfig(ctx, serviceID)
		validationReceipt = command
		if validationErr != nil || config != ConfigValid {
			return nil, validationReceipt, fmt.Errorf("compensation config validation did not succeed")
		}
	}
	command, err := e.runSystemd(ctx, action, binding)
	return &command, validationReceipt, err
}

func confirmed(step PlanStep, before, after ServiceObservation) bool {
	switch step.Action {
	case ActionInspect:
		return after.Active != ActiveUnknown && after.Install != InstallUnknown
	case ActionStart, ActionRestart, ActionReload:
		return after.Install == InstallInstalled && after.Active == ActiveActive && after.Config != ConfigInvalid && after.DependenciesReady && after.ExpectedListenersOwned && after.InternallyHealthy && after.ExternallyFunctional && after.Health == HealthHealthy
	case ActionStop:
		return after.Active == ActiveInactive && after.Process.MainPID == 0
	case ActionEnable:
		return after.Enable == EnableEnabled || after.Enable == EnableStatic
	case ActionDisable:
		return after.Enable == EnableDisabled || after.Enable == EnableStatic
	case ActionInstall:
		return after.Install == InstallInstalled && after.Config == ConfigValid
	case ActionRemove:
		return after.Install == InstallAbsent && after.Active != ActiveActive
	case ActionRepair:
		if before.Active == ActiveActive {
			return after.Install == InstallInstalled && after.Config == ConfigValid && after.Active == ActiveActive && after.Health == HealthHealthy && after.InternallyHealthy
		}
		return after.Install == InstallInstalled && after.Config == ConfigValid && after.Active == before.Active
	default:
		return false
	}
}

func stateRestored(before, after ServiceObservation) bool {
	if before.Install != after.Install || before.Enable != after.Enable || before.Active != after.Active || before.Config == ConfigInvalid || after.Config == ConfigInvalid {
		return false
	}
	if before.Active == ActiveActive {
		return after.Process.BootID == before.Process.BootID && after.Process.Executable == before.Process.Executable && after.Process.UID == before.Process.UID && after.DependenciesReady && after.ExpectedListenersOwned && after.InternallyHealthy && after.ExternallyFunctional && after.Health == HealthHealthy
	}
	return true
}

func (e *LinuxExecutor) Execute(ctx context.Context, request ExecutionRequest) (LifecycleReceipt, error) {
	now := e.clock.Now().UTC()
	if request.Operation.State != OperationRunning || request.Operation.PlanID != request.Plan.ID || request.Operation.PlanDigest != request.Plan.Digest {
		return LifecycleReceipt{}, fmt.Errorf("%w: execution binding mismatch", ErrInvalid)
	}
	if err := e.registry.ValidateExecutablePlan(request.Plan, now); err != nil {
		return LifecycleReceipt{}, err
	}
	receiptID, err := e.ids.NewID("service-receipt")
	if err != nil {
		return LifecycleReceipt{}, err
	}
	executionContext, cancel := context.WithTimeout(ctx, maxExecutionDuration)
	defer cancel()
	receipt := LifecycleReceipt{
		ID: receiptID, OperationID: request.Operation.ID, PlanID: request.Plan.ID, PlanDigest: request.Plan.Digest,
		Outcome: "confirmed", StartedAt: now,
	}
	var executionErr error
	for _, step := range request.Plan.Steps {
		binding, known := e.bindings[step.ServiceID]
		if !known || binding.Unit == "" {
			executionErr = ErrUnsupported
			break
		}
		before, beforeErr := e.observer.Observe(executionContext, request.Plan.NodeID, step.ServiceID, step.ExpectedObservedGeneration, step.ExpectedConfigGeneration, nil)
		if beforeErr != nil {
			before = e.ambiguousObservation(request.Plan.NodeID, step)
		}
		stepReceipt := StepReceipt{Index: step.Index, ServiceID: step.ServiceID, Action: step.Action, Before: before}
		if beforeErr != nil {
			stepReceipt.After = before
			stepReceipt.Outcome = "ambiguous"
			stepReceipt, _ = SealStepReceipt(stepReceipt)
			receipt.Steps = append(receipt.Steps, stepReceipt)
			executionErr = fmt.Errorf("%w: pre-action observation", ErrAmbiguous)
			break
		}

		needsValidation := step.Action == ActionStart || step.Action == ActionRestart || step.Action == ActionReload
		if needsValidation {
			config, validation, command, validationErr := e.observer.validateConfig(executionContext, step.ServiceID)
			stepReceipt.Validation = validation
			if command != nil {
				stepReceipt.Commands = append(stepReceipt.Commands, *command)
			}
			if validationErr != nil || config != ConfigValid {
				stepReceipt.After = before
				stepReceipt.Outcome = "failed"
				stepReceipt, _ = SealStepReceipt(stepReceipt)
				receipt.Steps = append(receipt.Steps, stepReceipt)
				executionErr = fmt.Errorf("service config validation did not succeed")
				break
			}
		}

		if packageAction, delegated := packageActionFor(step.Action); delegated {
			if binding.PackageProfile == "" {
				executionErr = ErrUnsupported
			} else {
				packageReceipt, packageErr := e.packages.Delegate(executionContext, PackageDelegation{
					OperationID: request.Operation.ID, LifecyclePlanID: request.Plan.ID, LifecyclePlanDigest: request.Plan.Digest,
					NodeID: request.Plan.NodeID, ServiceID: step.ServiceID, ProfileID: binding.PackageProfile,
					Action: packageAction, ExpectedConfigGeneration: step.ExpectedConfigGeneration,
				})
				if packageErr != nil || !validID(packageReceipt.ReceiptID) || packageReceipt.PlanDigest != request.Plan.Digest || packageReceipt.ProfileID != binding.PackageProfile || packageReceipt.EvidenceDigest == "" || packageReceipt.Outcome != "confirmed" {
					executionErr = fmt.Errorf("package-maintenance delegation did not confirm")
				} else {
					stepReceipt.PackageReceiptRef = packageReceipt.ReceiptID
				}
			}
		} else if step.Action != ActionInspect {
			command, commandErr := e.runSystemd(executionContext, step.Action, binding)
			stepReceipt.Commands = append(stepReceipt.Commands, command)
			if commandErr != nil {
				executionErr = commandErr
			}
		}

		after, afterErr := e.observer.Observe(executionContext, request.Plan.NodeID, step.ServiceID, step.ExpectedObservedGeneration, step.ExpectedConfigGeneration, nil)
		if afterErr != nil {
			after = e.ambiguousObservation(request.Plan.NodeID, step)
			executionErr = fmt.Errorf("%w: post-action observation", ErrAmbiguous)
		}
		stepReceipt.After = after
		stepReceipt.Health = ProbeResult{Kind: "health", State: after.Health, EvidenceDigest: after.EvidenceDigest, ObservedAt: after.ObservedAt}
		if executionErr == nil && !confirmed(step, before, after) {
			executionErr = fmt.Errorf("%w: postcondition not proven", ErrAmbiguous)
		}
		if executionErr == nil {
			stepReceipt.Outcome = "confirmed"
		} else if step.Compensate != "" && !step.Irreversible {
			compensation, compensationValidation, compensationErr := e.runCompensation(executionContext, step.ServiceID, step.Compensate, binding)
			stepReceipt.Compensation = compensation
			if compensationValidation != nil {
				stepReceipt.Commands = append(stepReceipt.Commands, *compensationValidation)
			}
			restored, restoredErr := e.observer.Observe(executionContext, request.Plan.NodeID, step.ServiceID, step.ExpectedObservedGeneration, step.ExpectedConfigGeneration, nil)
			if compensationErr == nil && restoredErr == nil && stateRestored(before, restored) {
				stepReceipt.After = restored
				stepReceipt.CompensationResult = "confirmed"
				stepReceipt.Outcome = "compensated"
			} else {
				stepReceipt.CompensationResult = "ambiguous"
				stepReceipt.Outcome = "ambiguous"
				executionErr = fmt.Errorf("%w: compensation not proven", ErrAmbiguous)
			}
		} else if errors.Is(executionErr, ErrAmbiguous) || errors.Is(executionErr, context.DeadlineExceeded) || step.Irreversible {
			stepReceipt.Outcome = "ambiguous"
		} else {
			stepReceipt.Outcome = "failed"
		}
		stepReceipt, _ = SealStepReceipt(stepReceipt)
		receipt.Steps = append(receipt.Steps, stepReceipt)
		if executionErr != nil {
			switch stepReceipt.Outcome {
			case "compensated":
				receipt.Outcome = "compensated"
			case "failed":
				receipt.Outcome = "failed"
			default:
				receipt.Outcome = "ambiguous"
			}
			break
		}
	}
	if executionContext.Err() == context.DeadlineExceeded && executionErr == nil {
		executionErr = context.DeadlineExceeded
		receipt.Outcome = "ambiguous"
	}
	if executionErr != nil && receipt.Outcome == "confirmed" {
		if len(receipt.Steps) == 0 {
			receipt.Outcome = "ambiguous"
		} else {
			switch receipt.Steps[len(receipt.Steps)-1].Outcome {
			case "failed":
				receipt.Outcome = "failed"
			case "compensated":
				receipt.Outcome = "compensated"
			default:
				receipt.Outcome = "ambiguous"
			}
		}
	}
	if executionErr != nil {
		for i := len(receipt.Steps) - 1; i >= 0; i-- {
			stepReceipt := receipt.Steps[i]
			planStep := request.Plan.Steps[stepReceipt.Index]
			if stepReceipt.Outcome != "confirmed" || planStep.Compensate == "" || planStep.Irreversible {
				continue
			}
			binding := e.bindings[planStep.ServiceID]
			compensation, compensationValidation, compensationErr := e.runCompensation(executionContext, planStep.ServiceID, planStep.Compensate, binding)
			stepReceipt.Compensation = compensation
			if compensationValidation != nil {
				stepReceipt.Commands = append(stepReceipt.Commands, *compensationValidation)
			}
			restored, restoredErr := e.observer.Observe(executionContext, request.Plan.NodeID, planStep.ServiceID, planStep.ExpectedObservedGeneration, planStep.ExpectedConfigGeneration, nil)
			if compensationErr == nil && restoredErr == nil && stateRestored(stepReceipt.Before, restored) {
				stepReceipt.After = restored
				stepReceipt.CompensationResult = "confirmed"
				stepReceipt.Outcome = "compensated"
			} else {
				stepReceipt.CompensationResult = "ambiguous"
				stepReceipt.Outcome = "ambiguous"
				receipt.Outcome = "ambiguous"
				executionErr = fmt.Errorf("%w: plan compensation not proven", ErrAmbiguous)
			}
			stepReceipt, _ = SealStepReceipt(stepReceipt)
			receipt.Steps[i] = stepReceipt
		}
	}
	if len(receipt.Steps) == 0 && executionErr != nil {
		receipt.Outcome = "ambiguous"
	}
	receipt.CompletedAt = e.clock.Now().UTC()
	receipt, err = SealLifecycleReceipt(receipt)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	return receipt, executionErr
}
