//go:build linux

package dns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
)

type LinuxPowerDNSPlatform string

const (
	PowerDNSUbuntuNoble LinuxPowerDNSPlatform = "ubuntu-noble"
	PowerDNSAlma9       LinuxPowerDNSPlatform = "alma-9"
)

type PowerDNSRuntimeOperation string

const (
	PowerDNSValidateConfiguration PowerDNSRuntimeOperation = "validate-configuration"
	PowerDNSReloadService         PowerDNSRuntimeOperation = "reload-service"
	PowerDNSProbeService          PowerDNSRuntimeOperation = "probe-service"
	PowerDNSRollbackConfiguration PowerDNSRuntimeOperation = "rollback-configuration"
	PowerDNSRediscoverZones       PowerDNSRuntimeOperation = "rediscover-zones"
	PowerDNSNotifyZone            PowerDNSRuntimeOperation = "notify-zone"
)

type PowerDNSOwnership struct {
	PDNSGID uint32 `json:"pdns_gid"`
}

func (ownership PowerDNSOwnership) Validate() error {
	if ownership.PDNSGID == 0 {
		return ErrInvalidDNS
	}
	return nil
}

type PowerDNSRuntimeReceipt struct {
	Operation      PowerDNSRuntimeOperation `json:"operation"`
	GenerationID   string                   `json:"generation_id,omitempty"`
	EvidenceDigest string                   `json:"evidence_digest"`
	Success        bool                     `json:"success"`
	Healthy        bool                     `json:"healthy"`
	ObservedAt     time.Time                `json:"observed_at"`
}

type PowerDNSActivationReceipt struct {
	GenerationID        string                 `json:"generation_id"`
	SnapshotDigest      string                 `json:"snapshot_digest"`
	GenerationDigest    string                 `json:"generation_digest"`
	DatabaseFingerprint string                 `json:"database_fingerprint"`
	PreviousGeneration  string                 `json:"previous_generation,omitempty"`
	Validation          PowerDNSRuntimeReceipt `json:"validation"`
	Reload              PowerDNSRuntimeReceipt `json:"reload"`
	Probe               PowerDNSRuntimeReceipt `json:"probe"`
	Rollback             PowerDNSRuntimeReceipt `json:"rollback"`
	RolledBack           bool                   `json:"rolled_back"`
	ObservedAt           time.Time              `json:"observed_at"`
}

type powerDNSProfile struct {
	systemctl        string
	pdnsServer       string
	pdnsControl      string
	pdnsUtil         string
	dig              string
	unit             string
	configuration    powerDNSBinding
	primarySetting   string
	secondarySetting string
}

type powerDNSBinding struct {
	link   string
	target string
}

func profileForPowerDNS(platform LinuxPowerDNSPlatform) (powerDNSProfile, error) {
	profile := powerDNSProfile{
		systemctl:        "/usr/bin/systemctl",
		pdnsServer:       "/usr/sbin/pdns_server",
		pdnsControl:      "/usr/bin/pdns_control",
		pdnsUtil:         "/usr/bin/pdnsutil",
		dig:              "/usr/bin/dig",
		unit:             "pdns.service",
		primarySetting:   "primary",
		secondarySetting: "secondary",
	}
	switch platform {
	case PowerDNSUbuntuNoble:
		profile.configuration = powerDNSBinding{
			link:   "/etc/powerdns/pdns.conf",
			target: PowerDNSConfigurationRoot + "/current/" + powerDNSConfigurationKey,
		}
	case PowerDNSAlma9:
		profile.configuration = powerDNSBinding{
			link:   "/etc/pdns/pdns.conf",
			target: PowerDNSConfigurationRoot + "/current/" + powerDNSConfigurationKey,
		}
	default:
		return powerDNSProfile{}, ErrInvalidDNS
	}
	return profile, nil
}

// LinuxPowerDNSHost is the privileged configuration boundary. Callers provide
// only a non-secret snapshot; this host resolves the credential, materializes a
// root-owned immutable generation, and executes a closed set of PowerDNS and
// systemd operations.
type LinuxPowerDNSHost struct {
	Store                      *daemoncfg.Store
	Platform                   LinuxPowerDNSPlatform
	Ownership                  PowerDNSOwnership
	Resolver                   PowerDNSCredentialResolver
	ControlDatabaseFingerprint string
	Now                        func() time.Time

	profile powerDNSProfile
	mu      sync.Mutex
}

func OpenLinuxPowerDNSHost(platform LinuxPowerDNSPlatform, ownership PowerDNSOwnership, resolver PowerDNSCredentialResolver, controlDatabaseFingerprint string) (*LinuxPowerDNSHost, error) {
	if ownership.Validate() != nil || resolver == nil || !powerDNSSHA256(controlDatabaseFingerprint) {
		return nil, ErrInvalidDNS
	}
	profile, err := profileForPowerDNS(platform)
	if err != nil {
		return nil, err
	}
	store, err := daemoncfg.OpenStore(PowerDNSConfigurationRoot, PowerDNSConfigurationRoot)
	if err != nil {
		return nil, err
	}
	return &LinuxPowerDNSHost{
		Store:                      store,
		Platform:                   platform,
		Ownership:                  ownership,
		Resolver:                   resolver,
		ControlDatabaseFingerprint: controlDatabaseFingerprint,
		profile:                    profile,
	}, nil
}

func (host *LinuxPowerDNSHost) Close() error {
	if host == nil {
		return nil
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.Store == nil {
		return nil
	}
	err := host.Store.Close()
	host.Store = nil
	return err
}

func (host *LinuxPowerDNSHost) now() time.Time {
	if host.Now != nil {
		return host.Now().UTC()
	}
	return time.Now().UTC()
}

func (host *LinuxPowerDNSHost) EnsureBindings(ctx context.Context) error {
	if host == nil {
		return ErrInvalidDNS
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	return host.ensureBindings(ctx)
}

func (host *LinuxPowerDNSHost) ensureBindings(ctx context.Context) error {
	if host.Store == nil || ctx == nil {
		return ErrInvalidDNS
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return ensurePowerDNSBinding(host.profile.configuration)
}

func (host *LinuxPowerDNSHost) currentGeneration(ctx context.Context) (string, error) {
	if err := host.ensureBindings(ctx); err != nil {
		return "", err
	}
	generation, err := host.Store.Current()
	if err != nil {
		return "", err
	}
	if generation == "" {
		return "", ErrInvalidDNS
	}
	return generation, nil
}

func (host *LinuxPowerDNSHost) observedCurrentGeneration(ctx context.Context) (string, error) {
	if host.Store == nil || ctx == nil {
		return "", ErrInvalidDNS
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := observePowerDNSBinding(host.profile.configuration); err != nil {
		return "", err
	}
	generation, err := host.Store.Current()
	if err != nil {
		return "", err
	}
	if generation == "" {
		return "", ErrInvalidDNS
	}
	return generation, nil
}

func (host *LinuxPowerDNSHost) ApplyConfiguration(ctx context.Context, snapshot PowerDNSConfigSnapshot) (PowerDNSActivationReceipt, error) {
	receipt := PowerDNSActivationReceipt{ObservedAt: time.Now().UTC()}
	if host == nil || ctx == nil {
		return receipt, ErrInvalidDNS
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	receipt.ObservedAt = host.now()
	if host.Store == nil || host.Resolver == nil {
		return receipt, ErrInvalidDNS
	}
	canonical, err := snapshot.canonical(host.ControlDatabaseFingerprint)
	if err != nil {
		return receipt, err
	}
	receipt.DatabaseFingerprint = canonical.Database.Fingerprint
	if err = host.ensureBindings(ctx); err != nil {
		return receipt, err
	}
	var credential []byte
	if canonical.Database.Backend==PowerDNSBackendMariaDB{credential,err=host.Resolver.ResolvePowerDNSDatabaseCredential(ctx,canonical.Database);if err!=nil{return receipt,ErrPowerDNSConfigCredential}}
	defer clearPowerDNSBytes(credential)
	generation, err := renderPowerDNSGeneration(canonical, credential, host.Ownership, host.profile, host.ControlDatabaseFingerprint)
	if err != nil {
		return receipt, errors.Join(ErrPowerDNSConfigCredential, err)
	}
	defer clearPowerDNSArtifacts(generation.Artifacts)
	receipt.GenerationID = generation.ID
	receipt.SnapshotDigest = generation.SnapshotDigest
	receipt.GenerationDigest = generation.SnapshotDigest

	if _, err = host.Store.Stage(ctx, generation.ID, generation.StorageDigest, generation.Artifacts); err != nil {
		return receipt, err
	}
	current, err := host.Store.Current()
	if err != nil {
		return receipt, err
	}
	receipt.PreviousGeneration = current
	if current == generation.ID {
		receipt.Probe, err = host.probe(ctx, generation.ID)
		return receipt, err
	}

	receipt.Validation, err = host.validateGeneration(ctx, generation.ID, credential)
	if err != nil {
		return receipt, err
	}
	previous, err := host.Store.Activate(ctx, generation.ID)
	if err != nil {
		return receipt, err
	}
	receipt.PreviousGeneration = previous
	receipt.Reload, err = host.reload(ctx, generation.ID)
	var probeErr error
	receipt.Probe, probeErr = host.probe(ctx, generation.ID)
	if err == nil && probeErr == nil {
		return receipt, nil
	}

	var rollbackErr error
	receipt.Rollback, receipt.RolledBack, rollbackErr = host.rollback(ctx, previous, err, probeErr)
	if receipt.RolledBack {
		return receipt, errors.Join(err, probeErr)
	}
	return receipt, errors.Join(ErrPowerDNSAmbiguous, err, probeErr, rollbackErr)
}

func (host *LinuxPowerDNSHost) Reload(ctx context.Context) (PowerDNSRuntimeReceipt, error) {
	if host == nil || ctx == nil {
		return PowerDNSRuntimeReceipt{}, ErrInvalidDNS
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	generation, err := host.currentGeneration(ctx)
	if err != nil {
		return PowerDNSRuntimeReceipt{}, err
	}
	return host.reload(ctx, generation)
}

func (host *LinuxPowerDNSHost) Probe(ctx context.Context) (PowerDNSRuntimeReceipt, error) {
	if host == nil || ctx == nil {
		return PowerDNSRuntimeReceipt{}, ErrInvalidDNS
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	generation, err := host.observedCurrentGeneration(ctx)
	if err != nil {
		return PowerDNSRuntimeReceipt{}, err
	}
	return host.probe(ctx, generation)
}

// Rediscover asks the authoritative server to reread the dedicated backend
// after a secured database commit. The operation has no caller-controlled
// executable, option, or path surface.
func (host *LinuxPowerDNSHost) Rediscover(ctx context.Context) (PowerDNSRuntimeReceipt, error) {
	if host == nil || ctx == nil {
		return PowerDNSRuntimeReceipt{}, ErrInvalidDNS
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	generation, err := host.currentGeneration(ctx)
	if err != nil {
		return PowerDNSRuntimeReceipt{}, err
	}
	receipt := PowerDNSRuntimeReceipt{
		Operation:    PowerDNSRediscoverZones,
		GenerationID: generation,
		ObservedAt:   host.now(),
	}
	output, err := runPowerDNSProcess(ctx, host.profile.pdnsControl, "rediscover")
	receipt.EvidenceDigest = digestPowerDNSEvidence(string(output), powerDNSErrorText(err))
	receipt.Success = err == nil
	receipt.Healthy = err == nil
	return receipt, err
}

// NotifyZone queues authoritative NOTIFY for one validated, absolute zone
// identity after its database transaction has committed.
func (host *LinuxPowerDNSHost) NotifyZone(ctx context.Context, zone DNSName) (PowerDNSRuntimeReceipt, error) {
	if host == nil || ctx == nil || !validPowerDNSZoneName(zone) {
		return PowerDNSRuntimeReceipt{}, ErrInvalidDNS
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	generation, err := host.currentGeneration(ctx)
	if err != nil {
		return PowerDNSRuntimeReceipt{}, err
	}
	receipt := PowerDNSRuntimeReceipt{
		Operation:    PowerDNSNotifyZone,
		GenerationID: generation,
		ObservedAt:   host.now(),
	}
	output, err := runPowerDNSProcess(ctx, host.profile.pdnsControl, "notify", zone.String())
	receipt.EvidenceDigest = digestPowerDNSEvidence(zone.String(), string(output), powerDNSErrorText(err))
	receipt.Success = err == nil
	receipt.Healthy = err == nil
	return receipt, err
}

func validPowerDNSZoneName(zone DNSName) bool {
	value := zone.String()
	if value == "" || value == "@" || strings.Contains(value, "*") {
		return false
	}
	parsed, err := ParseName(value)
	return err == nil && parsed.String() == value
}

func (host *LinuxPowerDNSHost) validateGeneration(ctx context.Context, generation string, credential []byte) (PowerDNSRuntimeReceipt, error) {
	receipt := PowerDNSRuntimeReceipt{
		Operation:    PowerDNSValidateConfiguration,
		GenerationID: generation,
		ObservedAt:   host.now(),
	}
	configurationDirectory := filepath.Join(PowerDNSConfigurationRoot, "generations", generation, "pdns")
	output, err := runPowerDNSProcess(ctx, host.profile.pdnsServer, "--config-dir="+configurationDirectory, "--config=check")
	defer clearPowerDNSBytes(output)
	redacted := bytes.ReplaceAll(output, credential, []byte("[REDACTED]"))
	receipt.EvidenceDigest = digestPowerDNSEvidence(string(redacted), redactedPowerDNSErrorText(err, credential))
	clearPowerDNSBytes(redacted)
	receipt.Success = err == nil
	return receipt, err
}

func (host *LinuxPowerDNSHost) reload(ctx context.Context, generation string) (PowerDNSRuntimeReceipt, error) {
	receipt := PowerDNSRuntimeReceipt{
		Operation:    PowerDNSReloadService,
		GenerationID: generation,
		ObservedAt:   host.now(),
	}
	// A credential mount pins one config generation for the service lifetime.
	// Restart to consume the newly activated generation, including on rollback.
	output, err := runPowerDNSProcess(ctx, host.profile.systemctl, "restart", host.profile.unit)
	receipt.EvidenceDigest = digestPowerDNSEvidence(string(output), powerDNSErrorText(err))
	receipt.Success = err == nil
	receipt.Healthy = err == nil
	return receipt, err
}

func (host *LinuxPowerDNSHost) probe(ctx context.Context, generation string) (PowerDNSRuntimeReceipt, error) {
	receipt := PowerDNSRuntimeReceipt{
		Operation:    PowerDNSProbeService,
		GenerationID: generation,
		ObservedAt:   host.now(),
	}
	activeOutput, activeErr := runPowerDNSProcess(ctx, host.profile.systemctl, "is-active", "--quiet", host.profile.unit)
	pingOutput, pingErr := runPowerDNSProcess(ctx, host.profile.pdnsControl, "ping")
	pingValid := pingErr == nil && strings.EqualFold(strings.TrimSpace(string(pingOutput)), "PONG")
	if !pingValid && pingErr == nil {
		pingErr = ErrPowerDNSIntegrity
	}
	receipt.EvidenceDigest = digestPowerDNSEvidence(
		string(activeOutput), powerDNSErrorText(activeErr),
		string(pingOutput), powerDNSErrorText(pingErr),
	)
	receipt.Success = activeErr == nil && pingErr == nil
	receipt.Healthy = receipt.Success
	return receipt, errors.Join(activeErr, pingErr)
}

func (host *LinuxPowerDNSHost) rollback(ctx context.Context, previous string, applyErrors ...error) (PowerDNSRuntimeReceipt, bool, error) {
	receipt := PowerDNSRuntimeReceipt{
		Operation:    PowerDNSRollbackConfiguration,
		GenerationID: previous,
		ObservedAt:   host.now(),
	}
	rollbackErr := host.Store.Rollback(ctx, previous)
	reloadReceipt := PowerDNSRuntimeReceipt{Operation: PowerDNSReloadService, GenerationID: previous, ObservedAt: host.now()}
	probeReceipt := PowerDNSRuntimeReceipt{Operation: PowerDNSProbeService, GenerationID: previous, ObservedAt: host.now()}
	var reloadErr error
	var probeErr error
	if rollbackErr == nil && previous != "" {
		reloadReceipt, reloadErr = host.reload(ctx, previous)
		if reloadErr == nil {
			probeReceipt, probeErr = host.probe(ctx, previous)
		}
	} else if rollbackErr == nil {
		reloadErr = ErrPowerDNSAmbiguous
	}
	evidence := []string{
		powerDNSErrorText(rollbackErr),
		reloadReceipt.EvidenceDigest,
		powerDNSErrorText(reloadErr),
		probeReceipt.EvidenceDigest,
		powerDNSErrorText(probeErr),
	}
	for _, applyErr := range applyErrors {
		evidence = append(evidence, powerDNSErrorText(applyErr))
	}
	receipt.EvidenceDigest = digestPowerDNSEvidence(evidence...)
	receipt.Success = rollbackErr == nil && reloadErr == nil && probeErr == nil
	receipt.Healthy = receipt.Success
	return receipt, receipt.Healthy, errors.Join(rollbackErr, reloadErr, probeErr)
}

func ensurePowerDNSBinding(binding powerDNSBinding) error {
	if !validPowerDNSBinding(binding) {
		return ErrInvalidDNS
	}
	directory := filepath.Dir(binding.link)
	if err := ensurePowerDNSConfigDirectory(directory); err != nil {
		return err
	}
	existing, err := os.Lstat(binding.link)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Symlink(binding.target, binding.link); err != nil {
			return err
		}
		return syncPowerDNSDirectory(directory)
	}
	if err != nil {
		return err
	}
	metadata, ok := existing.Sys().(*syscall.Stat_t)
	if existing.Mode()&os.ModeSymlink == 0 || !ok || metadata.Uid != 0 {
		return daemoncfg.ErrConflict
	}
	target, err := os.Readlink(binding.link)
	if err != nil || target != binding.target {
		return daemoncfg.ErrConflict
	}
	return nil
}

func checkPowerDNSBindingBeforeActivation(binding powerDNSBinding) error {
	if !validPowerDNSBinding(binding) { return ErrInvalidDNS }
	if err := validateRootOwnedPowerDNSDirectory("/etc"); err != nil { return err }
	if err := validateRootOwnedPowerDNSDirectory(filepath.Dir(binding.link)); err != nil { return err }
	_, err := os.Lstat(binding.link)
	if errors.Is(err, os.ErrNotExist) { return nil }
	if err != nil { return err }
	return observePowerDNSBinding(binding)
}

func observePowerDNSBinding(binding powerDNSBinding) error {
	if !validPowerDNSBinding(binding) {
		return ErrInvalidDNS
	}
	directory := filepath.Dir(binding.link)
	if err := validateRootOwnedPowerDNSDirectory("/etc"); err != nil {
		return err
	}
	if err := validateRootOwnedPowerDNSDirectory(directory); err != nil {
		return err
	}
	existing, err := os.Lstat(binding.link)
	if err != nil {
		return err
	}
	metadata, ok := existing.Sys().(*syscall.Stat_t)
	if existing.Mode()&os.ModeSymlink == 0 || !ok || metadata.Uid != 0 {
		return daemoncfg.ErrConflict
	}
	target, err := os.Readlink(binding.link)
	if err != nil || target != binding.target {
		return daemoncfg.ErrConflict
	}
	return nil
}

func validPowerDNSBinding(binding powerDNSBinding) bool {
	ubuntu := powerDNSBinding{
		link:   "/etc/powerdns/pdns.conf",
		target: PowerDNSConfigurationRoot + "/current/" + powerDNSConfigurationKey,
	}
	alma := powerDNSBinding{
		link:   "/etc/pdns/pdns.conf",
		target: PowerDNSConfigurationRoot + "/current/" + powerDNSConfigurationKey,
	}
	return binding == ubuntu || binding == alma
}

func ensurePowerDNSConfigDirectory(directory string) error {
	if directory != "/etc/powerdns" && directory != "/etc/pdns" {
		return ErrInvalidDNS
	}
	if err := validateRootOwnedPowerDNSDirectory("/etc"); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return validateRootOwnedPowerDNSDirectory(directory)
}

func validateRootOwnedPowerDNSDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.Join(ErrPowerDNSIntegrity, err)
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		return ErrPowerDNSIntegrity
	}
	return nil
}

func syncPowerDNSDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func runPowerDNSProcess(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	if ctx == nil || !validPowerDNSExecutable(executable) {
		return nil, ErrInvalidDNS
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	command.Stdin = nil
	output := &powerDNSBoundedOutput{limit: 1 << 20}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if output.overflow {
		return output.buffer.Bytes(), errors.Join(ErrPowerDNSIntegrity, err)
	}
	if err != nil {
		return output.buffer.Bytes(), fmt.Errorf("fixed PowerDNS operation failed: %w", err)
	}
	return append([]byte(nil), output.buffer.Bytes()...), nil
}

func validPowerDNSExecutable(executable string) bool {
	switch executable {
	case "/usr/bin/systemctl", "/usr/sbin/pdns_server", "/usr/bin/pdns_control", "/usr/bin/pdnsutil", "/usr/bin/dig":
		return true
	default:
		return false
	}
}

type powerDNSBoundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (output *powerDNSBoundedOutput) Write(value []byte) (int, error) {
	original := len(value)
	remaining := output.limit - output.buffer.Len()
	if remaining <= 0 {
		output.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		output.overflow = true
	}
	_, _ = output.buffer.Write(value)
	return original, nil
}

func digestPowerDNSEvidence(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(hash, strconv.Itoa(len(value)))
		_, _ = io.WriteString(hash, ":")
		_, _ = io.WriteString(hash, value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func powerDNSErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func redactedPowerDNSErrorText(err error, secret []byte) string {
	if err == nil {
		return ""
	}
	message := []byte(err.Error())
	defer clearPowerDNSBytes(message)
	redacted := bytes.ReplaceAll(message, secret, []byte("[REDACTED]"))
	defer clearPowerDNSBytes(redacted)
	return string(redacted)
}
