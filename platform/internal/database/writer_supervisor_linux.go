//go:build linux

package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const writerSupervisorUnit = "cyberpanel-mariadb-writer-supervisor.service"
const writerSupervisorPath = "/etc/systemd/system/" + writerSupervisorUnit
const writerDependencyPath = "/etc/systemd/system/mariadb.service.d/91-cyberpanel-writer-gate.conf"
const writerHeartbeatPath = mariaDBRunRoot + "/ha-writer-heartbeat.json"

const writerSupervisorService = "[Unit]\nDescription=CyberPanel independent MariaDB lease supervisor\nAfter=local-fs.target\nBefore=mariadb.service\n\n[Service]\nType=simple\nExecStart=/usr/local/libexec/cyberpanel/panel-execd --mariadb-writer-supervisor\nUser=root\nGroup=root\nRestart=no\nKillMode=control-group\nTimeoutStopSec=2s\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=full\nReadWritePaths=/var/lib/cyberpanel/database /run/cyberpanel/database\nRestrictAddressFamilies=AF_UNIX\n\n[Install]\nWantedBy=multi-user.target\n"
const writerDependency = "[Unit]\nBindsTo=panel-execd.service cyberpanel-mariadb-writer-supervisor.service\nAfter=panel-execd.service cyberpanel-mariadb-writer-supervisor.service\n\n[Service]\nRestart=no\nKillMode=control-group\nTimeoutStopSec=2s\nSendSIGKILL=yes\n"

type writerHeartbeat struct {
	PID             int       `json:"pid"`
	CertificateID   string    `json:"certificate_id,omitempty"`
	FenceConfigPath string    `json:"fence_config_path"`
	ValidUntil      time.Time `json:"valid_until"`
}

// This command sum cannot run a caller-selected unit or arbitrary executable.
func writerSystemctl(ctx context.Context, operation string) ([]byte, error) {
	var arguments []string
	switch operation {
	case "reload":
		arguments = []string{"daemon-reload"}
	case "start":
		arguments = []string{"start", writerSupervisorUnit}
	case "enable":
		arguments = []string{"enable", writerSupervisorUnit}
	case "stop":
		arguments = []string{"stop", "--no-block", mariaDBService}
	case "kill":
		arguments = []string{"kill", "--kill-whom=all", "--signal=SIGKILL", mariaDBService}
	case "database":
		arguments = []string{"show", mariaDBService, "--property=BindsTo", "--property=After", "--property=Restart", "--property=KillMode", "--property=TimeoutStopUSec", "--property=SendSIGKILL", "--property=ActiveState"}
	case "executor":
		arguments = []string{"show", "panel-execd.service", "--property=MainPID", "--property=ActiveState"}
	case "supervisor":
		arguments = []string{"show", writerSupervisorUnit, "--property=MainPID", "--property=ActiveState", "--property=ExecStart", "--property=User", "--property=FragmentPath", "--property=DropInPaths"}
	default:
		return nil, ErrInvalidCommand
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/usr/bin/systemctl", arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output := &limitedBuffer{remaining: 16 << 10}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil || output.overflow {
		return nil, ErrUnauthorized
	}
	return append([]byte(nil), output.buffer.Bytes()...), nil
}

func systemdProperties(output []byte) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			result[key] = value
		}
	}
	return result
}
func containsUnit(value, want string) bool {
	for _, unit := range strings.Fields(value) {
		if unit == want {
			return true
		}
	}
	return false
}
func validWriterDatabaseUnit(database map[string]string) bool {
	return containsUnit(database["BindsTo"], "panel-execd.service") && containsUnit(database["BindsTo"], writerSupervisorUnit) && containsUnit(database["After"], "panel-execd.service") && containsUnit(database["After"], writerSupervisorUnit) && database["Restart"] == "no" && database["KillMode"] == "control-group" && database["TimeoutStopUSec"] == "2s" && database["SendSIGKILL"] == "yes"
}

func (executor *LinuxMariaDBExecutor) installWriterSupervisor(ctx context.Context) error {
	dependencyDirectory := filepath.Dir(writerDependencyPath)
	if err := os.MkdirAll(dependencyDirectory, 0755); err != nil {
		return err
	}
	// Systemd configuration directories are intentionally world-readable. The
	// generic database state helper requires mode 0700, so use the root-owned,
	// non-writable-by-group-or-world directory check here instead.
	if err := verifyRootDirectory(dependencyDirectory); err != nil {
		return err
	}
	if err := atomicRootFile(writerSupervisorPath, []byte(writerSupervisorService), 0644); err != nil {
		return err
	}
	if err := atomicRootFile(writerDependencyPath, []byte(writerDependency), 0644); err != nil {
		return err
	}
	if _, err := writerSystemctl(ctx, "reload"); err != nil {
		return err
	}
	if _, err := writerSystemctl(ctx, "enable"); err != nil {
		return err
	}
	heartbeatErr := executor.publishWriterHeartbeat()
	if _, err := writerSystemctl(ctx, "start"); err != nil {
		return err
	}
	if err := executor.verifyWriterSupervisor(ctx); err != nil {
		return err
	}
	executor.writer.mu.Lock()
	executor.writer.supervised = true
	executor.writer.mu.Unlock()
	return heartbeatErr
}

func (executor *LinuxMariaDBExecutor) verifyWriterSupervisor(ctx context.Context) error {
	// Both fixed files and effective manager state are checked: a later
	// systemd override cannot silently remove the mandatory process fence.
	for path, want := range map[string]string{writerSupervisorPath: writerSupervisorService, writerDependencyPath: writerDependency} {
		actual, present, err := readManagedConfig(path)
		if err != nil || !present || string(actual) != want {
			return ErrUnauthorized
		}
	}
	if err := verifyWriterFenceConfig(executor.writerFenceConfigPath()); err != nil {
		return err
	}
	output, err := writerSystemctl(ctx, "database")
	if err != nil {
		return err
	}
	database := systemdProperties(output)
	if !validWriterDatabaseUnit(database) {
		return ErrUnauthorized
	}
	output, err = writerSystemctl(ctx, "executor")
	if err != nil {
		return err
	}
	process := systemdProperties(output)
	if process["ActiveState"] != "active" || process["MainPID"] != strconv.Itoa(os.Getpid()) {
		return ErrUnauthorized
	}
	output, err = writerSystemctl(ctx, "supervisor")
	if err != nil {
		return err
	}
	supervisor := systemdProperties(output)
	pid, err := strconv.ParseUint(supervisor["MainPID"], 10, 32)
	if err != nil || pid <= 1 || int(pid) == os.Getpid() || supervisor["ActiveState"] != "active" || supervisor["User"] != "root" || supervisor["FragmentPath"] != writerSupervisorPath || supervisor["DropInPaths"] != "" || !strings.Contains(supervisor["ExecStart"], "argv[]=/usr/local/libexec/cyberpanel/panel-execd --mariadb-writer-supervisor ;") {
		return ErrUnauthorized
	}
	return nil
}

func (executor *LinuxMariaDBExecutor) publishWriterHeartbeat() error {
	executor.writer.mu.Lock()
	active, managed, safe := executor.writer.active, executor.writer.managed, executor.writer.safe
	executor.writer.mu.Unlock()
	if !managed {
		return nil
	}
	if active == nil && !safe {
		return ErrUnauthorized
	}
	configPath := executor.writerFenceConfigPath()
	if err := verifyWriterFenceConfig(configPath); err != nil {
		return err
	}
	now := executor.now().UTC()
	heartbeat := writerHeartbeat{PID: os.Getpid(), FenceConfigPath: configPath, ValidUntil: now.Add(2 * time.Second)}
	if active != nil {
		heartbeat.CertificateID = active.Certificate.ID
		if active.Certificate.ExpiresAt.Before(heartbeat.ValidUntil) {
			heartbeat.ValidUntil = active.Certificate.ExpiresAt
		}
	}
	payload, err := json.Marshal(heartbeat)
	if err != nil {
		return err
	}
	return atomicRootFile(writerHeartbeatPath, payload, 0600)
}

func readWriterHeartbeat() (writerHeartbeat, error) {
	var heartbeat writerHeartbeat
	info, err := os.Lstat(writerHeartbeatPath)
	if err != nil {
		return heartbeat, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() > 1024 {
		return heartbeat, ErrUnauthorized
	}
	payload, err := os.ReadFile(writerHeartbeatPath)
	if err != nil {
		return heartbeat, ErrUnauthorized
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&heartbeat) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return heartbeat, ErrUnauthorized
	}
	now := time.Now().UTC()
	if heartbeat.PID <= 1 || (heartbeat.CertificateID != "" && !validSHA256(heartbeat.CertificateID)) || !now.Before(heartbeat.ValidUntil) || heartbeat.ValidUntil.After(now.Add(3*time.Second)) || verifyWriterFenceConfig(heartbeat.FenceConfigPath) != nil {
		return heartbeat, ErrUnauthorized
	}
	return heartbeat, nil
}

// RunMariaDBWriterSupervisor runs in an independent root-owned systemd cgroup.
// It never enables writes. Missing/expired heartbeat, executor identity change,
// or shutdown stops and kills the MariaDB service. If this process itself dies,
// the effective BindsTo+After dependency makes systemd stop MariaDB instead.
func RunMariaDBWriterSupervisor(ctx context.Context) error {
	if os.Geteuid() != 0 || ctx == nil {
		return ErrUnauthorized
	}
	stop := func() error {
		bounded, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_, stopErr := writerSystemctl(bounded, "stop")
		_, killErr := writerSystemctl(bounded, "kill")
		output, observeErr := writerSystemctl(bounded, "database")
		state := systemdProperties(output)["ActiveState"]
		receipt := struct {
			Reason, State string
			ObservedAt    time.Time
		}{"independent_supervisor_lease_loss", "stop_unconfirmed", time.Now().UTC()}
		if observeErr == nil && (state == "inactive" || state == "failed") {
			receipt.State = "service_stopped"
			stopErr = nil
			killErr = nil
		}
		payload, _ := json.Marshal(receipt)
		writeErr := atomicRootFile(mariaDBStateRoot+"/effects/ha-supervisor-stop.json", payload, 0600)
		return errors.Join(stopErr, killErr, observeErr, writeErr)
	}
	defer stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		heartbeat, err := readWriterHeartbeat()
		if err == nil {
			output, checkErr := writerSystemctl(ctx, "executor")
			process := systemdProperties(output)
			if checkErr != nil || process["ActiveState"] != "active" || process["MainPID"] != strconv.Itoa(heartbeat.PID) {
				err = ErrUnauthorized
			}
		}
		if err == nil {
			output, checkErr := writerSystemctl(ctx, "database")
			if checkErr != nil || !validWriterDatabaseUnit(systemdProperties(output)) {
				err = ErrUnauthorized
			}
		}
		if err != nil {
			_ = stop()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
