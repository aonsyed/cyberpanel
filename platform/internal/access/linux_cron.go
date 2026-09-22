//go:build linux

package access

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/scheduler"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const linuxCronStateRoot = "/var/lib/cyberpanel/access-cron"

type linuxCronManifest struct {
	SiteID     SiteID           `json:"site_id"`
	Binding    LinuxSiteBinding `json:"binding"`
	Generation uint64           `json:"generation"`
	Jobs       []CronJob        `json:"jobs"`
	Digest     string           `json:"digest"`
}
type LinuxCronExecutor struct {
	Files   *LinuxFileExecutor
	Secrets *LinuxAccessSecretSource
	mu      sync.Mutex
	runs    map[string]*exec.Cmd
}

func NewLinuxCronExecutor(files *LinuxFileExecutor, secretSource *LinuxAccessSecretSource) (*LinuxCronExecutor, error) {
	if files == nil {
		return nil, ErrInvalidState
	}
	return &LinuxCronExecutor{Files: files, Secrets: secretSource, runs: map[string]*exec.Cmd{}}, nil
}
func cronUnitToken(binding LinuxSiteBinding, job CronJob) string {
	return "cyberpanel-cron-" + binding.SiteKey + "-" + string(job.ID)
}
func systemdEscapeArgument(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	if value == "" {
		return `""`
	}
	safe := true
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("/_-.@:", character)) {
			safe = false
			break
		}
	}
	if safe {
		return value
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `\n`, `\n`, `\r`, `\r`, `\t`, `\t`).Replace(value) + `"`
}
func renderCalendar(expression string) (string, error) {
	special := map[string]string{"@reboot": "boot", "@yearly": "*-01-01 00:00:00", "@annually": "*-01-01 00:00:00", "@monthly": "*-*-01 00:00:00", "@weekly": "Sun *-*-* 00:00:00", "@daily": "*-*-* 00:00:00", "@midnight": "*-*-* 00:00:00", "@hourly": "*-*-* *:00:00"}
	if value, found := special[expression]; found {
		return value, nil
	}
	normalized, err := scheduler.NormalizeExpression(expression)
	if err != nil {
		return "", ErrInvalidState
	}
	fields := strings.Fields(normalized)
	if len(fields) != 5 {
		return "", ErrInvalidState
	}
	weekdays, err := systemdWeekdays(fields[4])
	if err != nil {
		return "", err
	}
	prefix := ""
	if weekdays != "*" {
		prefix = weekdays + " "
	}
	return prefix + "*-" + fields[3] + "-" + fields[2] + " " + fields[1] + ":" + fields[0] + ":00", nil
}
func systemdWeekdays(field string) (string, error) {
	names := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
	items := strings.Split(field, ",")
	for index, item := range items {
		base, step, hasStep := strings.Cut(item, "/")
		if base == "*" {
			if hasStep {
				items[index] = base + "/" + step
			}
			continue
		}
		start, end, hasRange := strings.Cut(base, "-")
		first, err := strconv.Atoi(start)
		if err != nil || first < 0 || first > 7 {
			return "", ErrInvalidState
		}
		value := names[first]
		if hasRange {
			last, parseErr := strconv.Atoi(end)
			if parseErr != nil || last < first || last > 7 {
				return "", ErrInvalidState
			}
			value += "-" + names[last]
		}
		if hasStep {
			value += "/" + step
		}
		items[index] = value
	}
	return strings.Join(items, ","), nil
}
func atomicRootFile(path string, content []byte, mode os.FileMode) error {
	directory := path[:strings.LastIndexByte(path, '/')]
	if err := ensureAccessDirectory(directory, 0755, 0, 0); err != nil {
		return err
	}
	temporary := path + ".new"
	fd, err := syscall.Open(temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	if _, err = file.Write(content); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(temporary, mode)
	}
	if err == nil {
		err = os.Rename(temporary, path)
	}
	if err != nil {
		_ = os.Remove(temporary)
	}
	return err
}
func (executor *LinuxCronExecutor) ApplySchedule(ctx context.Context, site SiteID, generation uint64, jobs []CronJob) (CronApplyReceipt, error) {
	binding, err := executor.Files.Resolver.ResolveAccessSite(ctx, site)
	if err != nil {
		return CronApplyReceipt{}, err
	}
	for _, job := range jobs {
		if job.SiteID != site || job.Validate() != nil {
			return CronApplyReceipt{}, ErrInvalidState
		}
	}
	canonical, _ := json.Marshal(jobs)
	digest := sha256.Sum256(canonical)
	manifest := linuxCronManifest{SiteID: site, Binding: binding, Generation: generation, Jobs: jobs, Digest: hex.EncodeToString(digest[:])}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return CronApplyReceipt{}, err
	}
	if err = ensureAccessDirectory(linuxCronStateRoot, 0700, 0, 0); err != nil {
		return CronApplyReceipt{}, err
	}
	manifestPath := linuxCronStateRoot + "/" + binding.SiteKey + ".json"
	if err = atomicRootFile(manifestPath, encoded, 0600); err != nil {
		return CronApplyReceipt{}, err
	}
	wanted := map[string]struct{}{}
	for _, job := range jobs {
		if !job.Enabled {
			continue
		}
		token := cronUnitToken(binding, job)
		wanted[token] = struct{}{}
		calendar, calendarErr := renderCalendar(job.Schedule.String())
		if calendarErr != nil {
			return CronApplyReceipt{}, calendarErr
		}
		service := fmt.Sprintf("[Unit]\nDescription=CyberPanel site cron %s\n\n[Service]\nType=oneshot\nExecStart=/usr/local/libexec/cyberpanel/panel-cron-exec --manifest %s --job %s\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nReadWritePaths=/var/lib/cyberpanel/sites /var/lib/cyberpanel/access-cron\n", job.ID, systemdEscapeArgument(manifestPath), systemdEscapeArgument(string(job.ID)))
		timer := "[Unit]\nDescription=CyberPanel site cron timer " + string(job.ID) + "\n\n[Timer]\nAccuracySec=1s\nPersistent=true\n"
		if calendar == "boot" {
			timer += "OnBootSec=1min\n"
		} else {
			timer += "OnCalendar=" + calendar + " " + job.Timezone + "\n"
		}
		timer += "Unit=" + token + ".service\n\n[Install]\nWantedBy=timers.target\n"
		if err = atomicRootFile("/etc/systemd/system/"+token+".service", []byte(service), 0644); err != nil {
			return CronApplyReceipt{}, err
		}
		if err = atomicRootFile("/etc/systemd/system/"+token+".timer", []byte(timer), 0644); err != nil {
			return CronApplyReceipt{}, err
		}
	}
	entries, _ := os.ReadDir("/etc/systemd/system")
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "cyberpanel-cron-"+binding.SiteKey+"-") && (strings.HasSuffix(entry.Name(), ".service") || strings.HasSuffix(entry.Name(), ".timer")) {
			token := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), ".service"), ".timer")
			if _, ok := wanted[token]; !ok {
				if strings.HasSuffix(entry.Name(), ".timer") {
					if _, err := runFixedAccess(ctx, "/usr/bin/systemctl", nil, "disable", "--now", token+".timer"); err != nil {
						return CronApplyReceipt{}, err
					}
					if _, err := runFixedAccess(ctx, "/usr/bin/systemctl", nil, "stop", token+".service"); err != nil {
						return CronApplyReceipt{}, err
					}
				}
			}
		}
	}
	// Stop while both unit files still exist; directory order normally lists
	// the service before its timer, and an idle service may not be loaded yet.
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "cyberpanel-cron-"+binding.SiteKey+"-") && (strings.HasSuffix(entry.Name(), ".service") || strings.HasSuffix(entry.Name(), ".timer")) {
			token := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), ".service"), ".timer")
			if _, ok := wanted[token]; !ok {
				if err := os.Remove("/etc/systemd/system/" + entry.Name()); err != nil {
					return CronApplyReceipt{}, err
				}
			}
		}
	}
	if _, err = runFixedAccess(ctx, "/usr/bin/systemctl", nil, "daemon-reload"); err != nil {
		return CronApplyReceipt{}, err
	}
	for token := range wanted {
		if _, err = runFixedAccess(ctx, "/usr/bin/systemctl", nil, "enable", "--now", token+".timer"); err != nil && !strings.Contains(err.Error(), "not meant to be enabled") {
			return CronApplyReceipt{}, err
		}
	}
	now := time.Now().UTC()
	return CronApplyReceipt{SiteID: site, Generation: generation, Digest: manifest.Digest, Receipt: accessReceipt("cron", string(site), strconv.FormatUint(generation, 10), manifest.Digest), AppliedAt: now}, nil
}
func (executor *LinuxCronExecutor) RunNow(ctx context.Context, job CronJob) (CronRun, error) {
	if err := job.Validate(); err != nil {
		return CronRun{}, err
	}
	binding, err := executor.Files.Resolver.ResolveAccessSite(ctx, job.SiteID)
	if err != nil {
		return CronRun{}, err
	}
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		return CronRun{}, err
	}
	run := CronRun{JobID: job.ID, RunID: "cron-" + hex.EncodeToString(random[:]), State: "running", StartedAt: time.Now().UTC()}
	exitCode, outputRef, err := executor.run(ctx, binding, job, run.RunID)
	run.FinishedAt = time.Now().UTC()
	run.ExitCode = exitCode
	run.OutputRef = outputRef
	if err != nil {
		run.State = "failed"
		return run, err
	}
	run.State = "succeeded"
	return run, nil
}
func (executor *LinuxCronExecutor) CancelRun(ctx context.Context, run CronRun) error {
	if !validID(run.RunID) {
		return ErrInvalidID
	}
	executor.mu.Lock()
	command := executor.runs[run.RunID]
	executor.mu.Unlock()
	if command == nil || command.Process == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return command.Process.Kill()
}
func (executor *LinuxCronExecutor) run(ctx context.Context, binding LinuxSiteBinding, job CronJob, runID string) (int, string, error) {
	if job.Invocation.Kind == InvocationHTTP {
		return executor.runHTTP(ctx, job, runID)
	}
	program := job.Invocation.Program
	binary := ""
	args := []string{}
	root := LinuxAccessSitesRoot + "/" + binding.SiteKey + "/roots/g" + strconv.FormatUint(binding.Generation, 10) + "/releases/current"
	entry := root
	if !program.Entrypoint.IsRoot() {
		entry += "/" + program.Entrypoint.String()
	}
	switch program.Program {
	case ProgramPHP:
		binary = "/usr/local/lsws/lsphp83/bin/php"
		args = append(args, entry)
	case ProgramWPCLI:
		binary = "/usr/local/bin/wp"
	case ProgramComposer:
		binary = "/usr/local/bin/composer"
	case ProgramNode:
		binary = "/usr/bin/node"
		args = append(args, entry)
	case ProgramPython:
		binary = "/usr/bin/python3"
		args = append(args, entry)
	case ProgramSiteBinary:
		binary = entry
	default:
		return -1, "", ErrInvalidState
	}
	args = append(args, program.Arguments...)
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = root
	environment := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + root, "LANG=C"}
	for key, value := range program.Environment {
		environment = append(environment, key+"="+value)
	}
	command.Env = environment
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: binding.UID, Gid: binding.GID, NoSetGroups: true}}
	executor.trackRun(runID, command)
	output, err := command.CombinedOutput()
	executor.untrackRun(runID, command)
	if len(output) > 1<<20 {
		output = output[:1<<20]
	}
	outputRef := ""
	if job.Output != OutputDiscard {
		if ensureErr := ensureAccessDirectory(linuxCronStateRoot+"/runs", 0700, 0, 0); ensureErr == nil {
			path := linuxCronStateRoot + "/runs/" + runID + ".log"
			if atomicRootFile(path, output, 0600) == nil {
				outputRef = path
			}
		}
	}
	exitCode := 0
	if err != nil {
		exitCode = -1
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		}
	}
	return exitCode, outputRef, err
}
func (executor *LinuxCronExecutor) runHTTP(ctx context.Context, job CronJob, runID string) (int, string, error) {
	invocation := job.Invocation.HTTP
	arguments := []string{"--silent", "--show-error", "--location", "--max-time", strconv.Itoa(int(job.TimeoutSeconds)), "--request", invocation.Method}
	for name, value := range invocation.Headers {
		arguments = append(arguments, "--header", name+": "+value)
	}
	var body []byte
	if invocation.BodySecretRef != "" {
		if executor.Secrets == nil {
			return -1, "", ErrInvalidState
		}
		material, err := executor.Secrets.Read(ctx, invocation.BodySecretRef, secrets.PurposeAuthentication, secrets.OperationRead, string(job.ID))
		if err != nil {
			return -1, "", err
		}
		body = material
		defer wipeAccess(body)
		arguments = append(arguments, "--data-binary", "@-")
	}
	arguments = append(arguments, "--write-out", "\n%{http_code}", "--", invocation.URL)
	command := exec.CommandContext(ctx, "/usr/bin/curl", arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.Stdin = bytes.NewReader(body)
	executor.trackRun(runID, command)
	output, err := command.CombinedOutput()
	executor.untrackRun(runID, command)
	if err == nil {
		separator := bytes.LastIndexByte(output, '\n')
		if separator < 0 {
			err = ErrIntegrity
		} else {
			status, parseErr := strconv.Atoi(strings.TrimSpace(string(output[separator+1:])))
			if parseErr != nil {
				err = ErrIntegrity
			} else if !expectedHTTPStatus(status, invocation.ExpectedStatuses) {
				err = fmt.Errorf("unexpected HTTP status %d", status)
			}
		}
	}
	if len(output) > 1<<20 {
		output = output[:1<<20]
	}
	outputRef := ""
	if job.Output != OutputDiscard {
		_ = ensureAccessDirectory(linuxCronStateRoot+"/runs", 0700, 0, 0)
		path := linuxCronStateRoot + "/runs/" + runID + ".log"
		if atomicRootFile(path, output, 0600) == nil {
			outputRef = path
		}
	}
	exitCode := 0
	if err != nil {
		exitCode = -1
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		}
	}
	return exitCode, outputRef, err
}
func expectedHTTPStatus(status int, expected []int) bool {
	if len(expected) == 0 {
		return status >= 200 && status < 400
	}
	for _, value := range expected {
		if status == value {
			return true
		}
	}
	return false
}
func (executor *LinuxCronExecutor) trackRun(id string, command *exec.Cmd) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.runs == nil {
		executor.runs = map[string]*exec.Cmd{}
	}
	executor.runs[id] = command
}
func (executor *LinuxCronExecutor) untrackRun(id string, command *exec.Cmd) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.runs[id] == command {
		delete(executor.runs, id)
	}
}

var _ CronExecutor = (*LinuxCronExecutor)(nil)

func RunLinuxCronManifestJob(ctx context.Context, manifestPath string, jobID CronJobID) error {
	if !strings.HasPrefix(manifestPath, linuxCronStateRoot+"/") || strings.Contains(strings.TrimPrefix(manifestPath, linuxCronStateRoot+"/"), "/") {
		return ErrInvalidPath
	}
	info, err := os.Lstat(manifestPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return ErrIntegrity
	}
	content, err := os.ReadFile(manifestPath)
	if err != nil || len(content) == 0 || len(content) > 16<<20 {
		return ErrIntegrity
	}
	var manifest linuxCronManifest
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil {
		return ErrIntegrity
	}
	canonical, _ := json.Marshal(manifest.Jobs)
	digest := sha256.Sum256(canonical)
	if manifest.Digest != hex.EncodeToString(digest[:]) || !validLinuxBinding(manifest.Binding) {
		return ErrIntegrity
	}
	for _, job := range manifest.Jobs {
		if job.ID == jobID {
			if !job.Enabled || job.SiteID != manifest.SiteID {
				return ErrInvalidState
			}
			client, clientErr := NewLocalAccessClient()
			if clientErr != nil {
				return clientErr
			}
			_, clientErr = client.RunNow(ctx, job)
			return clientErr
		}
	}
	return ErrNotFound
}
