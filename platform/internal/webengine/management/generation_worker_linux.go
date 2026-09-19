//go:build linux

package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation/fsstore"
)

const LinuxLifecycleWorkerMode = "--private-webengine-candidate"
const lifecycleControlPath = "/usr/local/lsws/bin/lswsctrl"

type lifecycleWorkerInput struct {
	Candidate lifecycleGenerationInput `json:"candidate"`
	Mode string `json:"mode"`
	Challenges []lifecycleChallenge `json:"challenges,omitempty"`
	ConversionEffectID string `json:"conversion_effect_id,omitempty"`
	TargetPlan *ArtifactPlan `json:"target_plan,omitempty"`
	PackageAction string `json:"package_action,omitempty"`
}

type lifecycleWorkerResult struct {
	Validation ValidationReceipt `json:"validation"`
	Probe ProbeReceipt `json:"probe"`
	PackageDigest string `json:"package_digest,omitempty"`
}

type lifecycleBoundedOutput struct { bytes.Buffer; maximum int }
func (output *lifecycleBoundedOutput) Write(content []byte) (int, error) {
	if len(content) > output.maximum-output.Len() { return 0, ErrInvalid }
	return output.Buffer.Write(content)
}

func trustedLifecycleProgram(program string) error {
	info, err := os.Lstat(program)
	if err==nil&&info.Mode()&os.ModeSymlink!=0&&(program==lifecycleBinaryPath||program==lifecycleControlPath){
		resolved,resolveErr:=filepath.EvalSymlinks(program)
		if resolveErr!=nil||!strings.HasPrefix(resolved,"/usr/local/lsws/bin"+string(os.PathSeparator))||!rootOwnedFile(info){return ErrInvalid}
		return trustedLifecycleProgram(resolved)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 || !rootOwnedFile(info) { return ErrUnsupported }
	canonical, err := filepath.EvalSymlinks(program)
	if err != nil || canonical != program { return ErrInvalid }
	return nil
}

func runLifecycleCandidate(ctx context.Context, input lifecycleGenerationInput, mode string) (result lifecycleWorkerResult, err error) {
	if ctx == nil || mode != "validate" && mode != "probe" { return result, ErrInvalid }
	if _, err = renderLifecycleGeneration(ctx, input); err != nil { return result, err }
	edition, err := readLifecycleEdition()
	if err != nil || edition != input.Render.Desired.Engine.Edition { return result, ErrUnsupported }
	if err = trustedLifecycleProgram(lifecycleBinaryPath); err != nil { return result, err }
	program, err := os.Executable()
	if err != nil { return result, err }
	// This is the installed privileged broker itself, not a caller-chosen
	// executable, shell fragment, image, namespace path, or service template.
	if err = trustedLifecycleProgram(program); err != nil { return result, err }
	worker := lifecycleWorkerInput{Candidate: input, Mode: mode}
	if mode == "probe" {
		var cleanup func() error
		worker.Challenges, cleanup, err = prepareLifecycleChallenges(input.Render)
		if err != nil { return result, err }
		defer func() { err = errors.Join(err, cleanup()) }()
	}
	return runLifecycleWorker(ctx,worker)
}

func runLifecycleWorker(ctx context.Context,worker lifecycleWorkerInput)(result lifecycleWorkerResult,err error){
	program,err:=os.Executable();if err!=nil{return result,err}
	if err=trustedLifecycleProgram(program);err!=nil{return result,err}
	content, err := json.Marshal(worker)
	if err != nil || len(content) > linuxManagementMaximumFrame { return result, ErrInvalid }
	maximum:=2*time.Minute;if worker.Mode=="packages"{maximum=25*time.Minute}
	ctx, cancel := context.WithTimeout(ctx, maximum)
	defer cancel()
	command := exec.CommandContext(ctx, program, LinuxLifecycleWorkerMode)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	command.Stdin = bytes.NewReader(content)
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET|syscall.CLONE_NEWNS|syscall.CLONE_NEWPID, Pdeathsig: syscall.SIGKILL}
	output := &lifecycleBoundedOutput{maximum: 1<<20}
	command.Stdout, command.Stderr = output, io.Discard
	runErr := command.Run()
	if decodeLifecyclePayload(output.Bytes(), &result) != nil { return lifecycleWorkerResult{}, errors.Join(ErrAmbiguous, runErr) }
	if runErr != nil { return result, errors.Join(ErrAmbiguous, runErr) }
	if worker.Mode=="packages"{if !validSHA256(result.PackageDigest){return result,ErrAmbiguous};return result,nil}
	if !result.Validation.Valid || result.Validation.ConfigDigest != worker.Candidate.ConfigDigest || worker.Mode == "probe" && (result.Probe.ConfigDigest != worker.Candidate.ConfigDigest || !result.Probe.PHP || !validSHA256(result.Probe.EvidenceDigest)) { return result, ErrAmbiguous }
	return result, nil
}

// RunLinuxLifecycleWorker is a fixed broker re-exec entrypoint. It refuses a
// host-namespace invocation before mounting or starting any engine process.
func RunLinuxLifecycleWorker() (err error) {
	if os.Geteuid() != 0 { return ErrInvalid }
	for _, kind := range []string{"net", "mnt", "pid"} {
		self, selfErr := os.Readlink("/proc/self/ns/"+kind)
		init, initErr := os.Readlink("/proc/1/ns/"+kind)
		if selfErr != nil || initErr != nil || self == init { return ErrInvalid }
	}
	content, err := io.ReadAll(io.LimitReader(os.Stdin, linuxManagementMaximumFrame+1))
	if err != nil || len(content) > linuxManagementMaximumFrame { return ErrInvalid }
	var input lifecycleWorkerInput
	if decodeLifecyclePayload(content, &input) != nil || input.Mode != "validate" && input.Mode != "probe" && input.Mode!="packages" { return ErrInvalid }
	maximum:=110*time.Second;if input.Mode=="packages"{maximum=24*time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), maximum)
	defer cancel()
	if input.Mode=="packages"{
		result,packageErr:=executeConversionPackages(ctx,input)
		encoded,encodeErr:=json.Marshal(result);if encodeErr==nil{_,encodeErr=os.Stdout.Write(encoded)}
		return errors.Join(packageErr,encodeErr)
	}
	generation, err := renderLifecycleGeneration(ctx, input.Candidate)
	if err != nil { return err }
	edition:=generation.Edition
	var store *fsstore.Store
	if input.TargetPlan!=nil{
		record,authorityErr:=conversionAuthority(input.ConversionEffectID)
		if authorityErr!=nil||record.Phase!=conversionPhasePreflight||digestJSON(*input.TargetPlan)!=digestJSON(record.Input.Plan)||generation.ContentDigest!=record.Input.Generation.ContentDigest{return ErrConflict}
		imageRoot:=filepath.Join(conversionDirectory(input.ConversionEffectID),"image")
		digest,digestErr:=conversionImageDigest(ctx,imageRoot);if digestErr!=nil||digest!=record.ImageDigest{return ErrConflict}
		engineRoot:=filepath.Join(imageRoot,"usr/local/lsws")
		if err=syscall.Mount("","/","",syscall.MS_REC|syscall.MS_PRIVATE,"");err!=nil{return err}
		if err=syscall.Mount(engineRoot,"/usr/local/lsws","",syscall.MS_BIND|syscall.MS_REC,"");err!=nil{return err}
		store,err=fsstore.New(filepath.Join(engineRoot,"conf"),edition)
	}else{
		installed,editionErr:=readLifecycleEdition();if editionErr!=nil||installed!=edition{return ErrUnsupported}
		store,err=openLifecycleStore(edition)
	}
	if err != nil { return err }
	master, err := store.GenerationPath(ctx, activation.Receipt{Edition: generation.Edition, Digest: generation.ContentDigest})
	closeErr := store.Close()
	if err != nil || closeErr != nil { return errors.Join(err, closeErr) }
	if err = isolateLifecycleFiles(master, edition); err != nil { return err }
	if len(input.Candidate.PrivateTLS) != 0 {
		if err = validatePrivateTLSMaterials(input.Candidate.Render, input.Candidate.PrivateTLS, time.Now().UTC()); err != nil { return err }
		if err = mountPrivateTLSMaterials(input.Candidate.PrivateTLS); err != nil { return err }
	}
	var result lifecycleWorkerResult
	defer func() {
		encoded, encodeErr := json.Marshal(result)
		if encodeErr == nil { _, encodeErr = os.Stdout.Write(encoded) }
		err = errors.Join(err, encodeErr)
	}()
	parser, err := fixedLifecycleWorkerCommand(ctx, lifecycleBinaryPath, "-t")
	if err != nil { return err }
	result.Validation = ValidationReceipt{EffectID: input.Candidate.Request.EffectID, ConfigDigest: generation.ContentDigest, ParserDigest: linuxManagementDigest(parser), SemanticDigest: generation.DesiredDigest, Valid: true, ObservedAt: time.Now().UTC()}
	if input.Mode == "validate" { return nil }
	if _, err = fixedLifecycleWorkerCommand(ctx, "/usr/sbin/ip", "link", "set", "dev", "lo", "up"); err != nil { return err }
	if _, err = fixedLifecycleWorkerCommand(ctx, lifecycleControlPath, "start"); err != nil { return err }
	defer func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_, stopErr := fixedLifecycleWorkerCommand(stopCtx, lifecycleControlPath, "stop")
		err = errors.Join(err, stopErr)
	}()
	// lswsctrl may return before the private listener is ready. Only retry
	// connection startup, with a bounded deadline; never invent success.
	for attempt := 0; attempt < 20; attempt++ {
		result.Probe, err = executeLifecycleProbes(ctx, input.Candidate, input.Challenges)
		if err == nil {
			result.Probe.ConfigValid = result.Validation.Valid
			result.Probe.ParserDigest = result.Validation.ParserDigest
			result.Probe.SemanticDigest = result.Validation.SemanticDigest
			return nil
		}
		var networkErr net.Error
		if !errors.As(err, &networkErr) { return err }
		select { case <-ctx.Done(): return ctx.Err(); case <-time.After(250*time.Millisecond): }
	}
	return err
}

func fixedLifecycleWorkerCommand(ctx context.Context, program string, arguments ...string) ([]byte, error) {
	allowed := program == lifecycleBinaryPath && len(arguments) == 1 && arguments[0] == "-t" || program == lifecycleControlPath && len(arguments) == 1 && (arguments[0] == "start" || arguments[0] == "stop") || program == "/usr/sbin/ip" && len(arguments) == 5 && arguments[0] == "link" && arguments[1] == "set" && arguments[2] == "dev" && arguments[3] == "lo" && arguments[4] == "up"
	if !allowed { return nil, ErrInvalid }
	if err := trustedLifecycleProgram(program); err != nil { return nil, err }
	command := exec.CommandContext(ctx, program, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	output := &lifecycleBoundedOutput{maximum: 1<<20}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	return output.Bytes(), err
}

func isolateLifecycleFiles(candidate string, edition webengine.Edition) error {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil { return err }
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil { return err }
	// New PID namespace init exiting kills every candidate descendant. Private
	// /tmp, /run, log directories and shared memory prevent host PID/socket/log
	// contamination. Only already-managed external LSAPI sockets are preserved.
	if err := lifecycleTmpfs("/tmp", "mode=1777,size=64m"); err != nil { return err }
	if err := os.Mkdir("/tmp/site-runtime", 0o700); err != nil { return err }
	if err := syscall.Mount("/run/cyberpanel/site-runtime", "/tmp/site-runtime", "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil { return err }
	if err := syscall.Mount("", "/tmp/site-runtime", "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil { return err }
	if err := lifecycleTmpfs("/run", "mode=0755,size=16m"); err != nil { return err }
	if err := os.MkdirAll("/run/cyberpanel/site-runtime", 0o755); err != nil { return err }
	if err := syscall.Mount("/tmp/site-runtime", "/run/cyberpanel/site-runtime", "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil { return err }
	for _, directory := range []string{"/usr/local/lsws/logs", "/usr/local/lsws/admin/logs", "/usr/local/lsws/admin/tmp", "/dev/shm"} {
		if err := lifecycleTmpfs(directory, "mode=0770,size=32m"); err != nil { return err }
	}
	master := filepath.Join(lifecycleConfigurationRoot, "httpd_config.conf")
	if edition == webengine.EditionLiteSpeedEnterprise { master = filepath.Join(lifecycleConfigurationRoot, "httpd_config.xml") }
	if err := syscall.Mount(lifecycleConfigurationRoot, lifecycleConfigurationRoot, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil { return err }
	if err := syscall.Mount(candidate, master, "", syscall.MS_BIND, ""); err != nil { return err }
	if err := syscall.Mount("", master, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil { return err }
	return syscall.Mount("", lifecycleConfigurationRoot, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, "")
}

func lifecycleTmpfs(directory, options string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return ErrInvalid }
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory { return ErrInvalid }
	if err := syscall.Mount("tmpfs", directory, "tmpfs", syscall.MS_NODEV|syscall.MS_NOSUID, options); err != nil { return err }
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok { return ErrInvalid }
	if err := os.Chown(directory, int(metadata.Uid), int(metadata.Gid)); err != nil { return err }
	return os.Chmod(directory, info.Mode().Perm() | (info.Mode() & os.ModeSticky))
}
