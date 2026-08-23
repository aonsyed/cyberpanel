//go:build linux

package operations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const DefaultOperationsStateRoot = "/var/lib/cyberpanel/operations"

type FixedCommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type LinuxFixedCommandRunner struct{}

func (LinuxFixedCommandRunner) Run(ctx context.Context, binary string, arguments ...string) ([]byte, error) {
	if !allowedOperationsBinary(binary) { return nil, ErrInvalidEffect }
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	if len(output) > 4<<20 { output = output[:4<<20]; if err == nil { err = errors.New("command output limit exceeded") } }
	return output, err
}

func allowedOperationsBinary(binary string) bool {
	switch binary {
	case "/usr/bin/systemctl", "/usr/bin/journalctl", "/usr/bin/loginctl", "/usr/bin/ss", "/usr/bin/findmnt", "/usr/bin/stat", "/usr/bin/chattr",
		"/usr/sbin/nft", "/usr/bin/firewall-cmd", "/usr/sbin/sshd", "/usr/sbin/xfs_quota", "/usr/sbin/setquota", "/usr/sbin/quotacheck",
		"/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/rpm", "/usr/bin/dpkg-query", "/usr/bin/redis-cli", "/usr/bin/curl",
		"/usr/local/lsws/bin/openlitespeed", "/usr/local/lsws/bin/lshttpd", "/usr/local/lsws/bin/lswsctrl":
		return true
	default:
		return false
	}
}

type OperationsVolume struct {
	MountPath string
	QuotaBackend string
}

type OperationsPackage struct {
	APTName string
	DNFName string
}

type LinuxOperationsConfig struct {
	StateRoot string
	Volumes map[string]OperationsVolume
	Packages map[string]OperationsPackage
	WAFPacks map[string]string
	Secrets LinuxManagedServiceSecretSource
	Runner FixedCommandRunner
	Clock Clock
}

func DefaultLinuxOperationsConfig() LinuxOperationsConfig {
	return LinuxOperationsConfig{
		StateRoot: DefaultOperationsStateRoot,
		Volumes: map[string]OperationsVolume{
			"hosting": {MountPath: "/home", QuotaBackend: "auto"},
			"cyberpanel": {MountPath: "/var/lib/cyberpanel", QuotaBackend: "auto"},
		},
		Packages: map[string]OperationsPackage{
			"openlitespeed": {APTName: "openlitespeed", DNFName: "openlitespeed"},
			"litespeed": {APTName: "litespeed", DNFName: "litespeed"},
			"mariadb-server": {APTName: "mariadb-server", DNFName: "mariadb-server"},
			"postfix": {APTName: "postfix", DNFName: "postfix"},
			"dovecot": {APTName: "dovecot-core", DNFName: "dovecot"},
			"powerdns": {APTName: "pdns-server", DNFName: "pdns"},
			"pureftpd": {APTName: "pure-ftpd", DNFName: "pure-ftpd"},
			"redis": {APTName: "redis-server", DNFName: "redis"},
			"elasticsearch": {APTName: "elasticsearch", DNFName: "elasticsearch"},
			"modsecurity-crs": {APTName: "modsecurity-crs", DNFName: "mod_security_crs"},
		},
		WAFPacks: map[string]string{
			"owasp:crs": "/usr/share/modsecurity-crs/owasp-crs.load",
		},
		Runner: LinuxFixedCommandRunner{}, Clock: SystemClock{},
	}
}

type LinuxOperationsExecutor struct {
	stateRoot string
	volumes map[string]OperationsVolume
	packages map[string]OperationsPackage
	wafPacks map[string]string
	secrets LinuxManagedServiceSecretSource
	runner FixedCommandRunner
	clock Clock
	mu sync.Mutex
}

type operationsJournalRecord struct {
	Request EffectRequest `json:"request"`
	Receipt EffectReceipt `json:"receipt"`
	Snapshots []operationsFileSnapshot `json:"snapshots,omitempty"`
	CompensationToken SecretRef `json:"compensation_token,omitempty"`
	Compensation *CompensationReceipt `json:"compensation,omitempty"`
}

type operationsFileSnapshot struct {
	Path string `json:"path"`
	Existed bool `json:"existed"`
	Mode uint32 `json:"mode,omitempty"`
	UID int `json:"uid,omitempty"`
	GID int `json:"gid,omitempty"`
	Content []byte `json:"content,omitempty"`
}

type linuxEffectResult struct {
	Result EffectResult
	Activation *ActivationEvidence
	Snapshots []operationsFileSnapshot
	MutationObserved bool
}

func NewLinuxOperationsExecutor(config LinuxOperationsConfig) (*LinuxOperationsExecutor, error) {
	if os.Geteuid() != 0 { return nil, ErrUnauthorized }
	if config.StateRoot == "" { config.StateRoot = DefaultOperationsStateRoot }
	if config.StateRoot != DefaultOperationsStateRoot { return nil, ErrInvalidResource }
	if config.Runner == nil { config.Runner = LinuxFixedCommandRunner{} }
	if config.Clock == nil { config.Clock = SystemClock{} }
	if len(config.Volumes) == 0 || len(config.Packages) == 0 { return nil, ErrInvalidResource }
	if err := ensureOperationsStateRoot(config.StateRoot); err != nil { return nil, err }
	return &LinuxOperationsExecutor{stateRoot: config.StateRoot, volumes: cloneVolumes(config.Volumes), packages: clonePackages(config.Packages), wafPacks: cloneStrings(config.WAFPacks), secrets:config.Secrets, runner: config.Runner, clock: config.Clock}, nil
}

func ensureOperationsStateRoot(root string) error {
	for _, directory := range []string{
		root,
		filepath.Join(root, "effects"),
		filepath.Join(root, "generations"),
		filepath.Join(root, "runtime"),
		filepath.Join(root, "security"),
		filepath.Join(root, "security", "leases"),
		filepath.Join(root, "security", "firewall"),
		filepath.Join(root, "security", "firewall", "generations"),
		filepath.Join(root, "security", "ssh"),
		filepath.Join(root, "security", "ssh", "generations"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil { return err }
		info, err := os.Lstat(directory); if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 { return errors.New("unsafe operations state directory") }
		if err = os.Chown(directory, 0, 0); err != nil { return err }
	}
	return nil
}

func cloneVolumes(source map[string]OperationsVolume) map[string]OperationsVolume { result := make(map[string]OperationsVolume, len(source)); for key, value := range source { result[key] = value }; return result }
func clonePackages(source map[string]OperationsPackage) map[string]OperationsPackage { result := make(map[string]OperationsPackage, len(source)); for key, value := range source { result[key] = value }; return result }
func cloneStrings(source map[string]string) map[string]string { result := make(map[string]string, len(source)); for key, value := range source { result[key] = value }; return result }

func (executor *LinuxOperationsExecutor) ObserveOrApply(ctx context.Context, request EffectRequest) (EffectReceipt, error) {
	if ctx == nil || validateEffectRequest(request) != nil { return EffectReceipt{}, ErrInvalidEffect }
	executor.mu.Lock(); defer executor.mu.Unlock()
	if record, found, err := executor.loadJournal(request.EffectID); err != nil { return EffectReceipt{}, err } else if found {
		if record.Request.RequestDigest != request.RequestDigest { return EffectReceipt{}, ErrIdempotency }
		return record.Receipt, receiptError(record.Receipt)
	}
	completedAt := executor.clock.Now().UTC()
	result, effectErr := executor.apply(ctx, request)
	receipt := EffectReceipt{EffectID: request.EffectID, RequestDigest: request.RequestDigest, CompletedAt: completedAt, Result: result.Result, Activation: result.Activation}
	var token SecretRef
	var retainedSnapshots []operationsFileSnapshot
	if effectErr == nil {
		receipt.Outcome = EffectConfirmed; receipt.MutationObserved = effectIsMutation(request.Kind); receipt.ProofDigest = effectProof(request, result)
		if request.Kind == EffectProcessInvestigate && request.ProcessInvestigate != nil { if err := executor.storeProcessProof(receipt.ProofDigest, request.ProcessInvestigate.Process); err != nil { return EffectReceipt{}, err } }
		if request.Kind == EffectServiceDiagnose && request.ServiceDiagnose != nil { if err := executor.storeDiagnosticProof(receipt.ProofDigest, request.ServiceDiagnose.Service); err != nil { return EffectReceipt{}, err } }
	} else {
		receipt.Outcome = EffectRejected; receipt.FailureCode = stableFailureCode(effectErr)
		if result.MutationObserved {
			restoreErr := executor.restoreSnapshots(result.Snapshots)
			externalErr := executor.rollbackExternal(ctx, request, result.Snapshots)
			if restoreErr != nil || externalErr != nil {
				var tokenErr error;token,tokenErr = newCompensationToken();if tokenErr!=nil{return EffectReceipt{},tokenErr}; receipt.MutationObserved = true; receipt.CompensationToken = token
				if restoreErr != nil || request.Kind==EffectResourceProfile || request.Kind==EffectServicePolicy { retainedSnapshots=result.Snapshots }
				receipt.Outcome = EffectAmbiguous
				receipt.FailureCode = "rollback_ambiguous"
			}
		}
		if errors.Is(effectErr, ErrCompensationFailed) {
			receipt.Outcome = EffectAmbiguous
			receipt.MutationObserved = result.MutationObserved
			if receipt.FailureCode == "" || receipt.FailureCode == "host_operation_failed" { receipt.FailureCode = "security_state_ambiguous" }
		}
	}
	if receipt.Outcome == EffectAmbiguous { receipt.ProofDigest = effectProof(request, result) }
	record := operationsJournalRecord{Request: request, Receipt: receipt, Snapshots: retainedSnapshots, CompensationToken: token}
	if err := executor.storeJournal(record); err != nil { return EffectReceipt{}, err }
	return receipt, effectErr
}

func receiptError(receipt EffectReceipt) error {
	switch receipt.Outcome { case EffectConfirmed: return nil; case EffectRejected: return fmt.Errorf("operations effect rejected: %s", receipt.FailureCode); default: return ErrCompensationFailed }
}

func (executor *LinuxOperationsExecutor) Compensate(ctx context.Context, request CompensationRequest) (CompensationReceipt, error) {
	if ctx == nil || validateCompensationRequest(request) != nil { return CompensationReceipt{}, ErrInvalidEffect }
	executor.mu.Lock(); defer executor.mu.Unlock()
	record, found, err := executor.loadJournal(request.EffectID); if err != nil { return CompensationReceipt{}, err }
	if !found || record.Request.RequestDigest != request.RequestDigest || record.CompensationToken != request.CompensationToken { return CompensationReceipt{}, ErrIdempotency }
	if record.Compensation != nil { return *record.Compensation, receiptErrorForCompensation(*record.Compensation) }
	receipt := CompensationReceipt{EffectID: request.EffectID, RequestDigest: request.RequestDigest, CompensationToken: request.CompensationToken, CompletedAt: executor.clock.Now().UTC()}
	if err = executor.restoreSnapshots(record.Snapshots); err == nil { err = executor.rollbackExternal(ctx, record.Request, record.Snapshots) }
	if err != nil { receipt.Outcome = EffectAmbiguous; receipt.FailureCode = "restore_ambiguous" } else { receipt.Outcome = EffectConfirmed; receipt.ProofDigest = snapshotProof(record.Snapshots) }
	record.Compensation = &receipt
	if storeErr := executor.storeJournal(record); storeErr != nil { return CompensationReceipt{}, storeErr }
	return receipt, receiptErrorForCompensation(receipt)
}

func receiptErrorForCompensation(receipt CompensationReceipt) error { if receipt.Outcome == EffectConfirmed { return nil }; return ErrCompensationFailed }

func (executor *LinuxOperationsExecutor) apply(ctx context.Context, request EffectRequest) (linuxEffectResult, error) {
	switch request.Kind {
	case EffectResourceProfile: return executor.applyResourceProfile(ctx, *request.ResourceProfile)
	case EffectTransferReset: return executor.resetTransfer(*request.TransferReset)
	case EffectTransferSample: return executor.sampleTransfer(*request.TransferSample)
	case EffectFirewallPolicy: return executor.applyFirewall(ctx, request, *request.FirewallPolicy)
	case EffectSSHPolicy: return executor.applySSHPolicy(ctx, request, *request.SSHPolicy)
	case EffectPutSSHKey: return executor.putSSHKey(*request.PutSSHKey)
	case EffectDeleteSSHKey: return executor.deleteSSHKey(*request.DeleteSSHKey)
	case EffectWAFPolicy: return executor.applyWAF(ctx, *request.WAFPolicy)
	case EffectServicePolicy: return executor.applyServicePolicy(ctx, *request.ServicePolicy)
	case EffectServiceControl: return executor.controlService(ctx, *request.ServiceControl)
	case EffectServiceDiagnose: return executor.diagnoseService(ctx, *request.ServiceDiagnose)
	case EffectServiceRepair: return executor.repairService(ctx, *request.ServiceRepair)
	case EffectMetricsQuery: return executor.queryMetrics(ctx, *request.MetricsQuery)
	case EffectLogQuery: return executor.queryLogs(ctx, *request.LogQuery)
	case EffectSSHLoginQuery: return executor.querySSHLogins(ctx, *request.SSHLoginQuery)
	case EffectSSHSessionQuery: return executor.querySSHSessions(ctx, *request.SSHSessionQuery)
	case EffectProcessInvestigate: return executor.investigateProcess(ctx, *request.ProcessInvestigate)
	case EffectProcessTerminate: return executor.terminateProcess(ctx, *request.ProcessTerminate)
	case EffectPackageTransaction: return executor.applyPackageTransaction(ctx, *request.PackageTransaction)
	case EffectManagedService: return executor.applyManagedService(ctx, *request.ManagedService)
	default: return linuxEffectResult{}, ErrInvalidEffect
	}
}

func (executor *LinuxOperationsExecutor) journalPath(effectID string) (string, error) {
	if !strings.HasPrefix(effectID, "hostfx-") || len(effectID) != len("hostfx-")+64 || strings.Trim(effectID[len("hostfx-"):], "0123456789abcdef") != "" { return "", ErrInvalidEffect }
	return filepath.Join(executor.stateRoot, "effects", effectID+".json"), nil
}

func (executor *LinuxOperationsExecutor) loadJournal(effectID string) (operationsJournalRecord, bool, error) {
	path, err := executor.journalPath(effectID); if err != nil { return operationsJournalRecord{}, false, err }
	content, err := os.ReadFile(path); if errors.Is(err, os.ErrNotExist) { return operationsJournalRecord{}, false, nil }; if err != nil { return operationsJournalRecord{}, false, err }
	var record operationsJournalRecord
	decoder := json.NewDecoder(strings.NewReader(string(content))); decoder.DisallowUnknownFields()
	if err = decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{})!=io.EOF || validateEffectRequest(record.Request) != nil || !effectReceiptMatches(record.Request, record.Receipt) { return operationsJournalRecord{}, false, ErrInvalidReceipt }
	return record, true, nil
}

func (executor *LinuxOperationsExecutor) storeJournal(record operationsJournalRecord) error {
	path, err := executor.journalPath(record.Request.EffectID); if err != nil { return err }
	content, err := json.Marshal(record); if err != nil { return err }
	return atomicOperationsFile(path, content, 0o600)
}

func atomicOperationsFile(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path); temporary, err := os.CreateTemp(directory, ".candidate-"); if err != nil { return err }
	temporaryPath := temporary.Name(); defer os.Remove(temporaryPath)
	if err = temporary.Chmod(mode); err == nil { _, err = temporary.Write(content) }
	if err == nil { err = temporary.Sync() }
	if closeErr := temporary.Close(); err == nil { err = closeErr }; if err != nil { return err }
	if err = os.Rename(temporaryPath, path); err != nil { return err }
	dir, err := os.Open(directory); if err != nil { return err }; defer dir.Close(); return dir.Sync()
}

func (executor *LinuxOperationsExecutor) writeCandidate(kind string, content []byte) (string, error) {
	if kind != "firewall" && kind != "waf" && kind != "ssh" { return "", ErrInvalidEffect }
	file, err := os.CreateTemp(filepath.Join(executor.stateRoot, "runtime"), "."+kind+"-candidate-"); if err != nil { return "", err }
	path := file.Name()
	if err = file.Chmod(0o600); err == nil { _, err = file.Write(content) }
	if err == nil { err = file.Sync() }
	if closeErr := file.Close(); err == nil { err = closeErr }
	if err != nil { _ = os.Remove(path); return "", err }
	return path, nil
}

func (executor *LinuxOperationsExecutor) snapshotFile(path string) (operationsFileSnapshot, error) {
	if !allowedManagedPath(path) { return operationsFileSnapshot{}, ErrInvalidEffect }
	info, err := os.Lstat(path); if errors.Is(err, os.ErrNotExist) { return operationsFileSnapshot{Path: path}, nil }; if err != nil { return operationsFileSnapshot{}, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64<<20 { return operationsFileSnapshot{}, ErrInvalidEffect }
	content, err := os.ReadFile(path); if err != nil { return operationsFileSnapshot{}, err }
	uid, gid := 0, 0
	if stat, ok := info.Sys().(*syscall.Stat_t); ok { uid, gid = int(stat.Uid), int(stat.Gid) }
	return operationsFileSnapshot{Path: path, Existed: true, Mode: uint32(info.Mode().Perm()), UID: uid, GID: gid, Content: content}, nil
}

func (executor *LinuxOperationsExecutor) replaceManagedFile(path string, content []byte, mode os.FileMode) (operationsFileSnapshot, error) {
	snapshot, err := executor.snapshotFile(path); if err != nil { return operationsFileSnapshot{}, err }
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil { return operationsFileSnapshot{}, err }
	if err = atomicOperationsFile(path, content, mode); err != nil { return operationsFileSnapshot{}, err }
	if err = os.Chown(path, 0, 0); err != nil { return operationsFileSnapshot{}, err }
	return snapshot, nil
}

func (executor *LinuxOperationsExecutor) restoreSnapshots(snapshots []operationsFileSnapshot) error {
	var joined error
	for index := len(snapshots)-1; index >= 0; index-- {
		snapshot := snapshots[index]
		if !allowedManagedPath(snapshot.Path) { joined = errors.Join(joined, ErrInvalidEffect); continue }
		if !snapshot.Existed { if err := os.Remove(snapshot.Path); err != nil && !errors.Is(err, os.ErrNotExist) { joined = errors.Join(joined, err) }; continue }
		if err := atomicOperationsFile(snapshot.Path, snapshot.Content, os.FileMode(snapshot.Mode)); err != nil { joined = errors.Join(joined, err); continue }
		if err := os.Chown(snapshot.Path, snapshot.UID, snapshot.GID); err != nil { joined = errors.Join(joined, err) }
	}
	return joined
}

func allowedManagedPath(path string) bool {
	clean := filepath.Clean(path)
	for _, prefix := range []string{"/etc/cyberpanel/", "/etc/firewalld/zones/", "/etc/firewalld/policies/", "/etc/ssh/sshd_config.d/", "/etc/ssh/authorized_keys/", "/etc/redis/", "/etc/elasticsearch/", "/usr/local/lsws/conf/modsec/", DefaultOperationsStateRoot + "/"} {
		if strings.HasPrefix(clean, prefix) && !strings.Contains(clean, "..") { return true }
	}
	return false
}

func effectProof(request EffectRequest, result linuxEffectResult) string { encoded, _ := json.Marshal(struct { Request EffectRequest `json:"request"`; Result EffectResult `json:"result"`; Activation *ActivationEvidence `json:"activation,omitempty"` }{request, result.Result, result.Activation}); digest := sha256.Sum256(append([]byte("cyberpanel:operations:proof:v1\x00"), encoded...)); return hex.EncodeToString(digest[:]) }
func snapshotProof(snapshots []operationsFileSnapshot) string { encoded, _ := json.Marshal(snapshots); digest := sha256.Sum256(append([]byte("cyberpanel:operations:compensation:v1\x00"), encoded...)); return hex.EncodeToString(digest[:]) }
func newCompensationToken() (SecretRef, error) { var entropy [32]byte; if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil { return SecretRef{}, err }; return NewSecretRef("comp-"+hex.EncodeToString(entropy[:])) }
func stableFailureCode(err error) string { switch { case errors.Is(err, context.DeadlineExceeded): return "deadline_exceeded"; case errors.Is(err, ErrInvalidEffect), errors.Is(err, ErrInvalidResource): return "invalid_effect"; case errors.Is(err, os.ErrPermission): return "permission_denied"; default: return "host_operation_failed" } }
