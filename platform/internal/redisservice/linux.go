//go:build linux

package redisservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	redisServerPath   = "/usr/bin/redis-server"
	redisCheckRDBPath = "/usr/bin/redis-check-rdb"
	redisCheckAOFPath = "/usr/bin/redis-check-aof"
	systemctlPath     = "/usr/bin/systemctl"
	maxCommandOutput  = 32 << 10
	maxCommandTime    = 30 * time.Second
	maxProbeTime      = 5 * time.Second
	maxRESPBytes      = 256 << 10
	maxRESPLine       = 4096
	maxAOFFiles       = 128
	maxExecutionTime  = 15 * time.Minute
)

type RuntimeOwnership struct {
	UID int
	GID int
}

type OwnershipResolver interface {
	RedisOwnership(context.Context) (RuntimeOwnership, error)
}

type TLSMaterial struct {
	Roots       *x509.CertPool
	Certificate tls.Certificate
}

type TLSMaterialProvider interface {
	ClientMaterial(context.Context, string, string) (TLSMaterial, error)
}

type ArtifactWriteRequest struct {
	ID               string
	GroupID          string
	InstanceID       InstanceID
	Kind             ArtifactKind
	RedisVersion     string
	ConfigGeneration uint64
	MaxBytes         int64
}

type ArtifactStore interface {
	Put(context.Context, ArtifactWriteRequest, io.Reader) (ArtifactDescriptor, error)
	Open(context.Context, string) (ArtifactDescriptor, io.ReadCloser, error)
}

type FixedCommand struct {
	InstanceID InstanceID
	Program    string
	Args       []string
	Timeout    time.Duration
}

type CommandResult struct {
	ExitCode int
	Output   []byte
	TimedOut bool
	Duration time.Duration
}

type CommandRunner interface {
	Run(context.Context, FixedCommand) (CommandResult, error)
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	remaining int
	truncated bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	kept := 0
	if b.remaining > 0 {
		kept = len(value)
		if kept > b.remaining {
			kept = b.remaining
		}
		_, _ = b.buffer.Write(value[:kept])
		b.remaining -= kept
	}
	if kept < original {
		b.truncated = true
	}
	return original, nil
}

type BoundedExecRunner struct{}

func NewBoundedExecRunner() *BoundedExecRunner { return &BoundedExecRunner{} }

func managedUnit(id InstanceID) string {
	return "cyberpanel-redis@" + string(id) + ".service"
}

func isGenerationConfigPath(id InstanceID, path string) bool {
	clean := filepath.Clean(path)
	root := filepath.Clean(instanceConfigDirectory(id) + "/generations")
	relative, err := filepath.Rel(root, clean)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
		return false
	}
	parts := strings.Split(relative, string(os.PathSeparator))
	if len(parts) != 2 || parts[1] != "redis.conf" {
		return false
	}
	generation, err := strconv.ParseUint(parts[0], 10, 64)
	return err == nil && validGeneration(generation)
}

func isRestoreDataPath(id InstanceID, path string) bool {
	clean := filepath.Clean(path)
	root := filepath.Clean(instanceDataDirectory(id) + "/restore")
	relative, err := filepath.Rel(root, clean)
	return err == nil && relative != "." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func allowedCommand(command FixedCommand) bool {
	if !instanceIDPattern.MatchString(string(command.InstanceID)) || command.Timeout <= 0 || command.Timeout > maxCommandTime || command.Program == "" || command.Program[0] != '/' {
		return false
	}
	if command.Program == redisServerPath {
		if len(command.Args) == 1 && command.Args[0] == "--version" {
			return true
		}
		return len(command.Args) == 3 && isGenerationConfigPath(command.InstanceID, command.Args[0]) && command.Args[1] == "--test-memory" && command.Args[2] == "1"
	}
	if command.Program == systemctlPath {
		if len(command.Args) == 1 && command.Args[0] == "daemon-reload" {
			return true
		}
		if len(command.Args) == 2 && command.Args[1] == managedUnit(command.InstanceID) {
			switch command.Args[0] {
			case "start", "stop", "restart", "reload", "enable", "disable":
				return true
			}
		}
		if len(command.Args) == 4 && command.Args[0] == "show" && command.Args[1] == "--no-pager" && command.Args[2] == "--property=LoadState,UnitFileState,ActiveState,SubState,MainPID" && command.Args[3] == managedUnit(command.InstanceID) {
			return true
		}
		return false
	}
	if command.Program == redisCheckRDBPath {
		return len(command.Args) == 1 && isRestoreDataPath(command.InstanceID, command.Args[0]) && (filepath.Base(command.Args[0]) == "dump.rdb" || strings.HasSuffix(filepath.Base(command.Args[0]), ".rdb"))
	}
	if command.Program == redisCheckAOFPath {
		return len(command.Args) == 1 && isRestoreDataPath(command.InstanceID, command.Args[0]) && strings.HasSuffix(filepath.Base(command.Args[0]), ".aof")
	}
	return false
}

func (r *BoundedExecRunner) Run(ctx context.Context, command FixedCommand) (CommandResult, error) {
	if !allowedCommand(command) {
		return CommandResult{}, fmt.Errorf("%w: command is not allowlisted", ErrUnauthorized)
	}
	commandContext, cancel := context.WithTimeout(ctx, command.Timeout)
	defer cancel()
	process := exec.CommandContext(commandContext, command.Program, command.Args...)
	process.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/", "TMPDIR=/tmp"}
	process.Dir = "/"
	output := &boundedBuffer{remaining: maxCommandOutput}
	process.Stdout = output
	process.Stderr = output
	started := time.Now()
	err := process.Run()
	result := CommandResult{ExitCode: 0, Output: append([]byte(nil), output.buffer.Bytes()...), Duration: time.Since(started)}
	if contextErr := commandContext.Err(); contextErr != nil {
		result.ExitCode = -1
		result.TimedOut = contextErr == context.DeadlineExceeded
		return result, contextErr
	}
	if output.truncated {
		return result, fmt.Errorf("%w: command output exceeded bound", ErrAmbiguous)
	}
	if err == nil {
		return result, nil
	}
	if exitError, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	result.ExitCode = -1
	return result, fmt.Errorf("execute fixed Redis command: %w", err)
}

func commandEvidence(command FixedCommand, result CommandResult) (string, string, error) {
	commandDigest, err := digestValue(struct {
		Program string   `json:"program"`
		Args    []string `json:"args"`
	}{command.Program, command.Args})
	if err != nil {
		return "", "", err
	}
	outputDigest, err := digestValue(struct {
		Output []byte `json:"output"`
	}{result.Output})
	return commandDigest, outputDigest, err
}

func ensureDirectory(path string, mode os.FileMode, uid, gid int) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: unsafe managed directory", ErrInvalid)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
		return fmt.Errorf("%w: managed directory ownership", ErrInvalid)
	}
	return nil
}

func ensureRuntimePaths(spec InstanceSpec, owner RuntimeOwnership) error {
	if owner.UID <= 0 || owner.GID <= 0 {
		return fmt.Errorf("%w: Redis runtime must use dedicated non-root ownership", ErrInvalid)
	}
	directories := []struct {
		path string
		mode os.FileMode
		uid  int
		gid  int
	}{
		{"/etc/cyberpanel", 0o750, 0, 0},
		{configRoot, 0o750, 0, 0},
		{instanceConfigDirectory(spec.ID), 0o750, 0, owner.GID},
		{instanceConfigDirectory(spec.ID) + "/generations", 0o750, 0, owner.GID},
		{"/var/lib/cyberpanel", 0o750, 0, 0},
		{dataRoot, 0o750, 0, 0},
		{instanceDataDirectory(spec.ID), 0o700, owner.UID, owner.GID},
		{"/run/cyberpanel", 0o755, 0, 0},
		{runRoot, 0o755, 0, 0},
		{runRoot + "/" + string(spec.ID), 0o750, owner.UID, owner.GID},
	}
	for _, directory := range directories {
		if err := ensureDirectory(directory.path, directory.mode, directory.uid, directory.gid); err != nil {
			return fmt.Errorf("prepare fixed Redis path: %w", err)
		}
	}
	return nil
}

func atomicOwnedFile(path string, data []byte, mode os.FileMode, uid, gid int, token string) error {
	if len(data) == 0 || len(data) > MaxConfigBytes || !validID(token) {
		return fmt.Errorf("%w: staged file input", ErrInvalid)
	}
	if info, err := os.Lstat(path); err == nil {
		stat, statOK := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !statOK || int(stat.Uid) != uid || int(stat.Gid) != gid || info.Mode().Perm() != mode.Perm() {
			return fmt.Errorf("%w: immutable generation file metadata", ErrInvalid)
		}
		existing, readErr := readBoundedFile(path, MaxConfigBytes)
		if readErr == nil && bytes.Equal(existing, data) {
			return nil
		}
		return fmt.Errorf("%w: immutable generation file differs", ErrConflict)
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary := path + ".tmp-" + token
	fd, err := syscall.Open(temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	file := os.NewFile(uintptr(fd), temporary)
	if err := file.Chown(uid, gid); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if err := writeFull(file, data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func atomicReplaceOwnedFile(path string, data []byte, mode os.FileMode, uid, gid int, token string) error {
	if len(data) == 0 || len(data) > MaxConfigBytes || !validID(token) {
		return fmt.Errorf("%w: mutable managed file input", ErrInvalid)
	}
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !ok || int(stat.Uid) != uid || int(stat.Gid) != gid || info.Mode().Perm() != mode.Perm() {
			return fmt.Errorf("%w: mutable managed file metadata", ErrInvalid)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary := path + ".tmp-" + token
	fd, err := syscall.Open(temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer os.Remove(temporary)
	if err := file.Chown(uid, gid); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := writeFull(file, data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, fmt.Errorf("%w: unsafe or oversized managed file", ErrInvalid)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: bounded managed file read", ErrInvalid)
	}
	return data, nil
}

func generationDigest(id InstanceID, generation uint64) (string, error) {
	redisConfig, err := readBoundedFile(redisConfigPath(id, generation), MaxConfigBytes)
	if err != nil {
		return "", err
	}
	aclConfig, err := readBoundedFile(aclConfigPath(id, generation), MaxConfigBytes)
	if err != nil {
		return "", err
	}
	dropIn, err := readBoundedFile(systemdDropInPath(id, generation), MaxConfigBytes)
	if err != nil {
		return "", err
	}
	return digestValue(struct {
		InstanceID       InstanceID `json:"instance_id"`
		ConfigGeneration uint64     `json:"config_generation"`
		RedisConfig      []byte     `json:"redis_config"`
		ACLConfig        []byte     `json:"acl_config"`
		SystemdDropIn    []byte     `json:"systemd_drop_in"`
	}{id, generation, redisConfig, aclConfig, dropIn})
}

func stageGeneration(spec InstanceSpec, rendered RenderedGeneration, owner RuntimeOwnership, token string) error {
	if rendered.InstanceID != spec.ID || rendered.ConfigGeneration != spec.ConfigGeneration {
		return fmt.Errorf("%w: rendered generation binding", ErrInvalid)
	}
	if err := ensureRuntimePaths(spec, owner); err != nil {
		return err
	}
	directory := generationDirectory(spec.ID, spec.ConfigGeneration)
	if err := ensureDirectory(directory, 0o750, 0, owner.GID); err != nil {
		return err
	}
	if err := atomicOwnedFile(redisConfigPath(spec.ID, spec.ConfigGeneration), rendered.RedisConfig, 0o640, 0, owner.GID, token); err != nil {
		return err
	}
	if err := atomicOwnedFile(aclConfigPath(spec.ID, spec.ConfigGeneration), rendered.ACLConfig, 0o640, 0, owner.GID, token); err != nil {
		return err
	}
	if err := atomicOwnedFile(systemdDropInPath(spec.ID, spec.ConfigGeneration), rendered.SystemdDropIn, 0o644, 0, 0, token); err != nil {
		return err
	}
	digest, err := generationDigest(spec.ID, spec.ConfigGeneration)
	if err != nil || digest != rendered.ConfigDigest {
		return fmt.Errorf("%w: staged generation digest", ErrAmbiguous)
	}
	return nil
}

func currentGeneration(id InstanceID) (uint64, error) {
	path := instanceConfigDirectory(id) + "/current"
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return 0, fmt.Errorf("%w: current generation pointer is not a symlink", ErrInvalid)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return 0, err
	}
	parts := strings.Split(target, "/")
	if len(parts) != 2 || parts[0] != "generations" {
		return 0, fmt.Errorf("%w: current generation pointer target", ErrInvalid)
	}
	generation, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || !validGeneration(generation) {
		return 0, fmt.Errorf("%w: current generation pointer value", ErrInvalid)
	}
	return generation, nil
}

func switchGeneration(spec InstanceSpec, owner RuntimeOwnership, token string) (uint64, error) {
	previous, err := currentGeneration(spec.ID)
	if err != nil {
		return 0, err
	}
	if _, err := generationDigest(spec.ID, spec.ConfigGeneration); err != nil {
		return 0, err
	}
	link := instanceConfigDirectory(spec.ID) + "/current"
	temporary := link + ".tmp-" + token
	if err := os.Symlink("generations/"+strconv.FormatUint(spec.ConfigGeneration, 10), temporary); err != nil {
		return 0, err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, link); err != nil {
		return 0, err
	}
	dropInDirectory := "/etc/systemd/system/" + managedUnit(spec.ID) + ".d"
	if err := ensureDirectory(dropInDirectory, 0o755, 0, 0); err != nil {
		return previous, err
	}
	dropIn, err := readBoundedFile(systemdDropInPath(spec.ID, spec.ConfigGeneration), MaxConfigBytes)
	if err != nil {
		return previous, err
	}
	if err := atomicReplaceOwnedFile(dropInDirectory+"/50-managed.conf", dropIn, 0o644, 0, 0, token); err != nil {
		return previous, err
	}
	_ = owner
	return previous, nil
}

func restoreGeneration(id InstanceID, generation uint64, token string) error {
	if !validGeneration(generation) {
		return fmt.Errorf("%w: no prior generation", ErrAmbiguous)
	}
	if _, err := generationDigest(id, generation); err != nil {
		return err
	}
	dropIn, err := readBoundedFile(systemdDropInPath(id, generation), MaxConfigBytes)
	if err != nil {
		return err
	}
	dropInPath := "/etc/systemd/system/" + managedUnit(id) + ".d/50-managed.conf"
	if err := atomicReplaceOwnedFile(dropInPath, dropIn, 0o644, 0, 0, token); err != nil {
		return err
	}
	link := instanceConfigDirectory(id) + "/current"
	temporary := link + ".rollback-" + token
	if err := os.Symlink("generations/"+strconv.FormatUint(generation, 10), temporary); err != nil {
		return err
	}
	defer os.Remove(temporary)
	return os.Rename(temporary, link)
}

type respReader struct {
	reader    *bufio.Reader
	remaining int
}

func newRESPReader(reader io.Reader) *respReader {
	return &respReader{reader: bufio.NewReaderSize(reader, 4096), remaining: maxRESPBytes}
}

func (r *respReader) line() ([]byte, error) {
	line, err := r.reader.ReadBytes('\n')
	r.remaining -= len(line)
	if err != nil || r.remaining < 0 || len(line) > maxRESPLine || len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, fmt.Errorf("%w: malformed bounded RESP line", ErrAmbiguous)
	}
	return line[:len(line)-2], nil
}

func (r *respReader) value() (byte, []byte, error) {
	prefix, err := r.reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	r.remaining--
	line, err := r.line()
	if err != nil {
		return 0, nil, err
	}
	switch prefix {
	case '+', '-', ':':
		return prefix, line, nil
	case '$':
		length, parseErr := strconv.Atoi(string(line))
		if parseErr != nil || length < 0 || length > r.remaining-2 || length > maxRESPBytes {
			return 0, nil, fmt.Errorf("%w: RESP bulk length", ErrAmbiguous)
		}
		data := make([]byte, length+2)
		if _, err := io.ReadFull(r.reader, data); err != nil || data[length] != '\r' || data[length+1] != '\n' {
			return 0, nil, fmt.Errorf("%w: RESP bulk payload", ErrAmbiguous)
		}
		r.remaining -= len(data)
		return prefix, data[:length], nil
	default:
		return 0, nil, fmt.Errorf("%w: unsupported RESP type", ErrAmbiguous)
	}
}

func redisCommand(arguments ...[]byte) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("*" + strconv.Itoa(len(arguments)) + "\r\n")
	for _, argument := range arguments {
		buffer.WriteString("$" + strconv.Itoa(len(argument)) + "\r\n")
		buffer.Write(argument)
		buffer.WriteString("\r\n")
	}
	return buffer.Bytes()
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func parseINFO(data []byte, allowed map[string]bool) (map[string]string, error) {
	if len(data) > maxRESPBytes {
		return nil, fmt.Errorf("%w: INFO response bound", ErrAmbiguous)
	}
	values := make(map[string]string)
	for _, rawLine := range bytes.Split(data, []byte{'\n'}) {
		line := strings.TrimSuffix(string(rawLine), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || len(key) == 0 || len(key) > 64 || len(value) > 256 {
			return nil, fmt.Errorf("%w: unexpected INFO field", ErrAmbiguous)
		}
		for _, character := range key {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
				return nil, fmt.Errorf("%w: non-canonical INFO key", ErrAmbiguous)
			}
		}
		if !allowed[key] {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate INFO field", ErrAmbiguous)
		}
		values[key] = value
	}
	return values, nil
}

type ProbeEvidence struct {
	Version              string
	ProcessID            int64
	RunID                string
	DatasetBytes         uint64
	ConnectedClients     uint32
	LastSuccessfulSaveAt time.Time
	EvidenceDigest       string
}

func (runtime *LinuxRuntime) dial(ctx context.Context, spec InstanceSpec) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: maxProbeTime}
	if spec.Listener.Mode == ListenerUnix {
		info, err := os.Lstat(unixSocketPath(spec.ID))
		owner, ownerErr := runtime.ownership.RedisOwnership(ctx)
		stat, statOK := func() (*syscall.Stat_t, bool) {
			if info == nil {
				return nil, false
			}
			value, ok := info.Sys().(*syscall.Stat_t)
			return value, ok
		}()
		if err != nil || ownerErr != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || !statOK || int(stat.Uid) != owner.UID || int(stat.Gid) != owner.GID {
			return nil, fmt.Errorf("%w: unsafe Redis Unix socket", ErrInvalid)
		}
		return dialer.DialContext(ctx, "unix", unixSocketPath(spec.ID))
	}
	address := net.JoinHostPort(spec.Listener.LoopbackAddress, strconv.Itoa(int(spec.Listener.Port)))
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if !spec.Listener.TLS {
		return connection, nil
	}
	material, err := runtime.tls.ClientMaterial(ctx, spec.Listener.CertificateRef, spec.Listener.ClientCARef)
	if err != nil || material.Roots == nil || len(material.Certificate.Certificate) == 0 {
		connection.Close()
		return nil, fmt.Errorf("%w: TLS client material", ErrInvalid)
	}
	tlsConnection := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: spec.Listener.TLSServerName, RootCAs: material.Roots,
		Certificates: []tls.Certificate{material.Certificate},
	})
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		connection.Close()
		return nil, err
	}
	return tlsConnection, nil
}

func (runtime *LinuxRuntime) probe(ctx context.Context, spec InstanceSpec) (ProbeEvidence, error) {
	if len(spec.ACLUsers) == 0 {
		return ProbeEvidence{}, fmt.Errorf("%w: probe ACL user", ErrInvalid)
	}
	secret, err := runtime.secrets.Resolve(ctx, spec.ACLUsers[0].SecretRef)
	if err != nil {
		return ProbeEvidence{}, fmt.Errorf("%w: probe secret reference unavailable", ErrInvalid)
	}
	defer zeroBytes(secret)
	if len(secret) < 32 || len(secret) > 256 || secretHash(secret) != spec.ACLUsers[0].SecretRef.Digest {
		return ProbeEvidence{}, fmt.Errorf("%w: probe secret binding", ErrInvalid)
	}
	probeContext, cancel := context.WithTimeout(ctx, maxProbeTime)
	defer cancel()
	connection, err := runtime.dial(probeContext, spec)
	if err != nil {
		return ProbeEvidence{}, fmt.Errorf("%w: Redis local probe dial", ErrAmbiguous)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(maxProbeTime))
	authCommand := redisCommand([]byte("AUTH"), []byte(spec.ACLUsers[0].Name), secret)
	if err := writeFull(connection, authCommand); err != nil {
		zeroBytes(authCommand)
		return ProbeEvidence{}, fmt.Errorf("%w: Redis local AUTH write", ErrAmbiguous)
	}
	zeroBytes(authCommand)
	commands := [][]byte{
		redisCommand([]byte("PING")),
		redisCommand([]byte("INFO"), []byte("server")),
		redisCommand([]byte("INFO"), []byte("clients")),
		redisCommand([]byte("INFO"), []byte("memory")),
		redisCommand([]byte("INFO"), []byte("persistence")),
	}
	for _, command := range commands {
		if err := writeFull(connection, command); err != nil {
			return ProbeEvidence{}, fmt.Errorf("%w: Redis local probe write", ErrAmbiguous)
		}
	}
	reader := newRESPReader(connection)
	prefix, value, err := reader.value()
	if err != nil || prefix != '+' || string(value) != "OK" {
		return ProbeEvidence{}, fmt.Errorf("%w: Redis AUTH not confirmed", ErrAmbiguous)
	}
	prefix, value, err = reader.value()
	if err != nil || prefix != '+' || string(value) != "PONG" {
		return ProbeEvidence{}, fmt.Errorf("%w: Redis PING not confirmed", ErrAmbiguous)
	}
	responses := make([]map[string]string, 0, 4)
	allowed := []map[string]bool{
		{"redis_version": true, "run_id": true, "process_id": true},
		{"connected_clients": true},
		{"used_memory_dataset": true},
		{"rdb_last_save_time": true, "loading": true, "aof_enabled": true},
	}
	for _, fields := range allowed {
		prefix, value, err = reader.value()
		if err != nil || prefix != '$' {
			return ProbeEvidence{}, fmt.Errorf("%w: Redis INFO response", ErrAmbiguous)
		}
		parsed, parseErr := parseINFO(value, fields)
		if parseErr != nil {
			return ProbeEvidence{}, parseErr
		}
		responses = append(responses, parsed)
	}
	version := responses[0]["redis_version"]
	if _, _, _, err := parseVersion(version); err != nil || version != spec.Support.RedisVersion {
		return ProbeEvidence{}, fmt.Errorf("%w: actual Redis version differs from qualified version", ErrUnsupported)
	}
	processID, err := strconv.ParseInt(responses[0]["process_id"], 10, 64)
	if err != nil || processID <= 0 || !canonicalRunID(responses[0]["run_id"]) {
		return ProbeEvidence{}, fmt.Errorf("%w: Redis process identity", ErrAmbiguous)
	}
	clients, err := strconv.ParseUint(responses[1]["connected_clients"], 10, 32)
	if err != nil {
		return ProbeEvidence{}, fmt.Errorf("%w: Redis client count", ErrAmbiguous)
	}
	dataset, err := strconv.ParseUint(responses[2]["used_memory_dataset"], 10, 64)
	if err != nil || dataset > spec.ResourceProfile.MemoryLimitBytes {
		return ProbeEvidence{}, fmt.Errorf("%w: Redis dataset capacity", ErrCapacity)
	}
	lastSave, err := strconv.ParseInt(responses[3]["rdb_last_save_time"], 10, 64)
	if err != nil || responses[3]["loading"] != "0" {
		return ProbeEvidence{}, fmt.Errorf("%w: Redis persistence state", ErrAmbiguous)
	}
	expectedAOF := "0"
	if spec.Persistence.AOF != AOFDisabled {
		expectedAOF = "1"
	}
	if responses[3]["aof_enabled"] != expectedAOF {
		return ProbeEvidence{}, fmt.Errorf("%w: Redis AOF policy drift", ErrAmbiguous)
	}
	evidence := ProbeEvidence{
		Version: version, ProcessID: processID, RunID: responses[0]["run_id"], DatasetBytes: dataset,
		ConnectedClients: uint32(clients), LastSuccessfulSaveAt: time.Unix(lastSave, 0).UTC(),
	}
	evidence.EvidenceDigest, err = digestValue(evidence)
	return evidence, err
}

func parseRedisServerVersion(output []byte) (string, error) {
	if len(output) == 0 || len(output) > maxCommandOutput {
		return "", fmt.Errorf("%w: Redis version output", ErrAmbiguous)
	}
	for _, field := range strings.Fields(string(output)) {
		if strings.HasPrefix(field, "v=") {
			version := strings.TrimPrefix(field, "v=")
			if _, _, _, err := parseVersion(version); err != nil {
				return "", err
			}
			return version, nil
		}
	}
	return "", fmt.Errorf("%w: Redis version token missing", ErrAmbiguous)
}

func canonicalRunID(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func systemdCommand(id InstanceID, action string) FixedCommand {
	return FixedCommand{InstanceID: id, Program: systemctlPath, Args: []string{action, managedUnit(id)}, Timeout: maxCommandTime}
}

func (runtime *LinuxRuntime) runCommand(ctx context.Context, command FixedCommand) (string, string, error) {
	result, runErr := runtime.runner.Run(ctx, command)
	commandDigest, outputDigest, digestErr := commandEvidence(command, result)
	if digestErr != nil {
		return "", "", digestErr
	}
	if runErr != nil {
		return commandDigest, outputDigest, runErr
	}
	if result.TimedOut {
		return commandDigest, outputDigest, context.DeadlineExceeded
	}
	if result.ExitCode != 0 {
		return commandDigest, outputDigest, fmt.Errorf("fixed Redis command failed")
	}
	return commandDigest, outputDigest, nil
}

func (runtime *LinuxRuntime) qualifyInstalledVersion(ctx context.Context, spec InstanceSpec) (string, string, string, error) {
	command := FixedCommand{InstanceID: spec.ID, Program: redisServerPath, Args: []string{"--version"}, Timeout: maxCommandTime}
	result, runErr := runtime.runner.Run(ctx, command)
	commandDigest, outputDigest, digestErr := commandEvidence(command, result)
	if digestErr != nil {
		return "", "", "", digestErr
	}
	version, versionErr := parseRedisServerVersion(result.Output)
	if runErr != nil || result.TimedOut || result.ExitCode != 0 || versionErr != nil || version != spec.Support.RedisVersion {
		return "", commandDigest, outputDigest, fmt.Errorf("%w: installed Redis version is not qualified", ErrUnsupported)
	}
	return version, commandDigest, outputDigest, nil
}

func stableFileReader(path string, limit int64, owner RuntimeOwnership) (*os.File, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !statOK || int(stat.Uid) != owner.UID || int(stat.Gid) != owner.GID || info.Size() <= 0 || info.Size() > limit {
		return nil, nil, fmt.Errorf("%w: backup source file", ErrInvalid)
	}
	file, err := os.Open(path)
	return file, info, err
}

func sourceUnchanged(path string, before os.FileInfo) bool {
	after, err := os.Lstat(path)
	return err == nil && after.Mode().IsRegular() && os.SameFile(before, after) && after.Size() == before.Size() && after.ModTime() == before.ModTime()
}

func artifactMatchesRequest(descriptor ArtifactDescriptor, request ArtifactWriteRequest) bool {
	return descriptor.ID == request.ID && descriptor.GroupID == request.GroupID && descriptor.InstanceID == request.InstanceID && descriptor.Kind == request.Kind && descriptor.RedisVersion == request.RedisVersion && descriptor.ConfigGeneration == request.ConfigGeneration && descriptor.SizeBytes > 0 && descriptor.SizeBytes <= request.MaxBytes && validateArtifact(descriptor) == nil
}

type aofSource struct {
	reader io.Reader
	files  []*os.File
	paths  []string
	infos  []os.FileInfo
	size   int64
}

func openAOFSource(directory string, owner RuntimeOwnership) (*aofSource, error) {
	directoryInfo, directoryErr := os.Lstat(directory)
	directoryStat, statOK := func() (*syscall.Stat_t, bool) {
		if directoryInfo == nil {
			return nil, false
		}
		value, ok := directoryInfo.Sys().(*syscall.Stat_t)
		return value, ok
	}()
	if directoryErr != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm()&0o077 != 0 || !statOK || int(directoryStat.Uid) != owner.UID || int(directoryStat.Gid) != owner.GID {
		return nil, fmt.Errorf("%w: unsafe AOF source directory", ErrInvalid)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 || len(entries) > maxAOFFiles {
		return nil, fmt.Errorf("%w: AOF file count", ErrInvalid)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	source := &aofSource{}
	readers := []io.Reader{bytes.NewReader([]byte("CPRAOF1\n"))}
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, "/") || strings.Contains(name, "..") || (!strings.HasSuffix(name, ".aof") && !strings.HasSuffix(name, ".rdb") && !strings.HasSuffix(name, ".manifest")) || len(name) > 255 {
			source.Close()
			return nil, fmt.Errorf("%w: AOF bundle name", ErrInvalid)
		}
		path := directory + "/" + name
		file, info, openErr := stableFileReader(path, MaxArtifactBytes, owner)
		if openErr != nil {
			source.Close()
			return nil, openErr
		}
		header := make([]byte, 2+len(name)+8)
		binary.BigEndian.PutUint16(header[:2], uint16(len(name)))
		copy(header[2:2+len(name)], name)
		binary.BigEndian.PutUint64(header[2+len(name):], uint64(info.Size()))
		readers = append(readers, bytes.NewReader(header), io.LimitReader(file, info.Size()))
		source.files = append(source.files, file)
		source.paths = append(source.paths, path)
		source.infos = append(source.infos, info)
		source.size += int64(len(header)) + info.Size()
		if source.size > MaxArtifactBytes {
			source.Close()
			return nil, fmt.Errorf("%w: AOF bundle size", ErrCapacity)
		}
	}
	readers = append(readers, bytes.NewReader([]byte{0, 0}))
	source.reader = io.MultiReader(readers...)
	return source, nil
}

func (source *aofSource) Close() error {
	var first error
	for _, file := range source.files {
		if err := file.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (source *aofSource) Stable() bool {
	for index, path := range source.paths {
		if !sourceUnchanged(path, source.infos[index]) {
			return false
		}
	}
	return true
}

func (runtime *LinuxRuntime) backup(ctx context.Context, spec InstanceSpec, owner RuntimeOwnership) ([]ArtifactDescriptor, error) {
	groupID, err := runtime.ids.NewID("redis-backup")
	if err != nil {
		return nil, err
	}
	if !validID(groupID) {
		return nil, fmt.Errorf("%w: generated backup group id", ErrInvalid)
	}
	artifacts := make([]ArtifactDescriptor, 0, 2)
	if spec.Persistence.RDB != RDBDisabled {
		path := instanceDataDirectory(spec.ID) + "/dump.rdb"
		file, info, err := stableFileReader(path, MaxArtifactBytes, owner)
		if err != nil {
			return nil, fmt.Errorf("open stable RDB backup source: %w", err)
		}
		artifactID, idErr := runtime.ids.NewID("redis-rdb")
		if idErr != nil {
			file.Close()
			return nil, idErr
		}
		if !validID(artifactID) {
			file.Close()
			return nil, fmt.Errorf("%w: generated RDB artifact id", ErrInvalid)
		}
		request := ArtifactWriteRequest{ID: artifactID, GroupID: groupID, InstanceID: spec.ID, Kind: ArtifactRDB, RedisVersion: spec.Support.RedisVersion, ConfigGeneration: spec.ConfigGeneration, MaxBytes: MaxArtifactBytes}
		descriptor, storeErr := runtime.artifacts.Put(ctx, request, io.LimitReader(file, info.Size()))
		closeErr := file.Close()
		if storeErr != nil || closeErr != nil || !sourceUnchanged(path, info) || !artifactMatchesRequest(descriptor, request) {
			return nil, fmt.Errorf("%w: RDB backup stream not stable", ErrAmbiguous)
		}
		artifacts = append(artifacts, descriptor)
	}
	if spec.Backup.IncludeAOF && spec.Persistence.AOF != AOFDisabled {
		source, err := openAOFSource(instanceDataDirectory(spec.ID)+"/appendonlydir", owner)
		if err != nil {
			return nil, fmt.Errorf("open stable AOF backup source: %w", err)
		}
		artifactID, idErr := runtime.ids.NewID("redis-aof")
		if idErr != nil {
			source.Close()
			return nil, idErr
		}
		if !validID(artifactID) {
			source.Close()
			return nil, fmt.Errorf("%w: generated AOF artifact id", ErrInvalid)
		}
		request := ArtifactWriteRequest{ID: artifactID, GroupID: groupID, InstanceID: spec.ID, Kind: ArtifactAOF, RedisVersion: spec.Support.RedisVersion, ConfigGeneration: spec.ConfigGeneration, MaxBytes: MaxArtifactBytes}
		descriptor, storeErr := runtime.artifacts.Put(ctx, request, source.reader)
		stable := source.Stable()
		closeErr := source.Close()
		if storeErr != nil || closeErr != nil || !stable || !artifactMatchesRequest(descriptor, request) {
			return nil, fmt.Errorf("%w: AOF backup stream not stable", ErrAmbiguous)
		}
		artifacts = append(artifacts, descriptor)
	}
	return artifacts, nil
}

func copyArtifactFile(reader io.Reader, path string, expected ArtifactDescriptor, owner RuntimeOwnership, token string) error {
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return fmt.Errorf("%w: restore target already exists", ErrConflict)
	}
	temporary := path + ".tmp-" + token
	fd, err := syscall.Open(temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer os.Remove(temporary)
	if err := file.Chown(owner.UID, owner.GID); err != nil {
		file.Close()
		return err
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, expected.SizeBytes+1))
	if err != nil || written != expected.SizeBytes || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		file.Close()
		return fmt.Errorf("%w: restore artifact digest or size", ErrAmbiguous)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func copyBundleMember(reader io.Reader, path string, size int64, owner RuntimeOwnership, token string) error {
	if size <= 0 || size > MaxArtifactBytes {
		return fmt.Errorf("%w: AOF member size", ErrInvalid)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return fmt.Errorf("%w: AOF restore member already exists", ErrConflict)
	}
	temporary := path + ".tmp-" + token
	fd, err := syscall.Open(temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer os.Remove(temporary)
	if err := file.Chown(owner.UID, owner.GID); err != nil {
		file.Close()
		return err
	}
	written, err := io.Copy(file, io.LimitReader(reader, size))
	if err != nil || written != size {
		file.Close()
		return fmt.Errorf("%w: truncated AOF bundle member", ErrAmbiguous)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func copyAOFBundle(reader io.Reader, directory string, expected ArtifactDescriptor, owner RuntimeOwnership, token string) error {
	limited := io.LimitReader(reader, expected.SizeBytes+1)
	hash := sha256.New()
	tee := io.TeeReader(limited, hash)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(tee, magic); err != nil || string(magic) != "CPRAOF1\n" {
		return fmt.Errorf("%w: AOF bundle magic", ErrInvalid)
	}
	var consumed int64 = 8
	for files := 0; files <= maxAOFFiles; files++ {
		var nameLength uint16
		if err := binary.Read(tee, binary.BigEndian, &nameLength); err != nil {
			return fmt.Errorf("%w: AOF bundle header", ErrInvalid)
		}
		consumed += 2
		if nameLength == 0 {
			break
		}
		if files == maxAOFFiles || nameLength > 255 {
			return fmt.Errorf("%w: AOF bundle file bound", ErrInvalid)
		}
		nameBytes := make([]byte, nameLength)
		if _, err := io.ReadFull(tee, nameBytes); err != nil {
			return err
		}
		name := string(nameBytes)
		if strings.Contains(name, "/") || strings.Contains(name, "..") || (!strings.HasSuffix(name, ".aof") && !strings.HasSuffix(name, ".rdb") && !strings.HasSuffix(name, ".manifest")) {
			return fmt.Errorf("%w: AOF restore file name", ErrInvalid)
		}
		var size uint64
		if err := binary.Read(tee, binary.BigEndian, &size); err != nil || size == 0 || size > uint64(MaxArtifactBytes) {
			return fmt.Errorf("%w: AOF restore file size", ErrInvalid)
		}
		consumed += int64(nameLength) + 8 + int64(size)
		if consumed > expected.SizeBytes {
			return fmt.Errorf("%w: AOF bundle exceeds descriptor", ErrInvalid)
		}
		if err := copyBundleMember(tee, directory+"/"+name, int64(size), owner, token+"-"+strconv.Itoa(files)); err != nil {
			return err
		}
	}
	extra := make([]byte, 1)
	extraBytes, extraErr := tee.Read(extra)
	if extraBytes != 0 || extraErr != io.EOF || consumed != expected.SizeBytes || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return fmt.Errorf("%w: AOF bundle digest", ErrAmbiguous)
	}
	return nil
}

type stagedRestore struct {
	root       string
	dataPath   string
	descriptor ArtifactDescriptor
}

func (runtime *LinuxRuntime) stageRestore(ctx context.Context, request ExecutionRequest, owner RuntimeOwnership, token string) (stagedRestore, error) {
	if request.Plan.Artifact == nil {
		return stagedRestore{}, fmt.Errorf("%w: restore artifact", ErrInvalid)
	}
	descriptor, reader, err := runtime.artifacts.Open(ctx, request.Plan.Artifact.ID)
	if err != nil {
		return stagedRestore{}, fmt.Errorf("%w: restore artifact unavailable", ErrStale)
	}
	readerOpen := true
	defer func() {
		if readerOpen {
			_ = reader.Close()
		}
	}()
	if !sameArtifact(descriptor, *request.Plan.Artifact) {
		return stagedRestore{}, ErrStale
	}
	restoreRoot := instanceDataDirectory(request.Spec.ID) + "/restore"
	if err := ensureDirectory(restoreRoot, 0o700, owner.UID, owner.GID); err != nil {
		return stagedRestore{}, err
	}
	isolated := restoreRoot + "/" + request.Operation.ID
	if err := ensureDirectory(isolated, 0o700, owner.UID, owner.GID); err != nil {
		return stagedRestore{}, err
	}
	staged := stagedRestore{root: isolated, descriptor: descriptor}
	if descriptor.Kind == ArtifactRDB {
		staged.dataPath = isolated + "/dump.rdb"
		if err := copyArtifactFile(reader, staged.dataPath, descriptor, owner, token); err != nil {
			return stagedRestore{}, err
		}
	} else {
		staged.dataPath = isolated + "/appendonlydir"
		if err := ensureDirectory(staged.dataPath, 0o700, owner.UID, owner.GID); err != nil {
			return stagedRestore{}, err
		}
		if err := copyAOFBundle(reader, staged.dataPath, descriptor, owner, token); err != nil {
			return stagedRestore{}, err
		}
	}
	if err := reader.Close(); err != nil {
		return stagedRestore{}, fmt.Errorf("%w: restore artifact stream close", ErrAmbiguous)
	}
	readerOpen = false
	return staged, nil
}

func (runtime *LinuxRuntime) verifyRestore(ctx context.Context, spec InstanceSpec, staged stagedRestore) (string, string, error) {
	if staged.descriptor.RedisVersion != spec.Support.RedisVersion {
		return "", "", fmt.Errorf("%w: restore Redis version binding", ErrUnsupported)
	}
	_, versionCommandDigest, versionOutputDigest, versionErr := runtime.qualifyInstalledVersion(ctx, spec)
	if versionErr != nil {
		return versionCommandDigest, versionOutputDigest, versionErr
	}
	if staged.descriptor.Kind == ArtifactRDB {
		checkCommandDigest, checkOutputDigest, checkErr := runtime.runCommand(ctx, FixedCommand{InstanceID: spec.ID, Program: redisCheckRDBPath, Args: []string{staged.dataPath}, Timeout: maxCommandTime})
		commandDigest, _ := digestValue([]string{versionCommandDigest, checkCommandDigest})
		outputDigest, _ := digestValue([]string{versionOutputDigest, checkOutputDigest})
		return commandDigest, outputDigest, checkErr
	}
	entries, err := os.ReadDir(staged.dataPath)
	if err != nil || len(entries) == 0 || len(entries) > maxAOFFiles {
		return "", "", fmt.Errorf("%w: staged AOF file set", ErrInvalid)
	}
	commandDigests := []string{versionCommandDigest}
	outputDigests := []string{versionOutputDigest}
	manifestSeen := false
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".manifest") {
			if manifestSeen || validateAOFManifest(staged.dataPath+"/"+entry.Name(), staged.dataPath) != nil {
				return "", "", fmt.Errorf("%w: invalid AOF manifest", ErrInvalid)
			}
			manifestSeen = true
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".aof") {
			if strings.HasSuffix(entry.Name(), ".rdb") {
				commandDigest, outputDigest, commandErr := runtime.runCommand(ctx, FixedCommand{InstanceID: spec.ID, Program: redisCheckRDBPath, Args: []string{staged.dataPath + "/" + entry.Name()}, Timeout: maxCommandTime})
				if commandErr != nil {
					return "", "", commandErr
				}
				commandDigests = append(commandDigests, commandDigest)
				outputDigests = append(outputDigests, outputDigest)
			}
			continue
		}
		commandDigest, outputDigest, commandErr := runtime.runCommand(ctx, FixedCommand{InstanceID: spec.ID, Program: redisCheckAOFPath, Args: []string{staged.dataPath + "/" + entry.Name()}, Timeout: maxCommandTime})
		if commandErr != nil {
			return "", "", commandErr
		}
		commandDigests = append(commandDigests, commandDigest)
		outputDigests = append(outputDigests, outputDigest)
	}
	if len(commandDigests) == 0 || !manifestSeen {
		return "", "", fmt.Errorf("%w: no AOF segment verified", ErrInvalid)
	}
	commandDigest, _ := digestValue(commandDigests)
	outputDigest, _ := digestValue(outputDigests)
	return commandDigest, outputDigest, nil
}

func validateAOFManifest(path, directory string) error {
	data, err := readBoundedFile(path, 64<<10)
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, raw := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(strings.TrimSuffix(raw, "\r"))
		if len(fields) != 6 || fields[0] != "file" || fields[2] != "seq" || fields[4] != "type" || (fields[5] != "b" && fields[5] != "i" && fields[5] != "h") || strings.Contains(fields[1], "/") || strings.Contains(fields[1], "..") || (!strings.HasSuffix(fields[1], ".aof") && !strings.HasSuffix(fields[1], ".rdb")) || seen[fields[1]] {
			return fmt.Errorf("%w: AOF manifest line", ErrInvalid)
		}
		sequence, sequenceErr := strconv.ParseUint(fields[3], 10, 64)
		if sequenceErr != nil || sequence == 0 {
			return fmt.Errorf("%w: AOF manifest sequence", ErrInvalid)
		}
		info, statErr := os.Lstat(directory + "/" + fields[1])
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: AOF manifest member", ErrInvalid)
		}
		seen[fields[1]] = true
	}
	if len(seen) == 0 {
		return fmt.Errorf("%w: empty AOF manifest", ErrInvalid)
	}
	return nil
}

func switchRestoredData(spec InstanceSpec, staged stagedRestore, operationID string, owner RuntimeOwnership) (string, error) {
	live := instanceDataDirectory(spec.ID) + "/dump.rdb"
	if staged.descriptor.Kind == ArtifactAOF {
		live = instanceDataDirectory(spec.ID) + "/appendonlydir"
	}
	recovery := instanceDataDirectory(spec.ID) + "/recovery-" + operationID
	if _, err := os.Lstat(recovery); !os.IsNotExist(err) {
		return "", fmt.Errorf("%w: recovery target already exists", ErrConflict)
	}
	if info, err := os.Lstat(live); err == nil {
		stat, statOK := info.Sys().(*syscall.Stat_t)
		typeOK := info.Mode().IsRegular()
		if staged.descriptor.Kind == ArtifactAOF {
			typeOK = info.IsDir()
		}
		if !typeOK || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !statOK || int(stat.Uid) != owner.UID || int(stat.Gid) != owner.GID {
			return "", fmt.Errorf("%w: unsafe live Redis dataset", ErrInvalid)
		}
		if err := os.Rename(live, recovery); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Rename(staged.dataPath, live); err != nil {
		if recovery != "" {
			_ = os.Rename(recovery, live)
		}
		return "", err
	}
	return recovery, nil
}

func rollbackRestoredData(spec InstanceSpec, descriptor ArtifactDescriptor, recovery string) error {
	if recovery == "" {
		return fmt.Errorf("%w: no local recovery dataset", ErrAmbiguous)
	}
	live := instanceDataDirectory(spec.ID) + "/dump.rdb"
	if descriptor.Kind == ArtifactAOF {
		live = instanceDataDirectory(spec.ID) + "/appendonlydir"
	}
	failed := live + ".failed-" + filepath.Base(recovery)
	if _, err := os.Lstat(failed); !os.IsNotExist(err) {
		return fmt.Errorf("%w: failed restore quarantine already exists", ErrConflict)
	}
	if err := os.Rename(live, failed); err != nil {
		return err
	}
	return os.Rename(recovery, live)
}

type unitProperties struct {
	LoadState     string
	UnitFileState string
	ActiveState   string
	SubState      string
	MainPID       int64
}

func parseUnitProperties(output []byte) (unitProperties, error) {
	if len(output) == 0 || len(output) > maxCommandOutput || bytes.IndexByte(output, 0) >= 0 {
		return unitProperties{}, fmt.Errorf("%w: bounded systemd properties", ErrAmbiguous)
	}
	allowed := map[string]bool{"LoadState": true, "UnitFileState": true, "ActiveState": true, "SubState": true, "MainPID": true}
	values := make(map[string]string, len(allowed))
	for _, raw := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowed[key] || len(value) > 128 {
			return unitProperties{}, fmt.Errorf("%w: unexpected systemd property", ErrAmbiguous)
		}
		if _, duplicate := values[key]; duplicate {
			return unitProperties{}, fmt.Errorf("%w: duplicate systemd property", ErrAmbiguous)
		}
		values[key] = value
	}
	if len(values) != len(allowed) {
		return unitProperties{}, fmt.Errorf("%w: incomplete systemd properties", ErrAmbiguous)
	}
	pid, err := strconv.ParseInt(values["MainPID"], 10, 64)
	if err != nil || pid < 0 {
		return unitProperties{}, fmt.Errorf("%w: systemd process identity", ErrAmbiguous)
	}
	return unitProperties{LoadState: values["LoadState"], UnitFileState: values["UnitFileState"], ActiveState: values["ActiveState"], SubState: values["SubState"], MainPID: pid}, nil
}

func (runtime *LinuxRuntime) inspectUnit(ctx context.Context, id InstanceID) (unitProperties, string, string, error) {
	command := FixedCommand{InstanceID: id, Program: systemctlPath, Args: []string{"show", "--no-pager", "--property=LoadState,UnitFileState,ActiveState,SubState,MainPID", managedUnit(id)}, Timeout: maxCommandTime}
	result, runErr := runtime.runner.Run(ctx, command)
	commandDigest, outputDigest, digestErr := commandEvidence(command, result)
	if digestErr != nil {
		return unitProperties{}, "", "", digestErr
	}
	if runErr != nil || result.TimedOut || result.ExitCode != 0 {
		return unitProperties{}, commandDigest, outputDigest, fmt.Errorf("%w: systemd observation failed", ErrAmbiguous)
	}
	properties, err := parseUnitProperties(result.Output)
	return properties, commandDigest, outputDigest, err
}

func (runtime *LinuxRuntime) rollbackGeneration(ctx context.Context, request ExecutionRequest, generation uint64, token string) error {
	if request.Observed.ActualConfigDigest == "" || !validSHA256(request.Observed.ActualConfigDigest) {
		return fmt.Errorf("%w: prior config digest unavailable", ErrAmbiguous)
	}
	if err := restoreGeneration(request.Spec.ID, generation, token); err != nil {
		return err
	}
	if _, _, err := runtime.runCommand(ctx, FixedCommand{InstanceID: request.Spec.ID, Program: systemctlPath, Args: []string{"daemon-reload"}, Timeout: maxCommandTime}); err != nil {
		return err
	}
	properties, _, _, err := runtime.inspectUnit(ctx, request.Spec.ID)
	if err != nil {
		return err
	}
	enabled := properties.UnitFileState == "enabled"
	if enabled != request.Observed.Enabled {
		action := "disable"
		if request.Observed.Enabled {
			action = "enable"
		}
		if _, _, err := runtime.runCommand(ctx, systemdCommand(request.Spec.ID, action)); err != nil {
			return err
		}
	}
	if request.Observed.Lifecycle == LifecycleRunning {
		if _, _, err := runtime.runCommand(ctx, systemdCommand(request.Spec.ID, "restart")); err != nil {
			return err
		}
		if _, err := runtime.probe(ctx, request.Spec); err != nil {
			return err
		}
	} else if properties.ActiveState == "active" {
		if _, _, err := runtime.runCommand(ctx, systemdCommand(request.Spec.ID, "stop")); err != nil {
			return err
		}
	}
	properties, _, _, err = runtime.inspectUnit(ctx, request.Spec.ID)
	if err != nil || (properties.UnitFileState == "enabled") != request.Observed.Enabled || (properties.ActiveState == "active") != (request.Observed.Lifecycle == LifecycleRunning) {
		return fmt.Errorf("%w: prior unit state not proven", ErrAmbiguous)
	}
	current, err := currentGeneration(request.Spec.ID)
	if err != nil || current != generation {
		return fmt.Errorf("%w: prior config generation not proven", ErrAmbiguous)
	}
	digest, err := generationDigest(request.Spec.ID, generation)
	if err != nil || digest != request.Observed.ActualConfigDigest {
		return fmt.Errorf("%w: prior config digest not proven", ErrAmbiguous)
	}
	return nil
}

func (runtime *LinuxRuntime) rollbackDataset(ctx context.Context, request ExecutionRequest, staged stagedRestore, recovery string) error {
	if err := rollbackRestoredData(request.Spec, staged.descriptor, recovery); err != nil {
		return err
	}
	if _, _, err := runtime.runCommand(ctx, systemdCommand(request.Spec.ID, "restart")); err != nil {
		return err
	}
	if _, err := runtime.probe(ctx, request.Spec); err != nil {
		return err
	}
	current, err := currentGeneration(request.Spec.ID)
	if err != nil || current != request.Spec.ConfigGeneration {
		return fmt.Errorf("%w: active config after dataset rollback", ErrAmbiguous)
	}
	return nil
}

func mutationMayBeAmbiguous(kind StepKind) bool {
	switch kind {
	case StepEnable, StepDisable, StepStop, StepSwitchConfig, StepActivate, StepReload, StepRestart, StepBackupStream, StepRestoreSwitch:
		return true
	default:
		return false
	}
}

func (runtime *LinuxRuntime) verifyRecoveryReference(ctx context.Context, request ExecutionRequest) error {
	reference := request.Plan.Recovery.RecoveryArtifactRef
	if !validID(reference) {
		return fmt.Errorf("%w: recovery artifact reference", ErrInvalid)
	}
	descriptor, reader, err := runtime.artifacts.Open(ctx, reference)
	if err != nil {
		return fmt.Errorf("%w: recovery artifact unavailable", ErrStale)
	}
	if closeErr := reader.Close(); closeErr != nil {
		return fmt.Errorf("%w: recovery artifact availability", ErrAmbiguous)
	}
	if descriptor.ID != reference || descriptor.InstanceID != request.Spec.ID || descriptor.ConfigGeneration != request.Observed.ConfigGeneration || compatibleArtifact(request.Spec, descriptor) != nil || (request.Observed.ActualVersion != "" && descriptor.RedisVersion != request.Observed.ActualVersion) || (request.Plan.Artifact != nil && descriptor.ID == request.Plan.Artifact.ID) {
		return fmt.Errorf("%w: recovery artifact binding", ErrStale)
	}
	return nil
}

type LinuxRuntime struct {
	runner     CommandRunner
	secrets    SecretResolver
	tls        TLSMaterialProvider
	artifacts  ArtifactStore
	packages   PackageMaintenance
	ownership  OwnershipResolver
	remaps     RemapGuard
	clock      Clock
	ids        IDSource
}

func NewLinuxRuntime(runner CommandRunner, secrets SecretResolver, tlsProvider TLSMaterialProvider, artifacts ArtifactStore, packages PackageMaintenance, ownership OwnershipResolver, remaps RemapGuard, clock Clock, ids IDSource) (*LinuxRuntime, error) {
	if runner == nil || secrets == nil || tlsProvider == nil || artifacts == nil || packages == nil || ownership == nil || remaps == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: incomplete Linux runtime dependencies", ErrInvalid)
	}
	return &LinuxRuntime{runner: runner, secrets: secrets, tls: tlsProvider, artifacts: artifacts, packages: packages, ownership: ownership, remaps: remaps, clock: clock, ids: ids}, nil
}

func (runtime *LinuxRuntime) Execute(ctx context.Context, request ExecutionRequest) (ExecutionResult, error) {
	if request.Operation.State != OperationRunning || request.Operation.PlanID != request.Plan.ID || request.Operation.PlanDigest != request.Plan.Digest || request.Spec.ID != request.Plan.InstanceID {
		return ExecutionResult{}, fmt.Errorf("%w: runtime execution binding", ErrInvalid)
	}
	sealedPlan, err := SealLifecyclePlan(request.Plan)
	if err != nil || sealedPlan.Digest != request.Plan.Digest {
		return ExecutionResult{}, ErrStale
	}
	owner, err := runtime.ownership.RedisOwnership(ctx)
	if err != nil || owner.UID <= 0 || owner.GID <= 0 {
		return ExecutionResult{}, fmt.Errorf("%w: Redis runtime ownership unavailable", ErrInvalid)
	}
	token, err := runtime.ids.NewID("redis-stage")
	if err != nil {
		return ExecutionResult{}, err
	}
	if !validID(token) {
		return ExecutionResult{}, fmt.Errorf("%w: generated staging id", ErrInvalid)
	}
	receiptID, err := runtime.ids.NewID("redis-receipt")
	if err != nil {
		return ExecutionResult{}, err
	}
	if !validID(receiptID) {
		return ExecutionResult{}, fmt.Errorf("%w: generated receipt id", ErrInvalid)
	}
	executionContext, cancel := context.WithTimeout(ctx, maxExecutionTime)
	defer cancel()
	receipt := LifecycleReceipt{ID: receiptID, OperationID: request.Operation.ID, PlanID: request.Plan.ID, PlanDigest: request.Plan.Digest, Outcome: "confirmed", StartedAt: runtime.clock.Now().UTC()}
	result := ExecutionResult{}
	var rendered RenderedGeneration
	var staged stagedRestore
	var previousGeneration uint64
	var switchedGeneration bool
	var generationMutationPossible bool
	var recoveryDataset string
	var crossedIrreversible bool
	var executionErr error
	for _, step := range request.Plan.Steps {
		stepReceipt := StepReceipt{Index: step.Index, Kind: step.Kind, Outcome: "confirmed", BeforeDigest: request.Observed.EvidenceDigest}
		switch step.Kind {
		case StepQualify:
			stepReceipt.ObservedVersion, stepReceipt.CommandDigest, stepReceipt.OutputDigest, executionErr = runtime.qualifyInstalledVersion(executionContext, request.Spec)
		case StepInstall, StepRemovePackage:
			action := PackageInstall
			if step.Kind == StepRemovePackage {
				action = PackageRemove
				executionErr = runtime.verifyRecoveryReference(executionContext, request)
			}
			var packageReceipt PackageReceipt
			var packageErr error
			if executionErr == nil {
				packageReceipt, packageErr = runtime.packages.Delegate(executionContext, PackageDelegation{
				OperationID: request.Operation.ID, LifecyclePlanID: request.Plan.ID, LifecyclePlanDigest: request.Plan.Digest,
				InstanceID: request.Spec.ID, ConsumerSnapshotGeneration: request.Plan.ConsumerSnapshotGeneration, ConsumerSnapshotDigest: request.Plan.ConsumerSnapshotDigest,
				RecoveryArtifactID: request.Plan.Recovery.RecoveryArtifactRef,
				ProfileID: RedisPackageProfile, Action: action, RedisVersion: request.Spec.Support.RedisVersion, SupportDigest: request.Spec.Support.QualificationDigest,
				})
			}
			if executionErr != nil || packageErr != nil || !validID(packageReceipt.ID) || packageReceipt.PlanDigest != request.Plan.Digest || packageReceipt.ProfileID != RedisPackageProfile || packageReceipt.Outcome != "confirmed" || !validSHA256(packageReceipt.EvidenceDigest) {
				executionErr = fmt.Errorf("package-maintenance delegation did not confirm")
			} else {
				stepReceipt.AfterDigest = packageReceipt.EvidenceDigest
			}
		case StepRender:
			rendered, executionErr = RenderGeneration(executionContext, request.Spec, runtime.secrets)
			stepReceipt.ConfigDigest = rendered.ConfigDigest
		case StepStage:
			if rendered.ConfigDigest == "" {
				executionErr = fmt.Errorf("%w: render step missing", ErrInvalid)
			} else {
				executionErr = stageGeneration(request.Spec, rendered, owner, token)
				stepReceipt.ConfigDigest = rendered.ConfigDigest
			}
		case StepValidate:
			command := FixedCommand{InstanceID: request.Spec.ID, Program: redisServerPath, Args: []string{redisConfigPath(request.Spec.ID, request.Spec.ConfigGeneration), "--test-memory", "1"}, Timeout: maxCommandTime}
			stepReceipt.CommandDigest, stepReceipt.OutputDigest, executionErr = runtime.runCommand(executionContext, command)
		case StepEnable, StepDisable, StepStop:
			action := "enable"
			if step.Kind == StepDisable {
				action = "disable"
			} else if step.Kind == StepStop {
				action = "stop"
			}
			stepReceipt.CommandDigest, stepReceipt.OutputDigest, executionErr = runtime.runCommand(executionContext, systemdCommand(request.Spec.ID, action))
		case StepSwitchConfig:
			generationMutationPossible = true
			previousGeneration, executionErr = switchGeneration(request.Spec, owner, token)
			switchedGeneration = executionErr == nil
			if executionErr == nil {
				stepReceipt.ConfigDigest, executionErr = generationDigest(request.Spec.ID, request.Spec.ConfigGeneration)
			}
			if executionErr == nil {
				stepReceipt.CommandDigest, stepReceipt.OutputDigest, executionErr = runtime.runCommand(executionContext, FixedCommand{InstanceID: request.Spec.ID, Program: systemctlPath, Args: []string{"daemon-reload"}, Timeout: maxCommandTime})
			}
		case StepActivate, StepReload, StepRestart:
			if planContains(request.Plan, StepStage) && !switchedGeneration {
				generationMutationPossible = true
				previousGeneration, executionErr = switchGeneration(request.Spec, owner, token)
				switchedGeneration = executionErr == nil
			}
			var reloadCommandDigest, reloadOutputDigest string
			if executionErr == nil {
				reloadCommandDigest, reloadOutputDigest, executionErr = runtime.runCommand(executionContext, FixedCommand{InstanceID: request.Spec.ID, Program: systemctlPath, Args: []string{"daemon-reload"}, Timeout: maxCommandTime})
			}
			action := "start"
			if step.Kind == StepReload {
				action = "reload"
			} else if step.Kind == StepRestart {
				action = "restart"
			}
			if executionErr == nil {
				actionCommandDigest, actionOutputDigest, actionErr := runtime.runCommand(executionContext, systemdCommand(request.Spec.ID, action))
				stepReceipt.CommandDigest, _ = digestValue([]string{reloadCommandDigest, actionCommandDigest})
				stepReceipt.OutputDigest, _ = digestValue([]string{reloadOutputDigest, actionOutputDigest})
				executionErr = actionErr
			} else if reloadCommandDigest != "" {
				stepReceipt.CommandDigest = reloadCommandDigest
				stepReceipt.OutputDigest = reloadOutputDigest
			}
		case StepProbe:
			probe, probeErr := runtime.probe(executionContext, request.Spec)
			if probeErr != nil {
				executionErr = probeErr
			} else {
				stepReceipt.ObservedVersion = probe.Version
				stepReceipt.AfterDigest = probe.EvidenceDigest
				current, currentErr := currentGeneration(request.Spec.ID)
				if currentErr != nil || current != request.Spec.ConfigGeneration {
					executionErr = fmt.Errorf("%w: active config generation", ErrAmbiguous)
				} else {
					stepReceipt.ConfigDigest, executionErr = generationDigest(request.Spec.ID, current)
				}
			}
		case StepBackupStream:
			result.Artifacts, executionErr = runtime.backup(executionContext, request.Spec, owner)
			if len(result.Artifacts) != 0 {
				stepReceipt.ArtifactID = result.Artifacts[0].GroupID
				stepReceipt.AfterDigest, _ = digestValue(result.Artifacts)
			}
		case StepRestoreStage:
			staged, executionErr = runtime.stageRestore(executionContext, request, owner, token)
			if executionErr == nil {
				stepReceipt.ArtifactID = staged.descriptor.ID
				stepReceipt.AfterDigest = staged.descriptor.SHA256
			}
		case StepRestoreVerify:
			if staged.dataPath == "" {
				executionErr = fmt.Errorf("%w: restore staging missing", ErrInvalid)
			} else {
				stepReceipt.CommandDigest, stepReceipt.OutputDigest, executionErr = runtime.verifyRestore(executionContext, request.Spec, staged)
			}
		case StepRestoreSwitch:
			executionErr = runtime.verifyRecoveryReference(executionContext, request)
			if executionErr == nil && request.Consumers == nil {
				executionErr = fmt.Errorf("%w: restore consumer state is unavailable", ErrConsumersPresent)
			} else if executionErr == nil {
				mutationInvoked := false
				var switchErr error
				fenceErr := runtime.remaps.WithRestoreFence(executionContext, request.Plan.InstanceID, request.Plan.Remap, *request.Consumers, func() error {
					if mutationInvoked {
						return fmt.Errorf("%w: restore mutation invoked more than once", ErrConflict)
					}
					mutationInvoked = true
					recoveryDataset, switchErr = switchRestoredData(request.Spec, staged, request.Operation.ID, owner)
					return switchErr
				})
				if switchErr != nil {
					executionErr = switchErr
				} else if fenceErr != nil {
					executionErr = fmt.Errorf("%w: fenced restore switch not proven", ErrConsumersPresent)
				} else if !mutationInvoked {
					executionErr = fmt.Errorf("%w: fenced restore mutation was not executed", ErrAmbiguous)
				} else {
					stepReceipt.ArtifactID = staged.descriptor.ID
				}
			}
		default:
			executionErr = fmt.Errorf("%w: runtime step %s", ErrUnsupported, step.Kind)
		}
		if executionErr != nil {
			if generationMutationPossible && previousGeneration != 0 {
				if rollbackErr := runtime.rollbackGeneration(executionContext, request, previousGeneration, token); rollbackErr == nil {
					stepReceipt.Compensation = "prior config generation restored"
					stepReceipt.Outcome = "compensated"
				} else {
					stepReceipt.Outcome = "ambiguous"
					executionErr = fmt.Errorf("%w: config rollback not proven", ErrAmbiguous)
				}
			} else if recoveryDataset != "" {
				if rollbackErr := runtime.rollbackDataset(executionContext, request, staged, recoveryDataset); rollbackErr == nil {
					stepReceipt.Compensation = "prior dataset restored"
					stepReceipt.Outcome = "compensated"
				} else {
					stepReceipt.Outcome = "ambiguous"
					executionErr = fmt.Errorf("%w: dataset rollback not proven", ErrAmbiguous)
				}
			} else if step.Irreversible || crossedIrreversible || mutationMayBeAmbiguous(step.Kind) || errorsIsDeadline(executionErr) {
				stepReceipt.Outcome = "ambiguous"
			} else {
				stepReceipt.Outcome = "failed"
			}
		}
		if executionErr == nil && step.Irreversible {
			crossedIrreversible = true
		}
		stepReceipt, _ = SealStepReceipt(stepReceipt)
		receipt.Steps = append(receipt.Steps, stepReceipt)
		if executionErr != nil {
			receipt.Outcome = stepReceipt.Outcome
			break
		}
	}
	if executionContext.Err() == context.DeadlineExceeded && executionErr == nil {
		executionErr = context.DeadlineExceeded
		receipt.Outcome = "ambiguous"
	}
	receipt.CompletedAt = runtime.clock.Now().UTC()
	receipt, err = SealLifecycleReceipt(receipt)
	if err != nil {
		return ExecutionResult{}, err
	}
	result.Receipt = receipt
	return result, executionErr
}

func errorsIsDeadline(err error) bool {
	return err == context.DeadlineExceeded || err == context.Canceled
}

func canonicalBootID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func processIdentity(pid int64) (string, uint64, error) {
	if pid <= 0 {
		return "", 0, fmt.Errorf("%w: invalid process id", ErrAmbiguous)
	}
	processRoot := "/proc/" + strconv.FormatInt(pid, 10)
	executable, err := os.Readlink(processRoot + "/exe")
	if err != nil || executable != redisServerPath {
		return "", 0, fmt.Errorf("%w: Redis executable identity", ErrAmbiguous)
	}
	bootData, err := readBoundedFile("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return "", 0, err
	}
	bootID := strings.TrimSpace(string(bootData))
	if !canonicalBootID(bootID) {
		return "", 0, fmt.Errorf("%w: boot identity", ErrAmbiguous)
	}
	statData, err := readBoundedFile(processRoot+"/stat", 4096)
	if err != nil {
		return "", 0, err
	}
	closing := bytes.LastIndex(statData, []byte(") "))
	if closing < 2 {
		return "", 0, fmt.Errorf("%w: process stat shape", ErrAmbiguous)
	}
	fields := strings.Fields(string(statData[closing+2:]))
	if len(fields) <= 19 {
		return "", 0, fmt.Errorf("%w: process stat bounds", ErrAmbiguous)
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTicks == 0 {
		return "", 0, fmt.Errorf("%w: process start identity", ErrAmbiguous)
	}
	return bootID, startTicks, nil
}

func desiredStateMatches(spec InstanceSpec, observation InstanceObservation, unit unitProperties) bool {
	switch spec.DesiredLifecycle {
	case LifecycleRunning:
		return observation.Lifecycle == LifecycleRunning && observation.Enabled && unit.SubState == "running"
	case LifecycleStopped:
		return observation.Lifecycle == LifecycleStopped && observation.Enabled
	case LifecycleInstalled:
		return observation.Lifecycle == LifecycleInstalled && !observation.Enabled
	case LifecycleRemoved:
		return observation.Lifecycle == LifecycleAbsent || observation.Lifecycle == LifecycleRemoved
	default:
		return false
	}
}

func (runtime *LinuxRuntime) Observe(ctx context.Context, spec InstanceSpec, generation uint64) (InstanceObservation, error) {
	sealedSpec, err := SealInstanceSpec(spec)
	if err != nil || sealedSpec.Digest != spec.Digest || !validGeneration(generation) {
		return InstanceObservation{}, fmt.Errorf("%w: observation binding", ErrInvalid)
	}
	observed := InstanceObservation{
		InstanceID: spec.ID, NodeID: spec.NodeID, Generation: generation,
		Lifecycle: LifecycleAbsent, Health: HealthIndeterminate, Drift: DriftIndeterminate,
		ObservedAt: runtime.clock.Now().UTC(),
	}
	observationContext, cancel := context.WithTimeout(ctx, maxCommandTime+maxProbeTime)
	defer cancel()
	unit, _, _, unitErr := runtime.inspectUnit(observationContext, spec.ID)
	if unitErr != nil {
		return SealObservation(observed)
	}
	if unit.LoadState == "not-found" {
		observed.Enabled = false
		observed.Lifecycle = LifecycleAbsent
		if spec.DesiredLifecycle == LifecycleRemoved {
			observed.Health = HealthHealthy
			observed.Drift = DriftNone
		} else {
			observed.Health = HealthFailed
			observed.Drift = DriftPresent
		}
		return SealObservation(observed)
	}
	if unit.LoadState != "loaded" || (unit.UnitFileState != "enabled" && unit.UnitFileState != "disabled") {
		return SealObservation(observed)
	}
	observed.Enabled = unit.UnitFileState == "enabled"
	switch unit.ActiveState {
	case "active":
		if unit.SubState != "running" || unit.MainPID <= 0 {
			observed.Lifecycle = LifecycleRunning
			observed.Health = HealthIndeterminate
		} else {
			observed.Lifecycle = LifecycleRunning
		}
	case "inactive":
		if unit.MainPID != 0 {
			return SealObservation(observed)
		}
		if observed.Enabled {
			observed.Lifecycle = LifecycleStopped
		} else {
			observed.Lifecycle = LifecycleInstalled
		}
	case "failed":
		observed.Lifecycle = LifecycleStopped
		observed.Health = HealthFailed
	default:
		return SealObservation(observed)
	}
	versionCommand := FixedCommand{InstanceID: spec.ID, Program: redisServerPath, Args: []string{"--version"}, Timeout: maxCommandTime}
	versionResult, versionRunErr := runtime.runner.Run(observationContext, versionCommand)
	version, versionErr := parseRedisServerVersion(versionResult.Output)
	if versionRunErr != nil || versionResult.TimedOut || versionResult.ExitCode != 0 || versionErr != nil {
		return SealObservation(observed)
	}
	observed.ActualVersion = version
	if version != spec.Support.RedisVersion {
		observed.Health = HealthUnsupported
	}
	current, currentErr := currentGeneration(spec.ID)
	if currentErr != nil {
		return SealObservation(observed)
	}
	observed.ConfigGeneration = current
	if current != 0 {
		observed.ActualConfigDigest, currentErr = generationDigest(spec.ID, current)
		if currentErr != nil {
			observed.ActualConfigDigest = ""
			return SealObservation(observed)
		}
	}
	expectedGeneration, renderErr := RenderGeneration(observationContext, spec, runtime.secrets)
	if renderErr != nil {
		return SealObservation(observed)
	}
	if observed.Lifecycle == LifecycleRunning && unit.SubState == "running" {
		probe, probeErr := runtime.probe(observationContext, spec)
		if probeErr != nil || probe.ProcessID != unit.MainPID {
			return SealObservation(observed)
		}
		bootID, startTicks, identityErr := processIdentity(probe.ProcessID)
		if identityErr != nil {
			return SealObservation(observed)
		}
		observed.ProcessBootID = bootID
		observed.ProcessID = probe.ProcessID
		observed.ProcessStartTicks = startTicks
		observed.DatasetBytes = probe.DatasetBytes
		observed.ConnectedClients = probe.ConnectedClients
		observed.LastSuccessfulSaveAt = probe.LastSuccessfulSaveAt
	}
	exactConfig := observed.ConfigGeneration == spec.ConfigGeneration && observed.ActualConfigDigest == expectedGeneration.ConfigDigest
	exactVersion := observed.ActualVersion == spec.Support.RedisVersion
	exactState := desiredStateMatches(spec, observed, unit)
	if exactConfig && exactVersion && exactState && (observed.Lifecycle != LifecycleRunning || observed.ProcessStartTicks != 0) {
		observed.Drift = DriftNone
		observed.Health = HealthHealthy
	} else {
		observed.Drift = DriftPresent
		if observed.Health != HealthFailed && observed.Health != HealthUnsupported {
			observed.Health = HealthDegraded
		}
	}
	return SealObservation(observed)
}
