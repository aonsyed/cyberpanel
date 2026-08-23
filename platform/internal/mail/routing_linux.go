//go:build linux

package mail

import (
	"bytes"
	"context"
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

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
)

const (
	RoutingConfigurationRoot = "/var/lib/cyberpanel/mail-routing"
	routingWorkRoot          = "/var/lib/cyberpanel/mail-routing-work"
	routingPostmapBinary     = "/usr/sbin/postmap"
	routingPostfixBinary     = "/usr/sbin/postfix"
	routingProcessOutput     = 1 << 20
	routingMapMaximumBytes   = 32 << 20
)

type LinuxRoutingRuntime struct {
	Store      *daemoncfg.Store
	PostfixGID uint32
	Now        func() time.Time
	mu         sync.Mutex
}

func OpenLinuxRoutingRuntime(postfixGID uint32) (*LinuxRoutingRuntime, error) {
	if postfixGID == 0 {
		return nil, ErrInvalidCommand
	}
	store, err := daemoncfg.OpenStore(RoutingConfigurationRoot, RoutingConfigurationRoot)
	if err != nil {
		return nil, err
	}
	if err = ensureRoutingWorkRoot(); err != nil {
		store.Close()
		return nil, err
	}
	return &LinuxRoutingRuntime{Store: store, PostfixGID: postfixGID}, nil
}

func (runtime *LinuxRoutingRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.Store == nil {
		return nil
	}
	err := runtime.Store.Close()
	runtime.Store = nil
	return err
}

func (runtime *LinuxRoutingRuntime) ApplyRoutingGeneration(ctx context.Context, generation RoutingMapGeneration) (RoutingActivationReceipt, error) {
	receipt := RoutingActivationReceipt{GenerationID: generation.ID, SnapshotDigest: generation.SnapshotDigest, SourceDigest: generation.SourceDigest, ObservedAt: routingRuntimeNow(runtime)}
	if runtime == nil || runtime.Store == nil || runtime.PostfixGID == 0 || ctx == nil || generation.Validate() != nil {
		return receipt, ErrInvalidCommand
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	current, err := runtime.Store.Current()
	if err != nil {
		return receipt, err
	}
	receipt.PreviousID = current
	if current == generation.ID {
		artifactDigest, loadErr := routingStoredArtifactDigest(generation.ID)
		if loadErr != nil {
			return receipt, loadErr
		}
		receipt.ArtifactDigest = artifactDigest
		receipt.ProbeDigest, loadErr = runtime.probeGeneration(ctx, generation, artifactDigest, true)
		checkOutput, checkErr := routingRunProcess(ctx, routingPostfixBinary, "check")
		reloadOutput, reloadErr := routingRunProcess(ctx, routingPostfixBinary, "reload")
		receipt.ReloadDigest = routingEvidenceDigest(string(checkOutput), string(reloadOutput), routingErrorText(checkErr), routingErrorText(reloadErr))
		return receipt, errors.Join(loadErr, checkErr, reloadErr)
	}
	artifactDigest, storedErr := routingStoredArtifactDigest(generation.ID)
	if storedErr != nil {
		if !errors.Is(storedErr, os.ErrNotExist) {
			return receipt, storedErr
		}
		artifacts, preparedDigest, prepareErr := runtime.prepareRoutingArtifacts(ctx, generation)
		if prepareErr != nil {
			return receipt, prepareErr
		}
		defer wipeRoutingArtifacts(artifacts)
		artifactDigest = preparedDigest
		if _, err = runtime.Store.Stage(ctx, generation.ID, artifactDigest, artifacts); err != nil {
			return receipt, err
		}
	}
	receipt.ArtifactDigest = artifactDigest
	probe, probeErr := runtime.probeGeneration(ctx, generation, artifactDigest, false)
	var precheck []byte
	var checkErr error
	if current != "" {
		precheck, checkErr = routingRunProcess(ctx, routingPostfixBinary, "check")
	}
	receipt.ValidationDigest = routingEvidenceDigest(probe, string(precheck), routingErrorText(probeErr), routingErrorText(checkErr))
	if probeErr != nil || checkErr != nil {
		return receipt, errors.Join(probeErr, checkErr)
	}
	previous, err := runtime.Store.Activate(ctx, generation.ID)
	if err != nil {
		return receipt, err
	}
	receipt.PreviousID = previous
	checkOutput, checkErr := routingRunProcess(ctx, routingPostfixBinary, "check")
	reloadOutput, reloadErr := routingRunProcess(ctx, routingPostfixBinary, "reload")
	receipt.ReloadDigest = routingEvidenceDigest(string(checkOutput), string(reloadOutput), routingErrorText(checkErr), routingErrorText(reloadErr))
	receipt.ProbeDigest, probeErr = runtime.probeGeneration(ctx, generation, artifactDigest, true)
	if checkErr == nil && reloadErr == nil && probeErr == nil {
		return receipt, nil
	}
	original := errors.Join(checkErr, reloadErr, probeErr)
	rollbackErr := runtime.Store.Rollback(ctx, previous)
	rollbackCheck, rollbackCheckErr := routingRunProcess(ctx, routingPostfixBinary, "check")
	rollbackReload, rollbackReloadErr := routingRunProcess(ctx, routingPostfixBinary, "reload")
	rollbackProbeErr := runtime.probeCurrentID(previous)
	receipt.RollbackDigest = routingEvidenceDigest(string(rollbackCheck), string(rollbackReload), routingErrorText(rollbackErr), routingErrorText(rollbackCheckErr), routingErrorText(rollbackReloadErr), routingErrorText(rollbackProbeErr))
	receipt.RolledBack = rollbackErr == nil && rollbackCheckErr == nil && rollbackReloadErr == nil && rollbackProbeErr == nil
	if receipt.RolledBack {
		return receipt, original
	}
	return receipt, errors.Join(ErrAmbiguous, original, rollbackErr, rollbackCheckErr, rollbackReloadErr, rollbackProbeErr)
}

func (runtime *LinuxRoutingRuntime) prepareRoutingArtifacts(ctx context.Context, generation RoutingMapGeneration) ([]daemoncfg.Artifact, string, error) {
	if err := ensureRoutingWorkRoot(); err != nil {
		return nil, "", err
	}
	work, err := os.MkdirTemp(routingWorkRoot, "routing-")
	if err != nil {
		return nil, "", err
	}
	defer cleanupRoutingWork(work)
	sources := []struct {
		name    string
		content []byte
		postmap bool
	}{
		{"virtual_aliases", generation.VirtualAliases, true},
		{"routing_actions", generation.RoutingActions, true},
		{"routing_patterns.regexp", generation.PatternRoutes, false},
		{"routing_policy.json", generation.PolicyMetadata, false},
		{"source.digest", []byte(generation.SourceDigest + "\n"), false},
	}
	for _, source := range sources {
		path := filepath.Join(work, source.name)
		if err = writeRoutingWorkFile(path, source.content, runtime.PostfixGID); err != nil {
			return nil, "", err
		}
		if source.postmap {
			if _, err = routingRunProcess(ctx, routingPostmapBinary, "hash:"+path); err != nil {
				return nil, "", err
			}
		}
	}
	artifacts := make([]daemoncfg.Artifact, 0, 7)
	for _, name := range []string{"virtual_aliases", "virtual_aliases.db", "routing_actions", "routing_actions.db", "routing_patterns.regexp", "routing_policy.json", "source.digest"} {
		content, readErr := readRoutingOwnedFile(filepath.Join(work, name), routingMapMaximumBytes)
		if readErr != nil {
			wipeRoutingArtifacts(artifacts)
			return nil, "", readErr
		}
		artifacts = append(artifacts, daemoncfg.Artifact{Path: name, Mode: 0440, GID: runtime.PostfixGID, Content: content})
	}
	digest, err := daemoncfg.ComputeDigest(artifacts)
	if err != nil {
		wipeRoutingArtifacts(artifacts)
		return nil, "", err
	}
	return artifacts, digest, nil
}

func (runtime *LinuxRoutingRuntime) probeGeneration(ctx context.Context, generation RoutingMapGeneration, artifactDigest string, requireCurrent bool) (string, error) {
	if _, err := runtime.Store.Verify(generation.ID, artifactDigest); err != nil {
		return "", err
	}
	if requireCurrent {
		current, err := runtime.Store.Current()
		if err != nil || current != generation.ID {
			return "", errors.Join(ErrConflict, err)
		}
	}
	root := filepath.Join(RoutingConfigurationRoot, "generations", generation.ID)
	digestRaw, err := readRoutingOwnedFile(filepath.Join(root, "source.digest"), 128)
	if err != nil || string(digestRaw) != generation.SourceDigest+"\n" {
		return "", errors.Join(ErrInvalidReceipt, err)
	}
	evidence := []string{generation.ID, generation.SourceDigest, artifactDigest}
	for _, probe := range generation.Probes {
		mapPath := filepath.Join(root, probe.Map)
		output, queryErr := routingRunProcess(ctx, routingPostmapBinary, "-q", probe.Key, "hash:"+mapPath)
		actual := strings.TrimSpace(string(output))
		evidence = append(evidence, probe.Map, probe.Key, actual, routingErrorText(queryErr))
		if queryErr != nil || actual != probe.Expected {
			return routingEvidenceDigest(evidence...), errors.Join(ErrInvalidReceipt, queryErr)
		}
	}
	return routingEvidenceDigest(evidence...), nil
}

func (runtime *LinuxRoutingRuntime) probeCurrentID(expected string) error {
	current, err := runtime.Store.Current()
	if err != nil || current != expected {
		return errors.Join(ErrConflict, err)
	}
	return nil
}

func ensureRoutingWorkRoot() error {
	if err := os.MkdirAll(routingWorkRoot, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(routingWorkRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return ErrUnauthorized
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		return ErrUnauthorized
	}
	return nil
}

func writeRoutingWorkFile(path string, content []byte, gid uint32) error {
	if filepath.Dir(path) == path || filepath.Clean(path) != path || filepath.Dir(path) == routingWorkRoot || !strings.HasPrefix(path, routingWorkRoot+string(os.PathSeparator)) || len(content) > routingMapMaximumBytes || gid == 0 {
		return ErrInvalidCommand
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0640)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	written, writeErr := file.Write(content)
	if writeErr == nil && written != len(content) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if writeErr == nil {
		writeErr = syscall.Fchown(fd, 0, int(gid))
	}
	if writeErr == nil {
		writeErr = syscall.Fchmod(fd, 0640)
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func readRoutingOwnedFile(path string, maximum int) ([]byte, error) {
	if maximum <= 0 || maximum > routingMapMaximumBytes || filepath.Clean(path) != path || !strings.HasPrefix(path, RoutingConfigurationRoot+string(os.PathSeparator)) && !strings.HasPrefix(path, routingWorkRoot+string(os.PathSeparator)) {
		return nil, ErrInvalidCommand
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > int64(maximum) || info.Mode().Perm()&0022 != 0 {
		return nil, ErrInvalidReceipt
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		return nil, ErrInvalidReceipt
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(content) > maximum {
		return nil, errors.Join(ErrInvalidReceipt, err)
	}
	return content, nil
}

func routingRunProcess(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	if ctx == nil || executable != routingPostmapBinary && executable != routingPostfixBinary || !validRoutingArguments(executable, arguments) {
		return nil, ErrInvalidCommand
	}
	commandContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, executable, arguments...)
	command.Stdin = nil
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output := &routingBoundedOutput{limit: routingProcessOutput}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if output.overflow {
		return append([]byte(nil), output.buffer.Bytes()...), errors.Join(ErrInvalidReceipt, err)
	}
	if err != nil {
		return append([]byte(nil), output.buffer.Bytes()...), fmt.Errorf("fixed routing operation failed: %w", err)
	}
	return append([]byte(nil), output.buffer.Bytes()...), nil
}

func validRoutingArguments(executable string, arguments []string) bool {
	if executable == routingPostfixBinary {
		return len(arguments) == 1 && (arguments[0] == "check" || arguments[0] == "reload")
	}
	if len(arguments) == 1 {
		return validRoutingMapArgument(arguments[0])
	}
	return len(arguments) == 3 && arguments[0] == "-q" && len(arguments[1]) > 0 && len(arguments[1]) <= 4096 && !strings.ContainsAny(arguments[1], "\x00\r\n") && validRoutingMapArgument(arguments[2])
}

func validRoutingMapArgument(argument string) bool {
	if !strings.HasPrefix(argument, "hash:") {
		return false
	}
	path := strings.TrimPrefix(argument, "hash:")
	if filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return false
	}
	return strings.HasPrefix(path, routingWorkRoot+string(os.PathSeparator)) || strings.HasPrefix(path, filepath.Join(RoutingConfigurationRoot, "generations")+string(os.PathSeparator))
}

type routingBoundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (output *routingBoundedOutput) Write(value []byte) (int, error) {
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

func routingStoredArtifactDigest(id string) (string, error) {
	if !validOpaque(id) {
		return "", ErrInvalidCommand
	}
	raw, err := readRoutingOwnedFile(filepath.Join(RoutingConfigurationRoot, "generations", id, "manifest.json"), 4<<20)
	if err != nil {
		return "", err
	}
	var envelope struct {
		Manifest daemoncfg.Manifest `json:"manifest"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Manifest.GenerationID != id || !validRoutingDigest(envelope.Manifest.Digest) {
		return "", ErrInvalidReceipt
	}
	return envelope.Manifest.Digest, nil
}

func cleanupRoutingWork(path string) {
	if filepath.Dir(path) == routingWorkRoot && strings.HasPrefix(filepath.Base(path), "routing-") {
		_ = os.RemoveAll(path)
	}
}

func wipeRoutingArtifacts(artifacts []daemoncfg.Artifact) {
	for index := range artifacts {
		for offset := range artifacts[index].Content {
			artifacts[index].Content[offset] = 0
		}
	}
}

func routingRuntimeNow(runtime *LinuxRoutingRuntime) time.Time {
	if runtime != nil && runtime.Now != nil {
		return runtime.Now().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func routingEvidenceDigest(values ...string) string {
	digest, _ := routingDigest("mail-routing-runtime-evidence-v1", values)
	return digest
}

func routingErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
