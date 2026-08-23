//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanel"
)

const protocolVersion = uint32(1)
const maximumFrameBytes = 1 << 20
const helperSocketPath = "/run/cyberpanel-migration/cutover.sock"
const helperStateDirectory = "/var/lib/cyberpanel-migration/cutover"
const helperGenerationDirectory = "/var/lib/cyberpanel-migration/source-sessions"
const helperPlanDirectory = "/var/lib/cyberpanel-migration/source-plans"

type helperConfig struct {
	SourceInstallationID string `json:"source_installation_id"`
	SocketPath string `json:"socket_path"`
	StateDirectory string `json:"state_directory"`
	GenerationDirectory string `json:"generation_directory"`
	PlanDirectory string `json:"plan_directory"`
	AllowedPeerUID uint32 `json:"allowed_peer_uid"`
	AllowedPeerGID uint32 `json:"allowed_peer_gid"`
	ApprovedSiteSourceIDs []string `json:"approved_site_source_ids"`
	ApprovalKeys map[string]string `json:"approval_keys"`
	AllowedTargetInstallationIDs []string `json:"allowed_target_installation_ids"`
	MaximumPlanLifetimeSeconds uint64 `json:"maximum_plan_lifetime_seconds"`
	FenceLeaseSeconds uint64 `json:"fence_lease_seconds"`
}

type wireRequest struct {
	Version uint32 `json:"version"`
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
	Quiesce *cyberpanel.QuiesceRequest `json:"quiesce,omitempty"`
	HandleID string `json:"handle_id,omitempty"`
	Fence *migration.SourceFence `json:"fence,omitempty"`
	Command *cyberpanel.FenceCommand `json:"command,omitempty"`
}

type wireResponse struct {
	Version uint32 `json:"version"`
	RequestID string `json:"request_id"`
	Observation *cyberpanel.QuiesceObservation `json:"observation,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

type serviceReceipt struct {
	Unit string `json:"unit"`
	WasActive bool `json:"was_active"`
}

type fenceReceipt struct {
	Version uint32 `json:"version"`
	Request cyberpanel.QuiesceRequest `json:"request"`
	HandleID string `json:"handle_id"`
	SourceGeneration uint64 `json:"source_generation"`
	ExpiresAt time.Time `json:"expires_at"`
	EvidenceDigest string `json:"evidence_digest"`
	FenceDigest string `json:"fence_digest,omitempty"`
	Services []serviceReceipt `json:"services"`
	DatabaseManaged bool `json:"database_managed"`
	DatabaseWasReadOnly bool `json:"database_was_read_only"`
	State string `json:"state"`
	RestoreTo string `json:"restore_to,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type helper struct {
	config helperConfig
	plans *cyberpanel.FilePlanStore
	verifier *cyberpanel.LocalApprovalVerifier
	mu sync.Mutex
}

func main() {
	log.SetFlags(0)
	flags := flag.NewFlagSet("cyberpanel-cutover", flag.ExitOnError)
	configPath := flags.String("config", "", "absolute root-owned helper configuration")
	_ = flags.Parse(os.Args[1:])
	if flags.NArg() != 0 || *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: cyberpanel-cutover -config /etc/cyberpanel/migration/cutover.json")
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		log.Fatal("cyberpanel-cutover must run as root")
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load cutover helper configuration: %v", err)
	}
	daemon, err := newHelper(config)
	if err != nil {
		log.Fatalf("initialize cutover helper: %v", err)
	}
	defer daemon.plans.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err = daemon.recover(ctx); err != nil {
		log.Fatalf("recover cutover fence: %v", err)
	}
	if err = daemon.serve(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		log.Fatalf("serve cutover helper: %v", err)
	}
}

func loadConfig(path string) (helperConfig, error) {
	var value helperConfig
	raw, err := readOwnedFile(path, 0, 0o600, maximumFrameBytes)
	if err != nil {
		return value, err
	}
	if err = decodeStrict(raw, &value); err != nil {
		return helperConfig{}, err
	}
	if !bounded(value.SourceInstallationID, 256) || value.AllowedPeerUID == 0 || value.AllowedPeerGID == 0 || len(value.ApprovedSiteSourceIDs) == 0 || len(value.ApprovedSiteSourceIDs) > 4096 || len(value.ApprovalKeys) == 0 || len(value.ApprovalKeys) > 64 || len(value.AllowedTargetInstallationIDs) == 0 || len(value.AllowedTargetInstallationIDs) > 64 {
		return helperConfig{}, cyberpanel.ErrInvalid
	}
	for _, path := range []string{value.SocketPath, value.StateDirectory, value.GenerationDirectory, value.PlanDirectory} {
		if !canonicalPath(path) {
			return helperConfig{}, cyberpanel.ErrInvalid
		}
	}
	if value.SocketPath != helperSocketPath || value.StateDirectory != helperStateDirectory || value.GenerationDirectory != helperGenerationDirectory || value.PlanDirectory != helperPlanDirectory {
		return helperConfig{}, cyberpanel.ErrDenied
	}
	if value.StateDirectory == value.GenerationDirectory || value.StateDirectory == value.PlanDirectory || value.GenerationDirectory == value.PlanDirectory {
		return helperConfig{}, cyberpanel.ErrInvalid
	}
	if err = validateDirectory(filepath.Dir(value.StateDirectory), 0, 0, 0o711); err != nil {
		return helperConfig{}, err
	}
	if err = validateDirectory(filepath.Dir(value.SocketPath), 0, value.AllowedPeerGID, 0o750); err != nil {
		return helperConfig{}, err
	}
	if err = validateDirectory(value.StateDirectory, 0, 0, 0o700); err != nil {
		return helperConfig{}, err
	}
	if err = validateDirectory(value.GenerationDirectory, value.AllowedPeerUID, value.AllowedPeerGID, 0o700); err != nil {
		return helperConfig{}, err
	}
	if err = validateDirectory(value.PlanDirectory, value.AllowedPeerUID, value.AllowedPeerGID, 0o700); err != nil {
		return helperConfig{}, err
	}
	if value.MaximumPlanLifetimeSeconds < 60 || value.MaximumPlanLifetimeSeconds > uint64((30*24*time.Hour)/time.Second) || value.FenceLeaseSeconds < 30 || value.FenceLeaseSeconds > 3600 {
		return helperConfig{}, cyberpanel.ErrInvalid
	}
	sort.Strings(value.ApprovedSiteSourceIDs)
	for index, site := range value.ApprovedSiteSourceIDs {
		if !bounded(site, 192) || index > 0 && site == value.ApprovedSiteSourceIDs[index-1] {
			return helperConfig{}, cyberpanel.ErrInvalid
		}
	}
	return value, nil
}

func newHelper(config helperConfig) (*helper, error) {
	plans, err := cyberpanel.OpenFilePlanStore(config.PlanDirectory)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]ed25519.PublicKey, len(config.ApprovalKeys))
	for id, encoded := range config.ApprovalKeys {
		raw, decodeErr := hex.DecodeString(encoded)
		if !bounded(id, 128) || decodeErr != nil || len(raw) != ed25519.PublicKeySize || encoded != strings.ToLower(encoded) {
			plans.Close()
			return nil, cyberpanel.ErrInvalid
		}
		keys[id] = ed25519.PublicKey(raw)
	}
	targets := make(map[string]struct{}, len(config.AllowedTargetInstallationIDs))
	for _, id := range config.AllowedTargetInstallationIDs {
		if !bounded(id, 256) {
			plans.Close()
			return nil, cyberpanel.ErrInvalid
		}
		targets[id] = struct{}{}
	}
	verifier, err := cyberpanel.NewLocalApprovalVerifier(cyberpanel.LocalApprovalPolicy{SourceInstallationID: config.SourceInstallationID, Keys: keys, MaximumLifetime: time.Duration(config.MaximumPlanLifetimeSeconds) * time.Second, AllowedTargets: targets, AllowedSchemaHashes: map[string]struct{}{cyberpanel.CanonicalManifestSchemaHash(): {}}})
	if err != nil {
		plans.Close()
		return nil, err
	}
	return &helper{config: config, plans: plans, verifier: verifier}, nil
}

func (h *helper) serve(ctx context.Context) error {
	if info, err := os.Lstat(h.config.SocketPath); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != 0 || stat.Gid != h.config.AllowedPeerGID || info.Mode().Perm()&0o007 != 0 {
			return cyberpanel.ErrDenied
		}
		if err = os.Remove(h.config.SocketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: h.config.SocketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(h.config.SocketPath)
	if err = os.Chown(h.config.SocketPath, 0, int(h.config.AllowedPeerGID)); err == nil {
		err = os.Chmod(h.config.SocketPath, 0o660)
	}
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		_ = listener.SetDeadline(time.Now().Add(10 * time.Second))
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if networkError, ok := acceptErr.(net.Error); ok && networkError.Timeout() { if expireErr := h.expire(ctx); expireErr != nil { return expireErr }; continue }
			return acceptErr
		}
		h.handleConnection(ctx, connection)
	}
}

func (h *helper) handleConnection(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Minute))
	credentials, err := peerCredentials(connection)
	if err != nil || credentials == nil || credentials.Uid != h.config.AllowedPeerUID || credentials.Gid != h.config.AllowedPeerGID || credentials.Pid <= 1 {
		return
	}
	raw, err := readFrame(bufio.NewReaderSize(connection, maximumFrameBytes))
	var request wireRequest
	if err == nil {
		err = decodeStrict(raw, &request)
	}
	response := wireResponse{Version: protocolVersion, RequestID: request.RequestID}
	if err == nil {
		response.Observation, err = h.dispatch(ctx, request)
	}
	if err != nil {
		response.Observation = nil
		response.ErrorCode = errorCode(err)
	}
	encoded, encodeErr := json.Marshal(response)
	if encodeErr != nil || len(encoded) > maximumFrameBytes {
		return
	}
	writer := bufio.NewWriterSize(connection, 64<<10)
	if writeFrame(writer, encoded) == nil {
		_ = writer.Flush()
	}
}

func (h *helper) dispatch(ctx context.Context, request wireRequest) (*cyberpanel.QuiesceObservation, error) {
	if request.Version != protocolVersion || !requestID(request.RequestID) {
		return nil, cyberpanel.ErrInvalid
	}
	switch request.Operation {
	case "begin_quiesce":
		if request.Quiesce == nil || request.HandleID != "" || request.Fence != nil || request.Command != nil { return nil, cyberpanel.ErrInvalid }
		observation, err := h.begin(ctx, *request.Quiesce); return &observation, err
	case "bind_fence":
		if request.Quiesce != nil || !handleID(request.HandleID) || request.Fence == nil || request.Command != nil { return nil, cyberpanel.ErrInvalid }
		return nil, h.bind(ctx, request.HandleID, *request.Fence)
	case "abort_unbound":
		if request.Quiesce != nil || !handleID(request.HandleID) || request.Fence != nil || request.Command != nil { return nil, cyberpanel.ErrInvalid }
		return nil, h.abort(ctx, request.HandleID)
	case "assert_quiesced":
		if request.Quiesce != nil || request.HandleID != "" || request.Fence != nil || request.Command == nil { return nil, cyberpanel.ErrInvalid }
		return nil, h.status(ctx, *request.Command)
	case "unquiesce", "commit", "rollback":
		if request.Quiesce != nil || request.HandleID != "" || request.Fence != nil || request.Command == nil { return nil, cyberpanel.ErrInvalid }
		return nil, h.finish(ctx, request.Operation, *request.Command)
	default:
		return nil, cyberpanel.ErrInvalid
	}
}

func (h *helper) begin(ctx context.Context, request cyberpanel.QuiesceRequest) (cyberpanel.QuiesceObservation, error) {
	h.mu.Lock(); defer h.mu.Unlock()
	approved, generation, err := h.approvedGeneration(ctx, request)
	if err != nil { return cyberpanel.QuiesceObservation{}, err }
	if request.Mode != "service_fence" { return cyberpanel.QuiesceObservation{}, cyberpanel.ErrDenied }
	receipts, err := h.receipts()
	if err != nil { return cyberpanel.QuiesceObservation{}, err }
	for _, existing := range receipts {
		if active(existing.State) {
			if existing.Request.MigrationID == request.MigrationID && existing.Request.ExpectedFence == request.ExpectedFence && sameRequest(existing.Request, request) && time.Now().UTC().Before(existing.ExpiresAt) && (existing.State == "unbound" || existing.State == "bound") {
				return existing.observation(), nil
			}
			return cyberpanel.QuiesceObservation{}, cyberpanel.ErrDenied
		}
	}
	services, err := observeServices(ctx, approved.Plan.Selection)
	if err != nil { return cyberpanel.QuiesceObservation{}, err }
	databaseManaged := approved.Plan.Selection.Databases
	databaseReadOnly := false
	if databaseManaged { databaseReadOnly, err = readOnly(ctx); if err != nil { return cyberpanel.QuiesceObservation{}, err } }
	if len(services) == 0 && !databaseManaged { return cyberpanel.QuiesceObservation{}, cyberpanel.ErrDenied }
	now := time.Now().UTC()
	expires := now.Add(time.Duration(h.config.FenceLeaseSeconds) * time.Second)
	if expires.After(approved.Plan.ExpiresAt) { expires = approved.Plan.ExpiresAt.UTC() }
	if !expires.After(now) { return cyberpanel.QuiesceObservation{}, cyberpanel.ErrDenied }
	handle, err := randomID("fence_")
	if err != nil { return cyberpanel.QuiesceObservation{}, err }
	receipt := fenceReceipt{Version: 1, Request: request, HandleID: handle, SourceGeneration: generation.SourceGeneration, ExpiresAt: expires, Services: services, DatabaseManaged: databaseManaged, DatabaseWasReadOnly: databaseReadOnly, State: "applying", UpdatedAt: now}
	receipt.EvidenceDigest = evidence(receipt)
	if err = h.persist(receipt); err != nil { return cyberpanel.QuiesceObservation{}, err }
	if err = applyFence(ctx, receipt); err != nil {
		receipt.State, receipt.RestoreTo, receipt.UpdatedAt = "restoring", "aborted", time.Now().UTC(); _ = h.persist(receipt)
		restoreErr := restoreFence(ctx, receipt)
		if restoreErr == nil { receipt.State, receipt.RestoreTo, receipt.UpdatedAt = "aborted", "", time.Now().UTC(); restoreErr = h.persist(receipt) }
		return cyberpanel.QuiesceObservation{}, errors.Join(err, restoreErr)
	}
	receipt.State, receipt.UpdatedAt = "unbound", time.Now().UTC()
	if err = h.persist(receipt); err != nil {
		receipt.State, receipt.RestoreTo, receipt.UpdatedAt = "restoring", "aborted", time.Now().UTC(); _ = h.persist(receipt)
		restoreErr := restoreFence(ctx, receipt)
		if restoreErr == nil { receipt.State, receipt.RestoreTo, receipt.UpdatedAt = "aborted", "", time.Now().UTC(); restoreErr = h.persist(receipt) }
		return cyberpanel.QuiesceObservation{}, errors.Join(err, restoreErr)
	}
	return receipt.observation(), nil
}

func (h *helper) approvedGeneration(ctx context.Context, request cyberpanel.QuiesceRequest) (cyberpanel.ApprovedPlan, cyberpanel.CutoverGenerationReceipt, error) {
	if !request.MigrationID.Valid() || request.SourceInstallationID != h.config.SourceInstallationID || request.ExpectedFence == 0 || !digest(request.TargetPlanDigest) || !digest(request.ApprovalDigest) { return cyberpanel.ApprovedPlan{}, cyberpanel.CutoverGenerationReceipt{}, cyberpanel.ErrInvalid }
	approved, err := h.plans.ApprovedPlan(ctx, request.MigrationID)
	if err != nil { return approved, cyberpanel.CutoverGenerationReceipt{}, err }
	now := time.Now().UTC()
	if err = h.verifier.VerifyApprovedPlan(ctx, approved, now); err != nil { return approved, cyberpanel.CutoverGenerationReceipt{}, err }
	planDigest, err := cyberpanel.ApprovedSourcePlanDigest(approved)
	if err != nil || approved.Plan.SourceInstallationID != request.SourceInstallationID || approved.Plan.TargetPlanDigest != request.TargetPlanDigest || approved.Plan.QuiesceMode != request.Mode || !sameStrings(approved.Plan.SiteSourceIDs, request.SiteSourceIDs) || !sameSet(approved.Plan.SiteSourceIDs, h.config.ApprovedSiteSourceIDs) || planDigest != request.ApprovalDigest { return approved, cyberpanel.CutoverGenerationReceipt{}, errors.Join(err, cyberpanel.ErrDenied) }
	path := filepath.Join(h.config.GenerationDirectory, request.MigrationID.String()+".generation.json")
	raw, err := readOwnedFile(path, h.config.AllowedPeerUID, 0o400, maximumFrameBytes)
	var generation cyberpanel.CutoverGenerationReceipt
	if err == nil { err = decodeStrict(raw, &generation) }
	if err != nil { return approved, generation, err }
	if generation.Version != 1 || generation.MigrationID != request.MigrationID || generation.SourceInstallationID != request.SourceInstallationID || generation.SourceGeneration == 0 || generation.ApprovedPlanDigest != planDigest || !sameStrings(generation.SiteSourceIDs, request.SiteSourceIDs) || generation.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(generation.ObservedAt) > 2*time.Minute { return approved, generation, cyberpanel.ErrDenied }
	return approved, generation, nil
}

func (h *helper) bind(ctx context.Context, handle string, fence migration.SourceFence) error {
	h.mu.Lock(); defer h.mu.Unlock()
	receipt, err := h.find(func(value fenceReceipt) bool { return value.HandleID == handle })
	if err != nil { return err }
	if receipt.Request.MigrationID != fence.MigrationID || receipt.SourceGeneration != fence.Generation || receipt.Request.ExpectedFence != fence.Fence || !digest(fence.Digest) || !fence.ExpiresAt.Equal(receipt.ExpiresAt) || fence.Digest != expectedFenceDigest(receipt, fence) { return cyberpanel.ErrDenied }
	if receipt.State == "bound" && receipt.FenceDigest == fence.Digest { return nil }
	if receipt.State != "unbound" || !time.Now().UTC().Before(receipt.ExpiresAt) { return cyberpanel.ErrDenied }
	receipt.State, receipt.FenceDigest, receipt.UpdatedAt = "bound", fence.Digest, time.Now().UTC()
	return h.persist(receipt)
}

func (h *helper) abort(ctx context.Context, handle string) error {
	h.mu.Lock(); defer h.mu.Unlock()
	receipt, err := h.find(func(value fenceReceipt) bool { return value.HandleID == handle })
	if errors.Is(err, migration.ErrNotFound) { return nil }
	if err != nil || receipt.State == "aborted" { return err }
	if receipt.State != "unbound" && receipt.State != "applying" && receipt.State != "restoring" { return cyberpanel.ErrDenied }
	return h.restore(ctx, receipt, "aborted")
}

func (h *helper) status(ctx context.Context, command cyberpanel.FenceCommand) error {
	h.mu.Lock(); defer h.mu.Unlock()
	receipt, err := h.command(command)
	if err != nil { return err }
	if receipt.State != "bound" || !time.Now().UTC().Before(receipt.ExpiresAt) { return cyberpanel.ErrDenied }
	return verifyFence(ctx, receipt)
}

func (h *helper) finish(ctx context.Context, operation string, command cyberpanel.FenceCommand) error {
	h.mu.Lock(); defer h.mu.Unlock()
	receipt, err := h.command(command)
	if err != nil { return err }
	target := map[string]string{"unquiesce": "unquiesced", "rollback": "rolled_back", "commit": "committed"}[operation]
	if receipt.State == target { return nil }
	if receipt.State != "bound" { return cyberpanel.ErrDenied }
	if operation == "commit" {
		if !time.Now().UTC().Before(receipt.ExpiresAt) { return cyberpanel.ErrDenied }
		if err = verifyFence(ctx, receipt); err != nil { return err }
		receipt.State, receipt.UpdatedAt = target, time.Now().UTC(); return h.persist(receipt)
	}
	return h.restore(ctx, receipt, target)
}

func (h *helper) restore(ctx context.Context, receipt fenceReceipt, target string) error {
	receipt.State, receipt.RestoreTo, receipt.UpdatedAt = "restoring", target, time.Now().UTC()
	if err := h.persist(receipt); err != nil { return err }
	if err := restoreFence(ctx, receipt); err != nil { return err }
	receipt.State, receipt.RestoreTo, receipt.UpdatedAt = target, "", time.Now().UTC()
	return h.persist(receipt)
}

func (h *helper) command(command cyberpanel.FenceCommand) (fenceReceipt, error) {
	if !command.MigrationID.Valid() || command.SourceGeneration == 0 || command.ExpectedFence == 0 || !digest(command.FenceDigest) { return fenceReceipt{}, cyberpanel.ErrInvalid }
	receipt, err := h.find(func(value fenceReceipt) bool { return value.FenceDigest == command.FenceDigest })
	if err != nil { return receipt, err }
	if receipt.Request.MigrationID != command.MigrationID || receipt.SourceGeneration != command.SourceGeneration || receipt.Request.ExpectedFence != command.ExpectedFence { return receipt, cyberpanel.ErrDenied }
	return receipt, nil
}

func (h *helper) recover(ctx context.Context) error {
	h.mu.Lock(); defer h.mu.Unlock()
	receipts, err := h.receipts()
	if err != nil { return err }
	activeCount := 0
	for _, receipt := range receipts { if active(receipt.State) { activeCount++ } }
	if activeCount > 1 { return cyberpanel.ErrDenied }
	for _, receipt := range receipts {
		switch receipt.State {
		case "applying", "unbound":
			if err = h.restore(ctx, receipt, "aborted"); err != nil { return err }
		case "restoring":
			target := receipt.RestoreTo; if target == "" { target = "rolled_back" }
			if err = h.restore(ctx, receipt, target); err != nil { return err }
		case "bound":
			if !time.Now().UTC().Before(receipt.ExpiresAt) { if err = h.restore(ctx, receipt, "rolled_back"); err != nil { return err } } else if err = applyFence(ctx, receipt); err != nil { return err }
		case "committed":
			if err = applyFence(ctx, receipt); err != nil { return err }
		}
	}
	return nil
}

func (h *helper) expire(ctx context.Context) error {
	h.mu.Lock(); defer h.mu.Unlock(); receipts, err := h.receipts(); if err != nil { return err }
	for _, receipt := range receipts { if receipt.State == "bound" && !time.Now().UTC().Before(receipt.ExpiresAt) { if err = h.restore(ctx, receipt, "rolled_back"); err != nil { return err } } }
	return nil
}

func (h *helper) receipts() ([]fenceReceipt, error) {
	entries, err := os.ReadDir(h.config.StateDirectory)
	if err != nil || len(entries) > 4096 { return nil, errors.Join(err, cyberpanel.ErrInvalid) }
	values := make([]fenceReceipt, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".receipt.json") { continue }
		raw, readErr := readOwnedFile(filepath.Join(h.config.StateDirectory, entry.Name()), 0, 0o600, maximumFrameBytes)
		var receipt fenceReceipt
		if readErr == nil { readErr = decodeStrict(raw, &receipt) }
		if readErr != nil || receipt.Version != 1 || entry.Name() != receipt.Request.MigrationID.String()+".receipt.json" || !validReceipt(receipt) { return nil, errors.Join(readErr, cyberpanel.ErrInvalid) }
		values = append(values, receipt)
	}
	return values, nil
}

func (h *helper) find(match func(fenceReceipt) bool) (fenceReceipt, error) {
	values, err := h.receipts(); if err != nil { return fenceReceipt{}, err }
	for _, value := range values { if match(value) { return value, nil } }
	return fenceReceipt{}, migration.ErrNotFound
}

func (h *helper) persist(receipt fenceReceipt) error {
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > maximumFrameBytes { return errors.Join(err, cyberpanel.ErrInvalid) }
	temporary, err := os.CreateTemp(h.config.StateDirectory, ".receipt-")
	if err != nil { return err }
	name := temporary.Name(); defer os.Remove(name)
	if err = temporary.Chmod(0o600); err == nil { _, err = temporary.Write(encoded) }
	if err == nil { err = temporary.Sync() }
	closeErr := temporary.Close(); if err == nil { err = closeErr }
	if err != nil { return err }
	if err = os.Rename(name, filepath.Join(h.config.StateDirectory, receipt.Request.MigrationID.String()+".receipt.json")); err != nil { return err }
	directory, err := os.Open(h.config.StateDirectory); if err != nil { return err }; defer directory.Close(); return directory.Sync()
}

func observeServices(ctx context.Context, selection cyberpanel.ResourceSelection) ([]serviceReceipt, error) {
	units := []string{"lscpd.service"}
	if selection.Sites { units = append(units, "lsws.service") }
	if selection.DNS { units = append(units, "pdns.service") }
	if selection.Mail { units = append(units, "postfix.service", "dovecot.service") }
	if selection.Credentials { units = append(units, "pure-ftpd.service") }
	if selection.Schedules || selection.BackupPolicies { units = append(units, "cron.service", "crond.service") }
	if selection.Containers { units = append(units, "docker.service") }
	values := make([]serviceReceipt, 0, len(units))
	for _, unit := range units { loaded, active, err := serviceState(ctx, unit); if err != nil { return nil, err }; if loaded { values = append(values, serviceReceipt{Unit: unit, WasActive: active}) } }
	return values, nil
}

func applyFence(ctx context.Context, receipt fenceReceipt) error {
	for _, service := range receipt.Services { if err := runFixed(ctx, "/usr/bin/systemctl", "stop", service.Unit); err != nil { return err } }
	if receipt.DatabaseManaged { if err := setReadOnly(ctx, true); err != nil { return err } }
	return verifyFence(ctx, receipt)
}

func verifyFence(ctx context.Context, receipt fenceReceipt) error {
	for _, service := range receipt.Services { active, err := serviceActive(ctx, service.Unit); if err != nil { return err }; if active { return cyberpanel.ErrChanged } }
	if receipt.DatabaseManaged { value, err := readOnly(ctx); if err != nil { return err }; if !value { return cyberpanel.ErrChanged } }
	return nil
}

func restoreFence(ctx context.Context, receipt fenceReceipt) error {
	var failures []error
	if receipt.DatabaseManaged && !receipt.DatabaseWasReadOnly { failures = append(failures, setReadOnly(ctx, false)) }
	for index := len(receipt.Services)-1; index >= 0; index-- { if receipt.Services[index].WasActive { failures = append(failures, runFixed(ctx, "/usr/bin/systemctl", "start", receipt.Services[index].Unit)) } }
	return errors.Join(failures...)
}

func serviceActive(ctx context.Context, unit string) (bool, error) {
	loaded, active, err := serviceState(ctx, unit); if err != nil { return false, err }; if !loaded { return false, nil }; return active, nil
}

func serviceState(ctx context.Context, unit string) (bool, bool, error) {
	output, err := execFixed(ctx, "/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit)
	if err != nil { return false, false, err }
	state := strings.TrimSpace(string(output)); if state == "not-found" { return false, false, nil }; if state != "loaded" { return false, false, cyberpanel.ErrChanged }
	output, err = execFixed(ctx, "/usr/bin/systemctl", "is-active", unit)
	state = strings.TrimSpace(string(output))
	switch state { case "active", "activating", "reloading", "deactivating": return true, true, nil; case "inactive", "failed": return true, false, nil }
	return false, false, errors.Join(err, cyberpanel.ErrChanged)
}

func readOnly(ctx context.Context) (bool, error) {
	output, err := execFixed(ctx, "/usr/bin/mariadb", "--protocol=socket", "--batch", "--skip-column-names", "--execute=SELECT @@GLOBAL.read_only")
	if err != nil { return false, err }
	switch strings.TrimSpace(string(output)) { case "0": return false, nil; case "1": return true, nil; default: return false, cyberpanel.ErrChanged }
}

func setReadOnly(ctx context.Context, enabled bool) error {
	value := "OFF"; if enabled { value = "ON" }
	_, err := execFixed(ctx, "/usr/bin/mariadb", "--protocol=socket", "--batch", "--skip-column-names", "--execute=SET GLOBAL read_only="+value)
	return err
}

func execFixed(ctx context.Context, binary string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, binary, arguments...); command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}; return command.CombinedOutput()
}

func runFixed(ctx context.Context, binary string, arguments ...string) error { _, err := execFixed(ctx, binary, arguments...); return err }

func (r fenceReceipt) observation() cyberpanel.QuiesceObservation { return cyberpanel.QuiesceObservation{HandleID: r.HandleID, SourceGeneration: r.SourceGeneration, ExpiresAt: r.ExpiresAt, EvidenceDigest: r.EvidenceDigest} }
func evidence(receipt fenceReceipt) string { copy := receipt; copy.EvidenceDigest, copy.FenceDigest, copy.State, copy.RestoreTo, copy.UpdatedAt = "", "", "", "", time.Time{}; raw, _ := json.Marshal(struct{ Domain string `json:"domain"`; Receipt fenceReceipt `json:"receipt"` }{"cyberpanel-cutover-evidence-v1", copy}); sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func expectedFenceDigest(receipt fenceReceipt, fence migration.SourceFence) string { raw, _ := json.Marshal(struct{ Domain string `json:"domain"`; MigrationID migration.ID `json:"migration_id"`; Generation uint64 `json:"generation"`; Fence uint64 `json:"fence"`; ExpiresAt time.Time `json:"expires_at"`; TargetPlanDigest string `json:"target_plan_digest"`; ApprovalDigest string `json:"approval_digest"`; EvidenceDigest string `json:"evidence_digest"` }{"cyberpanel-source-fence-v1", fence.MigrationID, fence.Generation, fence.Fence, fence.ExpiresAt.UTC(), receipt.Request.TargetPlanDigest, receipt.Request.ApprovalDigest, receipt.EvidenceDigest}); sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func sameRequest(left, right cyberpanel.QuiesceRequest) bool { return left.MigrationID == right.MigrationID && left.SourceInstallationID == right.SourceInstallationID && sameStrings(left.SiteSourceIDs, right.SiteSourceIDs) && left.Mode == right.Mode && left.ExpectedFence == right.ExpectedFence && left.TargetPlanDigest == right.TargetPlanDigest && left.ApprovalDigest == right.ApprovalDigest }
func sameStrings(left, right []string) bool { if len(left) != len(right) { return false }; for index := range left { if left[index] != right[index] { return false } }; return true }
func sameSet(left, right []string) bool { left = append([]string(nil), left...); right = append([]string(nil), right...); sort.Strings(left); sort.Strings(right); return sameStrings(left, right) }
func active(state string) bool { return state == "applying" || state == "unbound" || state == "bound" || state == "restoring" || state == "committed" }
func validReceipt(value fenceReceipt) bool { if !value.Request.MigrationID.Valid() || !bounded(value.Request.SourceInstallationID, 256) || value.Request.Mode != "service_fence" || value.Request.ExpectedFence == 0 || !digest(value.Request.TargetPlanDigest) || !digest(value.Request.ApprovalDigest) || !handleID(value.HandleID) || value.SourceGeneration == 0 || value.ExpiresAt.IsZero() || !digest(value.EvidenceDigest) || evidence(value) != value.EvidenceDigest || len(value.Services) == 0 && !value.DatabaseManaged || (value.State == "bound" || value.State == "committed" || value.State == "unquiesced" || value.State == "rolled_back") && !digest(value.FenceDigest) { return false }; switch value.State { case "applying", "unbound", "bound", "restoring", "aborted", "unquiesced", "rolled_back", "committed": default: return false }; if value.State == "restoring" && value.RestoreTo != "aborted" && value.RestoreTo != "unquiesced" && value.RestoreTo != "rolled_back" || value.State != "restoring" && value.RestoreTo != "" { return false }; allowed := map[string]bool{"lscpd.service": true, "lsws.service": true, "pdns.service": true, "postfix.service": true, "dovecot.service": true, "pure-ftpd.service": true, "cron.service": true, "crond.service": true, "docker.service": true}; seen := map[string]bool{}; for _, service := range value.Services { if !allowed[service.Unit] || seen[service.Unit] { return false }; seen[service.Unit] = true }; return true }
func digest(value string) bool { if len(value) != 64 || value != strings.ToLower(value) { return false }; _, err := hex.DecodeString(value); return err == nil }
func requestID(value string) bool { return strings.HasPrefix(value, "helper_") && len(value) == 55 && hexText(strings.TrimPrefix(value, "helper_")) }
func handleID(value string) bool { return strings.HasPrefix(value, "fence_") && len(value) == 54 && hexText(strings.TrimPrefix(value, "fence_")) }
func hexText(value string) bool { _, err := hex.DecodeString(value); return err == nil && value == strings.ToLower(value) }
func randomID(prefix string) (string, error) { raw := make([]byte, 24); if _, err := io.ReadFull(rand.Reader, raw); err != nil { return "", err }; return prefix + hex.EncodeToString(raw), nil }
func bounded(value string, maximum int) bool { return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00") }
func canonicalPath(value string) bool { return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value }

func validateDirectory(path string, uid, gid uint32, mode os.FileMode) error {
	info, err := os.Lstat(path); if err != nil { return err }; stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || stat.Uid != uid || stat.Gid != gid { return cyberpanel.ErrDenied }
	resolved, err := filepath.EvalSymlinks(path); if err != nil || resolved != path { return errors.Join(err, cyberpanel.ErrDenied) }; return nil
}

func readOwnedFile(path string, uid uint32, mode os.FileMode, maximum int64) ([]byte, error) {
	if !canonicalPath(path) { return nil, cyberpanel.ErrInvalid }
	before, err := os.Lstat(path); if err != nil { return nil, err }; stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != mode || stat.Uid != uid || before.Size() < 2 || before.Size() > maximum { return nil, cyberpanel.ErrDenied }
	file, err := os.Open(path); if err != nil { return nil, err }; defer file.Close(); after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) { return nil, errors.Join(err, cyberpanel.ErrChanged) }
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1)); if err != nil || int64(len(raw)) != after.Size() { return nil, errors.Join(err, cyberpanel.ErrChanged) }
	final, err := file.Stat(); if err != nil { return nil, err }; finalStat, finalOK := final.Sys().(*syscall.Stat_t); if !finalOK || !os.SameFile(after, final) || !final.Mode().IsRegular() || final.Mode().Perm() != mode || finalStat.Uid != uid || final.Size() != after.Size() || final.ModTime() != after.ModTime() { return nil, cyberpanel.ErrChanged }; return raw, nil
}

func decodeStrict(raw []byte, target any) error { decoder := json.NewDecoder(bytes.NewReader(raw)); decoder.DisallowUnknownFields(); if err := decoder.Decode(target); err != nil { return cyberpanel.ErrInvalid }; var trailing any; if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) { return cyberpanel.ErrInvalid }; return nil }
func peerCredentials(connection *net.UnixConn) (*syscall.Ucred, error) { raw, err := connection.SyscallConn(); if err != nil { return nil, err }; var credentials *syscall.Ucred; var controlErr error; err = raw.Control(func(fd uintptr) { credentials, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) }); return credentials, errors.Join(err, controlErr) }
func readFrame(reader io.Reader) ([]byte, error) { var header [4]byte; if _, err := io.ReadFull(reader, header[:]); err != nil { return nil, err }; size := binary.BigEndian.Uint32(header[:]); if size == 0 || size > maximumFrameBytes { return nil, cyberpanel.ErrInvalid }; value := make([]byte, size); _, err := io.ReadFull(reader, value); return value, err }
func writeFrame(writer io.Writer, value []byte) error { if len(value) == 0 || len(value) > maximumFrameBytes { return cyberpanel.ErrInvalid }; var header [4]byte; binary.BigEndian.PutUint32(header[:], uint32(len(value))); if _, err := writer.Write(header[:]); err != nil { return err }; count, err := writer.Write(value); if err == nil && count != len(value) { err = io.ErrShortWrite }; return err }
func errorCode(err error) string { switch { case errors.Is(err, cyberpanel.ErrInvalid), errors.Is(err, migration.ErrInvalid): return "INVALID_REQUEST"; case errors.Is(err, cyberpanel.ErrDenied): return "DENIED"; case errors.Is(err, cyberpanel.ErrChanged): return "CHANGED"; case errors.Is(err, migration.ErrNotFound), errors.Is(err, os.ErrNotExist): return "NOT_FOUND"; default: return "INTERNAL" } }
