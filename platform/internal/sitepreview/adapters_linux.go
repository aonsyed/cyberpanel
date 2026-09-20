//go:build linux

package sitepreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/executor/webactivation"
	hostingservice "github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/noderelease"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/enterprise"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
)

const (
	DefaultLinuxRouteRoot       = "/var/lib/cyberpanel/sitepreview/routes"
	DefaultLinuxArtifactRoot    = "/var/lib/cyberpanel/sitepreview/artifacts"
	DefaultLinuxRouteHelper     = "/usr/local/libexec/cyberpanel/cyberpanel-sitepreview-route"
	DefaultLinuxChromiumHelper  = "/usr/local/libexec/cyberpanel/cyberpanel-sitepreview-chromium"
	linuxAdapterProtocolVersion = uint16(1)
	linuxChromeIsolateArgument  = "--cyberpanel-sitepreview-isolate"
	linuxUnshareExecutable      = "/usr/bin/unshare"
	linuxIPExecutable           = "/usr/sbin/ip"
	linuxControlDatabase        = "/var/lib/cyberpanel/control/control.db"
)

type LinuxRouteRuntime struct {
	root   string
	helper string
	mutex  sync.Mutex
}

func NewLinuxRouteRuntime(root, helper string) (*LinuxRouteRuntime, error) {
	if root == "" {
		root = DefaultLinuxRouteRoot
	}
	if helper == "" {
		helper = DefaultLinuxRouteHelper
	}
	if root != DefaultLinuxRouteRoot || helper != DefaultLinuxRouteHelper || ensureLinuxPrivateDirectory(root) != nil || validateRootHelper(helper) != nil {
		return nil, ErrPolicyDenied
	}
	return &LinuxRouteRuntime{root: root, helper: helper}, nil
}

type linuxRouteManifest struct {
	Version uint16    `json:"version"`
	Digest  string    `json:"digest"`
	Spec    RouteSpec `json:"spec"`
}
type linuxRouteHelperRequest struct {
	Version     uint16     `json:"version"`
	Operation   string     `json:"operation"`
	ManifestRef string     `json:"manifest_ref"`
	SpecDigest  string     `json:"spec_digest"`
	Lease       RouteLease `json:"lease,omitempty"`
}

func (runtime *LinuxRouteRuntime) InstallExactPreview(ctx context.Context, spec RouteSpec) (RouteEffectReceipt, error) {
	return runtime.apply(ctx, "install", spec, RouteLease{})
}
func (runtime *LinuxRouteRuntime) ObserveExactPreview(ctx context.Context, spec RouteSpec, lease RouteLease) (RouteEffectReceipt, error) {
	return runtime.apply(ctx, "observe", spec, lease)
}
func (runtime *LinuxRouteRuntime) ExpireExactPreview(ctx context.Context, spec RouteSpec, lease RouteLease) (RouteEffectReceipt, error) {
	return runtime.apply(ctx, "expire", spec, lease)
}
func (runtime *LinuxRouteRuntime) RollbackExactPreview(ctx context.Context, spec RouteSpec, lease RouteLease) (RouteEffectReceipt, error) {
	return runtime.apply(ctx, "rollback", spec, lease)
}

func (runtime *LinuxRouteRuntime) apply(ctx context.Context, operation string, spec RouteSpec, lease RouteLease) (RouteEffectReceipt, error) {
	if runtime == nil || ctx == nil || spec.Validate() != nil || !validRouteOperation(operation) {
		return RouteEffectReceipt{}, ErrInvalid
	}
	if operation != "install" {
		if lease.Validate() != nil || lease.SessionID != spec.SessionID || lease.SpecDigest != digestJSON("cyberpanel:sitepreview:route:v1", spec) {
			return RouteEffectReceipt{}, ErrInvalid
		}
	} else if lease != (RouteLease{}) {
		return RouteEffectReceipt{}, ErrInvalid
	}
	runtime.mutex.Lock()
	defer runtime.mutex.Unlock()
	if ensureLinuxPrivateDirectory(runtime.root) != nil || validateRootHelper(runtime.helper) != nil {
		return RouteEffectReceipt{}, ErrPolicyDenied
	}
	specDigest := digestJSON("cyberpanel:sitepreview:route:v1", spec)
	manifest := linuxRouteManifest{Version: linuxAdapterProtocolVersion, Digest: specDigest, Spec: spec}
	if err := stageRouteManifest(runtime.root, manifest); err != nil {
		return RouteEffectReceipt{}, err
	}
	request := linuxRouteHelperRequest{Version: linuxAdapterProtocolVersion, Operation: operation, ManifestRef: "route-" + specDigest, SpecDigest: specDigest, Lease: lease}
	var receipt RouteEffectReceipt
	if err := invokeFixedHelper(ctx, runtime.helper, request, &receipt, 256<<10); err != nil {
		return RouteEffectReceipt{Outcome: RouteAmbiguous}, errors.Join(ErrAmbiguous, err)
	}
	if receipt.Validate(spec) != nil {
		return RouteEffectReceipt{Outcome: RouteAmbiguous}, ErrIntegrity
	}
	switch operation {
	case "install", "observe":
		if receipt.Outcome != RouteApplied && receipt.Outcome != RouteAmbiguous {
			return RouteEffectReceipt{}, ErrIntegrity
		}
	case "expire":
		if receipt.Outcome != RouteAbsent && receipt.Outcome != RouteAmbiguous {
			return RouteEffectReceipt{}, ErrIntegrity
		}
	case "rollback":
		if receipt.Outcome != RouteRolledBack && receipt.Outcome != RouteAmbiguous {
			return RouteEffectReceipt{}, ErrIntegrity
		}
	}
	if receipt.Outcome == RouteApplied && (!receipt.Lease.ExpiresAt.Equal(spec.ExpiresAt) || receipt.Lease.RollbackUntil.Before(spec.ExpiresAt)) {
		return RouteEffectReceipt{}, ErrIntegrity
	}
	return receipt, nil
}

func validRouteOperation(value string) bool {
	return value == "install" || value == "observe" || value == "expire" || value == "rollback"
}

func stageRouteManifest(root string, manifest linuxRouteManifest) error {
	if manifest.Version != linuxAdapterProtocolVersion || !validDigest(manifest.Digest) || manifest.Spec.Validate() != nil || manifest.Digest != digestJSON("cyberpanel:sitepreview:route:v1", manifest.Spec) {
		return ErrInvalid
	}
	directory := filepath.Join(root, "generations")
	if err := ensureLinuxPrivateDirectory(directory); err != nil {
		return err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded) == 0 || len(encoded) > 128<<10 {
		return ErrInvalid
	}
	path := filepath.Join(directory, "route-"+manifest.Digest+".json")
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if bytes.Equal(existing, encoded) {
			return nil
		}
		return ErrIntegrity
	} else if !errors.Is(readErr, fs.ErrNotExist) {
		return readErr
	}
	temporary := path + ".staging"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(encoded); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Link(temporary, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			existing, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(existing, encoded) {
				return ErrIntegrity
			}
		} else {
			return err
		}
	}
	if err = os.Remove(temporary); err != nil {
		return err
	}
	ok = true
	return syncDirectory(directory)
}

type LinuxChromeNamespace struct{ helper string }

func NewLinuxChromeNamespace(helper string) (*LinuxChromeNamespace, error) {
	if helper == "" {
		helper = DefaultLinuxChromiumHelper
	}
	if helper != DefaultLinuxChromiumHelper || validateRootHelper(helper) != nil {
		return nil, ErrPolicyDenied
	}
	return &LinuxChromeNamespace{helper: helper}, nil
}

type linuxChromeHelperRequest struct {
	Version uint16       `json:"version"`
	Launch  ChromeLaunch `json:"launch"`
}

func (namespace *LinuxChromeNamespace) RunIsolatedChrome(ctx context.Context, launch ChromeLaunch) (NavigationReceipt, error) {
	if namespace == nil || ctx == nil || launch.Validate() != nil || validateRootHelper(namespace.helper) != nil {
		return NavigationReceipt{}, ErrInvalid
	}
	var receipt NavigationReceipt
	if err := invokeFixedHelper(ctx, namespace.helper, linuxChromeHelperRequest{Version: linuxAdapterProtocolVersion, Launch: launch}, &receipt, 512<<10); err != nil {
		return NavigationReceipt{}, err
	}
	if receipt.JobID != launch.JobID || !receipt.ProfileIsolated || !receipt.ExtensionsOff || !receipt.DownloadsOff || !receipt.CredentialsOff || !receipt.FileURLsOff || !receipt.DataURLsOff || !validDigest(receipt.EvidenceDigest) ||
		receipt.StartedAt.IsZero() || receipt.FinishedAt.Before(receipt.StartedAt) || receipt.FinishedAt.After(launch.Deadline) || receipt.ResponseBytes == 0 || receipt.ResponseBytes > launch.MaximumResponseBytes || len(receipt.Hops) == 0 || len(receipt.Hops) > int(launch.MaximumRedirects)+1 {
		return NavigationReceipt{}, ErrIntegrity
	}
	for _, hop := range receipt.Hops {
		if hop.ResolvedAddress.Unmap() != launch.AllowedEndpoint.Addr().Unmap() {
			return NavigationReceipt{}, ErrPolicyDenied
		}
	}
	return receipt, nil
}

type LinuxArtifactStore struct {
	root  string
	mutex sync.Mutex
}

func NewLinuxArtifactStore(root string) (*LinuxArtifactStore, error) {
	if root == "" {
		root = DefaultLinuxArtifactRoot
	}
	if root != DefaultLinuxArtifactRoot || ensureLinuxPrivateDirectory(root) != nil {
		return nil, ErrPolicyDenied
	}
	return &LinuxArtifactStore{root: root}, nil
}

func (store *LinuxArtifactStore) PutScreenshot(ctx context.Context, job ScreenshotJob, mediaType string, source io.Reader, maximum uint64) (ArtifactStorageReceipt, error) {
	if store == nil || ctx == nil || job.Validate() != nil || mediaType != "image/png" || source == nil || maximum == 0 || maximum > MaximumScreenshotBytes {
		return ArtifactStorageReceipt{}, ErrInvalid
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if err := ensureLinuxPrivateDirectory(store.root); err != nil {
		return ArtifactStorageReceipt{}, err
	}
	tenantDirectory := filepath.Join(store.root, string(job.TenantID))
	if err := ensureLinuxPrivateDirectory(tenantDirectory); err != nil {
		return ArtifactStorageReceipt{}, err
	}
	temporary := filepath.Join(tenantDirectory, "job-"+string(job.ID)+"-g"+fmt.Sprint(job.Generation)+".part")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ArtifactStorageReceipt{}, err
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(temporary)
		}
	}()
	hasher := sha256.New()
	limited := &io.LimitedReader{R: source, N: int64(maximum) + 1}
	written, err := io.Copy(io.MultiWriter(file, hasher), limited)
	if err != nil {
		return ArtifactStorageReceipt{}, err
	}
	if written <= 0 || uint64(written) > maximum {
		return ArtifactStorageReceipt{}, ErrPolicyDenied
	}
	if err = file.Sync(); err != nil {
		return ArtifactStorageReceipt{}, err
	}
	if err = file.Close(); err != nil {
		return ArtifactStorageReceipt{}, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	reference := artifactStorageReference(job, digest)
	final := filepath.Join(tenantDirectory, reference+".png")
	if err = os.Link(temporary, final); err != nil {
		return ArtifactStorageReceipt{}, err
	}
	if err = os.Remove(temporary); err != nil {
		return ArtifactStorageReceipt{}, err
	}
	keep = true
	if err = syncDirectory(tenantDirectory); err != nil {
		return ArtifactStorageReceipt{}, err
	}
	return ArtifactStorageReceipt{StorageRef: reference, ByteSize: uint64(written), Digest: digest}, nil
}

func (store *LinuxArtifactStore) DiscardScreenshot(ctx context.Context, job ScreenshotJob, receipt ArtifactStorageReceipt) error {
	if store == nil || ctx == nil || job.Validate() != nil || receipt.Validate(job.Limits.MaximumBytes) != nil || receipt.StorageRef != artifactStorageReference(job, receipt.Digest) {
		return ErrInvalid
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	directory := filepath.Join(store.root, string(job.TenantID))
	if ensureLinuxPrivateDirectory(directory) != nil {
		return ErrPolicyDenied
	}
	path := filepath.Join(directory, receipt.StorageRef+".png")
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return ErrIntegrity
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func artifactStorageReference(job ScreenshotJob, digest string) string {
	sum := sha256.Sum256([]byte("cyberpanel:sitepreview:artifact-storage:v1\x00" + string(job.TenantID) + "\x00" + string(job.ID) + "\x00" + digest))
	return "png-" + hex.EncodeToString(sum[:])
}

func invokeFixedHelper(ctx context.Context, helper string, request any, response any, maximum int) error {
	if ctx == nil || validateRootHelper(helper) != nil || response == nil || maximum < 1024 || maximum > 1<<20 {
		return ErrInvalid
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) == 0 || len(encoded) > 256<<10 {
		return ErrInvalid
	}
	output := &limitedBuffer{maximum: maximum}
	resolved, err := resolveRootHelper(helper)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, resolved)
	command.Stdin = bytes.NewReader(encoded)
	command.Stdout = output
	command.Stderr = io.Discard
	if err = command.Run(); err != nil {
		return err
	}
	if output.overflow {
		return ErrIntegrity
	}
	if err = decodeStored(output.content, response); err != nil {
		return err
	}
	return nil
}

type limitedBuffer struct {
	content  []byte
	maximum  int
	overflow bool
}

func (buffer *limitedBuffer) Write(content []byte) (int, error) {
	if buffer.overflow {
		return 0, ErrIntegrity
	}
	if len(buffer.content)+len(content) > buffer.maximum {
		buffer.overflow = true
		return 0, ErrIntegrity
	}
	buffer.content = append(buffer.content, content...)
	return len(content), nil
}

func validateRootHelper(path string) error {
	_, err := resolveRootHelper(path)
	return err
}

func resolveRootHelper(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || (path != DefaultLinuxRouteHelper && path != DefaultLinuxChromiumHelper) {
		return "", ErrPolicyDenied
	}
	resolved, err := noderelease.ResolveSitePreviewHelperPath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return "", ErrPolicyDenied
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return "", ErrPolicyDenied
	}
	return resolved, nil
}

func ensureLinuxPrivateDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || (!withinLinuxRoot(path, DefaultLinuxRouteRoot) && !withinLinuxRoot(path, DefaultLinuxArtifactRoot)) {
		return ErrPolicyDenied
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrPolicyDenied
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return ErrPolicyDenied
	}
	return nil
}

func withinLinuxRoot(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(os.PathSeparator))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// RunLinuxRouteHelper serves the closed stdin/stdout protocol used by
// LinuxRouteRuntime. It accepts only manifests already staged below the fixed
// route root and persists the exact effect receipt before returning it.
func RunLinuxRouteHelper(ctx context.Context, input io.Reader, output io.Writer) error {
	if ctx == nil || input == nil || output == nil {
		return ErrInvalid
	}
	var request linuxRouteHelperRequest
	if err := decodeHelperRequest(input, &request, 256<<10); err != nil || request.Version != linuxAdapterProtocolVersion || !validRouteOperation(request.Operation) ||
		request.ManifestRef != "route-"+request.SpecDigest || !validDigest(request.SpecDigest) {
		return ErrInvalid
	}
	manifest, err := loadRouteManifest(request.ManifestRef, request.SpecDigest)
	if err != nil {
		return err
	}
	receipt, err := applyRouteHelper(ctx, request, manifest.Spec)
	if err != nil {
		return err
	}
	return encodeHelperResponse(output, receipt)
}

func loadRouteManifest(reference, digest string) (linuxRouteManifest, error) {
	var manifest linuxRouteManifest
	path := filepath.Join(DefaultLinuxRouteRoot, "generations", reference+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 128<<10 {
		return manifest, errors.Join(ErrIntegrity, err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return manifest, ErrIntegrity
	}
	content, err := os.ReadFile(path)
	if err != nil || decodeStored(content, &manifest) != nil || manifest.Version != linuxAdapterProtocolVersion || manifest.Digest != digest ||
		manifest.Spec.Validate() != nil || digestJSON("cyberpanel:sitepreview:route:v1", manifest.Spec) != digest {
		return linuxRouteManifest{}, errors.Join(ErrIntegrity, err)
	}
	return manifest, nil
}

func applyRouteHelper(ctx context.Context, request linuxRouteHelperRequest, spec RouteSpec) (RouteEffectReceipt, error) {
	stateRoot := filepath.Join(DefaultLinuxRouteRoot, "active")
	if err := ensureLinuxPrivateDirectory(stateRoot); err != nil {
		return RouteEffectReceipt{}, err
	}
	route, err := exactPreviewProxyRoute(spec)
	if err != nil {
		return RouteEffectReceipt{}, err
	}
	webCatalog, database, err := openExactPreviewCatalog(ctx)
	if err != nil {
		return RouteEffectReceipt{}, err
	}
	defer database.Close()
	path := filepath.Join(stateRoot, "route-"+request.SpecDigest+".json")
	stored, found, err := loadRouteEffect(path, spec)
	if err != nil {
		return RouteEffectReceipt{}, err
	}
	if request.Operation == "install" {
		if request.Lease != (RouteLease{}) {
			return RouteEffectReceipt{}, ErrInvalid
		}
		if !time.Now().UTC().Before(spec.ExpiresAt) {
			return RouteEffectReceipt{}, ErrExpired
		}
		if found && stored.Outcome != RouteApplied {
			return RouteEffectReceipt{}, ErrConflict
		}
		installed, plan, err := exactPreviewRouteState(ctx, webCatalog, route)
		if err != nil {
			return RouteEffectReceipt{}, err
		}
		installedBefore := installed
		if !installed {
			plan, err = applyExactPreviewRoute(ctx, webCatalog, route, false, request.SpecDigest)
			if err != nil {
				return RouteEffectReceipt{}, err
			}
		}
		proof, probeErr := probeInstalledPreviewRoute(ctx, spec, plan)
		if probeErr != nil {
			var rollbackErr error
			if !installedBefore {
				_, rollbackErr = applyExactPreviewRoute(ctx, webCatalog, route, true, request.SpecDigest)
			}
			return RouteEffectReceipt{}, errors.Join(probeErr, rollbackErr)
		}
		if found {
			stored.Proof = proof
			stored.EvidenceDigest = routeHelperReceipt(RouteApplied, stored.Lease, proof).EvidenceDigest
			if err = saveRouteEffect(path, stored, spec); err != nil {
				return RouteEffectReceipt{}, err
			}
			return stored, nil
		}
		now := proof.ObservedAt
		lease := RouteLease{ID: RouteLeaseID("lease-" + request.SpecDigest[:48]), SessionID: spec.SessionID, SpecDigest: request.SpecDigest,
			RuntimeToken: "route-" + request.SpecDigest[:48], State: "active", Generation: 1, ExpiresAt: spec.ExpiresAt.UTC(), RollbackUntil: spec.ExpiresAt.UTC().Add(15 * time.Minute), UpdatedAt: now}
		receipt := routeHelperReceipt(RouteApplied, lease, proof)
		if err = saveRouteEffect(path, receipt, spec); err != nil {
			_, rollbackErr := applyExactPreviewRoute(ctx, webCatalog, route, true, request.SpecDigest)
			return RouteEffectReceipt{}, errors.Join(err, rollbackErr)
		}
		return receipt, nil
	}
	if request.Lease.Validate() != nil || request.Lease.SessionID != spec.SessionID || request.Lease.SpecDigest != request.SpecDigest || !found || !sameRouteLeaseIdentity(stored.Lease, request.Lease) {
		return RouteEffectReceipt{}, ErrIntegrity
	}
	wantOutcome, wantState := RouteApplied, "active"
	switch request.Operation {
	case "expire":
		wantOutcome, wantState = RouteAbsent, "expired"
	case "rollback":
		wantOutcome, wantState = RouteRolledBack, "rolled_back"
	}
	if stored.Lease.Generation == request.Lease.Generation+1 {
		if stored.Outcome != wantOutcome || stored.Lease.State != wantState {
			return RouteEffectReceipt{}, ErrConflict
		}
		return stored, nil
	}
	if stored.Lease.Generation != request.Lease.Generation || stored.Lease.State != request.Lease.State {
		return RouteEffectReceipt{}, ErrConflict
	}
	var proof RouteProof
	if request.Operation == "observe" {
		if stored.Lease.State != "active" || !time.Now().UTC().Before(spec.ExpiresAt) {
			return RouteEffectReceipt{}, ErrExpired
		}
		installed, plan, stateErr := exactPreviewRouteState(ctx, webCatalog, route)
		if stateErr != nil || !installed {
			return RouteEffectReceipt{}, errors.Join(ErrIntegrity, stateErr)
		}
		proof, err = probeInstalledPreviewRoute(ctx, spec, plan)
		if err != nil {
			return RouteEffectReceipt{}, err
		}
	} else {
		installed, _, stateErr := exactPreviewRouteState(ctx, webCatalog, route)
		if stateErr != nil {
			return RouteEffectReceipt{}, stateErr
		}
		if installed {
			if _, err = applyExactPreviewRoute(ctx, webCatalog, route, true, request.SpecDigest); err != nil {
				return RouteEffectReceipt{}, err
			}
		}
		if installed, _, err = exactPreviewRouteState(ctx, webCatalog, route); err != nil || installed {
			return RouteEffectReceipt{}, errors.Join(ErrAmbiguous, err)
		}
	}
	lease := stored.Lease
	lease.State, lease.Generation, lease.UpdatedAt = wantState, lease.Generation+1, time.Now().UTC()
	if request.Operation == "observe" {
		lease.UpdatedAt = proof.ObservedAt
	}
	receipt := routeHelperReceipt(wantOutcome, lease, proof)
	if err = saveRouteEffect(path, receipt, spec); err != nil {
		return RouteEffectReceipt{}, err
	}
	return receipt, nil
}

type deniedSiteInputResolver struct{}

func (deniedSiteInputResolver) Resolve(context.Context, hostingservice.SiteEffectRequest) (composer.SiteInput, error) {
	return composer.SiteInput{}, ErrPolicyDenied
}

func exactPreviewProxyRoute(spec RouteSpec) (composer.ProxyRouteInput, error) {
	preview, previewErr := webengine.ParseHostname(spec.PreviewHostname)
	host, hostErr := webengine.ParseHostname(spec.HostHeader)
	if previewErr != nil || hostErr != nil || spec.Backend.Protocol != BackendHTTP || !spec.Backend.Address.IsLoopback() || spec.Backend.Address.Zone() != "" || spec.SNI != spec.HostHeader {
		return composer.ProxyRouteInput{}, ErrPolicyDenied
	}
	return composer.ProxyRouteInput{Ref: webengine.ResourceRef("sitepreview/" + string(spec.SessionID)), Hostname: preview, UpstreamAddress: spec.Backend.Address.Unmap(), UpstreamPort: spec.Backend.Port, HostHeader: host, Generation: spec.SiteGeneration}, nil
}

func openExactPreviewCatalog(ctx context.Context) (*catalog.SQLCatalog, *sql.DB, error) {
	info, err := os.Lstat(linuxControlDatabase)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, nil, errors.Join(ErrPolicyDenied, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() {
		return nil, nil, ErrPolicyDenied
	}
	database, err := sql.Open("sqlite", "file:"+linuxControlDatabase+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=trusted_schema(0)")
	if err != nil {
		return nil, nil, err
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	if err = database.PingContext(ctx); err != nil {
		database.Close()
		return nil, nil, err
	}
	opened, err := os.Stat(linuxControlDatabase)
	if err != nil || !os.SameFile(info, opened) {
		database.Close()
		return nil, nil, errors.Join(ErrPolicyDenied, err)
	}
	webCatalog, err := catalog.New(database, deniedSiteInputResolver{})
	if err != nil {
		database.Close()
		return nil, nil, err
	}
	return webCatalog, database, nil
}

func exactPreviewRouteState(ctx context.Context, webCatalog *catalog.SQLCatalog, wanted composer.ProxyRouteInput) (bool, composer.Plan, error) {
	plan, err := webCatalog.CurrentPlan(ctx)
	if err != nil {
		return false, composer.Plan{}, err
	}
	found := false
	for _, route := range plan.ProxyRoutes {
		if route.Ref == wanted.Ref {
			if found || route != wanted {
				return false, composer.Plan{}, ErrConflict
			}
			found = true
		} else if route.Hostname == wanted.Hostname {
			return false, composer.Plan{}, ErrConflict
		}
	}
	return found, plan, nil
}

func applyExactPreviewRoute(ctx context.Context, webCatalog *catalog.SQLCatalog, route composer.ProxyRouteInput, withdraw bool, specDigest string) (composer.Plan, error) {
	current, err := webCatalog.CurrentPlan(ctx)
	if err != nil {
		return composer.Plan{}, err
	}
	operation := "install"
	if withdraw {
		operation = "withdraw"
	}
	effectID := "sitepreview-" + operation + "-" + specDigest[:32] + "-g" + strconv.FormatUint(current.SnapshotGeneration, 10)
	prepared, err := webCatalog.PrepareProxyRoute(ctx, effectID, route, withdraw)
	if err != nil {
		return composer.Plan{}, err
	}
	request, digest, err := renderExactPreviewPlan(ctx, prepared.Plan)
	if err != nil {
		_ = webCatalog.RejectProxyRoute(ctx, prepared)
		return composer.Plan{}, err
	}
	client, err := webactivation.NewLocalClient()
	if err != nil {
		_ = webCatalog.RejectProxyRoute(ctx, prepared)
		return composer.Plan{}, err
	}
	receipt, activateErr := client.ApplyVerified(ctx, request, digest)
	if activateErr != nil || receipt.Status != activation.Applied || !receipt.Confirmed || receipt.Digest != digest {
		return composer.Plan{}, errors.Join(ErrAmbiguous, activateErr)
	}
	if err = webCatalog.FinalizeProxyRoute(ctx, prepared, receipt.Digest); err != nil {
		return composer.Plan{}, errors.Join(ErrAmbiguous, err)
	}
	return prepared.Plan, nil
}

func renderExactPreviewPlan(ctx context.Context, plan composer.Plan) (native.RenderRequest, string, error) {
	composed, err := composer.Compose(plan)
	if err != nil {
		return native.RenderRequest{}, "", err
	}
	request := native.RenderRequest{Desired: composed.Desired, Snapshot: composed.Snapshot}
	var renderer native.Renderer
	switch composed.Desired.Engine.Edition {
	case webengine.EditionOpenLiteSpeed:
		renderer = ols.New()
	case webengine.EditionLiteSpeedEnterprise:
		renderer = enterprise.New()
	default:
		return native.RenderRequest{}, "", ErrPolicyDenied
	}
	generation, err := renderer.Render(ctx, request)
	if err != nil {
		return native.RenderRequest{}, "", err
	}
	return request, generation.ContentDigest, nil
}

func probeInstalledPreviewRoute(ctx context.Context, spec RouteSpec, plan composer.Plan) (RouteProof, error) {
	_, activeDigest, err := renderExactPreviewPlan(ctx, plan)
	if err != nil {
		return RouteProof{}, err
	}
	port := uint16(0)
	for _, listener := range plan.Engine.Listeners {
		if listener.Ref == webengine.ResourceRef("listener/https") && listener.TLSMode == webengine.TLSModeTLS {
			if port != 0 {
				return RouteProof{}, ErrIntegrity
			}
			port = listener.Port
		}
	}
	if port == 0 {
		return RouteProof{}, ErrIntegrity
	}
	endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(dialCtx, network, endpoint)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: spec.PreviewHostname}, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(spec.PreviewHostname, strconv.Itoa(int(port)))+"/", nil)
	if err != nil {
		return RouteProof{}, err
	}
	request.Host = spec.PreviewHostname
	response, err := transport.RoundTrip(request)
	if err != nil {
		return RouteProof{}, err
	}
	_, readErr := io.CopyN(io.Discard, response.Body, 1)
	closeErr := response.Body.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || response.StatusCode < 200 || response.StatusCode >= 500 {
		return RouteProof{}, errors.Join(ErrPolicyDenied, readErr, closeErr)
	}
	now := time.Now().UTC()
	evidence := digestJSON("cyberpanel:sitepreview:installed-route:v1", struct {
		SpecDigest   string
		ActiveDigest string
		Status       int
		ObservedAt   time.Time
	}{specDigest(spec), activeDigest, response.StatusCode, now})
	proof := RouteProof{SpecDigest: specDigest(spec), Engine: spec.Engine, HostProved: true, SNIProved: response.TLS != nil,
		PHPGeneration: spec.PHPGeneration, TLSGeneration: spec.TLSGeneration, CacheGeneration: spec.CacheGeneration, WAFGeneration: spec.WAFGeneration,
		SiteGeneration: spec.SiteGeneration, ObservedAt: now, EvidenceDigest: evidence}
	if !proof.ValidFor(spec) {
		return RouteProof{}, ErrIntegrity
	}
	return proof, nil
}

func sameRouteLeaseIdentity(left, right RouteLease) bool {
	return left.ID == right.ID && left.SessionID == right.SessionID && left.SpecDigest == right.SpecDigest && left.RuntimeToken == right.RuntimeToken &&
		left.ExpiresAt.Equal(right.ExpiresAt) && left.RollbackUntil.Equal(right.RollbackUntil)
}

func routeHelperReceipt(outcome RouteEffectOutcome, lease RouteLease, proof RouteProof) RouteEffectReceipt {
	value := struct {
		Outcome RouteEffectOutcome
		Lease   RouteLease
		Proof   RouteProof
	}{outcome, lease, proof}
	return RouteEffectReceipt{Outcome: outcome, Lease: lease, Proof: proof, EvidenceDigest: digestJSON("cyberpanel:sitepreview:route-effect:v1", value)}
}

func loadRouteEffect(path string, spec RouteSpec) (RouteEffectReceipt, bool, error) {
	var receipt RouteEffectReceipt
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return receipt, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 256<<10 {
		return receipt, false, errors.Join(ErrIntegrity, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || decodeStored(content, &receipt) != nil || receipt.Validate(spec) != nil {
		return RouteEffectReceipt{}, false, errors.Join(ErrIntegrity, err)
	}
	return receipt, true, nil
}

func saveRouteEffect(path string, receipt RouteEffectReceipt, spec RouteSpec) error {
	if receipt.Validate(spec) != nil {
		return ErrIntegrity
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) == 0 || len(encoded) > 256<<10 {
		return ErrIntegrity
	}
	temporary := path + ".new-" + strconv.Itoa(os.Getpid())
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, fs.ErrExist) {
		_ = os.Remove(temporary)
		file, err = os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	}
	if err != nil {
		return err
	}
	writeErr := func() error {
		if _, writeErr := file.Write(encoded); writeErr != nil {
			return writeErr
		}
		if syncErr := file.Sync(); syncErr != nil {
			return syncErr
		}
		return file.Close()
	}()
	if writeErr != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return writeErr
	}
	if err = os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func probeExactRoute(ctx context.Context, spec RouteSpec) (RouteProof, error) {
	endpoint := netip.AddrPortFrom(spec.Backend.Address, spec.Backend.Port)
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(dialCtx, network, endpoint.String())
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, ServerName: spec.SNI},
		ResponseHeaderTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()
	rawURL := string(spec.Backend.Protocol) + "://" + net.JoinHostPort(spec.HostHeader, strconv.Itoa(int(spec.Backend.Port))) + "/"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return RouteProof{}, err
	}
	request.Host = spec.HostHeader
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return RouteProof{}, err
	}
	_, readErr := io.CopyN(io.Discard, response.Body, 1)
	closeErr := response.Body.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || response.StatusCode < 200 || response.StatusCode >= 500 {
		return RouteProof{}, errors.Join(ErrPolicyDenied, readErr, closeErr)
	}
	now := time.Now().UTC()
	tlsDigest := "clear"
	if response.TLS != nil && len(response.TLS.PeerCertificates) != 0 {
		sum := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
		tlsDigest = hex.EncodeToString(sum[:])
	}
	evidence := digestJSON("cyberpanel:sitepreview:route-probe:v1", struct {
		SpecDigest string
		Status     int
		TLS        string
		ObservedAt time.Time
	}{specDigest(spec), response.StatusCode, tlsDigest, now})
	proof := RouteProof{SpecDigest: specDigest(spec), Engine: spec.Engine, HostProved: true, SNIProved: spec.Backend.Protocol == BackendHTTP || response.TLS != nil,
		PHPGeneration: spec.PHPGeneration, TLSGeneration: spec.TLSGeneration, CacheGeneration: spec.CacheGeneration, WAFGeneration: spec.WAFGeneration,
		SiteGeneration: spec.SiteGeneration, ObservedAt: now, EvidenceDigest: evidence}
	if !proof.ValidFor(spec) {
		return RouteProof{}, ErrIntegrity
	}
	return proof, nil
}

func specDigest(spec RouteSpec) string { return digestJSON("cyberpanel:sitepreview:route:v1", spec) }

type linuxChromeIsolationReceipt struct {
	NamespaceID      string    `json:"namespace_id"`
	ProfileIsolated  bool      `json:"profile_isolated"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
	ScreenshotDigest string    `json:"screenshot_digest"`
}

// RunLinuxChromiumHelperCommand serves the public helper protocol with no
// arguments and the private re-exec stage used after unshare with one fixed
// argument. No caller-controlled executable, namespace option, or endpoint is
// accepted by either stage.
func RunLinuxChromiumHelperCommand(ctx context.Context, arguments []string, input io.Reader, output io.Writer) error {
	if ctx == nil || input == nil || output == nil {
		return ErrInvalid
	}
	if len(arguments) == 1 && arguments[0] == linuxChromeIsolateArgument {
		return runLinuxChromeIsolate(ctx, input, output)
	}
	if len(arguments) != 0 {
		return ErrInvalid
	}
	var request linuxChromeHelperRequest
	if err := decodeHelperRequest(input, &request, 256<<10); err != nil || request.Version != linuxAdapterProtocolVersion || request.Launch.Validate() != nil ||
		!withinLinuxRoot(request.Launch.ProfileDirectory, DefaultChromiumProfileRoot) || filepath.Dir(request.Launch.OutputPath) != request.Launch.ProfileDirectory {
		return ErrInvalid
	}
	hops, responseBytes, err := observeExactNavigation(ctx, request.Launch)
	if err != nil {
		return err
	}
	isolation, err := runChromeInNamespaces(ctx, request)
	if err != nil {
		return err
	}
	receipt := NavigationReceipt{JobID: request.Launch.JobID, NamespaceID: isolation.NamespaceID, ProfileIsolated: isolation.ProfileIsolated,
		ExtensionsOff: true, DownloadsOff: true, CredentialsOff: true, FileURLsOff: true, DataURLsOff: true, Hops: hops, ResponseBytes: responseBytes,
		StartedAt: isolation.StartedAt, FinishedAt: isolation.FinishedAt}
	receipt.EvidenceDigest = digestJSON("cyberpanel:sitepreview:chromium-navigation:v1", struct {
		Launch           ChromeLaunch
		NamespaceID      string
		Hops             []NavigationHop
		ResponseBytes    uint64
		ScreenshotDigest string
		StartedAt        time.Time
		FinishedAt       time.Time
	}{request.Launch, isolation.NamespaceID, hops, responseBytes, isolation.ScreenshotDigest, isolation.StartedAt, isolation.FinishedAt})
	if receipt.StartedAt.IsZero() || receipt.FinishedAt.Before(receipt.StartedAt) || receipt.FinishedAt.After(request.Launch.Deadline) ||
		receipt.ResponseBytes == 0 || receipt.ResponseBytes > request.Launch.MaximumResponseBytes || !validDigest(receipt.EvidenceDigest) {
		return ErrIntegrity
	}
	return encodeHelperResponse(output, receipt)
}

func runChromeInNamespaces(ctx context.Context, request linuxChromeHelperRequest) (linuxChromeIsolationReceipt, error) {
	var receipt linuxChromeIsolationReceipt
	if validateRootExecutable(linuxUnshareExecutable) != nil {
		return receipt, ErrPolicyDenied
	}
	executable, err := os.Executable()
	expected, resolveErr := resolveRootHelper(DefaultLinuxChromiumHelper)
	if err != nil || resolveErr != nil || executable != expected {
		return receipt, ErrPolicyDenied
	}
	hostUser, err := os.Readlink("/proc/self/ns/user")
	if err != nil {
		return receipt, err
	}
	hostNetwork, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return receipt, err
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return receipt, err
	}
	parentFile, childFile := os.NewFile(uintptr(fds[0]), "sitepreview-parent"), os.NewFile(uintptr(fds[1]), "sitepreview-child")
	connection, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = childFile.Close()
		return receipt, err
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		_ = childFile.Close()
		return receipt, ErrIntegrity
	}
	defer control.Close()
	encoded, err := json.Marshal(request)
	if err != nil {
		_ = childFile.Close()
		return receipt, err
	}
	output := &limitedBuffer{maximum: 512 << 10}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(runCtx, linuxUnshareExecutable, "--user", "--map-root-user", "--net", "--", executable, linuxChromeIsolateArgument)
	command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(encoded), output, io.Discard
	command.ExtraFiles = []*os.File{childFile}
	command.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/nonexistent", "CYBERPANEL_PARENT_USER_NS=" + hostUser, "CYBERPANEL_PARENT_NET_NS=" + hostNetwork}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err = command.Start(); err != nil {
		_ = childFile.Close()
		return receipt, err
	}
	_ = childFile.Close()
	connections := make(chan net.Conn)
	readErrors := make(chan error, 1)
	go receiveIsolatedConnections(control, connections, readErrors)
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var proxies sync.WaitGroup
	for {
		select {
		case accepted, open := <-connections:
			if open {
				proxies.Add(1)
				go func() { defer proxies.Done(); proxyExactConnection(runCtx, accepted, request.Launch.AllowedEndpoint) }()
			}
		case waitErr := <-done:
			cancel()
			_ = control.Close()
			proxies.Wait()
			if waitErr != nil || output.overflow || decodeStored(output.content, &receipt) != nil {
				return linuxChromeIsolationReceipt{}, errors.Join(waitErr, ErrIntegrity)
			}
			return receipt, nil
		case receiveErr := <-readErrors:
			cancel()
			<-done
			proxies.Wait()
			return linuxChromeIsolationReceipt{}, receiveErr
		case <-ctx.Done():
			cancel()
			<-done
			proxies.Wait()
			return linuxChromeIsolationReceipt{}, ctx.Err()
		}
	}
}

func runLinuxChromeIsolate(ctx context.Context, input io.Reader, output io.Writer) error {
	if os.Getenv("CYBERPANEL_PARENT_USER_NS") == "" || os.Getenv("CYBERPANEL_PARENT_NET_NS") == "" {
		return ErrPolicyDenied
	}
	userNamespace, userErr := os.Readlink("/proc/self/ns/user")
	networkNamespace, networkErr := os.Readlink("/proc/self/ns/net")
	if userErr != nil || networkErr != nil || userNamespace == os.Getenv("CYBERPANEL_PARENT_USER_NS") || networkNamespace == os.Getenv("CYBERPANEL_PARENT_NET_NS") {
		return ErrPolicyDenied
	}
	var request linuxChromeHelperRequest
	if err := decodeHelperRequest(input, &request, 256<<10); err != nil || request.Version != linuxAdapterProtocolVersion || request.Launch.Validate() != nil ||
		!withinLinuxRoot(request.Launch.ProfileDirectory, DefaultChromiumProfileRoot) {
		return ErrInvalid
	}
	if validateRootExecutable(linuxIPExecutable) != nil {
		return ErrPolicyDenied
	}
	if err := runIP(ctx, "link", "set", "dev", "lo", "up"); err != nil {
		return err
	}
	address := request.Launch.AllowedEndpoint.Addr().Unmap()
	if !address.IsLoopback() {
		prefix := "/32"
		if address.Is6() {
			prefix = "/128"
		}
		if err := runIP(ctx, "address", "add", address.String()+prefix, "dev", "lo"); err != nil {
			return err
		}
	}
	controlFile := os.NewFile(3, "sitepreview-control")
	connection, err := net.FileConn(controlFile)
	_ = controlFile.Close()
	if err != nil {
		return err
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return ErrIntegrity
	}
	defer control.Close()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IP(address.AsSlice()), Port: int(request.Launch.AllowedEndpoint.Port())})
	if err != nil {
		return err
	}
	defer listener.Close()
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			accepted, acceptErr := listener.AcceptTCP()
			if acceptErr != nil {
				return
			}
			file, fileErr := accepted.File()
			_ = accepted.Close()
			if fileErr != nil {
				return
			}
			_, _, sendErr := control.WriteMsgUnix([]byte{1}, syscall.UnixRights(int(file.Fd())), nil)
			_ = file.Close()
			if sendErr != nil {
				return
			}
		}
	}()
	started := time.Now().UTC()
	command := exec.CommandContext(ctx, request.Launch.Binary, request.Launch.Arguments...)
	command.Stdin, command.Stdout, command.Stderr = nil, io.Discard, io.Discard
	command.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=" + request.Launch.ProfileDirectory, "XDG_CACHE_HOME=" + request.Launch.ProfileDirectory, "XDG_CONFIG_HOME=" + request.Launch.ProfileDirectory}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	runErr := command.Run()
	finished := time.Now().UTC()
	_ = listener.Close()
	<-acceptDone
	if runErr != nil || finished.After(request.Launch.Deadline) {
		return errors.Join(runErr, context.DeadlineExceeded)
	}
	info, err := os.Lstat(request.Launch.OutputPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || uint64(info.Size()) > request.Launch.MaximumResponseBytes {
		return errors.Join(ErrIntegrity, err)
	}
	screenshot, err := os.Open(request.Launch.OutputPath)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	written, hashErr := io.Copy(hasher, io.LimitReader(screenshot, int64(request.Launch.MaximumResponseBytes)+1))
	closeErr := screenshot.Close()
	if hashErr != nil || closeErr != nil || written <= 0 || uint64(written) > request.Launch.MaximumResponseBytes {
		return errors.Join(ErrIntegrity, hashErr, closeErr)
	}
	sum := sha256.Sum256([]byte(userNamespace + "\x00" + networkNamespace))
	receipt := linuxChromeIsolationReceipt{NamespaceID: "ns-" + hex.EncodeToString(sum[:16]), ProfileIsolated: true, StartedAt: started, FinishedAt: finished, ScreenshotDigest: hex.EncodeToString(hasher.Sum(nil))}
	return encodeHelperResponse(output, receipt)
}

func receiveIsolatedConnections(control *net.UnixConn, connections chan<- net.Conn, result chan<- error) {
	defer close(connections)
	for {
		payload, rights := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
		count, controlCount, _, _, err := control.ReadMsgUnix(payload, rights)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			result <- err
			return
		}
		if count != 1 || controlCount == 0 {
			result <- ErrIntegrity
			return
		}
		messages, err := syscall.ParseSocketControlMessage(rights[:controlCount])
		if err != nil || len(messages) != 1 {
			result <- ErrIntegrity
			return
		}
		fds, err := syscall.ParseUnixRights(&messages[0])
		if err != nil || len(fds) != 1 {
			result <- ErrIntegrity
			return
		}
		file := os.NewFile(uintptr(fds[0]), "sitepreview-connection")
		connection, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			result <- err
			return
		}
		connections <- connection
	}
}

func proxyExactConnection(ctx context.Context, isolated net.Conn, endpoint netip.AddrPort) {
	defer isolated.Close()
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", endpoint.String())
	if err != nil {
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	copyStream := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		if tcp, ok := destination.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyStream(upstream, isolated)
	go copyStream(isolated, upstream)
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func observeExactNavigation(ctx context.Context, launch ChromeLaunch) ([]NavigationHop, uint64, error) {
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(dialCtx, network, launch.AllowedEndpoint.String())
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: launch.SNI}, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	current := launch.URL
	hops := make([]NavigationHop, 0, int(launch.MaximumRedirects)+1)
	var total uint64
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return nil, 0, err
		}
		request.Host = launch.Host
		response, err := client.Do(request)
		if err != nil {
			return nil, 0, err
		}
		remaining := int64(launch.MaximumResponseBytes-total) + 1
		read, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, remaining))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || uint64(read) > launch.MaximumResponseBytes-total {
			return nil, 0, errors.Join(ErrPolicyDenied, readErr, closeErr)
		}
		total += uint64(read)
		hops = append(hops, NavigationHop{URL: current, ResolvedAddress: launch.AllowedEndpoint.Addr(), Status: uint16(response.StatusCode)})
		if response.StatusCode < 300 || response.StatusCode > 399 {
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				return nil, 0, ErrPolicyDenied
			}
			if total == 0 {
				return nil, 0, ErrPolicyDenied
			}
			return hops, total, nil
		}
		if len(hops) > int(launch.MaximumRedirects) {
			return nil, 0, ErrPolicyDenied
		}
		location, err := response.Location()
		if err != nil {
			return nil, 0, ErrPolicyDenied
		}
		if location.Scheme != "http" && location.Scheme != "https" || location.Hostname() != launch.Host || effectiveURLPort(location) != launch.AllowedEndpoint.Port() || location.User != nil || location.Fragment != "" {
			return nil, 0, ErrPolicyDenied
		}
		current = location.String()
	}
}

func runIP(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, linuxIPExecutable, arguments...)
	command.Stdin, command.Stdout, command.Stderr = nil, io.Discard, io.Discard
	command.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	return command.Run()
}

func validateRootExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
		return errors.Join(ErrPolicyDenied, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return ErrPolicyDenied
	}
	return nil
}

func decodeHelperRequest(input io.Reader, target any, maximum int64) error {
	limited := &io.LimitedReader{R: input, N: maximum + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || limited.N <= 0 {
		return ErrInvalid
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	return nil
}

func encodeHelperResponse(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
