//go:build linux

package apps

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	linuxApplicationRuntimeStateRoot = "/var/lib/cyberpanel/application-runtime"
	linuxApplicationManifestVersion  = 1
)

var certifiedVersionPattern = regexp.MustCompile(`[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+._~][0-9A-Za-z.-]+)?`)

type linuxApplicationReleaseManifest struct {
	Version          uint32                `json:"version"`
	InstallationID   InstallationID        `json:"installation_id"`
	TenantID         TenantID              `json:"tenant_id"`
	SiteID           SiteID                `json:"site_id"`
	DefinitionID     DefinitionID          `json:"definition_id"`
	Kind             ApplicationKind       `json:"kind"`
	ProductVersion   string                `json:"product_version"`
	RecipeDigest     string                `json:"recipe_digest"`
	DefinitionDigest string                `json:"definition_digest"`
	Artifact         ArtifactReference     `json:"artifact"`
	ReleaseID        ReleaseID              `json:"release_id"`
	RuntimeID        string                 `json:"runtime_id"`
	CanonicalURL     string                 `json:"canonical_url"`
	Database         DatabaseBinding        `json:"database"`
	Probes           []ProbeDefinition      `json:"probes"`
	CreatedAt        time.Time              `json:"created_at"`
}

type linuxApplicationActiveRelease struct {
	Version        uint32       `json:"version"`
	InstallationID InstallationID `json:"installation_id"`
	ReleaseID      ReleaseID    `json:"release_id"`
	ManifestDigest string       `json:"manifest_digest"`
	ActivatedAt    time.Time    `json:"activated_at"`
}

func (manifest linuxApplicationReleaseManifest) Validate() error {
	if manifest.Version != linuxApplicationManifestVersion || !validID(string(manifest.InstallationID)) || !validID(string(manifest.TenantID)) || !validID(string(manifest.SiteID)) || !validID(string(manifest.DefinitionID)) || !manifest.Kind.Valid() || !versionPattern.MatchString(manifest.ProductVersion) || !validDigest(manifest.RecipeDigest) || !validDigest(manifest.DefinitionDigest) || !validID(string(manifest.ReleaseID)) || !validApplicationRuntimeID(manifest.RuntimeID) || manifest.CreatedAt.IsZero() {
		return ErrIntegrity
	}
	if err := manifest.Artifact.Validate(); err != nil { return err }
	if err := manifest.Database.Validate(); err != nil { return err }
	parsed, err := url.Parse(manifest.CanonicalURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Port() != "" && parsed.Port() != "443" {
		return ErrIntegrity
	}
	if len(manifest.Probes) == 0 || len(manifest.Probes) > 16 { return ErrIntegrity }
	seenProbes := make(map[string]struct{}, len(manifest.Probes))
	for _, probe := range manifest.Probes {
		if !componentNamePattern.MatchString(probe.Name) || probe.Name == "application_version" || probe.Name == "application_structure" || probe.Timeout <= 0 || probe.Timeout > 10*time.Minute {
			return ErrIntegrity
		}
		if _, exists := seenProbes[probe.Name]; exists { return ErrIntegrity }
		seenProbes[probe.Name] = struct{}{}
		switch probe.Kind {
		case ProbeHTTP:
			if !strings.HasPrefix(probe.RelativeEndpoint, "/") || strings.ContainsAny(probe.RelativeEndpoint, "\\\x00\r\n?#") || len(probe.ExpectedStatus) == 0 { return ErrIntegrity }
			for _, status := range probe.ExpectedStatus { if status < 100 || status > 599 { return ErrIntegrity } }
		case ProbeCLI, ProbeDatabase, ProbeIntegrity, ProbeBackground:
		default:
			return ErrIntegrity
		}
	}
	return nil
}

func validApplicationRuntimeID(value string) bool {
	switch value {
	case "php82", "php83", "php84":
		return true
	default:
		return false
	}
}

func applicationManifestFromInstall(execution InstallExecution) linuxApplicationReleaseManifest {
	return linuxApplicationReleaseManifest{
		Version: linuxApplicationManifestVersion, InstallationID: execution.Installation, TenantID: execution.Scope.TenantID, SiteID: execution.Scope.SiteID, DefinitionID: execution.Definition.ID,
		Kind: execution.Definition.Kind, ProductVersion: execution.Definition.Recipe.ProductVersion, RecipeDigest: execution.Definition.Recipe.RecipeDigest,
		DefinitionDigest: execution.Definition.DefinitionDigest, Artifact: execution.Definition.Artifact, ReleaseID: execution.ReleaseID,
		RuntimeID: execution.RuntimeID, CanonicalURL: execution.CanonicalURL, Database: execution.Database,
		Probes: append([]ProbeDefinition(nil), execution.Definition.InstallProbes...), CreatedAt: execution.Definition.Recipe.PublishedAt.UTC(),
	}
}

func applicationManifestFromUpdate(current linuxApplicationReleaseManifest, execution UpdateExecution) linuxApplicationReleaseManifest {
	probes := execution.Definition.UpdateProbes
	if len(probes) == 0 { probes = execution.Definition.InstallProbes }
	return linuxApplicationReleaseManifest{
		Version: linuxApplicationManifestVersion, InstallationID: execution.Installation, TenantID: current.TenantID, SiteID: current.SiteID, DefinitionID: execution.Definition.ID,
		Kind: execution.Definition.Kind, ProductVersion: execution.Definition.Recipe.ProductVersion, RecipeDigest: execution.Definition.Recipe.RecipeDigest,
		DefinitionDigest: execution.Definition.DefinitionDigest, Artifact: execution.Definition.Artifact, ReleaseID: execution.TargetRelease.ID,
		RuntimeID: current.RuntimeID, CanonicalURL: current.CanonicalURL, Database: current.Database,
		Probes: append([]ProbeDefinition(nil), probes...), CreatedAt: execution.Definition.Recipe.PublishedAt.UTC(),
	}
}

func applicationManifestMatchesScope(manifest linuxApplicationReleaseManifest, scope SiteExecutionScope) bool {
	return manifest.TenantID == scope.TenantID && manifest.SiteID == scope.SiteID
}

func validateCertifiedUpdateExecution(execution UpdateExecution) error {
	if execution.Scope.Validate() != nil || execution.Definition.Validate(time.Now().UTC()) != nil || execution.Definition.Kind == ApplicationWordPress || !execution.Definition.Lifecycle.Update || !validID(string(execution.Installation)) || !validID(string(execution.FromReleaseID)) || !validID(string(execution.TargetRelease.ID)) || !validID(string(execution.SnapshotID)) || !execution.WriteFence || len(execution.Components) != 0 {
		return ErrInvalid
	}
	if execution.TargetRelease.InstallationID != execution.Installation || execution.TargetRelease.ProductVersion != execution.Definition.Recipe.ProductVersion || execution.TargetRelease.ContentDigest != execution.Definition.Artifact.Digest || execution.TargetRelease.RecipeDigest != execution.Definition.Recipe.RecipeDigest || execution.TargetRelease.SnapshotID != execution.SnapshotID || execution.TargetRelease.CreatedAt.IsZero() || execution.ShadowBinding != applicationShadowToken(execution.Installation, execution.TargetRelease.ID) {
		return ErrConflict
	}
	return nil
}

func validateCertifiedInstallerInput(execution InstallExecution) error {
	if execution.Validate(time.Now().UTC()) != nil || execution.Definition.Kind == ApplicationWordPress || !execution.Definition.Lifecycle.Install { return ErrInvalid }
	if strings.TrimSpace(execution.Title) == "" || len(execution.Title) > 256 || len(execution.Locale) > 64 || len(execution.Timezone) > 128 || len(execution.Administrator.DisplayName) > 256 || strings.ContainsAny(execution.Title+execution.Locale+execution.Timezone+execution.Administrator.DisplayName, "\x00\r\n") {
		return ErrInvalid
	}
	return applicationManifestFromInstall(execution).Validate()
}

func applicationManifestDirectory(installation InstallationID) (string, error) {
	if !validID(string(installation)) { return "", ErrInvalid }
	value := filepath.Join(linuxApplicationRuntimeStateRoot, string(installation))
	if !strings.HasPrefix(value, linuxApplicationRuntimeStateRoot+string(os.PathSeparator)) { return "", ErrPolicyDenied }
	return value, nil
}

func applicationReleaseManifestPath(installation InstallationID, release ReleaseID) (string, error) {
	if !validID(string(release)) { return "", ErrInvalid }
	directory, err := applicationManifestDirectory(installation)
	if err != nil { return "", err }
	return filepath.Join(directory, string(release)+".json"), nil
}

func ensureApplicationStateDirectory(path string) error {
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, linuxApplicationRuntimeStateRoot) { return ErrPolicyDenied }
	if err := os.MkdirAll(path, 0700); err != nil { return err }
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 { return ErrIntegrity }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 { return ErrIntegrity }
	return os.Chmod(path, 0700)
}

func writeRootApplicationState(path string, payload []byte) error {
	if len(payload) == 0 || len(payload) > 4<<20 { return ErrInvalid }
	if err := ensureApplicationStateDirectory(filepath.Dir(path)); err != nil { return err }
	temporary := path + ".new"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil { return err }
	_, writeErr := file.Write(payload)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil { _ = os.Remove(temporary); return err }
	if err = os.Rename(temporary, path); err != nil { _ = os.Remove(temporary); return err }
	directory, err := os.Open(filepath.Dir(path))
	if err != nil { return err }
	defer directory.Close()
	return directory.Sync()
}

func (runtime *LinuxApplicationRuntime) saveApplicationReleaseManifest(manifest linuxApplicationReleaseManifest) error {
	if err := manifest.Validate(); err != nil { return err }
	path, err := applicationReleaseManifestPath(manifest.InstallationID, manifest.ReleaseID)
	if err != nil { return err }
	payload, err := json.Marshal(manifest)
	if err != nil { return err }
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if bytes.Equal(existing, payload) { return nil }
		return ErrConflict
	} else if !errors.Is(readErr, os.ErrNotExist) { return readErr }
	return writeRootApplicationState(path, payload)
}

func (runtime *LinuxApplicationRuntime) loadApplicationReleaseManifest(installation InstallationID, release ReleaseID) (linuxApplicationReleaseManifest, error) {
	var manifest linuxApplicationReleaseManifest
	path, err := applicationReleaseManifestPath(installation, release)
	if err != nil { return manifest, err }
	payload, err := os.ReadFile(path)
	if err != nil { return manifest, err }
	if len(payload) == 0 || len(payload) > 4<<20 || json.Unmarshal(payload, &manifest) != nil || manifest.InstallationID != installation || manifest.ReleaseID != release || manifest.Validate() != nil {
		return linuxApplicationReleaseManifest{}, ErrIntegrity
	}
	return manifest, nil
}

func (runtime *LinuxApplicationRuntime) activateApplicationRelease(manifest linuxApplicationReleaseManifest) error {
	if err := runtime.saveApplicationReleaseManifest(manifest); err != nil { return err }
	payload, err := json.Marshal(manifest)
	if err != nil { return err }
	digest := sha256.Sum256(payload)
	active := linuxApplicationActiveRelease{Version: 1, InstallationID: manifest.InstallationID, ReleaseID: manifest.ReleaseID, ManifestDigest: hex.EncodeToString(digest[:]), ActivatedAt: time.Now().UTC()}
	encoded, err := json.Marshal(active)
	if err != nil { return err }
	directory, err := applicationManifestDirectory(manifest.InstallationID)
	if err != nil { return err }
	return writeRootApplicationState(filepath.Join(directory, "active.json"), encoded)
}

func (runtime *LinuxApplicationRuntime) loadActiveApplicationManifest(installation InstallationID) (linuxApplicationReleaseManifest, error) {
	directory, err := applicationManifestDirectory(installation)
	if err != nil { return linuxApplicationReleaseManifest{}, err }
	payload, err := os.ReadFile(filepath.Join(directory, "active.json"))
	if err != nil { return linuxApplicationReleaseManifest{}, err }
	var active linuxApplicationActiveRelease
	if len(payload) > 64<<10 || json.Unmarshal(payload, &active) != nil || active.Version != 1 || active.InstallationID != installation || !validID(string(active.ReleaseID)) || !validDigest(active.ManifestDigest) || active.ActivatedAt.IsZero() {
		return linuxApplicationReleaseManifest{}, ErrIntegrity
	}
	manifest, err := runtime.loadApplicationReleaseManifest(installation, active.ReleaseID)
	if err != nil { return linuxApplicationReleaseManifest{}, err }
	encoded, _ := json.Marshal(manifest)
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != active.ManifestDigest { return linuxApplicationReleaseManifest{}, ErrIntegrity }
	return manifest, nil
}

func (runtime *LinuxApplicationRuntime) recordInstalledApplication(execution InstallExecution) error {
	manifest := applicationManifestFromInstall(execution)
	return runtime.activateApplicationRelease(manifest)
}

func (runtime *LinuxApplicationRuntime) recordUpdatedApplication(execution UpdateExecution) error {
	current, err := runtime.loadActiveApplicationManifest(execution.Installation)
	if err != nil { return err }
	if current.Kind != execution.Definition.Kind || current.ReleaseID != execution.FromReleaseID || !applicationManifestMatchesScope(current, execution.Scope) { return ErrConflict }
	return runtime.saveApplicationReleaseManifest(applicationManifestFromUpdate(current, execution))
}

func (runtime *LinuxApplicationRuntime) removeApplicationState(installation InstallationID) error {
	directory, err := applicationManifestDirectory(installation)
	if err != nil { return err }
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) { return nil }
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return ErrIntegrity }
	return os.RemoveAll(directory)
}

func trustedApplicationExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 { return ErrPolicyDenied }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 { return ErrPolicyDenied }
	return nil
}

func applicationPHPBinary(runtimeID string) (string, error) {
	var binary string
	switch runtimeID {
	case "php82": binary = "/usr/local/lsws/lsphp82/bin/lsphp"
	case "php83": binary = "/usr/local/lsws/lsphp83/bin/lsphp"
	case "php84": binary = "/usr/local/lsws/lsphp84/bin/lsphp"
	default: return "", ErrUnsupported
	}
	if err := trustedApplicationExecutable(binary); err != nil { return "", err }
	return binary, nil
}

func applicationMariaDBBinary(dump bool) (string, error) {
	candidates := []string{"/usr/bin/mariadb", "/usr/bin/mysql"}
	if dump { candidates = []string{"/usr/bin/mariadb-dump", "/usr/bin/mysqldump"} }
	for _, candidate := range candidates {
		if trustedApplicationExecutable(candidate) == nil { return candidate, nil }
	}
	return "", ErrUnsupported
}

func (runtime *LinuxApplicationRuntime) php(ctx context.Context, scope linuxApplicationScope, runtimeID string, input []byte, maximum int, args ...string) ([]byte, []byte, int, error) {
	binary, err := applicationPHPBinary(runtimeID)
	if err != nil { return nil, nil, -1, err }
	base := []string{"-d", "display_errors=0", "-d", "log_errors=1", "-d", "memory_limit=-1"}
	return runtime.command(ctx, scope, binary, input, maximum, append(base, args...)...)
}

func pinnedApplicationArtifactPath(reference ArtifactReference) (string, error) {
	if err := reference.Validate(); err != nil { return "", err }
	root, manifest, err := linuxApplicationCatalogSnapshot(DefaultApplicationCatalogRoot, time.Now().UTC())
	if err != nil { return "", fmt.Errorf("%w: pinned application catalog", ErrRecipeUnavailable) }
	artifact, found := catalogManifestArtifact(manifest, reference.Digest)
	if !found || artifact.Size != reference.Size { return "", ErrRecipeUntrusted }
	artifactRoot := filepath.Join(root, "artifacts")
	value := filepath.Join(artifactRoot, reference.Digest+".tar.gz")
	if !strings.HasPrefix(value, artifactRoot+string(os.PathSeparator)) { return "", ErrPolicyDenied }
	info, err := os.Lstat(value)
	if err != nil { return "", fmt.Errorf("%w: pinned application artifact", ErrRecipeUnavailable) }
	if validateRootCatalogFileInfo(info, reference.Size, true) != nil { return "", ErrRecipeUntrusted }
	digest, err := digestLinuxApplicationFile(value, uint64(reference.Size))
	if err != nil || digest != reference.Digest { return "", ErrRecipeUntrusted }
	if err := validatePinnedApplicationArchive(value); err != nil { return "", err }
	return value, nil
}

func validatePinnedApplicationArchive(filename string) error {
	file, err := os.Open(filename)
	if err != nil { return err }
	defer file.Close()
	zip, err := gzip.NewReader(file)
	if err != nil { return ErrRecipeUntrusted }
	defer zip.Close()
	reader := tar.NewReader(zip)
	var top string
	var entries, expanded uint64
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) { break }
		if nextErr != nil { return ErrRecipeUntrusted }
		entries++
		if entries > 2_000_000 || header.Size < 0 { return ErrRecipeUntrusted }
		expanded += uint64(header.Size)
		if expanded > 64<<30 { return ErrRecipeUntrusted }
		name := strings.TrimPrefix(header.Name, "./")
		if name == "" || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name { return ErrRecipeUntrusted }
		parts := strings.Split(name, "/")
		if len(parts) < 2 || parts[0] == "" || parts[0] == "." || parts[0] == ".." { return ErrRecipeUntrusted }
		if top == "" { top = parts[0] } else if top != parts[0] { return ErrRecipeUntrusted }
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
		case tar.TypeSymlink, tar.TypeLink:
			if header.Linkname == "" || strings.ContainsAny(header.Linkname, "\\\x00") || path.IsAbs(header.Linkname) { return ErrRecipeUntrusted }
			resolved := path.Clean(path.Join(path.Dir(name), header.Linkname))
			if resolved == ".." || strings.HasPrefix(resolved, "../") || !strings.HasPrefix(resolved, top+"/") { return ErrRecipeUntrusted }
		default:
			return ErrRecipeUntrusted
		}
	}
	if entries == 0 || top == "" { return ErrRecipeUntrusted }
	return nil
}

func ensureSiteOwnedDirectory(path string, binding LinuxApplicationSiteBinding) error {
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, linuxApplicationSitesRoot+string(os.PathSeparator)) { return ErrPolicyDenied }
	if err := os.Mkdir(path, 0750); err != nil { return err }
	if err := os.Chown(path, int(binding.UID), int(binding.GID)); err != nil { _ = os.Remove(path); return err }
	return nil
}

func ensureSiteOwnedParents(root, target string, binding LinuxApplicationSiteBinding) error {
	cleanRoot, cleanTarget := filepath.Clean(root), filepath.Clean(target)
	if cleanTarget != cleanRoot && !strings.HasPrefix(cleanTarget, cleanRoot+string(os.PathSeparator)) { return ErrPolicyDenied }
	relative, err := filepath.Rel(cleanRoot, cleanTarget)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) { return ErrPolicyDenied }
	current := cleanRoot
	if relative == "." { return nil }
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			if err := os.Mkdir(current, 0750); err != nil { return err }
			if err := os.Chown(current, int(binding.UID), int(binding.GID)); err != nil { return err }
			continue
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return ErrPolicyDenied }
	}
	return nil
}

func (runtime *LinuxApplicationRuntime) extractPinnedApplicationArtifact(ctx context.Context, scope linuxApplicationScope, reference ArtifactReference) error {
	artifact, err := pinnedApplicationArtifactPath(reference)
	if err != nil { return err }
	temporary := filepath.Join(scope.root, ".cyberpanel-artifact-"+reference.Digest[:24]+".tar.gz")
	if !strings.HasPrefix(temporary, scope.root+string(os.PathSeparator)) { return ErrPolicyDenied }
	source, err := os.Open(artifact)
	if err != nil { return err }
	defer source.Close()
	target, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0400)
	if err != nil { return err }
	copied, copyErr := io.Copy(target, io.LimitReader(source, reference.Size+1))
	syncErr := target.Sync()
	chownErr := target.Chown(int(scope.binding.UID), int(scope.binding.GID))
	closeErr := target.Close()
	if err = errors.Join(copyErr, syncErr, chownErr, closeErr); err != nil || copied != reference.Size { _ = os.Remove(temporary); if err != nil { return err }; return ErrIntegrity }
	defer os.Remove(temporary)
	_, stderr, _, err := runtime.command(ctx, scope, runtime.Tar, nil, 2<<20, "--extract", "--gzip", "--file", temporary, "--directory", scope.root, "--strip-components=1", "--no-same-owner", "--no-same-permissions", "--delay-directory-restore")
	if err != nil { return fmt.Errorf("extract pinned application artifact: %w: %s", err, boundedApplicationOutput(stderr)) }
	return nil
}

func boundedApplicationOutput(value []byte) string {
	value = bytes.TrimSpace(value)
	if len(value) > 4096 { value = value[:4096] }
	return string(value)
}

func redactedApplicationOutput(value []byte, secrets ...[]byte) string {
	redacted := append([]byte(nil), value...)
	for _, secret := range secrets {
		if len(secret) > 0 { redacted = bytes.ReplaceAll(redacted, secret, []byte("[redacted]")) }
	}
	return boundedApplicationOutput(redacted)
}

func validateCertifiedInstallDestination(scope linuxApplicationScope) error {
	if filepath.Base(scope.root) != "current" { return ErrUnsupported }
	entries, err := os.ReadDir(scope.root)
	if err != nil { return err }
	for _, entry := range entries {
		switch entry.Name() {
		case ".well-known", "index.html", "50x.html":
		default:
			return ErrConflict
		}
	}
	return nil
}

func (runtime *LinuxApplicationRuntime) copyApplicationPath(ctx context.Context, sourceScope, targetScope linuxApplicationScope, relative string, required bool) error {
	parsed, err := ParseRelativePath(relative)
	if err != nil || parsed.IsRoot() { return ErrInvalid }
	source, err := secureLinuxApplicationEntry(sourceScope.root, parsed)
	if errors.Is(err, os.ErrNotExist) && !required { return nil }
	if err != nil { return err }
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 { return ErrPolicyDenied }
	target := filepath.Join(targetScope.root, filepath.FromSlash(relative))
	if info.IsDir() {
		if err := ensureSiteOwnedParents(targetScope.root, target, targetScope.binding); err != nil { return err }
		_, stderr, _, runErr := runtime.command(ctx, sourceScope, "/usr/bin/rsync", nil, 2<<20, "-a", "--safe-links", "--", source+string(os.PathSeparator), target+string(os.PathSeparator))
		if runErr != nil { return fmt.Errorf("preserve application directory: %w: %s", runErr, boundedApplicationOutput(stderr)) }
		return nil
	}
	if !info.Mode().IsRegular() { return ErrPolicyDenied }
	if err := ensureSiteOwnedParents(targetScope.root, filepath.Dir(target), targetScope.binding); err != nil { return err }
	_, stderr, _, runErr := runtime.command(ctx, sourceScope, "/usr/bin/cp", nil, 1<<20, "--preserve=mode,timestamps", "--", source, target)
	if runErr != nil { return fmt.Errorf("preserve application file: %w: %s", runErr, boundedApplicationOutput(stderr)) }
	return nil
}

func secureLinuxApplicationEntry(root string, relative RelativePath) (string, error) {
	current := filepath.Clean(root)
	for _, component := range strings.Split(relative.String(), "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil { return "", err }
		if info.Mode()&os.ModeSymlink != 0 { return "", ErrPolicyDenied }
	}
	if current != root && !strings.HasPrefix(current, root+string(os.PathSeparator)) { return "", ErrPolicyDenied }
	return current, nil
}

const certifiedApplicationArgumentBootstrap = `<?php
declare(strict_types=1);
$input = getcwd() . '/.cyberpanel-bootstrap.json';
$raw = @file_get_contents($input);
if ($raw === false) { exit(125); }
$data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
@unlink($input);
if (!is_array($data) || !isset($data['arguments']) || !is_array($data['arguments'])) { exit(125); }
$arguments = array_values(array_filter($data['arguments'], static fn($value) => is_string($value) && !str_contains($value, "\0")));
if (count($arguments) !== count($data['arguments']) || count($arguments) > 128) { exit(125); }
$_SERVER['argv'] = array_merge([$_SERVER['argv'][0]], $arguments);
$GLOBALS['argv'] = $_SERVER['argv'];
$_SERVER['argc'] = count($_SERVER['argv']);
$GLOBALS['argc'] = $_SERVER['argc'];
`

func writeSiteBootstrapFile(path string, content []byte, scope linuxApplicationScope) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil { return err }
	_, writeErr := file.Write(content)
	syncErr := file.Sync()
	chownErr := file.Chown(int(scope.binding.UID), int(scope.binding.GID))
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, chownErr, closeErr); err != nil { _ = os.Remove(path); return err }
	return nil
}

func applicationPrivateTemporaryDirectory(scope linuxApplicationScope) (string, error) {
	generationRoot := filepath.Join(linuxApplicationSitesRoot, scope.binding.SiteKey, "roots", "g"+strconv.FormatUint(scope.binding.Generation, 10))
	directory := filepath.Join(generationRoot, "tmp")
	if !strings.HasPrefix(directory, linuxApplicationSitesRoot+string(os.PathSeparator)) { return "", ErrPolicyDenied }
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 { return "", ErrPolicyDenied }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != scope.binding.UID || stat.Gid != scope.binding.GID { return "", ErrPolicyDenied }
	return directory, nil
}

func writeSiteTemporaryFile(scope linuxApplicationScope, pattern string, content []byte) (string, error) {
	if pattern == "" || strings.ContainsAny(pattern, "/\\\x00") { return "", ErrInvalid }
	directory, err := applicationPrivateTemporaryDirectory(scope)
	if err != nil { return "", err }
	file, err := os.CreateTemp(directory, pattern)
	if err != nil { return "", err }
	path := file.Name()
	_, writeErr := file.Write(content)
	syncErr := file.Sync()
	chownErr := file.Chown(int(scope.binding.UID), int(scope.binding.GID))
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, chownErr, closeErr); err != nil { _ = os.Remove(path); return "", err }
	return path, nil
}

func wipeApplicationBootstrapFile(path string) {
	file, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err == nil {
		if info, statErr := file.Stat(); statErr == nil && info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= 1<<20 {
			zeroes := make([]byte, info.Size())
			_, _ = file.WriteAt(zeroes, 0)
			for index := range zeroes { zeroes[index] = 0 }
			_ = file.Sync()
		}
		_ = file.Close()
	}
	_ = os.Remove(path)
}

func (runtime *LinuxApplicationRuntime) runApplicationBootstrap(ctx context.Context, scope linuxApplicationScope, runtimeID, entry string, arguments []string, secrets ...[]byte) error {
	entryPath, err := secureLinuxApplicationEntry(scope.root, MustRelativePath(entry))
	if err != nil { return err }
	info, err := os.Lstat(entryPath)
	if err != nil || !info.Mode().IsRegular() { return ErrIntegrity }
	bootstrapPath := filepath.Join(scope.root, ".cyberpanel-bootstrap.php")
	inputPath := filepath.Join(scope.root, ".cyberpanel-bootstrap.json")
	encoded, err := json.Marshal(struct { Arguments []string `json:"arguments"` }{Arguments: arguments})
	if err != nil { return err }
	defer func() { for index := range encoded { encoded[index] = 0 } }()
	if err := writeSiteBootstrapFile(bootstrapPath, []byte(certifiedApplicationArgumentBootstrap), scope); err != nil { return err }
	defer wipeApplicationBootstrapFile(bootstrapPath)
	if err := writeSiteBootstrapFile(inputPath, encoded, scope); err != nil { return err }
	defer wipeApplicationBootstrapFile(inputPath)
	_, stderr, _, runErr := runtime.php(ctx, scope, runtimeID, nil, 4<<20, "-d", "auto_prepend_file="+bootstrapPath, entryPath)
	if runErr != nil { return fmt.Errorf("run certified application installer: %w: %s", runErr, redactedApplicationOutput(stderr, secrets...)) }
	return nil
}

func (runtime *LinuxApplicationRuntime) runApplicationPHP(ctx context.Context, scope linuxApplicationScope, runtimeID, entry string, arguments ...string) error {
	entryPath, err := secureLinuxApplicationEntry(scope.root, MustRelativePath(entry))
	if err != nil { return err }
	args := append([]string{entryPath}, arguments...)
	_, stderr, _, runErr := runtime.php(ctx, scope, runtimeID, nil, 4<<20, args...)
	if runErr != nil { return fmt.Errorf("run certified application command: %w: %s", runErr, boundedApplicationOutput(stderr)) }
	return nil
}

func applicationDatabaseHost(binding DatabaseBinding) (string, error) {
	if binding.Engine != "mariadb" || binding.EndpointRef != "local-mariadb" { return "", ErrUnsupported }
	return "localhost", nil
}

func administratorName(displayName string) (string, string) {
	parts := strings.Fields(displayName)
	if len(parts) == 0 { return "Site", "Administrator" }
	if len(parts) == 1 { return parts[0], "Administrator" }
	return parts[0], strings.Join(parts[1:], " ")
}

func (runtime *LinuxApplicationRuntime) installCertifiedApplicationPayload(ctx context.Context, scope linuxApplicationScope, execution InstallExecution) error {
	databasePassword, err := runtime.Secrets.ApplicationSecret(ctx, execution.Database.PasswordRef, execution.Scope.TenantID, execution.Scope.SiteID, execution.Installation, "database")
	if err != nil { return err }
	defer wipeLinuxApplicationBytes(databasePassword)
	administratorPassword, err := runtime.Secrets.ApplicationSecret(ctx, execution.Administrator.PasswordRef, execution.Scope.TenantID, execution.Scope.SiteID, execution.Installation, "administrator")
	if err != nil { return err }
	defer wipeLinuxApplicationBytes(administratorPassword)
	host, err := applicationDatabaseHost(execution.Database)
	if err != nil { return err }
	firstName, lastName := administratorName(execution.Administrator.DisplayName)
	databaseSecret, administratorSecret := string(databasePassword), string(administratorPassword)
	baseURL := strings.TrimRight(execution.CanonicalURL, "/")
	canonical, err := url.Parse(execution.CanonicalURL)
	if err != nil || canonical.Hostname() == "" { return ErrIntegrity }
	var entry string
	var arguments []string
	switch execution.Definition.Kind {
	case ApplicationJoomla:
		entry = "installation/joomla.php"
		prefix := "cp_" + linuxApplicationDigest([]byte(execution.Installation))[:8] + "_"
		arguments = []string{"install", "--site-name=" + execution.Title, "--admin-user=" + execution.Administrator.DisplayName, "--admin-username=" + execution.Administrator.Username, "--admin-password=" + administratorSecret, "--admin-email=" + execution.Administrator.Email, "--db-type=mysqli", "--db-host=" + host, "--db-user=" + execution.Database.PrincipalName, "--db-pass=" + databaseSecret, "--db-name=" + execution.Database.DatabaseName, "--db-prefix=" + prefix, "--no-interaction"}
	case ApplicationPrestaShop:
		entry = "install/index_cli.php"
		language := strings.ToLower(strings.Split(strings.ReplaceAll(execution.Locale, "-", "_"), "_")[0])
		arguments = []string{"--domain=" + canonical.Hostname(), "--db_server=" + host, "--db_name=" + execution.Database.DatabaseName, "--db_user=" + execution.Database.PrincipalName, "--db_password=" + databaseSecret, "--prefix=cp_", "--name=" + execution.Title, "--firstname=" + firstName, "--lastname=" + lastName, "--email=" + execution.Administrator.Email, "--password=" + administratorSecret, "--language=" + language, "--ssl=1"}
	case ApplicationMautic:
		entry = "bin/console"
		arguments = []string{"mautic:install", baseURL, "--db_driver=pdo_mysql", "--db_host=" + host, "--db_port=3306", "--db_name=" + execution.Database.DatabaseName, "--db_user=" + execution.Database.PrincipalName, "--db_password=" + databaseSecret, "--db_backup_tables=false", "--admin_firstname=" + firstName, "--admin_lastname=" + lastName, "--admin_username=" + execution.Administrator.Username, "--admin_email=" + execution.Administrator.Email, "--admin_password=" + administratorSecret, "--force", "--no-interaction"}
	case ApplicationMagento:
		entry = "bin/magento"
		arguments = []string{"setup:install", "--base-url=" + baseURL + "/", "--base-url-secure=" + baseURL + "/", "--use-secure=1", "--use-secure-admin=1", "--db-host=" + host, "--db-name=" + execution.Database.DatabaseName, "--db-user=" + execution.Database.PrincipalName, "--db-password=" + databaseSecret, "--admin-firstname=" + firstName, "--admin-lastname=" + lastName, "--admin-email=" + execution.Administrator.Email, "--admin-user=" + execution.Administrator.Username, "--admin-password=" + administratorSecret, "--language=" + execution.Locale, "--currency=USD", "--timezone=" + execution.Timezone, "--use-rewrites=1", "--search-engine=opensearch", "--opensearch-host=127.0.0.1", "--opensearch-port=9200", "--opensearch-enable-auth=0", "--cleanup-database", "--no-interaction"}
	default:
		return ErrUnsupported
	}
	if err := runtime.runApplicationBootstrap(ctx, scope, execution.RuntimeID, entry, arguments, databasePassword, administratorPassword); err != nil { return err }
	switch execution.Definition.Kind {
	case ApplicationJoomla:
		if _, _, _, err := runtime.command(ctx, scope, "/usr/bin/rm", nil, 1<<20, "-rf", "--", filepath.Join(scope.root, "installation")); err != nil { return err }
	case ApplicationPrestaShop:
		if _, _, _, err := runtime.command(ctx, scope, "/usr/bin/rm", nil, 1<<20, "-rf", "--", filepath.Join(scope.root, "install")); err != nil { return err }
	case ApplicationMautic:
		if err := runtime.runApplicationPHP(ctx, scope, execution.RuntimeID, "bin/console", "mautic:assets:generate", "--no-interaction"); err != nil { return err }
		if err := runtime.runApplicationPHP(ctx, scope, execution.RuntimeID, "bin/console", "cache:clear", "--no-warmup", "--no-interaction"); err != nil { return err }
	case ApplicationMagento:
		if err := runtime.runApplicationPHP(ctx, scope, execution.RuntimeID, "bin/magento", "setup:di:compile", "--no-interaction"); err != nil { return err }
		if err := runtime.runApplicationPHP(ctx, scope, execution.RuntimeID, "bin/magento", "setup:static-content:deploy", "-f", execution.Locale, "--no-interaction"); err != nil { return err }
		if err := runtime.runApplicationPHP(ctx, scope, execution.RuntimeID, "bin/magento", "indexer:reindex", "--no-interaction"); err != nil { return err }
	}
	return validateCertifiedApplicationConfiguration(scope, execution.Definition.Kind)
}

func validateCertifiedApplicationConfiguration(scope linuxApplicationScope, kind ApplicationKind) error {
	var alternatives []string
	switch kind {
	case ApplicationJoomla: alternatives = []string{"configuration.php"}
	case ApplicationPrestaShop: alternatives = []string{"app/config/parameters.php", "config/settings.inc.php"}
	case ApplicationMautic: alternatives = []string{"config/local.php", "app/config/local.php"}
	case ApplicationMagento: alternatives = []string{"app/etc/env.php"}
	default: return ErrUnsupported
	}
	for _, candidate := range alternatives {
		entry, err := secureLinuxApplicationEntry(scope.root, MustRelativePath(candidate))
		if err != nil { continue }
		info, statErr := os.Lstat(entry)
		if statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 { return nil }
	}
	return ErrIntegrity
}

func (runtime *LinuxApplicationRuntime) installCertifiedApplication(ctx context.Context, execution InstallExecution) (ExecutionReceipt, error) {
	if err := validateCertifiedInstallerInput(execution); err != nil { return ExecutionReceipt{}, err }
	current, err := runtime.resolve(ctx, execution.Scope)
	if err != nil { return ExecutionReceipt{}, err }
	if err := validateCertifiedInstallDestination(current); err != nil { return ExecutionReceipt{}, err }
	parent := filepath.Dir(current.root)
	token := linuxApplicationDigest([]byte(string(execution.Installation)+"\x00"+string(execution.ReleaseID)))[:32]
	stagePath := filepath.Join(parent, ".app-install-"+token)
	backupPath := filepath.Join(parent, ".app-before-install-"+token)
	if !strings.HasPrefix(stagePath, parent+string(os.PathSeparator)) || !strings.HasPrefix(backupPath, parent+string(os.PathSeparator)) { return ExecutionReceipt{}, ErrPolicyDenied }
	if err := ensureSiteOwnedDirectory(stagePath, current.binding); err != nil { return ExecutionReceipt{}, err }
	stage := linuxApplicationScope{binding: current.binding, root: stagePath}
	committed := false
	defer func() { if !committed { _ = os.RemoveAll(stagePath) } }()
	if err := runtime.extractPinnedApplicationArtifact(ctx, stage, execution.Definition.Artifact); err != nil { return ExecutionReceipt{}, err }
	if _, err := os.Lstat(filepath.Join(current.root, ".well-known")); err == nil {
		if err := runtime.copyApplicationPath(ctx, current, stage, ".well-known", false); err != nil { return ExecutionReceipt{}, err }
	} else if !errors.Is(err, os.ErrNotExist) { return ExecutionReceipt{}, err }
	if err := runtime.installCertifiedApplicationPayload(ctx, stage, execution); err != nil { return ExecutionReceipt{}, err }
	manifest := applicationManifestFromInstall(execution)
	if err := runtime.saveApplicationReleaseManifest(manifest); err != nil { return ExecutionReceipt{}, err }
	if _, err := os.Lstat(backupPath); err == nil { return ExecutionReceipt{}, ErrConflict } else if !errors.Is(err, os.ErrNotExist) { return ExecutionReceipt{}, err }
	if err := os.Rename(current.root, backupPath); err != nil { return ExecutionReceipt{}, err }
	if err := os.Rename(stagePath, current.root); err != nil { _ = os.Rename(backupPath, current.root); return ExecutionReceipt{}, err }
	if err := runtime.activateApplicationRelease(manifest); err != nil {
		_ = os.Rename(current.root, stagePath)
		_ = os.Rename(backupPath, current.root)
		return ExecutionReceipt{}, err
	}
	committed = true
	_ = os.RemoveAll(backupPath)
	return receiptForApplication("install", execution.Scope, execution.Installation, execution, execution.Definition.Artifact.Digest, execution.ReleaseID, "", false), nil
}

func certifiedApplicationPreservePaths(kind ApplicationKind) []string {
	switch kind {
	case ApplicationJoomla:
		return []string{"configuration.php", "images", ".well-known"}
	case ApplicationPrestaShop:
		return []string{"app/config/parameters.php", "config/settings.inc.php", "img", "download", "upload", ".well-known"}
	case ApplicationMautic:
		return []string{"config/local.php", "app/config/local.php", "media", ".well-known"}
	case ApplicationMagento:
		return []string{"app/etc/env.php", "pub/media", ".well-known"}
	default:
		return nil
	}
}

func (runtime *LinuxApplicationRuntime) prepareCertifiedApplicationUpdate(ctx context.Context, execution UpdateExecution) (ExecutionReceipt, error) {
	if err := validateCertifiedUpdateExecution(execution); err != nil { return ExecutionReceipt{}, err }
	current, err := runtime.loadActiveApplicationManifest(execution.Installation)
	if err != nil { return ExecutionReceipt{}, err }
	if current.Kind != execution.Definition.Kind || current.InstallationID != execution.Installation || current.ReleaseID != execution.FromReleaseID || !applicationManifestMatchesScope(current, execution.Scope) { return ExecutionReceipt{}, ErrConflict }
	if _, err := pinnedApplicationArtifactPath(execution.Definition.Artifact); err != nil { return ExecutionReceipt{}, err }
	if err := runtime.VerifyApplicationSnapshot(ctx, execution.SnapshotID); err != nil { return ExecutionReceipt{}, err }
	return receiptForApplication("prepare_update", execution.Scope, execution.Installation, execution, execution.TargetRelease.ContentDigest, execution.TargetRelease.ID, execution.SnapshotID, false), nil
}

func (runtime *LinuxApplicationRuntime) applyCertifiedApplicationUpdate(ctx context.Context, execution UpdateExecution) (ExecutionReceipt, error) {
	if err := validateCertifiedUpdateExecution(execution); err != nil { return ExecutionReceipt{}, err }
	currentScope, err := runtime.resolve(ctx, execution.Scope)
	if err != nil { return ExecutionReceipt{}, err }
	shadow, err := runtime.shadowScope(currentScope, execution.ShadowBinding)
	if err != nil { return ExecutionReceipt{}, err }
	current, err := runtime.loadActiveApplicationManifest(execution.Installation)
	if err != nil { return ExecutionReceipt{}, err }
	if current.Kind != execution.Definition.Kind || current.ReleaseID != execution.FromReleaseID || !applicationManifestMatchesScope(current, execution.Scope) { return ExecutionReceipt{}, ErrConflict }
	stagePath := shadow.root + ".next"
	previousPath := shadow.root + ".previous"
	for _, candidate := range []string{stagePath, previousPath} {
		if !strings.HasPrefix(candidate, filepath.Dir(shadow.root)+string(os.PathSeparator)) { return ExecutionReceipt{}, ErrPolicyDenied }
		if _, statErr := os.Lstat(candidate); statErr == nil { return ExecutionReceipt{}, ErrConflict } else if !errors.Is(statErr, os.ErrNotExist) { return ExecutionReceipt{}, statErr }
	}
	if err := ensureSiteOwnedDirectory(stagePath, shadow.binding); err != nil { return ExecutionReceipt{}, err }
	stage := linuxApplicationScope{binding: shadow.binding, root: stagePath}
	committed := false
	defer func() { if !committed { _ = os.RemoveAll(stagePath) } }()
	if err := runtime.extractPinnedApplicationArtifact(ctx, stage, execution.Definition.Artifact); err != nil { return ExecutionReceipt{}, err }
	for _, relative := range certifiedApplicationPreservePaths(current.Kind) {
		if err := runtime.copyApplicationPath(ctx, shadow, stage, relative, false); err != nil && !errors.Is(err, os.ErrNotExist) { return ExecutionReceipt{}, err }
	}
	if err := validateCertifiedApplicationConfiguration(stage, current.Kind); err != nil { return ExecutionReceipt{}, err }
	manifest := applicationManifestFromUpdate(current, execution)
	if err := runtime.saveApplicationReleaseManifest(manifest); err != nil { return ExecutionReceipt{}, err }
	if err := os.Rename(shadow.root, previousPath); err != nil { return ExecutionReceipt{}, err }
	if err := os.Rename(stagePath, shadow.root); err != nil { _ = os.Rename(previousPath, shadow.root); return ExecutionReceipt{}, err }
	if err := os.RemoveAll(previousPath); err != nil {
		_ = os.Rename(shadow.root, stagePath)
		_ = os.Rename(previousPath, shadow.root)
		return ExecutionReceipt{}, err
	}
	committed = true
	return receiptForApplication("apply_update", execution.Scope, execution.Installation, execution, execution.TargetRelease.ContentDigest, execution.TargetRelease.ID, execution.SnapshotID, false), nil
}

func (runtime *LinuxApplicationRuntime) runCertifiedApplicationUpgrade(ctx context.Context, scope linuxApplicationScope, manifest linuxApplicationReleaseManifest) error {
	switch manifest.Kind {
	case ApplicationJoomla:
		if err := runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "cli/joomla.php", "database:fix", "--no-interaction"); err != nil { return err }
		if _, stderr, _, err := runtime.command(ctx, scope, "/usr/bin/rm", nil, 1<<20, "-rf", "--", filepath.Join(scope.root, "installation")); err != nil { return fmt.Errorf("remove Joomla installer: %w: %s", err, boundedApplicationOutput(stderr)) }
		return runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "cli/joomla.php", "cache:clean", "--no-interaction")
	case ApplicationPrestaShop:
		if err := runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "install/upgrade/upgrade.php"); err != nil { return err }
		_, _, _, err := runtime.command(ctx, scope, "/usr/bin/rm", nil, 1<<20, "-rf", "--", filepath.Join(scope.root, "install"))
		return err
	case ApplicationMautic:
		if err := runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/console", "doctrine:migrations:migrate", "--no-interaction", "--allow-no-migration"); err != nil { return err }
		if err := runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/console", "mautic:assets:generate", "--no-interaction"); err != nil { return err }
		return runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/console", "cache:clear", "--no-warmup", "--no-interaction")
	case ApplicationMagento:
		if err := runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/magento", "maintenance:enable", "--no-interaction"); err != nil { return err }
		disableMaintenance := true
		defer func() {
			if disableMaintenance {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
				defer cancel()
				_ = runtime.runApplicationPHP(cleanup, scope, manifest.RuntimeID, "bin/magento", "maintenance:disable", "--no-interaction")
			}
		}()
		if err := runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/magento", "setup:upgrade", "--keep-generated", "--no-interaction"); err != nil { return err }
		if err := runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/magento", "setup:di:compile", "--no-interaction"); err != nil { return err }
		if err := runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/magento", "setup:static-content:deploy", "-f", "--no-interaction"); err != nil { return err }
		if err := runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/magento", "indexer:reindex", "--no-interaction"); err != nil { return err }
		if err := runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/magento", "cache:flush", "--no-interaction"); err != nil { return err }
		disableMaintenance = false
		return runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/magento", "maintenance:disable", "--no-interaction")
	default:
		return ErrUnsupported
	}
}

func (runtime *LinuxApplicationRuntime) promoteApplicationRelease(ctx context.Context, execution PromotionExecution) (ExecutionReceipt, error) {
	if execution.Scope.Validate() != nil || !validID(string(execution.Installation)) || !validID(string(execution.FromReleaseID)) || !validID(string(execution.ToReleaseID)) || !validID(string(execution.SnapshotID)) || !validDigest(execution.ExpectedHealthDigest) || execution.WriteFrontier == 0 { return ExecutionReceipt{}, ErrInvalid }
	scope, err := runtime.resolve(ctx, execution.Scope)
	if err != nil { return ExecutionReceipt{}, err }
	manifest, err := runtime.loadApplicationReleaseManifest(execution.Installation, execution.ToReleaseID)
	if err != nil { return ExecutionReceipt{}, err }
	if !applicationManifestMatchesScope(manifest, execution.Scope) { return ExecutionReceipt{}, ErrPolicyDenied }
	if manifest.Kind != ApplicationWordPress {
		if err := runtime.runCertifiedApplicationUpgrade(ctx, scope, manifest); err != nil { return ExecutionReceipt{}, err }
	}
	if err := runtime.activateApplicationRelease(manifest); err != nil { return ExecutionReceipt{}, err }
	return receiptForApplication("promote", execution.Scope, execution.Installation, execution, execution.ToReleaseID, execution.ToReleaseID, execution.SnapshotID, false), nil
}

func (runtime *LinuxApplicationRuntime) rollbackApplicationRelease(ctx context.Context, execution PromotionExecution) (ExecutionReceipt, error) {
	if execution.Scope.Validate() != nil || !validID(string(execution.Installation)) || !validID(string(execution.FromReleaseID)) || !validID(string(execution.ToReleaseID)) || !validID(string(execution.SnapshotID)) || execution.WriteFrontier == 0 { return ExecutionReceipt{}, ErrInvalid }
	scope, err := runtime.resolve(ctx, execution.Scope)
	if err != nil { return ExecutionReceipt{}, err }
	manifest, err := runtime.loadApplicationReleaseManifest(execution.Installation, execution.ToReleaseID)
	if err != nil { return ExecutionReceipt{}, err }
	if !applicationManifestMatchesScope(manifest, execution.Scope) { return ExecutionReceipt{}, ErrPolicyDenied }
	if execution.SnapshotID != "" {
		if err := runtime.restoreApplicationDatabase(ctx, scope, manifest, execution.SnapshotID); err != nil { return ExecutionReceipt{}, err }
	}
	if err := runtime.activateApplicationRelease(manifest); err != nil { return ExecutionReceipt{}, err }
	return receiptForApplication("rollback", execution.Scope, execution.Installation, execution, execution.ToReleaseID, execution.ToReleaseID, execution.SnapshotID, false), nil
}

func (runtime *LinuxApplicationRuntime) repairCertifiedApplication(ctx context.Context, execution RepairExecution) (ExecutionReceipt, error) {
	if execution.Scope.Validate() != nil || !validID(string(execution.Installation)) || execution.Kind == ApplicationWordPress || len(execution.Actions) == 0 || len(execution.Actions) > 16 { return ExecutionReceipt{}, ErrInvalid }
	manifest, err := runtime.loadActiveApplicationManifest(execution.Installation)
	if err != nil { return ExecutionReceipt{}, err }
	if manifest.Kind != execution.Kind || manifest.RecipeDigest != execution.Recipe.RecipeDigest || !applicationManifestMatchesScope(manifest, execution.Scope) { return ExecutionReceipt{}, ErrConflict }
	scope, err := runtime.resolve(ctx, execution.Scope)
	if err != nil { return ExecutionReceipt{}, err }
	for _, action := range execution.Actions {
		switch action {
		case RepairCache:
			switch manifest.Kind {
			case ApplicationJoomla: err = runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "cli/joomla.php", "cache:clean", "--no-interaction")
			case ApplicationPrestaShop, ApplicationMautic: err = runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/console", "cache:clear", "--no-warmup", "--no-interaction")
			case ApplicationMagento: err = runtime.runApplicationPHP(ctx, scope, manifest.RuntimeID, "bin/magento", "cache:flush", "--no-interaction")
			}
		case RepairDatabase:
			err = runtime.runCertifiedApplicationUpgrade(ctx, scope, manifest)
		case RepairPermissions:
			err = os.Chown(scope.root, int(scope.binding.UID), int(scope.binding.GID))
		default:
			return ExecutionReceipt{}, ErrUnsupported
		}
		if err != nil { return ExecutionReceipt{}, err }
	}
	return receiptForApplication("repair", execution.Scope, execution.Installation, execution, execution.Actions, "", SnapshotID(execution.RecoveryPointID), false), nil
}

func (runtime *LinuxApplicationRuntime) applicationVersion(ctx context.Context, scope linuxApplicationScope, manifest linuxApplicationReleaseManifest) (string, error) {
	var stdout, stderr []byte
	var err error
	switch manifest.Kind {
	case ApplicationJoomla:
		stdout, stderr, _, err = runtime.php(ctx, scope, manifest.RuntimeID, nil, 1<<20, filepath.Join(scope.root, "cli/joomla.php"), "--version")
	case ApplicationPrestaShop:
		stdout, stderr, _, err = runtime.php(ctx, scope, manifest.RuntimeID, nil, 1<<20, "-r", "require 'config/defines.inc.php'; echo _PS_VERSION_; ")
	case ApplicationMautic:
		stdout, stderr, _, err = runtime.php(ctx, scope, manifest.RuntimeID, nil, 1<<20, filepath.Join(scope.root, "bin/console"), "--version")
	case ApplicationMagento:
		stdout, stderr, _, err = runtime.php(ctx, scope, manifest.RuntimeID, nil, 1<<20, filepath.Join(scope.root, "bin/magento"), "--version")
	default:
		return "", ErrUnsupported
	}
	if err != nil { return "", fmt.Errorf("application version: %w: %s", err, boundedApplicationOutput(stderr)) }
	value := strings.TrimSpace(string(stdout))
	if strings.Contains(value, manifest.ProductVersion) { return manifest.ProductVersion, nil }
	detected := certifiedVersionPattern.FindString(value)
	if detected == "" || !versionPattern.MatchString(detected) { return "", ErrIntegrity }
	return detected, nil
}

func certifiedApplicationEntrypoints(kind ApplicationKind) []string {
	switch kind {
	case ApplicationJoomla: return []string{"index.php", "cli/joomla.php"}
	case ApplicationPrestaShop: return []string{"index.php", "bin/console"}
	case ApplicationMautic: return []string{"index.php", "bin/console"}
	case ApplicationMagento: return []string{"pub/index.php", "bin/magento"}
	default: return nil
	}
}

func (runtime *LinuxApplicationRuntime) applicationIntegrity(scope linuxApplicationScope, manifest linuxApplicationReleaseManifest) (string, error) {
	if err := validateCertifiedApplicationConfiguration(scope, manifest.Kind); err != nil { return "", err }
	hash := sha256.New()
	for _, relative := range certifiedApplicationEntrypoints(manifest.Kind) {
		parsed := MustRelativePath(relative)
		entry, err := secureLinuxApplicationEntry(scope.root, parsed)
		if err != nil { return "", err }
		info, err := os.Lstat(entry)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() { return "", ErrIntegrity }
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != scope.binding.UID || stat.Gid != scope.binding.GID { return "", ErrPolicyDenied }
		_, _ = hash.Write([]byte(relative + "\x00" + strconv.FormatInt(info.Size(), 10) + "\x00" + info.Mode().String() + "\x00"))
	}
	_, _ = hash.Write([]byte(manifest.Artifact.Digest))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func applicationOptionFileValue(value []byte) (string, error) {
	if len(value) == 0 || len(value) > 4096 || bytes.IndexByte(value, 0) >= 0 || bytes.Contains(value, []byte("\r")) || bytes.Contains(value, []byte("\n")) { return "", ErrIntegrity }
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"")
	return replacer.Replace(string(value)), nil
}

func (runtime *LinuxApplicationRuntime) withApplicationDatabaseDefaults(ctx context.Context, scope linuxApplicationScope, manifest linuxApplicationReleaseManifest, callback func(string) error) error {
	if manifest.Database.EndpointRef != "local-mariadb" || manifest.Database.Engine != "mariadb" { return ErrUnsupported }
	password, err := runtime.Secrets.ApplicationSecret(ctx, manifest.Database.PasswordRef, manifest.TenantID, manifest.SiteID, manifest.InstallationID, "database")
	if err != nil { return err }
	defer wipeLinuxApplicationBytes(password)
	encoded, err := applicationOptionFileValue(password)
	if err != nil { return err }
	content := []byte("[client]\nuser=\"" + manifest.Database.PrincipalName + "\"\npassword=\"" + encoded + "\"\nhost=localhost\nprotocol=socket\ndefault-character-set=utf8mb4\n")
	defer wipeLinuxApplicationBytes(content)
	defaults, err := writeSiteTemporaryFile(scope, ".cyberpanel-database-*.cnf", content)
	if err != nil { return err }
	defer wipeApplicationBootstrapFile(defaults)
	return callback(defaults)
}

func (runtime *LinuxApplicationRuntime) probeApplicationDatabase(ctx context.Context, scope linuxApplicationScope, manifest linuxApplicationReleaseManifest) (string, error) {
	client, err := applicationMariaDBBinary(false)
	if err != nil { return "", err }
	var output []byte
	err = runtime.withApplicationDatabaseDefaults(ctx, scope, manifest, func(defaults string) error {
		stdout, stderr, _, runErr := runtime.command(ctx, scope, client, nil, 1<<20, "--defaults-extra-file="+defaults, "--batch", "--skip-column-names", "--execute=SELECT 1", manifest.Database.DatabaseName)
		if runErr != nil { return fmt.Errorf("probe application database: %w: %s", runErr, boundedApplicationOutput(stderr)) }
		output = stdout
		return nil
	})
	if err != nil { return "", err }
	if strings.TrimSpace(string(output)) != "1" { return "", ErrIntegrity }
	return linuxApplicationDigest(bytes.TrimSpace(output)), nil
}

func (runtime *LinuxApplicationRuntime) probeApplicationHTTP(ctx context.Context, manifest linuxApplicationReleaseManifest, probe ProbeDefinition) (string, error) {
	canonical, err := url.Parse(manifest.CanonicalURL)
	if err != nil { return "", ErrIntegrity }
	requestURL := *canonical
	requestURL.Path = path.Join(canonical.Path, probe.RelativeEndpoint)
	requestURL.RawPath, requestURL.RawQuery, requestURL.Fragment = "", "", ""
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxIdleConns: 0, TLSHandshakeTimeout: probe.Timeout,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: canonical.Hostname()},
		DialContext: func(dialContext context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: probe.Timeout}).DialContext(dialContext, "tcp", "127.0.0.1:443")
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: probe.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil { return "", err }
	request.Host = canonical.Host
	request.Header.Set("User-Agent", "CyberPanel-Application-Probe/1")
	response, err := client.Do(request)
	if err != nil { return "", err }
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	passed := false
	for _, status := range probe.ExpectedStatus { if response.StatusCode == status { passed = true } }
	if !passed { return "", fmt.Errorf("%w: HTTP status %d", ErrIntegrity, response.StatusCode) }
	return linuxApplicationDigest([]byte(strconv.Itoa(response.StatusCode)+"\x00"+response.Header.Get("Location"))), nil
}

func (runtime *LinuxApplicationRuntime) probeApplicationBackground(ctx context.Context, scope linuxApplicationScope, manifest linuxApplicationReleaseManifest) (string, error) {
	var entry string
	var arguments []string
	switch manifest.Kind {
	case ApplicationMautic:
		entry, arguments = "bin/console", []string{"about", "--no-interaction"}
	case ApplicationMagento:
		entry, arguments = "bin/magento", []string{"indexer:status", "--no-interaction"}
	default:
		return "", ErrUnsupported
	}
	entryPath, err := secureLinuxApplicationEntry(scope.root, MustRelativePath(entry))
	if err != nil { return "", err }
	stdout, stderr, _, runErr := runtime.php(ctx, scope, manifest.RuntimeID, nil, 2<<20, append([]string{entryPath}, arguments...)...)
	if runErr != nil { return "", fmt.Errorf("application background probe: %w: %s", runErr, boundedApplicationOutput(stderr)) }
	return linuxApplicationDigest(bytes.TrimSpace(stdout)), nil
}

func (runtime *LinuxApplicationRuntime) observeCertifiedApplication(ctx context.Context, scope linuxApplicationScope, manifest linuxApplicationReleaseManifest, activated bool) (ComponentInventory, HealthObservation, error) {
	if err := manifest.Validate(); err != nil { return ComponentInventory{}, HealthObservation{}, err }
	now := time.Now().UTC()
	receipts := make([]ProbeReceipt, 0, len(manifest.Probes)+1)
	healthState := HealthHealthy
	failures := make([]string, 0)
	record := func(name string, required bool, started time.Time, digest string, probeErr error) {
		passed := probeErr == nil && validDigest(digest)
		if !passed { digest = linuxApplicationDigest([]byte(name+"\x00failed")); failures = append(failures, name); if required { healthState = HealthUnhealthy } else if healthState == HealthHealthy { healthState = HealthDegraded } }
		receipts = append(receipts, ProbeReceipt{Name: name, Passed: passed, Digest: digest, Duration: time.Since(started), ObservedAt: time.Now().UTC()})
	}
	started := time.Now()
	versionContext, cancelVersion := context.WithTimeout(ctx, 2*time.Minute)
	version, versionErr := runtime.applicationVersion(versionContext, scope, manifest)
	cancelVersion()
	if versionErr == nil && version != manifest.ProductVersion { versionErr = ErrIntegrity }
	versionDigest := ""
	if versionErr == nil { versionDigest = linuxApplicationDigest([]byte(version)) }
	record("application_version", true, started, versionDigest, versionErr)
	started = time.Now()
	integrityDigest, integrityErr := runtime.applicationIntegrity(scope, manifest)
	record("application_structure", true, started, integrityDigest, integrityErr)
	for _, probe := range manifest.Probes {
		started = time.Now()
		if !activated && (probe.Kind == ProbeHTTP || probe.Kind == ProbeBackground) { continue }
		probeContext, cancelProbe := context.WithTimeout(ctx, probe.Timeout)
		switch probe.Kind {
		case ProbeHTTP:
			digest, probeErr := runtime.probeApplicationHTTP(probeContext, manifest, probe)
			record(probe.Name, probe.Required, started, digest, probeErr)
		case ProbeDatabase:
			digest, probeErr := runtime.probeApplicationDatabase(probeContext, scope, manifest)
			record(probe.Name, probe.Required, started, digest, probeErr)
		case ProbeBackground:
			digest, probeErr := runtime.probeApplicationBackground(probeContext, scope, manifest)
			record(probe.Name, probe.Required, started, digest, probeErr)
		case ProbeIntegrity:
			record(probe.Name, probe.Required, started, integrityDigest, integrityErr)
		case ProbeCLI:
			record(probe.Name, probe.Required, started, versionDigest, versionErr)
		}
		cancelProbe()
	}
	component := Component{Kind: ComponentCore, Name: string(manifest.Kind), Version: manifest.ProductVersion, Digest: manifest.Artifact.Digest, State: ComponentActive, Origin: "cyberpanel-signed-catalog"}
	inventory := ComponentInventory{InstallationID: manifest.InstallationID, Generation: uint64(now.UnixNano()), ObservedAt: now, SourceDigest: linuxApplicationDigest([]byte(string(manifest.ReleaseID)+"\x00"+manifest.Artifact.Digest)), Components: []Component{component}}
	summary := "all required application probes passed"
	if len(failures) > 0 { summary = "failed probes: " + strings.Join(failures, ", ") }
	health := HealthObservation{State: healthState, CheckedAt: now, DefinitionDigest: manifest.DefinitionDigest, ReleaseDigest: manifest.Artifact.Digest, ProbeReceipts: receipts, Summary: summary}
	return inventory, health, nil
}

func (runtime *LinuxApplicationRuntime) inspectCertifiedApplication(ctx context.Context, execution InspectExecution) (ComponentInventory, HealthObservation, ExecutionReceipt, error) {
	if execution.Scope.Validate() != nil || !validID(string(execution.Installation)) || execution.Kind == ApplicationWordPress || !validDigest(execution.RecipeDigest) { return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, ErrInvalid }
	manifest, err := runtime.loadActiveApplicationManifest(execution.Installation)
	if err != nil { return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, err }
	if manifest.Kind != execution.Kind || manifest.RecipeDigest != execution.RecipeDigest || !applicationManifestMatchesScope(manifest, execution.Scope) { return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, ErrConflict }
	scope, err := runtime.resolve(ctx, execution.Scope)
	if err != nil { return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, err }
	inventory, health, err := runtime.observeCertifiedApplication(ctx, scope, manifest, true)
	if err != nil { return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, err }
	return inventory, health, receiptForApplication("inspect", execution.Scope, execution.Installation, execution, inventory, manifest.ReleaseID, "", false), nil
}

func (runtime *LinuxApplicationRuntime) probeCertifiedApplicationUpdate(ctx context.Context, execution UpdateExecution) (HealthObservation, ExecutionReceipt, error) {
	if err := validateCertifiedUpdateExecution(execution); err != nil { return HealthObservation{}, ExecutionReceipt{}, err }
	manifest, err := runtime.loadApplicationReleaseManifest(execution.Installation, execution.TargetRelease.ID)
	if err != nil { return HealthObservation{}, ExecutionReceipt{}, err }
	if manifest.Kind != execution.Definition.Kind || manifest.RecipeDigest != execution.Definition.Recipe.RecipeDigest || !applicationManifestMatchesScope(manifest, execution.Scope) { return HealthObservation{}, ExecutionReceipt{}, ErrConflict }
	scope, err := runtime.resolve(ctx, execution.Scope)
	if err != nil { return HealthObservation{}, ExecutionReceipt{}, err }
	shadow, err := runtime.shadowScope(scope, execution.ShadowBinding)
	if err != nil { return HealthObservation{}, ExecutionReceipt{}, err }
	inventory, health, err := runtime.observeCertifiedApplication(ctx, shadow, manifest, false)
	if err != nil { return HealthObservation{}, ExecutionReceipt{}, err }
	return health, receiptForApplication("probe_update", execution.Scope, execution.Installation, execution, inventory, execution.TargetRelease.ID, execution.SnapshotID, false), nil
}

func (runtime *LinuxApplicationRuntime) dumpApplicationDatabase(ctx context.Context, scope linuxApplicationScope, manifest linuxApplicationReleaseManifest, destination string, maximum uint64) error {
	binary, err := applicationMariaDBBinary(true)
	if err != nil { return err }
	err = runtime.withApplicationDatabaseDefaults(ctx, scope, manifest, func(defaults string) error {
		_, stderr, _, runErr := runtime.command(ctx, scope, binary, nil, 2<<20, "--defaults-extra-file="+defaults, "--single-transaction", "--skip-lock-tables", "--routines", "--events", "--triggers", "--hex-blob", "--result-file="+destination, manifest.Database.DatabaseName)
		if runErr != nil { return fmt.Errorf("snapshot application database: %w: %s", runErr, boundedApplicationOutput(stderr)) }
		return nil
	})
	if err != nil { return err }
	info, err := os.Lstat(destination)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || uint64(info.Size()) > maximum { return ErrIntegrity }
	if err := os.Chmod(destination, 0600); err != nil { return err }
	return nil
}

func extractApplicationDatabaseSnapshot(snapshot Snapshot, directory string, maximum uint64) (string, error) {
	archivePath := filepath.Join(linuxApplicationSnapshotRoot, string(snapshot.ID), "snapshot.tar.gz")
	file, err := os.Open(archivePath)
	if err != nil { return "", err }
	defer file.Close()
	zip, err := gzip.NewReader(file)
	if err != nil { return "", ErrIntegrity }
	defer zip.Close()
	reader := tar.NewReader(zip)
	expected := "." + string(snapshot.ID) + ".sql"
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) { return "", ErrNotFound }
		if nextErr != nil { return "", nextErr }
		name := strings.TrimPrefix(header.Name, "./")
		if name != expected { continue }
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size <= 0 || uint64(header.Size) > maximum { return "", ErrIntegrity }
		target, err := os.CreateTemp(directory, ".cyberpanel-restore-*.sql")
		if err != nil { return "", err }
		destination := target.Name()
		copied, copyErr := io.Copy(target, io.LimitReader(reader, int64(maximum)+1))
		syncErr := target.Sync()
		closeErr := target.Close()
		if err = errors.Join(copyErr, syncErr, closeErr); err != nil { _ = os.Remove(destination); return "", err }
		if copied != header.Size { _ = os.Remove(destination); return "", ErrIntegrity }
		return destination, nil
	}
}

func (runtime *LinuxApplicationRuntime) clearApplicationDatabase(ctx context.Context, scope linuxApplicationScope, manifest linuxApplicationReleaseManifest, client, defaults string) error {
	stdout, stderr, _, err := runtime.command(ctx, scope, client, nil, 8<<20, "--defaults-extra-file="+defaults, "--batch", "--skip-column-names", "--execute=SHOW FULL TABLES", manifest.Database.DatabaseName)
	if err != nil { return fmt.Errorf("inventory application database: %w: %s", err, boundedApplicationOutput(stderr)) }
	lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	if len(lines) > 100000 { return ErrPolicyDenied }
	var statements strings.Builder
	statements.WriteString("SET FOREIGN_KEY_CHECKS=0;\n")
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) == 0 || fields[0] == "" || strings.ContainsAny(fields[0], "\x00\r\n") { continue }
		name := strings.ReplaceAll(fields[0], "`", "``")
		if len(fields) > 1 && strings.EqualFold(fields[1], "VIEW") { statements.WriteString("DROP VIEW IF EXISTS `"+name+"`;\n") } else { statements.WriteString("DROP TABLE IF EXISTS `"+name+"`;\n") }
	}
	statements.WriteString("SET FOREIGN_KEY_CHECKS=1;\n")
	_, stderr, _, err = runtime.command(ctx, scope, client, []byte(statements.String()), 2<<20, "--defaults-extra-file="+defaults, manifest.Database.DatabaseName)
	if err != nil { return fmt.Errorf("clear application database: %w: %s", err, boundedApplicationOutput(stderr)) }
	return nil
}

func (runtime *LinuxApplicationRuntime) restoreApplicationDatabase(ctx context.Context, scope linuxApplicationScope, manifest linuxApplicationReleaseManifest, snapshotID SnapshotID) error {
	snapshot, err := loadLinuxApplicationSnapshot(snapshotID)
	if err != nil { return err }
	if snapshot.InstallationID != manifest.InstallationID || snapshot.DatabaseDigest == "" { return ErrIntegrity }
	directory, err := applicationPrivateTemporaryDirectory(scope)
	if err != nil { return err }
	temporary, err := extractApplicationDatabaseSnapshot(snapshot, directory, 256<<30)
	if err != nil { return err }
	defer os.Remove(temporary)
	digest, err := digestLinuxApplicationFile(temporary, 256<<30)
	if err != nil || digest != snapshot.DatabaseDigest { return ErrIntegrity }
	if err := os.Chown(temporary, int(scope.binding.UID), int(scope.binding.GID)); err != nil { return err }
	client, err := applicationMariaDBBinary(false)
	if err != nil { return err }
	return runtime.withApplicationDatabaseDefaults(ctx, scope, manifest, func(defaults string) error {
		if err := runtime.clearApplicationDatabase(ctx, scope, manifest, client, defaults); err != nil { return err }
		input, err := os.Open(temporary)
		if err != nil { return err }
		defer input.Close()
		stdout, stderr, exit, runErr := runtime.commandReader(ctx, scope, client, input, 2<<20, "--defaults-extra-file="+defaults, manifest.Database.DatabaseName)
		_ = stdout
		if runErr != nil { return fmt.Errorf("restore application database: %w: %s", runErr, boundedApplicationOutput(stderr)) }
		if exit != 0 { return fmt.Errorf("%w: restore application database exit %d", ErrIntegrity, exit) }
		return nil
	})
}

func (runtime *LinuxApplicationRuntime) commandReader(ctx context.Context, scope linuxApplicationScope, binary string, input io.Reader, maximum int, args ...string) ([]byte, []byte, int, error) {
	if maximum <= 0 || maximum > 8<<20 { maximum = 8 << 20 }
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = scope.root
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME="+scope.root, "LANG=C.UTF-8"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: scope.binding.UID, Gid: scope.binding.GID, NoSetGroups: true}}
	command.Stdin = input
	var stdout, stderr limitedApplicationBuffer
	stdout.maximum, stderr.maximum = maximum, maximum
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exit *exec.ExitError
		if errors.As(err, &exit) { exitCode = exit.ExitCode() }
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode, err
}
