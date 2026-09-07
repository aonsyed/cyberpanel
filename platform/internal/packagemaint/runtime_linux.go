//go:build linux

package packagemaint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	DefaultLinuxRuntimeCatalogPath = "/etc/cyberpanel/package-maintenance/catalog.json"
	DefaultLinuxRuntimeTrustRoot   = "/etc/cyberpanel/package-maintenance/trust.d"
	LinuxBrokerSocketPath          = "/run/cyberpanel/package-maintenance.sock"
	DefaultLinuxJournalRoot        = "/var/lib/cyberpanel/package-maintenance"

	LinuxAuthorizationAdapterID      = "package.maintenance.authorization"
	LinuxAuthorizationAdapterVersion = "linux-local-v1"

	linuxAuthorizationDomain = "cyberpanel-package-maintenance-authorization-v1\n"
	linuxCatalogMaximumBytes = 16 << 20
	linuxTrustKeyMaximumBytes = 4096
)

type LinuxRepositoryPolicy struct {
	ID                string  `json:"id"`
	Manager           Manager `json:"manager"`
	Origin            string  `json:"origin"`
	MetadataRevision  string  `json:"metadata_revision"`
	SigningKeyID      string  `json:"signing_key_id"`
	TrustAnchorDigest string  `json:"trust_anchor_digest"`
}

type LinuxPackageRule struct {
	Name           string       `json:"name"`
	Architecture   string       `json:"architecture"`
	Action         ChangeAction `json:"action"`
	FromVersion    string       `json:"from_version"`
	ToVersion      string       `json:"to_version"`
	RepositoryID   string       `json:"repository_id"`
}

type LinuxTransactionPolicy struct {
	ID       string               `json:"id"`
	IndividualUpdate bool         `json:"individual_update,omitempty"`
	Packages []LinuxPackageRule   `json:"packages"`
	Services []ServiceImpact      `json:"services"`
	Disk     DiskEstimate         `json:"disk"`
	Reboot   RebootEstimate       `json:"reboot"`
	Recovery RecoveryEligibility  `json:"recovery"`
	Frontier IrreversibleFrontier `json:"frontier"`
}

type LinuxAuthorizationKey struct {
	ID        string    `json:"id"`
	PublicKey string    `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// LinuxRuntimeCatalog is a release-signed, support-tuple-specific package
// maintenance policy. It is the only source of package identities, repository
// epochs, service probes, and authorization verification keys.
type LinuxRuntimeCatalog struct {
	SchemaVersion     uint32                   `json:"schema_version"`
	Sequence          uint64                   `json:"sequence"`
	IssuedAt          time.Time                `json:"issued_at"`
	ExpiresAt         time.Time                `json:"expires_at"`
	NodeID            string                   `json:"node_id"`
	Manager           Manager                  `json:"manager"`
	Repositories      []LinuxRepositoryPolicy  `json:"repositories"`
	Transactions      []LinuxTransactionPolicy `json:"transactions"`
	AuthorizationKeys []LinuxAuthorizationKey  `json:"authorization_keys"`

	digest            string
	authorizationKeys map[string]ed25519.PublicKey
}

type signedLinuxRuntimeCatalog struct {
	Payload   LinuxRuntimeCatalog `json:"payload"`
	KeyID     string              `json:"key_id"`
	Signature string              `json:"signature"`
}

func LinuxRuntimeConfigured() (bool, error) {
	catalog, catalogErr := os.Lstat(DefaultLinuxRuntimeCatalogPath)
	trust, trustErr := os.Lstat(DefaultLinuxRuntimeTrustRoot)
	catalogMissing := errors.Is(catalogErr, os.ErrNotExist)
	trustMissing := errors.Is(trustErr, os.ErrNotExist)
	if catalogMissing && trustMissing {
		return false, nil
	}
	if catalogErr != nil || trustErr != nil || catalog == nil || trust == nil {
		return false, fmt.Errorf("package maintenance deployment material is incomplete")
	}
	return true, nil
}

func LoadDefaultLinuxRuntimeCatalog(now time.Time) (*LinuxRuntimeCatalog, error) {
	return LoadLinuxRuntimeCatalog(DefaultLinuxRuntimeCatalogPath, DefaultLinuxRuntimeTrustRoot, now)
}

func LoadLinuxRuntimeCatalog(path, trustRoot string, now time.Time) (*LinuxRuntimeCatalog, error) {
	if path != DefaultLinuxRuntimeCatalogPath || trustRoot != DefaultLinuxRuntimeTrustRoot || now.IsZero() {
		return nil, ErrInvalid
	}
	raw, err := readRootOwnedLinuxRuntimeFile(path, linuxCatalogMaximumBytes)
	if err != nil {
		return nil, err
	}
	var signed signedLinuxRuntimeCatalog
	if err = decodeLinuxRuntimeJSON(raw, &signed); err != nil || !safeID.MatchString(signed.KeyID) || signed.Signature == "" {
		return nil, ErrUnauthorized
	}
	canonical, err := json.Marshal(signed.Payload)
	if err != nil {
		return nil, err
	}
	publicKey, err := readLinuxRuntimeTrustKey(trustRoot, signed.KeyID)
	if err != nil {
		return nil, err
	}
	signature, err := decodeLinuxRuntimeBase64(signed.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(publicKey, canonical, signature) {
		return nil, ErrUnauthorized
	}
	catalog := signed.Payload
	if err = catalog.validate(now.UTC()); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	catalog.digest = hex.EncodeToString(digest[:])
	catalog.authorizationKeys = make(map[string]ed25519.PublicKey, len(catalog.AuthorizationKeys))
	for _, entry := range catalog.AuthorizationKeys {
		decoded, decodeErr := decodeLinuxRuntimeBase64(entry.PublicKey, ed25519.PublicKeySize)
		if decodeErr != nil {
			return nil, ErrInvalid
		}
		catalog.authorizationKeys[entry.ID] = ed25519.PublicKey(decoded)
	}
	return &catalog, nil
}

func (catalog LinuxRuntimeCatalog) validate(now time.Time) error {
	if catalog.SchemaVersion != 1 || catalog.Sequence == 0 || catalog.IssuedAt.IsZero() || !catalog.ExpiresAt.After(catalog.IssuedAt) ||
		catalog.IssuedAt.After(now.Add(5*time.Minute)) || !now.Before(catalog.ExpiresAt) || catalog.ExpiresAt.Sub(catalog.IssuedAt) > 370*24*time.Hour ||
		!safeID.MatchString(catalog.NodeID) || !validManager(catalog.Manager) || len(catalog.Repositories) == 0 ||
		len(catalog.Repositories) > MaximumRepositories || len(catalog.Transactions) == 0 || len(catalog.Transactions) > 128 ||
		len(catalog.AuthorizationKeys) == 0 || len(catalog.AuthorizationKeys) > 32 {
		return ErrInvalid
	}
	repositories := make(map[string]struct{}, len(catalog.Repositories))
	trustAnchor := ""
	for _, repository := range catalog.Repositories {
		if !safeID.MatchString(repository.ID) || repository.Manager != catalog.Manager || repository.Origin == "" ||
			len(repository.Origin) > 2048 || strings.ContainsAny(repository.Origin, "\x00\r\n") || !validDigest(repository.MetadataRevision) ||
			!safeID.MatchString(repository.SigningKeyID) || !validDigest(repository.TrustAnchorDigest) {
			return ErrInvalid
		}
		if _, duplicate := repositories[repository.ID]; duplicate {
			return ErrConflict
		}
		repositories[repository.ID] = struct{}{}
		if trustAnchor == "" {
			trustAnchor = repository.TrustAnchorDigest
		} else if trustAnchor != repository.TrustAnchorDigest {
			return ErrInvalid
		}
	}
	transactions := make(map[string]struct{}, len(catalog.Transactions))
	for _, transaction := range catalog.Transactions {
		if !safeID.MatchString(transaction.ID) || len(transaction.Packages) == 0 || len(transaction.Packages) > MaximumChanges ||
			len(transaction.Services) > MaximumServiceImpacts || !validReboot(transaction.Reboot) || validateRecovery(transaction.Recovery) != nil ||
			transaction.Recovery.Kind != RecoveryNone || transaction.Recovery.Eligible || transaction.Recovery.Required ||
			!safeID.MatchString(transaction.Frontier.Step) || !safeID.MatchString(transaction.Frontier.ReasonCode) ||
			!transaction.Frontier.RequiresCommitAuthorization {
			return ErrInvalid
		}
		if _, duplicate := transactions[transaction.ID]; duplicate {
			return ErrConflict
		}
		transactions[transaction.ID] = struct{}{}
		packages := make(map[string]struct{}, len(transaction.Packages))
		for _, rule := range transaction.Packages {
			if transaction.IndividualUpdate && rule.Action != ChangeUpgrade { return ErrInvalid }
			if !safePackage.MatchString(rule.Name) || !safeArchitecture.MatchString(rule.Architecture) ||
				(rule.Action != ChangeUpgrade && rule.Action != ChangeReinstall) || !safeVersion.MatchString(rule.FromVersion) ||
				!safeVersion.MatchString(rule.ToVersion) || !safeID.MatchString(rule.RepositoryID) {
				return ErrInvalid
			}
			if rule.Action == ChangeUpgrade && rule.FromVersion == rule.ToVersion || rule.Action == ChangeReinstall && rule.FromVersion != rule.ToVersion {
				return ErrInvalid
			}
			if _, registered := repositories[rule.RepositoryID]; !registered {
				return ErrUnauthorized
			}
			key := rule.Name + "\x00" + rule.Architecture
			if _, duplicate := packages[key]; duplicate {
				return ErrConflict
			}
			packages[key] = struct{}{}
		}
		services := make(map[string]struct{}, len(transaction.Services))
		for _, service := range transaction.Services {
			if service.Action != ServiceReload && service.Action != ServiceRestart || service.ProbeID != "systemd_active" || linuxServiceProbeUnits[service.ServiceID] == "" {
				return ErrUnsupported
			}
			key := service.ServiceID + "\x00" + service.ProbeID
			if _, duplicate := services[key]; duplicate {
				return ErrConflict
			}
			services[key] = struct{}{}
		}
	}
	authorizationKeys := make(map[string]struct{}, len(catalog.AuthorizationKeys))
	activeAuthorizationKeys := 0
	for _, key := range catalog.AuthorizationKeys {
		decoded, err := decodeLinuxRuntimeBase64(key.PublicKey, ed25519.PublicKeySize)
		if !safeID.MatchString(key.ID) || err != nil || len(decoded) != ed25519.PublicKeySize || key.NotBefore.IsZero() || !key.NotAfter.After(key.NotBefore) {
			return ErrInvalid
		}
		if _, duplicate := authorizationKeys[key.ID]; duplicate {
			return ErrConflict
		}
		authorizationKeys[key.ID] = struct{}{}
		if !now.Before(key.NotBefore) && now.Before(key.NotAfter) {
			activeAuthorizationKeys++
		}
	}
	if activeAuthorizationKeys == 0 {
		return ErrUnauthorized
	}
	return nil
}

func readLinuxRuntimeTrustKey(root, keyID string) (ed25519.PublicKey, error) {
	if root != DefaultLinuxRuntimeTrustRoot || !safeID.MatchString(keyID) {
		return nil, ErrInvalid
	}
	if err := requireRootOwnedLinuxRuntimeDirectory(root); err != nil {
		return nil, err
	}
	path := filepath.Join(root, keyID+".pub")
	if filepath.Dir(path) != root {
		return nil, ErrInvalid
	}
	raw, err := readRootOwnedLinuxRuntimeFile(path, linuxTrustKeyMaximumBytes)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeLinuxRuntimeBase64(strings.TrimSpace(string(raw)), ed25519.PublicKeySize)
	if err != nil {
		return nil, ErrUnauthorized
	}
	return ed25519.PublicKey(decoded), nil
}

func decodeLinuxRuntimeBase64(value string, size int) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		decoded, err := encoding.DecodeString(strings.TrimSpace(value))
		if err == nil && len(decoded) == size {
			return decoded, nil
		}
	}
	return nil, ErrInvalid
}

func requireRootOwnedLinuxRuntimeDirectory(path string) error {
	information, err := os.Lstat(path)
	if err != nil {
		return err
	}
	metadata, ok := information.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 || information.Mode().Perm()&0022 != 0 {
		return ErrUnauthorized
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return ErrUnauthorized
	}
	return nil
}

func readRootOwnedLinuxRuntimeFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	metadata, ok := before.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || metadata.Nlink != 1 || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&0022 != 0 || before.Size() <= 0 || before.Size() > maximum {
		return nil, ErrUnauthorized
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrUnauthorized
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != before.Size() || int64(len(raw)) > maximum {
		return nil, ErrInvalid
	}
	return raw, nil
}

func decodeLinuxRuntimeJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func DetectLinuxManager() (Manager, error) {
	raw, err := readRootOwnedLinuxRuntimeFile("/etc/os-release", 64<<10)
	if err != nil {
		return "", ErrUnsupported
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			values[key] = strings.Trim(strings.TrimSpace(value), "\"")
		}
	}
	switch values["ID"] {
	case "ubuntu":
		if values["VERSION_ID"] == "24.04" {
			return ManagerAPT, nil
		}
	case "almalinux":
		if strings.HasPrefix(values["VERSION_ID"], "9") {
			return ManagerDNF, nil
		}
	}
	return "", ErrUnsupported
}

type LinuxSignedRuntime struct {
	catalog   *LinuxRuntimeCatalog
	runner    Runner
	inventory LinuxInventory
	now       func() time.Time
}

func NewLinuxSignedRuntime(catalog *LinuxRuntimeCatalog, runner Runner, now func() time.Time) (*LinuxSignedRuntime, error) {
	if catalog == nil || catalog.digest == "" || !validDigest(catalog.digest) {
		return nil, ErrInvalid
	}
	manager, err := DetectLinuxManager()
	if err != nil || manager != catalog.Manager {
		return nil, ErrUnsupported
	}
	if runner == nil {
		runner = LinuxRunner{}
	}
	if now == nil {
		now = time.Now
	}
	runtime := &LinuxSignedRuntime{catalog: catalog, runner: runner, now: now}
	runtime.inventory = LinuxInventory{Runner: runner, Now: now}
	return runtime, nil
}

func (runtime *LinuxSignedRuntime) Snapshot(ctx context.Context, request InventoryRequest) (InventorySnapshot, error) {
	if runtime == nil || runtime.catalog == nil || request.NodeID != runtime.catalog.NodeID || request.Manager != runtime.catalog.Manager {
		return InventorySnapshot{}, ErrUnsupported
	}
	snapshot, err := runtime.inventory.Snapshot(ctx, request)
	if err != nil {
		return InventorySnapshot{}, err
	}
	return runtime.trustSnapshot(ctx, snapshot)
}

func (runtime *LinuxSignedRuntime) trustSnapshot(ctx context.Context, snapshot InventorySnapshot) (InventorySnapshot, error) {
	revisions, trustAnchor, err := runtime.repositoryEvidence(ctx, snapshot)
	if err != nil {
		return InventorySnapshot{}, err
	}
	policies := make(map[string]LinuxRepositoryPolicy, len(runtime.catalog.Repositories))
	for _, policy := range runtime.catalog.Repositories {
		policies[policy.ID] = policy
	}
	if len(snapshot.Repositories) != len(policies) {
		return InventorySnapshot{}, ErrUnauthorized
	}
	trusted := make(map[string]LinuxRepositoryPolicy, len(policies))
	for index := range snapshot.Repositories {
		repository := &snapshot.Repositories[index]
		policy, found := policies[repository.ID]
		if !found || repository.Manager != policy.Manager || repository.Origin != policy.Origin || revisions[repository.ID] != policy.MetadataRevision ||
			policy.TrustAnchorDigest != trustAnchor {
			return InventorySnapshot{}, ErrUnauthorized
		}
		repository.MetadataRevision = policy.MetadataRevision
		repository.SigningKeyID = policy.SigningKeyID
		repository.Signature = SignatureVerified
		repository.Digest, err = digestRepository(*repository)
		if err != nil {
			return InventorySnapshot{}, err
		}
		trusted[repository.ID] = policy
	}
	for index := range snapshot.Provenance {
		provenance := &snapshot.Provenance[index]
		if provenance.RepositoryID == "" {
			continue
		}
		policy, found := trusted[provenance.RepositoryID]
		if !found || provenance.LocalArtifact {
			return InventorySnapshot{}, ErrUnauthorized
		}
		provenance.Signature = SignatureVerified
		provenance.SigningKeyID = policy.SigningKeyID
		copyOfProvenance := *provenance
		copyOfProvenance.Digest = ""
		provenance.Digest, err = canonicalDigest(copyOfProvenance)
		if err != nil {
			return InventorySnapshot{}, err
		}
	}
	if err = SealInventory(&snapshot); err != nil {
		return InventorySnapshot{}, err
	}
	return snapshot, nil
}

func (runtime *LinuxSignedRuntime) repositoryEvidence(ctx context.Context, snapshot InventorySnapshot) (map[string]string, string, error) {
	trustAnchor, err := linuxRepositoryTrustAnchorDigest(snapshot.Manager)
	if err != nil {
		return nil, "", err
	}
	if snapshot.Manager == ManagerAPT {
		result, runErr := runtime.runner.Run(ctx, aptGetPath, []string{"indextargets", "--format", "$(IDENTIFIER)\t$(SITE)\t$(RELEASE)\t$(COMPONENT)\t$(TRUSTED)"}, MaximumOutputBytes)
		if runErr != nil || result.ExitCode != 0 || lineLimitExceeded(result.Output, MaximumRepositories) {
			return nil, "", ErrUnsupported
		}
		lines := boundedLines(result.Output, MaximumRepositories)
		if len(lines) == 0 {
			return nil, "", ErrUnauthorized
		}
		for _, line := range lines {
			fields := strings.Split(line, "\t")
			if len(fields) != 5 || !linuxTruthValue(fields[4]) {
				return nil, "", ErrUnauthorized
			}
		}
		sort.Strings(lines)
		return map[string]string{"apt-resolved": digestStrings(lines...)}, trustAnchor, nil
	}
	if err = validateDNFRepositoryConfiguration(runtime.catalog.Repositories); err != nil {
		return nil, "", err
	}
	result, runErr := runtime.runner.Run(ctx, dnfPath, []string{"-q", "--cacheonly", "repoinfo", "--enabled"}, MaximumOutputBytes)
	if runErr != nil || result.ExitCode != 0 || lineLimitExceeded(result.Output, MaximumRepositories*64) {
		return nil, "", ErrUnsupported
	}
	revisions, err := parseDNFRepositoryRevisions(result.Output)
	if err != nil {
		return nil, "", err
	}
	return revisions, trustAnchor, nil
}

func parseDNFRepositoryRevisions(output []byte) (map[string]string, error) {
	revisions := make(map[string]string)
	current := ""
	for _, line := range boundedLines(output, MaximumRepositories*64) {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "repo-id":
			if !safeID.MatchString(value) {
				return nil, ErrInvalid
			}
			current = value
		case "repo-revision":
			if current == "" || value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
				return nil, ErrInvalid
			}
			identifier := "dnf-" + current
			if _, duplicate := revisions[identifier]; duplicate {
				return nil, ErrConflict
			}
			revisions[identifier] = digestStrings(current, value)
		}
	}
	if len(revisions) == 0 || len(revisions) > MaximumRepositories {
		return nil, ErrUnauthorized
	}
	return revisions, nil
}

func linuxTruthValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "yes", "true":
		return true
	default:
		return false
	}
}

type linuxTrustFile struct {
	path   string
	digest string
}

func linuxRepositoryTrustAnchorDigest(manager Manager) (string, error) {
	var roots []string
	var standalone []string
	if manager == ManagerAPT {
		roots = []string{"/etc/apt/sources.list.d", "/etc/apt/keyrings", "/usr/share/keyrings"}
		standalone = []string{"/etc/apt/sources.list"}
	} else if manager == ManagerDNF {
		roots = []string{"/etc/yum.repos.d", "/etc/pki/rpm-gpg"}
	} else {
		return "", ErrUnsupported
	}
	files := make([]linuxTrustFile, 0, 128)
	for _, path := range standalone {
		raw, err := readRootOwnedLinuxRuntimeFile(path, 8<<20)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(raw)
		files = append(files, linuxTrustFile{path: path, digest: hex.EncodeToString(sum[:])})
	}
	for _, root := range roots {
		if err := requireRootOwnedLinuxRuntimeDirectory(root); err != nil {
			return "", err
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return "", err
		}
		for _, entry := range entries {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || len(files) >= 512 {
				continue
			}
			path := filepath.Join(root, entry.Name())
			raw, readErr := readRootOwnedLinuxRuntimeFile(path, 8<<20)
			if readErr != nil {
				return "", readErr
			}
			sum := sha256.Sum256(raw)
			files = append(files, linuxTrustFile{path: path, digest: hex.EncodeToString(sum[:])})
		}
	}
	if len(files) == 0 {
		return "", ErrUnauthorized
	}
	sort.Slice(files, func(left, right int) bool { return files[left].path < files[right].path })
	parts := make([]string, 0, len(files))
	for _, file := range files {
		parts = append(parts, file.path+"\x00"+file.digest)
	}
	return digestStrings(parts...), nil
}

func validateDNFRepositoryConfiguration(policies []LinuxRepositoryPolicy) error {
	root := "/etc/yum.repos.d"
	if err := requireRootOwnedLinuxRuntimeDirectory(root); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	sections := make(map[string]map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".repo" {
			continue
		}
		raw, readErr := readRootOwnedLinuxRuntimeFile(filepath.Join(root, entry.Name()), 1<<20)
		if readErr != nil {
			return readErr
		}
		section := ""
		for _, rawLine := range strings.Split(string(raw), "\n") {
			line := strings.TrimSpace(rawLine)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
				if !safeID.MatchString(section) {
					return ErrInvalid
				}
				if sections[section] == nil {
					sections[section] = make(map[string]string)
				}
				continue
			}
			key, value, found := strings.Cut(line, "=")
			if !found || section == "" {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			if key == "enabled" || key == "gpgcheck" || key == "repo_gpgcheck" || key == "gpgkey" {
				sections[section][key] = strings.TrimSpace(value)
			}
		}
	}
	for _, policy := range policies {
		if !strings.HasPrefix(policy.ID, "dnf-") {
			return ErrInvalid
		}
		section := sections[strings.TrimPrefix(policy.ID, "dnf-")]
		if section == nil || !linuxTruthValue(section["enabled"]) || !linuxTruthValue(section["gpgcheck"]) ||
			!linuxTruthValue(section["repo_gpgcheck"]) || section["gpgkey"] == "" || len(section["gpgkey"]) > 4096 {
			return ErrUnauthorized
		}
	}
	return nil
}

func (runtime *LinuxSignedRuntime) ResolveSecurityUpdates(ctx context.Context, snapshot InventorySnapshot) (SolverAttestation, error) {
	if runtime == nil || runtime.catalog == nil || ctx == nil || snapshot.Validate() != nil || snapshot.NodeID != runtime.catalog.NodeID ||
		snapshot.Manager != runtime.catalog.Manager || runtime.catalog.validate(runtime.now().UTC()) != nil {
		return SolverAttestation{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return SolverAttestation{}, err
	}
	var selected LinuxTransactionPolicy
	var changes []PackageChange
	matches := 0
	for _, transaction := range runtime.catalog.Transactions {
		if transaction.IndividualUpdate { continue }
		resolved, match := linuxTransactionChanges(snapshot, transaction)
		if !match {
			continue
		}
		selected = transaction
		changes = resolved
		matches++
	}
	if matches == 0 {
		return SolverAttestation{}, ErrUnsupported
	}
	if matches != 1 {
		return SolverAttestation{}, ErrConflict
	}
	attestation := SolverAttestation{
		ResolverID:       "signed_linux_" + strconv.FormatUint(runtime.catalog.Sequence, 10),
		InventoryDigest: snapshot.ContentDigest,
		Changes:          changes,
		Services:         append([]ServiceImpact(nil), selected.Services...),
		Disk:             selected.Disk,
		Reboot:           selected.Reboot,
		Recovery:         selected.Recovery,
		Frontier:         selected.Frontier,
		ResolvedAt:       runtime.now().UTC(),
	}
	if err := SealSolverAttestation(&attestation); err != nil {
		return SolverAttestation{}, err
	}
	return attestation, nil
}

func linuxTransactionChanges(snapshot InventorySnapshot, transaction LinuxTransactionPolicy) ([]PackageChange, bool) {
	type candidate struct {
		installed  Package
		provenance Provenance
	}
	candidates := make(map[string]candidate)
	for _, installed := range snapshot.Packages {
		if !installed.PendingSecurity || installed.CandidateVersion == "" || installed.RepositoryID == "" {
			continue
		}
		var source Provenance
		found := false
		for _, provenance := range snapshot.Provenance {
			if provenance.PackageName == installed.Name && provenance.Architecture == installed.Architecture &&
				provenance.Version == installed.CandidateVersion && provenance.RepositoryID == installed.RepositoryID &&
				provenance.Signature == SignatureVerified && provenance.SigningKeyID != "" && !provenance.LocalArtifact {
				source = provenance
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
		candidates[installed.Name+"\x00"+installed.Architecture] = candidate{installed: installed, provenance: source}
	}
	if len(candidates) == 0 || len(candidates) != len(transaction.Packages) {
		return nil, false
	}
	changes := make([]PackageChange, 0, len(transaction.Packages))
	for _, rule := range transaction.Packages {
		value, found := candidates[rule.Name+"\x00"+rule.Architecture]
		if !found || value.installed.InstalledVersion != rule.FromVersion || value.installed.CandidateVersion != rule.ToVersion ||
			value.installed.RepositoryID != rule.RepositoryID {
			return nil, false
		}
		changes = append(changes, PackageChange{Name: rule.Name, Architecture: rule.Architecture, Action: rule.Action,
			FromVersion: rule.FromVersion, ToVersion: rule.ToVersion, RepositoryID: rule.RepositoryID,
			ProvenanceDigest: value.provenance.Digest, Selected: true, Security: SecurityNone})
	}
	return changes, true
}

// IndividualUpdateOption contains an opaque reference to an explicitly signed
// update closure, never a caller-authored package identity or command.
type IndividualUpdateOption struct { Label string `json:"label"`; Value string `json:"value"` }

func InventoryPackageResourceID(snapshot InventorySnapshot, installed Package) string {
	return "pkg_" + digestStrings(snapshot.NodeID, string(snapshot.Manager), installed.Name, installed.Architecture)[:32]
}

func (catalog *LinuxRuntimeCatalog) individualReference(transaction LinuxTransactionPolicy) string {
	return "pkgtx_" + digestStrings(catalog.digest, transaction.ID)[:48]
}

func (catalog *LinuxRuntimeCatalog) IndividualUpdateOptions(snapshot InventorySnapshot, packageID string, now time.Time) []IndividualUpdateOption {
	result := []IndividualUpdateOption{}
	if catalog == nil || catalog.validate(now) != nil || snapshot.Validate() != nil || snapshot.NodeID != catalog.NodeID || snapshot.Manager != catalog.Manager { return result }
	for _, transaction := range catalog.Transactions {
		if !transaction.IndividualUpdate { continue }
		changes, ok := individualTransactionChanges(snapshot, transaction, packageID)
		if !ok { continue }
		for _, change := range changes {
			if InventoryPackageResourceID(snapshot, Package{Name: change.Name, Architecture: change.Architecture}) == packageID {
				result = append(result, IndividualUpdateOption{Label: change.ToVersion + " · " + strconv.Itoa(len(changes)) + " approved package update(s)", Value: catalog.individualReference(transaction)})
				break
			}
		}
	}
	return result
}

func individualTransactionChanges(snapshot InventorySnapshot, transaction LinuxTransactionPolicy, packageID string) ([]PackageChange, bool) {
	if !transaction.IndividualUpdate { return nil, false }
	for _, lock := range snapshot.Locks { if lock.Held || lock.RepairCode != "" { return nil, false } }
	changes := make([]PackageChange, 0, len(transaction.Packages))
	selected := packageID == ""
	for _, rule := range transaction.Packages {
		if rule.Action != ChangeUpgrade || rule.FromVersion == rule.ToVersion { return nil, false }
		for _, hold := range snapshot.Holds { if hold.PackageName == rule.Name { return nil, false } }
		var installed Package
		for _, candidate := range snapshot.Packages { if candidate.Name == rule.Name && candidate.Architecture == rule.Architecture { installed = candidate; break } }
		if installed.InstalledVersion != rule.FromVersion || installed.CandidateVersion != rule.ToVersion || installed.RepositoryID != rule.RepositoryID { return nil, false }
		trustedRepository := false
		keyID := ""
		for _, repository := range snapshot.Repositories { if repository.ID == rule.RepositoryID && repository.Enabled && repository.Signature == SignatureVerified && repository.SigningKeyID != "" { trustedRepository, keyID = true, repository.SigningKeyID } }
		if !trustedRepository { return nil, false }
		var source Provenance
		installedTrusted := false
		for _, provenance := range snapshot.Provenance {
			if provenance.PackageName != rule.Name || provenance.Architecture != rule.Architecture || provenance.RepositoryID != rule.RepositoryID || provenance.Signature != SignatureVerified || provenance.SigningKeyID != keyID || provenance.LocalArtifact { continue }
			if provenance.Version == rule.FromVersion && provenance.Digest == installed.ProvenanceDigest { installedTrusted = true }
			if provenance.Version == rule.ToVersion { source = provenance }
		}
		if !installedTrusted || source.Digest == "" { return nil, false }
		if InventoryPackageResourceID(snapshot, installed) == packageID { selected = true }
		changes = append(changes, PackageChange{Name: rule.Name, Architecture: rule.Architecture, Action: ChangeUpgrade,
			FromVersion: rule.FromVersion, ToVersion: rule.ToVersion, RepositoryID: rule.RepositoryID, ProvenanceDigest: source.Digest, Selected: true, Security: SecurityNone})
	}
	return changes, selected && len(changes) > 0
}

func (runtime *LinuxSignedRuntime) individualAttestation(snapshot InventorySnapshot, transaction LinuxTransactionPolicy, changes []PackageChange) (SolverAttestation, error) {
	attestation := SolverAttestation{ResolverID: runtime.catalog.individualReference(transaction), InventoryDigest: snapshot.ContentDigest,
		Changes: changes, Services: append([]ServiceImpact(nil), transaction.Services...), Disk: transaction.Disk, Reboot: transaction.Reboot,
		Recovery: transaction.Recovery, Frontier: transaction.Frontier, ResolvedAt: runtime.now().UTC()}
	err := SealSolverAttestation(&attestation)
	return attestation, err
}

func (runtime *LinuxSignedRuntime) ResolveIndividualUpdate(ctx context.Context, snapshot InventorySnapshot, reference, packageID string) (SolverAttestation, error) {
	if runtime == nil || runtime.catalog == nil || ctx == nil || snapshot.Validate() != nil || snapshot.NodeID != runtime.catalog.NodeID || snapshot.Manager != runtime.catalog.Manager || runtime.catalog.validate(runtime.now().UTC()) != nil || !safeID.MatchString(packageID) || !safeID.MatchString(reference) { return SolverAttestation{}, ErrInvalid }
	if err := ctx.Err(); err != nil { return SolverAttestation{}, err }
	for _, transaction := range runtime.catalog.Transactions {
		if !transaction.IndividualUpdate || runtime.catalog.individualReference(transaction) != reference { continue }
		changes, ok := individualTransactionChanges(snapshot, transaction, packageID)
		if !ok { return SolverAttestation{}, ErrUnsupported }
		return runtime.individualAttestation(snapshot, transaction, changes)
	}
	return SolverAttestation{}, ErrUnsupported
}

func (runtime *LinuxSignedRuntime) Resolve(ctx context.Context, snapshot InventorySnapshot, plan MaintenancePlan) (SolverAttestation, error) {
	if runtime == nil || runtime.catalog == nil || ctx == nil || snapshot.Validate() != nil || snapshot.NodeID != runtime.catalog.NodeID || snapshot.Manager != runtime.catalog.Manager || runtime.catalog.validate(runtime.now().UTC()) != nil { return SolverAttestation{}, ErrInvalid }
	if err := ctx.Err(); err != nil { return SolverAttestation{}, err }
	// The plan's solver digest binds the selected signed transaction reference
	// and full closure. Rebuild it from current inventory inside panel-execd.
	for _, transaction := range runtime.catalog.Transactions {
		changes, ok := individualTransactionChanges(snapshot, transaction, "")
		if !ok { continue }
		attestation, err := runtime.individualAttestation(snapshot, transaction, changes)
		if err == nil && attestation.TransactionDigest == plan.SolverDigest { return attestation, nil }
	}
	attestation, err := runtime.ResolveSecurityUpdates(ctx, snapshot)
	if err != nil { return SolverAttestation{}, err }
	if attestation.TransactionDigest != plan.SolverDigest { return SolverAttestation{}, ErrStalePlan }
	return attestation, nil
}

func (runtime *LinuxSignedRuntime) Allow(_ context.Context, plan MaintenancePlan, change PackageChange) error {
	if runtime == nil || runtime.catalog == nil || plan.NodeID != runtime.catalog.NodeID || plan.Manager != runtime.catalog.Manager ||
		change.Action != ChangeUpgrade && change.Action != ChangeReinstall || !change.Selected {
		return ErrUnauthorized
	}
	for _, transaction := range runtime.catalog.Transactions {
		if len(transaction.Packages) != len(plan.Changes) {
			continue
		}
		matchedPlan := true
		for _, rule := range transaction.Packages {
			found := false
			for _, planned := range plan.Changes {
				if planned.Name == rule.Name && planned.Architecture == rule.Architecture && planned.Action == rule.Action &&
					planned.FromVersion == rule.FromVersion && planned.ToVersion == rule.ToVersion && planned.RepositoryID == rule.RepositoryID && planned.Selected {
					found = true
					break
				}
			}
			if !found {
				matchedPlan = false
				break
			}
		}
		if !matchedPlan {
			continue
		}
		for _, rule := range transaction.Packages {
			if change.Name == rule.Name && change.Architecture == rule.Architecture && change.Action == rule.Action &&
				change.FromVersion == rule.FromVersion && change.ToVersion == rule.ToVersion && change.RepositoryID == rule.RepositoryID {
				return nil
			}
		}
	}
	return ErrUnauthorized
}

var linuxServiceProbeUnits = map[string]string{
	"panel_core":      "panel-core.service",
	"panel_gateway":   "panel-gateway.service",
	"panel_authn":     "panel-authd.service",
	"panel_secrets":   "panel-secretd.service",
	"panel_executor":  "panel-execd.service",
	"panel_provider":  "panel-providerd.service",
	"webengine":       "lsws.service",
	"database":        "mariadb.service",
	"dns":             "pdns.service",
	"ftp":             "pure-ftpd.service",
	"postfix":         "postfix.service",
	"dovecot":         "dovecot.service",
	"rspamd":          "rspamd.service",
	"redis":           "redis.service",
	"firewall":        "nftables.service",
}

func validLinuxSystemdProbeInvocation(argv []string) bool {
	if len(argv) != 3 || argv[0] != "is-active" || argv[1] != "--" {
		return false
	}
	for _, unit := range linuxServiceProbeUnits {
		if argv[2] == unit {
			return true
		}
	}
	return false
}

func (runtime *LinuxSignedRuntime) Probe(ctx context.Context, impact ServiceImpact) (ServiceProbeReceipt, error) {
	unit := linuxServiceProbeUnits[impact.ServiceID]
	if runtime == nil || runtime.runner == nil || unit == "" || impact.ProbeID != "systemd_active" ||
		impact.Action != ServiceReload && impact.Action != ServiceRestart {
		return ServiceProbeReceipt{}, ErrUnsupported
	}
	result, err := runtime.runner.Run(ctx, systemctlPath, []string{"is-active", "--", unit}, 4096)
	if err != nil {
		return ServiceProbeReceipt{}, err
	}
	observed := runtime.now().UTC()
	evidence := digestStrings(impact.ServiceID, impact.ProbeID, unit, strconv.Itoa(result.ExitCode), string(result.Output))
	return ServiceProbeReceipt{ServiceID: impact.ServiceID, ProbeID: impact.ProbeID,
		Healthy: result.ExitCode == 0 && strings.TrimSpace(string(result.Output)) == "active", EvidenceDigest: evidence, ObservedAt: observed}, nil
}

type protectedLinuxAuthorizationEnvelope struct {
	Evidence  AuthorizationEvidence `json:"evidence"`
	KeyID     string                `json:"key_id"`
	Signature string                `json:"signature"`
}

type ProtectedLinuxAuthorizer struct {
	material *secrets.MaterialClient
	catalog  *LinuxRuntimeCatalog
	now      func() time.Time
}

func NewProtectedLinuxAuthorizer(material *secrets.MaterialClient, catalog *LinuxRuntimeCatalog, now func() time.Time) (*ProtectedLinuxAuthorizer, error) {
	if material == nil || catalog == nil || !validDigest(catalog.digest) || len(catalog.authorizationKeys) == 0 {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &ProtectedLinuxAuthorizer{material: material, catalog: catalog, now: now}, nil
}

func (authorizer *ProtectedLinuxAuthorizer) Authorize(ctx context.Context, request AuthorizationRequest) (AuthorizationEvidence, error) {
	if authorizer == nil || authorizer.material == nil || authorizer.catalog == nil || ctx == nil ||
		request.Boundary != BoundaryAcceptance && request.Boundary != BoundaryCommit || !safeID.MatchString(request.OperationID) ||
		!safeID.MatchString(request.ActorID) || !safeID.MatchString(request.Scope) || !safeID.MatchString(request.PlanID) ||
		!validDigest(request.PlanDigest) || request.PlanGeneration == 0 || !validDigest(request.RequestDigest) {
		return AuthorizationEvidence{}, ErrUnauthorized
	}
	unsigned := request
	unsigned.RequestDigest = ""
	digest, err := canonicalDigest(unsigned)
	if err != nil || digest != request.RequestDigest {
		return AuthorizationEvidence{}, ErrUnauthorized
	}
	secretID, resourceID, err := linuxAuthorizationBinding(request)
	if err != nil {
		return AuthorizationEvidence{}, err
	}
	owner, _ := secrets.NewID("package_maintenance_authority")
	response, err := authorizer.material.Read(ctx, secrets.MaterialRequest{SecretID: secretID, OwnerTenantID: owner,
		Purpose: secrets.PurposeAuthentication, Operation: secrets.OperationRead, AdapterID: LinuxAuthorizationAdapterID,
		AdapterVersion: LinuxAuthorizationAdapterVersion, ResourceID: resourceID})
	if err != nil {
		return AuthorizationEvidence{}, ErrUnauthorized
	}
	defer wipeLinuxRuntimeBytes(response.Material)
	if len(response.Material) == 0 || len(response.Material) > 1<<20 {
		return AuthorizationEvidence{}, ErrUnauthorized
	}
	var envelope protectedLinuxAuthorizationEnvelope
	if err = decodeLinuxRuntimeJSON(response.Material, &envelope); err != nil || !safeID.MatchString(envelope.KeyID) {
		return AuthorizationEvidence{}, ErrUnauthorized
	}
	publicKey := authorizer.catalog.authorizationKeys[envelope.KeyID]
	if len(publicKey) != ed25519.PublicKeySize || !authorizer.authorizationKeyActive(envelope.KeyID, authorizer.now().UTC()) {
		return AuthorizationEvidence{}, ErrUnauthorized
	}
	payload, err := json.Marshal(envelope.Evidence)
	if err != nil {
		return AuthorizationEvidence{}, err
	}
	signature, err := decodeLinuxRuntimeBase64(envelope.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(publicKey, append([]byte(linuxAuthorizationDomain), payload...), signature) {
		return AuthorizationEvidence{}, ErrUnauthorized
	}
	evidence := envelope.Evidence
	if evidence.ActorID != request.ActorID || evidence.Scope != request.Scope || evidence.RequestDigest != request.RequestDigest ||
		evidence.PolicyDigest != authorizer.catalog.digest || evidence.Validate(request.MinimumAssurance, authorizer.now().UTC()) != nil {
		return AuthorizationEvidence{}, ErrUnauthorized
	}
	return evidence, nil
}

func (authorizer *ProtectedLinuxAuthorizer) authorizationKeyActive(id string, now time.Time) bool {
	for _, key := range authorizer.catalog.AuthorizationKeys {
		if key.ID == id {
			return !now.Before(key.NotBefore) && now.Before(key.NotAfter)
		}
	}
	return false
}

func linuxAuthorizationBinding(request AuthorizationRequest) (secrets.ID, secrets.ID, error) {
	if !validDigest(request.RequestDigest) || !safeID.MatchString(request.OperationID) || !safeID.MatchString(request.ActorID) {
		return "", "", ErrInvalid
	}
	sum := sha256.Sum256([]byte("cyberpanel-package-maintenance-authorization-binding-v1\x00" + string(request.Boundary) + "\x00" +
		request.OperationID + "\x00" + request.ActorID + "\x00" + request.RequestDigest))
	encoded := hex.EncodeToString(sum[:])[:48]
	secretID, secretErr := secrets.NewID("pkgauth_" + encoded)
	resourceID, resourceErr := secrets.NewID("pkgscope_" + encoded)
	if secretErr != nil || resourceErr != nil {
		return "", "", ErrInvalid
	}
	return secretID, resourceID, nil
}

func wipeLinuxRuntimeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

const (
	linuxBrokerProtocolVersion = uint8(1)
	linuxBrokerFrameLimit      = 96 << 20
	linuxJournalMaximumBytes   = 96 << 20
)

type LinuxBrokerOperation string

const (
	LinuxBrokerObserve LinuxBrokerOperation = "observe"
	LinuxBrokerResolve LinuxBrokerOperation = "resolve_security"
	LinuxBrokerApply   LinuxBrokerOperation = "apply"
	LinuxBrokerHold    LinuxBrokerOperation = "package_hold"
)

type LinuxBrokerRequest struct {
	Version     uint8                  `json:"version"`
	RequestID   string                 `json:"request_id"`
	Operation   LinuxBrokerOperation   `json:"operation"`
	Deadline    time.Time              `json:"deadline"`
	Observation *InventoryRequest      `json:"observation,omitempty"`
	Snapshot    *InventorySnapshot     `json:"snapshot,omitempty"`
	Execution   *ExecutionRequest      `json:"execution,omitempty"`
	Hold        *PackageHoldRequest    `json:"hold,omitempty"`
	TransactionReference string       `json:"transaction_reference,omitempty"`
	PackageResourceID string          `json:"package_resource_id,omitempty"`
}

type LinuxBrokerResponse struct {
	Version     uint8              `json:"version"`
	RequestID   string             `json:"request_id"`
	Operation   LinuxBrokerOperation `json:"operation"`
	Succeeded   bool               `json:"succeeded"`
	FailureCode string             `json:"failure_code,omitempty"`
	Inventory   *InventorySnapshot `json:"inventory,omitempty"`
	Attestation *SolverAttestation `json:"attestation,omitempty"`
	Receipt     *ExecutionReceipt  `json:"receipt,omitempty"`
	HoldReceipt *PackageHoldReceipt `json:"hold_receipt,omitempty"`
	CompletedAt time.Time          `json:"completed_at"`
}

func (request LinuxBrokerRequest) validate(now time.Time) error {
	if request.TransactionReference != "" || request.PackageResourceID != "" {
		if request.Operation != LinuxBrokerResolve || !safeID.MatchString(request.TransactionReference) || !safeID.MatchString(request.PackageResourceID) { return ErrInvalid }
	}
	if request.Version != linuxBrokerProtocolVersion || len(request.RequestID) != 36 || !strings.HasPrefix(request.RequestID, "pkg-") ||
		request.Deadline.Before(now.Add(-time.Second)) || request.Deadline.After(now.Add(2*time.Hour)) {
		return ErrInvalid
	}
	if decoded, err := hex.DecodeString(strings.TrimPrefix(request.RequestID, "pkg-")); err != nil || len(decoded) != 16 {
		return ErrInvalid
	}
	switch request.Operation {
	case LinuxBrokerObserve:
		if request.Observation == nil || request.Snapshot != nil || request.Execution != nil || request.Hold != nil || !safeID.MatchString(request.Observation.NodeID) ||
			!validManager(request.Observation.Manager) || request.Observation.Generation == 0 {
			return ErrInvalid
		}
	case LinuxBrokerResolve:
		if request.Observation != nil || request.Snapshot == nil || request.Execution != nil || request.Hold != nil || request.Snapshot.Validate() != nil {
			return ErrInvalid
		}
	case LinuxBrokerApply:
		if request.Observation != nil || request.Snapshot != nil || request.Execution == nil || request.Hold != nil || validateLinuxBrokerExecutionShape(*request.Execution) != nil {
			return ErrInvalid
		}
	case LinuxBrokerHold:
		if request.Observation != nil || request.Snapshot != nil || request.Execution != nil || request.Hold == nil || validatePackageHoldRequest(*request.Hold) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (response LinuxBrokerResponse) validate(request LinuxBrokerRequest, now time.Time) error {
	if response.Version != linuxBrokerProtocolVersion || response.RequestID != request.RequestID || response.Operation != request.Operation ||
		response.CompletedAt.IsZero() || response.CompletedAt.After(now.Add(time.Minute)) || response.Succeeded == (response.FailureCode != "") {
		return ErrInvalid
	}
	if !response.Succeeded && response.FailureCode == "" {
		return ErrInvalid
	}
	switch request.Operation {
	case LinuxBrokerObserve:
		if response.Succeeded && (response.Inventory == nil || response.Inventory.Validate() != nil) || response.Attestation != nil || response.Receipt != nil || response.HoldReceipt != nil {
			return ErrInvalid
		}
	case LinuxBrokerResolve:
		if response.Succeeded && (response.Attestation == nil || validateAttestation(*response.Attestation, request.Snapshot.ContentDigest, now) != nil) ||
			response.Inventory != nil || response.Receipt != nil || response.HoldReceipt != nil {
			return ErrInvalid
		}
	case LinuxBrokerApply:
		if response.Inventory != nil || response.Attestation != nil || response.HoldReceipt != nil || response.Receipt != nil && validReceiptStructure(*response.Receipt) == false {
			return ErrInvalid
		}
	case LinuxBrokerHold:
		if response.Attestation != nil || response.Receipt != nil || response.Succeeded && response.HoldReceipt == nil || (response.Inventory == nil) != (response.HoldReceipt == nil) ||
			response.HoldReceipt != nil && (validatePackageHoldReceipt(*response.HoldReceipt) != nil || response.Inventory.Validate() != nil ||
				response.HoldReceipt.EffectID != request.Hold.EffectID || response.HoldReceipt.RequestDigest != request.Hold.Digest ||
				response.HoldReceipt.AfterInventoryID != response.Inventory.ID || response.HoldReceipt.AfterInventoryDigest != response.Inventory.ContentDigest) {
			return ErrInvalid
		}
	}
	return nil
}

type LocalLinuxClient struct {
	Now func() time.Time
}

func NewLocalLinuxClient() (*LocalLinuxClient, error) {
	information, err := os.Lstat(LinuxBrokerSocketPath)
	if err != nil {
		return nil, err
	}
	metadata, ok := information.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || information.Mode()&os.ModeSocket == 0 || information.Mode().Perm()&0007 != 0 {
		return nil, ErrUnauthorized
	}
	return &LocalLinuxClient{}, nil
}

func (client *LocalLinuxClient) Snapshot(ctx context.Context, request InventoryRequest) (InventorySnapshot, error) {
	response, err := client.roundTrip(ctx, LinuxBrokerRequest{Operation: LinuxBrokerObserve, Observation: &request})
	if response.Inventory == nil {
		return InventorySnapshot{}, err
	}
	return *response.Inventory, err
}

func (client *LocalLinuxClient) ResolveSecurityUpdates(ctx context.Context, snapshot InventorySnapshot) (SolverAttestation, error) {
	response, err := client.roundTrip(ctx, LinuxBrokerRequest{Operation: LinuxBrokerResolve, Snapshot: &snapshot})
	if response.Attestation == nil {
		return SolverAttestation{}, err
	}
	return *response.Attestation, err
}

func (client *LocalLinuxClient) ResolveIndividualUpdate(ctx context.Context, snapshot InventorySnapshot, reference, packageID string) (SolverAttestation, error) {
	response, err := client.roundTrip(ctx, LinuxBrokerRequest{Operation: LinuxBrokerResolve, Snapshot: &snapshot, TransactionReference: reference, PackageResourceID: packageID})
	if response.Attestation == nil { return SolverAttestation{}, err }
	return *response.Attestation, err
}

func (client *LocalLinuxClient) Apply(ctx context.Context, request ExecutionRequest) (ExecutionReceipt, error) {
	response, err := client.roundTrip(ctx, LinuxBrokerRequest{Operation: LinuxBrokerApply, Execution: &request})
	if response.Receipt == nil {
		return ExecutionReceipt{}, err
	}
	return *response.Receipt, err
}

func (client *LocalLinuxClient) SetPackageHold(ctx context.Context, request PackageHoldRequest) (PackageHoldReceipt, InventorySnapshot, error) {
	response, err := client.roundTrip(ctx, LinuxBrokerRequest{Operation: LinuxBrokerHold, Hold: &request})
	if response.HoldReceipt == nil || response.Inventory == nil {
		return PackageHoldReceipt{}, InventorySnapshot{}, err
	}
	return *response.HoldReceipt, *response.Inventory, err
}

func (client *LocalLinuxClient) roundTrip(ctx context.Context, request LinuxBrokerRequest) (LinuxBrokerResponse, error) {
	if client == nil || ctx == nil {
		return LinuxBrokerResponse{}, ErrInvalid
	}
	identifier := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, identifier); err != nil {
		return LinuxBrokerResponse{}, err
	}
	now := time.Now().UTC()
	if client.Now != nil {
		now = client.Now().UTC()
	}
	request.Version = linuxBrokerProtocolVersion
	request.RequestID = "pkg-" + hex.EncodeToString(identifier)
	request.Deadline = now.Add(2 * time.Hour)
	if deadline, found := ctx.Deadline(); found && deadline.Before(request.Deadline) {
		request.Deadline = deadline.UTC()
	}
	if err := request.validate(now); err != nil {
		return LinuxBrokerResponse{}, err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", LinuxBrokerSocketPath)
	if err != nil {
		if ctx.Err() != nil {
			return LinuxBrokerResponse{}, ctx.Err()
		}
		return LinuxBrokerResponse{}, ErrAmbiguous
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	_ = connection.SetDeadline(request.Deadline)
	if err = writeLinuxBrokerFrame(connection, request); err != nil {
		return LinuxBrokerResponse{}, ErrAmbiguous
	}
	var response LinuxBrokerResponse
	if err = readLinuxBrokerFrame(connection, &response); err != nil {
		return LinuxBrokerResponse{}, ErrAmbiguous
	}
	if err = response.validate(request, time.Now().UTC()); err != nil {
		return LinuxBrokerResponse{}, ErrAmbiguous
	}
	if !response.Succeeded {
		return response, linuxBrokerFailureError(response.FailureCode)
	}
	return response, nil
}

func validateLinuxBrokerExecutionShape(request ExecutionRequest) error {
	if !safeID.MatchString(request.EffectID) || validatePlanAgainstInventory(request.Plan, request.Inventory) != nil ||
		request.ExpectedPlanGeneration != request.Plan.Generation || request.ExpectedInventoryGeneration != request.Inventory.Generation ||
		request.ExpectedInventoryGeneration != request.Plan.InventoryGeneration || request.ExpectedInventoryDigest != request.Inventory.ContentDigest ||
		request.ExpectedInventoryDigest != request.Plan.InventoryDigest || request.Fence == 0 ||
		validateEvidenceStored(request.Authorization, AssurancePhishingResistant) != nil ||
		request.Authorization.Scope != "package-maintenance:commit:"+request.Plan.ID {
		return ErrInvalid
	}
	authorization := AuthorizationRequest{Boundary: BoundaryCommit, OperationID: request.EffectID, ActorID: request.Authorization.ActorID,
		Scope: request.Authorization.Scope, PlanID: request.Plan.ID, PlanDigest: request.Plan.Digest, PlanGeneration: request.Plan.Generation,
		MinimumAssurance: AssurancePhishingResistant, Irreversible: true}
	digest, err := canonicalDigest(authorization)
	if err != nil || digest != request.Authorization.RequestDigest {
		return ErrUnauthorized
	}
	return nil
}

type LinuxBrokerServer struct {
	Authorizer        secrets.MaterialPeerAuthorizer
	Broker            *LinuxBroker
	MaximumConcurrent uint32
	once              sync.Once
	semaphore         chan struct{}
}

func (server *LinuxBrokerServer) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.Authorizer == nil || server.Broker == nil {
		return ErrInvalid
	}
	server.once.Do(func() {
		maximum := server.MaximumConcurrent
		if maximum == 0 || maximum > 32 {
			maximum = 8
		}
		server.semaphore = make(chan struct{}, maximum)
	})
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case server.semaphore <- struct{}{}:
			go func() {
				defer func() { <-server.semaphore; _ = connection.Close() }()
				server.serve(connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (server *LinuxBrokerServer) serve(connection net.Conn) {
	if _, err := server.Authorizer.Authorize(connection); err != nil {
		return
	}
	now := time.Now().UTC()
	_ = connection.SetReadDeadline(now.Add(15 * time.Second))
	var request LinuxBrokerRequest
	if readLinuxBrokerFrame(connection, &request) != nil || request.validate(now) != nil {
		return
	}
	_ = connection.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
	defer cancel()
	response := LinuxBrokerResponse{Version: linuxBrokerProtocolVersion, RequestID: request.RequestID,
		Operation: request.Operation, CompletedAt: time.Now().UTC()}
	var err error
	switch request.Operation {
	case LinuxBrokerObserve:
		var inventory InventorySnapshot
		inventory, err = server.Broker.Snapshot(ctx, *request.Observation)
		if err == nil {
			response.Inventory = &inventory
		}
	case LinuxBrokerResolve:
		var attestation SolverAttestation
		if request.TransactionReference != "" {
			attestation, err = server.Broker.runtime.ResolveIndividualUpdate(ctx, *request.Snapshot, request.TransactionReference, request.PackageResourceID)
		} else {
			attestation, err = server.Broker.ResolveSecurityUpdates(ctx, *request.Snapshot)
		}
		if err == nil {
			response.Attestation = &attestation
		}
	case LinuxBrokerApply:
		var receipt ExecutionReceipt
		receipt, err = server.Broker.Apply(ctx, *request.Execution)
		if receipt.EffectID != "" {
			response.Receipt = &receipt
		}
	case LinuxBrokerHold:
		var receipt PackageHoldReceipt
		var inventory InventorySnapshot
		receipt, inventory, err = server.Broker.SetPackageHold(ctx, *request.Hold)
		if receipt.EffectID != "" {
			response.HoldReceipt, response.Inventory = &receipt, &inventory
		}
	}
	response.Succeeded = err == nil
	if err != nil {
		response.FailureCode = classifyLinuxBrokerError(err)
	}
	response.CompletedAt = time.Now().UTC()
	_ = writeLinuxBrokerFrame(connection, response)
}

func ListenLinuxBroker(controlGID uint32) (*net.UnixListener, error) {
	if os.Geteuid() != 0 || controlGID == 0 {
		return nil, ErrUnauthorized
	}
	const directory = "/run/cyberpanel"
	if err := os.Mkdir(directory, 0711); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	information, err := os.Lstat(directory)
	if err != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 || information.Mode().Perm()&0002 != 0 {
		return nil, ErrUnauthorized
	}
	if information, err = os.Lstat(LinuxBrokerSocketPath); err == nil {
		if information.Mode()&os.ModeSocket == 0 {
			return nil, ErrUnauthorized
		}
		if err = os.Remove(LinuxBrokerSocketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: LinuxBrokerSocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chown(LinuxBrokerSocketPath, 0, int(controlGID)); err == nil {
		err = os.Chmod(LinuxBrokerSocketPath, 0660)
	}
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func writeLinuxBrokerFrame(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > linuxBrokerFrameLimit {
		return ErrInvalid
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
	if err = writeLinuxBrokerBytes(writer, header[:]); err != nil {
		return err
	}
	return writeLinuxBrokerBytes(writer, encoded)
}

func writeLinuxBrokerBytes(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func readLinuxBrokerFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > linuxBrokerFrameLimit {
		return ErrInvalid
	}
	encoded := make([]byte, size)
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return err
	}
	return decodeLinuxRuntimeJSON(encoded, target)
}

func classifyLinuxBrokerError(err error) string {
	for _, value := range []struct {
		err  error
		code string
	}{{ErrInvalid, "invalid"}, {ErrConflict, "conflict"}, {ErrStaleInventory, "stale_inventory"}, {ErrStalePlan, "stale_plan"},
		{ErrUnauthorized, "unauthorized"}, {ErrUnsupported, "unsupported"}, {ErrLocked, "locked"},
		{ErrRecoveryRequired, "recovery_required"}, {ErrAmbiguous, "ambiguous"}} {
		if errors.Is(err, value.err) {
			return value.code
		}
	}
	return "ambiguous"
}

func linuxBrokerFailureError(code string) error {
	switch code {
	case "invalid":
		return ErrInvalid
	case "conflict":
		return ErrConflict
	case "stale_inventory":
		return ErrStaleInventory
	case "stale_plan":
		return ErrStalePlan
	case "unauthorized":
		return ErrUnauthorized
	case "unsupported":
		return ErrUnsupported
	case "locked":
		return ErrLocked
	case "recovery_required":
		return ErrRecoveryRequired
	default:
		return ErrAmbiguous
	}
}

type linuxJournalCommand struct {
	Executable string         `json:"executable"`
	Argv       []string       `json:"argv"`
	StartedAt  time.Time      `json:"started_at"`
	Receipt    CommandReceipt `json:"receipt,omitempty"`
}

type linuxJournalEntry struct {
	SchemaVersion uint8                 `json:"schema_version"`
	RequestDigest string                `json:"request_digest"`
	Request       ExecutionRequest      `json:"request"`
	Commands      []linuxJournalCommand `json:"commands"`
	Receipt       ExecutionReceipt      `json:"receipt,omitempty"`
	FailureCode   string                `json:"failure_code,omitempty"`
	StartedAt     time.Time             `json:"started_at"`
	CompletedAt   time.Time             `json:"completed_at,omitempty"`
}

type linuxHoldJournalEntry struct {
	SchemaVersion uint8                 `json:"schema_version"`
	RequestDigest string                `json:"request_digest"`
	Request       PackageHoldRequest    `json:"request"`
	Before        InventorySnapshot     `json:"before,omitempty"`
	Command       linuxJournalCommand   `json:"command,omitempty"`
	After         InventorySnapshot     `json:"after,omitempty"`
	Receipt       PackageHoldReceipt    `json:"receipt,omitempty"`
	FailureCode   string                `json:"failure_code,omitempty"`
	StartedAt     time.Time             `json:"started_at"`
	CompletedAt   time.Time             `json:"completed_at,omitempty"`
}

type LinuxJournal struct {
	root string
	mu   sync.Mutex
}

func NewLinuxJournal(root string) (*LinuxJournal, error) {
	if root != DefaultLinuxJournalRoot || os.Geteuid() != 0 {
		return nil, ErrUnauthorized
	}
	if err := os.Mkdir(root, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := requireRootOwnedLinuxRuntimeDirectory(root); err != nil {
		return nil, err
	}
	information, err := os.Lstat(root)
	if err != nil || information.Mode().Perm() != 0700 {
		return nil, ErrUnauthorized
	}
	return &LinuxJournal{root: root}, nil
}

func (journal *LinuxJournal) prepare(request ExecutionRequest, requestDigest string, now time.Time) (linuxJournalEntry, bool, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	entry, found, err := journal.loadLocked(request.EffectID)
	if err != nil || found {
		return entry, found, err
	}
	entry = linuxJournalEntry{SchemaVersion: 1, RequestDigest: requestDigest, Request: request, StartedAt: now.UTC()}
	if err = journal.writeLocked(entry); err != nil {
		return linuxJournalEntry{}, false, err
	}
	return entry, false, nil
}

func (journal *LinuxJournal) commandStarted(effectID, requestDigest, executable string, argv []string, now time.Time) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	entry, found, err := journal.loadLocked(effectID)
	if err != nil || !found || entry.RequestDigest != requestDigest || entry.Receipt.EffectID != "" || !allowedInvocation(executable, argv) {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	entry.Commands = append(entry.Commands, linuxJournalCommand{Executable: executable, Argv: append([]string(nil), argv...), StartedAt: now.UTC()})
	return journal.writeLocked(entry)
}

func (journal *LinuxJournal) commandCompleted(effectID, requestDigest string, result CommandResult) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	entry, found, err := journal.loadLocked(effectID)
	if err != nil || !found || entry.RequestDigest != requestDigest || len(entry.Commands) == 0 {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	command := &entry.Commands[len(entry.Commands)-1]
	if command.Receipt.Executable != "" || command.Executable != result.Executable || !equalStrings(command.Argv, result.Argv) {
		return ErrConflict
	}
	command.Receipt = commandReceipt(result)
	return journal.writeLocked(entry)
}

func (journal *LinuxJournal) complete(effectID, requestDigest string, receipt ExecutionReceipt, failureCode string, now time.Time) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	entry, found, err := journal.loadLocked(effectID)
	if err != nil || !found || entry.RequestDigest != requestDigest || receipt.EffectID != effectID || !validReceiptStructure(receipt) {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	entry.Receipt = receipt
	entry.FailureCode = failureCode
	entry.CompletedAt = now.UTC()
	return journal.writeLocked(entry)
}

func (journal *LinuxJournal) discardBeforeEffect(effectID, requestDigest string) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	entry, found, err := journal.loadLocked(effectID)
	if err != nil || !found || entry.RequestDigest != requestDigest || len(entry.Commands) != 0 || entry.Receipt.EffectID != "" {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	return os.Remove(journal.path(effectID))
}

func (journal *LinuxJournal) loadLocked(effectID string) (linuxJournalEntry, bool, error) {
	if journal == nil || journal.root != DefaultLinuxJournalRoot || !safeID.MatchString(effectID) {
		return linuxJournalEntry{}, false, ErrInvalid
	}
	raw, err := readRootOwnedLinuxRuntimeFile(journal.path(effectID), linuxJournalMaximumBytes)
	if errors.Is(err, os.ErrNotExist) {
		return linuxJournalEntry{}, false, nil
	}
	if err != nil {
		return linuxJournalEntry{}, false, err
	}
	var entry linuxJournalEntry
	if decodeLinuxRuntimeJSON(raw, &entry) != nil || validateLinuxJournalEntry(entry) != nil {
		return linuxJournalEntry{}, false, ErrAmbiguous
	}
	return entry, true, nil
}

func (journal *LinuxJournal) prepareHold(request PackageHoldRequest, digest string, now time.Time) (linuxHoldJournalEntry, bool, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	entry, found, err := journal.loadHoldLocked(request.EffectID)
	if err != nil || found {
		return entry, found, err
	}
	entry = linuxHoldJournalEntry{SchemaVersion: 1, RequestDigest: digest, Request: request, StartedAt: now.UTC()}
	return entry, false, journal.writeHoldLocked(entry)
}

func (journal *LinuxJournal) startHold(request PackageHoldRequest, before InventorySnapshot, executable string, argv []string, now time.Time) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	entry, found, err := journal.loadHoldLocked(request.EffectID)
	if err != nil || !found || entry.RequestDigest != request.Digest || entry.Command.Executable != "" ||
		packageHoldMatchesInventory(request, before, true) != nil || !allowedInvocation(executable, argv) {
		if err != nil { return err }
		return ErrConflict
	}
	entry.Before = before
	entry.Command = linuxJournalCommand{Executable: executable, Argv: append([]string(nil), argv...), StartedAt: now.UTC()}
	return journal.writeHoldLocked(entry)
}

func (journal *LinuxJournal) recordHoldCommand(effectID, digest string, result CommandResult) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	entry, found, err := journal.loadHoldLocked(effectID)
	if err != nil || !found || entry.RequestDigest != digest || entry.Command.Executable != result.Executable ||
		!equalStrings(entry.Command.Argv, result.Argv) || result.StartedAt.IsZero() {
		if err != nil { return err }
		return ErrConflict
	}
	entry.Command.Receipt = commandReceipt(result)
	return journal.writeHoldLocked(entry)
}

func (journal *LinuxJournal) completeHold(entry linuxHoldJournalEntry, after InventorySnapshot,
	receipt PackageHoldReceipt, failure string, now time.Time) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	current, found, err := journal.loadHoldLocked(entry.Request.EffectID)
	if err != nil || !found || current.RequestDigest != entry.RequestDigest || validatePackageHoldReceipt(receipt) != nil || after.Validate() != nil {
		if err != nil { return err }
		return ErrConflict
	}
	if current.Command.Receipt.Executable == "" { current.Command.Receipt = receipt.Command }
	current.After, current.Receipt, current.FailureCode, current.CompletedAt = after, receipt, failure, now.UTC()
	return journal.writeHoldLocked(current)
}

func (journal *LinuxJournal) loadHoldLocked(effectID string) (linuxHoldJournalEntry, bool, error) {
	if journal == nil || journal.root != DefaultLinuxJournalRoot || !safeID.MatchString(effectID) {
		return linuxHoldJournalEntry{}, false, ErrInvalid
	}
	raw, err := readRootOwnedLinuxRuntimeFile(journal.holdPath(effectID), linuxJournalMaximumBytes)
	if errors.Is(err, os.ErrNotExist) { return linuxHoldJournalEntry{}, false, nil }
	if err != nil { return linuxHoldJournalEntry{}, false, err }
	var entry linuxHoldJournalEntry
	if decodeLinuxRuntimeJSON(raw, &entry) != nil || validateLinuxHoldJournalEntry(entry) != nil {
		return linuxHoldJournalEntry{}, false, ErrAmbiguous
	}
	return entry, true, nil
}

func (journal *LinuxJournal) writeHoldLocked(entry linuxHoldJournalEntry) error {
	if validateLinuxHoldJournalEntry(entry) != nil { return ErrInvalid }
	return journal.writeValueLocked(journal.holdPath(entry.Request.EffectID), entry)
}

func (journal *LinuxJournal) writeLocked(entry linuxJournalEntry) error {
	if validateLinuxJournalEntry(entry) != nil {
		return ErrInvalid
	}
	return journal.writeValueLocked(journal.path(entry.Request.EffectID), entry)
}

func (journal *LinuxJournal) writeValueLocked(path string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > linuxJournalMaximumBytes {
		return ErrInvalid
	}
	random := make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return err
	}
	temporary := filepath.Join(journal.root, "."+hex.EncodeToString(random)+".tmp")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	written := false
	defer func() {
		_ = file.Close()
		if !written {
			_ = os.Remove(temporary)
		}
	}()
	if err = writeLinuxBrokerBytes(file, encoded); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	written = true
	directory, err := os.Open(journal.root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (journal *LinuxJournal) path(effectID string) string {
	sum := sha256.Sum256([]byte("cyberpanel-package-maintenance-journal-v1\x00" + effectID))
	return filepath.Join(journal.root, hex.EncodeToString(sum[:])+".json")
}

func (journal *LinuxJournal) holdPath(effectID string) string {
	sum := sha256.Sum256([]byte("cyberpanel-package-hold-journal-v1\x00" + effectID))
	return filepath.Join(journal.root, hex.EncodeToString(sum[:])+".json")
}

func validateLinuxJournalEntry(entry linuxJournalEntry) error {
	if entry.SchemaVersion != 1 || !validDigest(entry.RequestDigest) || validateLinuxBrokerExecutionShape(entry.Request) != nil ||
		entry.StartedAt.IsZero() || len(entry.Commands) > MaximumChanges+8 {
		return ErrInvalid
	}
	digest, err := canonicalDigest(entry.Request)
	if err != nil || digest != entry.RequestDigest {
		return ErrInvalid
	}
	for _, command := range entry.Commands {
		if !allowedInvocation(command.Executable, command.Argv) || command.StartedAt.IsZero() {
			return ErrInvalid
		}
		if command.Receipt.Executable != "" && (command.Receipt.Executable != command.Executable || !validDigest(command.Receipt.ArgvDigest) ||
			!validDigest(command.Receipt.OutputDigest) || command.Receipt.StartedAt.IsZero() || command.Receipt.CompletedAt.Before(command.Receipt.StartedAt)) {
			return ErrInvalid
		}
	}
	if entry.Receipt.EffectID == "" {
		if entry.FailureCode != "" || !entry.CompletedAt.IsZero() {
			return ErrInvalid
		}
		return nil
	}
	if !validReceiptStructure(entry.Receipt) || entry.Receipt.EffectID != entry.Request.EffectID || entry.CompletedAt.IsZero() ||
		entry.FailureCode != "" && classifyLinuxBrokerError(linuxBrokerFailureError(entry.FailureCode)) != entry.FailureCode {
		return ErrInvalid
	}
	return nil
}

func validateLinuxHoldJournalEntry(entry linuxHoldJournalEntry) error {
	if entry.SchemaVersion != 1 || entry.RequestDigest != entry.Request.Digest || validatePackageHoldRequest(entry.Request) != nil ||
		entry.StartedAt.IsZero() {
		return ErrInvalid
	}
	if entry.Command.Executable == "" {
		if entry.Before.ID != "" || entry.Receipt.EffectID != "" || !entry.CompletedAt.IsZero() { return ErrInvalid }
		return nil
	}
	if packageHoldMatchesInventory(entry.Request, entry.Before, true) != nil || !allowedInvocation(entry.Command.Executable, entry.Command.Argv) || entry.Command.StartedAt.IsZero() {
		return ErrInvalid
	}
	if entry.Command.Receipt.Executable == "" {
		if entry.Receipt.EffectID != "" || !entry.CompletedAt.IsZero() { return ErrInvalid }
		return nil
	}
	command := entry.Command.Receipt
	argvDigest, _ := canonicalDigest(struct { Executable string `json:"executable"`; Argv []string `json:"argv"` }{entry.Command.Executable, entry.Command.Argv})
	if command.Executable != entry.Command.Executable || !validDigest(command.ArgvDigest) || !validDigest(command.OutputDigest) ||
		command.ArgvDigest != argvDigest || command.StartedAt.IsZero() || command.CompletedAt.Before(command.StartedAt) {
		return ErrInvalid
	}
	if entry.Receipt.EffectID == "" {
		if entry.After.ID != "" || !entry.CompletedAt.IsZero() { return ErrInvalid }
		return nil
	}
	if validatePackageHoldReceipt(entry.Receipt) != nil || entry.After.Validate() != nil ||
		entry.Receipt.EffectID != entry.Request.EffectID || entry.Receipt.AfterInventoryID != entry.After.ID ||
		entry.Receipt.AfterInventoryDigest != entry.After.ContentDigest || entry.CompletedAt.IsZero() ||
		entry.FailureCode != "" && classifyLinuxBrokerError(linuxBrokerFailureError(entry.FailureCode)) != entry.FailureCode {
		return ErrInvalid
	}
	return nil
}

type linuxJournalRunner struct {
	journal       *LinuxJournal
	effectID      string
	requestDigest string
	delegate      Runner
	now           func() time.Time
}

func (runner linuxJournalRunner) Run(ctx context.Context, executable string, argv []string, maximumOutput int) (CommandResult, error) {
	now := time.Now().UTC()
	if runner.now != nil {
		now = runner.now().UTC()
	}
	if err := runner.journal.commandStarted(runner.effectID, runner.requestDigest, executable, argv, now); err != nil {
		return CommandResult{}, err
	}
	result, runErr := runner.delegate.Run(ctx, executable, argv, maximumOutput)
	if err := runner.journal.commandCompleted(runner.effectID, runner.requestDigest, result); err != nil {
		return result, ErrAmbiguous
	}
	return result, runErr
}

type LinuxBroker struct {
	runtime *LinuxSignedRuntime
	executor LinuxExecutor
	journal *LinuxJournal
	now     func() time.Time
	applyMu sync.Mutex
}

func NewLinuxBroker(runtime *LinuxSignedRuntime, journal *LinuxJournal, now func() time.Time) (*LinuxBroker, error) {
	if runtime == nil || runtime.catalog == nil || journal == nil {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	executor := LinuxExecutor{Inventory: runtime, Verifier: runtime, Policy: runtime, ServiceProber: runtime, Now: now}
	return &LinuxBroker{runtime: runtime, executor: executor, journal: journal, now: now}, nil
}

func (broker *LinuxBroker) Snapshot(ctx context.Context, request InventoryRequest) (InventorySnapshot, error) {
	if broker == nil || broker.runtime == nil {
		return InventorySnapshot{}, ErrInvalid
	}
	return broker.runtime.Snapshot(ctx, request)
}

func (broker *LinuxBroker) ResolveSecurityUpdates(ctx context.Context, snapshot InventorySnapshot) (SolverAttestation, error) {
	if broker == nil || broker.runtime == nil {
		return SolverAttestation{}, ErrInvalid
	}
	return broker.runtime.ResolveSecurityUpdates(ctx, snapshot)
}

func (broker *LinuxBroker) Apply(ctx context.Context, request ExecutionRequest) (ExecutionReceipt, error) {
	if broker == nil || broker.runtime == nil || broker.journal == nil || ctx == nil || validateLinuxBrokerExecutionShape(request) != nil {
		return ExecutionReceipt{}, ErrInvalid
	}
	requestDigest, err := canonicalDigest(request)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	broker.applyMu.Lock()
	defer broker.applyMu.Unlock()
	now := broker.now().UTC()
	entry, found, err := broker.journal.prepare(request, requestDigest, now)
	if err != nil {
		return ExecutionReceipt{}, ErrAmbiguous
	}
	if found {
		if entry.RequestDigest != requestDigest {
			return ExecutionReceipt{}, ErrConflict
		}
		if entry.Receipt.EffectID != "" {
			if entry.FailureCode == "" {
				return entry.Receipt, nil
			}
			return entry.Receipt, linuxBrokerFailureError(entry.FailureCode)
		}
		if len(entry.Commands) != 0 {
			return broker.reconcile(ctx, entry)
		}
	}
	if broker.runtime.catalog.validate(now) != nil || request.Authorization.PolicyDigest != broker.runtime.catalog.digest ||
		request.Authorization.Validate(AssurancePhishingResistant, now) != nil || !now.Before(request.Plan.ExpiresAt) {
		_ = broker.journal.discardBeforeEffect(request.EffectID, requestDigest)
		return ExecutionReceipt{}, ErrUnauthorized
	}
	executor := broker.executor
	executor.Runner = linuxJournalRunner{journal: broker.journal, effectID: request.EffectID, requestDigest: requestDigest,
		delegate: broker.runtime.runner, now: broker.now}
	receipt, executionErr := executor.Apply(ctx, request)
	if receipt.EffectID == "" {
		entry, _, loadErr := broker.journal.load(request.EffectID)
		if loadErr == nil && len(entry.Commands) != 0 {
			return broker.reconcile(ctx, entry)
		}
		_ = broker.journal.discardBeforeEffect(request.EffectID, requestDigest)
		return ExecutionReceipt{}, executionErr
	}
	failure := ""
	if executionErr != nil {
		failure = classifyLinuxBrokerError(executionErr)
	}
	if err = broker.journal.complete(request.EffectID, requestDigest, receipt, failure, broker.now().UTC()); err != nil {
		return receipt, ErrAmbiguous
	}
	return receipt, executionErr
}

func (broker *LinuxBroker) SetPackageHold(ctx context.Context, request PackageHoldRequest) (PackageHoldReceipt, InventorySnapshot, error) {
	if broker == nil || broker.runtime == nil || broker.journal == nil || ctx == nil || validatePackageHoldRequest(request) != nil {
		return PackageHoldReceipt{}, InventorySnapshot{}, ErrInvalid
	}
	broker.applyMu.Lock()
	defer broker.applyMu.Unlock()
	now := broker.now().UTC()
	entry, found, err := broker.journal.prepareHold(request, request.Digest, now)
	if err != nil { return PackageHoldReceipt{}, InventorySnapshot{}, ErrAmbiguous }
	if found {
		if entry.RequestDigest != request.Digest { return PackageHoldReceipt{}, InventorySnapshot{}, ErrConflict }
		if entry.Receipt.EffectID != "" {
			if entry.FailureCode == "" { return entry.Receipt, entry.After, nil }
			return entry.Receipt, entry.After, linuxBrokerFailureError(entry.FailureCode)
		}
		if entry.Command.Executable != "" { return broker.reconcilePackageHold(ctx, entry) }
	}
	if broker.runtime.catalog.validate(now) != nil || request.Authorization.PolicyDigest != broker.runtime.catalog.digest ||
		request.Authorization.Validate(AssuranceMFA, now) != nil {
		return PackageHoldReceipt{}, InventorySnapshot{}, ErrUnauthorized
	}
	before, err := broker.runtime.Snapshot(ctx, InventoryRequest{NodeID: request.NodeID, Manager: request.Manager, Generation: request.InventoryGeneration})
	if err != nil || packageHoldMatchesInventory(request, before, true) != nil {
		if err != nil { return PackageHoldReceipt{}, InventorySnapshot{}, err }
		return PackageHoldReceipt{}, InventorySnapshot{}, ErrStaleInventory
	}
	executable, argv, err := packageHoldCommand(request)
	if err != nil { return PackageHoldReceipt{}, InventorySnapshot{}, err }
	if err = broker.journal.startHold(request, before, executable, argv, now); err != nil {
		return PackageHoldReceipt{}, InventorySnapshot{}, ErrAmbiguous
	}
	result, runErr := broker.runtime.runner.Run(ctx, executable, argv, MaximumOutputBytes)
	if result.StartedAt.IsZero() || broker.journal.recordHoldCommand(request.EffectID, request.Digest, result) != nil {
		loaded, _, _ := broker.journal.loadHold(request.EffectID)
		return broker.reconcilePackageHold(ctx, loaded)
	}
	entry.Before = before
	entry.Command = linuxJournalCommand{Executable: executable, Argv: argv, StartedAt: now, Receipt: commandReceipt(result)}
	after, observationErr := broker.runtime.Snapshot(ctx, InventoryRequest{NodeID: request.NodeID, Manager: request.Manager, Generation: request.InventoryGeneration + 1})
	if observationErr != nil { return PackageHoldReceipt{}, InventorySnapshot{}, ErrAmbiguous }
	return broker.finishPackageHold(entry, after, runErr != nil || result.ExitCode != 0 || packageLockOutput(result.Output))
}

func (journal *LinuxJournal) loadHold(effectID string) (linuxHoldJournalEntry, bool, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return journal.loadHoldLocked(effectID)
}

func (broker *LinuxBroker) reconcilePackageHold(ctx context.Context, entry linuxHoldJournalEntry) (PackageHoldReceipt, InventorySnapshot, error) {
	if entry.Request.EffectID == "" { return PackageHoldReceipt{}, InventorySnapshot{}, ErrAmbiguous }
	after, err := broker.runtime.Snapshot(ctx, InventoryRequest{NodeID: entry.Request.NodeID, Manager: entry.Request.Manager,
		Generation: entry.Request.InventoryGeneration + 1})
	if err != nil { return PackageHoldReceipt{}, InventorySnapshot{}, ErrAmbiguous }
	return broker.finishPackageHold(entry, after, entry.Command.Receipt.Executable == "" || entry.Command.Receipt.ExitCode != 0)
}

func (broker *LinuxBroker) finishPackageHold(entry linuxHoldJournalEntry, after InventorySnapshot,
	forceAmbiguous bool) (PackageHoldReceipt, InventorySnapshot, error) {
	now := broker.now().UTC()
	command := entry.Command.Receipt
	if command.Executable == "" {
		argvDigest, _ := canonicalDigest(struct { Executable string `json:"executable"`; Argv []string `json:"argv"` }{entry.Command.Executable, entry.Command.Argv})
		command = CommandReceipt{Executable: entry.Command.Executable, ArgvDigest: argvDigest,
			OutputDigest: digestStrings("package_hold_reconciled", entry.Request.EffectID, argvDigest), ExitCode: -1,
			StartedAt: entry.Command.StartedAt, CompletedAt: now}
	}
	confirmed := !forceAmbiguous && exactPackageHoldEffect(entry.Before, after, entry.Request)
	receipt := PackageHoldReceipt{EffectID: entry.Request.EffectID, RequestDigest: entry.Request.Digest,
		Action: entry.Request.Action, BeforeInventoryDigest: entry.Request.InventoryDigest, AfterInventoryID: after.ID,
		AfterInventoryGeneration: after.Generation, AfterInventoryDigest: after.ContentDigest,
		Held: packageHeld(after, entry.Request.PackageName), Command: command, Outcome: OutcomeAmbiguous,
		AuthorizationDigest: entry.Request.Authorization.Digest, ObservedAt: now}
	if confirmed { receipt.Outcome = OutcomeConfirmed }
	if SealPackageHoldReceipt(&receipt) != nil { return PackageHoldReceipt{}, InventorySnapshot{}, ErrAmbiguous }
	failure := ""
	if !confirmed { failure = "ambiguous" }
	if broker.journal.completeHold(entry, after, receipt, failure, now) != nil {
		return receipt, after, ErrAmbiguous
	}
	if !confirmed { return receipt, after, ErrAmbiguous }
	return receipt, after, nil
}

func (journal *LinuxJournal) load(effectID string) (linuxJournalEntry, bool, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return journal.loadLocked(effectID)
}

func (broker *LinuxBroker) reconcile(ctx context.Context, entry linuxJournalEntry) (ExecutionReceipt, error) {
	request := entry.Request
	after, err := broker.runtime.Snapshot(ctx, InventoryRequest{NodeID: request.Plan.NodeID, Manager: request.Plan.Manager,
		Generation: request.ExpectedInventoryGeneration + 1})
	if err != nil {
		return ExecutionReceipt{}, ErrAmbiguous
	}
	now := broker.now().UTC()
	receipt := ExecutionReceipt{EffectID: request.EffectID, PlanID: request.Plan.ID, PlanDigest: request.Plan.Digest,
		InventoryGeneration: request.Inventory.Generation, BeforeInventoryDigest: request.Inventory.ContentDigest,
		AfterInventoryDigest: after.ContentDigest, Fence: request.Fence, AuthorizationDigest: request.Authorization.Digest,
		ObservedPackages: observedPackages(request.Plan, after), IrreversibleCrossed: true}
	for _, command := range entry.Commands {
		if command.Receipt.Executable != "" {
			receipt.Commands = append(receipt.Commands, command.Receipt)
			continue
		}
		argvDigest, _ := canonicalDigest(struct {
			Executable string   `json:"executable"`
			Argv       []string `json:"argv"`
		}{Executable: command.Executable, Argv: command.Argv})
		receipt.Commands = append(receipt.Commands, CommandReceipt{Executable: command.Executable, ArgvDigest: argvDigest,
			OutputDigest: digestStrings("reconciled_after_worker_loss", request.EffectID, argvDigest), ExitCode: -1,
			StartedAt: command.StartedAt, CompletedAt: now})
	}
	resultErr := error(nil)
	if exactPackageEffect(request.Inventory, after, request.Plan.Changes) {
		receipt.Outcome = OutcomeConfirmed
		for _, service := range request.Plan.Services {
			probe, probeErr := broker.runtime.Probe(ctx, service)
			if probeErr != nil || !validProbeReceipt(probe, service) {
				receipt.Outcome = OutcomeRecoveryRequired
				resultErr = ErrRecoveryRequired
				break
			}
			receipt.ServiceProbes = append(receipt.ServiceProbes, probe)
			if service.Required && !probe.Healthy {
				receipt.Outcome = OutcomeRecoveryRequired
				resultErr = ErrRecoveryRequired
				break
			}
		}
	} else if samePackageState(request.Inventory, after) {
		receipt.Outcome = OutcomeFailed
		resultErr = ErrConflict
	} else {
		receipt.Outcome = OutcomeAmbiguous
		resultErr = ErrRecoveryRequired
	}
	sealExecutionReceipt(&receipt, now)
	failure := ""
	if resultErr != nil {
		failure = classifyLinuxBrokerError(resultErr)
	}
	if err = broker.journal.complete(request.EffectID, entry.RequestDigest, receipt, failure, now); err != nil {
		return receipt, ErrAmbiguous
	}
	return receipt, resultErr
}

// ReconcileRestart resumes only operations whose commit authorization and
// exact plan inputs were durably stored before process loss. Running effects
// are re-sent to the privileged broker, whose journal either returns the
// original receipt or derives a conservative receipt from native state.
func (service Service) ReconcileRestart(ctx context.Context, operationID string) (MaintenanceOperation, error) {
	if service.Store == nil || service.Executor == nil || ctx == nil || !safeID.MatchString(operationID) {
		return MaintenanceOperation{}, ErrInvalid
	}
	operation, err := service.Store.Operation(ctx, operationID)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	if operation.State != OperationAuthorized && operation.State != OperationRunning && operation.State != OperationVerifying {
		return operation, nil
	}
	plan, inventory, err := service.restartInputs(ctx, operation)
	if err != nil {
		return operation, err
	}
	rebootBoot, err := service.rebootBootIdentity(ctx, plan)
	if err != nil {
		return operation, err
	}
	actorID := operation.CommitAuthorization.ActorID
	if operation.State == OperationAuthorized {
		now := service.now()
		if !now.Before(plan.ExpiresAt) || operation.CommitAuthorization.Validate(AssurancePhishingResistant, now) != nil {
			failed, transitionErr := service.Store.Transition(ctx, operation.ID, operation.Generation, OperationAuthorized, OperationFailed,
				AuthorizationEvidence{}, ExecutionReceipt{}, makeAudit(operation.ID, operation.Generation+1, actorID, "restart", "authorization-expired",
				plan.Digest, operation.CommitAuthorization.Digest, now))
			if transitionErr != nil {
				return operation, transitionErr
			}
			return failed, ErrUnauthorized
		}
		operation, err = service.Store.Transition(ctx, operation.ID, operation.Generation, OperationAuthorized, OperationRunning,
			AuthorizationEvidence{}, ExecutionReceipt{}, makeAudit(operation.ID, operation.Generation+1, actorID, "restart", "execution-resumed",
			plan.Digest, operation.CommitAuthorization.Digest, now))
		if err != nil {
			return MaintenanceOperation{}, err
		}
	}
	if operation.State == OperationRunning {
		receipt, executionErr := service.Executor.Apply(ctx, ExecutionRequest{EffectID: operation.ID, Plan: plan, Inventory: inventory,
			ExpectedPlanGeneration: operation.PlanGeneration, ExpectedInventoryGeneration: operation.InventoryGeneration,
			ExpectedInventoryDigest: operation.InventoryDigest, Fence: operation.Fence, Authorization: operation.CommitAuthorization})
		if receipt.EffectID == "" {
			if executionErr == nil || errors.Is(executionErr, ErrAmbiguous) || ctx.Err() != nil {
				return operation, ErrAmbiguous
			}
			failed, transitionErr := service.Store.Transition(ctx, operation.ID, operation.Generation, OperationRunning, OperationFailed,
				AuthorizationEvidence{}, ExecutionReceipt{}, makeAudit(operation.ID, operation.Generation+1, actorID, "restart", "failed-before-effect",
				plan.Digest, digestStrings(operation.ID, "restart-preflight"), service.now()))
			if transitionErr != nil {
				return operation, transitionErr
			}
			return failed, normalizeExecutionError(executionErr)
		}
		if validateExecutionReceipt(receipt, operation, plan, operation.CommitAuthorization) != nil {
			return operation, ErrAmbiguous
		}
		operation, err = service.Store.Transition(ctx, operation.ID, operation.Generation, OperationRunning, OperationVerifying,
			AuthorizationEvidence{}, receipt, makeAudit(operation.ID, operation.Generation+1, actorID, "restart-verify", "effect-observed",
			plan.Digest, receipt.EvidenceDigest, service.now()))
		if err != nil {
			return MaintenanceOperation{}, err
		}
		if executionErr != nil && receipt.Outcome == OutcomeConfirmed {
			return operation, ErrAmbiguous
		}
	}
	if operation.State == OperationVerifying {
		if validateExecutionReceipt(operation.Receipt, operation, plan, operation.CommitAuthorization) != nil {
			return operation, ErrAmbiguous
		}
		target := operationStateForOutcome(operation.Receipt.Outcome)
		if target == OperationSucceeded {
			if err = service.publishRebootRequirement(ctx, plan, operation.Receipt, rebootBoot); err != nil {
				return operation, err
			}
		}
		operation, err = service.Store.Transition(ctx, operation.ID, operation.Generation, OperationVerifying, target,
			AuthorizationEvidence{}, operation.Receipt, makeAudit(operation.ID, operation.Generation+1, actorID, "restart-complete",
			string(operation.Receipt.Outcome), plan.Digest, operation.Receipt.EvidenceDigest, service.now()))
		if err != nil {
			return MaintenanceOperation{}, err
		}
		if target != OperationSucceeded && target != OperationRecovered {
			return operation, ErrRecoveryRequired
		}
	}
	return operation, nil
}

func (service Service) restartInputs(ctx context.Context, operation MaintenanceOperation) (MaintenancePlan, InventorySnapshot, error) {
	plan, err := service.Store.Plan(ctx, operation.PlanID)
	if err != nil {
		return MaintenancePlan{}, InventorySnapshot{}, err
	}
	if plan.Digest != operation.PlanDigest || plan.Generation != operation.PlanGeneration {
		return MaintenancePlan{}, InventorySnapshot{}, ErrStalePlan
	}
	latestPlan, err := service.Store.LatestPlan(ctx, plan.NodeID, plan.Manager)
	if err != nil || latestPlan.ID != plan.ID || latestPlan.Digest != plan.Digest || latestPlan.Generation != plan.Generation {
		if err != nil {
			return MaintenancePlan{}, InventorySnapshot{}, err
		}
		return MaintenancePlan{}, InventorySnapshot{}, ErrStalePlan
	}
	inventory, err := service.Store.LatestInventory(ctx, plan.NodeID, plan.Manager)
	if err != nil {
		return MaintenancePlan{}, InventorySnapshot{}, err
	}
	if inventory.Generation != operation.InventoryGeneration || inventory.ContentDigest != operation.InventoryDigest ||
		inventory.ID != plan.InventoryID || validatePlanAgainstInventory(plan, inventory) != nil {
		return MaintenancePlan{}, InventorySnapshot{}, ErrStaleInventory
	}
	return plan, inventory, nil
}

var _ InventoryProvider = (*LocalLinuxClient)(nil)
var _ MaintenanceExecutor = (*LocalLinuxClient)(nil)
