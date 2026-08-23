//go:build linux

package localruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	cyberpanelextractor "github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanel"
)

const (
	DefaultTrustPath             = "/etc/cyberpanel/migration/trust.json"
	DefaultChunkPath             = "/var/lib/cyberpanel/control/migration-chunks"
	defaultClientCertificatePath = "/run/credentials/panel-core.service/migration-client.crt"
	defaultClientKeyPath         = "/run/credentials/panel-core.service/migration-client.key"
	defaultCertificateAuthority  = "/run/credentials/panel-core.service/migration-ca.pem"
)

// Runtime is the local panel-core migration authority. The target side accepts
// only signed canonical resources and keeps their durable generations dark
// until the guarded cutover controller activates them.
type Runtime struct {
	Repository   *migration.SQLRepository
	Scopes       *migration.RuntimeScopeStore
	Orchestrator *migration.Orchestrator
	Target       *migration.CanonicalTargetImporter
	Chunks       *migration.ChunkStore
	cpanel       *cPanelIntake
}

type Config struct {
	ChunkPath                string
	MaximumChunkBytes        uint64
	TrustPath                string
	CPanelIntakePath         string
	CPanelQuarantinePath     string
	MaximumCPanelBundleBytes uint64
}

func New(ctx context.Context, db *sql.DB, repository *migration.SQLRepository) (*Runtime, error) {
	return NewWithConfig(ctx, db, repository, Config{
		TrustPath:            DefaultTrustPath,
		CPanelIntakePath:     DefaultCPanelIntakePath,
		CPanelQuarantinePath: DefaultCPanelQuarantinePath,
	})
}

func NewWithConfig(ctx context.Context, db *sql.DB, repository *migration.SQLRepository, config Config) (*Runtime, error) {
	if ctx == nil || db == nil || repository == nil {
		return nil, migration.ErrInvalid
	}
	if config.ChunkPath == "" {
		config.ChunkPath = DefaultChunkPath
	}
	if config.TrustPath == "" {
		config.TrustPath = DefaultTrustPath
	}
	if !filepath.IsAbs(config.ChunkPath) || filepath.Clean(config.ChunkPath) != config.ChunkPath {
		return nil, migration.ErrInvalid
	}
	if !filepath.IsAbs(config.TrustPath) || filepath.Clean(config.TrustPath) != config.TrustPath || (config.CPanelIntakePath == "") != (config.CPanelQuarantinePath == "") {
		return nil, migration.ErrInvalid
	}
	if err := ensurePrivateDirectory(config.ChunkPath); err != nil {
		return nil, err
	}
	chunks, err := migration.OpenChunkStore(config.ChunkPath, config.MaximumChunkBytes)
	if err != nil {
		return nil, err
	}
	closeChunks := true
	defer func() {
		if closeChunks {
			_ = chunks.Close()
		}
	}()
	scopes, err := migration.NewRuntimeScopeStore(db)
	if err != nil {
		return nil, err
	}
	if err = scopes.Bootstrap(ctx); err != nil {
		return nil, err
	}
	capacity := filesystemCapacity{path: config.ChunkPath}
	target, err := migration.NewSQLCanonicalTargetImporter(ctx, db, chunks, capacity)
	if err != nil {
		return nil, err
	}
	stager, err := migration.NewChunkStager(chunks, repository)
	if err != nil {
		return nil, err
	}
	verifier := configuredManifestVerifier{path: config.TrustPath}
	var cpanelIntake *cPanelIntake
	if config.CPanelIntakePath != "" {
		cpanelIntake, err = newCPanelIntake(config.CPanelIntakePath, config.CPanelQuarantinePath, config.MaximumCPanelBundleBytes, verifier)
		if err != nil {
			return nil, err
		}
	}
	source := &scopedExtractorSource{scopes:scopes, cpanel:cpanelIntake, clients:map[migration.ID]scopedClient{}, chunks:map[string][]migration.ID{}}
	orchestrator, err := migration.NewOrchestrator(repository, verifier, source, source, target)
	if err != nil {
		return nil, err
	}
	orchestrator.WithChunkStager(stager)
	closeChunks = false
	return &Runtime{Repository: repository, Scopes: scopes, Orchestrator: orchestrator, Target: target, Chunks: chunks, cpanel: cpanelIntake}, nil
}

func (runtime *Runtime) CPanelAvailable() bool {
	return runtime != nil && runtime.cpanel != nil && runtime.cpanel.Ready()
}

func (runtime *Runtime) AdmitCPanel(ctx context.Context, tenantID, endpoint string) (CPanelAdmission, error) {
	if !runtime.CPanelAvailable() {
		return CPanelAdmission{}, migration.ErrBlocked
	}
	return runtime.cpanel.Admit(ctx, tenantID, endpoint)
}

func (runtime *Runtime) Close() error {
	if runtime == nil || runtime.Chunks == nil {
		return nil
	}
	return runtime.Chunks.Close()
}

type trustDocument struct {
	TargetInstallationID string            `json:"target_installation_id"`
	SchemaHashes         []string          `json:"schema_hashes"`
	ManifestKeys         map[string]string `json:"manifest_keys"`
}

type configuredManifestVerifier struct{ path string }

func (verifier configuredManifestVerifier) Verify(ctx context.Context, manifest migration.Manifest) error {
	policy, err := loadTrustPolicy(verifier.path)
	if err != nil {
		return errors.Join(migration.ErrBlocked, err)
	}
	signed, err := migration.NewSignedManifestVerifier(policy)
	if err != nil {
		return err
	}
	return signed.Verify(ctx, manifest)
}

func loadTrustPolicy(path string) (migration.ManifestTrustPolicy, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return migration.ManifestTrustPolicy{}, migration.ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil {
		return migration.ManifestTrustPolicy{}, err
	}
	metadata, ownerKnown := before.Sys().(*syscall.Stat_t)
	if !ownerKnown || int(metadata.Uid) != 0 && int(metadata.Uid) != os.Geteuid() {
		return migration.ManifestTrustPolicy{}, migration.ErrBlocked
	}
	raw, err := readStableFile(path, 1<<20, false)
	if err != nil {
		return migration.ManifestTrustPolicy{}, err
	}
	after, err := os.Stat(path)
	if err != nil {
		return migration.ManifestTrustPolicy{}, err
	}
	afterMetadata, afterOwnerKnown := after.Sys().(*syscall.Stat_t)
	if !afterOwnerKnown || !os.SameFile(before, after) || int(afterMetadata.Uid) != int(metadata.Uid) {
		return migration.ManifestTrustPolicy{}, migration.ErrBlocked
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var document trustDocument
	if err = decoder.Decode(&document); err != nil {
		return migration.ManifestTrustPolicy{}, migration.ErrInvalid
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return migration.ManifestTrustPolicy{}, migration.ErrInvalid
	}
	policy := migration.ManifestTrustPolicy{TargetInstallationID: strings.TrimSpace(document.TargetInstallationID), SchemaHashes: map[string]struct{}{}, Keys: map[string]ed25519.PublicKey{}}
	for _, digest := range document.SchemaHashes {
		digest = strings.ToLower(strings.TrimSpace(digest))
		if len(digest) != sha256.Size*2 {
			return migration.ManifestTrustPolicy{}, migration.ErrInvalid
		}
		if _, err = hex.DecodeString(digest); err != nil {
			return migration.ManifestTrustPolicy{}, migration.ErrInvalid
		}
		policy.SchemaHashes[digest] = struct{}{}
	}
	for keyID, encoded := range document.ManifestKeys {
		rawKey, decodeErr := hex.DecodeString(strings.TrimSpace(encoded))
		if decodeErr != nil || len(rawKey) != ed25519.PublicKeySize || strings.TrimSpace(keyID) != keyID {
			return migration.ManifestTrustPolicy{}, migration.ErrInvalid
		}
		policy.Keys[keyID] = ed25519.PublicKey(rawKey)
	}
	return policy, nil
}

type scopedClient struct{ endpoint string; client *cyberpanelextractor.Client }
type scopedExtractorSource struct{ scopes *migration.RuntimeScopeStore; cpanel *cPanelIntake; mu sync.RWMutex; clients map[migration.ID]scopedClient; chunks map[string][]migration.ID }

func (source *scopedExtractorSource) Discover(ctx context.Context, id migration.ID) (migration.Manifest, error) {
	scope, local, err := source.localScope(ctx, id)
	if err != nil {
		return migration.Manifest{}, err
	}
	var manifest migration.Manifest
	if local {
		manifest, err = source.cpanel.Discover(ctx, scope)
	} else {
		var client *cyberpanelextractor.Client
		client, err = source.client(ctx, id)
		if err == nil {
			manifest, err = client.Discover(ctx, id)
		}
	}
	if err != nil {
		return migration.Manifest{}, err
	}
	source.rememberManifest(manifest)
	return manifest, nil
}

func (source *scopedExtractorSource) rememberManifest(manifest migration.Manifest) {
	source.mu.Lock()
	for _, chunk := range manifest.Chunks {
		values := source.chunks[chunk.Digest]
		found := false
		for _, existing := range values { if existing == manifest.MigrationID { found = true; break } }
		if !found { values = append(values, manifest.MigrationID) }
		if len(values) > 64 { values = values[len(values)-64:] }
		source.chunks[chunk.Digest] = values
	}
	source.mu.Unlock()
}

func (source *scopedExtractorSource) OpenChunk(ctx context.Context, digest string, offset, length uint64) ([]byte, error) {
	if source == nil || source.scopes == nil || ctx == nil || len(digest) != sha256.Size*2 || length == 0 || length > 16<<20 {
		return nil, migration.ErrInvalid
	}
	source.mu.RLock()
	ids := append([]migration.ID(nil), source.chunks[digest]...)
	source.mu.RUnlock()
	if len(ids) == 0 {
		return nil, migration.ErrNotFound
	}
	var result error
	for _, id := range ids {
		scope, local, err := source.localScope(ctx, id)
		if err == nil && local {
			var value []byte
			value, err = source.cpanel.OpenChunk(ctx, scope, digest, offset, length)
			if err == nil {
				return value, nil
			}
		} else if err == nil {
			var client *cyberpanelextractor.Client
			client, err = source.client(ctx, id)
			if err == nil {
				var value []byte
				value, err = client.OpenChunk(ctx, digest, offset, length)
				if err == nil {
					return value, nil
				}
			}
		}
		result = errors.Join(result, err)
	}
	return nil, result
}

func (source *scopedExtractorSource) Generation(ctx context.Context, id migration.ID) (uint64, error) {
	scope, local, err := source.localScope(ctx, id)
	if err != nil {
		return 0, err
	}
	if local {
		return source.cpanel.Generation(ctx, scope)
	}
	client, err := source.client(ctx, id)
	if err != nil {
		return 0, err
	}
	return client.Generation(ctx, id)
}

func (source *scopedExtractorSource) Quiesce(ctx context.Context, id migration.ID, plan migration.Plan, expectedFence uint64) (migration.SourceFence, error) {
	_, local, err := source.localScope(ctx, id)
	if err != nil {
		return migration.SourceFence{}, err
	}
	if local {
		return migration.SourceFence{}, migration.ErrBlocked
	}
	client, err := source.client(ctx, id)
	if err != nil {
		return migration.SourceFence{}, err
	}
	return client.Quiesce(ctx, id, plan, expectedFence)
}

func (source *scopedExtractorSource) Unquiesce(ctx context.Context, fence migration.SourceFence) error {
	_, local, err := source.localScope(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	if local {
		return migration.ErrBlocked
	}
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	return client.Unquiesce(ctx, fence)
}

func (source *scopedExtractorSource) FinalDelta(ctx context.Context, fence migration.SourceFence, base migration.Manifest) (migration.Manifest, error) {
	_, local, err := source.localScope(ctx, fence.MigrationID)
	if err != nil {
		return migration.Manifest{}, err
	}
	if local {
		return migration.Manifest{}, migration.ErrBlocked
	}
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return migration.Manifest{}, err
	}
	return client.FinalDelta(ctx, fence, base)
}

func (source *scopedExtractorSource) CommitSource(ctx context.Context, fence migration.SourceFence) error {
	_, local, err := source.localScope(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	if local {
		return migration.ErrBlocked
	}
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	return client.CommitSource(ctx, fence)
}

func (source *scopedExtractorSource) RollbackSource(ctx context.Context, fence migration.SourceFence) error {
	_, local, err := source.localScope(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	if local {
		return migration.ErrBlocked
	}
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	return client.RollbackSource(ctx, fence)
}

func (source *scopedExtractorSource) localScope(ctx context.Context, id migration.ID) (migration.RuntimeScope, bool, error) {
	if source == nil || source.scopes == nil || ctx == nil || !id.Valid() {
		return migration.RuntimeScope{}, false, migration.ErrInvalid
	}
	scope, err := source.scopes.LoadByMigration(ctx, id)
	if err != nil {
		return migration.RuntimeScope{}, false, err
	}
	if source.cpanel != nil && source.cpanel.OwnsEndpoint(scope.SourceEndpoint) {
		return scope, true, nil
	}
	if strings.HasPrefix(scope.SourceEndpoint, "file:") {
		return migration.RuntimeScope{}, false, migration.ErrBlocked
	}
	return scope, false, nil
}

func (source *scopedExtractorSource) client(ctx context.Context, id migration.ID) (*cyberpanelextractor.Client, error) {
	if source == nil || source.scopes == nil || ctx == nil || !id.Valid() {
		return nil, migration.ErrInvalid
	}
	scope, err := source.scopes.LoadByMigration(ctx, id)
	if err != nil {
		return nil, err
	}
	if source.cpanel != nil && source.cpanel.OwnsEndpoint(scope.SourceEndpoint) {
		return nil, migration.ErrConflict
	}
	source.mu.RLock()
	cached, found := source.clients[id]
	source.mu.RUnlock()
	if found {
		if cached.endpoint != scope.SourceEndpoint || cached.client == nil { return nil, migration.ErrConflict }
		return cached.client, nil
	}
	dial, err := extractorDialer(scope.SourceEndpoint)
	if err != nil {
		return nil, err
	}
	client, err := cyberpanelextractor.NewClient(dial, 48<<20, 2*time.Minute)
	if err != nil { return nil, err }
	source.mu.Lock()
	if existing, present := source.clients[id]; present {
		source.mu.Unlock()
		if existing.endpoint != scope.SourceEndpoint || existing.client == nil { return nil, migration.ErrConflict }
		return existing.client, nil
	}
	source.clients[id] = scopedClient{endpoint:scope.SourceEndpoint, client:client}
	source.mu.Unlock()
	return client, nil
}

func extractorDialer(endpoint string) (cyberpanelextractor.DialContext, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, migration.ErrInvalid
	}
	address := parsed.Host
	if parsed.Port() == "" {
		address = net.JoinHostPort(parsed.Hostname(), "443")
	}
	certificatePEM, err := readStableFile(defaultClientCertificatePath, 1<<20, false)
	if err != nil {
		return nil, errors.Join(migration.ErrBlocked, err)
	}
	keyPEM, err := readStableFile(defaultClientKeyPath, 1<<20, true)
	if err != nil {
		return nil, errors.Join(migration.ErrBlocked, err)
	}
	certificateAuthority, err := readStableFile(defaultCertificateAuthority, 1<<20, false)
	if err != nil {
		return nil, errors.Join(migration.ErrBlocked, err)
	}
	identity, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, migration.ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificateAuthority) {
		return nil, migration.ErrInvalid
	}
	configuration := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: parsed.Hostname(), RootCAs: roots, Certificates: []tls.Certificate{identity}}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}, Config: configuration}
	return func(ctx context.Context) (net.Conn, error) { return dialer.DialContext(ctx, "tcp", address) }, nil
}

type filesystemCapacity struct{ path string }

func (provider filesystemCapacity) Capacity(ctx context.Context) (map[string]uint64, error) {
	if ctx == nil || !filepath.IsAbs(provider.path) || filepath.Clean(provider.path) != provider.path {
		return nil, migration.ErrInvalid
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	var statistics syscall.Statfs_t
	if err := syscall.Statfs(provider.path, &statistics); err != nil {
		return nil, err
	}
	free := uint64(statistics.Bavail)
	block := uint64(statistics.Bsize)
	if block != 0 && free > ^uint64(0)/block {
		free = ^uint64(0)
	} else {
		free *= block
	}
	objects := uint64(statistics.Ffree)
	var system syscall.Sysinfo_t
	if err := syscall.Sysinfo(&system); err != nil {
		return nil, err
	}
	memory := uint64(system.Freeram)
	unit := uint64(system.Unit)
	if unit != 0 && memory > ^uint64(0)/unit {
		memory = ^uint64(0)
	} else {
		memory *= unit
	}
	cpuMilli := uint64(runtime.NumCPU()) * 1000
	return map[string]uint64{"disk_bytes": free, "database_bytes": free, "mail_bytes": free, "certificate_bytes": free, "container_bytes": free, "dns_recordsets": objects, "mailboxes": objects, "transfer_bytes": ^uint64(0), "memory_bytes": memory, "cpu_milli": cpuMilli, "io_bytes_per_second": ^uint64(0), "max_connections": 10000, "enabled": ^uint64(0)}, nil
}

func ensurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return migration.ErrInvalid
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return migration.ErrInvalid
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(metadata.Uid) != os.Geteuid() {
		return migration.ErrBlocked
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return migration.ErrBlocked
	}
	return nil
}

func readStableFile(path string, maximum int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum || info.Mode().Perm()&0o022 != 0 || private && info.Mode().Perm()&0o077 != 0 {
		return nil, migration.ErrBlocked
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(info, after) || int64(len(raw)) != info.Size() {
		return nil, fmt.Errorf("migration authority changed while reading")
	}
	return raw, nil
}

var _ migration.SourceReader = (*scopedExtractorSource)(nil)
var _ migration.CutoverSource = (*scopedExtractorSource)(nil)
var _ migration.TargetCapacityProvider = filesystemCapacity{}
