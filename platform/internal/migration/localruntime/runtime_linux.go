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
	"github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanelbackup"
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
	cyberPanelBackup *cyberpanelbackup.Intake
	maintenanceMu     sync.Mutex
	maintenanceCancel context.CancelFunc
	maintenanceDone   chan struct{}
	closed            bool
}

type Config struct {
	ChunkPath                string
	MaximumChunkBytes        uint64
	TrustPath                string
	CPanelIntakePath         string
	CPanelQuarantinePath     string
	MaximumCPanelBundleBytes uint64
	EnableCyberPanelBackup   bool
	TargetFactory TargetFactory
}

// TargetFactory binds ordinary domain commands at the core composition root.
// SQL migration projections are never a fallback for missing host capabilities.
type TargetFactory func(context.Context,*sql.DB,*migration.ChunkStore,migration.TargetCapacityProvider,*migration.RuntimeScopeStore)(*migration.CanonicalTargetImporter,error)

func New(ctx context.Context, db *sql.DB, repository *migration.SQLRepository, factories ...TargetFactory) (*Runtime, error) {
	if len(factories)!=1||factories[0]==nil{return nil,migration.ErrBlocked}
	return NewWithConfig(ctx, db, repository, Config{
		TrustPath:            DefaultTrustPath,
		CPanelIntakePath:     DefaultCPanelIntakePath,
		CPanelQuarantinePath: DefaultCPanelQuarantinePath,
		EnableCyberPanelBackup: true,
		TargetFactory: factories[0],
	})
}

func NewWithConfig(ctx context.Context, db *sql.DB, repository *migration.SQLRepository, config Config) (*Runtime, error) {
	if ctx == nil || db == nil || repository == nil || config.TargetFactory == nil {
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
	target, err := config.TargetFactory(ctx, db, chunks, capacity, scopes)
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
	var backupIntake *cyberpanelbackup.Intake
	if config.EnableCyberPanelBackup {
		backupIntake, err = cyberpanelbackup.New(verifier)
		if err != nil {
			return nil, err
		}
	}
	stager.WithReferenceStore(scopes)
	localSources := []localMigrationSource{}
	if cpanelIntake != nil {
		localSources = append(localSources, cpanelIntake)
	}
	if backupIntake != nil {
		localSources = append(localSources, backupIntake)
	}
	source := &scopedExtractorSource{repository:repository, scopes:scopes, locals:localSources, clients:map[migration.ID]scopedClient{}, chunks:map[string][]migration.ID{}, clock:time.Now}
	orchestrator, err := migration.NewOrchestrator(repository, verifier, source, source, target)
	if err != nil {
		return nil, err
	}
	orchestrator.WithChunkStager(stager)
	closeChunks = false
	return &Runtime{Repository: repository, Scopes: scopes, Orchestrator: orchestrator, Target: target, Chunks: chunks, cpanel: cpanelIntake, cyberPanelBackup: backupIntake}, nil
}

func (runtime *Runtime) CPanelAvailable() bool {
	return runtime != nil && runtime.cpanel != nil && runtime.cpanel.Ready()
}

func (runtime *Runtime) CyberPanelBackupAvailable() bool {
	return runtime != nil && runtime.cyberPanelBackup != nil && runtime.cyberPanelBackup.Ready()
}

func (runtime *Runtime) StartChunkMaintenance(ctx context.Context, auditor migration.ChunkMaintenanceAuditor) error {
	if runtime == nil || runtime.Scopes == nil || runtime.Chunks == nil || ctx == nil || auditor == nil {
		return migration.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	scheduler, err := migration.NewChunkMaintenanceScheduler(runtime.Scopes, runtime.Chunks, auditor, migration.DefaultChunkMaintenanceConfig())
	if err != nil {
		return err
	}
	runtime.maintenanceMu.Lock()
	defer runtime.maintenanceMu.Unlock()
	if runtime.closed || runtime.maintenanceDone != nil {
		return migration.ErrConflict
	}
	runContext, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	runtime.maintenanceCancel = cancel
	runtime.maintenanceDone = done
	go func() {
		defer close(done)
		scheduler.Run(runContext)
	}()
	return nil
}

func (runtime *Runtime) AdmitCPanel(ctx context.Context, tenantID, endpoint string) (CPanelAdmission, error) {
	if !runtime.CPanelAvailable() {
		return CPanelAdmission{}, migration.ErrBlocked
	}
	return runtime.cpanel.Admit(ctx, tenantID, endpoint)
}

func (runtime *Runtime) AdmitCyberPanelBackup(ctx context.Context, tenantID, endpoint string) (cyberpanelbackup.Admission, error) {
	if !runtime.CyberPanelBackupAvailable() {
		return cyberpanelbackup.Admission{}, migration.ErrBlocked
	}
	return runtime.cyberPanelBackup.Admit(ctx, tenantID, endpoint)
}

func (runtime *Runtime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.maintenanceMu.Lock()
	if runtime.closed {
		runtime.maintenanceMu.Unlock()
		return nil
	}
	runtime.closed = true
	cancel, done, chunks := runtime.maintenanceCancel, runtime.maintenanceDone, runtime.Chunks
	runtime.maintenanceMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	if chunks == nil {
		return nil
	}
	return chunks.Close()
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
type localMigrationSource interface {
	Discover(context.Context, migration.RuntimeScope) (migration.Manifest, error)
	OpenChunk(context.Context, migration.RuntimeScope, string, uint64, uint64) ([]byte, error)
	Generation(context.Context, migration.RuntimeScope) (uint64, error)
	OwnsEndpoint(string) bool
}
type scopedExtractorSource struct{ repository migration.Repository; scopes *migration.RuntimeScopeStore; locals []localMigrationSource; mu sync.RWMutex; clients map[migration.ID]scopedClient; chunks map[string][]migration.ID; clock func()time.Time }

func (source *scopedExtractorSource) Discover(ctx context.Context, id migration.ID) (migration.Manifest, error) {
	scope, local, err := source.localScope(ctx, id)
	if err != nil {
		return migration.Manifest{}, err
	}
	var manifest migration.Manifest
	if local != nil {
		manifest, err = local.Discover(ctx, scope)
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
		if err == nil && local != nil {
			var value []byte
			value, err = local.OpenChunk(ctx, scope, digest, offset, length)
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
	if local != nil {
		return local.Generation(ctx, scope)
	}
	client, err := source.client(ctx, id)
	if err != nil {
		return 0, err
	}
	return client.Generation(ctx, id)
}

func (source *scopedExtractorSource) Quiesce(ctx context.Context, id migration.ID, plan migration.Plan, expectedFence uint64) (migration.SourceFence, error) {
	state, err := source.localFenceState(ctx, id)
	if err != nil {
		return migration.SourceFence{}, err
	}
	if state.local != nil {
		if expectedFence == 0 || expectedFence != state.fence || !sameLocalCutoverPlan(plan, state.plan) {
			return migration.SourceFence{}, migration.ErrConflict
		}
		now := time.Now().UTC()
		if source.clock != nil {
			now = source.clock().UTC()
		}
		fence := migration.SourceFence{MigrationID:id, Generation:state.manifest.SourceGeneration, Fence:expectedFence, ExpiresAt:now.Add(plan.RollbackWindow).UTC()}
		fence.Digest = localSourceFenceDigest(state.scope, state.manifest, state.plan, fence)
		return fence, nil
	}
	client, err := source.client(ctx, id)
	if err != nil {
		return migration.SourceFence{}, err
	}
	return client.Quiesce(ctx, id, plan, expectedFence)
}

func (source *scopedExtractorSource) Unquiesce(ctx context.Context, fence migration.SourceFence) error {
	state, err := source.localFenceState(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	if state.local != nil {
		_, err = source.validateLocalFence(state, fence, false)
		return err
	}
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	return client.Unquiesce(ctx, fence)
}

func (source *scopedExtractorSource) FinalDelta(ctx context.Context, fence migration.SourceFence, base migration.Manifest) (migration.Manifest, error) {
	state, err := source.localFenceState(ctx, fence.MigrationID)
	if err != nil {
		return migration.Manifest{}, err
	}
	if state.local != nil {
		manifest, validateErr := source.validateLocalFence(state, fence, true)
		if validateErr != nil {
			return migration.Manifest{}, validateErr
		}
		if base.MigrationID != manifest.MigrationID || base.Source != manifest.Source || base.MerkleRoot != manifest.MerkleRoot || base.SourceGeneration != manifest.SourceGeneration {
			return migration.Manifest{}, migration.ErrConflict
		}
		return manifest, nil
	}
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return migration.Manifest{}, err
	}
	return client.FinalDelta(ctx, fence, base)
}

func (source *scopedExtractorSource) CommitSource(ctx context.Context, fence migration.SourceFence) error {
	state, err := source.localFenceState(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	if state.local != nil {
		_, err = source.validateLocalFence(state, fence, true)
		return err
	}
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	return client.CommitSource(ctx, fence)
}

func (source *scopedExtractorSource) RollbackSource(ctx context.Context, fence migration.SourceFence) error {
	state, err := source.localFenceState(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	if state.local != nil {
		_, err = source.validateLocalFence(state, fence, false)
		return err
	}
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	return client.RollbackSource(ctx, fence)
}

type localFenceState struct {
	scope    migration.RuntimeScope
	local    localMigrationSource
	manifest migration.Manifest
	plan     migration.Plan
	fence    uint64
}

func (source *scopedExtractorSource) localFenceState(ctx context.Context, id migration.ID) (localFenceState, error) {
	if source == nil || source.repository == nil || ctx == nil || !id.Valid() {
		return localFenceState{}, migration.ErrInvalid
	}
	scope, local, err := source.localScope(ctx, id)
	if err != nil || local == nil {
		return localFenceState{scope:scope, local:local}, err
	}
	manifest, err := local.Discover(ctx, scope)
	if err != nil {
		return localFenceState{}, err
	}
	record, err := source.repository.Migration(ctx, id)
	if err != nil {
		return localFenceState{}, err
	}
	plan, err := source.repository.Plan(ctx, record.PlanDigest)
	if err != nil {
		return localFenceState{}, err
	}
	if manifest.Validate() != nil || manifest.MigrationID != id || manifest.Source != record.Source || (manifest.Source != migration.SourceCPanel && manifest.Source != migration.SourceCyberPanelBackup) || manifest.MerkleRoot != record.ManifestRoot || manifest.SourceGeneration != record.SourceGeneration || plan.MigrationID != id || plan.ManifestRoot != manifest.MerkleRoot || plan.DryRunDigest != record.PlanDigest || plan.ApprovedAt == nil || plan.ApprovedAt.IsZero() || !isLocalDigest(plan.ApprovalDigest) || plan.RollbackWindow <= 0 || plan.RollbackWindow > 24*time.Hour || plan.QuiesceMode != "write_fence" || len(plan.Unsupported) != 0 {
		return localFenceState{}, migration.ErrConflict
	}
	return localFenceState{scope:scope, local:local, manifest:manifest, plan:plan, fence:record.Fence}, nil
}

func (source *scopedExtractorSource) validateLocalFence(state localFenceState, fence migration.SourceFence, requireLive bool) (migration.Manifest, error) {
	if state.local == nil || fence.MigrationID != state.manifest.MigrationID || fence.Generation != state.manifest.SourceGeneration || fence.Fence == 0 || fence.Fence != state.fence || fence.ExpiresAt.IsZero() || fence.Digest != localSourceFenceDigest(state.scope, state.manifest, state.plan, fence) {
		return migration.Manifest{}, migration.ErrConflict
	}
	if requireLive {
		now := time.Now().UTC()
		if source.clock != nil {
			now = source.clock().UTC()
		}
		if !now.Before(fence.ExpiresAt) {
			return migration.Manifest{}, migration.ErrBlocked
		}
	}
	return state.manifest, nil
}

func sameLocalCutoverPlan(left, right migration.Plan) bool {
	if left.ApprovedAt == nil || right.ApprovedAt == nil {
		return false
	}
	return left.ID == right.ID && left.MigrationID == right.MigrationID && left.ManifestRoot == right.ManifestRoot && left.DryRunDigest == right.DryRunDigest && left.ApprovalDigest == right.ApprovalDigest && left.RollbackWindow == right.RollbackWindow && left.QuiesceMode == right.QuiesceMode && left.CutoverMethod == right.CutoverMethod && left.ApprovedAt.Equal(*right.ApprovedAt)
}

func localSourceFenceDigest(scope migration.RuntimeScope, manifest migration.Manifest, plan migration.Plan, fence migration.SourceFence) string {
	approvedAt := time.Time{}
	if plan.ApprovedAt != nil {
		approvedAt = plan.ApprovedAt.UTC()
	}
	raw, _ := json.Marshal(struct {
		Domain               string               `json:"domain"`
		TenantID             string               `json:"tenant_id"`
		SourceEndpoint       string               `json:"source_endpoint"`
		MigrationID          migration.ID         `json:"migration_id"`
		Source               migration.SourceKind `json:"source"`
		SourceInstallationID string               `json:"source_installation_id"`
		TargetInstallationID string               `json:"target_installation_id"`
		ManifestRoot         string               `json:"manifest_root"`
		Generation           uint64               `json:"generation"`
		Fence                uint64               `json:"fence"`
		ExpiresAt            time.Time            `json:"expires_at"`
		PlanID               migration.ID         `json:"plan_id"`
		PlanDigest           string               `json:"plan_digest"`
		ApprovalDigest       string               `json:"approval_digest"`
		ApprovedAt           time.Time            `json:"approved_at"`
	}{Domain:"local-immutable-source-fence-v1", TenantID:scope.TenantID, SourceEndpoint:scope.SourceEndpoint, MigrationID:manifest.MigrationID, Source:manifest.Source, SourceInstallationID:manifest.SourceInstallationID, TargetInstallationID:manifest.TargetInstallationID, ManifestRoot:manifest.MerkleRoot, Generation:fence.Generation, Fence:fence.Fence, ExpiresAt:fence.ExpiresAt.UTC(), PlanID:plan.ID, PlanDigest:plan.DryRunDigest, ApprovalDigest:plan.ApprovalDigest, ApprovedAt:approvedAt})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (source *scopedExtractorSource) localScope(ctx context.Context, id migration.ID) (migration.RuntimeScope, localMigrationSource, error) {
	if source == nil || source.scopes == nil || ctx == nil || !id.Valid() {
		return migration.RuntimeScope{}, nil, migration.ErrInvalid
	}
	scope, err := source.scopes.LoadByMigration(ctx, id)
	if err != nil {
		return migration.RuntimeScope{}, nil, err
	}
	for _, local := range source.locals {
		if local != nil && local.OwnsEndpoint(scope.SourceEndpoint) {
			return scope, local, nil
		}
	}
	if strings.HasPrefix(scope.SourceEndpoint, "file:") {
		return migration.RuntimeScope{}, nil, migration.ErrBlocked
	}
	return scope, nil, nil
}

func (source *scopedExtractorSource) client(ctx context.Context, id migration.ID) (*cyberpanelextractor.Client, error) {
	if source == nil || source.scopes == nil || ctx == nil || !id.Valid() {
		return nil, migration.ErrInvalid
	}
	scope, err := source.scopes.LoadByMigration(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, local := range source.locals {
		if local != nil && local.OwnsEndpoint(scope.SourceEndpoint) {
			return nil, migration.ErrConflict
		}
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
