//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	hostingservice "github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/sqlrepo"
	mailcontrol "github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	localmigration "github.com/aonsyed/cyberpanel/platform/internal/migration/localruntime"
)

const migrationHostSchema = `CREATE TABLE IF NOT EXISTS panel_migration_host_effects(
 migration_id TEXT NOT NULL,kind TEXT NOT NULL,source_id TEXT NOT NULL,target_id TEXT NOT NULL,
 intent_json BLOB NOT NULL,domain_intent_json BLOB NOT NULL,scope_digest TEXT NOT NULL,state TEXT NOT NULL,evidence_json BLOB NOT NULL,
 PRIMARY KEY(migration_id,kind,source_id),UNIQUE(target_id));
 CREATE TABLE IF NOT EXISTS panel_migration_host_activations(
 migration_id TEXT PRIMARY KEY,plan_digest TEXT NOT NULL,fence INTEGER NOT NULL,state TEXT NOT NULL,receipt_json BLOB NOT NULL);`

// Domain receipts and desired state are journaled here. SQL is never used as
// proof that a file, process, route, database or DNS record exists on the host.
type migrationHostTarget struct {
	db               *sql.DB
	chunks           *migration.ChunkStore
	scopes           *migration.RuntimeScopeStore
	repository       *migration.SQLRepository
	hosting          hostingservice.Service
	sites            *sqlrepo.Repository
	files            *access.FileService
	dns              *dns.TenantZoneAuthority
	database         migration.CanonicalImportHandler
	auxiliary        *migrationAuxiliaryTarget
	certificate      *migrationCertificateTarget
	mail             *migrationMailTarget
	container        *migrationContainerTarget
	applicationProbe migration.TargetProbe
	mu               sync.Mutex
}

func migrationTargetFactory(hosting hostingservice.Service, sites *sqlrepo.Repository, files *access.FileService, dnsClient *dns.TenantZoneAuthority, repository *migration.SQLRepository, applicationProbe migration.TargetProbe, containerApplications *containers.ApplicationService, secretsFactory func(context.Context, *sql.DB, *migration.RuntimeScopeStore) (migration.MigrationSecretGateway, error), databaseFactory func(context.Context, *sql.DB, *migration.ChunkStore, *migration.RuntimeScopeStore) (migration.CanonicalImportHandler, error), auxiliaryServices migrationAuxiliaryServices, certificateFactory func(context.Context, *sql.DB, *migration.ChunkStore, *migration.RuntimeScopeStore) (*migrationCertificateTarget, error), mailStore mailcontrol.SQLControlRepository, mailProjector mailcontrol.RepositorySnapshotProjector, mailRuntime *mailcontrol.MailDaemonClient) localmigration.TargetFactory {
	return func(ctx context.Context, db *sql.DB, chunks *migration.ChunkStore, capacity migration.TargetCapacityProvider, scopes *migration.RuntimeScopeStore) (*migration.CanonicalTargetImporter, error) {
		if sites == nil || files == nil || files.Executor == nil || dnsClient == nil || repository == nil || applicationProbe == nil || containerApplications == nil || secretsFactory == nil || databaseFactory == nil || mailStore.DB == nil || mailProjector.Store == nil || mailRuntime == nil {
			return nil, migration.ErrBlocked
		}
		ledger, err := migration.NewSQLImportLedger(db)
		if err != nil {
			return nil, err
		}
		if err = ledger.Bootstrap(ctx); err != nil {
			return nil, err
		}
		if _, err = db.ExecContext(ctx, migrationHostSchema); err != nil {
			return nil, err
		}
		secrets, err := secretsFactory(ctx, db, scopes)
		if err != nil {
			return nil, err
		}
		target := &migrationHostTarget{db: db, chunks: chunks, scopes: scopes, repository: repository, hosting: hosting, sites: sites, files: files, dns: dnsClient, applicationProbe: applicationProbe}
		if databaseFactory != nil {
			target.database, err = databaseFactory(ctx, db, chunks, scopes)
			if err != nil {
				return nil, err
			}
		}
		target.auxiliary, err = newMigrationAuxiliaryTarget(ctx, target, auxiliaryServices)
		if err != nil {
			return nil, err
		}
		if certificateFactory == nil {
			return nil, migration.ErrBlocked
		}
		target.certificate, err = certificateFactory(ctx, db, chunks, scopes)
		if err != nil {
			return nil, err
		}
		target.container, err = newMigrationContainerTarget(target, containerApplications)
		if err != nil {
			return nil, err
		}
		secretTarget, ok := secrets.(*migrationSecretTarget)
		if !ok {
			return nil, migration.ErrBlocked
		}
		target.mail, err = newMigrationMailTarget(ctx, target, chunks, mailStore, mailProjector, mailRuntime, secretTarget)
		if err != nil {
			return nil, err
		}
		return migration.NewCanonicalTargetImporter(capacity, target, target, target, ledger, secrets)
	}
}

func migrationHostDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func migrationHostEffect(intent migration.ImportIntent, evidence any, generation, bytes, objects uint64) migration.ImportEffect {
	digest := migrationHostDigest(evidence)
	return migration.ImportEffect{EffectID: intent.EffectID, InputDigest: intent.InputDigest, OutputDigest: digest, Status: migration.ImportEffectApplied, TargetGeneration: generation, BytesWritten: bytes, ObjectsWritten: objects, EvidenceDigest: digest, AppliedAt: time.Now().UTC()}
}
func migrationHostFailure(intent migration.ImportIntent, err error) (migration.ImportEffect, error) {
	return migration.ImportEffect{EffectID: intent.EffectID, InputDigest: intent.InputDigest, Status: migration.ImportEffectAmbiguous, ErrorCode: "DOMAIN_EFFECT_REQUIRES_OBSERVATION", AppliedAt: time.Now().UTC()}, err
}

func (target *migrationHostTarget) admitted(ctx context.Context, intent migration.ImportIntent) (migration.RuntimeScope, error) {
	if err := migration.ValidateCanonicalImportIntent(intent); err != nil {
		return migration.RuntimeScope{}, err
	}
	value, err := target.repository.Migration(ctx, intent.MigrationID)
	if err != nil {
		return migration.RuntimeScope{}, err
	}
	if value.SourceGeneration != intent.SourceGeneration || value.Fence != intent.Fence {
		return migration.RuntimeScope{}, migration.ErrConflict
	}
	plan, err := target.repository.Plan(ctx, value.PlanDigest)
	if err != nil {
		return migration.RuntimeScope{}, err
	}
	if plan.ApprovedAt == nil || plan.ApprovalDigest == "" || plan.MigrationID != value.ID || plan.ManifestRoot != value.ManifestRoot || len(plan.Unsupported) != 0 {
		return migration.RuntimeScope{}, migration.ErrBlocked
	}
	matched := false
	for _, mapping := range plan.Mappings {
		if mapping.SourceKind == string(intent.Kind) && mapping.SourceID == intent.SourceID && mapping.TargetID == intent.TargetID && mapping.Disposition == migration.DispositionCreate {
			matched = true
		}
	}
	if !matched || (intent.Disposition != migration.DispositionCreate && intent.Disposition != migration.DispositionMerge) {
		return migration.RuntimeScope{}, migration.ErrBlocked
	}
	if _, err = target.supportedManifest(ctx, value); err != nil {
		return migration.RuntimeScope{}, err
	}
	var state, planDigest string
	if err = target.db.QueryRowContext(ctx, `SELECT state,plan_digest FROM panel_migration_import_runs WHERE migration_id=?`, intent.MigrationID.String()).Scan(&state, &planDigest); err != nil {
		return migration.RuntimeScope{}, err
	}
	if state != "prepared" || planDigest != plan.DryRunDigest {
		return migration.RuntimeScope{}, migration.ErrBlocked
	}
	return target.scopes.LoadByMigration(ctx, intent.MigrationID)
}

func (target *migrationHostTarget) saveIntent(ctx context.Context, intent migration.ImportIntent) error {
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	binding, err := target.scopeBinding(ctx, intent.MigrationID)
	if err != nil {
		return err
	}
	var prior []byte
	var state, storedBinding string
	err = target.db.QueryRowContext(ctx, `SELECT intent_json,state,scope_digest FROM panel_migration_host_effects WHERE migration_id=? AND kind=? AND source_id=?`, intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String()).Scan(&prior, &state, &storedBinding)
	if err == nil {
		var previous migration.ImportIntent
		if storedBinding != binding || json.Unmarshal(prior, &previous) != nil || previous.TargetID != intent.TargetID || previous.InputDigest != intent.InputDigest || previous.EffectID != intent.EffectID {
			return migration.ErrConflict
		}
		if state == "active" || state == "compensated" {
			return migration.ErrWriteFrontier
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = target.db.ExecContext(ctx, `INSERT INTO panel_migration_host_effects(migration_id,kind,source_id,target_id,intent_json,domain_intent_json,scope_digest,state,evidence_json) VALUES(?,?,?,?,?,?,?,'staging','{}')`, intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String(), intent.TargetID.String(), raw, raw, binding)
	return err
}

func (target *migrationHostTarget) scopeBinding(ctx context.Context, id migration.ID) (string, error) {
	scope, err := target.scopes.LoadByMigration(ctx, id)
	if err != nil {
		return "", err
	}
	value, err := target.repository.Migration(ctx, id)
	if err != nil {
		return "", err
	}
	return migrationHostDigest(struct{ Tenant, Plan, Project, Migration string }{scope.TenantID, value.PlanDigest, "migration-" + id.String(), id.String()}), nil
}

func (target *migrationHostTarget) observeDatabase(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	var raw []byte
	if err := target.db.QueryRowContext(ctx, `SELECT domain_intent_json FROM panel_migration_host_effects WHERE migration_id=? AND kind=? AND source_id=? AND target_id=?`, intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String(), intent.TargetID.String()).Scan(&raw); err != nil {
		return migration.ImportEffect{}, err
	}
	var origin migration.ImportIntent
	if json.Unmarshal(raw, &origin) != nil || origin.MigrationID != intent.MigrationID || origin.TargetID != intent.TargetID || origin.Kind != migration.ImportDatabase || target.database == nil {
		return migration.ImportEffect{}, migration.ErrConflict
	}
	return target.database.Observe(ctx, origin)
}

func (target *migrationHostTarget) finishEffect(ctx context.Context, intent migration.ImportIntent, effect migration.ImportEffect) error {
	raw, err := json.Marshal(effect)
	if err != nil {
		return err
	}
	result, err := target.db.ExecContext(ctx, `UPDATE panel_migration_host_effects SET state='dark',evidence_json=? WHERE migration_id=? AND kind=? AND source_id=? AND state IN ('staging','dark')`, raw, intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return migration.ErrConflict
	}
	return nil
}

func (target *migrationHostTarget) ApplyCanonicalImport(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	target.mu.Lock()
	defer target.mu.Unlock()
	return target.apply(ctx, intent)
}
func (target *migrationHostTarget) apply(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	scope, err := target.admitted(ctx, intent)
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	if intent.Disposition == migration.DispositionMerge {
		return target.unchangedDelta(ctx, scope, intent)
	}
	switch intent.Kind {
	case migration.ImportSite, migration.ImportDNSZone, migration.ImportCertificate:
	case migration.ImportMailDomain:
		if target.mail == nil {
			return migrationHostFailure(intent, fmt.Errorf("%w: mail import adapter unbound", migration.ErrBlocked))
		}
	case migration.ImportContainer:
		if target.container == nil {
			return migrationHostFailure(intent, fmt.Errorf("%w: protected container ingress unbound", migration.ErrBlocked))
		}
	case migration.ImportDatabase:
		if target.database == nil {
			return migrationHostFailure(intent, fmt.Errorf("%w: database import adapter unbound", migration.ErrBlocked))
		}
	default:
		if !migrationAuxiliaryKind(intent.Kind) || target.auxiliary == nil {
			return migrationHostFailure(intent, fmt.Errorf("%w: unsupported target kind %s", migration.ErrBlocked, intent.Kind))
		}
	}
	if err = target.saveIntent(ctx, intent); err != nil {
		return migrationHostFailure(intent, err)
	}
	var effect migration.ImportEffect
	switch intent.Kind {
	case migration.ImportSite:
		effect, err = target.importSite(ctx, scope, intent)
	case migration.ImportDNSZone:
		effect, err = target.stageDNS(ctx, scope, intent)
	case migration.ImportDatabase:
		effect, err = target.database.Apply(ctx, intent)
	case migration.ImportCertificate:
		effect, err = target.certificate.Apply(ctx, intent)
	case migration.ImportMailDomain:
		effect, err = target.mail.Apply(ctx, intent)
	case migration.ImportContainer:
		effect, err = target.container.Apply(ctx, intent)
	default:
		effect, err = target.auxiliary.Apply(ctx, intent)
	}
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	if effect.Status != migration.ImportEffectApplied || effect.EvidenceDigest == "" {
		return migrationHostFailure(intent, migration.ErrAmbiguous)
	}
	if err = target.finishEffect(ctx, intent, effect); err != nil {
		return migrationHostFailure(intent, err)
	}
	return effect, nil
}

func (target *migrationHostTarget) ObserveCanonicalImport(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	target.mu.Lock()
	defer target.mu.Unlock()
	// Each concrete operation reconciles its own scoped state: hosting commands
	// use durable effect IDs, files are read back before a missing upload is retried.
	return target.apply(ctx, intent)
}

func (target *migrationHostTarget) entries(ctx context.Context, value migration.Migration, plan migration.Plan) ([]migration.ImportIntent, error) {
	if plan.MigrationID != value.ID || plan.ManifestRoot != value.ManifestRoot || plan.DryRunDigest != value.PlanDigest || plan.ApprovedAt == nil || plan.ApprovalDigest == "" || len(plan.Unsupported) != 0 {
		return nil, migration.ErrBlocked
	}
	manifest, err := target.supportedManifest(ctx, value)
	if err != nil {
		return nil, err
	}
	binding, err := target.scopeBinding(ctx, value.ID)
	if err != nil {
		return nil, err
	}
	entries := []migration.ImportIntent{}
	siteCount := 0
	for _, mapping := range plan.Mappings {
		if mapping.Disposition != migration.DispositionCreate {
			return nil, migration.ErrBlocked
		}
		kind := migration.ImportResourceKind(mapping.SourceKind)
		if kind != migration.ImportSite && kind != migration.ImportDNSZone && (kind != migration.ImportDatabase || target.database == nil) && (kind != migration.ImportCertificate || target.certificate == nil) && (kind != migration.ImportMailDomain || target.mail == nil) && (kind != migration.ImportContainer || target.container == nil) && (!migrationAuxiliaryKind(kind) || target.auxiliary == nil) {
			return nil, fmt.Errorf("%w: target kind %s is not bound", migration.ErrBlocked, kind)
		}
		if kind == migration.ImportSite {
			siteCount++
		}
		var storedBinding string
		if err = target.db.QueryRowContext(ctx, `SELECT scope_digest FROM panel_migration_host_effects WHERE migration_id=? AND kind=? AND source_id=?`, value.ID.String(), mapping.SourceKind, mapping.SourceID.String()).Scan(&storedBinding); err != nil || storedBinding != binding {
			return nil, errors.Join(migration.ErrConflict, err)
		}
		var raw []byte
		var state string
		if err := target.db.QueryRowContext(ctx, `SELECT intent_json,state FROM panel_migration_host_effects WHERE migration_id=? AND kind=? AND source_id=?`, value.ID.String(), mapping.SourceKind, mapping.SourceID.String()).Scan(&raw, &state); err != nil {
			return nil, err
		}
		var intent migration.ImportIntent
		if json.Unmarshal(raw, &intent) != nil || intent.TargetID != mapping.TargetID || intent.MigrationID != value.ID || intent.SourceGeneration != value.SourceGeneration || intent.Fence != value.Fence || (state != "dark" && state != "active") || migration.ValidateCanonicalImportIntent(intent) != nil {
			return nil, migration.ErrConflict
		}
		entries = append(entries, intent)
	}
	if siteCount != 1 || len(entries) != len(manifest.Sites)+len(manifest.Databases)+len(manifest.DNSZones)+len(manifest.MailDomains)+len(manifest.Schedules)+len(manifest.Repositories)+len(manifest.BackupPolicies)+len(manifest.Certificates)+len(manifest.Containers) {
		return nil, fmt.Errorf("%w: this target adapter requires one site and complete supported mappings", migration.ErrBlocked)
	}
	return entries, nil
}

// A true flag for an unrepresented domain means validated absence in the
// signed admission manifest, not a probe or successful import of that domain.
func (target *migrationHostTarget) supportedManifest(ctx context.Context, value migration.Migration) (migration.Manifest, error) {
	manifest, err := target.repository.Manifest(ctx, value.ManifestRoot)
	if err != nil {
		return manifest, err
	}
	if manifest.MigrationID != value.ID || manifest.MerkleRoot != value.ManifestRoot || manifest.Validate() != nil {
		return manifest, migration.ErrInvalid
	}
	if len(manifest.Sites) != 1 || len(manifest.Credentials) != 0 || len(manifest.MailDomains) > 0 && target.mail == nil || len(manifest.Containers) > 1 || len(manifest.Containers) > 0 && target.container == nil {
		return manifest, fmt.Errorf("%w: credential principal authority, mail handler, or protected container ingress unavailable", migration.ErrBlocked)
	}
	linked := manifest.Sites[0].ContainerApplicationIDs
	if len(manifest.Containers) == 0 {
		if len(linked) != 0 {
			return manifest, migration.ErrConflict
		}
		return manifest, nil
	}
	container := manifest.Containers[0]
	if container.SiteID != manifest.Sites[0].SourceID || len(linked) != 1 || linked[0] != container.SourceID {
		return manifest, fmt.Errorf("%w: container workload is not exactly linked to its tenant-owned site", migration.ErrBlocked)
	}
	return manifest, nil
}

func (target *migrationHostTarget) sourceFence(ctx context.Context, value migration.Migration) error {
	current, err := target.repository.Migration(ctx, value.ID)
	if err != nil {
		return err
	}
	if current.Phase != value.Phase || current.Fence != value.Fence || current.SourceGeneration != value.SourceGeneration || current.PlanDigest != value.PlanDigest {
		return migration.ErrConflict
	}
	if current.Phase != migration.PhaseFinalSync && current.Phase != migration.PhaseCutoverCommitting {
		return migration.ErrBlocked
	}
	var fence migration.SourceFence
	if err = target.repository.Receipt(ctx, value.ID, "source_fence", &fence); err != nil {
		return err
	}
	digest, parseErr := hex.DecodeString(fence.Digest)
	if parseErr != nil || len(digest) != sha256.Size || fence.MigrationID != value.ID || fence.Generation != value.SourceGeneration || fence.Fence != value.Fence || fence.Fence == 0 || !fence.ExpiresAt.After(time.Now().UTC()) {
		return migration.ErrBlocked
	}
	return nil
}

// An immutable backup still passes through final sync. Rebind an identical
// resource to the new source fence only after live readback; changed contents
// require a future guarded replacement protocol and are explicitly blocked.
func (target *migrationHostTarget) unchangedDelta(ctx context.Context, scope migration.RuntimeScope, intent migration.ImportIntent) (migration.ImportEffect, error) {
	value, err := target.repository.Migration(ctx, intent.MigrationID)
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	if err = target.sourceFence(ctx, value); err != nil {
		return migrationHostFailure(intent, err)
	}
	var raw []byte
	var state string
	if err = target.db.QueryRowContext(ctx, `SELECT intent_json,state FROM panel_migration_host_effects WHERE migration_id=? AND kind=? AND source_id=?`, intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String()).Scan(&raw, &state); err != nil {
		return migrationHostFailure(intent, err)
	}
	var prior migration.ImportIntent
	if json.Unmarshal(raw, &prior) != nil || state != "dark" || prior.TargetID != intent.TargetID || intent.Kind == migration.ImportContainer && prior.SourceGeneration != intent.SourceGeneration || migrationHostDigest(prior.Payload) != migrationHostDigest(intent.Payload) || migrationHostDigest(prior.Chunks) != migrationHostDigest(intent.Chunks) || migrationHostDigest(prior.SecretIDs) != migrationHostDigest(intent.SecretIDs) {
		return migrationHostFailure(intent, fmt.Errorf("%w: changed final delta requires guarded resource replacement", migration.ErrBlocked))
	}
	var proof string
	var generation, bytes, objects uint64
	switch intent.Kind {
	case migration.ImportSite:
		proof, err = target.probeSite(ctx, scope, prior, false)
	case migration.ImportDNSZone:
		proof, err = target.observeDNS(ctx, scope, prior, false)
	case migration.ImportDatabase:
		if target.database == nil {
			return migrationHostFailure(intent, migration.ErrBlocked)
		}
		var observed migration.ImportEffect
		observed, err = target.observeDatabase(ctx, prior)
		if observed.Status != migration.ImportEffectApplied {
			err = errors.Join(migration.ErrBlocked, err)
		}
		proof = observed.EvidenceDigest
		generation = observed.TargetGeneration
		bytes = observed.BytesWritten
		objects = observed.ObjectsWritten
	case migration.ImportCertificate:
		var observed migration.ImportEffect
		observed, err = target.observeCertificate(ctx, prior)
		proof = observed.EvidenceDigest
		generation = observed.TargetGeneration
		objects = observed.ObjectsWritten
	case migration.ImportMailDomain:
		var observed migration.ImportEffect
		observed, err = target.observeMail(ctx, prior)
		if observed.Status != migration.ImportEffectApplied {
			err = errors.Join(migration.ErrBlocked, err)
		}
		proof = observed.EvidenceDigest
		generation = observed.TargetGeneration
		bytes = observed.BytesWritten
		objects = observed.ObjectsWritten
	case migration.ImportContainer:
		if target.container == nil {
			return migrationHostFailure(intent, migration.ErrBlocked)
		}
		var observed migration.ImportEffect
		observed, err = target.container.Observe(ctx, prior)
		if observed.Status != migration.ImportEffectApplied {
			err = errors.Join(migration.ErrBlocked, err)
		}
		proof = observed.EvidenceDigest
		generation = observed.TargetGeneration
		bytes = observed.BytesWritten
		objects = observed.ObjectsWritten
	default:
		if !migrationAuxiliaryKind(intent.Kind) {
			return migrationHostFailure(intent, migration.ErrBlocked)
		}
		var observed migration.ImportEffect
		observed, err = target.observeAuxiliary(ctx, prior)
		if observed.Status != migration.ImportEffectApplied {
			err = errors.Join(migration.ErrBlocked, err)
		}
		proof = observed.EvidenceDigest
		generation = observed.TargetGeneration
		objects = observed.ObjectsWritten
	}
	if err != nil || proof == "" {
		return migrationHostFailure(intent, errors.Join(migration.ErrBlocked, err))
	}
	if generation == 0 {
		generation = 1
	}
	effect := migrationHostEffect(intent, proof, generation, bytes, objects)
	intentRaw, _ := json.Marshal(intent)
	effectRaw, _ := json.Marshal(effect)
	result, err := target.db.ExecContext(ctx, `UPDATE panel_migration_host_effects SET intent_json=?,evidence_json=? WHERE migration_id=? AND kind=? AND source_id=? AND state='dark' AND intent_json=?`, intentRaw, effectRaw, intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String(), raw)
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return migrationHostFailure(intent, errors.Join(migration.ErrConflict, err))
	}
	return effect, nil
}

func (target *migrationHostTarget) VerifyDark(ctx context.Context, value migration.Migration, plan migration.Plan) (migration.Verification, error) {
	target.mu.Lock()
	defer target.mu.Unlock()
	if value.Phase != migration.PhaseBaseSync {
		return migration.Verification{}, migration.ErrInvalid
	}
	entries, err := target.entries(ctx, value, plan)
	if err != nil {
		return migration.Verification{}, err
	}
	scope, err := target.scopes.LoadByMigration(ctx, value.ID)
	if err != nil {
		return migration.Verification{}, err
	}
	evidence := []string{migrationHostDigest(struct{ Root, AbsentDomains string }{value.ManifestRoot, "access_credentials"})}
	auxiliary, err := target.auxiliaryProofs(ctx, entries, false)
	if err != nil {
		return migration.Verification{}, err
	}
	evidence = append(evidence, auxiliary...)
	certificates, err := target.certificateProofs(ctx, entries)
	if err != nil {
		return migration.Verification{}, err
	}
	evidence = append(evidence, certificates...)
	mailProofs, err := target.mailProofs(ctx, entries, false)
	if err != nil {
		return migration.Verification{}, err
	}
	evidence = append(evidence, mailProofs...)
	containerState := "validated-absent"
	for _, intent := range entries {
		switch intent.Kind {
		case migration.ImportSite:
			proof, probeErr := target.probeSite(ctx, scope, intent, false)
			if probeErr != nil {
				return migration.Verification{}, probeErr
			}
			evidence = append(evidence, proof)
		case migration.ImportDNSZone:
			proof, probeErr := target.observeDNS(ctx, scope, intent, false)
			if probeErr != nil {
				return migration.Verification{}, probeErr
			}
			evidence = append(evidence, proof)
		case migration.ImportDatabase:
			effect, probeErr := target.observeDatabase(ctx, intent)
			if probeErr != nil || effect.Status != migration.ImportEffectApplied {
				return migration.Verification{}, errors.Join(migration.ErrBlocked, probeErr)
			}
			evidence = append(evidence, effect.EvidenceDigest)
		case migration.ImportContainer:
			if target.container == nil {
				return migration.Verification{}, migration.ErrBlocked
			}
			effect, probeErr := target.container.Observe(ctx, intent)
			if probeErr != nil || effect.Status != migration.ImportEffectApplied {
				return migration.Verification{}, errors.Join(migration.ErrBlocked, probeErr)
			}
			evidence = append(evidence, effect.EvidenceDigest)
			containerState = "staged-unstarted-unexposed"
		}
	}
	evidence = append(evidence, migrationHostDigest(struct{ Domain, State string }{"containers", containerState}))
	// Files and maintenance routing were observed. Do not substitute an engine
	// generation hash for execution of the imported PHP application or TLS.
	verification := migration.Verification{HTTP: true, Files: true, Database: true, DNS: true, Mail: true, Cron: true, Containers: true, Backups: true, EvidenceDigest: migrationHostDigest(evidence), ObservedAt: time.Now().UTC()}
	if target.applicationProbe == nil {
		return verification, fmt.Errorf("%w: shadow PHP/TLS rehearsal probes are not bound", migration.ErrBlocked)
	}
	application, err := target.applicationProbe.VerifyDark(ctx, value, plan)
	if err != nil || !application.HTTP || !application.PHP || !application.TLS || application.EvidenceDigest == "" {
		return verification, errors.Join(migration.ErrBlocked, err)
	}
	verification.PHP = true
	verification.TLS = true
	verification.EvidenceDigest = migrationHostDigest([]string{verification.EvidenceDigest, application.EvidenceDigest})
	return verification, nil
}

func (target *migrationHostTarget) ActivateMigration(ctx context.Context, value migration.Migration, plan migration.Plan) (migration.ActivationReceipt, error) {
	target.mu.Lock()
	defer target.mu.Unlock()
	if value.Phase != migration.PhaseCutoverCommitting || value.Fence == 0 {
		return migration.ActivationReceipt{}, migration.ErrBlocked
	}
	if err := target.sourceFence(ctx, value); err != nil {
		return migration.ActivationReceipt{}, err
	}
	entries, err := target.entries(ctx, value, plan)
	if err != nil {
		return migration.ActivationReceipt{}, err
	}
	scope, err := target.scopes.LoadByMigration(ctx, value.ID)
	if err != nil {
		return migration.ActivationReceipt{}, err
	}
	for _, intent := range entries {
		if intent.Kind == migration.ImportContainer {
			return migration.ActivationReceipt{}, fmt.Errorf("%w: exact tenant-owned container route binding and staged workload activation transaction are unbound", migration.ErrBlocked)
		}
	}
	// Re-probe the actual candidate immediately before making it public. An old
	// SQL-only verification record is deliberately not sufficient authority.
	if target.applicationProbe == nil {
		return migration.ActivationReceipt{}, migration.ErrBlocked
	}
	probeValue := value
	probeValue.Phase = migration.PhaseBaseSync
	application, err := target.applicationProbe.VerifyDark(ctx, probeValue, plan)
	if err != nil || !application.HTTP || !application.PHP || !application.TLS || application.EvidenceDigest == "" {
		return migration.ActivationReceipt{}, errors.Join(migration.ErrBlocked, err)
	}
	return target.activateEntries(ctx, value, plan, scope, entries)
}

func (target *migrationHostTarget) CompensateCanonicalImport(ctx context.Context, intent migration.ImportIntent, effect migration.ImportEffect) (migration.ImportEffect, error) {
	target.mu.Lock()
	defer target.mu.Unlock()
	if migration.ValidateCanonicalImportIntent(intent) != nil {
		return migrationHostFailure(intent, migration.ErrInvalid)
	}
	var activationState string
	activationErr := target.db.QueryRowContext(ctx, `SELECT state FROM panel_migration_host_activations WHERE migration_id=?`, intent.MigrationID.String()).Scan(&activationState)
	if activationErr == nil {
		return migrationHostFailure(intent, migration.ErrWriteFrontier)
	}
	if !errors.Is(activationErr, sql.ErrNoRows) {
		return migrationHostFailure(intent, activationErr)
	}
	var state string
	err := target.db.QueryRowContext(ctx, `SELECT state FROM panel_migration_host_effects WHERE migration_id=? AND kind=? AND source_id=?`, intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String()).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		effect = migrationHostEffect(intent, "no-domain-effect-record", 0, 0, 0)
		effect.Status = migration.ImportEffectCompensated
		return effect, nil
	}
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	if state == "active" {
		return migrationHostFailure(intent, migration.ErrWriteFrontier)
	}
	if intent.Kind == migration.ImportCertificate {
		origin, loadErr := target.auxiliaryOrigin(ctx, intent)
		if loadErr != nil {
			return migrationHostFailure(intent, loadErr)
		}
		compensated, cleanupErr := target.certificate.Compensate(ctx, origin, effect)
		if cleanupErr != nil || compensated.Status != migration.ImportEffectCompensated || compensated.EvidenceDigest == "" {
			return migrationHostFailure(intent, errors.Join(migration.ErrAmbiguous, cleanupErr))
		}
		compensated.EffectID = intent.EffectID
		compensated.InputDigest = intent.InputDigest
		return target.saveCompensation(ctx, intent, compensated)
	}
	if intent.Kind == migration.ImportMailDomain {
		origin, loadErr := target.auxiliaryOrigin(ctx, intent)
		if loadErr != nil {
			return migrationHostFailure(intent, loadErr)
		}
		compensated, cleanupErr := target.mail.Compensate(ctx, origin, effect)
		if cleanupErr != nil || compensated.Status != migration.ImportEffectCompensated || compensated.EvidenceDigest == "" {
			return migrationHostFailure(intent, errors.Join(migration.ErrAmbiguous, cleanupErr))
		}
		compensated.EffectID = intent.EffectID
		compensated.InputDigest = intent.InputDigest
		return target.saveCompensation(ctx, intent, compensated)
	}
	if intent.Kind == migration.ImportContainer && target.container != nil {
		if intent.Disposition != migration.DispositionCreate {
			return migrationHostFailure(intent, migration.ErrBlocked)
		}
		compensated, cleanupErr := target.container.Compensate(ctx, intent, effect)
		if cleanupErr != nil || compensated.Status != migration.ImportEffectCompensated || compensated.EvidenceDigest == "" {
			return migrationHostFailure(intent, errors.Join(migration.ErrAmbiguous, cleanupErr))
		}
		compensated.EffectID = intent.EffectID
		compensated.InputDigest = intent.InputDigest
		return target.saveCompensation(ctx, intent, compensated)
	}
	if migrationAuxiliaryKind(intent.Kind) {
		origin, loadErr := target.auxiliaryOrigin(ctx, intent)
		if loadErr != nil {
			return migrationHostFailure(intent, loadErr)
		}
		compensated, cleanupErr := target.auxiliary.Compensate(ctx, origin, effect)
		if cleanupErr != nil || compensated.Status != migration.ImportEffectCompensated || compensated.EvidenceDigest == "" {
			return migrationHostFailure(intent, errors.Join(migration.ErrAmbiguous, cleanupErr))
		}
		compensated.EffectID = intent.EffectID
		compensated.InputDigest = intent.InputDigest
		return target.saveCompensation(ctx, intent, compensated)
	}
	if state == "compensated" {
		var raw []byte
		if err = target.db.QueryRowContext(ctx, `SELECT evidence_json FROM panel_migration_host_effects WHERE migration_id=? AND kind=? AND source_id=?`, intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String()).Scan(&raw); err != nil {
			return migrationHostFailure(intent, err)
		}
		var prior migration.ImportEffect
		if json.Unmarshal(raw, &prior) != nil || prior.Status != migration.ImportEffectCompensated || prior.EvidenceDigest == "" {
			return migrationHostFailure(intent, migration.ErrAmbiguous)
		}
		return prior, nil
	}
	if intent.Kind == migration.ImportDatabase && target.database != nil {
		if intent.Disposition != migration.DispositionCreate {
			return migrationHostFailure(intent, migration.ErrBlocked)
		}
		effect, err = target.database.Compensate(ctx, intent, effect)
		if err != nil || effect.Status != migration.ImportEffectCompensated || effect.EvidenceDigest == "" {
			return migrationHostFailure(intent, errors.Join(migration.ErrAmbiguous, err))
		}
		return target.saveCompensation(ctx, intent, effect)
	}
	if intent.Kind == migration.ImportSite {
		scope, loadErr := target.scopes.LoadByMigration(ctx, intent.MigrationID)
		if loadErr != nil {
			return migrationHostFailure(intent, loadErr)
		}
		tenant, parseErr := site.NewTenantID(scope.TenantID)
		if parseErr != nil {
			return migrationHostFailure(intent, parseErr)
		}
		id, parseErr := site.NewSiteID(intent.TargetID.String())
		if parseErr != nil {
			return migrationHostFailure(intent, parseErr)
		}
		aggregate, loadErr := target.sites.Load(ctx, tenant, id)
		if loadErr != nil {
			return migrationHostFailure(intent, loadErr)
		}
		proofs := []string{}
		if aggregate.Lifecycle() == site.LifecycleProvisioning {
			receipt, applyErr := target.hosting.Handle(ctx, hostingservice.BeginDelete{CommandID: "migration-cancel-delete-" + intent.EffectID, Actor: hostingservice.Actor{TenantID: tenant}, TenantID: tenant, SiteID: id, ExpectedGeneration: aggregate.Generation()})
			if applyErr != nil || receipt.Effect.Outcome != hostingservice.EffectConfirmed {
				return migrationHostFailure(intent, errors.Join(migration.ErrAmbiguous, applyErr))
			}
			proofs = append(proofs, receipt.Effect.ProbeDigest)
			aggregate, loadErr = target.sites.Load(ctx, tenant, id)
			if loadErr != nil {
				return migrationHostFailure(intent, loadErr)
			}
		}
		if aggregate.Lifecycle() == site.LifecycleDeleting {
			receipt, applyErr := target.hosting.Handle(ctx, hostingservice.MarkQuarantined{CommandID: "migration-cancel-quarantine-" + intent.EffectID, Actor: hostingservice.Actor{TenantID: tenant}, TenantID: tenant, SiteID: id, ExpectedGeneration: aggregate.Generation()})
			if applyErr != nil || receipt.Effect.Outcome != hostingservice.EffectConfirmed {
				return migrationHostFailure(intent, errors.Join(migration.ErrAmbiguous, applyErr))
			}
			proofs = append(proofs, receipt.Effect.ProbeDigest)
			aggregate, loadErr = target.sites.Load(ctx, tenant, id)
			if loadErr != nil {
				return migrationHostFailure(intent, loadErr)
			}
		}
		if aggregate.Lifecycle() != site.LifecycleQuarantined {
			return migrationHostFailure(intent, migration.ErrWriteFrontier)
		}
		if len(proofs) == 0 {
			return migrationHostFailure(intent, migration.ErrAmbiguous)
		}
		effect = migrationHostEffect(intent, proofs, aggregate.Generation(), 0, 0)
		effect.Status = migration.ImportEffectCompensated
		return target.saveCompensation(ctx, intent, effect)
	}
	if intent.Kind != migration.ImportDNSZone {
		return migrationHostFailure(intent, migration.ErrBlocked)
	}
	scope, err := target.scopes.LoadByMigration(ctx, intent.MigrationID)
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	proof, err := target.observeDNS(ctx, scope, intent, false)
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	effect = migrationHostEffect(intent, []string{"unpublished-dns-intent-discarded", proof}, 1, 0, 0)
	effect.Status = migration.ImportEffectCompensated
	return target.saveCompensation(ctx, intent, effect)
}

func (target *migrationHostTarget) saveCompensation(ctx context.Context, intent migration.ImportIntent, effect migration.ImportEffect) (migration.ImportEffect, error) {
	raw, err := json.Marshal(effect)
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	result, err := target.db.ExecContext(ctx, `UPDATE panel_migration_host_effects SET state='compensated',evidence_json=? WHERE migration_id=? AND kind=? AND source_id=? AND state<>'active'`, raw, intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String())
	if err != nil {
		return migrationHostFailure(intent, err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return migrationHostFailure(intent, errors.Join(migration.ErrConflict, err))
	}
	return effect, nil
}

func (target *migrationHostTarget) FinalizeMigration(ctx context.Context, value migration.Migration) error {
	if value.Phase != migration.PhaseCommitted && value.Phase != migration.PhaseCleanup {
		return migration.ErrBlocked
	}
	var state string
	if err := target.db.QueryRowContext(ctx, `SELECT state FROM panel_migration_host_activations WHERE migration_id=? AND plan_digest=? AND fence=?`, value.ID.String(), value.PlanDigest, value.Fence).Scan(&state); err != nil {
		return err
	}
	if state != "active" && state != "finalized" {
		return migration.ErrBlocked
	}
	_, err := target.db.ExecContext(ctx, `UPDATE panel_migration_host_activations SET state='finalized' WHERE migration_id=? AND state='active'`, value.ID.String())
	return err
}

func migrationPHPProfile(value string) (site.PHPProfile, error) {
	switch strings.ToLower(strings.ReplaceAll(value, " ", "")) {
	case "php82", "php8.2", "8.2":
		return site.PHPProfile82, nil
	case "php83", "php8.3", "8.3":
		return site.PHPProfile83, nil
	case "php84", "php8.4", "8.4":
		return site.PHPProfile84, nil
	}
	return "", migration.ErrBlocked
}

var _ migration.ImportCommandGateway = (*migrationHostTarget)(nil)
var _ migration.TargetProbe = (*migrationHostTarget)(nil)
var _ migration.TargetActivationController = (*migrationHostTarget)(nil)
