package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

type ImportResourceKind string

const (
	ImportSite             ImportResourceKind = "site"
	ImportDatabase         ImportResourceKind = "database"
	ImportDNSZone          ImportResourceKind = "dns_zone"
	ImportMailDomain       ImportResourceKind = "mail_domain"
	ImportCertificate      ImportResourceKind = "certificate"
	ImportCredential       ImportResourceKind = "credential"
	ImportSchedule         ImportResourceKind = "schedule"
	ImportRepository       ImportResourceKind = "repository"
	ImportContainer        ImportResourceKind = "container_application"
	ImportBackupPolicy     ImportResourceKind = "backup_policy"
)

type ImportIntent struct {
	MigrationID  ID
	EffectID     string
	Kind         ImportResourceKind
	SourceID     ID
	TargetID     ID
	Disposition  ResourceDisposition
	InputDigest  string
	Payload      json.RawMessage
	Chunks       []Chunk
	SecretIDs    []string
	SourceGeneration uint64
	Fence        uint64
	Dark         bool
}

type ImportEffectStatus string

const (
	ImportEffectApplied     ImportEffectStatus = "applied"
	ImportEffectRejected    ImportEffectStatus = "rejected"
	ImportEffectAmbiguous   ImportEffectStatus = "ambiguous"
	ImportEffectCompensated ImportEffectStatus = "compensated"
)

type ImportEffect struct {
	EffectID       string
	InputDigest    string
	OutputDigest   string
	Status         ImportEffectStatus
	TargetGeneration uint64
	BytesWritten   uint64
	ObjectsWritten uint64
	EvidenceDigest string
	AppliedAt      time.Time
	ErrorCode      string
}

type CleanupReceipt struct {
	MigrationID          ID
	PlanDigest           string
	ResourcesChecked     uint64
	ResourcesCompensated uint64
	ResourcesAbsent      uint64
	SecretsRevoked       bool
	EvidenceDigest       string
	CleanedAt            time.Time
}

type ImportCommandGateway interface {
	ApplyCanonicalImport(context.Context, ImportIntent) (ImportEffect, error)
	ObserveCanonicalImport(context.Context, ImportIntent) (ImportEffect, error)
	CompensateCanonicalImport(context.Context, ImportIntent, ImportEffect) (ImportEffect, error)
}

// ValidateCanonicalImportIntent exposes the canonical payload/digest boundary
// to ordinary domain adapters without invoking the SQL projection authority.
func ValidateCanonicalImportIntent(intent ImportIntent) error { _,err:=validateCanonicalIntent(intent);return err }

type TargetCapacityProvider interface{ Capacity(context.Context) (map[string]uint64, error) }

type MigrationSecretGateway interface {
	ImportMigrationSecret(context.Context, ID, SecretEnvelope) error
	RevokeMigrationSecrets(context.Context, ID) error
}

type TargetProbe interface {
	VerifyDark(context.Context, Migration, Plan) (Verification, error)
	VerifyActive(context.Context, Migration, Plan, ActivationReceipt) (Verification, error)
}

type TargetActivationController interface {
	ActivateMigration(context.Context, Migration, Plan) (ActivationReceipt, error)
	DeactivateMigration(context.Context, ActivationReceipt) error
	FinalizeMigration(context.Context, Migration) error
}

type ImportLedger interface {
	Prepare(context.Context, Migration, Plan) error
	BeginCancellation(context.Context, ID) error
	LoadEffect(context.Context, ID, string) (ImportEffect, bool, error)
	PutEffect(context.Context, ID, ImportIntent, ImportEffect) error
	MarkCanceled(context.Context, ID) error
	MarkFinalized(context.Context, ID, string) error
}

// CanonicalTargetImporter translates a signed source-neutral manifest into the
// target's ordinary typed command gateway. It never invokes a CyberPanel or
// cPanel parser inside the destination runtime.
type CanonicalTargetImporter struct {
	capacity   TargetCapacityProvider
	gateway    ImportCommandGateway
	probe      TargetProbe
	activation TargetActivationController
	ledger     ImportLedger
	secrets    MigrationSecretGateway
	clock      func() time.Time
}

func NewCanonicalTargetImporter(capacity TargetCapacityProvider, gateway ImportCommandGateway, probe TargetProbe, activation TargetActivationController, ledger ImportLedger, secrets MigrationSecretGateway) (*CanonicalTargetImporter, error) {
	if capacity == nil || gateway == nil || probe == nil || activation == nil || ledger == nil || secrets == nil {
		return nil, ErrInvalid
	}
	return &CanonicalTargetImporter{capacity: capacity, gateway: gateway, probe: probe, activation: activation, ledger: ledger, secrets: secrets, clock: time.Now}, nil
}

func (target *CanonicalTargetImporter) Capacity(ctx context.Context) (map[string]uint64, error) {
	values, err := target.capacity.Capacity(ctx)
	if err != nil {
		return nil, err
	}
	return cloneCapacity(values), nil
}

func (target *CanonicalTargetImporter) Plan(ctx context.Context, manifest Manifest) ([]Mapping, error) {
	if target == nil || ctx == nil || manifest.Validate() != nil {
		return nil, ErrInvalid
	}
	resources, err := manifestResources(manifest)
	if err != nil {
		return nil, err
	}
	mappings := make([]Mapping, 0, len(resources))
	for _, resource := range resources {
		targetID, err := deterministicTargetID(resource.kind, manifest.TargetInstallationID, resource.sourceID)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, Mapping{SourceKind: string(resource.kind), SourceID: resource.sourceID, TargetID: targetID, Disposition: DispositionCreate, Reason: "canonical greenfield import", Capacity: resource.capacity})
	}
	return mappings, nil
}

func (target *CanonicalTargetImporter) Prepare(ctx context.Context, migration Migration, plan Plan) error {
	if target == nil || ctx == nil || validateMigration(migration) != nil || validatePlan(plan) != nil || plan.MigrationID != migration.ID || plan.ManifestRoot != migration.ManifestRoot || plan.DryRunDigest != migration.PlanDigest || plan.ApprovedAt == nil || plan.ApprovedAt.IsZero() || !isDigest(plan.ApprovalDigest) || len(plan.Unsupported) != 0 {
		return ErrInvalid
	}
	available, err := target.Capacity(ctx)
	if err != nil {
		return err
	}
	for key, required := range plan.RequiredCapacity {
		if available[key] < required {
			return errors.Join(ErrCapacity, fmt.Errorf("%s requires %d, available %d", key, required, available[key]))
		}
	}
	return target.ledger.Prepare(ctx, migration, plan)
}

func (target *CanonicalTargetImporter) ImportResource(ctx context.Context, migration Migration, mapping Mapping, manifest Manifest) (ResourceProgress, error) {
	if target == nil || validateMigration(migration) != nil || manifest.Validate() != nil || manifest.MigrationID != migration.ID || !validDisposition(mapping.Disposition) {
		return ResourceProgress{}, ErrInvalid
	}
	resource, err := locateManifestResource(manifest, ImportResourceKind(mapping.SourceKind), mapping.SourceID)
	if err != nil {
		return ResourceProgress{}, err
	}
	intent, err := buildImportIntent(migration, mapping, resource, true)
	if err != nil {
		return ResourceProgress{}, err
	}
	if err := target.importSecrets(ctx, migration.ID, intent.SecretIDs, manifest.Secrets); err != nil {
		return ResourceProgress{}, err
	}
	effect, err := target.apply(ctx, intent)
	if err != nil {
		return progressFromEffect(migration, intent, effect, PhasePausedRetryable, target.clock().UTC()), err
	}
	return progressFromEffect(migration, intent, effect, PhaseBaseSync, target.clock().UTC()), nil
}

func (target *CanonicalTargetImporter) ApplyDelta(ctx context.Context, migration Migration, manifest Manifest) ([]ResourceProgress, error) {
	if target == nil || validateMigration(migration) != nil || manifest.Validate() != nil || manifest.MigrationID != migration.ID {
		return nil, ErrInvalid
	}
	resources, err := manifestResources(manifest)
	if err != nil {
		return nil, err
	}
	progress := make([]ResourceProgress, 0, len(resources))
	for _, resource := range resources {
		targetID, targetErr := deterministicTargetID(resource.kind, manifest.TargetInstallationID, resource.sourceID)
		if targetErr != nil {
			return progress, targetErr
		}
		mapping := Mapping{SourceKind: string(resource.kind), SourceID: resource.sourceID, TargetID: targetID, Disposition: DispositionMerge, Reason: "fenced final delta", Capacity: resource.capacity}
		intent, buildErr := buildImportIntent(migration, mapping, resource, true)
		if buildErr != nil {
			return progress, buildErr
		}
		if secretErr := target.importSecrets(ctx, migration.ID, intent.SecretIDs, manifest.Secrets); secretErr != nil {
			return progress, secretErr
		}
		effect, applyErr := target.apply(ctx, intent)
		progress = append(progress, progressFromEffect(migration, intent, effect, PhaseFinalSync, target.clock().UTC()))
		if applyErr != nil {
			return progress, applyErr
		}
	}
	return progress, nil
}

func (target *CanonicalTargetImporter) VerifyDark(ctx context.Context, migration Migration, plan Plan) (Verification, error) {
	return target.probe.VerifyDark(ctx, migration, plan)
}

func (target *CanonicalTargetImporter) Activate(ctx context.Context, migration Migration, plan Plan) (ActivationReceipt, error) {
	if target == nil || ctx == nil {
		return ActivationReceipt{}, ErrInvalid
	}
	available, err := target.Capacity(ctx)
	if err != nil {
		return ActivationReceipt{}, err
	}
	for key, required := range plan.RequiredCapacity {
		if available[key] < required {
			return ActivationReceipt{}, errors.Join(ErrCapacity, fmt.Errorf("%s requires %d, available %d", key, required, available[key]))
		}
	}
	receipt, err := target.activation.ActivateMigration(ctx, migration, plan)
	if err != nil {
		return receipt, err
	}
	if receipt.MigrationID != migration.ID || receipt.TargetGeneration == 0 || !isDigest(receipt.EvidenceDigest) || receipt.ActivatedAt.IsZero() {
		return receipt, ErrAmbiguous
	}
	return receipt, nil
}

func (target *CanonicalTargetImporter) VerifyActive(ctx context.Context, migration Migration, plan Plan, receipt ActivationReceipt) (Verification, error) {
	return target.probe.VerifyActive(ctx, migration, plan, receipt)
}

func (target *CanonicalTargetImporter) Deactivate(ctx context.Context, receipt ActivationReceipt) error {
	if err := target.activation.DeactivateMigration(ctx, receipt); err != nil {
		return err
	}
	return target.secrets.RevokeMigrationSecrets(ctx, receipt.MigrationID)
}

func (target *CanonicalTargetImporter) Finalize(ctx context.Context, migration Migration) error {
	if err := target.activation.FinalizeMigration(ctx, migration); err != nil {
		return err
	}
	return target.ledger.MarkFinalized(ctx, migration.ID, migration.LastCheckpoint)
}

func (target *CanonicalTargetImporter) Cleanup(ctx context.Context, migration Migration, plan Plan, manifest Manifest) (CleanupReceipt, error) {
	if target == nil || ctx == nil || migration.Phase != PhaseRollingBack || validateMigration(migration) != nil || validatePlan(plan) != nil || manifest.Validate() != nil || plan.MigrationID != migration.ID || manifest.MigrationID != migration.ID || plan.ManifestRoot != manifest.MerkleRoot || plan.DryRunDigest != migration.PlanDigest {
		return CleanupReceipt{}, ErrInvalid
	}
	if err := target.ledger.BeginCancellation(ctx, migration.ID); err != nil {
		return CleanupReceipt{}, err
	}
	mappings := append([]Mapping(nil), plan.Mappings...)
	sort.Slice(mappings, func(i, j int) bool {
		if mappings[i].SourceKind == mappings[j].SourceKind {
			return mappings[i].SourceID < mappings[j].SourceID
		}
		return mappings[i].SourceKind < mappings[j].SourceKind
	})
	entries := make([]cleanupEvidenceEntry, 0, len(mappings))
	for _, mapping := range mappings {
		if mapping.Disposition == DispositionSkip || mapping.Disposition == DispositionBlock {
			continue
		}
		resource, err := locateManifestResource(manifest, ImportResourceKind(mapping.SourceKind), mapping.SourceID)
		if err != nil {
			return CleanupReceipt{}, err
		}
		intent, err := buildImportIntent(migration, mapping, resource, true)
		if err != nil {
			return CleanupReceipt{}, err
		}
		effect, err := target.cleanupEffect(ctx, intent)
		if err != nil {
			return CleanupReceipt{}, err
		}
		entries = append(entries, cleanupEvidenceEntry{Kind: intent.Kind, SourceID: intent.SourceID, TargetID: intent.TargetID, EffectID: intent.EffectID, InputDigest: intent.InputDigest, OutputDigest: effect.OutputDigest, TargetGeneration: effect.TargetGeneration, EvidenceDigest: effect.EvidenceDigest})
	}
	if err := target.secrets.RevokeMigrationSecrets(ctx, migration.ID); err != nil {
		return CleanupReceipt{}, errors.Join(ErrAmbiguous, err)
	}
	if err := target.ledger.MarkCanceled(ctx, migration.ID); err != nil {
		return CleanupReceipt{}, err
	}
	now := target.clock().UTC()
	receipt := CleanupReceipt{MigrationID: migration.ID, PlanDigest: plan.DryRunDigest, ResourcesChecked: uint64(len(entries)), SecretsRevoked: true, CleanedAt: now}
	for _, entry := range entries {
		if entry.TargetGeneration == 0 {
			receipt.ResourcesAbsent++
		} else {
			receipt.ResourcesCompensated++
		}
	}
	receipt.EvidenceDigest = digestJSON(struct {
		Domain         string
		Migration      ID
		Plan           string
		Entries        []cleanupEvidenceEntry
		SecretsRevoked bool
		CleanedAt      time.Time
	}{"migration-cancel-cleanup-v1", migration.ID, plan.DryRunDigest, entries, true, now})
	return receipt, nil
}

type cleanupEvidenceEntry struct {
	Kind             ImportResourceKind
	SourceID         ID
	TargetID         ID
	EffectID         string
	InputDigest      string
	OutputDigest     string
	TargetGeneration uint64
	EvidenceDigest   string
}

func (target *CanonicalTargetImporter) cleanupEffect(ctx context.Context, intent ImportIntent) (ImportEffect, error) {
	effect, found, err := target.ledger.LoadEffect(ctx, intent.MigrationID, intent.EffectID)
	if err != nil {
		return ImportEffect{}, err
	}
	if found {
		if !effectMatches(effect, intent) {
			return effect, ErrConflict
		}
		if effect.Status == ImportEffectCompensated {
			return effect, nil
		}
	} else {
		effect = ambiguousImportEffect(intent, "CLEANUP_OBSERVATION_REQUIRED", target.clock().UTC())
	}
	compensated, compensateErr := target.gateway.CompensateCanonicalImport(ctx, intent, effect)
	if compensateErr != nil || compensated.Status == ImportEffectAmbiguous {
		return compensated, errors.Join(ErrAmbiguous, compensateErr)
	}
	if !effectMatches(compensated, intent) || compensated.Status != ImportEffectCompensated || !isDigest(compensated.EvidenceDigest) {
		return compensated, errors.Join(ErrAmbiguous, ErrInvalid)
	}
	if err := target.ledger.PutEffect(ctx, intent.MigrationID, intent, compensated); err != nil {
		return compensated, errors.Join(ErrAmbiguous, err)
	}
	return compensated, nil
}

func (target *CanonicalTargetImporter) importSecrets(ctx context.Context, migrationID ID, identifiers []string, catalog []SecretEnvelope) error {
	if len(identifiers) == 0 {
		return nil
	}
	byID := make(map[string]SecretEnvelope, len(catalog))
	for _, envelope := range catalog {
		current, present := byID[envelope.SecretID]
		if !present || current.Version < envelope.Version {
			byID[envelope.SecretID] = envelope
		}
	}
	for _, identifier := range compactStrings(identifiers) {
		envelope, present := byID[identifier]
		if !present {
			return errors.Join(ErrInvalid, fmt.Errorf("secret %s is absent from manifest", identifier))
		}
		if err := target.secrets.ImportMigrationSecret(ctx, migrationID, envelope); err != nil {
			return err
		}
	}
	return nil
}

func (target *CanonicalTargetImporter) apply(ctx context.Context, intent ImportIntent) (ImportEffect, error) {
	if existing, found, err := target.ledger.LoadEffect(ctx, intent.MigrationID, intent.EffectID); err != nil {
		return ImportEffect{}, err
	} else if found {
		if !effectMatches(existing, intent) {
			return existing, ErrConflict
		}
		if existing.Status == ImportEffectApplied {
			return existing, nil
		}
		if existing.Status == ImportEffectRejected || existing.Status == ImportEffectCompensated {
			return existing, ErrBlocked
		}
		observed, observeErr := target.gateway.ObserveCanonicalImport(ctx, intent)
		if observeErr != nil || observed.Status == ImportEffectAmbiguous {
			return observed, errors.Join(ErrAmbiguous, observeErr)
		}
		if err := target.ledger.PutEffect(ctx, intent.MigrationID, intent, observed); err != nil {
			return observed, err
		}
		if observed.Status != ImportEffectApplied {
			return observed, ErrBlocked
		}
		return observed, nil
	}
	effect, err := target.gateway.ApplyCanonicalImport(ctx, intent)
	if err != nil && effect.Status == "" {
		effect = ImportEffect{EffectID: intent.EffectID, InputDigest: intent.InputDigest, Status: ImportEffectAmbiguous, AppliedAt: target.clock().UTC(), ErrorCode: "TRANSPORT_AMBIGUOUS"}
	}
	if !effectMatches(effect, intent) {
		return effect, errors.Join(ErrAmbiguous, ErrInvalid)
	}
	if storeErr := target.ledger.PutEffect(ctx, intent.MigrationID, intent, effect); storeErr != nil {
		return effect, errors.Join(ErrAmbiguous, err, storeErr)
	}
	if effect.Status == ImportEffectAmbiguous {
		return effect, errors.Join(ErrAmbiguous, err)
	}
	if effect.Status != ImportEffectApplied {
		return effect, errors.Join(ErrBlocked, err)
	}
	return effect, err
}

type manifestResource struct {
	kind      ImportResourceKind
	sourceID  ID
	payload   json.RawMessage
	chunks    []Chunk
	secretIDs []string
	capacity  map[string]uint64
}

func manifestResources(manifest Manifest) ([]manifestResource, error) {
	var resources []manifestResource
	appendResource := func(kind ImportResourceKind, id ID, value any, chunks []Chunk, secrets []string, capacity map[string]uint64) error {
		payload, err := json.Marshal(value)
		if err != nil {
			return err
		}
		resources = append(resources, manifestResource{kind: kind, sourceID: id, payload: payload, chunks: append([]Chunk(nil), chunks...), secretIDs: append([]string(nil), secrets...), capacity: cloneCapacity(capacity)})
		return nil
	}
	for _, value := range manifest.Sites {
		capacity := cloneCapacity(value.ResourceProfile)
		capacity["disk_bytes"] += chunkBytes(value.Content)
		if err := appendResource(ImportSite, value.SourceID, value, value.Content, nil, capacity); err != nil { return nil, err }
	}
	for _, value := range manifest.Databases {
		if err := appendResource(ImportDatabase, value.SourceID, value, value.Dump, principalSecrets(value.Principals), map[string]uint64{"database_bytes": chunkBytes(value.Dump)}); err != nil { return nil, err }
	}
	for _, value := range manifest.DNSZones {
		if err := appendResource(ImportDNSZone, value.SourceID, value, nil, nil, map[string]uint64{"dns_recordsets": uint64(len(value.RecordSets))}); err != nil { return nil, err }
	}
	for _, value := range manifest.MailDomains {
		chunks := append([]Chunk(nil), value.MailData...)
		secrets := []string{value.DKIMSecretID}
		for _, mailbox := range value.Mailboxes { chunks = append(chunks, mailbox.Data...); secrets = append(secrets, mailbox.CredentialSecretID) }
		if err := appendResource(ImportMailDomain, value.SourceID, value, chunks, compactStrings(secrets), map[string]uint64{"mail_bytes": chunkBytes(chunks), "mailboxes": uint64(len(value.Mailboxes))}); err != nil { return nil, err }
	}
	for _, value := range manifest.Certificates {
		chunks := append(append([]Chunk(nil), value.Certificate...), value.Chain...)
		if err := appendResource(ImportCertificate, value.SourceID, value, chunks, []string{value.PrivateKeySecretID}, map[string]uint64{"certificate_bytes": chunkBytes(chunks)}); err != nil { return nil, err }
	}
	for _, value := range manifest.Credentials {
		if err := appendResource(ImportCredential, value.SourceID, value, nil, compactStrings([]string{value.SecretID}), nil); err != nil { return nil, err }
	}
	for _, value := range manifest.Schedules {
		if err := appendResource(ImportSchedule, value.SourceID, value, nil, nil, nil); err != nil { return nil, err }
	}
	for _, value := range manifest.Repositories {
		if err := appendResource(ImportRepository, value.SourceID, value, nil, compactStrings([]string{value.CredentialSecretID}), nil); err != nil { return nil, err }
	}
	for _, value := range manifest.Containers {
		chunks := append(append([]Chunk(nil), value.Descriptor...), value.VolumeData...)
		if err := appendResource(ImportContainer, value.SourceID, value, chunks, compactStrings(value.SecretIDs), map[string]uint64{"container_bytes": chunkBytes(chunks)}); err != nil { return nil, err }
	}
	for _, value := range manifest.BackupPolicies {
		if err := appendResource(ImportBackupPolicy, value.SourceID, value, nil, compactStrings([]string{value.CredentialSecretID}), nil); err != nil { return nil, err }
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].kind == resources[j].kind { return resources[i].sourceID < resources[j].sourceID }
		return resources[i].kind < resources[j].kind
	})
	return resources, nil
}

func locateManifestResource(manifest Manifest, kind ImportResourceKind, sourceID ID) (manifestResource, error) {
	resources, err := manifestResources(manifest)
	if err != nil { return manifestResource{}, err }
	for _, resource := range resources {
		if resource.kind == kind && resource.sourceID == sourceID { return resource, nil }
	}
	return manifestResource{}, ErrNotFound
}

func buildImportIntent(migration Migration, mapping Mapping, resource manifestResource, dark bool) (ImportIntent, error) {
	if mapping.SourceID != resource.sourceID || ImportResourceKind(mapping.SourceKind) != resource.kind || !mapping.TargetID.Valid() {
		return ImportIntent{}, ErrInvalid
	}
	input := struct {
		MigrationID ID
		Kind ImportResourceKind
		SourceID, TargetID ID
		Disposition ResourceDisposition
		Payload json.RawMessage
		Chunks []Chunk
		Secrets []string
		Generation, Fence uint64
	}{migration.ID, resource.kind, resource.sourceID, mapping.TargetID, mapping.Disposition, resource.payload, canonicalChunks(resource.chunks), compactStrings(resource.secretIDs), migration.SourceGeneration, migration.Fence}
	raw, err := json.Marshal(input)
	if err != nil { return ImportIntent{}, err }
	sum := sha256.Sum256(raw)
	inputDigest := hex.EncodeToString(sum[:])
	effectSum := sha256.Sum256([]byte("migration-import-v1\x00" + migration.ID.String() + "\x00" + string(resource.kind) + "\x00" + resource.sourceID.String() + "\x00" + mapping.TargetID.String() + "\x00" + inputDigest))
	return ImportIntent{MigrationID: migration.ID, EffectID: hex.EncodeToString(effectSum[:]), Kind: resource.kind, SourceID: resource.sourceID, TargetID: mapping.TargetID, Disposition: mapping.Disposition, InputDigest: inputDigest, Payload: append(json.RawMessage(nil), resource.payload...), Chunks: canonicalChunks(resource.chunks), SecretIDs: compactStrings(resource.secretIDs), SourceGeneration: migration.SourceGeneration, Fence: migration.Fence, Dark: dark}, nil
}

func deterministicTargetID(kind ImportResourceKind, installation string, sourceID ID) (ID, error) {
	sum := sha256.Sum256([]byte("migration-target-v1\x00" + installation + "\x00" + string(kind) + "\x00" + sourceID.String()))
	prefix := strings.ReplaceAll(string(kind), "_", "-")
	if len(prefix) > 24 { prefix = prefix[:24] }
	return NewID("m_" + prefix + "_" + hex.EncodeToString(sum[:12]))
}

func progressFromEffect(migration Migration, intent ImportIntent, effect ImportEffect, phase Phase, now time.Time) ResourceProgress {
	return ResourceProgress{MigrationID: migration.ID, Kind: string(intent.Kind), SourceID: intent.SourceID, TargetID: intent.TargetID, Phase: phase, Checkpoint: string(effect.Status), EffectID: intent.EffectID, InputDigest: intent.InputDigest, OutputDigest: effect.OutputDigest, BytesTransferred: effect.BytesWritten, ObjectsTransferred: effect.ObjectsWritten, Attempt: 1, UpdatedAt: now, ErrorCode: effect.ErrorCode}
}

func effectMatches(effect ImportEffect, intent ImportIntent) bool {
	if effect.EffectID != intent.EffectID || effect.InputDigest != intent.InputDigest || effect.AppliedAt.IsZero() {
		return false
	}
	switch effect.Status {
	case ImportEffectApplied:
		return effect.TargetGeneration > 0 && isDigest(effect.OutputDigest) && isDigest(effect.EvidenceDigest)
	case ImportEffectRejected, ImportEffectCompensated, ImportEffectAmbiguous:
		return true
	default:
		return false
	}
}

func chunkBytes(chunks []Chunk) uint64 { var total uint64; for _, chunk := range chunks { if ^uint64(0)-total < chunk.Size { return ^uint64(0) }; total += chunk.Size }; return total }
func cloneCapacity(values map[string]uint64) map[string]uint64 { out := make(map[string]uint64, len(values)); for key, value := range values { out[key] = value }; return out }
func principalSecrets(values []DatabasePrincipal) []string { out := make([]string, 0, len(values)); for _, value := range values { out = append(out, value.SecretID) }; return compactStrings(out) }
func compactStrings(values []string) []string { set := map[string]struct{}{}; for _, value := range values { if value != "" { set[value] = struct{}{} } }; out := make([]string, 0, len(set)); for value := range set { out = append(out, value) }; sort.Strings(out); return out }

const importLedgerSchema = `
CREATE TABLE IF NOT EXISTS panel_migration_import_runs(migration_id TEXT PRIMARY KEY,plan_digest TEXT NOT NULL,state TEXT NOT NULL,prepared_at TEXT NOT NULL,finalized_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS panel_migration_import_effects(migration_id TEXT NOT NULL,effect_id TEXT NOT NULL,input_digest TEXT NOT NULL,intent_json BLOB NOT NULL,effect_json BLOB NOT NULL,status TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(migration_id,effect_id));`

type SQLImportLedger struct { db *sql.DB; mu sync.Mutex; clock func() time.Time }

func NewSQLImportLedger(db *sql.DB) (*SQLImportLedger, error) { if db == nil { return nil, ErrInvalid }; return &SQLImportLedger{db: db, clock: time.Now}, nil }
func (ledger *SQLImportLedger) Bootstrap(ctx context.Context) error {
	if ledger == nil || ledger.db == nil || ctx == nil { return ErrInvalid }
	ledger.mu.Lock(); defer ledger.mu.Unlock()
	_, err := ledger.db.ExecContext(ctx, importLedgerSchema)
	return err
}

func (ledger *SQLImportLedger) Prepare(ctx context.Context, migration Migration, plan Plan) error {
	if ledger == nil || ledger.db == nil || ctx == nil || validateMigration(migration) != nil || validatePlan(plan) != nil || migration.ID != plan.MigrationID { return ErrInvalid }
	ledger.mu.Lock(); defer ledger.mu.Unlock()
	tx, err := ledger.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	var planDigest, state string
	err = tx.QueryRowContext(ctx, `SELECT plan_digest,state FROM panel_migration_import_runs WHERE migration_id=?`, migration.ID.String()).Scan(&planDigest, &state)
	if err == nil {
		if planDigest != plan.DryRunDigest || state != "prepared" { return ErrConflict }
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) { return err }
	_, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_import_runs(migration_id,plan_digest,state,prepared_at,finalized_at) VALUES(?,?,'prepared',?,?)`, migration.ID.String(), plan.DryRunDigest, encodeTime(ledger.clock().UTC()), "")
	if err != nil { return err }
	return tx.Commit()
}

func (ledger *SQLImportLedger) LoadEffect(ctx context.Context, migrationID ID, effectID string) (ImportEffect, bool, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || !migrationID.Valid() || !isDigest(effectID) { return ImportEffect{}, false, ErrInvalid }
	var raw []byte
	err := ledger.db.QueryRowContext(ctx, `SELECT effect_json FROM panel_migration_import_effects WHERE migration_id=? AND effect_id=?`, migrationID.String(), effectID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) { return ImportEffect{}, false, nil }
	if err != nil { return ImportEffect{}, false, err }
	var effect ImportEffect
	if err := strictDecode(raw, &effect, 1<<20); err != nil { return ImportEffect{}, false, err }
	return effect, true, nil
}

func (ledger *SQLImportLedger) BeginCancellation(ctx context.Context, migrationID ID) error {
	if ledger == nil || ledger.db == nil || ctx == nil || !migrationID.Valid() { return ErrInvalid }
	ledger.mu.Lock(); defer ledger.mu.Unlock()
	tx, err := ledger.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	var state string
	err = tx.QueryRowContext(ctx, `SELECT state FROM panel_migration_import_runs WHERE migration_id=?`, migrationID.String()).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) { return nil }
	if err != nil { return err }
	if state == "canceling" || state == "canceled" { return nil }
	if state != "prepared" { return ErrWriteFrontier }
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_import_runs SET state='canceling' WHERE migration_id=? AND state='prepared'`, migrationID.String())
	if err != nil { return err }
	rows, err := result.RowsAffected(); if err != nil { return err }; if rows != 1 { return ErrConflict }
	return tx.Commit()
}

func (ledger *SQLImportLedger) PutEffect(ctx context.Context, migrationID ID, intent ImportIntent, effect ImportEffect) error {
	if ledger == nil || ledger.db == nil || ctx == nil || !migrationID.Valid() || migrationID != intent.MigrationID || !effectMatches(effect, intent) { return ErrInvalid }
	intentRaw, err := canonicalJSON(intent, 8<<20); if err != nil { return err }
	effectRaw, err := canonicalJSON(effect, 1<<20); if err != nil { return err }
	redactedIntent := []byte("{}")
	storedIntentRaw := intentRaw
	if effect.Status == ImportEffectCompensated { storedIntentRaw = redactedIntent }
	ledger.mu.Lock(); defer ledger.mu.Unlock()
	tx, err := ledger.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	var storedInput, storedStatus string
	var storedIntent, storedEffect []byte
	err = tx.QueryRowContext(ctx, `SELECT input_digest,intent_json,effect_json,status FROM panel_migration_import_effects WHERE migration_id=? AND effect_id=?`, migrationID.String(), intent.EffectID).Scan(&storedInput, &storedIntent, &storedEffect, &storedStatus)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_import_effects(migration_id,effect_id,input_digest,intent_json,effect_json,status,updated_at) VALUES(?,?,?,?,?,?,?)`, migrationID.String(), intent.EffectID, intent.InputDigest, storedIntentRaw, effectRaw, string(effect.Status), encodeTime(ledger.clock().UTC()))
		if err != nil { return err }
		return tx.Commit()
	}
	if err != nil { return err }
	if storedInput != intent.InputDigest { return ErrConflict }
	if ImportEffectStatus(storedStatus) == ImportEffectCompensated && effect.Status == ImportEffectCompensated && bytes.Equal(storedEffect, effectRaw) { return nil }
	if !bytes.Equal(storedIntent, intentRaw) { return ErrConflict }
	if bytes.Equal(storedEffect, effectRaw) && storedStatus == string(effect.Status) { return nil }
	if effect.Status != ImportEffectCompensated && ImportEffectStatus(storedStatus) != ImportEffectAmbiguous { return ErrConflict }
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_import_effects SET intent_json=?,effect_json=?,status=?,updated_at=? WHERE migration_id=? AND effect_id=? AND input_digest=? AND status=?`, storedIntentRaw, effectRaw, string(effect.Status), encodeTime(ledger.clock().UTC()), migrationID.String(), intent.EffectID, intent.InputDigest, storedStatus)
	if err != nil { return err }
	rows, err := result.RowsAffected(); if err != nil { return err }; if rows != 1 { return ErrConflict }
	return tx.Commit()
}

func (ledger *SQLImportLedger) MarkCanceled(ctx context.Context, migrationID ID) error {
	if ledger == nil || ledger.db == nil || ctx == nil || !migrationID.Valid() { return ErrInvalid }
	ledger.mu.Lock(); defer ledger.mu.Unlock()
	tx, err := ledger.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	var state string
	err = tx.QueryRowContext(ctx, `SELECT state FROM panel_migration_import_runs WHERE migration_id=?`, migrationID.String()).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) { return nil }
	if err != nil { return err }
	if state == "canceled" { return nil }
	if state != "canceling" { return ErrWriteFrontier }
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_import_runs SET state='canceled',finalized_at=? WHERE migration_id=? AND state='canceling'`, encodeTime(ledger.clock().UTC()), migrationID.String())
	if err != nil { return err }
	rows, err := result.RowsAffected(); if err != nil { return err }; if rows != 1 { return ErrConflict }
	return tx.Commit()
}

func (ledger *SQLImportLedger) MarkFinalized(ctx context.Context, migrationID ID, checkpoint string) error {
	if ledger == nil || ledger.db == nil || ctx == nil || !migrationID.Valid() || checkpoint == "" { return ErrInvalid }
	ledger.mu.Lock(); defer ledger.mu.Unlock()
	tx, err := ledger.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	var state string
	err = tx.QueryRowContext(ctx, `SELECT state FROM panel_migration_import_runs WHERE migration_id=?`, migrationID.String()).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) { return ErrNotFound }
	if err != nil { return err }
	if state == "finalized" { return nil }
	if state != "prepared" && state != "active" { return ErrConflict }
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_import_runs SET state='finalized',finalized_at=? WHERE migration_id=? AND state=?`, encodeTime(ledger.clock().UTC()), migrationID.String(), state)
	if err != nil { return err }
	rows, err := result.RowsAffected(); if err != nil { return err }; if rows != 1 { return ErrConflict }
	return tx.Commit()
}

// LocalImportGateway is a closed in-process command router. Each resource kind
// must have one explicitly registered typed handler; no fallback reflection or
// generic shell/SQL execution exists.
type CanonicalImportHandler interface {
	Apply(context.Context, ImportIntent) (ImportEffect, error)
	Observe(context.Context, ImportIntent) (ImportEffect, error)
	Compensate(context.Context, ImportIntent, ImportEffect) (ImportEffect, error)
}

type LocalImportGateway struct { handlers map[ImportResourceKind]CanonicalImportHandler }

func NewLocalImportGateway(handlers map[ImportResourceKind]CanonicalImportHandler) (*LocalImportGateway, error) {
	required := []ImportResourceKind{ImportSite, ImportDatabase, ImportDNSZone, ImportMailDomain, ImportCertificate, ImportCredential, ImportSchedule, ImportRepository, ImportContainer, ImportBackupPolicy}
	copyHandlers := make(map[ImportResourceKind]CanonicalImportHandler, len(handlers))
	for _, kind := range required { handler := handlers[kind]; if handler == nil { return nil, fmt.Errorf("%w: missing import handler %s", ErrInvalid, kind) }; copyHandlers[kind] = handler }
	if len(copyHandlers) != len(handlers) { return nil, ErrInvalid }
	return &LocalImportGateway{handlers: copyHandlers}, nil
}

func (gateway *LocalImportGateway) ApplyCanonicalImport(ctx context.Context, intent ImportIntent) (ImportEffect, error) { handler, err := gateway.handler(intent); if err != nil { return ImportEffect{}, err }; return handler.Apply(ctx, intent) }
func (gateway *LocalImportGateway) ObserveCanonicalImport(ctx context.Context, intent ImportIntent) (ImportEffect, error) { handler, err := gateway.handler(intent); if err != nil { return ImportEffect{}, err }; return handler.Observe(ctx, intent) }
func (gateway *LocalImportGateway) CompensateCanonicalImport(ctx context.Context, intent ImportIntent, effect ImportEffect) (ImportEffect, error) { handler, err := gateway.handler(intent); if err != nil { return ImportEffect{}, err }; return handler.Compensate(ctx, intent, effect) }
func (gateway *LocalImportGateway) handler(intent ImportIntent) (CanonicalImportHandler, error) { if gateway == nil || !isDigest(intent.EffectID) || !isDigest(intent.InputDigest) || !intent.MigrationID.Valid() || !intent.SourceID.Valid() || !intent.TargetID.Valid() { return nil, ErrInvalid }; handler := gateway.handlers[intent.Kind]; if handler == nil { return nil, ErrBlocked }; return handler, nil }

// StrictCanonicalPayload decodes the source-neutral resource DTO for a typed
// handler and rejects unknown fields, trailing data, and noncanonical bytes.
func StrictCanonicalPayload(payload json.RawMessage, destination any) error {
	if len(payload) == 0 || len(payload) > 8<<20 || destination == nil { return ErrInvalid }
	decoder := json.NewDecoder(bytes.NewReader(payload)); decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil { return err }
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) { return ErrInvalid }
	raw, err := json.Marshal(destination); if err != nil || !bytes.Equal(raw, payload) { return ErrInvalid }
	return nil
}
