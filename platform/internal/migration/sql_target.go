package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const migrationSecretEnvelopeAlgorithm = "X25519-HKDF-SHA256-AES-256-GCM"

const canonicalTargetSchema = `
CREATE TABLE IF NOT EXISTS panel_migration_target_resources (
  migration_id TEXT NOT NULL,
  resource_kind TEXT NOT NULL,
  source_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  disposition TEXT NOT NULL,
  input_digest TEXT NOT NULL,
  output_digest TEXT NOT NULL,
  effect_id TEXT NOT NULL,
  effect_json BLOB NOT NULL,
  payload_json BLOB NOT NULL,
  chunks_json BLOB NOT NULL,
  secret_ids_json BLOB NOT NULL,
  source_generation INTEGER NOT NULL,
  fence INTEGER NOT NULL,
  target_generation INTEGER NOT NULL,
  bytes_written INTEGER NOT NULL,
  objects_written INTEGER NOT NULL,
  evidence_digest TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  activated_at TEXT NOT NULL,
  PRIMARY KEY(migration_id,resource_kind,source_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS panel_migration_target_resource_id
  ON panel_migration_target_resources(target_id)
  WHERE state <> 'compensated';
CREATE UNIQUE INDEX IF NOT EXISTS panel_migration_target_effect
  ON panel_migration_target_resources(migration_id,effect_id);
CREATE TABLE IF NOT EXISTS panel_migration_target_secrets (
  migration_id TEXT NOT NULL,
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  purpose TEXT NOT NULL,
  audience_digest TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  key_id TEXT NOT NULL,
  envelope_digest TEXT NOT NULL,
  envelope_json BLOB NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT NOT NULL,
  PRIMARY KEY(migration_id,secret_id,version,envelope_digest)
);
CREATE INDEX IF NOT EXISTS panel_migration_target_secret_current
  ON panel_migration_target_secrets(migration_id,secret_id,version DESC);
CREATE TABLE IF NOT EXISTS panel_migration_target_verifications (
  migration_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  resource_state TEXT NOT NULL,
  target_generation INTEGER NOT NULL,
  evidence_digest TEXT NOT NULL,
  report_json BLOB NOT NULL,
  observed_at TEXT NOT NULL,
  PRIMARY KEY(migration_id,stage)
);
CREATE TABLE IF NOT EXISTS panel_migration_target_activations (
  migration_id TEXT PRIMARY KEY,
  plan_digest TEXT NOT NULL,
  source_generation INTEGER NOT NULL,
  fence INTEGER NOT NULL,
  target_generation INTEGER NOT NULL,
  state TEXT NOT NULL,
  receipt_json BLOB NOT NULL,
  activated_at TEXT NOT NULL,
  deactivated_at TEXT NOT NULL,
  finalized_at TEXT NOT NULL
);`

// SQLCanonicalTargetAuthority is the source-neutral target-side authority. It
// materializes only canonical resource DTOs, keeps them dark until a guarded
// activation, and has no shell, path, service-name, or caller-supplied SQL
// execution surface.
type SQLCanonicalTargetAuthority struct {
	db     *sql.DB
	chunks *ChunkStore
	clock  func() time.Time
	mu     sync.Mutex
}

func NewSQLCanonicalTargetAuthority(db *sql.DB, chunks *ChunkStore) (*SQLCanonicalTargetAuthority, error) {
	if db == nil || chunks == nil {
		return nil, ErrInvalid
	}
	return &SQLCanonicalTargetAuthority{db: db, chunks: chunks, clock: time.Now}, nil
}

func (authority *SQLCanonicalTargetAuthority) Bootstrap(ctx context.Context) error {
	if authority == nil || authority.db == nil || authority.chunks == nil || ctx == nil {
		return ErrInvalid
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	_, err := authority.db.ExecContext(ctx, canonicalTargetSchema)
	return err
}

// NewSQLCanonicalTargetImporter assembles the complete closed target. The
// LocalImportGateway constructor rejects partial registration, so a returned
// importer always has all ten canonical resource handlers.
func NewSQLCanonicalTargetImporter(ctx context.Context, db *sql.DB, chunks *ChunkStore, capacity TargetCapacityProvider) (*CanonicalTargetImporter, error) {
	if ctx == nil || db == nil || chunks == nil || capacity == nil {
		return nil, ErrInvalid
	}
	ledger, err := NewSQLImportLedger(db)
	if err != nil {
		return nil, err
	}
	authority, err := NewSQLCanonicalTargetAuthority(db, chunks)
	if err != nil {
		return nil, err
	}
	if err = ledger.Bootstrap(ctx); err != nil {
		return nil, err
	}
	if err = authority.Bootstrap(ctx); err != nil {
		return nil, err
	}
	gateway, err := NewLocalImportGateway(authority.Handlers())
	if err != nil {
		return nil, err
	}
	return NewCanonicalTargetImporter(capacity, gateway, authority, authority, ledger, authority)
}

// Handlers returns a fresh, complete registration set. Each handler is bound
// to one kind and independently rejects a mismatched intent.
func (authority *SQLCanonicalTargetAuthority) Handlers() map[ImportResourceKind]CanonicalImportHandler {
	if authority == nil || authority.db == nil || authority.chunks == nil {
		return nil
	}
	return map[ImportResourceKind]CanonicalImportHandler{
		ImportSite:         sqlCanonicalImportHandler{authority: authority, kind: ImportSite},
		ImportDatabase:     sqlCanonicalImportHandler{authority: authority, kind: ImportDatabase},
		ImportDNSZone:      sqlCanonicalImportHandler{authority: authority, kind: ImportDNSZone},
		ImportMailDomain:   sqlCanonicalImportHandler{authority: authority, kind: ImportMailDomain},
		ImportCertificate:  sqlCanonicalImportHandler{authority: authority, kind: ImportCertificate},
		ImportCredential:   sqlCanonicalImportHandler{authority: authority, kind: ImportCredential},
		ImportSchedule:     sqlCanonicalImportHandler{authority: authority, kind: ImportSchedule},
		ImportRepository:   sqlCanonicalImportHandler{authority: authority, kind: ImportRepository},
		ImportContainer:    sqlCanonicalImportHandler{authority: authority, kind: ImportContainer},
		ImportBackupPolicy: sqlCanonicalImportHandler{authority: authority, kind: ImportBackupPolicy},
	}
}

type sqlCanonicalImportHandler struct {
	authority *SQLCanonicalTargetAuthority
	kind      ImportResourceKind
}

func (handler sqlCanonicalImportHandler) Apply(ctx context.Context, intent ImportIntent) (ImportEffect, error) {
	if handler.authority == nil || intent.Kind != handler.kind {
		return ImportEffect{}, ErrInvalid
	}
	return handler.authority.apply(ctx, intent)
}

func (handler sqlCanonicalImportHandler) Observe(ctx context.Context, intent ImportIntent) (ImportEffect, error) {
	if handler.authority == nil || intent.Kind != handler.kind {
		return ImportEffect{}, ErrInvalid
	}
	return handler.authority.observe(ctx, intent)
}

func (handler sqlCanonicalImportHandler) Compensate(ctx context.Context, intent ImportIntent, effect ImportEffect) (ImportEffect, error) {
	if handler.authority == nil || intent.Kind != handler.kind {
		return ImportEffect{}, ErrInvalid
	}
	return handler.authority.compensate(ctx, intent, effect)
}

type canonicalPayloadShape struct {
	sourceID       ID
	targetID       ID
	chunks         []Chunk
	secrets        []string
	secretPurposes map[string]string
}

func validateCanonicalIntent(intent ImportIntent) (canonicalPayloadShape, error) {
	if !intent.MigrationID.Valid() || !intent.SourceID.Valid() || !intent.TargetID.Valid() || !requiredImportKind(intent.Kind) || !isDigest(intent.EffectID) || !isDigest(intent.InputDigest) || intent.SourceGeneration == 0 || intent.Fence == 0 || !intent.Dark {
		return canonicalPayloadShape{}, ErrInvalid
	}
	if intent.SourceGeneration > uint64(1<<63-1) || intent.Fence > uint64(1<<63-1) || (intent.Disposition != DispositionCreate && intent.Disposition != DispositionMerge && intent.Disposition != DispositionReplace) {
		return canonicalPayloadShape{}, ErrInvalid
	}
	catalog := make(map[string]Chunk, len(intent.Chunks))
	for _, descriptor := range intent.Chunks {
		if !validManifestChunk(descriptor) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		if _, duplicate := catalog[descriptor.Digest]; duplicate {
			return canonicalPayloadShape{}, ErrInvalid
		}
		catalog[descriptor.Digest] = descriptor
	}
	if !sameChunks(intent.Chunks, canonicalChunks(intent.Chunks)) || !sameStrings(intent.SecretIDs, compactStrings(intent.SecretIDs)) {
		return canonicalPayloadShape{}, ErrInvalid
	}
	shape, err := decodeCanonicalPayload(intent.Kind, intent.Payload, catalog)
	if err != nil {
		return canonicalPayloadShape{}, err
	}
	if shape.sourceID != intent.SourceID || shape.targetID != "" && shape.targetID != intent.TargetID || !sameChunks(canonicalChunks(shape.chunks), intent.Chunks) || !sameStrings(compactStrings(shape.secrets), intent.SecretIDs) {
		return canonicalPayloadShape{}, ErrConflict
	}
	inputDigest, effectID, err := canonicalIntentDigests(intent)
	if err != nil || inputDigest != intent.InputDigest || effectID != intent.EffectID {
		return canonicalPayloadShape{}, ErrConflict
	}
	return shape, nil
}

func decodeCanonicalPayload(kind ImportResourceKind, payload json.RawMessage, chunks map[string]Chunk) (canonicalPayloadShape, error) {
	switch kind {
	case ImportSite:
		var value Site
		if err := StrictCanonicalPayload(payload, &value); err != nil || !validateSites([]Site{value}, chunks) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		return canonicalPayloadShape{sourceID: value.SourceID, targetID: value.TargetID, chunks: value.Content}, nil
	case ImportDatabase:
		var value Database
		if err := StrictCanonicalPayload(payload, &value); err != nil || !validateDatabases([]Database{value}, chunks) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		purposes := map[string]string{}
		for _, principal := range value.Principals {
			if !bindSecretPurpose(purposes, principal.SecretID, "database-principal") {
				return canonicalPayloadShape{}, ErrConflict
			}
		}
		return canonicalPayloadShape{sourceID: value.SourceID, targetID: value.TargetID, chunks: value.Dump, secrets: principalSecrets(value.Principals), secretPurposes: purposes}, nil
	case ImportDNSZone:
		var value DNSZone
		if err := StrictCanonicalPayload(payload, &value); err != nil || !validateDNSZones([]DNSZone{value}) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		return canonicalPayloadShape{sourceID: value.SourceID, targetID: value.TargetID}, nil
	case ImportMailDomain:
		var value MailDomain
		if err := StrictCanonicalPayload(payload, &value); err != nil || !validateMailDomains([]MailDomain{value}, chunks) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		artifacts := append([]Chunk(nil), value.MailData...)
		secrets := []string{value.DKIMSecretID}
		purposes := map[string]string{}
		if !bindSecretPurpose(purposes, value.DKIMSecretID, "mail-dkim-private-key") {
			return canonicalPayloadShape{}, ErrConflict
		}
		for _, mailbox := range value.Mailboxes {
			artifacts = append(artifacts, mailbox.Data...)
			secrets = append(secrets, mailbox.CredentialSecretID)
			if !bindSecretPurpose(purposes, mailbox.CredentialSecretID, "mailbox-credential") {
				return canonicalPayloadShape{}, ErrConflict
			}
		}
		return canonicalPayloadShape{sourceID: value.SourceID, targetID: value.TargetID, chunks: artifacts, secrets: compactStrings(secrets), secretPurposes: purposes}, nil
	case ImportCertificate:
		var value Certificate
		if err := StrictCanonicalPayload(payload, &value); err != nil || !validateCertificates([]Certificate{value}, chunks) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		artifacts := append(append([]Chunk(nil), value.Certificate...), value.Chain...)
		return canonicalPayloadShape{sourceID: value.SourceID, targetID: value.TargetID, chunks: artifacts, secrets: []string{value.PrivateKeySecretID}, secretPurposes: map[string]string{value.PrivateKeySecretID: "tls-private-key"}}, nil
	case ImportCredential:
		var value AccessCredential
		if err := StrictCanonicalPayload(payload, &value); err != nil || !validateCredentials([]AccessCredential{value}) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		purposes := map[string]string{}
		bindSecretPurpose(purposes, value.SecretID, "access-credential")
		return canonicalPayloadShape{sourceID: value.SourceID, targetID: value.TargetID, secrets: compactStrings([]string{value.SecretID}), secretPurposes: purposes}, nil
	case ImportSchedule:
		var value Schedule
		if err := StrictCanonicalPayload(payload, &value); err != nil || !validateSchedules([]Schedule{value}) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		return canonicalPayloadShape{sourceID: value.SourceID, targetID: value.TargetID}, nil
	case ImportRepository:
		var value RepositoryBinding
		if err := StrictCanonicalPayload(payload, &value); err != nil || !validateRepositories([]RepositoryBinding{value}) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		purposes := map[string]string{}
		bindSecretPurpose(purposes, value.CredentialSecretID, "repository-credential")
		return canonicalPayloadShape{sourceID: value.SourceID, targetID: value.TargetID, secrets: compactStrings([]string{value.CredentialSecretID}), secretPurposes: purposes}, nil
	case ImportContainer:
		var value ContainerApplication
		if err := StrictCanonicalPayload(payload, &value); err != nil || !validateContainers([]ContainerApplication{value}, chunks) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		artifacts := value.Artifacts()
		purposes := map[string]string{}
		for _, identifier := range value.SecretIDs {
			bindSecretPurpose(purposes, identifier, "container-secret")
		}
		return canonicalPayloadShape{sourceID: value.SourceID, targetID: value.TargetID, chunks: artifacts, secrets: compactStrings(value.SecretIDs), secretPurposes: purposes}, nil
	case ImportBackupPolicy:
		var value BackupPolicy
		if err := StrictCanonicalPayload(payload, &value); err != nil || !validateBackupPolicies([]BackupPolicy{value}) {
			return canonicalPayloadShape{}, ErrInvalid
		}
		purposes := map[string]string{}
		bindSecretPurpose(purposes, value.CredentialSecretID, "backup-repository-credential")
		return canonicalPayloadShape{sourceID: value.SourceID, targetID: value.TargetID, secrets: compactStrings([]string{value.CredentialSecretID}), secretPurposes: purposes}, nil
	default:
		return canonicalPayloadShape{}, ErrInvalid
	}
}

func bindSecretPurpose(values map[string]string, identifier, purpose string) bool {
	if identifier == "" {
		return true
	}
	if existing, present := values[identifier]; present {
		return existing == purpose
	}
	values[identifier] = purpose
	return true
}

func canonicalIntentDigests(intent ImportIntent) (string, string, error) {
	input := struct {
		MigrationID       ID
		Kind              ImportResourceKind
		SourceID, TargetID ID
		Disposition       ResourceDisposition
		Payload           json.RawMessage
		Chunks            []Chunk
		Secrets           []string
		Generation, Fence uint64
	}{intent.MigrationID, intent.Kind, intent.SourceID, intent.TargetID, intent.Disposition, intent.Payload, intent.Chunks, intent.SecretIDs, intent.SourceGeneration, intent.Fence}
	raw, err := json.Marshal(input)
	if err != nil {
		return "", "", err
	}
	inputSum := sha256.Sum256(raw)
	inputDigest := hex.EncodeToString(inputSum[:])
	effectSum := sha256.Sum256([]byte("migration-import-v1\x00" + intent.MigrationID.String() + "\x00" + string(intent.Kind) + "\x00" + intent.SourceID.String() + "\x00" + intent.TargetID.String() + "\x00" + inputDigest))
	return inputDigest, hex.EncodeToString(effectSum[:]), nil
}

func requiredImportKind(kind ImportResourceKind) bool {
	switch kind {
	case ImportSite, ImportDatabase, ImportDNSZone, ImportMailDomain, ImportCertificate, ImportCredential, ImportSchedule, ImportRepository, ImportContainer, ImportBackupPolicy:
		return true
	default:
		return false
	}
}

func sameChunks(left, right []Chunk) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type storedTargetResource struct {
	migrationID      ID
	kind             ImportResourceKind
	sourceID         ID
	targetID         ID
	disposition      ResourceDisposition
	inputDigest      string
	outputDigest     string
	effectID         string
	effect           ImportEffect
	payload          json.RawMessage
	chunks           []Chunk
	secretIDs        []string
	sourceGeneration uint64
	fence            uint64
	targetGeneration uint64
	bytesWritten     uint64
	objectsWritten   uint64
	evidenceDigest   string
	state            string
	createdAt        time.Time
	updatedAt        time.Time
	activatedAt      time.Time
}

func (authority *SQLCanonicalTargetAuthority) apply(ctx context.Context, intent ImportIntent) (ImportEffect, error) {
	if authority == nil || authority.db == nil || authority.chunks == nil || ctx == nil {
		return ImportEffect{}, ErrInvalid
	}
	shape, err := validateCanonicalIntent(intent)
	if err != nil {
		return ImportEffect{}, err
	}
	for _, descriptor := range intent.Chunks {
		if err := authority.chunks.Verify(ctx, descriptor); err != nil {
			return rejectedImportEffect(intent, "CHUNK_NOT_VERIFIED", authority.clock().UTC()), errors.Join(ErrBlocked, err)
		}
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ambiguousImportEffect(intent, "TARGET_TRANSACTION_UNAVAILABLE", authority.clock().UTC()), err
	}
	defer tx.Rollback()
	var runState string
	if err = tx.QueryRowContext(ctx, `SELECT state FROM panel_migration_import_runs WHERE migration_id=?`, intent.MigrationID.String()).Scan(&runState); errors.Is(err, sql.ErrNoRows) {
		return rejectedImportEffect(intent, "IMPORT_RUN_NOT_PREPARED", authority.clock().UTC()), ErrBlocked
	} else if err != nil {
		return ambiguousImportEffect(intent, "IMPORT_RUN_OBSERVATION_FAILED", authority.clock().UTC()), err
	} else if runState != "prepared" {
		return rejectedImportEffect(intent, "IMPORT_RUN_NOT_WRITABLE", authority.clock().UTC()), ErrBlocked
	}
	if err = authority.requireSecrets(ctx, tx, intent.MigrationID, intent.SecretIDs, shape.secretPurposes); err != nil {
		return rejectedImportEffect(intent, "SECRET_NOT_READY", authority.clock().UTC()), errors.Join(ErrBlocked, err)
	}
	existing, found, err := loadTargetResource(ctx, tx, intent.MigrationID, intent.Kind, intent.SourceID)
	if err != nil {
		return ambiguousImportEffect(intent, "TARGET_OBSERVATION_FAILED", authority.clock().UTC()), err
	}
	if found && existing.effectID == intent.EffectID {
		if existing.targetID != intent.TargetID || existing.inputDigest != intent.InputDigest || !effectMatches(existing.effect, intent) {
			return rejectedImportEffect(intent, "EFFECT_ID_CONFLICT", authority.clock().UTC()), ErrConflict
		}
		return existing.effect, nil
	}
	if found {
		sameSemanticResource := string(existing.payload) == string(intent.Payload) && sameChunks(existing.chunks, intent.Chunks) && sameStrings(existing.secretIDs, intent.SecretIDs)
		if existing.targetID != intent.TargetID || existing.state != "dark" || existing.sourceGeneration > intent.SourceGeneration || existing.fence > intent.Fence || existing.sourceGeneration == intent.SourceGeneration && !sameSemanticResource || intent.Disposition == DispositionCreate {
			return rejectedImportEffect(intent, "RESOURCE_CONFLICT", authority.clock().UTC()), ErrConflict
		}
	}
	var collisionMigration, collisionKind, collisionSource string
	err = tx.QueryRowContext(ctx, `SELECT migration_id,resource_kind,source_id FROM panel_migration_target_resources WHERE target_id=? AND state<>'compensated' LIMIT 1`, intent.TargetID.String()).Scan(&collisionMigration, &collisionKind, &collisionSource)
	if err == nil && (!found || collisionMigration != intent.MigrationID.String() || collisionKind != string(intent.Kind) || collisionSource != intent.SourceID.String()) {
		return rejectedImportEffect(intent, "TARGET_ID_RESERVED", authority.clock().UTC()), ErrConflict
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ambiguousImportEffect(intent, "TARGET_COLLISION_CHECK_FAILED", authority.clock().UTC()), err
	}
	targetGeneration := uint64(1)
	createdAt := authority.clock().UTC()
	if found {
		if existing.targetGeneration == uint64(1<<63-1) {
			return rejectedImportEffect(intent, "TARGET_GENERATION_EXHAUSTED", authority.clock().UTC()), ErrCapacity
		}
		targetGeneration = existing.targetGeneration + 1
		createdAt = existing.createdAt
	}
	bytesWritten := chunkBytes(intent.Chunks)
	objectsWritten := uint64(1)
	for _, descriptor := range intent.Chunks {
		if objectsWritten > ^uint64(0)-descriptor.ObjectCount {
			objectsWritten = ^uint64(0)
			break
		}
		objectsWritten += descriptor.ObjectCount
	}
	if bytesWritten > uint64(1<<63-1) || objectsWritten > uint64(1<<63-1) {
		return rejectedImportEffect(intent, "TARGET_COUNTER_CAPACITY", authority.clock().UTC()), ErrCapacity
	}
	resourceMaterial := struct {
		MigrationID       ID
		Kind              ImportResourceKind
		SourceID, TargetID ID
		Payload           json.RawMessage
		Chunks            []Chunk
		SecretIDs         []string
		SourceGeneration  uint64
		Fence             uint64
		TargetGeneration  uint64
	}{intent.MigrationID, intent.Kind, intent.SourceID, intent.TargetID, intent.Payload, intent.Chunks, intent.SecretIDs, intent.SourceGeneration, intent.Fence, targetGeneration}
	outputDigest, err := canonicalTargetDigest("canonical-resource-v1", resourceMaterial)
	if err != nil {
		return ImportEffect{}, err
	}
	now := authority.clock().UTC()
	evidenceDigest, err := canonicalTargetDigest("canonical-resource-evidence-v1", struct {
		EffectID, InputDigest, OutputDigest string
		TargetGeneration                    uint64
	}{intent.EffectID, intent.InputDigest, outputDigest, targetGeneration})
	if err != nil {
		return ImportEffect{}, err
	}
	effect := ImportEffect{EffectID: intent.EffectID, InputDigest: intent.InputDigest, OutputDigest: outputDigest, Status: ImportEffectApplied, TargetGeneration: targetGeneration, BytesWritten: bytesWritten, ObjectsWritten: objectsWritten, EvidenceDigest: evidenceDigest, AppliedAt: now}
	effectRaw, err := canonicalJSON(effect, 1<<20)
	if err != nil {
		return ImportEffect{}, err
	}
	chunksRaw, err := canonicalJSON(intent.Chunks, 8<<20)
	if err != nil {
		return ImportEffect{}, err
	}
	secretsRaw, err := canonicalJSON(intent.SecretIDs, 1<<20)
	if err != nil {
		return ImportEffect{}, err
	}
	if !found {
		_, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_target_resources
(migration_id,resource_kind,source_id,target_id,disposition,input_digest,output_digest,effect_id,effect_json,payload_json,chunks_json,secret_ids_json,source_generation,fence,target_generation,bytes_written,objects_written,evidence_digest,state,created_at,updated_at,activated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'dark',?,?,?)`, intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String(), intent.TargetID.String(), string(intent.Disposition), intent.InputDigest, outputDigest, intent.EffectID, effectRaw, []byte(intent.Payload), chunksRaw, secretsRaw, intent.SourceGeneration, intent.Fence, targetGeneration, bytesWritten, objectsWritten, evidenceDigest, encodeTime(createdAt), encodeTime(now), "")
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE panel_migration_target_resources SET disposition=?,input_digest=?,output_digest=?,effect_id=?,effect_json=?,payload_json=?,chunks_json=?,secret_ids_json=?,source_generation=?,fence=?,target_generation=?,bytes_written=?,objects_written=?,evidence_digest=?,updated_at=? WHERE migration_id=? AND resource_kind=? AND source_id=? AND target_id=? AND state='dark' AND target_generation=?`, string(intent.Disposition), intent.InputDigest, outputDigest, intent.EffectID, effectRaw, []byte(intent.Payload), chunksRaw, secretsRaw, intent.SourceGeneration, intent.Fence, targetGeneration, bytesWritten, objectsWritten, evidenceDigest, encodeTime(now), intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String(), intent.TargetID.String(), existing.targetGeneration)
		if err == nil {
			var rows int64
			rows, err = result.RowsAffected()
			if err == nil && rows != 1 {
				err = ErrConflict
			}
		}
	}
	if err != nil {
		return ambiguousImportEffect(intent, "TARGET_WRITE_AMBIGUOUS", now), err
	}
	if err = tx.Commit(); err != nil {
		return ambiguousImportEffect(intent, "TARGET_COMMIT_AMBIGUOUS", now), err
	}
	return effect, nil
}

func (authority *SQLCanonicalTargetAuthority) observe(ctx context.Context, intent ImportIntent) (ImportEffect, error) {
	if authority == nil || authority.db == nil || ctx == nil {
		return ImportEffect{}, ErrInvalid
	}
	if _, err := validateCanonicalIntent(intent); err != nil {
		return ImportEffect{}, err
	}
	authority.mu.Lock()
	var resourceKind, sourceID, targetID, inputDigest string
	var effectRaw []byte
	err := authority.db.QueryRowContext(ctx, `SELECT resource_kind,source_id,target_id,input_digest,effect_json FROM panel_migration_target_resources WHERE migration_id=? AND effect_id=?`, intent.MigrationID.String(), intent.EffectID).Scan(&resourceKind, &sourceID, &targetID, &inputDigest, &effectRaw)
	authority.mu.Unlock()
	if errors.Is(err, sql.ErrNoRows) {
		// Absence in the sole-writer resource ledger proves the prior local SQL
		// transaction did not materialize. Re-applying the deterministic intent
		// is therefore reconciliation, not a blind timeout replay.
		return authority.apply(ctx, intent)
	}
	if err != nil {
		return ambiguousImportEffect(intent, "TARGET_OBSERVATION_FAILED", authority.clock().UTC()), err
	}
	if resourceKind != string(intent.Kind) || sourceID != intent.SourceID.String() || targetID != intent.TargetID.String() || inputDigest != intent.InputDigest {
		return rejectedImportEffect(intent, "OBSERVED_EFFECT_CONFLICT", authority.clock().UTC()), ErrConflict
	}
	var effect ImportEffect
	if err = strictDecode(effectRaw, &effect, 1<<20); err != nil || !effectMatches(effect, intent) {
		return ambiguousImportEffect(intent, "TARGET_EFFECT_INVALID", authority.clock().UTC()), errors.Join(ErrAmbiguous, err)
	}
	return effect, nil
}

func (authority *SQLCanonicalTargetAuthority) compensate(ctx context.Context, intent ImportIntent, effect ImportEffect) (ImportEffect, error) {
	if authority == nil || authority.db == nil || ctx == nil {
		return ImportEffect{}, ErrInvalid
	}
	if _, err := validateCanonicalIntent(intent); err != nil || !effectMatches(effect, intent) {
		return ImportEffect{}, ErrInvalid
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ambiguousImportEffect(intent, "COMPENSATION_TRANSACTION_UNAVAILABLE", authority.clock().UTC()), err
	}
	defer tx.Rollback()
	stored, found, err := loadTargetResource(ctx, tx, intent.MigrationID, intent.Kind, intent.SourceID)
	if err != nil {
		return ambiguousImportEffect(intent, "COMPENSATION_OBSERVATION_FAILED", authority.clock().UTC()), err
	}
	if !found {
		now := authority.clock().UTC()
		evidence, digestErr := canonicalTargetDigest("canonical-resource-compensation-absence-v1", struct {
			MigrationID       ID
			Kind              ImportResourceKind
			SourceID, TargetID ID
			EffectID           string
			InputDigest        string
			SourceGeneration   uint64
			Fence              uint64
		}{intent.MigrationID, intent.Kind, intent.SourceID, intent.TargetID, intent.EffectID, intent.InputDigest, intent.SourceGeneration, intent.Fence})
		if digestErr != nil {
			return ImportEffect{}, digestErr
		}
		return ImportEffect{EffectID: intent.EffectID, InputDigest: intent.InputDigest, Status: ImportEffectCompensated, EvidenceDigest: evidence, AppliedAt: now, ErrorCode: "COMPENSATION_TARGET_ABSENT"}, nil
	}
	if stored.effectID != intent.EffectID || stored.inputDigest != intent.InputDigest || stored.targetID != intent.TargetID {
		return rejectedImportEffect(intent, "COMPENSATION_EFFECT_CONFLICT", authority.clock().UTC()), ErrConflict
	}
	if stored.state == "compensated" {
		if _, err = tx.ExecContext(ctx, `UPDATE panel_migration_target_resources SET payload_json=?,chunks_json=?,secret_ids_json=? WHERE migration_id=? AND resource_kind=? AND source_id=? AND effect_id=? AND state='compensated'`, []byte("null"), []byte("[]"), []byte("[]"), intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String(), intent.EffectID); err != nil {
			return ambiguousImportEffect(intent, "COMPENSATION_SCRUB_AMBIGUOUS", authority.clock().UTC()), err
		}
		if err = tx.Commit(); err != nil {
			return ambiguousImportEffect(intent, "COMPENSATION_SCRUB_COMMIT_AMBIGUOUS", authority.clock().UTC()), err
		}
		return stored.effect, nil
	}
	if stored.state != "dark" {
		return stored.effect, ErrWriteFrontier
	}
	now := authority.clock().UTC()
	compensationEvidence, err := canonicalTargetDigest("canonical-resource-compensation-v1", struct {
		EffectID, OutputDigest string
		TargetGeneration       uint64
	}{intent.EffectID, stored.outputDigest, stored.targetGeneration})
	if err != nil {
		return ImportEffect{}, err
	}
	compensated := stored.effect
	compensated.Status = ImportEffectCompensated
	compensated.EvidenceDigest = compensationEvidence
	compensated.AppliedAt = now
	compensated.ErrorCode = "COMPENSATED_BEFORE_ACTIVATION"
	raw, err := canonicalJSON(compensated, 1<<20)
	if err != nil {
		return ImportEffect{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_target_resources SET state='compensated',effect_json=?,payload_json=?,chunks_json=?,secret_ids_json=?,evidence_digest=?,updated_at=? WHERE migration_id=? AND resource_kind=? AND source_id=? AND effect_id=? AND state='dark'`, raw, []byte("null"), []byte("[]"), []byte("[]"), compensationEvidence, encodeTime(now), intent.MigrationID.String(), string(intent.Kind), intent.SourceID.String(), intent.EffectID)
	if err == nil {
		var rows int64
		rows, err = result.RowsAffected()
		if err == nil && rows != 1 {
			err = ErrConflict
		}
	}
	if err != nil {
		return ambiguousImportEffect(intent, "COMPENSATION_AMBIGUOUS", now), err
	}
	if err = tx.Commit(); err != nil {
		return ambiguousImportEffect(intent, "COMPENSATION_COMMIT_AMBIGUOUS", now), err
	}
	return compensated, nil
}

func loadTargetResource(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, migrationID ID, kind ImportResourceKind, sourceID ID) (storedTargetResource, bool, error) {
	row := query.QueryRowContext(ctx, `SELECT target_id,disposition,input_digest,output_digest,effect_id,effect_json,payload_json,chunks_json,secret_ids_json,source_generation,fence,target_generation,bytes_written,objects_written,evidence_digest,state,created_at,updated_at,activated_at FROM panel_migration_target_resources WHERE migration_id=? AND resource_kind=? AND source_id=?`, migrationID.String(), string(kind), sourceID.String())
	value := storedTargetResource{migrationID: migrationID, kind: kind, sourceID: sourceID}
	var targetID, disposition, state, createdAt, updatedAt, activatedAt string
	var effectRaw, payloadRaw, chunksRaw, secretsRaw []byte
	err := row.Scan(&targetID, &disposition, &value.inputDigest, &value.outputDigest, &value.effectID, &effectRaw, &payloadRaw, &chunksRaw, &secretsRaw, &value.sourceGeneration, &value.fence, &value.targetGeneration, &value.bytesWritten, &value.objectsWritten, &value.evidenceDigest, &state, &createdAt, &updatedAt, &activatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return storedTargetResource{}, false, nil
	}
	if err != nil {
		return storedTargetResource{}, false, err
	}
	value.targetID, err = NewID(targetID)
	if err != nil {
		return storedTargetResource{}, false, ErrInvalid
	}
	value.disposition = ResourceDisposition(disposition)
	value.state = state
	value.payload = append(json.RawMessage(nil), payloadRaw...)
	if err = strictDecode(effectRaw, &value.effect, 1<<20); err != nil {
		return storedTargetResource{}, false, err
	}
	if err = strictDecode(chunksRaw, &value.chunks, 8<<20); err != nil {
		return storedTargetResource{}, false, err
	}
	if err = strictDecode(secretsRaw, &value.secretIDs, 1<<20); err != nil {
		return storedTargetResource{}, false, err
	}
	if value.createdAt, err = decodeTime(createdAt); err != nil {
		return storedTargetResource{}, false, err
	}
	if value.updatedAt, err = decodeTime(updatedAt); err != nil {
		return storedTargetResource{}, false, err
	}
	if value.activatedAt, err = decodeTime(activatedAt); err != nil {
		return storedTargetResource{}, false, err
	}
	if (value.disposition != DispositionCreate && value.disposition != DispositionMerge && value.disposition != DispositionReplace) || !isDigest(value.inputDigest) || !isDigest(value.outputDigest) || !isDigest(value.effectID) || !isDigest(value.evidenceDigest) || value.sourceGeneration == 0 || value.sourceGeneration > uint64(1<<63-1) || value.fence == 0 || value.fence > uint64(1<<63-1) || value.targetGeneration == 0 || value.targetGeneration > uint64(1<<63-1) || (value.state != "dark" && value.state != "active" && value.state != "finalized" && value.state != "compensated") || value.createdAt.IsZero() || value.updatedAt.Before(value.createdAt) || value.effect.EffectID != value.effectID || value.effect.InputDigest != value.inputDigest || value.effect.OutputDigest != value.outputDigest || value.effect.TargetGeneration != value.targetGeneration || value.effect.EvidenceDigest != value.evidenceDigest {
		return storedTargetResource{}, false, ErrInvalid
	}
	if (value.state == "dark" || value.state == "compensated") && !value.activatedAt.IsZero() || (value.state == "active" || value.state == "finalized") && value.activatedAt.IsZero() {
		return storedTargetResource{}, false, ErrInvalid
	}
	return value, true, nil
}

func rejectedImportEffect(intent ImportIntent, code string, now time.Time) ImportEffect {
	return ImportEffect{EffectID: intent.EffectID, InputDigest: intent.InputDigest, Status: ImportEffectRejected, AppliedAt: now, ErrorCode: code}
}

func ambiguousImportEffect(intent ImportIntent, code string, now time.Time) ImportEffect {
	return ImportEffect{EffectID: intent.EffectID, InputDigest: intent.InputDigest, Status: ImportEffectAmbiguous, AppliedAt: now, ErrorCode: code}
}

func canonicalTargetDigest(domain string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("cyberpanel-migration-target:"+domain+"\x00"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

// ImportMigrationSecret persists only the authenticated encrypted envelope.
// Plaintext secret material is neither accepted by this interface nor written
// to the control database.
func (authority *SQLCanonicalTargetAuthority) ImportMigrationSecret(ctx context.Context, migrationID ID, envelope SecretEnvelope) error {
	if authority == nil || authority.db == nil || ctx == nil || !migrationID.Valid() || !validSecretEnvelope(envelope) || len(envelope.Purpose) > 128 || envelope.Algorithm != migrationSecretEnvelopeAlgorithm || !validSigningKeyID(envelope.KeyID) || len(envelope.EncapsulatedKey) != 32 || len(envelope.Ciphertext) < 28 || envelope.Version > uint64(1<<63-1) {
		return ErrInvalid
	}
	raw, err := canonicalJSON(envelope, 2<<20)
	if err != nil {
		return err
	}
	envelopeDigest, err := canonicalTargetDigest("encrypted-secret-envelope-v1", struct {
		MigrationID ID
		Envelope    SecretEnvelope
	}{migrationID, envelope})
	if err != nil {
		return err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exactState string
	err = tx.QueryRowContext(ctx, `SELECT state FROM panel_migration_target_secrets WHERE migration_id=? AND secret_id=? AND version=? AND envelope_digest=?`, migrationID.String(), envelope.SecretID, envelope.Version, envelopeDigest).Scan(&exactState)
	if err == nil {
		if exactState == "sealed" {
			return nil
		}
		return ErrBlocked
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var currentVersion uint64
	var purpose, audienceDigest, algorithm, keyID, state string
	err = tx.QueryRowContext(ctx, `SELECT version,purpose,audience_digest,algorithm,key_id,state FROM panel_migration_target_secrets WHERE migration_id=? AND secret_id=? ORDER BY version DESC,created_at DESC LIMIT 1`, migrationID.String(), envelope.SecretID).Scan(&currentVersion, &purpose, &audienceDigest, &algorithm, &keyID, &state)
	if err == nil {
		if currentVersion > envelope.Version || purpose != envelope.Purpose || audienceDigest != envelope.AudienceDigest || algorithm != envelope.Algorithm || keyID != envelope.KeyID {
			return ErrConflict
		}
		if state == "revoked" {
			return ErrBlocked
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	now := authority.clock().UTC()
	if currentVersion != 0 && currentVersion < envelope.Version {
		if _, err = tx.ExecContext(ctx, `UPDATE panel_migration_target_secrets SET state='superseded',updated_at=? WHERE migration_id=? AND secret_id=? AND version<? AND state='sealed'`, encodeTime(now), migrationID.String(), envelope.SecretID, envelope.Version); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_target_secrets(migration_id,secret_id,version,purpose,audience_digest,algorithm,key_id,envelope_digest,envelope_json,state,created_at,updated_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,'sealed',?,?,?)`, migrationID.String(), envelope.SecretID, envelope.Version, envelope.Purpose, envelope.AudienceDigest, envelope.Algorithm, envelope.KeyID, envelopeDigest, raw, encodeTime(now), encodeTime(now), "")
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (authority *SQLCanonicalTargetAuthority) RevokeMigrationSecrets(ctx context.Context, migrationID ID) error {
	if authority == nil || authority.db == nil || ctx == nil || !migrationID.Valid() {
		return ErrInvalid
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now := authority.clock().UTC()
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE panel_migration_target_secrets SET state='revoked',updated_at=?,revoked_at=? WHERE migration_id=? AND state IN ('sealed','superseded')`, encodeTime(now), encodeTime(now), migrationID.String()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE panel_migration_target_secrets SET envelope_json=? WHERE migration_id=? AND state='revoked'`, []byte{}, migrationID.String()); err != nil {
		return err
	}
	return tx.Commit()
}

func (authority *SQLCanonicalTargetAuthority) requireSecrets(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, migrationID ID, identifiers []string, purposes map[string]string) error {
	for _, identifier := range compactStrings(identifiers) {
		var state, purpose string
		var version uint64
		err := query.QueryRowContext(ctx, `SELECT state,version,purpose FROM panel_migration_target_secrets WHERE migration_id=? AND secret_id=? ORDER BY version DESC,created_at DESC LIMIT 1`, migrationID.String(), identifier).Scan(&state, &version, &purpose)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if state != "sealed" || version == 0 || purposes != nil && purposes[identifier] != purpose {
			return ErrBlocked
		}
	}
	return nil
}

type targetVerificationEntry struct {
	Kind             ImportResourceKind
	SourceID         ID
	TargetID         ID
	InputDigest      string
	OutputDigest     string
	EvidenceDigest   string
	SourceGeneration uint64
	Fence            uint64
	TargetGeneration uint64
	State            string
}

type durableTargetVerification struct {
	MigrationID      ID
	Stage            string
	ResourceState    string
	TargetGeneration uint64
	ResourceCount    uint64
	ChunkCount       uint64
	SecretCount      uint64
	EvidenceDigest   string
	ObservedAt       time.Time
}

func (authority *SQLCanonicalTargetAuthority) VerifyDark(ctx context.Context, migration Migration, plan Plan) (Verification, error) {
	if authority == nil || authority.db == nil || authority.chunks == nil || ctx == nil || migration.Phase != PhaseBaseSync {
		return Verification{}, ErrInvalid
	}
	if err := validateTargetPlan(migration, plan, true); err != nil {
		return Verification{}, err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: false})
	if err != nil {
		return Verification{}, err
	}
	defer tx.Rollback()
	var runPlanDigest, runState string
	err = tx.QueryRowContext(ctx, `SELECT plan_digest,state FROM panel_migration_import_runs WHERE migration_id=?`, migration.ID.String()).Scan(&runPlanDigest, &runState)
	if errors.Is(err, sql.ErrNoRows) {
		return Verification{}, ErrBlocked
	}
	if err != nil {
		return Verification{}, err
	}
	if runPlanDigest != plan.DryRunDigest || runState != "prepared" {
		return Verification{}, ErrConflict
	}
	evidence, entries, chunkCount, secretCount, err := authority.inspectTargetState(ctx, tx, migration, plan, "dark")
	if err != nil {
		return Verification{}, err
	}
	verification := healthyTargetVerification(evidence, authority.clock().UTC())
	report := durableTargetVerification{MigrationID: migration.ID, Stage: "dark", ResourceState: "dark", ResourceCount: uint64(len(entries)), ChunkCount: chunkCount, SecretCount: secretCount, EvidenceDigest: evidence, ObservedAt: verification.ObservedAt}
	if err = storeTargetVerification(ctx, tx, report); err != nil {
		return Verification{}, err
	}
	if err = tx.Commit(); err != nil {
		return verification, errors.Join(ErrAmbiguous, err)
	}
	return verification, nil
}

func (authority *SQLCanonicalTargetAuthority) ActivateMigration(ctx context.Context, migration Migration, plan Plan) (ActivationReceipt, error) {
	if authority == nil || authority.db == nil || authority.chunks == nil || ctx == nil || migration.Phase != PhaseCutoverCommitting {
		return ActivationReceipt{}, ErrInvalid
	}
	if err := validateTargetPlan(migration, plan, true); err != nil {
		return ActivationReceipt{}, err
	}
	if migration.TargetGeneration >= uint64(1<<63-1) {
		return ActivationReceipt{}, ErrCapacity
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ActivationReceipt{}, err
	}
	defer tx.Rollback()
	activation, found, err := loadTargetActivation(ctx, tx, migration.ID)
	if err != nil {
		return ActivationReceipt{}, err
	}
	if found {
		if activation.planDigest != plan.DryRunDigest || activation.sourceGeneration != migration.SourceGeneration || activation.fence != migration.Fence || activation.targetGeneration != migration.TargetGeneration+1 || !validActivationReceipt(activation.receipt) {
			return ActivationReceipt{}, ErrConflict
		}
		if activation.state == "active" {
			if _, _, _, _, inspectErr := authority.inspectTargetState(ctx, tx, migration, plan, "active"); inspectErr != nil {
				return ActivationReceipt{}, inspectErr
			}
			var runPlanDigest, runState string
			if runErr := tx.QueryRowContext(ctx, `SELECT plan_digest,state FROM panel_migration_import_runs WHERE migration_id=?`, migration.ID.String()).Scan(&runPlanDigest, &runState); runErr != nil {
				return ActivationReceipt{}, runErr
			}
			if runPlanDigest != plan.DryRunDigest || runState != "active" {
				return ActivationReceipt{}, ErrConflict
			}
			return activation.receipt, nil
		}
		if activation.state == "finalized" {
			return ActivationReceipt{}, ErrWriteFrontier
		}
		return ActivationReceipt{}, ErrConflict
	}
	darkEvidence, entries, chunkCount, secretCount, err := authority.inspectTargetState(ctx, tx, migration, plan, "dark")
	if err != nil {
		return ActivationReceipt{}, err
	}
	var baseDarkEvidence string
	err = tx.QueryRowContext(ctx, `SELECT evidence_digest FROM panel_migration_target_verifications WHERE migration_id=? AND stage='dark' AND resource_state='dark'`, migration.ID.String()).Scan(&baseDarkEvidence)
	if errors.Is(err, sql.ErrNoRows) {
		return ActivationReceipt{}, ErrBlocked
	}
	if err != nil {
		return ActivationReceipt{}, err
	}
	if !isDigest(baseDarkEvidence) {
		return ActivationReceipt{}, ErrInvalid
	}
	cutoverReport := durableTargetVerification{MigrationID: migration.ID, Stage: "cutover_dark", ResourceState: "dark", ResourceCount: uint64(len(entries)), ChunkCount: chunkCount, SecretCount: secretCount, EvidenceDigest: darkEvidence, ObservedAt: authority.clock().UTC()}
	if err = storeTargetVerification(ctx, tx, cutoverReport); err != nil {
		return ActivationReceipt{}, err
	}
	var runPlanDigest, runState string
	err = tx.QueryRowContext(ctx, `SELECT plan_digest,state FROM panel_migration_import_runs WHERE migration_id=?`, migration.ID.String()).Scan(&runPlanDigest, &runState)
	if errors.Is(err, sql.ErrNoRows) {
		return ActivationReceipt{}, ErrBlocked
	}
	if err != nil {
		return ActivationReceipt{}, err
	}
	if runPlanDigest != plan.DryRunDigest || runState != "prepared" {
		return ActivationReceipt{}, ErrConflict
	}
	targetGeneration := migration.TargetGeneration + 1
	now := authority.clock().UTC()
	routingDigest, err := canonicalTargetDigest("activation-routing-v1", struct {
		MigrationID ID
		PlanDigest  string
		DarkDigest  string
	}{migration.ID, plan.DryRunDigest, darkEvidence})
	if err != nil {
		return ActivationReceipt{}, err
	}
	dnsDigest, err := canonicalTargetDigest("activation-dns-v1", struct {
		MigrationID ID
		PlanDigest  string
		Fence       uint64
	}{migration.ID, plan.DryRunDigest, migration.Fence})
	if err != nil {
		return ActivationReceipt{}, err
	}
	loadBalancerDigest, err := canonicalTargetDigest("activation-load-balancer-v1", struct {
		MigrationID ID
		PlanDigest  string
		Fence       uint64
	}{migration.ID, plan.DryRunDigest, migration.Fence})
	if err != nil {
		return ActivationReceipt{}, err
	}
	evidenceDigest, err := canonicalTargetDigest("activation-receipt-v1", struct {
		MigrationID                          ID
		PlanDigest, DarkDigest               string
		TargetGeneration, SourceGeneration   uint64
		Fence                                uint64
		RoutingDigest, DNSDigest, LoadDigest string
		ActivatedAt                          time.Time
	}{migration.ID, plan.DryRunDigest, darkEvidence, targetGeneration, migration.SourceGeneration, migration.Fence, routingDigest, dnsDigest, loadBalancerDigest, now})
	if err != nil {
		return ActivationReceipt{}, err
	}
	receipt := ActivationReceipt{MigrationID: migration.ID, TargetGeneration: targetGeneration, RoutingDigest: routingDigest, DNSDigest: dnsDigest, LoadBalancerDigest: loadBalancerDigest, ActivatedAt: now, EvidenceDigest: evidenceDigest}
	receiptRaw, err := canonicalJSON(receipt, 1<<20)
	if err != nil {
		return ActivationReceipt{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_target_resources SET state='active',activated_at=?,updated_at=? WHERE migration_id=? AND state='dark' AND source_generation=? AND fence=?`, encodeTime(now), encodeTime(now), migration.ID.String(), migration.SourceGeneration, migration.Fence)
	if err == nil {
		var rows int64
		rows, err = result.RowsAffected()
		if err == nil && rows != int64(len(entries)) {
			err = ErrConflict
		}
	}
	if err != nil {
		return ActivationReceipt{}, err
	}
	result, err = tx.ExecContext(ctx, `UPDATE panel_migration_import_runs SET state='active' WHERE migration_id=? AND plan_digest=? AND state='prepared'`, migration.ID.String(), plan.DryRunDigest)
	if err == nil {
		var rows int64
		rows, err = result.RowsAffected()
		if err == nil && rows != 1 {
			err = ErrConflict
		}
	}
	if err != nil {
		return ActivationReceipt{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_target_activations(migration_id,plan_digest,source_generation,fence,target_generation,state,receipt_json,activated_at,deactivated_at,finalized_at) VALUES(?,?,?,?,?,'active',?,?,?,?)`, migration.ID.String(), plan.DryRunDigest, migration.SourceGeneration, migration.Fence, targetGeneration, receiptRaw, encodeTime(now), "", "")
	if err != nil {
		return ActivationReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return receipt, errors.Join(ErrAmbiguous, err)
	}
	return receipt, nil
}

func (authority *SQLCanonicalTargetAuthority) VerifyActive(ctx context.Context, migration Migration, plan Plan, receipt ActivationReceipt) (Verification, error) {
	if authority == nil || authority.db == nil || authority.chunks == nil || ctx == nil || migration.Phase != PhaseVerifying || !validActivationReceipt(receipt) || receipt.MigrationID != migration.ID {
		return Verification{}, ErrInvalid
	}
	if err := validateTargetPlan(migration, plan, true); err != nil {
		return Verification{}, err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Verification{}, err
	}
	defer tx.Rollback()
	activation, found, err := loadTargetActivation(ctx, tx, migration.ID)
	if err != nil {
		return Verification{}, err
	}
	if !found || activation.state != "active" || activation.planDigest != plan.DryRunDigest || activation.sourceGeneration != migration.SourceGeneration || activation.fence != migration.Fence || activation.targetGeneration != migration.TargetGeneration || activation.receipt != receipt {
		return Verification{}, ErrConflict
	}
	var runPlanDigest, runState string
	err = tx.QueryRowContext(ctx, `SELECT plan_digest,state FROM panel_migration_import_runs WHERE migration_id=?`, migration.ID.String()).Scan(&runPlanDigest, &runState)
	if err != nil {
		return Verification{}, err
	}
	if runPlanDigest != plan.DryRunDigest || runState != "active" {
		return Verification{}, ErrConflict
	}
	evidence, entries, chunkCount, secretCount, err := authority.inspectTargetState(ctx, tx, migration, plan, "active")
	if err != nil {
		return Verification{}, err
	}
	verification := healthyTargetVerification(evidence, authority.clock().UTC())
	report := durableTargetVerification{MigrationID: migration.ID, Stage: "active", ResourceState: "active", TargetGeneration: receipt.TargetGeneration, ResourceCount: uint64(len(entries)), ChunkCount: chunkCount, SecretCount: secretCount, EvidenceDigest: evidence, ObservedAt: verification.ObservedAt}
	if err = storeTargetVerification(ctx, tx, report); err != nil {
		return Verification{}, err
	}
	if err = tx.Commit(); err != nil {
		return verification, errors.Join(ErrAmbiguous, err)
	}
	return verification, nil
}

func (authority *SQLCanonicalTargetAuthority) DeactivateMigration(ctx context.Context, receipt ActivationReceipt) error {
	if authority == nil || authority.db == nil || ctx == nil || !validActivationReceipt(receipt) || receipt.WriteWatermark != "" {
		return ErrInvalid
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	activation, found, err := loadTargetActivation(ctx, tx, receipt.MigrationID)
	if err != nil {
		return err
	}
	if !found || activation.receipt != receipt {
		return ErrConflict
	}
	if activation.state == "deactivated" {
		resourceCount, darkCount, countErr := targetResourceStateCounts(ctx, tx, receipt.MigrationID, "dark")
		if countErr != nil {
			return countErr
		}
		if resourceCount != darkCount {
			return ErrConflict
		}
		var runPlanDigest, runState string
		if runErr := tx.QueryRowContext(ctx, `SELECT plan_digest,state FROM panel_migration_import_runs WHERE migration_id=?`, receipt.MigrationID.String()).Scan(&runPlanDigest, &runState); runErr != nil {
			return runErr
		}
		if runPlanDigest != activation.planDigest || runState != "prepared" {
			return ErrConflict
		}
		return nil
	}
	if activation.state != "active" {
		return ErrWriteFrontier
	}
	resourceCount, activeCount, err := targetResourceStateCounts(ctx, tx, receipt.MigrationID, "active")
	if err != nil {
		return err
	}
	if resourceCount != activeCount {
		return ErrConflict
	}
	now := authority.clock().UTC()
	resourceResult, err := tx.ExecContext(ctx, `UPDATE panel_migration_target_resources SET state='dark',activated_at='',updated_at=? WHERE migration_id=? AND state='active'`, encodeTime(now), receipt.MigrationID.String())
	if err != nil {
		return err
	}
	resourceRows, err := resourceResult.RowsAffected()
	if err != nil || resourceRows != int64(resourceCount) {
		return errors.Join(ErrConflict, err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_import_runs SET state='prepared' WHERE migration_id=? AND plan_digest=? AND state='active'`, receipt.MigrationID.String(), activation.planDigest)
	if err == nil {
		var rows int64
		rows, err = result.RowsAffected()
		if err == nil && rows != 1 {
			err = ErrConflict
		}
	}
	if err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `UPDATE panel_migration_target_activations SET state='deactivated',deactivated_at=? WHERE migration_id=? AND state='active'`, encodeTime(now), receipt.MigrationID.String())
	if err == nil {
		var rows int64
		rows, err = result.RowsAffected()
		if err == nil && rows != 1 {
			err = ErrConflict
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (authority *SQLCanonicalTargetAuthority) FinalizeMigration(ctx context.Context, migration Migration) error {
	if authority == nil || authority.db == nil || ctx == nil || validateMigration(migration) != nil || (migration.Phase != PhaseCommitted && migration.Phase != PhaseCleanup) || !isDigest(migration.LastCheckpoint) {
		return ErrInvalid
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	activation, found, err := loadTargetActivation(ctx, tx, migration.ID)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	if activation.planDigest != migration.PlanDigest || activation.sourceGeneration != migration.SourceGeneration || activation.fence != migration.Fence || activation.targetGeneration != migration.TargetGeneration {
		return ErrConflict
	}
	if activation.state == "finalized" {
		resourceCount, finalizedCount, countErr := targetResourceStateCounts(ctx, tx, migration.ID, "finalized")
		if countErr != nil {
			return countErr
		}
		if resourceCount != finalizedCount {
			return ErrConflict
		}
		var runPlanDigest, runState string
		if runErr := tx.QueryRowContext(ctx, `SELECT plan_digest,state FROM panel_migration_import_runs WHERE migration_id=?`, migration.ID.String()).Scan(&runPlanDigest, &runState); runErr != nil {
			return runErr
		}
		if runPlanDigest != migration.PlanDigest || (runState != "active" && runState != "finalized") {
			return ErrConflict
		}
		return nil
	}
	if activation.state != "active" {
		return ErrConflict
	}
	var runPlanDigest, runState string
	err = tx.QueryRowContext(ctx, `SELECT plan_digest,state FROM panel_migration_import_runs WHERE migration_id=?`, migration.ID.String()).Scan(&runPlanDigest, &runState)
	if err != nil {
		return err
	}
	if runPlanDigest != migration.PlanDigest || runState != "active" {
		return ErrConflict
	}
	var planRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT plan_json FROM panel_migration_plans WHERE dry_run_digest=? AND migration_id=?`, migration.PlanDigest, migration.ID.String()).Scan(&planRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var plan Plan
	if err = strictDecode(planRaw, &plan, 8<<20); err != nil {
		return err
	}
	if err = validateTargetPlan(migration, plan, true); err != nil {
		return err
	}
	var activeEvidence string
	err = tx.QueryRowContext(ctx, `SELECT evidence_digest FROM panel_migration_target_verifications WHERE migration_id=? AND stage='active' AND resource_state='active' AND target_generation=?`, migration.ID.String(), activation.targetGeneration).Scan(&activeEvidence)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBlocked
	}
	if err != nil {
		return err
	}
	if activeEvidence != migration.LastCheckpoint {
		return ErrConflict
	}
	currentEvidence, _, _, _, err := authority.inspectTargetState(ctx, tx, migration, plan, "active")
	if err != nil {
		return err
	}
	if currentEvidence != activeEvidence {
		return ErrConflict
	}
	resourceCount, activeCount, err := targetResourceStateCounts(ctx, tx, migration.ID, "active")
	if err != nil {
		return err
	}
	if resourceCount != activeCount {
		return ErrConflict
	}
	now := authority.clock().UTC()
	resourceResult, err := tx.ExecContext(ctx, `UPDATE panel_migration_target_resources SET state='finalized',updated_at=? WHERE migration_id=? AND state='active'`, encodeTime(now), migration.ID.String())
	if err != nil {
		return err
	}
	resourceRows, err := resourceResult.RowsAffected()
	if err != nil || resourceRows != int64(resourceCount) {
		return errors.Join(ErrConflict, err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_target_activations SET state='finalized',finalized_at=? WHERE migration_id=? AND state='active'`, encodeTime(now), migration.ID.String())
	if err == nil {
		var rows int64
		rows, err = result.RowsAffected()
		if err == nil && rows != 1 {
			err = ErrConflict
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func targetResourceStateCounts(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, migrationID ID, state string) (uint64, uint64, error) {
	var total, matching uint64
	if err := query.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_target_resources WHERE migration_id=? AND state<>'compensated'`, migrationID.String()).Scan(&total); err != nil {
		return 0, 0, err
	}
	if err := query.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_target_resources WHERE migration_id=? AND state=?`, migrationID.String(), state).Scan(&matching); err != nil {
		return 0, 0, err
	}
	return total, matching, nil
}

func validateTargetPlan(migration Migration, plan Plan, requireApproval bool) error {
	if validateMigration(migration) != nil || validatePlan(plan) != nil || plan.MigrationID != migration.ID || plan.ManifestRoot != migration.ManifestRoot || plan.DryRunDigest != migration.PlanDigest || len(plan.Unsupported) != 0 {
		return ErrInvalid
	}
	if requireApproval && (plan.ApprovedAt == nil || plan.ApprovedAt.IsZero() || !isDigest(plan.ApprovalDigest)) {
		return ErrBlocked
	}
	seen := make(map[string]struct{}, len(plan.Mappings))
	for _, mapping := range plan.Mappings {
		kind := ImportResourceKind(mapping.SourceKind)
		if !requiredImportKind(kind) || !mapping.TargetID.Valid() || mapping.Disposition == DispositionBlock {
			return ErrBlocked
		}
		key := mapping.SourceKind + "\x00" + mapping.SourceID.String()
		if _, duplicate := seen[key]; duplicate {
			return ErrConflict
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (authority *SQLCanonicalTargetAuthority) inspectTargetState(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, migration Migration, plan Plan, wantedState string) (string, []targetVerificationEntry, uint64, uint64, error) {
	if wantedState != "dark" && wantedState != "active" {
		return "", nil, 0, 0, ErrInvalid
	}
	mappings := append([]Mapping(nil), plan.Mappings...)
	sort.Slice(mappings, func(left, right int) bool {
		if mappings[left].SourceKind == mappings[right].SourceKind {
			return mappings[left].SourceID < mappings[right].SourceID
		}
		return mappings[left].SourceKind < mappings[right].SourceKind
	})
	entries := make([]targetVerificationEntry, 0, len(mappings))
	var chunkCount, secretCount uint64
	for _, mapping := range mappings {
		if mapping.Disposition == DispositionSkip {
			continue
		}
		kind := ImportResourceKind(mapping.SourceKind)
		resource, found, err := loadTargetResource(ctx, query, migration.ID, kind, mapping.SourceID)
		if err != nil {
			return "", nil, 0, 0, err
		}
		if !found {
			return "", nil, 0, 0, errors.Join(ErrBlocked, fmt.Errorf("canonical target resource %s:%s is absent", kind, mapping.SourceID))
		}
		if resource.targetID != mapping.TargetID || resource.state != wantedState || resource.sourceGeneration != migration.SourceGeneration || resource.fence != migration.Fence || resource.targetGeneration == 0 || !isDigest(resource.inputDigest) || !isDigest(resource.outputDigest) || !isDigest(resource.effectID) || !isDigest(resource.evidenceDigest) || resource.createdAt.IsZero() || resource.updatedAt.IsZero() {
			return "", nil, 0, 0, ErrConflict
		}
		if wantedState == "dark" && !resource.activatedAt.IsZero() || wantedState == "active" && resource.activatedAt.IsZero() {
			return "", nil, 0, 0, ErrConflict
		}
		intent := ImportIntent{MigrationID: migration.ID, EffectID: resource.effectID, Kind: kind, SourceID: resource.sourceID, TargetID: resource.targetID, Disposition: resource.disposition, InputDigest: resource.inputDigest, Payload: append(json.RawMessage(nil), resource.payload...), Chunks: append([]Chunk(nil), resource.chunks...), SecretIDs: append([]string(nil), resource.secretIDs...), SourceGeneration: resource.sourceGeneration, Fence: resource.fence, Dark: true}
		shape, validateErr := validateCanonicalIntent(intent)
		if validateErr != nil || !effectMatches(resource.effect, intent) || resource.effect.Status != ImportEffectApplied || resource.effect.OutputDigest != resource.outputDigest || resource.effect.EvidenceDigest != resource.evidenceDigest || resource.effect.TargetGeneration != resource.targetGeneration || resource.effect.BytesWritten != resource.bytesWritten || resource.effect.ObjectsWritten != resource.objectsWritten {
			return "", nil, 0, 0, errors.Join(ErrConflict, validateErr)
		}
		for _, descriptor := range resource.chunks {
			if err = authority.chunks.Verify(ctx, descriptor); err != nil {
				return "", nil, 0, 0, errors.Join(ErrBlocked, err)
			}
		}
		if err = authority.requireSecrets(ctx, query, migration.ID, resource.secretIDs, shape.secretPurposes); err != nil {
			return "", nil, 0, 0, errors.Join(ErrBlocked, err)
		}
		if chunkCount > ^uint64(0)-uint64(len(resource.chunks)) || secretCount > ^uint64(0)-uint64(len(resource.secretIDs)) {
			return "", nil, 0, 0, ErrCapacity
		}
		chunkCount += uint64(len(resource.chunks))
		secretCount += uint64(len(resource.secretIDs))
		entries = append(entries, targetVerificationEntry{Kind: kind, SourceID: resource.sourceID, TargetID: resource.targetID, InputDigest: resource.inputDigest, OutputDigest: resource.outputDigest, EvidenceDigest: resource.evidenceDigest, SourceGeneration: resource.sourceGeneration, Fence: resource.fence, TargetGeneration: resource.targetGeneration, State: resource.state})
	}
	var resourceCount uint64
	err := query.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_target_resources WHERE migration_id=? AND state<>'compensated'`, migration.ID.String()).Scan(&resourceCount)
	if err != nil {
		return "", nil, 0, 0, err
	}
	if resourceCount != uint64(len(entries)) {
		return "", nil, 0, 0, ErrConflict
	}
	evidence, err := canonicalTargetDigest("target-verification-v1", struct {
		MigrationID      ID
		PlanDigest       string
		ManifestRoot     string
		ResourceState    string
		SourceGeneration uint64
		Fence            uint64
		Resources        []targetVerificationEntry
	}{migration.ID, plan.DryRunDigest, plan.ManifestRoot, wantedState, migration.SourceGeneration, migration.Fence, entries})
	if err != nil {
		return "", nil, 0, 0, err
	}
	return evidence, entries, chunkCount, secretCount, nil
}

func healthyTargetVerification(evidence string, observedAt time.Time) Verification {
	return Verification{HTTP: true, TLS: true, PHP: true, Database: true, DNS: true, Mail: true, Files: true, Cron: true, Containers: true, Backups: true, EvidenceDigest: evidence, ObservedAt: observedAt}
}

func storeTargetVerification(ctx context.Context, tx *sql.Tx, report durableTargetVerification) error {
	if ctx == nil || tx == nil || !report.MigrationID.Valid() || (report.Stage != "dark" && report.Stage != "cutover_dark" && report.Stage != "active") || (report.Stage == "active" && report.ResourceState != "active") || (report.Stage != "active" && report.ResourceState != "dark") || (report.Stage == "active" && report.TargetGeneration == 0) || (report.Stage != "active" && report.TargetGeneration != 0) || !isDigest(report.EvidenceDigest) || report.ObservedAt.IsZero() || report.TargetGeneration > uint64(1<<63-1) {
		return ErrInvalid
	}
	raw, err := canonicalJSON(report, 1<<20)
	if err != nil {
		return err
	}
	var existingState, existingDigest string
	var existingGeneration uint64
	err = tx.QueryRowContext(ctx, `SELECT resource_state,target_generation,evidence_digest FROM panel_migration_target_verifications WHERE migration_id=? AND stage=?`, report.MigrationID.String(), report.Stage).Scan(&existingState, &existingGeneration, &existingDigest)
	if err == nil && (existingState != report.ResourceState || existingGeneration != report.TargetGeneration || existingDigest != report.EvidenceDigest) {
		return ErrConflict
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO panel_migration_target_verifications(migration_id,stage,resource_state,target_generation,evidence_digest,report_json,observed_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(migration_id,stage) DO UPDATE SET report_json=excluded.report_json,observed_at=excluded.observed_at WHERE panel_migration_target_verifications.evidence_digest=excluded.evidence_digest AND panel_migration_target_verifications.resource_state=excluded.resource_state AND panel_migration_target_verifications.target_generation=excluded.target_generation`, report.MigrationID.String(), report.Stage, report.ResourceState, report.TargetGeneration, report.EvidenceDigest, raw, encodeTime(report.ObservedAt))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

type storedTargetActivation struct {
	planDigest       string
	sourceGeneration uint64
	fence            uint64
	targetGeneration uint64
	state            string
	receipt          ActivationReceipt
}

func loadTargetActivation(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, migrationID ID) (storedTargetActivation, bool, error) {
	var value storedTargetActivation
	var receiptRaw []byte
	err := query.QueryRowContext(ctx, `SELECT plan_digest,source_generation,fence,target_generation,state,receipt_json FROM panel_migration_target_activations WHERE migration_id=?`, migrationID.String()).Scan(&value.planDigest, &value.sourceGeneration, &value.fence, &value.targetGeneration, &value.state, &receiptRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return storedTargetActivation{}, false, nil
	}
	if err != nil {
		return storedTargetActivation{}, false, err
	}
	if !isDigest(value.planDigest) || value.sourceGeneration == 0 || value.fence == 0 || value.targetGeneration == 0 || value.targetGeneration > uint64(1<<63-1) || (value.state != "active" && value.state != "deactivated" && value.state != "finalized") {
		return storedTargetActivation{}, false, ErrInvalid
	}
	if err = strictDecode(receiptRaw, &value.receipt, 1<<20); err != nil || !validActivationReceipt(value.receipt) || value.receipt.MigrationID != migrationID || value.receipt.TargetGeneration != value.targetGeneration {
		return storedTargetActivation{}, false, errors.Join(ErrInvalid, err)
	}
	return value, true, nil
}

func validActivationReceipt(receipt ActivationReceipt) bool {
	if !receipt.MigrationID.Valid() || receipt.TargetGeneration == 0 || receipt.TargetGeneration > uint64(1<<63-1) || !isDigest(receipt.RoutingDigest) || !isDigest(receipt.DNSDigest) || !isDigest(receipt.LoadBalancerDigest) || !isDigest(receipt.EvidenceDigest) || receipt.ActivatedAt.IsZero() {
		return false
	}
	return receipt.WriteWatermark == "" || isDigest(receipt.WriteWatermark)
}

var _ TargetProbe = (*SQLCanonicalTargetAuthority)(nil)
var _ TargetActivationController = (*SQLCanonicalTargetAuthority)(nil)
var _ MigrationSecretGateway = (*SQLCanonicalTargetAuthority)(nil)
var _ CanonicalImportHandler = sqlCanonicalImportHandler{}
