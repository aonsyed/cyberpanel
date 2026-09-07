//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const migrationTargetSecretSchema = `
CREATE TABLE IF NOT EXISTS panel_migration_secret_bindings (
 migration_id TEXT NOT NULL, envelope_id TEXT NOT NULL, envelope_digest TEXT NOT NULL,
 tenant_id TEXT NOT NULL, source_kind TEXT NOT NULL, source_installation TEXT NOT NULL,
 target_installation TEXT NOT NULL, manifest_root TEXT NOT NULL, authority_json BLOB NOT NULL,
 envelope_json BLOB NOT NULL, metadata_json BLOB NOT NULL, state TEXT NOT NULL,
 PRIMARY KEY(migration_id,envelope_id)
);
CREATE TABLE IF NOT EXISTS panel_migration_secret_cancellations (
 migration_id TEXT PRIMARY KEY, canceled_at TEXT NOT NULL
);`

// Factory-installed typed consumers must derive this authority from the signed
// canonical resource and approved target mapping. There is no generic audience
// fallback, and no API returning imported plaintext to command handlers.
type migrationSecretAudienceResolver func(context.Context, migration.Manifest, migration.Plan, migration.RuntimeScope, migration.SecretEnvelope) (secrets.ID, secrets.Purpose, secrets.AudienceBinding, error)

type migrationSecretTarget struct {
	db *sql.DB
	scopes *migration.RuntimeScopeStore
	repository *migration.SQLRepository
	management *secrets.ManagementClient
	material *secrets.MaterialClient
	audienceResolver migrationSecretAudienceResolver
	mu sync.Mutex
}

type migrationSecretAuthority struct {
	ID secrets.ID `json:"id"`
	Owner secrets.ID `json:"owner"`
	Purpose secrets.Purpose `json:"purpose"`
	Audience secrets.AudienceBinding `json:"audience"`
}

type migrationSecretRow struct {
	digest, tenant, source, sourceInstallation, targetInstallation, manifestRoot, state string
	authority, envelope, metadata []byte
}

func newMigrationSecretTarget(ctx context.Context, db *sql.DB, scopes *migration.RuntimeScopeStore) (*migrationSecretTarget, error) {
	if ctx == nil || db == nil || scopes == nil { return nil, migration.ErrInvalid }
	repository, err := migration.NewSQLRepository(db)
	if err != nil { return nil, err }
	management, err := secrets.NewLocalManagementClient()
	if err != nil { return nil, err }
	material, err := secrets.NewLocalMaterialClient()
	if err != nil { return nil, err }
	if _, err := db.ExecContext(ctx, migrationTargetSecretSchema); err != nil { return nil, err }
	target := &migrationSecretTarget{db: db, scopes: scopes, repository: repository, management: management, material: material}
	target.audienceResolver = target.databaseAudience
	return target, nil
}

// Only the currently connected MariaDB principal consumer is admitted. Other
// purposes and credentials shared by several target principals need a typed
// consumer binding, not a permissive migration-wide secret audience.
func (target *migrationSecretTarget) databaseAudience(ctx context.Context, manifest migration.Manifest, plan migration.Plan, scope migration.RuntimeScope, envelope migration.SecretEnvelope) (secrets.ID, secrets.Purpose, secrets.AudienceBinding, error) {
	if err := ctx.Err(); err != nil { return "", "", secrets.AudienceBinding{}, err }
	if envelope.Purpose != "database-principal" { return "", "", secrets.AudienceBinding{}, migration.ErrBlocked }
	var principalID string
	for _, value := range manifest.Databases {
		for _, principal := range value.Principals {
			if principal.SecretID != envelope.SecretID { continue }
			if principalID != "" || principal.CredentialDisposition != migration.CredentialPreserved { return "", "", secrets.AudienceBinding{}, migration.ErrBlocked }
			var targetID migration.ID
			for _, mapping := range plan.Mappings {
				if mapping.SourceKind == string(migration.ImportDatabase) && mapping.SourceID == value.SourceID {
					if targetID != "" || mapping.Disposition != migration.DispositionCreate || !mapping.TargetID.Valid() { return "", "", secrets.AudienceBinding{}, migration.ErrBlocked }
					targetID = mapping.TargetID
				}
			}
			if targetID == "" { return "", "", secrets.AudienceBinding{}, migration.ErrBlocked }
			principalID = migration.DatabaseImportPrincipalID(manifest.MigrationID, targetID, principal.Name)
		}
	}
	if principalID == "" { return "", "", secrets.AudienceBinding{}, migration.ErrBlocked }
	release, err := webEngineExecutableDigest("/usr/local/libexec/cyberpanel/panel-execd")
	if err != nil { return "", "", secrets.AudienceBinding{}, err }
	return database.DatabaseTenantOwnerID(scope.TenantID), secrets.PurposeDatabase, secrets.AudienceBinding{
		AdapterID: database.MariaDBSecretAdapterID, AdapterVersion: database.MariaDBSecretAdapterVersion,
		Account: "local-mariadb", Origin: "local://panel-execd/mariadb", ResourceKind: "database_principal",
		ResourceID: database.DatabaseAudienceID(principalID), ResourceGeneration: 1,
		Operations: []secrets.Operation{secrets.OperationAuthenticate}, ConsumerReleaseDigest: release,
	}, nil
}

func migrationSecretDigest(value any) (string, []byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 2<<20 { return "", nil, migration.ErrInvalid }
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), raw, nil
}

func (target *migrationSecretTarget) approved(ctx context.Context, id migration.ID, envelope migration.SecretEnvelope) (migration.Manifest, migration.RuntimeScope, migrationSecretAuthority, error) {
	var authority migrationSecretAuthority
	if target.audienceResolver == nil { return migration.Manifest{}, migration.RuntimeScope{}, authority, migration.ErrBlocked }
	value, err := target.repository.Migration(ctx, id)
	if err != nil { return migration.Manifest{}, migration.RuntimeScope{}, authority, err }
	if value.Phase == migration.PhaseCanceled || value.Phase == migration.PhaseRolledBack || value.Phase == migration.PhaseRollingBack || value.Phase == migration.PhaseFailedTerminal || value.ManifestRoot == "" || value.PlanDigest == "" { return migration.Manifest{}, migration.RuntimeScope{}, authority, migration.ErrBlocked }
	scope, err := target.scopes.LoadByMigration(ctx, id)
	if err != nil { return migration.Manifest{}, scope, authority, err }
	manifest, err := target.repository.Manifest(ctx, value.ManifestRoot)
	if err != nil { return manifest, scope, authority, err }
	verifier, err := migrationTargetSecretVerifier()
	if err != nil { return manifest, scope, authority, err }
	if err := verifier.Verify(ctx, manifest); err != nil { return manifest, scope, authority, err }
	if manifest.MigrationID != id || manifest.Source != value.Source || (manifest.Source != migration.SourceCyberPanel && manifest.Source != migration.SourceCPanel && manifest.Source != migration.SourceCanonical) { return manifest, scope, authority, migration.ErrBlocked }
	digest, _, err := migrationSecretDigest(envelope)
	if err != nil { return manifest, scope, authority, err }
	matched := false
	for _, candidate := range manifest.Secrets {
		if candidate.SecretID != envelope.SecretID { continue }
		candidateDigest, _, err := migrationSecretDigest(candidate)
		if err != nil || candidateDigest != digest || matched { return manifest, scope, authority, migration.ErrConflict }
		matched = true
	}
	if !matched { return manifest, scope, authority, migration.ErrBlocked }
	plan, err := target.repository.Plan(ctx, value.PlanDigest)
	if err != nil || plan.MigrationID != id || plan.ApprovedAt == nil { return manifest, scope, authority, errors.Join(migration.ErrBlocked, err) }
	owner, purpose, audience, err := target.audienceResolver(ctx, manifest, plan, scope, envelope)
	if err != nil { return manifest, scope, authority, err }
	// Existing target consumers use either literal valid tenant IDs or the
	// shared tenant_<SHA256> projection. Neither admits installation ownership.
	tenantHash := sha256.Sum256([]byte("tenant\x00"+scope.TenantID))
	if scope.TenantID == "" || (owner != scopedSecretID("tenant", scope.TenantID) && owner != secrets.ID("tenant_"+hex.EncodeToString(tenantHash[:])[:48])) || audience.Validate() != nil { return manifest, scope, authority, migration.ErrBlocked }
	idHash := sha256.Sum256([]byte(manifest.TargetInstallationID+"\x00"+scope.TenantID+"\x00"+id.String()+"\x00"+envelope.SecretID))
	authority = migrationSecretAuthority{ID: secrets.ID("migsecret_"+hex.EncodeToString(idHash[:])[:48]), Owner: owner, Purpose: purpose, Audience: audience}
	return manifest, scope, authority, nil
}

func (target *migrationSecretTarget) ImportMigrationSecret(ctx context.Context, id migration.ID, envelope migration.SecretEnvelope) error {
	if target == nil || ctx == nil || !id.Valid() { return migration.ErrInvalid }
	target.mu.Lock()
	defer target.mu.Unlock()
	manifest, scope, authority, err := target.approved(ctx, id, envelope)
	if err != nil { return err }
	// Reject missing keys or unsupported credential representation before a
	// pending enrollment journal can require cancellation reconciliation.
	preflight, err := target.decrypt(ctx, id, manifest.TargetInstallationID, envelope)
	if err != nil { return err }
	authority, checkedMaterial, err := migrationSecretMaterial(string(manifest.Source), envelope.Purpose, preflight, authority)
	wipeBytes(preflight)
	wipeBytes(checkedMaterial)
	if err != nil { return err }
	digest, encodedEnvelope, err := migrationSecretDigest(envelope)
	if err != nil { return err }
	_, encodedAuthority, err := migrationSecretDigest(authority)
	if err != nil { return err }
	tx, err := target.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	var canceled int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_secret_cancellations WHERE migration_id=?`, id.String()).Scan(&canceled); err != nil { return err }
	if canceled != 0 { return migration.ErrBlocked }
	_, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_secret_bindings(migration_id,envelope_id,envelope_digest,tenant_id,source_kind,source_installation,target_installation,manifest_root,authority_json,envelope_json,metadata_json,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending') ON CONFLICT(migration_id,envelope_id) DO NOTHING`, id.String(), envelope.SecretID, digest, scope.TenantID, string(manifest.Source), manifest.SourceInstallationID, manifest.TargetInstallationID, manifest.MerkleRoot, encodedAuthority, encodedEnvelope, []byte{})
	if err != nil { return err }
	if err := tx.Commit(); err != nil { return err }
	row, err := target.load(ctx, id, envelope.SecretID)
	if err != nil { return err }
	if row.digest != digest || row.tenant != scope.TenantID || row.source != string(manifest.Source) || row.sourceInstallation != manifest.SourceInstallationID || row.targetInstallation != manifest.TargetInstallationID || !bytes.Equal(row.authority, encodedAuthority) { return migration.ErrConflict }
	if row.state != "pending" && row.state != "enrolled" { return migration.ErrBlocked }
	metadata, err := target.enroll(ctx, id, row, envelope, authority)
	if err != nil { return err }
	_, encodedMetadata, err := migrationSecretDigest(metadata)
	if err != nil { return err }
	if row.state == "enrolled" && !bytes.Equal(row.metadata, encodedMetadata) { return migration.ErrConflict }
	result, err := target.db.ExecContext(ctx, `UPDATE panel_migration_secret_bindings SET metadata_json=?,state='enrolled' WHERE migration_id=? AND envelope_id=? AND envelope_digest=? AND state IN ('pending','enrolled') AND NOT EXISTS(SELECT 1 FROM panel_migration_secret_cancellations WHERE migration_id=?)`, encodedMetadata, id.String(), envelope.SecretID, digest, id.String())
	if err != nil { return err }
	count, err := result.RowsAffected()
	if err != nil { return err }
	if count != 1 {
		// A concurrent cancellation owns the durable tombstone. Revocation is
		// best-effort here and remains replayable from the pending journal row.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if _, saveErr := target.db.ExecContext(cleanup, `UPDATE panel_migration_secret_bindings SET metadata_json=? WHERE migration_id=? AND envelope_id=? AND envelope_digest=? AND state!='revoked'`, encodedMetadata, id.String(), envelope.SecretID, digest); saveErr != nil { return errors.Join(migration.ErrAmbiguous, saveErr) }
		_, revokeErr := target.management.Revoke(cleanup, migrationSecretRevokeRequest(metadata))
		return errors.Join(migration.ErrBlocked, revokeErr)
	}
	return nil
}

func (target *migrationSecretTarget) enroll(ctx context.Context, id migration.ID, row migrationSecretRow, envelope migration.SecretEnvelope, authority migrationSecretAuthority) (secrets.Metadata, error) {
	plaintext, err := target.decrypt(ctx, id, row.targetInstallation, envelope)
	if err != nil { return secrets.Metadata{}, err }
	defer wipeBytes(plaintext)
	preparedAuthority, prepared, err := migrationSecretMaterial(row.source, envelope.Purpose, plaintext, authority)
	defer wipeBytes(prepared)
	if err != nil { return secrets.Metadata{}, err }
	if preparedAuthority.Audience.ResourceKind != authority.Audience.ResourceKind { return secrets.Metadata{}, migration.ErrConflict }
	metadata, err := target.management.PutExact(ctx, secrets.PutRequest{ID: authority.ID, OwnerTenantID: authority.Owner, Purpose: authority.Purpose, Audience: authority.Audience, Plaintext: prepared})
	if err != nil { return secrets.Metadata{}, err }
	if metadata.Validate() != nil || metadata.ID != authority.ID || metadata.OwnerTenantID != authority.Owner || metadata.Purpose != authority.Purpose || metadata.Version != 1 || metadata.State != secrets.StateActive { return secrets.Metadata{}, migration.ErrConflict }
	_, actual, err := migrationSecretDigest(metadata.Audience)
	_, expected, expectedErr := migrationSecretDigest(authority.Audience)
	if err != nil || expectedErr != nil || !bytes.Equal(actual, expected) { return secrets.Metadata{}, migration.ErrConflict }
	return metadata, nil
}

func (target *migrationSecretTarget) load(ctx context.Context, id migration.ID, envelopeID string) (migrationSecretRow, error) {
	var row migrationSecretRow
	err := target.db.QueryRowContext(ctx, `SELECT envelope_digest,tenant_id,source_kind,source_installation,target_installation,manifest_root,authority_json,envelope_json,metadata_json,state FROM panel_migration_secret_bindings WHERE migration_id=? AND envelope_id=?`, id.String(), envelopeID).
		Scan(&row.digest, &row.tenant, &row.source, &row.sourceInstallation, &row.targetInstallation, &row.manifestRoot, &row.authority, &row.envelope, &row.metadata, &row.state)
	if errors.Is(err, sql.ErrNoRows) { return row, migration.ErrNotFound }
	return row, err
}

// Resolve returns only a broker reference. Its consumer still needs the
// broker's one-time delivery grant for the exact typed resource audience.
func (target *migrationSecretTarget) Resolve(ctx context.Context, id migration.ID, envelopeID string) (secrets.Metadata, error) {
	if target == nil || ctx == nil || !id.Valid() { return secrets.Metadata{}, migration.ErrInvalid }
	target.mu.Lock()
	defer target.mu.Unlock()
	row, err := target.load(ctx, id, envelopeID)
	if err != nil { return secrets.Metadata{}, err }
	if row.state != "enrolled" { return secrets.Metadata{}, migration.ErrBlocked }
	var metadata secrets.Metadata
	if json.Unmarshal(row.metadata, &metadata) != nil || metadata.Validate() != nil { return secrets.Metadata{}, migration.ErrConflict }
	var envelope migration.SecretEnvelope
	if err := json.Unmarshal(row.envelope, &envelope); err != nil { return secrets.Metadata{}, migration.ErrInvalid }
	digest, _, err := migrationSecretDigest(envelope)
	if err != nil || digest != row.digest || envelope.SecretID != envelopeID { return secrets.Metadata{}, migration.ErrConflict }
	manifest, scope, authority, err := target.approved(ctx, id, envelope)
	if err != nil { return secrets.Metadata{}, err }
	if metadata.Audience.ResourceKind == "database_principal_native_hash" {
		if envelope.Purpose != "database-principal" || authority.Audience.ResourceKind != "database_principal" { return secrets.Metadata{}, migration.ErrBlocked }
		authority.Audience.ResourceKind = "database_principal_native_hash"
	}
	_, encodedAuthority, err := migrationSecretDigest(authority)
	if err != nil || row.tenant != scope.TenantID || row.source != string(manifest.Source) || row.sourceInstallation != manifest.SourceInstallationID || row.targetInstallation != manifest.TargetInstallationID || !bytes.Equal(row.authority, encodedAuthority) { return secrets.Metadata{}, migration.ErrConflict }
	var canceled int
	if err := target.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_secret_cancellations WHERE migration_id=?`, id.String()).Scan(&canceled); err != nil { return secrets.Metadata{}, err }
	if canceled != 0 { return secrets.Metadata{}, migration.ErrBlocked }
	if metadata.ID != authority.ID || metadata.OwnerTenantID != authority.Owner || metadata.Purpose != authority.Purpose || metadata.State != secrets.StateActive || metadata.Version != 1 { return secrets.Metadata{}, migration.ErrConflict }
	_, actualAudience, err := migrationSecretDigest(metadata.Audience)
	_, expectedAudience, expectedErr := migrationSecretDigest(authority.Audience)
	if err != nil || expectedErr != nil || !bytes.Equal(actualAudience, expectedAudience) { return secrets.Metadata{}, migration.ErrConflict }
	return metadata, nil
}

func migrationPasswordIsHash(value []byte) bool {
	if len(value) == 0 { return true }
	// MariaDB/MySQL, crypt, bcrypt and Argon strings are never passwords here.
	if value[0] == '*' || value[0] == '$' || bytes.HasPrefix(value, []byte("{SHA")) { return true }
	if len(value) == 16 || len(value) == 40 || len(value) == 64 {
		for _, char := range value { if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F') { return false } }
		return true
	}
	return false
}

func migrationSecretMaterial(source, purpose string, value []byte, authority migrationSecretAuthority) (migrationSecretAuthority, []byte, error) {
	if purpose != "database-principal" { return authority, append([]byte(nil), value...), nil }
	if authority.Purpose != secrets.PurposeDatabase || authority.Audience.AdapterID != database.MariaDBSecretAdapterID || authority.Audience.AdapterVersion != database.MariaDBSecretAdapterVersion || (authority.Audience.ResourceKind != "database_principal" && authority.Audience.ResourceKind != "database_principal_native_hash") { return authority, nil, migration.ErrBlocked }
	// Only the sealed typed marker attests plugin selection. A raw '*hash'
	// never becomes a credential merely because it resembles MySQL syntax.
	hash, err := database.DecodeNativePasswordHashCredential(value)
	defer wipeBytes(hash)
	if err == nil {
		encoded, err := database.EncodeNativePasswordHashCredential(hash)
		if err != nil { wipeBytes(encoded); return authority, nil, migration.ErrBlocked }
		authority.Audience.ResourceKind = "database_principal_native_hash"
		return authority, encoded, nil
	}
	if source == string(migration.SourceCyberPanel) || authority.Audience.ResourceKind == "database_principal_native_hash" || migrationPasswordIsHash(value) || bytes.IndexByte(value, 0) >= 0 {
		return authority, nil, errors.Join(migration.ErrBlocked, errors.New("database credential lacks a supported plugin-attested type; explicit reset required"))
	}
	return authority, append([]byte(nil), value...), nil
}

func migrationSecretRevokeRequest(metadata secrets.Metadata) secrets.RevokeRequest {
	return secrets.RevokeRequest{ID: metadata.ID, OwnerTenantID: metadata.OwnerTenantID, Purpose: metadata.Purpose, Audience: metadata.Audience, ExpectedVersion: metadata.Version, ExpectedBindingDigest: metadata.BindingDigest}
}

func (target *migrationSecretTarget) RevokeMigrationSecrets(ctx context.Context, id migration.ID) error {
	if target == nil || ctx == nil || !id.Valid() { return migration.ErrInvalid }
	target.mu.Lock()
	defer target.mu.Unlock()
	scope, err := target.scopes.LoadByMigration(ctx, id)
	if err != nil { return err }
	if _, err := target.db.ExecContext(ctx, `INSERT INTO panel_migration_secret_cancellations(migration_id,canceled_at) VALUES(?,?) ON CONFLICT(migration_id) DO NOTHING`, id.String(), time.Now().UTC().Format(time.RFC3339Nano)); err != nil { return err }
	rows, err := target.db.QueryContext(ctx, `SELECT envelope_id FROM panel_migration_secret_bindings WHERE migration_id=? AND state!='revoked' ORDER BY envelope_id`, id.String())
	if err != nil { return err }
	var identifiers []string
	for rows.Next() {
		var identifier string
		if err := rows.Scan(&identifier); err != nil { rows.Close(); return err }
		identifiers = append(identifiers, identifier)
		if len(identifiers) > 100000 { rows.Close(); return migration.ErrCapacity }
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil { return err }
	for _, identifier := range identifiers {
		row, err := target.load(ctx, id, identifier)
		if err != nil { return err }
		if row.tenant != scope.TenantID { return migration.ErrConflict }
		if _, err := target.db.ExecContext(ctx, `UPDATE panel_migration_secret_bindings SET state='revoking' WHERE migration_id=? AND envelope_id=? AND state!='revoked'`, id.String(), identifier); err != nil { return err }
		var metadata secrets.Metadata
		if len(row.metadata) == 0 {
			// Recover a broker commit whose response or local receipt was lost.
			// If no enrollment happened, exact-create followed by revoke safely
			// closes that race too; a missing key remains a visible cleanup error.
			var envelope migration.SecretEnvelope
			var authority migrationSecretAuthority
			if json.Unmarshal(row.envelope, &envelope) != nil || json.Unmarshal(row.authority, &authority) != nil { return migration.ErrInvalid }
			digest, _, err := migrationSecretDigest(envelope)
			if err != nil || digest != row.digest { return migration.ErrConflict }
			metadata, err = target.enroll(ctx, id, row, envelope, authority)
			if err != nil { return err }
			_, encoded, err := migrationSecretDigest(metadata)
			if err != nil { return err }
			if _, err := target.db.ExecContext(ctx, `UPDATE panel_migration_secret_bindings SET metadata_json=? WHERE migration_id=? AND envelope_id=? AND state='revoking'`, encoded, id.String(), identifier); err != nil { return err }
		} else if json.Unmarshal(row.metadata, &metadata) != nil || metadata.Validate() != nil { return migration.ErrInvalid }
		if _, err := target.management.Revoke(ctx, migrationSecretRevokeRequest(metadata)); err != nil { return err }
		if _, err := target.db.ExecContext(ctx, `UPDATE panel_migration_secret_bindings SET state='revoked',envelope_json=?,metadata_json=? WHERE migration_id=? AND envelope_id=? AND state='revoking'`, []byte{}, []byte{}, id.String(), identifier); err != nil { return err }
	}
	return nil
}

// The existing broker owns the target's X25519 private key. Provision exactly
// 32 raw bytes under this target+key-ID record, installation ownership,
// PurposeFederation, AdapterID cyberpanel.migration / version 1, operation
// decrypt, and ResourceID equal to the record ID. Pin ConsumerReleaseDigest to
// panel-core. Key generation/distribution is deliberately not inferred here.
func migrationTargetSealingKeyID(targetInstallation, keyID string) secrets.ID {
	sum := sha256.Sum256([]byte(targetInstallation+"\x00"+keyID))
	return secrets.ID("migration_key_"+hex.EncodeToString(sum[:])[:48])
}

func (target *migrationSecretTarget) decrypt(ctx context.Context, id migration.ID, installation string, envelope migration.SecretEnvelope) ([]byte, error) {
	if installation == "" || envelope.KeyID == "" || envelope.Algorithm != "X25519-HKDF-SHA256-AES-256-GCM" || envelope.Version != 1 || len(envelope.EncapsulatedKey) != 32 || len(envelope.Ciphertext) < 29 || len(envelope.Ciphertext) > (900<<10)+28 || len(envelope.AudienceDigest) != 64 { return nil, migration.ErrInvalid }
	keyID := migrationTargetSealingKeyID(installation, envelope.KeyID)
	response, err := target.material.Read(ctx, secrets.MaterialRequest{SecretID: keyID, OwnerTenantID: secrets.ID("installation"), Purpose: secrets.PurposeFederation, Operation: secrets.OperationDecrypt, AdapterID: "cyberpanel.migration", AdapterVersion: "1", ResourceID: keyID})
	if err != nil { return nil, errors.Join(migration.ErrBlocked, err) }
	defer wipeBytes(response.Material)
	if len(response.Material) != 32 { return nil, migration.ErrInvalid }
	key, err := ecdh.X25519().NewPrivateKey(response.Material)
	if err != nil { return nil, migration.ErrInvalid }
	peer, err := ecdh.X25519().NewPublicKey(envelope.EncapsulatedKey)
	if err != nil { return nil, migration.ErrInvalid }
	shared, err := key.ECDH(peer)
	if err != nil { return nil, migration.ErrInvalid }
	defer wipeBytes(shared)
	// Exact inverse of cyberpanel.X25519Sealer, including its domain, AAD,
	// HKDF salt/info, and nonce prefix; this is not a second envelope protocol.
	salt := sha256.Sum256([]byte("cyberpanel-migration-secret-v1\x00"+id.String()+"\x00"+envelope.AudienceDigest))
	extract := hmac.New(sha256.New, salt[:])
	extract.Write(shared)
	prk := extract.Sum(nil)
	defer wipeBytes(prk)
	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte(envelope.Purpose+"\x00"+envelope.SecretID))
	expand.Write([]byte{1})
	derived := expand.Sum(nil)
	defer wipeBytes(derived)
	block, err := aes.NewCipher(derived)
	if err != nil { return nil, migration.ErrInvalid }
	aead, err := cipher.NewGCM(block)
	if err != nil { return nil, migration.ErrInvalid }
	aad, err := json.Marshal(struct {
		Domain string `json:"domain"`; MigrationID string `json:"migration_id"`; SecretID string `json:"secret_id"`
		Purpose string `json:"purpose"`; AudienceDigest string `json:"audience_digest"`; KeyID string `json:"key_id"`
	}{"cyberpanel-migration-secret-v1", id.String(), envelope.SecretID, envelope.Purpose, envelope.AudienceDigest, envelope.KeyID})
	if err != nil { return nil, migration.ErrInvalid }
	plaintext, err := aead.Open(nil, envelope.Ciphertext[:aead.NonceSize()], envelope.Ciphertext[aead.NonceSize():], aad)
	if err != nil || len(plaintext) == 0 || len(plaintext) > 900<<10 { wipeBytes(plaintext); return nil, migration.ErrBlocked }
	return plaintext, nil
}

func migrationTargetSecretVerifier() (*migration.SignedManifestVerifier, error) {
	const path = "/etc/cyberpanel/migration/trust.json"
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil { return nil, err }
	defer file.Close()
	before, err := file.Stat()
	if err != nil { return nil, err }
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 || (stat.Uid != 0 && int(stat.Uid) != os.Geteuid()) || stat.Nlink != 1 || before.Size() < 1 || before.Size() > 1<<20 { return nil, migration.ErrBlocked }
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil { return nil, err }
	after, err := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Size() != after.Size() || before.Size() != int64(len(raw)) || !before.ModTime().Equal(after.ModTime()) { return nil, migration.ErrConflict }
	var document struct { TargetInstallationID string `json:"target_installation_id"`; SchemaHashes []string `json:"schema_hashes"`; ManifestKeys map[string]string `json:"manifest_keys"` }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF { return nil, migration.ErrInvalid }
	policy := migration.ManifestTrustPolicy{TargetInstallationID: document.TargetInstallationID, Keys: map[string]ed25519.PublicKey{}, SchemaHashes: map[string]struct{}{}}
	for _, hash := range document.SchemaHashes { policy.SchemaHashes[strings.ToLower(strings.TrimSpace(hash))] = struct{}{} }
	for id, text := range document.ManifestKeys {
		key, err := hex.DecodeString(strings.TrimSpace(text))
		if err != nil || len(key) != ed25519.PublicKeySize { return nil, migration.ErrInvalid }
		policy.Keys[id] = ed25519.PublicKey(key)
	}
	return migration.NewSignedManifestVerifier(policy)
}

var _ migration.MigrationSecretGateway = (*migrationSecretTarget)(nil)
