package certificates

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const materialRepositorySchema = `
CREATE TABLE IF NOT EXISTS managed_certificate_material_v1 (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    certificate_generation INTEGER NOT NULL,
    record_generation INTEGER NOT NULL,
    source TEXT NOT NULL,
    state TEXT NOT NULL,
    leaf_fingerprint_sha256 TEXT NOT NULL UNIQUE,
    identity_digest TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    material_json BLOB NOT NULL,
    UNIQUE (tenant_id, resource_id, certificate_generation)
);
CREATE INDEX IF NOT EXISTS managed_certificate_material_scope_v1
    ON managed_certificate_material_v1 (tenant_id, resource_id, created_at, id);
CREATE TABLE IF NOT EXISTS managed_certificate_material_idempotency_v1 (
    tenant_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    material_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, resource_id, operation, idempotency_key)
);`

type MaterialRepository struct {
	DB *sql.DB
}

type MaterialOperationalUpdate struct {
	ExpectedRecordGeneration uint64
	State                    MaterialLifecycleState
	Consumers                []MaterialConsumerBinding
	LastDeployment           *MaterialDeploymentResult
	ObservedAt               time.Time
}

type materialListCursor struct {
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

func (repository MaterialRepository) Bootstrap(ctx context.Context) error {
	if repository.DB == nil || ctx == nil {
		return ErrMaterialInvalid
	}
	_, err := repository.DB.ExecContext(ctx, materialRepositorySchema)
	return err
}

func (repository MaterialRepository) ResolveIdempotency(ctx context.Context, tenantID, resourceID, operation, key, requestDigest string) (ManagedCertificateGeneration, bool, error) {
	if repository.DB == nil || ctx == nil || !validMaterialIdentifier(tenantID) || !validMaterialIdentifier(resourceID) ||
		!validMaterialOperation(operation) || !validMaterialIdempotencyKey(key) || !validSHA256Hex(requestDigest) {
		return ManagedCertificateGeneration{}, false, ErrMaterialInvalid
	}
	var storedDigest, materialID string
	err := repository.DB.QueryRowContext(ctx, `SELECT request_digest, material_id
        FROM managed_certificate_material_idempotency_v1
        WHERE tenant_id=? AND resource_id=? AND operation=? AND idempotency_key=?`,
		tenantID, resourceID, operation, key).Scan(&storedDigest, &materialID)
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedCertificateGeneration{}, false, nil
	}
	if err != nil {
		return ManagedCertificateGeneration{}, false, err
	}
	if storedDigest != requestDigest {
		return ManagedCertificateGeneration{}, false, ErrMaterialConflict
	}
	generation, err := repository.Get(ctx, tenantID, resourceID, materialID)
	if err != nil {
		return ManagedCertificateGeneration{}, false, errors.Join(ErrMaterialAmbiguous, err)
	}
	return generation, true, nil
}

// PreflightCreate is advisory; CreateCAS repeats every ownership, duplicate,
// idempotency, and generation check inside the metadata transaction.
func (repository MaterialRepository) PreflightCreate(ctx context.Context, tenantID, resourceID, fingerprint string, expectedLatest uint64) error {
	if repository.DB == nil || ctx == nil || !validMaterialIdentifier(tenantID) || !validMaterialIdentifier(resourceID) || !validSHA256Hex(fingerprint) {
		return ErrMaterialInvalid
	}
	latest, err := materialLatestGeneration(ctx, repository.DB, tenantID, resourceID)
	if err != nil {
		return err
	}
	if latest != expectedLatest {
		return ErrMaterialConflict
	}
	return materialCheckFingerprintOwner(ctx, repository.DB, tenantID, resourceID, fingerprint)
}

func (repository MaterialRepository) PreflightGeneration(ctx context.Context, tenantID, resourceID string, expectedLatest uint64) error {
	if repository.DB == nil || ctx == nil || !validMaterialIdentifier(tenantID) || !validMaterialIdentifier(resourceID) {
		return ErrMaterialInvalid
	}
	latest, err := materialLatestGeneration(ctx, repository.DB, tenantID, resourceID)
	if err != nil {
		return err
	}
	if latest != expectedLatest {
		return ErrMaterialConflict
	}
	return nil
}

func (repository MaterialRepository) CreateCAS(ctx context.Context, generation ManagedCertificateGeneration, expectedLatest uint64, operation, idempotencyKey, requestDigest string) (ManagedCertificateGeneration, bool, error) {
	if repository.DB == nil || ctx == nil || !validMaterialOperation(operation) || !validMaterialIdempotencyKey(idempotencyKey) ||
		!validSHA256Hex(requestDigest) || generation.CertificateGeneration != expectedLatest+1 {
		return ManagedCertificateGeneration{}, false, ErrMaterialInvalid
	}
	if err := verifySealedManagedCertificateGeneration(generation); err != nil {
		return ManagedCertificateGeneration{}, false, err
	}
	tx, err := repository.DB.BeginTx(ctx, nil)
	if err != nil {
		return ManagedCertificateGeneration{}, false, err
	}
	defer tx.Rollback()
	prior, found, err := resolveMaterialIdempotencyTx(ctx, tx, generation.TenantID, generation.ResourceID, operation, idempotencyKey, requestDigest)
	if err != nil || found {
		return prior, false, err
	}
	latest, err := materialLatestGeneration(ctx, tx, generation.TenantID, generation.ResourceID)
	if err != nil {
		return ManagedCertificateGeneration{}, false, err
	}
	if latest != expectedLatest {
		return ManagedCertificateGeneration{}, false, ErrMaterialConflict
	}
	if err = materialCheckFingerprintOwner(ctx, tx, generation.TenantID, generation.ResourceID, generation.LeafFingerprintSHA256); err != nil {
		return ManagedCertificateGeneration{}, false, err
	}
	encoded, err := json.Marshal(generation)
	if err != nil || len(encoded) == 0 || len(encoded) > MaximumMaterialPEMBytes*2 {
		return ManagedCertificateGeneration{}, false, ErrMaterialInvalid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO managed_certificate_material_v1
        (id,tenant_id,resource_id,certificate_generation,record_generation,source,state,leaf_fingerprint_sha256,
         identity_digest,record_digest,created_at,updated_at,material_json)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		generation.ID, generation.TenantID, generation.ResourceID, generation.CertificateGeneration, generation.RecordGeneration,
		generation.Source, generation.State, generation.LeafFingerprintSHA256, generation.IdentityDigest, generation.RecordDigest,
		materialTimeText(generation.CreatedAt), materialTimeText(generation.UpdatedAt), encoded)
	if err != nil {
		if ownerErr := materialCheckFingerprintOwner(ctx, tx, generation.TenantID, generation.ResourceID, generation.LeafFingerprintSHA256); ownerErr != nil {
			return ManagedCertificateGeneration{}, false, ownerErr
		}
		return ManagedCertificateGeneration{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO managed_certificate_material_idempotency_v1
        (tenant_id,resource_id,operation,idempotency_key,request_digest,material_id,created_at)
        VALUES(?,?,?,?,?,?,?)`, generation.TenantID, generation.ResourceID, operation, idempotencyKey, requestDigest, generation.ID, materialTimeText(generation.CreatedAt))
	if err != nil {
		prior, found, resolveErr := resolveMaterialIdempotencyTx(ctx, tx, generation.TenantID, generation.ResourceID, operation, idempotencyKey, requestDigest)
		if resolveErr != nil {
			return ManagedCertificateGeneration{}, false, resolveErr
		}
		if found {
			return prior, false, nil
		}
		return ManagedCertificateGeneration{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return ManagedCertificateGeneration{}, false, errors.Join(ErrMaterialAmbiguous, err)
	}
	return generation, true, nil
}

func (repository MaterialRepository) Get(ctx context.Context, tenantID, resourceID, materialID string) (ManagedCertificateGeneration, error) {
	if repository.DB == nil || ctx == nil || !validMaterialIdentifier(tenantID) || !validMaterialIdentifier(resourceID) || !validMaterialIdentifier(materialID) {
		return ManagedCertificateGeneration{}, ErrMaterialInvalid
	}
	generation, err := getManagedMaterial(ctx, repository.DB, tenantID, resourceID, materialID)
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedCertificateGeneration{}, ErrMaterialNotFound
	}
	return generation, err
}

func (repository MaterialRepository) List(ctx context.Context, tenantID, resourceID, cursor string, limit int) ([]ManagedCertificateGeneration, string, error) {
	if repository.DB == nil || ctx == nil || !validMaterialIdentifier(tenantID) || (resourceID != "" && !validMaterialIdentifier(resourceID)) ||
		limit < 1 || limit > MaximumMaterialListLimit {
		return nil, "", ErrMaterialInvalid
	}
	after, err := decodeMaterialListCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	query := `SELECT id,tenant_id,resource_id,certificate_generation,record_generation,source,state,
        leaf_fingerprint_sha256,identity_digest,record_digest,created_at,updated_at,material_json
        FROM managed_certificate_material_v1
        WHERE tenant_id=? AND (created_at>? OR (created_at=? AND id>?))`
	arguments := []any{tenantID, after.CreatedAt, after.CreatedAt, after.ID}
	if resourceID != "" {
		query += ` AND resource_id=?`
		arguments = append(arguments, resourceID)
	}
	query += ` ORDER BY created_at,id LIMIT ?`
	arguments = append(arguments, limit+1)
	rows, err := repository.DB.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]ManagedCertificateGeneration, 0, limit+1)
	created := make([]string, 0, limit+1)
	for rows.Next() {
		generation, createdAt, scanErr := scanManagedMaterial(rows)
		if scanErr != nil {
			return nil, "", scanErr
		}
		items = append(items, generation)
		created = append(created, createdAt)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > limit {
		last := items[limit-1]
		next, err = encodeMaterialListCursor(materialListCursor{CreatedAt: created[limit-1], ID: last.ID})
		if err != nil {
			return nil, "", err
		}
		items = items[:limit]
	}
	return items, next, nil
}

func (repository MaterialRepository) UpdateOperationalCAS(ctx context.Context, tenantID, resourceID, materialID string, update MaterialOperationalUpdate) (ManagedCertificateGeneration, error) {
	if repository.DB == nil || ctx == nil || !validMaterialIdentifier(tenantID) || !validMaterialIdentifier(resourceID) ||
		!validMaterialIdentifier(materialID) || update.ExpectedRecordGeneration == 0 || update.ObservedAt.IsZero() ||
		len(update.Consumers) > MaximumMaterialConsumers {
		return ManagedCertificateGeneration{}, ErrMaterialInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, nil)
	if err != nil {
		return ManagedCertificateGeneration{}, err
	}
	defer tx.Rollback()
	generation, err := getManagedMaterial(ctx, tx, tenantID, resourceID, materialID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ManagedCertificateGeneration{}, ErrMaterialNotFound
		}
		return ManagedCertificateGeneration{}, err
	}
	if generation.RecordGeneration != update.ExpectedRecordGeneration || generation.State == MaterialStateRetired {
		return ManagedCertificateGeneration{}, ErrMaterialConflict
	}
	identityDigest := generation.IdentityDigest
	generation.RecordGeneration++
	generation.State = update.State
	generation.Consumers = append([]MaterialConsumerBinding(nil), update.Consumers...)
	if update.LastDeployment == nil {
		generation.LastDeployment = nil
	} else {
		copy := *update.LastDeployment
		generation.LastDeployment = &copy
	}
	generation.UpdatedAt = update.ObservedAt.UTC()
	if err = sealManagedCertificateGeneration(&generation); err != nil || generation.IdentityDigest != identityDigest {
		return ManagedCertificateGeneration{}, ErrMaterialInvalid
	}
	if err = updateManagedMaterialTx(ctx, tx, generation, update.ExpectedRecordGeneration); err != nil {
		return ManagedCertificateGeneration{}, err
	}
	if err = tx.Commit(); err != nil {
		return ManagedCertificateGeneration{}, errors.Join(ErrMaterialAmbiguous, err)
	}
	return generation, nil
}

func (repository MaterialRepository) RetireCAS(ctx context.Context, tenantID, resourceID, materialID, idempotencyKey, requestDigest string, expectedRecordGeneration uint64, now time.Time) (ManagedCertificateGeneration, bool, error) {
	if repository.DB == nil || ctx == nil || !validMaterialIdentifier(tenantID) || !validMaterialIdentifier(resourceID) ||
		!validMaterialIdentifier(materialID) || !validMaterialIdempotencyKey(idempotencyKey) || !validSHA256Hex(requestDigest) ||
		expectedRecordGeneration == 0 || now.IsZero() {
		return ManagedCertificateGeneration{}, false, ErrMaterialInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, nil)
	if err != nil {
		return ManagedCertificateGeneration{}, false, err
	}
	defer tx.Rollback()
	prior, found, err := resolveMaterialIdempotencyTx(ctx, tx, tenantID, resourceID, "retire", idempotencyKey, requestDigest)
	if err != nil || found {
		return prior, found, err
	}
	generation, err := getManagedMaterial(ctx, tx, tenantID, resourceID, materialID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ManagedCertificateGeneration{}, false, ErrMaterialNotFound
		}
		return ManagedCertificateGeneration{}, false, err
	}
	if generation.RecordGeneration != expectedRecordGeneration {
		return ManagedCertificateGeneration{}, false, ErrMaterialConflict
	}
	if !generation.RetirementEligibility().Eligible {
		return ManagedCertificateGeneration{}, false, ErrMaterialNotRetirable
	}
	identityDigest := generation.IdentityDigest
	generation.State = MaterialStateRetired
	generation.RecordGeneration++
	generation.RetiredAt = now.UTC()
	generation.UpdatedAt = now.UTC()
	if err = sealManagedCertificateGeneration(&generation); err != nil || generation.IdentityDigest != identityDigest {
		return ManagedCertificateGeneration{}, false, ErrMaterialInvalid
	}
	if err = updateManagedMaterialTx(ctx, tx, generation, expectedRecordGeneration); err != nil {
		return ManagedCertificateGeneration{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO managed_certificate_material_idempotency_v1
        (tenant_id,resource_id,operation,idempotency_key,request_digest,material_id,created_at)
        VALUES(?,?,?,?,?,?,?)`, tenantID, resourceID, "retire", idempotencyKey, requestDigest, materialID, materialTimeText(now))
	if err != nil {
		return ManagedCertificateGeneration{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return ManagedCertificateGeneration{}, false, errors.Join(ErrMaterialAmbiguous, err)
	}
	return generation, false, nil
}

func NewManagedMaterialID(tenantID, resourceID, fingerprint string) (string, error) {
	if !validMaterialIdentifier(tenantID) || !validMaterialIdentifier(resourceID) || !validSHA256Hex(fingerprint) {
		return "", ErrMaterialInvalid
	}
	sum := sha256.Sum256([]byte("managed-certificate-material-v1\x00" + tenantID + "\x00" + resourceID + "\x00" + fingerprint))
	return "material_" + hex.EncodeToString(sum[:])[:48], nil
}

type materialSQLQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type materialSQLScanner interface {
	Scan(...any) error
}

func materialLatestGeneration(ctx context.Context, query materialSQLQuerier, tenantID, resourceID string) (uint64, error) {
	var latest sql.NullInt64
	err := query.QueryRowContext(ctx, `SELECT MAX(certificate_generation) FROM managed_certificate_material_v1 WHERE tenant_id=? AND resource_id=?`, tenantID, resourceID).Scan(&latest)
	if err != nil {
		return 0, err
	}
	if !latest.Valid {
		return 0, nil
	}
	if latest.Int64 < 0 {
		return 0, ErrMaterialInvalid
	}
	return uint64(latest.Int64), nil
}

func materialCheckFingerprintOwner(ctx context.Context, query materialSQLQuerier, tenantID, resourceID, fingerprint string) error {
	var ownerTenant, ownerResource string
	err := query.QueryRowContext(ctx, `SELECT tenant_id,resource_id FROM managed_certificate_material_v1 WHERE leaf_fingerprint_sha256=?`, fingerprint).Scan(&ownerTenant, &ownerResource)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if ownerTenant != tenantID || ownerResource != resourceID {
		return ErrMaterialOwnership
	}
	return ErrMaterialDuplicate
}

func resolveMaterialIdempotencyTx(ctx context.Context, tx *sql.Tx, tenantID, resourceID, operation, key, requestDigest string) (ManagedCertificateGeneration, bool, error) {
	var storedDigest, materialID string
	err := tx.QueryRowContext(ctx, `SELECT request_digest,material_id FROM managed_certificate_material_idempotency_v1
        WHERE tenant_id=? AND resource_id=? AND operation=? AND idempotency_key=?`, tenantID, resourceID, operation, key).Scan(&storedDigest, &materialID)
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedCertificateGeneration{}, false, nil
	}
	if err != nil {
		return ManagedCertificateGeneration{}, false, err
	}
	if storedDigest != requestDigest {
		return ManagedCertificateGeneration{}, false, ErrMaterialConflict
	}
	generation, err := getManagedMaterial(ctx, tx, tenantID, resourceID, materialID)
	if err != nil {
		return ManagedCertificateGeneration{}, false, errors.Join(ErrMaterialAmbiguous, err)
	}
	return generation, true, nil
}

func getManagedMaterial(ctx context.Context, query materialSQLQuerier, tenantID, resourceID, materialID string) (ManagedCertificateGeneration, error) {
	row := query.QueryRowContext(ctx, `SELECT id,tenant_id,resource_id,certificate_generation,record_generation,source,state,
        leaf_fingerprint_sha256,identity_digest,record_digest,created_at,updated_at,material_json
        FROM managed_certificate_material_v1 WHERE tenant_id=? AND resource_id=? AND id=?`, tenantID, resourceID, materialID)
	generation, _, err := scanManagedMaterial(row)
	return generation, err
}

func scanManagedMaterial(scanner materialSQLScanner) (ManagedCertificateGeneration, string, error) {
	var id, tenantID, resourceID, source, state, fingerprint, identityDigest, recordDigest, createdAt, updatedAt string
	var certificateGeneration, recordGeneration uint64
	var encoded []byte
	err := scanner.Scan(&id, &tenantID, &resourceID, &certificateGeneration, &recordGeneration, &source, &state,
		&fingerprint, &identityDigest, &recordDigest, &createdAt, &updatedAt, &encoded)
	if err != nil {
		return ManagedCertificateGeneration{}, "", err
	}
	if len(encoded) == 0 || len(encoded) > MaximumMaterialPEMBytes*2 {
		return ManagedCertificateGeneration{}, "", ErrMaterialInvalid
	}
	var generation ManagedCertificateGeneration
	if json.Unmarshal(encoded, &generation) != nil || generation.ID != id || generation.TenantID != tenantID || generation.ResourceID != resourceID ||
		generation.CertificateGeneration != certificateGeneration || generation.RecordGeneration != recordGeneration || string(generation.Source) != source ||
		string(generation.State) != state || generation.LeafFingerprintSHA256 != fingerprint || generation.IdentityDigest != identityDigest ||
		generation.RecordDigest != recordDigest || materialTimeText(generation.CreatedAt) != createdAt || materialTimeText(generation.UpdatedAt) != updatedAt {
		return ManagedCertificateGeneration{}, "", ErrMaterialInvalid
	}
	if err = verifySealedManagedCertificateGeneration(generation); err != nil {
		return ManagedCertificateGeneration{}, "", err
	}
	return generation, createdAt, nil
}

func verifySealedManagedCertificateGeneration(generation ManagedCertificateGeneration) error {
	identityDigest := generation.IdentityDigest
	recordDigest := generation.RecordDigest
	copy := generation
	if err := sealManagedCertificateGeneration(&copy); err != nil {
		return err
	}
	if copy.IdentityDigest != identityDigest || copy.RecordDigest != recordDigest {
		return ErrMaterialInvalid
	}
	return nil
}

func updateManagedMaterialTx(ctx context.Context, tx *sql.Tx, generation ManagedCertificateGeneration, expectedRecordGeneration uint64) error {
	encoded, err := json.Marshal(generation)
	if err != nil || len(encoded) == 0 || len(encoded) > MaximumMaterialPEMBytes*2 {
		return ErrMaterialInvalid
	}
	result, err := tx.ExecContext(ctx, `UPDATE managed_certificate_material_v1 SET
        record_generation=?,state=?,record_digest=?,updated_at=?,material_json=?
        WHERE id=? AND tenant_id=? AND resource_id=? AND record_generation=? AND identity_digest=?`,
		generation.RecordGeneration, generation.State, generation.RecordDigest, materialTimeText(generation.UpdatedAt), encoded,
		generation.ID, generation.TenantID, generation.ResourceID, expectedRecordGeneration, generation.IdentityDigest)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrMaterialConflict
	}
	return nil
}

func encodeMaterialListCursor(cursor materialListCursor) (string, error) {
	if cursor.CreatedAt == "" || !validMaterialIdentifier(cursor.ID) {
		return "", ErrMaterialInvalid
	}
	if _, err := time.Parse(time.RFC3339Nano, cursor.CreatedAt); err != nil {
		return "", ErrMaterialInvalid
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeMaterialListCursor(value string) (materialListCursor, error) {
	if value == "" {
		return materialListCursor{}, nil
	}
	if len(value) > 512 {
		return materialListCursor{}, ErrMaterialInvalid
	}
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(encoded) > 384 {
		return materialListCursor{}, ErrMaterialInvalid
	}
	var cursor materialListCursor
	if json.Unmarshal(encoded, &cursor) != nil || cursor.CreatedAt == "" || !validMaterialIdentifier(cursor.ID) {
		return materialListCursor{}, ErrMaterialInvalid
	}
	parsed, err := time.Parse(time.RFC3339Nano, cursor.CreatedAt)
	if err != nil || materialTimeText(parsed) != cursor.CreatedAt {
		return materialListCursor{}, ErrMaterialInvalid
	}
	return cursor, nil
}

func materialTimeText(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func validMaterialOperation(value string) bool {
	return value == "import" || value == "self_signed" || value == "retire"
}

func validMaterialIdempotencyKey(value string) bool {
	return len(value) >= 8 && len(value) <= 192 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}
