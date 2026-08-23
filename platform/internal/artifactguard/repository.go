package artifactguard

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	MaximumListArtifacts = 500
	MaximumGrantPage     = 200
)

type SQLiteRepository struct {
	db *sql.DB
}

func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: nil database", ErrInvalid)
	}
	return &SQLiteRepository{db: db}, nil
}

func (r *SQLiteRepository) Initialize(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS artifactguard_artifacts (
			tenant_id TEXT NOT NULL,
			artifact_id TEXT NOT NULL,
			node_id TEXT NOT NULL,
			object_id TEXT NOT NULL,
			source_kind TEXT NOT NULL,
			source_id TEXT NOT NULL,
			source_generation INTEGER NOT NULL,
			generation INTEGER NOT NULL,
			lifecycle TEXT NOT NULL,
			retention_state TEXT NOT NULL,
			retain_until_ns INTEGER NOT NULL,
			legal_hold_id TEXT NOT NULL,
			digest TEXT NOT NULL,
			body BLOB NOT NULL,
			created_at_ns INTEGER NOT NULL,
			updated_at_ns INTEGER NOT NULL,
			PRIMARY KEY (tenant_id, artifact_id),
			UNIQUE (tenant_id, object_id)
		)`,
		`CREATE INDEX IF NOT EXISTS artifactguard_artifacts_created
			ON artifactguard_artifacts (tenant_id, created_at_ns, artifact_id)`,
		`CREATE INDEX IF NOT EXISTS artifactguard_artifacts_retention
			ON artifactguard_artifacts (tenant_id, retention_state, retain_until_ns, artifact_id)`,
		`CREATE TABLE IF NOT EXISTS artifactguard_holds (
			tenant_id TEXT NOT NULL,
			hold_id TEXT NOT NULL,
			artifact_id TEXT NOT NULL,
			generation INTEGER NOT NULL,
			state TEXT NOT NULL,
			digest TEXT NOT NULL,
			body BLOB NOT NULL,
			created_at_ns INTEGER NOT NULL,
			updated_at_ns INTEGER NOT NULL,
			PRIMARY KEY (tenant_id, hold_id),
			FOREIGN KEY (tenant_id, artifact_id)
				REFERENCES artifactguard_artifacts (tenant_id, artifact_id)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS artifactguard_holds_active
			ON artifactguard_holds (tenant_id, artifact_id)
			WHERE state = 'active'`,
		`CREATE TABLE IF NOT EXISTS artifactguard_grants (
			tenant_id TEXT NOT NULL,
			grant_id TEXT NOT NULL,
			artifact_id TEXT NOT NULL,
			audience_principal TEXT NOT NULL,
			operation TEXT NOT NULL,
			generation INTEGER NOT NULL,
			state TEXT NOT NULL,
			expires_at_ns INTEGER NOT NULL,
			consumed_at_ns INTEGER NOT NULL,
			digest TEXT NOT NULL,
			body BLOB NOT NULL,
			issued_at_ns INTEGER NOT NULL,
			PRIMARY KEY (tenant_id, grant_id),
			FOREIGN KEY (tenant_id, artifact_id)
				REFERENCES artifactguard_artifacts (tenant_id, artifact_id)
		)`,
		`CREATE INDEX IF NOT EXISTS artifactguard_grants_audience
			ON artifactguard_grants (tenant_id, audience_principal, issued_at_ns, grant_id)`,
		`CREATE TABLE IF NOT EXISTS artifactguard_deletion_receipts (
			tenant_id TEXT NOT NULL,
			receipt_id TEXT NOT NULL,
			artifact_id TEXT NOT NULL,
			object_id TEXT NOT NULL,
			digest TEXT NOT NULL,
			body BLOB NOT NULL,
			completed_at_ns INTEGER NOT NULL,
			PRIMARY KEY (tenant_id, receipt_id),
			UNIQUE (tenant_id, artifact_id),
			UNIQUE (tenant_id, object_id)
		)`,
	}
	for _, statement := range statements {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("artifactguard: initialize repository: %w", err)
		}
	}
	return nil
}

func (r *SQLiteRepository) CreateArtifact(ctx context.Context, artifact Artifact) (Artifact, error) {
	sealed, err := SealArtifact(artifact)
	if err != nil {
		return Artifact{}, err
	}
	if sealed.Lifecycle != LifecycleStaging || sealed.Generation != 1 ||
		sealed.ObjectGeneration != 0 || sealed.ObjectDigest != "" {
		return Artifact{}, fmt.Errorf("%w: initial artifact state", ErrInvalid)
	}
	body, err := json.Marshal(sealed)
	if err != nil {
		return Artifact{}, fmt.Errorf("%w: encode artifact", ErrInvalid)
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO artifactguard_artifacts (
		tenant_id, artifact_id, node_id, object_id, source_kind, source_id,
		source_generation, generation, lifecycle,
		retention_state, retain_until_ns, legal_hold_id, digest, body,
		created_at_ns, updated_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(sealed.TenantID), string(sealed.ID), string(sealed.NodeID), string(sealed.ObjectID),
		string(sealed.Source.Kind), sealed.Source.ID, sealed.Source.Generation,
		sealed.Generation, string(sealed.Lifecycle), string(sealed.Retention.State),
		sealed.Retention.RetainUntil.UnixNano(), string(sealed.Retention.LegalHoldID),
		sealed.Digest, body, sealed.CreatedAt.UnixNano(), sealed.UpdatedAt.UnixNano(),
	)
	if err == nil {
		return sealed, nil
	}
	existing, getErr := r.GetArtifact(ctx, sealed.TenantID, sealed.ID)
	if getErr == nil && existing.Digest == sealed.Digest {
		return existing, nil
	}
	if getErr == nil {
		return Artifact{}, ErrConflict
	}
	return Artifact{}, fmt.Errorf("artifactguard: create artifact: %w", err)
}

func (r *SQLiteRepository) GetArtifact(
	ctx context.Context,
	tenantID TenantID,
	artifactID ArtifactID,
) (Artifact, error) {
	if !validLocalID(string(tenantID)) || !validLocalID(string(artifactID)) {
		return Artifact{}, fmt.Errorf("%w: artifact scope", ErrInvalid)
	}
	var body []byte
	err := r.db.QueryRowContext(ctx,
		`SELECT body FROM artifactguard_artifacts WHERE tenant_id = ? AND artifact_id = ?`,
		string(tenantID), string(artifactID),
	).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	if err != nil {
		return Artifact{}, fmt.Errorf("artifactguard: get artifact: %w", err)
	}
	return decodeArtifact(body, tenantID, artifactID)
}

type ArtifactCursor struct {
	CreatedAt  time.Time
	ArtifactID ArtifactID
}

type ArtifactPage struct {
	Items      []Artifact
	NextCursor *ArtifactCursor
}

func (r *SQLiteRepository) ListArtifacts(
	ctx context.Context,
	tenantID TenantID,
	cursor *ArtifactCursor,
	limit int,
) (ArtifactPage, error) {
	if !validLocalID(string(tenantID)) || limit <= 0 || limit > MaximumListArtifacts {
		return ArtifactPage{}, fmt.Errorf("%w: artifact list", ErrInvalid)
	}
	createdAfter := int64(-1 << 63)
	idAfter := ""
	if cursor != nil {
		if cursor.CreatedAt.IsZero() || !validLocalID(string(cursor.ArtifactID)) {
			return ArtifactPage{}, fmt.Errorf("%w: artifact cursor", ErrInvalid)
		}
		createdAfter = canonicalTime(cursor.CreatedAt).UnixNano()
		idAfter = string(cursor.ArtifactID)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT body FROM artifactguard_artifacts
		WHERE tenant_id = ? AND (
			created_at_ns > ? OR (created_at_ns = ? AND artifact_id > ?)
		)
		ORDER BY created_at_ns ASC, artifact_id ASC
		LIMIT ?`, string(tenantID), createdAfter, createdAfter, idAfter, limit+1)
	if err != nil {
		return ArtifactPage{}, fmt.Errorf("artifactguard: list artifacts: %w", err)
	}
	defer rows.Close()
	items := make([]Artifact, 0, limit+1)
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return ArtifactPage{}, fmt.Errorf("artifactguard: scan artifact list: %w", err)
		}
		artifact, err := decodeArtifact(body, tenantID, "")
		if err != nil {
			return ArtifactPage{}, err
		}
		items = append(items, artifact)
	}
	if err := rows.Err(); err != nil {
		return ArtifactPage{}, fmt.Errorf("artifactguard: iterate artifact list: %w", err)
	}
	page := ArtifactPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		page.Items = items[:limit]
		page.NextCursor = &ArtifactCursor{CreatedAt: last.CreatedAt, ArtifactID: last.ID}
	}
	return page, nil
}

func (r *SQLiteRepository) FinalizeArtifact(
	ctx context.Context,
	tenantID TenantID,
	artifactID ArtifactID,
	expectedGeneration uint64,
	stored StoredObject,
	now time.Time,
) (Artifact, error) {
	current, err := r.GetArtifact(ctx, tenantID, artifactID)
	if err != nil {
		return Artifact{}, err
	}
	if current.Generation != expectedGeneration {
		return Artifact{}, ErrStaleGeneration
	}
	if current.Lifecycle != LifecycleStaging || current.Integrity != IntegrityPending ||
		stored.ObjectID != current.ObjectID || stored.Generation == 0 ||
		!validDigest(stored.Digest) || stored.Size <= 0 || now.IsZero() {
		return Artifact{}, fmt.Errorf("%w: finalize artifact", ErrInvalid)
	}
	next := current
	next.ObjectGeneration = stored.Generation
	next.ObjectDigest = stored.Digest
	next.Integrity = IntegrityVerified
	next.Lifecycle = LifecycleAvailable
	next.Generation++
	next.UpdatedAt = canonicalTime(now)
	sealed, err := SealArtifact(next)
	if err != nil {
		return Artifact{}, err
	}
	return r.updateArtifactCAS(ctx, current, sealed)
}

func (r *SQLiteRepository) ExpireRetention(
	ctx context.Context,
	tenantID TenantID,
	artifactID ArtifactID,
	expectedGeneration uint64,
	now time.Time,
) (Artifact, error) {
	current, err := r.GetArtifact(ctx, tenantID, artifactID)
	if err != nil {
		return Artifact{}, err
	}
	if current.Generation != expectedGeneration {
		return Artifact{}, ErrStaleGeneration
	}
	if current.Retention.State != RetentionStateActive ||
		canonicalTime(now).Before(current.Retention.RetainUntil) {
		return Artifact{}, ErrRetentionActive
	}
	next := current
	next.Retention.State = RetentionStateExpired
	next.Generation++
	next.UpdatedAt = canonicalTime(now)
	sealed, err := SealArtifact(next)
	if err != nil {
		return Artifact{}, err
	}
	return r.updateArtifactCAS(ctx, current, sealed)
}

func (r *SQLiteRepository) MarkAmbiguous(
	ctx context.Context,
	tenantID TenantID,
	artifactID ArtifactID,
	expectedGeneration uint64,
	now time.Time,
) (Artifact, error) {
	current, err := r.GetArtifact(ctx, tenantID, artifactID)
	if err != nil {
		return Artifact{}, err
	}
	if current.Generation != expectedGeneration {
		return Artifact{}, ErrStaleGeneration
	}
	if current.Lifecycle == LifecycleDeleted || current.Lifecycle == LifecycleAmbiguous {
		return Artifact{}, ErrUnsupportedState
	}
	next := current
	next.Lifecycle = LifecycleAmbiguous
	next.Generation++
	next.UpdatedAt = canonicalTime(now)
	sealed, err := SealArtifact(next)
	if err != nil {
		return Artifact{}, err
	}
	return r.updateArtifactCAS(ctx, current, sealed)
}

func (r *SQLiteRepository) PlaceLegalHold(
	ctx context.Context,
	hold LegalHold,
	expectedArtifactGeneration uint64,
) (Artifact, LegalHold, error) {
	sealedHold, err := SealLegalHold(hold)
	if err != nil {
		return Artifact{}, LegalHold{}, err
	}
	if sealedHold.State != HoldActive || sealedHold.Generation != 1 {
		return Artifact{}, LegalHold{}, fmt.Errorf("%w: initial hold state", ErrInvalid)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Artifact{}, LegalHold{}, fmt.Errorf("artifactguard: begin legal hold: %w", err)
	}
	defer tx.Rollback()
	artifact, err := getArtifactTx(ctx, tx, sealedHold.TenantID, sealedHold.ArtifactID)
	if err != nil {
		return Artifact{}, LegalHold{}, err
	}
	if artifact.Generation != expectedArtifactGeneration {
		return Artifact{}, LegalHold{}, ErrStaleGeneration
	}
	if artifact.Lifecycle == LifecycleDeleted || artifact.Lifecycle == LifecycleDeleting ||
		artifact.Retention.State == RetentionStateHeld ||
		!artifact.UpdatedAt.Before(sealedHold.UpdatedAt) {
		return Artifact{}, LegalHold{}, ErrConflict
	}
	holdBody, _ := json.Marshal(sealedHold)
	if _, err := tx.ExecContext(ctx, `INSERT INTO artifactguard_holds (
		tenant_id, hold_id, artifact_id, generation, state, digest, body,
		created_at_ns, updated_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(sealedHold.TenantID), string(sealedHold.ID), string(sealedHold.ArtifactID),
		sealedHold.Generation, string(sealedHold.State), sealedHold.Digest, holdBody,
		sealedHold.CreatedAt.UnixNano(), sealedHold.UpdatedAt.UnixNano(),
	); err != nil {
		return Artifact{}, LegalHold{}, fmt.Errorf("artifactguard: insert legal hold: %w", err)
	}
	next := artifact
	next.Retention.State = RetentionStateHeld
	next.Retention.LegalHoldID = sealedHold.ID
	next.Generation++
	next.UpdatedAt = sealedHold.UpdatedAt
	next, err = SealArtifact(next)
	if err != nil {
		return Artifact{}, LegalHold{}, err
	}
	if err := updateArtifactTx(ctx, tx, artifact, next); err != nil {
		return Artifact{}, LegalHold{}, err
	}
	if err := tx.Commit(); err != nil {
		return Artifact{}, LegalHold{}, fmt.Errorf("artifactguard: commit legal hold: %w", err)
	}
	return next, sealedHold, nil
}

func (r *SQLiteRepository) ReleaseLegalHold(
	ctx context.Context,
	tenantID TenantID,
	holdID HoldID,
	expectedHoldGeneration uint64,
	expectedArtifactGeneration uint64,
	now time.Time,
) (Artifact, LegalHold, error) {
	if now.IsZero() || !validLocalID(string(tenantID)) || !validLocalID(string(holdID)) {
		return Artifact{}, LegalHold{}, fmt.Errorf("%w: release hold", ErrInvalid)
	}
	now = canonicalTime(now)
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Artifact{}, LegalHold{}, fmt.Errorf("artifactguard: begin hold release: %w", err)
	}
	defer tx.Rollback()
	hold, err := getHoldTx(ctx, tx, tenantID, holdID)
	if err != nil {
		return Artifact{}, LegalHold{}, err
	}
	if hold.Generation != expectedHoldGeneration || hold.State != HoldActive {
		return Artifact{}, LegalHold{}, ErrStaleGeneration
	}
	artifact, err := getArtifactTx(ctx, tx, tenantID, hold.ArtifactID)
	if err != nil {
		return Artifact{}, LegalHold{}, err
	}
	if artifact.Generation != expectedArtifactGeneration ||
		artifact.Retention.State != RetentionStateHeld || artifact.Retention.LegalHoldID != hold.ID {
		return Artifact{}, LegalHold{}, ErrStaleGeneration
	}
	released := hold
	released.State = HoldReleased
	released.Generation++
	released.UpdatedAt = now
	released.ReleasedAt = now
	released, err = SealLegalHold(released)
	if err != nil {
		return Artifact{}, LegalHold{}, err
	}
	holdBody, _ := json.Marshal(released)
	result, err := tx.ExecContext(ctx, `UPDATE artifactguard_holds SET
		generation = ?, state = ?, digest = ?, body = ?, updated_at_ns = ?
		WHERE tenant_id = ? AND hold_id = ? AND generation = ? AND state = 'active'`,
		released.Generation, string(released.State), released.Digest, holdBody,
		released.UpdatedAt.UnixNano(), string(tenantID), string(holdID), expectedHoldGeneration,
	)
	if err != nil {
		return Artifact{}, LegalHold{}, fmt.Errorf("artifactguard: release legal hold: %w", err)
	}
	if err := requireOneRow(result); err != nil {
		return Artifact{}, LegalHold{}, err
	}
	next := artifact
	next.Retention.LegalHoldID = ""
	if now.Before(next.Retention.RetainUntil) {
		next.Retention.State = RetentionStateActive
	} else {
		next.Retention.State = RetentionStateExpired
	}
	next.Generation++
	next.UpdatedAt = now
	next, err = SealArtifact(next)
	if err != nil {
		return Artifact{}, LegalHold{}, err
	}
	if err := updateArtifactTx(ctx, tx, artifact, next); err != nil {
		return Artifact{}, LegalHold{}, err
	}
	if err := tx.Commit(); err != nil {
		return Artifact{}, LegalHold{}, fmt.Errorf("artifactguard: commit hold release: %w", err)
	}
	return next, released, nil
}

func (r *SQLiteRepository) CreateGrant(
	ctx context.Context,
	grant DownloadGrant,
) (DownloadGrant, error) {
	sealed, err := SealDownloadGrant(grant)
	if err != nil {
		return DownloadGrant{}, err
	}
	if sealed.State != GrantIssued || sealed.Generation != 1 {
		return DownloadGrant{}, fmt.Errorf("%w: initial grant state", ErrInvalid)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return DownloadGrant{}, fmt.Errorf("artifactguard: begin grant creation: %w", err)
	}
	defer tx.Rollback()
	artifact, err := getArtifactTx(ctx, tx, sealed.TenantID, sealed.ArtifactID)
	if err != nil {
		return DownloadGrant{}, err
	}
	if artifact.Digest != sealed.ArtifactDigest || artifact.Lifecycle != LifecycleAvailable ||
		artifact.Integrity != IntegrityVerified {
		return DownloadGrant{}, ErrIntegrity
	}
	body, _ := json.Marshal(sealed)
	_, err = tx.ExecContext(ctx, `INSERT INTO artifactguard_grants (
		tenant_id, grant_id, artifact_id, audience_principal, operation, generation,
		state, expires_at_ns, consumed_at_ns, digest, body, issued_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(sealed.TenantID), string(sealed.ID), string(sealed.ArtifactID),
		string(sealed.AudiencePrincipal), string(sealed.Operation), sealed.Generation,
		string(sealed.State), sealed.ExpiresAt.UnixNano(), int64(0), sealed.Digest,
		body, sealed.IssuedAt.UnixNano(),
	)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return DownloadGrant{}, fmt.Errorf("artifactguard: commit grant creation: %w", err)
		}
		return sealed, nil
	}
	existing, getErr := getGrantTx(ctx, tx, sealed.TenantID, sealed.ID, sealed.AudiencePrincipal)
	if getErr == nil && existing.Digest == sealed.Digest {
		if err := tx.Commit(); err != nil {
			return DownloadGrant{}, fmt.Errorf("artifactguard: commit idempotent grant: %w", err)
		}
		return existing, nil
	}
	if getErr == nil {
		return DownloadGrant{}, ErrConflict
	}
	return DownloadGrant{}, fmt.Errorf("artifactguard: create grant: %w", err)
}

func (r *SQLiteRepository) GetGrant(
	ctx context.Context,
	tenantID TenantID,
	grantID GrantID,
	audience PrincipalID,
) (DownloadGrant, error) {
	if !validLocalID(string(tenantID)) || !validLocalID(string(grantID)) ||
		!validLocalID(string(audience)) {
		return DownloadGrant{}, fmt.Errorf("%w: grant scope", ErrInvalid)
	}
	var body []byte
	err := r.db.QueryRowContext(ctx, `SELECT body FROM artifactguard_grants
		WHERE tenant_id = ? AND grant_id = ? AND audience_principal = ?`,
		string(tenantID), string(grantID), string(audience),
	).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return DownloadGrant{}, ErrNotFound
	}
	if err != nil {
		return DownloadGrant{}, fmt.Errorf("artifactguard: get grant: %w", err)
	}
	return decodeGrant(body, tenantID, grantID, audience)
}

type GrantCursor struct {
	IssuedAt time.Time
	GrantID  GrantID
}

type GrantPage struct {
	Items      []DownloadGrant
	NextCursor *GrantCursor
}

func (r *SQLiteRepository) ListGrants(
	ctx context.Context,
	tenantID TenantID,
	audience PrincipalID,
	cursor *GrantCursor,
	limit int,
) (GrantPage, error) {
	if !validLocalID(string(tenantID)) || !validLocalID(string(audience)) ||
		limit <= 0 || limit > MaximumGrantPage {
		return GrantPage{}, fmt.Errorf("%w: grant list", ErrInvalid)
	}
	issuedAfter := int64(-1 << 63)
	idAfter := ""
	if cursor != nil {
		if cursor.IssuedAt.IsZero() || !validLocalID(string(cursor.GrantID)) {
			return GrantPage{}, fmt.Errorf("%w: grant cursor", ErrInvalid)
		}
		issuedAfter = canonicalTime(cursor.IssuedAt).UnixNano()
		idAfter = string(cursor.GrantID)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT body FROM artifactguard_grants
		WHERE tenant_id = ? AND audience_principal = ? AND (
			issued_at_ns > ? OR (issued_at_ns = ? AND grant_id > ?)
		)
		ORDER BY issued_at_ns ASC, grant_id ASC
		LIMIT ?`, string(tenantID), string(audience), issuedAfter, issuedAfter, idAfter, limit+1)
	if err != nil {
		return GrantPage{}, fmt.Errorf("artifactguard: list grants: %w", err)
	}
	defer rows.Close()
	items := make([]DownloadGrant, 0, limit+1)
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return GrantPage{}, fmt.Errorf("artifactguard: scan grant list: %w", err)
		}
		var grant DownloadGrant
		if err := json.Unmarshal(body, &grant); err != nil {
			return GrantPage{}, ErrIntegrity
		}
		decoded, err := decodeGrant(body, tenantID, grant.ID, audience)
		if err != nil {
			return GrantPage{}, err
		}
		items = append(items, decoded)
	}
	if err := rows.Err(); err != nil {
		return GrantPage{}, fmt.Errorf("artifactguard: iterate grant list: %w", err)
	}
	page := GrantPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		page.Items = items[:limit]
		page.NextCursor = &GrantCursor{IssuedAt: last.IssuedAt, GrantID: last.ID}
	}
	return page, nil
}

func (r *SQLiteRepository) ConsumeGrant(
	ctx context.Context,
	tenantID TenantID,
	grantID GrantID,
	audience PrincipalID,
	operation GrantOperation,
	expectedGeneration uint64,
	now time.Time,
) (DownloadGrant, error) {
	if now.IsZero() || !operation.valid() {
		return DownloadGrant{}, fmt.Errorf("%w: consume grant", ErrInvalid)
	}
	now = canonicalTime(now)
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return DownloadGrant{}, fmt.Errorf("artifactguard: begin consume grant: %w", err)
	}
	defer tx.Rollback()
	grant, err := getGrantTx(ctx, tx, tenantID, grantID, audience)
	if err != nil {
		return DownloadGrant{}, err
	}
	if grant.Generation != expectedGeneration || grant.Operation != operation {
		return DownloadGrant{}, ErrStaleGeneration
	}
	artifact, err := getArtifactTx(ctx, tx, tenantID, grant.ArtifactID)
	if err != nil {
		return DownloadGrant{}, err
	}
	if artifact.Digest != grant.ArtifactDigest || artifact.Lifecycle != LifecycleAvailable ||
		artifact.Integrity != IntegrityVerified {
		return DownloadGrant{}, ErrIntegrity
	}
	if grant.State == GrantConsumed {
		return DownloadGrant{}, ErrConsumed
	}
	if grant.State != GrantIssued {
		return DownloadGrant{}, ErrExpired
	}
	if !now.Before(grant.ExpiresAt) {
		expired := grant
		expired.State = GrantExpired
		expired.Generation++
		expired, sealErr := SealDownloadGrant(expired)
		if sealErr != nil {
			return DownloadGrant{}, sealErr
		}
		if err := updateGrantTx(ctx, tx, grant, expired); err != nil {
			return DownloadGrant{}, err
		}
		if err := tx.Commit(); err != nil {
			return DownloadGrant{}, fmt.Errorf("artifactguard: commit grant expiry: %w", err)
		}
		return DownloadGrant{}, ErrExpired
	}
	consumed := grant
	consumed.State = GrantConsumed
	consumed.Generation++
	consumed.ConsumedAt = now
	consumed, err = SealDownloadGrant(consumed)
	if err != nil {
		return DownloadGrant{}, err
	}
	if err := updateGrantTx(ctx, tx, grant, consumed); err != nil {
		return DownloadGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return DownloadGrant{}, fmt.Errorf("artifactguard: commit grant consumption: %w", err)
	}
	return consumed, nil
}

func (r *SQLiteRepository) RevokeGrant(
	ctx context.Context,
	tenantID TenantID,
	grantID GrantID,
	audience PrincipalID,
	expectedGeneration uint64,
) (DownloadGrant, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return DownloadGrant{}, fmt.Errorf("artifactguard: begin grant revocation: %w", err)
	}
	defer tx.Rollback()
	grant, err := getGrantTx(ctx, tx, tenantID, grantID, audience)
	if err != nil {
		return DownloadGrant{}, err
	}
	if grant.Generation != expectedGeneration {
		return DownloadGrant{}, ErrStaleGeneration
	}
	if grant.State == GrantConsumed {
		return DownloadGrant{}, ErrConsumed
	}
	if grant.State != GrantIssued {
		return DownloadGrant{}, ErrConflict
	}
	revoked := grant
	revoked.State = GrantRevoked
	revoked.Generation++
	revoked, err = SealDownloadGrant(revoked)
	if err != nil {
		return DownloadGrant{}, err
	}
	if err := updateGrantTx(ctx, tx, grant, revoked); err != nil {
		return DownloadGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return DownloadGrant{}, fmt.Errorf("artifactguard: commit grant revocation: %w", err)
	}
	return revoked, nil
}

func (r *SQLiteRepository) BeginDeletion(
	ctx context.Context,
	tenantID TenantID,
	artifactID ArtifactID,
	expectedGeneration uint64,
	now time.Time,
) (Artifact, error) {
	if now.IsZero() {
		return Artifact{}, fmt.Errorf("%w: deletion time", ErrInvalid)
	}
	current, err := r.GetArtifact(ctx, tenantID, artifactID)
	if err != nil {
		return Artifact{}, err
	}
	if current.Generation != expectedGeneration {
		return Artifact{}, ErrStaleGeneration
	}
	if current.Lifecycle != LifecycleAvailable || current.Integrity != IntegrityVerified {
		return Artifact{}, ErrUnsupportedState
	}
	if current.Retention.State == RetentionStateHeld || current.Retention.LegalHoldID != "" {
		return Artifact{}, ErrLegalHold
	}
	if current.Retention.State != RetentionStateExpired ||
		canonicalTime(now).Before(current.Retention.RetainUntil) {
		return Artifact{}, ErrRetentionActive
	}
	next := current
	next.Lifecycle = LifecycleDeleting
	next.Generation++
	next.UpdatedAt = canonicalTime(now)
	sealed, err := SealArtifact(next)
	if err != nil {
		return Artifact{}, err
	}
	return r.updateArtifactCAS(ctx, current, sealed)
}

func (r *SQLiteRepository) CompleteDeletion(
	ctx context.Context,
	deleting Artifact,
	receipt DeletionReceipt,
	now time.Time,
) (Artifact, DeletionReceipt, error) {
	if now.IsZero() {
		return Artifact{}, DeletionReceipt{}, fmt.Errorf("%w: deletion completion time", ErrInvalid)
	}
	sealedReceipt, err := SealDeletionReceipt(receipt)
	if err != nil {
		return Artifact{}, DeletionReceipt{}, err
	}
	if deleting.Lifecycle != LifecycleDeleting || sealedReceipt.ArtifactID != deleting.ID ||
		sealedReceipt.TenantID != deleting.TenantID || sealedReceipt.ObjectID != deleting.ObjectID ||
		sealedReceipt.ArtifactGeneration != deleting.Generation ||
		sealedReceipt.ObjectGeneration != deleting.ObjectGeneration ||
		sealedReceipt.ObjectDigest != deleting.ObjectDigest {
		return Artifact{}, DeletionReceipt{}, fmt.Errorf("%w: deletion receipt binding", ErrInvalid)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Artifact{}, DeletionReceipt{}, fmt.Errorf("artifactguard: begin deletion receipt: %w", err)
	}
	defer tx.Rollback()
	current, err := getArtifactTx(ctx, tx, deleting.TenantID, deleting.ID)
	if err != nil {
		return Artifact{}, DeletionReceipt{}, err
	}
	if current.Generation != deleting.Generation || current.Digest != deleting.Digest {
		return Artifact{}, DeletionReceipt{}, ErrStaleGeneration
	}
	receiptBody, _ := json.Marshal(sealedReceipt)
	if _, err := tx.ExecContext(ctx, `INSERT INTO artifactguard_deletion_receipts (
		tenant_id, receipt_id, artifact_id, object_id, digest, body, completed_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		string(sealedReceipt.TenantID), string(sealedReceipt.ID), string(sealedReceipt.ArtifactID),
		string(sealedReceipt.ObjectID), sealedReceipt.Digest, receiptBody,
		sealedReceipt.CompletedAt.UnixNano(),
	); err != nil {
		existing, getErr := getDeletionReceiptTx(ctx, tx, deleting.TenantID, deleting.ID)
		if getErr != nil || existing.Digest != sealedReceipt.Digest {
			return Artifact{}, DeletionReceipt{}, fmt.Errorf("artifactguard: record deletion receipt: %w", err)
		}
		sealedReceipt = existing
	}
	next := current
	if sealedReceipt.Status == DeletionAmbiguous {
		next.Lifecycle = LifecycleAmbiguous
	} else {
		next.Lifecycle = LifecycleDeleted
	}
	next.Generation++
	next.UpdatedAt = canonicalTime(now)
	next, err = SealArtifact(next)
	if err != nil {
		return Artifact{}, DeletionReceipt{}, err
	}
	if err := updateArtifactTx(ctx, tx, current, next); err != nil {
		return Artifact{}, DeletionReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Artifact{}, DeletionReceipt{}, fmt.Errorf("artifactguard: commit deletion receipt: %w", err)
	}
	return next, sealedReceipt, nil
}

func (r *SQLiteRepository) GetDeletionReceipt(
	ctx context.Context,
	tenantID TenantID,
	artifactID ArtifactID,
) (DeletionReceipt, error) {
	var body []byte
	err := r.db.QueryRowContext(ctx, `SELECT body FROM artifactguard_deletion_receipts
		WHERE tenant_id = ? AND artifact_id = ?`, string(tenantID), string(artifactID)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return DeletionReceipt{}, ErrNotFound
	}
	if err != nil {
		return DeletionReceipt{}, fmt.Errorf("artifactguard: get deletion receipt: %w", err)
	}
	return decodeDeletionReceipt(body, tenantID, artifactID)
}

func (r *SQLiteRepository) updateArtifactCAS(
	ctx context.Context,
	current Artifact,
	next Artifact,
) (Artifact, error) {
	if current.Generation+1 != next.Generation || !ArtifactIdentityEqual(current, next) ||
		current.CreatedAt != next.CreatedAt ||
		(!ArtifactTransitionAllowed(current.Lifecycle, next.Lifecycle) && current.Lifecycle != next.Lifecycle) {
		return Artifact{}, fmt.Errorf("%w: artifact CAS transition", ErrInvalid)
	}
	body, _ := json.Marshal(next)
	result, err := r.db.ExecContext(ctx, `UPDATE artifactguard_artifacts SET
		generation = ?, lifecycle = ?, retention_state = ?, retain_until_ns = ?,
		legal_hold_id = ?, digest = ?, body = ?, updated_at_ns = ?
		WHERE tenant_id = ? AND artifact_id = ? AND generation = ? AND digest = ?`,
		next.Generation, string(next.Lifecycle), string(next.Retention.State),
		next.Retention.RetainUntil.UnixNano(), string(next.Retention.LegalHoldID), next.Digest,
		body, next.UpdatedAt.UnixNano(), string(current.TenantID), string(current.ID),
		current.Generation, current.Digest,
	)
	if err != nil {
		return Artifact{}, fmt.Errorf("artifactguard: update artifact: %w", err)
	}
	if err := requireOneRow(result); err != nil {
		return Artifact{}, err
	}
	return next, nil
}

func getArtifactTx(
	ctx context.Context,
	tx *sql.Tx,
	tenantID TenantID,
	artifactID ArtifactID,
) (Artifact, error) {
	var body []byte
	err := tx.QueryRowContext(ctx, `SELECT body FROM artifactguard_artifacts
		WHERE tenant_id = ? AND artifact_id = ?`, string(tenantID), string(artifactID)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	if err != nil {
		return Artifact{}, fmt.Errorf("artifactguard: get artifact transaction: %w", err)
	}
	return decodeArtifact(body, tenantID, artifactID)
}

func updateArtifactTx(ctx context.Context, tx *sql.Tx, current, next Artifact) error {
	if current.Generation+1 != next.Generation || !ArtifactIdentityEqual(current, next) ||
		(!ArtifactTransitionAllowed(current.Lifecycle, next.Lifecycle) && current.Lifecycle != next.Lifecycle) {
		return fmt.Errorf("%w: artifact transaction transition", ErrInvalid)
	}
	body, _ := json.Marshal(next)
	result, err := tx.ExecContext(ctx, `UPDATE artifactguard_artifacts SET
		generation = ?, lifecycle = ?, retention_state = ?, retain_until_ns = ?,
		legal_hold_id = ?, digest = ?, body = ?, updated_at_ns = ?
		WHERE tenant_id = ? AND artifact_id = ? AND generation = ? AND digest = ?`,
		next.Generation, string(next.Lifecycle), string(next.Retention.State),
		next.Retention.RetainUntil.UnixNano(), string(next.Retention.LegalHoldID), next.Digest,
		body, next.UpdatedAt.UnixNano(), string(current.TenantID), string(current.ID),
		current.Generation, current.Digest,
	)
	if err != nil {
		return fmt.Errorf("artifactguard: update artifact transaction: %w", err)
	}
	return requireOneRow(result)
}

func getHoldTx(
	ctx context.Context,
	tx *sql.Tx,
	tenantID TenantID,
	holdID HoldID,
) (LegalHold, error) {
	var body []byte
	err := tx.QueryRowContext(ctx, `SELECT body FROM artifactguard_holds
		WHERE tenant_id = ? AND hold_id = ?`, string(tenantID), string(holdID)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return LegalHold{}, ErrNotFound
	}
	if err != nil {
		return LegalHold{}, fmt.Errorf("artifactguard: get legal hold: %w", err)
	}
	var hold LegalHold
	if err := json.Unmarshal(body, &hold); err != nil {
		return LegalHold{}, ErrIntegrity
	}
	sealed, err := SealLegalHold(hold)
	if err != nil || sealed.Digest != hold.Digest || hold.TenantID != tenantID || hold.ID != holdID {
		return LegalHold{}, ErrIntegrity
	}
	return hold, nil
}

func getGrantTx(
	ctx context.Context,
	tx *sql.Tx,
	tenantID TenantID,
	grantID GrantID,
	audience PrincipalID,
) (DownloadGrant, error) {
	var body []byte
	err := tx.QueryRowContext(ctx, `SELECT body FROM artifactguard_grants
		WHERE tenant_id = ? AND grant_id = ? AND audience_principal = ?`,
		string(tenantID), string(grantID), string(audience),
	).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return DownloadGrant{}, ErrNotFound
	}
	if err != nil {
		return DownloadGrant{}, fmt.Errorf("artifactguard: get grant transaction: %w", err)
	}
	return decodeGrant(body, tenantID, grantID, audience)
}

func updateGrantTx(ctx context.Context, tx *sql.Tx, current, next DownloadGrant) error {
	if current.Generation+1 != next.Generation || current.ID != next.ID ||
		current.TenantID != next.TenantID || current.ArtifactID != next.ArtifactID ||
		current.AudiencePrincipal != next.AudiencePrincipal || current.Operation != next.Operation ||
		current.ArtifactDigest != next.ArtifactDigest {
		return fmt.Errorf("%w: grant transition", ErrInvalid)
	}
	body, _ := json.Marshal(next)
	consumedAt := int64(0)
	if !next.ConsumedAt.IsZero() {
		consumedAt = next.ConsumedAt.UnixNano()
	}
	result, err := tx.ExecContext(ctx, `UPDATE artifactguard_grants SET
		generation = ?, state = ?, expires_at_ns = ?, consumed_at_ns = ?, digest = ?, body = ?
		WHERE tenant_id = ? AND grant_id = ? AND generation = ? AND digest = ?`,
		next.Generation, string(next.State), next.ExpiresAt.UnixNano(), consumedAt, next.Digest, body,
		string(current.TenantID), string(current.ID), current.Generation, current.Digest,
	)
	if err != nil {
		return fmt.Errorf("artifactguard: update grant: %w", err)
	}
	return requireOneRow(result)
}

func getDeletionReceiptTx(
	ctx context.Context,
	tx *sql.Tx,
	tenantID TenantID,
	artifactID ArtifactID,
) (DeletionReceipt, error) {
	var body []byte
	err := tx.QueryRowContext(ctx, `SELECT body FROM artifactguard_deletion_receipts
		WHERE tenant_id = ? AND artifact_id = ?`, string(tenantID), string(artifactID)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return DeletionReceipt{}, ErrNotFound
	}
	if err != nil {
		return DeletionReceipt{}, err
	}
	return decodeDeletionReceipt(body, tenantID, artifactID)
}

func decodeArtifact(body []byte, tenantID TenantID, artifactID ArtifactID) (Artifact, error) {
	var artifact Artifact
	if err := json.Unmarshal(body, &artifact); err != nil {
		return Artifact{}, ErrIntegrity
	}
	if artifact.TenantID != tenantID || artifactID != "" && artifact.ID != artifactID {
		return Artifact{}, ErrIntegrity
	}
	if err := artifact.Validate(); err != nil {
		return Artifact{}, ErrIntegrity
	}
	return artifact, nil
}

func decodeGrant(
	body []byte,
	tenantID TenantID,
	grantID GrantID,
	audience PrincipalID,
) (DownloadGrant, error) {
	var grant DownloadGrant
	if err := json.Unmarshal(body, &grant); err != nil {
		return DownloadGrant{}, ErrIntegrity
	}
	sealed, err := SealDownloadGrant(grant)
	if err != nil || sealed.Digest != grant.Digest || grant.TenantID != tenantID ||
		grant.ID != grantID || grant.AudiencePrincipal != audience {
		return DownloadGrant{}, ErrIntegrity
	}
	return grant, nil
}

func decodeDeletionReceipt(
	body []byte,
	tenantID TenantID,
	artifactID ArtifactID,
) (DeletionReceipt, error) {
	var receipt DeletionReceipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		return DeletionReceipt{}, ErrIntegrity
	}
	sealed, err := SealDeletionReceipt(receipt)
	if err != nil || sealed.Digest != receipt.Digest || receipt.TenantID != tenantID ||
		receipt.ArtifactID != artifactID {
		return DeletionReceipt{}, ErrIntegrity
	}
	return receipt, nil
}

func requireOneRow(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("artifactguard: inspect CAS result: %w", err)
	}
	if count != 1 {
		return ErrStaleGeneration
	}
	return nil
}

type Authorizer interface {
	Authorize(context.Context, Actor, Action, Artifact) error
}

type StepUpVerifier interface {
	Verify(context.Context, Actor, StepUpEvidence, Action, Artifact, time.Time) error
}

type Auditor interface {
	Record(context.Context, AuditEvent) error
}

type AccessService struct {
	Repository *SQLiteRepository
	Encryption EncryptionService
	Authorizer Authorizer
	StepUp     StepUpVerifier
	Auditor    Auditor
	Now        func() time.Time
}

type GrantRequest struct {
	Actor       Actor
	ArtifactID  ArtifactID
	Operation   GrantOperation
	Filename    string
	MediaType   string
	Lifetime    time.Duration
	StepUp      StepUpEvidence
}

func (s AccessService) IssueGrant(ctx context.Context, request GrantRequest) (DownloadGrant, error) {
	now, err := s.dependencies()
	if err != nil {
		return DownloadGrant{}, err
	}
	if !request.Operation.valid() || request.Lifetime <= 0 || request.Lifetime > MaximumGrantLifetime {
		return DownloadGrant{}, fmt.Errorf("%w: grant request", ErrInvalid)
	}
	artifact, err := s.Repository.GetArtifact(ctx, request.Actor.TenantID, request.ArtifactID)
	if err != nil {
		return DownloadGrant{}, err
	}
	if artifact.Lifecycle != LifecycleAvailable || artifact.Integrity != IntegrityVerified {
		return DownloadGrant{}, ErrUnsupportedState
	}
	action := ActionRead
	if request.Operation == GrantExport {
		action = ActionExport
	}
	if _, err := s.authorizeAndAudit(ctx, request.Actor, action, artifact, request.StepUp, now); err != nil {
		return DownloadGrant{}, err
	}
	grantID, err := randomLocalID("grant")
	if err != nil {
		return DownloadGrant{}, err
	}
	metadata := DownloadMetadata{
		Filename:      request.Filename,
		MediaType:     request.MediaType,
		ContentLength: artifact.ContentSize,
		ContentDigest: artifact.ContentDigest,
	}
	if err := metadata.Validate(); err != nil {
		return DownloadGrant{}, err
	}
	grant := DownloadGrant{
		ID:                GrantID(grantID),
		ArtifactID:        artifact.ID,
		ArtifactDigest:    artifact.Digest,
		TenantID:          artifact.TenantID,
		AudiencePrincipal: request.Actor.PrincipalID,
		Operation:         request.Operation,
		Metadata:          metadata,
		OneUse:            true,
		State:             GrantIssued,
		Generation:        1,
		IssuedAt:          now,
		ExpiresAt:         now.Add(request.Lifetime),
	}
	return s.Repository.CreateGrant(ctx, grant)
}

type DownloadRequest struct {
	Actor              Actor
	GrantID            GrantID
	ExpectedGeneration uint64
	Operation          GrantOperation
	StepUp             StepUpEvidence
}

func (s AccessService) Download(
	ctx context.Context,
	request DownloadRequest,
	sink AtomicPlaintextSink,
) (DownloadMetadata, error) {
	now, err := s.dependencies()
	if err != nil {
		return DownloadMetadata{}, err
	}
	if sink == nil || !request.Operation.valid() || request.ExpectedGeneration == 0 {
		return DownloadMetadata{}, fmt.Errorf("%w: download request", ErrInvalid)
	}
	grant, err := s.Repository.GetGrant(ctx, request.Actor.TenantID, request.GrantID, request.Actor.PrincipalID)
	if err != nil {
		return DownloadMetadata{}, err
	}
	if grant.Generation != request.ExpectedGeneration || grant.Operation != request.Operation ||
		grant.State != GrantIssued {
		if grant.State == GrantConsumed {
			return DownloadMetadata{}, ErrConsumed
		}
		return DownloadMetadata{}, ErrStaleGeneration
	}
	if !now.Before(grant.ExpiresAt) {
		return DownloadMetadata{}, ErrExpired
	}
	artifact, err := s.Repository.GetArtifact(ctx, request.Actor.TenantID, grant.ArtifactID)
	if err != nil {
		return DownloadMetadata{}, err
	}
	if artifact.Digest != grant.ArtifactDigest || artifact.Lifecycle != LifecycleAvailable ||
		artifact.Integrity != IntegrityVerified {
		return DownloadMetadata{}, ErrIntegrity
	}
	action := ActionRead
	if request.Operation == GrantExport {
		action = ActionExport
	}
	if _, err := s.authorizeAndAudit(ctx, request.Actor, action, artifact, request.StepUp, now); err != nil {
		return DownloadMetadata{}, err
	}
	if _, err := s.Repository.ConsumeGrant(
		ctx,
		request.Actor.TenantID,
		request.GrantID,
		request.Actor.PrincipalID,
		request.Operation,
		request.ExpectedGeneration,
		now,
	); err != nil {
		return DownloadMetadata{}, err
	}
	if err := s.Encryption.Open(ctx, artifact, sink); err != nil {
		return DownloadMetadata{}, err
	}
	return grant.Metadata, nil
}

type DeleteRequest struct {
	Actor              Actor
	ArtifactID         ArtifactID
	ExpectedGeneration uint64
	StepUp             StepUpEvidence
}

func (s AccessService) Delete(ctx context.Context, request DeleteRequest) (DeletionReceipt, error) {
	now, err := s.dependencies()
	if err != nil {
		return DeletionReceipt{}, err
	}
	if request.ExpectedGeneration == 0 {
		return DeletionReceipt{}, fmt.Errorf("%w: delete generation", ErrInvalid)
	}
	artifact, err := s.Repository.GetArtifact(ctx, request.Actor.TenantID, request.ArtifactID)
	if err != nil {
		return DeletionReceipt{}, err
	}
	existing, receiptErr := s.Repository.GetDeletionReceipt(
		ctx,
		request.Actor.TenantID,
		request.ArtifactID,
	)
	if receiptErr == nil {
		if existing.ArtifactGeneration != request.ExpectedGeneration+1 ||
			existing.ObjectID != artifact.ObjectID || existing.ObjectDigest != artifact.ObjectDigest {
			return DeletionReceipt{}, ErrStaleGeneration
		}
		if _, err := s.authorizeAndAudit(
			ctx,
			request.Actor,
			ActionDelete,
			artifact,
			request.StepUp,
			now,
		); err != nil {
			return DeletionReceipt{}, err
		}
		if existing.Status == DeletionAmbiguous {
			return existing, ErrAmbiguous
		}
		return existing, nil
	} else if !errors.Is(receiptErr, ErrNotFound) {
		return DeletionReceipt{}, receiptErr
	}
	if artifact.Generation != request.ExpectedGeneration {
		return DeletionReceipt{}, ErrStaleGeneration
	}
	auditID, err := s.authorizeAndAudit(ctx, request.Actor, ActionDelete, artifact, request.StepUp, now)
	if err != nil {
		return DeletionReceipt{}, err
	}
	receiptID, err := randomLocalID("delete")
	if err != nil {
		return DeletionReceipt{}, err
	}
	deleting, err := s.Repository.BeginDeletion(
		ctx,
		request.Actor.TenantID,
		request.ArtifactID,
		request.ExpectedGeneration,
		now,
	)
	if err != nil {
		return DeletionReceipt{}, err
	}
	result, deleteErr := s.Encryption.Objects.DeleteExact(ctx, ExactObjectDelete{
		TenantID:           deleting.TenantID,
		ObjectID:           deleting.ObjectID,
		ExpectedGeneration: deleting.ObjectGeneration,
		ExpectedDigest:     deleting.ObjectDigest,
	})
	status := DeletionAmbiguous
	if deleteErr == nil && result.ObjectID == deleting.ObjectID &&
		result.Generation == deleting.ObjectGeneration && result.Digest == deleting.ObjectDigest {
		switch result.Status {
		case ExactDeleted:
			status = DeletionCompleted
		case ExactAlreadyAbsent:
			status = DeletionAlreadyAbsent
		case ExactDeleteUnknown:
		}
	}
	receipt := DeletionReceipt{
		ID:                 ReceiptID(receiptID),
		ArtifactID:         deleting.ID,
		TenantID:           deleting.TenantID,
		ObjectID:           deleting.ObjectID,
		ArtifactGeneration: deleting.Generation,
		ObjectGeneration:   deleting.ObjectGeneration,
		ObjectDigest:       deleting.ObjectDigest,
		Status:             status,
		Actor:              request.Actor.PrincipalID,
		AuditID:            auditID,
		CompletedAt:        now,
	}
	_, sealedReceipt, completeErr := s.Repository.CompleteDeletion(ctx, deleting, receipt, now)
	if completeErr != nil {
		_, _ = s.Repository.MarkAmbiguous(ctx, deleting.TenantID, deleting.ID, deleting.Generation, now)
		return DeletionReceipt{}, ErrAmbiguous
	}
	if deleteErr != nil || status == DeletionAmbiguous {
		return sealedReceipt, ErrAmbiguous
	}
	return sealedReceipt, nil
}

func (s AccessService) dependencies() (time.Time, error) {
	if s.Repository == nil || s.Encryption.Keys == nil || s.Encryption.Objects == nil ||
		s.Authorizer == nil || s.StepUp == nil || s.Auditor == nil || s.Now == nil {
		return time.Time{}, fmt.Errorf("%w: access service dependencies", ErrInvalid)
	}
	now := canonicalTime(s.Now())
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("%w: service clock", ErrInvalid)
	}
	return now, nil
}

func (s AccessService) authorizeAndAudit(
	ctx context.Context,
	actor Actor,
	action Action,
	artifact Artifact,
	evidence StepUpEvidence,
	now time.Time,
) (string, error) {
	if actor.TenantID != artifact.TenantID || !validLocalID(string(actor.PrincipalID)) {
		return "", ErrUnauthorized
	}
	auditID, err := randomLocalID("audit")
	if err != nil {
		return "", err
	}
	decisionErr := s.Authorizer.Authorize(ctx, actor, action, artifact)
	if decisionErr == nil && requiresStepUp(action, artifact.DataClass) {
		if !validStepUpBinding(actor, action, artifact, evidence, now) {
			decisionErr = ErrStepUpRequired
		} else {
			decisionErr = s.StepUp.Verify(ctx, actor, evidence, action, artifact, now)
			if decisionErr != nil {
				decisionErr = ErrStepUpRequired
			}
		}
	}
	outcome := "authorized"
	reason := "policy_allowed"
	if decisionErr != nil {
		outcome = "denied"
		reason = "policy_denied"
		if errors.Is(decisionErr, ErrStepUpRequired) {
			reason = "step_up_required"
		}
	}
	event := AuditEvent{
		ID:                 auditID,
		TenantID:           actor.TenantID,
		PrincipalID:        actor.PrincipalID,
		ArtifactID:         artifact.ID,
		ArtifactGeneration: artifact.Generation,
		ArtifactDigest:     artifact.Digest,
		Action:             action,
		Outcome:            outcome,
		ReasonCode:         reason,
		OccurredAt:         now,
	}
	if err := s.Auditor.Record(ctx, event); err != nil {
		return "", fmt.Errorf("artifactguard: record authorization audit: %w", err)
	}
	if decisionErr != nil {
		if errors.Is(decisionErr, ErrStepUpRequired) {
			return "", ErrStepUpRequired
		}
		return "", ErrUnauthorized
	}
	return auditID, nil
}

func requiresStepUp(action Action, _ DataClass) bool {
	return action == ActionRead || action == ActionExport || action == ActionDelete
}

func validStepUpBinding(
	actor Actor,
	action Action,
	artifact Artifact,
	evidence StepUpEvidence,
	now time.Time,
) bool {
	return validLocalID(evidence.ID) && validDigest(evidence.Digest) &&
		evidence.TenantID == actor.TenantID && evidence.PrincipalID == actor.PrincipalID &&
		evidence.Action == action && evidence.ArtifactID == artifact.ID &&
		evidence.ExpiresAt.After(now) && evidence.ExpiresAt.Sub(now) <= MaximumGrantLifetime
}

func randomLocalID(prefix string) (string, error) {
	if !validLocalID(prefix) {
		return "", fmt.Errorf("%w: identifier prefix", ErrInvalid)
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", fmt.Errorf("artifactguard: generate identifier: %w", err)
	}
	return prefix + ":" + hex.EncodeToString(random[:]), nil
}
