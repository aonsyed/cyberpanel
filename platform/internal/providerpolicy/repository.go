package providerpolicy

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const databaseTimeFormat = "2006-01-02T15:04:05.000000000Z"

type SQLiteRepository struct{ db *sql.DB }

func OpenSQLiteRepository(path string) (*SQLiteRepository, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	return &SQLiteRepository{db: database}, nil
}

func NewSQLiteRepository(database *sql.DB) (*SQLiteRepository, error) {
	if database == nil {
		return nil, ErrInvalid
	}
	return &SQLiteRepository{db: database}, nil
}

func (repository *SQLiteRepository) Close() error {
	if repository == nil || repository.db == nil {
		return nil
	}
	return repository.db.Close()
}

func (repository *SQLiteRepository) Bootstrap(ctx context.Context) error {
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS provider_policy_bindings_v1 (
			binding_id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			consent_revision INTEGER NOT NULL CHECK (consent_revision > 0),
			lifecycle TEXT NOT NULL CHECK (lifecycle IN ('enabled','suspended','deleting')),
			document BLOB NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(tenant_id, provider_id, binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS provider_policy_bindings_tenant_v1 ON provider_policy_bindings_v1(tenant_id, provider_id, binding_id)`,
		`CREATE TABLE IF NOT EXISTS provider_policy_consents_v1 (
			binding_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			revision INTEGER NOT NULL CHECK (revision > 0),
			record_digest TEXT NOT NULL UNIQUE,
			document BLOB NOT NULL,
			granted_at TEXT NOT NULL,
			PRIMARY KEY(binding_id, revision)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS provider_policy_consents_tenant_v1 ON provider_policy_consents_v1(tenant_id, binding_id, revision)`,
		`CREATE TRIGGER IF NOT EXISTS provider_policy_consents_no_update_v1 BEFORE UPDATE ON provider_policy_consents_v1 BEGIN SELECT RAISE(ABORT, 'consent history is immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS provider_policy_consents_no_delete_v1 BEFORE DELETE ON provider_policy_consents_v1 BEGIN SELECT RAISE(ABORT, 'consent history is immutable'); END`,
		`CREATE TABLE IF NOT EXISTS provider_policy_runtime_v1 (
			binding_id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			inflight INTEGER NOT NULL CHECK (inflight >= 0),
			tokens REAL NOT NULL CHECK (tokens >= 0),
			refilled_at TEXT NOT NULL,
			circuit TEXT NOT NULL CHECK (circuit IN ('closed','open','half_open')),
			consecutive_failures INTEGER NOT NULL CHECK (consecutive_failures >= 0),
			opened_until TEXT NOT NULL,
			half_open_inflight INTEGER NOT NULL CHECK (half_open_inflight >= 0),
			FOREIGN KEY(binding_id) REFERENCES provider_policy_bindings_v1(binding_id)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS provider_policy_permits_v1 (
			permit_id TEXT PRIMARY KEY,
			binding_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			fence_token TEXT NOT NULL,
			fence_digest TEXT NOT NULL UNIQUE,
			half_open_probe INTEGER NOT NULL CHECK (half_open_probe IN (0,1)),
			active INTEGER NOT NULL CHECK (active IN (0,1)),
			acquired_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			completed_at TEXT NOT NULL,
			outcome TEXT NOT NULL,
			FOREIGN KEY(binding_id) REFERENCES provider_policy_bindings_v1(binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS provider_policy_permits_active_v1 ON provider_policy_permits_v1(binding_id, active, expires_at)`,
		`CREATE TABLE IF NOT EXISTS provider_policy_observations_v1 (
			observation_id TEXT PRIMARY KEY,
			binding_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			health TEXT NOT NULL,
			observed_at TEXT NOT NULL,
			digest TEXT NOT NULL UNIQUE,
			document BLOB NOT NULL,
			FOREIGN KEY(binding_id) REFERENCES provider_policy_bindings_v1(binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS provider_policy_observations_latest_v1 ON provider_policy_observations_v1(binding_id, observed_at DESC)`,
		`CREATE TRIGGER IF NOT EXISTS provider_policy_observations_no_update_v1 BEFORE UPDATE ON provider_policy_observations_v1 BEGIN SELECT RAISE(ABORT, 'observations are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS provider_policy_observations_no_delete_v1 BEFORE DELETE ON provider_policy_observations_v1 BEGIN SELECT RAISE(ABORT, 'observations are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS provider_policy_workflows_v1 (
			workflow_id TEXT PRIMARY KEY,
			binding_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			kind TEXT NOT NULL CHECK (kind IN ('deletion','reauthorization')),
			state TEXT NOT NULL CHECK (state IN ('pending','awaiting_proof','completed','failed')),
			generation INTEGER NOT NULL CHECK (generation > 0),
			document BLOB NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(binding_id) REFERENCES provider_policy_bindings_v1(binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS provider_policy_workflows_binding_v1 ON provider_policy_workflows_v1(binding_id, updated_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := repository.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (repository *SQLiteRepository) PutBinding(ctx context.Context, binding Binding, expectedGeneration uint64, consent *ConsentRecord) error {
	if binding.Validate() != nil || binding.Generation != expectedGeneration+1 || expectedGeneration > 9223372036854775807 {
		return ErrInvalid
	}
	document, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var currentConsent uint64
	if expectedGeneration > 0 {
		err = transaction.QueryRowContext(ctx, `SELECT consent_revision FROM provider_policy_bindings_v1 WHERE binding_id=? AND tenant_id=? AND generation=?`,
			binding.ID, binding.TenantID, expectedGeneration).Scan(&currentConsent)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStale
		}
		if err != nil {
			return err
		}
	}
	consentRequired := expectedGeneration == 0 || binding.EgressConsentRevision != currentConsent
	if consentRequired {
		if consent == nil || consent.Validate() != nil || !consentMatchesBinding(*consent, binding) {
			return ErrInvalid
		}
		consentDocument, marshalErr := json.Marshal(consent)
		if marshalErr != nil {
			return marshalErr
		}
		_, err = transaction.ExecContext(ctx, `INSERT INTO provider_policy_consents_v1(binding_id,tenant_id,revision,record_digest,document,granted_at) VALUES(?,?,?,?,?,?)`,
			consent.BindingID, consent.TenantID, consent.Revision, consent.RecordDigest, consentDocument, formatTime(consent.GrantedAt))
		if err != nil {
			return ErrConflict
		}
	} else if consent != nil {
		return ErrInvalid
	}
	if expectedGeneration == 0 {
		_, err = transaction.ExecContext(ctx, `INSERT INTO provider_policy_bindings_v1(binding_id,tenant_id,provider_id,generation,consent_revision,lifecycle,document,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
			binding.ID, binding.TenantID, binding.ProviderID, binding.Generation, binding.EgressConsentRevision, binding.Lifecycle, document, formatTime(binding.UpdatedAt))
		if err != nil {
			return ErrConflict
		}
		_, err = transaction.ExecContext(ctx, `INSERT INTO provider_policy_runtime_v1(binding_id,tenant_id,generation,inflight,tokens,refilled_at,circuit,consecutive_failures,opened_until,half_open_inflight) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			binding.ID, binding.TenantID, 1, 0, binding.Resilience.RateCapacity, formatTime(binding.UpdatedAt), CircuitClosed, 0, "", 0)
	} else {
		result, updateErr := transaction.ExecContext(ctx, `UPDATE provider_policy_bindings_v1 SET provider_id=?,generation=?,consent_revision=?,lifecycle=?,document=?,updated_at=? WHERE binding_id=? AND tenant_id=? AND generation=?`,
			binding.ProviderID, binding.Generation, binding.EgressConsentRevision, binding.Lifecycle, document, formatTime(binding.UpdatedAt), binding.ID, binding.TenantID, expectedGeneration)
		if updateErr != nil {
			return updateErr
		}
		affected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if affected != 1 {
			return ErrStale
		}
		_, err = transaction.ExecContext(ctx, `UPDATE provider_policy_runtime_v1 SET tokens=MIN(tokens,?) WHERE binding_id=? AND tenant_id=?`,
			binding.Resilience.RateCapacity, binding.ID, binding.TenantID)
	}
	if err != nil {
		return err
	}
	return transaction.Commit()
}

func consentMatchesBinding(consent ConsentRecord, binding Binding) bool {
	if consent.BindingID != binding.ID || consent.TenantID != binding.TenantID || consent.Revision != binding.EgressConsentRevision || consent.Purpose != binding.Purpose ||
		consent.Destination != binding.Destination || consent.Region != binding.Region || len(consent.DataClasses) != len(binding.AllowedDataClasses) {
		return false
	}
	for index := range consent.DataClasses {
		if consent.DataClasses[index] != binding.AllowedDataClasses[index] {
			return false
		}
	}
	return true
}

func (repository *SQLiteRepository) LoadBinding(ctx context.Context, tenantID TenantID, bindingID BindingID) (Binding, error) {
	if !validID(string(tenantID)) || !validID(string(bindingID)) {
		return Binding{}, ErrInvalid
	}
	var document []byte
	if err := repository.db.QueryRowContext(ctx, `SELECT document FROM provider_policy_bindings_v1 WHERE tenant_id=? AND binding_id=?`, tenantID, bindingID).Scan(&document); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Binding{}, ErrNotFound
		}
		return Binding{}, err
	}
	var binding Binding
	if decodeStrict(document, &binding) != nil || binding.Validate() != nil || binding.ID != bindingID || binding.TenantID != tenantID {
		return Binding{}, ErrIntegrity
	}
	return binding, nil
}

func (repository *SQLiteRepository) ListBindings(ctx context.Context, tenantID TenantID, limit int) ([]Binding, error) {
	if !validID(string(tenantID)) || limit < 1 || limit > 500 {
		return nil, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT document FROM provider_policy_bindings_v1 WHERE tenant_id=? ORDER BY provider_id,binding_id LIMIT ?`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := make([]Binding, 0)
	for rows.Next() {
		var document []byte
		var binding Binding
		if rows.Scan(&document) != nil || decodeStrict(document, &binding) != nil || binding.Validate() != nil || binding.TenantID != tenantID {
			return nil, ErrIntegrity
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

func (repository *SQLiteRepository) LoadConsent(ctx context.Context, tenantID TenantID, bindingID BindingID, revision uint64) (ConsentRecord, error) {
	if !validID(string(tenantID)) || !validID(string(bindingID)) || revision == 0 {
		return ConsentRecord{}, ErrInvalid
	}
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM provider_policy_consents_v1 WHERE tenant_id=? AND binding_id=? AND revision=?`, tenantID, bindingID, revision).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return ConsentRecord{}, ErrNotFound
	}
	if err != nil {
		return ConsentRecord{}, err
	}
	var consent ConsentRecord
	if decodeStrict(document, &consent) != nil || consent.Validate() != nil || consent.TenantID != tenantID || consent.BindingID != bindingID || consent.Revision != revision {
		return ConsentRecord{}, ErrIntegrity
	}
	return consent, nil
}

func (repository *SQLiteRepository) Runtime(ctx context.Context, binding Binding, now time.Time) (RuntimeSnapshot, error) {
	if binding.Validate() != nil || now.IsZero() {
		return RuntimeSnapshot{}, ErrInvalid
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	defer transaction.Rollback()
	if err = repository.expirePermits(ctx, transaction, binding, now.UTC()); err != nil {
		return RuntimeSnapshot{}, err
	}
	snapshot, err := loadRuntime(ctx, transaction, binding.ID, binding.TenantID)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	if snapshot.Circuit == CircuitOpen && !now.Before(snapshot.OpenedUntil) {
		result, updateErr := transaction.ExecContext(ctx, `UPDATE provider_policy_runtime_v1 SET circuit=?,generation=generation+1 WHERE binding_id=? AND tenant_id=? AND generation=?`,
			CircuitHalfOpen, binding.ID, binding.TenantID, snapshot.Generation)
		if updateErr != nil {
			return RuntimeSnapshot{}, updateErr
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			return RuntimeSnapshot{}, ErrStale
		}
		snapshot.Generation++
		snapshot.Circuit = CircuitHalfOpen
	}
	snapshot.Tokens = refillTokens(snapshot.Tokens, snapshot.RefilledAt, now.UTC(), binding.Resilience)
	snapshot.RefilledAt = now.UTC()
	if err = transaction.Commit(); err != nil {
		return RuntimeSnapshot{}, err
	}
	return snapshot, nil
}

func (repository *SQLiteRepository) Acquire(ctx context.Context, binding Binding, request AdmissionRequest, expectedRuntimeGeneration uint64, now time.Time, lease time.Duration) (Permit, error) {
	if binding.Validate() != nil || request.Validate() != nil || request.BindingID != binding.ID || request.TenantID != binding.TenantID || expectedRuntimeGeneration == 0 ||
		lease < time.Second || lease > 15*time.Minute || now.IsZero() {
		return Permit{}, ErrInvalid
	}
	now = now.UTC()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Permit{}, err
	}
	defer transaction.Rollback()
	var storedBindingGeneration uint64
	var lifecycle Lifecycle
	if err = transaction.QueryRowContext(ctx, `SELECT generation,lifecycle FROM provider_policy_bindings_v1 WHERE binding_id=? AND tenant_id=?`, binding.ID, binding.TenantID).Scan(&storedBindingGeneration, &lifecycle); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Permit{}, ErrNotFound
		}
		return Permit{}, err
	}
	if storedBindingGeneration != binding.Generation || lifecycle != LifecycleEnabled {
		return Permit{}, ErrStale
	}
	snapshot, err := loadRuntime(ctx, transaction, binding.ID, binding.TenantID)
	if err != nil {
		return Permit{}, err
	}
	if snapshot.Generation != expectedRuntimeGeneration {
		return Permit{}, ErrStale
	}
	snapshot.Tokens = refillTokens(snapshot.Tokens, snapshot.RefilledAt, now, binding.Resilience)
	if snapshot.Inflight >= binding.Resilience.ConcurrencyLimit {
		return Permit{}, ErrDeferred
	}
	if snapshot.Tokens < 1 {
		return Permit{}, ErrDeferred
	}
	probe := request.HalfOpenProbe
	if snapshot.Circuit == CircuitOpen {
		return Permit{}, ErrDeferred
	}
	if snapshot.Circuit == CircuitHalfOpen && (!probe || snapshot.HalfOpenInflight >= binding.Resilience.HalfOpenProbeLimit) {
		return Permit{}, ErrDeferred
	}
	if snapshot.Circuit == CircuitClosed && probe {
		probe = false
	}
	permitID, err := randomIdentifier("ppp_")
	if err != nil {
		return Permit{}, err
	}
	fenceToken, err := randomHex(32)
	if err != nil {
		return Permit{}, err
	}
	permit := Permit{ID: PermitID(permitID), BindingID: binding.ID, TenantID: binding.TenantID, RuntimeGeneration: snapshot.Generation + 1,
		HalfOpenProbe: probe, AcquiredAt: now, ExpiresAt: now.Add(lease), FenceToken: fenceToken, FenceDigest: digest([]byte(fenceToken))}
	if permit.Validate() != nil {
		return Permit{}, ErrIntegrity
	}
	halfOpenIncrement := 0
	if probe {
		halfOpenIncrement = 1
	}
	result, err := transaction.ExecContext(ctx, `UPDATE provider_policy_runtime_v1 SET generation=generation+1,inflight=inflight+1,tokens=?,refilled_at=?,half_open_inflight=half_open_inflight+? WHERE binding_id=? AND tenant_id=? AND generation=?`,
		snapshot.Tokens-1, formatTime(now), halfOpenIncrement, binding.ID, binding.TenantID, snapshot.Generation)
	if err != nil {
		return Permit{}, err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return Permit{}, ErrStale
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO provider_policy_permits_v1(permit_id,binding_id,tenant_id,fence_token,fence_digest,half_open_probe,active,acquired_at,expires_at,completed_at,outcome) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		permit.ID, permit.BindingID, permit.TenantID, permit.FenceToken, permit.FenceDigest, permit.HalfOpenProbe, true, formatTime(permit.AcquiredAt), formatTime(permit.ExpiresAt), "", "")
	if err != nil {
		return Permit{}, err
	}
	if err = transaction.Commit(); err != nil {
		return Permit{}, err
	}
	return permit, nil
}

func (repository *SQLiteRepository) Complete(ctx context.Context, binding Binding, permit Permit, outcome OperationOutcome, now time.Time) (RuntimeSnapshot, error) {
	if binding.Validate() != nil || permit.Validate() != nil || permit.BindingID != binding.ID || permit.TenantID != binding.TenantID || now.IsZero() {
		return RuntimeSnapshot{}, ErrInvalid
	}
	switch outcome {
	case OutcomeSuccess, OutcomeTransient, OutcomePermanent:
	default:
		return RuntimeSnapshot{}, ErrInvalid
	}
	now = now.UTC()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	defer transaction.Rollback()
	var active bool
	var storedFence string
	var storedProbe bool
	var expiresAtText string
	err = transaction.QueryRowContext(ctx, `SELECT active,fence_token,half_open_probe,expires_at FROM provider_policy_permits_v1 WHERE permit_id=? AND binding_id=? AND tenant_id=?`,
		permit.ID, permit.BindingID, permit.TenantID).Scan(&active, &storedFence, &storedProbe, &expiresAtText)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeSnapshot{}, ErrNotFound
	}
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	expiresAt, err := parseTime(expiresAtText)
	if err != nil || !active || storedFence != permit.FenceToken || storedProbe != permit.HalfOpenProbe || now.After(expiresAt) {
		return RuntimeSnapshot{}, ErrStale
	}
	snapshot, err := loadRuntime(ctx, transaction, binding.ID, binding.TenantID)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	if snapshot.Generation < permit.RuntimeGeneration || snapshot.Inflight < 1 || permit.HalfOpenProbe && snapshot.HalfOpenInflight < 1 {
		return RuntimeSnapshot{}, ErrStale
	}
	snapshot.Inflight--
	if permit.HalfOpenProbe {
		snapshot.HalfOpenInflight--
	}
	switch outcome {
	case OutcomeSuccess:
		if permit.HalfOpenProbe && snapshot.Circuit == CircuitHalfOpen {
			snapshot.ConsecutiveFailures = 0
			if snapshot.HalfOpenInflight == 0 {
				snapshot.Circuit = CircuitClosed
				snapshot.OpenedUntil = time.Time{}
			}
		} else if snapshot.Circuit == CircuitClosed {
			snapshot.ConsecutiveFailures = 0
		}
	case OutcomeTransient:
		snapshot.ConsecutiveFailures++
		if permit.HalfOpenProbe || snapshot.Circuit == CircuitHalfOpen || snapshot.ConsecutiveFailures >= binding.Resilience.FailureThreshold {
			var cancelled int
			if err = transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM provider_policy_permits_v1 WHERE binding_id=? AND tenant_id=? AND active=1 AND half_open_probe=1 AND permit_id<>?`,
				binding.ID, binding.TenantID, permit.ID).Scan(&cancelled); err != nil {
				return RuntimeSnapshot{}, err
			}
			if cancelled > 0 {
				_, err = transaction.ExecContext(ctx, `UPDATE provider_policy_permits_v1 SET active=0,completed_at=?,outcome='circuit_reopened' WHERE binding_id=? AND tenant_id=? AND active=1 AND half_open_probe=1 AND permit_id<>?`,
					formatTime(now), binding.ID, binding.TenantID, permit.ID)
				if err != nil {
					return RuntimeSnapshot{}, err
				}
				snapshot.Inflight -= cancelled
				if snapshot.Inflight < 0 {
					return RuntimeSnapshot{}, ErrIntegrity
				}
			}
			snapshot.Circuit = CircuitOpen
			snapshot.OpenedUntil = now.Add(binding.Resilience.OpenDuration)
			snapshot.HalfOpenInflight = 0
		}
	case OutcomePermanent:
	}
	result, err := transaction.ExecContext(ctx, `UPDATE provider_policy_runtime_v1 SET generation=generation+1,inflight=?,circuit=?,consecutive_failures=?,opened_until=?,half_open_inflight=? WHERE binding_id=? AND tenant_id=? AND generation=?`,
		snapshot.Inflight, snapshot.Circuit, snapshot.ConsecutiveFailures, optionalTime(snapshot.OpenedUntil), snapshot.HalfOpenInflight, binding.ID, binding.TenantID, snapshot.Generation)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return RuntimeSnapshot{}, ErrStale
	}
	result, err = transaction.ExecContext(ctx, `UPDATE provider_policy_permits_v1 SET active=0,completed_at=?,outcome=? WHERE permit_id=? AND active=1 AND fence_token=?`,
		formatTime(now), outcome, permit.ID, permit.FenceToken)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	affected, _ = result.RowsAffected()
	if affected != 1 {
		return RuntimeSnapshot{}, ErrStale
	}
	snapshot.Generation++
	if err = transaction.Commit(); err != nil {
		return RuntimeSnapshot{}, err
	}
	return snapshot, nil
}

func (repository *SQLiteRepository) expirePermits(ctx context.Context, transaction *sql.Tx, binding Binding, now time.Time) error {
	rows, err := transaction.QueryContext(ctx, `SELECT permit_id,half_open_probe FROM provider_policy_permits_v1 WHERE binding_id=? AND tenant_id=? AND active=1 AND expires_at<=?`,
		binding.ID, binding.TenantID, formatTime(now))
	if err != nil {
		return err
	}
	count := 0
	probes := 0
	for rows.Next() {
		var permitID string
		var probe bool
		if err = rows.Scan(&permitID, &probe); err != nil {
			rows.Close()
			return err
		}
		count++
		if probe {
			probes++
		}
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	_, err = transaction.ExecContext(ctx, `UPDATE provider_policy_permits_v1 SET active=0,completed_at=?,outcome='lease_expired' WHERE binding_id=? AND tenant_id=? AND active=1 AND expires_at<=?`,
		formatTime(now), binding.ID, binding.TenantID, formatTime(now))
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `UPDATE provider_policy_runtime_v1 SET generation=generation+1,inflight=MAX(0,inflight-?),half_open_inflight=MAX(0,half_open_inflight-?) WHERE binding_id=? AND tenant_id=?`,
		count, probes, binding.ID, binding.TenantID)
	return err
}

func loadRuntime(ctx context.Context, querier interface{ QueryRowContext(context.Context, string, ...any) *sql.Row }, bindingID BindingID, tenantID TenantID) (RuntimeSnapshot, error) {
	var snapshot RuntimeSnapshot
	var refilledAtText, openedUntilText string
	err := querier.QueryRowContext(ctx, `SELECT generation,inflight,tokens,refilled_at,circuit,consecutive_failures,opened_until,half_open_inflight FROM provider_policy_runtime_v1 WHERE binding_id=? AND tenant_id=?`,
		bindingID, tenantID).Scan(&snapshot.Generation, &snapshot.Inflight, &snapshot.Tokens, &refilledAtText, &snapshot.Circuit, &snapshot.ConsecutiveFailures, &openedUntilText, &snapshot.HalfOpenInflight)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeSnapshot{}, ErrNotFound
	}
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	snapshot.RefilledAt, err = parseTime(refilledAtText)
	if err != nil {
		return RuntimeSnapshot{}, ErrIntegrity
	}
	if openedUntilText != "" {
		snapshot.OpenedUntil, err = parseTime(openedUntilText)
		if err != nil {
			return RuntimeSnapshot{}, ErrIntegrity
		}
	}
	return snapshot, nil
}

func (repository *SQLiteRepository) RecordObservation(ctx context.Context, observation Observation) error {
	if observation.Validate() != nil {
		return ErrInvalid
	}
	document, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	_, err = repository.db.ExecContext(ctx, `INSERT INTO provider_policy_observations_v1(observation_id,binding_id,tenant_id,health,observed_at,digest,document) VALUES(?,?,?,?,?,?,?)`,
		observation.ID, observation.BindingID, observation.TenantID, observation.Health, formatTime(observation.ObservedAt), observation.Digest, document)
	if err != nil {
		return ErrConflict
	}
	return nil
}

func (repository *SQLiteRepository) LatestObservation(ctx context.Context, tenantID TenantID, bindingID BindingID) (Observation, error) {
	if !validID(string(tenantID)) || !validID(string(bindingID)) {
		return Observation{}, ErrInvalid
	}
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM provider_policy_observations_v1 WHERE tenant_id=? AND binding_id=? ORDER BY observed_at DESC,observation_id DESC LIMIT 1`,
		tenantID, bindingID).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return Observation{}, ErrNotFound
	}
	if err != nil {
		return Observation{}, err
	}
	var observation Observation
	if decodeStrict(document, &observation) != nil || observation.Validate() != nil || observation.TenantID != tenantID || observation.BindingID != bindingID {
		return Observation{}, ErrIntegrity
	}
	return observation, nil
}

func (repository *SQLiteRepository) BeginWorkflow(ctx context.Context, binding Binding, expectedBindingGeneration uint64, workflow LifecycleWorkflow) error {
	if binding.Validate() != nil || binding.Generation != expectedBindingGeneration+1 || workflow.Validate() != nil || workflow.BindingID != binding.ID || workflow.TenantID != binding.TenantID ||
		workflow.BindingGeneration != binding.Generation || workflow.Generation != 1 || workflow.State != WorkflowPending || binding.Lifecycle == LifecycleEnabled {
		return ErrInvalid
	}
	bindingDocument, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	workflowDocument, err := json.Marshal(workflow)
	if err != nil {
		return err
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `UPDATE provider_policy_bindings_v1 SET generation=?,lifecycle=?,document=?,updated_at=? WHERE binding_id=? AND tenant_id=? AND generation=?`,
		binding.Generation, binding.Lifecycle, bindingDocument, formatTime(binding.UpdatedAt), binding.ID, binding.TenantID, expectedBindingGeneration)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrStale
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO provider_policy_workflows_v1(workflow_id,binding_id,tenant_id,kind,state,generation,document,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		workflow.ID, workflow.BindingID, workflow.TenantID, workflow.Kind, workflow.State, workflow.Generation, workflowDocument, formatTime(workflow.UpdatedAt))
	if err != nil {
		return ErrConflict
	}
	return transaction.Commit()
}

func (repository *SQLiteRepository) LoadWorkflow(ctx context.Context, tenantID TenantID, workflowID WorkflowID) (LifecycleWorkflow, error) {
	if !validID(string(tenantID)) || !validID(string(workflowID)) {
		return LifecycleWorkflow{}, ErrInvalid
	}
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM provider_policy_workflows_v1 WHERE tenant_id=? AND workflow_id=?`, tenantID, workflowID).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return LifecycleWorkflow{}, ErrNotFound
	}
	if err != nil {
		return LifecycleWorkflow{}, err
	}
	var workflow LifecycleWorkflow
	if decodeStrict(document, &workflow) != nil || workflow.Validate() != nil || workflow.TenantID != tenantID || workflow.ID != workflowID {
		return LifecycleWorkflow{}, ErrIntegrity
	}
	return workflow, nil
}

func (repository *SQLiteRepository) TransitionWorkflow(ctx context.Context, workflow LifecycleWorkflow, expectedGeneration uint64, binding *Binding, expectedBindingGeneration uint64) error {
	if workflow.Validate() != nil || workflow.Generation != expectedGeneration+1 || expectedGeneration == 0 || workflow.State == WorkflowPending {
		return ErrInvalid
	}
	document, err := json.Marshal(workflow)
	if err != nil {
		return err
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if binding != nil {
		if binding.Validate() != nil || binding.ID != workflow.BindingID || binding.TenantID != workflow.TenantID || binding.Generation != expectedBindingGeneration+1 ||
			workflow.Kind != WorkflowReauthorization || workflow.State != WorkflowCompleted || binding.Lifecycle != LifecycleEnabled {
			return ErrInvalid
		}
		bindingDocument, marshalErr := json.Marshal(binding)
		if marshalErr != nil {
			return marshalErr
		}
		bindingResult, updateErr := transaction.ExecContext(ctx, `UPDATE provider_policy_bindings_v1 SET generation=?,lifecycle=?,document=?,updated_at=? WHERE binding_id=? AND tenant_id=? AND generation=?`,
			binding.Generation, binding.Lifecycle, bindingDocument, formatTime(binding.UpdatedAt), binding.ID, binding.TenantID, expectedBindingGeneration)
		if updateErr != nil {
			return updateErr
		}
		bindingAffected, rowsErr := bindingResult.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if bindingAffected != 1 {
			return ErrStale
		}
	} else if expectedBindingGeneration != 0 {
		return ErrInvalid
	}
	result, err := transaction.ExecContext(ctx, `UPDATE provider_policy_workflows_v1 SET state=?,generation=?,document=?,updated_at=? WHERE workflow_id=? AND binding_id=? AND tenant_id=? AND generation=?`,
		workflow.State, workflow.Generation, document, formatTime(workflow.UpdatedAt), workflow.ID, workflow.BindingID, workflow.TenantID, expectedGeneration)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrStale
	}
	return transaction.Commit()
}

func formatTime(value time.Time) string { return value.UTC().Format(databaseTimeFormat) }

func parseTime(value string) (time.Time, error) { return time.Parse(databaseTimeFormat, value) }

func optionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return formatTime(value)
}

func randomIdentifier(prefix string) (string, error) {
	value, err := randomHex(16)
	if err != nil {
		return "", err
	}
	return prefix + value, nil
}

func randomHex(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func decodeStrict(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrIntegrity
	}
	return nil
}
