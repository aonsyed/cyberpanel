package outboundwebhooks

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteRepository struct{ db *sql.DB }

const databaseTimeFormat = "2006-01-02T15:04:05.000000000Z"

func formatDatabaseTime(value time.Time) string { return value.UTC().Format(databaseTimeFormat) }
func parseDatabaseTime(value string) (time.Time, error) { return time.Parse(databaseTimeFormat, value) }

func OpenSQLiteRepository(path string) (*SQLiteRepository, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return &SQLiteRepository{db: db}, nil
}

func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &SQLiteRepository{db: db}, nil
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
		`CREATE TABLE IF NOT EXISTS outbound_webhook_endpoints_v1 (
			endpoint_id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			document BLOB NOT NULL,
			enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
			rate_per_minute INTEGER NOT NULL CHECK (rate_per_minute > 0),
			rate_burst INTEGER NOT NULL CHECK (rate_burst > 0),
			rate_tokens REAL NOT NULL CHECK (rate_tokens >= 0),
			rate_updated_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS outbound_webhook_endpoints_tenant_v1 ON outbound_webhook_endpoints_v1(tenant_id, endpoint_id)`,
		`CREATE TABLE IF NOT EXISTS outbound_webhook_outbox_v1 (
			delivery_id TEXT PRIMARY KEY,
			deduplication_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			endpoint_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'retry', 'succeeded', 'dead_letter')),
			attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
			generation INTEGER NOT NULL CHECK (generation > 0),
			next_attempt_at TEXT NOT NULL,
			lease_owner TEXT NOT NULL DEFAULT '',
			lease_token TEXT NOT NULL DEFAULT '',
			lease_started_at TEXT NOT NULL DEFAULT '',
			lease_until TEXT NOT NULL DEFAULT '',
			delivery_document BLOB NOT NULL,
			endpoint_document BLOB NOT NULL,
			body_digest TEXT NOT NULL,
			terminal_reason TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(endpoint_id, deduplication_id),
			FOREIGN KEY(endpoint_id) REFERENCES outbound_webhook_endpoints_v1(endpoint_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS outbound_webhook_outbox_ready_v1 ON outbound_webhook_outbox_v1(state, next_attempt_at, created_at)`,
		`CREATE INDEX IF NOT EXISTS outbound_webhook_outbox_tenant_v1 ON outbound_webhook_outbox_v1(tenant_id, endpoint_id, state)`,
		`CREATE TABLE IF NOT EXISTS outbound_webhook_attempts_v1 (
			delivery_id TEXT NOT NULL,
			attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
			fence_token TEXT NOT NULL,
			outcome TEXT NOT NULL CHECK (outcome IN ('delivered', 'retry', 'dead_letter', 'lease_expired')),
			http_status INTEGER NOT NULL,
			code TEXT NOT NULL,
			retry_after_ns INTEGER NOT NULL CHECK (retry_after_ns >= 0),
			response_digest TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			receipt_digest TEXT NOT NULL UNIQUE,
			document BLOB NOT NULL,
			PRIMARY KEY(delivery_id, attempt_number),
			FOREIGN KEY(delivery_id) REFERENCES outbound_webhook_outbox_v1(delivery_id)
		) STRICT`,
		`CREATE TRIGGER IF NOT EXISTS outbound_webhook_attempts_no_update_v1
			BEFORE UPDATE ON outbound_webhook_attempts_v1 BEGIN SELECT RAISE(ABORT, 'webhook attempts are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS outbound_webhook_attempts_no_delete_v1
			BEFORE DELETE ON outbound_webhook_attempts_v1 BEGIN SELECT RAISE(ABORT, 'webhook attempts are immutable'); END`,
	}
	for _, statement := range statements {
		if _, err := repository.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (repository *SQLiteRepository) PutEndpoint(ctx context.Context, endpoint Endpoint, expectedGeneration uint64) error {
	if endpoint.Validate() != nil || endpoint.Generation != expectedGeneration+1 || expectedGeneration > 9223372036854775807 {
		return ErrInvalid
	}
	document, err := json.Marshal(endpoint)
	if err != nil {
		return err
	}
	nowText := formatDatabaseTime(endpoint.UpdatedAt)
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if expectedGeneration == 0 {
		_, err = transaction.ExecContext(ctx, `INSERT INTO outbound_webhook_endpoints_v1
			(endpoint_id, tenant_id, generation, document, enabled, rate_per_minute, rate_burst, rate_tokens, rate_updated_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, endpoint.ID, endpoint.TenantID, endpoint.Generation, document, endpoint.Enabled,
			endpoint.Rate.RequestsPerMinute, endpoint.Rate.Burst, endpoint.Rate.Burst, nowText, nowText)
		if err != nil {
			return ErrConflict
		}
	} else {
		result, updateErr := transaction.ExecContext(ctx, `UPDATE outbound_webhook_endpoints_v1 SET generation = ?, document = ?, enabled = ?,
			rate_per_minute = ?, rate_burst = ?, rate_tokens = MIN(rate_tokens, ?), rate_updated_at = ?, updated_at = ?
			WHERE endpoint_id = ? AND tenant_id = ? AND generation = ?`, endpoint.Generation, document, endpoint.Enabled,
			endpoint.Rate.RequestsPerMinute, endpoint.Rate.Burst, endpoint.Rate.Burst, nowText, nowText, endpoint.ID, endpoint.TenantID, expectedGeneration)
		if updateErr != nil {
			return updateErr
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			return ErrStale
		}
	}
	return transaction.Commit()
}

func (repository *SQLiteRepository) LoadEndpoint(ctx context.Context, tenantID TenantID, endpointID EndpointID) (Endpoint, error) {
	if !validIdentifier(string(tenantID)) || !validIdentifier(string(endpointID)) {
		return Endpoint{}, ErrInvalid
	}
	var document []byte
	var generation int64
	err := repository.db.QueryRowContext(ctx, `SELECT generation, document FROM outbound_webhook_endpoints_v1 WHERE tenant_id = ? AND endpoint_id = ?`, tenantID, endpointID).
		Scan(&generation, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return Endpoint{}, ErrNotFound
	}
	if err != nil {
		return Endpoint{}, err
	}
	endpoint, err := decodeEndpoint(document)
	if err != nil || endpoint.TenantID != tenantID || endpoint.ID != endpointID || endpoint.Generation != uint64(generation) {
		return Endpoint{}, ErrIntegrity
	}
	return cloneEndpoint(endpoint), nil
}

func (repository *SQLiteRepository) Enqueue(ctx context.Context, delivery PreparedDelivery, now time.Time) (bool, error) {
	if delivery.Validate() != nil || now.IsZero() {
		return false, ErrInvalid
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer transaction.Rollback()
	var endpointDocument []byte
	err = transaction.QueryRowContext(ctx, `SELECT document FROM outbound_webhook_endpoints_v1 WHERE tenant_id = ? AND endpoint_id = ? AND enabled = 1`,
		delivery.Envelope.TenantID, delivery.Envelope.EndpointID).Scan(&endpointDocument)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	endpoint, err := decodeEndpoint(endpointDocument)
	if err != nil || !endpoint.Enabled || endpoint.Audience != delivery.Envelope.Audience || !endpoint.Selects(delivery.Envelope.Type) {
		return false, ErrIntegrity
	}
	var existingDocument []byte
	err = transaction.QueryRowContext(ctx, `SELECT delivery_document FROM outbound_webhook_outbox_v1 WHERE delivery_id = ?`, delivery.Envelope.DeliveryID).Scan(&existingDocument)
	if err == nil {
		existing, decodeErr := decodePreparedDelivery(existingDocument)
		if decodeErr != nil || existing.BodyDigest != delivery.BodyDigest || existing.Envelope.DeduplicationID != delivery.Envelope.DeduplicationID {
			return false, ErrIntegrity
		}
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	deliveryDocument, err := json.Marshal(delivery)
	if err != nil {
		return false, err
	}
	nowText := formatDatabaseTime(now)
	_, err = transaction.ExecContext(ctx, `INSERT INTO outbound_webhook_outbox_v1
		(delivery_id, deduplication_id, tenant_id, endpoint_id, event_type, state, attempt_count, generation, next_attempt_at,
		delivery_document, endpoint_document, body_digest, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'pending', 0, 1, ?, ?, ?, ?, ?, ?)`, delivery.Envelope.DeliveryID, delivery.Envelope.DeduplicationID,
		delivery.Envelope.TenantID, delivery.Envelope.EndpointID, delivery.Envelope.Type, nowText, deliveryDocument, endpointDocument,
		delivery.BodyDigest, nowText, nowText)
	if err != nil {
		return false, ErrConflict
	}
	if err := transaction.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

type claimCandidate struct {
	deliveryDocument []byte
	endpointDocument []byte
	deliveryID       string
	state            string
	attemptCount     int64
	generation       int64
	nextAttemptAt    string
	leaseOwner       string
	leaseToken       string
	leaseStartedAt   string
	leaseUntil       string
	ratePerMinute    int64
	rateBurst        int64
	rateTokens       float64
	rateUpdatedAt    string
}

func (repository *SQLiteRepository) Claim(ctx context.Context, worker WorkerID, now time.Time, lease time.Duration) (DeliveryClaim, error) {
	if !validIdentifier(string(worker)) || now.IsZero() || lease < 5*time.Second || lease > 5*time.Minute {
		return DeliveryClaim{}, ErrInvalid
	}
	now = now.UTC()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return DeliveryClaim{}, err
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, `SELECT o.delivery_document, o.endpoint_document, o.delivery_id, o.state, o.attempt_count, o.generation,
		o.next_attempt_at, o.lease_owner, o.lease_token, o.lease_started_at, o.lease_until,
		e.rate_per_minute, e.rate_burst, e.rate_tokens, e.rate_updated_at
		FROM outbound_webhook_outbox_v1 o JOIN outbound_webhook_endpoints_v1 e ON e.endpoint_id = o.endpoint_id
		WHERE e.enabled = 1 AND ((o.state IN ('pending', 'retry') AND o.next_attempt_at <= ?) OR (o.state = 'leased' AND o.lease_until <= ?))
		ORDER BY o.next_attempt_at, o.created_at LIMIT 64`, formatDatabaseTime(now), formatDatabaseTime(now))
	if err != nil {
		return DeliveryClaim{}, err
	}
	candidates := make([]claimCandidate, 0, 64)
	for rows.Next() {
		var candidate claimCandidate
		if err := rows.Scan(&candidate.deliveryDocument, &candidate.endpointDocument, &candidate.deliveryID, &candidate.state, &candidate.attemptCount,
			&candidate.generation, &candidate.nextAttemptAt, &candidate.leaseOwner, &candidate.leaseToken, &candidate.leaseStartedAt, &candidate.leaseUntil,
			&candidate.ratePerMinute, &candidate.rateBurst, &candidate.rateTokens, &candidate.rateUpdatedAt); err != nil {
			rows.Close()
			return DeliveryClaim{}, err
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return DeliveryClaim{}, err
	}
	if err := rows.Close(); err != nil {
		return DeliveryClaim{}, err
	}
	for _, candidate := range candidates {
		delivery, decodeErr := decodePreparedDelivery(candidate.deliveryDocument)
		endpoint, endpointErr := decodeEndpoint(candidate.endpointDocument)
		rateUpdatedAt, rateErr := parseDatabaseTime(candidate.rateUpdatedAt)
		nextAttemptAt, nextErr := parseDatabaseTime(candidate.nextAttemptAt)
		if decodeErr != nil || endpointErr != nil || rateErr != nil || candidate.deliveryID != string(delivery.Envelope.DeliveryID) ||
			nextErr != nil || endpoint.ID != delivery.Envelope.EndpointID || endpoint.TenantID != delivery.Envelope.TenantID ||
			candidate.attemptCount < 0 || candidate.attemptCount > 65535 || candidate.generation <= 0 || candidate.ratePerMinute <= 0 || candidate.rateBurst <= 0 {
			return DeliveryClaim{}, ErrIntegrity
		}
		if candidate.state == string(StateLeased) {
			if err := insertExpiredLeaseReceipt(ctx, transaction, delivery.Envelope.DeliveryID, candidate, now); err != nil {
				return DeliveryClaim{}, err
			}
		}
		tokens := replenishedTokens(candidate.rateTokens, float64(candidate.rateBurst), float64(candidate.ratePerMinute), rateUpdatedAt, now)
		if tokens < 1 {
			wait := time.Duration(math.Ceil((1-tokens)*60/float64(candidate.ratePerMinute)*float64(time.Second)))
			if wait < time.Second {
				wait = time.Second
			}
			state := candidate.state
			if state == string(StateLeased) {
				state = string(StateRetry)
			}
			_, err = transaction.ExecContext(ctx, `UPDATE outbound_webhook_outbox_v1 SET state = ?, next_attempt_at = ?, lease_owner = '', lease_token = '',
				lease_started_at = '', lease_until = '', generation = generation + 1, updated_at = ? WHERE delivery_id = ? AND generation = ?`,
				state, formatDatabaseTime(now.Add(wait)), formatDatabaseTime(now), delivery.Envelope.DeliveryID, candidate.generation)
			if err != nil {
				return DeliveryClaim{}, err
			}
			_, err = transaction.ExecContext(ctx, `UPDATE outbound_webhook_endpoints_v1 SET rate_tokens = ?, rate_updated_at = ? WHERE endpoint_id = ?`,
				tokens, formatDatabaseTime(now), endpoint.ID)
			if err != nil {
				return DeliveryClaim{}, err
			}
			continue
		}
		leaseToken, err := randomFenceToken()
		if err != nil {
			return DeliveryClaim{}, err
		}
		leaseUntil := now.Add(lease)
		result, err := transaction.ExecContext(ctx, `UPDATE outbound_webhook_outbox_v1 SET state = 'leased', attempt_count = attempt_count + 1,
			generation = generation + 1, lease_owner = ?, lease_token = ?, lease_started_at = ?, lease_until = ?, updated_at = ?
			WHERE delivery_id = ? AND generation = ? AND ((state IN ('pending', 'retry') AND next_attempt_at <= ?) OR (state = 'leased' AND lease_until <= ?))`,
			worker, leaseToken, formatDatabaseTime(now), formatDatabaseTime(leaseUntil), formatDatabaseTime(now), delivery.Envelope.DeliveryID,
			candidate.generation, formatDatabaseTime(now), formatDatabaseTime(now))
		if err != nil {
			return DeliveryClaim{}, err
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			continue
		}
		if _, err := transaction.ExecContext(ctx, `UPDATE outbound_webhook_endpoints_v1 SET rate_tokens = ?, rate_updated_at = ? WHERE endpoint_id = ?`,
			tokens-1, formatDatabaseTime(now), endpoint.ID); err != nil {
			return DeliveryClaim{}, err
		}
		if err := transaction.Commit(); err != nil {
			return DeliveryClaim{}, err
		}
		return DeliveryClaim{Delivery: delivery, Endpoint: endpoint, State: StateLeased, Attempt: uint16(candidate.attemptCount + 1),
			Generation: uint64(candidate.generation + 1), LeaseOwner: worker, LeaseToken: leaseToken, LeaseUntil: leaseUntil, NextAttemptAt: nextAttemptAt}, nil
	}
	if err := transaction.Commit(); err != nil {
		return DeliveryClaim{}, err
	}
	return DeliveryClaim{}, ErrNotFound
}

func (repository *SQLiteRepository) Finalize(ctx context.Context, claim DeliveryClaim, result SendResult, now time.Time) (AttemptReceipt, error) {
	if now.IsZero() || result.Validate() != nil || claim.Delivery.Validate() != nil || claim.Endpoint.Validate() != nil || claim.State != StateLeased ||
		!validIdentifier(string(claim.LeaseOwner)) || !validDigest(claim.LeaseToken) {
		return AttemptReceipt{}, ErrInvalid
	}
	now = now.UTC()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return AttemptReceipt{}, err
	}
	defer transaction.Rollback()
	var state, leaseOwner, leaseToken, leaseUntil string
	var generation, attemptCount int64
	err = transaction.QueryRowContext(ctx, `SELECT state, lease_owner, lease_token, lease_until, generation, attempt_count FROM outbound_webhook_outbox_v1 WHERE delivery_id = ?`,
		claim.Delivery.Envelope.DeliveryID).Scan(&state, &leaseOwner, &leaseToken, &leaseUntil, &generation, &attemptCount)
	if errors.Is(err, sql.ErrNoRows) {
		return AttemptReceipt{}, ErrNotFound
	}
	parsedLeaseUntil, parseErr := parseDatabaseTime(leaseUntil)
	if err != nil || parseErr != nil || state != string(StateLeased) || leaseOwner != string(claim.LeaseOwner) || leaseToken != claim.LeaseToken || generation != int64(claim.Generation) ||
		attemptCount != int64(claim.Attempt) || !parsedLeaseUntil.After(now) {
		return AttemptReceipt{}, ErrLeaseLost
	}
	nextState := StateDeadLetter
	outcome := OutcomeDeadLetter
	nextAttemptAt := now
	terminalReason := result.Code
	if result.Delivered {
		nextState = StateSucceeded
		outcome = OutcomeDelivered
		terminalReason = ""
	} else if result.Retryable && claim.Attempt < claim.Endpoint.Retry.MaximumAttempts {
		nextState = StateRetry
		outcome = OutcomeRetry
		terminalReason = ""
		delay := exponentialBackoff(claim.Endpoint.Retry, claim.Attempt)
		if result.RetryAfter > delay {
			delay = result.RetryAfter
		}
		if delay > 24*time.Hour {
			delay = 24 * time.Hour
		}
		nextAttemptAt = now.Add(delay)
	}
	receipt := AttemptReceipt{DeliveryID: claim.Delivery.Envelope.DeliveryID, Attempt: claim.Attempt, FenceToken: claim.LeaseToken,
		Outcome: outcome, HTTPStatus: result.HTTPStatus, Code: result.Code, RetryAfter: result.RetryAfter, ResponseDigest: result.ResponseDigest,
		StartedAt: result.StartedAt.UTC(), FinishedAt: result.FinishedAt.UTC()}
	receipt.Digest = attemptReceiptDigest(receipt)
	if receipt.Validate() != nil {
		return AttemptReceipt{}, ErrIntegrity
	}
	updateResult, err := transaction.ExecContext(ctx, `UPDATE outbound_webhook_outbox_v1 SET state = ?, generation = generation + 1,
		next_attempt_at = ?, lease_owner = '', lease_token = '', lease_started_at = '', lease_until = '', terminal_reason = ?, updated_at = ?
		WHERE delivery_id = ? AND state = 'leased' AND lease_owner = ? AND lease_token = ? AND generation = ?`, nextState, formatDatabaseTime(nextAttemptAt),
		terminalReason, formatDatabaseTime(now), claim.Delivery.Envelope.DeliveryID, claim.LeaseOwner, claim.LeaseToken, claim.Generation)
	if err != nil {
		return AttemptReceipt{}, err
	}
	affected, _ := updateResult.RowsAffected()
	if affected != 1 {
		return AttemptReceipt{}, ErrLeaseLost
	}
	if err := insertAttemptReceipt(ctx, transaction, receipt); err != nil {
		return AttemptReceipt{}, err
	}
	if err := transaction.Commit(); err != nil {
		return AttemptReceipt{}, err
	}
	return receipt, nil
}

func (repository *SQLiteRepository) Health(ctx context.Context, tenantID TenantID, endpointID EndpointID, now time.Time) (DeliveryHealth, error) {
	if !validIdentifier(string(tenantID)) || endpointID != "" && !validIdentifier(string(endpointID)) || now.IsZero() {
		return DeliveryHealth{}, ErrInvalid
	}
	if endpointID != "" {
		var exists int
		err := repository.db.QueryRowContext(ctx, `SELECT 1 FROM outbound_webhook_endpoints_v1 WHERE tenant_id = ? AND endpoint_id = ?`, tenantID, endpointID).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return DeliveryHealth{}, ErrNotFound
		}
		if err != nil {
			return DeliveryHealth{}, err
		}
	}
	query := `SELECT
		COALESCE(SUM(CASE WHEN state = 'pending' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN state = 'leased' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN state = 'retry' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN state = 'succeeded' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN state = 'dead_letter' THEN 1 ELSE 0 END), 0),
		COALESCE(MIN(CASE WHEN state IN ('pending', 'retry') THEN created_at ELSE NULL END), '')
		FROM outbound_webhook_outbox_v1 WHERE tenant_id = ?`
	arguments := []any{tenantID}
	if endpointID != "" {
		query += ` AND endpoint_id = ?`
		arguments = append(arguments, endpointID)
	}
	var health DeliveryHealth
	var oldest string
	health.TenantID = tenantID
	health.EndpointID = endpointID
	err := repository.db.QueryRowContext(ctx, query, arguments...).Scan(&health.Pending, &health.Leased, &health.Retrying, &health.Succeeded, &health.DeadLetter, &oldest)
	if err != nil {
		return DeliveryHealth{}, err
	}
	health.ObservedAt = now.UTC()
	health.State = "healthy"
	if oldest != "" {
		parsed, parseErr := parseDatabaseTime(oldest)
		if parseErr != nil {
			return DeliveryHealth{}, ErrIntegrity
		}
		health.OldestPending = parsed
	}
	if health.DeadLetter > 0 {
		health.State = "degraded"
		health.Reason = "dead_letter_deliveries"
	} else if !health.OldestPending.IsZero() && health.OldestPending.Before(now.Add(-5*time.Minute)) {
		health.State = "degraded"
		health.Reason = "delivery_backlog"
	}
	return health, nil
}

func insertExpiredLeaseReceipt(ctx context.Context, transaction *sql.Tx, deliveryID DeliveryID, candidate claimCandidate, now time.Time) error {
	if candidate.attemptCount <= 0 || candidate.attemptCount > 65535 || !validDigest(candidate.leaseToken) {
		return ErrIntegrity
	}
	startedAt, err := parseDatabaseTime(candidate.leaseStartedAt)
	if err != nil {
		return ErrIntegrity
	}
	receipt := AttemptReceipt{DeliveryID: deliveryID, Attempt: uint16(candidate.attemptCount), FenceToken: candidate.leaseToken,
		Outcome: OutcomeLeaseExpired, Code: "lease_expired", StartedAt: startedAt, FinishedAt: now}
	receipt.Digest = attemptReceiptDigest(receipt)
	return insertAttemptReceipt(ctx, transaction, receipt)
}

func insertAttemptReceipt(ctx context.Context, transaction *sql.Tx, receipt AttemptReceipt) error {
	if receipt.Validate() != nil {
		return ErrIntegrity
	}
	document, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO outbound_webhook_attempts_v1
		(delivery_id, attempt_number, fence_token, outcome, http_status, code, retry_after_ns, response_digest, started_at, finished_at, receipt_digest, document)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, receipt.DeliveryID, receipt.Attempt, receipt.FenceToken, receipt.Outcome, receipt.HTTPStatus,
		receipt.Code, int64(receipt.RetryAfter), receipt.ResponseDigest, formatDatabaseTime(receipt.StartedAt),
		formatDatabaseTime(receipt.FinishedAt), receipt.Digest, document)
	return err
}

func replenishedTokens(tokens, burst, perMinute float64, updatedAt, now time.Time) float64 {
	if tokens < 0 {
		tokens = 0
	}
	if elapsed := now.Sub(updatedAt); elapsed > 0 {
		tokens += elapsed.Seconds() * perMinute / 60
	}
	if tokens > burst {
		tokens = burst
	}
	return tokens
}

func exponentialBackoff(policy RetryPolicy, attempt uint16) time.Duration {
	delay := policy.InitialBackoff
	for current := uint16(1); current < attempt && delay < policy.MaximumBackoff; current++ {
		if delay > policy.MaximumBackoff/2 {
			return policy.MaximumBackoff
		}
		delay *= 2
	}
	if delay > policy.MaximumBackoff {
		return policy.MaximumBackoff
	}
	return delay
}

func randomFenceToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func decodeEndpoint(document []byte) (Endpoint, error) {
	var endpoint Endpoint
	if decodeStoredJSON(document, &endpoint) != nil || endpoint.Validate() != nil {
		return Endpoint{}, ErrIntegrity
	}
	return endpoint, nil
}

func decodePreparedDelivery(document []byte) (PreparedDelivery, error) {
	var delivery PreparedDelivery
	if decodeStoredJSON(document, &delivery) != nil || delivery.Validate() != nil {
		return PreparedDelivery{}, ErrIntegrity
	}
	return delivery, nil
}

func decodeStoredJSON(document []byte, target any) error {
	if len(document) == 0 || len(document) > 1<<20 {
		return ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrIntegrity
	}
	return nil
}

func cloneEndpoint(endpoint Endpoint) Endpoint {
	endpoint.EventSelectors = append([]string(nil), endpoint.EventSelectors...)
	return endpoint
}

var _ Repository = (*SQLiteRepository)(nil)
