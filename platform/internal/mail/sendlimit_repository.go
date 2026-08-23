package mail

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

const SendLimitSchema = `
CREATE TABLE IF NOT EXISTS mail_send_limit_policies_v1 (
    tenant_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
    effective_at TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    policy_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id,scope_kind,domain_id,mailbox_id,revision)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS mail_send_limit_policy_heads_v1 (
    tenant_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (tenant_id,scope_kind,domain_id,mailbox_id),
    FOREIGN KEY (tenant_id,scope_kind,domain_id,mailbox_id,revision)
        REFERENCES mail_send_limit_policies_v1 (tenant_id,scope_kind,domain_id,mailbox_id,revision)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS mail_send_limit_decisions_v1 (
    tenant_id TEXT NOT NULL,
    message_key TEXT NOT NULL,
    effect_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    decision TEXT NOT NULL,
    decision_code TEXT NOT NULL,
    receipt_digest TEXT NOT NULL,
    receipt_json BLOB NOT NULL,
    decided_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id,message_key),
    UNIQUE (tenant_id,effect_key)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS mail_send_limit_reservations_v1 (
    reservation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    message_key TEXT NOT NULL,
    effect_key TEXT NOT NULL,
    decision_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','expired')),
    messages INTEGER NOT NULL CHECK (messages > 0),
    recipients INTEGER NOT NULL CHECK (recipients > 0),
    bytes INTEGER NOT NULL CHECK (bytes > 0),
    hour_start TEXT NOT NULL,
    month_start TEXT NOT NULL,
    reserved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    finalized_at TEXT,
    UNIQUE (tenant_id,message_key),
    UNIQUE (tenant_id,effect_key)
);
CREATE INDEX IF NOT EXISTS mail_send_limit_reservation_expiry_v1
    ON mail_send_limit_reservations_v1 (state,expires_at,reservation_id);
CREATE TABLE IF NOT EXISTS mail_send_limit_counters_v1 (
    tenant_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    window_kind TEXT NOT NULL,
    bucket_start TEXT NOT NULL,
    reserved_messages INTEGER NOT NULL CHECK (reserved_messages >= 0),
    reserved_recipients INTEGER NOT NULL CHECK (reserved_recipients >= 0),
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes >= 0),
    committed_messages INTEGER NOT NULL CHECK (committed_messages >= 0),
    committed_recipients INTEGER NOT NULL CHECK (committed_recipients >= 0),
    committed_bytes INTEGER NOT NULL CHECK (committed_bytes >= 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id,scope_kind,domain_id,mailbox_id,window_kind,bucket_start)
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS mail_send_limit_decision_no_update_v1
BEFORE UPDATE ON mail_send_limit_decisions_v1 BEGIN
    SELECT RAISE(ABORT,'send-limit decisions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS mail_send_limit_decision_no_delete_v1
BEFORE DELETE ON mail_send_limit_decisions_v1 BEGIN
    SELECT RAISE(ABORT,'send-limit decisions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS mail_send_limit_policy_no_update_v1
BEFORE UPDATE ON mail_send_limit_policies_v1 BEGIN
    SELECT RAISE(ABORT,'send-limit policy revisions are immutable');
END;
`

type SendLimitRepository interface {
	PutPolicy(context.Context, SendLimitPolicy, uint64) (SendLimitPolicy, error)
	EffectivePolicies(context.Context, SendLimitIdentity, time.Time) ([]SendLimitPolicy, error)
	ListPolicies(context.Context, string, SendLimitScopeKind, DomainID, MailboxID, uint32) ([]SendLimitPolicy, error)
	Reserve(context.Context, SendLimitReservationRequest) (SendLimitDecisionReceipt, error)
	Commit(context.Context, SendLimitFinalizeRequest) (SendLimitLifecycleReceipt, error)
	Release(context.Context, SendLimitFinalizeRequest) (SendLimitLifecycleReceipt, error)
	Scavenge(context.Context, time.Time, uint32) (uint32, error)
	Usage(context.Context, string, time.Time, uint32) ([]SendLimitUsageProjection, error)
}

type SQLSendLimitRepository struct {
	DB     *sql.DB
	writer sync.Mutex
}

func NewSQLSendLimitRepository(db *sql.DB) (*SQLSendLimitRepository, error) {
	if db == nil {
		return nil, ErrInvalidCommand
	}
	return &SQLSendLimitRepository{DB: db}, nil
}

func (repository *SQLSendLimitRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.DB == nil || ctx == nil {
		return ErrInvalidCommand
	}
	var mode string
	if err := repository.DB.QueryRowContext(ctx, `PRAGMA journal_mode=WAL`).Scan(&mode); err != nil || strings.ToLower(mode) != "wal" {
		return errors.Join(ErrInvalidReceipt, err)
	}
	for _, pragma := range []string{`PRAGMA synchronous=FULL`, `PRAGMA foreign_keys=ON`, `PRAGMA busy_timeout=5000`} {
		if _, err := repository.DB.ExecContext(ctx, pragma); err != nil {
			return err
		}
	}
	_, err := repository.DB.ExecContext(ctx, SendLimitSchema)
	return err
}

func (repository *SQLSendLimitRepository) PutPolicy(ctx context.Context, policy SendLimitPolicy, expected uint64) (SendLimitPolicy, error) {
	if repository == nil || repository.DB == nil || ctx == nil || policy.Validate() != nil || policy.Revision != expected+1 {
		return SendLimitPolicy{}, ErrInvalidCommand
	}
	raw, err := encodeSendLimitPolicy(policy)
	if err != nil {
		return SendLimitPolicy{}, err
	}
	digest, err := policy.Digest()
	if err != nil {
		return SendLimitPolicy{}, err
	}
	err = repository.immediate(ctx, func(connection *sql.Conn) error {
		var current uint64
		var priorEffective string
		var priorCreated string
		loadErr := connection.QueryRowContext(ctx, `SELECT h.revision,p.effective_at,p.created_at
            FROM mail_send_limit_policy_heads_v1 h JOIN mail_send_limit_policies_v1 p
            ON p.tenant_id=h.tenant_id AND p.scope_kind=h.scope_kind AND p.domain_id=h.domain_id AND p.mailbox_id=h.mailbox_id AND p.revision=h.revision
            WHERE h.tenant_id=? AND h.scope_kind=? AND h.domain_id=? AND h.mailbox_id=?`, sendLimitScopeColumns(policy.Scope)...).Scan(&current, &priorEffective, &priorCreated)
		if errors.Is(loadErr, sql.ErrNoRows) {
			if expected != 0 {
				return ErrConflict
			}
		} else if loadErr != nil {
			return loadErr
		} else {
			if current != expected {
				return ErrConflict
			}
			priorEffectiveAt, parseErr := time.Parse(time.RFC3339Nano, priorEffective)
			priorCreatedAt, createdErr := time.Parse(time.RFC3339Nano, priorCreated)
			if parseErr != nil || createdErr != nil || policy.EffectiveAt.Before(priorEffectiveAt) || policy.CreatedAt.Before(priorCreatedAt) {
				return ErrInvalidCommand
			}
		}
		columns := sendLimitScopeColumns(policy.Scope)
		if _, insertErr := connection.ExecContext(ctx, `INSERT INTO mail_send_limit_policies_v1
            (tenant_id,scope_kind,domain_id,mailbox_id,revision,enabled,effective_at,policy_digest,policy_json,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)`, columns[0], columns[1], columns[2], columns[3], policy.Revision, policy.Enabled, sendLimitTimestamp(policy.EffectiveAt), digest, raw, sendLimitTimestamp(policy.CreatedAt)); insertErr != nil {
			return insertErr
		}
		if expected == 0 {
			_, loadErr = connection.ExecContext(ctx, `INSERT INTO mail_send_limit_policy_heads_v1
                (tenant_id,scope_kind,domain_id,mailbox_id,revision) VALUES(?,?,?,?,?)`, columns[0], columns[1], columns[2], columns[3], policy.Revision)
			return loadErr
		}
		result, updateErr := connection.ExecContext(ctx, `UPDATE mail_send_limit_policy_heads_v1 SET revision=?
            WHERE tenant_id=? AND scope_kind=? AND domain_id=? AND mailbox_id=? AND revision=?`, policy.Revision, columns[0], columns[1], columns[2], columns[3], expected)
		if updateErr != nil {
			return updateErr
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil || changed != 1 {
			return errors.Join(ErrConflict, rowsErr)
		}
		return nil
	})
	if err != nil {
		return SendLimitPolicy{}, err
	}
	return policy, nil
}

func (repository *SQLSendLimitRepository) EffectivePolicies(ctx context.Context, identity SendLimitIdentity, at time.Time) ([]SendLimitPolicy, error) {
	if repository == nil || repository.DB == nil || ctx == nil || identity.Validate() != nil || !sendLimitCanonicalTime(at) {
		return nil, ErrInvalidCommand
	}
	return loadEffectiveSendLimitPolicies(ctx, repository.DB, identity, at)
}

func (repository *SQLSendLimitRepository) ListPolicies(ctx context.Context, tenant string, afterKind SendLimitScopeKind, afterDomain DomainID, afterMailbox MailboxID, limit uint32) ([]SendLimitPolicy, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenant) || limit == 0 || limit > SendLimitMaximumList || !validSendLimitAfter(afterKind, afterDomain, afterMailbox) {
		return nil, ErrInvalidCommand
	}
	rows, err := repository.DB.QueryContext(ctx, `SELECT p.tenant_id,p.scope_kind,p.domain_id,p.mailbox_id,p.policy_json
        FROM mail_send_limit_policy_heads_v1 h JOIN mail_send_limit_policies_v1 p
        ON p.tenant_id=h.tenant_id AND p.scope_kind=h.scope_kind AND p.domain_id=h.domain_id AND p.mailbox_id=h.mailbox_id AND p.revision=h.revision
        WHERE p.tenant_id=? AND (p.scope_kind>? OR (p.scope_kind=? AND p.domain_id>?) OR (p.scope_kind=? AND p.domain_id=? AND p.mailbox_id>?))
        ORDER BY p.scope_kind,p.domain_id,p.mailbox_id LIMIT ?`, tenant, afterKind, afterKind, afterDomain, afterKind, afterDomain, afterMailbox, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := make([]SendLimitPolicy, 0, limit)
	for rows.Next() {
		var storedTenant string
		var storedKind SendLimitScopeKind
		var storedDomain DomainID
		var storedMailbox MailboxID
		var raw []byte
		if err = rows.Scan(&storedTenant, &storedKind, &storedDomain, &storedMailbox, &raw); err != nil {
			return nil, err
		}
		policy, decodeErr := decodeSendLimitPolicy(raw)
		if decodeErr != nil || policy.Scope.TenantID != storedTenant || policy.Scope.Kind != storedKind || policy.Scope.DomainID != storedDomain || policy.Scope.MailboxID != storedMailbox {
			return nil, ErrInvalidReceipt
		}
		policies = append(policies, policy)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return policies, nil
}

func (repository *SQLSendLimitRepository) Reserve(ctx context.Context, request SendLimitReservationRequest) (SendLimitDecisionReceipt, error) {
	if repository == nil || repository.DB == nil || ctx == nil || request.Validate() != nil {
		return SendLimitDecisionReceipt{}, ErrInvalidCommand
	}
	requestDigest, err := sendLimitReservationRequestDigest(request)
	if err != nil {
		return SendLimitDecisionReceipt{}, err
	}
	var receipt SendLimitDecisionReceipt
	err = repository.immediate(ctx, func(connection *sql.Conn) error {
		prior, found, loadErr := lookupSendLimitDecision(ctx, connection, request.Identity.TenantID, request.MessageKey, request.EffectKey, requestDigest)
		if loadErr != nil {
			return loadErr
		}
		if found {
			if prior.Decision == SendLimitPermit {
				reservation, reservationErr := loadSendLimitReservation(ctx, connection, prior.ReservationID)
				if reservationErr != nil {
					return reservationErr
				}
				if reservation.TenantID != request.Identity.TenantID || reservation.DomainID != request.Identity.DomainID || reservation.MailboxID != request.Identity.MailboxID || reservation.MessageKey != request.MessageKey || reservation.EffectKey != request.EffectKey || reservation.DecisionDigest != prior.ReceiptDigest {
					return ErrInvalidReceipt
				}
				if reservation.State == SendLimitReleased || reservation.State == SendLimitExpired || reservation.State == SendLimitReserved && !request.At.Before(reservation.ExpiresAt) || request.At.Before(prior.ReservedAt) {
					return ErrConflict
				}
			}
			receipt = prior
			return nil
		}
		if loadErr = expireDueSendLimitTenant(ctx, connection, request.Identity.TenantID, request.At); loadErr != nil {
			return loadErr
		}
		policies, policyErr := loadEffectiveSendLimitPolicies(ctx, connection, request.Identity, request.At)
		if policyErr != nil {
			return policyErr
		}
		active := make([]SendLimitPolicy, 0, len(policies))
		bindings := make([]SendLimitPolicyBinding, 0, len(policies))
		for _, policy := range policies {
			if !policy.Enabled {
				continue
			}
			digest, digestErr := policy.Digest()
			if digestErr != nil {
				return digestErr
			}
			active = append(active, policy)
			bindings = append(bindings, SendLimitPolicyBinding{Scope: policy.Scope, Revision: policy.Revision, Digest: digest})
		}
		receipt = SendLimitDecisionReceipt{MessageKey: request.MessageKey, EffectKey: request.EffectKey, RequestDigest: requestDigest, Decision: SendLimitPermit, Code: SendLimitCodePermit, Policies: bindings, ReservedAt: request.At}
		if len(active) == 0 {
			receipt.Decision = SendLimitDefer
			receipt.Code = SendLimitCodePolicyUnavailable
			return insertSendLimitDecision(ctx, connection, request.Identity.TenantID, &receipt)
		}
		emergency := !request.Identity.DependenciesAvailable
		if emergency {
			for _, policy := range active {
				if policy.Dependency.Mode == SendLimitFailClosed {
					receipt.Decision = SendLimitDefer
					receipt.Code = SendLimitCodeDependencyUnavailable
					return insertSendLimitDecision(ctx, connection, request.Identity.TenantID, &receipt)
				}
			}
			receipt.Emergency = true
		}
		amount := request.Amount()
		hourStart, hourReset := sendLimitHourBounds(request.At)
		monthStart, monthReset := sendLimitMonthBounds(request.At)
		warning := false
		for _, policy := range active {
			for _, window := range []SendLimitWindowKind{SendLimitHour, SendLimitMonth} {
				bucketStart := hourStart
				reset := hourReset
				limit := policy.Hourly
				threshold := policy.Warnings.HourlyBasisPoints
				if window == SendLimitMonth {
					bucketStart = monthStart
					reset = monthReset
					limit = policy.Monthly
					threshold = policy.Warnings.MonthlyBasisPoints
				}
				if emergency {
					limit = policy.Dependency.EmergencyHourly
					if window == SendLimitMonth {
						limit = policy.Dependency.EmergencyMonthly
					}
				}
				reserved, committed, counterErr := readSendLimitCounter(ctx, connection, policy.Scope, window, bucketStart)
				if counterErr != nil {
					return counterErr
				}
				used, addErr := reserved.Add(committed)
				if addErr != nil {
					return addErr
				}
				projected, addErr := used.Add(amount)
				if addErr != nil {
					return addErr
				}
				projection := SendLimitUsageProjection{Scope: policy.Scope, Window: window, BucketStart: bucketStart, ResetsAt: reset, Limit: limit, Reserved: reserved, Committed: committed, Projected: projected}
				projection.Warning = sendLimitWarning(projected, limit, threshold)
				warning = warning || projection.Warning
				receipt.Usage = append(receipt.Usage, projection)
				if dimension := sendLimitExceeded(projected, limit); dimension != "" && receipt.Decision == SendLimitPermit {
					receipt.Decision = SendLimitDefer
					receipt.Code = sendLimitExceededCode(policy.Scope.Kind, window, dimension)
				}
			}
		}
		if receipt.Decision != SendLimitPermit {
			return insertSendLimitDecision(ctx, connection, request.Identity.TenantID, &receipt)
		}
		if emergency && warning {
			receipt.Code = SendLimitCodePermitEmergencyWarning
		} else if emergency {
			receipt.Code = SendLimitCodePermitEmergency
		} else if warning {
			receipt.Code = SendLimitCodePermitWarning
		}
		for _, scope := range request.Identity.Scopes() {
			for _, window := range []SendLimitWindowKind{SendLimitHour, SendLimitMonth} {
				bucket := hourStart
				if window == SendLimitMonth {
					bucket = monthStart
				}
				if addErr := addSendLimitReserved(ctx, connection, scope, window, bucket, amount, request.At); addErr != nil {
					return addErr
				}
			}
		}
		receipt.ReservationID = sendLimitReservationID(request, requestDigest)
		expires := request.At.Add(request.ReservationTTL)
		receipt.ExpiresAt = &expires
		if sealErr := sealSendLimitDecision(&receipt); sealErr != nil {
			return sealErr
		}
		if insertErr := insertSendLimitReservation(ctx, connection, request, receipt, hourStart, monthStart); insertErr != nil {
			return insertErr
		}
		return insertSendLimitDecision(ctx, connection, request.Identity.TenantID, &receipt)
	})
	if err != nil {
		return SendLimitDecisionReceipt{}, err
	}
	return receipt, nil
}

func (repository *SQLSendLimitRepository) Commit(ctx context.Context, request SendLimitFinalizeRequest) (SendLimitLifecycleReceipt, error) {
	return repository.finalize(ctx, request, SendLimitCommitted)
}

func (repository *SQLSendLimitRepository) Release(ctx context.Context, request SendLimitFinalizeRequest) (SendLimitLifecycleReceipt, error) {
	return repository.finalize(ctx, request, SendLimitReleased)
}

func (repository *SQLSendLimitRepository) finalize(ctx context.Context, request SendLimitFinalizeRequest, desired SendLimitReservationState) (SendLimitLifecycleReceipt, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validSendLimitKey(request.ReservationID, "slres_") || !validSendLimitKey(request.MessageKey, "slmsg_") || !validSendLimitKey(request.EffectKey, "sleff_") || !validSendLimitDigest(request.ReceiptDigest) || !sendLimitCanonicalTime(request.At) {
		return SendLimitLifecycleReceipt{}, ErrInvalidCommand
	}
	var receipt SendLimitLifecycleReceipt
	var terminalErr error
	err := repository.immediate(ctx, func(connection *sql.Conn) error {
		reservation, loadErr := loadSendLimitReservation(ctx, connection, request.ReservationID)
		if loadErr != nil {
			return loadErr
		}
		if reservation.MessageKey != request.MessageKey || reservation.EffectKey != request.EffectKey || reservation.DecisionDigest != request.ReceiptDigest {
			return ErrConflict
		}
		if reservation.State != SendLimitReserved {
			if reservation.State != desired && !(desired == SendLimitReleased && reservation.State == SendLimitExpired) {
				return ErrConflict
			}
			receipt, loadErr = lifecycleSendLimitReceipt(reservation.ReservationID, reservation.State, reservation.DecisionDigest, reservation.FinalizedAt)
			return loadErr
		}
		state := desired
		if !request.At.Before(reservation.ExpiresAt) {
			state = SendLimitExpired
			if desired == SendLimitCommitted {
				terminalErr = ErrConflict
			}
		}
		if updateErr := finalizeSendLimitCounters(ctx, connection, reservation, state, request.At); updateErr != nil {
			return updateErr
		}
		result, updateErr := connection.ExecContext(ctx, `UPDATE mail_send_limit_reservations_v1 SET state=?,finalized_at=?
            WHERE reservation_id=? AND state='reserved'`, state, sendLimitTimestamp(request.At), reservation.ReservationID)
		if updateErr != nil {
			return updateErr
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil || changed != 1 {
			return errors.Join(ErrConflict, rowsErr)
		}
		reservation.State = state
		reservation.FinalizedAt = request.At
		receipt, updateErr = lifecycleSendLimitReceipt(reservation.ReservationID, state, reservation.DecisionDigest, request.At)
		return updateErr
	})
	if err != nil {
		return SendLimitLifecycleReceipt{}, err
	}
	return receipt, terminalErr
}

func (repository *SQLSendLimitRepository) Scavenge(ctx context.Context, now time.Time, limit uint32) (uint32, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !sendLimitCanonicalTime(now) || limit == 0 || limit > SendLimitMaximumScavenge {
		return 0, ErrInvalidCommand
	}
	var count uint32
	err := repository.immediate(ctx, func(connection *sql.Conn) error {
		rows, queryErr := connection.QueryContext(ctx, `SELECT reservation_id FROM mail_send_limit_reservations_v1
            WHERE state='reserved' AND expires_at<=? ORDER BY expires_at,reservation_id LIMIT ?`, sendLimitTimestamp(now), limit)
		if queryErr != nil {
			return queryErr
		}
		var ids []string
		for rows.Next() {
			var id string
			if queryErr = rows.Scan(&id); queryErr != nil {
				rows.Close()
				return queryErr
			}
			ids = append(ids, id)
		}
		queryErr = rows.Err()
		rows.Close()
		if queryErr != nil {
			return queryErr
		}
		for _, id := range ids {
			reservation, loadErr := loadSendLimitReservation(ctx, connection, id)
			if loadErr != nil {
				return loadErr
			}
			if reservation.State != SendLimitReserved || reservation.ExpiresAt.After(now) {
				continue
			}
			if loadErr = finalizeSendLimitCounters(ctx, connection, reservation, SendLimitExpired, now); loadErr != nil {
				return loadErr
			}
			result, updateErr := connection.ExecContext(ctx, `UPDATE mail_send_limit_reservations_v1 SET state='expired',finalized_at=? WHERE reservation_id=? AND state='reserved'`, sendLimitTimestamp(now), id)
			if updateErr != nil {
				return updateErr
			}
			changed, rowsErr := result.RowsAffected()
			if rowsErr != nil || changed != 1 {
				return errors.Join(ErrConflict, rowsErr)
			}
			count++
		}
		return nil
	})
	return count, err
}

func (repository *SQLSendLimitRepository) Usage(ctx context.Context, tenant string, at time.Time, limit uint32) ([]SendLimitUsageProjection, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenant) || !sendLimitCanonicalTime(at) || limit == 0 || limit > SendLimitMaximumList {
		return nil, ErrInvalidCommand
	}
	hourStart, hourReset := sendLimitHourBounds(at)
	monthStart, monthReset := sendLimitMonthBounds(at)
	rows, err := repository.DB.QueryContext(ctx, `SELECT scope_kind,domain_id,mailbox_id,window_kind,bucket_start,
        reserved_messages,reserved_recipients,reserved_bytes,committed_messages,committed_recipients,committed_bytes
        FROM mail_send_limit_counters_v1 WHERE tenant_id=? AND ((window_kind=? AND bucket_start=?) OR (window_kind=? AND bucket_start=?))
		ORDER BY scope_kind,domain_id,mailbox_id,window_kind LIMIT ?`, tenant, SendLimitHour, sendLimitTimestamp(hourStart), SendLimitMonth, sendLimitTimestamp(monthStart), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projections := make([]SendLimitUsageProjection, 0, limit)
	for rows.Next() {
		var kind SendLimitScopeKind
		var domain DomainID
		var mailbox MailboxID
		var window SendLimitWindowKind
		var bucket string
		var reserved SendLimitAmount
		var committed SendLimitAmount
		if err = rows.Scan(&kind, &domain, &mailbox, &window, &bucket, &reserved.Messages, &reserved.Recipients, &reserved.Bytes, &committed.Messages, &committed.Recipients, &committed.Bytes); err != nil {
			return nil, err
		}
		scope := SendLimitScope{TenantID: tenant, Kind: kind, DomainID: domain, MailboxID: mailbox}
		bucketAt, parseErr := time.Parse(time.RFC3339Nano, bucket)
		if parseErr != nil || scope.Validate() != nil || !validSendLimitAmount(reserved) || !validSendLimitAmount(committed) {
			return nil, ErrInvalidReceipt
		}
		reset := hourReset
		if window == SendLimitMonth {
			reset = monthReset
		}
		used, addErr := reserved.Add(committed)
		if addErr != nil {
			return nil, addErr
		}
		projections = append(projections, SendLimitUsageProjection{Scope: scope, Window: window, BucketStart: bucketAt, ResetsAt: reset, Reserved: reserved, Committed: committed, Projected: used})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return projections, nil
}

type sendLimitReservation struct {
	ReservationID string
	TenantID       string
	DomainID       DomainID
	MailboxID      MailboxID
	MessageKey     string
	EffectKey      string
	DecisionDigest string
	State          SendLimitReservationState
	Amount         SendLimitAmount
	HourStart      time.Time
	MonthStart     time.Time
	ReservedAt     time.Time
	ExpiresAt      time.Time
	FinalizedAt    time.Time
}

type sendLimitQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (repository *SQLSendLimitRepository) immediate(ctx context.Context, operation func(*sql.Conn) error) error {
	repository.writer.Lock()
	defer repository.writer.Unlock()
	connection, err := repository.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	for _, pragma := range []string{`PRAGMA foreign_keys=ON`, `PRAGMA busy_timeout=5000`} {
		if _, err = connection.ExecContext(ctx, pragma); err != nil {
			return err
		}
	}
	if _, err = connection.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = connection.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	if err = operation(connection); err != nil {
		return err
	}
	if _, err = connection.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}

func loadEffectiveSendLimitPolicies(ctx context.Context, source interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, identity SendLimitIdentity, at time.Time) ([]SendLimitPolicy, error) {
	policies := make([]SendLimitPolicy, 0, 3)
	for _, scope := range identity.Scopes() {
		columns := sendLimitScopeColumns(scope)
		var raw []byte
		err := source.QueryRowContext(ctx, `SELECT policy_json FROM mail_send_limit_policies_v1
            WHERE tenant_id=? AND scope_kind=? AND domain_id=? AND mailbox_id=? AND effective_at<=?
            ORDER BY revision DESC LIMIT 1`, columns[0], columns[1], columns[2], columns[3], sendLimitTimestamp(at)).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		policy, decodeErr := decodeSendLimitPolicy(raw)
		if decodeErr != nil || policy.Scope != scope || policy.EffectiveAt.After(at) {
			return nil, ErrInvalidReceipt
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

func lookupSendLimitDecision(ctx context.Context, connection *sql.Conn, tenant, messageKey, effectKey, requestDigest string) (SendLimitDecisionReceipt, bool, error) {
	rows, err := connection.QueryContext(ctx, `SELECT message_key,effect_key,request_digest,receipt_json FROM mail_send_limit_decisions_v1
        WHERE tenant_id=? AND (message_key=? OR effect_key=?) LIMIT 2`, tenant, messageKey, effectKey)
	if err != nil {
		return SendLimitDecisionReceipt{}, false, err
	}
	defer rows.Close()
	var receipts []SendLimitDecisionReceipt
	for rows.Next() {
		var storedMessage string
		var storedEffect string
		var storedDigest string
		var raw []byte
		if err = rows.Scan(&storedMessage, &storedEffect, &storedDigest, &raw); err != nil {
			return SendLimitDecisionReceipt{}, false, err
		}
		if storedMessage != messageKey || storedEffect != effectKey || storedDigest != requestDigest {
			return SendLimitDecisionReceipt{}, false, ErrConflict
		}
		receipt, decodeErr := decodeSendLimitDecision(raw)
		if decodeErr != nil || receipt.MessageKey != messageKey || receipt.EffectKey != effectKey || receipt.RequestDigest != requestDigest {
			return SendLimitDecisionReceipt{}, false, ErrInvalidReceipt
		}
		receipts = append(receipts, receipt)
	}
	if err = rows.Err(); err != nil {
		return SendLimitDecisionReceipt{}, false, err
	}
	if len(receipts) > 1 {
		return SendLimitDecisionReceipt{}, false, ErrAmbiguous
	}
	if len(receipts) == 1 {
		return receipts[0], true, nil
	}
	return SendLimitDecisionReceipt{}, false, nil
}

func insertSendLimitDecision(ctx context.Context, connection *sql.Conn, tenant string, receipt *SendLimitDecisionReceipt) error {
	if receipt == nil {
		return ErrInvalidCommand
	}
	if receipt.ReceiptDigest == "" {
		if err := sealSendLimitDecision(receipt); err != nil {
			return err
		}
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(*receipt)
	if err != nil || len(raw) == 0 || len(raw) > 128<<10 {
		return errors.Join(ErrInvalidReceipt, err)
	}
	_, err = connection.ExecContext(ctx, `INSERT INTO mail_send_limit_decisions_v1
        (tenant_id,message_key,effect_key,request_digest,decision,decision_code,receipt_digest,receipt_json,decided_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, tenant, receipt.MessageKey, receipt.EffectKey, receipt.RequestDigest, receipt.Decision, receipt.Code, receipt.ReceiptDigest, raw, sendLimitTimestamp(receipt.ReservedAt))
	return err
}

func sealSendLimitDecision(receipt *SendLimitDecisionReceipt) error {
	if receipt == nil || receipt.ReceiptDigest != "" {
		return ErrInvalidCommand
	}
	copyReceipt := *receipt
	digest, err := sendLimitDigest("mail-send-limit-decision-v1", copyReceipt)
	if err != nil {
		return err
	}
	receipt.ReceiptDigest = digest
	return receipt.Validate()
}

func insertSendLimitReservation(ctx context.Context, connection *sql.Conn, request SendLimitReservationRequest, receipt SendLimitDecisionReceipt, hourStart, monthStart time.Time) error {
	_, err := connection.ExecContext(ctx, `INSERT INTO mail_send_limit_reservations_v1
        (reservation_id,tenant_id,domain_id,mailbox_id,message_key,effect_key,decision_digest,state,messages,recipients,bytes,hour_start,month_start,reserved_at,expires_at)
        VALUES(?,?,?,?,?,?,?,'reserved',?,?,?,?,?,?,?)`, receipt.ReservationID, request.Identity.TenantID, request.Identity.DomainID, request.Identity.MailboxID, request.MessageKey, request.EffectKey, receipt.ReceiptDigest, request.Amount().Messages, request.Amount().Recipients, request.Amount().Bytes, sendLimitTimestamp(hourStart), sendLimitTimestamp(monthStart), sendLimitTimestamp(request.At), sendLimitTimestamp(*receipt.ExpiresAt))
	return err
}

func readSendLimitCounter(ctx context.Context, source sendLimitQueryer, scope SendLimitScope, window SendLimitWindowKind, bucket time.Time) (SendLimitAmount, SendLimitAmount, error) {
	columns := sendLimitScopeColumns(scope)
	var reserved SendLimitAmount
	var committed SendLimitAmount
	err := source.QueryRowContext(ctx, `SELECT reserved_messages,reserved_recipients,reserved_bytes,committed_messages,committed_recipients,committed_bytes
        FROM mail_send_limit_counters_v1 WHERE tenant_id=? AND scope_kind=? AND domain_id=? AND mailbox_id=? AND window_kind=? AND bucket_start=?`, columns[0], columns[1], columns[2], columns[3], window, sendLimitTimestamp(bucket)).Scan(&reserved.Messages, &reserved.Recipients, &reserved.Bytes, &committed.Messages, &committed.Recipients, &committed.Bytes)
	if errors.Is(err, sql.ErrNoRows) {
		return SendLimitAmount{}, SendLimitAmount{}, nil
	}
	if err != nil {
		return SendLimitAmount{}, SendLimitAmount{}, err
	}
	if !validSendLimitAmount(reserved) || !validSendLimitAmount(committed) {
		return SendLimitAmount{}, SendLimitAmount{}, ErrInvalidReceipt
	}
	return reserved, committed, nil
}

func addSendLimitReserved(ctx context.Context, connection *sql.Conn, scope SendLimitScope, window SendLimitWindowKind, bucket time.Time, amount SendLimitAmount, at time.Time) error {
	reserved, committed, err := readSendLimitCounter(ctx, connection, scope, window, bucket)
	if err != nil {
		return err
	}
	if _, err = reserved.Add(amount); err != nil {
		return err
	}
	if _, err = committed.Add(amount); err != nil {
		return err
	}
	columns := sendLimitScopeColumns(scope)
	_, err = connection.ExecContext(ctx, `INSERT INTO mail_send_limit_counters_v1
        (tenant_id,scope_kind,domain_id,mailbox_id,window_kind,bucket_start,reserved_messages,reserved_recipients,reserved_bytes,committed_messages,committed_recipients,committed_bytes,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,0,0,0,?) ON CONFLICT(tenant_id,scope_kind,domain_id,mailbox_id,window_kind,bucket_start) DO UPDATE SET
        reserved_messages=reserved_messages+excluded.reserved_messages,reserved_recipients=reserved_recipients+excluded.reserved_recipients,
        reserved_bytes=reserved_bytes+excluded.reserved_bytes,updated_at=excluded.updated_at`, columns[0], columns[1], columns[2], columns[3], window, sendLimitTimestamp(bucket), amount.Messages, amount.Recipients, amount.Bytes, sendLimitTimestamp(at))
	return err
}

func loadSendLimitReservation(ctx context.Context, source sendLimitQueryer, id string) (sendLimitReservation, error) {
	var reservation sendLimitReservation
	var hour string
	var month string
	var reservedAt string
	var expiresAt string
	var finalized sql.NullString
	err := source.QueryRowContext(ctx, `SELECT reservation_id,tenant_id,domain_id,mailbox_id,message_key,effect_key,decision_digest,state,
        messages,recipients,bytes,hour_start,month_start,reserved_at,expires_at,finalized_at
        FROM mail_send_limit_reservations_v1 WHERE reservation_id=?`, id).Scan(&reservation.ReservationID, &reservation.TenantID, &reservation.DomainID, &reservation.MailboxID, &reservation.MessageKey, &reservation.EffectKey, &reservation.DecisionDigest, &reservation.State, &reservation.Amount.Messages, &reservation.Amount.Recipients, &reservation.Amount.Bytes, &hour, &month, &reservedAt, &expiresAt, &finalized)
	if errors.Is(err, sql.ErrNoRows) {
		return sendLimitReservation{}, ErrNotFound
	}
	if err != nil {
		return sendLimitReservation{}, err
	}
	reservation.HourStart, err = time.Parse(time.RFC3339Nano, hour)
	if err == nil {
		reservation.MonthStart, err = time.Parse(time.RFC3339Nano, month)
	}
	if err == nil {
		reservation.ReservedAt, err = time.Parse(time.RFC3339Nano, reservedAt)
	}
	if err == nil {
		reservation.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	}
	if err == nil && finalized.Valid {
		reservation.FinalizedAt, err = time.Parse(time.RFC3339Nano, finalized.String)
	}
	scope := SendLimitScope{TenantID: reservation.TenantID, Kind: SendLimitMailboxScope, DomainID: reservation.DomainID, MailboxID: reservation.MailboxID}
	validState := reservation.State == SendLimitReserved || reservation.State == SendLimitCommitted || reservation.State == SendLimitReleased || reservation.State == SendLimitExpired
	validFinalized := reservation.State == SendLimitReserved && reservation.FinalizedAt.IsZero() || reservation.State != SendLimitReserved && sendLimitCanonicalTime(reservation.FinalizedAt)
	hourStart, _ := sendLimitHourBounds(reservation.ReservedAt)
	monthStart, _ := sendLimitMonthBounds(reservation.ReservedAt)
	if err != nil || scope.Validate() != nil || !validSendLimitKey(reservation.ReservationID, "slres_") || !validSendLimitKey(reservation.MessageKey, "slmsg_") || !validSendLimitKey(reservation.EffectKey, "sleff_") || !validSendLimitDigest(reservation.DecisionDigest) || !validSendLimitAmount(reservation.Amount) || reservation.Amount.Messages != 1 || !validState || !validFinalized || !sendLimitCanonicalTime(reservation.ReservedAt) || !sendLimitCanonicalTime(reservation.ExpiresAt) || !reservation.ExpiresAt.After(reservation.ReservedAt) || reservation.HourStart != hourStart || reservation.MonthStart != monthStart {
		return sendLimitReservation{}, ErrInvalidReceipt
	}
	return reservation, nil
}

func finalizeSendLimitCounters(ctx context.Context, connection *sql.Conn, reservation sendLimitReservation, state SendLimitReservationState, at time.Time) error {
	identity := SendLimitIdentity{TenantID: reservation.TenantID, DomainID: reservation.DomainID, MailboxID: reservation.MailboxID}
	for _, scope := range identity.Scopes() {
		for _, window := range []SendLimitWindowKind{SendLimitHour, SendLimitMonth} {
			bucket := reservation.HourStart
			if window == SendLimitMonth {
				bucket = reservation.MonthStart
			}
			columns := sendLimitScopeColumns(scope)
			query := `UPDATE mail_send_limit_counters_v1 SET reserved_messages=reserved_messages-?,reserved_recipients=reserved_recipients-?,reserved_bytes=reserved_bytes-?,updated_at=?
                WHERE tenant_id=? AND scope_kind=? AND domain_id=? AND mailbox_id=? AND window_kind=? AND bucket_start=?
                AND reserved_messages>=? AND reserved_recipients>=? AND reserved_bytes>=?`
			arguments := []any{reservation.Amount.Messages, reservation.Amount.Recipients, reservation.Amount.Bytes, sendLimitTimestamp(at), columns[0], columns[1], columns[2], columns[3], window, sendLimitTimestamp(bucket), reservation.Amount.Messages, reservation.Amount.Recipients, reservation.Amount.Bytes}
			if state == SendLimitCommitted {
				query = `UPDATE mail_send_limit_counters_v1 SET reserved_messages=reserved_messages-?,reserved_recipients=reserved_recipients-?,reserved_bytes=reserved_bytes-?,
                    committed_messages=committed_messages+?,committed_recipients=committed_recipients+?,committed_bytes=committed_bytes+?,updated_at=?
                    WHERE tenant_id=? AND scope_kind=? AND domain_id=? AND mailbox_id=? AND window_kind=? AND bucket_start=?
                    AND reserved_messages>=? AND reserved_recipients>=? AND reserved_bytes>=?`
				arguments = []any{reservation.Amount.Messages, reservation.Amount.Recipients, reservation.Amount.Bytes, reservation.Amount.Messages, reservation.Amount.Recipients, reservation.Amount.Bytes, sendLimitTimestamp(at), columns[0], columns[1], columns[2], columns[3], window, sendLimitTimestamp(bucket), reservation.Amount.Messages, reservation.Amount.Recipients, reservation.Amount.Bytes}
			}
			result, err := connection.ExecContext(ctx, query, arguments...)
			if err != nil {
				return err
			}
			changed, err := result.RowsAffected()
			if err != nil || changed != 1 {
				return errors.Join(ErrInvalidReceipt, err)
			}
		}
	}
	return nil
}

func lifecycleSendLimitReceipt(id string, state SendLimitReservationState, decisionDigest string, at time.Time) (SendLimitLifecycleReceipt, error) {
	receipt := SendLimitLifecycleReceipt{ReservationID: id, State: state, DecisionDigest: decisionDigest, OccurredAt: at}
	digest, err := sendLimitDigest("mail-send-limit-lifecycle-v1", receipt)
	if err != nil {
		return SendLimitLifecycleReceipt{}, err
	}
	receipt.ReceiptDigest = digest
	return receipt, receipt.Validate()
}

func sendLimitExceeded(projected, limit SendLimitAmount) string {
	if limit.Messages != 0 && projected.Messages > limit.Messages {
		return "messages"
	}
	if limit.Recipients != 0 && projected.Recipients > limit.Recipients {
		return "recipients"
	}
	if limit.Bytes != 0 && projected.Bytes > limit.Bytes {
		return "bytes"
	}
	return ""
}

func sendLimitWarning(projected, limit SendLimitAmount, threshold uint16) bool {
	return sendLimitDimensionWarning(projected.Messages, limit.Messages, threshold) || sendLimitDimensionWarning(projected.Recipients, limit.Recipients, threshold) || sendLimitDimensionWarning(projected.Bytes, limit.Bytes, threshold)
}

func sendLimitDimensionWarning(value, limit uint64, threshold uint16) bool {
	if limit == 0 {
		return false
	}
	whole := (limit / 10000) * uint64(threshold)
	remainder := ((limit % 10000) * uint64(threshold) + 9999) / 10000
	return value >= whole+remainder
}

func sendLimitReservationID(request SendLimitReservationRequest, requestDigest string) string {
	digest, _ := sendLimitDigest("mail-send-limit-reservation-id-v1", []string{request.Identity.TenantID, request.MessageKey, request.EffectKey, requestDigest})
	return "slres_" + digest[:48]
}

func sendLimitReservationRequestDigest(request SendLimitReservationRequest) (string, error) {
	return sendLimitDigest("mail-send-limit-reservation-request-v1", struct {
		MessageKey     string    `json:"message_key"`
		EffectKey      string    `json:"effect_key"`
		TenantID       string    `json:"tenant_id"`
		DomainID       DomainID  `json:"domain_id"`
		MailboxID      MailboxID `json:"mailbox_id"`
		MailboxAddress Address   `json:"mailbox_address"`
		Recipients     uint32    `json:"recipients"`
		MessageBytes   uint64    `json:"message_bytes"`
	}{MessageKey: request.MessageKey, EffectKey: request.EffectKey, TenantID: request.Identity.TenantID, DomainID: request.Identity.DomainID, MailboxID: request.Identity.MailboxID, MailboxAddress: request.Identity.MailboxAddress, Recipients: request.Recipients, MessageBytes: request.MessageBytes})
}

func expireDueSendLimitTenant(ctx context.Context, connection *sql.Conn, tenant string, now time.Time) error {
	rows, err := connection.QueryContext(ctx, `SELECT reservation_id FROM mail_send_limit_reservations_v1
        WHERE tenant_id=? AND state='reserved' AND expires_at<=? ORDER BY expires_at,reservation_id LIMIT ?`, tenant, sendLimitTimestamp(now), SendLimitMaximumScavenge+1)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(ids) > int(SendLimitMaximumScavenge) {
		return ErrRateLimited
	}
	for _, id := range ids {
		reservation, loadErr := loadSendLimitReservation(ctx, connection, id)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = finalizeSendLimitCounters(ctx, connection, reservation, SendLimitExpired, now); loadErr != nil {
			return loadErr
		}
		result, updateErr := connection.ExecContext(ctx, `UPDATE mail_send_limit_reservations_v1 SET state='expired',finalized_at=? WHERE reservation_id=? AND state='reserved'`, sendLimitTimestamp(now), id)
		if updateErr != nil {
			return updateErr
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil || changed != 1 {
			return errors.Join(ErrConflict, rowsErr)
		}
	}
	return nil
}

func sendLimitScopeColumns(scope SendLimitScope) []any {
	return []any{scope.TenantID, scope.Kind, string(scope.DomainID), string(scope.MailboxID)}
}

func validSendLimitAfter(kind SendLimitScopeKind, domain DomainID, mailbox MailboxID) bool {
	if kind == "" {
		return domain == "" && mailbox == ""
	}
	return SendLimitScope{TenantID: "cursor", Kind: kind, DomainID: domain, MailboxID: mailbox}.Validate() == nil
}

func sendLimitTimestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func decodeSendLimitDecision(raw []byte) (SendLimitDecisionReceipt, error) {
	if len(raw) == 0 || len(raw) > 128<<10 {
		return SendLimitDecisionReceipt{}, ErrInvalidReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt SendLimitDecisionReceipt
	if err := decoder.Decode(&receipt); err != nil || decoder.Decode(&struct{}{}) != io.EOF || receipt.Validate() != nil {
		return SendLimitDecisionReceipt{}, ErrInvalidReceipt
	}
	return receipt, nil
}
