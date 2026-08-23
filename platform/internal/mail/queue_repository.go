package mail

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

const QueueAdminSchema = `
CREATE TABLE IF NOT EXISTS mail_queue_admin_operations_v1 (
    partition_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    action TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','completed')),
    lease_token TEXT NOT NULL,
    lease_until TEXT NOT NULL,
    receipt_json BLOB,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (partition_id, operation_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS mail_queue_admin_operation_age_v1
    ON mail_queue_admin_operations_v1 (status, lease_until);
`

const queueOperationLease = 30 * time.Second

type QueueOperationClaim struct {
	Token   string
	Receipt *QueueActionReceipt
}

type QueueOperationRepository interface {
	Lookup(context.Context, string, string, string) (QueueActionReceipt, bool, error)
	Claim(context.Context, string, string, QueueAdminAction, string, time.Time) (QueueOperationClaim, error)
	Complete(context.Context, string, string, string, string, QueueActionReceipt) error
}

type SQLQueueOperationRepository struct {
	DB     *sql.DB
	writer sync.Mutex
}

func NewSQLQueueOperationRepository(db *sql.DB) (*SQLQueueOperationRepository, error) {
	if db == nil {
		return nil, ErrInvalidCommand
	}
	return &SQLQueueOperationRepository{DB: db}, nil
}

func (repository *SQLQueueOperationRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.DB == nil || ctx == nil {
		return ErrInvalidCommand
	}
	_, err := repository.DB.ExecContext(ctx, QueueAdminSchema)
	return err
}

func (repository *SQLQueueOperationRepository) Lookup(ctx context.Context, partition, operationID, requestDigest string) (QueueActionReceipt, bool, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(partition) || !validOpaque(operationID) || !validQueueDigest(requestDigest) {
		return QueueActionReceipt{}, false, ErrInvalidCommand
	}
	var storedDigest string
	var status string
	var raw []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT request_digest,status,receipt_json
        FROM mail_queue_admin_operations_v1 WHERE partition_id=? AND operation_id=?`, partition, operationID).Scan(&storedDigest, &status, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return QueueActionReceipt{}, false, nil
	}
	if err != nil {
		return QueueActionReceipt{}, false, err
	}
	if storedDigest != requestDigest {
		return QueueActionReceipt{}, false, ErrConflict
	}
	if status == "pending" {
		if len(raw) != 0 {
			return QueueActionReceipt{}, false, ErrInvalidReceipt
		}
		return QueueActionReceipt{}, false, nil
	}
	if status != "completed" {
		return QueueActionReceipt{}, false, ErrInvalidReceipt
	}
	receipt, err := decodeQueueReceipt(raw)
	if err != nil || receipt.OperationID != operationID || receipt.RequestDigest != requestDigest {
		return QueueActionReceipt{}, false, errors.Join(ErrInvalidReceipt, err)
	}
	return receipt, true, nil
}

func (repository *SQLQueueOperationRepository) Claim(ctx context.Context, partition, operationID string, action QueueAdminAction, requestDigest string, now time.Time) (QueueOperationClaim, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(partition) || !validOpaque(operationID) || !validQueueDigest(requestDigest) || !canonicalQueueTime(now) || !validQueueAdminAction(action) && action != QueueAdminFlush {
		return QueueOperationClaim{}, ErrInvalidCommand
	}
	token, err := newQueueClaimToken()
	if err != nil {
		return QueueOperationClaim{}, err
	}
	leaseUntil := now.Add(queueOperationLease)
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return QueueOperationClaim{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO mail_queue_admin_operations_v1
        (partition_id,operation_id,action,request_digest,status,lease_token,lease_until,created_at)
        VALUES(?,?,?,?, 'pending',?,?,?) ON CONFLICT (partition_id,operation_id) DO NOTHING`, partition, operationID, action, requestDigest, token, queueOperationTimestamp(leaseUntil), queueOperationTimestamp(now))
	if err != nil {
		return QueueOperationClaim{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return QueueOperationClaim{}, err
	}
	if inserted == 1 {
		if err = tx.Commit(); err != nil {
			return QueueOperationClaim{}, err
		}
		return QueueOperationClaim{Token: token}, nil
	}
	var storedAction QueueAdminAction
	var storedDigest string
	var status string
	var priorToken string
	var priorLease string
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT action,request_digest,status,lease_token,lease_until,receipt_json
        FROM mail_queue_admin_operations_v1 WHERE partition_id=? AND operation_id=?`, partition, operationID).Scan(&storedAction, &storedDigest, &status, &priorToken, &priorLease, &raw); err != nil {
		return QueueOperationClaim{}, err
	}
	if storedAction != action || storedDigest != requestDigest {
		return QueueOperationClaim{}, ErrConflict
	}
	if status == "completed" {
		receipt, decodeErr := decodeQueueReceipt(raw)
		if decodeErr != nil || receipt.OperationID != operationID || receipt.RequestDigest != requestDigest || receipt.Action != action {
			return QueueOperationClaim{}, errors.Join(ErrInvalidReceipt, decodeErr)
		}
		if err = tx.Commit(); err != nil {
			return QueueOperationClaim{}, err
		}
		return QueueOperationClaim{Receipt: &receipt}, nil
	}
	if status != "pending" || len(raw) != 0 {
		return QueueOperationClaim{}, ErrInvalidReceipt
	}
	parsedLease, parseErr := time.Parse(time.RFC3339Nano, priorLease)
	if parseErr != nil || priorToken == "" {
		return QueueOperationClaim{}, ErrInvalidReceipt
	}
	if parsedLease.After(now) {
		return QueueOperationClaim{}, ErrRateLimited
	}
	result, err = tx.ExecContext(ctx, `UPDATE mail_queue_admin_operations_v1 SET lease_token=?,lease_until=?
        WHERE partition_id=? AND operation_id=? AND status='pending' AND request_digest=? AND lease_token=? AND lease_until=?`, token, queueOperationTimestamp(leaseUntil), partition, operationID, requestDigest, priorToken, priorLease)
	if err != nil {
		return QueueOperationClaim{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return QueueOperationClaim{}, err
	}
	if changed != 1 {
		return QueueOperationClaim{}, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return QueueOperationClaim{}, err
	}
	return QueueOperationClaim{Token: token}, nil
}

func (repository *SQLQueueOperationRepository) Complete(ctx context.Context, partition, operationID, requestDigest, token string, receipt QueueActionReceipt) error {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(partition) || !validOpaque(operationID) || !validQueueDigest(requestDigest) || !validOpaque(token) || receipt.OperationID != operationID || receipt.RequestDigest != requestDigest {
		return ErrInvalidCommand
	}
	if err := validateQueueActionReceipt(receipt); err != nil {
		return err
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) == 0 || len(raw) > 128<<10 {
		return errors.Join(ErrInvalidReceipt, err)
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.DB.ExecContext(ctx, `UPDATE mail_queue_admin_operations_v1 SET
        status='completed',receipt_json=?,completed_at=?,lease_token='',lease_until=?
        WHERE partition_id=? AND operation_id=? AND status='pending' AND request_digest=? AND lease_token=?`, raw, queueOperationTimestamp(receipt.CompletedAt), queueOperationTimestamp(receipt.CompletedAt), partition, operationID, requestDigest, token)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrConflict
	}
	return nil
}

func newQueueClaimToken() (string, error) {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "queueclaim_" + hex.EncodeToString(raw[:]), nil
}

func queueOperationTimestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
