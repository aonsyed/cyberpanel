package extensions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	_ "modernc.org/sqlite"
)

type Admission struct {
	CommandID          CommandID
	RequestDigest      string
	Action             LifecycleAction
	ExtensionID        ExtensionID
	ExpectedGeneration uint64
	AcceptedAt         time.Time
}

func (admission Admission) Validate() error {
	if !validID(string(admission.CommandID)) || !validDigest(admission.RequestDigest) || !validLifecycleAction(admission.Action) ||
		!validID(string(admission.ExtensionID)) || admission.ExpectedGeneration > math.MaxInt64 || admission.AcceptedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type Completion struct {
	Admission Admission
	Next      *ExtensionInstallation
	Purge     bool
	Receipt   OperationReceipt
}

type InstallationPage struct {
	Installations []ExtensionInstallation `json:"installations"`
	NextCursor    ExtensionID             `json:"next_cursor,omitempty"`
}

type Repository interface {
	Bootstrap(context.Context) error
	Load(context.Context, ExtensionID) (ExtensionInstallation, error)
	List(context.Context, ExtensionID, uint16) (InstallationPage, error)
	Receipt(context.Context, CommandID, string) (*OperationReceipt, error)
	Admit(context.Context, Admission) (*OperationReceipt, error)
	Complete(context.Context, Completion) error
}

func (repository *SQLiteRepository) Receipt(ctx context.Context, id CommandID, requestDigest string) (*OperationReceipt, error) {
	if !validID(string(id)) || !validDigest(requestDigest) {
		return nil, ErrInvalid
	}
	receipt, found, err := loadReceipt(ctx, repository.db, id)
	if err != nil || !found {
		return nil, err
	}
	if receipt.RequestDigest != requestDigest {
		return nil, ErrConflict
	}
	return &receipt, nil
}

type SQLiteRepository struct {
	db *sql.DB
}

func OpenSQLiteRepository(path string) (*SQLiteRepository, error) {
	if path == "" || path == ":memory:" {
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
		`CREATE TABLE IF NOT EXISTS extension_installations_v1 (
			extension_id TEXT PRIMARY KEY,
			generation INTEGER NOT NULL CHECK (generation > 0),
			document BLOB NOT NULL,
			updated_at TEXT NOT NULL
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS extension_admissions_v1 (
			command_id TEXT PRIMARY KEY,
			request_digest TEXT NOT NULL,
			action TEXT NOT NULL,
			extension_id TEXT NOT NULL,
			expected_generation INTEGER NOT NULL CHECK (expected_generation >= 0),
			status TEXT NOT NULL CHECK (status IN ('accepted', 'completed')),
			accepted_at TEXT NOT NULL
		) STRICT`,
		`CREATE UNIQUE INDEX IF NOT EXISTS extension_admissions_active_v1
			ON extension_admissions_v1(extension_id) WHERE status = 'accepted'`,
		`CREATE TABLE IF NOT EXISTS extension_receipts_v1 (
			command_id TEXT PRIMARY KEY,
			request_digest TEXT NOT NULL,
			extension_id TEXT NOT NULL,
			receipt_digest TEXT NOT NULL UNIQUE,
			document BLOB NOT NULL,
			recorded_at TEXT NOT NULL,
			FOREIGN KEY(command_id) REFERENCES extension_admissions_v1(command_id)
		) STRICT`,
		`CREATE TRIGGER IF NOT EXISTS extension_receipts_no_update_v1
			BEFORE UPDATE ON extension_receipts_v1 BEGIN SELECT RAISE(ABORT, 'extension receipts are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS extension_receipts_no_delete_v1
			BEFORE DELETE ON extension_receipts_v1 BEGIN SELECT RAISE(ABORT, 'extension receipts are immutable'); END`,
	}
	for _, statement := range statements {
		if _, err := repository.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (repository *SQLiteRepository) Load(ctx context.Context, id ExtensionID) (ExtensionInstallation, error) {
	if !validID(string(id)) {
		return ExtensionInstallation{}, ErrInvalid
	}
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM extension_installations_v1 WHERE extension_id = ?`, id).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return ExtensionInstallation{}, ErrNotFound
	}
	if err != nil {
		return ExtensionInstallation{}, err
	}
	installation, err := decodeInstallation(document)
	if err != nil || installation.ID != id {
		return ExtensionInstallation{}, ErrIntegrity
	}
	return cloneInstallation(installation), nil
}

func (repository *SQLiteRepository) List(ctx context.Context, after ExtensionID, limit uint16) (InstallationPage, error) {
	if after != "" && !validID(string(after)) || limit == 0 || limit > 500 {
		return InstallationPage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT document FROM extension_installations_v1 WHERE extension_id > ? ORDER BY extension_id LIMIT ?`, after, int(limit)+1)
	if err != nil {
		return InstallationPage{}, err
	}
	defer rows.Close()
	values := make([]ExtensionInstallation, 0, limit)
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return InstallationPage{}, err
		}
		installation, err := decodeInstallation(document)
		if err != nil {
			return InstallationPage{}, ErrIntegrity
		}
		values = append(values, cloneInstallation(installation))
	}
	if err := rows.Err(); err != nil {
		return InstallationPage{}, err
	}
	page := InstallationPage{Installations: values}
	if len(values) > int(limit) {
		page.NextCursor = values[limit-1].ID
		page.Installations = values[:limit]
	}
	return page, nil
}

func (repository *SQLiteRepository) Admit(ctx context.Context, admission Admission) (*OperationReceipt, error) {
	if err := admission.Validate(); err != nil {
		return nil, err
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer transaction.Rollback()
	if receipt, found, err := loadReceipt(ctx, transaction, admission.CommandID); err != nil {
		return nil, err
	} else if found {
		if receipt.RequestDigest != admission.RequestDigest {
			return nil, ErrConflict
		}
		return &receipt, nil
	}
	var requestDigest, action, extensionID, status string
	var expected int64
	err = transaction.QueryRowContext(ctx, `SELECT request_digest, action, extension_id, expected_generation, status FROM extension_admissions_v1 WHERE command_id = ?`, admission.CommandID).
		Scan(&requestDigest, &action, &extensionID, &expected, &status)
	if err == nil {
		if requestDigest != admission.RequestDigest || action != string(admission.Action) || extensionID != string(admission.ExtensionID) || expected != int64(admission.ExpectedGeneration) {
			return nil, ErrConflict
		}
		return nil, ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var generation int64
	err = transaction.QueryRowContext(ctx, `SELECT generation FROM extension_installations_v1 WHERE extension_id = ?`, admission.ExtensionID).Scan(&generation)
	if admission.ExpectedGeneration == 0 {
		if err == nil {
			return nil, ErrStale
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	} else {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		if generation != int64(admission.ExpectedGeneration) {
			return nil, ErrStale
		}
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO extension_admissions_v1
		(command_id, request_digest, action, extension_id, expected_generation, status, accepted_at)
		VALUES (?, ?, ?, ?, ?, 'accepted', ?)`, admission.CommandID, admission.RequestDigest, admission.Action, admission.ExtensionID,
		admission.ExpectedGeneration, admission.AcceptedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, ErrConflict
	}
	if err := transaction.Commit(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (repository *SQLiteRepository) Complete(ctx context.Context, completion Completion) error {
	if err := completion.Admission.Validate(); err != nil || completion.Receipt.Validate() != nil {
		return ErrInvalid
	}
	if completion.Receipt.CommandID != completion.Admission.CommandID || completion.Receipt.RequestDigest != completion.Admission.RequestDigest ||
		completion.Receipt.Action != completion.Admission.Action || completion.Receipt.ExtensionID != completion.Admission.ExtensionID ||
		completion.Receipt.ExpectedGeneration != completion.Admission.ExpectedGeneration || completion.Purge && completion.Next != nil ||
		completion.Receipt.Outcome == ReceiptApplied && !completion.Purge && completion.Next == nil ||
		completion.Receipt.Outcome == ReceiptAmbiguous && (completion.Purge || completion.Next != nil) {
		return ErrInvalid
	}
	if completion.Next != nil {
		if completion.Next.Validate() != nil || completion.Next.ID != completion.Admission.ExtensionID || completion.Next.Generation != completion.Receipt.ResultGeneration {
			return ErrInvalid
		}
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var requestDigest, action, extensionID, status string
	var expected int64
	err = transaction.QueryRowContext(ctx, `SELECT request_digest, action, extension_id, expected_generation, status FROM extension_admissions_v1 WHERE command_id = ?`, completion.Admission.CommandID).
		Scan(&requestDigest, &action, &extensionID, &expected, &status)
	if err != nil || requestDigest != completion.Admission.RequestDigest || action != string(completion.Admission.Action) ||
		extensionID != string(completion.Admission.ExtensionID) || expected != int64(completion.Admission.ExpectedGeneration) || status != "accepted" {
		return ErrConflict
	}
	if completion.Receipt.Outcome == ReceiptApplied {
		if completion.Purge {
			result, err := transaction.ExecContext(ctx, `DELETE FROM extension_installations_v1 WHERE extension_id = ? AND generation = ?`, completion.Admission.ExtensionID, completion.Admission.ExpectedGeneration)
			if err != nil {
				return err
			}
			if affected, _ := result.RowsAffected(); affected != 1 {
				return ErrStale
			}
		} else {
			document, err := json.Marshal(completion.Next)
			if err != nil {
				return err
			}
			if completion.Admission.ExpectedGeneration == 0 {
				_, err = transaction.ExecContext(ctx, `INSERT INTO extension_installations_v1 (extension_id, generation, document, updated_at) VALUES (?, ?, ?, ?)`,
					completion.Next.ID, completion.Next.Generation, document, completion.Next.UpdatedAt.UTC().Format(time.RFC3339Nano))
			} else {
				var result sql.Result
				result, err = transaction.ExecContext(ctx, `UPDATE extension_installations_v1 SET generation = ?, document = ?, updated_at = ? WHERE extension_id = ? AND generation = ?`,
					completion.Next.Generation, document, completion.Next.UpdatedAt.UTC().Format(time.RFC3339Nano), completion.Next.ID, completion.Admission.ExpectedGeneration)
				if err == nil {
					if affected, _ := result.RowsAffected(); affected != 1 {
						return ErrStale
					}
				}
			}
			if err != nil {
				return err
			}
		}
	}
	receiptDocument, err := json.Marshal(completion.Receipt)
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO extension_receipts_v1 (command_id, request_digest, extension_id, receipt_digest, document, recorded_at) VALUES (?, ?, ?, ?, ?, ?)`,
		completion.Receipt.CommandID, completion.Receipt.RequestDigest, completion.Receipt.ExtensionID, completion.Receipt.Digest, receiptDocument,
		completion.Receipt.RecordedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if _, err = transaction.ExecContext(ctx, `UPDATE extension_admissions_v1 SET status = 'completed' WHERE command_id = ? AND status = 'accepted'`, completion.Admission.CommandID); err != nil {
		return err
	}
	return transaction.Commit()
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadReceipt(ctx context.Context, query rowQuerier, id CommandID) (OperationReceipt, bool, error) {
	var document []byte
	err := query.QueryRowContext(ctx, `SELECT document FROM extension_receipts_v1 WHERE command_id = ?`, id).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return OperationReceipt{}, false, nil
	}
	if err != nil {
		return OperationReceipt{}, false, err
	}
	var receipt OperationReceipt
	if err := json.Unmarshal(document, &receipt); err != nil || receipt.Validate() != nil || receipt.CommandID != id {
		return OperationReceipt{}, false, ErrIntegrity
	}
	return receipt, true, nil
}

func decodeInstallation(document []byte) (ExtensionInstallation, error) {
	var installation ExtensionInstallation
	if len(document) == 0 || len(document) > maximumReleaseDocumentBytes || json.Unmarshal(document, &installation) != nil || installation.Validate() != nil {
		return ExtensionInstallation{}, ErrIntegrity
	}
	return installation, nil
}
