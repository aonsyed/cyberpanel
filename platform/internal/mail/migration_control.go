package mail

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const MigrationControlSchema = `
CREATE TABLE IF NOT EXISTS mail_migration_reservation_v1(singleton INTEGER PRIMARY KEY CHECK(singleton=1),import_id TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS mail_migration_imports_v1(import_id TEXT PRIMARY KEY,bundle_json BLOB NOT NULL,generation_json BLOB NOT NULL,state TEXT NOT NULL,receipt_json BLOB NOT NULL);
`

type MigrationBundle struct {
	ID       string                 `json:"id"`
	Domain   DomainProjection       `json:"domain"`
	Maildirs []MaildirImportRequest `json:"maildirs"`
}

type MailPublicationRequest struct {
	Operation         string           `json:"operation"`
	Bundle            MigrationBundle  `json:"bundle"`
	Generation        ConfigGeneration `json:"generation"`
	SourceFenceDigest string           `json:"source_fence_digest,omitempty"`
}

type MailPublicationReceipt struct {
	ImportID            string    `json:"import_id"`
	ConfigurationDigest string    `json:"configuration_digest"`
	StorageDigest       string    `json:"storage_digest"`
	GenerationID        string    `json:"generation_id"`
	PreviousGeneration  string    `json:"previous_generation,omitempty"`
	ValidationDigest    string    `json:"validation_digest,omitempty"`
	ActivationDigest    string    `json:"activation_digest,omitempty"`
	MaildirDigest       string    `json:"maildir_digest,omitempty"`
	ServiceDigest       string    `json:"service_digest,omitempty"`
	EvidenceDigest      string    `json:"evidence_digest"`
	State               string    `json:"state"`
	RolledBack          bool      `json:"rolled_back,omitempty"`
	ServicesStopped     bool      `json:"services_stopped,omitempty"`
	ObservedAt          time.Time `json:"observed_at"`
}

// MigrationCoordinator reserves the whole node mail writer while a new domain
// is private. Ordinary accepted operations must finish before reservation; no
// partially-created domain/mailbox can enter the socket-map resource catalog.
type MigrationCoordinator struct {
	DB        *sql.DB
	Projector RepositorySnapshotProjector
}

func (coordinator MigrationCoordinator) Prepare(ctx context.Context, bundle MigrationBundle) (ConfigGeneration, error) {
	if coordinator.DB == nil || ctx == nil || !validOpaque(bundle.ID) || !bundle.Domain.Domain.StaticRoutes || bundle.Domain.Domain.Tenant == "" {
		return ConfigGeneration{}, ErrInvalidCommand
	}
	raw, err := json.Marshal(bundle)
	if err != nil || len(raw) > 1<<20 {
		return ConfigGeneration{}, ErrInvalidCommand
	}
	tx, err := coordinator.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ConfigGeneration{}, err
	}
	defer tx.Rollback()
	var prior, generationRaw []byte
	var state string
	err = tx.QueryRowContext(ctx, `SELECT bundle_json,generation_json,state FROM mail_migration_imports_v1 WHERE import_id=?`, bundle.ID).Scan(&prior, &generationRaw, &state)
	if err == nil {
		if !bytes.Equal(prior, raw) || state == "canceled" {
			return ConfigGeneration{}, ErrConflict
		}
		if len(generationRaw) > 2 {
			var generation ConfigGeneration
			if json.Unmarshal(generationRaw, &generation) != nil {
				return generation, ErrInvalidReceipt
			}
			return generation, tx.Commit()
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return ConfigGeneration{}, err
	}
	var operations int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mail_operations_v2 WHERE status IN ('accepted','ambiguous')`).Scan(&operations); err != nil {
		return ConfigGeneration{}, err
	}
	if operations != 0 {
		return ConfigGeneration{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mail_migration_reservation_v1(singleton,import_id) VALUES(1,?) ON CONFLICT(singleton) DO NOTHING`, bundle.ID); err != nil {
		return ConfigGeneration{}, err
	}
	var reserved string
	if err := tx.QueryRowContext(ctx, `SELECT import_id FROM mail_migration_reservation_v1 WHERE singleton=1`).Scan(&reserved); err != nil || reserved != bundle.ID {
		return ConfigGeneration{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mail_migration_imports_v1 VALUES(?,?,'{}','preparing','{}') ON CONFLICT(import_id) DO NOTHING`, bundle.ID, raw); err != nil {
		return ConfigGeneration{}, err
	}
	if err := tx.Commit(); err != nil {
		return ConfigGeneration{}, err
	}
	snapshot, err := coordinator.Projector.ProjectMail(ctx, EffectRequest{TenantID: bundle.Domain.Domain.Tenant, Generation: 1})
	if err != nil {
		return ConfigGeneration{}, err
	}
	for _, domain := range snapshot.Domains {
		if domain.Domain.Name == bundle.Domain.Domain.Name || domain.Domain.ID == bundle.Domain.Domain.ID {
			return ConfigGeneration{}, ErrConflict
		}
	}
	snapshot.Domains = append(snapshot.Domains, bundle.Domain)
	generation, err := (ConfigRenderer{}).Render(snapshot)
	if err != nil {
		return generation, err
	}
	generationRaw, err = json.Marshal(generation)
	if err != nil {
		return generation, err
	}
	_, err = coordinator.DB.ExecContext(ctx, `UPDATE mail_migration_imports_v1 SET generation_json=?,state='prepared' WHERE import_id=? AND state='preparing'`, generationRaw, bundle.ID)
	return generation, err
}

func (coordinator MigrationCoordinator) MarkActivating(ctx context.Context, id string) error {
	result, err := coordinator.DB.ExecContext(ctx, `UPDATE mail_migration_imports_v1 SET state='activating' WHERE import_id=? AND state IN ('prepared','activating') AND EXISTS(SELECT 1 FROM mail_migration_reservation_v1 WHERE import_id=?)`, id, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrConflict
	}
	return nil
}

func (coordinator MigrationCoordinator) Complete(ctx context.Context, bundle MigrationBundle, receipt MailPublicationReceipt) error {
	if receipt.State != "active" || receipt.ImportID != bundle.ID || !validMailEvidenceDigest(receipt.EvidenceDigest) {
		return ErrInvalidReceipt
	}
	tx, err := coordinator.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw, generationRaw []byte
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT bundle_json,generation_json,state FROM mail_migration_imports_v1 WHERE import_id=?`, bundle.ID).Scan(&raw, &generationRaw, &state); err != nil {
		return err
	}
	expected, _ := json.Marshal(bundle)
	var generation ConfigGeneration
	if !bytes.Equal(raw, expected) || json.Unmarshal(generationRaw, &generation) != nil || generation.Digest != receipt.ConfigurationDigest {
		return ErrConflict
	}
	if state == "active" {
		return tx.Commit()
	}
	if state != "activating" {
		return ErrConflict
	}
	values, err := migrationResources(bundle)
	if err != nil {
		return err
	}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mail_resources_v2 VALUES(?,?,?,?,?,?,?)`, value.TenantID, value.Kind, value.ID, value.Generation, value.State, encoded, value.UpdatedAt); err != nil {
			return err
		}
	}
	receiptRaw, _ := json.Marshal(receipt)
	if _, err := tx.ExecContext(ctx, `UPDATE mail_migration_imports_v1 SET state='active',receipt_json=? WHERE import_id=?`, receiptRaw, bundle.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mail_migration_reservation_v1 WHERE import_id=?`, bundle.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (coordinator MigrationCoordinator) Observe(ctx context.Context, bundle MigrationBundle) error {
	values, err := migrationResources(bundle)
	if err != nil {
		return err
	}
	store := SQLControlRepository{DB: coordinator.DB}
	for _, expected := range values {
		actual, found, err := store.Load(ctx, expected.TenantID, expected.Kind, expected.ID)
		if err != nil {
			return err
		}
		if !found || actual.State != StateActive || actual.Generation != 1 || !bytes.Equal(actual.Spec, expected.Spec) {
			return ErrConflict
		}
	}
	return nil
}

func (coordinator MigrationCoordinator) Cancel(ctx context.Context, id string) error {
	tx, err := coordinator.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM mail_migration_imports_v1 WHERE import_id=?`, id).Scan(&state); err != nil {
		return err
	}
	if state != "preparing" && state != "prepared" && state != "canceled" {
		return ErrAmbiguous
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mail_migration_imports_v1 SET state='canceled' WHERE import_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mail_migration_reservation_v1 WHERE import_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func migrationResources(bundle MigrationBundle) ([]ResourceEnvelope, error) {
	values := []ResourceEnvelope{}
	add := func(kind ResourceKind, id string, value any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		values = append(values, ResourceEnvelope{Kind: kind, ID: id, TenantID: bundle.Domain.Domain.Tenant, Generation: 1, State: StateActive, Spec: raw, UpdatedAt: time.Now().UTC()})
		return nil
	}
	if err := add(ResourcePolicy, string(bundle.Domain.Policy.ID), bundle.Domain.Policy); err != nil {
		return nil, err
	}
	if err := add(ResourceDomain, string(bundle.Domain.Domain.ID), bundle.Domain.Domain); err != nil {
		return nil, err
	}
	for _, box := range bundle.Domain.Mailboxes {
		if err := add(ResourceMailbox, string(box.ID), box); err != nil {
			return nil, err
		}
	}
	for _, alias := range bundle.Domain.Aliases {
		if err := add(ResourceAlias, string(alias.ID), alias); err != nil {
			return nil, err
		}
	}
	return values, nil
}
