// Package sqlrepo provides the transactional SQL implementation of the
// hosting service repository contract. The caller owns the database driver.
package sqlrepo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

const Schema = `
CREATE TABLE IF NOT EXISTS hosting_sites (
 tenant_id TEXT NOT NULL, site_id TEXT NOT NULL, generation BIGINT NOT NULL,
 aggregate_json TEXT NOT NULL, PRIMARY KEY (tenant_id, site_id)
);
CREATE TABLE IF NOT EXISTS hosting_commands (
 command_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, site_id TEXT NOT NULL,
 digest TEXT NOT NULL, status TEXT NOT NULL, receipt_json TEXT NOT NULL,
 proposal_json TEXT NOT NULL, effect_id TEXT NOT NULL UNIQUE,
 accepted_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS hosting_commands_scope ON hosting_commands (tenant_id, site_id);
`

type Repository struct{ db *sql.DB }

func New(db *sql.DB) (*Repository, error) {
	if db == nil { return nil, errors.New("sql database is required") }
	return &Repository{db: db}, nil
}

func (r *Repository) Bootstrap(ctx context.Context) error {
	if r == nil || r.db == nil { return errors.New("sql repository is required") }
	_, err := r.db.ExecContext(ctx, Schema)
	return err
}

func (r *Repository) LookupCommand(ctx context.Context, scope service.CommandScope, commandID, digest string) (service.OperationReceipt, bool, error) {
	if r == nil || r.db == nil { return service.OperationReceipt{}, false, errors.New("sql repository is required") }
	var storedTenant, storedSite, storedDigest string; var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT tenant_id, site_id, digest, receipt_json FROM hosting_commands WHERE command_id = ?`, commandID).Scan(&storedTenant, &storedSite, &storedDigest, &raw)
	if errors.Is(err, sql.ErrNoRows) { return service.OperationReceipt{}, false, nil }
	if err != nil { return service.OperationReceipt{}, false, err }
	if storedTenant != scope.TenantID.String() || storedSite != scope.SiteID.String() || storedDigest != digest {
		return service.OperationReceipt{}, false, service.ErrIdempotencyConflict
	}
	receipt, err := decodeReceipt(raw)
	return receipt, true, err
}

func (r *Repository) Load(ctx context.Context, tenant site.TenantID, id site.SiteID) (site.Site, error) {
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT aggregate_json FROM hosting_sites WHERE tenant_id = ? AND site_id = ?`, tenant.String(), id.String()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) { return site.Site{}, service.ErrNotFound }
	if err != nil { return site.Site{}, err }
	aggregate, err := site.Restore(raw)
	if err != nil || aggregate.TenantID() != tenant || aggregate.ID() != id { return site.Site{}, service.ErrNotFound }
	return aggregate, nil
}

// List returns tenant-owned aggregates in stable site-ID order. The opaque
// cursor is the last validated site ID from the previous page; callers never
// supply SQL, offsets, or sort expressions.
func (r *Repository) List(ctx context.Context, tenant site.TenantID, cursor string, limit int) ([]site.Site, string, uint64, error) {
	if r == nil || r.db == nil || tenant.String() == "" || limit < 1 || limit > 500 {
		return nil, "", 0, errors.New("invalid hosting list request")
	}
	if cursor != "" {
		if _, err := site.NewSiteID(cursor); err != nil { return nil, "", 0, errors.New("invalid hosting cursor") }
	}
	var total uint64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosting_sites WHERE tenant_id = ?`, tenant.String()).Scan(&total); err != nil { return nil, "", 0, err }
	rows, err := r.db.QueryContext(ctx, `SELECT site_id, aggregate_json FROM hosting_sites WHERE tenant_id = ? AND site_id > ? ORDER BY site_id ASC LIMIT ?`, tenant.String(), cursor, limit+1)
	if err != nil { return nil, "", 0, err }
	defer rows.Close()
	values := make([]site.Site, 0, limit)
	next := ""
	for rows.Next() {
		var storedID string
		var raw []byte
		if err = rows.Scan(&storedID, &raw); err != nil { return nil, "", 0, err }
		aggregate, restoreErr := site.Restore(raw)
		if restoreErr != nil || aggregate.TenantID() != tenant || aggregate.ID().String() != storedID { return nil, "", 0, errors.New("corrupt hosting aggregate") }
		if len(values) == limit { next = values[len(values)-1].ID().String(); break }
		values = append(values, aggregate)
	}
	if err = rows.Err(); err != nil { return nil, "", 0, err }
	return values, strings.TrimSpace(next), total, nil
}

func (r *Repository) Admit(ctx context.Context, admission service.Admission) (service.AdmissionResult, error) {
	if r == nil || r.db == nil { return service.AdmissionResult{}, errors.New("sql repository is required") }
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return service.AdmissionResult{}, err }
	defer tx.Rollback()
	var digest string; var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT digest, receipt_json FROM hosting_commands WHERE command_id = ?`, admission.CommandID).Scan(&digest, &raw)
	if err == nil {
		receipt, decodeErr := decodeReceipt(raw); if decodeErr != nil { return service.AdmissionResult{}, decodeErr }
		if digest != admission.Digest || receipt.Scope != admission.Scope { return service.AdmissionResult{Kind: service.AdmissionConflict}, tx.Commit() }
		return service.AdmissionResult{Kind: service.AdmissionExistingSame, Receipt: receipt}, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) { return service.AdmissionResult{}, err }
	var currentGeneration uint64
	err = tx.QueryRowContext(ctx, `SELECT generation FROM hosting_sites WHERE tenant_id = ? AND site_id = ?`, admission.Scope.TenantID.String(), admission.Scope.SiteID.String()).Scan(&currentGeneration)
	if errors.Is(err, sql.ErrNoRows) { currentGeneration = 0; err = nil }
	if err != nil { return service.AdmissionResult{}, err }
	if currentGeneration != admission.ExpectedGeneration { return service.AdmissionResult{}, site.ErrStaleGeneration }
	if admission.Proposal.TenantID() != admission.Scope.TenantID || admission.Proposal.ID() != admission.Scope.SiteID { return service.AdmissionResult{}, errors.New("proposal scope mismatch") }
	proposal, err := admission.Proposal.Snapshot(); if err != nil { return service.AdmissionResult{}, err }
	receipt := service.OperationReceipt{CommandID: admission.CommandID, Digest: admission.Digest, Scope: admission.Scope, Status: service.OperationAccepted, AcceptedAt: admission.AcceptedAt.UTC(), Request: admission.Request}
	encoded, err := canonicalJSON(receipt); if err != nil { return service.AdmissionResult{}, err }
	_, err = tx.ExecContext(ctx, `INSERT INTO hosting_commands (command_id, tenant_id, site_id, digest, status, receipt_json, proposal_json, effect_id, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		admission.CommandID, admission.Scope.TenantID.String(), admission.Scope.SiteID.String(), admission.Digest, receipt.Status, encoded, proposal, admission.Request.EffectID, receipt.AcceptedAt)
	if err != nil { return service.AdmissionResult{}, err }
	if err := tx.Commit(); err != nil { return service.AdmissionResult{}, err }
	return service.AdmissionResult{Kind: service.AdmissionNew, Receipt: receipt}, nil
}

func (r *Repository) Complete(ctx context.Context, completion service.Completion) (service.OperationReceipt, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return service.OperationReceipt{}, err }; defer tx.Rollback()
	var digest string; var receiptRaw, proposal []byte
	err = tx.QueryRowContext(ctx, `SELECT digest, receipt_json, proposal_json FROM hosting_commands WHERE command_id = ? AND tenant_id = ? AND site_id = ?`, completion.CommandID, completion.Scope.TenantID.String(), completion.Scope.SiteID.String()).Scan(&digest, &receiptRaw, &proposal)
	if errors.Is(err, sql.ErrNoRows) { return service.OperationReceipt{}, service.ErrNotFound }; if err != nil { return service.OperationReceipt{}, err }
	receipt, err := decodeReceipt(receiptRaw); if err != nil { return service.OperationReceipt{}, err }
	if digest != completion.Digest || !reflect.DeepEqual(receipt.Request, completion.Request) || receipt.Status == service.OperationApplied || receipt.Status == service.OperationDegraded { return receipt, tx.Commit() }
	receipt.Status, receipt.Effect = completion.Status, completion.Effect
	encoded, err := canonicalJSON(receipt); if err != nil { return service.OperationReceipt{}, err }
	if completion.Status == service.OperationApplied {
		aggregate, err := site.Restore(proposal); if err != nil { return service.OperationReceipt{}, err }
		result, err := tx.ExecContext(ctx, `INSERT INTO hosting_sites (tenant_id, site_id, generation, aggregate_json) VALUES (?, ?, ?, ?)
ON CONFLICT (tenant_id, site_id) DO UPDATE SET generation = excluded.generation, aggregate_json = excluded.aggregate_json WHERE hosting_sites.generation = ?`,
			aggregate.TenantID().String(), aggregate.ID().String(), aggregate.Generation(), proposal, aggregate.Generation()-1)
		if err != nil { return service.OperationReceipt{}, err }
		changed, err := result.RowsAffected(); if err != nil || changed != 1 { return service.OperationReceipt{}, site.ErrStaleGeneration }
	}
	_, err = tx.ExecContext(ctx, `UPDATE hosting_commands SET status = ?, receipt_json = ? WHERE command_id = ?`, receipt.Status, encoded, receipt.CommandID)
	if err != nil { return service.OperationReceipt{}, err }
	if err := tx.Commit(); err != nil { return service.OperationReceipt{}, err }
	return receipt, nil
}

func decodeReceipt(raw []byte) (service.OperationReceipt, error) { var receipt service.OperationReceipt; if err := json.Unmarshal(raw, &receipt); err != nil { return service.OperationReceipt{}, fmt.Errorf("decode receipt: %w", err) }; return receipt, nil }
func canonicalJSON(value any) ([]byte, error) { return json.Marshal(value) }
var _ service.SiteRepository = (*Repository)(nil)
