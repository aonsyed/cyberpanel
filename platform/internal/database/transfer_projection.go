package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

const createTransferPromotionsTable = `CREATE TABLE IF NOT EXISTS panel_database_transfer_promotions (
job_id TEXT PRIMARY KEY,
job_digest TEXT NOT NULL,
isolated_json BLOB NOT NULL,
promotion_json BLOB NOT NULL
)`

type transferPromotionRepository interface {
	LookupTransferPromotion(context.Context, TransferJob, IsolatedTransferDatabase) (TransferPromotion, bool, error)
	RecordTransferPromotion(context.Context, TransferJob, IsolatedTransferDatabase, TransferPromotion) error
}

// PromoteDatabaseTransfer joins the native promotion proof to control.db.
// This is an internal coordinator entrypoint: its caller must authorize the
// transfer actor, like the callers of Handle. No SQL projection is accepted
// from an HTTP client. A failed projection can retry the exact broker command
// and finish from its durable receipt without repeating the native mutation.
func (coordinator Coordinator) PromoteDatabaseTransfer(ctx context.Context, request TransferImportRequest) (TransferPromotion, error) {
	if ctx == nil || coordinator.repository == nil || request.Action != "promote" || request.validate() != nil {
		return TransferPromotion{}, ErrInvalidCommand
	}
	repository, ok := coordinator.repository.(transferPromotionRepository)
	if !ok {
		return TransferPromotion{}, ErrUnavailable
	}
	executor, ok := coordinator.executor.(TransferImportExecutor)
	if !ok {
		return TransferPromotion{}, ErrUnavailable
	}
	job, isolated := request.Job, *request.Isolated
	envelope, err := coordinator.repository.LoadResource(ctx, KindDatabase, job.DatabaseID)
	if err != nil {
		return TransferPromotion{}, err
	}
	database, err := transferProjectionDatabase(envelope, job)
	if err != nil {
		return TransferPromotion{}, err
	}
	prior, found, err := repository.LookupTransferPromotion(ctx, job, isolated)
	if err != nil {
		return TransferPromotion{}, err
	}
	if found {
		if database.Generation < prior.TargetGeneration {
			return TransferPromotion{}, ErrTransferStale
		}
		return prior, nil
	}
	if database.Generation != job.DatabaseGeneration {
		return TransferPromotion{}, ErrTransferStale
	}
	result, err := executor.ExecuteTransferImport(ctx, request)
	if err != nil {
		return TransferPromotion{}, err
	}
	if !result.matches(request) {
		return TransferPromotion{}, ErrInvalidReceipt
	}
	promotion := *result.Promotion
	if err = repository.RecordTransferPromotion(ctx, job, isolated, promotion); err != nil {
		return promotion, errors.Join(ErrAmbiguous, err)
	}
	return promotion, nil
}

func transferProjectionDatabase(envelope ResourceEnvelope, job TransferJob) (Database, error) {
	resource, err := DecodeResource(envelope)
	if err != nil {
		return Database{}, err
	}
	database, ok := resource.(*Database)
	if !ok || database.ID != job.DatabaseID || database.TenantID != job.TenantID || database.SiteID != job.SiteID || database.InstanceID != job.InstanceID || !workspaceReady(database.Metadata) {
		return Database{}, ErrUnauthorized
	}
	return *database, nil
}

func scanTransferPromotion(row rowScanner, job TransferJob, isolated IsolatedTransferDatabase) (TransferPromotion, bool, error) {
	var digest string
	var isolatedJSON, promotionJSON []byte
	if err := row.Scan(&digest, &isolatedJSON, &promotionJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TransferPromotion{}, false, nil
		}
		return TransferPromotion{}, false, err
	}
	var stored IsolatedTransferDatabase
	var promotion TransferPromotion
	if digest != job.Digest || json.Unmarshal(isolatedJSON, &stored) != nil || stored != isolated || json.Unmarshal(promotionJSON, &promotion) != nil || promotion.Validate(job, isolated) != nil {
		return TransferPromotion{}, false, ErrTransferStale
	}
	return promotion, true, nil
}

func (repository *SQLRepository) LookupTransferPromotion(ctx context.Context, job TransferJob, isolated IsolatedTransferDatabase) (TransferPromotion, bool, error) {
	if repository == nil || repository.db == nil || ctx == nil || job.Validate() != nil || job.Direction != TransferImport || isolated.Validate(job) != nil {
		return TransferPromotion{}, false, ErrTransferInvalid
	}
	return scanTransferPromotion(repository.db.QueryRowContext(ctx, `SELECT job_digest,isolated_json,promotion_json FROM panel_database_transfer_promotions WHERE job_id=?`, job.ID.String()), job, isolated)
}

func (repository *SQLRepository) RecordTransferPromotion(ctx context.Context, job TransferJob, isolated IsolatedTransferDatabase, promotion TransferPromotion) error {
	if repository == nil || repository.db == nil || ctx == nil || job.Validate() != nil || job.Direction != TransferImport || isolated.Validate(job) != nil || promotion.Validate(job, isolated) != nil || promotion.TargetGeneration != job.DatabaseGeneration+1 {
		return ErrTransferInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	envelope, err := scanResource(KindDatabase, job.DatabaseID, tx.QueryRowContext(ctx, `SELECT tenant_id,site_id,parent_id,physical_name,generation,spec_json,status_json FROM panel_database_resources WHERE kind=? AND resource_id=?`, string(KindDatabase), job.DatabaseID.String()))
	if err != nil {
		return err
	}
	database, err := transferProjectionDatabase(envelope, job)
	if err != nil {
		return err
	}
	prior, found, err := scanTransferPromotion(tx.QueryRowContext(ctx, `SELECT job_digest,isolated_json,promotion_json FROM panel_database_transfer_promotions WHERE job_id=?`, job.ID.String()), job, isolated)
	if err != nil {
		return err
	}
	if found {
		if prior != promotion || database.Generation < promotion.TargetGeneration {
			return ErrTransferStale
		}
		return tx.Commit()
	}
	if database.Generation != job.DatabaseGeneration {
		return ErrTransferStale
	}
	database.Generation = promotion.TargetGeneration
	database.Status = readyStatus(database.Generation)
	database.Status.ProofDigest = promotion.ProofDigest
	envelope, err = EncodeResource(database)
	if err != nil {
		return err
	}
	conflict, err := applyMutation(ctx, tx, ResourceMutation{Kind: MutationUpsert, ExpectedGeneration: job.DatabaseGeneration, Resource: envelope}, promotion.CompletedAt)
	if err != nil {
		return err
	}
	if conflict {
		return ErrTransferStale
	}
	isolatedJSON, _ := json.Marshal(isolated)
	promotionJSON, _ := json.Marshal(promotion)
	if _, err = tx.ExecContext(ctx, `INSERT INTO panel_database_transfer_promotions(job_id,job_digest,isolated_json,promotion_json) VALUES(?,?,?,?)`, job.ID.String(), job.Digest, isolatedJSON, promotionJSON); err != nil {
		return err
	}
	return tx.Commit()
}
