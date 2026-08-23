package migration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

const chunkMaintenanceSchema = `
CREATE TABLE IF NOT EXISTS panel_migration_chunk_maintenance (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  lease_owner TEXT NOT NULL,
  lease_token TEXT NOT NULL,
  lease_fence INTEGER NOT NULL,
  lease_until TEXT NOT NULL,
  release_cursor TEXT NOT NULL,
  gc_cursor TEXT NOT NULL,
  state TEXT NOT NULL,
  cycle_started_at TEXT NOT NULL,
  cycle_completed_at TEXT NOT NULL,
  last_success_at TEXT NOT NULL,
  last_error TEXT NOT NULL,
  evidence_digest TEXT NOT NULL,
  released_migrations INTEGER NOT NULL,
  gc_receipts INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK(lease_fence >= 0),
  CHECK(released_migrations >= 0),
  CHECK(gc_receipts >= 0),
  CHECK(state IN ('idle','running','healthy','degraded','needs_reconciliation','stopped'))
);
INSERT OR IGNORE INTO panel_migration_chunk_maintenance(singleton,lease_owner,lease_token,lease_fence,lease_until,release_cursor,gc_cursor,state,cycle_started_at,cycle_completed_at,last_success_at,last_error,evidence_digest,released_migrations,gc_receipts,updated_at)
VALUES(1,'','',0,'','','','idle','','','','','',0,0,'');
CREATE TABLE IF NOT EXISTS panel_migration_chunk_gc_reconciliations (
  digest TEXT NOT NULL,
  object_epoch INTEGER NOT NULL,
  tenant_id TEXT NOT NULL,
  migration_id TEXT NOT NULL,
  resolution TEXT NOT NULL,
  ambiguous_evidence_digest TEXT NOT NULL,
  receipt_json BLOB NOT NULL,
  reconciled_at TEXT NOT NULL,
  PRIMARY KEY(digest,object_epoch),
  FOREIGN KEY(digest,object_epoch) REFERENCES panel_migration_chunk_gc_receipts(digest,object_epoch) ON DELETE RESTRICT,
  FOREIGN KEY(migration_id) REFERENCES panel_migration_scopes(migration_id) ON DELETE RESTRICT,
  CHECK(object_epoch > 0),
  CHECK(resolution IN ('confirm_deleted','retain_present'))
);`

const (
	ChunkMaintenanceHealthy             = "healthy"
	ChunkMaintenanceDegraded            = "degraded"
	ChunkMaintenanceNeedsReconciliation = "needs_reconciliation"
	ChunkMaintenanceStopped             = "stopped"
)

type ChunkMaintenanceConfig struct {
	Interval          time.Duration
	Jitter            time.Duration
	ExpireAfter       time.Duration
	QuarantineDelay   time.Duration
	CycleTimeout      time.Duration
	LeaseDuration     time.Duration
	ReleaseLimit      uint16
	GarbageLimit      uint16
}

func DefaultChunkMaintenanceConfig() ChunkMaintenanceConfig {
	return ChunkMaintenanceConfig{
		Interval:        30 * time.Minute,
		Jitter:          5 * time.Minute,
		ExpireAfter:     30 * 24 * time.Hour,
		QuarantineDelay: DefaultChunkQuarantineDelay,
		CycleTimeout:    2 * time.Minute,
		LeaseDuration:   3 * time.Minute,
		ReleaseLimit:    32,
		GarbageLimit:    32,
	}
}

type ChunkMaintenanceEvidence struct {
	LeaseFence         uint64
	State              string
	FailureCode        string
	ReleaseCursor      string
	GarbageCursor      string
	ReleasedMigrations uint32
	GarbageReceipts    uint32
	StartedAt          time.Time
	CompletedAt        time.Time
	EvidenceDigest     string
}

type ChunkMaintenanceAuditor interface {
	RecordMigrationChunkMaintenance(context.Context, ChunkMaintenanceEvidence) error
}

type ChunkMaintenanceScheduler struct {
	store    *RuntimeScopeStore
	chunks   *ChunkStore
	auditor  ChunkMaintenanceAuditor
	config   ChunkMaintenanceConfig
	workerID string
}

type chunkMaintenanceLease struct {
	Owner         string
	Token         string
	Fence         uint64
	Until         time.Time
	ReleaseCursor string
	GarbageCursor string
	LastSuccessAt time.Time
	StartedAt     time.Time
}

func NewChunkMaintenanceScheduler(store *RuntimeScopeStore, chunks *ChunkStore, auditor ChunkMaintenanceAuditor, config ChunkMaintenanceConfig) (*ChunkMaintenanceScheduler, error) {
	if store == nil || store.db == nil || chunks == nil || auditor == nil || validateChunkMaintenanceConfig(config) != nil {
		return nil, ErrInvalid
	}
	workerID, err := newChunkMaintenanceWorkerID()
	if err != nil {
		return nil, err
	}
	return &ChunkMaintenanceScheduler{store: store, chunks: chunks, auditor: auditor, config: config, workerID: workerID}, nil
}

func (scheduler *ChunkMaintenanceScheduler) Run(ctx context.Context) {
	if scheduler == nil || ctx == nil {
		return
	}
	if !waitChunkMaintenance(ctx, scheduler.jitter(0, scheduler.store.clock().UTC())) {
		return
	}
	var fence uint64
	for {
		evidence, claimed, _ := scheduler.RunOnce(ctx)
		if claimed {
			fence = evidence.LeaseFence
		}
		if !waitChunkMaintenance(ctx, scheduler.config.Interval+scheduler.jitter(fence, scheduler.store.clock().UTC())) {
			return
		}
	}
}

func (scheduler *ChunkMaintenanceScheduler) RunOnce(ctx context.Context) (ChunkMaintenanceEvidence, bool, error) {
	if scheduler == nil || scheduler.store == nil || scheduler.chunks == nil || scheduler.auditor == nil || ctx == nil {
		return ChunkMaintenanceEvidence{}, false, ErrInvalid
	}
	lease, claimed, err := scheduler.store.claimChunkMaintenance(ctx, scheduler.workerID, scheduler.config.LeaseDuration)
	if err != nil || !claimed {
		return ChunkMaintenanceEvidence{}, claimed, err
	}
	cycleContext, cancel := context.WithTimeout(ctx, scheduler.config.CycleTimeout)
	releases, releaseCursor, releaseErr := scheduler.store.releaseExpiredChunkReferencesAfter(cycleContext, lease.StartedAt.Add(-scheduler.config.ExpireAfter), scheduler.config.QuarantineDelay, lease.ReleaseCursor, scheduler.config.ReleaseLimit)
	var garbage []ChunkGCReceipt
	garbageCursor := lease.GarbageCursor
	var garbageErr error
	var reconciliationErr error
	needsReconciliation := false
	if cycleContext.Err() == nil {
		garbage, garbageCursor, garbageErr = scheduler.store.collectChunkGarbageAfter(cycleContext, scheduler.chunks, lease.GarbageCursor, scheduler.config.GarbageLimit)
	} else {
		garbageErr = cycleContext.Err()
	}
	if cycleContext.Err() == nil {
		needsReconciliation, reconciliationErr = scheduler.store.hasAmbiguousChunkGC(cycleContext)
	}
	cancel()
	workErr := errors.Join(releaseErr, garbageErr, reconciliationErr)
	completedAt := scheduler.store.clock().UTC()
	if completedAt.Before(lease.StartedAt) {
		completedAt = lease.StartedAt
	}
	evidence := ChunkMaintenanceEvidence{
		LeaseFence:         lease.Fence,
		State:              ChunkMaintenanceHealthy,
		FailureCode:        chunkMaintenanceFailure(workErr),
		ReleaseCursor:      releaseCursor,
		GarbageCursor:      garbageCursor,
		ReleasedMigrations: uint32(len(releases)),
		GarbageReceipts:    uint32(len(garbage)),
		StartedAt:          lease.StartedAt,
		CompletedAt:        completedAt,
	}
	if ctx.Err() != nil {
		evidence.State = ChunkMaintenanceStopped
	} else if needsReconciliation || errors.Is(workErr, ErrAmbiguous) || hasAmbiguousChunkGCReceipt(garbage) {
		evidence.State = ChunkMaintenanceNeedsReconciliation
	} else if workErr != nil {
		evidence.State = ChunkMaintenanceDegraded
	}
	evidence.EvidenceDigest = chunkMaintenanceEvidenceDigest(evidence)
	finalizeContext, finalizeCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer finalizeCancel()
	auditErr := scheduler.auditor.RecordMigrationChunkMaintenance(finalizeContext, evidence)
	if auditErr != nil {
		if evidence.FailureCode == "" {
			evidence.FailureCode = "audit_unavailable"
		} else {
			evidence.FailureCode += ",audit_unavailable"
		}
		if evidence.State == ChunkMaintenanceHealthy {
			evidence.State = ChunkMaintenanceDegraded
		}
		evidence.EvidenceDigest = chunkMaintenanceEvidenceDigest(evidence)
	}
	completeErr := scheduler.store.completeChunkMaintenance(finalizeContext, lease, evidence)
	return evidence, true, errors.Join(workErr, auditErr, completeErr)
}

func (store *RuntimeScopeStore) claimChunkMaintenance(ctx context.Context, owner string, duration time.Duration) (chunkMaintenanceLease, bool, error) {
	if store == nil || store.db == nil || ctx == nil || !runtimeScopeText(owner, 128) || duration <= 0 {
		return chunkMaintenanceLease{}, false, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.clock().UTC()
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return chunkMaintenanceLease{}, false, err
	}
	defer tx.Rollback()
	var fence int64
	var token, untilRaw, releaseCursor, garbageCursor, lastSuccessRaw string
	if err = tx.QueryRowContext(ctx, `SELECT lease_token,lease_fence,lease_until,release_cursor,gc_cursor,last_success_at FROM panel_migration_chunk_maintenance WHERE singleton=1`).Scan(&token, &fence, &untilRaw, &releaseCursor, &garbageCursor, &lastSuccessRaw); err != nil {
		return chunkMaintenanceLease{}, false, err
	}
	if fence < 0 || fence == math.MaxInt64 || releaseCursor != "" && !validMigrationCursor(releaseCursor) || garbageCursor != "" && !isDigest(garbageCursor) {
		return chunkMaintenanceLease{}, false, ErrAmbiguous
	}
	if token != "" {
		until, decodeErr := decodeTime(untilRaw)
		if decodeErr != nil || until.IsZero() {
			return chunkMaintenanceLease{}, false, ErrAmbiguous
		}
		if until.After(now) {
			return chunkMaintenanceLease{}, false, tx.Commit()
		}
	}
	lastSuccess := time.Time{}
	if lastSuccessRaw != "" {
		lastSuccess, err = decodeTime(lastSuccessRaw)
		if err != nil {
			return chunkMaintenanceLease{}, false, ErrAmbiguous
		}
	}
	lease := chunkMaintenanceLease{Owner: owner, Fence: uint64(fence + 1), Until: now.Add(duration), ReleaseCursor: releaseCursor, GarbageCursor: garbageCursor, LastSuccessAt: lastSuccess, StartedAt: now}
	lease.Token = chunkMaintenanceLeaseToken(owner, lease.Fence, now)
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_chunk_maintenance SET lease_owner=?,lease_token=?,lease_fence=?,lease_until=?,state='running',cycle_started_at=?,last_error='',updated_at=? WHERE singleton=1 AND lease_fence=? AND (lease_token='' OR lease_until<=?)`, lease.Owner, lease.Token, lease.Fence, encodeTime(lease.Until), encodeTime(now), encodeTime(now), fence, encodeTime(now))
	if err != nil {
		return chunkMaintenanceLease{}, false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return chunkMaintenanceLease{}, false, err
	}
	if affected != 1 {
		return chunkMaintenanceLease{}, false, tx.Commit()
	}
	if err = tx.Commit(); err != nil {
		return chunkMaintenanceLease{}, false, err
	}
	return lease, true, nil
}

func (store *RuntimeScopeStore) completeChunkMaintenance(ctx context.Context, lease chunkMaintenanceLease, evidence ChunkMaintenanceEvidence) error {
	if store == nil || store.db == nil || ctx == nil || lease.Token == "" || lease.Fence == 0 || evidence.LeaseFence != lease.Fence || !evidence.StartedAt.Equal(lease.StartedAt) || evidence.CompletedAt.After(lease.Until) || !validChunkMaintenanceEvidence(evidence) || evidence.ReleaseCursor != "" && !validMigrationCursor(evidence.ReleaseCursor) || evidence.GarbageCursor != "" && !isDigest(evidence.GarbageCursor) {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lastSuccess := lease.LastSuccessAt
	if evidence.State == ChunkMaintenanceHealthy {
		lastSuccess = evidence.CompletedAt
	}
	result, err := store.db.ExecContext(ctx, `UPDATE panel_migration_chunk_maintenance SET lease_owner='',lease_token='',lease_until='',release_cursor=?,gc_cursor=?,state=?,cycle_completed_at=?,last_success_at=?,last_error=?,evidence_digest=?,released_migrations=?,gc_receipts=?,updated_at=? WHERE singleton=1 AND lease_owner=? AND lease_token=? AND lease_fence=? AND lease_until>=?`, evidence.ReleaseCursor, evidence.GarbageCursor, evidence.State, encodeTime(evidence.CompletedAt), encodeOptionalChunkMaintenanceTime(lastSuccess), evidence.FailureCode, evidence.EvidenceDigest, evidence.ReleasedMigrations, evidence.GarbageReceipts, encodeTime(evidence.CompletedAt), lease.Owner, lease.Token, lease.Fence, encodeTime(evidence.CompletedAt))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrConflict
	}
	return nil
}

func validateChunkMaintenanceConfig(config ChunkMaintenanceConfig) error {
	if config.Interval < time.Minute || config.Interval > 24*time.Hour || config.Jitter < 0 || config.Jitter > config.Interval || config.ExpireAfter < time.Hour || config.ExpireAfter > 365*24*time.Hour || config.QuarantineDelay <= 0 || config.QuarantineDelay > maximumChunkQuarantineDelay || config.CycleTimeout < 5*time.Second || config.CycleTimeout > 10*time.Minute || config.LeaseDuration <= config.CycleTimeout || config.LeaseDuration > 15*time.Minute || config.ReleaseLimit == 0 || config.ReleaseLimit > 200 || config.GarbageLimit == 0 || config.GarbageLimit > 200 {
		return ErrInvalid
	}
	return nil
}

func (scheduler *ChunkMaintenanceScheduler) jitter(fence uint64, now time.Time) time.Duration {
	if scheduler.config.Jitter == 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(scheduler.workerID + "\x00" + now.UTC().Format(time.RFC3339Nano) + "\x00" + hex.EncodeToString([]byte{byte(fence >> 56), byte(fence >> 48), byte(fence >> 40), byte(fence >> 32), byte(fence >> 24), byte(fence >> 16), byte(fence >> 8), byte(fence)})))
	return time.Duration(binary.BigEndian.Uint64(sum[:8]) % (uint64(scheduler.config.Jitter) + 1))
}

func waitChunkMaintenance(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func newChunkMaintenanceWorkerID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "migration-chunk-maintenance-" + hex.EncodeToString(raw), nil
}

func chunkMaintenanceLeaseToken(owner string, fence uint64, now time.Time) string {
	sum := sha256.Sum256([]byte(owner + "\x00" + now.UTC().Format(time.RFC3339Nano) + "\x00" + strconv.FormatUint(fence, 10)))
	return hex.EncodeToString(sum[:])
}

func chunkMaintenanceEvidenceDigest(evidence ChunkMaintenanceEvidence) string {
	evidence.EvidenceDigest = ""
	return digestJSON(struct {
		Domain   string
		Evidence ChunkMaintenanceEvidence
	}{Domain: "migration-chunk-maintenance-v1", Evidence: evidence})
}

func chunkMaintenanceFailure(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrAmbiguous):
		return "reconciliation_required"
	case errors.Is(err, context.DeadlineExceeded):
		return "cycle_deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrConflict):
		return "state_conflict"
	case errors.Is(err, ErrInvalid):
		return "invalid_state"
	default:
		return "internal_error"
	}
}

func hasAmbiguousChunkGCReceipt(receipts []ChunkGCReceipt) bool {
	for _, receipt := range receipts {
		if receipt.State == "ambiguous" {
			return true
		}
	}
	return false
}

func validMigrationCursor(value string) bool {
	_, err := NewID(value)
	return err == nil
}

func encodeOptionalChunkMaintenanceTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return encodeTime(value)
}

func validChunkMaintenanceState(value string) bool {
	return value == ChunkMaintenanceHealthy || value == ChunkMaintenanceDegraded || value == ChunkMaintenanceNeedsReconciliation || value == ChunkMaintenanceStopped
}

func validChunkMaintenanceEvidence(evidence ChunkMaintenanceEvidence) bool {
	return evidence.LeaseFence > 0 && validChunkMaintenanceState(evidence.State) && len(evidence.FailureCode) <= 256 && !strings.ContainsRune(evidence.FailureCode, 0) && !evidence.StartedAt.IsZero() && !evidence.CompletedAt.Before(evidence.StartedAt) && evidence.EvidenceDigest == chunkMaintenanceEvidenceDigest(evidence)
}
