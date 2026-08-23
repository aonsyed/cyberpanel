// Package backup provides durable, immutable backup and recovery orchestration.
package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type PolicyID string; type RepositoryID string; type RecoveryPointID string; type ArtifactID string; type CopyID string; type HoldID string; type LeaseID string; type RestoreID string; type TransferID string; type JobID string
type ProviderKind string
const ( Local ProviderKind = "local"; SFTP ProviderKind = "sftp"; S3 ProviderKind = "s3"; AWS ProviderKind = "aws"; Wasabi ProviderKind = "wasabi"; Backblaze ProviderKind = "backblaze"; GoogleDrive ProviderKind = "google_drive"; DigitalOceanSpaces ProviderKind = "do_spaces"; MinIO ProviderKind = "minio" )
type Policy struct { ID PolicyID `json:"id"`; Repository RepositoryID `json:"repository"`; Schedule string `json:"schedule"`; KeepLast uint32 `json:"keep_last"`; Verify bool `json:"verify"`; Consistency string `json:"consistency"` }
type Repository struct { ID RepositoryID `json:"id"`; Kind ProviderKind `json:"kind"`; Endpoint string `json:"endpoint"`; Bucket string `json:"bucket"`; CredentialRef string `json:"credential_ref"` }
type RecoveryPoint struct { ID RecoveryPointID `json:"id"`; Policy PolicyID `json:"policy"`; Frontier uint64 `json:"write_frontier"`; State string `json:"state"`; CreatedAt time.Time `json:"created_at"`; CommittedAt time.Time `json:"committed_at"` }
type Artifact struct { ID ArtifactID `json:"id"`; RecoveryPoint RecoveryPointID `json:"recovery_point"`; Component string `json:"component"`; Digest string `json:"digest"`; Size int64 `json:"size"`; Object string `json:"object"` }
type Manifest struct { RecoveryPoint RecoveryPointID `json:"recovery_point"`; Frontier uint64 `json:"frontier"`; Artifacts []Artifact `json:"artifacts"`; Digest string `json:"digest"` }
type Copy struct { ID CopyID `json:"id"`; RecoveryPoint RecoveryPointID `json:"recovery_point"`; Repository RepositoryID `json:"repository"`; Marker string `json:"commit_marker"`; VerifiedAt time.Time `json:"verified_at"` }
type Hold struct { ID HoldID `json:"id"`; RecoveryPoint RecoveryPointID `json:"recovery_point"`; Reason string `json:"reason"`; Until time.Time `json:"until"` }
type Lease struct { ID LeaseID `json:"id"`; Resource string `json:"resource"`; Owner string `json:"owner"`; Until time.Time `json:"until"` }
type StableView struct { Name string `json:"name"`; Frontier uint64 `json:"frontier"`; Token string `json:"token"` }
type RestorePlan struct { ID RestoreID `json:"id"`; RecoveryPoint RecoveryPointID `json:"recovery_point"`; Target string `json:"target"`; Stage string `json:"stage"`; WriteFrontier uint64 `json:"write_frontier"` }
type Transfer struct { ID TransferID `json:"id"`; Source string `json:"source"`; Target string `json:"target"`; State string `json:"state"`; Checkpoint string `json:"checkpoint"` }
type ScheduledJob struct { ID JobID `json:"id"`; Policy PolicyID `json:"policy"`; NextRun time.Time `json:"next_run"`; State string `json:"state"` }
type Barrier interface { Stable(context.Context, string) (StableView, error); Release(context.Context, StableView) error }
type Provider interface { Stage(context.Context, Repository, Artifact) error; Commit(context.Context, Repository, Manifest) (string, error); Read(context.Context, Repository, Artifact) ([]byte, error); Verify(context.Context, Repository, Manifest) error; Delete(context.Context, Repository, RecoveryPointID) error }
type Promoter interface { Stage(context.Context, RestorePlan) error; Promote(context.Context, RestorePlan) error; Rollback(context.Context, RestorePlan) error }
type Mover interface { Transfer(context.Context, Transfer) error }

const Schema = `CREATE TABLE IF NOT EXISTS backup_recovery_points (id TEXT PRIMARY KEY, point_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS backup_artifacts (id TEXT PRIMARY KEY, recovery_point_id TEXT NOT NULL, artifact_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS backup_manifests (recovery_point_id TEXT PRIMARY KEY, manifest_json TEXT NOT NULL, committed_at TIMESTAMP NULL); CREATE TABLE IF NOT EXISTS backup_holds (id TEXT PRIMARY KEY, recovery_point_id TEXT NOT NULL, hold_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS backup_leases (resource TEXT PRIMARY KEY, lease_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS backup_restores (id TEXT PRIMARY KEY, restore_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS backup_transfers (id TEXT PRIMARY KEY, transfer_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS backup_jobs (id TEXT PRIMARY KEY, job_json TEXT NOT NULL);`
type SQLRepository struct { DB *sql.DB }
func (r SQLRepository) Bootstrap(ctx context.Context) error { if r.DB == nil { return errors.New("backup database required") }; _, err := r.DB.ExecContext(ctx, Schema); return err }
func (r SQLRepository) Create(ctx context.Context, point RecoveryPoint) error { return r.put(ctx, `INSERT INTO backup_recovery_points (id, point_json) VALUES (?, ?)`, point.ID, point) }
func (r SQLRepository) AddArtifact(ctx context.Context, artifact Artifact) error { return r.put(ctx, `INSERT INTO backup_artifacts (id, recovery_point_id, artifact_json) VALUES (?, ?, ?)`, artifact.ID, artifact.RecoveryPoint, artifact) }
func (r SQLRepository) Commit(ctx context.Context, manifest Manifest) error { return r.put(ctx, `INSERT INTO backup_manifests (recovery_point_id, manifest_json, committed_at) VALUES (?, ?, ?)`, manifest.RecoveryPoint, manifest, time.Now().UTC()) }
func (r SQLRepository) Hold(ctx context.Context, hold Hold) error { return r.put(ctx, `INSERT INTO backup_holds (id, recovery_point_id, hold_json) VALUES (?, ?, ?)`, hold.ID, hold.RecoveryPoint, hold) }
func (r SQLRepository) SaveRestore(ctx context.Context, plan RestorePlan) error { return r.put(ctx, `INSERT INTO backup_restores (id, restore_json) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET restore_json = excluded.restore_json`, plan.ID, plan) }
func (r SQLRepository) SaveTransfer(ctx context.Context, transfer Transfer) error { return r.put(ctx, `INSERT INTO backup_transfers (id, transfer_json) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET transfer_json = excluded.transfer_json`, transfer.ID, transfer) }
func (r SQLRepository) SaveJob(ctx context.Context, job ScheduledJob) error { return r.put(ctx, `INSERT INTO backup_jobs (id, job_json) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET job_json = excluded.job_json`, job.ID, job) }
func (r SQLRepository) put(ctx context.Context, query string, values ...any) error { if r.DB == nil { return errors.New("backup database required") }; n := len(values)-1; b, err := json.Marshal(values[n]); if err != nil { return err }; values[n] = b; _, err = r.DB.ExecContext(ctx, query, values...); return err }
func (r SQLRepository) CanPrune(ctx context.Context, point RecoveryPointID, now time.Time) (bool, error) { var count int; err := r.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_holds WHERE recovery_point_id = ? AND (hold_json IS NOT NULL)`, point).Scan(&count); return count == 0, err }

type Coordinator struct { Store SQLRepository; Barrier Barrier; Provider Provider }
func (c Coordinator) Capture(ctx context.Context, policy Policy, repository Repository, point RecoveryPoint, artifacts []Artifact) (Manifest, error) { if c.Barrier == nil || c.Provider == nil { return Manifest{}, errors.New("backup barrier and provider required") }; view, err := c.Barrier.Stable(ctx, string(point.ID)); if err != nil { return Manifest{}, err }; defer c.Barrier.Release(ctx, view); point.Frontier, point.State, point.CreatedAt = view.Frontier, "staging", time.Now().UTC(); if err = c.Store.Create(ctx, point); err != nil { return Manifest{}, err }; for _, artifact := range artifacts { artifact.RecoveryPoint = point.ID; if err = c.Provider.Stage(ctx, repository, artifact); err != nil { return Manifest{}, err }; if err = c.Store.AddArtifact(ctx, artifact); err != nil { return Manifest{}, err } }; manifest := Manifest{RecoveryPoint: point.ID, Frontier: view.Frontier, Artifacts: artifacts}; marker, err := c.Provider.Commit(ctx, repository, manifest); if err != nil || marker == "" { if err == nil { err = errors.New("missing commit marker") }; return Manifest{}, err }; if err = c.Store.Commit(ctx, manifest); err != nil { return Manifest{}, err }; return manifest, nil }
func (c Coordinator) Restore(ctx context.Context, plan RestorePlan, promoter Promoter) error { if promoter == nil { return errors.New("restore promoter required") }; plan.Stage = "staged"; if err := c.Store.SaveRestore(ctx, plan); err != nil { return err }; if err := promoter.Stage(ctx, plan); err != nil { return err }; plan.Stage = "promoted"; if err := promoter.Promote(ctx, plan); err != nil { return promoter.Rollback(ctx, plan) }; return c.Store.SaveRestore(ctx, plan) }
func (c Coordinator) Transfer(ctx context.Context, transfer Transfer, mover Mover) error { if mover == nil { return errors.New("transfer mover required") }; transfer.State = "running"; if err := c.Store.SaveTransfer(ctx, transfer); err != nil { return err }; if err := mover.Transfer(ctx, transfer); err != nil { return err }; transfer.State = "complete"; return c.Store.SaveTransfer(ctx, transfer) }
