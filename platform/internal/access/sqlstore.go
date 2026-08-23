package access

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const Schema = `
CREATE TABLE IF NOT EXISTS access_file_operations (
 id TEXT PRIMARY KEY, command_id TEXT NOT NULL UNIQUE, site_id TEXT NOT NULL,
 state TEXT NOT NULL, operation_json BLOB NOT NULL, receipt TEXT NOT NULL DEFAULT '', error_code TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMP NOT NULL, finished_at TIMESTAMP NULL
);
CREATE INDEX IF NOT EXISTS access_file_operations_site ON access_file_operations(site_id, created_at);
CREATE TABLE IF NOT EXISTS access_uploads (
 id TEXT PRIMARY KEY, site_id TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL,
 upload_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS access_uploads_expiry ON access_uploads(state, updated_at);
CREATE TABLE IF NOT EXISTS access_downloads (
 id TEXT PRIMARY KEY, site_id TEXT NOT NULL, lease_json BLOB NOT NULL, expires_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS access_trash (
 id TEXT PRIMARY KEY, site_id TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL,
 trash_json BLOB NOT NULL, purge_after TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS access_trash_retention ON access_trash(state, purge_after);
CREATE TABLE IF NOT EXISTS access_archives (
 id TEXT PRIMARY KEY, site_id TEXT NOT NULL, state TEXT NOT NULL, archive_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS access_ftps_accounts (
 id TEXT PRIMARY KEY, site_id TEXT NOT NULL, username TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
 generation INTEGER NOT NULL, account_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS access_ftps_site ON access_ftps_accounts(site_id, state);
CREATE TABLE IF NOT EXISTS access_ssh_keys (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL, generation INTEGER NOT NULL, key_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS access_grants (
 id TEXT PRIMARY KEY, site_id TEXT NOT NULL, tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL,
 protocol TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL, grant_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS access_grants_site ON access_grants(site_id, state);
CREATE TABLE IF NOT EXISTS access_terminal_sessions (
 id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, session_json BLOB NOT NULL, expires_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS access_cron_jobs (
 id TEXT PRIMARY KEY, site_id TEXT NOT NULL, state TEXT NOT NULL, enabled INTEGER NOT NULL,
 generation INTEGER NOT NULL, job_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS access_cron_site ON access_cron_jobs(site_id, state, enabled);
CREATE TABLE IF NOT EXISTS access_cron_generations (
 site_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, receipt_json BLOB NULL, updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS access_cron_runs (
 run_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, run_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS access_git_repositories (
 id TEXT PRIMARY KEY, site_id TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL,
 repository_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS access_git_site ON access_git_repositories(site_id, state);
CREATE TABLE IF NOT EXISTS access_git_deploy_keys (
 id TEXT PRIMARY KEY, repository_id TEXT NOT NULL UNIQUE, site_id TEXT NOT NULL, state TEXT NOT NULL,
 generation INTEGER NOT NULL, key_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS access_git_webhooks (
 id TEXT PRIMARY KEY, repository_id TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL,
 webhook_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS access_git_deliveries (
 webhook_id TEXT NOT NULL, delivery_id TEXT NOT NULL, payload_digest TEXT NOT NULL, received_at TIMESTAMP NOT NULL,
 PRIMARY KEY(webhook_id, delivery_id)
);
CREATE TABLE IF NOT EXISTS access_git_deployments (
 id TEXT PRIMARY KEY, repository_id TEXT NOT NULL, site_id TEXT NOT NULL, state TEXT NOT NULL,
 generation INTEGER NOT NULL, deployment_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS access_git_deploy_queue ON access_git_deployments(state, updated_at);
CREATE TABLE IF NOT EXISTS access_staging_syncs (
 id TEXT PRIMARY KEY, live_site_id TEXT NOT NULL, staging_site_id TEXT NOT NULL, state TEXT NOT NULL,
 generation INTEGER NOT NULL, sync_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS access_staging_sync_queue ON access_staging_syncs(state, updated_at);
`

type SQLStore struct{ DB *sql.DB }

func (store SQLStore) Bootstrap(ctx context.Context) error {
	if store.DB == nil { return errors.New("access database is required") }
	_, err := store.DB.ExecContext(ctx, Schema)
	return err
}

func marshal(value any) ([]byte, error) { return json.Marshal(value) }

func decode(data []byte, target any) error {
	if len(data) == 0 { return ErrIntegrity }
	if err := json.Unmarshal(data, target); err != nil { return errors.Join(ErrIntegrity, err) }
	return nil
}

func changed(result sql.Result) error {
	count, err := result.RowsAffected(); if err != nil { return err }
	if count != 1 { return ErrStaleGeneration }
	return nil
}

func noRows(err error) error { if errors.Is(err, sql.ErrNoRows) { return ErrNotFound }; return err }

func (store SQLStore) AdmitFileOperation(ctx context.Context, operation FileOperation) error {
	encoded, err := marshal(operation); if err != nil { return err }
	siteID := operation.Source.Root.SiteID; if siteID == "" { siteID = operation.Destination.Root.SiteID }
	_, err = store.DB.ExecContext(ctx, `INSERT INTO access_file_operations (id, command_id, site_id, state, operation_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`, operation.ID, operation.Mutation.CommandID, siteID, operation.State, encoded, operation.StartedAt)
	return err
}

func (store SQLStore) FinishFileOperation(ctx context.Context, id FileOperationID, state OperationState, receipt, errorCode string, finishedAt time.Time) error {
	result, err := store.DB.ExecContext(ctx, `UPDATE access_file_operations SET state = ?, receipt = ?, error_code = ?, finished_at = ? WHERE id = ? AND state NOT IN ('committed','compensated')`, state, receipt, errorCode, nullTime(finishedAt), id)
	if err != nil { return err }; return changed(result)
}

func (store SQLStore) CreateUpload(ctx context.Context, upload UploadSession) error {
	encoded, err := marshal(upload); if err != nil { return err }
	_, err = store.DB.ExecContext(ctx, `INSERT INTO access_uploads (id, site_id, state, generation, upload_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, upload.ID, upload.Destination.Root.SiteID, upload.State, upload.Generation, encoded, time.Now().UTC())
	return err
}

func (store SQLStore) LoadUpload(ctx context.Context, id UploadID) (UploadSession, error) {
	var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT upload_json FROM access_uploads WHERE id = ?`, id).Scan(&encoded)
	if err != nil { return UploadSession{}, noRows(err) }; var upload UploadSession; return upload, decode(encoded, &upload)
}

func (store SQLStore) AdvanceUpload(ctx context.Context, upload UploadSession, expected uint64) error {
	encoded, err := marshal(upload); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_uploads SET state = ?, generation = ?, upload_json = ?, updated_at = ? WHERE id = ? AND generation = ?`, upload.State, upload.Generation, encoded, time.Now().UTC(), upload.ID, expected); if err != nil { return err }; return changed(result)
}

func (store SQLStore) SaveDownload(ctx context.Context, lease DownloadLease) error {
	encoded, err := marshal(lease); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_downloads (id, site_id, lease_json, expires_at) VALUES (?, ?, ?, ?)`, lease.ID, lease.Source.Root.SiteID, encoded, lease.ExpiresAt); return err
}
func (store SQLStore) LoadDownload(ctx context.Context,id DownloadID)(DownloadLease,error){var encoded []byte;err:=store.DB.QueryRowContext(ctx,`SELECT lease_json FROM access_downloads WHERE id=?`,id).Scan(&encoded);if err!=nil{return DownloadLease{},noRows(err)};var lease DownloadLease;return lease,decode(encoded,&lease)}
func (store SQLStore) DeleteDownload(ctx context.Context, id DownloadID) error { _, err := store.DB.ExecContext(ctx, `DELETE FROM access_downloads WHERE id = ?`, id); return err }

func (store SQLStore) SaveTrash(ctx context.Context, entry TrashEntry) error { encoded, err := marshal(entry); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_trash (id, site_id, state, generation, trash_json, purge_after) VALUES (?, ?, ?, ?, ?, ?)`, entry.ID, entry.SiteID, entry.State, entry.Generation, encoded, entry.PurgeAfter); return err }
func (store SQLStore) LoadTrash(ctx context.Context, id TrashEntryID) (TrashEntry, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT trash_json FROM access_trash WHERE id = ?`, id).Scan(&encoded); if err != nil { return TrashEntry{}, noRows(err) }; var entry TrashEntry; return entry, decode(encoded, &entry) }
func (store SQLStore) AdvanceTrash(ctx context.Context, entry TrashEntry, expected uint64) error { encoded, err := marshal(entry); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_trash SET state = ?, generation = ?, trash_json = ?, purge_after = ? WHERE id = ? AND generation = ?`, entry.State, entry.Generation, encoded, entry.PurgeAfter, entry.ID, expected); if err != nil { return err }; return changed(result) }
func (store SQLStore) SaveArchive(ctx context.Context, archive Archive) error { encoded, err := marshal(archive); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_archives (id, site_id, state, archive_json, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET state=excluded.state, archive_json=excluded.archive_json, updated_at=excluded.updated_at`, archive.ID, archive.SiteID, archive.State, encoded, time.Now().UTC()); return err }

func (store SQLStore) CreateFTPS(ctx context.Context, account FTPSAccount) error { encoded, err := marshal(account); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_ftps_accounts (id, site_id, username, state, generation, account_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, account.ID, account.SiteID, account.Username, account.State, account.Generation, encoded, account.UpdatedAt); return err }
func (store SQLStore) LoadFTPS(ctx context.Context, id FTPSAccountID) (FTPSAccount, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT account_json FROM access_ftps_accounts WHERE id = ?`, id).Scan(&encoded); if err != nil { return FTPSAccount{}, noRows(err) }; var account FTPSAccount; return account, decode(encoded, &account) }
func (store SQLStore) AdvanceFTPS(ctx context.Context, account FTPSAccount, expected uint64) error { encoded, err := marshal(account); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_ftps_accounts SET state=?, generation=?, account_json=?, updated_at=? WHERE id=? AND generation=?`, account.State, account.Generation, encoded, account.UpdatedAt, account.ID, expected); if err != nil { return err }; return changed(result) }

func (store SQLStore) CreateSSHKey(ctx context.Context, key SSHKey) error { encoded, err := marshal(key); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_ssh_keys (id, tenant_id, principal_id, fingerprint, state, generation, key_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, key.ID, key.TenantID, key.PrincipalID, key.PublicKey.Fingerprint, key.State, key.Generation, encoded, time.Now().UTC()); return err }
func (store SQLStore) LoadSSHKey(ctx context.Context, id SSHKeyID) (SSHKey, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT key_json FROM access_ssh_keys WHERE id = ?`, id).Scan(&encoded); if err != nil { return SSHKey{}, noRows(err) }; var key SSHKey; return key, decode(encoded, &key) }
func (store SQLStore) AdvanceSSHKey(ctx context.Context, key SSHKey, expected uint64) error { encoded, err := marshal(key); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_ssh_keys SET state=?, generation=?, key_json=?, updated_at=? WHERE id=? AND generation=?`, key.State, key.Generation, encoded, time.Now().UTC(), key.ID, expected); if err != nil { return err }; return changed(result) }

func (store SQLStore) CreateAccessGrant(ctx context.Context, grant AccessGrant) error { encoded, err := marshal(grant); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_grants (id, site_id, tenant_id, principal_id, protocol, state, generation, grant_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, grant.ID, grant.SiteID, grant.TenantID, grant.PrincipalID, grant.Protocol, grant.State, grant.Generation, encoded, grant.UpdatedAt); return err }
func (store SQLStore) LoadAccessGrant(ctx context.Context, id AccessGrantID) (AccessGrant, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT grant_json FROM access_grants WHERE id = ?`, id).Scan(&encoded); if err != nil { return AccessGrant{}, noRows(err) }; var grant AccessGrant; return grant, decode(encoded, &grant) }
func (store SQLStore) AdvanceAccessGrant(ctx context.Context, grant AccessGrant, expected uint64) error { encoded, err := marshal(grant); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_grants SET state=?, generation=?, grant_json=?, updated_at=? WHERE id=? AND generation=?`, grant.State, grant.Generation, encoded, grant.UpdatedAt, grant.ID, expected); if err != nil { return err }; return changed(result) }
func (store SQLStore) SaveTerminalSession(ctx context.Context, session TerminalSession) error { encoded, err := marshal(session); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_terminal_sessions (id, grant_id, session_json, expires_at) VALUES (?, ?, ?, ?)`, session.ID, session.GrantID, encoded, session.ExpiresAt); return err }
func (store SQLStore) LoadTerminalSession(ctx context.Context, id TerminalSessionID) (TerminalSession, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT session_json FROM access_terminal_sessions WHERE id = ?`, id).Scan(&encoded); if err != nil { return TerminalSession{}, noRows(err) }; var session TerminalSession; return session, decode(encoded, &session) }
func (store SQLStore) DeleteTerminalSession(ctx context.Context, id TerminalSessionID) error { _, err := store.DB.ExecContext(ctx, `DELETE FROM access_terminal_sessions WHERE id = ?`, id); return err }

type CredentialRecord struct {
	Kind string
	FTPS *FTPSAccount
	SSHKey *SSHKey
	Grant *AccessGrant
}

// ListCredentials merges the three closed credential resource kinds into a
// stable tenant page without exposing the backing schema to the API layer.
func (store SQLStore) ListCredentials(ctx context.Context, tenant TenantID, siteIDs []SiteID, cursor string, limit uint16) ([]CredentialRecord,string,uint64,error) {
	if store.DB==nil||tenant==""||len(cursor)>256{return nil,"",0,ErrInvalidID};if limit==0{limit=100};if limit>500{return nil,"",0,ErrLimitExceeded}
	allowedSites:=make(map[SiteID]struct{},len(siteIDs));for _,id:=range siteIDs{if requireID("site",string(id))!=nil{return nil,"",0,ErrInvalidID};allowedSites[id]=struct{}{}}
	type rowValue struct{key,kind string;raw []byte};values:=[]rowValue{}
	queries:=[]struct{kind,query string;args []any}{
		{"ftps",`SELECT 'ftps:'||id,account_json FROM access_ftps_accounts WHERE state<>'deleted'`,nil},
		{"grant",`SELECT 'grant:'||id,grant_json FROM access_grants WHERE tenant_id=? AND state<>'deleted'`,[]any{tenant}},
	}
	for _,item:=range queries{rows,err:=store.DB.QueryContext(ctx,item.query,item.args...);if err!=nil{return nil,"",0,err};for rows.Next(){var key string;var raw []byte;if err=rows.Scan(&key,&raw);err!=nil{rows.Close();return nil,"",0,err};if item.kind=="ftps"{var account FTPSAccount;if decode(raw,&account)!=nil{rows.Close();return nil,"",0,ErrIntegrity};if _,ok:=allowedSites[account.SiteID];!ok{continue}};values=append(values,rowValue{key:key,kind:item.kind,raw:raw})};if err=rows.Err();err!=nil{rows.Close();return nil,"",0,err};rows.Close()}
	sort.Slice(values,func(i,j int)bool{return values[i].key<values[j].key});total:=uint64(len(values));start:=sort.Search(len(values),func(i int)bool{return values[i].key>cursor});end:=start+int(limit);if end>len(values){end=len(values)};next:="";if end<len(values)&&end>start{next=values[end-1].key}
	out:=make([]CredentialRecord,0,end-start);for _,value:=range values[start:end]{record:=CredentialRecord{Kind:value.kind};switch value.kind{case"ftps":var item FTPSAccount;if decode(value.raw,&item)!=nil{return nil,"",0,ErrIntegrity};record.FTPS=&item;case"ssh_key":var item SSHKey;if decode(value.raw,&item)!=nil{return nil,"",0,ErrIntegrity};record.SSHKey=&item;case"grant":var item AccessGrant;if decode(value.raw,&item)!=nil{return nil,"",0,ErrIntegrity};record.Grant=&item};out=append(out,record)};return out,next,total,nil
}

func (store SQLStore) CreateCron(ctx context.Context, job CronJob) error { encoded, err := marshal(job); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_cron_jobs (id, site_id, state, enabled, generation, job_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, job.ID, job.SiteID, job.State, job.Enabled, job.Generation, encoded, job.UpdatedAt); return err }
func (store SQLStore) LoadCron(ctx context.Context, id CronJobID) (CronJob, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT job_json FROM access_cron_jobs WHERE id = ?`, id).Scan(&encoded); if err != nil { return CronJob{}, noRows(err) }; var job CronJob; return job, decode(encoded, &job) }
func (store SQLStore) ListCrons(ctx context.Context, site SiteID, includePending bool) ([]CronJob, error) { query := `SELECT job_json FROM access_cron_jobs WHERE site_id=? AND state='active' AND enabled=1 ORDER BY id`; if includePending { query = `SELECT job_json FROM access_cron_jobs WHERE site_id=? AND state IN ('pending','active') AND enabled=1 ORDER BY id` }; rows, err := store.DB.QueryContext(ctx, query, site); if err != nil { return nil, err }; defer rows.Close(); jobs := []CronJob{}; for rows.Next() { var encoded []byte; if err = rows.Scan(&encoded); err != nil { return nil, err }; var job CronJob; if err = decode(encoded, &job); err != nil { return nil, err }; jobs = append(jobs, job) }; return jobs, rows.Err() }
func (store SQLStore) AdvanceCron(ctx context.Context, job CronJob, expected uint64) error { encoded, err := marshal(job); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_cron_jobs SET state=?, enabled=?, generation=?, job_json=?, updated_at=? WHERE id=? AND generation=?`, job.State, job.Enabled, job.Generation, encoded, job.UpdatedAt, job.ID, expected); if err != nil { return err }; return changed(result) }
func (store SQLStore) DeleteCron(ctx context.Context, id CronJobID, expected uint64) error { result, err := store.DB.ExecContext(ctx, `DELETE FROM access_cron_jobs WHERE id=? AND generation=?`, id, expected); if err != nil { return err }; return changed(result) }
func (store SQLStore) NextCronGeneration(ctx context.Context, site SiteID) (uint64, error) { tx, err := store.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return 0, err }; defer tx.Rollback(); var generation uint64; err = tx.QueryRowContext(ctx, `SELECT generation FROM access_cron_generations WHERE site_id=?`, site).Scan(&generation); if errors.Is(err, sql.ErrNoRows) { generation = 1; _, err = tx.ExecContext(ctx, `INSERT INTO access_cron_generations (site_id, generation, updated_at) VALUES (?, ?, ?)`, site, generation, time.Now().UTC()) } else if err == nil { generation++; _, err = tx.ExecContext(ctx, `UPDATE access_cron_generations SET generation=?, updated_at=? WHERE site_id=?`, generation, time.Now().UTC(), site) }; if err != nil { return 0, err }; if err = tx.Commit(); err != nil { return 0, err }; return generation, nil }
func (store SQLStore) SaveCronReceipt(ctx context.Context, receipt CronApplyReceipt) error { encoded, err := marshal(receipt); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_cron_generations SET receipt_json=?, updated_at=? WHERE site_id=? AND generation=?`, encoded, receipt.AppliedAt, receipt.SiteID, receipt.Generation); if err != nil { return err }; return changed(result) }
func (store SQLStore) SaveCronRun(ctx context.Context, run CronRun) error { encoded, err := marshal(run); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_cron_runs (run_id, job_id, run_json, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(run_id) DO UPDATE SET run_json=excluded.run_json, updated_at=excluded.updated_at`, run.RunID, run.JobID, encoded, time.Now().UTC()); return err }

func (store SQLStore) CreateRepository(ctx context.Context, repository GitRepository) error { encoded, err := marshal(repository); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_git_repositories (id, site_id, state, generation, repository_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, repository.ID, repository.SiteID, repository.State, repository.Generation, encoded, repository.UpdatedAt); return err }
func (store SQLStore) LoadRepository(ctx context.Context, id GitRepositoryID) (GitRepository, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT repository_json FROM access_git_repositories WHERE id=?`, id).Scan(&encoded); if err != nil { return GitRepository{}, noRows(err) }; var repository GitRepository; return repository, decode(encoded, &repository) }
func (store SQLStore) AdvanceRepository(ctx context.Context, repository GitRepository, expected uint64) error { encoded, err := marshal(repository); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_git_repositories SET state=?, generation=?, repository_json=?, updated_at=? WHERE id=? AND generation=?`, repository.State, repository.Generation, encoded, repository.UpdatedAt, repository.ID, expected); if err != nil { return err }; return changed(result) }
func (store SQLStore) CreateDeployKey(ctx context.Context, key DeployKey) error { encoded, err := marshal(key); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_git_deploy_keys (id, repository_id, site_id, state, generation, key_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, key.ID, key.RepositoryID, key.SiteID, key.State, key.Generation, encoded, time.Now().UTC()); return err }
func (store SQLStore) LoadDeployKey(ctx context.Context, id DeployKeyID) (DeployKey, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT key_json FROM access_git_deploy_keys WHERE id=?`, id).Scan(&encoded); if err != nil { return DeployKey{}, noRows(err) }; var key DeployKey; return key, decode(encoded, &key) }
func (store SQLStore) AdvanceDeployKey(ctx context.Context, key DeployKey, expected uint64) error { encoded, err := marshal(key); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_git_deploy_keys SET state=?, generation=?, key_json=?, updated_at=? WHERE id=? AND generation=?`, key.State, key.Generation, encoded, time.Now().UTC(), key.ID, expected); if err != nil { return err }; return changed(result) }
func (store SQLStore) CreateWebhook(ctx context.Context, webhook Webhook) error { encoded, err := marshal(webhook); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_git_webhooks (id, repository_id, state, generation, webhook_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, webhook.ID, webhook.RepositoryID, webhook.State, webhook.Generation, encoded, time.Now().UTC()); return err }
func (store SQLStore) LoadWebhook(ctx context.Context, id WebhookID) (Webhook, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT webhook_json FROM access_git_webhooks WHERE id=?`, id).Scan(&encoded); if err != nil { return Webhook{}, noRows(err) }; var webhook Webhook; return webhook, decode(encoded, &webhook) }
func (store SQLStore) AdvanceWebhook(ctx context.Context, webhook Webhook, expected uint64) error { encoded, err := marshal(webhook); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_git_webhooks SET state=?, generation=?, webhook_json=?, updated_at=? WHERE id=? AND generation=?`, webhook.State, webhook.Generation, encoded, time.Now().UTC(), webhook.ID, expected); if err != nil { return err }; return changed(result) }
func (store SQLStore) ClaimWebhookDelivery(ctx context.Context, delivery WebhookDelivery) (bool, error) { result, err := store.DB.ExecContext(ctx, `INSERT INTO access_git_deliveries (webhook_id, delivery_id, payload_digest, received_at) VALUES (?, ?, ?, ?) ON CONFLICT(webhook_id, delivery_id) DO NOTHING`, delivery.WebhookID, delivery.DeliveryID, deploymentPayloadDigest(delivery.Body), delivery.ReceivedAt); if err != nil { return false, err }; count, err := result.RowsAffected(); return count == 1, err }
func (store SQLStore) CreateDeployment(ctx context.Context, deployment Deployment) error { encoded, err := marshal(deployment); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_git_deployments (id, repository_id, site_id, state, generation, deployment_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, deployment.ID, deployment.RepositoryID, deployment.SiteID, deployment.State, deployment.Generation, encoded, deployment.RequestedAt); return err }
func (store SQLStore) LoadDeployment(ctx context.Context, id DeploymentID) (Deployment, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT deployment_json FROM access_git_deployments WHERE id=?`, id).Scan(&encoded); if err != nil { return Deployment{}, noRows(err) }; var deployment Deployment; return deployment, decode(encoded, &deployment) }
func (store SQLStore) AdvanceDeployment(ctx context.Context, deployment Deployment, expected uint64) error { encoded, err := marshal(deployment); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_git_deployments SET state=?, generation=?, deployment_json=?, updated_at=? WHERE id=? AND generation=?`, deployment.State, deployment.Generation, encoded, time.Now().UTC(), deployment.ID, expected); if err != nil { return err }; return changed(result) }
func (store SQLStore) CreateStagingSync(ctx context.Context, sync StagingSync) error { encoded, err := marshal(sync); if err != nil { return err }; _, err = store.DB.ExecContext(ctx, `INSERT INTO access_staging_syncs (id, live_site_id, staging_site_id, state, generation, sync_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, sync.ID, sync.LiveSiteID, sync.StagingSiteID, sync.State, sync.Generation, encoded, sync.CreatedAt); return err }
func (store SQLStore) LoadStagingSync(ctx context.Context, id StagingSyncID) (StagingSync, error) { var encoded []byte; err := store.DB.QueryRowContext(ctx, `SELECT sync_json FROM access_staging_syncs WHERE id=?`, id).Scan(&encoded); if err != nil { return StagingSync{}, noRows(err) }; var sync StagingSync; return sync, decode(encoded, &sync) }
func (store SQLStore) AdvanceStagingSync(ctx context.Context, sync StagingSync, expected uint64) error { encoded, err := marshal(sync); if err != nil { return err }; result, err := store.DB.ExecContext(ctx, `UPDATE access_staging_syncs SET state=?, generation=?, sync_json=?, updated_at=? WHERE id=? AND generation=?`, sync.State, sync.Generation, encoded, time.Now().UTC(), sync.ID, expected); if err != nil { return err }; return changed(result) }

func nullTime(value time.Time) any { if value.IsZero() { return nil }; return value }
