package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const SQLSchema = `
CREATE TABLE IF NOT EXISTS app_installations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    definition_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    generation INTEGER NOT NULL,
    installation_json BLOB NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    UNIQUE(site_id, id)
);
CREATE INDEX IF NOT EXISTS app_installations_tenant_site ON app_installations(tenant_id, site_id, state);
CREATE TABLE IF NOT EXISTS app_secret_leases (
    secret_id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    version INTEGER NOT NULL,
    state TEXT NOT NULL,
    metadata_json BLOB NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS app_secret_leases_installation ON app_secret_leases(installation_id, purpose, state);
CREATE TABLE IF NOT EXISTS app_component_inventories (
    installation_id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    source_digest TEXT NOT NULL,
    inventory_json BLOB NOT NULL,
    observed_at TIMESTAMP NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES app_installations(id)
);
CREATE TABLE IF NOT EXISTS app_update_policies (
    id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL UNIQUE,
    generation INTEGER NOT NULL,
    policy_json BLOB NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES app_installations(id)
);
CREATE TABLE IF NOT EXISTS app_wordpress_settings (
    installation_id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    settings_json BLOB NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES app_installations(id)
);
CREATE TABLE IF NOT EXISTS app_lscache_policies (
    installation_id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    policy_json BLOB NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES app_installations(id)
);
CREATE TABLE IF NOT EXISTS app_access_protections (
    installation_id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    binding_json BLOB NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES app_installations(id)
);
CREATE TABLE IF NOT EXISTS app_releases (
    id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    release_json BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES app_installations(id)
);
CREATE INDEX IF NOT EXISTS app_releases_installation ON app_releases(installation_id, created_at);
CREATE TABLE IF NOT EXISTS app_backup_profiles (
    id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    profile_json BLOB NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES app_installations(id)
);
CREATE INDEX IF NOT EXISTS app_backup_profiles_installation ON app_backup_profiles(installation_id, id);
CREATE TABLE IF NOT EXISTS app_recovery_points (
    id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    verified INTEGER NOT NULL,
    point_json BLOB NOT NULL,
    committed_at TIMESTAMP NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES app_installations(id),
    FOREIGN KEY(profile_id) REFERENCES app_backup_profiles(id)
);
CREATE INDEX IF NOT EXISTS app_recovery_points_installation ON app_recovery_points(installation_id, committed_at);
CREATE TABLE IF NOT EXISTS app_deployments (
    id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    installation_id TEXT NOT NULL,
    state TEXT NOT NULL,
    deployment_json BLOB NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES app_installations(id)
);
CREATE INDEX IF NOT EXISTS app_deployments_installation ON app_deployments(installation_id, state, updated_at);
CREATE TABLE IF NOT EXISTS app_operations (
    command_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    installation_id TEXT,
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    stage TEXT NOT NULL,
    operation_json BLOB NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS app_operations_scope ON app_operations(tenant_id, site_id, state, updated_at);
DROP INDEX IF EXISTS app_operations_active_installation;
CREATE UNIQUE INDEX app_operations_active_installation ON app_operations(installation_id) WHERE installation_id IS NOT NULL AND state IN ('admitted','executing','compensating');
CREATE TABLE IF NOT EXISTS app_staging_relations (
    id TEXT PRIMARY KEY,
    source_installation_id TEXT NOT NULL,
    target_installation_id TEXT NOT NULL UNIQUE,
    generation INTEGER NOT NULL,
    relation_json BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL,
    UNIQUE(source_installation_id, target_installation_id)
);
CREATE TABLE IF NOT EXISTS app_staging_syncs (
    id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    relation_id TEXT NOT NULL,
    state TEXT NOT NULL,
    sync_json BLOB NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(relation_id) REFERENCES app_staging_relations(id)
);
CREATE INDEX IF NOT EXISTS app_staging_syncs_relation ON app_staging_syncs(relation_id, state, updated_at);
CREATE TABLE IF NOT EXISTS app_login_grants (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    generation INTEGER NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    grant_json BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS app_login_grants_installation ON app_login_grants(installation_id, state, expires_at);
CREATE TABLE IF NOT EXISTS app_scan_runs (
    id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    installation_id TEXT NOT NULL,
    state TEXT NOT NULL,
    run_json BLOB NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS app_scan_runs_installation ON app_scan_runs(installation_id, state, updated_at);
CREATE TABLE IF NOT EXISTS app_scan_policies (
    installation_id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    policy_json BLOB NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES app_installations(id)
);
CREATE TABLE IF NOT EXISTS app_findings (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    state TEXT NOT NULL,
    severity TEXT NOT NULL,
    path TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    finding_json BLOB NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES app_scan_runs(id)
);
CREATE INDEX IF NOT EXISTS app_findings_installation ON app_findings(installation_id, state, severity, id);
CREATE TABLE IF NOT EXISTS app_remediations (
    id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    installation_id TEXT NOT NULL,
    state TEXT NOT NULL,
    generation INTEGER NOT NULL,
    remediation_json BLOB NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS app_remediations_installation ON app_remediations(installation_id, state, updated_at);
`

type ApplicationStore interface {
	AdmitOperation(context.Context, Operation) (Operation, bool, error)
	LoadOperation(context.Context, CommandID) (Operation, error)
	ListOperations(context.Context, InstallationID, uint16, string) ([]Operation, string, error)
	UpdateOperation(context.Context, Operation) error
	CreateInstallation(context.Context, ApplicationInstallation) error
	LoadInstallation(context.Context, InstallationID) (ApplicationInstallation, error)
	UpdateInstallation(context.Context, ApplicationInstallation, uint64) error
	ListInstallations(context.Context, TenantID, SiteID, uint16, string) ([]ApplicationInstallation, string, error)
	SaveInventory(context.Context, ComponentInventory) error
	LoadInventory(context.Context, InstallationID) (ComponentInventory, error)
	SaveUpdatePolicy(context.Context, UpdatePolicy, uint64) error
	LoadUpdatePolicy(context.Context, InstallationID) (UpdatePolicy, error)
	SaveRelease(context.Context, Release) error
	LoadRelease(context.Context, ReleaseID) (Release, error)
	CreateDeployment(context.Context, Deployment) error
	UpdateDeployment(context.Context, Deployment) error
	LoadDeployment(context.Context, DeploymentID) (Deployment, error)
	SaveWordPressSettings(context.Context, InstallationID, WordPressSettings, uint64) error
	LoadWordPressSettings(context.Context, InstallationID) (WordPressSettings, error)
	SaveLSCachePolicy(context.Context, LSCachePolicy, uint64) error
	LoadLSCachePolicy(context.Context, InstallationID) (LSCachePolicy, error)
}

type SQLRepository struct { DB *sql.DB }

func (repository SQLRepository) Bootstrap(ctx context.Context) error {
	if repository.DB == nil { return errors.New("application database is required") }
	tx, err := repository.DB.BeginTx(ctx, nil)
	if err != nil { return err }
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, SQLSchema); err != nil { return err }
	return tx.Commit()
}

func encode(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil { return nil, fmt.Errorf("encode application resource: %w", err) }
	return data, nil
}

func decode(data []byte, target any) error {
	if len(data) == 0 { return ErrIntegrity }
	if err := json.Unmarshal(data, target); err != nil { return fmt.Errorf("%w: %v", ErrIntegrity, err) }
	return nil
}

func (repository SQLRepository) AdmitOperation(ctx context.Context, operation Operation) (Operation, bool, error) {
	if repository.DB == nil { return Operation{}, false, errors.New("application database is required") }
	if err := operation.Validate(); err != nil { return Operation{}, false, err }
	existing, err := repository.LoadOperation(ctx, operation.CommandID)
	if err == nil {
		if existing.Kind != operation.Kind || existing.RequestDigest != operation.RequestDigest || existing.TenantID != operation.TenantID || existing.SiteID != operation.SiteID || existing.InstallationID != operation.InstallationID { return Operation{}, false, ErrConflict }
		return existing, false, nil
	}
	if !errors.Is(err, ErrNotFound) { return Operation{}, false, err }
	payload, err := encode(operation)
	if err != nil { return Operation{}, false, err }
	// A recovery journal is retained evidence, not a running mutator. Only an
	// explicit same-owner removal may pass an install's failed health boundary.
	// The guarded INSERT and unique active-mutator index arbitrate atomically.
	result, err := repository.DB.ExecContext(ctx, `INSERT INTO app_operations (command_id, kind, tenant_id, site_id, installation_id, request_digest, state, stage, operation_json, updated_at)
SELECT ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?
WHERE NOT EXISTS (
 SELECT 1 FROM app_operations prior WHERE prior.installation_id=NULLIF(?, '') AND prior.state='recovery_required'
 AND NOT (?='remove' AND prior.kind='install' AND prior.stage='health' AND prior.tenant_id=? AND prior.site_id=?)
)`, operation.CommandID, operation.Kind, operation.TenantID, operation.SiteID, operation.InstallationID, operation.RequestDigest, operation.State, operation.Stage, payload, operation.UpdatedAt, operation.InstallationID, operation.Kind, operation.TenantID, operation.SiteID)
	if err == nil {
		count, err := result.RowsAffected()
		if err != nil { return Operation{}, false, err }
		if count != 1 { return Operation{}, false, ErrRecoveryRequired }
		return operation, true, nil
	}
	existing, loadErr := repository.LoadOperation(ctx, operation.CommandID)
	if loadErr == nil && existing.Kind == operation.Kind && existing.RequestDigest == operation.RequestDigest && existing.TenantID == operation.TenantID && existing.SiteID == operation.SiteID && existing.InstallationID == operation.InstallationID { return existing, false, nil }
	if loadErr == nil { return Operation{}, false, ErrConflict }
	return Operation{}, false, err
}

func (repository SQLRepository) LoadOperation(ctx context.Context, id CommandID) (Operation, error) {
	if err := requireID("command", string(id)); err != nil { return Operation{}, err }
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT operation_json FROM app_operations WHERE command_id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return Operation{}, ErrNotFound }
	if err != nil { return Operation{}, err }
	var operation Operation
	if err := decode(payload, &operation); err != nil { return Operation{}, err }
	return operation, operation.Validate()
}

func (repository SQLRepository) UpdateOperation(ctx context.Context, operation Operation) error {
	if err := operation.Validate(); err != nil { return err }
	payload, err := encode(operation)
	if err != nil { return err }
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_operations SET state = ?, stage = ?, operation_json = ?, updated_at = ? WHERE command_id = ?`, operation.State, operation.Stage, payload, operation.UpdatedAt, operation.CommandID)
	if err != nil { return err }
	return requireOne(result)
}

func (repository SQLRepository) ListOperations(ctx context.Context, installationID InstallationID, limit uint16, cursor string) ([]Operation, string, error) {
	if err := requireID("installation", string(installationID)); err != nil { return nil, "", err }
	if limit == 0 { limit = 100 }
	if limit > 500 || len(cursor) > 128 { return nil, "", ErrInvalid }
	rows, err := repository.DB.QueryContext(ctx, `SELECT operation_json FROM app_operations WHERE installation_id = ? AND command_id > ? ORDER BY command_id LIMIT ?`, installationID, cursor, limit+1)
	if err != nil { return nil, "", err }
	defer rows.Close()
	items := make([]Operation, 0, limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil { return nil, "", err }
		var operation Operation
		if err := decode(payload, &operation); err != nil { return nil, "", err }
		items = append(items, operation)
	}
	if err := rows.Err(); err != nil { return nil, "", err }
	next := ""
	if len(items) > int(limit) { next = string(items[limit-1].CommandID); items = items[:limit] }
	return items, next, nil
}

func (repository SQLRepository) CreateInstallation(ctx context.Context, installation ApplicationInstallation) error {
	if err := installation.Validate(time.Now().UTC()); err != nil { return err }
	payload, err := encode(installation)
	if err != nil { return err }
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_installations (id, tenant_id, site_id, definition_id, kind, state, generation, installation_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, installation.ID, installation.TenantID, installation.SiteID, installation.DefinitionID, installation.Kind, installation.State, installation.Generation, payload, installation.UpdatedAt)
	return err
}

func (repository SQLRepository) LoadInstallation(ctx context.Context, id InstallationID) (ApplicationInstallation, error) {
	if err := requireID("installation", string(id)); err != nil { return ApplicationInstallation{}, err }
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT installation_json FROM app_installations WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return ApplicationInstallation{}, ErrNotFound }
	if err != nil { return ApplicationInstallation{}, err }
	var installation ApplicationInstallation
	if err := decode(payload, &installation); err != nil { return ApplicationInstallation{}, err }
	return installation, installation.Validate(time.Now().UTC())
}

func (repository SQLRepository) UpdateInstallation(ctx context.Context, installation ApplicationInstallation, expectedGeneration uint64) error {
	if err := installation.Validate(time.Now().UTC()); err != nil { return err }
	if installation.Generation != expectedGeneration+1 { return ErrStaleGeneration }
	payload, err := encode(installation)
	if err != nil { return err }
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_installations SET state = ?, generation = ?, installation_json = ?, updated_at = ? WHERE id = ? AND generation = ?`, installation.State, installation.Generation, payload, installation.UpdatedAt, installation.ID, expectedGeneration)
	if err != nil { return err }
	return requireGeneration(result)
}

func (repository SQLRepository) ListInstallations(ctx context.Context, tenantID TenantID, siteID SiteID, limit uint16, cursor string) ([]ApplicationInstallation, string, error) {
	if err := requireID("tenant", string(tenantID)); err != nil { return nil, "", err }
	if siteID != "" { if err := requireID("site", string(siteID)); err != nil { return nil, "", err } }
	if limit == 0 { limit = 100 }
	if limit > 500 || len(cursor) > 128 { return nil, "", ErrInvalid }
	query := `SELECT installation_json FROM app_installations WHERE tenant_id = ? AND id > ?`
	arguments := []any{tenantID, cursor}
	if siteID != "" { query += ` AND site_id = ?`; arguments = append(arguments, siteID) }
	query += ` ORDER BY id LIMIT ?`; arguments = append(arguments, limit+1)
	rows, err := repository.DB.QueryContext(ctx, query, arguments...)
	if err != nil { return nil, "", err }
	defer rows.Close()
	items := make([]ApplicationInstallation, 0, limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil { return nil, "", err }
		var item ApplicationInstallation
		if err := decode(payload, &item); err != nil { return nil, "", err }
		items = append(items, item)
	}
	if err := rows.Err(); err != nil { return nil, "", err }
	next := ""
	if len(items) > int(limit) { next = string(items[limit-1].ID); items = items[:limit] }
	return items, next, nil
}

func (repository SQLRepository) SaveInventory(ctx context.Context, inventory ComponentInventory) error {
	if err := inventory.Validate(); err != nil { return err }
	payload, err := encode(inventory)
	if err != nil { return err }
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_component_inventories (installation_id, generation, source_digest, inventory_json, observed_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(installation_id) DO UPDATE SET generation = excluded.generation, source_digest = excluded.source_digest, inventory_json = excluded.inventory_json, observed_at = excluded.observed_at WHERE app_component_inventories.generation < excluded.generation`, inventory.InstallationID, inventory.Generation, inventory.SourceDigest, payload, inventory.ObservedAt)
	return err
}

func (repository SQLRepository) LoadInventory(ctx context.Context, id InstallationID) (ComponentInventory, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT inventory_json FROM app_component_inventories WHERE installation_id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return ComponentInventory{}, ErrNotFound }
	if err != nil { return ComponentInventory{}, err }
	var inventory ComponentInventory
	if err := decode(payload, &inventory); err != nil { return ComponentInventory{}, err }
	return inventory, inventory.Validate()
}

func (repository SQLRepository) SaveUpdatePolicy(ctx context.Context, policy UpdatePolicy, expectedGeneration uint64) error {
	if err := policy.Validate(); err != nil { return err }
	payload, err := encode(policy)
	if err != nil { return err }
	if expectedGeneration == 0 {
		_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_update_policies (id, installation_id, generation, policy_json) VALUES (?, ?, ?, ?)`, policy.ID, policy.InstallationID, policy.Generation, payload)
		return err
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_update_policies SET generation = ?, policy_json = ? WHERE installation_id = ? AND generation = ?`, policy.Generation, payload, policy.InstallationID, expectedGeneration)
	if err != nil { return err }
	return requireGeneration(result)
}

func (repository SQLRepository) LoadUpdatePolicy(ctx context.Context, id InstallationID) (UpdatePolicy, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT policy_json FROM app_update_policies WHERE installation_id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return UpdatePolicy{}, ErrNotFound }
	if err != nil { return UpdatePolicy{}, err }
	var policy UpdatePolicy
	if err := decode(payload, &policy); err != nil { return UpdatePolicy{}, err }
	return policy, policy.Validate()
}

func (repository SQLRepository) SaveRelease(ctx context.Context, release Release) error {
	if err := requireID("release", string(release.ID)); err != nil { return err }
	if err := requireID("installation", string(release.InstallationID)); err != nil { return err }
	if !validDigest(release.ContentDigest) || !validDigest(release.RecipeDigest) || release.CreatedAt.IsZero() { return ErrInvalid }
	payload, err := encode(release)
	if err != nil { return err }
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_releases (id, installation_id, content_digest, release_json, created_at) VALUES (?, ?, ?, ?, ?)`, release.ID, release.InstallationID, release.ContentDigest, payload, release.CreatedAt)
	return err
}

func (repository SQLRepository) LoadRelease(ctx context.Context, id ReleaseID) (Release, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT release_json FROM app_releases WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return Release{}, ErrNotFound }
	if err != nil { return Release{}, err }
	var release Release
	if err := decode(payload, &release); err != nil { return Release{}, err }
	return release, nil
}

func (repository SQLRepository) SaveApplicationBackupProfile(ctx context.Context, profile ApplicationBackupProfile, expectedGeneration uint64) error {
	if err := profile.Validate(); err != nil { return err }
	payload, err := encode(profile)
	if err != nil { return err }
	if expectedGeneration == 0 {
		_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_backup_profiles (id, installation_id, generation, profile_json) VALUES (?, ?, ?, ?)`, profile.ID, profile.InstallationID, profile.Generation, payload)
		return err
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_backup_profiles SET generation = ?, profile_json = ? WHERE id = ? AND generation = ?`, profile.Generation, payload, profile.ID, expectedGeneration)
	if err != nil { return err }
	return requireGeneration(result)
}

func (repository SQLRepository) LoadApplicationBackupProfile(ctx context.Context, id ApplicationBackupProfileID) (ApplicationBackupProfile, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT profile_json FROM app_backup_profiles WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return ApplicationBackupProfile{}, ErrNotFound }
	if err != nil { return ApplicationBackupProfile{}, err }
	var profile ApplicationBackupProfile
	if err := decode(payload, &profile); err != nil { return ApplicationBackupProfile{}, err }
	return profile, profile.Validate()
}

func (repository SQLRepository) SaveApplicationRecoveryPoint(ctx context.Context, point ApplicationRecoveryPoint) error {
	if err := requireID("recovery point", string(point.ID)); err != nil { return err }
	if err := requireID("installation", string(point.InstallationID)); err != nil { return err }
	if err := requireID("backup profile", string(point.ProfileID)); err != nil { return err }
	if !validDigest(point.ManifestDigest) || !point.Verified || point.CreatedAt.IsZero() || point.CommittedAt.IsZero() { return ErrInvalid }
	payload, err := encode(point)
	if err != nil { return err }
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_recovery_points (id, installation_id, profile_id, manifest_digest, verified, point_json, committed_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, point.ID, point.InstallationID, point.ProfileID, point.ManifestDigest, point.Verified, payload, point.CommittedAt)
	return err
}

func (repository SQLRepository) LoadApplicationRecoveryPoint(ctx context.Context, id RecoveryPointID) (ApplicationRecoveryPoint, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT point_json FROM app_recovery_points WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return ApplicationRecoveryPoint{}, ErrNotFound }
	if err != nil { return ApplicationRecoveryPoint{}, err }
	var point ApplicationRecoveryPoint
	if err := decode(payload, &point); err != nil { return ApplicationRecoveryPoint{}, err }
	return point, nil
}

func (repository SQLRepository) CreateDeployment(ctx context.Context, deployment Deployment) error {
	payload, err := encode(deployment)
	if err != nil { return err }
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_deployments (id, command_id, installation_id, state, deployment_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, deployment.ID, deployment.CommandID, deployment.InstallationID, deployment.State, payload, deployment.UpdatedAt)
	return err
}

func (repository SQLRepository) UpdateDeployment(ctx context.Context, deployment Deployment) error {
	payload, err := encode(deployment)
	if err != nil { return err }
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_deployments SET state = ?, deployment_json = ?, updated_at = ? WHERE id = ?`, deployment.State, payload, deployment.UpdatedAt, deployment.ID)
	if err != nil { return err }
	return requireOne(result)
}

func (repository SQLRepository) LoadDeployment(ctx context.Context, id DeploymentID) (Deployment, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT deployment_json FROM app_deployments WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return Deployment{}, ErrNotFound }
	if err != nil { return Deployment{}, err }
	var deployment Deployment
	if err := decode(payload, &deployment); err != nil { return Deployment{}, err }
	return deployment, nil
}

func (repository SQLRepository) SaveWordPressSettings(ctx context.Context, id InstallationID, settings WordPressSettings, expectedGeneration uint64) error {
	if err := settings.Validate(); err != nil { return err }
	payload, err := encode(settings)
	if err != nil { return err }
	if expectedGeneration == 0 {
		_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_wordpress_settings (installation_id, generation, settings_json) VALUES (?, ?, ?)`, id, settings.Generation, payload)
		return err
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_wordpress_settings SET generation = ?, settings_json = ? WHERE installation_id = ? AND generation = ?`, settings.Generation, payload, id, expectedGeneration)
	if err != nil { return err }
	return requireGeneration(result)
}

func (repository SQLRepository) LoadWordPressSettings(ctx context.Context, id InstallationID) (WordPressSettings, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT settings_json FROM app_wordpress_settings WHERE installation_id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return WordPressSettings{}, ErrNotFound }
	if err != nil { return WordPressSettings{}, err }
	var settings WordPressSettings
	if err := decode(payload, &settings); err != nil { return WordPressSettings{}, err }
	return settings, settings.Validate()
}

func (repository SQLRepository) SaveLSCachePolicy(ctx context.Context, policy LSCachePolicy, expectedGeneration uint64) error {
	if err := policy.Validate(); err != nil { return err }
	payload, err := encode(policy)
	if err != nil { return err }
	if expectedGeneration == 0 {
		_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_lscache_policies (installation_id, generation, policy_json) VALUES (?, ?, ?)`, policy.InstallationID, policy.Generation, payload)
		return err
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_lscache_policies SET generation = ?, policy_json = ? WHERE installation_id = ? AND generation = ?`, policy.Generation, payload, policy.InstallationID, expectedGeneration)
	if err != nil { return err }
	return requireGeneration(result)
}

func (repository SQLRepository) LoadLSCachePolicy(ctx context.Context, id InstallationID) (LSCachePolicy, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT policy_json FROM app_lscache_policies WHERE installation_id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return LSCachePolicy{}, ErrNotFound }
	if err != nil { return LSCachePolicy{}, err }
	var policy LSCachePolicy
	if err := decode(payload, &policy); err != nil { return LSCachePolicy{}, err }
	return policy, policy.Validate()
}

func (repository SQLRepository) SaveAccessProtection(ctx context.Context, binding AccessProtectionBinding, expectedGeneration uint64) error {
	if err := binding.Validate(); err != nil { return err }
	payload, err := encode(binding)
	if err != nil { return err }
	if expectedGeneration == 0 {
		_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_access_protections (installation_id, policy_id, generation, binding_json) VALUES (?, ?, ?, ?)`, binding.InstallationID, binding.PolicyID, binding.Generation, payload)
		return err
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_access_protections SET policy_id = ?, generation = ?, binding_json = ? WHERE installation_id = ? AND generation = ?`, binding.PolicyID, binding.Generation, payload, binding.InstallationID, expectedGeneration)
	if err != nil { return err }
	return requireGeneration(result)
}

func (repository SQLRepository) LoadAccessProtection(ctx context.Context, installationID InstallationID) (AccessProtectionBinding, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT binding_json FROM app_access_protections WHERE installation_id = ?`, installationID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return AccessProtectionBinding{}, ErrNotFound }
	if err != nil { return AccessProtectionBinding{}, err }
	var binding AccessProtectionBinding
	if err := decode(payload, &binding); err != nil { return AccessProtectionBinding{}, err }
	return binding, binding.Validate()
}

func (repository SQLRepository) CreateStagingRelation(ctx context.Context, relation StagingRelation) error {
	if err := relation.Validate(); err != nil { return err }
	payload, err := encode(relation)
	if err != nil { return err }
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_staging_relations (id, source_installation_id, target_installation_id, generation, relation_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`, relation.ID, relation.SourceInstallationID, relation.TargetInstallationID, relation.Generation, payload, relation.CreatedAt)
	return err
}

func (repository SQLRepository) LoadStagingRelation(ctx context.Context, id StagingRelationID) (StagingRelation, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT relation_json FROM app_staging_relations WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return StagingRelation{}, ErrNotFound }
	if err != nil { return StagingRelation{}, err }
	var relation StagingRelation
	return relation, decode(payload, &relation)
}

func (repository SQLRepository) DeleteStagingRelation(ctx context.Context, id StagingRelationID, generation uint64) error {
	result, err := repository.DB.ExecContext(ctx, `DELETE FROM app_staging_relations WHERE id = ? AND generation = ?`, id, generation)
	if err != nil { return err }
	return requireGeneration(result)
}

func (repository SQLRepository) CreateStagingSync(ctx context.Context, sync StagingSync) error {
	if err := sync.Validate(); err != nil { return err }
	payload, err := encode(sync)
	if err != nil { return err }
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_staging_syncs (id, command_id, relation_id, state, sync_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, sync.ID, sync.CommandID, sync.RelationID, sync.State, payload, sync.UpdatedAt)
	return err
}

func (repository SQLRepository) UpdateStagingSync(ctx context.Context, sync StagingSync) error {
	if err := sync.Validate(); err != nil { return err }
	payload, err := encode(sync)
	if err != nil { return err }
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_staging_syncs SET state = ?, sync_json = ?, updated_at = ? WHERE id = ?`, sync.State, payload, sync.UpdatedAt, sync.ID)
	if err != nil { return err }
	return requireOne(result)
}

func (repository SQLRepository) LoadStagingSync(ctx context.Context, id SyncID) (StagingSync, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT sync_json FROM app_staging_syncs WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return StagingSync{}, ErrNotFound }
	if err != nil { return StagingSync{}, err }
	var sync StagingSync
	return sync, decode(payload, &sync)
}

func (repository SQLRepository) CreateLoginGrant(ctx context.Context, grant LoginGrant) error {
	if err := grant.Validate(); err != nil { return err }
	payload, err := encode(grant)
	if err != nil { return err }
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_login_grants (id, tenant_id, site_id, installation_id, token_hash, state, generation, expires_at, grant_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, grant.ID, grant.TenantID, grant.SiteID, grant.InstallationID, grant.TokenHash, grant.State, grant.Generation, grant.ExpiresAt, payload)
	return err
}

func (repository SQLRepository) LoadLoginGrant(ctx context.Context, id LoginGrantID) (LoginGrant, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT grant_json FROM app_login_grants WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return LoginGrant{}, ErrNotFound }
	if err != nil { return LoginGrant{}, err }
	var grant LoginGrant
	if err := decode(payload, &grant); err != nil { return LoginGrant{}, err }
	return grant, grant.Validate()
}

func (repository SQLRepository) ConsumeLoginGrant(ctx context.Context, id LoginGrantID, generation uint64, now time.Time) (LoginGrant, error) {
	grant, err := repository.LoadLoginGrant(ctx, id)
	if err != nil { return LoginGrant{}, err }
	if grant.State != LoginGrantIssued || grant.Generation != generation { return LoginGrant{}, ErrGrantConsumed }
	if !now.Before(grant.ExpiresAt) { return LoginGrant{}, ErrGrantExpired }
	grant.State, grant.ConsumedAt, grant.Generation = LoginGrantConsumed, now.UTC(), grant.Generation+1
	payload, err := encode(grant)
	if err != nil { return LoginGrant{}, err }
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_login_grants SET state = ?, generation = ?, grant_json = ? WHERE id = ? AND state = ? AND generation = ? AND expires_at > ?`, grant.State, grant.Generation, payload, id, LoginGrantIssued, generation, now)
	if err != nil { return LoginGrant{}, err }
	if err := requireGeneration(result); err != nil { return LoginGrant{}, ErrGrantConsumed }
	return grant, nil
}

func (repository SQLRepository) RevokeLoginGrant(ctx context.Context, id LoginGrantID, now time.Time) error {
	grant, err := repository.LoadLoginGrant(ctx, id)
	if err != nil { return err }
	if grant.State != LoginGrantIssued { return nil }
	grant.State, grant.RevokedAt, grant.Generation = LoginGrantRevoked, now.UTC(), grant.Generation+1
	payload, err := encode(grant)
	if err != nil { return err }
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_login_grants SET state = ?, generation = ?, grant_json = ? WHERE id = ? AND state = ?`, grant.State, grant.Generation, payload, id, LoginGrantIssued)
	if err != nil { return err }
	return requireGeneration(result)
}

func (repository SQLRepository) CreateScan(ctx context.Context, run ScanRun) error {
	if err := run.Validate(); err != nil { return err }
	payload, err := encode(run)
	if err != nil { return err }
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_scan_runs (id, command_id, installation_id, state, run_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, run.ID, run.CommandID, run.InstallationID, run.State, payload, run.UpdatedAt)
	return err
}

func (repository SQLRepository) SaveScanPolicy(ctx context.Context, policy ScanPolicy, expectedGeneration uint64) error {
	if err := policy.Validate(); err != nil { return err }
	payload, err := encode(policy)
	if err != nil { return err }
	if expectedGeneration == 0 {
		_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_scan_policies (installation_id, provider_id, generation, policy_json) VALUES (?, ?, ?, ?)`, policy.InstallationID, policy.ProviderID, policy.Generation, payload)
		return err
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_scan_policies SET provider_id = ?, generation = ?, policy_json = ? WHERE installation_id = ? AND generation = ?`, policy.ProviderID, policy.Generation, payload, policy.InstallationID, expectedGeneration)
	if err != nil { return err }
	return requireGeneration(result)
}

func (repository SQLRepository) LoadScanPolicy(ctx context.Context, installationID InstallationID) (ScanPolicy, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT policy_json FROM app_scan_policies WHERE installation_id = ?`, installationID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return ScanPolicy{}, ErrNotFound }
	if err != nil { return ScanPolicy{}, err }
	var policy ScanPolicy
	if err := decode(payload, &policy); err != nil { return ScanPolicy{}, err }
	return policy, policy.Validate()
}

func (repository SQLRepository) UpdateScan(ctx context.Context, run ScanRun) error {
	if err := run.Validate(); err != nil { return err }
	payload, err := encode(run)
	if err != nil { return err }
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_scan_runs SET state = ?, run_json = ?, updated_at = ? WHERE id = ?`, run.State, payload, run.UpdatedAt, run.ID)
	if err != nil { return err }
	return requireOne(result)
}

func (repository SQLRepository) LoadScan(ctx context.Context, id ScanRunID) (ScanRun, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT run_json FROM app_scan_runs WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return ScanRun{}, ErrNotFound }
	if err != nil { return ScanRun{}, err }
	var run ScanRun
	if err := decode(payload, &run); err != nil { return ScanRun{}, err }
	return run, run.Validate()
}

func (repository SQLRepository) SaveFindings(ctx context.Context, runID ScanRunID, findings []Finding) error {
	tx, err := repository.DB.BeginTx(ctx, nil)
	if err != nil { return err }
	defer tx.Rollback()
	for _, finding := range findings {
		if finding.ScanRunID != runID { return ErrConflict }
		var priorPayload []byte
		if loadErr:=tx.QueryRowContext(ctx,`SELECT finding_json FROM app_findings WHERE id=?`,finding.ID).Scan(&priorPayload);loadErr==nil{var prior Finding;if decode(priorPayload,&prior)!=nil{return ErrIntegrity};finding.FirstSeenAt=prior.FirstSeenAt;finding.Generation=prior.Generation+1;if prior.State==FindingAccepted&&(prior.SuppressedUntil.IsZero()||prior.SuppressedUntil.After(finding.LastSeenAt)){finding.State=FindingAccepted;finding.SuppressedBy=prior.SuppressedBy;finding.SuppressionReason=prior.SuppressionReason;finding.SuppressedUntil=prior.SuppressedUntil}}else if !errors.Is(loadErr,sql.ErrNoRows){return loadErr}
		if err := finding.Validate(); err != nil { return err }
		payload, err := encode(finding)
		if err != nil { return err }
		_, err = tx.ExecContext(ctx, `INSERT INTO app_findings (id, scan_run_id, installation_id, state, severity, path, content_digest, finding_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET scan_run_id = excluded.scan_run_id, state = excluded.state, severity = excluded.severity, path = excluded.path, content_digest = excluded.content_digest, finding_json = excluded.finding_json, updated_at = excluded.updated_at`, finding.ID, finding.ScanRunID, finding.InstallationID, finding.State, finding.Severity, finding.Path.String(), finding.ContentDigest, payload, finding.LastSeenAt)
		if err != nil { return err }
	}
	return tx.Commit()
}

func (repository SQLRepository) ListFindings(ctx context.Context, installationID InstallationID, state FindingState, limit uint16, cursor string) ([]Finding, string, error) {
	if limit == 0 { limit = 100 }
	if limit > 500 || len(cursor) > 128 { return nil, "", ErrInvalid }
	rows, err := repository.DB.QueryContext(ctx, `SELECT finding_json FROM app_findings WHERE installation_id = ? AND (? = '' OR state = ?) AND id > ? ORDER BY id LIMIT ?`, installationID, state, state, cursor, limit+1)
	if err != nil { return nil, "", err }
	defer rows.Close()
	items := make([]Finding, 0, limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil { return nil, "", err }
		var finding Finding
		if err := decode(payload, &finding); err != nil { return nil, "", err }
		items = append(items, finding)
	}
	if err := rows.Err(); err != nil { return nil, "", err }
	next := ""
	if len(items) > int(limit) { next = string(items[limit-1].ID); items = items[:limit] }
	return items, next, nil
}

func (repository SQLRepository) ListScopedFindings(ctx context.Context, tenantID TenantID, installationID InstallationID, state FindingState, limit uint16, cursor string) ([]Finding, string, error) {
	if tenantID != "" { if err := requireID("tenant", string(tenantID)); err != nil { return nil, "", err } }
	if installationID != "" { if err := requireID("installation", string(installationID)); err != nil { return nil, "", err } }
	if limit == 0 { limit = 100 }
	if limit > 500 || len(cursor) > 128 { return nil, "", ErrInvalid }
	rows, err := repository.DB.QueryContext(ctx, `SELECT f.finding_json FROM app_findings f JOIN app_installations i ON i.id=f.installation_id WHERE (?='' OR i.tenant_id=?) AND (?='' OR f.installation_id=?) AND (?='' OR f.state=?) AND f.id>? ORDER BY f.id LIMIT ?`, tenantID, tenantID, installationID, installationID, state, state, cursor, limit+1)
	if err != nil { return nil, "", err }
	defer rows.Close()
	items := make([]Finding, 0, limit)
	for rows.Next() { var payload []byte; if err := rows.Scan(&payload); err != nil { return nil, "", err }; var finding Finding; if err := decode(payload, &finding); err != nil { return nil, "", err }; items=append(items,finding) }
	if err := rows.Err(); err != nil { return nil, "", err }
	next := ""; if len(items)>int(limit) { next=string(items[limit-1].ID); items=items[:limit] }
	return items,next,nil
}

func (repository SQLRepository) LoadFinding(ctx context.Context, id FindingID) (Finding, error) {
	if err:=requireID("finding",string(id));err!=nil{return Finding{},err};var payload []byte
	err:=repository.DB.QueryRowContext(ctx,`SELECT finding_json FROM app_findings WHERE id=?`,id).Scan(&payload)
	if errors.Is(err,sql.ErrNoRows){return Finding{},ErrNotFound};if err!=nil{return Finding{},err};var finding Finding;if err=decode(payload,&finding);err!=nil{return Finding{},err};return finding,finding.Validate()
}

func (repository SQLRepository) UpdateFinding(ctx context.Context, finding Finding, expectedGeneration uint64) error {
	if err:=finding.Validate();err!=nil{return err};if finding.Generation!=expectedGeneration+1{return ErrStaleGeneration};payload,err:=encode(finding);if err!=nil{return err}
	var priorPayload []byte;if err=repository.DB.QueryRowContext(ctx,`SELECT finding_json FROM app_findings WHERE id=?`,finding.ID).Scan(&priorPayload);errors.Is(err,sql.ErrNoRows){return ErrNotFound}else if err!=nil{return err};var prior Finding;if decode(priorPayload,&prior)!=nil{return ErrIntegrity};if prior.Generation!=expectedGeneration{return ErrStaleGeneration}
	result,err:=repository.DB.ExecContext(ctx,`UPDATE app_findings SET state=?,severity=?,path=?,content_digest=?,finding_json=?,updated_at=? WHERE id=? AND finding_json=?`,finding.State,finding.Severity,finding.Path.String(),finding.ContentDigest,payload,finding.LastSeenAt,finding.ID,priorPayload)
	if err!=nil{return err};return requireGeneration(result)
}

func (repository SQLRepository) CreateRemediation(ctx context.Context, plan RemediationPlan) error {
	if err := plan.Validate(); err != nil { return err }
	payload, err := encode(plan)
	if err != nil { return err }
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO app_remediations (id, command_id, installation_id, state, generation, remediation_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, plan.ID, plan.CommandID, plan.InstallationID, plan.State, plan.Generation, payload, plan.UpdatedAt)
	return err
}

func (repository SQLRepository) UpdateRemediation(ctx context.Context, plan RemediationPlan) error {
	if err := plan.Validate(); err != nil { return err }
	payload, err := encode(plan)
	if err != nil { return err }
	result, err := repository.DB.ExecContext(ctx, `UPDATE app_remediations SET state = ?, generation = ?, remediation_json = ?, updated_at = ? WHERE id = ? AND generation = ?`, plan.State, plan.Generation, payload, plan.UpdatedAt, plan.ID, plan.Generation-1)
	if err != nil { return err }
	return requireGeneration(result)
}

func (repository SQLRepository) LoadRemediation(ctx context.Context, id RemediationPlanID) (RemediationPlan, error) {
	var payload []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT remediation_json FROM app_remediations WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) { return RemediationPlan{}, ErrNotFound }
	if err != nil { return RemediationPlan{}, err }
	var plan RemediationPlan
	if err := decode(payload, &plan); err != nil { return RemediationPlan{}, err }
	return plan, plan.Validate()
}

func requireOne(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil { return err }
	if count != 1 { return ErrNotFound }
	return nil
}

func requireGeneration(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil { return err }
	if count != 1 { return ErrStaleGeneration }
	return nil
}
