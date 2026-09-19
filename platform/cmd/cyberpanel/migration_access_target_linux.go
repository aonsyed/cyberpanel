//go:build linux

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const migrationAccessSchema = `
CREATE TABLE IF NOT EXISTS panel_migration_access_principals(
 migration_id TEXT NOT NULL,target_id TEXT NOT NULL,input_digest TEXT NOT NULL,
 desired_json BLOB NOT NULL,state TEXT NOT NULL,attempt INTEGER NOT NULL,evidence_json BLOB NOT NULL,
 PRIMARY KEY(migration_id,target_id),UNIQUE(migration_id,input_digest));
CREATE TABLE IF NOT EXISTS panel_migration_access_activations(
 migration_id TEXT PRIMARY KEY,effect_id TEXT NOT NULL,plan_digest TEXT NOT NULL,fence_digest TEXT NOT NULL,
 desired_json BLOB NOT NULL,state TEXT NOT NULL,attempt INTEGER NOT NULL,evidence_json BLOB NOT NULL);`

type migrationAccessTarget struct {
	host     *migrationHostTarget
	executor access.MigrationPrincipalExecutor
}

func newMigrationAccessTarget(ctx context.Context, host *migrationHostTarget, executor access.MigrationPrincipalExecutor) (*migrationAccessTarget, error) {
	if ctx == nil || host == nil || executor == nil {
		return nil, migration.ErrBlocked
	}
	if _, err := host.db.ExecContext(ctx, migrationAccessSchema); err != nil {
		return nil, err
	}
	return &migrationAccessTarget{host: host, executor: executor}, nil
}

func migrationAccessTargetHome(source string) (access.RelativePath, error) {
	// The canonical target names the imported document root "public". Only the
	// source site root and paths beneath its admitted public_html tree exist in
	// the target generation; accepting another legacy path would expose an
	// unrelated or absent directory.
	switch {
	case source == "":
		return access.ParseRelativePath("")
	case source == "public_html":
		return access.ParseRelativePath("public")
	case strings.HasPrefix(source, "public_html/"):
		return access.ParseRelativePath("public/" + strings.TrimPrefix(source, "public_html/"))
	default:
		return access.RelativePath{}, migration.ErrBlocked
	}
}

func (target *migrationSecretTarget) accessAudience(ctx context.Context, manifest migration.Manifest, plan migration.Plan, scope migration.RuntimeScope, envelope migration.SecretEnvelope) (secrets.ID, secrets.Purpose, secrets.AudienceBinding, error) {
	if ctx == nil || envelope.Purpose != "access-credential" {
		return "", "", secrets.AudienceBinding{}, migration.ErrBlocked
	}
	if err := ctx.Err(); err != nil {
		return "", "", secrets.AudienceBinding{}, err
	}
	var principal migration.AccessPrincipal
	var mapped migration.ID
	for _, candidate := range manifest.AccessPrincipals {
		if candidate.Credential == nil || candidate.Credential.SecretID != envelope.SecretID {
			continue
		}
		if principal.SourceID != "" || candidate.Kind != migration.AccessPrincipalFTPS || candidate.Credential.Format != migration.AccessCredentialUnixCryptHash {
			return "", "", secrets.AudienceBinding{}, migration.ErrConflict
		}
		principal = candidate
	}
	if principal.SourceID == "" {
		return "", "", secrets.AudienceBinding{}, migration.ErrBlocked
	}
	for _, mapping := range plan.Mappings {
		if mapping.SourceKind != string(migration.ImportCredential) || mapping.SourceID != principal.SourceID {
			continue
		}
		if mapped != "" || mapping.Disposition != migration.DispositionCreate || !mapping.TargetID.Valid() {
			return "", "", secrets.AudienceBinding{}, migration.ErrConflict
		}
		mapped = mapping.TargetID
	}
	if mapped == "" {
		return "", "", secrets.AudienceBinding{}, migration.ErrBlocked
	}
	release, err := webEngineExecutableDigest("/usr/local/libexec/cyberpanel/panel-execd")
	if err != nil {
		return "", "", secrets.AudienceBinding{}, err
	}
	return access.AccessTenantOwnerID(scope.TenantID), secrets.PurposeAuthentication, secrets.AudienceBinding{
		AdapterID:             access.LinuxAccessSecretAdapterID,
		AdapterVersion:        access.LinuxAccessSecretAdapterVersion,
		Account:               principal.Username,
		Origin:                "local://panel-execd/access",
		ResourceKind:          "migration_access_unix_hash",
		ResourceID:            access.AccessSecretAudienceID(principal.PrincipalID.String()),
		ResourceGeneration:    1,
		Operations:            []secrets.Operation{secrets.OperationAuthenticate},
		ConsumerReleaseDigest: release,
	}, nil
}

func (target *migrationAccessTarget) desired(ctx context.Context, intent migration.ImportIntent) (access.MigrationPrincipal, error) {
	var desired access.MigrationPrincipal
	if target == nil || migration.ValidateCanonicalImportIntent(intent) != nil || intent.Kind != migration.ImportCredential || len(intent.Chunks) != 0 {
		return desired, migration.ErrInvalid
	}
	var source migration.AccessPrincipal
	if migrationAuxiliaryDecode(intent.Payload, &source) != nil || source.SourceID != intent.SourceID || source.TargetID != "" {
		return desired, migration.ErrInvalid
	}
	value, err := target.host.repository.Migration(ctx, intent.MigrationID)
	if err != nil {
		return desired, err
	}
	plan, err := target.host.repository.Plan(ctx, value.PlanDigest)
	if err != nil {
		return desired, err
	}
	manifest, err := target.host.repository.Manifest(ctx, value.ManifestRoot)
	if err != nil {
		return desired, err
	}
	matchedPrincipal := false
	for _, candidate := range manifest.AccessPrincipals {
		if candidate.SourceID != source.SourceID {
			continue
		}
		if matchedPrincipal || migrationHostDigest(candidate) != migrationHostDigest(source) {
			return desired, migration.ErrConflict
		}
		matchedPrincipal = true
	}
	if !matchedPrincipal {
		return desired, migration.ErrConflict
	}
	scope, err := target.host.scopes.LoadByMigration(ctx, intent.MigrationID)
	if err != nil {
		return desired, err
	}
	var siteSource migration.Site
	for _, candidate := range manifest.Sites {
		if candidate.SourceID == source.SiteID {
			if siteSource.SourceID != "" {
				return desired, migration.ErrConflict
			}
			siteSource = candidate
		}
	}
	if siteSource.SourceID == "" || siteSource.TenantID != source.TenantID {
		return desired, migration.ErrConflict
	}
	var siteTarget migration.ID
	for _, mapping := range plan.Mappings {
		if mapping.SourceKind != string(migration.ImportSite) || mapping.SourceID != source.SiteID {
			continue
		}
		if siteTarget != "" || mapping.Disposition != migration.DispositionCreate || !mapping.TargetID.Valid() {
			return desired, migration.ErrConflict
		}
		siteTarget = mapping.TargetID
	}
	if siteTarget == "" {
		return desired, migration.ErrBlocked
	}
	home, err := migrationAccessTargetHome(source.HomeRelative)
	if err != nil {
		return desired, err
	}
	desired = access.MigrationPrincipal{
		EffectID:    intent.EffectID,
		MigrationID: intent.MigrationID.String(),
		PrincipalID: access.PrincipalID(source.PrincipalID.String()),
		TenantID:    access.TenantID(scope.TenantID),
		SiteID:      access.SiteID(siteTarget.String()),
		Kind:        access.MigrationPrincipalKind(source.Kind),
		Policy:      access.MigrationAccessPolicy(source.Policy),
		Username:    source.Username,
		Home:        home,
		UID:         source.UID,
		GID:         source.GID,
		Enabled:     source.Enabled,
	}
	for _, sourceKey := range source.AuthorizedKeys {
		key, parseErr := access.ParsePublicKey(sourceKey.PublicKey)
		if parseErr != nil || string(key.Algorithm) != sourceKey.Algorithm || key.Fingerprint != sourceKey.Fingerprint {
			return desired, migration.ErrInvalid
		}
		desired.AuthorizedKeys = append(desired.AuthorizedKeys, access.MigrationAuthorizedKey{
			ID:        access.SSHKeyID(sourceKey.KeyID.String()),
			Name:      sourceKey.Label,
			PublicKey: key,
		})
	}
	if source.Credential != nil {
		desired.Credential = &access.MigrationCredentialReference{
			Reference: source.Credential.SecretID,
			Format:    access.MigrationCredentialFormat(source.Credential.Format),
		}
	}
	if err = desired.Validate(); err != nil {
		return desired, err
	}
	return desired, nil
}

func migrationAccessEffect(intent migration.ImportIntent, observation access.MigrationAccessObservation) migration.ImportEffect {
	effect := migration.ImportEffect{EffectID: intent.EffectID, InputDigest: intent.InputDigest, AppliedAt: observation.ObservedAt, ErrorCode: observation.ErrorCode}
	switch observation.Status {
	case access.MigrationAccessApplied:
		effect.Status = migration.ImportEffectApplied
		effect.OutputDigest = observation.EvidenceDigest
		effect.EvidenceDigest = observation.EvidenceDigest
		effect.TargetGeneration = 1
		effect.ObjectsWritten = 1
	case access.MigrationAccessCompensated:
		effect.Status = migration.ImportEffectCompensated
		effect.EvidenceDigest = observation.EvidenceDigest
	case access.MigrationAccessTerminal:
		effect.Status = migration.ImportEffectRejected
	default:
		effect.Status = migration.ImportEffectAmbiguous
	}
	return effect
}

func (target *migrationAccessTarget) claim(ctx context.Context, intent migration.ImportIntent, desired access.MigrationPrincipal) (uint32, string, error) {
	raw, err := json.Marshal(desired)
	if err != nil {
		return 0, "", err
	}
	tx, err := target.host.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, "", err
	}
	defer tx.Rollback()
	var stored []byte
	var digest, state string
	var attempt uint32
	err = tx.QueryRowContext(ctx, `SELECT desired_json,input_digest,state,attempt FROM panel_migration_access_principals WHERE migration_id=? AND target_id=?`, intent.MigrationID.String(), intent.TargetID.String()).Scan(&stored, &digest, &state, &attempt)
	switch {
	case err == nil:
		if digest != intent.InputDigest || string(stored) != string(raw) {
			return 0, state, migration.ErrConflict
		}
		previous := attempt
		attempt++
		result, updateErr := tx.ExecContext(ctx, `UPDATE panel_migration_access_principals SET attempt=? WHERE migration_id=? AND target_id=? AND attempt=?`, attempt, intent.MigrationID.String(), intent.TargetID.String(), previous)
		if updateErr != nil {
			return 0, state, updateErr
		}
		count, countErr := result.RowsAffected()
		if countErr != nil || count != 1 {
			return 0, state, errors.Join(migration.ErrConflict, countErr)
		}
	case errors.Is(err, sql.ErrNoRows):
		attempt = 1
		_, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_access_principals(migration_id,target_id,input_digest,desired_json,state,attempt,evidence_json) VALUES(?,?,?,?,'claimed',1,'{}')`, intent.MigrationID.String(), intent.TargetID.String(), intent.InputDigest, raw)
		if err != nil {
			return 0, state, err
		}
	default:
		return 0, state, err
	}
	if err = tx.Commit(); err != nil {
		return 0, state, err
	}
	return attempt, state, nil
}

func (target *migrationAccessTarget) save(ctx context.Context, intent migration.ImportIntent, state string, observation access.MigrationAccessObservation) (migration.ImportEffect, error) {
	raw, err := json.Marshal(observation)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	result, err := target.host.db.ExecContext(ctx, `UPDATE panel_migration_access_principals SET state=?,evidence_json=? WHERE migration_id=? AND target_id=? AND input_digest=?`, state, raw, intent.MigrationID.String(), intent.TargetID.String(), intent.InputDigest)
	if err == nil {
		var count int64
		count, err = result.RowsAffected()
		if err == nil && count != 1 {
			err = migration.ErrConflict
		}
	}
	return migrationAccessEffect(intent, observation), err
}

func (target *migrationAccessTarget) Apply(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	desired, err := target.desired(ctx, intent)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	attempt, state, err := target.claim(ctx, intent, desired)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	if state == "active" || state == "compensated" || state == "terminal" {
		return target.Observe(ctx, intent)
	}
	observation, err := target.executor.StageMigrationPrincipal(ctx, desired, attempt)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	if observation.Validate(desired.EffectID) != nil {
		return migration.ImportEffect{}, migration.ErrAmbiguous
	}
	switch observation.Status {
	case access.MigrationAccessApplied:
		if observation.State != "dark" {
			return migration.ImportEffect{}, migration.ErrConflict
		}
		return target.save(ctx, intent, "dark", observation)
	case access.MigrationAccessTerminal:
		return target.save(ctx, intent, "terminal", observation)
	default:
		return target.save(ctx, intent, "ambiguous", observation)
	}
}

func (target *migrationAccessTarget) origin(ctx context.Context, intent migration.ImportIntent) (migration.ImportIntent, access.MigrationPrincipal, error) {
	origin, err := target.host.auxiliaryOrigin(ctx, intent)
	if err != nil {
		return origin, access.MigrationPrincipal{}, err
	}
	desired, err := target.desired(ctx, origin)
	return origin, desired, err
}

func (target *migrationAccessTarget) Observe(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	origin, desired, err := target.origin(ctx, intent)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	observation, err := target.executor.ObserveMigrationPrincipal(ctx, desired)
	if err != nil || observation.Validate(desired.EffectID) != nil {
		return migration.ImportEffect{}, errors.Join(migration.ErrAmbiguous, err)
	}
	state := observation.State
	if observation.Status == access.MigrationAccessTerminal {
		state = "terminal"
	}
	if observation.Status == access.MigrationAccessCompensated {
		state = "compensated"
	}
	return target.save(ctx, origin, state, observation)
}

func (target *migrationAccessTarget) proofs(ctx context.Context, entries []migration.ImportIntent, active bool) ([]string, error) {
	proofs := []string{}
	for _, intent := range entries {
		if intent.Kind != migration.ImportCredential {
			continue
		}
		effect, err := target.Observe(ctx, intent)
		if err != nil || effect.Status != migration.ImportEffectApplied || effect.EvidenceDigest == "" {
			return nil, errors.Join(migration.ErrBlocked, err)
		}
		var state string
		if err = target.host.db.QueryRowContext(ctx, `SELECT state FROM panel_migration_access_principals WHERE migration_id=? AND target_id=?`, intent.MigrationID.String(), intent.TargetID.String()).Scan(&state); err != nil {
			return nil, err
		}
		wanted := "dark"
		if active {
			wanted = "active"
		}
		if state != wanted {
			return nil, migration.ErrConflict
		}
		proofs = append(proofs, effect.EvidenceDigest)
	}
	return proofs, nil
}

func (target *migrationAccessTarget) Activate(ctx context.Context, value migration.Migration, plan migration.Plan, entries []migration.ImportIntent, publish bool) (string, error) {
	principals := []access.MigrationPrincipal{}
	for _, intent := range entries {
		if intent.Kind != migration.ImportCredential {
			continue
		}
		_, desired, err := target.origin(ctx, intent)
		if err != nil {
			return "", err
		}
		principals = append(principals, desired)
	}
	if len(principals) == 0 {
		return migrationHostDigest("no-access-principals"), nil
	}
	sort.Slice(principals, func(i, j int) bool { return principals[i].PrincipalID < principals[j].PrincipalID })
	var fence migration.SourceFence
	if err := target.host.repository.Receipt(ctx, value.ID, "source_fence", &fence); err != nil {
		return "", err
	}
	if fence.MigrationID != value.ID || fence.Generation != value.SourceGeneration || fence.Fence != value.Fence || fence.ExpiresAt.IsZero() {
		return "", migration.ErrBlocked
	}
	effectID := access.MigrationAccessEffectID("migration-access-activation-v1", value.ID.String(), plan.DryRunDigest, fence.Digest)
	batch := access.MigrationPrincipalBatch{
		EffectID: effectID, MigrationID: value.ID.String(), PlanDigest: plan.DryRunDigest,
		Fence:      access.MigrationFenceBinding{SourceGeneration: fence.Generation, Fence: fence.Fence, Digest: fence.Digest, ExpiresAt: fence.ExpiresAt},
		Principals: principals,
		Action:     access.MigrationActivationAdmit,
	}
	encoded, err := json.Marshal(batch)
	if err != nil {
		return "", err
	}
	digest := migrationHostDigest(batch)
	tx, err := target.host.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var stored, evidence []byte
	var storedEffect, storedPlan, storedFence, state string
	var attempt uint32
	err = tx.QueryRowContext(ctx, `SELECT effect_id,plan_digest,fence_digest,desired_json,state,attempt,evidence_json FROM panel_migration_access_activations WHERE migration_id=?`, value.ID.String()).Scan(&storedEffect, &storedPlan, &storedFence, &stored, &state, &attempt, &evidence)
	switch {
	case err == nil:
		var previous access.MigrationPrincipalBatch
		if storedEffect != effectID || storedPlan != plan.DryRunDigest || storedFence != fence.Digest || json.Unmarshal(stored, &previous) != nil || migrationHostDigest(previous) != digest || state != "claimed" && state != "admitted" && state != "activating" && state != "active" {
			return "", migration.ErrConflict
		}
		previousAttempt := attempt
		attempt++
		result, updateErr := tx.ExecContext(ctx, `UPDATE panel_migration_access_activations SET attempt=? WHERE migration_id=? AND attempt=?`, attempt, value.ID.String(), previousAttempt)
		if updateErr != nil {
			return "", updateErr
		}
		count, countErr := result.RowsAffected()
		if countErr != nil || count != 1 {
			return "", errors.Join(migration.ErrConflict, countErr)
		}
	case errors.Is(err, sql.ErrNoRows):
		attempt = 1
		state = "claimed"
		_, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_access_activations(migration_id,effect_id,plan_digest,fence_digest,desired_json,state,attempt,evidence_json) VALUES(?,?,?,?,?,'claimed',1,'{}')`, value.ID.String(), effectID, plan.DryRunDigest, fence.Digest, encoded)
		if err != nil {
			return "", err
		}
	default:
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	batch.Attempt = attempt
	if state == "claimed" {
		// Admission is separately durable in the privileged executor. If a
		// response was lost and the lease has since expired, observe that prior
		// admission without creating a new one.
		fenceErr := target.host.sourceFence(ctx, value)
		batch.Action = access.MigrationActivationAdmit
		if fenceErr != nil {
			batch.Action = access.MigrationActivationObserveAdmission
		}
		admission, admissionErr := target.executor.ActivateMigrationPrincipals(ctx, batch)
		if admissionErr != nil || admission.Validate(effectID) != nil {
			return "", errors.Join(migration.ErrAmbiguous, fenceErr, admissionErr)
		}
		if admission.Status != access.MigrationAccessApplied || admission.State != "admitted" {
			if admission.Status == access.MigrationAccessTerminal {
				return "", errors.Join(fenceErr, fmt.Errorf("%w: %s", migration.ErrBlocked, admission.ErrorCode))
			}
			return "", errors.Join(migration.ErrAmbiguous, fenceErr)
		}
		result, updateErr := target.host.db.ExecContext(ctx, `UPDATE panel_migration_access_activations SET state='admitted' WHERE migration_id=? AND effect_id=? AND state='claimed'`, value.ID.String(), effectID)
		if updateErr != nil {
			return "", updateErr
		}
		count, countErr := result.RowsAffected()
		if countErr != nil || count != 1 {
			return "", errors.Join(migration.ErrConflict, countErr)
		}
		state = "admitted"
	}
	if !publish {
		if state != "admitted" {
			return "", migration.ErrWriteFrontier
		}
		batch.Action = access.MigrationActivationObserveAdmission
		observation, observeErr := target.executor.ActivateMigrationPrincipals(ctx, batch)
		if observeErr != nil || observation.Validate(effectID) != nil || observation.Status != access.MigrationAccessApplied || observation.State != "admitted" {
			return "", errors.Join(migration.ErrAmbiguous, observeErr)
		}
		return observation.EvidenceDigest, nil
	}
	if state == "admitted" {
		result, updateErr := target.host.db.ExecContext(ctx, `UPDATE panel_migration_access_activations SET state='activating' WHERE migration_id=? AND effect_id=? AND state='admitted'`, value.ID.String(), effectID)
		if updateErr != nil {
			return "", updateErr
		}
		count, countErr := result.RowsAffected()
		if countErr != nil || count != 1 {
			return "", errors.Join(migration.ErrConflict, countErr)
		}
		state = "activating"
	}
	batch.Action = access.MigrationActivationCommit
	observation, err := target.executor.ActivateMigrationPrincipals(ctx, batch)
	if err != nil || observation.Validate(effectID) != nil {
		return "", errors.Join(migration.ErrAmbiguous, err)
	}
	if observation.Status != access.MigrationAccessApplied || observation.State != "active" {
		if observation.Status == access.MigrationAccessTerminal {
			return "", fmt.Errorf("%w: %s", migration.ErrBlocked, observation.ErrorCode)
		}
		return "", migration.ErrAmbiguous
	}
	if state == "active" {
		var recorded access.MigrationAccessObservation
		if json.Unmarshal(evidence, &recorded) != nil || recorded.Validate(effectID) != nil || recorded.EvidenceDigest != observation.EvidenceDigest {
			return "", migration.ErrConflict
		}
		if _, err = target.proofs(ctx, entries, true); err != nil {
			return "", err
		}
		return observation.EvidenceDigest, nil
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		return "", errors.Join(migration.ErrAmbiguous, err)
	}
	transaction, err := target.host.db.BeginTx(ctx, nil)
	if err != nil {
		return "", errors.Join(migration.ErrAmbiguous, err)
	}
	defer transaction.Rollback()
	for _, intent := range entries {
		if intent.Kind != migration.ImportCredential {
			continue
		}
		result, updateErr := transaction.ExecContext(ctx, `UPDATE panel_migration_access_principals SET state='active' WHERE migration_id=? AND target_id=? AND state IN ('dark','active')`, value.ID.String(), intent.TargetID.String())
		if updateErr != nil {
			return "", errors.Join(migration.ErrAmbiguous, updateErr)
		}
		count, countErr := result.RowsAffected()
		if countErr != nil || count != 1 {
			return "", errors.Join(migration.ErrAmbiguous, migration.ErrConflict, countErr)
		}
	}
	result, err := transaction.ExecContext(ctx, `UPDATE panel_migration_access_activations SET state='active',evidence_json=? WHERE migration_id=? AND effect_id=? AND state='activating'`, raw, value.ID.String(), effectID)
	if err != nil {
		return "", errors.Join(migration.ErrAmbiguous, err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return "", errors.Join(migration.ErrAmbiguous, migration.ErrConflict, err)
	}
	if err = transaction.Commit(); err != nil {
		return "", errors.Join(migration.ErrAmbiguous, err)
	}
	return observation.EvidenceDigest, nil
}

func (target *migrationAccessTarget) Compensate(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	origin, desired, err := target.origin(ctx, intent)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	attempt, state, err := target.claim(ctx, origin, desired)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	if state == "active" {
		return migration.ImportEffect{}, migration.ErrWriteFrontier
	}
	observation, err := target.executor.CompensateMigrationPrincipal(ctx, desired, attempt)
	if err != nil || observation.Validate(desired.EffectID) != nil {
		return migration.ImportEffect{}, errors.Join(migration.ErrAmbiguous, err)
	}
	if observation.Status != access.MigrationAccessCompensated {
		return migrationAccessEffect(origin, observation), migration.ErrWriteFrontier
	}
	return target.save(ctx, origin, "compensated", observation)
}
