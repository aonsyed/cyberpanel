// Package catalog provides the durable single-writer catalog used to compose
// all site projections into one node-wide web-engine generation.
package catalog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/controller"
)

var (
	ErrNotConfigured = errors.New("web-engine node is not configured")
	ErrChangeBusy    = errors.New("another web-engine change is pending")
	ErrChangeMissing = errors.New("web-engine change does not exist")
	ErrChangeClosed  = errors.New("web-engine change is already closed")
)

const Schema = `
CREATE TABLE IF NOT EXISTS webengine_node_config (
 singleton_id INTEGER PRIMARY KEY,
 revision BIGINT NOT NULL,
 snapshot_generation BIGINT NOT NULL,
 config_json TEXT NOT NULL,
 applied_digest TEXT NOT NULL,
 updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS webengine_node_changes (
 change_token TEXT PRIMARY KEY,
 effect_id TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL,
 expected_revision BIGINT NOT NULL,
 plan_json TEXT NOT NULL,
 proposed_config_json TEXT NOT NULL,
 activation_digest TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,
 completed_at TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS webengine_one_pending_node_change
 ON webengine_node_changes(status) WHERE status = 'pending';
CREATE TABLE IF NOT EXISTS webengine_site_inputs (
 tenant_id TEXT NOT NULL,
 site_id TEXT NOT NULL,
 projection_generation BIGINT NOT NULL,
 projection_digest TEXT NOT NULL,
 effect_id TEXT NOT NULL,
 input_json TEXT NOT NULL,
 PRIMARY KEY (tenant_id, site_id)
);
CREATE TABLE IF NOT EXISTS webengine_changes (
 change_token TEXT PRIMARY KEY,
 effect_id TEXT NOT NULL UNIQUE,
 tenant_id TEXT NOT NULL,
 site_id TEXT NOT NULL,
 status TEXT NOT NULL,
 plan_json TEXT NOT NULL,
 proposed_input_json TEXT NOT NULL,
 withdraw INTEGER NOT NULL,
 activation_digest TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,
 completed_at TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS webengine_one_pending_change
 ON webengine_changes(status) WHERE status = 'pending';
CREATE TABLE IF NOT EXISTS webengine_proxy_routes (
 route_ref TEXT PRIMARY KEY,
 generation BIGINT NOT NULL,
 input_json TEXT NOT NULL,
 updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS webengine_proxy_changes (
 change_token TEXT PRIMARY KEY,
 effect_id TEXT NOT NULL UNIQUE,
 route_ref TEXT NOT NULL,
 status TEXT NOT NULL,
 plan_json TEXT NOT NULL,
 proposed_json TEXT NOT NULL,
 withdraw INTEGER NOT NULL,
 activation_digest TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,
 completed_at TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS webengine_one_pending_proxy_change ON webengine_proxy_changes(status) WHERE status='pending';
CREATE TABLE IF NOT EXISTS webengine_tenant_workload_routes_v1 (
 reservation_id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 site_id TEXT NOT NULL,
 domain_id TEXT NOT NULL,
 hostname TEXT NOT NULL,
 listener_ref TEXT NOT NULL,
 workload_id TEXT NOT NULL,
 recipe_digest TEXT NOT NULL,
 image_digest TEXT NOT NULL,
 generation BIGINT NOT NULL,
 target_endpoint TEXT NOT NULL,
 activation_authority_digest TEXT NOT NULL,
 site_projection_generation BIGINT NOT NULL,
 site_projection_digest TEXT NOT NULL,
 site_configuration_generation BIGINT NOT NULL,
 site_configuration_digest TEXT NOT NULL,
 reservation_digest TEXT NOT NULL UNIQUE,
 route_ref TEXT NOT NULL UNIQUE,
 activation_effect_id TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL,
 activation_generation BIGINT NOT NULL,
 candidate_digest TEXT NOT NULL,
 observation_digest TEXT NOT NULL,
 receipt_json TEXT NOT NULL,
 activated_at TIMESTAMP,
 created_at TIMESTAMP NOT NULL,
 updated_at TIMESTAMP NOT NULL,
 discarded_at TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS webengine_one_live_tenant_workload_route_v1
 ON webengine_tenant_workload_routes_v1(hostname,listener_ref) WHERE state<>'discarded';
CREATE TABLE IF NOT EXISTS webengine_access_policies (
 policy_ref TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 site_id TEXT NOT NULL,
 hostname TEXT NOT NULL,
 generation BIGINT NOT NULL,
 input_json TEXT NOT NULL,
 updated_at TIMESTAMP NOT NULL,
 UNIQUE (tenant_id, site_id, hostname, policy_ref)
);
CREATE TABLE IF NOT EXISTS webengine_access_changes (
 change_token TEXT PRIMARY KEY,
 effect_id TEXT NOT NULL UNIQUE,
 policy_ref TEXT NOT NULL,
 status TEXT NOT NULL,
 plan_json TEXT NOT NULL,
 proposed_json TEXT NOT NULL,
 withdraw INTEGER NOT NULL,
 activation_digest TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,
 completed_at TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS webengine_one_pending_access_change ON webengine_access_changes(status) WHERE status='pending';
`

type NodeConfiguration struct {
	Revision   uint64              `json:"revision"`
	Engine     composer.NodeEngine `json:"engine"`
	DefaultTLS *composer.TLSInput  `json:"default_tls,omitempty"`
}

// SiteInputResolver prepares the host-owned runtime identity, roots, PHP pool,
// and certificate references for one accepted site projection. Implementations
// must be idempotent by EffectID.
type SiteInputResolver interface {
	Resolve(context.Context, service.SiteEffectRequest) (composer.SiteInput, error)
}

type SQLCatalog struct {
	db       *sql.DB
	resolver SiteInputResolver
	clock    func() time.Time
}

func New(db *sql.DB, resolver SiteInputResolver) (*SQLCatalog, error) {
	if db == nil || resolver == nil {
		return nil, errors.New("database and site input resolver are required")
	}
	return &SQLCatalog{db: db, resolver: resolver, clock: time.Now}, nil
}

func (catalog *SQLCatalog) Bootstrap(ctx context.Context) error {
	if catalog == nil || catalog.db == nil {
		return errors.New("web-engine catalog is required")
	}
	_, err := catalog.db.ExecContext(ctx, Schema)
	return err
}

func (catalog *SQLCatalog) Configure(ctx context.Context, configuration NodeConfiguration, expectedRevision uint64) error {
	if catalog == nil || catalog.db == nil || configuration.Revision != expectedRevision+1 || len(configuration.Engine.Listeners) == 0 {
		return errors.New("invalid node configuration")
	}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		return err
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current uint64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM webengine_node_config WHERE singleton_id = 1`).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		current = 0
	} else if err != nil {
		return err
	}
	if current != expectedRevision {
		return errors.New("stale node configuration revision")
	}
	if current == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO webengine_node_config
 (singleton_id, revision, snapshot_generation, config_json, applied_digest, updated_at)
 VALUES (1, ?, 0, ?, '', ?)`, configuration.Revision, encoded, catalog.clock().UTC())
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE webengine_node_config
 SET revision = ?, config_json = ?, updated_at = ? WHERE singleton_id = 1 AND revision = ?`,
			configuration.Revision, encoded, catalog.clock().UTC(), expectedRevision)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// EnsureConfigured creates the initial node listener model and applies only
// closed, code-defined configuration migrations. It never merges caller text
// or rewrites operator-owned listeners heuristically.
func (catalog *SQLCatalog) EnsureConfigured(ctx context.Context, configuration NodeConfiguration) error {
	if catalog == nil || catalog.db == nil || configuration.Revision == 0 || len(configuration.Engine.Listeners) == 0 {
		return errors.New("invalid initial node configuration")
	}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		return err
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revision uint64
	var stored []byte
	err = tx.QueryRowContext(ctx, `SELECT revision,config_json FROM webengine_node_config WHERE singleton_id=1`).Scan(&revision, &stored)
	if err == nil {
		var current NodeConfiguration
		if json.Unmarshal(stored, &current) != nil || current.Revision != revision {
			return errors.New("invalid stored node configuration")
		}
		currentEncoded, _ := json.Marshal(current)
		if revision == configuration.Revision && string(currentEncoded) == string(encoded) || compatibleRuntimeNodeConfiguration(current, configuration) {
			return tx.Commit()
		}
		// A privileged edition conversion can durably switch the host before
		// the control process finalizes its prepared node change. On restart,
		// the edition marker therefore names the prepared edition while the
		// current row still names the source edition. Admit only that exact,
		// already-journaled transition here; Runtime.Inspect will reconcile the
		// broker receipt and either finalize or reject it before serving work.
		if compatiblePendingEditionConfiguration(ctx, tx, current, configuration) {
			return tx.Commit()
		}
		if !closedNodeConfigurationUpgrade(current, configuration) {
			return errors.New("initial node configuration conflicts with stored state")
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE webengine_node_config SET revision=?,config_json=?,updated_at=? WHERE singleton_id=1 AND revision=?`,
			configuration.Revision, encoded, catalog.clock().UTC(), revision)
		if updateErr != nil {
			return updateErr
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if changed != 1 {
			return errors.New("stale node configuration revision")
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webengine_node_config(singleton_id,revision,snapshot_generation,config_json,applied_digest,updated_at) VALUES(1,?,0,?,'',?)`,
		configuration.Revision, encoded, catalog.clock().UTC())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func compatiblePendingEditionConfiguration(ctx context.Context, tx *sql.Tx, current, baseline NodeConfiguration) bool {
	if ctx == nil || tx == nil || current.Revision == 0 || current.Engine.Edition == baseline.Engine.Edition {
		return false
	}
	var expectedRevision uint64
	var proposal []byte
	if err := tx.QueryRowContext(ctx, `SELECT expected_revision,proposed_config_json FROM webengine_node_changes WHERE status='pending' LIMIT 1`).Scan(&expectedRevision, &proposal); err != nil || expectedRevision != current.Revision {
		return false
	}
	var prepared NodeConfiguration
	if json.Unmarshal(proposal, &prepared) != nil || prepared.Revision != current.Revision+1 ||
		prepared.Engine.Edition == current.Engine.Edition || prepared.Engine.Edition != baseline.Engine.Edition ||
		prepared.Engine.Tuning.Generation != current.Engine.Tuning.Generation+1 {
		return false
	}
	return compatibleRuntimeNodeConfiguration(prepared, baseline)
}

func closedNodeConfigurationUpgrade(current, target NodeConfiguration) bool {
	if current.Engine.Edition != target.Engine.Edition || current.Revision == 0 || current.Revision >= target.Revision {
		return false
	}
	upgraded := current
	if upgraded.Revision == 1 {
		upgraded.Revision = 2
		upgraded.Engine.PreviewProxyPort = target.Engine.PreviewProxyPort
		if upgraded.DefaultTLS == nil {
			if target.DefaultTLS == nil || target.DefaultTLS.PolicyRef != "tls/preview-default" || target.DefaultTLS.MaterialKey != "preview-default" || target.DefaultTLS.Generation != 1 || target.DefaultTLS.OwnerScope != (service.CommandScope{}) {
				return false
			}
			upgraded.DefaultTLS = target.DefaultTLS
		}
		for _, desired := range target.Engine.Listeners {
			found := false
			for _, existing := range upgraded.Engine.Listeners {
				if existing.Ref == desired.Ref {
					found = true
					break
				}
			}
			if !found {
				upgraded.Engine.Listeners = append(upgraded.Engine.Listeners, desired)
			}
		}
	}
	if upgraded.Revision == 2 && target.Revision == 3 && upgraded.Engine.Tuning == (webengine.WebEngineTuning{}) {
		upgraded.Engine.Tuning = target.Engine.Tuning
		upgraded.Revision = 3
	}
	left, leftErr := json.Marshal(upgraded)
	right, rightErr := json.Marshal(target)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func compatibleRuntimeNodeConfiguration(current, baseline NodeConfiguration) bool {
	if current.Revision < baseline.Revision || current.Engine.Tuning.Generation == 0 || current.Engine.Edition != baseline.Engine.Edition {
		return false
	}
	normalized := current
	normalized.Revision = baseline.Revision
	normalized.Engine.Tuning = baseline.Engine.Tuning
	left, leftErr := json.Marshal(normalized)
	right, rightErr := json.Marshal(baseline)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func (catalog *SQLCatalog) Prepare(ctx context.Context, request service.SiteEffectRequest) (controller.PreparedPlan, error) {
	if catalog == nil || catalog.db == nil || catalog.resolver == nil {
		return controller.PreparedPlan{}, errors.New("web-engine catalog is required")
	}
	input, err := catalog.resolver.Resolve(ctx, request)
	if err != nil {
		return controller.PreparedPlan{}, fmt.Errorf("resolve site runtime: %w", err)
	}
	if input.Scope != request.Scope {
		return controller.PreparedPlan{}, errors.New("site runtime resolver returned the wrong scope")
	}
	input.Projection = request.Projection
	input.Withdraw = request.Withdraw

	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return controller.PreparedPlan{}, err
	}
	defer tx.Rollback()
	if existing, found, err := loadExistingChange(ctx, tx, request.EffectID); err != nil {
		return controller.PreparedPlan{}, err
	} else if found {
		if existing.status == "rejected" {
			return controller.PreparedPlan{}, ErrChangeClosed
		}
		return controller.PreparedPlan{Token: existing.token, Plan: existing.plan}, tx.Commit()
	}
	var pendingEffect string
	err = tx.QueryRowContext(ctx, `SELECT effect_id FROM webengine_changes WHERE status = 'pending' UNION ALL SELECT effect_id FROM webengine_proxy_changes WHERE status = 'pending' UNION ALL SELECT effect_id FROM webengine_access_changes WHERE status = 'pending' UNION ALL SELECT effect_id FROM webengine_node_changes WHERE status = 'pending' LIMIT 1`).Scan(&pendingEffect)
	if err == nil {
		return controller.PreparedPlan{}, fmt.Errorf("%w: %s", ErrChangeBusy, pendingEffect)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return controller.PreparedPlan{}, err
	}

	if err := guardTenantWorkloadSiteTx(ctx, tx, input); err != nil {
		return controller.PreparedPlan{}, err
	}
	if err := preserveOwnedSiteTLS(ctx, tx, &input); err != nil {
		return controller.PreparedPlan{}, err
	}
	configuration, snapshotGeneration, err := loadConfiguration(ctx, tx)
	if err != nil {
		return controller.PreparedPlan{}, err
	}
	sites, err := loadSiteInputs(ctx, tx, request.Scope, input)
	if err != nil {
		return controller.PreparedPlan{}, err
	}
	proxyRoutes, err := loadProxyRoutes(ctx, tx, composer.ProxyRouteInput{}, true)
	if err != nil {
		return controller.PreparedPlan{}, err
	}
	accessPolicies, err := loadAccessPoliciesForSitePlan(ctx, tx, request.Scope, input, request.Withdraw)
	if err != nil {
		return controller.PreparedPlan{}, err
	}
	plan := composer.Plan{
		Engine:             configuration.Engine,
		SnapshotGeneration: snapshotGeneration + 1,
		Sites:              sites,
		DefaultTLS:         configuration.DefaultTLS,
		ProxyRoutes:        proxyRoutes,
		AccessPolicies:     accessPolicies,
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return controller.PreparedPlan{}, err
	}
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return controller.PreparedPlan{}, err
	}
	token, err := controller.NewChangeToken(changeToken(request.EffectID))
	if err != nil {
		return controller.PreparedPlan{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webengine_changes
 (change_token, effect_id, tenant_id, site_id, status, plan_json, proposed_input_json, withdraw, activation_digest, created_at)
 VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, '', ?)`, token.String(), request.EffectID,
		request.Scope.TenantID.String(), request.Scope.SiteID.String(), planJSON, inputJSON, boolInt(request.Withdraw), catalog.clock().UTC())
	if err != nil {
		return controller.PreparedPlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return controller.PreparedPlan{}, err
	}
	return controller.PreparedPlan{Token: token, Plan: plan}, nil
}

func (catalog *SQLCatalog) Finalize(ctx context.Context, token controller.ChangeToken, activationDigest string) error {
	if catalog == nil || catalog.db == nil || token.String() == "" || !validDigest(activationDigest) {
		return errors.New("invalid finalization")
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	change, err := loadChangeForUpdate(ctx, tx, token)
	if err != nil {
		return err
	}
	if change.status == "finalized" {
		if change.activationDigest != activationDigest {
			return ErrChangeClosed
		}
		return tx.Commit()
	}
	if change.status != "pending" {
		return ErrChangeClosed
	}
	var plan composer.Plan
	if err := json.Unmarshal(change.planJSON, &plan); err != nil {
		return err
	}
	if change.withdraw {
		_, err = tx.ExecContext(ctx, `DELETE FROM webengine_site_inputs WHERE tenant_id = ? AND site_id = ?`, change.tenantID, change.siteID)
		if err == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM webengine_access_policies WHERE tenant_id = ? AND site_id = ?`, change.tenantID, change.siteID)
		}
	} else {
		var input composer.SiteInput
		if err := json.Unmarshal(change.inputJSON, &input); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO webengine_site_inputs
 (tenant_id, site_id, projection_generation, projection_digest, effect_id, input_json)
 VALUES (?, ?, ?, ?, ?, ?)
 ON CONFLICT (tenant_id, site_id) DO UPDATE SET projection_generation = excluded.projection_generation,
 projection_digest = excluded.projection_digest, effect_id = excluded.effect_id, input_json = excluded.input_json`,
			change.tenantID, change.siteID, input.Projection.Generation, projectionDigestFromInput(input), change.effectID, change.inputJSON)
		if err == nil {
			err = pruneAccessPoliciesForSite(ctx, tx, input)
		}
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE webengine_node_config SET snapshot_generation = ?, applied_digest = ?, updated_at = ? WHERE singleton_id = 1`,
		plan.SnapshotGeneration, activationDigest, catalog.clock().UTC())
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE webengine_changes SET status = 'finalized', activation_digest = ?, completed_at = ? WHERE change_token = ? AND status = 'pending'`,
		activationDigest, catalog.clock().UTC(), token.String())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (catalog *SQLCatalog) Reject(ctx context.Context, token controller.ChangeToken, effectID string) error {
	if catalog == nil || catalog.db == nil || token.String() == "" || effectID == "" {
		return errors.New("invalid rejection")
	}
	result, err := catalog.db.ExecContext(ctx, `UPDATE webengine_changes SET status = 'rejected', completed_at = ?
 WHERE change_token = ? AND effect_id = ? AND status = 'pending'`, catalog.clock().UTC(), token.String(), effectID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return ErrChangeClosed
	}
	return nil
}

type storedChange struct {
	token            controller.ChangeToken
	effectID         string
	tenantID         string
	siteID           string
	status           string
	plan             composer.Plan
	planJSON         []byte
	inputJSON        []byte
	withdraw         bool
	activationDigest string
}

func loadExistingChange(ctx context.Context, tx *sql.Tx, effectID string) (storedChange, bool, error) {
	var rawToken, status string
	var planJSON []byte
	err := tx.QueryRowContext(ctx, `SELECT change_token, status, plan_json FROM webengine_changes WHERE effect_id = ?`, effectID).Scan(&rawToken, &status, &planJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return storedChange{}, false, nil
	}
	if err != nil {
		return storedChange{}, false, err
	}
	token, err := controller.NewChangeToken(rawToken)
	if err != nil {
		return storedChange{}, false, err
	}
	var plan composer.Plan
	if err := json.Unmarshal(planJSON, &plan); err != nil {
		return storedChange{}, false, err
	}
	return storedChange{token: token, status: status, plan: plan}, true, nil
}

func loadChangeForUpdate(ctx context.Context, tx *sql.Tx, token controller.ChangeToken) (storedChange, error) {
	var change storedChange
	var withdraw int
	err := tx.QueryRowContext(ctx, `SELECT effect_id, tenant_id, site_id, status, plan_json, proposed_input_json, withdraw, activation_digest
 FROM webengine_changes WHERE change_token = ?`, token.String()).Scan(&change.effectID, &change.tenantID, &change.siteID,
		&change.status, &change.planJSON, &change.inputJSON, &withdraw, &change.activationDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return storedChange{}, ErrChangeMissing
	}
	change.token = token
	change.withdraw = withdraw != 0
	return change, err
}

func loadConfiguration(ctx context.Context, tx *sql.Tx) (NodeConfiguration, uint64, error) {
	var raw []byte
	var generation uint64
	err := tx.QueryRowContext(ctx, `SELECT config_json, snapshot_generation FROM webengine_node_config WHERE singleton_id = 1`).Scan(&raw, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeConfiguration{}, 0, ErrNotConfigured
	}
	if err != nil {
		return NodeConfiguration{}, 0, err
	}
	var configuration NodeConfiguration
	if err := json.Unmarshal(raw, &configuration); err != nil {
		return NodeConfiguration{}, 0, err
	}
	return configuration, generation, nil
}

func loadSiteInputs(ctx context.Context, tx *sql.Tx, replacementScope service.CommandScope, replacement composer.SiteInput) ([]composer.SiteInput, error) {
	rows, err := tx.QueryContext(ctx, `SELECT tenant_id, site_id, input_json FROM webengine_site_inputs ORDER BY tenant_id, site_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sites := make([]composer.SiteInput, 0)
	replaced := false
	for rows.Next() {
		var tenantID, siteID string
		var raw []byte
		if err := rows.Scan(&tenantID, &siteID, &raw); err != nil {
			return nil, err
		}
		if tenantID == replacementScope.TenantID.String() && siteID == replacementScope.SiteID.String() {
			sites = append(sites, replacement)
			replaced = true
			continue
		}
		var input composer.SiteInput
		if err := json.Unmarshal(raw, &input); err != nil {
			return nil, err
		}
		sites = append(sites, input)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !replaced {
		sites = append(sites, replacement)
	}
	return sites, nil
}

func changeToken(effectID string) string {
	digest := sha256.Sum256([]byte("cyberpanel:webengine-change:v1\x00" + effectID))
	return "chg-" + hex.EncodeToString(digest[:])
}

func projectionDigestFromInput(input composer.SiteInput) string {
	digest := sha256.Sum256(mustJSON(input.Projection))
	return hex.EncodeToString(digest[:])
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func validDigest(value string) bool {
	return len(value) == 64 && len([]byte(value)) == 64 && trimHex(value) == ""
}

func trimHex(value string) string {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return string(character)
		}
	}
	return ""
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

var _ controller.PlanCatalog = (*SQLCatalog)(nil)
