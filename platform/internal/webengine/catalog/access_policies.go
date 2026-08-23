package catalog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
)

type PreparedAccessPolicy struct {
	Token     string
	EffectID  string
	Policy    composer.AccessPolicyInput
	Withdraw  bool
	Finalized bool
	Plan      composer.Plan
}

func (catalog *SQLCatalog) AccessPolicyChange(ctx context.Context, effectID string) (PreparedAccessPolicy, error) {
	if catalog == nil || catalog.db == nil || effectID == "" {
		return PreparedAccessPolicy{}, errors.New("invalid access policy change lookup")
	}
	var prepared PreparedAccessPolicy
	var status string
	var planRaw, proposal []byte
	err := catalog.db.QueryRowContext(ctx, `SELECT change_token,status,plan_json,proposed_json,withdraw FROM webengine_access_changes WHERE effect_id=?`, effectID).Scan(&prepared.Token, &status, &planRaw, &proposal, &prepared.Withdraw)
	if err != nil {
		return PreparedAccessPolicy{}, err
	}
	if status == "rejected" || json.Unmarshal(planRaw, &prepared.Plan) != nil || json.Unmarshal(proposal, &prepared.Policy) != nil {
		return PreparedAccessPolicy{}, ErrChangeClosed
	}
	prepared.EffectID = effectID
	prepared.Finalized = status == "finalized"
	return prepared, nil
}

func (catalog *SQLCatalog) AccessPolicy(ctx context.Context, policyRef string) (composer.AccessPolicyInput, error) {
	if catalog == nil || catalog.db == nil || policyRef == "" {
		return composer.AccessPolicyInput{}, errors.New("invalid access policy lookup")
	}
	var raw []byte
	if err := catalog.db.QueryRowContext(ctx, `SELECT input_json FROM webengine_access_policies WHERE policy_ref=?`, policyRef).Scan(&raw); err != nil {
		return composer.AccessPolicyInput{}, err
	}
	var policy composer.AccessPolicyInput
	if err := json.Unmarshal(raw, &policy); err != nil || string(policy.PolicyRef) != policyRef {
		return composer.AccessPolicyInput{}, errors.New("invalid stored access policy")
	}
	return policy, nil
}

func (catalog *SQLCatalog) PrepareAccessPolicy(ctx context.Context, effectID string, policy composer.AccessPolicyInput, withdraw bool) (PreparedAccessPolicy, error) {
	if catalog == nil || catalog.db == nil || effectID == "" || len(effectID) > 255 || policy.PolicyRef == "" || policy.Generation == 0 {
		return PreparedAccessPolicy{}, errors.New("invalid access policy change")
	}
	proposal, err := json.Marshal(policy)
	if err != nil {
		return PreparedAccessPolicy{}, err
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return PreparedAccessPolicy{}, err
	}
	defer tx.Rollback()
	var token, status string
	var planRaw, storedProposal []byte
	var storedWithdraw bool
	err = tx.QueryRowContext(ctx, `SELECT change_token,status,plan_json,proposed_json,withdraw FROM webengine_access_changes WHERE effect_id=?`, effectID).Scan(&token, &status, &planRaw, &storedProposal, &storedWithdraw)
	if err == nil {
		if string(storedProposal) != string(proposal) || storedWithdraw != withdraw || status == "rejected" {
			return PreparedAccessPolicy{}, ErrChangeClosed
		}
		var plan composer.Plan
		if json.Unmarshal(planRaw, &plan) != nil {
			return PreparedAccessPolicy{}, errors.New("invalid stored access policy plan")
		}
		return PreparedAccessPolicy{Token: token, EffectID: effectID, Policy: policy, Withdraw: withdraw, Finalized: status == "finalized", Plan: plan}, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PreparedAccessPolicy{}, err
	}
	var pending string
	if scanErr := tx.QueryRowContext(ctx, `SELECT effect_id FROM webengine_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_proxy_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_access_changes WHERE status='pending' LIMIT 1`).Scan(&pending); scanErr == nil {
		return PreparedAccessPolicy{}, fmt.Errorf("%w: %s", ErrChangeBusy, pending)
	} else if !errors.Is(scanErr, sql.ErrNoRows) {
		return PreparedAccessPolicy{}, scanErr
	}
	var existingRaw []byte
	loadErr := tx.QueryRowContext(ctx, `SELECT input_json FROM webengine_access_policies WHERE policy_ref=?`, policy.PolicyRef).Scan(&existingRaw)
	if errors.Is(loadErr, sql.ErrNoRows) {
		if withdraw || policy.Generation != 1 {
			return PreparedAccessPolicy{}, ErrChangeMissing
		}
	} else if loadErr != nil {
		return PreparedAccessPolicy{}, loadErr
	} else {
		var current composer.AccessPolicyInput
		if json.Unmarshal(existingRaw, &current) != nil || current.PolicyRef != policy.PolicyRef || current.Scope != policy.Scope || current.Hostname != policy.Hostname || policy.Generation != current.Generation+1 {
			return PreparedAccessPolicy{}, ErrChangeClosed
		}
	}
	configuration, snapshotGeneration, err := loadConfiguration(ctx, tx)
	if err != nil {
		return PreparedAccessPolicy{}, err
	}
	sites, err := loadAllSiteInputsForProxy(ctx, tx)
	if err != nil {
		return PreparedAccessPolicy{}, err
	}
	routes, err := loadProxyRoutes(ctx, tx, composer.ProxyRouteInput{}, true)
	if err != nil {
		return PreparedAccessPolicy{}, err
	}
	policies, err := loadAccessPolicies(ctx, tx, string(policy.PolicyRef), withdraw)
	if err != nil {
		return PreparedAccessPolicy{}, err
	}
	if !withdraw {
		policies = append(policies, policy)
	}
	plan := composer.Plan{Engine: configuration.Engine, SnapshotGeneration: snapshotGeneration + 1, Sites: sites, DefaultTLS: configuration.DefaultTLS, ProxyRoutes: routes, AccessPolicies: policies}
	planRaw, err = json.Marshal(plan)
	if err != nil {
		return PreparedAccessPolicy{}, err
	}
	sum := sha256.Sum256([]byte("cyberpanel:webengine-access-change:v1\x00" + effectID + "\x00" + string(proposal)))
	token = "access-" + hex.EncodeToString(sum[:24])
	_, err = tx.ExecContext(ctx, `INSERT INTO webengine_access_changes(change_token,effect_id,policy_ref,status,plan_json,proposed_json,withdraw,activation_digest,created_at) VALUES(?,?,?,'pending',?,?,?,'',?)`, token, effectID, policy.PolicyRef, planRaw, proposal, withdraw, catalog.clock().UTC())
	if err != nil {
		return PreparedAccessPolicy{}, err
	}
	if err = tx.Commit(); err != nil {
		return PreparedAccessPolicy{}, err
	}
	return PreparedAccessPolicy{Token: token, EffectID: effectID, Policy: policy, Withdraw: withdraw, Plan: plan}, nil
}

func (catalog *SQLCatalog) FinalizeAccessPolicy(ctx context.Context, prepared PreparedAccessPolicy, activationDigest string) error {
	if catalog == nil || catalog.db == nil || prepared.Token == "" || prepared.EffectID == "" || !validDigest(activationDigest) {
		return errors.New("invalid access policy finalization")
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status, existingDigest string
	var proposal []byte
	var withdraw bool
	err = tx.QueryRowContext(ctx, `SELECT status,activation_digest,proposed_json,withdraw FROM webengine_access_changes WHERE change_token=? AND effect_id=?`, prepared.Token, prepared.EffectID).Scan(&status, &existingDigest, &proposal, &withdraw)
	if err != nil {
		return err
	}
	if status == "finalized" {
		if existingDigest != activationDigest {
			return ErrChangeClosed
		}
		return tx.Commit()
	}
	if status != "pending" {
		return ErrChangeClosed
	}
	var policy composer.AccessPolicyInput
	if json.Unmarshal(proposal, &policy) != nil || policy.PolicyRef != prepared.Policy.PolicyRef {
		return errors.New("invalid access policy proposal")
	}
	if withdraw {
		_, err = tx.ExecContext(ctx, `DELETE FROM webengine_access_policies WHERE policy_ref=?`, policy.PolicyRef)
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `INSERT INTO webengine_access_policies(policy_ref,tenant_id,site_id,hostname,generation,input_json,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(policy_ref) DO UPDATE SET generation=excluded.generation,input_json=excluded.input_json,updated_at=excluded.updated_at WHERE webengine_access_policies.tenant_id=excluded.tenant_id AND webengine_access_policies.site_id=excluded.site_id AND webengine_access_policies.hostname=excluded.hostname`, policy.PolicyRef, policy.Scope.TenantID.String(), policy.Scope.SiteID.String(), policy.Hostname.String(), policy.Generation, proposal, catalog.clock().UTC())
		if err == nil {
			var changed int64
			changed, err = result.RowsAffected()
			if err == nil && changed != 1 { err = ErrChangeClosed }
		}
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE webengine_node_config SET snapshot_generation=?,applied_digest=?,updated_at=? WHERE singleton_id=1`, prepared.Plan.SnapshotGeneration, activationDigest, catalog.clock().UTC())
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE webengine_access_changes SET status='finalized',activation_digest=?,completed_at=? WHERE change_token=? AND status='pending'`, activationDigest, catalog.clock().UTC(), prepared.Token)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (catalog *SQLCatalog) RejectAccessPolicy(ctx context.Context, prepared PreparedAccessPolicy) error {
	if catalog == nil || catalog.db == nil || prepared.Token == "" || prepared.EffectID == "" {
		return errors.New("invalid access policy rejection")
	}
	result, err := catalog.db.ExecContext(ctx, `UPDATE webengine_access_changes SET status='rejected',completed_at=? WHERE change_token=? AND effect_id=? AND status='pending'`, catalog.clock().UTC(), prepared.Token, prepared.EffectID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		var status string
		if err = catalog.db.QueryRowContext(ctx, `SELECT status FROM webengine_access_changes WHERE change_token=?`, prepared.Token).Scan(&status); err != nil {
			return err
		}
		if status != "rejected" {
			return ErrChangeClosed
		}
	}
	return nil
}

func loadAccessPolicies(ctx context.Context, tx *sql.Tx, replacementRef string, withdraw bool) ([]composer.AccessPolicyInput, error) {
	rows, err := tx.QueryContext(ctx, `SELECT input_json FROM webengine_access_policies WHERE policy_ref<>? ORDER BY policy_ref`, replacementRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []composer.AccessPolicyInput{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var value composer.AccessPolicyInput
		if json.Unmarshal(raw, &value) != nil {
			return nil, errors.New("invalid stored access policy")
		}
		values = append(values, value)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	_ = withdraw
	return values, nil
}

func loadAccessPoliciesForSitePlan(ctx context.Context, tx *sql.Tx, scope service.CommandScope, proposed composer.SiteInput, withdraw bool) ([]composer.AccessPolicyInput, error) {
	rows, err := tx.QueryContext(ctx, `SELECT input_json FROM webengine_access_policies ORDER BY policy_ref`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []composer.AccessPolicyInput{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var value composer.AccessPolicyInput
		if json.Unmarshal(raw, &value) != nil {
			return nil, errors.New("invalid stored access policy")
		}
		if value.Scope == scope {
			if withdraw || !siteInputContainsHostname(proposed, value.Hostname.String()) { continue }
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func pruneAccessPoliciesForSite(ctx context.Context, tx *sql.Tx, proposed composer.SiteInput) error {
	rows, err := tx.QueryContext(ctx, `SELECT policy_ref,hostname FROM webengine_access_policies WHERE tenant_id=? AND site_id=?`, proposed.Scope.TenantID.String(), proposed.Scope.SiteID.String())
	if err != nil { return err }
	type stalePolicy struct{ ref, hostname string }
	var stale []stalePolicy
	for rows.Next() {
		var value stalePolicy
		if err = rows.Scan(&value.ref, &value.hostname); err != nil { rows.Close(); return err }
		if !siteInputContainsHostname(proposed, value.hostname) { stale = append(stale, value) }
	}
	if err = rows.Err(); err != nil { rows.Close(); return err }
	if err = rows.Close(); err != nil { return err }
	for _, value := range stale {
		if _, err = tx.ExecContext(ctx, `DELETE FROM webengine_access_policies WHERE policy_ref=? AND tenant_id=? AND site_id=? AND hostname=?`, value.ref, proposed.Scope.TenantID.String(), proposed.Scope.SiteID.String(), value.hostname); err != nil { return err }
	}
	return nil
}

func siteInputContainsHostname(input composer.SiteInput, hostname string) bool {
	for _, binding := range input.Projection.Bindings { if binding.Hostname.String() == hostname { return true } }
	return false
}
