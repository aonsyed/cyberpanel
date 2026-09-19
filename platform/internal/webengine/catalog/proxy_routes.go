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

	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
)

type PreparedProxyRoute struct{Token string;EffectID string;Route composer.ProxyRouteInput;Withdraw bool;Plan composer.Plan}

func (catalog *SQLCatalog) PrepareProxyRoute(ctx context.Context, effectID string, route composer.ProxyRouteInput, withdraw bool) (PreparedProxyRoute, error) {
	if catalog == nil || catalog.db == nil || effectID == "" || route.Ref == "" || route.Generation == 0 {
		return PreparedProxyRoute{}, errors.New("invalid proxy route change")
	}
	proposal, err := json.Marshal(route)
	if err != nil {
		return PreparedProxyRoute{}, err
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return PreparedProxyRoute{}, err
	}
	defer tx.Rollback()
	var token, status string
	var planRaw, storedProposal []byte
	var storedWithdraw bool
	err = tx.QueryRowContext(ctx, `SELECT change_token,status,plan_json,proposed_json,withdraw FROM webengine_proxy_changes WHERE effect_id=?`, effectID).Scan(&token, &status, &planRaw, &storedProposal, &storedWithdraw)
	if err == nil {
		if string(storedProposal) != string(proposal) || storedWithdraw != withdraw || status == "rejected" {
			return PreparedProxyRoute{}, ErrChangeClosed
		}
		var plan composer.Plan
		if json.Unmarshal(planRaw, &plan) != nil {
			return PreparedProxyRoute{}, errors.New("invalid stored proxy plan")
		}
		return PreparedProxyRoute{Token: token, EffectID: effectID, Route: route, Withdraw: withdraw, Plan: plan}, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PreparedProxyRoute{}, err
	}
	if err = guardTenantWorkloadRouteTx(ctx, tx, effectID, route, withdraw); err != nil {
		return PreparedProxyRoute{}, err
	}
	handoff, err := loadTenantWorkloadRouteHandoff(ctx, tx, effectID, route)
	if err != nil || withdraw && handoff != nil {
		return PreparedProxyRoute{}, errors.Join(ErrChangeClosed, err)
	}
	var pending string
	if scanErr := tx.QueryRowContext(ctx, `SELECT effect_id FROM webengine_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_proxy_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_access_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_node_changes WHERE status='pending' LIMIT 1`).Scan(&pending); scanErr == nil {
		return PreparedProxyRoute{}, fmt.Errorf("%w: %s", ErrChangeBusy, pending)
	} else if !errors.Is(scanErr, sql.ErrNoRows) {
		return PreparedProxyRoute{}, scanErr
	}
	configuration, snapshotGeneration, err := loadConfiguration(ctx, tx)
	if err != nil {
		return PreparedProxyRoute{}, err
	}
	sites, err := loadAllSiteInputsForProxy(ctx, tx, handoff)
	if err != nil {
		return PreparedProxyRoute{}, err
	}
	routes, err := loadProxyRoutes(ctx, tx, route, withdraw)
	if err != nil {
		return PreparedProxyRoute{}, err
	}
	policies, err := loadAccessPolicies(ctx, tx, "", true)
	if err != nil {
		return PreparedProxyRoute{}, err
	}
	plan := composer.Plan{Engine: configuration.Engine, SnapshotGeneration: snapshotGeneration + 1, Sites: sites, DefaultTLS: configuration.DefaultTLS, ProxyRoutes: routes, AccessPolicies: policies}
	planRaw, err = json.Marshal(plan)
	if err != nil {
		return PreparedProxyRoute{}, err
	}
	sum := sha256.Sum256([]byte("cyberpanel:webengine-proxy-change:v1\x00" + effectID + "\x00" + string(proposal)))
	token = "proxy-" + hex.EncodeToString(sum[:24])
	_, err = tx.ExecContext(ctx, `INSERT INTO webengine_proxy_changes(change_token,effect_id,route_ref,status,plan_json,proposed_json,withdraw,activation_digest,created_at) VALUES(?,?,?,'pending',?,?,?,'',?)`, token, effectID, route.Ref, planRaw, proposal, withdraw, catalog.clock().UTC())
	if err != nil {
		return PreparedProxyRoute{}, err
	}
	if err = tx.Commit(); err != nil {
		return PreparedProxyRoute{}, err
	}
	return PreparedProxyRoute{Token: token, EffectID: effectID, Route: route, Withdraw: withdraw, Plan: plan}, nil
}

func(catalog *SQLCatalog)PendingProxyRoute(ctx context.Context,effectID string,generation uint64)(PreparedProxyRoute,error){var token,status string;var planRaw,proposal []byte;var withdraw bool;err:=catalog.db.QueryRowContext(ctx,`SELECT change_token,status,plan_json,proposed_json,withdraw FROM webengine_proxy_changes WHERE effect_id=?`,effectID).Scan(&token,&status,&planRaw,&proposal,&withdraw);if err!=nil{return PreparedProxyRoute{},err};if status!="pending"{return PreparedProxyRoute{},ErrChangeClosed};var plan composer.Plan;var route composer.ProxyRouteInput;if json.Unmarshal(planRaw,&plan)!=nil||json.Unmarshal(proposal,&route)!=nil||plan.SnapshotGeneration!=generation{return PreparedProxyRoute{},errors.New("invalid pending proxy route")};return PreparedProxyRoute{Token:token,EffectID:effectID,Route:route,Withdraw:withdraw,Plan:plan},nil}

func (catalog *SQLCatalog) FinalizeProxyRoute(ctx context.Context, prepared PreparedProxyRoute, activationDigest string) error {
	if prepared.Token == "" || prepared.EffectID == "" || activationDigest == "" {
		return errors.New("invalid proxy route finalization")
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	var proposal []byte
	var withdraw bool
	err = tx.QueryRowContext(ctx, `SELECT status,proposed_json,withdraw FROM webengine_proxy_changes WHERE change_token=? AND effect_id=?`, prepared.Token, prepared.EffectID).Scan(&status, &proposal, &withdraw)
	if err != nil {
		return err
	}
	if status == "finalized" {
		return tx.Commit()
	}
	if status != "pending" {
		return ErrChangeClosed
	}
	var route composer.ProxyRouteInput
	if json.Unmarshal(proposal, &route) != nil {
		return errors.New("invalid proxy route proposal")
	}
	handoff, handoffErr := loadTenantWorkloadRouteHandoff(ctx, tx, prepared.EffectID, route)
	if handoffErr != nil || withdraw && handoff != nil {
		return errors.Join(ErrChangeClosed, handoffErr)
	}
	if handoff != nil {
		result, deleteErr := tx.ExecContext(ctx, `DELETE FROM webengine_site_inputs WHERE tenant_id=? AND site_id=? AND projection_generation=? AND projection_digest=?`, handoff.tenantID, handoff.siteID, handoff.projectionGeneration, handoff.projectionDigest)
		if deleteErr != nil {
			return deleteErr
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil || changed != 1 {
			return errors.Join(ErrChangeClosed, rowsErr)
		}
	}
	if withdraw {
		_, err = tx.ExecContext(ctx, `DELETE FROM webengine_proxy_routes WHERE route_ref=?`, route.Ref)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO webengine_proxy_routes(route_ref,generation,input_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(route_ref) DO UPDATE SET generation=excluded.generation,input_json=excluded.input_json,updated_at=excluded.updated_at`, route.Ref, route.Generation, proposal, catalog.clock().UTC())
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE webengine_node_config SET snapshot_generation=?,applied_digest=?,updated_at=? WHERE singleton_id=1`, prepared.Plan.SnapshotGeneration, activationDigest, catalog.clock().UTC())
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE webengine_proxy_changes SET status='finalized',activation_digest=?,completed_at=? WHERE change_token=? AND status='pending'`, activationDigest, catalog.clock().UTC(), prepared.Token)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func(catalog *SQLCatalog)RejectProxyRoute(ctx context.Context,prepared PreparedProxyRoute)error{result,err:=catalog.db.ExecContext(ctx,`UPDATE webengine_proxy_changes SET status='rejected',completed_at=? WHERE change_token=? AND effect_id=? AND status='pending'`,catalog.clock().UTC(),prepared.Token,prepared.EffectID);if err!=nil{return err};count,_:=result.RowsAffected();if count==0{var status string;if err=catalog.db.QueryRowContext(ctx,`SELECT status FROM webengine_proxy_changes WHERE change_token=?`,prepared.Token).Scan(&status);err!=nil{return err};if status!="rejected"{return ErrChangeClosed}};return nil}

func loadAllSiteInputsForProxy(ctx context.Context, tx *sql.Tx, handoff *tenantWorkloadRouteHandoff) ([]composer.SiteInput, error) {
	rows, err := tx.QueryContext(ctx, `SELECT tenant_id,site_id,projection_generation,projection_digest,input_json FROM webengine_site_inputs ORDER BY tenant_id,site_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []composer.SiteInput{}
	matched := handoff == nil
	for rows.Next() {
		var tenantID, siteID, digest string
		var generation uint64
		var raw []byte
		if err = rows.Scan(&tenantID, &siteID, &generation, &digest, &raw); err != nil {
			return nil, err
		}
		var value composer.SiteInput
		if json.Unmarshal(raw, &value) != nil {
			return nil, errors.New("invalid stored site input")
		}
		if handoff != nil && tenantID == handoff.tenantID && siteID == handoff.siteID {
			if matched || generation != handoff.projectionGeneration || digest != handoff.projectionDigest {
				return nil, ErrChangeClosed
			}
			matched = true
			continue
		}
		values = append(values, value)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if !matched {
		return nil, ErrChangeClosed
	}
	return values, nil
}
func loadProxyRoutes(ctx context.Context,tx *sql.Tx,replacement composer.ProxyRouteInput,withdraw bool)([]composer.ProxyRouteInput,error){rows,err:=tx.QueryContext(ctx,`SELECT input_json FROM webengine_proxy_routes WHERE route_ref<>? ORDER BY route_ref`,replacement.Ref);if err!=nil{return nil,err};defer rows.Close();values:=[]composer.ProxyRouteInput{};for rows.Next(){var raw []byte;if err=rows.Scan(&raw);err!=nil{return nil,err};var value composer.ProxyRouteInput;if json.Unmarshal(raw,&value)!=nil{return nil,errors.New("invalid stored proxy route")};values=append(values,value)};if err=rows.Err();err!=nil{return nil,err};if !withdraw{values=append(values,replacement)};return values,nil}

var _=time.Now
