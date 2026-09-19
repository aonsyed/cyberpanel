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

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
)

// NodeState is the durable node-wide desired-state checkpoint. It contains no
// native configuration text or privileged filesystem path.
type NodeState struct {
	Configuration      NodeConfiguration
	SnapshotGeneration uint64
	AppliedDigest      string
	UpdatedAt          time.Time
}

// PreparedNodeConfiguration is an immutable node-wide candidate recorded
// before rendering or activation begins.
type PreparedNodeConfiguration struct {
	Token            string
	EffectID         string
	ExpectedRevision uint64
	Configuration    NodeConfiguration
	Plan             composer.Plan
	Finalized        bool
	ActivationDigest string
}

func (catalog *SQLCatalog) NodeConfigurationChange(ctx context.Context, effectID string) (PreparedNodeConfiguration, error) {
	if catalog == nil || catalog.db == nil || effectID == "" {
		return PreparedNodeConfiguration{}, errors.New("invalid node configuration change lookup")
	}
	var prepared PreparedNodeConfiguration
	var status string
	var planRaw, proposal []byte
	err := catalog.db.QueryRowContext(ctx, `SELECT change_token,status,expected_revision,plan_json,proposed_config_json,activation_digest FROM webengine_node_changes WHERE effect_id=?`, effectID).Scan(
		&prepared.Token, &status, &prepared.ExpectedRevision, &planRaw, &proposal, &prepared.ActivationDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return PreparedNodeConfiguration{}, ErrChangeMissing
	}
	if err != nil {
		return PreparedNodeConfiguration{}, err
	}
	if (status != "pending" && status != "finalized") || json.Unmarshal(planRaw, &prepared.Plan) != nil || json.Unmarshal(proposal, &prepared.Configuration) != nil {
		return PreparedNodeConfiguration{}, ErrChangeClosed
	}
	prepared.EffectID = effectID
	prepared.Finalized = status == "finalized"
	return prepared, nil
}

func (catalog *SQLCatalog) NodeState(ctx context.Context) (NodeState, error) {
	if catalog == nil || catalog.db == nil {
		return NodeState{}, ErrNotConfigured
	}
	var state NodeState
	var raw []byte
	err := catalog.db.QueryRowContext(ctx, `SELECT config_json,snapshot_generation,applied_digest,updated_at FROM webengine_node_config WHERE singleton_id=1`).Scan(
		&raw, &state.SnapshotGeneration, &state.AppliedDigest, &state.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeState{}, ErrNotConfigured
	}
	if err != nil {
		return NodeState{}, err
	}
	if err = json.Unmarshal(raw, &state.Configuration); err != nil || state.Configuration.Revision == 0 ||
		(state.SnapshotGeneration == 0 && state.AppliedDigest != "") || (state.SnapshotGeneration != 0 && !validDigest(state.AppliedDigest)) {
		return NodeState{}, errors.New("invalid stored node configuration")
	}
	return state, nil
}

// PlanForEdition returns one complete canonical plan without changing the
// durable edition. The requested generation must be the next immutable
// snapshot, preventing callers from selecting or reusing a generation.
func (catalog *SQLCatalog) PlanForEdition(ctx context.Context, edition webengine.Edition, snapshotGeneration uint64) (composer.Plan, error) {
	if catalog == nil || catalog.db == nil ||
		edition != webengine.EditionOpenLiteSpeed && edition != webengine.EditionLiteSpeedEnterprise || snapshotGeneration == 0 {
		return composer.Plan{}, errors.New("invalid web-engine target plan")
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return composer.Plan{}, err
	}
	defer tx.Rollback()
	configuration, currentGeneration, err := loadConfiguration(ctx, tx)
	if err != nil {
		return composer.Plan{}, err
	}
	if snapshotGeneration != currentGeneration+1 {
		return composer.Plan{}, ErrChangeClosed
	}
	if configuration.Engine.Edition != edition { configuration.Engine.Tuning.Generation++ }
	configuration.Engine.Edition = edition
	plan, err := loadCompletePlan(ctx, tx, configuration, snapshotGeneration)
	if err != nil {
		return composer.Plan{}, err
	}
	if err = tx.Commit(); err != nil {
		return composer.Plan{}, err
	}
	return plan, nil
}

func (catalog *SQLCatalog) PrepareNodeConfiguration(ctx context.Context, effectID string, configuration NodeConfiguration, expectedRevision uint64) (PreparedNodeConfiguration, error) {
	return catalog.prepareNodeConfiguration(ctx, effectID, configuration, expectedRevision, false)
}

// PrepareEditionConfiguration shares the existing durable node-change journal,
// but explicitly admits an edition transition. Ordinary tuning cannot do so.
func (catalog *SQLCatalog) PrepareEditionConfiguration(ctx context.Context, effectID string, configuration NodeConfiguration, expectedRevision uint64) (PreparedNodeConfiguration, error) {
	return catalog.prepareNodeConfiguration(ctx, effectID, configuration, expectedRevision, true)
}

func (catalog *SQLCatalog) CurrentPlan(ctx context.Context) (composer.Plan, error) {
	if catalog == nil || catalog.db == nil { return composer.Plan{}, ErrChangeClosed }
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil { return composer.Plan{}, err }
	defer tx.Rollback()
	configuration, snapshot, err := loadConfiguration(ctx, tx)
	if err != nil || snapshot == 0 { return composer.Plan{}, ErrChangeClosed }
	plan, err := loadCompletePlan(ctx, tx, configuration, snapshot)
	if err != nil { return composer.Plan{}, err }
	return plan, tx.Commit()
}

func (catalog *SQLCatalog) prepareNodeConfiguration(ctx context.Context, effectID string, configuration NodeConfiguration, expectedRevision uint64, editionChange bool) (PreparedNodeConfiguration, error) {
	if catalog == nil || catalog.db == nil || len(effectID) < 8 || len(effectID) > 255 || expectedRevision == 0 ||
		configuration.Revision != expectedRevision+1 || configuration.Engine.Tuning.Generation == 0 || len(configuration.Engine.Listeners) == 0 {
		return PreparedNodeConfiguration{}, errors.New("invalid node configuration change")
	}
	proposal, err := json.Marshal(configuration)
	if err != nil {
		return PreparedNodeConfiguration{}, err
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return PreparedNodeConfiguration{}, err
	}
	defer tx.Rollback()
	var prepared PreparedNodeConfiguration
	var status string
	var planRaw, storedProposal []byte
	err = tx.QueryRowContext(ctx, `SELECT change_token,status,expected_revision,plan_json,proposed_config_json,activation_digest FROM webengine_node_changes WHERE effect_id=?`, effectID).Scan(
		&prepared.Token, &status, &prepared.ExpectedRevision, &planRaw, &storedProposal, &prepared.ActivationDigest)
	if err == nil {
		if prepared.ExpectedRevision != expectedRevision || string(storedProposal) != string(proposal) || (status != "pending" && status != "finalized") ||
			json.Unmarshal(planRaw, &prepared.Plan) != nil || json.Unmarshal(storedProposal, &prepared.Configuration) != nil {
			return PreparedNodeConfiguration{}, ErrChangeClosed
		}
		prepared.EffectID = effectID
		prepared.Finalized = status == "finalized"
		return prepared, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PreparedNodeConfiguration{}, err
	}
	var pending string
	if scanErr := tx.QueryRowContext(ctx, `SELECT effect_id FROM webengine_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_proxy_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_access_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_node_changes WHERE status='pending' LIMIT 1`).Scan(&pending); scanErr == nil {
		return PreparedNodeConfiguration{}, fmt.Errorf("%w: %s", ErrChangeBusy, pending)
	} else if !errors.Is(scanErr, sql.ErrNoRows) {
		return PreparedNodeConfiguration{}, scanErr
	}
	current, snapshotGeneration, err := loadConfiguration(ctx, tx)
	if err != nil {
		return PreparedNodeConfiguration{}, err
	}
	if current.Revision != expectedRevision || (current.Engine.Edition != configuration.Engine.Edition) != editionChange ||
		configuration.Engine.Edition != webengine.EditionOpenLiteSpeed && configuration.Engine.Edition != webengine.EditionLiteSpeedEnterprise ||
		configuration.Engine.Tuning.Generation != current.Engine.Tuning.Generation+1 {
		return PreparedNodeConfiguration{}, ErrChangeClosed
	}
	plan, err := loadCompletePlan(ctx, tx, configuration, snapshotGeneration+1)
	if err != nil {
		return PreparedNodeConfiguration{}, err
	}
	planRaw, err = json.Marshal(plan)
	if err != nil {
		return PreparedNodeConfiguration{}, err
	}
	sum := sha256.Sum256([]byte("cyberpanel:webengine-node-change:v1\x00" + effectID + "\x00" + string(proposal)))
	prepared = PreparedNodeConfiguration{
		Token: "node-" + hex.EncodeToString(sum[:24]), EffectID: effectID, ExpectedRevision: expectedRevision,
		Configuration: configuration, Plan: plan,
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webengine_node_changes(change_token,effect_id,status,expected_revision,plan_json,proposed_config_json,activation_digest,created_at) VALUES(?,?,'pending',?,?,?,'',?)`,
		prepared.Token, effectID, expectedRevision, planRaw, proposal, catalog.clock().UTC())
	if err != nil {
		return PreparedNodeConfiguration{}, err
	}
	if err = tx.Commit(); err != nil {
		return PreparedNodeConfiguration{}, err
	}
	return prepared, nil
}

func (catalog *SQLCatalog) FinalizeNodeConfiguration(ctx context.Context, prepared PreparedNodeConfiguration, activationDigest string) error {
	if catalog == nil || catalog.db == nil || prepared.Token == "" || prepared.EffectID == "" || !validDigest(activationDigest) {
		return errors.New("invalid node configuration finalization")
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status, existingDigest string
	var expectedRevision uint64
	var planRaw, proposal []byte
	err = tx.QueryRowContext(ctx, `SELECT status,expected_revision,plan_json,proposed_config_json,activation_digest FROM webengine_node_changes WHERE change_token=? AND effect_id=?`,
		prepared.Token, prepared.EffectID).Scan(&status, &expectedRevision, &planRaw, &proposal, &existingDigest)
	if err != nil {
		return err
	}
	if status == "finalized" {
		if existingDigest != activationDigest {
			return ErrChangeClosed
		}
		return tx.Commit()
	}
	if status != "pending" || expectedRevision != prepared.ExpectedRevision {
		return ErrChangeClosed
	}
	var configuration NodeConfiguration
	var plan composer.Plan
	if json.Unmarshal(proposal, &configuration) != nil || json.Unmarshal(planRaw, &plan) != nil ||
		configuration.Revision != expectedRevision+1 || plan.Engine.Tuning.Generation != configuration.Engine.Tuning.Generation {
		return errors.New("invalid stored node configuration proposal")
	}
	result, err := tx.ExecContext(ctx, `UPDATE webengine_node_config SET revision=?,snapshot_generation=?,config_json=?,applied_digest=?,updated_at=? WHERE singleton_id=1 AND revision=?`,
		configuration.Revision, plan.SnapshotGeneration, proposal, activationDigest, catalog.clock().UTC(), expectedRevision)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrChangeClosed
	}
	result, err = tx.ExecContext(ctx, `UPDATE webengine_node_changes SET status='finalized',activation_digest=?,completed_at=? WHERE change_token=? AND status='pending'`,
		activationDigest, catalog.clock().UTC(), prepared.Token)
	if err != nil {
		return err
	}
	changed, err = result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrChangeClosed
	}
	return tx.Commit()
}

func (catalog *SQLCatalog) RejectNodeConfiguration(ctx context.Context, prepared PreparedNodeConfiguration) error {
	if catalog == nil || catalog.db == nil || prepared.Token == "" || prepared.EffectID == "" {
		return errors.New("invalid node configuration rejection")
	}
	result, err := catalog.db.ExecContext(ctx, `UPDATE webengine_node_changes SET status='rejected',completed_at=? WHERE change_token=? AND effect_id=? AND status='pending'`,
		catalog.clock().UTC(), prepared.Token, prepared.EffectID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 1 {
		return nil
	}
	var status string
	if err = catalog.db.QueryRowContext(ctx, `SELECT status FROM webengine_node_changes WHERE change_token=? AND effect_id=?`, prepared.Token, prepared.EffectID).Scan(&status); err != nil {
		return err
	}
	if status == "rejected" {
		return nil
	}
	return ErrChangeClosed
}

func loadCompletePlan(ctx context.Context, tx *sql.Tx, configuration NodeConfiguration, snapshotGeneration uint64) (composer.Plan, error) {
	sites, err := loadAllSiteInputsForProxy(ctx, tx, nil)
	if err != nil {
		return composer.Plan{}, err
	}
	routes, err := loadProxyRoutes(ctx, tx, composer.ProxyRouteInput{}, true)
	if err != nil {
		return composer.Plan{}, err
	}
	policies, err := loadAccessPolicies(ctx, tx, "", true)
	if err != nil {
		return composer.Plan{}, err
	}
	return composer.Plan{
		Engine: configuration.Engine, SnapshotGeneration: snapshotGeneration, Sites: sites,
		DefaultTLS: configuration.DefaultTLS, ProxyRoutes: routes, AccessPolicies: policies,
	}, nil
}
