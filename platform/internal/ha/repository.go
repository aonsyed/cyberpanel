package ha

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const SQLSchema = `
CREATE TABLE IF NOT EXISTS ha_node_groups (id TEXT PRIMARY KEY, generation INTEGER NOT NULL, group_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS ha_nodes (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, workload_identity TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL, node_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE INDEX IF NOT EXISTS ha_nodes_group ON ha_nodes(group_id, state, id);
CREATE UNIQUE INDEX IF NOT EXISTS ha_nodes_workload_identity ON ha_nodes(workload_identity);
CREATE TABLE IF NOT EXISTS ha_enrollment_tokens (token_id TEXT PRIMARY KEY, token_digest TEXT NOT NULL UNIQUE, node_id TEXT NOT NULL UNIQUE, command_id TEXT NOT NULL UNIQUE, consumed_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS ha_health (node_id TEXT NOT NULL, observer_node_id TEXT NOT NULL, sequence INTEGER NOT NULL, health_json BLOB NOT NULL, observed_at TIMESTAMP NOT NULL, PRIMARY KEY(node_id, observer_node_id));
CREATE TABLE IF NOT EXISTS ha_placement_groups (id TEXT PRIMARY KEY, node_group_id TEXT NOT NULL, generation INTEGER NOT NULL, placement_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS ha_replica_sets (id TEXT PRIMARY KEY, placement_group_id TEXT NOT NULL, kind TEXT NOT NULL, resource_id TEXT NOT NULL, generation INTEGER NOT NULL, replica_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS ha_replication_channels (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, kind TEXT NOT NULL, resource_id TEXT NOT NULL, source_node_id TEXT NOT NULL, target_node_id TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL, channel_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL, UNIQUE(kind, resource_id, source_node_id, target_node_id));
CREATE INDEX IF NOT EXISTS ha_channels_resource ON ha_replication_channels(kind, resource_id, state);
CREATE TABLE IF NOT EXISTS ha_checkpoints (id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, source_generation INTEGER NOT NULL, write_frontier INTEGER NOT NULL, manifest_digest TEXT NOT NULL, checkpoint_json BLOB NOT NULL, verified_at TIMESTAMP NOT NULL, UNIQUE(channel_id, source_generation, write_frontier));
CREATE INDEX IF NOT EXISTS ha_checkpoints_channel ON ha_checkpoints(channel_id, write_frontier DESC);
CREATE TABLE IF NOT EXISTS ha_replication_health (channel_id TEXT NOT NULL, sequence INTEGER NOT NULL, source_generation INTEGER NOT NULL, target_generation INTEGER NOT NULL, checkpoint_id TEXT NOT NULL, write_frontier INTEGER NOT NULL, state TEXT NOT NULL, healthy INTEGER NOT NULL, caught_up INTEGER NOT NULL, failure_digest TEXT NOT NULL, evidence_digest TEXT NOT NULL UNIQUE, health_json BLOB NOT NULL, observed_at TIMESTAMP NOT NULL, valid_until TIMESTAMP NOT NULL, PRIMARY KEY(channel_id, sequence));
CREATE INDEX IF NOT EXISTS ha_replication_health_current ON ha_replication_health(channel_id, sequence DESC);
CREATE TABLE IF NOT EXISTS ha_database_clusters (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, topology TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL, cluster_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS ha_writer_leases (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, resource_id TEXT NOT NULL, holder_node_id TEXT NOT NULL, fencing_token INTEGER NOT NULL, authority_epoch INTEGER NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL, lease_json BLOB NOT NULL, expires_at TIMESTAMP NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ha_active_writer_lease ON ha_writer_leases(resource_id) WHERE state = 'active';
CREATE TABLE IF NOT EXISTS ha_fences (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, target_node_id TEXT NOT NULL, class TEXT NOT NULL, fencing_token INTEGER NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL, fence_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS ha_traffic_policies (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, provider_mode TEXT NOT NULL, generation INTEGER NOT NULL, policy_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS ha_promotions (id TEXT PRIMARY KEY, command_id TEXT NOT NULL UNIQUE, group_id TEXT NOT NULL, resource_id TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL, promotion_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ha_active_promotion ON ha_promotions(resource_id) WHERE state NOT IN ('committed','rolled_back','failed');
CREATE TABLE IF NOT EXISTS ha_promotion_approvals (
 approval_id TEXT PRIMARY KEY,
 promotion_id TEXT NOT NULL,
 tenant_id TEXT NOT NULL,
 actor_id TEXT NOT NULL,
 command_id TEXT NOT NULL UNIQUE,
 idempotency_key TEXT NOT NULL,
 plan_digest TEXT NOT NULL,
 promotion_generation INTEGER NOT NULL,
 fence_id TEXT NOT NULL DEFAULT '',
 admission_json BLOB NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 accepted_at TIMESTAMP NOT NULL,
 UNIQUE(promotion_id,actor_id),
 UNIQUE(promotion_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS ha_promotion_approvals_plan ON ha_promotion_approvals(promotion_id,plan_digest,expires_at);
CREATE TABLE IF NOT EXISTS ha_failover_runs (id TEXT PRIMARY KEY, promotion_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL, step TEXT NOT NULL, run_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS ha_backup_copies (id TEXT PRIMARY KEY, recovery_point_id TEXT NOT NULL, target_node_id TEXT NOT NULL, manifest_digest TEXT NOT NULL, copy_json BLOB NOT NULL, verified_at TIMESTAMP NOT NULL, UNIQUE(recovery_point_id, target_node_id));
CREATE TABLE IF NOT EXISTS ha_mail_topologies (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, writer_node_id TEXT NOT NULL, generation INTEGER NOT NULL, topology_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL);
	CREATE TABLE IF NOT EXISTS ha_dns_topologies (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, primary_node_id TEXT NOT NULL, generation INTEGER NOT NULL, topology_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL);
	CREATE TABLE IF NOT EXISTS ha_local_workload_authority (tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, resource_id TEXT NOT NULL, workload_identity TEXT NOT NULL UNIQUE, writer_node_id TEXT NOT NULL, state TEXT NOT NULL, fencing_token INTEGER NOT NULL, authority_epoch INTEGER NOT NULL, generation INTEGER NOT NULL, fence_uncertain INTEGER NOT NULL, authority_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL, PRIMARY KEY(tenant_id,group_id,resource_id));
	CREATE INDEX IF NOT EXISTS ha_local_workload_writer ON ha_local_workload_authority(group_id,writer_node_id,state);
	CREATE TABLE IF NOT EXISTS ha_local_channel_bindings (channel_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, resource_id TEXT NOT NULL, source_node_id TEXT NOT NULL, target_node_id TEXT NOT NULL, generation INTEGER NOT NULL, binding_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL, UNIQUE(tenant_id,group_id,resource_id,source_node_id,target_node_id));
	CREATE TABLE IF NOT EXISTS ha_local_replication_evidence (evidence_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, resource_id TEXT NOT NULL, channel_id TEXT NOT NULL, target_node_id TEXT NOT NULL, sequence INTEGER NOT NULL, evidence_digest TEXT NOT NULL UNIQUE, caught_up INTEGER NOT NULL, healthy INTEGER NOT NULL, valid_until TIMESTAMP NOT NULL, evidence_json BLOB NOT NULL, observed_at TIMESTAMP NOT NULL, UNIQUE(channel_id,sequence));
	CREATE INDEX IF NOT EXISTS ha_local_replication_current ON ha_local_replication_evidence(tenant_id,group_id,resource_id,target_node_id,sequence DESC);
	CREATE TABLE IF NOT EXISTS ha_local_authority_decisions (decision_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, resource_id TEXT NOT NULL, kind TEXT NOT NULL, expected_generation INTEGER NOT NULL, previous_writer TEXT NOT NULL, candidate TEXT NOT NULL, lease_id TEXT NOT NULL, checkpoint_id TEXT NOT NULL, evidence_id TEXT NOT NULL, fence_id TEXT NOT NULL, decision_digest TEXT NOT NULL UNIQUE, expires_at TIMESTAMP NOT NULL, decision_json BLOB NOT NULL, created_at TIMESTAMP NOT NULL);
	CREATE TABLE IF NOT EXISTS ha_local_fence_outcomes (fence_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, decision_id TEXT NOT NULL, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, resource_id TEXT NOT NULL, outcome TEXT NOT NULL, evidence_digest TEXT NOT NULL UNIQUE, outcome_json BLOB NOT NULL, observed_at TIMESTAMP NOT NULL, valid_until TIMESTAMP NOT NULL);
	CREATE TABLE IF NOT EXISTS ha_local_operations (operation_id TEXT PRIMARY KEY, kind TEXT NOT NULL, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, resource_id TEXT NOT NULL, expected_generation INTEGER NOT NULL, operation_digest TEXT NOT NULL, state TEXT NOT NULL, receipt_json BLOB NOT NULL, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL);
	CREATE UNIQUE INDEX IF NOT EXISTS ha_local_operation_digest ON ha_local_operations(operation_id,operation_digest);
	`

type Store interface {
	CreateNodeGroup(context.Context, NodeGroup) error; LoadNodeGroup(context.Context, NodeGroupID) (NodeGroup, error); UpdateNodeGroup(context.Context, NodeGroup, uint64) error
	SaveNode(context.Context, NodeMember, uint64) error; LoadNode(context.Context, NodeID) (NodeMember, error); ListNodes(context.Context, NodeGroupID) ([]NodeMember, error); SaveHealth(context.Context, HealthObservation) error
	SavePlacementGroup(context.Context, PlacementGroup, uint64) error; LoadPlacementGroup(context.Context, PlacementGroupID) (PlacementGroup, error)
	SaveReplicaSet(context.Context, ReplicaSet, uint64) error; LoadReplicaSet(context.Context, ReplicaSetID) (ReplicaSet, error)
	CreateChannel(context.Context, ReplicationChannel) error; LoadChannel(context.Context, ChannelID) (ReplicationChannel, error); UpdateChannel(context.Context, ReplicationChannel, uint64) error
	SaveCheckpoint(context.Context, ReplicationCheckpoint) error; LoadCheckpoint(context.Context, CheckpointID) (ReplicationCheckpoint, error); LatestCheckpoint(context.Context, ChannelID) (ReplicationCheckpoint, error)
	CommitReplicationOutcome(context.Context, ReplicationChannel, uint64, *ReplicationCheckpoint, ReplicationChannelHealth) error; LatestReplicationHealth(context.Context, ChannelID) (ReplicationChannelHealth, error)
	SaveDatabaseCluster(context.Context, DatabaseCluster, uint64) error; LoadDatabaseCluster(context.Context, ID) (DatabaseCluster, error)
	CreateLease(context.Context, WriterLease) error; LoadLease(context.Context, WriterLeaseID) (WriterLease, error); ActiveWriterLeaseByResource(context.Context, string) (WriterLease, error); UpdateLease(context.Context, WriterLease, uint64) error
	SaveFence(context.Context, Fence, uint64) error; LoadFence(context.Context, FenceID) (Fence, error)
	SaveTrafficPolicy(context.Context, TrafficPolicy, uint64) error; LoadTrafficPolicy(context.Context, TrafficPolicyID) (TrafficPolicy, error)
	CreatePromotion(context.Context, Promotion) error; LoadPromotion(context.Context, PromotionID) (Promotion, error); UpdatePromotion(context.Context, Promotion, uint64) error
	CreateFailoverRun(context.Context, FailoverRun) error; LoadFailoverRun(context.Context, FailoverRunID) (FailoverRun, error); UpdateFailoverRun(context.Context, FailoverRun) error
	SaveBackupCopy(context.Context, BackupReplicaCopy) error
	SaveMailTopology(context.Context, MailTopology, uint64) error; LoadMailTopology(context.Context, ID) (MailTopology, error)
	SaveDNSTopology(context.Context, DNSTopology, uint64) error; LoadDNSTopology(context.Context, ID) (DNSTopology, error)
}

type SQLRepository struct{ DB *sql.DB }
func (repository SQLRepository) Bootstrap(ctx context.Context) error {
	if repository.DB == nil { return errors.New("ha database required") }
	if ctx == nil { return ErrInvalid }
	if err := repository.migrateNodeWorkloadIdentity(ctx); err != nil { return fmt.Errorf("migrate HA node workload identities: %w", err) }
	_, err := repository.DB.ExecContext(ctx, SQLSchema)
	return err
}

type nodeTableColumn struct { notNull bool; primaryKey bool }
type migratedNodeRow struct { node NodeMember; raw []byte }

func (repository SQLRepository) migrateNodeWorkloadIdentity(ctx context.Context) error {
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()

	columnRows, err := tx.QueryContext(ctx, `PRAGMA table_info(ha_nodes)`)
	if err != nil { return err }
	columns := map[string]nodeTableColumn{}
	for columnRows.Next() {
		var position, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err = columnRows.Scan(&position, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil { columnRows.Close(); return err }
		if _, duplicate := columns[name]; duplicate { columnRows.Close(); return fmt.Errorf("%w: duplicate ha_nodes column", ErrInvalid) }
		columns[name] = nodeTableColumn{notNull:notNull == 1, primaryKey:primaryKey == 1}
	}
	if err = columnRows.Err(); err != nil { columnRows.Close(); return err }
	if err = columnRows.Close(); err != nil { return err }
	if len(columns) == 0 { return tx.Commit() }

	for _, name := range []string{"id", "group_id", "state", "generation", "node_json", "updated_at"} {
		if _, exists := columns[name]; !exists { return fmt.Errorf("%w: ha_nodes missing %s", ErrInvalid, name) }
	}
	if !columns["id"].primaryKey { return fmt.Errorf("%w: ha_nodes id is not the primary key", ErrInvalid) }
	_, hasIdentity := columns["workload_identity"]
	needsRebuild := !hasIdentity || !columns["workload_identity"].notNull
	query := `SELECT id,group_id,state,generation,node_json FROM ha_nodes ORDER BY id`
	if hasIdentity { query = `SELECT id,group_id,state,generation,node_json,workload_identity FROM ha_nodes ORDER BY id` }
	rows, err := tx.QueryContext(ctx, query)
	if err != nil { return err }
	identities := map[string]NodeID{}
	values := []migratedNodeRow{}
	for rows.Next() {
		var id, groupID, state string
		var generation int64
		var raw []byte
		var storedIdentity sql.NullString
		if hasIdentity { err = rows.Scan(&id, &groupID, &state, &generation, &raw, &storedIdentity) } else { err = rows.Scan(&id, &groupID, &state, &generation, &raw) }
		if err != nil { rows.Close(); return err }
		if generation <= 0 { rows.Close(); return fmt.Errorf("%w: invalid ha_nodes generation", ErrInvalid) }
		var node NodeMember
		if err = decode(raw, &node); err != nil { rows.Close(); return fmt.Errorf("%w: corrupt ha_nodes JSON", ErrInvalid) }
		if err = node.Validate(); err != nil { rows.Close(); return fmt.Errorf("%w: invalid ha_nodes JSON", ErrInvalid) }
		if string(node.ID) != id || string(node.GroupID) != groupID || string(node.State) != state || node.Generation != uint64(generation) { rows.Close(); return fmt.Errorf("%w: ha_nodes columns disagree with JSON", ErrInvalid) }
		if previous, duplicate := identities[node.WorkloadIdentity]; duplicate && previous != node.ID { rows.Close(); return fmt.Errorf("%w: duplicate HA workload identity", ErrConflict) }
		identities[node.WorkloadIdentity] = node.ID
		if hasIdentity {
			if !storedIdentity.Valid || storedIdentity.String == "" { needsRebuild = true } else if storedIdentity.String != node.WorkloadIdentity { rows.Close(); return fmt.Errorf("%w: ha_nodes workload identity disagrees with JSON", ErrInvalid) }
		}
		values = append(values, migratedNodeRow{node:node, raw:append([]byte(nil), raw...)})
	}
	if err = rows.Err(); err != nil { rows.Close(); return err }
	if err = rows.Close(); err != nil { return err }

	if !needsRebuild {
		if _, err = tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS ha_nodes_group ON ha_nodes(group_id,state,id)`); err != nil { return err }
		if _, err = tx.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS ha_nodes_workload_identity ON ha_nodes(workload_identity)`); err != nil { return err }
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE ha_nodes__workload_identity_migration (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, workload_identity TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL, node_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL)`); err != nil { return err }
	for _, value := range values {
		node := value.node
		if _, err = tx.ExecContext(ctx, `INSERT INTO ha_nodes__workload_identity_migration (id,group_id,workload_identity,state,generation,node_json,updated_at) VALUES (?,?,?,?,?,?,?)`, node.ID, node.GroupID, node.WorkloadIdentity, node.State, node.Generation, value.raw, node.UpdatedAt); err != nil { return err }
	}
	if _, err = tx.ExecContext(ctx, `DROP TABLE ha_nodes`); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `ALTER TABLE ha_nodes__workload_identity_migration RENAME TO ha_nodes`); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `CREATE INDEX ha_nodes_group ON ha_nodes(group_id,state,id)`); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `CREATE UNIQUE INDEX ha_nodes_workload_identity ON ha_nodes(workload_identity)`); err != nil { return err }
	return tx.Commit()
}
func encode(value any) ([]byte,error) { return json.Marshal(value) }
func decode(data []byte,value any) error { if len(data)==0{return ErrInvalid}; if json.Unmarshal(data,value)!=nil{return ErrInvalid}; return nil }
func one(result sql.Result) error { count,err:=result.RowsAffected();if err!=nil{return err};if count!=1{return ErrNotFound};return nil }
func cas(result sql.Result) error { count,err:=result.RowsAffected();if err!=nil{return err};if count!=1{return ErrStaleGeneration};return nil }

func (r SQLRepository) CreateNodeGroup(ctx context.Context,v NodeGroup) error { if e:=v.Validate();e!=nil{return e};b,e:=encode(v);if e!=nil{return e};_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_node_groups (id,generation,group_json,updated_at) VALUES (?,?,?,?)`,v.ID,v.Generation,b,v.UpdatedAt);return e }
func (r SQLRepository) LoadNodeGroup(ctx context.Context,id NodeGroupID)(NodeGroup,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT group_json FROM ha_node_groups WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return NodeGroup{},ErrNotFound};if e!=nil{return NodeGroup{},e};var v NodeGroup;e=decode(b,&v);return v,e}
func (r SQLRepository) UpdateNodeGroup(ctx context.Context,v NodeGroup,g uint64)error{if e:=v.Validate();e!=nil{return e};b,e:=encode(v);if e!=nil{return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_node_groups SET generation=?,group_json=?,updated_at=? WHERE id=? AND generation=?`,v.Generation,b,v.UpdatedAt,v.ID,g);if e!=nil{return e};return cas(x)}
func (r SQLRepository) SaveNode(ctx context.Context,v NodeMember,g uint64)error{if e:=v.Validate();e!=nil{return e};b,e:=encode(v);if e!=nil{return e};if g==0{_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_nodes (id,group_id,workload_identity,state,generation,node_json,updated_at) VALUES (?,?,?,?,?,?,?)`,v.ID,v.GroupID,v.WorkloadIdentity,v.State,v.Generation,b,v.UpdatedAt);return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_nodes SET state=?,generation=?,node_json=?,updated_at=? WHERE id=? AND generation=? AND workload_identity=?`,v.State,v.Generation,b,v.UpdatedAt,v.ID,g,v.WorkloadIdentity);if e!=nil{return e};return cas(x)}
func (r SQLRepository) LoadNode(ctx context.Context,id NodeID)(NodeMember,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT node_json FROM ha_nodes WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return NodeMember{},ErrNotFound};if e!=nil{return NodeMember{},e};var v NodeMember;e=decode(b,&v);if e==nil{e=v.Validate()};return v,e}
func (r SQLRepository) ListNodes(ctx context.Context,id NodeGroupID)([]NodeMember,error){rows,e:=r.DB.QueryContext(ctx,`SELECT node_json FROM ha_nodes WHERE group_id=? ORDER BY id`,id);if e!=nil{return nil,e};defer rows.Close();v:=[]NodeMember{};for rows.Next(){var b []byte;if e:=rows.Scan(&b);e!=nil{return nil,e};var n NodeMember;if e:=decode(b,&n);e!=nil{return nil,e};v=append(v,n)};return v,rows.Err()}
func (r SQLRepository) ListAllNodes(ctx context.Context,cursor string,limit uint16)([]NodeMember,string,uint64,error){if r.DB==nil||ctx==nil||cursor!=""&&!validID(cursor){return nil,"",0,ErrInvalid};if limit==0{limit=100};if limit>500{return nil,"",0,ErrInvalid};var total uint64;if err:=r.DB.QueryRowContext(ctx,`SELECT COUNT(*) FROM ha_nodes`).Scan(&total);err!=nil{return nil,"",0,err};rows,err:=r.DB.QueryContext(ctx,`SELECT node_json FROM ha_nodes WHERE id>? ORDER BY id LIMIT ?`,cursor,int(limit)+1);if err!=nil{return nil,"",0,err};defer rows.Close();values:=make([]NodeMember,0,int(limit)+1);for rows.Next(){var raw []byte;if err=rows.Scan(&raw);err!=nil{return nil,"",0,err};var node NodeMember;if err=decode(raw,&node);err!=nil{return nil,"",0,err};if err=node.Validate();err!=nil{return nil,"",0,err};values=append(values,node)};if err=rows.Err();err!=nil{return nil,"",0,err};next:="";if len(values)>int(limit){next=string(values[limit-1].ID);values=values[:limit]};return values,next,total,nil}
func (r SQLRepository) AdmitEnrollment(ctx context.Context,enrollment VerifiedEnrollment,commandID string)(NodeMember,bool,error){if r.DB==nil||ctx==nil||!validID(commandID)||!validID(enrollment.TokenID)||!validDigest(enrollment.TokenDigest)||enrollment.Group.ID!=enrollment.Node.GroupID||enrollment.Group.Validate()!=nil||enrollment.Node.Validate()!=nil{return NodeMember{},false,ErrInvalid};tx,err:=r.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return NodeMember{},false,err};defer tx.Rollback();var digest,nodeID,existingCommand string;err=tx.QueryRowContext(ctx,`SELECT token_digest,node_id,command_id FROM ha_enrollment_tokens WHERE token_id=? OR token_digest=? OR command_id=? LIMIT 1`,enrollment.TokenID,enrollment.TokenDigest,commandID).Scan(&digest,&nodeID,&existingCommand);if err==nil{if digest!=enrollment.TokenDigest||nodeID!=string(enrollment.Node.ID)||existingCommand!=commandID{return NodeMember{},false,ErrConflict};var raw []byte;if err=tx.QueryRowContext(ctx,`SELECT node_json FROM ha_nodes WHERE id=? AND workload_identity=?`,nodeID,enrollment.Node.WorkloadIdentity).Scan(&raw);err!=nil{return NodeMember{},false,err};var node NodeMember;if err=decode(raw,&node);err!=nil{return NodeMember{},false,err};return node,false,tx.Commit()};if !errors.Is(err,sql.ErrNoRows){return NodeMember{},false,err};var groupRaw []byte;err=tx.QueryRowContext(ctx,`SELECT group_json FROM ha_node_groups WHERE id=?`,enrollment.Group.ID).Scan(&groupRaw);if err==nil{var existing NodeGroup;if err=decode(groupRaw,&existing);err!=nil{return NodeMember{},false,err};if !sameEnrollmentGroup(existing,enrollment.Group){return NodeMember{},false,ErrConflict}}else if errors.Is(err,sql.ErrNoRows){groupRaw,err=encode(enrollment.Group);if err==nil{_,err=tx.ExecContext(ctx,`INSERT INTO ha_node_groups (id,generation,group_json,updated_at) VALUES (?,?,?,?)`,enrollment.Group.ID,enrollment.Group.Generation,groupRaw,enrollment.Group.UpdatedAt)};if err!=nil{return NodeMember{},false,err}}else{return NodeMember{},false,err};var occupied string;err=tx.QueryRowContext(ctx,`SELECT id FROM ha_nodes WHERE id=? OR workload_identity=? LIMIT 1`,enrollment.Node.ID,enrollment.Node.WorkloadIdentity).Scan(&occupied);if err==nil{return NodeMember{},false,ErrConflict};if !errors.Is(err,sql.ErrNoRows){return NodeMember{},false,err};nodeRaw,err:=encode(enrollment.Node);if err!=nil{return NodeMember{},false,err};if _,err=tx.ExecContext(ctx,`INSERT INTO ha_nodes (id,group_id,workload_identity,state,generation,node_json,updated_at) VALUES (?,?,?,?,?,?,?)`,enrollment.Node.ID,enrollment.Node.GroupID,enrollment.Node.WorkloadIdentity,enrollment.Node.State,enrollment.Node.Generation,nodeRaw,enrollment.Node.UpdatedAt);err!=nil{return NodeMember{},false,err};if _,err=tx.ExecContext(ctx,`INSERT INTO ha_enrollment_tokens (token_id,token_digest,node_id,command_id,consumed_at) VALUES (?,?,?,?,?)`,enrollment.TokenID,enrollment.TokenDigest,enrollment.Node.ID,commandID,enrollment.Node.UpdatedAt);err!=nil{return NodeMember{},false,err};if err=tx.Commit();err!=nil{return NodeMember{},false,err};return enrollment.Node,true,nil}
func (r SQLRepository) SaveHealth(ctx context.Context,v HealthObservation)error{b,e:=encode(v);if e!=nil{return e};_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_health (node_id,observer_node_id,sequence,health_json,observed_at) VALUES (?,?,?,?,?) ON CONFLICT(node_id,observer_node_id) DO UPDATE SET sequence=excluded.sequence,health_json=excluded.health_json,observed_at=excluded.observed_at WHERE ha_health.sequence < excluded.sequence`,v.NodeID,v.ObserverNodeID,v.Sequence,b,v.ObservedAt);return e}
func (r SQLRepository) ListHealthObservations(ctx context.Context,id NodeID)([]HealthObservation,error){
	if r.DB==nil||ctx==nil||!validID(string(id)){return nil,ErrInvalid}
	rows,err:=r.DB.QueryContext(ctx,`SELECT observer_node_id,sequence,health_json FROM ha_health WHERE node_id=? ORDER BY observer_node_id`,id)
	if err!=nil{return nil,err}
	defer rows.Close()
	values:=[]HealthObservation{}
	for rows.Next(){
		var observer string
		var sequence uint64
		var raw []byte
		if err=rows.Scan(&observer,&sequence,&raw);err!=nil{return nil,err}
		var observation HealthObservation
		if err=decode(raw,&observation);err!=nil{return nil,err}
		if observation.NodeID!=id||string(observation.ObserverNodeID)!=observer||observation.Sequence!=sequence||!validHealthObservation(observation){return nil,ErrInvalid}
		values=append(values,observation)
	}
	if err=rows.Err();err!=nil{return nil,err}
	return values,nil
}
func validHealthObservation(observation HealthObservation)bool{
	if !validID(string(observation.NodeID))||!validID(string(observation.ObserverNodeID))||observation.Sequence==0||observation.Signature==""||observation.Latency<0||observation.ObservedAt.IsZero()||!observation.ValidUntil.After(observation.ObservedAt){return false}
	switch observation.State{case HealthHealthy,HealthDegraded,HealthUnreachable,HealthFenced,HealthUnknown:return true;default:return false}
}
func (r SQLRepository) SavePlacementGroup(ctx context.Context,v PlacementGroup,g uint64)error{b,e:=encode(v);if e!=nil{return e};if g==0{_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_placement_groups (id,node_group_id,generation,placement_json) VALUES (?,?,?,?)`,v.ID,v.NodeGroupID,v.Generation,b);return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_placement_groups SET generation=?,placement_json=? WHERE id=? AND generation=?`,v.Generation,b,v.ID,g);if e!=nil{return e};return cas(x)}
func (r SQLRepository) LoadPlacementGroup(ctx context.Context,id PlacementGroupID)(PlacementGroup,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT placement_json FROM ha_placement_groups WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return PlacementGroup{},ErrNotFound};if e!=nil{return PlacementGroup{},e};var v PlacementGroup;e=decode(b,&v);return v,e}
func (r SQLRepository) SaveReplicaSet(ctx context.Context,v ReplicaSet,g uint64)error{b,e:=encode(v);if e!=nil{return e};if g==0{_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_replica_sets (id,placement_group_id,kind,resource_id,generation,replica_json,updated_at) VALUES (?,?,?,?,?,?,?)`,v.ID,v.PlacementGroupID,v.Kind,v.ResourceID,v.Generation,b,v.UpdatedAt);return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_replica_sets SET generation=?,replica_json=?,updated_at=? WHERE id=? AND generation=?`,v.Generation,b,v.UpdatedAt,v.ID,g);if e!=nil{return e};return cas(x)}
func (r SQLRepository) LoadReplicaSet(ctx context.Context,id ReplicaSetID)(ReplicaSet,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT replica_json FROM ha_replica_sets WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return ReplicaSet{},ErrNotFound};if e!=nil{return ReplicaSet{},e};var v ReplicaSet;e=decode(b,&v);return v,e}
func (r SQLRepository) CreateChannel(ctx context.Context,v ReplicationChannel)error{if e:=v.Validate();e!=nil{return e};b,e:=encode(v);if e!=nil{return e};_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_replication_channels (id,group_id,kind,resource_id,source_node_id,target_node_id,state,generation,channel_json,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,v.ID,v.GroupID,v.Kind,v.ResourceID,v.SourceNodeID,v.TargetNodeID,v.State,v.Generation,b,v.UpdatedAt);return e}
func (r SQLRepository) LoadChannel(ctx context.Context,id ChannelID)(ReplicationChannel,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT channel_json FROM ha_replication_channels WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return ReplicationChannel{},ErrNotFound};if e!=nil{return ReplicationChannel{},e};var v ReplicationChannel;e=decode(b,&v);return v,e}
func (r SQLRepository) ChannelForResourceTarget(ctx context.Context,group NodeGroupID,resource string,source,target NodeID)(ReplicationChannel,error){if r.DB==nil||ctx==nil||!validID(string(group))||resource==""||!validID(string(source))||!validID(string(target))||source==target{return ReplicationChannel{},ErrInvalid};var raw []byte;err:=r.DB.QueryRowContext(ctx,`SELECT channel_json FROM ha_replication_channels WHERE group_id=? AND resource_id=? AND source_node_id=? AND target_node_id=? AND state IN ('caught_up','lagging','syncing') ORDER BY CASE state WHEN 'caught_up' THEN 0 WHEN 'lagging' THEN 1 ELSE 2 END,updated_at DESC LIMIT 1`,group,resource,source,target).Scan(&raw);if errors.Is(err,sql.ErrNoRows){return ReplicationChannel{},ErrNotFound};if err!=nil{return ReplicationChannel{},err};var channel ReplicationChannel;if err=decode(raw,&channel);err!=nil{return ReplicationChannel{},err};if err=channel.Validate();err!=nil{return ReplicationChannel{},err};return channel,nil}
func (r SQLRepository) UpdateChannel(ctx context.Context,v ReplicationChannel,g uint64)error{if e:=v.Validate();e!=nil{return e};b,e:=encode(v);if e!=nil{return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_replication_channels SET state=?,generation=?,channel_json=?,updated_at=? WHERE id=? AND generation=?`,v.State,v.Generation,b,v.UpdatedAt,v.ID,g);if e!=nil{return e};return cas(x)}
func (r SQLRepository) SaveCheckpoint(ctx context.Context,v ReplicationCheckpoint)error{if e:=v.Validate();e!=nil{return e};b,e:=encode(v);if e!=nil{return e};_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_checkpoints (id,channel_id,source_generation,write_frontier,manifest_digest,checkpoint_json,verified_at) VALUES (?,?,?,?,?,?,?)`,v.ID,v.ChannelID,v.SourceGeneration,v.WriteFrontier,v.ManifestDigest,b,v.VerifiedAt);return e}
func (r SQLRepository) LoadCheckpoint(ctx context.Context,id CheckpointID)(ReplicationCheckpoint,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT checkpoint_json FROM ha_checkpoints WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return ReplicationCheckpoint{},ErrNotFound};if e!=nil{return ReplicationCheckpoint{},e};var v ReplicationCheckpoint;e=decode(b,&v);return v,e}
func (r SQLRepository) LatestCheckpoint(ctx context.Context,id ChannelID)(ReplicationCheckpoint,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT checkpoint_json FROM ha_checkpoints WHERE channel_id=? ORDER BY write_frontier DESC LIMIT 1`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return ReplicationCheckpoint{},ErrNotFound};if e!=nil{return ReplicationCheckpoint{},e};var v ReplicationCheckpoint;e=decode(b,&v);return v,e}
func (r SQLRepository) CommitReplicationOutcome(ctx context.Context,channel ReplicationChannel,expectedGeneration uint64,checkpoint *ReplicationCheckpoint,health ReplicationChannelHealth)error{
	if r.DB==nil||ctx==nil||expectedGeneration==0||expectedGeneration>=uint64(1<<63-1)||channel.Generation!=expectedGeneration+1||channel.ID!=health.ChannelID||channel.Generation!=health.ChannelGeneration||channel.State!=health.State{return ErrInvalid}
	if err:=channel.Validate();err!=nil{return err}
	if err:=health.Validate();err!=nil{return err}
	if checkpoint==nil{
		if channel.State!=ChannelFailed||health.CheckpointID!=""||health.WriteFrontier!=0{return ErrInvalid}
	}else{
		if err:=checkpoint.Validate();err!=nil{return err}
		if channel.State!=ChannelCaughtUp||checkpoint.ChannelID!=channel.ID||checkpoint.SourceGeneration!=health.SourceGeneration||checkpoint.ID!=health.CheckpointID||checkpoint.WriteFrontier!=health.WriteFrontier{return ErrConflict}
	}
	channelRaw,err:=encode(channel);if err!=nil{return err}
	healthRaw,err:=encode(health);if err!=nil{return err}
	var checkpointRaw []byte
	if checkpoint!=nil{checkpointRaw,err=encode(*checkpoint);if err!=nil{return err}}
	tx,err:=r.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return err};defer tx.Rollback()
	var storedDigest string
	err=tx.QueryRowContext(ctx,`SELECT evidence_digest FROM ha_replication_health WHERE channel_id=? AND sequence=?`,health.ChannelID,health.ChannelGeneration).Scan(&storedDigest)
	if err==nil{
		if storedDigest!=health.EvidenceDigest{return ErrConflict}
		var storedChannel []byte
		if err=tx.QueryRowContext(ctx,`SELECT channel_json FROM ha_replication_channels WHERE id=?`,channel.ID).Scan(&storedChannel);err!=nil{return err}
		if !bytes.Equal(storedChannel,channelRaw){return ErrConflict}
		if checkpoint!=nil{
			var storedCheckpoint []byte
			if err=tx.QueryRowContext(ctx,`SELECT checkpoint_json FROM ha_checkpoints WHERE id=?`,checkpoint.ID).Scan(&storedCheckpoint);err!=nil{return err}
			if !bytes.Equal(storedCheckpoint,checkpointRaw){return ErrConflict}
		}
		return tx.Commit()
	}
	if !errors.Is(err,sql.ErrNoRows){return err}
	var latest sql.NullInt64
	if err=tx.QueryRowContext(ctx,`SELECT MAX(sequence) FROM ha_replication_health WHERE channel_id=?`,channel.ID).Scan(&latest);err!=nil{return err}
	if latest.Valid&&uint64(latest.Int64)>=health.ChannelGeneration{return ErrStaleGeneration}
	if checkpoint!=nil{
		var storedCheckpoint []byte
		loadErr:=tx.QueryRowContext(ctx,`SELECT checkpoint_json FROM ha_checkpoints WHERE id=? OR (channel_id=? AND source_generation=? AND write_frontier=?) LIMIT 1`,checkpoint.ID,checkpoint.ChannelID,checkpoint.SourceGeneration,checkpoint.WriteFrontier).Scan(&storedCheckpoint)
		switch{
		case loadErr==nil:
			if !bytes.Equal(storedCheckpoint,checkpointRaw){return ErrConflict}
		case errors.Is(loadErr,sql.ErrNoRows):
			if _,err=tx.ExecContext(ctx,`INSERT INTO ha_checkpoints (id,channel_id,source_generation,write_frontier,manifest_digest,checkpoint_json,verified_at) VALUES (?,?,?,?,?,?,?)`,checkpoint.ID,checkpoint.ChannelID,checkpoint.SourceGeneration,checkpoint.WriteFrontier,checkpoint.ManifestDigest,checkpointRaw,checkpoint.VerifiedAt);err!=nil{return err}
		default:
			return loadErr
		}
	}
	result,err:=tx.ExecContext(ctx,`UPDATE ha_replication_channels SET state=?,generation=?,channel_json=?,updated_at=? WHERE id=? AND generation=?`,channel.State,channel.Generation,channelRaw,channel.UpdatedAt,channel.ID,expectedGeneration);if err!=nil{return err}
	if err=cas(result);err!=nil{return err}
	_,err=tx.ExecContext(ctx,`INSERT INTO ha_replication_health (channel_id,sequence,source_generation,target_generation,checkpoint_id,write_frontier,state,healthy,caught_up,failure_digest,evidence_digest,health_json,observed_at,valid_until) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,health.ChannelID,health.ChannelGeneration,health.SourceGeneration,health.TargetGeneration,health.CheckpointID,health.WriteFrontier,health.State,health.Healthy,health.CaughtUp,health.FailureDigest,health.EvidenceDigest,healthRaw,health.ObservedAt,health.ValidUntil);if err!=nil{return err}
	return tx.Commit()
}
func (r SQLRepository) LatestReplicationHealth(ctx context.Context,id ChannelID)(ReplicationChannelHealth,error){
	if r.DB==nil||ctx==nil||!validID(string(id)){return ReplicationChannelHealth{},ErrInvalid}
	var raw []byte
	err:=r.DB.QueryRowContext(ctx,`SELECT health_json FROM ha_replication_health WHERE channel_id=? ORDER BY sequence DESC LIMIT 1`,id).Scan(&raw)
	if errors.Is(err,sql.ErrNoRows){return ReplicationChannelHealth{},ErrNotFound};if err!=nil{return ReplicationChannelHealth{},err}
	var health ReplicationChannelHealth
	if err=decode(raw,&health);err!=nil{return ReplicationChannelHealth{},err}
	if err=health.Validate();err!=nil{return ReplicationChannelHealth{},err}
	return health,nil
}
func (r SQLRepository) SaveDatabaseCluster(ctx context.Context,v DatabaseCluster,g uint64)error{if e:=v.Validate();e!=nil{return e};b,e:=encode(v);if e!=nil{return e};if g==0{_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_database_clusters (id,group_id,topology,state,generation,cluster_json,updated_at) VALUES (?,?,?,?,?,?,?)`,v.ID,v.GroupID,v.Topology,v.State,v.Generation,b,v.UpdatedAt);return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_database_clusters SET state=?,generation=?,cluster_json=?,updated_at=? WHERE id=? AND generation=?`,v.State,v.Generation,b,v.UpdatedAt,v.ID,g);if e!=nil{return e};return cas(x)}
func (r SQLRepository) LoadDatabaseCluster(ctx context.Context,id ID)(DatabaseCluster,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT cluster_json FROM ha_database_clusters WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return DatabaseCluster{},ErrNotFound};if e!=nil{return DatabaseCluster{},e};var v DatabaseCluster;e=decode(b,&v);return v,e}
func (r SQLRepository) CreateLease(ctx context.Context,v WriterLease)error{b,e:=encode(v);if e!=nil{return e};_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_writer_leases (id,group_id,resource_id,holder_node_id,fencing_token,authority_epoch,state,generation,lease_json,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,v.ID,v.GroupID,v.ResourceID,v.HolderNodeID,v.FencingToken,v.AuthorityEpoch,v.State,v.Generation,b,v.ExpiresAt);return e}
func (r SQLRepository) LoadLease(ctx context.Context,id WriterLeaseID)(WriterLease,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT lease_json FROM ha_writer_leases WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return WriterLease{},ErrNotFound};if e!=nil{return WriterLease{},e};var v WriterLease;e=decode(b,&v);return v,e}
func (r SQLRepository) ActiveWriterLeaseByResource(ctx context.Context,resource string)(WriterLease,error){if r.DB==nil||ctx==nil||resource==""{return WriterLease{},ErrInvalid};var raw []byte;err:=r.DB.QueryRowContext(ctx,`SELECT lease_json FROM ha_writer_leases WHERE resource_id=? AND state='active' ORDER BY authority_epoch DESC,fencing_token DESC LIMIT 1`,resource).Scan(&raw);if errors.Is(err,sql.ErrNoRows){return WriterLease{},ErrNotFound};if err!=nil{return WriterLease{},err};var lease WriterLease;if err=decode(raw,&lease);err!=nil{return WriterLease{},err};return lease,nil}
func (r SQLRepository) ListActiveWriterLeases(ctx context.Context,id NodeGroupID)([]WriterLease,error){
	if r.DB==nil||ctx==nil||!validID(string(id)){return nil,ErrInvalid}
	rows,err:=r.DB.QueryContext(ctx,`SELECT lease_json FROM ha_writer_leases WHERE group_id=? AND state=? ORDER BY resource_id`,id,LeaseActive)
	if err!=nil{return nil,err}
	defer rows.Close()
	values:=[]WriterLease{}
	for rows.Next(){
		var raw []byte
		if err=rows.Scan(&raw);err!=nil{return nil,err}
		var lease WriterLease
		if err=decode(raw,&lease);err!=nil{return nil,err}
		if lease.GroupID!=id||lease.State!=LeaseActive||!validID(string(lease.ID))||lease.ResourceID==""||!validID(string(lease.HolderNodeID))||lease.Generation==0||lease.ExpiresAt.IsZero(){return nil,ErrInvalid}
		values=append(values,lease)
	}
	if err=rows.Err();err!=nil{return nil,err}
	return values,nil
}
func (r SQLRepository) UpdateLease(ctx context.Context,v WriterLease,g uint64)error{b,e:=encode(v);if e!=nil{return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_writer_leases SET holder_node_id=?,fencing_token=?,authority_epoch=?,state=?,generation=?,lease_json=?,expires_at=? WHERE id=? AND generation=?`,v.HolderNodeID,v.FencingToken,v.AuthorityEpoch,v.State,v.Generation,b,v.ExpiresAt,v.ID,g);if e!=nil{return e};return cas(x)}
func (r SQLRepository) SaveFence(ctx context.Context,v Fence,g uint64)error{b,e:=encode(v);if e!=nil{return e};if g==0{_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_fences (id,group_id,target_node_id,class,fencing_token,state,generation,fence_json) VALUES (?,?,?,?,?,?,?,?)`,v.ID,v.GroupID,v.TargetNodeID,v.Class,v.FencingToken,v.State,v.Generation,b);return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_fences SET state=?,generation=?,fence_json=? WHERE id=? AND generation=?`,v.State,v.Generation,b,v.ID,g);if e!=nil{return e};return cas(x)}
func (r SQLRepository) LoadFence(ctx context.Context,id FenceID)(Fence,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT fence_json FROM ha_fences WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return Fence{},ErrNotFound};if e!=nil{return Fence{},e};var v Fence;e=decode(b,&v);return v,e}
func (r SQLRepository) SaveTrafficPolicy(ctx context.Context,v TrafficPolicy,g uint64)error{b,e:=encode(v);if e!=nil{return e};if g==0{_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_traffic_policies (id,group_id,provider_mode,generation,policy_json,updated_at) VALUES (?,?,?,?,?,?)`,v.ID,v.GroupID,v.ProviderMode,v.Generation,b,v.UpdatedAt);return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_traffic_policies SET generation=?,policy_json=?,updated_at=? WHERE id=? AND generation=?`,v.Generation,b,v.UpdatedAt,v.ID,g);if e!=nil{return e};return cas(x)}
func (r SQLRepository) LoadTrafficPolicy(ctx context.Context,id TrafficPolicyID)(TrafficPolicy,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT policy_json FROM ha_traffic_policies WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return TrafficPolicy{},ErrNotFound};if e!=nil{return TrafficPolicy{},e};var v TrafficPolicy;e=decode(b,&v);return v,e}
func (r SQLRepository) TrafficPolicyByResource(ctx context.Context,group NodeGroupID,resource string)(TrafficPolicy,error){if r.DB==nil||ctx==nil||!validID(string(group))||resource==""{return TrafficPolicy{},ErrInvalid};rows,err:=r.DB.QueryContext(ctx,`SELECT policy_json FROM ha_traffic_policies WHERE group_id=? ORDER BY updated_at DESC`,group);if err!=nil{return TrafficPolicy{},err};defer rows.Close();var selected TrafficPolicy;found:=false;for rows.Next(){var raw []byte;if err=rows.Scan(&raw);err!=nil{return TrafficPolicy{},err};var policy TrafficPolicy;if err=decode(raw,&policy);err!=nil{return TrafficPolicy{},err};if policy.Resource!=resource{continue};if found{return TrafficPolicy{},ErrProviderAmbiguous};selected=policy;found=true};if err=rows.Err();err!=nil{return TrafficPolicy{},err};if !found{return TrafficPolicy{},ErrNotFound};return selected,nil}
func (r SQLRepository) CreatePromotion(ctx context.Context,v Promotion)error{b,e:=encode(v);if e!=nil{return e};_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_promotions (id,command_id,group_id,resource_id,state,generation,promotion_json,updated_at) VALUES (?,?,?,?,?,?,?,?)`,v.ID,v.CommandID,v.GroupID,v.ResourceID,v.State,v.Generation,b,v.UpdatedAt);return e}
func (r SQLRepository) LoadPromotion(ctx context.Context,id PromotionID)(Promotion,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT promotion_json FROM ha_promotions WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return Promotion{},ErrNotFound};if e!=nil{return Promotion{},e};var v Promotion;e=decode(b,&v);return v,e}
func (r SQLRepository) PromotionByCommand(ctx context.Context,id CommandID)(Promotion,error){if r.DB==nil||ctx==nil||!validID(string(id)){return Promotion{},ErrInvalid};var raw []byte;err:=r.DB.QueryRowContext(ctx,`SELECT promotion_json FROM ha_promotions WHERE command_id=?`,id).Scan(&raw);if errors.Is(err,sql.ErrNoRows){return Promotion{},ErrNotFound};if err!=nil{return Promotion{},err};var promotion Promotion;if err=decode(raw,&promotion);err!=nil{return Promotion{},err};return promotion,nil}
func (r SQLRepository) UpdatePromotion(ctx context.Context,v Promotion,g uint64)error{b,e:=encode(v);if e!=nil{return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_promotions SET state=?,generation=?,promotion_json=?,updated_at=? WHERE id=? AND generation=?`,v.State,v.Generation,b,v.UpdatedAt,v.ID,g);if e!=nil{return e};return cas(x)}

func (r SQLRepository) AdmitPromotionApproval(ctx context.Context, admission PromotionApprovalAdmission) (PromotionApprovalAdmission, bool, error) {
	if r.DB == nil || ctx == nil || admission.FenceID != "" || admission.Validate(admission.AcceptedAt) != nil {
		return PromotionApprovalAdmission{}, false, ErrDataLossApproval
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return PromotionApprovalAdmission{}, false, err }
	defer tx.Rollback()
	if existing, found, loadErr := loadPromotionApprovalAdmission(ctx, tx, `command_id=?`, admission.CommandID); loadErr != nil {
		return PromotionApprovalAdmission{}, false, loadErr
	} else if found {
		if !samePromotionApprovalAdmission(existing, admission) { return PromotionApprovalAdmission{}, false, ErrConflict }
		if err = tx.Commit(); err != nil { return PromotionApprovalAdmission{}, false, err }
		return existing, false, nil
	}
	var collision uint64
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ha_promotion_approvals WHERE approval_id=? OR (promotion_id=? AND actor_id=?) OR (promotion_id=? AND idempotency_key=?)`, admission.Approval.ID, admission.Approval.PromotionID, admission.Approval.ActorID, admission.Approval.PromotionID, admission.IdempotencyKey).Scan(&collision)
	if err != nil { return PromotionApprovalAdmission{}, false, err }
	if collision != 0 { return PromotionApprovalAdmission{}, false, ErrConflict }
	var promotionRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT promotion_json FROM ha_promotions WHERE id=? AND generation=? AND state=?`, admission.Approval.PromotionID, admission.Approval.PromotionGeneration, PromotionPlanned).Scan(&promotionRaw)
	if errors.Is(err, sql.ErrNoRows) { return PromotionApprovalAdmission{}, false, ErrStaleGeneration }
	if err != nil { return PromotionApprovalAdmission{}, false, err }
	var promotion Promotion
	if err = decode(promotionRaw, &promotion); err != nil { return PromotionApprovalAdmission{}, false, err }
	planDigest, digestErr := PromotionPlanDigest(promotion)
	if digestErr != nil || planDigest != admission.Approval.PlanDigest || promotion.ID != admission.Approval.PromotionID || promotion.GroupID != admission.Approval.GroupID || promotion.Generation != admission.Approval.PromotionGeneration {
		return PromotionApprovalAdmission{}, false, errors.Join(digestErr, ErrConflict)
	}
	raw, err := encode(admission)
	if err != nil { return PromotionApprovalAdmission{}, false, err }
	_, err = tx.ExecContext(ctx, `INSERT INTO ha_promotion_approvals(approval_id,promotion_id,tenant_id,actor_id,command_id,idempotency_key,plan_digest,promotion_generation,fence_id,admission_json,expires_at,accepted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, admission.Approval.ID, admission.Approval.PromotionID, admission.Approval.TenantID, admission.Approval.ActorID, admission.CommandID, admission.IdempotencyKey, admission.Approval.PlanDigest, admission.Approval.PromotionGeneration, "", raw, admission.Approval.ExpiresAt, admission.AcceptedAt)
	if err != nil { return PromotionApprovalAdmission{}, false, errors.Join(err, ErrConflict) }
	if err = tx.Commit(); err != nil { return PromotionApprovalAdmission{}, false, err }
	return admission, true, nil
}

func (r SQLRepository) PromotionApprovalAdmission(ctx context.Context, id string) (PromotionApprovalAdmission, error) {
	if r.DB == nil || ctx == nil || !validID(id) { return PromotionApprovalAdmission{}, ErrInvalid }
	admission, found, err := loadPromotionApprovalAdmission(ctx, r.DB, `approval_id=?`, id)
	if err != nil { return PromotionApprovalAdmission{}, err }
	if !found { return PromotionApprovalAdmission{}, ErrNotFound }
	return admission, nil
}

func (r SQLRepository) PromotionApprovalAdmissions(ctx context.Context, promotionID PromotionID, planDigest string, now time.Time) ([]PromotionApprovalAdmission, error) {
	if r.DB == nil || ctx == nil || !validID(string(promotionID)) || !validDigest(planDigest) || now.IsZero() { return nil, ErrInvalid }
	rows, err := r.DB.QueryContext(ctx, `SELECT admission_json,fence_id FROM ha_promotion_approvals WHERE promotion_id=? AND plan_digest=? AND expires_at>? ORDER BY actor_id,approval_id`, promotionID, planDigest, now)
	if err != nil { return nil, err }
	defer rows.Close()
	values := make([]PromotionApprovalAdmission, 0, 2)
	for rows.Next() {
		var raw []byte
		var fenceID FenceID
		if err = rows.Scan(&raw, &fenceID); err != nil { return nil, err }
		var admission PromotionApprovalAdmission
		if decode(raw, &admission) != nil || admission.Approval.PromotionID != promotionID || admission.Approval.PlanDigest != planDigest || admission.FenceID != "" { return nil, ErrInvalid }
		admission.FenceID = fenceID
		values = append(values, admission)
		if len(values) > maximumAdministrativeFenceApprovals { return nil, ErrConflict }
	}
	if err = rows.Err(); err != nil { return nil, err }
	if len(values) == 0 { return nil, ErrNotFound }
	return values, nil
}

func (r SQLRepository) BindPromotionApprovalFence(ctx context.Context, approvalID string, fenceID FenceID) error {
	if r.DB == nil || ctx == nil || !validID(approvalID) || !validID(string(fenceID)) { return ErrInvalid }
	result, err := r.DB.ExecContext(ctx, `UPDATE ha_promotion_approvals SET fence_id=? WHERE approval_id=? AND (fence_id='' OR fence_id=?)`, fenceID, approvalID, fenceID)
	if err != nil { return err }
	if rows, countErr := result.RowsAffected(); countErr != nil || rows != 1 { return errors.Join(countErr, ErrConflict) }
	return nil
}

func (r SQLRepository) AttachPromotionApprovals(ctx context.Context, promotionID PromotionID, generation uint64, planDigest string, approvals []Approval, now time.Time) (Promotion, error) {
	if r.DB == nil || ctx == nil || !validID(string(promotionID)) || generation == 0 || !validDigest(planDigest) || now.IsZero() || len(approvals) < minimumAdministrativeFenceApprovals || len(approvals) > maximumAdministrativeFenceApprovals { return Promotion{}, ErrDataLossApproval }
	canonical := append([]Approval(nil), approvals...)
	sort.Slice(canonical, func(left, right int) bool { if canonical[left].ActorID == canonical[right].ActorID { return canonical[left].ID < canonical[right].ID }; return canonical[left].ActorID < canonical[right].ActorID })
	tenantID := canonical[0].TenantID
	identifiers := make(map[string]struct{}, len(canonical))
	for index, approval := range canonical {
		if approval.Validate(now) != nil || approval.TenantID != tenantID || approval.GroupID != canonical[0].GroupID || approval.PromotionID != promotionID || approval.PromotionGeneration != generation || approval.PlanDigest != planDigest || approval.FenceChallenge != planDigest || index > 0 && canonical[index-1].ActorID == approval.ActorID { return Promotion{}, ErrDataLossApproval }
		if _, duplicate := identifiers[approval.ID]; duplicate { return Promotion{}, ErrDataLossApproval }
		identifiers[approval.ID] = struct{}{}
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return Promotion{}, err }
	defer tx.Rollback()
	for _, approval := range canonical {
		stored, found, loadErr := loadPromotionApprovalAdmission(ctx, tx, `approval_id=?`, approval.ID)
		if loadErr != nil || !found || !samePromotionApproval(stored.Approval, approval) { return Promotion{}, errors.Join(loadErr, ErrDataLossApproval) }
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT promotion_json FROM ha_promotions WHERE id=? AND generation=? AND state=?`, promotionID, generation, PromotionPlanned).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) { return Promotion{}, ErrStaleGeneration }
	if err != nil { return Promotion{}, err }
	var promotion Promotion
	if err = decode(raw, &promotion); err != nil { return Promotion{}, err }
	digest, digestErr := PromotionPlanDigest(promotion)
	if digestErr != nil || digest != planDigest || promotion.GroupID != canonical[0].GroupID { return Promotion{}, errors.Join(digestErr, ErrConflict) }
	if len(promotion.Approvals) != 0 && !samePromotionApprovals(promotion.Approvals, canonical) { return Promotion{}, ErrConflict }
	promotion.Approvals = canonical
	raw, err = encode(promotion)
	if err != nil { return Promotion{}, err }
	result, err := tx.ExecContext(ctx, `UPDATE ha_promotions SET promotion_json=? WHERE id=? AND generation=? AND state=?`, raw, promotion.ID, generation, PromotionPlanned)
	if err != nil { return Promotion{}, err }
	if err = cas(result); err != nil { return Promotion{}, err }
	if err = tx.Commit(); err != nil { return Promotion{}, err }
	return promotion, nil
}

func loadPromotionApprovalAdmission(ctx context.Context, queryer interface{ QueryRowContext(context.Context, string, ...any) *sql.Row }, predicate string, argument any) (PromotionApprovalAdmission, bool, error) {
	var raw []byte
	var fenceID FenceID
	err := queryer.QueryRowContext(ctx, `SELECT admission_json,fence_id FROM ha_promotion_approvals WHERE `+predicate, argument).Scan(&raw, &fenceID)
	if errors.Is(err, sql.ErrNoRows) { return PromotionApprovalAdmission{}, false, nil }
	if err != nil { return PromotionApprovalAdmission{}, false, err }
	var admission PromotionApprovalAdmission
	if decode(raw, &admission) != nil || admission.FenceID != "" { return PromotionApprovalAdmission{}, false, ErrInvalid }
	admission.FenceID = fenceID
	return admission, true, nil
}

func samePromotionApprovalAdmission(left, right PromotionApprovalAdmission) bool {
	return left.CommandID == right.CommandID && left.IdempotencyKey == right.IdempotencyKey && samePromotionApproval(left.Approval, right.Approval)
}

func samePromotionApprovals(left, right []Approval) bool {
	if len(left) != len(right) { return false }
	for index := range left { if !samePromotionApproval(left[index], right[index]) { return false } }
	return true
}

func samePromotionApproval(left, right Approval) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.PromotionID == right.PromotionID && left.GroupID == right.GroupID && left.ActorID == right.ActorID && left.CredentialID == right.CredentialID && left.SessionID == right.SessionID && left.AuthzEpoch == right.AuthzEpoch && left.TenantAuthzEpoch == right.TenantAuthzEpoch && left.PromotionGeneration == right.PromotionGeneration && left.Kind == right.Kind && left.PlanDigest == right.PlanDigest && left.FenceChallenge == right.FenceChallenge && left.PhishingResistant == right.PhishingResistant && left.IssuedAt.Equal(right.IssuedAt) && left.ExpiresAt.Equal(right.ExpiresAt) && left.Signature == right.Signature
}
func (r SQLRepository) CreateFailoverRun(ctx context.Context,v FailoverRun)error{b,e:=encode(v);if e!=nil{return e};_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_failover_runs (id,promotion_id,state,step,run_json,updated_at) VALUES (?,?,?,?,?,?)`,v.ID,v.PromotionID,v.State,v.Step,b,v.UpdatedAt);return e}
func (r SQLRepository) LoadFailoverRun(ctx context.Context,id FailoverRunID)(FailoverRun,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT run_json FROM ha_failover_runs WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return FailoverRun{},ErrNotFound};if e!=nil{return FailoverRun{},e};var v FailoverRun;e=decode(b,&v);return v,e}
func (r SQLRepository) UpdateFailoverRun(ctx context.Context,v FailoverRun)error{b,e:=encode(v);if e!=nil{return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_failover_runs SET state=?,step=?,run_json=?,updated_at=? WHERE id=?`,v.State,v.Step,b,v.UpdatedAt,v.ID);if e!=nil{return e};return one(x)}
func (r SQLRepository) SaveBackupCopy(ctx context.Context,v BackupReplicaCopy)error{if !validDigest(v.ManifestDigest)||v.CommitMarker==""||v.VerifiedAt.IsZero(){return ErrInvalid};b,e:=encode(v);if e!=nil{return e};_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_backup_copies (id,recovery_point_id,target_node_id,manifest_digest,copy_json,verified_at) VALUES (?,?,?,?,?,?)`,v.ID,v.RecoveryPointID,v.TargetNodeID,v.ManifestDigest,b,v.VerifiedAt);return e}
func (r SQLRepository) SaveMailTopology(ctx context.Context,v MailTopology,g uint64)error{if e:=v.Validate();e!=nil{return e};b,e:=encode(v);if e!=nil{return e};if g==0{_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_mail_topologies (id,group_id,writer_node_id,generation,topology_json,updated_at) VALUES (?,?,?,?,?,?)`,v.ID,v.GroupID,v.MailboxWriterNodeID,v.Generation,b,v.UpdatedAt);return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_mail_topologies SET writer_node_id=?,generation=?,topology_json=?,updated_at=? WHERE id=? AND generation=?`,v.MailboxWriterNodeID,v.Generation,b,v.UpdatedAt,v.ID,g);if e!=nil{return e};return cas(x)}
func (r SQLRepository) LoadMailTopology(ctx context.Context,id ID)(MailTopology,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT topology_json FROM ha_mail_topologies WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return MailTopology{},ErrNotFound};if e!=nil{return MailTopology{},e};var v MailTopology;e=decode(b,&v);return v,e}
func (r SQLRepository) SaveDNSTopology(ctx context.Context,v DNSTopology,g uint64)error{b,e:=encode(v);if e!=nil{return e};if g==0{_,e=r.DB.ExecContext(ctx,`INSERT INTO ha_dns_topologies (id,group_id,primary_node_id,generation,topology_json,updated_at) VALUES (?,?,?,?,?,?)`,v.ID,v.GroupID,v.PrimaryNodeID,v.Generation,b,v.UpdatedAt);return e};x,e:=r.DB.ExecContext(ctx,`UPDATE ha_dns_topologies SET primary_node_id=?,generation=?,topology_json=?,updated_at=? WHERE id=? AND generation=?`,v.PrimaryNodeID,v.Generation,b,v.UpdatedAt,v.ID,g);if e!=nil{return e};return cas(x)}
func (r SQLRepository) LoadDNSTopology(ctx context.Context,id ID)(DNSTopology,error){var b []byte;e:=r.DB.QueryRowContext(ctx,`SELECT topology_json FROM ha_dns_topologies WHERE id=?`,id).Scan(&b);if errors.Is(e,sql.ErrNoRows){return DNSTopology{},ErrNotFound};if e!=nil{return DNSTopology{},e};var v DNSTopology;e=decode(b,&v);return v,e}

func sameEnrollmentGroup(left,right NodeGroup)bool{
	if left.ID!=right.ID||left.Name!=right.Name||left.CoordinatorID!=right.CoordinatorID||left.MinimumManagers!=right.MinimumManagers||left.AutomaticFailover!=right.AutomaticFailover{return false}
	leftFences:=sortedIDs(left.RequiredFenceClasses);rightFences:=sortedIDs(right.RequiredFenceClasses)
	if len(leftFences)!=len(rightFences){return false}
	for index:=range leftFences{if leftFences[index]!=rightFences[index]{return false}}
	return true
}

const (
	writerAuthorityFailureFence      = "fence_required"
	writerAuthorityFailureSplitBrain = "split_brain"
	writerAuthorityFailureEvidence   = "caught_up_evidence_required"
)

func (r SQLRepository) DemoteWriter(ctx context.Context,operation WriterAuthorityOperation,now time.Time)(WriterAuthorityReceipt,error){operation.Kind=WriterAuthorityDemote;return r.applyWriterAuthorityOperation(ctx,operation,now)}
func (r SQLRepository) ReconcileWriter(ctx context.Context,operation WriterAuthorityOperation,now time.Time)(WriterAuthorityReceipt,error){operation.Kind=WriterAuthorityReconcile;return r.applyWriterAuthorityOperation(ctx,operation,now)}
func (r SQLRepository) FailbackWriter(ctx context.Context,operation WriterAuthorityOperation,now time.Time)(WriterAuthorityReceipt,error){operation.Kind=WriterAuthorityFailback;return r.applyWriterAuthorityOperation(ctx,operation,now)}

func (r SQLRepository) applyWriterAuthorityOperation(ctx context.Context,operation WriterAuthorityOperation,now time.Time)(WriterAuthorityReceipt,error){
	if r.DB==nil||ctx==nil||now.IsZero(){return WriterAuthorityReceipt{},ErrInvalid}
	now=now.UTC()
	if err:=operation.Validate();err!=nil{return WriterAuthorityReceipt{},err}
	tx,err:=r.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable})
	if err!=nil{return WriterAuthorityReceipt{},err}
	defer tx.Rollback()
	if receipt,found,err:=loadWriterAuthorityReceipt(ctx,tx,operation);err!=nil{return WriterAuthorityReceipt{},err}else if found{
		if err=tx.Commit();err!=nil{return WriterAuthorityReceipt{},err}
		return receipt,writerAuthorityReceiptError(receipt)
	}
	authority,err:=loadLocalWriterAuthority(ctx,tx,operation)
	if err!=nil{return WriterAuthorityReceipt{},err}
	if authority.Generation!=operation.ExpectedGeneration{return WriterAuthorityReceipt{},ErrStaleGeneration}
	if authority.WriterNodeID!=operation.PreviousWriterNodeID{
		return finishUncertainWriterAuthority(ctx,tx,authority,operation,now,writerAuthorityFailureSplitBrain,ErrSplitBrainRisk)
	}
	if err=revokePreviousWriterLease(ctx,tx,operation,now);err!=nil{
		return finishUncertainWriterAuthority(ctx,tx,authority,operation,now,writerAuthorityFailureSplitBrain,ErrSplitBrainRisk)
	}
	fence,err:=loadWriterFenceProof(ctx,tx,authority,operation,now)
	if err!=nil{return finishUncertainWriterAuthority(ctx,tx,authority,operation,now,writerAuthorityFailureFence,ErrFenceRequired)}
	if operation.Kind==WriterAuthorityFailback{
		if err=loadFailbackEvidence(ctx,tx,authority,operation,fence,now);err!=nil{return finishUncertainWriterAuthority(ctx,tx,authority,operation,now,writerAuthorityFailureEvidence,ErrCheckpointStale)}
	}
	active,err:=activeWriterLeases(ctx,tx,operation.ResourceID,now)
	if err!=nil{return WriterAuthorityReceipt{},err}
	if len(active)!=1||active[0].ID!=operation.WriterLeaseID||active[0].HolderNodeID!=operation.WriterNodeID||active[0].GroupID!=operation.GroupID||active[0].FencingToken<=authority.FencingToken||active[0].FencingToken!=fence.FencingToken||active[0].AuthorityEpoch!=fence.AuthorityEpoch{
		return finishUncertainWriterAuthority(ctx,tx,authority,operation,now,writerAuthorityFailureSplitBrain,ErrSplitBrainRisk)
	}
	authority.WriterNodeID=active[0].HolderNodeID
	authority.State=LocalWriterActive
	authority.FencingToken=active[0].FencingToken
	authority.AuthorityEpoch=active[0].AuthorityEpoch
	authority.Generation++
	authority.FenceUncertain=false
	authority.LastFenceID=fence.ID
	if operation.Kind==WriterAuthorityFailback{authority.LastEvidenceID=operation.EvidenceID}
	authority.UpdatedAt=now
	if err=updateLocalWriterAuthority(ctx,tx,authority,operation.ExpectedGeneration);err!=nil{return WriterAuthorityReceipt{},err}
	receipt:=WriterAuthorityReceipt{OperationID:operation.OperationID,OperationDigest:operation.OperationDigest,Kind:operation.Kind,TenantID:operation.TenantID,GroupID:operation.GroupID,ResourceID:operation.ResourceID,PreviousGeneration:operation.ExpectedGeneration,Generation:authority.Generation,WriterNodeID:authority.WriterNodeID,WriterLeaseID:active[0].ID,FenceID:fence.ID,EvidenceID:authority.LastEvidenceID,State:authority.State,CompletedAt:now}
	if err=insertWriterAuthorityOperation(ctx,tx,operation,receipt);err!=nil{return WriterAuthorityReceipt{},err}
	if err=tx.Commit();err!=nil{return WriterAuthorityReceipt{},err}
	return receipt,nil
}

func loadWriterAuthorityReceipt(ctx context.Context,tx *sql.Tx,operation WriterAuthorityOperation)(WriterAuthorityReceipt,bool,error){
	var digest string
	var raw []byte
	err:=tx.QueryRowContext(ctx,`SELECT operation_digest,receipt_json FROM ha_local_operations WHERE operation_id=?`,operation.OperationID).Scan(&digest,&raw)
	if errors.Is(err,sql.ErrNoRows){return WriterAuthorityReceipt{},false,nil}
	if err!=nil{return WriterAuthorityReceipt{},false,err}
	if digest!=operation.OperationDigest{return WriterAuthorityReceipt{},false,ErrConflict}
	var receipt WriterAuthorityReceipt
	if err=decode(raw,&receipt);err!=nil{return WriterAuthorityReceipt{},false,err}
	if receipt.OperationID!=operation.OperationID||receipt.OperationDigest!=operation.OperationDigest{return WriterAuthorityReceipt{},false,ErrConflict}
	return receipt,true,nil
}

func loadLocalWriterAuthority(ctx context.Context,tx *sql.Tx,operation WriterAuthorityOperation)(LocalWriterAuthority,error){
	var authority LocalWriterAuthority
	var raw []byte
	err:=tx.QueryRowContext(ctx,`SELECT authority_json FROM ha_local_workload_authority WHERE tenant_id=? AND group_id=? AND resource_id=?`,operation.TenantID,operation.GroupID,operation.ResourceID).Scan(&raw)
	if errors.Is(err,sql.ErrNoRows){return LocalWriterAuthority{},ErrNotFound}
	if err!=nil{return LocalWriterAuthority{},err}
	if err=decode(raw,&authority);err!=nil{return LocalWriterAuthority{},err}
	if err=authority.Validate();err!=nil{return LocalWriterAuthority{},err}
	if authority.TenantID!=operation.TenantID||authority.GroupID!=operation.GroupID||authority.ResourceID!=operation.ResourceID{return LocalWriterAuthority{},ErrConflict}
	return authority,nil
}

func revokePreviousWriterLease(ctx context.Context,tx *sql.Tx,operation WriterAuthorityOperation,now time.Time)error{
	var raw []byte
	err:=tx.QueryRowContext(ctx,`SELECT lease_json FROM ha_writer_leases WHERE id=?`,operation.PreviousWriterLeaseID).Scan(&raw)
	if errors.Is(err,sql.ErrNoRows){return ErrLeaseLost}
	if err!=nil{return err}
	var lease WriterLease
	if err=decode(raw,&lease);err!=nil{return err}
	if lease.ID!=operation.PreviousWriterLeaseID||lease.GroupID!=operation.GroupID||lease.ResourceID!=operation.ResourceID||lease.HolderNodeID!=operation.PreviousWriterNodeID{return ErrConflict}
	if lease.State!=LeaseActive{
		if lease.State==LeaseRevoked||lease.State==LeaseExpired||lease.State==LeaseLost{return nil}
		return ErrConflict
	}
	previousGeneration:=lease.Generation
	if now.Before(lease.ExpiresAt){lease.State=LeaseRevoked}else{lease.State=LeaseExpired}
	lease.Generation++
	payload,err:=encode(lease)
	if err!=nil{return err}
	result,err:=tx.ExecContext(ctx,`UPDATE ha_writer_leases SET state=?,generation=?,lease_json=? WHERE id=? AND generation=? AND state='active'`,lease.State,lease.Generation,payload,lease.ID,previousGeneration)
	if err!=nil{return err}
	return cas(result)
}

func loadWriterFenceProof(ctx context.Context,tx *sql.Tx,authority LocalWriterAuthority,operation WriterAuthorityOperation,now time.Time)(Fence,error){
	if authority.LastFenceID==operation.FenceID{return Fence{},ErrFenceRequired}
	var raw []byte
	err:=tx.QueryRowContext(ctx,`SELECT fence_json FROM ha_fences WHERE id=?`,operation.FenceID).Scan(&raw)
	if errors.Is(err,sql.ErrNoRows){return Fence{},ErrFenceRequired}
	if err!=nil{return Fence{},err}
	var fence Fence
	if err=decode(raw,&fence);err!=nil{return Fence{},err}
	if err=fence.Validate(now);err!=nil{return Fence{},err}
	if fence.State!=FenceProven||fence.GroupID!=operation.GroupID||fence.TargetNodeID!=operation.PreviousWriterNodeID||fence.ProviderReceipt==""||!now.Before(fence.ValidUntil){return Fence{},ErrFenceRequired}
	return fence,nil
}

func loadFailbackEvidence(ctx context.Context,tx *sql.Tx,authority LocalWriterAuthority,operation WriterAuthorityOperation,fence Fence,now time.Time)error{
	if authority.LastEvidenceID==operation.EvidenceID{return ErrCheckpointStale}
	var raw []byte
	err:=tx.QueryRowContext(ctx,`SELECT evidence_json FROM ha_local_replication_evidence WHERE evidence_id=?`,operation.EvidenceID).Scan(&raw)
	if errors.Is(err,sql.ErrNoRows){return ErrCheckpointStale}
	if err!=nil{return err}
	var evidence LocalReplicationEvidence
	if err=decode(raw,&evidence);err!=nil{return err}
	if err=evidence.Validate();err!=nil{return err}
	if !evidence.Usable(now)||evidence.TenantID!=operation.TenantID||evidence.GroupID!=operation.GroupID||evidence.ResourceID!=operation.ResourceID||evidence.SourceNodeID!=operation.PreviousWriterNodeID||evidence.TargetNodeID!=operation.WriterNodeID||evidence.EvidenceID!=ID(operation.EvidenceID)||fence.AppliedAt.Before(evidence.ObservedAt){return ErrCheckpointStale}
	var bindingRaw []byte
	err=tx.QueryRowContext(ctx,`SELECT binding_json FROM ha_local_channel_bindings WHERE channel_id=?`,evidence.ChannelID).Scan(&bindingRaw)
	if errors.Is(err,sql.ErrNoRows){return ErrCheckpointStale}
	if err!=nil{return err}
	var binding LocalChannelBinding
	if err=decode(bindingRaw,&binding);err!=nil{return err}
	if err=binding.Validate();err!=nil{return err}
	if binding.Generation!=evidence.BindingGeneration||binding.TenantID!=operation.TenantID||binding.GroupID!=operation.GroupID||binding.ResourceID!=operation.ResourceID||binding.SourceNodeID!=operation.PreviousWriterNodeID||binding.TargetNodeID!=operation.WriterNodeID{return ErrCheckpointStale}
	return nil
}

func activeWriterLeases(ctx context.Context,tx *sql.Tx,resourceID string,now time.Time)([]WriterLease,error){
	rows,err:=tx.QueryContext(ctx,`SELECT lease_json FROM ha_writer_leases WHERE resource_id=? AND state='active' ORDER BY authority_epoch,fencing_token,id`,resourceID)
	if err!=nil{return nil,err}
	var leases []WriterLease
	for rows.Next(){var raw []byte;if err=rows.Scan(&raw);err!=nil{rows.Close();return nil,err};var lease WriterLease;if err=decode(raw,&lease);err!=nil{rows.Close();return nil,err};leases=append(leases,lease)}
	if err=rows.Close();err!=nil{return nil,err}
	if err=rows.Err();err!=nil{return nil,err}
	active:=make([]WriterLease,0,len(leases))
	for _,lease:=range leases{
		if now.Before(lease.ExpiresAt){if err=lease.Validate(now);err!=nil{return nil,err};active=append(active,lease);continue}
		previousGeneration:=lease.Generation
		lease.State=LeaseExpired
		lease.Generation++
		payload,encodeErr:=encode(lease)
		if encodeErr!=nil{return nil,encodeErr}
		result,updateErr:=tx.ExecContext(ctx,`UPDATE ha_writer_leases SET state=?,generation=?,lease_json=? WHERE id=? AND generation=? AND state='active'`,lease.State,lease.Generation,payload,lease.ID,previousGeneration)
		if updateErr!=nil{return nil,updateErr}
		if updateErr=cas(result);updateErr!=nil{return nil,updateErr}
	}
	return active,nil
}

func finishUncertainWriterAuthority(ctx context.Context,tx *sql.Tx,authority LocalWriterAuthority,operation WriterAuthorityOperation,now time.Time,failure string,reason error)(WriterAuthorityReceipt,error){
	authority.State=LocalWriterUncertain
	authority.FenceUncertain=true
	authority.Generation++
	authority.UpdatedAt=now
	if err:=updateLocalWriterAuthority(ctx,tx,authority,operation.ExpectedGeneration);err!=nil{return WriterAuthorityReceipt{},err}
	receipt:=WriterAuthorityReceipt{OperationID:operation.OperationID,OperationDigest:operation.OperationDigest,Kind:operation.Kind,TenantID:operation.TenantID,GroupID:operation.GroupID,ResourceID:operation.ResourceID,PreviousGeneration:operation.ExpectedGeneration,Generation:authority.Generation,WriterNodeID:authority.WriterNodeID,WriterLeaseID:operation.PreviousWriterLeaseID,State:authority.State,Failure:failure,CompletedAt:now}
	if err:=insertWriterAuthorityOperation(ctx,tx,operation,receipt);err!=nil{return WriterAuthorityReceipt{},err}
	if err:=tx.Commit();err!=nil{return WriterAuthorityReceipt{},err}
	return receipt,reason
}

func updateLocalWriterAuthority(ctx context.Context,tx *sql.Tx,authority LocalWriterAuthority,expectedGeneration uint64)error{
	payload,err:=encode(authority)
	if err!=nil{return err}
	result,err:=tx.ExecContext(ctx,`UPDATE ha_local_workload_authority SET writer_node_id=?,state=?,fencing_token=?,authority_epoch=?,generation=?,fence_uncertain=?,authority_json=?,updated_at=? WHERE tenant_id=? AND group_id=? AND resource_id=? AND generation=?`,authority.WriterNodeID,authority.State,authority.FencingToken,authority.AuthorityEpoch,authority.Generation,authority.FenceUncertain,payload,authority.UpdatedAt,authority.TenantID,authority.GroupID,authority.ResourceID,expectedGeneration)
	if err!=nil{return err}
	return cas(result)
}

func insertWriterAuthorityOperation(ctx context.Context,tx *sql.Tx,operation WriterAuthorityOperation,receipt WriterAuthorityReceipt)error{
	payload,err:=encode(receipt)
	if err!=nil{return err}
	_,err=tx.ExecContext(ctx,`INSERT INTO ha_local_operations (operation_id,kind,tenant_id,group_id,resource_id,expected_generation,operation_digest,state,receipt_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,operation.OperationID,operation.Kind,operation.TenantID,operation.GroupID,operation.ResourceID,operation.ExpectedGeneration,operation.OperationDigest,receipt.State,payload,operation.RequestedAt,receipt.CompletedAt)
	return err
}

func writerAuthorityReceiptError(receipt WriterAuthorityReceipt)error{
	switch receipt.Failure{case writerAuthorityFailureFence:return ErrFenceRequired;case writerAuthorityFailureEvidence:return ErrCheckpointStale;case writerAuthorityFailureSplitBrain:return ErrSplitBrainRisk;default:return nil}
}
