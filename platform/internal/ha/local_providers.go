package ha

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	LocalMariaDBResourceID          = "mariadb-local"
	LocalOLSListenerTrafficKind    = "local_ols_lse_listener"
	LocalOLSListenerProviderBinding = "local-webengine"
)

const localLeaseAuthoritySchema = `
CREATE TABLE IF NOT EXISTS ha_local_lease_authority_v1(
 lease_id TEXT PRIMARY KEY,
 group_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 holder_node_id TEXT NOT NULL,
 fencing_token INTEGER NOT NULL,
 authority_epoch INTEGER NOT NULL,
 quorum_digest TEXT NOT NULL,
 state TEXT NOT NULL,
 lease_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ha_local_lease_authority_one_active
 ON ha_local_lease_authority_v1(resource_id) WHERE state='active';
`

// LocalSQLLeaseAuthority is a durable, quorum-bound authority distinct from
// the orchestration projection in ha_writer_leases. The coordinator persists
// that projection only after this authority has issued or revoked the lease.
type LocalSQLLeaseAuthority struct {
	db  *sql.DB
	now func() time.Time
}

func NewLocalSQLLeaseAuthority(ctx context.Context, repository *SQLRepository, now func() time.Time) (*LocalSQLLeaseAuthority, error) {
	if ctx == nil || repository == nil || repository.DB == nil { return nil, ErrInvalid }
	if now == nil { now = time.Now }
	authority := &LocalSQLLeaseAuthority{db:repository.DB, now:now}
	if _, err := authority.db.ExecContext(ctx, localLeaseAuthoritySchema); err != nil { return nil, err }
	return authority, nil
}

func (authority *LocalSQLLeaseAuthority) AcquireWriterLease(ctx context.Context, proposed WriterLease, quorum QuorumObservation) (WriterLease, error) {
	now := authority.current()
	if authority == nil || authority.db == nil || ctx == nil || proposed.State != LeasePending || proposed.Generation != 1 || proposed.ResourceID != LocalMariaDBResourceID || proposed.GroupID != quorum.GroupID || proposed.AuthorityEpoch != quorum.Epoch || proposed.QuorumDigest != quorum.Digest || quorum.Validate(now) != nil || proposed.Validate(now) != nil || !now.Before(proposed.ExpiresAt) {
		return WriterLease{}, ErrNoQuorum
	}
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil { return WriterLease{}, err }
	defer tx.Rollback()
	if existing, found, loadErr := loadAuthorityLease(ctx, tx, proposed.ID); loadErr != nil { return WriterLease{}, loadErr } else if found {
		if !sameAuthorityLease(existing, proposed) || existing.State != LeaseActive || !now.Before(existing.ExpiresAt) { return WriterLease{}, ErrConflict }
		if err = tx.Commit(); err != nil { return WriterLease{}, err }
		return existing, nil
	}
	if err = expireAuthorityLeases(ctx, tx, proposed.ResourceID, now); err != nil { return WriterLease{}, err }
	var activeID string
	if err = tx.QueryRowContext(ctx, `SELECT lease_id FROM ha_local_lease_authority_v1 WHERE resource_id=? AND state='active'`, proposed.ResourceID).Scan(&activeID); err == nil {
		return WriterLease{}, ErrConflict
	} else if !errors.Is(err, sql.ErrNoRows) { return WriterLease{}, err }
	active := proposed
	active.State = LeaseActive
	payload, err := json.Marshal(active)
	if err != nil { return WriterLease{}, err }
	_, err = tx.ExecContext(ctx, `INSERT INTO ha_local_lease_authority_v1(lease_id,group_id,resource_id,holder_node_id,fencing_token,authority_epoch,quorum_digest,state,lease_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, active.ID, active.GroupID, active.ResourceID, active.HolderNodeID, active.FencingToken, active.AuthorityEpoch, active.QuorumDigest, active.State, payload, now)
	if err != nil { return WriterLease{}, err }
	if err = tx.Commit(); err != nil { return WriterLease{}, err }
	return active, nil
}

func (authority *LocalSQLLeaseAuthority) RenewWriterLease(ctx context.Context, lease WriterLease, quorum QuorumObservation) (WriterLease, error) {
	now := authority.current()
	if authority == nil || authority.db == nil || ctx == nil || lease.State != LeaseActive || lease.ResourceID != LocalMariaDBResourceID || lease.GroupID != quorum.GroupID || lease.AuthorityEpoch != quorum.Epoch || lease.QuorumDigest != quorum.Digest || quorum.Validate(now) != nil || lease.Validate(now) != nil {
		return WriterLease{}, ErrLeaseLost
	}
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil { return WriterLease{}, err }
	defer tx.Rollback()
	stored, found, err := loadAuthorityLease(ctx, tx, lease.ID)
	if err != nil { return WriterLease{}, err }
	if !found || stored.State != LeaseActive || !sameAuthorityLease(stored, lease) || !now.Before(stored.ExpiresAt) { return WriterLease{}, ErrLeaseLost }
	lifetime := stored.ExpiresAt.Sub(stored.IssuedAt)
	if lifetime <= 0 || lifetime > 24*time.Hour { return WriterLease{}, ErrInvalid }
	stored.RenewAfter = now.Add(lifetime / 2)
	stored.ExpiresAt = now.Add(lifetime)
	payload, err := json.Marshal(stored)
	if err != nil { return WriterLease{}, err }
	result, err := tx.ExecContext(ctx, `UPDATE ha_local_lease_authority_v1 SET lease_json=?,updated_at=? WHERE lease_id=? AND state='active' AND fencing_token=? AND authority_epoch=?`, payload, now, stored.ID, stored.FencingToken, stored.AuthorityEpoch)
	if err != nil { return WriterLease{}, err }
	if changed, countErr := result.RowsAffected(); countErr != nil || changed != 1 { return WriterLease{}, errors.Join(countErr, ErrLeaseLost) }
	if err = tx.Commit(); err != nil { return WriterLease{}, err }
	return stored, nil
}

func (authority *LocalSQLLeaseAuthority) RevokeWriterLease(ctx context.Context, id WriterLeaseID, fencingToken, authorityEpoch uint64) error {
	if authority == nil || authority.db == nil || ctx == nil || !validID(string(id)) || fencingToken == 0 || authorityEpoch == 0 { return ErrInvalid }
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	lease, found, err := loadAuthorityLease(ctx, tx, id)
	if err != nil { return err }
	if !found { return ErrNotFound }
	if lease.FencingToken != fencingToken || lease.AuthorityEpoch != authorityEpoch { return ErrLeaseLost }
	if lease.State == LeaseRevoked || lease.State == LeaseExpired || lease.State == LeaseLost { return tx.Commit() }
	if lease.State != LeaseActive { return ErrLeaseLost }
	lease.State = LeaseRevoked
	lease.Generation++
	payload, err := json.Marshal(lease)
	if err != nil { return err }
	result, err := tx.ExecContext(ctx, `UPDATE ha_local_lease_authority_v1 SET state=?,lease_json=?,updated_at=? WHERE lease_id=? AND state='active' AND fencing_token=? AND authority_epoch=?`, lease.State, payload, authority.current(), id, fencingToken, authorityEpoch)
	if err != nil { return err }
	if changed, countErr := result.RowsAffected(); countErr != nil || changed != 1 { return errors.Join(countErr, ErrLeaseLost) }
	return tx.Commit()
}

func (authority *LocalSQLLeaseAuthority) ObserveWriterLease(ctx context.Context, id WriterLeaseID) (WriterLease, error) {
	if authority == nil || authority.db == nil || ctx == nil || !validID(string(id)) { return WriterLease{}, ErrInvalid }
	tx, err := authority.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil { return WriterLease{}, err }
	defer tx.Rollback()
	lease, found, err := loadAuthorityLease(ctx, tx, id)
	if err != nil { return WriterLease{}, err }
	if !found { return WriterLease{}, ErrNotFound }
	now := authority.current()
	if lease.State == LeaseActive && !now.Before(lease.ExpiresAt) {
		lease.State = LeaseExpired
		lease.Generation++
		if err = updateAuthorityLease(ctx, tx, lease, now, LeaseActive); err != nil { return WriterLease{}, err }
	}
	if err = tx.Commit(); err != nil { return WriterLease{}, err }
	return lease, nil
}

func (authority *LocalSQLLeaseAuthority) current() time.Time {
	if authority != nil && authority.now != nil { return authority.now().UTC() }
	return time.Now().UTC()
}

func loadAuthorityLease(ctx context.Context, tx *sql.Tx, id WriterLeaseID) (WriterLease, bool, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT lease_json FROM ha_local_lease_authority_v1 WHERE lease_id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) { return WriterLease{}, false, nil }
	if err != nil { return WriterLease{}, false, err }
	var lease WriterLease
	if json.Unmarshal(raw, &lease) != nil || lease.ID != id { return WriterLease{}, false, ErrInvalid }
	return lease, true, nil
}

func expireAuthorityLeases(ctx context.Context, tx *sql.Tx, resource string, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT lease_json FROM ha_local_lease_authority_v1 WHERE resource_id=? AND state='active'`, resource)
	if err != nil { return err }
	var expired []WriterLease
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil { rows.Close(); return err }
		var lease WriterLease
		if json.Unmarshal(raw, &lease) != nil { rows.Close(); return ErrInvalid }
		if !now.Before(lease.ExpiresAt) { lease.State=LeaseExpired; lease.Generation++; expired=append(expired,lease) }
	}
	if err = rows.Err(); err != nil { rows.Close(); return err }
	if err = rows.Close(); err != nil { return err }
	for _, lease := range expired { if err = updateAuthorityLease(ctx, tx, lease, now, LeaseActive); err != nil { return err } }
	return nil
}

func updateAuthorityLease(ctx context.Context, tx *sql.Tx, lease WriterLease, now time.Time, previous LeaseState) error {
	payload, err := json.Marshal(lease)
	if err != nil { return err }
	result, err := tx.ExecContext(ctx, `UPDATE ha_local_lease_authority_v1 SET state=?,lease_json=?,updated_at=? WHERE lease_id=? AND state=?`, lease.State, payload, now, lease.ID, previous)
	if err != nil { return err }
	changed, err := result.RowsAffected()
	if err != nil { return err }
	if changed != 1 { return ErrLeaseLost }
	return nil
}

func sameAuthorityLease(actual, proposed WriterLease) bool {
	return actual.ID==proposed.ID && actual.GroupID==proposed.GroupID && actual.ResourceID==proposed.ResourceID && actual.HolderNodeID==proposed.HolderNodeID && actual.FencingToken==proposed.FencingToken && actual.AuthorityEpoch==proposed.AuthorityEpoch && actual.QuorumDigest==proposed.QuorumDigest && actual.IssuedAt.Equal(proposed.IssuedAt) && actual.RenewAfter.Equal(proposed.RenewAfter) && actual.ExpiresAt.Equal(proposed.ExpiresAt) && sameProtectedWritePaths(actual.EnforcedWritePaths,proposed.EnforcedWritePaths)
}

// LocalMariaDBWriterGate maps the generic writer-gate contract only onto the
// typed MariaDB replication executor and its protected permit signer.
type LocalMariaDBWriterGate struct {
	Store    Store
	Executor DatabaseReplicationExecutor
	Signer   WritePermitSigner
	Now      func() time.Time
}

func NewLocalMariaDBWriterGate(store Store, executor DatabaseReplicationExecutor, signer WritePermitSigner, now func() time.Time) (*LocalMariaDBWriterGate, error) {
	if store == nil || executor == nil || signer == nil { return nil, ErrInvalid }
	if now == nil { now = time.Now }
	return &LocalMariaDBWriterGate{Store:store, Executor:executor, Signer:signer, Now:now}, nil
}

func (gate *LocalMariaDBWriterGate) FreezeResourceWrites(ctx context.Context, resource string, node NodeID, fencingToken uint64, paths []string) (string, error) {
	cluster, err := localMariaDBCluster(ctx, gate.Store, resource)
	if err != nil || !validID(string(node)) || fencingToken == 0 || len(paths) == 0 { return "", errors.Join(err, ErrInvalid) }
	receipt, err := gate.Executor.FreezeDatabaseWrites(ctx, cluster, node, fencingToken)
	if err != nil || receipt == "" { return receipt, errors.Join(err, ErrProviderAmbiguous) }
	observed, err := gate.Executor.ObserveCluster(ctx, cluster)
	member, memberErr := requiredDatabaseMember(observed, node)
	if err != nil || memberErr != nil || !member.ReadOnly { return receipt, errors.Join(err, memberErr, ErrSplitBrainRisk) }
	return localProviderReceipt("freeze_mariadb_writes", resource, node, fencingToken, member.Sequence, receipt, gate.current())
}

func (gate *LocalMariaDBWriterGate) ActivateResourceWrites(ctx context.Context, lease WriterLease) (WritePermit, error) {
	now := gate.current()
	if lease.State != LeaseActive || lease.ResourceID != LocalMariaDBResourceID || lease.Validate(now) != nil { return WritePermit{}, ErrLeaseLost }
	cluster, err := localMariaDBCluster(ctx, gate.Store, lease.ResourceID)
	if err != nil || cluster.GroupID != lease.GroupID { return WritePermit{}, errors.Join(err, ErrConflict) }
	receipt, frontier, err := gate.Executor.PromoteDatabaseWriter(ctx, cluster, lease.HolderNodeID, lease)
	if err != nil || receipt == "" || frontier == 0 { return WritePermit{}, errors.Join(err, ErrIrreversibleFrontier) }
	observed, err := gate.Executor.ObserveCluster(ctx, cluster)
	member, memberErr := requiredDatabaseMember(observed, lease.HolderNodeID)
	if err != nil || memberErr != nil || member.ReadOnly || member.Sequence < frontier || observed.WriterNodeID != lease.HolderNodeID { return WritePermit{}, errors.Join(err, memberErr, ErrSplitBrainRisk) }
	paths := append([]string(nil), lease.EnforcedWritePaths...)
	sort.Strings(paths)
	permit := WritePermit{ResourceID:lease.ResourceID, NodeID:lease.HolderNodeID, LeaseID:lease.ID, FencingToken:lease.FencingToken, AuthorityEpoch:lease.AuthorityEpoch, WritePaths:paths, IssuedAt:now, ExpiresAt:lease.ExpiresAt}
	permit, err = gate.Signer.SignWritePermit(ctx, permit)
	if err != nil || permit.Signature == "" { return WritePermit{}, errors.Join(err, ErrLeaseLost) }
	return permit, nil
}

func (gate *LocalMariaDBWriterGate) RevokeWritePermit(ctx context.Context, permit WritePermit) error {
	if permit.ResourceID != LocalMariaDBResourceID || permit.Signature == "" || permit.FencingToken == 0 { return ErrInvalid }
	cluster, err := localMariaDBCluster(ctx, gate.Store, permit.ResourceID)
	if err != nil { return err }
	receipt, err := gate.Executor.FreezeDatabaseWrites(ctx, cluster, permit.NodeID, permit.FencingToken)
	if err != nil || receipt == "" { return errors.Join(err, ErrSplitBrainRisk) }
	return nil
}

func (gate *LocalMariaDBWriterGate) current() time.Time { if gate != nil && gate.Now != nil { return gate.Now().UTC() }; return time.Now().UTC() }

type LocalMariaDBPromotionExecutor struct {
	Store    Store
	Database DatabaseReplicationExecutor
	Now      func() time.Time
}

func NewLocalMariaDBPromotionExecutor(store Store, database DatabaseReplicationExecutor, now func() time.Time) (*LocalMariaDBPromotionExecutor, error) {
	if store == nil || database == nil { return nil, ErrInvalid }
	if now == nil { now = time.Now }
	return &LocalMariaDBPromotionExecutor{Store:store, Database:database, Now:now}, nil
}

func (executor *LocalMariaDBPromotionExecutor) FreezeWorkloadWrites(ctx context.Context, promotion Promotion, fencingToken uint64) (string, error) {
	cluster, err := localMariaDBCluster(ctx, executor.Store, promotion.ResourceID)
	if err != nil { return "", err }
	receipt, err := executor.Database.FreezeDatabaseWrites(ctx, cluster, promotion.PreviousWriter, fencingToken)
	if err != nil || receipt == "" { return receipt, errors.Join(err, ErrSplitBrainRisk) }
	return localProviderReceipt("freeze_mariadb_workload", promotion.ResourceID, promotion.PreviousWriter, fencingToken, promotion.CheckpointFrontier, receipt, executor.current())
}

func (executor *LocalMariaDBPromotionExecutor) ActivateCandidateServices(ctx context.Context, promotion Promotion, lease WriterLease) (string, uint64, error) {
	cluster, err := localMariaDBCluster(ctx, executor.Store, promotion.ResourceID)
	if err != nil || lease.State != LeaseActive || lease.ID != promotion.LeaseID || lease.HolderNodeID != promotion.Candidate || lease.ResourceID != promotion.ResourceID { return "", 0, errors.Join(err, ErrLeaseLost) }
	observed, err := executor.Database.ObserveCluster(ctx, cluster)
	member, memberErr := requiredDatabaseMember(observed, promotion.Candidate)
	if err != nil || memberErr != nil || member.ReadOnly || observed.WriterNodeID != promotion.Candidate || member.Sequence < promotion.CheckpointFrontier {
		return "", member.Sequence, errors.Join(err, memberErr, ErrIrreversibleFrontier)
	}
	receipt, err := localProviderReceipt("activate_mariadb_candidate", promotion.ResourceID, promotion.Candidate, lease.FencingToken, member.Sequence, member.GTID, executor.current())
	return receipt, member.Sequence, err
}

func (executor *LocalMariaDBPromotionExecutor) DemotePreviousServices(ctx context.Context, promotion Promotion, fencingToken uint64) (string, error) {
	cluster, err := localMariaDBCluster(ctx, executor.Store, promotion.ResourceID)
	if err != nil { return "", err }
	receipt, err := executor.Database.DemoteDatabaseWriter(ctx, cluster, promotion.PreviousWriter, fencingToken)
	if err != nil || receipt == "" { return receipt, errors.Join(err, ErrSplitBrainRisk) }
	return localProviderReceipt("demote_mariadb_previous", promotion.ResourceID, promotion.PreviousWriter, fencingToken, promotion.WriteFrontier, receipt, executor.current())
}

func (executor *LocalMariaDBPromotionExecutor) ProbeCandidate(ctx context.Context, promotion Promotion) (string, error) {
	cluster, err := localMariaDBCluster(ctx, executor.Store, promotion.ResourceID)
	if err != nil { return "", err }
	observed, err := executor.Database.ObserveCluster(ctx, cluster)
	member, memberErr := requiredDatabaseMember(observed, promotion.Candidate)
	if err != nil || memberErr != nil || member.ReadOnly || member.Sequence < promotion.CheckpointFrontier { return "", errors.Join(err, memberErr, ErrIrreversibleFrontier) }
	return localProviderReceipt("probe_mariadb_candidate", promotion.ResourceID, promotion.Candidate, 0, member.Sequence, member.GTID, executor.current())
}

func (executor *LocalMariaDBPromotionExecutor) ProbeExternalTraffic(_ context.Context, promotion Promotion, receipt TrafficReceipt) (string, error) {
	if promotion.ResourceID != LocalMariaDBResourceID || receipt.PolicyID != promotion.TrafficPolicyID || validateTrafficReceipt(receipt) != nil || receipt.ProviderReceipt == "" { return "", ErrProviderAmbiguous }
	return receipt.ProviderReceipt, nil
}

func (*LocalMariaDBPromotionExecutor) RestorePreviousServices(context.Context, Promotion, uint64) (string, error) {
	return "", ErrUnsupported
}

func (executor *LocalMariaDBPromotionExecutor) KeepPreviousFenced(_ context.Context, promotion Promotion, until time.Time) error {
	if promotion.ResourceID != LocalMariaDBResourceID || !until.After(executor.current()) { return ErrExpired }
	// Extending a fence requires the original provider token and receipt, which
	// this interface does not carry. Never manufacture a replacement token.
	return ErrUnsupported
}

func (executor *LocalMariaDBPromotionExecutor) current() time.Time { if executor != nil && executor.Now != nil { return executor.Now().UTC() }; return time.Now().UTC() }

func localMariaDBCluster(ctx context.Context, store Store, resource string) (DatabaseCluster, error) {
	if ctx == nil || store == nil || resource != LocalMariaDBResourceID { return DatabaseCluster{}, ErrUnsupported }
	cluster, err := store.LoadDatabaseCluster(ctx, ID(resource))
	if err != nil { return DatabaseCluster{}, err }
	if cluster.ID != ID(LocalMariaDBResourceID) || cluster.Topology != DatabasePrimaryReplica || cluster.Validate() != nil { return DatabaseCluster{}, ErrUnsupported }
	return cluster, nil
}

func requiredDatabaseMember(cluster DatabaseCluster, node NodeID) (DatabaseMember, error) {
	var selected DatabaseMember
	found := false
	for _, member := range cluster.Members {
		if member.NodeID != node { continue }
		if found { return DatabaseMember{}, ErrConflict }
		selected, found = member, true
	}
	if !found || selected.Validate() != nil { return DatabaseMember{}, ErrNotFound }
	return selected, nil
}

func localProviderReceipt(operation, resource string, node NodeID, token, frontier uint64, upstream string, observedAt time.Time) (string, error) {
	if operation == "" || resource != LocalMariaDBResourceID || !validID(string(node)) || upstream == "" || observedAt.IsZero() { return "", ErrInvalid }
	proof := sha256.Sum256([]byte(operation+"\x00"+resource+"\x00"+string(node)+"\x00"+fmt.Sprint(token)+"\x00"+fmt.Sprint(frontier)+"\x00"+upstream))
	payload, err := json.Marshal(struct {
		Operation string `json:"operation"`
		ResourceID string `json:"resource_id"`
		NodeID NodeID `json:"node_id"`
		FencingToken uint64 `json:"fencing_token,omitempty"`
		Frontier uint64 `json:"frontier,omitempty"`
		UpstreamReceipt string `json:"upstream_receipt"`
		ProofDigest string `json:"proof_digest"`
		ObservedAt time.Time `json:"observed_at"`
	}{operation,resource,node,token,frontier,upstream,hex.EncodeToString(proof[:]),observedAt.UTC()})
	if err != nil { return "", err }
	return string(payload), nil
}

var _ LeaseAuthority = (*LocalSQLLeaseAuthority)(nil)
var _ WriterGate = (*LocalMariaDBWriterGate)(nil)
var _ PromotionExecutor = (*LocalMariaDBPromotionExecutor)(nil)
