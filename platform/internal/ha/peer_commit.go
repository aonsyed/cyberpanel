package ha

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"sync"
	"time"
)

const (
	peerCommitEvidenceSchemaVersion = 1
	writerActivationSchemaVersion   = 1
	maximumWriterActivationBytes    = 256 << 10
	databaseFenceAuthorityVersion   = 1
	databaseSourceFenceVersion      = 1
	databaseSourceFenceAction       = "freeze"
	databaseSourceFenceOutcome      = "source_fenced_observed_v1"
)

type databaseSourceFenceAuthority struct {
	SchemaVersion    uint32                `json:"schema_version"`
	ProposalID       string                `json:"proposal_id"`
	PlanDigest       string                `json:"plan_digest"`
	PromotionID      PromotionID           `json:"promotion_id"`
	PreviousLeaseID  WriterLeaseID         `json:"previous_lease_id"`
	AuthorityEpoch   uint64                `json:"authority_epoch"`
	TopologyEpoch    uint64                `json:"topology_epoch"`
	TopologyDigest   string                `json:"topology_digest"`
	MembershipDigest string                `json:"membership_digest"`
	DeploymentEpoch  uint64                `json:"deployment_epoch"`
	DeploymentDigest string                `json:"deployment_digest"`
	Cluster          DatabaseCluster       `json:"cluster"`
	SourceNodeID     NodeID                `json:"source_node_id"`
	FencingToken     uint64                `json:"fencing_token"`
	Channel          ReplicationChannel    `json:"channel"`
	Checkpoint       ReplicationCheckpoint `json:"checkpoint"`
	ExpiresAt        time.Time             `json:"expires_at"`
}

type databaseCandidateWriterAuthority struct {
	SchemaVersion      uint32                `json:"schema_version"`
	ProposalID         string                `json:"proposal_id"`
	PlanDigest         string                `json:"plan_digest"`
	PromotionID        PromotionID           `json:"promotion_id"`
	PreviousLeaseID    WriterLeaseID         `json:"previous_lease_id"`
	AuthorityEpoch     uint64                `json:"authority_epoch"`
	TopologyEpoch      uint64                `json:"topology_epoch"`
	TopologyDigest     string                `json:"topology_digest"`
	MembershipDigest   string                `json:"membership_digest"`
	DeploymentEpoch    uint64                `json:"deployment_epoch"`
	DeploymentDigest   string                `json:"deployment_digest"`
	Cluster            DatabaseCluster       `json:"cluster"`
	SourceNodeID       NodeID                `json:"source_node_id"`
	CandidateNodeID    NodeID                `json:"candidate_node_id"`
	FencingToken       uint64                `json:"fencing_token"`
	Channel            ReplicationChannel    `json:"channel"`
	Checkpoint         ReplicationCheckpoint `json:"checkpoint"`
	Lease              WriterLease           `json:"lease"`
	SourceFenceReceipt json.RawMessage       `json:"source_fence_receipt"`
	ExpiresAt          time.Time             `json:"expires_at"`
}

// Mirrors database.DatabaseSourceFenceReceipt without importing the database
// package back into HA. SourceFenceReceipt stays raw on the wire; this mirror
// exists only to authenticate its exact canonical bytes against a commit plan.
type databaseSourceFenceReceipt struct {
	SchemaVersion     uint32                `json:"schema_version"`
	AuthorityEpoch    uint64                `json:"authority_epoch"`
	ClusterGeneration uint64                `json:"cluster_generation"`
	PromotionID       PromotionID           `json:"promotion_id"`
	PreviousLeaseID   WriterLeaseID         `json:"previous_lease_id"`
	EffectID          string                `json:"effect_id"`
	Action            string                `json:"action"`
	ClusterID         ID                    `json:"cluster_id"`
	SourceNodeID      NodeID                `json:"source_node_id"`
	FencingToken      uint64                `json:"fencing_token"`
	ReadOnly          bool                  `json:"read_only"`
	Checkpoint        ReplicationCheckpoint `json:"checkpoint"`
	Outcome           string                `json:"outcome"`
	ProofDigest       string                `json:"proof_digest"`
	FencedAt          time.Time             `json:"fenced_at"`
	ExpiresAt         time.Time             `json:"expires_at"`
}

// Root-observed local evidence. LocalSeal protects only the owning root journal;
// peer authority requires the separately signed node envelope below.
type NodeFenceEvidence struct {
	SchemaVersion      uint32                `json:"schema_version"`
	Channel            ReplicationChannel    `json:"channel"`
	Checkpoint         ReplicationCheckpoint `json:"checkpoint"`
	NodeID             NodeID                `json:"node_id"`
	AuthorityEpoch     uint64                `json:"authority_epoch"`
	DeploymentEpoch    uint64                `json:"deployment_epoch"`
	DeploymentDigest   string                `json:"deployment_digest"`
	FencingToken       uint64                `json:"fencing_token"`
	GTID               string                `json:"gtid"`
	Frontier           uint64                `json:"frontier"`
	SourceFenceReceipt json.RawMessage       `json:"source_fence_receipt"`
	// CursorDigest is retained as the wire name for v1 compatibility. It is the
	// digest of the exact durable old-writer fence receipt, not a replication
	// cursor, and must agree across the source and candidate observations.
	CursorDigest       string    `json:"cursor_digest"`
	SessionFenceDigest string    `json:"session_fence_digest"`
	ObservationDigest  string    `json:"observation_digest"`
	ReplicaDigest      string    `json:"replica_digest"`
	ObservedAt         time.Time `json:"observed_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	LocalSeal          string    `json:"local_seal"`
}

// Matches the database broker's candidate certificate JSON without importing
// that broker or giving this domain direct access to its private local seal.
type CandidateWriterEvidence struct {
	SchemaVersion      uint32                `json:"schema_version"`
	ID                 string                `json:"id"`
	Channel            ReplicationChannel    `json:"channel"`
	Checkpoint         ReplicationCheckpoint `json:"checkpoint"`
	ClusterID          ID                    `json:"cluster_id"`
	ClusterGeneration  uint64                `json:"cluster_generation"`
	TopologyDigest     string                `json:"topology_digest"`
	DeploymentDigest   string                `json:"deployment_digest"`
	DeploymentEpoch    uint64                `json:"deployment_epoch"`
	AuthorityEpoch     uint64                `json:"authority_epoch"`
	OldWriter          NodeID                `json:"old_writer"`
	Candidate          NodeID                `json:"candidate"`
	Lease              WriterLease           `json:"lease"`
	FenceEffectID      string                `json:"fence_effect_id"`
	FenceDigest        string                `json:"fence_digest"`
	ReplicaDigest      string                `json:"replica_digest"`
	SessionFenceDigest string                `json:"session_fence_digest"`
	GTID               string                `json:"gtid"`
	Frontier           uint64                `json:"frontier"`
	IssuedAt           time.Time             `json:"issued_at"`
	ExpiresAt          time.Time             `json:"expires_at"`
	LocalSeal          string                `json:"local_seal"`
}

type PeerCommitPlan struct {
	Prepare    PeerVoteProof         `json:"prepare"`
	Channel    ReplicationChannel    `json:"channel"`
	Checkpoint ReplicationCheckpoint `json:"checkpoint"`
	Lease      WriterLease           `json:"lease"`
	Bootstrap  bool                  `json:"bootstrap"`
}

func (plan PeerCommitPlan) Digest() string { return peerCommitDigest(plan) }

type PeerNodeEvidence struct {
	PlanDigest   string                   `json:"plan_digest"`
	Node         NodeFenceEvidence        `json:"node"`
	Candidate    *CandidateWriterEvidence `json:"candidate,omitempty"`
	SigningKeyID string                   `json:"signing_key_id"`
	Signature    []byte                   `json:"signature"`
}

func (evidence PeerNodeEvidence) payload() []byte {
	evidence.Signature = nil
	return mustPeerVoteJSON(struct {
		Domain   string
		Evidence PeerNodeEvidence
	}{"cyberpanel-ha-owning-node-fence-v1", evidence})
}

type PeerCommitRequest struct {
	Plan      PeerCommitPlan   `json:"plan"`
	Source    PeerNodeEvidence `json:"source"`
	Candidate PeerNodeEvidence `json:"candidate"`
}

func (request PeerCommitRequest) Digest() string { return peerCommitDigest(request) }

type PeerCommitVote struct {
	VoterID      NodeID    `json:"voter_id"`
	SigningKeyID string    `json:"signing_key_id"`
	CommitDigest string    `json:"commit_digest"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Signature    []byte    `json:"signature"`
}

func (vote PeerCommitVote) payload() []byte {
	vote.Signature = nil
	return mustPeerVoteJSON(struct {
		Domain string
		Vote   PeerCommitVote
	}{"cyberpanel-ha-post-fence-commit-v1", vote})
}

type WriterActivationCertificate struct {
	Request PeerCommitRequest `json:"request"`
	Votes   []PeerCommitVote  `json:"votes"`
}

func (certificate WriterActivationCertificate) Digest() string { return peerCommitDigest(certificate) }

type PeerCommitProjection struct {
	ProofDigest  string        `json:"proof_digest"`
	LeaseID      WriterLeaseID `json:"lease_id"`
	FencingEpoch uint64        `json:"fencing_epoch"`
	Voters       []NodeID      `json:"voters"`
	ExpiresAt    time.Time     `json:"expires_at"`
	State        string        `json:"state"`
}

// PeerCommitObservationRequest carries the source receipt only after the
// source owner has produced it. It is an internal peer message, never CLI
// input, and lets the candidate observe and seal the exact same fence bytes.
type PeerCommitObservationRequest struct {
	Plan               PeerCommitPlan  `json:"plan"`
	SourceFenceReceipt json.RawMessage `json:"source_fence_receipt,omitempty"`
}

type PeerCommitTransport interface {
	ObserveCommitNode(context.Context, PeerVoter, PeerCommitObservationRequest) (PeerNodeEvidence, error)
	RequestCommit(context.Context, PeerVoter, PeerCommitRequest) (PeerCommitVote, error)
	AdmitCommit(context.Context, PeerVoter, WriterActivationCertificate) error
}
type PeerCommitService struct {
	Prepare        *PeerVoteService
	Transport      PeerCommitTransport
	ObserveLocal   func(context.Context, PeerCommitPlan, json.RawMessage) (NodeFenceEvidence, error)
	CandidateLocal func(context.Context, PeerCommitPlan, json.RawMessage) (CandidateWriterEvidence, error)
}

func peerCommitDigest(value any) string { return federatedHADigest(mustPeerVoteJSON(value)) }
func peerSame(left, right any) bool {
	return bytes.Equal(mustPeerVoteJSON(left), mustPeerVoteJSON(right))
}

func databaseFenceAuthority(topology PeerVoteTopology, plan PeerCommitPlan, cluster DatabaseCluster) (databaseSourceFenceAuthority, error) {
	proposal := plan.Prepare.Proposal
	if cluster.Validate() != nil || cluster.ID != ID(plan.Lease.ResourceID) || cluster.GroupID != plan.Lease.GroupID || topology.AuthorityEpoch != proposal.AuthorityEpoch || topology.Control.TopologyEpoch != proposal.TopologyEpoch || !validDigest(topology.Control.TopologyDigest) || topology.DeploymentEpoch == 0 || !validDigest(topology.DeploymentDigest) || PeerMembershipDigest(topology.GroupID, topology.Control) != proposal.MembershipDigest {
		return databaseSourceFenceAuthority{}, ErrConflict
	}
	return databaseSourceFenceAuthority{SchemaVersion: databaseFenceAuthorityVersion, ProposalID: proposal.ID, PlanDigest: plan.Digest(), PromotionID: proposal.PromotionID, PreviousLeaseID: proposal.PreviousLeaseID, AuthorityEpoch: proposal.AuthorityEpoch, TopologyEpoch: proposal.TopologyEpoch, TopologyDigest: topology.Control.TopologyDigest, MembershipDigest: proposal.MembershipDigest, DeploymentEpoch: topology.DeploymentEpoch, DeploymentDigest: topology.DeploymentDigest, Cluster: cluster, SourceNodeID: plan.Channel.SourceNodeID, FencingToken: plan.Lease.FencingToken, Channel: plan.Channel, Checkpoint: plan.Checkpoint, ExpiresAt: plan.Lease.ExpiresAt}, nil
}

// LoadDatabaseSourceFenceAuthority returns the only source-fence input accepted
// by the database adapter. Callers transport these canonical bytes unchanged.
func LoadDatabaseSourceFenceAuthority(topology PeerVoteTopology, plan PeerCommitPlan, cluster DatabaseCluster) (json.RawMessage, error) {
	authority, err := databaseFenceAuthority(topology, plan, cluster)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(mustPeerVoteJSON(authority)), nil
}

// LoadDatabaseCandidateWriterAuthority binds candidate evidence to the exact
// persisted source-fence bytes instead of allowing a caller-supplied digest.
func LoadDatabaseCandidateWriterAuthority(topology PeerVoteTopology, plan PeerCommitPlan, cluster DatabaseCluster, sourceFenceReceipt json.RawMessage) (json.RawMessage, error) {
	base, err := databaseFenceAuthority(topology, plan, cluster)
	if err != nil {
		return nil, err
	}
	var receipt databaseSourceFenceReceipt
	if decodeCanonicalPeerCommitJSON(sourceFenceReceipt, &receipt) != nil || receipt.SchemaVersion != databaseSourceFenceVersion || receipt.ClusterID != cluster.ID || receipt.ClusterGeneration != cluster.Generation || receipt.PromotionID != plan.Prepare.Proposal.PromotionID || receipt.PreviousLeaseID != plan.Prepare.Proposal.PreviousLeaseID || receipt.AuthorityEpoch != plan.Prepare.Proposal.AuthorityEpoch || receipt.SourceNodeID != plan.Channel.SourceNodeID || receipt.FencingToken != plan.Lease.FencingToken || !peerSame(receipt.Checkpoint, plan.Checkpoint) || !receipt.ExpiresAt.Equal(plan.Lease.ExpiresAt) {
		return nil, ErrFenceRequired
	}
	authority := databaseCandidateWriterAuthority{SchemaVersion: base.SchemaVersion, ProposalID: base.ProposalID, PlanDigest: base.PlanDigest, PromotionID: base.PromotionID, PreviousLeaseID: base.PreviousLeaseID, AuthorityEpoch: base.AuthorityEpoch, TopologyEpoch: base.TopologyEpoch, TopologyDigest: base.TopologyDigest, MembershipDigest: base.MembershipDigest, DeploymentEpoch: base.DeploymentEpoch, DeploymentDigest: base.DeploymentDigest, Cluster: cluster, SourceNodeID: base.SourceNodeID, CandidateNodeID: plan.Channel.TargetNodeID, FencingToken: base.FencingToken, Channel: base.Channel, Checkpoint: base.Checkpoint, Lease: plan.Lease, SourceFenceReceipt: append(json.RawMessage(nil), sourceFenceReceipt...), ExpiresAt: base.ExpiresAt}
	return json.RawMessage(mustPeerVoteJSON(authority)), nil
}

func validateDatabaseSourceFenceReceipt(topology PeerVoteTopology, plan PeerCommitPlan, raw json.RawMessage, now time.Time) (databaseSourceFenceReceipt, string, error) {
	var receipt databaseSourceFenceReceipt
	if decodeCanonicalPeerCommitJSON(raw, &receipt) != nil {
		return databaseSourceFenceReceipt{}, "", ErrFenceRequired
	}
	proposal := plan.Prepare.Proposal
	if receipt.SchemaVersion != databaseSourceFenceVersion || receipt.AuthorityEpoch != proposal.AuthorityEpoch || receipt.ClusterGeneration == 0 || receipt.PromotionID != proposal.PromotionID || receipt.PreviousLeaseID != proposal.PreviousLeaseID || !validID(receipt.EffectID) || receipt.Action != databaseSourceFenceAction || receipt.ClusterID != ID(plan.Lease.ResourceID) || receipt.SourceNodeID != plan.Channel.SourceNodeID || receipt.FencingToken != plan.Lease.FencingToken || !receipt.ReadOnly || !peerSame(receipt.Checkpoint, plan.Checkpoint) || receipt.Outcome != databaseSourceFenceOutcome || !validDigest(receipt.ProofDigest) || receipt.FencedAt.Before(plan.Lease.IssuedAt.Add(-5*time.Second)) || receipt.FencedAt.After(now.Add(5*time.Second)) || !receipt.ExpiresAt.Equal(plan.Lease.ExpiresAt) || !receipt.ExpiresAt.After(receipt.FencedAt) || !now.Before(receipt.ExpiresAt) || proposal.TopologyEpoch != topology.Control.TopologyEpoch || proposal.MembershipDigest != PeerMembershipDigest(topology.GroupID, topology.Control) {
		return databaseSourceFenceReceipt{}, "", ErrFenceRequired
	}
	return receipt, federatedHADigest(raw), nil
}

func currentPeerVoteTopology(ctx context.Context, db *sql.DB) (PeerVoteTopology, error) {
	if ctx == nil || db == nil {
		return PeerVoteTopology{}, ErrInvalid
	}
	bundle, err := LoadAdmittedPeerDeployment(ctx, db)
	if err != nil {
		return PeerVoteTopology{}, err
	}
	deploymentDigest, err := StaticDeploymentDigest(bundle)
	if err != nil || bundle.PeerControl == nil {
		return PeerVoteTopology{}, errors.Join(err, ErrForbidden)
	}
	return PeerVoteTopology{NodeID: NodeID(bundle.Trust.NodeID), GroupID: bundle.Group.ID, AuthorityEpoch: bundle.AuthorityEpoch, DeploymentEpoch: bundle.DeploymentEpoch, DeploymentDigest: deploymentDigest, Control: *bundle.PeerControl}, nil
}

func loadCurrentPeerCommitPlan(ctx context.Context, db *sql.DB, proposalID string) (PeerVoteTopology, PeerCommitPlan, DatabaseCluster, error) {
	if !validID(proposalID) {
		return PeerVoteTopology{}, PeerCommitPlan{}, DatabaseCluster{}, ErrForbidden
	}
	topology, err := currentPeerVoteTopology(ctx, db)
	if err != nil {
		return PeerVoteTopology{}, PeerCommitPlan{}, DatabaseCluster{}, err
	}
	var raw []byte
	if err = db.QueryRowContext(ctx, `SELECT plan_json FROM ha_peer_commit_plans_v1 WHERE id=?`, proposalID).Scan(&raw); err != nil {
		return PeerVoteTopology{}, PeerCommitPlan{}, DatabaseCluster{}, ErrForbidden
	}
	var plan PeerCommitPlan
	if decodeCanonicalPeerCommitJSON(raw, &plan) != nil || plan.Prepare.Proposal.ID != proposalID || validateCommitPlan(topology, plan, time.Now().UTC()) != nil {
		return PeerVoteTopology{}, PeerCommitPlan{}, DatabaseCluster{}, ErrForbidden
	}
	cluster, err := (SQLRepository{DB: db}).LoadDatabaseCluster(ctx, ID(plan.Lease.ResourceID))
	if err != nil || cluster.Validate() != nil || cluster.GroupID != topology.GroupID {
		return PeerVoteTopology{}, PeerCommitPlan{}, DatabaseCluster{}, errors.Join(err, ErrForbidden)
	}
	return topology, plan, cluster, nil
}

func verifyPersistedSourceFenceReceipt(ctx context.Context, query peerCommitQueryer, topology PeerVoteTopology, plan PeerCommitPlan, expected json.RawMessage, now time.Time) error {
	_, digest, err := validateDatabaseSourceFenceReceipt(topology, plan, expected, now)
	if err != nil {
		return err
	}
	var storedDigest string
	var stored []byte
	if err = query.QueryRowContext(ctx, `SELECT receipt_digest,receipt_json FROM ha_peer_source_fence_receipts_v1 WHERE plan_digest=?`, plan.Digest()).Scan(&storedDigest, &stored); err != nil || storedDigest != digest || !bytes.Equal(stored, expected) {
		return errors.Join(err, ErrFenceRequired)
	}
	return nil
}

// VerifyDatabaseWriterFenceAuthority is the source-side root seam. The opaque
// bytes must be the exact authority HA derives from current durable state.
func VerifyDatabaseWriterFenceAuthority(ctx context.Context, db *sql.DB, raw json.RawMessage) error {
	var input databaseSourceFenceAuthority
	if decodeCanonicalPeerCommitJSON(raw, &input) != nil || input.SchemaVersion != databaseFenceAuthorityVersion {
		return ErrForbidden
	}
	topology, plan, cluster, err := loadCurrentPeerCommitPlan(ctx, db, input.ProposalID)
	if err != nil || topology.NodeID != plan.Channel.SourceNodeID {
		return errors.Join(err, ErrForbidden)
	}
	expected, err := LoadDatabaseSourceFenceAuthority(topology, plan, cluster)
	if err != nil || !bytes.Equal(raw, expected) {
		return errors.Join(err, ErrForbidden)
	}
	return nil
}

// VerifyDatabaseWriterCandidateAuthority is the target-side root seam. It
// additionally requires the exact source receipt already authenticated and
// persisted by HA before the candidate broker may observe or seal anything.
func VerifyDatabaseWriterCandidateAuthority(ctx context.Context, db *sql.DB, raw json.RawMessage) error {
	var input databaseCandidateWriterAuthority
	if decodeCanonicalPeerCommitJSON(raw, &input) != nil || input.SchemaVersion != databaseFenceAuthorityVersion {
		return ErrForbidden
	}
	topology, plan, cluster, err := loadCurrentPeerCommitPlan(ctx, db, input.ProposalID)
	if err != nil || topology.NodeID != plan.Channel.TargetNodeID {
		return errors.Join(err, ErrForbidden)
	}
	receipt, _, err := validateDatabaseSourceFenceReceipt(topology, plan, input.SourceFenceReceipt, time.Now().UTC())
	if err != nil || receipt.ClusterID != cluster.ID || receipt.ClusterGeneration != cluster.Generation {
		return errors.Join(err, ErrFenceRequired)
	}
	if err = verifyPersistedSourceFenceReceipt(ctx, db, topology, plan, input.SourceFenceReceipt, time.Now().UTC()); err != nil {
		return err
	}
	expected, err := LoadDatabaseCandidateWriterAuthority(topology, plan, cluster, input.SourceFenceReceipt)
	if err != nil || !bytes.Equal(raw, expected) {
		return errors.Join(err, ErrForbidden)
	}
	return nil
}

func (service *PeerCommitService) Bootstrap(ctx context.Context) error {
	if service == nil || service.Prepare == nil || service.Transport == nil || service.ObserveLocal == nil || service.CandidateLocal == nil {
		return ErrInvalid
	}
	_, err := service.Prepare.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ha_peer_commit_plans_v1(id TEXT PRIMARY KEY,plan_json BLOB NOT NULL,request_json BLOB,certificate_json BLOB);
CREATE TABLE IF NOT EXISTS ha_peer_node_evidence_v1(plan_digest TEXT PRIMARY KEY,evidence_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS ha_peer_commit_votes_v1(resource_id TEXT NOT NULL,topology_epoch INTEGER NOT NULL,fencing_epoch INTEGER NOT NULL,commit_digest TEXT NOT NULL,vote_json BLOB NOT NULL,PRIMARY KEY(resource_id,topology_epoch,fencing_epoch));
CREATE TABLE IF NOT EXISTS ha_peer_writer_certificates_v1(proof_digest TEXT PRIMARY KEY,resource_id TEXT NOT NULL,topology_epoch INTEGER NOT NULL,fencing_epoch INTEGER NOT NULL,lease_id TEXT NOT NULL UNIQUE,certificate_json BLOB NOT NULL,UNIQUE(resource_id,topology_epoch,fencing_epoch));
CREATE TABLE IF NOT EXISTS ha_peer_source_fence_receipts_v1(plan_digest TEXT PRIMARY KEY,receipt_digest TEXT NOT NULL,receipt_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS ha_peer_writer_activation_consumptions_v1(proof_digest TEXT PRIMARY KEY,lease_id TEXT NOT NULL UNIQUE,node_id TEXT NOT NULL,lease_generation INTEGER NOT NULL,consumed_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS ha_peer_genesis_v1(group_id TEXT PRIMARY KEY,membership_digest TEXT NOT NULL,lease_json BLOB NOT NULL,closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1)));`)
	return err
}

// Genesis is a revoked watermark, never a claim that any node may write. The
// lexicographically first configured voter merely names a deterministic prior
// holder. The actual source still has to prove a current privileged fence.
func (service *PeerCommitService) ReconcileGenesis(ctx context.Context) (WriterLease, error) {
	topology, err := service.Prepare.Topology(ctx)
	if err != nil {
		return WriterLease{}, err
	}
	bundle, err := LoadAdmittedPeerDeployment(ctx, service.Prepare.DB)
	if err != nil {
		return WriterLease{}, err
	}
	voters := append([]PeerVoter(nil), topology.Control.Voters...)
	sort.Slice(voters, func(i, j int) bool { return voters[i].NodeID < voters[j].NodeID })
	if len(voters) == 0 {
		return WriterLease{}, ErrNoQuorum
	}
	digest := PeerMembershipDigest(topology.GroupID, topology.Control)
	issued := bundle.Group.CreatedAt.UTC()
	lease := WriterLease{ID: WriterLeaseID("ha_genesis_" + digest[:48]), GroupID: topology.GroupID, ResourceID: LocalMariaDBResourceID, HolderNodeID: voters[0].NodeID, EnforcedWritePaths: []string{"mariadb-local"}, FencingToken: 1, AuthorityEpoch: topology.AuthorityEpoch, QuorumDigest: peerCommitDigest(struct{ Domain, Digest string }{"cyberpanel-ha-revoked-genesis-v1", digest}), IssuedAt: issued, RenewAfter: issued.Add(time.Nanosecond), ExpiresAt: issued.Add(2 * time.Nanosecond), State: LeaseRevoked, Generation: 1}
	if lease.Validate(service.Prepare.now()) != nil {
		return WriterLease{}, ErrInvalid
	}
	tx, err := service.Prepare.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return WriterLease{}, err
	}
	defer tx.Rollback()
	var existing []byte
	var membership string
	var closed int
	err = tx.QueryRowContext(ctx, `SELECT membership_digest,lease_json,closed FROM ha_peer_genesis_v1 WHERE group_id=?`, topology.GroupID).Scan(&membership, &existing, &closed)
	if err == nil {
		var stored WriterLease
		var projected []byte
		if membership != digest || (closed != 0 && closed != 1) || decodeCanonicalPeerCommitJSON(existing, &stored) != nil || !peerSame(stored, lease) || tx.QueryRowContext(ctx, `SELECT lease_json FROM ha_writer_leases WHERE id=?`, lease.ID).Scan(&projected) != nil || !bytes.Equal(projected, existing) {
			return WriterLease{}, ErrConflict
		}
		return stored, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return WriterLease{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM ha_writer_leases WHERE resource_id=?)+(SELECT COUNT(*) FROM ha_peer_writer_certificates_v1 WHERE resource_id=?)`, lease.ResourceID, lease.ResourceID).Scan(&count); err != nil {
		return WriterLease{}, err
	}
	if count != 0 {
		return WriterLease{}, errors.Join(ErrConflict, ErrNotFound)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO ha_peer_genesis_v1(group_id,membership_digest,lease_json)VALUES(?,?,?)`, lease.GroupID, digest, mustPeerVoteJSON(lease)); err != nil {
		return WriterLease{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO ha_writer_leases(id,group_id,resource_id,holder_node_id,fencing_token,authority_epoch,state,generation,lease_json,expires_at)VALUES(?,?,?,?,?,?,?,?,?,?)`, lease.ID, lease.GroupID, lease.ResourceID, lease.HolderNodeID, lease.FencingToken, lease.AuthorityEpoch, lease.State, lease.Generation, mustPeerVoteJSON(lease), lease.ExpiresAt); err != nil {
		return WriterLease{}, err
	}
	return lease, tx.Commit()
}

func validateCommitPlan(topology PeerVoteTopology, plan PeerCommitPlan, now time.Time) error {
	proposal := plan.Prepare.Proposal
	if _, err := projectPeerVoteProof(topology, proposal, plan.Prepare, mustPeerVoteJSON(plan.Prepare), now); err != nil {
		return err
	}
	for index, vote := range plan.Prepare.Votes {
		if index > 0 && plan.Prepare.Votes[index-1].VoterID >= vote.VoterID {
			return ErrNoQuorum
		}
	}
	if plan.Channel.Validate() != nil || plan.Checkpoint.Validate() != nil || plan.Channel.Kind != DataDatabase || plan.Channel.ResourceID != LocalMariaDBResourceID || plan.Channel.GroupID != topology.GroupID || plan.Channel.SourceNodeID != proposal.PreviousWriter || plan.Channel.TargetNodeID != proposal.Candidate || plan.Channel.State != ChannelCaughtUp || plan.Checkpoint.ChannelID != plan.Channel.ID || plan.Checkpoint.LagBytes != 0 || plan.Checkpoint.LagDuration != 0 {
		return ErrCheckpointStale
	}
	lease := plan.Lease
	if lease.Validate(now) != nil || lease.State != LeaseActive || lease.Generation != 1 || lease.GroupID != proposal.GroupID || lease.ResourceID != proposal.ResourceID || lease.HolderNodeID != proposal.Candidate || lease.FencingToken != proposal.FencingEpoch || lease.AuthorityEpoch != proposal.AuthorityEpoch || lease.QuorumDigest != proposal.Digest() || !peerSame(lease.EnforcedWritePaths, []string{"mariadb-local"}) || lease.IssuedAt.Before(proposal.IssuedAt) || lease.IssuedAt.After(now.Add(5*time.Second)) || lease.ExpiresAt.After(proposal.ExpiresAt) || lease.ExpiresAt.Sub(lease.IssuedAt) > 20*time.Second {
		return ErrLeaseLost
	}
	return nil
}
func validateRootNodeEvidence(topology PeerVoteTopology, plan PeerCommitPlan, value NodeFenceEvidence, node NodeID, now time.Time) error {
	if value.SchemaVersion != peerCommitEvidenceSchemaVersion || value.NodeID != node || !peerSame(value.Channel, plan.Channel) || !peerSame(value.Checkpoint, plan.Checkpoint) || value.AuthorityEpoch != topology.AuthorityEpoch || value.DeploymentEpoch != topology.DeploymentEpoch || !validDigest(value.DeploymentDigest) || value.FencingToken != plan.Lease.FencingToken || value.GTID != plan.Checkpoint.Position || value.Frontier != plan.Checkpoint.WriteFrontier || !validDigest(value.CursorDigest) || !validDigest(value.SessionFenceDigest) || !validDigest(value.ObservationDigest) || !validDigest(value.LocalSeal) || value.ObservedAt.Before(plan.Lease.IssuedAt.Add(-5*time.Second)) || value.ObservedAt.After(now.Add(5*time.Second)) || !value.ExpiresAt.After(value.ObservedAt) || !now.Before(value.ExpiresAt) || value.ExpiresAt.Before(plan.Lease.ExpiresAt) || value.ExpiresAt.Sub(value.ObservedAt) > 30*time.Second {
		return ErrFenceRequired
	}
	receipt, digest, err := validateDatabaseSourceFenceReceipt(topology, plan, value.SourceFenceReceipt, now)
	if err != nil || value.CursorDigest != digest || value.ObservedAt.Before(receipt.FencedAt) || value.ExpiresAt.After(receipt.ExpiresAt) {
		return ErrFenceRequired
	}
	// Node-specific deployment bundles have different digests. The owner binds
	// its evidence to its exact admitted bundle before signing; other voters
	// verify that owner signature and re-fetch the exact signed envelope.
	if node == topology.NodeID && value.DeploymentDigest != topology.DeploymentDigest {
		return ErrForbidden
	}
	if node == plan.Channel.TargetNodeID {
		if !validDigest(value.ReplicaDigest) {
			return ErrCheckpointStale
		}
	} else if value.ReplicaDigest != "" && !validDigest(value.ReplicaDigest) {
		return ErrForbidden
	}
	return nil
}
func validateCandidateWriterEvidence(topology PeerVoteTopology, plan PeerCommitPlan, value NodeFenceEvidence, candidate *CandidateWriterEvidence, now time.Time) error {
	receipt, digest, receiptErr := validateDatabaseSourceFenceReceipt(topology, plan, value.SourceFenceReceipt, now)
	if candidate == nil || receiptErr != nil || candidate.SchemaVersion != peerCommitEvidenceSchemaVersion || !validID(candidate.ID) || candidate.ClusterGeneration != receipt.ClusterGeneration || !peerSame(candidate.Channel, plan.Channel) || !peerSame(candidate.Checkpoint, plan.Checkpoint) || !peerSame(candidate.Lease, plan.Lease) || candidate.ClusterID != receipt.ClusterID || candidate.ClusterID != ID(LocalMariaDBResourceID) || candidate.TopologyDigest != topology.Control.TopologyDigest || !validDigest(candidate.TopologyDigest) || candidate.AuthorityEpoch != topology.AuthorityEpoch || candidate.DeploymentDigest != value.DeploymentDigest || !validDigest(candidate.DeploymentDigest) || candidate.DeploymentEpoch != value.DeploymentEpoch || candidate.OldWriter != plan.Channel.SourceNodeID || candidate.Candidate != plan.Channel.TargetNodeID || !validID(candidate.FenceEffectID) || candidate.FenceEffectID != receipt.EffectID || candidate.FenceDigest != digest || candidate.FenceDigest != value.CursorDigest || !validDigest(candidate.FenceDigest) || candidate.ReplicaDigest != value.ReplicaDigest || !validDigest(candidate.ReplicaDigest) || candidate.SessionFenceDigest != value.SessionFenceDigest || !validDigest(candidate.SessionFenceDigest) || candidate.GTID != value.GTID || candidate.Frontier != value.Frontier || candidate.IssuedAt.Before(receipt.FencedAt) || candidate.IssuedAt.Before(plan.Lease.IssuedAt) || candidate.IssuedAt.After(now.Add(5*time.Second)) || !candidate.ExpiresAt.After(candidate.IssuedAt) || !candidate.ExpiresAt.Equal(plan.Lease.ExpiresAt) || !now.Before(candidate.ExpiresAt) || !validDigest(candidate.LocalSeal) {
		return ErrCheckpointStale
	}
	return nil
}
func validateNodeEvidence(topology PeerVoteTopology, plan PeerCommitPlan, evidence PeerNodeEvidence, node NodeID, now time.Time) error {
	value := evidence.Node
	if evidence.PlanDigest != plan.Digest() || !validID(evidence.SigningKeyID) || validateRootNodeEvidence(topology, plan, value, node, now) != nil {
		return ErrFenceRequired
	}
	if node == plan.Channel.TargetNodeID {
		if validateCandidateWriterEvidence(topology, plan, value, evidence.Candidate, now) != nil {
			return ErrCheckpointStale
		}
	} else if evidence.Candidate != nil {
		return ErrForbidden
	}
	for _, voter := range topology.Control.Voters {
		if voter.NodeID == node && voter.VoteKeyID == evidence.SigningKeyID && ed25519.Verify(ed25519.PublicKey(voter.VotePublicKey), evidence.payload(), evidence.Signature) {
			return nil
		}
	}
	return ErrForbidden
}
func stableNodeEvidence(value NodeFenceEvidence) string {
	value.ObservedAt = time.Time{}
	value.ExpiresAt = time.Time{}
	value.LocalSeal = ""
	value.ObservationDigest = ""
	return peerCommitDigest(value)
}

func (service *PeerCommitService) persistCommitPlan(ctx context.Context, plan PeerCommitPlan) error {
	raw := mustPeerVoteJSON(plan)
	if _, err := service.Prepare.DB.ExecContext(ctx, `INSERT OR IGNORE INTO ha_peer_commit_plans_v1(id,plan_json)VALUES(?,?)`, plan.Prepare.Proposal.ID, raw); err != nil {
		return err
	}
	var stored []byte
	if err := service.Prepare.DB.QueryRowContext(ctx, `SELECT plan_json FROM ha_peer_commit_plans_v1 WHERE id=?`, plan.Prepare.Proposal.ID).Scan(&stored); err != nil || !bytes.Equal(stored, raw) {
		return errors.Join(err, ErrConflict)
	}
	return nil
}

func (service *PeerCommitService) persistSourceFenceReceipt(ctx context.Context, plan PeerCommitPlan, raw json.RawMessage) error {
	_, digest, err := validateDatabaseSourceFenceReceiptMustCurrent(service, ctx, plan, raw)
	if err != nil {
		return err
	}
	if _, err = service.Prepare.DB.ExecContext(ctx, `INSERT OR IGNORE INTO ha_peer_source_fence_receipts_v1(plan_digest,receipt_digest,receipt_json)VALUES(?,?,?)`, plan.Digest(), digest, []byte(raw)); err != nil {
		return err
	}
	var storedDigest string
	var stored []byte
	if err = service.Prepare.DB.QueryRowContext(ctx, `SELECT receipt_digest,receipt_json FROM ha_peer_source_fence_receipts_v1 WHERE plan_digest=?`, plan.Digest()).Scan(&storedDigest, &stored); err != nil || storedDigest != digest || !bytes.Equal(stored, raw) {
		return errors.Join(err, ErrConflict)
	}
	return nil
}

func validateDatabaseSourceFenceReceiptMustCurrent(service *PeerCommitService, ctx context.Context, plan PeerCommitPlan, raw json.RawMessage) (databaseSourceFenceReceipt, string, error) {
	if service == nil || service.Prepare == nil {
		return databaseSourceFenceReceipt{}, "", ErrInvalid
	}
	topology, err := service.Prepare.Topology(ctx)
	if err != nil {
		return databaseSourceFenceReceipt{}, "", err
	}
	return validateDatabaseSourceFenceReceipt(topology, plan, raw, service.Prepare.now())
}

func validateCommitRequestBinding(request PeerCommitRequest) error {
	if request.Source.Node.NodeID != request.Plan.Channel.SourceNodeID || request.Source.Candidate != nil || request.Candidate.Node.NodeID != request.Plan.Channel.TargetNodeID || request.Candidate.Candidate == nil {
		return ErrForbidden
	}
	if !bytes.Equal(request.Source.Node.SourceFenceReceipt, request.Candidate.Node.SourceFenceReceipt) || request.Source.Node.CursorDigest != request.Candidate.Node.CursorDigest || request.Candidate.Candidate.FenceDigest != request.Source.Node.CursorDigest {
		return ErrFenceRequired
	}
	return nil
}

func (service *PeerCommitService) ObserveNode(ctx context.Context, caller NodeID, request PeerCommitObservationRequest) (PeerNodeEvidence, error) {
	if service == nil || ctx == nil {
		return PeerNodeEvidence{}, ErrInvalid
	}
	plan := request.Plan
	topology, err := service.Prepare.Topology(ctx)
	if err != nil {
		return PeerNodeEvidence{}, err
	}
	if err = validateCommitPlan(topology, plan, service.Prepare.now()); err != nil {
		return PeerNodeEvidence{}, err
	}
	allowed := false
	var local PeerVoter
	for _, voter := range topology.Control.Voters {
		if voter.NodeID == caller {
			allowed = true
		}
		if voter.NodeID == topology.NodeID {
			local = voter
		}
	}
	if !allowed || local.NodeID == "" || (topology.NodeID != plan.Channel.SourceNodeID && topology.NodeID != plan.Channel.TargetNodeID) {
		return PeerNodeEvidence{}, ErrForbidden
	}
	if topology.NodeID == plan.Channel.SourceNodeID {
		if len(request.SourceFenceReceipt) != 0 {
			return PeerNodeEvidence{}, ErrForbidden
		}
	} else {
		if _, _, err = validateDatabaseSourceFenceReceipt(topology, plan, request.SourceFenceReceipt, service.Prepare.now()); err != nil {
			return PeerNodeEvidence{}, err
		}
	}
	store := SQLRepository{DB: service.Prepare.DB}
	localChannel, channelErr := store.LoadChannel(ctx, plan.Channel.ID)
	localCheckpoint, checkpointErr := store.LoadCheckpoint(ctx, plan.Checkpoint.ID)
	if channelErr != nil || checkpointErr != nil || !peerSame(localChannel, plan.Channel) || !peerSame(localCheckpoint, plan.Checkpoint) {
		return PeerNodeEvidence{}, errors.Join(channelErr, checkpointErr, ErrCheckpointStale)
	}
	// Only a locally persisted prepare promise can expose evidence for a plan.
	var promise string
	if err = service.Prepare.DB.QueryRowContext(ctx, `SELECT proposal_digest FROM ha_peer_promotion_votes_v1 WHERE resource_id=? AND topology_epoch=? AND fencing_epoch=?`, plan.Lease.ResourceID, topology.Control.TopologyEpoch, plan.Lease.FencingToken).Scan(&promise); err != nil || promise != plan.Prepare.Proposal.Digest() {
		return PeerNodeEvidence{}, ErrNoQuorum
	}
	if err = service.persistCommitPlan(ctx, plan); err != nil {
		return PeerNodeEvidence{}, err
	}
	if topology.NodeID == plan.Channel.TargetNodeID {
		if err = service.persistSourceFenceReceipt(ctx, plan, request.SourceFenceReceipt); err != nil {
			return PeerNodeEvidence{}, err
		}
	}
	now := service.Prepare.now()
	fresh, err := service.ObserveLocal(ctx, plan, request.SourceFenceReceipt)
	if err != nil {
		return PeerNodeEvidence{}, err
	}
	if topology.NodeID == plan.Channel.TargetNodeID && !bytes.Equal(fresh.SourceFenceReceipt, request.SourceFenceReceipt) {
		return PeerNodeEvidence{}, ErrFenceRequired
	}
	if err = validateRootNodeEvidence(topology, plan, fresh, topology.NodeID, now); err != nil {
		return PeerNodeEvidence{}, err
	}
	receipt, _, receiptErr := validateDatabaseSourceFenceReceipt(topology, plan, fresh.SourceFenceReceipt, now)
	cluster, clusterErr := store.LoadDatabaseCluster(ctx, ID(plan.Lease.ResourceID))
	if receiptErr != nil || clusterErr != nil || cluster.ID != receipt.ClusterID || cluster.GroupID != topology.GroupID || cluster.Generation != receipt.ClusterGeneration {
		return PeerNodeEvidence{}, errors.Join(receiptErr, clusterErr, ErrFenceRequired)
	}
	if err = service.persistSourceFenceReceipt(ctx, plan, fresh.SourceFenceReceipt); err != nil {
		return PeerNodeEvidence{}, err
	}
	var freshCandidate *CandidateWriterEvidence
	if topology.NodeID == plan.Channel.TargetNodeID {
		candidate, issueErr := service.CandidateLocal(ctx, plan, fresh.SourceFenceReceipt)
		if issueErr != nil {
			return PeerNodeEvidence{}, issueErr
		}
		if err = validateCandidateWriterEvidence(topology, plan, fresh, &candidate, now); err != nil {
			return PeerNodeEvidence{}, err
		}
		freshCandidate = &candidate
	}
	var raw []byte
	err = service.Prepare.DB.QueryRowContext(ctx, `SELECT evidence_json FROM ha_peer_node_evidence_v1 WHERE plan_digest=?`, plan.Digest()).Scan(&raw)
	if err == nil {
		var cached PeerNodeEvidence
		if decodeCanonicalPeerCommitJSON(raw, &cached) != nil || stableNodeEvidence(cached.Node) != stableNodeEvidence(fresh) || validateNodeEvidence(topology, plan, cached, topology.NodeID, now) != nil {
			return PeerNodeEvidence{}, ErrConflict
		}
		if freshCandidate == nil && cached.Candidate != nil || freshCandidate != nil && (cached.Candidate == nil || !peerSame(*cached.Candidate, *freshCandidate)) {
			return PeerNodeEvidence{}, ErrConflict
		}
		return cached, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PeerNodeEvidence{}, err
	}
	evidence := PeerNodeEvidence{PlanDigest: plan.Digest(), Node: fresh, SigningKeyID: local.VoteKeyID}
	evidence.Candidate = freshCandidate
	evidence.Signature, err = service.Prepare.Sign(ctx, evidence.payload())
	if err != nil {
		return PeerNodeEvidence{}, err
	}
	if err = validateNodeEvidence(topology, plan, evidence, topology.NodeID, service.Prepare.now()); err != nil {
		return PeerNodeEvidence{}, err
	}
	if _, err = service.Prepare.DB.ExecContext(ctx, `INSERT INTO ha_peer_node_evidence_v1(plan_digest,evidence_json)VALUES(?,?)`, plan.Digest(), mustPeerVoteJSON(evidence)); err != nil {
		return PeerNodeEvidence{}, err
	}
	return evidence, nil
}

func (service *PeerCommitService) independentlyVerify(ctx context.Context, request PeerCommitRequest) error {
	topology, err := service.Prepare.Topology(ctx)
	if err != nil {
		return err
	}
	if err = validateCommitPlan(topology, request.Plan, service.Prepare.now()); err != nil {
		return err
	}
	if err = validateCommitRequestBinding(request); err != nil {
		return err
	}
	for _, item := range []struct {
		node     NodeID
		evidence PeerNodeEvidence
	}{{request.Plan.Channel.SourceNodeID, request.Source}, {request.Plan.Channel.TargetNodeID, request.Candidate}} {
		node, expected := item.node, item.evidence
		observation := PeerCommitObservationRequest{Plan: request.Plan}
		if node == request.Plan.Channel.TargetNodeID {
			observation.SourceFenceReceipt = append(json.RawMessage(nil), request.Source.Node.SourceFenceReceipt...)
		}
		if err = validateNodeEvidence(topology, request.Plan, expected, node, service.Prepare.now()); err != nil {
			return err
		}
		var observed PeerNodeEvidence
		if node == topology.NodeID {
			observed, err = service.ObserveNode(ctx, topology.NodeID, observation)
		} else {
			found := false
			for _, voter := range topology.Control.Voters {
				if voter.NodeID == node {
					found = true
					observed, err = service.Transport.ObserveCommitNode(ctx, voter, observation)
					break
				}
			}
			if !found {
				return ErrForbidden
			}
		}
		if err != nil || !peerSame(observed, expected) {
			return errors.Join(ErrFenceRequired, err)
		}
	}
	return service.persistSourceFenceReceipt(ctx, request.Plan, request.Source.Node.SourceFenceReceipt)
}

type peerCommitQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func validateLocalCommitPredecessor(ctx context.Context, query peerCommitQueryer, topology PeerVoteTopology, plan PeerCommitPlan, now time.Time) (WriterLease, error) {
	proposal := plan.Prepare.Proposal
	var raw []byte
	if err := query.QueryRowContext(ctx, `SELECT lease_json FROM ha_writer_leases WHERE id=?`, proposal.PreviousLeaseID).Scan(&raw); err != nil {
		return WriterLease{}, errors.Join(err, ErrLeaseLost)
	}
	var old WriterLease
	if decodeCanonicalPeerCommitJSON(raw, &old) != nil || old.Validate(now) != nil || old.ID != proposal.PreviousLeaseID || old.GroupID != proposal.GroupID || old.ResourceID != proposal.ResourceID || old.HolderNodeID != proposal.PreviousWriter || old.FencingToken != proposal.PreviousFencingEpoch || old.AuthorityEpoch != proposal.AuthorityEpoch || !peerSame(old.EnforcedWritePaths, []string{"mariadb-local"}) || (old.State != LeaseActive && old.State != LeaseRevoked && old.State != LeaseExpired) {
		return WriterLease{}, ErrLeaseLost
	}
	var highest uint64
	if err := query.QueryRowContext(ctx, `SELECT COALESCE(MAX(fencing_token),0) FROM ha_writer_leases WHERE resource_id=?`, proposal.ResourceID).Scan(&highest); err != nil || highest != proposal.PreviousFencingEpoch {
		return WriterLease{}, errors.Join(err, ErrLeaseLost)
	}
	var competing int
	if err := query.QueryRowContext(ctx, `SELECT COUNT(*) FROM ha_writer_leases WHERE resource_id=? AND state='active' AND id<>?`, proposal.ResourceID, proposal.PreviousLeaseID).Scan(&competing); err != nil || competing != 0 {
		return WriterLease{}, errors.Join(err, ErrLeaseLost)
	}
	membership := PeerMembershipDigest(topology.GroupID, topology.Control)
	var genesisMembership string
	var genesisRaw []byte
	var closed int
	genesisErr := query.QueryRowContext(ctx, `SELECT membership_digest,lease_json,closed FROM ha_peer_genesis_v1 WHERE group_id=?`, proposal.GroupID).Scan(&genesisMembership, &genesisRaw, &closed)
	if plan.Bootstrap {
		var genesis WriterLease
		if genesisErr != nil || genesisMembership != membership || closed != 0 || decodeCanonicalPeerCommitJSON(genesisRaw, &genesis) != nil || genesis.State != LeaseRevoked || !peerSame(genesis, old) {
			return WriterLease{}, errors.Join(genesisErr, ErrConflict)
		}
		expectedID := "ha_bootstrap_" + membership[:48]
		expectedPlan := peerCommitDigest(struct {
			Domain     string
			Channel    ReplicationChannel
			Checkpoint ReplicationCheckpoint
			Genesis    WriterLease
		}{"cyberpanel-ha-genesis-plan-v1", plan.Channel, plan.Checkpoint, genesis})
		if proposal.ID != expectedID || string(proposal.PromotionID) != expectedID || proposal.PromotionGeneration != 1 || proposal.Coordinator != genesis.HolderNodeID || proposal.PlanDigest != expectedPlan {
			return WriterLease{}, ErrConflict
		}
	} else {
		if genesisErr == nil {
			var genesis WriterLease
			if genesisMembership != membership || (closed != 0 && closed != 1) || decodeCanonicalPeerCommitJSON(genesisRaw, &genesis) != nil || closed == 0 || peerSame(genesis, old) {
				return WriterLease{}, ErrConflict
			}
		} else if !errors.Is(genesisErr, sql.ErrNoRows) {
			return WriterLease{}, genesisErr
		}
	}
	return old, nil
}

func (service *PeerCommitService) CastCommit(ctx context.Context, caller NodeID, request PeerCommitRequest) (PeerCommitVote, error) {
	if service == nil || ctx == nil {
		return PeerCommitVote{}, ErrInvalid
	}
	topology, err := service.Prepare.Topology(ctx)
	if err != nil {
		return PeerCommitVote{}, err
	}
	if caller != request.Plan.Prepare.Proposal.Coordinator {
		return PeerCommitVote{}, ErrForbidden
	}
	if err = service.independentlyVerify(ctx, request); err != nil {
		return PeerCommitVote{}, err
	}
	tx, err := service.Prepare.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return PeerCommitVote{}, err
	}
	defer tx.Rollback()
	proposal := request.Plan.Prepare.Proposal
	var promise string
	if err = tx.QueryRowContext(ctx, `SELECT proposal_digest FROM ha_peer_promotion_votes_v1 WHERE resource_id=? AND topology_epoch=? AND fencing_epoch=?`, proposal.ResourceID, proposal.TopologyEpoch, proposal.FencingEpoch).Scan(&promise); err != nil || promise != proposal.Digest() {
		return PeerCommitVote{}, ErrConflict
	}
	if _, err = validateLocalCommitPredecessor(ctx, tx, topology, request.Plan, service.Prepare.now()); err != nil {
		return PeerCommitVote{}, err
	}
	var raw []byte
	var prior string
	err = tx.QueryRowContext(ctx, `SELECT commit_digest,vote_json FROM ha_peer_commit_votes_v1 WHERE resource_id=? AND topology_epoch=? AND fencing_epoch=?`, proposal.ResourceID, proposal.TopologyEpoch, proposal.FencingEpoch).Scan(&prior, &raw)
	if err == nil {
		var vote PeerCommitVote
		if prior != request.Digest() || decodeCanonicalPeerCommitJSON(raw, &vote) != nil || verifyPeerCommitVote(topology, request, vote, service.Prepare.now()) != nil {
			return PeerCommitVote{}, ErrConflict
		}
		return vote, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PeerCommitVote{}, err
	}
	var local PeerVoter
	for _, voter := range topology.Control.Voters {
		if voter.NodeID == topology.NodeID {
			local = voter
		}
	}
	if local.NodeID == "" {
		return PeerCommitVote{}, ErrForbidden
	}
	issued := service.Prepare.now()
	if latest := latestCommitEvidenceTime(request); latest.After(issued) {
		issued = latest
	}
	vote := PeerCommitVote{VoterID: local.NodeID, SigningKeyID: local.VoteKeyID, CommitDigest: request.Digest(), IssuedAt: issued, ExpiresAt: request.Plan.Lease.ExpiresAt}
	vote.Signature, err = service.Prepare.Sign(ctx, vote.payload())
	if err != nil {
		return PeerCommitVote{}, err
	}
	if err = verifyPeerCommitVote(topology, request, vote, service.Prepare.now()); err != nil {
		return PeerCommitVote{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO ha_peer_commit_votes_v1(resource_id,topology_epoch,fencing_epoch,commit_digest,vote_json)VALUES(?,?,?,?,?)`, proposal.ResourceID, proposal.TopologyEpoch, proposal.FencingEpoch, request.Digest(), mustPeerVoteJSON(vote)); err != nil {
		return PeerCommitVote{}, err
	}
	return vote, tx.Commit()
}

func latestCommitEvidenceTime(request PeerCommitRequest) time.Time {
	latest := request.Plan.Lease.IssuedAt
	for _, value := range []time.Time{request.Source.Node.ObservedAt, request.Candidate.Node.ObservedAt, request.Candidate.Candidate.IssuedAt} {
		if value.After(latest) {
			latest = value
		}
	}
	return latest
}
func verifyPeerCommitVote(topology PeerVoteTopology, request PeerCommitRequest, vote PeerCommitVote, now time.Time) error {
	if !validID(string(vote.VoterID)) || !validID(vote.SigningKeyID) || vote.CommitDigest != request.Digest() || vote.IssuedAt.Before(latestCommitEvidenceTime(request)) || vote.IssuedAt.After(now.Add(5*time.Second)) || !vote.ExpiresAt.After(vote.IssuedAt) || !vote.ExpiresAt.Equal(request.Plan.Lease.ExpiresAt) || !now.Before(vote.ExpiresAt) {
		return ErrNoQuorum
	}
	for _, voter := range topology.Control.Voters {
		if voter.NodeID == vote.VoterID && voter.VoteKeyID == vote.SigningKeyID && ed25519.Verify(ed25519.PublicKey(voter.VotePublicKey), vote.payload(), vote.Signature) {
			return nil
		}
	}
	return ErrNoQuorum
}

func VerifyWriterActivationCertificate(topology PeerVoteTopology, certificate WriterActivationCertificate, now time.Time) error {
	request := certificate.Request
	if err := validateCommitPlan(topology, request.Plan, now); err != nil {
		return err
	}
	if err := validateNodeEvidence(topology, request.Plan, request.Source, request.Plan.Channel.SourceNodeID, now); err != nil {
		return err
	}
	if err := validateNodeEvidence(topology, request.Plan, request.Candidate, request.Plan.Channel.TargetNodeID, now); err != nil {
		return err
	}
	if err := validateCommitRequestBinding(request); err != nil {
		return err
	}
	seen := map[NodeID]bool{}
	for index, vote := range certificate.Votes {
		if seen[vote.VoterID] || index > 0 && certificate.Votes[index-1].VoterID >= vote.VoterID || verifyPeerCommitVote(topology, request, vote, now) != nil {
			return ErrNoQuorum
		}
		seen[vote.VoterID] = true
	}
	if len(seen) < len(topology.Control.Voters)/2+1 {
		return ErrNoQuorum
	}
	return nil
}

func (service *PeerCommitService) AdmitCertificate(ctx context.Context, certificate WriterActivationCertificate) error {
	if service == nil || ctx == nil {
		return ErrInvalid
	}
	topology, err := service.Prepare.Topology(ctx)
	if err != nil {
		return err
	}
	if err = VerifyWriterActivationCertificate(topology, certificate, service.Prepare.now()); err != nil {
		return err
	}
	if err = service.independentlyVerify(ctx, certificate.Request); err != nil {
		return err
	}
	lease := certificate.Request.Plan.Lease
	proposal := certificate.Request.Plan.Prepare.Proposal
	tx, err := service.Prepare.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var stored []byte
	err = tx.QueryRowContext(ctx, `SELECT certificate_json FROM ha_peer_writer_certificates_v1 WHERE resource_id=? AND topology_epoch=? AND fencing_epoch=?`, lease.ResourceID, proposal.TopologyEpoch, lease.FencingToken).Scan(&stored)
	if err == nil {
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	old, err := validateLocalCommitPredecessor(ctx, tx, topology, certificate.Request.Plan, service.Prepare.now())
	if err != nil {
		return err
	}
	// The majority certificate, not elapsed time, retires the old projection.
	if old.State == LeaseActive {
		previous := old.Generation
		old.State = LeaseRevoked
		old.Generation++
		result, updateErr := tx.ExecContext(ctx, `UPDATE ha_writer_leases SET state=?,generation=?,lease_json=? WHERE id=? AND generation=? AND state='active'`, old.State, old.Generation, mustPeerVoteJSON(old), old.ID, previous)
		if updateErr != nil {
			return updateErr
		}
		if changed, countErr := result.RowsAffected(); countErr != nil || changed != 1 {
			return errors.Join(countErr, ErrLeaseLost)
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO ha_writer_leases(id,group_id,resource_id,holder_node_id,fencing_token,authority_epoch,state,generation,lease_json,expires_at)VALUES(?,?,?,?,?,?,?,?,?,?)`, lease.ID, lease.GroupID, lease.ResourceID, lease.HolderNodeID, lease.FencingToken, lease.AuthorityEpoch, lease.State, lease.Generation, mustPeerVoteJSON(lease), lease.ExpiresAt); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO ha_peer_writer_certificates_v1(proof_digest,resource_id,topology_epoch,fencing_epoch,lease_id,certificate_json)VALUES(?,?,?,?,?,?)`, certificate.Digest(), lease.ResourceID, proposal.TopologyEpoch, lease.FencingToken, lease.ID, mustPeerVoteJSON(certificate)); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE ha_peer_genesis_v1 SET closed=1 WHERE group_id=? AND closed=0`, lease.GroupID)
	if err != nil {
		return err
	}
	if certificate.Request.Plan.Bootstrap {
		if changed, countErr := result.RowsAffected(); countErr != nil || changed != 1 {
			return errors.Join(countErr, ErrConflict)
		}
	}
	return tx.Commit()
}

func (service *PeerCommitService) prepareBootstrap(ctx context.Context, channel ReplicationChannel, checkpoint ReplicationCheckpoint) (PeerVoteProof, error) {
	topology, err := service.Prepare.Topology(ctx)
	if err != nil {
		return PeerVoteProof{}, err
	}
	if channel.Validate() != nil || checkpoint.Validate() != nil || channel.Kind != DataDatabase || channel.ResourceID != LocalMariaDBResourceID || channel.GroupID != topology.GroupID || channel.State != ChannelCaughtUp || checkpoint.ChannelID != channel.ID || checkpoint.LagBytes != 0 || checkpoint.LagDuration != 0 {
		return PeerVoteProof{}, ErrCheckpointStale
	}
	genesis, err := service.ReconcileGenesis(ctx)
	if err != nil {
		return PeerVoteProof{}, err
	}
	if topology.NodeID != genesis.HolderNodeID || channel.SourceNodeID != genesis.HolderNodeID {
		return PeerVoteProof{}, ErrForbidden
	}
	var closed int
	if err = service.Prepare.DB.QueryRowContext(ctx, `SELECT closed FROM ha_peer_genesis_v1 WHERE group_id=?`, topology.GroupID).Scan(&closed); err != nil || closed != 0 {
		return PeerVoteProof{}, ErrConflict
	}
	membership := PeerMembershipDigest(topology.GroupID, topology.Control)
	planDigest := peerCommitDigest(struct {
		Domain     string
		Channel    ReplicationChannel
		Checkpoint ReplicationCheckpoint
		Genesis    WriterLease
	}{"cyberpanel-ha-genesis-plan-v1", channel, checkpoint, genesis})
	id := "ha_bootstrap_" + membership[:48]
	var raw []byte
	err = service.Prepare.DB.QueryRowContext(ctx, `SELECT proposal_json FROM ha_peer_vote_proposals_v1 WHERE id=?`, id).Scan(&raw)
	var proposal PeerVoteProposal
	if err == nil {
		if decodeCanonicalPeerCommitJSON(raw, &proposal) != nil || proposal.PlanDigest != planDigest {
			return PeerVoteProof{}, ErrConflict
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		now := service.Prepare.now()
		proposal = PeerVoteProposal{ID: id, Coordinator: topology.NodeID, GroupID: topology.GroupID, ResourceID: LocalMariaDBResourceID, PromotionID: PromotionID(id), PromotionGeneration: 1, PlanDigest: planDigest, Candidate: channel.TargetNodeID, PreviousWriter: channel.SourceNodeID, PreviousLeaseID: genesis.ID, PreviousFencingEpoch: genesis.FencingToken, FencingEpoch: genesis.FencingToken + 1, TopologyEpoch: topology.Control.TopologyEpoch, MembershipDigest: membership, AuthorityEpoch: topology.AuthorityEpoch, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
		if proposal.Validate(now) != nil {
			return PeerVoteProof{}, ErrInvalid
		}
		if _, err = service.Prepare.DB.ExecContext(ctx, `INSERT INTO ha_peer_vote_proposals_v1(id,promotion_id,promotion_generation,membership_digest,proposal_json)VALUES(?,?,?,?,?)`, id, id, 1, membership, mustPeerVoteJSON(proposal)); err != nil {
			return PeerVoteProof{}, err
		}
	} else {
		return PeerVoteProof{}, err
	}
	proof := PeerVoteProof{Proposal: proposal}
	var mutex sync.Mutex
	var pending sync.WaitGroup
	for _, voter := range topology.Control.Voters {
		pending.Add(1)
		go func(voter PeerVoter) {
			defer pending.Done()
			var vote PeerPromotionVote
			var callErr error
			if voter.NodeID == topology.NodeID {
				vote, callErr = service.Prepare.Cast(ctx, topology.NodeID, proposal)
			} else {
				vote, callErr = service.Prepare.Transport.RequestVote(ctx, voter, proposal)
			}
			if callErr == nil && vote.VoterID == voter.NodeID && verifyPeerVote(topology, proposal, vote, service.Prepare.now()) == nil {
				mutex.Lock()
				proof.Votes = append(proof.Votes, vote)
				mutex.Unlock()
			}
		}(voter)
	}
	pending.Wait()
	sort.Slice(proof.Votes, func(i, j int) bool { return proof.Votes[i].VoterID < proof.Votes[j].VoterID })
	if _, err = projectPeerVoteProof(topology, proposal, proof, mustPeerVoteJSON(proof), service.Prepare.now()); err != nil {
		return PeerVoteProof{}, err
	}
	_, err = service.Prepare.DB.ExecContext(ctx, `UPDATE ha_peer_vote_proposals_v1 SET proof_json=? WHERE id=? AND proof_json IS NULL`, mustPeerVoteJSON(proof), id)
	if err != nil {
		return PeerVoteProof{}, err
	}
	if err = service.Prepare.DB.QueryRowContext(ctx, `SELECT proof_json FROM ha_peer_vote_proposals_v1 WHERE id=?`, id).Scan(&raw); err != nil || decodeCanonicalPeerCommitJSON(raw, &proof) != nil {
		return PeerVoteProof{}, ErrConflict
	}
	return proof, nil
}

// Root input names existing records only. Neither lease bytes nor authority
// evidence can be supplied through the collection endpoint.
type PeerCommitInput struct {
	PromotionID  PromotionID  `json:"promotion_id,omitempty"`
	ChannelID    ChannelID    `json:"channel_id,omitempty"`
	CheckpointID CheckpointID `json:"checkpoint_id,omitempty"`
	Bootstrap    bool         `json:"bootstrap"`
}

func (service *PeerCommitService) Collect(ctx context.Context, input PeerCommitInput) (PeerCommitProjection, error) {
	if service == nil || ctx == nil {
		return PeerCommitProjection{}, ErrInvalid
	}
	topology, err := service.Prepare.Topology(ctx)
	if err != nil {
		return PeerCommitProjection{}, err
	}
	store := SQLRepository{DB: service.Prepare.DB}
	var proof PeerVoteProof
	var channel ReplicationChannel
	var checkpoint ReplicationCheckpoint
	if input.Bootstrap {
		if input.PromotionID != "" || !validID(string(input.ChannelID)) || !validID(string(input.CheckpointID)) {
			return PeerCommitProjection{}, ErrInvalid
		}
		channel, err = store.LoadChannel(ctx, input.ChannelID)
		if err != nil {
			return PeerCommitProjection{}, err
		}
		checkpoint, err = store.LoadCheckpoint(ctx, input.CheckpointID)
		if err != nil {
			return PeerCommitProjection{}, err
		}
		proof, err = service.prepareBootstrap(ctx, channel, checkpoint)
		if err != nil {
			return PeerCommitProjection{}, err
		}
	} else {
		if !validID(string(input.PromotionID)) || input.ChannelID != "" || input.CheckpointID != "" {
			return PeerCommitProjection{}, ErrInvalid
		}
		promotion, loadErr := store.LoadPromotion(ctx, input.PromotionID)
		if loadErr != nil {
			return PeerCommitProjection{}, loadErr
		}
		checkpoint, err = store.LoadCheckpoint(ctx, promotion.CheckpointID)
		if err != nil {
			return PeerCommitProjection{}, err
		}
		channel, err = store.LoadChannel(ctx, checkpoint.ChannelID)
		if err != nil {
			return PeerCommitProjection{}, err
		}
		var raw []byte
		err = service.Prepare.DB.QueryRowContext(ctx, `SELECT proof_json FROM ha_peer_vote_proposals_v1 WHERE promotion_id=? AND membership_digest=? AND proof_json IS NOT NULL ORDER BY promotion_generation DESC LIMIT 1`, promotion.ID, PeerMembershipDigest(topology.GroupID, topology.Control)).Scan(&raw)
		if err != nil || decodeCanonicalPeerCommitJSON(raw, &proof) != nil {
			return PeerCommitProjection{}, ErrNoQuorum
		}
		if promotion.Automatic || promotion.PotentialDataLoss || promotion.ID != proof.Proposal.PromotionID || promotion.GroupID != proof.Proposal.GroupID || promotion.ResourceID != proof.Proposal.ResourceID || promotion.Candidate != proof.Proposal.Candidate || promotion.PreviousWriter != proof.Proposal.PreviousWriter || promotion.LeaseID != proof.Proposal.PreviousLeaseID || promotion.CheckpointID != checkpoint.ID || promotion.CheckpointFrontier != checkpoint.WriteFrontier {
			return PeerCommitProjection{}, ErrConflict
		}
	}
	if channel.Validate() != nil || checkpoint.Validate() != nil || channel.GroupID != topology.GroupID || checkpoint.ChannelID != channel.ID {
		return PeerCommitProjection{}, ErrInvalid
	}
	proposal := proof.Proposal
	var raw []byte
	var plan PeerCommitPlan
	err = service.Prepare.DB.QueryRowContext(ctx, `SELECT plan_json FROM ha_peer_commit_plans_v1 WHERE id=?`, proposal.ID).Scan(&raw)
	if err == nil {
		if decodeCanonicalPeerCommitJSON(raw, &plan) != nil || !peerSame(plan.Prepare, proof) || !peerSame(plan.Channel, channel) || !peerSame(plan.Checkpoint, checkpoint) || plan.Bootstrap != input.Bootstrap {
			return PeerCommitProjection{}, ErrConflict
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		now := service.Prepare.now()
		plan = PeerCommitPlan{Prepare: proof, Channel: channel, Checkpoint: checkpoint, Bootstrap: input.Bootstrap, Lease: WriterLease{ID: WriterLeaseID("ha_writer_" + proposal.Digest()[:48]), GroupID: proposal.GroupID, ResourceID: proposal.ResourceID, HolderNodeID: proposal.Candidate, EnforcedWritePaths: []string{"mariadb-local"}, FencingToken: proposal.FencingEpoch, AuthorityEpoch: proposal.AuthorityEpoch, QuorumDigest: proposal.Digest(), IssuedAt: now, RenewAfter: now.Add(10 * time.Second), ExpiresAt: now.Add(20 * time.Second), State: LeaseActive, Generation: 1}}
		if err = validateCommitPlan(topology, plan, now); err != nil {
			return PeerCommitProjection{}, err
		}
		if _, err = service.Prepare.DB.ExecContext(ctx, `INSERT INTO ha_peer_commit_plans_v1(id,plan_json)VALUES(?,?)`, proposal.ID, mustPeerVoteJSON(plan)); err != nil {
			return PeerCommitProjection{}, err
		}
	} else {
		return PeerCommitProjection{}, err
	}
	if err = validateCommitPlan(topology, plan, service.Prepare.now()); err != nil {
		return PeerCommitProjection{}, err
	}
	var certificate WriterActivationCertificate
	if err = service.Prepare.DB.QueryRowContext(ctx, `SELECT certificate_json FROM ha_peer_commit_plans_v1 WHERE id=?`, proposal.ID).Scan(&raw); err != nil {
		return PeerCommitProjection{}, err
	}
	if len(raw) != 0 {
		return PeerCommitProjection{}, ErrConflict
	}
	request := PeerCommitRequest{Plan: plan}
	for _, node := range []NodeID{channel.SourceNodeID, channel.TargetNodeID} {
		observation := PeerCommitObservationRequest{Plan: plan}
		if node == channel.TargetNodeID {
			observation.SourceFenceReceipt = append(json.RawMessage(nil), request.Source.Node.SourceFenceReceipt...)
		}
		var evidence PeerNodeEvidence
		if node == topology.NodeID {
			evidence, err = service.ObserveNode(ctx, topology.NodeID, observation)
		} else {
			found := false
			for _, voter := range topology.Control.Voters {
				if voter.NodeID == node {
					found = true
					evidence, err = service.Transport.ObserveCommitNode(ctx, voter, observation)
					break
				}
			}
			if !found {
				return PeerCommitProjection{}, ErrForbidden
			}
		}
		if err != nil {
			return PeerCommitProjection{}, err
		}
		if node == channel.SourceNodeID {
			request.Source = evidence
		} else {
			request.Candidate = evidence
		}
	}
	if _, err = service.Prepare.DB.ExecContext(ctx, `UPDATE ha_peer_commit_plans_v1 SET request_json=? WHERE id=? AND request_json IS NULL`, mustPeerVoteJSON(request), proposal.ID); err != nil {
		return PeerCommitProjection{}, err
	}
	if err = service.Prepare.DB.QueryRowContext(ctx, `SELECT request_json FROM ha_peer_commit_plans_v1 WHERE id=?`, proposal.ID).Scan(&raw); err != nil || decodeCanonicalPeerCommitJSON(raw, &request) != nil {
		return PeerCommitProjection{}, ErrConflict
	}
	if err = validateCommitRequestBinding(request); err != nil {
		return PeerCommitProjection{}, err
	}
	certificate.Request = request
	var mutex sync.Mutex
	var pending sync.WaitGroup
	for _, voter := range topology.Control.Voters {
		pending.Add(1)
		go func(voter PeerVoter) {
			defer pending.Done()
			var vote PeerCommitVote
			var callErr error
			if voter.NodeID == topology.NodeID {
				vote, callErr = service.CastCommit(ctx, topology.NodeID, request)
			} else {
				vote, callErr = service.Transport.RequestCommit(ctx, voter, request)
			}
			if callErr == nil && vote.VoterID == voter.NodeID {
				mutex.Lock()
				certificate.Votes = append(certificate.Votes, vote)
				mutex.Unlock()
			}
		}(voter)
	}
	pending.Wait()
	sort.Slice(certificate.Votes, func(i, j int) bool { return certificate.Votes[i].VoterID < certificate.Votes[j].VoterID })
	if err = VerifyWriterActivationCertificate(topology, certificate, service.Prepare.now()); err != nil {
		return PeerCommitProjection{}, err
	}
	result, err := service.Prepare.DB.ExecContext(ctx, `UPDATE ha_peer_commit_plans_v1 SET certificate_json=? WHERE id=? AND certificate_json IS NULL`, mustPeerVoteJSON(certificate), proposal.ID)
	if err != nil {
		return PeerCommitProjection{}, err
	}
	if changed, countErr := result.RowsAffected(); countErr != nil || changed != 1 {
		return PeerCommitProjection{}, errors.Join(countErr, ErrConflict)
	}
	if err = service.Prepare.DB.QueryRowContext(ctx, `SELECT certificate_json FROM ha_peer_commit_plans_v1 WHERE id=?`, proposal.ID).Scan(&raw); err != nil || decodeCanonicalPeerCommitJSON(raw, &certificate) != nil || !peerSame(certificate.Request, request) {
		return PeerCommitProjection{}, ErrConflict
	}
	return service.distribute(ctx, topology, certificate)
}
func (service *PeerCommitService) distribute(ctx context.Context, topology PeerVoteTopology, certificate WriterActivationCertificate) (PeerCommitProjection, error) {
	if err := VerifyWriterActivationCertificate(topology, certificate, service.Prepare.now()); err != nil {
		return PeerCommitProjection{}, err
	}
	var mutex sync.Mutex
	var pending sync.WaitGroup
	accepted := map[NodeID]bool{}
	for _, voter := range topology.Control.Voters {
		pending.Add(1)
		go func(voter PeerVoter) {
			defer pending.Done()
			var err error
			if voter.NodeID == topology.NodeID {
				err = service.AdmitCertificate(ctx, certificate)
			} else {
				err = service.Transport.AdmitCommit(ctx, voter, certificate)
			}
			if err == nil {
				mutex.Lock()
				accepted[voter.NodeID] = true
				mutex.Unlock()
			}
		}(voter)
	}
	pending.Wait()
	lease := certificate.Request.Plan.Lease
	if len(accepted) < len(topology.Control.Voters)/2+1 || !accepted[lease.HolderNodeID] {
		return PeerCommitProjection{}, ErrReconciliationRequired
	}
	voters := []NodeID{}
	for _, vote := range certificate.Votes {
		voters = append(voters, vote.VoterID)
	}
	return PeerCommitProjection{ProofDigest: certificate.Digest(), LeaseID: lease.ID, FencingEpoch: lease.FencingToken, Voters: voters, ExpiresAt: lease.ExpiresAt, State: "committed_writer_activation_authority"}, nil
}

type WriterActivationRequest struct {
	SchemaVersion        uint32                  `json:"schema_version"`
	Certificate          CandidateWriterEvidence `json:"certificate"`
	PostFenceCommitProof string                  `json:"post_fence_commit_proof"`
}

func decodeCanonicalPeerCommitJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumWriterActivationBytes || target == nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrInvalid
	}
	return nil
}

type writerActivationVerification uint8

const (
	writerActivationLoad writerActivationVerification = iota
	writerActivationAdmit
	writerActivationActive
)

func verifyWriterActivation(ctx context.Context, db *sql.DB, input WriterActivationRequest, mode writerActivationVerification) error {
	if ctx == nil || db == nil || input.SchemaVersion != writerActivationSchemaVersion || !validDigest(input.PostFenceCommitProof) {
		return ErrForbidden
	}
	topology, err := currentPeerVoteTopology(ctx, db)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var resource, leaseID string
	var topologyEpoch, fencingEpoch uint64
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT resource_id,topology_epoch,fencing_epoch,lease_id,certificate_json FROM ha_peer_writer_certificates_v1 WHERE proof_digest=?`, input.PostFenceCommitProof).Scan(&resource, &topologyEpoch, &fencingEpoch, &leaseID, &raw); err != nil {
		return ErrForbidden
	}
	var certificate WriterActivationCertificate
	now := time.Now().UTC()
	if decodeCanonicalPeerCommitJSON(raw, &certificate) != nil || certificate.Digest() != input.PostFenceCommitProof || VerifyWriterActivationCertificate(topology, certificate, now) != nil || certificate.Request.Candidate.Candidate == nil || !peerSame(*certificate.Request.Candidate.Candidate, input.Certificate) || input.Certificate.SchemaVersion != peerCommitEvidenceSchemaVersion || input.Certificate.Candidate != topology.NodeID {
		return ErrForbidden
	}
	lease := certificate.Request.Plan.Lease
	if resource != lease.ResourceID || topologyEpoch != certificate.Request.Plan.Prepare.Proposal.TopologyEpoch || fencingEpoch != lease.FencingToken || leaseID != string(lease.ID) {
		return ErrForbidden
	}
	if err = verifyPersistedSourceFenceReceipt(ctx, tx, topology, certificate.Request.Plan, certificate.Request.Source.Node.SourceFenceReceipt, now); err != nil {
		return ErrForbidden
	}
	var clusterRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT cluster_json FROM ha_database_clusters WHERE id=?`, input.Certificate.ClusterID).Scan(&clusterRaw); err != nil {
		return ErrForbidden
	}
	var cluster DatabaseCluster
	if decodeCanonicalPeerCommitJSON(clusterRaw, &cluster) != nil || cluster.ID != input.Certificate.ClusterID || cluster.GroupID != lease.GroupID || cluster.Generation != input.Certificate.ClusterGeneration {
		return ErrForbidden
	}
	var activeRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT lease_json FROM ha_writer_leases WHERE resource_id=? AND state='active' ORDER BY authority_epoch DESC,fencing_token DESC LIMIT 1`, LocalMariaDBResourceID).Scan(&activeRaw); err != nil {
		return ErrLeaseLost
	}
	var active WriterLease
	if decodeCanonicalPeerCommitJSON(activeRaw, &active) != nil || !peerSame(active, lease) {
		return ErrLeaseLost
	}
	var activeCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ha_writer_leases WHERE resource_id=? AND state='active'`, LocalMariaDBResourceID).Scan(&activeCount); err != nil || activeCount != 1 {
		return errors.Join(err, ErrLeaseLost)
	}
	var highest uint64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(fencing_token),0) FROM ha_writer_leases WHERE resource_id=?`, LocalMariaDBResourceID).Scan(&highest); err != nil || highest != lease.FencingToken {
		return ErrLeaseLost
	}
	var consumedProof, consumedLease, consumedNode string
	var consumedGeneration uint64
	err = tx.QueryRowContext(ctx, `SELECT proof_digest,lease_id,node_id,lease_generation FROM ha_peer_writer_activation_consumptions_v1 WHERE proof_digest=? OR lease_id=? LIMIT 1`, input.PostFenceCommitProof, lease.ID).Scan(&consumedProof, &consumedLease, &consumedNode, &consumedGeneration)
	consumed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	consumptionMatches := consumed && consumedProof == input.PostFenceCommitProof && consumedLease == string(lease.ID) && consumedNode == string(topology.NodeID) && consumedGeneration == lease.Generation
	switch mode {
	case writerActivationLoad:
		if consumed && !consumptionMatches {
			return ErrConflict
		}
	case writerActivationAdmit:
		if consumed {
			return ErrConflict
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO ha_peer_writer_activation_consumptions_v1(proof_digest,lease_id,node_id,lease_generation,consumed_at)VALUES(?,?,?,?,?)`, input.PostFenceCommitProof, lease.ID, topology.NodeID, lease.Generation, now); err != nil {
			return errors.Join(err, ErrConflict)
		}
	case writerActivationActive:
		if !consumptionMatches {
			return ErrForbidden
		}
	default:
		return ErrInvalid
	}
	return tx.Commit()
}

func decodeWriterActivation(raw json.RawMessage) (WriterActivationRequest, error) {
	var input WriterActivationRequest
	if decodeCanonicalPeerCommitJSON(raw, &input) != nil {
		return WriterActivationRequest{}, ErrForbidden
	}
	return input, nil
}

// AdmitWriterActivation is the one-shot database admission seam. It durably
// consumes the exact certificate for its candidate node and lease generation.
func AdmitWriterActivation(ctx context.Context, db *sql.DB, raw json.RawMessage) error {
	input, err := decodeWriterActivation(raw)
	if err != nil {
		return err
	}
	return verifyWriterActivation(ctx, db, input, writerActivationAdmit)
}

// VerifyWriterActivation preserves the original one-shot seam name. New
// database code should call AdmitWriterActivation for admission and
// VerifyActiveWriterAuthority for its continuous watchdog.
func VerifyWriterActivation(ctx context.Context, db *sql.DB, raw json.RawMessage) error {
	return AdmitWriterActivation(ctx, db, raw)
}

// VerifyActiveWriterAuthority is non-consuming and idempotent for the exact
// admitted proof while its topology, epoch, lease, cluster, and fence receipt
// all remain current. It never admits a proof on its own.
func VerifyActiveWriterAuthority(ctx context.Context, db *sql.DB, raw json.RawMessage) error {
	input, err := decodeWriterActivation(raw)
	if err != nil {
		return err
	}
	return verifyWriterActivation(ctx, db, input, writerActivationActive)
}

// LoadWriterActivation returns opaque canonical JSON. Database code transports
// these bytes unchanged and delegates all certificate semantics back to HA.
func LoadWriterActivation(ctx context.Context, db *sql.DB, lease WriterLease) (json.RawMessage, error) {
	if ctx == nil || db == nil {
		return nil, ErrInvalid
	}
	var raw []byte
	var digest string
	if err := db.QueryRowContext(ctx, `SELECT proof_digest,certificate_json FROM ha_peer_writer_certificates_v1 WHERE lease_id=?`, lease.ID).Scan(&digest, &raw); err != nil {
		return nil, ErrForbidden
	}
	var certificate WriterActivationCertificate
	if decodeCanonicalPeerCommitJSON(raw, &certificate) != nil || certificate.Request.Candidate.Candidate == nil || !peerSame(certificate.Request.Plan.Lease, lease) {
		return nil, ErrForbidden
	}
	input := WriterActivationRequest{SchemaVersion: writerActivationSchemaVersion, Certificate: *certificate.Request.Candidate.Candidate, PostFenceCommitProof: digest}
	if err := verifyWriterActivation(ctx, db, input, writerActivationLoad); err != nil {
		return nil, err
	}
	return json.RawMessage(mustPeerVoteJSON(input)), nil
}
