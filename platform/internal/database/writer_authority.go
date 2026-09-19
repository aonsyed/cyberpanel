package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

const (
	databaseWriterEvidenceSchemaVersion     uint32 = 1
	databaseWriterTransferSchemaVersion     uint32 = 1
	databaseWriterAuthoritySchemaVersion    uint32 = 1
	databaseSourceFenceReceiptSchemaVersion uint32 = 1
	databaseSourceFenceAction                      = "freeze"
	databaseSourceFenceOutcome                     = "source_fenced_observed_v1"
	maximumWriterAuthorityJSON                     = 256 << 10
)

// DatabaseWriterFenceAuthority is the package-local transport mirror for HA's
// canonical source-fence authority. HA alone constructs and authenticates
// these opaque bytes; the root database broker never derives authority from
// individual caller fields.
type DatabaseWriterFenceAuthority struct {
	SchemaVersion    uint32                   `json:"schema_version"`
	ProposalID       string                   `json:"proposal_id"`
	PlanDigest       string                   `json:"plan_digest"`
	PromotionID      ha.PromotionID           `json:"promotion_id"`
	PreviousLeaseID  ha.WriterLeaseID         `json:"previous_lease_id"`
	AuthorityEpoch   uint64                   `json:"authority_epoch"`
	TopologyEpoch    uint64                   `json:"topology_epoch"`
	TopologyDigest   string                   `json:"topology_digest"`
	MembershipDigest string                   `json:"membership_digest"`
	DeploymentEpoch  uint64                   `json:"deployment_epoch"`
	DeploymentDigest string                   `json:"deployment_digest"`
	Cluster          ha.DatabaseCluster       `json:"cluster"`
	SourceNodeID     ha.NodeID                `json:"source_node_id"`
	FencingToken     uint64                   `json:"fencing_token"`
	Channel          ha.ReplicationChannel    `json:"channel"`
	Checkpoint       ha.ReplicationCheckpoint `json:"checkpoint"`
	ExpiresAt        time.Time                `json:"expires_at"`
}

// DatabaseWriterCandidateAuthority is the corresponding candidate authority.
// SourceFenceReceipt is the exact byte string persisted by the old writer; no
// candidate or transport caller may reconstruct or edit it.
type DatabaseWriterCandidateAuthority struct {
	SchemaVersion      uint32                   `json:"schema_version"`
	ProposalID         string                   `json:"proposal_id"`
	PlanDigest         string                   `json:"plan_digest"`
	PromotionID        ha.PromotionID           `json:"promotion_id"`
	PreviousLeaseID    ha.WriterLeaseID         `json:"previous_lease_id"`
	AuthorityEpoch     uint64                   `json:"authority_epoch"`
	TopologyEpoch      uint64                   `json:"topology_epoch"`
	TopologyDigest     string                   `json:"topology_digest"`
	MembershipDigest   string                   `json:"membership_digest"`
	DeploymentEpoch    uint64                   `json:"deployment_epoch"`
	DeploymentDigest   string                   `json:"deployment_digest"`
	Cluster            ha.DatabaseCluster       `json:"cluster"`
	SourceNodeID       ha.NodeID                `json:"source_node_id"`
	CandidateNodeID    ha.NodeID                `json:"candidate_node_id"`
	FencingToken       uint64                   `json:"fencing_token"`
	Channel            ha.ReplicationChannel    `json:"channel"`
	Checkpoint         ha.ReplicationCheckpoint `json:"checkpoint"`
	Lease              ha.WriterLease           `json:"lease"`
	SourceFenceReceipt json.RawMessage          `json:"source_fence_receipt"`
	ExpiresAt          time.Time                `json:"expires_at"`
}

// DatabaseSourceFenceReceipt is the fixed v1 canonical source receipt. Its raw
// JSON is written once and SHA-256 hashed exactly as stored. Observer time and
// the node-local evidence seal remain outside this shared receipt.
type DatabaseSourceFenceReceipt struct {
	SchemaVersion     uint32                   `json:"schema_version"`
	AuthorityEpoch    uint64                   `json:"authority_epoch"`
	ClusterGeneration uint64                   `json:"cluster_generation"`
	PromotionID       ha.PromotionID           `json:"promotion_id"`
	PreviousLeaseID   ha.WriterLeaseID         `json:"previous_lease_id"`
	EffectID          string                   `json:"effect_id"`
	Action            string                   `json:"action"`
	ClusterID         ha.ID                    `json:"cluster_id"`
	SourceNodeID      ha.NodeID                `json:"source_node_id"`
	FencingToken      uint64                   `json:"fencing_token"`
	ReadOnly          bool                     `json:"read_only"`
	Checkpoint        ha.ReplicationCheckpoint `json:"checkpoint"`
	Outcome           string                   `json:"outcome"`
	ProofDigest       string                   `json:"proof_digest"`
	FencedAt          time.Time                `json:"fenced_at"`
	ExpiresAt         time.Time                `json:"expires_at"`
}

// DatabaseWriterCertificate is candidate-node evidence, not quorum authority.
// LocalSeal protects the root journal only; a remote verifier must authenticate
// the owning node and validate a separately admitted post-fence majority commit.
// In particular Checkpoint alone does NOT prove privileged old-writer fencing.
type DatabaseWriterCertificate struct {
	SchemaVersion      uint32                   `json:"schema_version"`
	ID                 string                   `json:"id"`
	Channel            ha.ReplicationChannel    `json:"channel"`
	Checkpoint         ha.ReplicationCheckpoint `json:"checkpoint"`
	ClusterID          ha.ID                    `json:"cluster_id"`
	ClusterGeneration  uint64                   `json:"cluster_generation"`
	TopologyDigest     string                   `json:"topology_digest"`
	DeploymentDigest   string                   `json:"deployment_digest"`
	DeploymentEpoch    uint64                   `json:"deployment_epoch"`
	AuthorityEpoch     uint64                   `json:"authority_epoch"`
	OldWriter          ha.NodeID                `json:"old_writer"`
	Candidate          ha.NodeID                `json:"candidate"`
	Lease              ha.WriterLease           `json:"lease"`
	FenceEffectID      string                   `json:"fence_effect_id"`
	FenceDigest        string                   `json:"fence_digest"`
	ReplicaDigest      string                   `json:"replica_digest"`
	SessionFenceDigest string                   `json:"session_fence_digest"`
	GTID               string                   `json:"gtid"`
	Frontier           uint64                   `json:"frontier"`
	IssuedAt           time.Time                `json:"issued_at"`
	ExpiresAt          time.Time                `json:"expires_at"`
	LocalSeal          string                   `json:"local_seal"`
}

// PostFenceCommitProof is a digest reference to a durable authority record,
// never inline caller JSON or a prepare vote. The injected verifier must check
// configured membership/majority, node signatures, old-writer session fencing,
// the exact certificate digest, current epoch, lease and revocation state.
type DatabaseWriterTransfer struct {
	SchemaVersion        uint32                    `json:"schema_version"`
	Certificate          DatabaseWriterCertificate `json:"certificate"`
	PostFenceCommitProof string                    `json:"post_fence_commit_proof"`
}

// DatabaseWriterFenceEvidence mirrors HA's NodeFenceEvidence JSON in this one
// adapter file. SourceFenceReceipt is identical on both nodes. CursorDigest is
// SHA-256 over those exact raw bytes; the observation and local seal are
// intentionally node-specific.
type DatabaseWriterFenceEvidence struct {
	SchemaVersion      uint32                   `json:"schema_version"`
	Channel            ha.ReplicationChannel    `json:"channel"`
	Checkpoint         ha.ReplicationCheckpoint `json:"checkpoint"`
	NodeID             ha.NodeID                `json:"node_id"`
	AuthorityEpoch     uint64                   `json:"authority_epoch"`
	DeploymentEpoch    uint64                   `json:"deployment_epoch"`
	DeploymentDigest   string                   `json:"deployment_digest"`
	FencingToken       uint64                   `json:"fencing_token"`
	GTID               string                   `json:"gtid"`
	Frontier           uint64                   `json:"frontier"`
	SourceFenceReceipt json.RawMessage          `json:"source_fence_receipt"`
	CursorDigest       string                   `json:"cursor_digest"`
	SessionFenceDigest string                   `json:"session_fence_digest"`
	ObservationDigest  string                   `json:"observation_digest"`
	ReplicaDigest      string                   `json:"replica_digest"`
	ObservedAt         time.Time                `json:"observed_at"`
	ExpiresAt          time.Time                `json:"expires_at"`
	LocalSeal          string                   `json:"local_seal"`
}

func decodeCanonicalWriterJSON(raw json.RawMessage, target any) error {
	if len(raw) == 0 || len(raw) > maximumWriterAuthorityJSON || target == nil {
		return ErrUnauthorized
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrUnauthorized
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrUnauthorized
	}
	return nil
}

func decodeDatabaseWriterFenceAuthority(raw json.RawMessage) (DatabaseWriterFenceAuthority, error) {
	var authority DatabaseWriterFenceAuthority
	if decodeCanonicalWriterJSON(raw, &authority) != nil || !validDatabaseWriterFenceAuthority(authority, time.Now().UTC()) {
		return DatabaseWriterFenceAuthority{}, ErrUnauthorized
	}
	return authority, nil
}

func decodeDatabaseWriterCandidateAuthority(raw json.RawMessage) (DatabaseWriterCandidateAuthority, error) {
	var authority DatabaseWriterCandidateAuthority
	if decodeCanonicalWriterJSON(raw, &authority) != nil || !validDatabaseWriterCandidateAuthority(authority, time.Now().UTC()) {
		return DatabaseWriterCandidateAuthority{}, ErrUnauthorized
	}
	return authority, nil
}

func decodeDatabaseSourceFenceReceipt(raw json.RawMessage) (DatabaseSourceFenceReceipt, error) {
	var receipt DatabaseSourceFenceReceipt
	if decodeCanonicalWriterJSON(raw, &receipt) != nil || !validDatabaseSourceFenceReceipt(receipt) {
		return DatabaseSourceFenceReceipt{}, ErrUnauthorized
	}
	return receipt, nil
}

func validDatabaseWriterFenceAuthority(authority DatabaseWriterFenceAuthority, now time.Time) bool {
	return authority.SchemaVersion == databaseWriterAuthoritySchemaVersion && authority.ProposalID != "" &&
		validSHA256(authority.PlanDigest) && authority.PromotionID != "" && authority.PreviousLeaseID != "" &&
		authority.AuthorityEpoch > 0 && authority.TopologyEpoch > 0 && validSHA256(authority.TopologyDigest) && validSHA256(authority.MembershipDigest) &&
		authority.DeploymentEpoch > 0 && validSHA256(authority.DeploymentDigest) &&
		authority.Cluster.Validate() == nil && authority.Cluster.ID == "mariadb-local" && authority.Cluster.Topology == ha.DatabasePrimaryReplica && authority.SourceNodeID == authority.Channel.SourceNodeID && authority.FencingToken > 0 &&
		validMariaDBReplicationChannel(authority.Channel) && authority.Channel.Kind == ha.DataDatabase && authority.Channel.ResourceID == string(authority.Cluster.ID) && authority.Channel.GroupID == authority.Cluster.GroupID &&
		authority.Checkpoint.Validate() == nil && authority.Checkpoint.ChannelID == authority.Channel.ID && authority.Checkpoint.LagBytes == 0 && authority.Checkpoint.LagDuration == 0 &&
		!authority.ExpiresAt.IsZero() && now.Before(authority.ExpiresAt)
}

func validDatabaseWriterCandidateAuthority(authority DatabaseWriterCandidateAuthority, now time.Time) bool {
	base := DatabaseWriterFenceAuthority{SchemaVersion: authority.SchemaVersion, ProposalID: authority.ProposalID, PlanDigest: authority.PlanDigest, PromotionID: authority.PromotionID, PreviousLeaseID: authority.PreviousLeaseID, AuthorityEpoch: authority.AuthorityEpoch, TopologyEpoch: authority.TopologyEpoch, TopologyDigest: authority.TopologyDigest, MembershipDigest: authority.MembershipDigest, DeploymentEpoch: authority.DeploymentEpoch, DeploymentDigest: authority.DeploymentDigest, Cluster: authority.Cluster, SourceNodeID: authority.SourceNodeID, FencingToken: authority.FencingToken, Channel: authority.Channel, Checkpoint: authority.Checkpoint, ExpiresAt: authority.ExpiresAt}
	lease := authority.Lease
	exactLease := lease.Validate(now) == nil && lease.State == ha.LeaseActive && lease.ResourceID == string(authority.Cluster.ID) && lease.GroupID == authority.Cluster.GroupID && lease.HolderNodeID == authority.CandidateNodeID && len(lease.EnforcedWritePaths) == 1 && lease.EnforcedWritePaths[0] == "mariadb-local" && !lease.IssuedAt.After(now.Add(5*time.Second)) && lease.ExpiresAt.Sub(lease.IssuedAt) <= 30*time.Second
	if !validDatabaseWriterFenceAuthority(base, now) || authority.CandidateNodeID != authority.Channel.TargetNodeID || !exactLease || lease.FencingToken != authority.FencingToken || lease.AuthorityEpoch != authority.AuthorityEpoch || !lease.ExpiresAt.Equal(authority.ExpiresAt) {
		return false
	}
	receipt, err := decodeDatabaseSourceFenceReceipt(authority.SourceFenceReceipt)
	return err == nil && !receipt.FencedAt.Before(authority.Lease.IssuedAt.Add(-5*time.Second)) && receipt.FencedAt.Before(now.Add(5*time.Second)) && sourceFenceReceiptMatchesAuthority(receipt, base)
}

func sameWriterValue(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func writerDigestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func certificatePayload(value DatabaseWriterCertificate) []byte {
	value.ID = ""
	value.LocalSeal = ""
	payload, _ := json.Marshal(value)
	return payload
}

func validDatabaseWriterCertificate(certificate DatabaseWriterCertificate, now time.Time) bool {
	lease := certificate.Lease
	return certificate.SchemaVersion == databaseWriterEvidenceSchemaVersion && validMariaDBReplicationChannel(certificate.Channel) && certificate.Checkpoint.Validate() == nil && certificate.Checkpoint.ChannelID == certificate.Channel.ID && certificate.ClusterID == "mariadb-local" && certificate.ClusterGeneration > 0 && certificate.Channel.ResourceID == string(certificate.ClusterID) && certificate.Channel.GroupID == lease.GroupID && certificate.OldWriter == certificate.Channel.SourceNodeID && certificate.Candidate == certificate.Channel.TargetNodeID && certificate.OldWriter != certificate.Candidate && lease.Validate(now) == nil && lease.State == ha.LeaseActive && lease.ResourceID == string(certificate.ClusterID) && lease.HolderNodeID == certificate.Candidate && len(lease.EnforcedWritePaths) == 1 && lease.EnforcedWritePaths[0] == "mariadb-local" && certificate.AuthorityEpoch == lease.AuthorityEpoch && certificate.DeploymentEpoch > 0 && validSHA256(certificate.TopologyDigest) && validSHA256(certificate.DeploymentDigest) && validSHA256(certificate.FenceDigest) && validSHA256(certificate.ReplicaDigest) && validSHA256(certificate.SessionFenceDigest) && certificate.FenceEffectID != "" && certificate.GTID == certificate.Checkpoint.Position && certificate.Frontier == certificate.Checkpoint.WriteFrontier && !certificate.IssuedAt.IsZero() && !certificate.IssuedAt.After(now.Add(5*time.Second)) && certificate.ExpiresAt.Equal(lease.ExpiresAt) && certificate.ExpiresAt.After(certificate.IssuedAt) && certificate.ExpiresAt.Sub(certificate.IssuedAt) <= 30*time.Second && certificate.ID == writerDigestBytes(certificatePayload(certificate)) && validSHA256(certificate.ID) && validSHA256(certificate.LocalSeal)
}

func validDatabaseWriterFenceEvidence(value DatabaseWriterFenceEvidence) bool {
	receipt, err := decodeDatabaseSourceFenceReceipt(value.SourceFenceReceipt)
	if err != nil || value.SchemaVersion != databaseWriterEvidenceSchemaVersion || !validMariaDBReplicationChannel(value.Channel) || value.Checkpoint.Validate() != nil || value.Checkpoint.ChannelID != value.Channel.ID || value.NodeID == "" || value.AuthorityEpoch == 0 || value.DeploymentEpoch == 0 || !validSHA256(value.DeploymentDigest) || value.FencingToken == 0 || value.GTID != value.Checkpoint.Position || value.Frontier != value.Checkpoint.WriteFrontier || value.CursorDigest != writerDigestBytes(value.SourceFenceReceipt) || !validSHA256(value.CursorDigest) || !validSHA256(value.SessionFenceDigest) || !validSHA256(value.ObservationDigest) || value.ObservedAt.IsZero() || value.ObservedAt.Before(receipt.FencedAt) || !value.ExpiresAt.After(value.ObservedAt) || !value.ExpiresAt.Equal(receipt.ExpiresAt) || !validSHA256(value.LocalSeal) {
		return false
	}
	if value.NodeID == value.Channel.TargetNodeID {
		return validSHA256(value.ReplicaDigest)
	}
	return value.NodeID == value.Channel.SourceNodeID && value.ReplicaDigest == ""
}

func validDatabaseSourceFenceReceipt(receipt DatabaseSourceFenceReceipt) bool {
	now := time.Now().UTC()
	return receipt.SchemaVersion == databaseSourceFenceReceiptSchemaVersion && receipt.AuthorityEpoch > 0 && receipt.ClusterGeneration > 0 && receipt.PromotionID != "" && receipt.PreviousLeaseID != "" && receipt.EffectID != "" && receipt.Action == databaseSourceFenceAction && receipt.ClusterID == "mariadb-local" && receipt.SourceNodeID != "" && receipt.FencingToken > 0 && receipt.ReadOnly && receipt.Checkpoint.Validate() == nil && receipt.Outcome == databaseSourceFenceOutcome && validSHA256(receipt.ProofDigest) && !receipt.FencedAt.IsZero() && receipt.FencedAt.Before(now.Add(5*time.Second)) && receipt.ExpiresAt.After(receipt.FencedAt) && now.Before(receipt.ExpiresAt)
}

func sourceFenceReceiptMatchesAuthority(receipt DatabaseSourceFenceReceipt, authority DatabaseWriterFenceAuthority) bool {
	return receipt.AuthorityEpoch == authority.AuthorityEpoch && receipt.ClusterGeneration == authority.Cluster.Generation && receipt.PromotionID == authority.PromotionID && receipt.PreviousLeaseID == authority.PreviousLeaseID && receipt.ClusterID == authority.Cluster.ID && receipt.SourceNodeID == authority.SourceNodeID && receipt.FencingToken == authority.FencingToken && sameWriterValue(receipt.Checkpoint, authority.Checkpoint) && receipt.ExpiresAt.Equal(authority.ExpiresAt)
}

func (client *BrokerClient) observeDatabaseWriterEvidence(ctx context.Context, action MariaDBHAAction, authority json.RawMessage) (DatabaseWriterFenceEvidence, error) {
	result, err := client.mariaDBHA(ctx, MariaDBHARequest{Action: action, WriterAuthority: append(json.RawMessage(nil), authority...)})
	if err != nil {
		return DatabaseWriterFenceEvidence{}, err
	}
	return *result.WriterFenceEvidence, nil
}

// ObserveDatabaseWriterFence is the source-node HA adapter seam. The caller
// transports HA's opaque authenticated authority and receives canonical local
// evidence containing the newly persisted exact source receipt.
func (client *BrokerClient) ObserveDatabaseWriterFence(ctx context.Context, authority json.RawMessage) (json.RawMessage, error) {
	evidence, err := client.observeDatabaseWriterEvidence(ctx, MariaDBHAWriterFenceEvidence, authority)
	if err != nil {
		return nil, err
	}
	return json.Marshal(evidence)
}

// ObserveDatabaseWriterCandidate observes the target replica and privileged
// session boundary while carrying the exact source receipt inside authority.
func (client *BrokerClient) ObserveDatabaseWriterCandidate(ctx context.Context, authority json.RawMessage) (json.RawMessage, error) {
	evidence, err := client.observeDatabaseWriterEvidence(ctx, MariaDBHAWriterCandidateEvidence, authority)
	if err != nil {
		return nil, err
	}
	return json.Marshal(evidence)
}

// WriterCertificateJSON emits candidate evidence from the same opaque target
// authority. It is never activation authority by itself.
func (client *BrokerClient) WriterCertificateJSON(ctx context.Context, authority json.RawMessage) (json.RawMessage, error) {
	result, err := client.mariaDBHA(ctx, MariaDBHARequest{Action: MariaDBHAWriterCertificate, WriterAuthority: append(json.RawMessage(nil), authority...)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(result.WriterCertificate)
}

// decodeDatabaseWriterTransfer accepts only the three-field HA activation
// adapter contract. Prepare proofs, caller quorum observations, and expanded
// envelopes cannot be smuggled through unknown JSON fields.
func decodeDatabaseWriterTransfer(raw json.RawMessage) (DatabaseWriterTransfer, error) {
	var transfer DatabaseWriterTransfer
	if decodeCanonicalWriterJSON(raw, &transfer) != nil || transfer.SchemaVersion != databaseWriterTransferSchemaVersion || transfer.Certificate.SchemaVersion != databaseWriterEvidenceSchemaVersion {
		return DatabaseWriterTransfer{}, ErrUnauthorized
	}
	return transfer, nil
}

func databaseWriterTransferJSON(transfer DatabaseWriterTransfer) (json.RawMessage, error) {
	raw, err := json.Marshal(transfer)
	if err != nil || len(raw) == 0 || len(raw) > maximumWriterAuthorityJSON {
		return nil, ErrUnauthorized
	}
	return raw, nil
}
