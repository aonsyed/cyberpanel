package ha

import (
	"context"
	"fmt"
	"time"
)

type SignedNodeIntent struct {
	IntentID string `json:"intent_id"`
	NodeID NodeID `json:"node_id"`
	GroupID NodeGroupID `json:"group_id"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	CapabilitySchemaVersion uint32 `json:"capability_schema_version"`
	Kind string `json:"kind"`
	ResourceID string `json:"resource_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	IdempotencyKey string `json:"idempotency_key"`
	EffectID string `json:"effect_id"`
	PayloadType string `json:"payload_type"`
	PayloadDigest string `json:"payload_digest"`
	Payload []byte `json:"payload"`
	FencingToken uint64 `json:"fencing_token,omitempty"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	SigningKeyID string `json:"signing_key_id"`
	SigningKeyEpoch uint64 `json:"signing_key_epoch"`
	Signature string `json:"signature"`
}

func (intent SignedNodeIntent) Validate(now time.Time) error { if !validID(intent.IntentID) || !validID(string(intent.NodeID)) || !validID(string(intent.GroupID)) || intent.AuthorityEpoch == 0 || intent.CapabilitySchemaVersion == 0 || intent.Kind == "" || intent.ResourceID == "" || intent.ExpectedGeneration == 0 || !validID(intent.IdempotencyKey) || !validID(intent.EffectID) || intent.PayloadType == "" || !validDigest(intent.PayloadDigest) || len(intent.Payload) == 0 || intent.IssuedAt.IsZero() || !intent.ExpiresAt.After(intent.IssuedAt) || !now.Before(intent.ExpiresAt) || !validID(intent.SigningKeyID) || intent.SigningKeyEpoch == 0 || intent.Signature == "" { return ErrInvalid }; return nil }

type NodeIntentReceipt struct { IntentID string `json:"intent_id"`; NodeID NodeID `json:"node_id"`; EffectID string `json:"effect_id"`; Accepted bool `json:"accepted"`; Terminal bool `json:"terminal"`; ObservedGeneration uint64 `json:"observed_generation"`; FencingToken uint64 `json:"fencing_token"`; OutputDigest string `json:"output_digest"`; Receipt string `json:"receipt"`; FailureCode string `json:"failure_code,omitempty"`; AcceptedAt time.Time `json:"accepted_at"`; CompletedAt time.Time `json:"completed_at,omitempty"` }

// Federation accepts a closed typed intent at the owning node. It cannot send
// shell, compose, SSH, SQL, host-path, or daemon-socket instructions.
type Federation interface {
	SubmitNodeIntent(context.Context, SignedNodeIntent) (NodeIntentReceipt, error)
	ObserveNodeIntent(context.Context, NodeID, string) (NodeIntentReceipt, error)
	CancelUnacceptedIntent(context.Context, NodeID, string) error
}

type LeaseAuthority interface {
	AcquireWriterLease(context.Context, WriterLease, QuorumObservation) (WriterLease, error)
	RenewWriterLease(context.Context, WriterLease, QuorumObservation) (WriterLease, error)
	RevokeWriterLease(context.Context, WriterLeaseID, uint64, uint64) error
	ObserveWriterLease(context.Context, WriterLeaseID) (WriterLease, error)
}

type WritePermit struct { ResourceID string `json:"resource_id"`; NodeID NodeID `json:"node_id"`; LeaseID WriterLeaseID `json:"lease_id"`; FencingToken uint64 `json:"fencing_token"`; AuthorityEpoch uint64 `json:"authority_epoch"`; WritePaths []string `json:"write_paths"`; IssuedAt time.Time `json:"issued_at"`; ExpiresAt time.Time `json:"expires_at"`; Signature string `json:"signature"` }
type WriterGate interface { FreezeResourceWrites(context.Context,string,NodeID,uint64,[]string)(string,error); ActivateResourceWrites(context.Context,WriterLease)(WritePermit,error); RevokeWritePermit(context.Context,WritePermit)error }
type WritePermitSigner interface { SignWritePermit(context.Context,WritePermit)(WritePermit,error) }

type FenceRequest struct { Fence Fence `json:"fence"`; Quorum QuorumObservation `json:"quorum"`; ExpectedBootID string `json:"expected_boot_id"`; ApprovalDigest string `json:"approval_digest,omitempty"`; PotentialDataLossAcknowledged bool `json:"potential_data_loss_acknowledged"` }
type FenceReceipt struct { FenceID FenceID `json:"fence_id"`; TargetNodeID NodeID `json:"target_node_id"`; Class FenceClass `json:"class"`; FencingToken uint64 `json:"fencing_token"`; ProtectedWritePaths []string `json:"protected_write_paths"`; ProofDigest string `json:"proof_digest"`; ProviderReceipt string `json:"provider_receipt"`; AppliedAt time.Time `json:"applied_at"`; ValidUntil time.Time `json:"valid_until"` }
type FenceProvider interface { Class() FenceClass; Fence(context.Context, FenceRequest) (FenceReceipt, error); Observe(context.Context, FenceRequest, FenceReceipt) (FenceReceipt, error); Release(context.Context, FenceRequest, FenceReceipt) error }

type StableView struct { ID string `json:"id"`; ResourceID string `json:"resource_id"`; Generation uint64 `json:"generation"`; WriteFrontier uint64 `json:"write_frontier"`; ManifestDigest string `json:"manifest_digest"`; Consistency string `json:"consistency"`; ExpiresAt time.Time `json:"expires_at"` }
type ReplicationExecution struct { Channel ReplicationChannel `json:"channel"`; SourceView StableView `json:"source_view"`; PreviousCheckpoint *ReplicationCheckpoint `json:"previous_checkpoint,omitempty"`; TargetGeneration uint64 `json:"target_generation"`; FencingToken uint64 `json:"fencing_token"`; EncryptedTransferGrant string `json:"encrypted_transfer_grant"` }
type ReplicationReceipt struct { ChannelID ChannelID `json:"channel_id"`; SourceNodeID NodeID `json:"source_node_id"`; TargetNodeID NodeID `json:"target_node_id"`; SourceGeneration uint64 `json:"source_generation"`; WriteFrontier uint64 `json:"write_frontier"`; Position string `json:"position"`; ManifestDigest string `json:"manifest_digest"`; BytesTransferred uint64 `json:"bytes_transferred"`; TargetReceipt string `json:"target_receipt"`; VerifiedAt time.Time `json:"verified_at"` }

type ReplicationExecutor interface {
	CreateStableView(context.Context, ReplicationChannel, uint64) (StableView, error)
	TransferSiteFiles(context.Context, ReplicationExecution) (ReplicationReceipt, error)
	TransferMailboxes(context.Context, ReplicationExecution) (ReplicationReceipt, error)
	TransferDNS(context.Context, ReplicationExecution) (ReplicationReceipt, error)
	TransferContainerVolume(context.Context, ReplicationExecution) (ReplicationReceipt, error)
	TransferBackupCopy(context.Context, ReplicationExecution) (ReplicationReceipt, error)
	VerifyTarget(context.Context, ReplicationExecution, ReplicationReceipt) error
	ReleaseStableView(context.Context, StableView) error
	RebuildTarget(context.Context, ReplicationExecution, ReplicationCheckpoint) (ReplicationReceipt, error)
}

type DatabaseReplicationExecutor interface {
	ObserveCluster(context.Context, DatabaseCluster) (DatabaseCluster, error)
	CreateDatabaseCheckpoint(context.Context, ReplicationChannel, uint64) (ReplicationCheckpoint, error)
	CatchUpReplica(context.Context, ReplicationChannel, ReplicationCheckpoint) (ReplicationReceipt, error)
	FreezeDatabaseWrites(context.Context, DatabaseCluster, NodeID, uint64) (string, error)
	PromoteDatabaseWriter(context.Context, DatabaseCluster, NodeID, WriterLease) (string, uint64, error)
	DemoteDatabaseWriter(context.Context, DatabaseCluster, NodeID, uint64) (string, error)
	RejoinDatabaseMember(context.Context, DatabaseCluster, NodeID, ReplicationCheckpoint) (string, error)
}

type ReplicaIntentKind string
const ( ReplicaPlace ReplicaIntentKind = "place"; ReplicaScale ReplicaIntentKind = "scale"; ReplicaUpdate ReplicaIntentKind = "update"; ReplicaDrain ReplicaIntentKind = "drain"; ReplicaRemove ReplicaIntentKind = "remove" )
type ReplicaIntent struct { Kind ReplicaIntentKind `json:"kind"`; ReplicaSetID ReplicaSetID `json:"replica_set_id"`; ReplicaID ReplicaID `json:"replica_id"`; WorkloadKind WorkloadKind `json:"workload_kind"`; ResourceID string `json:"resource_id"`; Revision string `json:"revision"`; ImageDigest string `json:"image_digest,omitempty"`; ResourceProfileID string `json:"resource_profile_id"`; SecretGrantRef string `json:"secret_grant_ref,omitempty"`; PrivateBindings []string `json:"private_bindings,omitempty"`; DesiredState ReplicaState `json:"desired_state"` }

func (intent ReplicaIntent) Validate() error { if !validID(string(intent.ReplicaSetID)) || !validID(string(intent.ReplicaID)) || intent.ResourceID == "" || intent.Revision == "" || !validID(intent.ResourceProfileID) { return ErrInvalid }; if intent.WorkloadKind == WorkloadContainer && (!validDigest(intent.ImageDigest) || intent.SecretGrantRef == "") { return ErrInvalid }; return nil }

type TrafficObservation struct { PolicyID TrafficPolicyID `json:"policy_id"`; Revision string `json:"revision"`; Digest string `json:"digest"`; Endpoints []TrafficEndpoint `json:"endpoints"`; ObservedAt time.Time `json:"observed_at"` }
type TrafficChange struct { Policy TrafficPolicy `json:"policy"`; EffectID string `json:"effect_id"`; Before TrafficObservation `json:"before"`; Desired TrafficObservation `json:"desired"` }
type TrafficReceipt struct { PolicyID TrafficPolicyID `json:"policy_id"`; EffectID string `json:"effect_id"`; BeforeDigest string `json:"before_digest"`; OutputDigest string `json:"output_digest"`; Revision string `json:"revision"`; ProviderReceipt string `json:"provider_receipt"`; AppliedAt time.Time `json:"applied_at"` }
type TrafficProvider interface { Observe(context.Context, TrafficPolicy) (TrafficObservation, error); ApplyConditional(context.Context, TrafficChange) (TrafficReceipt, error); ApplyObserve(context.Context, TrafficChange) (TrafficReceipt, error); CompensateConditional(context.Context, TrafficChange, TrafficReceipt) (TrafficReceipt, error) }

type PromotionExecutor interface {
	FreezeWorkloadWrites(context.Context, Promotion, uint64) (string, error)
	ActivateCandidateServices(context.Context, Promotion, WriterLease) (string, uint64, error)
	DemotePreviousServices(context.Context, Promotion, uint64) (string, error)
	ProbeCandidate(context.Context, Promotion) (string, error)
	ProbeExternalTraffic(context.Context, Promotion, TrafficReceipt) (string, error)
	RestorePreviousServices(context.Context, Promotion, uint64) (string, error)
	KeepPreviousFenced(context.Context, Promotion, time.Time) error
}

type BackupConsistency interface {
	LatestVerifiedCheckpoint(context.Context, string, NodeID, NodeID) (ReplicationCheckpoint, error)
	VerifyIndependentBackupCopy(context.Context, string, NodeID) (BackupReplicaCopy, error)
	ProtectRecoveryEvidence(context.Context, string, time.Time) error
}

type HealthAuthority interface {
	ObserveNode(context.Context, NodeID) (HealthObservation, error)
	Quorum(context.Context, NodeGroupID) (QuorumObservation, error)
}

type ManualFenceConfirmer interface {
	VerifyAdministrativeFence(context.Context, Fence, []Approval) (FenceReceipt, error)
}

func validateFenceCoverage(fences []FenceReceipt, required []string, now time.Time) error { covered := map[string]bool{}; for _, fence := range fences { if fence.ProofDigest == "" || !now.Before(fence.ValidUntil) { return ErrFenceFailed }; for _, path := range fence.ProtectedWritePaths { covered[path] = true } }; for _, path := range required { if !covered[path] { return fmt.Errorf("%w: uncovered write path %s", ErrFenceRequired, path) } }; return nil }
