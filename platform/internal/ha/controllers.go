package ha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

type TransferGrantIssuer interface { IssueReplicationGrant(context.Context, ReplicationChannel, StableView, time.Time) (string, error) }

type LocalChannelBinding struct {
	ChannelID    ChannelID   `json:"channel_id"`
	TenantID     string      `json:"tenant_id"`
	GroupID      NodeGroupID `json:"group_id"`
	ResourceID   string      `json:"resource_id"`
	SourceNodeID NodeID      `json:"source_node_id"`
	TargetNodeID NodeID      `json:"target_node_id"`
	Generation   uint64      `json:"generation"`
	UpdatedAt    time.Time   `json:"updated_at"`
}

func (binding LocalChannelBinding) Validate() error {
	if !validID(string(binding.ChannelID)) || !validID(binding.TenantID) || !validID(string(binding.GroupID)) || binding.ResourceID == "" || !validID(string(binding.SourceNodeID)) || !validID(string(binding.TargetNodeID)) || binding.SourceNodeID == binding.TargetNodeID || binding.Generation == 0 || binding.Generation > uint64(1<<63-1) || binding.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type LocalReplicationEvidence struct {
	EvidenceID        ID           `json:"evidence_id"`
	OperationID       OperationID  `json:"operation_id"`
	TenantID          string       `json:"tenant_id"`
	GroupID           NodeGroupID  `json:"group_id"`
	ResourceID        string       `json:"resource_id"`
	ChannelID         ChannelID    `json:"channel_id"`
	SourceNodeID      NodeID       `json:"source_node_id"`
	TargetNodeID      NodeID       `json:"target_node_id"`
	BindingGeneration uint64       `json:"binding_generation"`
	SourceGeneration  uint64       `json:"source_generation"`
	TargetGeneration  uint64       `json:"target_generation"`
	CheckpointID      CheckpointID `json:"checkpoint_id"`
	WriteFrontier     uint64       `json:"write_frontier"`
	ManifestDigest    string       `json:"manifest_digest"`
	Sequence          uint64       `json:"sequence"`
	CaughtUp          bool         `json:"caught_up"`
	Healthy           bool         `json:"healthy"`
	EvidenceDigest    string       `json:"evidence_digest"`
	ObservedAt        time.Time    `json:"observed_at"`
	ValidUntil        time.Time    `json:"valid_until"`
}

func (evidence LocalReplicationEvidence) Validate() error {
	if !validID(string(evidence.EvidenceID)) || !validID(string(evidence.OperationID)) || !validID(evidence.TenantID) || !validID(string(evidence.GroupID)) || evidence.ResourceID == "" || !validID(string(evidence.ChannelID)) || !validID(string(evidence.SourceNodeID)) || !validID(string(evidence.TargetNodeID)) || evidence.SourceNodeID == evidence.TargetNodeID || evidence.BindingGeneration == 0 || evidence.SourceGeneration == 0 || evidence.TargetGeneration == 0 || evidence.Sequence == 0 || evidence.BindingGeneration > uint64(1<<63-1) || evidence.SourceGeneration > uint64(1<<63-1) || evidence.TargetGeneration > uint64(1<<63-1) || evidence.Sequence > uint64(1<<63-1) || evidence.ObservedAt.IsZero() || !evidence.ValidUntil.After(evidence.ObservedAt) || !validDigest(evidence.EvidenceDigest) {
		return ErrInvalid
	}
	if evidence.CaughtUp && (!evidence.Healthy || !validID(string(evidence.CheckpointID)) || evidence.WriteFrontier == 0 || !validDigest(evidence.ManifestDigest)) {
		return ErrInvalid
	}
	digest, err := evidence.Digest()
	if err != nil {
		return err
	}
	if digest != evidence.EvidenceDigest {
		return ErrConflict
	}
	return nil
}

func (evidence LocalReplicationEvidence) Digest() (string, error) {
	evidence.EvidenceDigest = ""
	payload, err := json.Marshal(struct {
		Domain   string                   `json:"domain"`
		Evidence LocalReplicationEvidence `json:"evidence"`
	}{Domain:"cyberpanel-ha-local-replication-evidence-v1", Evidence:evidence})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func (evidence LocalReplicationEvidence) Usable(now time.Time) bool {
	return evidence.Validate() == nil && evidence.Healthy && evidence.CaughtUp && now.Before(evidence.ValidUntil)
}

type ReplicationChannelHealth struct {
	ChannelID         ChannelID    `json:"channel_id"`
	ChannelGeneration uint64       `json:"channel_generation"`
	SourceGeneration  uint64       `json:"source_generation"`
	TargetGeneration  uint64       `json:"target_generation"`
	CheckpointID      CheckpointID `json:"checkpoint_id,omitempty"`
	WriteFrontier     uint64       `json:"write_frontier,omitempty"`
	State             ChannelState `json:"state"`
	Healthy           bool         `json:"healthy"`
	CaughtUp          bool         `json:"caught_up"`
	FailureDigest     string       `json:"failure_digest,omitempty"`
	EvidenceDigest    string       `json:"evidence_digest"`
	ObservedAt        time.Time    `json:"observed_at"`
	ValidUntil        time.Time    `json:"valid_until"`
}

func (health ReplicationChannelHealth) Validate() error {
	if !validID(string(health.ChannelID)) || health.ChannelGeneration == 0 || health.SourceGeneration == 0 || health.TargetGeneration == 0 || health.ChannelGeneration > uint64(1<<63-1) || health.SourceGeneration > uint64(1<<63-1) || health.TargetGeneration > uint64(1<<63-1) || health.ObservedAt.IsZero() || !health.ValidUntil.After(health.ObservedAt) || !validDigest(health.EvidenceDigest) {
		return ErrInvalid
	}
	switch health.State {
	case ChannelCaughtUp:
		if !health.Healthy || !health.CaughtUp || !validID(string(health.CheckpointID)) || health.WriteFrontier == 0 || health.FailureDigest != "" {
			return ErrInvalid
		}
	case ChannelFailed:
		if health.Healthy || health.CaughtUp || health.CheckpointID != "" || health.WriteFrontier != 0 || !validDigest(health.FailureDigest) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	digest, err := health.Digest()
	if err != nil {
		return err
	}
	if digest != health.EvidenceDigest {
		return ErrConflict
	}
	return nil
}

func (health ReplicationChannelHealth) Digest() (string, error) {
	health.EvidenceDigest = ""
	payload, err := json.Marshal(struct {
		Domain string                   `json:"domain"`
		Health ReplicationChannelHealth `json:"health"`
	}{Domain:"cyberpanel-ha-replication-health-v1", Health:health})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

type ReplicationCoordinator struct { Store Store; Executor ReplicationExecutor; Database DatabaseReplicationExecutor; Grants TransferGrantIssuer; Now func() time.Time }
func (coordinator ReplicationCoordinator) now() time.Time { if coordinator.Now != nil { return coordinator.Now().UTC() }; return time.Now().UTC() }

func (coordinator ReplicationCoordinator) Replicate(ctx context.Context, channelID ChannelID, sourceGeneration, targetGeneration, fencingToken uint64) (ReplicationCheckpoint, error) {
	channel, err := coordinator.Store.LoadChannel(ctx, channelID); if err != nil { return ReplicationCheckpoint{}, err }; if channel.State == ChannelPaused || channel.State == ChannelFailed || fencingToken == 0 { return ReplicationCheckpoint{}, ErrConflict }
	previousGeneration := channel.Generation; channel.State, channel.Generation, channel.UpdatedAt = ChannelSyncing, channel.Generation+1, coordinator.now(); if err := coordinator.Store.UpdateChannel(ctx, channel, previousGeneration); err != nil { return ReplicationCheckpoint{}, err }
	if channel.Kind == DataDatabase { return coordinator.replicateDatabase(ctx, channel, sourceGeneration) }
	if coordinator.Executor == nil || coordinator.Grants == nil { return ReplicationCheckpoint{}, ErrInvalid }
	view, err := coordinator.Executor.CreateStableView(ctx, channel, sourceGeneration); if err != nil { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, err) }; defer coordinator.Executor.ReleaseStableView(ctx, view)
	if view.ResourceID != channel.ResourceID || view.Generation != sourceGeneration || view.WriteFrontier == 0 || !validDigest(view.ManifestDigest) || !coordinator.now().Before(view.ExpiresAt) { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, ErrInvalid) }
	grant, err := coordinator.Grants.IssueReplicationGrant(ctx, channel, view, view.ExpiresAt); if err != nil { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, err) }
	var previous *ReplicationCheckpoint; if checkpoint, loadErr := coordinator.Store.LatestCheckpoint(ctx, channel.ID); loadErr == nil { previous = &checkpoint }
	execution := ReplicationExecution{Channel: channel, SourceView: view, PreviousCheckpoint: previous, TargetGeneration: targetGeneration, FencingToken: fencingToken, EncryptedTransferGrant: grant}
	var receipt ReplicationReceipt
	switch channel.Kind { case DataSiteFiles: receipt, err = coordinator.Executor.TransferSiteFiles(ctx, execution); case DataMailboxes: receipt, err = coordinator.Executor.TransferMailboxes(ctx, execution); case DataDNS: receipt, err = coordinator.Executor.TransferDNS(ctx, execution); case DataContainerVolume: receipt, err = coordinator.Executor.TransferContainerVolume(ctx, execution); case DataBackupCopy: receipt, err = coordinator.Executor.TransferBackupCopy(ctx, execution); default: err = ErrInvalid }
	if err != nil { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, err) }
	if receipt.ChannelID != channel.ID || receipt.SourceNodeID != channel.SourceNodeID || receipt.TargetNodeID != channel.TargetNodeID || receipt.SourceGeneration != sourceGeneration || receipt.WriteFrontier != view.WriteFrontier || receipt.ManifestDigest != view.ManifestDigest || receipt.Position == "" || receipt.TargetReceipt == "" || receipt.VerifiedAt.IsZero() { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, ErrInvalid) }
	if previous != nil && receipt.WriteFrontier <= previous.WriteFrontier { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, ErrCheckpointStale) }
	if err := coordinator.Executor.VerifyTarget(ctx, execution, receipt); err != nil { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, err) }
	checkpointKey:=sha256.Sum256([]byte(string(channel.ID)+":"+fmt.Sprint(receipt.WriteFrontier)));checkpoint := ReplicationCheckpoint{ID: CheckpointID("cp-"+hex.EncodeToString(checkpointKey[:16])), ChannelID: channel.ID, SourceGeneration: sourceGeneration, WriteFrontier: receipt.WriteFrontier, Position: receipt.Position, ManifestDigest: receipt.ManifestDigest, StableViewRef: view.ID, BytesReplicated: receipt.BytesTransferred, Consistency: view.Consistency, Verified: true, CreatedAt: coordinator.now(), VerifiedAt: receipt.VerifiedAt}
	if err := checkpoint.Validate(); err != nil { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, err) }; if err := coordinator.Store.SaveCheckpoint(ctx, checkpoint); err != nil { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, err) }
	previousGeneration = channel.Generation; channel.State, channel.Generation, channel.UpdatedAt = ChannelCaughtUp, channel.Generation+1, coordinator.now(); if err := coordinator.Store.UpdateChannel(ctx, channel, previousGeneration); err != nil { return ReplicationCheckpoint{}, err }; return checkpoint, nil
}

func (coordinator ReplicationCoordinator) replicateDatabase(ctx context.Context, channel ReplicationChannel, sourceGeneration uint64) (ReplicationCheckpoint,error) { if coordinator.Database == nil { return ReplicationCheckpoint{}, ErrInvalid }; checkpoint, err := coordinator.Database.CreateDatabaseCheckpoint(ctx, channel, sourceGeneration); if err != nil { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, err) }; previous, loadErr := coordinator.Store.LatestCheckpoint(ctx, channel.ID); if loadErr == nil && checkpoint.WriteFrontier <= previous.WriteFrontier { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, ErrCheckpointStale) }; receipt, err := coordinator.Database.CatchUpReplica(ctx, channel, checkpoint); if err != nil { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, err) }; if receipt.WriteFrontier != checkpoint.WriteFrontier || receipt.ManifestDigest != checkpoint.ManifestDigest { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, ErrInvalid) }; if err := coordinator.Store.SaveCheckpoint(ctx, checkpoint); err != nil { return ReplicationCheckpoint{}, coordinator.failChannel(ctx, channel, err) }; previousGeneration := channel.Generation; channel.State, channel.Generation, channel.UpdatedAt = ChannelCaughtUp, channel.Generation+1, coordinator.now(); if err := coordinator.Store.UpdateChannel(ctx, channel, previousGeneration); err != nil { return ReplicationCheckpoint{}, err }; return checkpoint,nil }
func (coordinator ReplicationCoordinator) failChannel(ctx context.Context, channel ReplicationChannel, cause error) error { previous := channel.Generation; channel.State, channel.Generation, channel.UpdatedAt = ChannelFailed, channel.Generation+1, coordinator.now(); _ = coordinator.Store.UpdateChannel(ctx, channel, previous); return cause }

type DatabaseCoordinator struct { Store Store; Executor DatabaseReplicationExecutor; Health HealthAuthority; Leases LeaseAuthority; Now func() time.Time }
func (coordinator DatabaseCoordinator) now() time.Time { if coordinator.Now != nil { return coordinator.Now().UTC() }; return time.Now().UTC() }
func (coordinator DatabaseCoordinator) Reconcile(ctx context.Context, clusterID ID) (DatabaseCluster, error) { cluster, err := coordinator.Store.LoadDatabaseCluster(ctx, clusterID); if err != nil { return DatabaseCluster{}, err }; observed, err := coordinator.Executor.ObserveCluster(ctx, cluster); if err != nil { return DatabaseCluster{}, err }; if err := observed.Validate(); err != nil { return DatabaseCluster{}, err }; quorum, err := coordinator.Health.Quorum(ctx, cluster.GroupID); quorumErr:=err;if quorumErr==nil{quorumErr=quorum.Validate(coordinator.now())}; if quorumErr!=nil { if cluster.WriterNodeID != "" { _, _ = coordinator.Executor.FreezeDatabaseWrites(ctx, observed, cluster.WriterNodeID, cluster.Generation+1) }; previous := cluster.Generation; observed.State, observed.WriterNodeID, observed.WriterLeaseID, observed.Generation, observed.UpdatedAt = "frozen_no_quorum", "", "", cluster.Generation+1, coordinator.now(); _ = coordinator.Store.SaveDatabaseCluster(ctx, observed, previous); return observed, ErrNoQuorum }; if observed.Topology == DatabaseGalera { primary := 0; for _, member := range observed.Members { if member.State == DBSynced && member.ClusterStatus == "Primary" { primary++ } }; if primary < int(observed.QuorumRequired) { return observed, ErrNoQuorum } }; previous := cluster.Generation; observed.State, observed.Generation, observed.UpdatedAt = "healthy", cluster.Generation+1, coordinator.now(); if err := coordinator.Store.SaveDatabaseCluster(ctx, observed, previous); err != nil { return DatabaseCluster{}, err }; return observed, nil }

type PlacementCoordinator struct { Store Store; Federation Federation; IntentSigner IntentSigner; Now func() time.Time }
type IntentSigner interface { SignNodeIntent(context.Context, SignedNodeIntent) (SignedNodeIntent, error) }

func (coordinator PlacementCoordinator) SelectNodes(ctx context.Context, placement PlacementGroup, desired uint16) ([]NodeMember,error) { nodes, err := coordinator.Store.ListNodes(ctx, placement.NodeGroupID); if err != nil { return nil,err }; maintenance := map[NodeID]bool{}; for _, id := range placement.MaintenanceNodes { maintenance[id]=true }; eligible := map[NodeID]bool{}; for _, id := range placement.EligibleNodes { eligible[id]=true }; candidates:=[]NodeMember{}; domains:=map[string]bool{}; for _,node:=range nodes { if node.State!=NodeReady||maintenance[node.ID]||len(eligible)>0&&!eligible[node.ID]{continue}; match:=true;for key,value:=range placement.RequiredLabels{if node.Labels[key]!=value{match=false}}; if !match||node.Capacity.CPUCores-node.Capacity.ReservedCPU<placement.MinimumFreeCPU||node.Capacity.MemoryBytes-node.Capacity.ReservedMemory<placement.MinimumFreeMemory||node.Capacity.DiskBytes-node.Capacity.ReservedDisk<placement.MinimumFreeDisk{continue}; if placement.AntiAffinity&&domains[node.FailureDomain]{continue};candidates=append(candidates,node);domains[node.FailureDomain]=true;if len(candidates)==int(desired){break} };if len(candidates)<int(desired){return nil,ErrConflict};sort.Slice(candidates,func(i,j int)bool{return candidates[i].ID<candidates[j].ID});return candidates,nil }

func (coordinator PlacementCoordinator) ApplyReplicaIntent(ctx context.Context, group NodeGroup, node NodeMember, intent ReplicaIntent, expectedGeneration uint64, authorityEpoch uint64) (NodeIntentReceipt,error) { if coordinator.Federation==nil||coordinator.IntentSigner==nil{return NodeIntentReceipt{},ErrInvalid};if err:=intent.Validate();err!=nil{return NodeIntentReceipt{},err};payload,err:=json.Marshal(intent);if err!=nil{return NodeIntentReceipt{},err};sum:=sha256.Sum256(payload);now:=time.Now().UTC();wire:=SignedNodeIntent{IntentID:string(intent.ReplicaID)+":"+string(intent.Kind)+":"+intent.Revision,NodeID:node.ID,GroupID:group.ID,AuthorityEpoch:authorityEpoch,CapabilitySchemaVersion:node.Capabilities.SchemaVersion,Kind:"ha.replica."+string(intent.Kind),ResourceID:string(intent.ReplicaID),ExpectedGeneration:expectedGeneration,IdempotencyKey:string(intent.ReplicaID)+":"+intent.Revision,EffectID:string(intent.ReplicaID)+":"+string(intent.Kind),PayloadType:"ha.ReplicaIntent.v1",PayloadDigest:hex.EncodeToString(sum[:]),Payload:payload,IssuedAt:now,ExpiresAt:now.Add(10*time.Minute),SigningKeyID:"ha-intent",SigningKeyEpoch:authorityEpoch};wire,err=coordinator.IntentSigner.SignNodeIntent(ctx,wire);if err!=nil{return NodeIntentReceipt{},err};receipt,err:=coordinator.Federation.SubmitNodeIntent(ctx,wire);if err!=nil{return NodeIntentReceipt{},err};if receipt.IntentID!=wire.IntentID||receipt.NodeID!=node.ID||receipt.EffectID!=wire.EffectID||!receipt.Accepted{return NodeIntentReceipt{},ErrInvalid};return receipt,nil }

type BackupReplicationCoordinator struct { Store Store; Replication ReplicationCoordinator; Backup BackupConsistency }
func (coordinator BackupReplicationCoordinator) ReplicateAndProve(ctx context.Context, channelID ChannelID, sourceGeneration,targetGeneration,fencingToken uint64,recoveryPointID string,target NodeID)(BackupReplicaCopy,error){checkpoint,err:=coordinator.Replication.Replicate(ctx,channelID,sourceGeneration,targetGeneration,fencingToken);if err!=nil{return BackupReplicaCopy{},err};copy,err:=coordinator.Backup.VerifyIndependentBackupCopy(ctx,recoveryPointID,target);if err!=nil{return BackupReplicaCopy{},err};if copy.ManifestDigest!=checkpoint.ManifestDigest||copy.CommitMarker==""||copy.VerifiedAt.IsZero(){return BackupReplicaCopy{},ErrInvalid};if err:=coordinator.Store.SaveBackupCopy(ctx,copy);err!=nil{return BackupReplicaCopy{},err};return copy,nil}

func joinErrors(values ...error) error { var result error; for _,value:=range values { result=errors.Join(result,value) }; return result }
