// Package ha owns multi-node placement, replication, fencing, promotion, and
// traffic cutover. It never shares node-local control databases and never
// treats reachability failure as permission to promote a writer.
package ha

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid = errors.New("invalid high availability resource")
	ErrNotFound = errors.New("high availability resource not found")
	ErrConflict = errors.New("high availability resource conflict")
	ErrStaleGeneration = errors.New("stale high availability generation")
	ErrNoQuorum = errors.New("high availability quorum unavailable")
	ErrFenceRequired = errors.New("high availability fence proof required")
	ErrFenceFailed = errors.New("high availability fencing failed")
	ErrLeaseLost = errors.New("high availability writer lease lost")
	ErrSplitBrainRisk = errors.New("high availability split brain risk")
	ErrCheckpointStale = errors.New("high availability checkpoint is stale")
	ErrDataLossApproval = errors.New("potential data loss approval required")
	ErrUnsafePromotion = errors.New("high availability promotion is unsafe")
	ErrIrreversibleFrontier = errors.New("high availability crossed irreversible write frontier")
	ErrProviderAmbiguous = errors.New("high availability traffic provider ambiguous")
	ErrForbidden = errors.New("high availability operation forbidden")
	ErrExpired = errors.New("high availability authority expired")
	ErrUnsupported = errors.New("high availability capability unsupported")
)

type ID string
type NodeID string
type NodeGroupID string
type PlacementGroupID string
type ReplicaSetID string
type ReplicaID string
type ChannelID string
type CheckpointID string
type WriterLeaseID string
type FenceID string
type TrafficPolicyID string
type PromotionID string
type FailoverRunID string
type CommandID string
type OperationID string
type BackupCopyID string
type SiteID string
type ContainerApplicationID string

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
func validID(value string) bool { return idPattern.MatchString(value) }
func requireID(kind, value string) error { if !validID(value) { return fmt.Errorf("%w: %s identifier", ErrInvalid, kind) }; return nil }
func validDigest(value string) bool { if len(value) != sha256.Size*2 { return false }; _, err := hex.DecodeString(value); return err == nil && strings.ToLower(value) == value }

type NodeRole string
const ( RoleManager NodeRole = "manager"; RoleWorker NodeRole = "worker"; RoleData NodeRole = "data"; RoleIngress NodeRole = "ingress"; RoleMail NodeRole = "mail" )
type NodeState string
const ( NodeJoining NodeState = "joining"; NodeReady NodeState = "ready"; NodeDraining NodeState = "draining"; NodeFenced NodeState = "fenced"; NodeDegraded NodeState = "degraded"; NodeOffline NodeState = "offline"; NodeRetired NodeState = "retired" )

type ResourceCapacity struct { CPUCores uint32 `json:"cpu_cores"`; MemoryBytes uint64 `json:"memory_bytes"`; DiskBytes uint64 `json:"disk_bytes"`; Inodes uint64 `json:"inodes"`; ReservedCPU uint32 `json:"reserved_cpu"`; ReservedMemory uint64 `json:"reserved_memory"`; ReservedDisk uint64 `json:"reserved_disk"` }
type NodeCapabilities struct { SchemaVersion uint32 `json:"schema_version"`; OS string `json:"os"`; Architecture string `json:"architecture"`; WebEngines []string `json:"web_engines"`; Services []string `json:"services"`; ProviderCapabilities []string `json:"provider_capabilities"`; ContainerRuntime string `json:"container_runtime,omitempty"`; VersionDigest string `json:"version_digest"`; ObservedAt time.Time `json:"observed_at"` }
type NodeMember struct { ID NodeID `json:"id"`; GroupID NodeGroupID `json:"group_id"`; Roles []NodeRole `json:"roles"`; Labels map[string]string `json:"labels"`; FailureDomain string `json:"failure_domain"`; Capacity ResourceCapacity `json:"capacity"`; Capabilities NodeCapabilities `json:"capabilities"`; WorkloadIdentity string `json:"workload_identity"`; State NodeState `json:"state"`; Generation uint64 `json:"generation"`; JoinedAt time.Time `json:"joined_at"`; UpdatedAt time.Time `json:"updated_at"` }

func (node NodeMember) Validate() error {
	if err := requireID("node", string(node.ID)); err != nil { return err }
	if err := requireID("node group", string(node.GroupID)); err != nil { return err }
	if len(node.Roles) == 0 || len(node.Roles) > 5 || node.FailureDomain == "" || len(node.FailureDomain) > 128 || strings.TrimSpace(node.WorkloadIdentity) != node.WorkloadIdentity || len(node.WorkloadIdentity) < 3 || len(node.WorkloadIdentity) > 512 || strings.ContainsAny(node.WorkloadIdentity, "\x00\r\n\t ") || node.Generation == 0 || node.JoinedAt.IsZero() || node.UpdatedAt.IsZero() || node.UpdatedAt.Before(node.JoinedAt) || node.Capabilities.SchemaVersion == 0 || node.Capabilities.ObservedAt.IsZero() || !validDigest(node.Capabilities.VersionDigest) || node.Capacity.ReservedCPU>node.Capacity.CPUCores || node.Capacity.ReservedMemory>node.Capacity.MemoryBytes || node.Capacity.ReservedDisk>node.Capacity.DiskBytes { return ErrInvalid }
	switch node.State { case NodeJoining, NodeReady, NodeDraining, NodeFenced, NodeDegraded, NodeOffline, NodeRetired: default: return ErrInvalid }
	roles:=map[NodeRole]bool{};for _,role:=range node.Roles{if roles[role]||!validNodeRole(role){return ErrInvalid};roles[role]=true}
	for key, value := range node.Labels { if !validID(key) || len(value) > 256 || strings.ContainsAny(value,"\x00\r\n") { return ErrInvalid } }
	return nil
}

func validNodeRole(role NodeRole) bool { switch role { case RoleManager,RoleWorker,RoleData,RoleIngress,RoleMail:return true;default:return false } }

type NodeGroup struct { ID NodeGroupID `json:"id"`; Name string `json:"name"`; CoordinatorID string `json:"coordinator_id"`; MinimumManagers uint8 `json:"minimum_managers"`; AutomaticFailover bool `json:"automatic_failover"`; RequiredFenceClasses []FenceClass `json:"required_fence_classes"`; State string `json:"state"`; Generation uint64 `json:"generation"`; CreatedAt time.Time `json:"created_at"`; UpdatedAt time.Time `json:"updated_at"` }
func (group NodeGroup) Validate() error {
	if !validID(string(group.ID))||strings.TrimSpace(group.Name)==""||len(group.Name)>128||strings.ContainsAny(group.Name,"\x00\r\n")||!validID(group.CoordinatorID)||group.MinimumManagers==0||group.MinimumManagers%2==0||len(group.RequiredFenceClasses)==0||len(group.RequiredFenceClasses)>5||(group.State!="active"&&group.State!="forming")||group.Generation==0||group.CreatedAt.IsZero()||group.UpdatedAt.IsZero()||group.UpdatedAt.Before(group.CreatedAt){return ErrInvalid}
	seen:=map[FenceClass]bool{};for _,class:=range group.RequiredFenceClasses{if seen[class]||!validFenceClass(class){return ErrInvalid};seen[class]=true}
	return nil
}

func validFenceClass(class FenceClass)bool{switch class{case FencePower,FenceStorage,FenceDatabase,FenceMandatoryLease,FenceAdministrative:return true;default:return false}}

type HealthState string
const ( HealthHealthy HealthState = "healthy"; HealthDegraded HealthState = "degraded"; HealthUnreachable HealthState = "unreachable"; HealthFenced HealthState = "fenced"; HealthUnknown HealthState = "unknown" )
type HealthObservation struct { NodeID NodeID `json:"node_id"`; ObserverNodeID NodeID `json:"observer_node_id"`; State HealthState `json:"state"`; Checks map[string]bool `json:"checks"`; Latency time.Duration `json:"latency"`; BootID string `json:"boot_id"`; CapabilityDigest string `json:"capability_digest"`; ObservedAt time.Time `json:"observed_at"`; ValidUntil time.Time `json:"valid_until"`; Sequence uint64 `json:"sequence"`; Signature string `json:"signature"` }

type QuorumObservation struct { GroupID NodeGroupID `json:"group_id"`; Voters []NodeID `json:"voters"`; HealthyVoters []NodeID `json:"healthy_voters"`; Required uint16 `json:"required"`; Achieved bool `json:"achieved"`; Epoch uint64 `json:"epoch"`; ObservedAt time.Time `json:"observed_at"`; ValidUntil time.Time `json:"valid_until"`; Digest string `json:"digest"` }
func (observation QuorumObservation) Validate(now time.Time) error { if !validID(string(observation.GroupID)) || observation.Required == 0 || observation.Epoch == 0 || !observation.Achieved || len(observation.HealthyVoters) < int(observation.Required) || !now.Before(observation.ValidUntil) || !validDigest(observation.Digest) { return ErrNoQuorum }; return nil }

type PlacementGroup struct { ID PlacementGroupID `json:"id"`; NodeGroupID NodeGroupID `json:"node_group_id"`; EligibleNodes []NodeID `json:"eligible_nodes"`; RequiredLabels map[string]string `json:"required_labels"`; FailureDomainKey string `json:"failure_domain_key"`; AntiAffinity bool `json:"anti_affinity"`; MinimumFreeCPU uint32 `json:"minimum_free_cpu"`; MinimumFreeMemory uint64 `json:"minimum_free_memory"`; MinimumFreeDisk uint64 `json:"minimum_free_disk"`; MaintenanceNodes []NodeID `json:"maintenance_nodes"`; Generation uint64 `json:"generation"` }

type WorkloadKind string
const ( WorkloadStatelessSite WorkloadKind = "stateless_site"; WorkloadContainer WorkloadKind = "container_application"; WorkloadMailIngress WorkloadKind = "mail_ingress"; WorkloadDNS WorkloadKind = "dns_authority" )
type ReplicaState string
const ( ReplicaPending ReplicaState = "pending"; ReplicaStarting ReplicaState = "starting"; ReplicaReady ReplicaState = "ready"; ReplicaDraining ReplicaState = "draining"; ReplicaStopped ReplicaState = "stopped"; ReplicaFailed ReplicaState = "failed" )
type Replica struct { ID ReplicaID `json:"id"`; ReplicaSetID ReplicaSetID `json:"replica_set_id"`; NodeID NodeID `json:"node_id"`; Revision string `json:"revision"`; State ReplicaState `json:"state"`; HealthDigest string `json:"health_digest"`; IntentID string `json:"intent_id"`; ObservedReceipt string `json:"observed_receipt"`; StartedAt time.Time `json:"started_at,omitempty"`; UpdatedAt time.Time `json:"updated_at"` }
type ReplicaSet struct { ID ReplicaSetID `json:"id"`; PlacementGroupID PlacementGroupID `json:"placement_group_id"`; Kind WorkloadKind `json:"kind"`; ResourceID string `json:"resource_id"`; Desired uint16 `json:"desired"`; MinimumHealthy uint16 `json:"minimum_healthy"`; Revision string `json:"revision"`; ImageDigest string `json:"image_digest,omitempty"`; ResourceProfileID string `json:"resource_profile_id"`; SecretBundleRef string `json:"secret_bundle_ref,omitempty"`; TrafficPolicyID TrafficPolicyID `json:"traffic_policy_id,omitempty"`; Replicas []Replica `json:"replicas"`; Generation uint64 `json:"generation"`; UpdatedAt time.Time `json:"updated_at"` }

type DataKind string
const ( DataSiteFiles DataKind = "site_files"; DataDatabase DataKind = "database"; DataMailboxes DataKind = "mailboxes"; DataDNS DataKind = "dns"; DataContainerVolume DataKind = "container_volume"; DataBackupCopy DataKind = "backup_copy" )
type ChannelMode string
const ( ChannelSynchronous ChannelMode = "synchronous"; ChannelAsynchronous ChannelMode = "asynchronous"; ChannelSnapshotDelta ChannelMode = "snapshot_delta" )
type ChannelState string
const ( ChannelPending ChannelState = "pending"; ChannelSyncing ChannelState = "syncing"; ChannelCaughtUp ChannelState = "caught_up"; ChannelLagging ChannelState = "lagging"; ChannelPaused ChannelState = "paused"; ChannelFailed ChannelState = "failed"; ChannelRebuilding ChannelState = "rebuilding" )
type ReplicationChannel struct { ID ChannelID `json:"id"`; GroupID NodeGroupID `json:"group_id"`; Kind DataKind `json:"kind"`; ResourceID string `json:"resource_id"`; SourceNodeID NodeID `json:"source_node_id"`; TargetNodeID NodeID `json:"target_node_id"`; Mode ChannelMode `json:"mode"`; EncryptionProfile string `json:"encryption_profile"`; PurposeKeyRef string `json:"purpose_key_ref"`; Exclusions []string `json:"exclusions,omitempty"`; RPO time.Duration `json:"rpo"`; MaximumLagBytes uint64 `json:"maximum_lag_bytes"`; State ChannelState `json:"state"`; Generation uint64 `json:"generation"`; CreatedAt time.Time `json:"created_at"`; UpdatedAt time.Time `json:"updated_at"` }
func (channel ReplicationChannel) Validate() error { if !validID(string(channel.ID)) || !validID(string(channel.GroupID)) || !validID(string(channel.SourceNodeID)) || !validID(string(channel.TargetNodeID)) || channel.SourceNodeID == channel.TargetNodeID || channel.ResourceID == "" || !validID(channel.EncryptionProfile) || !validID(channel.PurposeKeyRef) || channel.RPO <= 0 || channel.Generation == 0 || channel.CreatedAt.IsZero() || channel.UpdatedAt.IsZero() { return ErrInvalid }; return nil }

type ReplicationCheckpoint struct { ID CheckpointID `json:"id"`; ChannelID ChannelID `json:"channel_id"`; SourceGeneration uint64 `json:"source_generation"`; WriteFrontier uint64 `json:"write_frontier"`; Position string `json:"position"`; ManifestDigest string `json:"manifest_digest"`; StableViewRef string `json:"stable_view_ref"`; BytesReplicated uint64 `json:"bytes_replicated"`; LagBytes uint64 `json:"lag_bytes"`; LagDuration time.Duration `json:"lag_duration"`; Consistency string `json:"consistency"`; Verified bool `json:"verified"`; CreatedAt time.Time `json:"created_at"`; VerifiedAt time.Time `json:"verified_at"` }
func (checkpoint ReplicationCheckpoint) Validate() error { if !validID(string(checkpoint.ID)) || !validID(string(checkpoint.ChannelID)) || checkpoint.SourceGeneration == 0 || checkpoint.WriteFrontier == 0 || checkpoint.Position == "" || !validDigest(checkpoint.ManifestDigest) || checkpoint.StableViewRef == "" || !checkpoint.Verified || checkpoint.CreatedAt.IsZero() || checkpoint.VerifiedAt.IsZero() { return ErrInvalid }; return nil }

type DatabaseTopology string
const ( DatabaseGalera DatabaseTopology = "galera"; DatabasePrimaryReplica DatabaseTopology = "primary_replica_gtid" )
type DatabaseMemberState string
const ( DBJoining DatabaseMemberState = "joining"; DBSynced DatabaseMemberState = "synced"; DBDonor DatabaseMemberState = "donor"; DBDesynced DatabaseMemberState = "desynced"; DBNonPrimary DatabaseMemberState = "non_primary"; DBFenced DatabaseMemberState = "fenced" )
type DatabaseMember struct { NodeID NodeID `json:"node_id"`; ServerUUID string `json:"server_uuid"`; State DatabaseMemberState `json:"state"`; ClusterStatus string `json:"cluster_status"`; ClusterSize uint16 `json:"cluster_size"`; LocalIndex int16 `json:"local_index"`; GTID string `json:"gtid"`; Sequence uint64 `json:"sequence"`; ReadOnly bool `json:"read_only"`; PublicListener bool `json:"public_listener"`; PeerCIDRs []string `json:"peer_cidrs"`; ObservedAt time.Time `json:"observed_at"` }
func (member DatabaseMember) Validate() error { if !validID(string(member.NodeID)) || member.ServerUUID == "" || member.PublicListener || member.ObservedAt.IsZero() { return ErrInvalid }; for _, cidr := range member.PeerCIDRs { _, network, err := net.ParseCIDR(cidr); if err != nil || network.String() != cidr { return ErrInvalid } }; return nil }
type DatabaseCluster struct { ID ID `json:"id"`; GroupID NodeGroupID `json:"group_id"`; Topology DatabaseTopology `json:"topology"`; Members []DatabaseMember `json:"members"`; DesiredVotingMembers uint16 `json:"desired_voting_members"`; QuorumRequired uint16 `json:"quorum_required"`; PrimaryComponentDigest string `json:"primary_component_digest"`; WriterNodeID NodeID `json:"writer_node_id,omitempty"`; WriterLeaseID WriterLeaseID `json:"writer_lease_id,omitempty"`; State string `json:"state"`; Generation uint64 `json:"generation"`; UpdatedAt time.Time `json:"updated_at"` }
func (cluster DatabaseCluster) Validate() error { if !validID(string(cluster.ID)) || !validID(string(cluster.GroupID)) || len(cluster.Members) < 2 || cluster.DesiredVotingMembers < 2 || cluster.QuorumRequired != cluster.DesiredVotingMembers/2+1 || cluster.Topology == DatabaseGalera && cluster.DesiredVotingMembers%2 == 0 || cluster.Generation == 0 || cluster.UpdatedAt.IsZero() { return ErrInvalid }; for _, member := range cluster.Members { if err := member.Validate(); err != nil { return err } }; return nil }

type LeaseState string
const ( LeasePending LeaseState = "pending"; LeaseActive LeaseState = "active"; LeaseExpired LeaseState = "expired"; LeaseRevoked LeaseState = "revoked"; LeaseLost LeaseState = "lost" )
type WriterLease struct { ID WriterLeaseID `json:"id"`; GroupID NodeGroupID `json:"group_id"`; ResourceID string `json:"resource_id"`; HolderNodeID NodeID `json:"holder_node_id"`; EnforcedWritePaths []string `json:"enforced_write_paths"`; FencingToken uint64 `json:"fencing_token"`; AuthorityEpoch uint64 `json:"authority_epoch"`; QuorumDigest string `json:"quorum_digest"`; IssuedAt time.Time `json:"issued_at"`; ExpiresAt time.Time `json:"expires_at"`; RenewAfter time.Time `json:"renew_after"`; State LeaseState `json:"state"`; Generation uint64 `json:"generation"` }
func (lease WriterLease) Validate(now time.Time) error { if !validID(string(lease.ID)) || !validID(string(lease.GroupID)) || lease.ResourceID == "" || !validID(string(lease.HolderNodeID)) || len(lease.EnforcedWritePaths) == 0 || lease.FencingToken == 0 || lease.AuthorityEpoch == 0 || !validDigest(lease.QuorumDigest) || lease.IssuedAt.IsZero() || !lease.ExpiresAt.After(lease.IssuedAt) || !lease.RenewAfter.After(lease.IssuedAt) || !lease.ExpiresAt.After(lease.RenewAfter) || lease.Generation == 0 { return ErrInvalid }; if lease.State == LeaseActive && !now.Before(lease.ExpiresAt) { return ErrLeaseLost }; return nil }

type FenceClass string
const ( FencePower FenceClass = "power"; FenceStorage FenceClass = "storage"; FenceDatabase FenceClass = "database"; FenceMandatoryLease FenceClass = "mandatory_lease"; FenceAdministrative FenceClass = "administrative" )
type FenceState string
const ( FencePlanned FenceState = "planned"; FenceApplying FenceState = "applying"; FenceProven FenceState = "proven"; FenceFailed FenceState = "failed"; FenceExpired FenceState = "expired" )
type Fence struct { ID FenceID `json:"id"`; GroupID NodeGroupID `json:"group_id"`; TargetNodeID NodeID `json:"target_node_id"`; Class FenceClass `json:"class"`; ProtectedWritePaths []string `json:"protected_write_paths"`; ProviderBindingID string `json:"provider_binding_id,omitempty"`; FencingToken uint64 `json:"fencing_token"`; AuthorityEpoch uint64 `json:"authority_epoch"`; Challenge string `json:"challenge"`; ProofDigest string `json:"proof_digest,omitempty"`; ProviderReceipt string `json:"provider_receipt,omitempty"`; State FenceState `json:"state"`; AppliedAt time.Time `json:"applied_at,omitempty"`; ValidUntil time.Time `json:"valid_until,omitempty"`; Generation uint64 `json:"generation"` }
func (fence Fence) Validate(now time.Time) error { if !validID(string(fence.ID)) || !validID(string(fence.GroupID)) || !validID(string(fence.TargetNodeID)) || len(fence.ProtectedWritePaths) == 0 || fence.FencingToken == 0 || fence.AuthorityEpoch == 0 || fence.Challenge == "" || fence.Generation == 0 { return ErrInvalid }; if fence.State == FenceProven && (!validDigest(fence.ProofDigest) || fence.ProviderReceipt == "" || fence.AppliedAt.IsZero() || !now.Before(fence.ValidUntil)) { return ErrFenceFailed }; return nil }

type TrafficProviderMode string
const ( TrafficAtomicCAS TrafficProviderMode = "atomic_cas"; TrafficObserveApply TrafficProviderMode = "observe_apply" )
type TrafficEndpoint struct { NodeID NodeID `json:"node_id"`; Address string `json:"address"`; Port uint16 `json:"port"`; Weight uint16 `json:"weight"`; Healthy bool `json:"healthy"`; HealthDigest string `json:"health_digest"` }
type TrafficPolicy struct { ID TrafficPolicyID `json:"id"`; GroupID NodeGroupID `json:"group_id"`; Kind string `json:"kind"`; ProviderBindingID string `json:"provider_binding_id"`; ProviderMode TrafficProviderMode `json:"provider_mode"`; Resource string `json:"resource"`; TTL uint32 `json:"ttl"`; Endpoints []TrafficEndpoint `json:"endpoints"`; ExpectedRevision string `json:"expected_revision"`; DesiredDigest string `json:"desired_digest"`; ObservedDigest string `json:"observed_digest,omitempty"`; Generation uint64 `json:"generation"`; UpdatedAt time.Time `json:"updated_at"` }

type PromotionState string
const ( PromotionPlanned PromotionState = "planned"; PromotionChecking PromotionState = "checking"; PromotionFencing PromotionState = "fencing"; PromotionFenced PromotionState = "fenced"; PromotionPromoting PromotionState = "promoting"; PromotionRouting PromotionState = "routing"; PromotionProbing PromotionState = "probing"; PromotionSoaking PromotionState = "soaking"; PromotionCommitted PromotionState = "committed"; PromotionRollingBack PromotionState = "rolling_back"; PromotionRolledBack PromotionState = "rolled_back"; PromotionFailForward PromotionState = "fail_forward"; PromotionFailed PromotionState = "failed" )
type Approval struct { ID string `json:"id"`; ActorID string `json:"actor_id"`; Kind string `json:"kind"`; PlanDigest string `json:"plan_digest"`; IssuedAt time.Time `json:"issued_at"`; ExpiresAt time.Time `json:"expires_at"`; Signature string `json:"signature"` }
type Promotion struct { ID PromotionID `json:"id"`; CommandID CommandID `json:"command_id"`; GroupID NodeGroupID `json:"group_id"`; ResourceID string `json:"resource_id"`; PreviousWriter NodeID `json:"previous_writer"`; Candidate NodeID `json:"candidate"`; ExpectedGeneration uint64 `json:"expected_generation"`; CheckpointID CheckpointID `json:"checkpoint_id"`; CheckpointFrontier uint64 `json:"checkpoint_frontier"`; MaximumDataLoss time.Duration `json:"maximum_data_loss"`; LeaseID WriterLeaseID `json:"lease_id,omitempty"`; FenceIDs []FenceID `json:"fence_ids"`; TrafficPolicyID TrafficPolicyID `json:"traffic_policy_id"`; Automatic bool `json:"automatic"`; PotentialDataLoss bool `json:"potential_data_loss"`; Approvals []Approval `json:"approvals"`; State PromotionState `json:"state"`; WriteFrontier uint64 `json:"write_frontier"`; Irreversible bool `json:"irreversible"`; Failure string `json:"failure,omitempty"`; Generation uint64 `json:"generation"`; CreatedAt time.Time `json:"created_at"`; UpdatedAt time.Time `json:"updated_at"` }

type FailoverRun struct { ID FailoverRunID `json:"id"`; PromotionID PromotionID `json:"promotion_id"`; PlanDigest string `json:"plan_digest"`; HealthQuorumDigest string `json:"health_quorum_digest"`; FenceProofDigest string `json:"fence_proof_digest,omitempty"`; TrafficBeforeDigest string `json:"traffic_before_digest,omitempty"`; TrafficAfterDigest string `json:"traffic_after_digest,omitempty"`; ProviderRevision string `json:"provider_revision,omitempty"`; State PromotionState `json:"state"`; Step string `json:"step"`; Attempt uint32 `json:"attempt"`; Failure string `json:"failure,omitempty"`; StartedAt time.Time `json:"started_at"`; UpdatedAt time.Time `json:"updated_at"`; CompletedAt time.Time `json:"completed_at,omitempty"` }

type BackupReplicaCopy struct { ID BackupCopyID `json:"id"`; RecoveryPointID string `json:"recovery_point_id"`; SourceNodeID NodeID `json:"source_node_id"`; TargetNodeID NodeID `json:"target_node_id"`; FailureDomain string `json:"failure_domain"`; ManifestDigest string `json:"manifest_digest"`; CommitMarker string `json:"commit_marker"`; VerifiedAt time.Time `json:"verified_at"`; CleanRestoreProvenAt time.Time `json:"clean_restore_proven_at,omitempty"` }

type MailTopology struct { ID ID `json:"id"`; GroupID NodeGroupID `json:"group_id"`; IngressNodes []NodeID `json:"ingress_nodes"`; MailboxWriterNodeID NodeID `json:"mailbox_writer_node_id"`; WriterLeaseID WriterLeaseID `json:"writer_lease_id"`; ReplicationChannels []ChannelID `json:"replication_channels"`; DeliveryQueuePolicy string `json:"delivery_queue_policy"`; MaximumMailboxLag time.Duration `json:"maximum_mailbox_lag"`; Generation uint64 `json:"generation"`; UpdatedAt time.Time `json:"updated_at"` }
func (topology MailTopology) Validate() error { if !validID(string(topology.ID))||!validID(string(topology.GroupID))||len(topology.IngressNodes)<2||!validID(string(topology.MailboxWriterNodeID))||!validID(string(topology.WriterLeaseID))||len(topology.ReplicationChannels)==0||topology.DeliveryQueuePolicy==""||topology.MaximumMailboxLag<=0||topology.Generation==0||topology.UpdatedAt.IsZero(){return ErrInvalid};return nil }

type DNSTopology struct { ID ID `json:"id"`; GroupID NodeGroupID `json:"group_id"`; PrimaryNodeID NodeID `json:"primary_node_id"`; SecondaryNodeIDs []NodeID `json:"secondary_node_ids"`; TransferChannelIDs []ChannelID `json:"transfer_channel_ids"`; TSIGKeyRefs []string `json:"tsig_key_refs"`; RequiredSerial uint64 `json:"required_serial"`; ObservedSerials map[NodeID]uint64 `json:"observed_serials"`; TrafficPolicyID TrafficPolicyID `json:"traffic_policy_id"`; Generation uint64 `json:"generation"`; UpdatedAt time.Time `json:"updated_at"` }
func (topology DNSTopology) Converged() bool { if len(topology.SecondaryNodeIDs)==0||topology.RequiredSerial==0{return false};if topology.ObservedSerials[topology.PrimaryNodeID]<topology.RequiredSerial{return false};for _,node:=range topology.SecondaryNodeIDs{if topology.ObservedSerials[node]<topology.RequiredSerial{return false}};return true }

func sortedIDs[T ~string](values []T) []string { result := make([]string, len(values)); for index := range values { result[index] = string(values[index]) }; sort.Strings(result); return result }
