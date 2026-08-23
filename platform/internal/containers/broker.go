package containers

import (
	"context"
	"net/netip"
	"time"
)

type EffectID string
type FenceToken uint64
type Grant struct{TenantID ID;ResourceID ID;Operation string;AuthzEpoch uint64;ExpiresAt time.Time;Digest string}
type ImagePolicyReceipt struct{ImageDigest,SBOMDigest,SignatureDigest,VulnerabilityDigest string;Verdict PolicyVerdict;PolicyVersion string}
type RuntimeReceipt struct{EffectID EffectID;ResourceID ID;RuntimeObjectID,SpecDigest,ObservedDigest string;Lifecycle Lifecycle;Health WorkloadHealth;Generation uint64;Fence FenceToken;Outcome string;ObservedAt time.Time;ErrorCode string}
type PullReceipt struct{EffectID EffectID;ImageDigest string;Bytes uint64;Policy ImagePolicyReceipt;Outcome string;ObservedAt time.Time}
type VolumeReceipt struct{EffectID EffectID;VolumeID ID;RuntimeObjectID,ConfigurationDigest string;QuotaBytes,InodeLimit,Generation uint64;Fence FenceToken;Outcome string;ObservedAt time.Time}
type NetworkReceipt struct{EffectID EffectID;NetworkID ID;RuntimeObjectID,ConfigurationDigest string;Generation uint64;Fence FenceToken;Internal bool;Outcome string;ObservedAt time.Time}
type ExposureReceipt struct{EffectID EffectID;ExposureID ID;ConfigurationDigest,BoundAddress string;BoundPort uint16;Generation,FirewallGeneration,RouteGeneration uint64;Fence FenceToken;Public bool;Outcome string;ObservedAt time.Time}
type ExecReceipt struct{EffectID EffectID;GrantID ID;ExitCode int;OutputDigest string;StartedAt,CompletedAt time.Time;Outcome string}
type VolumeSnapshotReceipt struct{EffectID EffectID;SnapshotID ID;ApplicationID ID;VolumeIDs []ID;ManifestDigest string;Bytes uint64;Fence FenceToken;Outcome string;ObservedAt,CompletedAt time.Time}
type StreamChunk struct{Cursor LogCursor;Data []byte;EOF bool;Truncated bool}

type Broker interface{
	InspectRuntime(context.Context)(RuntimeCapability,error)
	InstallRuntime(context.Context,RuntimeInstallRequest)(RuntimeReceipt,error)
	RemoveRuntime(context.Context,RuntimeMutationRequest)(RuntimeReceipt,error)
	ResolveImage(context.Context,ResolveImageRequest)(ImageReference,error)
	PullImage(context.Context,PullImageRequest)(PullReceipt,error)
	DeleteImage(context.Context,ImageMutationRequest)(PullReceipt,error)
	EnsureVolume(context.Context,VolumeMutationRequest)(VolumeReceipt,error)
	DeleteVolume(context.Context,VolumeMutationRequest)(VolumeReceipt,error)
	EnsureNetwork(context.Context,NetworkMutationRequest)(NetworkReceipt,error)
	DeleteNetwork(context.Context,NetworkMutationRequest)(NetworkReceipt,error)
	ApplyWorkload(context.Context,WorkloadMutationRequest)(RuntimeReceipt,error)
	ObserveWorkload(context.Context,WorkloadObservationRequest)(RuntimeReceipt,error)
	SetLifecycle(context.Context,WorkloadLifecycleRequest)(RuntimeReceipt,error)
	RestartWorkload(context.Context,WorkloadRestartRequest)(RuntimeReceipt,error)
	DeleteWorkload(context.Context,WorkloadMutationRequest)(RuntimeReceipt,error)
	ApplyExposure(context.Context,ExposureMutationRequest)(ExposureReceipt,error)
	DeleteExposure(context.Context,ExposureMutationRequest)(ExposureReceipt,error)
	Exec(context.Context,ExecRequest)(ExecReceipt,error)
	OpenLogs(context.Context,LogRequest)(LogStream,error)
	Stats(context.Context,WorkloadObservationRequest)(WorkloadObservation,error)
	SnapshotVolumes(context.Context,VolumeSnapshotRequest)(VolumeSnapshotReceipt,error)
	RestoreVolumes(context.Context,VolumeRestoreRequest)(VolumeSnapshotReceipt,error)
}

type RuntimeCapability struct{Backend,Version,APIVersion string;Rootless,UserNamespaces,CgroupV2,Seccomp,MAC,Checkpoint bool;Generation uint64}
type RuntimeInstallRequest struct{EffectID EffectID;ProfileID ID;ArtifactDigest,RepositorySnapshotDigest,CommitAuthorizationDigest string;Fence FenceToken}
type RuntimeMutationRequest struct{EffectID EffectID;ExpectedGeneration uint64;CommitAuthorizationDigest string;Fence FenceToken}
type ResolveImageRequest struct{EffectID EffectID;Grant Grant;RegistryCredentialID ID;Registry,Repository,Tag,Platform string}
type PullImageRequest struct{EffectID EffectID;Grant Grant;Image ImageReference;RegistryCredentialID ID;Policy ImagePolicyReceipt;Fence FenceToken}
type ImageMutationRequest struct{EffectID EffectID;Grant Grant;ImageDigest string;ExpectedGeneration uint64;Fence FenceToken}
type VolumeMutationRequest struct{EffectID EffectID;Grant Grant;VolumeID ID;ExpectedGeneration uint64;Tier RuntimeTier;QuotaBytes,InodeLimit uint64;Class string;Fence FenceToken}
type NetworkMutationRequest struct{EffectID EffectID;Grant Grant;NetworkID ID;ExpectedGeneration uint64;Tier RuntimeTier;IPv4,IPv6 netip.Prefix;Internal bool;DNSPolicy string;Fence FenceToken}
type WorkloadMutationRequest struct{EffectID EffectID;Grant Grant;WorkloadID ID;ExpectedGeneration uint64;Tier RuntimeTier;Spec WorkloadSpec;SpecDigest string;Fence FenceToken;CommitAuthorizationDigest string}
type WorkloadObservationRequest struct{Grant Grant;WorkloadID ID;ExpectedGeneration uint64}
type WorkloadLifecycleRequest struct{EffectID EffectID;Grant Grant;WorkloadID ID;ExpectedGeneration uint64;Lifecycle Lifecycle;Fence FenceToken;CommitAuthorizationDigest string}
type WorkloadRestartRequest struct{EffectID EffectID;Grant Grant;WorkloadID ID;ExpectedGeneration uint64;Fence FenceToken;CommitAuthorizationDigest string}
type ExposureMutationRequest struct{EffectID EffectID;Grant Grant;Exposure Exposure;ExpectedGeneration uint64;Fence FenceToken}
type ExecRequest struct{EffectID EffectID;Grant Grant;ExecGrant ExecGrant;Fence FenceToken;CommitAuthorizationDigest string}
type LogRequest struct{Grant Grant;WorkloadID ID;Cursor LogCursor;Since time.Time;TailLines,MaxBytes uint64;Follow bool;Deadline time.Time}
type VolumeSnapshotRequest struct{EffectID EffectID;SnapshotID ID;TenantID ID;ApplicationID ID;VolumeIDs []ID;Fence FenceToken}
type VolumeRestoreRequest struct{EffectID EffectID;SnapshotID ID;TenantID ID;ApplicationID ID;VolumeIDs []ID;Fence FenceToken}
type LogStream interface{Next(context.Context)(StreamChunk,error);Close()error}

type BrokerJournal interface{Accept(context.Context,EffectID,string,FenceToken)(RuntimeReceipt,bool,error);Complete(context.Context,RuntimeReceipt)error;Lookup(context.Context,EffectID)(RuntimeReceipt,bool,error)}
