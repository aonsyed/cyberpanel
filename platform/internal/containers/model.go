package containers

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid = errors.New("containers: invalid value")
	ErrNotFound = errors.New("containers: not found")
	ErrConflict = errors.New("containers: conflict")
	ErrForbidden = errors.New("containers: forbidden")
	ErrStale = errors.New("containers: stale generation")
	ErrPolicy = errors.New("containers: policy rejected")
	ErrAmbiguous = errors.New("containers: effect outcome ambiguous")
	ErrInUse = errors.New("containers: resource is in use")
)

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,95}$`)
var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type ID string
func NewID(value string)(ID,error){value=strings.TrimSpace(value);if !idPattern.MatchString(value){return "",fmt.Errorf("%w: id",ErrInvalid)};return ID(value),nil}
func(id ID)Valid()bool{return idPattern.MatchString(string(id))}
func(id ID)String()string{return string(id)}

type RuntimeTier string
const(
	TierTenantRootless RuntimeTier="tenant_rootless"
	TierAdminRootful RuntimeTier="admin_rootful"
)

type Lifecycle string
const(
	LifecyclePending Lifecycle="pending"
	LifecyclePulling Lifecycle="pulling"
	LifecycleCreating Lifecycle="creating"
	LifecycleRunning Lifecycle="running"
	LifecycleStopped Lifecycle="stopped"
	LifecyclePaused Lifecycle="paused"
	LifecycleUpdating Lifecycle="updating"
	LifecycleDegraded Lifecycle="degraded"
	LifecycleDeleting Lifecycle="deleting"
	LifecycleDeleted Lifecycle="deleted"
)

type WorkloadHealth string
const(
	HealthUnknown WorkloadHealth="unknown"
	HealthStarting WorkloadHealth="starting"
	HealthHealthy WorkloadHealth="healthy"
	HealthUnhealthy WorkloadHealth="unhealthy"
	HealthUnavailable WorkloadHealth="unavailable"
)

type ImageReference struct{ Registry string; Repository string; Digest string; Platform string }
func(i ImageReference)Validate()error{if strings.TrimSpace(i.Registry)==""||strings.ContainsAny(i.Registry,"/ @\t\r\n")||strings.Trim(i.Repository,"/")==""||strings.ContainsAny(i.Repository," @\t\r\n")||!digestPattern.MatchString(i.Digest){return fmt.Errorf("%w: image reference",ErrInvalid)};if i.Platform!="linux/amd64"&&i.Platform!="linux/arm64"{return fmt.Errorf("%w: platform",ErrInvalid)};return nil}

type RegistryCredential struct{ ID, TenantID ID; Registry, Account, SecretRef string; Generation uint64; CreatedAt,UpdatedAt time.Time; RevokedAt *time.Time }
func(r RegistryCredential)Validate()error{if !r.ID.Valid()||!r.TenantID.Valid()||strings.TrimSpace(r.Registry)==""||strings.TrimSpace(r.Account)==""||strings.TrimSpace(r.SecretRef)==""||r.Generation==0{return ErrInvalid};return nil}

type Image struct{ ID ID; TenantID ID; Reference ImageReference; SizeBytes uint64; ConfigDigest,ManifestDigest,SBOMDigest,SignatureDigest,VulnerabilityDigest string; PolicyVerdict PolicyVerdict; State ImageState; Generation uint64; PulledAt,VerifiedAt time.Time }
type ImageState string
const(ImageResolving ImageState="resolving";ImageReady ImageState="ready";ImageRejected ImageState="rejected";ImageDeleting ImageState="deleting";ImageDeleted ImageState="deleted")
type PolicyVerdict string
const(PolicyPending PolicyVerdict="pending";PolicyAllowed PolicyVerdict="allowed";PolicyDenied PolicyVerdict="denied";PolicyException PolicyVerdict="exception")

type EnvironmentValue struct{Name string; Value string; SecretRef string}
func(e EnvironmentValue)Validate()error{if !envNamePattern.MatchString(e.Name)||(e.Value=="")== (e.SecretRef==""){return fmt.Errorf("%w: environment",ErrInvalid)};if len(e.Value)>65536||strings.ContainsRune(e.Value,0){return fmt.Errorf("%w: environment value",ErrInvalid)};return nil}

type RuntimeUser struct{ UID,GID uint32 }
func(u RuntimeUser)Validate(tier RuntimeTier)error{if tier==TierTenantRootless&&(u.UID==0||u.GID==0){return fmt.Errorf("%w: tenant root mapping",ErrPolicy)};return nil}

type RestartPolicy string
const(RestartNever RestartPolicy="never";RestartOnFailure RestartPolicy="on_failure";RestartUnlessStopped RestartPolicy="unless_stopped")
type UpdatePolicy string
const(UpdateManual UpdatePolicy="manual";UpdatePinnedMaintenance UpdatePolicy="pinned_maintenance")

type HealthCheck struct{ Kind string; Path string; PortName string; CommandID ID; Interval,Timeout time.Duration; Successes,Failures uint8 }
func(h HealthCheck)Validate()error{if h.Kind!="http"&&h.Kind!="tcp"&&h.Kind!="exec"{return ErrInvalid};if h.Interval<time.Second||h.Timeout<=0||h.Timeout>=h.Interval||h.Successes==0||h.Failures==0{return ErrInvalid};if h.Kind=="http"&&(h.Path==""||!strings.HasPrefix(h.Path,"/")||h.PortName==""){return ErrInvalid};if h.Kind=="tcp"&&h.PortName==""{return ErrInvalid};if h.Kind=="exec"&&!h.CommandID.Valid(){return ErrInvalid};return nil}

type ResourceLimits struct{ CPUQuotaMicros,CPUPeriodMicros,MemoryHighBytes,MemoryMaxBytes,SwapMaxBytes,PIDsMax,ReadBPS,WriteBPS,ReadIOPS,WriteIOPS,StorageBytes,Inodes,NetworkEgressBPS uint64 }
func(r ResourceLimits)Validate()error{if r.CPUQuotaMicros==0||r.CPUPeriodMicros==0||r.MemoryMaxBytes==0||r.MemoryHighBytes>r.MemoryMaxBytes||r.PIDsMax==0||r.StorageBytes==0||r.Inodes==0{return fmt.Errorf("%w: resource limits",ErrInvalid)};return nil}

type Volume struct{ ID,TenantID ID; Name string; Tier RuntimeTier; Class string; QuotaBytes,InodeLimit uint64; State string; Generation uint64; CreatedAt,UpdatedAt time.Time }
type VolumeMount struct{ VolumeID ID; Target string; ReadOnly bool }
func(v VolumeMount)Validate()error{if !v.VolumeID.Valid()||!absoluteContainerPath(v.Target)||v.Target=="/"||strings.HasPrefix(v.Target,"/proc")||strings.HasPrefix(v.Target,"/sys")||strings.HasPrefix(v.Target,"/dev")||strings.Contains(v.Target,"..") {return fmt.Errorf("%w: volume mount",ErrPolicy)};return nil}

type Network struct{ ID,TenantID ID; Name string; Tier RuntimeTier; IPv4,IPv6 netip.Prefix; Internal bool; DNSPolicy string; State string; Generation uint64 }
type NetworkAttachment struct{ NetworkID ID; Aliases []string }

type PortProtocol string
const(ProtocolTCP PortProtocol="tcp";ProtocolUDP PortProtocol="udp")
type Port struct{Name string; ContainerPort uint16; Protocol PortProtocol}
type Exposure struct{ID,TenantID,WorkloadID ID;PortName string;Public bool;ListenerRef,DomainBindingRef string;AllowedCIDRs []netip.Prefix;Generation uint64;State string}

type CapabilityPolicy struct{ NoNewPrivileges bool; ReadOnlyRoot bool; DropAllCapabilities bool; SeccompProfile,MACProfile string; AllowPublicEgress bool; EgressPolicyID ID }
func(p CapabilityPolicy)Validate(tier RuntimeTier)error{if tier==TierTenantRootless&&(!p.NoNewPrivileges||!p.DropAllCapabilities||p.SeccompProfile==""||p.MACProfile==""){return fmt.Errorf("%w: tenant isolation",ErrPolicy)};return nil}

type WorkloadSpec struct{
	Image ImageReference
	CommandID ID
	Arguments []string
	WorkingDirectory string
	Environment []EnvironmentValue
	User RuntimeUser
	Restart RestartPolicy
	Update UpdatePolicy
	Health HealthCheck
	Limits ResourceLimits
	Volumes []VolumeMount
	Networks []NetworkAttachment
	Ports []Port
	Security CapabilityPolicy
}

func(s WorkloadSpec)Validate(tier RuntimeTier)error{if err:=s.Image.Validate();err!=nil{return err};if !s.CommandID.Valid()||!absoluteContainerPath(s.WorkingDirectory)||len(s.Arguments)>128{return ErrInvalid};if err:=s.User.Validate(tier);err!=nil{return err};if s.Restart!=RestartNever&&s.Restart!=RestartOnFailure&&s.Restart!=RestartUnlessStopped{return ErrInvalid};if s.Update!=UpdateManual&&s.Update!=UpdatePinnedMaintenance{return ErrInvalid};if err:=s.Health.Validate();err!=nil{return err};if err:=s.Limits.Validate();err!=nil{return err};if err:=s.Security.Validate(tier);err!=nil{return err};names:=map[string]bool{};for _,e:=range s.Environment{if err:=e.Validate();err!=nil{return err};if names[e.Name]{return ErrConflict};names[e.Name]=true};targets:=map[string]bool{};for _,m:=range s.Volumes{if err:=m.Validate();err!=nil{return err};if targets[m.Target]{return ErrConflict};targets[m.Target]=true};ports:=map[string]bool{};for _,p:=range s.Ports{if p.Name==""||p.ContainerPort==0||(p.Protocol!=ProtocolTCP&&p.Protocol!=ProtocolUDP)||ports[p.Name]{return ErrInvalid};ports[p.Name]=true};return nil}

type Workload struct{ ID,TenantID,ProjectID,SiteID ID; Name string; Tier RuntimeTier; Spec WorkloadSpec; DesiredLifecycle,ObservedLifecycle Lifecycle; ObservedHealth WorkloadHealth; RuntimeObjectID string; SpecDigest,ObservedDigest string; Generation,ObservedGeneration uint64; RestartCount uint64; CreatedAt,UpdatedAt time.Time; DeletedAt *time.Time }
func(w Workload)Validate()error{if !w.ID.Valid()||!w.TenantID.Valid()||strings.TrimSpace(w.Name)==""||(w.Tier!=TierTenantRootless&&w.Tier!=TierAdminRootful)||w.Generation==0{return ErrInvalid};if err:=w.Spec.Validate(w.Tier);err!=nil{return err};if !validLifecycle(w.DesiredLifecycle)||!validLifecycle(w.ObservedLifecycle)||w.ObservedHealth!=""&&!validWorkloadHealth(w.ObservedHealth){return ErrInvalid};return nil}

type ApplicationRecipe struct{ID ID;Name,Version,Digest,SigningKeyID,SignatureDigest,Signature string;Workloads []RecipeWorkload;Volumes []RecipeVolume;Networks []RecipeNetwork;HealthPolicy string;BackupPolicyID ID}
type RecipeWorkload struct{Name string;Spec WorkloadSpec;DependsOn []string;RoutePortName string}
type RecipeVolume struct{Name,Class,MountTarget string;QuotaBytes,InodeLimit uint64;Backup bool}
type RecipeNetwork struct{Name string;Internal bool}
type ContainerApplication struct{ID,TenantID,SiteID,RecipeID ID;RecipeVersion string;WorkloadIDs,VolumeIDs,NetworkIDs []ID;ActiveGeneration uint64;CandidateGeneration uint64;State string;DataGeneration uint64;FirstWriteAt *time.Time;CreatedAt,UpdatedAt time.Time}

type ExecGrant struct{ID,TenantID,WorkloadID ID;Tier RuntimeTier;RuntimeUser RuntimeUser;CommandID ID;Arguments []string;AssuranceDigest string;ExpiresAt time.Time;ConsumedAt *time.Time}
type LogCursor struct{WorkloadID ID;Stream string;Opaque string;At time.Time}
type WorkloadObservation struct{WorkloadID ID;RuntimeObjectID,SpecDigest,ImageDigest string;Health WorkloadHealth;Lifecycle Lifecycle;RestartCount uint64;CPUUsageNanos,MemoryBytes,ReadBytes,WriteBytes,NetworkRXBytes,NetworkTXBytes uint64;ObservedAt time.Time}

func validLifecycle(value Lifecycle)bool{switch value{case LifecyclePending,LifecyclePulling,LifecycleCreating,LifecycleRunning,LifecycleStopped,LifecyclePaused,LifecycleUpdating,LifecycleDegraded,LifecycleDeleting,LifecycleDeleted:return true};return false}
func validWorkloadHealth(value WorkloadHealth)bool{switch value{case HealthUnknown,HealthStarting,HealthHealthy,HealthUnhealthy,HealthUnavailable:return true};return false}
func absoluteContainerPath(value string)bool{return strings.HasPrefix(value,"/")&&!strings.Contains(value,"//")&&!strings.Contains(value,"/../")&&!strings.HasSuffix(value,"/..")&&!strings.ContainsRune(value,0)}
func canonicalEnvironment(values []EnvironmentValue)[]EnvironmentValue{out:=append([]EnvironmentValue(nil),values...);sort.Slice(out,func(i,j int)bool{return out[i].Name<out[j].Name});return out}
