package containers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// DefaultPolicy is the closed, fail-safe container policy used by panel-core.
// Images must already be digest pinned. Tenant workloads cannot request the
// rootful tier, host networking, privilege-bearing mounts, public host ports,
// or an exposure without a product-owned listener and domain binding.
type DefaultPolicy struct{AllowedRegistries map[string]struct{};Clock func()time.Time}
func NewDefaultPolicy(registries ...string)(*DefaultPolicy,error){allowed:=map[string]struct{}{};for _,registry:=range registries{registry=strings.ToLower(strings.TrimSpace(registry));if !validRegistryName(registry){return nil,ErrInvalid};allowed[registry]=struct{}{}};if len(allowed)==0{allowed["registry-1.docker.io"]=struct{}{};allowed["docker.io"]=struct{}{};allowed["quay.io"]=struct{}{}};return &DefaultPolicy{AllowedRegistries:allowed,Clock:time.Now},nil}
func(policy *DefaultPolicy)EvaluateImage(_ context.Context,_ ID,image ImageReference)(ImagePolicyReceipt,error){if policy==nil||image.Validate()!=nil{return ImagePolicyReceipt{Verdict:PolicyDenied,PolicyVersion:"container-default-v1"},ErrPolicy};if _,ok:=policy.AllowedRegistries[strings.ToLower(image.Registry)];!ok{return ImagePolicyReceipt{ImageDigest:image.Digest,Verdict:PolicyDenied,PolicyVersion:"container-default-v1"},ErrPolicy};return ImagePolicyReceipt{ImageDigest:image.Digest,Verdict:PolicyAllowed,PolicyVersion:"digest-pinned-isolation-v1"},nil}
func(policy *DefaultPolicy)AuthorizeTier(_ context.Context,grant Grant,tier RuntimeTier,operation string)error{if policy==nil||grant.TenantID==""||operation!="apply"&&operation!="exec"{return ErrForbidden};if tier!=TierTenantRootless{return ErrPolicy};return nil}
func(policy *DefaultPolicy)ValidateWorkload(_ context.Context,tenant ID,tier RuntimeTier,spec WorkloadSpec)error{if policy==nil||!tenant.Valid()||tier!=TierTenantRootless||spec.Validate(tier)!=nil{return ErrPolicy};if !spec.Security.NoNewPrivileges||!spec.Security.DropAllCapabilities||spec.Security.SeccompProfile!="runtime/default"||spec.Security.MACProfile!="panel/tenant"{return ErrPolicy};for _,mount:=range spec.Volumes{if mount.Target=="/run"||strings.HasPrefix(mount.Target,"/run/")||strings.HasPrefix(mount.Target,"/etc/"){return ErrPolicy}};return nil}
func(policy *DefaultPolicy)ValidateExposure(_ context.Context,tenant ID,exposure Exposure)error{if policy==nil||!tenant.Valid()||exposure.TenantID!=tenant||!exposure.ID.Valid()||!exposure.WorkloadID.Valid()||exposure.PortName==""||exposure.Generation==^uint64(0){return ErrPolicy};if exposure.Public&&(exposure.ListenerRef==""||exposure.DomainBindingRef=="")||!exposure.Public&&(exposure.ListenerRef!=""||exposure.DomainBindingRef!=""||len(exposure.AllowedCIDRs)>0){return ErrPolicy};if strings.ContainsAny(exposure.ListenerRef," \t\r\n")||strings.ContainsAny(exposure.DomainBindingRef,"/@ \t\r\n"){return ErrPolicy};for _,prefix:=range prefixesSorted(exposure.AllowedCIDRs){if !prefix.IsValid()||prefix.Addr().IsUnspecified()||prefix.Addr().IsMulticast(){return ErrPolicy}};return nil}

type BrokerVolumeBackupCoordinator struct{Repository Repository;Broker Broker;Clock func()time.Time}
func NewBrokerVolumeBackupCoordinator(repository Repository,broker Broker)(*BrokerVolumeBackupCoordinator,error){if nilValue(repository)||nilValue(broker){return nil,ErrInvalid};return &BrokerVolumeBackupCoordinator{Repository:repository,Broker:broker,Clock:time.Now},nil}
func(coordinator *BrokerVolumeBackupCoordinator)SnapshotVolumes(ctx context.Context,application ID,volumes []ID)(string,error){tenant,ordered,err:=coordinator.resolveVolumes(ctx,volumes);if err!=nil{return "",err};snapshotID,err:=NewID("snap_"+digestValue(struct{Application ID;Volumes []ID}{application,ordered})[:48]);if err!=nil{return "",err};effect:=EffectID("snapshot-"+digestValue(struct{Snapshot ID;Tenant ID}{snapshotID,tenant}));receipt,err:=coordinator.Broker.SnapshotVolumes(ctx,VolumeSnapshotRequest{EffectID:effect,SnapshotID:snapshotID,TenantID:tenant,ApplicationID:application,VolumeIDs:ordered,Fence:1});if err!=nil||receipt.Outcome!="confirmed"||receipt.EffectID!=effect||receipt.SnapshotID!=snapshotID||receipt.ApplicationID!=application||receipt.Fence!=1||len(receipt.ManifestDigest)!=64||receipt.Bytes==0||receipt.ObservedAt.IsZero()||receipt.CompletedAt.IsZero()||!sameProtocolIDs(ordered,receipt.VolumeIDs){return "",errors.Join(ErrAmbiguous,err)};return snapshotID.String(),nil}
func(coordinator *BrokerVolumeBackupCoordinator)RestoreVolumes(ctx context.Context,snapshot string,volumes []ID)error{snapshotID,err:=NewID(snapshot);if err!=nil{return err};tenant,ordered,err:=coordinator.resolveVolumes(ctx,volumes);if err!=nil{return err};effect:=EffectID("restore-"+digestValue(struct{Snapshot ID;Tenant ID;Volumes []ID}{snapshotID,tenant,ordered}));receipt,err:=coordinator.Broker.RestoreVolumes(ctx,VolumeRestoreRequest{EffectID:effect,SnapshotID:snapshotID,TenantID:tenant,VolumeIDs:ordered,Fence:1});if err!=nil||receipt.Outcome!="confirmed"{return errors.Join(ErrAmbiguous,err)};return nil}
func(coordinator *BrokerVolumeBackupCoordinator)resolveVolumes(ctx context.Context,ids []ID)(ID,[]ID,error){if coordinator==nil||nilValue(coordinator.Repository)||nilValue(coordinator.Broker)||len(ids)==0||len(ids)>64{return "",nil,ErrInvalid};ordered:=append([]ID(nil),ids...);sort.Slice(ordered,func(i,j int)bool{return ordered[i]<ordered[j]});var tenant ID;for index,id:=range ordered{if !id.Valid()||index>0&&id==ordered[index-1]{return "",nil,ErrInvalid};volume,err:=coordinator.Repository.VolumeByID(ctx,id);if err!=nil{return "",nil,err};if index==0{tenant=volume.TenantID}else if volume.TenantID!=tenant{return "",nil,ErrForbidden}};if !tenant.Valid(){return "",nil,ErrInvalid};return tenant,ordered,nil}

// SignedRecipeVerifier verifies the stored canonical recipe against an
// explicitly configured Ed25519 trust set. The signature itself remains in
// the recipe document; SignatureDigest binds its exact bytes.
type SignedRecipeVerifier struct{Keys map[string]ed25519.PublicKey}
func NewSignedRecipeVerifier(keys map[string]ed25519.PublicKey)(*SignedRecipeVerifier,error){copy:=map[string]ed25519.PublicKey{};for id,key:=range keys{if id==""||len(key)!=ed25519.PublicKeySize{return nil,ErrInvalid};copy[id]=append(ed25519.PublicKey(nil),key...)};if len(copy)==0{return nil,ErrInvalid};return &SignedRecipeVerifier{Keys:copy},nil}
func(verifier *SignedRecipeVerifier)Verify(ctx context.Context,recipe ApplicationRecipe)error{if verifier==nil||ctx==nil||recipe.SigningKeyID==""||len(recipe.Signature)==0{return ErrPolicy};select{case<-ctx.Done():return ctx.Err();default:};key:=verifier.Keys[recipe.SigningKeyID];signature,err:=base64.RawURLEncoding.DecodeString(recipe.Signature);if err!=nil{signature,err=base64.StdEncoding.DecodeString(recipe.Signature)};if err!=nil||len(signature)!=ed25519.SignatureSize||len(key)!=ed25519.PublicKeySize{return ErrPolicy};sum:=sha256.Sum256(signature);if hex.EncodeToString(sum[:])!=recipe.SignatureDigest{return ErrPolicy};unsigned:=recipe;unsigned.Digest="";unsigned.SignatureDigest="";unsigned.Signature="";payload,err:=canonicalContainerJSON(unsigned);if err!=nil{return err};payloadSum:=sha256.Sum256(payload);if hex.EncodeToString(payloadSum[:])!=recipe.Digest||!ed25519.Verify(key,payload,signature){return ErrPolicy};return nil}

type DeterministicIDAllocator struct{Namespace string}
func NewDeterministicIDAllocator(namespace string)(*DeterministicIDAllocator,error){namespace=strings.TrimSpace(namespace);if namespace==""||len(namespace)>64{return nil,ErrInvalid};return &DeterministicIDAllocator{Namespace:namespace},nil}
func(allocator *DeterministicIDAllocator)For(_ context.Context,parent ID,kind,name string)(ID,error){if allocator==nil||!parent.Valid()||kind==""||name==""||len(kind)>32||len(name)>128{return "",ErrInvalid};for _,value:=range []string{kind,name}{if strings.ContainsAny(value,"\x00\r\n"){return "",ErrInvalid}};sum:=sha256.Sum256([]byte("cyberpanel:container-id:v1\x00"+allocator.Namespace+"\x00"+parent.String()+"\x00"+kind+"\x00"+name));prefix:=kind;if len(prefix)>12{prefix=prefix[:12]};prefix=strings.Map(func(value rune)rune{if value>='a'&&value<='z'||value>='0'&&value<='9'||value=='_'||value=='-'{return value};return '_'},strings.ToLower(prefix));return NewID(prefix+"_"+hex.EncodeToString(sum[:24]))}

func canonicalContainerJSON(value any)([]byte,error){raw,err:=json.Marshal(value);if err!=nil{return nil,err};decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.UseNumber();var document any;if err=decoder.Decode(&document);err!=nil{return nil,err};return json.Marshal(document)}
