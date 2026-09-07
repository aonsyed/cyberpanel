package integrations

import (
	"context"
	"fmt"
	"errors"
	"time"
)

// N8NDefinition is a certified container-application contract. It contains no
// Compose document, daemon socket, host path, published arbitrary port, or
// Swarm credential. The container broker derives its closed workload graph.
type N8NDefinition struct {
	RecipeID ID `json:"recipe_id"`
	RecipeDigest string `json:"recipe_digest"`
	RecipeSignature string `json:"recipe_signature"`
	SigningKeyID string `json:"signing_key_id"`
	CatalogEpoch uint64 `json:"catalog_epoch"`
	Version string `json:"version"`
	Image OCIReference `json:"image"`
	ResolvedImageDigest string `json:"resolved_image_digest"`
	Architectures []string `json:"architectures"`
	DatabaseKind string `json:"database_kind"`
	InternalPort uint16 `json:"internal_port"`
	HealthPath string `json:"health_path"`
	MinimumMemory uint64 `json:"minimum_memory"`
	MinimumCPU uint32 `json:"minimum_cpu"`
	DefinitionDigest string `json:"definition_digest"`
}

func (definition N8NDefinition) Validate() error { if !validID(string(definition.RecipeID))||!validDigest(definition.RecipeDigest)||definition.RecipeSignature==""||!validID(definition.SigningKeyID)||definition.CatalogEpoch==0||definition.Version==""||definition.Image.Validate()!=nil||!validDigest(definition.ResolvedImageDigest)||len(definition.Architectures)==0||definition.DatabaseKind!="postgresql"||definition.InternalPort!=5678||definition.HealthPath!="/healthz"||definition.MinimumMemory<512<<20||definition.MinimumCPU==0||!validDigest(definition.DefinitionDigest){return ErrInvalid};return nil }

type N8NInstallation struct {
	ID ID `json:"id"`
	TenantID TenantID `json:"tenant_id"`
	SiteID string `json:"site_id"`
	Definition N8NDefinition `json:"definition"`
	DatabaseBindingRef string `json:"database_binding_ref"`
	DatabaseCredentialRef SecretRef `json:"database_credential_ref"`
	EncryptionKeyRef SecretRef `json:"encryption_key_ref"`
	OwnerCredentialRef SecretRef `json:"owner_credential_ref"`
	VolumeID string `json:"volume_id"`
	ResourceProfileID string `json:"resource_profile_id"`
	WebReplicas uint16 `json:"web_replicas"`
	WorkerReplicas uint16 `json:"worker_replicas"`
	WebhookReplicas uint16 `json:"webhook_replicas"`
	PrivateServiceBinding string `json:"private_service_binding"`
	PublicRouteBinding string `json:"public_route_binding"`
	State string `json:"state"`
	Generation uint64 `json:"generation"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (installation N8NInstallation) Validate() error { if !validID(string(installation.ID))||!validID(string(installation.TenantID))||!validID(installation.SiteID)||installation.Definition.Validate()!=nil||!validID(installation.DatabaseBindingRef)||!validID(string(installation.DatabaseCredentialRef))||!validID(string(installation.EncryptionKeyRef))||!validID(string(installation.OwnerCredentialRef))||!validID(installation.VolumeID)||!validID(installation.ResourceProfileID)||installation.WebReplicas==0||installation.WorkerReplicas==0||installation.WebhookReplicas==0||installation.PrivateServiceBinding==""||installation.PublicRouteBinding==""||installation.Generation==0||installation.CreatedAt.IsZero()||installation.UpdatedAt.IsZero(){return ErrInvalid};return nil }

type N8NWorkloadIntent struct {
	InstallationID ID `json:"installation_id"`
	Action string `json:"action"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	ImageDigest string `json:"image_digest"`
	DatabaseBindingRef string `json:"database_binding_ref"`
	SecretGrantRefs []string `json:"secret_grant_refs"`
	VolumeID string `json:"volume_id"`
	ResourceProfileID string `json:"resource_profile_id"`
	WebReplicas uint16 `json:"web_replicas"`
	WorkerReplicas uint16 `json:"worker_replicas"`
	WebhookReplicas uint16 `json:"webhook_replicas"`
	InternalPort uint16 `json:"internal_port"`
	PrivateServiceBinding string `json:"private_service_binding"`
}

func (intent N8NWorkloadIntent) Validate() error { if !validID(string(intent.InstallationID))||intent.ExpectedGeneration==0||!validDigest(intent.ImageDigest)||!validID(intent.DatabaseBindingRef)||len(intent.SecretGrantRefs)!=2||!validID(intent.VolumeID)||!validID(intent.ResourceProfileID)||intent.InternalPort!=5678||intent.PrivateServiceBinding==""{return ErrInvalid};switch intent.Action{case "install","scale","update","suspend","resume","remove":default:return ErrUnsupported};return nil }

type N8NReceipt struct { State string `json:"state"`;  InstallationID ID `json:"installation_id"`; Action string `json:"action"`; ObservedGeneration uint64 `json:"observed_generation"`; ImageDigest string `json:"image_digest"`; WorkloadDigest string `json:"workload_digest"`; PrivateEndpoint string `json:"private_endpoint"`; HealthDigest string `json:"health_digest"`; Receipt string `json:"receipt"`; CompletedAt time.Time `json:"completed_at"` }
type N8NContainerFederation interface { ApplyN8NIntent(context.Context,N8NWorkloadIntent)(N8NReceipt,error); ObserveN8N(context.Context,ID)(N8NReceipt,error) }

type N8NStore interface { SaveN8NInstallation(context.Context,N8NInstallation,uint64)error; LoadN8NInstallation(context.Context,ID)(N8NInstallation,error) }
type N8NCoordinator struct { Federation N8NContainerFederation; Store N8NStore }
func (coordinator N8NCoordinator) Apply(ctx context.Context, installation N8NInstallation, action string) (N8NReceipt,error) {
 if coordinator.Federation==nil||coordinator.Store==nil{return N8NReceipt{},ErrInvalid}
 if err:=installation.Validate();err!=nil{return N8NReceipt{},err}
 expected:=uint64(0)
 if action!="install"{
  persisted,err:=coordinator.Store.LoadN8NInstallation(ctx,installation.ID);if err!=nil{return N8NReceipt{},err}
  if persisted.TenantID!=installation.TenantID{return N8NReceipt{},ErrNotFound}
  if persisted.Generation!=installation.Generation{return N8NReceipt{},ErrStaleGeneration}
  expected=persisted.Generation
 } else {
  if _,err:=coordinator.Store.LoadN8NInstallation(ctx,installation.ID);err==nil{return N8NReceipt{},ErrStaleGeneration}else if !errors.Is(err,ErrNotFound){return N8NReceipt{},err}
 }
 intent:=N8NWorkloadIntent{InstallationID:installation.ID,Action:action,ExpectedGeneration:installation.Generation,ImageDigest:installation.Definition.ResolvedImageDigest,DatabaseBindingRef:installation.DatabaseBindingRef,DatabaseCredentialRef:installation.DatabaseCredentialRef,SecretGrantRefs:[]string{string(installation.EncryptionKeyRef),string(installation.OwnerCredentialRef)},VolumeID:installation.VolumeID,ResourceProfileID:installation.ResourceProfileID,WebReplicas:installation.WebReplicas,WorkerReplicas:installation.WorkerReplicas,WebhookReplicas:installation.WebhookReplicas,InternalPort:5678,PrivateServiceBinding:installation.PrivateServiceBinding}
 if err:=intent.Validate();err!=nil{return N8NReceipt{},err}
 // Save intent before effects, so a failed/uncertain install is discoverable.
 installation.State="reconciling";installation.Generation=expected+1;installation.UpdatedAt=time.Now().UTC()
 if err:=coordinator.Store.SaveN8NInstallation(ctx,installation,expected);err!=nil{return N8NReceipt{},err}
 receipt,err:=coordinator.Federation.ApplyN8NIntent(ctx,intent)
 if err!=nil{return N8NReceipt{},err}
 if receipt.InstallationID!=installation.ID||receipt.Action!=action||receipt.ImageDigest!=installation.Definition.ResolvedImageDigest||!validDigest(receipt.WorkloadDigest)||!validDigest(receipt.HealthDigest)||receipt.Receipt==""||receipt.CompletedAt.IsZero(){return N8NReceipt{},fmt.Errorf("%w: n8n receipt",ErrIntegrity)}
 switch receipt.State{case "active","starting","degraded","suspended","removed":default:return N8NReceipt{},ErrIntegrity}
 expected=installation.Generation;installation.Generation++;installation.State=receipt.State;installation.UpdatedAt=receipt.CompletedAt
 receipt.ObservedGeneration=installation.Generation
 if err:=coordinator.Store.SaveN8NInstallation(ctx,installation,expected);err!=nil{return N8NReceipt{},err}
 return receipt,nil
}
