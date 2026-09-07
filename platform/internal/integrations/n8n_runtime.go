package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/containers"
)

// N8NRuntime connects the integration coordinator to the local container broker.
// No central/fleet service participates in standalone admission or observation.
type N8NRuntime struct {
	Applications *containers.ApplicationService
	Containers *containers.Service
	Repository containers.Repository
	Store N8NStore
	Verifier containers.RecipeVerifier
	Allocator containers.IDAllocator
	AuthorizeSite func(context.Context, string, string) error
}

var ErrN8NRecipeUnavailable = errors.New("n8n signed recipe unavailable")
var ErrN8NRecipeTrust = errors.New("n8n release trust rejected")

func (service *N8NRuntime) Apply(ctx context.Context, meta containers.CommandMeta, installation N8NInstallation, action string) (N8NReceipt, error) {
	if service == nil || service.Applications == nil || service.Containers == nil || service.Repository == nil || service.Store == nil || service.Verifier == nil || service.Allocator == nil || service.AuthorizeSite == nil { return N8NReceipt{}, ErrInvalid }
	if string(installation.TenantID) != meta.Grant.TenantID.String() { return N8NReceipt{}, ErrNotFound }
	if err := service.AuthorizeSite(ctx, string(installation.TenantID), installation.SiteID); err != nil { return N8NReceipt{}, err }
	if action == "install" {
		if meta.ExpectedGeneration != 0 { return N8NReceipt{}, ErrStaleGeneration }
		installation.Generation = 1
		installation.CreatedAt, installation.UpdatedAt = time.Now().UTC(), time.Now().UTC()
	} else {
		current, err := service.Store.LoadN8NInstallation(ctx, installation.ID)
		if err != nil { return N8NReceipt{}, err }
		if current.TenantID != installation.TenantID { return N8NReceipt{}, ErrNotFound }
		if current.Generation != meta.ExpectedGeneration { return N8NReceipt{}, ErrStaleGeneration }
		if current.State == "removed" { return N8NReceipt{}, fmt.Errorf("%w: installation removed", ErrInvalid) }
		if action == "update" {
			if current.State != "active" && current.State != "starting" { return N8NReceipt{}, fmt.Errorf("%w: update requires reconciled installation", ErrInvalid) }
			current.Definition = installation.Definition
		}
		installation = current
	}
	if action == "scale" { return N8NReceipt{}, fmt.Errorf("%w: replica counts are fixed by the signed recipe; topology changes need a new recovery plan", ErrUnsupported) }
	if err := installation.Definition.Validate(); err != nil { return N8NReceipt{}, err }
	recipeID, err := containers.NewID(string(installation.Definition.RecipeID)); if err != nil { return N8NReceipt{}, err }
	recipe, err := service.Repository.Recipe(ctx, recipeID, installation.Definition.Version)
	if err != nil { return N8NReceipt{}, fmt.Errorf("%w: %s/%s: %v", ErrN8NRecipeUnavailable, recipeID, installation.Definition.Version, err) }
	if err = service.Verifier.Verify(ctx, recipe); err != nil { return N8NReceipt{}, fmt.Errorf("%w: %v", ErrN8NRecipeTrust, err) }
	if err = validateN8NRecipe(recipe, installation); err != nil { return N8NReceipt{}, err }
	applicationID, err := containers.NewID(string(installation.ID)); if err != nil { return N8NReceipt{}, err }
	volumeID, err := service.Allocator.For(ctx,applicationID,"volume","n8n_data"); if err != nil { return N8NReceipt{}, err }
	installation.VolumeID, installation.ResourceProfileID = volumeID.String(), recipe.ID.String()
	for _,workload:=range recipe.Workloads { if n8nRole(workload.Name)=="postgres" { databaseID,e:=service.Allocator.For(ctx,applicationID,"workload",workload.Name);if e!=nil{return N8NReceipt{},e};installation.DatabaseBindingRef=databaseID.String() } }
	if err:=installation.Validate();err!=nil{return N8NReceipt{},err}
	federation := &localN8NFederation{service:service, meta:meta, installation:installation, recipe:recipe}
	return (N8NCoordinator{Federation:federation, Store:service.Store}).Apply(ctx, installation, action)
}

func (service *N8NRuntime) Observe(ctx context.Context, meta containers.CommandMeta, id ID) (N8NReceipt, error) {
	installation, err := service.Store.LoadN8NInstallation(ctx, id); if err != nil { return N8NReceipt{}, err }
	if string(installation.TenantID) != meta.Grant.TenantID.String() { return N8NReceipt{}, ErrNotFound }
	if err = service.AuthorizeSite(ctx,string(installation.TenantID),installation.SiteID); err != nil { return N8NReceipt{}, err }
	federation := &localN8NFederation{service:service, meta:meta, installation:installation}
	return federation.ObserveN8N(ctx,id)
}

// These are the only release-owned placeholders that deployment may bind.
// The broker resolves IDs using tenant + workload + authentication purpose.
func n8nSecretBindings(installation N8NInstallation) map[string]string {
	return map[string]string{"secret_n8n_encryption":string(installation.EncryptionKeyRef), "secret_n8n_owner":string(installation.OwnerCredentialRef), "secret_n8n_database":string(installation.DatabaseCredentialRef)}
}

// ValidateN8NApplicationRecipe is shared by offline release assembly and node
// ingestion. Signature verification is separate and mandatory before deploy.
func ValidateN8NApplicationRecipe(recipe containers.ApplicationRecipe) error {
	if recipe.Name != "n8n" || len(recipe.Workloads) < 5 || len(recipe.Workloads) > 64 || len(recipe.Volumes) < 2 || len(recipe.Networks) == 0 { return ErrInvalid }
	counts:=map[string]int{}; names:=map[string]bool{}; volumes:=map[string]bool{}; networks:=map[string]bool{}; slots:=map[string]bool{}
	for _,volume:=range recipe.Volumes { if volumes[volume.Name]||volume.Name==""||volume.QuotaBytes==0||volume.InodeLimit==0||!volume.Backup { return ErrInvalid };volumes[volume.Name]=true }
	if !volumes["n8n_data"]||!volumes["postgres_data"] { return fmt.Errorf("%w: n8n_data and postgres_data backup volumes required",ErrInvalid) }
	for _,network:=range recipe.Networks { if network.Name==""||networks[network.Name]||!network.Internal { return ErrInvalid };networks[network.Name]=true }
	var image containers.ImageReference
	for _,workload:=range recipe.Workloads {
		role:=n8nRole(workload.Name);if role==""||len(workload.Name)>64||names[workload.Name]||workload.Spec.Validate(containers.TierTenantRootless)!=nil||len(workload.Spec.Networks)==0{return ErrInvalid};names[workload.Name]=true;counts[role]++
		for _,mount:=range workload.Spec.Volumes { name:=strings.TrimPrefix(mount.VolumeID.String(),"vol_");if !volumes[name]{return ErrInvalid} }
		for _,attachment:=range workload.Spec.Networks { name:=strings.TrimPrefix(attachment.NetworkID.String(),"net_");if !networks[name]{return ErrInvalid} }
		if role=="web"||role=="worker"||role=="webhook" {
			if image.Digest==""{image=workload.Spec.Image}else if image!=workload.Spec.Image{return fmt.Errorf("%w: n8n roles must share one pinned image",ErrInvalid)}
			if workload.Spec.Limits.MemoryMaxBytes<512<<20{return ErrInvalid}
		}
		if role=="web" { if workload.RoutePortName==""||workload.Spec.Health.Kind!="http"||workload.Spec.Health.Path!="/healthz"{return ErrInvalid};portFound:=false;for _,port:=range workload.Spec.Ports{if port.Name==workload.RoutePortName&&port.Name==workload.Spec.Health.PortName&&port.ContainerPort==5678&&port.Protocol==containers.ProtocolTCP{portFound=true}};if !portFound{return ErrInvalid} }
		for _,entry:=range workload.Spec.Environment { if entry.SecretRef==""{continue};switch entry.SecretRef{case "secret_n8n_encryption","secret_n8n_owner","secret_n8n_database":slots[entry.SecretRef]=true;default:return fmt.Errorf("%w: undeclared n8n secret slot",ErrInvalid)} }
	}
	if counts["web"]!=1||counts["postgres"]!=1||counts["redis"]!=1||counts["worker"]<1||counts["webhook"]<1||len(slots)!=3{return ErrInvalid}
	// Validate all edges and reject cycles without interpreting executable input.
	resolved:=map[string]bool{};for len(resolved)<len(names){progress:=false;for _,workload:=range recipe.Workloads{if resolved[workload.Name]{continue};ready:=true;for _,dependency:=range workload.DependsOn{if !names[dependency]{return ErrInvalid};if !resolved[dependency]{ready=false}};if ready{resolved[workload.Name]=true;progress=true}};if !progress{return fmt.Errorf("%w: n8n dependency cycle",ErrInvalid)}}
	return nil
}

func validateN8NRecipe(recipe containers.ApplicationRecipe, installation N8NInstallation) error {
	if err:=ValidateN8NApplicationRecipe(recipe);err!=nil{return err}
	definition := installation.Definition
	if recipe.Name != "n8n" || recipe.Digest != definition.RecipeDigest || recipe.Signature != definition.RecipeSignature || recipe.SigningKeyID != definition.SigningKeyID || recipe.Digest != definition.DefinitionDigest { return fmt.Errorf("%w: n8n definition does not match the signed recipe", ErrIntegrity) }
	compatible:=false;for _,architecture:=range definition.Architectures{if architecture==runtime.GOARCH||architecture=="linux/"+runtime.GOARCH{compatible=true}};if !compatible{return fmt.Errorf("%w: n8n definition excludes node architecture",ErrUnsupported)}
	if len(recipe.Volumes) < 2 || len(recipe.Networks) == 0 || len(recipe.Workloads) > 64 { return fmt.Errorf("%w: n8n requires persistent data and private database networking", ErrInvalid) }
	counts := map[string]uint16{}
	secrets := map[string]bool{}
	for _, network := range recipe.Networks { if !network.Internal { return ErrIntegrity } }
	for _, workload := range recipe.Workloads {
		if err := workload.Spec.Validate(containers.TierTenantRootless); err != nil { return err }
		if workload.Spec.Image.Platform != "linux/"+runtime.GOARCH { return fmt.Errorf("%w: signed workload architecture differs from node", ErrUnsupported) }
		role := n8nRole(workload.Name); counts[role]++
		if role == "" { return fmt.Errorf("%w: unknown n8n recipe role", ErrInvalid) }
		if len(workload.Spec.Networks) == 0 { return fmt.Errorf("%w: n8n workloads must use private recipe networks", ErrInvalid) }
		if role == "web" || role == "worker" || role == "webhook" {
			if workload.Spec.Image.Digest != "sha256:"+definition.ResolvedImageDigest || workload.Spec.Image.Registry != definition.Image.Registry || workload.Spec.Image.Repository != definition.Image.Repository { return fmt.Errorf("%w: n8n workload image differs from signed definition", ErrIntegrity) }
			if workload.Spec.Limits.MemoryMaxBytes < definition.MinimumMemory || workload.Spec.Limits.CPUQuotaMicros < uint64(definition.MinimumCPU) { return ErrInvalid }
		}
		if role == "web" {
			if workload.Spec.Health.Kind != "http" || workload.Spec.Health.Path != "/healthz" || workload.RoutePortName == "" { return fmt.Errorf("%w: n8n web health/route contract missing", ErrInvalid) }
			found := false; for _, port := range workload.Spec.Ports { if port.Name == workload.RoutePortName && port.ContainerPort == 5678 && port.Protocol == containers.ProtocolTCP { found = true } }; if !found { return ErrInvalid }
		}
		for _, environment := range workload.Spec.Environment {
			if environment.SecretRef != "" {
				if _, allowed := n8nSecretBindings(installation)[environment.SecretRef]; !allowed { return fmt.Errorf("%w: n8n recipe uses an undeclared secret slot", ErrInvalid) }
				secrets[environment.SecretRef] = true
			}
		}
	}
	if counts["web"] != installation.WebReplicas || counts["worker"] != installation.WorkerReplicas || counts["webhook"] != installation.WebhookReplicas || counts["postgres"] != 1 || counts["redis"] != 1 || len(secrets) != 3 { return fmt.Errorf("%w: n8n replica/database/secret bindings differ from signed graph", ErrInvalid) }
	// The current exposure broker binds one web workload, not a load-balancer.
	if counts["web"] != 1 { return fmt.Errorf("%w: local n8n route supports one signed web replica", ErrUnsupported) }
	return nil
}

func n8nRole(name string) string {
	for _, role := range []string{"postgres","redis","webhook","worker","web"} { if name == role || strings.HasPrefix(name,role+"_") { return role } }
	return ""
}

type localN8NFederation struct { service *N8NRuntime; meta containers.CommandMeta; installation N8NInstallation; recipe containers.ApplicationRecipe }

func (federation *localN8NFederation) metaFor(operation string, id containers.ID, generation uint64) containers.CommandMeta {
	meta := federation.meta
	meta.CommandID = "n8n-"+n8nDigest(struct{Parent,Operation,Resource string;Generation uint64}{meta.CommandID,operation,id.String(),generation})[:48]
	meta.Grant.Operation, meta.Grant.ResourceID = operation, id
	meta.Grant.Digest = n8nDigest(struct{ Parent, Operation, Resource string }{meta.CommandID,operation,id.String()})
	meta.ExpectedGeneration, meta.Fence = generation, containers.FenceToken(generation+1)
	return meta
}

func (federation *localN8NFederation) ApplyN8NIntent(ctx context.Context, intent N8NWorkloadIntent) (N8NReceipt, error) {
	if err := intent.Validate(); err != nil { return N8NReceipt{}, err }
	installation := federation.installation
	if intent.InstallationID != installation.ID || intent.ImageDigest != installation.Definition.ResolvedImageDigest { return N8NReceipt{}, ErrIntegrity }
	id, err := containers.NewID(string(installation.ID)); if err != nil { return N8NReceipt{}, err }
	tenant := federation.meta.Grant.TenantID
	var application containers.ContainerApplication
	switch intent.Action {
	case "install":
		siteID, e := containers.NewID(installation.SiteID); if e != nil { return N8NReceipt{}, e }
		application, _, err = federation.service.Applications.Deploy(ctx, containers.DeployApplicationCommand{Meta:federation.metaFor("application.deploy",id,0), ApplicationID:id, SiteID:siteID, RecipeID:federation.recipe.ID, RecipeVersion:federation.recipe.Version, SecretBindings:n8nSecretBindings(installation)})
	case "update":
		current, e := federation.service.Repository.Application(ctx,tenant,id); if e != nil { return N8NReceipt{}, e }
		application, _, err = federation.service.Applications.Update(ctx, containers.UpdateApplicationCommand{Meta:federation.metaFor("application.deploy",id,current.ActiveGeneration), ApplicationID:id, RecipeID:federation.recipe.ID, RecipeVersion:federation.recipe.Version, SecretBindings:n8nSecretBindings(installation)})
	case "suspend", "resume", "remove":
		application, err = federation.service.Repository.Application(ctx,tenant,id)
		if err != nil { return N8NReceipt{}, err }
		if intent.Action != "resume" { if err = federation.withdraw(ctx,id); err != nil { return N8NReceipt{}, err } }
		ids := append([]containers.ID(nil),application.WorkloadIDs...)
		if intent.Action != "resume" { for left,right:=0,len(ids)-1; left<right; left,right=left+1,right-1 { ids[left],ids[right]=ids[right],ids[left] } }
		for _, workloadID := range ids {
			workload, e := federation.service.Repository.Workload(ctx,tenant,workloadID); if e != nil { return N8NReceipt{}, e }
			lifecycle := containers.LifecycleStopped; if intent.Action == "resume" { lifecycle = containers.LifecycleRunning }; if intent.Action == "remove" { lifecycle = containers.LifecycleDeleting }
			if workload.ObservedLifecycle == containers.LifecycleDeleted && intent.Action == "remove" { continue }
			_, _, e = federation.service.Containers.SetLifecycle(ctx,containers.LifecycleCommand{Meta:federation.metaFor("workload.lifecycle",workloadID,workload.Generation), WorkloadID:workloadID, Lifecycle:lifecycle})
			if e != nil { return N8NReceipt{}, e }
		}
	default: return N8NReceipt{}, ErrUnsupported
	}
	if err != nil { return N8NReceipt{}, err }
	if intent.Action == "install" || intent.Action == "resume" || intent.Action == "update" { if err = federation.expose(ctx,application); err != nil { return N8NReceipt{}, err } }
	receipt, err := federation.ObserveN8N(ctx, installation.ID)
	if err != nil { return N8NReceipt{}, err }
	receipt.Action = intent.Action
	if intent.Action == "suspend" && receipt.State != "suspended" || intent.Action == "remove" && receipt.State != "removed" { return N8NReceipt{}, fmt.Errorf("%w: n8n lifecycle observation does not confirm request",ErrIntegrity) }
	return receipt, nil
}

func (federation *localN8NFederation) exposureID(ctx context.Context, id containers.ID) (containers.ID,error) { return federation.service.Allocator.For(ctx,id,"exposure","n8n") }
func (federation *localN8NFederation) withdraw(ctx context.Context, id containers.ID) error {
	exposureID, err := federation.exposureID(ctx,id); if err != nil { return err }
	exposure, err := federation.service.Repository.Exposure(ctx,federation.meta.Grant.TenantID,exposureID)
	if errors.Is(err,containers.ErrNotFound) { return nil }; if err != nil { return err }; if exposure.State == "deleted" { return nil }
	_, _, err = federation.service.Containers.DeleteExposure(ctx,containers.DeleteExposureCommand{Meta:federation.metaFor("exposure.delete",exposureID,exposure.Generation), ExposureID:exposureID})
	return err
}
func (federation *localN8NFederation) expose(ctx context.Context, application containers.ContainerApplication) error {
	id, err := federation.exposureID(ctx,application.ID); if err != nil { return err }
	generation := uint64(0)
	if current,e:=federation.service.Repository.Exposure(ctx,application.TenantID,id);e==nil { if current.State=="active" { return nil }; generation=current.Generation } else if !errors.Is(e,containers.ErrNotFound) { return e }
	for _,workload:=range federation.recipe.Workloads {
		if n8nRole(workload.Name)!="web" { continue }
		workloadID,e:=federation.service.Allocator.For(ctx,application.ID,"workload",workload.Name);if e!=nil{return e}
		_,_,e=federation.service.Containers.ApplyExposure(ctx,containers.ApplyExposureCommand{Meta:federation.metaFor("exposure.apply",id,generation),Exposure:containers.Exposure{ID:id,WorkloadID:workloadID,PortName:workload.RoutePortName,Public:true,ListenerRef:federation.installation.PrivateServiceBinding,DomainBindingRef:federation.installation.PublicRouteBinding}})
		return e
	}
	return fmt.Errorf("%w: n8n web route missing",ErrInvalid)
}

func (federation *localN8NFederation) ObserveN8N(ctx context.Context, id ID) (N8NReceipt,error) {
	if id != federation.installation.ID { return N8NReceipt{}, ErrNotFound }
	applicationID,e:=containers.NewID(string(id));if e!=nil{return N8NReceipt{},e}
	application,err:=federation.service.Repository.Application(ctx,federation.meta.Grant.TenantID,applicationID);if err!=nil{return N8NReceipt{},err}
	if len(application.WorkloadIDs)==0{return N8NReceipt{},fmt.Errorf("%w: no admitted n8n workloads",ErrIntegrity)}
	observations:=[]containers.Workload{};state:="active";observedAt:=time.Time{};stopped,deleted:=0,0;imageDigest:=""
	for _,workloadID:=range application.WorkloadIDs {
		stored,e:=federation.service.Repository.Workload(ctx,application.TenantID,workloadID);if e!=nil{return N8NReceipt{},e}
		var observed containers.Workload
		if stored.ObservedLifecycle==containers.LifecycleDeleted { observed=stored } else {
			observed,e=federation.service.Containers.Reconcile(ctx,application.TenantID,workloadID,federation.metaFor("workload.reconcile",workloadID,stored.Generation).Grant);if e!=nil{return N8NReceipt{},e}
		}
		if observed.UpdatedAt.After(observedAt){observedAt=observed.UpdatedAt}
		if observed.ObservedLifecycle==containers.LifecycleStopped{stopped++};if observed.ObservedLifecycle==containers.LifecycleDeleted{deleted++}
		if n8nRole(observed.Name)=="web"{imageDigest=strings.TrimPrefix(observed.Spec.Image.Digest,"sha256:")}
		if observed.ObservedHealth==containers.HealthUnhealthy { state="degraded" } else if (observed.ObservedHealth!=containers.HealthHealthy||observed.ObservedLifecycle!=containers.LifecycleRunning) && state!="degraded" { state="starting" }
		observations=append(observations,observed)
	}
	if stopped==len(observations){state="suspended"};if deleted==len(observations){state="removed"}
	if imageDigest!=federation.installation.Definition.ResolvedImageDigest{state="degraded"}
	endpoint:=""
	if exposureID,e:=federation.exposureID(ctx,applicationID);e==nil{if exposure,e:=federation.service.Repository.Exposure(ctx,application.TenantID,exposureID);e==nil&&exposure.State=="active"{endpoint=fmt.Sprintf("127.0.0.1:%d",containers.LoopbackExposurePort(exposure.WorkloadID,exposure.PortName))}}
	// Digests summarize actual broker observations; they do not assert healthy.
	digest:=n8nDigest(observations)
	return N8NReceipt{InstallationID:id,Action:"observe",ObservedGeneration:federation.installation.Generation,ImageDigest:imageDigest,WorkloadDigest:n8nDigest(application),PrivateEndpoint:endpoint,HealthDigest:digest,Receipt:digest,CompletedAt:observedAt,State:state},nil
}

func n8nDigest(value any) string { payload,_:=json.Marshal(value);sum:=sha256.Sum256(payload);return hex.EncodeToString(sum[:]) }
var _ N8NContainerFederation = (*localN8NFederation)(nil)
