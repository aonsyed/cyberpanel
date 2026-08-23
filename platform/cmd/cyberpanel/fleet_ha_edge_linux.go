//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/webactivation"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	webcatalog "github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/enterprise"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
)

type fleetHAEdge struct {
	repository *ha.SQLRepository
	groups     ha.GroupService
	verifier   ha.EnrollmentVerifier
	failover   ha.FailoverCoordinator
	providers  *localMariaDBHAProviders
	approvals  *haPromotionApprovalAuthority
	now        func() time.Time
}

func newFleetHAEdge(repository *ha.SQLRepository, providers *localMariaDBHAProviders, approvals *haPromotionApprovalAuthority, now func() time.Time) (*fleetHAEdge, error) {
	if repository == nil || repository.DB == nil {
		return nil, errors.New("fleet edge requires high-availability authority")
	}
	if now == nil {
		now = time.Now
	}
	edge := &fleetHAEdge{repository:repository, providers:providers, approvals:approvals, now:now}
	edge.groups = ha.GroupService{Store:*repository, Now:now}
	edge.verifier = ha.EnrollmentVerifier{Now:now}
	edge.failover = ha.FailoverCoordinator{Store:*repository, Now:now}
	return edge, nil
}

type localMariaDBHAProviders struct {
	leases         ha.LeaseAuthority
	gate           ha.WriterGate
	promotion      ha.PromotionExecutor
	traffic        ha.TrafficProvider
	fences         map[ha.FenceClass]ha.FenceProvider
	manualFence    ha.ManualFenceConfirmer
}

func newLocalMariaDBHAProviders(ctx context.Context, repository *ha.SQLRepository, database ha.DatabaseReplicationExecutor, signer ha.WritePermitSigner, catalog *webcatalog.SQLCatalog, activator *webactivation.Client, listeners []composer.ListenerInput, approvalVerifier ha.AdministrativeApprovalVerifier, sender ha.FederatedHAIntentSender, now func() time.Time) (*localMariaDBHAProviders, error) {
	if ctx == nil || repository == nil || repository.DB == nil || database == nil || signer == nil || catalog == nil || activator == nil { return nil, ha.ErrInvalid }
	leaseAuthority, err := ha.NewLocalSQLLeaseAuthority(ctx, repository, now)
	if err != nil { return nil, err }
	localGate, err := ha.NewLocalMariaDBWriterGate(*repository, database, signer, now)
	if err != nil { return nil, err }
	localPromotion, err := ha.NewLocalMariaDBPromotionExecutor(*repository, database, now)
	if err != nil { return nil, err }
	localTraffic, err := newLocalOLSListenerTrafficProvider(ctx, repository.DB, catalog, activator, listeners, now)
	if err != nil { return nil, err }
	dispatcher := &ha.FederatedHADispatcher{Sender:sender, Now:now}
	gate, err := ha.NewOwningNodeWriterGate(ha.NodeID(localFederationNodeID), localGate, dispatcher)
	if err != nil { return nil, err }
	promotion, err := ha.NewOwningNodePromotionExecutor(ha.NodeID(localFederationNodeID), localPromotion, dispatcher)
	if err != nil { return nil, err }
	traffic, err := ha.NewOwningNodeTrafficProvider(ha.NodeID(localFederationNodeID), localTraffic, dispatcher)
	if err != nil { return nil, err }
	fences := map[ha.FenceClass]ha.FenceProvider{}
	if provider, initializeErr := ha.NewLocalMariaDBFenceProvider(*repository, database, leaseAuthority, ha.NodeID(localFederationNodeID), now); initializeErr == nil {
		fences[provider.Class()] = provider
	}
	if provider, initializeErr := ha.NewMandatoryLeaseFenceProvider(*repository, leaseAuthority, ha.NodeID(localFederationNodeID), now); initializeErr == nil {
		fences[provider.Class()] = provider
	}
	var manualFence ha.ManualFenceConfirmer
	if approvalVerifier != nil {
		if confirmer, initializeErr := ha.NewAdministrativeFenceConfirmer(approvalVerifier, now); initializeErr == nil {
			manualFence = confirmer
		}
	}
	return &localMariaDBHAProviders{leases:leaseAuthority,gate:gate,promotion:promotion,traffic:traffic,fences:fences,manualFence:manualFence},nil
}

func (providers *localMariaDBHAProviders) coordinator(store ha.Store, group ha.NodeGroup, promotion ha.Promotion, policy ha.TrafficPolicy, now func() time.Time) (ha.FailoverCoordinator, error) {
	if providers == nil || providers.leases == nil || providers.gate == nil || providers.promotion == nil || providers.traffic == nil || promotion.ResourceID != ha.LocalMariaDBResourceID || policy.Resource != promotion.ResourceID || policy.Kind != ha.LocalOLSListenerTrafficKind || policy.ProviderBindingID != ha.LocalOLSListenerProviderBinding || policy.ProviderMode != ha.TrafficAtomicCAS {
		return ha.FailoverCoordinator{}, ha.ErrUnsupported
	}
	for _, class := range group.RequiredFenceClasses {
		if class == ha.FenceAdministrative {
			if providers.manualFence == nil { return ha.FailoverCoordinator{}, fmt.Errorf("%w: administrative fence confirmer", ha.ErrUnsupported) }
			continue
		}
		provider := providers.fences[class]
		if provider == nil || provider.Class() != class { return ha.FailoverCoordinator{}, fmt.Errorf("%w: %s fence provider", ha.ErrUnsupported, class) }
	}
	return ha.FailoverCoordinator{Store:store,Leases:providers.leases,Gate:providers.gate,FenceProviders:providers.fences,ManualFence:providers.manualFence,Traffic:providers.traffic,Executor:providers.promotion,Now:now},nil
}

type localOLSListenerTrafficProvider struct {
	db        *sql.DB
	catalog   *webcatalog.SQLCatalog
	activator *webactivation.Client
	renderers map[webengine.Edition]native.Renderer
	public    []composer.ListenerInput
	now       func() time.Time
	mu        sync.Mutex
}

const localOLSListenerTrafficSchema=`
CREATE TABLE IF NOT EXISTS ha_local_listener_traffic_v1(
 policy_id TEXT PRIMARY KEY,
 resource_id TEXT NOT NULL,
 effect_id TEXT NOT NULL UNIQUE,
 config_revision INTEGER NOT NULL,
 endpoints_json BLOB NOT NULL,
 endpoint_digest TEXT NOT NULL,
 provider_receipt BLOB NOT NULL,
 applied_at TIMESTAMP NOT NULL
);`

type localOLSListenerReceipt struct {
	EffectID        string `json:"effect_id"`
	ChangeToken     string `json:"change_token"`
	ActivationDigest string `json:"activation_digest"`
	BeforeDigest    string `json:"before_digest"`
	OutputDigest    string `json:"output_digest"`
	Revision        string `json:"revision"`
	Confirmed       bool   `json:"confirmed"`
}

func newLocalOLSListenerTrafficProvider(ctx context.Context,db *sql.DB,catalog *webcatalog.SQLCatalog, activator *webactivation.Client, listeners []composer.ListenerInput, now func() time.Time) (*localOLSListenerTrafficProvider, error) {
	if ctx==nil||db==nil||catalog == nil || activator == nil { return nil, ha.ErrInvalid }
	public := make([]composer.ListenerInput,0,2)
	for _, listener := range listeners {
		if listener.Ref != webengine.ResourceRef("listener/http") && listener.Ref != webengine.ResourceRef("listener/https") { continue }
		copy := listener
		copy.Addresses=append([]string(nil),listener.Addresses...)
		copy.Protocols=append([]webengine.Protocol(nil),listener.Protocols...)
		public=append(public,copy)
	}
	sort.Slice(public,func(left,right int)bool{return public[left].Ref<public[right].Ref})
	if len(public)!=2 || public[0].Ref!=webengine.ResourceRef("listener/http") || public[0].Port!=80 || public[1].Ref!=webengine.ResourceRef("listener/https") || public[1].Port!=443 { return nil,ha.ErrUnsupported }
	if _,err:=db.ExecContext(ctx,localOLSListenerTrafficSchema);err!=nil{return nil,err}
	if now==nil{now=time.Now}
	return &localOLSListenerTrafficProvider{db:db,catalog:catalog,activator:activator,renderers:map[webengine.Edition]native.Renderer{webengine.EditionOpenLiteSpeed:ols.New(),webengine.EditionLiteSpeedEnterprise:enterprise.New()},public:public,now:now},nil
}

func (provider *localOLSListenerTrafficProvider) Observe(ctx context.Context, policy ha.TrafficPolicy) (ha.TrafficObservation, error) {
	if provider==nil||provider.db==nil||provider.catalog==nil||ctx==nil||!provider.supports(policy){return ha.TrafficObservation{},ha.ErrUnsupported}
	state,err:=provider.catalog.NodeState(ctx);if err!=nil{return ha.TrafficObservation{},err}
	active,err:=provider.publicListenerState(state.Configuration.Engine.Listeners);if err!=nil{return ha.TrafficObservation{},err}
	endpoints:=append([]ha.TrafficEndpoint(nil),policy.Endpoints...)
	var storedRaw []byte
	var storedResource,storedDigest string
	if loadErr:=provider.db.QueryRowContext(ctx,`SELECT resource_id,endpoints_json,endpoint_digest FROM ha_local_listener_traffic_v1 WHERE policy_id=?`,policy.ID).Scan(&storedResource,&storedRaw,&storedDigest);loadErr==nil{
		if storedResource!=policy.Resource||json.Unmarshal(storedRaw,&endpoints)!=nil||trafficEndpointDigest(endpoints)!=storedDigest{return ha.TrafficObservation{},ha.ErrProviderAmbiguous}
	}else if !errors.Is(loadErr,sql.ErrNoRows){return ha.TrafficObservation{},loadErr}
	localPorts:=map[uint16]bool{}
	for index:=range endpoints{if endpoints[index].NodeID!=ha.NodeID("local"){continue};if localPorts[endpoints[index].Port]{return ha.TrafficObservation{},ha.ErrProviderAmbiguous};localPorts[endpoints[index].Port]=true;expectedActive:=endpoints[index].Weight==100;if storedRaw!=nil&&expectedActive!=active{return ha.TrafficObservation{},ha.ErrProviderAmbiguous};if storedRaw==nil&&active{endpoints[index].Weight=100;endpoints[index].Healthy=true}else if storedRaw==nil{endpoints[index].Weight=0;endpoints[index].Healthy=false}}
	if !localPorts[80]||!localPorts[443]||len(localPorts)!=2{return ha.TrafficObservation{},ha.ErrUnsupported}
	digest:=trafficEndpointDigest(endpoints)
	return ha.TrafficObservation{PolicyID:policy.ID,Revision:strconv.FormatUint(state.Configuration.Revision,10),Digest:digest,Endpoints:endpoints,ObservedAt:provider.now().UTC()},nil
}

func (provider *localOLSListenerTrafficProvider) ApplyConditional(ctx context.Context, change ha.TrafficChange) (ha.TrafficReceipt, error) {
	if provider==nil||ctx==nil||!provider.supports(change.Policy)||change.EffectID==""||change.Before.PolicyID!=change.Policy.ID||change.Desired.PolicyID!=change.Policy.ID||trafficEndpointDigest(change.Desired.Endpoints)!=change.Desired.Digest{return ha.TrafficReceipt{},ha.ErrInvalid}
	provider.mu.Lock();defer provider.mu.Unlock()
	if replayed,found,replayErr:=provider.replayTrafficReceipt(ctx,change);replayErr!=nil||found{return replayed,replayErr}
	before,err:=provider.Observe(ctx,change.Policy);if err!=nil{return ha.TrafficReceipt{},err}
	if before.Revision!=change.Before.Revision||before.Digest!=change.Before.Digest||change.Policy.ExpectedRevision!=""&&change.Policy.ExpectedRevision!=before.Revision{return ha.TrafficReceipt{},ha.ErrProviderAmbiguous}
	activate,err:=desiredLocalListenerState(change.Desired.Endpoints);if err!=nil{return ha.TrafficReceipt{},err}
	state,err:=provider.catalog.NodeState(ctx);if err!=nil{return ha.TrafficReceipt{},err}
	target:=cloneNodeConfiguration(state.Configuration)
	target.Revision++
	target.Engine.Tuning.Generation++
	target.Engine.Listeners=provider.targetListeners(target.Engine.Listeners,activate)
	prepared,lookupErr:=provider.catalog.NodeConfigurationChange(ctx,change.EffectID)
	if lookupErr==nil{
		if !sameNodeConfiguration(prepared.Configuration,target){return ha.TrafficReceipt{},ha.ErrConflict}
	}else if !errors.Is(lookupErr,webcatalog.ErrChangeMissing){return ha.TrafficReceipt{},lookupErr}else{
		prepared,err=provider.catalog.PrepareNodeConfiguration(ctx,change.EffectID,target,state.Configuration.Revision);if err!=nil{return ha.TrafficReceipt{},err}
	}
	activationDigest:=prepared.ActivationDigest
	if !prepared.Finalized{
		composed,composeErr:=composer.Compose(prepared.Plan);if composeErr!=nil{_=provider.catalog.RejectNodeConfiguration(ctx,prepared);return ha.TrafficReceipt{},composeErr}
		renderer:=provider.renderers[composed.Desired.Engine.Edition];if renderer==nil{_=provider.catalog.RejectNodeConfiguration(ctx,prepared);return ha.TrafficReceipt{},ha.ErrUnsupported}
		renderRequest:=native.RenderRequest{Desired:composed.Desired,Snapshot:composed.Snapshot}
		generation,renderErr:=renderer.Render(ctx,renderRequest);if renderErr!=nil{_=provider.catalog.RejectNodeConfiguration(ctx,prepared);return ha.TrafficReceipt{},renderErr}
		activated,activationErr:=provider.activator.ApplyVerified(ctx,renderRequest,generation.ContentDigest)
		if activated.Status==activation.RolledBack{_=provider.catalog.RejectNodeConfiguration(ctx,prepared);return ha.TrafficReceipt{},errors.Join(ha.ErrProviderAmbiguous,activationErr)}
		if activationErr!=nil||activated.Status!=activation.Applied||!activated.Confirmed||activated.Digest!=generation.ContentDigest{return ha.TrafficReceipt{},errors.Join(ha.ErrProviderAmbiguous,activationErr)}
		if err=provider.catalog.FinalizeNodeConfiguration(ctx,prepared,activated.Digest);err!=nil{return ha.TrafficReceipt{},errors.Join(ha.ErrProviderAmbiguous,err)}
		activationDigest=activated.Digest
	}
	providerEvidence,evidenceErr:=json.Marshal(localOLSListenerReceipt{EffectID:change.EffectID,ChangeToken:prepared.Token,ActivationDigest:activationDigest,BeforeDigest:before.Digest,OutputDigest:change.Desired.Digest,Revision:strconv.FormatUint(prepared.Configuration.Revision,10),Confirmed:true});if evidenceErr!=nil{return ha.TrafficReceipt{},evidenceErr}
	endpointRaw,evidenceErr:=json.Marshal(change.Desired.Endpoints);if evidenceErr!=nil{return ha.TrafficReceipt{},evidenceErr}
	appliedAt:=provider.now().UTC()
	result,storeErr:=provider.db.ExecContext(ctx,`INSERT INTO ha_local_listener_traffic_v1(policy_id,resource_id,effect_id,config_revision,endpoints_json,endpoint_digest,provider_receipt,applied_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(policy_id) DO UPDATE SET effect_id=excluded.effect_id,config_revision=excluded.config_revision,endpoints_json=excluded.endpoints_json,endpoint_digest=excluded.endpoint_digest,provider_receipt=excluded.provider_receipt,applied_at=excluded.applied_at WHERE ha_local_listener_traffic_v1.endpoint_digest=? OR ha_local_listener_traffic_v1.effect_id=excluded.effect_id`,change.Policy.ID,change.Policy.Resource,change.EffectID,prepared.Configuration.Revision,endpointRaw,change.Desired.Digest,providerEvidence,appliedAt,change.Before.Digest)
	if storeErr!=nil{return ha.TrafficReceipt{},errors.Join(ha.ErrProviderAmbiguous,storeErr)};if changed,countErr:=result.RowsAffected();countErr!=nil||changed!=1{return ha.TrafficReceipt{},errors.Join(ha.ErrProviderAmbiguous,countErr)}
	after,err:=provider.Observe(ctx,change.Policy);if err!=nil{return ha.TrafficReceipt{},err}
	if after.Digest!=change.Desired.Digest{return ha.TrafficReceipt{},ha.ErrProviderAmbiguous}
	return ha.TrafficReceipt{PolicyID:change.Policy.ID,EffectID:change.EffectID,BeforeDigest:before.Digest,OutputDigest:after.Digest,Revision:after.Revision,ProviderReceipt:string(providerEvidence),AppliedAt:appliedAt},nil
}

func (provider *localOLSListenerTrafficProvider) replayTrafficReceipt(ctx context.Context,change ha.TrafficChange)(ha.TrafficReceipt,bool,error){
	var policyID ha.TrafficPolicyID;var resource string;var endpointRaw,providerEvidence []byte;var endpointDigest string;var revision uint64;var appliedAt time.Time
	err:=provider.db.QueryRowContext(ctx,`SELECT policy_id,resource_id,config_revision,endpoints_json,endpoint_digest,provider_receipt,applied_at FROM ha_local_listener_traffic_v1 WHERE effect_id=?`,change.EffectID).Scan(&policyID,&resource,&revision,&endpointRaw,&endpointDigest,&providerEvidence,&appliedAt)
	if errors.Is(err,sql.ErrNoRows){return ha.TrafficReceipt{},false,nil};if err!=nil{return ha.TrafficReceipt{},false,err}
	var endpoints []ha.TrafficEndpoint;var evidence localOLSListenerReceipt
	if json.Unmarshal(endpointRaw,&endpoints)!=nil||json.Unmarshal(providerEvidence,&evidence)!=nil{return ha.TrafficReceipt{},true,ha.ErrConflict}
	activationProof,digestErr:=hex.DecodeString(evidence.ActivationDigest)
	if policyID!=change.Policy.ID||resource!=change.Policy.Resource||endpointDigest!=change.Desired.Digest||trafficEndpointDigest(endpoints)!=endpointDigest||evidence.EffectID!=change.EffectID||evidence.ChangeToken==""||evidence.BeforeDigest!=change.Before.Digest||evidence.OutputDigest!=change.Desired.Digest||evidence.Revision!=strconv.FormatUint(revision,10)||revision==0||appliedAt.IsZero()||digestErr!=nil||len(activationProof)!=sha256.Size||strings.ToLower(evidence.ActivationDigest)!=evidence.ActivationDigest||!evidence.Confirmed{return ha.TrafficReceipt{},true,ha.ErrConflict}
	observed,err:=provider.Observe(ctx,change.Policy);if err!=nil||observed.Digest!=endpointDigest{return ha.TrafficReceipt{},true,errors.Join(err,ha.ErrProviderAmbiguous)}
	return ha.TrafficReceipt{PolicyID:policyID,EffectID:change.EffectID,BeforeDigest:evidence.BeforeDigest,OutputDigest:evidence.OutputDigest,Revision:evidence.Revision,ProviderReceipt:string(providerEvidence),AppliedAt:appliedAt},true,nil
}

func (*localOLSListenerTrafficProvider) ApplyObserve(context.Context,ha.TrafficChange)(ha.TrafficReceipt,error){return ha.TrafficReceipt{},ha.ErrUnsupported}

func (provider *localOLSListenerTrafficProvider) CompensateConditional(ctx context.Context,change ha.TrafficChange,receipt ha.TrafficReceipt)(ha.TrafficReceipt,error){
	if provider==nil||receipt.PolicyID!=change.Policy.ID||receipt.EffectID!=change.EffectID||receipt.OutputDigest!=change.Desired.Digest||receipt.ProviderReceipt==""{return ha.TrafficReceipt{},ha.ErrInvalid}
	current,err:=provider.Observe(ctx,change.Policy);if err!=nil{return ha.TrafficReceipt{},err};if current.Digest!=receipt.OutputDigest{return ha.TrafficReceipt{},ha.ErrProviderAmbiguous}
	sum:=sha256.Sum256([]byte("cyberpanel-local-listener-compensation-v1\x00"+change.EffectID));policy:=change.Policy;policy.ExpectedRevision=current.Revision
	desired:=change.Before;desired.Revision="";desired.ObservedAt=provider.now().UTC()
	compensation:=ha.TrafficChange{Policy:policy,EffectID:"traffic_compensate_"+hex.EncodeToString(sum[:24]),Before:current,Desired:desired}
	return provider.ApplyConditional(ctx,compensation)
}

func (provider *localOLSListenerTrafficProvider) supports(policy ha.TrafficPolicy)bool{
	if policy.ID==""||policy.GroupID==""||policy.Kind!=ha.LocalOLSListenerTrafficKind||policy.ProviderBindingID!=ha.LocalOLSListenerProviderBinding||policy.ProviderMode!=ha.TrafficAtomicCAS||policy.Resource!=ha.LocalMariaDBResourceID||policy.Generation==0||len(policy.Endpoints)<4{return false}
	return true
}

func (provider *localOLSListenerTrafficProvider) publicListenerState(listeners []composer.ListenerInput)(bool,error){
	found:=map[webengine.ResourceRef]composer.ListenerInput{};for _,listener:=range listeners{if listener.Ref==webengine.ResourceRef("listener/http")||listener.Ref==webengine.ResourceRef("listener/https"){if _,duplicate:=found[listener.Ref];duplicate{return false,ha.ErrProviderAmbiguous};found[listener.Ref]=listener}}
	if len(found)==0{return false,nil};if len(found)!=len(provider.public){return false,ha.ErrProviderAmbiguous};for _,expected:=range provider.public{if !sameListener(found[expected.Ref],expected){return false,ha.ErrProviderAmbiguous}};return true,nil
}

func (provider *localOLSListenerTrafficProvider) targetListeners(current []composer.ListenerInput,active bool)[]composer.ListenerInput{
	result:=make([]composer.ListenerInput,0,len(current)+len(provider.public));for _,listener:=range current{if listener.Ref==webengine.ResourceRef("listener/http")||listener.Ref==webengine.ResourceRef("listener/https"){continue};result=append(result,cloneListener(listener))};if active{for _,listener:=range provider.public{result=append(result,cloneListener(listener))}};sort.Slice(result,func(left,right int)bool{return result[left].Ref<result[right].Ref});return result
}

func desiredLocalListenerState(endpoints []ha.TrafficEndpoint)(bool,error){ports:=map[uint16]uint16{};for _,endpoint:=range endpoints{if endpoint.NodeID==ha.NodeID("local"){if endpoint.Port!=80&&endpoint.Port!=443{return false,ha.ErrUnsupported};if _,duplicate:=ports[endpoint.Port];duplicate{return false,ha.ErrConflict};ports[endpoint.Port]=endpoint.Weight;if endpoint.Weight!=0&&endpoint.Weight!=100||endpoint.Weight==100&&!endpoint.Healthy{return false,ha.ErrInvalid}}};if len(ports)!=2{return false,ha.ErrUnsupported};if ports[80]!=ports[443]{return false,ha.ErrProviderAmbiguous};return ports[80]==100,nil}
func trafficEndpointDigest(endpoints []ha.TrafficEndpoint)string{payload,_:=json.Marshal(endpoints);sum:=sha256.Sum256(payload);return hex.EncodeToString(sum[:])}
func cloneListener(value composer.ListenerInput)composer.ListenerInput{value.Addresses=append([]string(nil),value.Addresses...);value.Protocols=append([]webengine.Protocol(nil),value.Protocols...);return value}
func sameListener(left,right composer.ListenerInput)bool{if left.Ref!=right.Ref||left.Port!=right.Port||left.TLSMode!=right.TLSMode||len(left.Addresses)!=len(right.Addresses)||len(left.Protocols)!=len(right.Protocols){return false};for index:=range left.Addresses{if left.Addresses[index]!=right.Addresses[index]{return false}};for index:=range left.Protocols{if left.Protocols[index]!=right.Protocols[index]{return false}};return true}
func cloneNodeConfiguration(value webcatalog.NodeConfiguration)webcatalog.NodeConfiguration{value.Engine.Listeners=append([]composer.ListenerInput(nil),value.Engine.Listeners...);for index:=range value.Engine.Listeners{value.Engine.Listeners[index]=cloneListener(value.Engine.Listeners[index])};if value.DefaultTLS!=nil{copy:=*value.DefaultTLS;value.DefaultTLS=&copy};return value}
func sameNodeConfiguration(left,right webcatalog.NodeConfiguration)bool{leftJSON,leftErr:=json.Marshal(left);rightJSON,rightErr:=json.Marshal(right);return leftErr==nil&&rightErr==nil&&string(leftJSON)==string(rightJSON)}

var _ ha.TrafficProvider=(*localOLSListenerTrafficProvider)(nil)

func (edge *fleetHAEdge) ListNodes(ctx context.Context, call apiserver.EdgeCall, page apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.FleetNodeProjection], error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "" {
		return apiserver.EdgePage[apiserver.FleetNodeProjection]{}, ha.ErrInvalid
	}
	values, next, total, err := edge.repository.ListAllNodes(ctx, page.Cursor, page.Limit)
	if err != nil {
		return apiserver.EdgePage[apiserver.FleetNodeProjection]{}, err
	}
	items := make([]apiserver.FleetNodeProjection, 0, len(values))
	for _, value := range values {
		items = append(items, fleetNodeProjection(value))
	}
	return apiserver.EdgePage[apiserver.FleetNodeProjection]{Items:items, NextCursor:next, Total:total}, nil
}

func (edge *fleetHAEdge) GetNode(ctx context.Context, call apiserver.EdgeCall) (apiserver.FleetNodeProjection, error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" {
		return apiserver.FleetNodeProjection{}, ha.ErrInvalid
	}
	node, err := edge.repository.LoadNode(ctx, ha.NodeID(call.ResourceID))
	if err != nil {
		return apiserver.FleetNodeProjection{}, err
	}
	return fleetNodeProjection(node), nil
}

func (edge *fleetHAEdge) TopologyStatus(ctx context.Context, call apiserver.EdgeCall) (apiserver.HATopologyStatusProjection, error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" {
		return apiserver.HATopologyStatusProjection{}, ha.ErrInvalid
	}
	selected, err := edge.repository.LoadNode(ctx, ha.NodeID(call.ResourceID))
	if err != nil {
		return apiserver.HATopologyStatusProjection{}, err
	}
	group, err := edge.repository.LoadNodeGroup(ctx, selected.GroupID)
	if err != nil {
		return apiserver.HATopologyStatusProjection{}, err
	}
	if err = group.Validate(); err != nil {
		return apiserver.HATopologyStatusProjection{}, err
	}
	nodes, err := edge.repository.ListNodes(ctx, group.ID)
	if err != nil {
		return apiserver.HATopologyStatusProjection{}, err
	}
	nodeProjections := make([]apiserver.FleetNodeProjection, 0, len(nodes))
	for _, node := range nodes {
		if err = node.Validate(); err != nil {
			return apiserver.HATopologyStatusProjection{}, err
		}
		nodeProjections = append(nodeProjections, fleetNodeProjection(node))
	}
	leases, err := edge.repository.ListActiveWriterLeases(ctx, group.ID)
	if err != nil {
		return apiserver.HATopologyStatusProjection{}, err
	}
	now := edge.now().UTC()
	authorities := make([]apiserver.HAWriterAuthorityProjection, 0, len(leases))
	for _, lease := range leases {
		paths := append([]string(nil), lease.EnforcedWritePaths...)
		sort.Strings(paths)
		authorities = append(authorities, apiserver.HAWriterAuthorityProjection{
			LeaseID:string(lease.ID), ResourceID:lease.ResourceID, HolderNodeID:string(lease.HolderNodeID), State:string(lease.State),
			EnforcedWritePaths:paths, Generation:lease.Generation, ExpiresAt:lease.ExpiresAt, Current:now.Before(lease.ExpiresAt),
		})
	}
	fenceClasses := make([]string, len(group.RequiredFenceClasses))
	for index, class := range group.RequiredFenceClasses {
		fenceClasses[index] = string(class)
	}
	sort.Strings(fenceClasses)
	return apiserver.HATopologyStatusProjection{
		ID:string(group.ID), SelectedNodeID:string(selected.ID), Name:group.Name, State:group.State, CoordinatorID:group.CoordinatorID,
		MinimumManagers:group.MinimumManagers, AutomaticFailoverConfigured:group.AutomaticFailover, RequiredFenceClasses:fenceClasses,
		Nodes:nodeProjections, WriterAuthorities:authorities, Generation:group.Generation, UpdatedAt:group.UpdatedAt,
	}, nil
}

func (edge *fleetHAEdge) NodeHealth(ctx context.Context, call apiserver.EdgeCall) (apiserver.HANodeHealthProjection, error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" {
		return apiserver.HANodeHealthProjection{}, ha.ErrInvalid
	}
	node, err := edge.repository.LoadNode(ctx, ha.NodeID(call.ResourceID))
	if err != nil {
		return apiserver.HANodeHealthProjection{}, err
	}
	observed, err := edge.repository.ListHealthObservations(ctx, node.ID)
	if err != nil {
		return apiserver.HANodeHealthProjection{}, err
	}
	now := edge.now().UTC()
	status := string(ha.HealthUnknown)
	firstFreshState, firstFreshBootID, firstFreshCapability := "", "", ""
	asymmetric := false
	var fresh, stale uint64
	observations := make([]apiserver.HAHealthObservationProjection, 0, len(observed))
	for _, observation := range observed {
		observer, loadErr := edge.repository.LoadNode(ctx, observation.ObserverNodeID)
		if loadErr != nil || observer.GroupID != node.GroupID {
			return apiserver.HANodeHealthProjection{}, ha.ErrInvalid
		}
		isFresh := now.Before(observation.ValidUntil)
		if isFresh {
			fresh++
			if firstFreshState == "" {
				firstFreshState = string(observation.State)
				firstFreshBootID = observation.BootID
				firstFreshCapability = observation.CapabilityDigest
			} else if firstFreshState != string(observation.State) || firstFreshBootID != observation.BootID || firstFreshCapability != observation.CapabilityDigest {
				asymmetric = true
			}
		} else {
			stale++
		}
		checks := make(map[string]bool, len(observation.Checks))
		for key, value := range observation.Checks {
			checks[key] = value
		}
		observations = append(observations, apiserver.HAHealthObservationProjection{
			ObserverNodeID:string(observation.ObserverNodeID), State:string(observation.State), Checks:checks, Latency:observation.Latency,
			BootID:observation.BootID, CapabilityDigest:observation.CapabilityDigest, ObservedAt:observation.ObservedAt,
			ValidUntil:observation.ValidUntil, Sequence:observation.Sequence, Fresh:isFresh,
		})
	}
	if asymmetric {
		status = "asymmetric"
	} else if firstFreshState != "" {
		status = firstFreshState
	}
	return apiserver.HANodeHealthProjection{
		ID:string(node.ID), NodeState:string(node.State), Status:status, Asymmetric:asymmetric,
		FreshObservations:fresh, StaleObservations:stale, Observations:observations, Generation:node.Generation,
	}, nil
}

func (edge *fleetHAEdge) EnrollNode(ctx context.Context, call apiserver.EdgeCall, payload apiserver.FleetEnrollPayload, token []byte) (apiserver.EdgeMutation[apiserver.FleetNodeProjection], error) {
	defer wipeFleetToken(token)
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "" || call.CommandID == "" || len(token) == 0 || strings.TrimSpace(payload.CentralFingerprint) == "" {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, ha.ErrInvalid
	}
	enrollment, err := edge.verifier.Verify(token, payload.CentralFingerprint)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, err
	}
	node, _, err := edge.repository.AdmitEnrollment(ctx, enrollment, call.CommandID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, err
	}
	projection := fleetNodeProjection(node)
	return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{OperationID:call.CommandID, State:string(node.State), Generation:node.Generation, Resource:projection}, nil
}

func (edge *fleetHAEdge) RevokeNode(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.FleetNodeProjection], error) {
	if edge == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" || call.ExpectedGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, ha.ErrInvalid
	}
	node, err := edge.groups.SetNodeState(ctx, ha.NodeID(call.ResourceID), call.ExpectedGeneration, ha.NodeRetired)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, err
	}
	projection := fleetNodeProjection(node)
	return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{OperationID:call.CommandID, State:string(node.State), Generation:node.Generation, Resource:projection}, nil
}

func (edge *fleetHAEdge) DrainNode(ctx context.Context, call apiserver.EdgeCall, payload apiserver.HANodeDrainPayload) (apiserver.EdgeMutation[apiserver.FleetNodeProjection], error) {
	if edge == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" || call.ExpectedGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, ha.ErrInvalid
	}
	node, err := edge.groups.BeginDrain(ctx, ha.NodeID(call.ResourceID), call.ExpectedGeneration, payload.Deadline, payload.Force)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, err
	}
	projection := fleetNodeProjection(node)
	return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{OperationID:call.CommandID, State:string(node.State), Generation:node.Generation, Resource:projection}, nil
}

func (edge *fleetHAEdge) PlanPromotion(ctx context.Context, call apiserver.EdgeCall, payload apiserver.HAPromotionPlanPayload) (apiserver.EdgeMutation[apiserver.HAPromotionProjection], error) {
	if edge == nil || edge.repository == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" || call.CommandID == "" || call.ExpectedGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrInvalid
	}
	resourceID := call.ResourceID
	expectedLeaseGeneration := call.ExpectedGeneration
	selectedWriter := ha.NodeID("")
	if payload.ProtectedResourceID != "" {
		resourceID = payload.ProtectedResourceID
		expectedLeaseGeneration = payload.WriterLeaseGeneration
		selectedWriter = ha.NodeID(call.ResourceID)
	}
	if existing, err := edge.repository.PromotionByCommand(ctx, ha.CommandID(call.CommandID)); err == nil {
		if existing.ResourceID != resourceID || selectedWriter != "" && existing.PreviousWriter != selectedWriter || existing.Candidate != ha.NodeID(payload.CandidateNodeID) || existing.MaximumDataLoss != payload.MaximumDataLoss || existing.ExpectedGeneration != expectedLeaseGeneration {
			return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrConflict
		}
		return promotionMutation(existing, promotionPlanDigest(existing)), nil
	} else if !errors.Is(err, ha.ErrNotFound) {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	now := edge.now().UTC()
	var writer ha.NodeMember
	if selectedWriter != "" {
		var err error
		writer, err = edge.repository.LoadNode(ctx, selectedWriter)
		if err != nil {
			return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
		}
		if writer.Generation != call.ExpectedGeneration {
			return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrStaleGeneration
		}
	}
	candidate, err := edge.repository.LoadNode(ctx, ha.NodeID(payload.CandidateNodeID))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if candidate.State != ha.NodeReady {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrUnsafePromotion
	}
	lease, err := edge.repository.ActiveWriterLeaseByResource(ctx, resourceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if lease.Generation != expectedLeaseGeneration || lease.GroupID != candidate.GroupID || selectedWriter != "" && (lease.HolderNodeID != selectedWriter || writer.GroupID != lease.GroupID) || lease.HolderNodeID == candidate.ID {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrStaleGeneration
	}
	if err = lease.Validate(now); err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	channel, err := edge.repository.ChannelForResourceTarget(ctx, candidate.GroupID, resourceID, lease.HolderNodeID, candidate.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	checkpoint, err := edge.repository.LatestCheckpoint(ctx, channel.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if err = checkpoint.Validate(); err != nil || checkpoint.SourceGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrCheckpointStale
	}
	traffic, err := edge.repository.TrafficPolicyByResource(ctx, candidate.GroupID, resourceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if !promotionTrafficCovers(traffic, lease.HolderNodeID, candidate.ID) {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrUnsafePromotion
	}
	potentialLoss := checkpoint.LagDuration > 0 || checkpoint.LagBytes > 0
	blocked := checkpoint.LagDuration > payload.MaximumDataLoss || payload.MaximumDataLoss == 0 && checkpoint.LagBytes > 0
	promotion := ha.Promotion{
		ID:ha.PromotionID(fleetEffectID("promotion", call.CommandID, resourceID)), CommandID:ha.CommandID(call.CommandID), GroupID:candidate.GroupID,
		ResourceID:resourceID, PreviousWriter:lease.HolderNodeID, Candidate:candidate.ID, ExpectedGeneration:expectedLeaseGeneration,
		CheckpointID:checkpoint.ID, CheckpointFrontier:checkpoint.WriteFrontier, MaximumDataLoss:payload.MaximumDataLoss, LeaseID:lease.ID,
		TrafficPolicyID:traffic.ID, Automatic:false, PotentialDataLoss:potentialLoss, State:ha.PromotionPlanned,
		WriteFrontier:checkpoint.WriteFrontier, Generation:1, CreatedAt:now, UpdatedAt:now,
	}
	if blocked {
		promotion.State = ha.PromotionFailed
		promotion.Failure = "latest verified checkpoint exceeds the requested maximum data loss"
	}
	if err = edge.repository.CreatePromotion(ctx, promotion); err != nil {
		existing, loadErr := edge.repository.PromotionByCommand(ctx, promotion.CommandID)
		if loadErr != nil || existing.ID != promotion.ID || existing.ResourceID != promotion.ResourceID || existing.PreviousWriter != promotion.PreviousWriter || existing.Candidate != promotion.Candidate || existing.ExpectedGeneration != promotion.ExpectedGeneration || existing.MaximumDataLoss != promotion.MaximumDataLoss {
			return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
		}
		promotion = existing
	}
	return promotionMutation(promotion, promotionPlanDigest(promotion)), nil
}

func (edge *fleetHAEdge) ApprovePromotion(ctx context.Context, call apiserver.EdgeCall, payload apiserver.HAPromotionApprovalPayload) (apiserver.EdgeMutation[apiserver.HAPromotionApprovalProjection], error) {
	if edge == nil || edge.repository == nil || edge.approvals == nil || ctx == nil || call.TenantID == "" || call.ResourceID == "" || call.CommandID == "" || call.IdempotencyKey == "" || call.ExpectedGeneration == 0 || call.PrincipalID == "" || call.CredentialID == "" || call.SessionID == "" || call.AuthzEpoch == 0 || call.Assurance < identity.AssurancePhishingResistant {
		return apiserver.EdgeMutation[apiserver.HAPromotionApprovalProjection]{}, ha.ErrUnsupported
	}
	promotion, err := edge.repository.LoadPromotion(ctx, ha.PromotionID(call.ResourceID))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionApprovalProjection]{}, err
	}
	planDigest, err := ha.PromotionPlanDigest(promotion)
	if err != nil || promotion.State != ha.PromotionPlanned || promotion.Generation != call.ExpectedGeneration || payload.PlanDigest != planDigest || payload.FenceChallenge != planDigest {
		return apiserver.EdgeMutation[apiserver.HAPromotionApprovalProjection]{}, errors.Join(err, ha.ErrDataLossApproval)
	}
	approval := ha.Approval{
		ID:payload.ApprovalID, TenantID:call.TenantID, PromotionID:promotion.ID, GroupID:promotion.GroupID,
		ActorID:call.PrincipalID, CredentialID:call.CredentialID, SessionID:call.SessionID,
		AuthzEpoch:call.AuthzEpoch, TenantAuthzEpoch:payload.TenantAuthzEpoch, PromotionGeneration:promotion.Generation,
		Kind:ha.AdministrativeFenceApprovalKind, PlanDigest:payload.PlanDigest, FenceChallenge:payload.FenceChallenge,
		PhishingResistant:true, IssuedAt:payload.IssuedAt.UTC(), ExpiresAt:payload.ExpiresAt.UTC(), Signature:payload.Signature,
	}
	admission, _, err := edge.approvals.Admit(ctx, promotion, ha.PromotionApprovalAdmission{CommandID:ha.CommandID(call.CommandID),IdempotencyKey:call.IdempotencyKey,Approval:approval})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionApprovalProjection]{}, err
	}
	projection := apiserver.HAPromotionApprovalProjection{
		ID:admission.Approval.ID, TenantID:admission.Approval.TenantID, PromotionID:string(admission.Approval.PromotionID),
		ActorID:admission.Approval.ActorID, PlanDigest:admission.Approval.PlanDigest, FenceChallenge:admission.Approval.FenceChallenge,
		PromotionGeneration:admission.Approval.PromotionGeneration, AcceptedAt:admission.AcceptedAt, ExpiresAt:admission.Approval.ExpiresAt,
	}
	return apiserver.EdgeMutation[apiserver.HAPromotionApprovalProjection]{OperationID:call.CommandID,State:"accepted",Generation:promotion.Generation,Resource:projection},nil
}

func (edge *fleetHAEdge) ExecutePromotion(ctx context.Context, call apiserver.EdgeCall, payload apiserver.HAPromotionExecutePayload) (apiserver.EdgeMutation[apiserver.HAPromotionProjection], error) {
	if edge == nil || edge.repository == nil || edge.approvals == nil || ctx == nil || call.TenantID != "" || call.ResourceID == "" || call.CommandID == "" || call.ExpectedGeneration == 0 || call.Assurance < identity.AssurancePhishingResistant || payload.PromotionID == "" || payload.WriterLeaseGeneration == 0 || payload.PlanDigest == "" {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrInvalid
	}
	selectedWriter, err := edge.repository.LoadNode(ctx, ha.NodeID(call.ResourceID))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if selectedWriter.Generation != call.ExpectedGeneration {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrStaleGeneration
	}
	promotion, err := edge.repository.LoadPromotion(ctx, ha.PromotionID(payload.PromotionID))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	if promotion.PreviousWriter != selectedWriter.ID || promotion.GroupID != selectedWriter.GroupID {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrConflict
	}
	var quorum ha.QuorumObservation
	if err = json.Unmarshal([]byte(payload.QuorumEvidence), &quorum); err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, ha.ErrInvalid
	}
	bindings, err := parsePromotionFenceBindings(payload.FenceProviderBindings)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err
	}
	runID := ha.FailoverRunID(fleetEffectID("failover", string(promotion.ID), promotion.ResourceID))
	request := ha.PromotionExecutionRequest{
		PromotionID:promotion.ID, RunID:runID, ExpectedLeaseGeneration:payload.WriterLeaseGeneration,
		Approval:ha.PromotionApprovalEvidence{
			CommandID:ha.CommandID(call.CommandID), ActorID:call.PrincipalID, CredentialID:call.CredentialID,
			SessionID:call.SessionID, AuthzEpoch:call.AuthzEpoch, PlanDigest:payload.PlanDigest,
			PhishingResistant:call.Assurance >= identity.AssurancePhishingResistant, ApprovedAt:edge.now().UTC(),
		},
		Quorum:quorum, FenceProviderBindings:bindings,
	}
	coordinator:=edge.failover
	if edge.providers!=nil{
		group,loadErr:=edge.repository.LoadNodeGroup(ctx,promotion.GroupID);if loadErr!=nil{return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{},loadErr}
		policy,loadErr:=edge.repository.LoadTrafficPolicy(ctx,promotion.TrafficPolicyID);if loadErr!=nil{return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{},loadErr}
		coordinator,loadErr=edge.providers.coordinator(*edge.repository,group,promotion,policy,edge.now);if loadErr!=nil{return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{},loadErr}
	}
	acceptedApprovals, err := edge.approvals.ApprovalsForPromotion(ctx, promotion, payload.PlanDigest)
	if err != nil { return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err }
	promotion, err = edge.repository.AttachPromotionApprovals(ctx, promotion.ID, promotion.Generation, payload.PlanDigest, acceptedApprovals, edge.now().UTC())
	if err != nil { return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, err }
	promotion, run, executeErr := coordinator.Execute(ctx, request)
	if executeErr != nil && !errors.Is(executeErr, ha.ErrReconciliationRequired) {
		return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{}, executeErr
	}
	return promotionExecutionMutation(promotion, run), nil
}

func fleetNodeProjection(node ha.NodeMember) apiserver.FleetNodeProjection {
	roles := make([]string, len(node.Roles))
	for index := range node.Roles {
		roles[index] = string(node.Roles[index])
	}
	sort.Strings(roles)
	name := strings.TrimSpace(node.Labels["name"])
	if name == "" {
		name = string(node.ID)
	}
	version := strings.TrimSpace(node.Labels["product_version"])
	if version == "" && len(node.Capabilities.VersionDigest) >= 12 {
		version = node.Capabilities.VersionDigest[:12]
	}
	return apiserver.FleetNodeProjection{ID:string(node.ID), Name:name, State:string(node.State), Roles:roles, Architecture:node.Capabilities.Architecture, Version:version, FailureDomain:node.FailureDomain, LastSeenAt:node.Capabilities.ObservedAt, Generation:node.Generation}
}

func promotionMutation(promotion ha.Promotion, digest string) apiserver.EdgeMutation[apiserver.HAPromotionProjection] {
	state := string(promotion.State)
	if promotion.State == ha.PromotionFailed && promotion.Failure != "" {
		state = "blocked"
	} else if promotion.PotentialDataLoss {
		state = "requires_approval"
	}
	projection := apiserver.HAPromotionProjection{
		ID:string(promotion.ID), ResourceID:promotion.ResourceID, PreviousWriterNodeID:string(promotion.PreviousWriter), CandidateNodeID:string(promotion.Candidate),
		WriterLeaseGeneration:promotion.ExpectedGeneration, MaximumDataLoss:promotion.MaximumDataLoss, PotentialDataLoss:promotion.PotentialDataLoss,
		PlanDigest:digest, State:state, Failure:promotion.Failure, Generation:promotion.Generation,
	}
	return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{OperationID:string(promotion.CommandID), State:state, Generation:promotion.Generation, Resource:projection}
}

func promotionPlanDigest(promotion ha.Promotion) string {
	digest, _ := ha.PromotionPlanDigest(promotion)
	return digest
}

func promotionExecutionMutation(promotion ha.Promotion, run ha.FailoverRun) apiserver.EdgeMutation[apiserver.HAPromotionProjection] {
	effects := make([]apiserver.HAPromotionEffectProjection, len(run.Effects))
	for index, receipt := range run.Effects {
		effects[index] = apiserver.HAPromotionEffectProjection{
			Sequence:receipt.Sequence, EffectID:receipt.EffectID, Kind:receipt.Kind, Outcome:string(receipt.Outcome),
			ReceiptDigest:receipt.ReceiptDigest, Frontier:receipt.Frontier, Irreversible:receipt.Irreversible,
			Failure:receipt.Failure, StartedAt:receipt.StartedAt, CompletedAt:receipt.CompletedAt,
		}
	}
	projection := apiserver.HAPromotionProjection{
		ID:string(promotion.ID), ResourceID:promotion.ResourceID, PreviousWriterNodeID:string(promotion.PreviousWriter), CandidateNodeID:string(promotion.Candidate),
		WriterLeaseGeneration:promotion.ExpectedGeneration, MaximumDataLoss:promotion.MaximumDataLoss, PotentialDataLoss:promotion.PotentialDataLoss,
		PlanDigest:run.PlanDigest, State:string(run.State), RunID:string(run.ID), Step:run.Step, Effects:effects,
		ReconciliationRequired:run.ReconciliationRequired, ReconciliationReason:run.ReconciliationReason,
		Failure:run.Failure, Generation:promotion.Generation,
	}
	return apiserver.EdgeMutation[apiserver.HAPromotionProjection]{OperationID:string(run.Approval.CommandID), State:string(run.State), Generation:promotion.Generation, Resource:projection}
}

func parsePromotionFenceBindings(value string) (map[ha.FenceClass]string, error) {
	result := map[ha.FenceClass]string{}
	for _, line := range strings.Split(strings.TrimSpace(value), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			return nil, ha.ErrInvalid
		}
		class := ha.FenceClass(strings.TrimSpace(parts[0]))
		switch class {
		case ha.FencePower, ha.FenceStorage, ha.FenceDatabase, ha.FenceMandatoryLease, ha.FenceAdministrative:
		default:
			return nil, ha.ErrInvalid
		}
		if _, duplicate := result[class]; duplicate {
			return nil, ha.ErrConflict
		}
		result[class] = strings.TrimSpace(parts[1])
	}
	return result, nil
}

func promotionTrafficCovers(policy ha.TrafficPolicy, previous, candidate ha.NodeID) bool {
	if policy.ID == "" || policy.Resource == "" || policy.Generation == 0 || policy.ProviderBindingID == "" {
		return false
	}
	previousFound, candidateFound := false, false
	for _, endpoint := range policy.Endpoints {
		if endpoint.NodeID == previous {
			previousFound = true
		}
		if endpoint.NodeID == candidate {
			candidateFound = true
		}
	}
	return previousFound && candidateFound
}

func fleetEffectID(kind, commandID, resourceID string) string {
	sum := sha256.Sum256([]byte("cyberpanel-fleet-edge-v1\x00" + kind + "\x00" + commandID + "\x00" + resourceID))
	return kind + "_" + hex.EncodeToString(sum[:])[:48]
}

func wipeFleetToken(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ apiserver.FleetEdgeService = (*fleetHAEdge)(nil)
var _ apiserver.HAEdgeService = (*fleetHAEdge)(nil)
