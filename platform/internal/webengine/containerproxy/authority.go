package containerproxy

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

type VerifiedActivator interface{ApplyVerified(context.Context,native.RenderRequest,string)(activation.Receipt,error)}
type Authority struct{Catalog *catalog.SQLCatalog;Activator VerifiedActivator;renderers map[webengine.Edition]native.Renderer;activation sync.Mutex}
func New(catalogValue *catalog.SQLCatalog,activator VerifiedActivator,renderers ...native.Renderer)(*Authority,error){if catalogValue==nil||nilAuthority(activator){return nil,containers.ErrInvalid};byEdition:=map[webengine.Edition]native.Renderer{};for _,renderer:=range renderers{if nilAuthority(renderer){return nil,containers.ErrInvalid};byEdition[renderer.Edition()]=renderer};if len(byEdition)!=2||byEdition[webengine.EditionOpenLiteSpeed]==nil||byEdition[webengine.EditionLiteSpeedEnterprise]==nil{return nil,containers.ErrInvalid};return &Authority{Catalog:catalogValue,Activator:activator,renderers:byEdition},nil}

func(authority *Authority)Prepare(ctx context.Context,exposure containers.Exposure)(uint64,error){route,err:=routeInput(exposure);if err!=nil{return 0,err};prepared,err:=authority.Catalog.PrepareProxyRoute(ctx,routeEffect(exposure),route,false);if err!=nil{return 0,err};return prepared.Plan.SnapshotGeneration,nil}
func(authority *Authority)Commit(ctx context.Context,exposure containers.Exposure,generation uint64)(uint64,error){if authority==nil||generation==0{return 0,containers.ErrInvalid};authority.activation.Lock();defer authority.activation.Unlock();prepared,err:=authority.Catalog.PendingProxyRoute(ctx,routeEffect(exposure),generation);if err!=nil{return 0,err};composed,err:=composer.Compose(prepared.Plan);if err!=nil{_=authority.Catalog.RejectProxyRoute(ctx,prepared);return 0,err};renderer:=authority.renderers[composed.Desired.Engine.Edition];if renderer==nil{_=authority.Catalog.RejectProxyRoute(ctx,prepared);return 0,containers.ErrPolicy};request:=native.RenderRequest{Desired:composed.Desired,Snapshot:composed.Snapshot};rendered,err:=renderer.Render(ctx,request);if err!=nil{_=authority.Catalog.RejectProxyRoute(ctx,prepared);return 0,err};receipt,err:=authority.Activator.ApplyVerified(ctx,request,rendered.ContentDigest);if err!=nil||receipt.Status!=activation.Applied||!receipt.Confirmed||receipt.Digest!=rendered.ContentDigest{return 0,errors.Join(containers.ErrAmbiguous,err)};if err=authority.Catalog.FinalizeProxyRoute(ctx,prepared,receipt.Digest);err!=nil{return 0,errors.Join(containers.ErrAmbiguous,err)};return prepared.Plan.SnapshotGeneration,nil}
func(authority *Authority)Rollback(ctx context.Context,exposure containers.Exposure,generation uint64)error{if authority==nil||generation==0{return containers.ErrInvalid};prepared,err:=authority.Catalog.PendingProxyRoute(ctx,routeEffect(exposure),generation);if err!=nil{return err};return authority.Catalog.RejectProxyRoute(ctx,prepared)}

func routeInput(exposure containers.Exposure)(composer.ProxyRouteInput,error){hostname,err:=webengine.ParseHostname(exposure.DomainBindingRef);if err!=nil{return composer.ProxyRouteInput{},containers.ErrInvalid};listener:=webengine.ResourceRef(exposure.ListenerRef);if !safeRouteRef(listener)||!exposure.ID.Valid()||!exposure.WorkloadID.Valid()||exposure.PortName==""||exposure.Generation==0{return composer.ProxyRouteInput{},containers.ErrInvalid};return composer.ProxyRouteInput{Ref:webengine.ResourceRef("container/"+exposure.ID.String()),Hostname:hostname,ListenerRef:listener,UpstreamPort:containers.LoopbackExposurePort(exposure.WorkloadID,exposure.PortName),Generation:exposure.Generation},nil}
func routeEffect(exposure containers.Exposure)string{return "container-route-"+exposure.ID.String()+"-g"+fmt.Sprint(exposure.Generation)}
func safeRouteRef(value webengine.ResourceRef)bool{raw:=string(value);if len(raw)<3||len(raw)>255||raw[0]=='/'||raw[len(raw)-1]=='/'{return false};for _,character:=range raw{if character!='/'&&character!='-'&&character!='_'&&character!='.'&&(character<'a'||character>'z')&&(character<'0'||character>'9'){return false}};return true}
func nilAuthority(value any)bool{if value==nil{return true};ref:=reflect.ValueOf(value);switch ref.Kind(){case reflect.Pointer,reflect.Interface,reflect.Func,reflect.Map,reflect.Slice,reflect.Chan:return ref.IsNil()};return false}

var _ containers.RouteCoordinator=(*Authority)(nil)
