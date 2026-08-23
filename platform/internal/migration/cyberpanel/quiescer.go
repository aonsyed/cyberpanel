package cyberpanel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

type GateScope struct { MigrationID migration.ID; SourceInstallationID string; SiteSourceIDs []string; Mode string; ExpectedFence uint64; TargetPlanDigest,ApprovalDigest string }
type ComponentLease struct { Token,EvidenceDigest string; ExpiresAt time.Time }
type ComponentAction struct { MigrationID migration.ID; SiteSourceIDs []string; SourceGeneration,ExpectedFence uint64; FenceDigest,Token string }
type ComponentGate interface { Freeze(context.Context,GateScope)(ComponentLease,error);Verify(context.Context,ComponentAction)error;Thaw(context.Context,ComponentAction)error;Commit(context.Context,ComponentAction)error;Rollback(context.Context,ComponentAction)error }
type NamedComponentGate struct { Name string; Gate ComponentGate }
type GenerationReader interface { Generation(context.Context,migration.ID)(uint64,error) }

type CoordinatedQuiescer struct { components []NamedComponentGate; generation GenerationReader; clock func()time.Time }
func NewCoordinatedQuiescer(components []NamedComponentGate,generation GenerationReader)(*CoordinatedQuiescer,error){if len(components)==0||generation==nil{return nil,ErrInvalid};values:=append([]NamedComponentGate(nil),components...);seen:=map[string]struct{}{};for _,component:=range values{if !validComponentName(component.Name)||component.Gate==nil{return nil,ErrInvalid};if _,duplicate:=seen[component.Name];duplicate{return nil,ErrInvalid};seen[component.Name]=struct{}{}};sort.Slice(values,func(i,j int)bool{return values[i].Name<values[j].Name});return &CoordinatedQuiescer{components:values,generation:generation,clock:time.Now},nil}

func(q *CoordinatedQuiescer)Freeze(ctx context.Context,request QuiesceRequest)(GateLease,error){if q==nil||ctx==nil||!request.MigrationID.Valid(){return GateLease{},ErrInvalid};scope:=GateScope{MigrationID:request.MigrationID,SourceInstallationID:request.SourceInstallationID,SiteSourceIDs:append([]string(nil),request.SiteSourceIDs...),Mode:request.Mode,ExpectedFence:request.ExpectedFence,TargetPlanDigest:request.TargetPlanDigest,ApprovalDigest:request.ApprovalDigest};token:=coordinatedToken{Version:1};minimumExpiry:=time.Time{};for _,component:=range q.components{lease,err:=component.Gate.Freeze(ctx,scope);if err!=nil{q.thawPartial(request,token);return GateLease{},err};candidate:=coordinatedComponent{Name:component.Name,Token:lease.Token,EvidenceDigest:lease.EvidenceDigest,ExpiresAt:lease.ExpiresAt.UTC()};if strings.TrimSpace(lease.Token)!=""{token.Components=append(token.Components,candidate)};if strings.TrimSpace(lease.Token)==""||len(lease.Token)>256<<10||!isDigest(lease.EvidenceDigest)||lease.ExpiresAt.IsZero()||!lease.ExpiresAt.After(q.clock().UTC()){q.thawPartial(request,token);return GateLease{},ErrInvalid};if minimumExpiry.IsZero()||lease.ExpiresAt.Before(minimumExpiry){minimumExpiry=lease.ExpiresAt.UTC()}};generation,err:=q.generation.Generation(ctx,request.MigrationID);if err!=nil||generation==0{q.thawPartial(request,token);return GateLease{},errors.Join(err,ErrChanged)};if !minimumExpiry.After(q.clock().UTC()){q.thawPartial(request,token);return GateLease{},ErrDenied};encoded,err:=json.Marshal(token);if err!=nil||len(encoded)>1<<20{q.thawPartial(request,token);if err!=nil{return GateLease{},err};return GateLease{},ErrInvalid};evidenceRaw,err:=json.Marshal(struct{Domain string;MigrationID migration.ID;Generation uint64;Components []coordinatedComponent}{Domain:"cyberpanel-coordinated-quiesce-v1",MigrationID:request.MigrationID,Generation:generation,Components:token.Components});if err!=nil{q.thawPartial(request,token);return GateLease{},err};sum:=sha256.Sum256(evidenceRaw);return GateLease{Token:string(encoded),SourceGeneration:generation,ExpiresAt:minimumExpiry,EvidenceDigest:hex.EncodeToString(sum[:])},nil}

func(q *CoordinatedQuiescer)Verify(ctx context.Context,check GateCheck)error{return q.each(ctx,check,false,func(gate ComponentGate,action ComponentAction)error{return gate.Verify(ctx,action)})}
func(q *CoordinatedQuiescer)Thaw(ctx context.Context,check GateCheck)error{return q.each(ctx,check,true,func(gate ComponentGate,action ComponentAction)error{return gate.Thaw(ctx,action)})}
func(q *CoordinatedQuiescer)Commit(ctx context.Context,check GateCheck)error{return q.each(ctx,check,false,func(gate ComponentGate,action ComponentAction)error{return gate.Commit(ctx,action)})}
func(q *CoordinatedQuiescer)Rollback(ctx context.Context,check GateCheck)error{return q.each(ctx,check,true,func(gate ComponentGate,action ComponentAction)error{return gate.Rollback(ctx,action)})}

type coordinatedToken struct { Version uint32 `json:"version"`;Components []coordinatedComponent `json:"components"` }
type coordinatedComponent struct { Name,Token,EvidenceDigest string;ExpiresAt time.Time }
func(q *CoordinatedQuiescer)each(ctx context.Context,check GateCheck,reverse bool,operation func(ComponentGate,ComponentAction)error)error{if q==nil||ctx==nil||!check.MigrationID.Valid()||check.SourceGeneration==0||check.ExpectedFence==0||check.Token==""{return ErrInvalid};token,err:=decodeCoordinatedToken(check.Token);if err!=nil{return err};if len(token.Components)!=len(q.components){return ErrDenied};var failures []error;for position:=0;position<len(q.components);position++{index:=position;if reverse{index=len(q.components)-1-position};component:=q.components[index];tokenComponent:=token.Components[index];if component.Name!=tokenComponent.Name{return ErrDenied};action:=ComponentAction{MigrationID:check.MigrationID,SiteSourceIDs:append([]string(nil),check.SiteSourceIDs...),SourceGeneration:check.SourceGeneration,ExpectedFence:check.ExpectedFence,FenceDigest:check.FenceDigest,Token:tokenComponent.Token};if err:=operation(component.Gate,action);err!=nil{failures=append(failures,err)}};return errors.Join(failures...)}
func(q *CoordinatedQuiescer)thawPartial(request QuiesceRequest,token coordinatedToken){cleanup,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel();for index:=len(token.Components)-1;index>=0;index--{component:=q.components[index];value:=token.Components[index];_ = component.Gate.Thaw(cleanup,ComponentAction{MigrationID:request.MigrationID,SiteSourceIDs:append([]string(nil),request.SiteSourceIDs...),ExpectedFence:request.ExpectedFence,Token:value.Token})}}
func decodeCoordinatedToken(value string)(coordinatedToken,error){if len(value)==0||len(value)>1<<20{return coordinatedToken{},ErrInvalid};decoder:=json.NewDecoder(strings.NewReader(value));decoder.DisallowUnknownFields();var token coordinatedToken;if err:=decoder.Decode(&token);err!=nil{return coordinatedToken{},ErrInvalid};var trailing any;if err:=decoder.Decode(&trailing);!errors.Is(err,io.EOF){return coordinatedToken{},ErrInvalid};if token.Version!=1||len(token.Components)==0{return coordinatedToken{},ErrInvalid};for _,component:=range token.Components{if !validComponentName(component.Name)||component.Token==""||len(component.Token)>256<<10||!isDigest(component.EvidenceDigest)||component.ExpiresAt.IsZero(){return coordinatedToken{},ErrInvalid}};return token,nil}
func validComponentName(value string)bool{if len(value)<2||len(value)>64{return false};for _,character:=range value{if(character<'a'||character>'z')&&(character<'0'||character>'9')&&character!='-'&&character!='_'{return false}};return true}

var _ TypedSiteQuiescer=(*CoordinatedQuiescer)(nil)
