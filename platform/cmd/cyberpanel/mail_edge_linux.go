//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
)

type mailEdge struct{store mail.SQLControlRepository;runtime *mail.MailDaemonClient}
func newMailEdge(store mail.SQLControlRepository,runtime *mail.MailDaemonClient)(apiserver.MailEdgeService,error){if store.DB==nil||runtime==nil{return nil,errors.New("mail edge dependencies required")};return &mailEdge{store:store,runtime:runtime},nil}

func(edge *mailEdge)ListRoutes(ctx context.Context,call apiserver.EdgeCall,page apiserver.EdgePagePayload)(apiserver.EdgePage[apiserver.MailRouteProjection],error){if edge==nil||edge.store.DB==nil||ctx==nil||call.TenantID==""{return apiserver.EdgePage[apiserver.MailRouteProjection]{},mail.ErrInvalidCommand};limit:=int(page.Limit);if limit==0{limit=100};resources,next,err:=edge.store.List(ctx,call.TenantID,mail.ResourceAlias,limit,page.Cursor);if err!=nil{return apiserver.EdgePage[apiserver.MailRouteProjection]{},err};items:=make([]apiserver.MailRouteProjection,0,len(resources));for _,resource:=range resources{var alias mail.Alias;if json.Unmarshal(resource.Spec,&alias)!=nil||string(alias.ID)!=resource.ID{return apiserver.EdgePage[apiserver.MailRouteProjection]{},mail.ErrInvalidReceipt};targets:=make([]string,len(alias.Targets));for index,target:=range alias.Targets{targets[index]=string(target)};kind:="alias";if alias.CatchAll{kind="catch_all"};if alias.PipeRef!=""{kind="pipe"};items=append(items,apiserver.MailRouteProjection{ID:resource.ID,DomainID:string(alias.Domain),Source:string(alias.Source),Targets:targets,Kind:kind,State:string(resource.State),Generation:resource.Generation,UpdatedAt:resource.UpdatedAt})};return apiserver.EdgePage[apiserver.MailRouteProjection]{Items:items,NextCursor:next},nil}

func(edge *mailEdge)RunDiagnostic(ctx context.Context,call apiserver.EdgeCall,payload apiserver.MailDiagnosticPayload)(apiserver.EdgeMutation[apiserver.MailDiagnosticProjection],error){if edge==nil||edge.runtime==nil||ctx==nil||call.TenantID==""||call.ResourceID==""{return apiserver.EdgeMutation[apiserver.MailDiagnosticProjection]{},mail.ErrInvalidCommand};services:=[]mail.MailService{mail.ServicePostfix,mail.ServiceDovecot};if payload.Depth=="deep"{services=append(services,mail.ServiceRspamd,mail.ServiceOpenDKIM,mail.ServiceRedis,mail.ServiceClamAV)};checks:=make([]string,0,len(services));findings:=[]string{};for _,service:=range services{receipt,err:=edge.runtime.ControlService(ctx,service,mail.ServiceProbe);if err!=nil{return apiserver.EdgeMutation[apiserver.MailDiagnosticProjection]{},err};checks=append(checks,string(service)+":"+receipt.EvidenceDigest);if !receipt.Active{findings=append(findings,string(service)+":unhealthy")}};state:="healthy";if len(findings)>0{state="degraded"};completed:=time.Now().UTC();operationID:=mailEdgeID(call,"diagnostic");projection:=apiserver.MailDiagnosticProjection{ID:operationID,ResourceID:call.ResourceID,State:state,Checks:checks,Findings:findings,CompletedAt:completed};return apiserver.EdgeMutation[apiserver.MailDiagnosticProjection]{OperationID:operationID,State:"applied",Generation:1,Resource:projection},nil}
func mailEdgeID(call apiserver.EdgeCall,purpose string)string{sum:=sha256.Sum256([]byte("mail-edge-v1\x00"+call.TenantID+"\x00"+call.ResourceID+"\x00"+call.CommandID+"\x00"+call.IdempotencyKey+"\x00"+purpose));return "mailedge_"+hex.EncodeToString(sum[:])}
var _ apiserver.MailEdgeService=(*mailEdge)(nil)
