package apiserver

import (
	"context"
	"net/http"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
)

type NotificationInboxProjectPayload struct {
	NotificationID integrations.ID `json:"notification_id"`
	PrincipalID string `json:"principal_id"`
}

type NotificationInboxEdgeService interface {
	NotificationInboxAvailable()bool
	ProjectInbox(context.Context,EdgeCall,NotificationInboxProjectPayload)(EdgeMutation[integrations.InboxItem],error)
	ListInbox(context.Context,EdgeCall,EdgePagePayload)(EdgePage[integrations.InboxItem],error)
	GetInboxItem(context.Context,EdgeCall)(integrations.InboxItem,error)
	MarkInboxRead(context.Context,EdgeCall)(EdgeMutation[integrations.InboxItem],error)
	AcknowledgeInbox(context.Context,EdgeCall)(EdgeMutation[integrations.InboxItem],error)
	DismissInbox(context.Context,EdgeCall)(EdgeMutation[integrations.InboxItem],error)
}

func registerNotificationContracts(registry *Registry)error{
	definitions:=[]Operation{
		consoleOperation("notification.inbox.project","operations:manage",identity.AssurancePassword,true,func()any{return &NotificationInboxProjectPayload{}},validateNotificationInboxProject,edgeTenantCreateScope),
		{Name:"notification.inbox.list",Auth:AuthRequired,SelfService:true,Assurance:identity.AssurancePassword,NewPayload:func()any{return &EdgePagePayload{}},ValidatePayload:validateEdgePage,ResolveScope:edgeTenantListScope},
		{Name:"notification.inbox.get",Auth:AuthRequired,SelfService:true,Assurance:identity.AssurancePassword,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:edgeTenantResourceReadScope},
		{Name:"notification.inbox.mark_read",Auth:AuthRequired,SelfService:true,Assurance:identity.AssurancePassword,Mutating:true,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:edgeTenantExistingMutationScope},
		{Name:"notification.inbox.acknowledge",Auth:AuthRequired,SelfService:true,Assurance:identity.AssurancePassword,Mutating:true,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:edgeTenantExistingMutationScope},
		{Name:"notification.inbox.dismiss",Auth:AuthRequired,SelfService:true,Assurance:identity.AssurancePassword,Mutating:true,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:edgeTenantExistingMutationScope},
	}
	for _,definition:=range definitions{if err:=register(registry,definition);err!=nil{return err}}
	return nil
}

func validateNotificationInboxProject(value any)error{payload:=value.(*NotificationInboxProjectPayload);if !validEdgeID(string(payload.NotificationID))||!validEdgeID(payload.PrincipalID){return invalid("notification inbox projection")};return nil}

func bindNotificationContracts(registry *Registry,services DomainServices)error{
	edge,ok:=services.IntegrationEdge.(NotificationInboxEdgeService);if !ok||edge==nil||!edge.NotificationInboxAvailable(){return nil}
	if err:=registry.Bind("notification.inbox.project",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){result,err:=edge.ProjectInbox(ctx,edgeCall(inv),*value.(*NotificationInboxProjectPayload));if err!=nil{return OperationResult{},mapDomainError(err)};return edgeOperationResult(http.StatusCreated,result),nil});err!=nil{return err}
	if err:=registry.Bind("notification.inbox.list",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){result,err:=edge.ListInbox(ctx,edgeCall(inv),*value.(*EdgePagePayload));if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:result},nil});err!=nil{return err}
	if err:=registry.Bind("notification.inbox.get",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){item,err:=edge.GetInboxItem(ctx,edgeCall(inv));if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:item,Generation:item.Generation},nil});err!=nil{return err}
	mutations:=[]struct{name string;handler func(context.Context,EdgeCall)(EdgeMutation[integrations.InboxItem],error)}{{"notification.inbox.mark_read",edge.MarkInboxRead},{"notification.inbox.acknowledge",edge.AcknowledgeInbox},{"notification.inbox.dismiss",edge.DismissInbox}}
	for _,mutation:=range mutations{current:=mutation;if err:=registry.Bind(current.name,func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){result,err:=current.handler(ctx,edgeCall(inv));if err!=nil{return OperationResult{},mapDomainError(err)};return edgeOperationResult(http.StatusOK,result),nil});err!=nil{return err}}
	return nil
}
