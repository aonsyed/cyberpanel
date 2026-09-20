package apiserver

import (
	"context"
	"net/http"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type DatabaseCreatePayload struct{Database database.Database `json:"database"`}
type DatabaseDeletePayload struct{DatabaseID database.ResourceID `json:"database_id"`;RecoveryPointRef database.ResourceID `json:"recovery_point_ref,omitempty"`;WaiveRecovery bool `json:"waive_recovery"`;ApprovalRef database.ResourceID `json:"approval_ref,omitempty"`}
type DatabasePrincipalCreatePayload struct{Principal database.DatabasePrincipal `json:"principal"`}
type DatabasePrincipalDeletePayload struct{PrincipalID database.ResourceID `json:"principal_id"`}
type DatabasePasswordRotatePayload struct{PrincipalID database.ResourceID `json:"principal_id"`;NewSecretRef database.SecretRef `json:"new_secret_ref"`}
type DatabaseGrantPayload struct{GrantSet database.GrantSet `json:"grant_set"`}
type DatabaseNetworkPayload struct{Policy database.NetworkAccessPolicy `json:"policy"`}
type DatabaseConsolePayload struct{Session database.DatabaseWorkspaceSession `json:"session"`}
type DatabaseWorkspacePayload struct{SessionID database.ResourceID `json:"session_id"`}
type DatabaseWorkspaceQueryPayload struct{SessionID database.ResourceID `json:"session_id"`;Statement string `json:"statement"`}
type DatabaseInstancePayload struct{Instance database.DatabaseInstance `json:"instance"`;ApprovalRef database.ResourceID `json:"approval_ref"`}
type DatabaseTuningPayload struct{Profile database.TuningProfile `json:"profile"`;ApprovalRef database.ResourceID `json:"approval_ref"`}
type DatabaseUpgradePayload struct{Upgrade database.DatabaseUpgrade `json:"upgrade"`;ApprovalRef database.ResourceID `json:"approval_ref"`}

func registerDatabaseContracts(registry *Registry)error{
	tenantOperations:=[]Operation{
		{Name:"database.database.create",Permission:identity.MustPermission("database:create"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabaseCreatePayload{}},ResolveScope:tenantScope},
		{Name:"database.database.delete",Permission:identity.MustPermission("database:delete"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabaseDeletePayload{}},ResolveScope:tenantScope},
		{Name:"database.principal.create",Permission:identity.MustPermission("database:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabasePrincipalCreatePayload{}},ResolveScope:tenantScope},
		{Name:"database.principal.delete",Permission:identity.MustPermission("database:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabasePrincipalDeletePayload{}},ResolveScope:tenantScope},
		{Name:"database.principal.rotate_password",Permission:identity.MustPermission("database:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabasePasswordRotatePayload{}},ResolveScope:tenantScope},
		{Name:"database.grants.replace",Permission:identity.MustPermission("database:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabaseGrantPayload{}},ResolveScope:tenantScope},
		{Name:"database.network.replace",Permission:identity.MustPermission("database:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabaseNetworkPayload{}},ResolveScope:tenantScope},
		{Name:"database.console.open",Permission:identity.MustPermission("database:console"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabaseConsolePayload{}},ResolveScope:tenantScope},
		{Name:"database.workspace.metadata",Permission:identity.MustPermission("database:console"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,NewPayload:func()any{return &DatabaseWorkspacePayload{}},ValidatePayload:func(value any)error{if value.(*DatabaseWorkspacePayload).SessionID.IsZero(){return ErrInvalidRequest};return nil},ResolveScope:siteScope},
		{Name:"database.workspace.query",Permission:identity.MustPermission("database:console"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,MaximumBodyBytes:database.MaximumWorkspaceStatementBytes+65536,NewPayload:func()any{return &DatabaseWorkspaceQueryPayload{}},ValidatePayload:func(value any)error{payload:=value.(*DatabaseWorkspaceQueryPayload);if payload.SessionID.IsZero(){return ErrInvalidRequest};_,_,err:=database.ParseWorkspaceStatement(payload.Statement);if err!=nil{return ErrInvalidRequest};return nil},ResolveScope:siteScope},
	}
	nodeOperations:=[]Operation{
		{Name:"database.instance.bind_external",Permission:identity.MustPermission("database:admin"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabaseInstancePayload{}},ResolveScope:installationScope},
		{Name:"database.tuning.request",Permission:identity.MustPermission("database:admin"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabaseTuningPayload{}},ResolveScope:installationScope},
		{Name:"database.upgrade.request",Permission:identity.MustPermission("database:admin"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DatabaseUpgradePayload{}},ResolveScope:installationScope},
	}
	for _,operation:=range append(tenantOperations,nodeOperations...){if err:=register(registry,operation);err!=nil{return err}}
	return registerDatabaseExportContracts(registry)
}

func bindDatabase(registry *Registry,services DomainServices)error{
	if services.Database==nil{return nil}
	if err:=bindDatabaseExportContracts(registry,services);err!=nil{return err}
	bind:=func(name string,builder func(Invocation,any)(database.Command,error))error{return registry.Bind(name,func(ctx context.Context,invocation Invocation,payload any)(OperationResult,error){command,err:=builder(invocation,payload);if err!=nil{return OperationResult{},err};receipt,err:=services.Database.Handle(ctx,command);if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:receipt},nil})}
	tenantHeader:=func(invocation Invocation,capability database.Capability)(database.CommandHeader,error){tenant,err:=site.NewTenantID(invocation.Request.TenantID);if err!=nil{return database.CommandHeader{},ErrInvalidRequest};return database.CommandHeader{CommandID:commandID(invocation),Actor:database.Actor{TenantID:tenant,Capability:capability},TenantID:tenant},nil}
	if err:=bind("database.database.create",func(inv Invocation,value any)(database.Command,error){header,err:=tenantHeader(inv,database.CapabilityTenantManage);if err!=nil{return nil,err};payload:=value.(*DatabaseCreatePayload);payload.Database.Metadata.TenantID=header.TenantID;payload.Database.Metadata.Generation=1;return database.CreateDatabase{Header:header,Database:payload.Database},nil});err!=nil{return err}
	if err:=bind("database.database.delete",func(inv Invocation,value any)(database.Command,error){header,err:=tenantHeader(inv,database.CapabilityTenantManage);if err!=nil{return nil,err};p:=value.(*DatabaseDeletePayload);return database.DeleteDatabase{Header:header,DatabaseID:p.DatabaseID,ExpectedGeneration:inv.Request.ExpectedGeneration,RecoveryPointRef:p.RecoveryPointRef,WaiveRecovery:p.WaiveRecovery,ApprovalRef:p.ApprovalRef},nil});err!=nil{return err}
	if err:=bind("database.principal.create",func(inv Invocation,value any)(database.Command,error){header,err:=tenantHeader(inv,database.CapabilityTenantManage);if err!=nil{return nil,err};p:=value.(*DatabasePrincipalCreatePayload);p.Principal.Metadata.TenantID=header.TenantID;p.Principal.Metadata.Generation=1;return database.CreatePrincipal{Header:header,Principal:p.Principal},nil});err!=nil{return err}
	if err:=bind("database.principal.delete",func(inv Invocation,value any)(database.Command,error){header,err:=tenantHeader(inv,database.CapabilityTenantManage);if err!=nil{return nil,err};return database.DeletePrincipal{Header:header,PrincipalID:value.(*DatabasePrincipalDeletePayload).PrincipalID,ExpectedGeneration:inv.Request.ExpectedGeneration},nil});err!=nil{return err}
	if err:=bind("database.principal.rotate_password",func(inv Invocation,value any)(database.Command,error){header,err:=tenantHeader(inv,database.CapabilityTenantManage);if err!=nil{return nil,err};p:=value.(*DatabasePasswordRotatePayload);return database.RotatePrincipalPassword{Header:header,PrincipalID:p.PrincipalID,ExpectedGeneration:inv.Request.ExpectedGeneration,NewSecretRef:p.NewSecretRef},nil});err!=nil{return err}
	if err:=bind("database.grants.replace",func(inv Invocation,value any)(database.Command,error){header,err:=tenantHeader(inv,database.CapabilityTenantManage);if err!=nil{return nil,err};p:=value.(*DatabaseGrantPayload);p.GrantSet.Metadata.TenantID=header.TenantID;p.GrantSet.Metadata.Generation=inv.Request.ExpectedGeneration+1;return database.ReplaceGrantSet{Header:header,GrantSet:p.GrantSet},nil});err!=nil{return err}
	if err:=bind("database.network.replace",func(inv Invocation,value any)(database.Command,error){header,err:=tenantHeader(inv,database.CapabilityTenantManage);if err!=nil{return nil,err};p:=value.(*DatabaseNetworkPayload);p.Policy.Metadata.TenantID=header.TenantID;p.Policy.Metadata.Generation=inv.Request.ExpectedGeneration+1;return database.ReplaceRemoteCIDRs{Header:header,Policy:p.Policy},nil});err!=nil{return err}
	if err:=bind("database.console.open",func(inv Invocation,value any)(database.Command,error){header,err:=tenantHeader(inv,database.CapabilityTenantConsole);if err!=nil{return nil,err};p:=value.(*DatabaseConsolePayload);p.Session.Metadata.TenantID=header.TenantID;p.Session.Metadata.Generation=1;if p.Session.ExpiresAt.IsZero(){p.Session.ExpiresAt=time.Now().UTC().Add(15*time.Minute)};return database.OpenConsoleSession{Header:header,Session:p.Session},nil});err!=nil{return err}
	if workspace,ok:=services.Database.(database.WorkspaceService);ok{
		workspaceCall:=func(inv Invocation,sessionID database.ResourceID)(database.WorkspaceCall,error){tenant,err:=site.NewTenantID(inv.Request.TenantID);if err!=nil{return database.WorkspaceCall{},ErrInvalidRequest};siteID,err:=site.NewSiteID(inv.Request.ResourceID);if err!=nil||sessionID.IsZero()||inv.Request.ExpectedGeneration==0{return database.WorkspaceCall{},ErrInvalidRequest};return database.WorkspaceCall{TenantID:tenant,SiteID:siteID,SessionID:sessionID,SessionGeneration:inv.Request.ExpectedGeneration},nil}
		if err:=registry.Bind("database.workspace.metadata",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){call,err:=workspaceCall(inv,value.(*DatabaseWorkspacePayload).SessionID);if err!=nil{return OperationResult{},err};result,err:=workspace.BrowseWorkspaceMetadata(ctx,call);if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:result,Generation:call.SessionGeneration},nil});err!=nil{return err}
		if err:=registry.Bind("database.workspace.query",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*DatabaseWorkspaceQueryPayload);call,err:=workspaceCall(inv,payload.SessionID);if err!=nil{return OperationResult{},err};result,err:=workspace.ExecuteWorkspaceStatement(ctx,call,payload.Statement);if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:result,Generation:call.SessionGeneration},nil});err!=nil{return err}
	}
	nodeHeader:=func(inv Invocation,approval database.ResourceID)database.CommandHeader{return database.CommandHeader{CommandID:commandID(inv),Actor:database.Actor{Capability:database.CapabilityNodeAdmin,ApprovalRef:approval}}}
	if err:=bind("database.instance.bind_external",func(inv Invocation,value any)(database.Command,error){p:=value.(*DatabaseInstancePayload);p.Instance.Metadata.Generation=1;return database.BindExternalInstance{Header:nodeHeader(inv,p.ApprovalRef),Instance:p.Instance},nil});err!=nil{return err}
	if err:=bind("database.tuning.request",func(inv Invocation,value any)(database.Command,error){p:=value.(*DatabaseTuningPayload);p.Profile.Metadata.Generation=inv.Request.ExpectedGeneration+1;return database.RequestTuning{Header:nodeHeader(inv,p.ApprovalRef),Profile:p.Profile},nil});err!=nil{return err}
	return bind("database.upgrade.request",func(inv Invocation,value any)(database.Command,error){p:=value.(*DatabaseUpgradePayload);p.Upgrade.Metadata.Generation=inv.Request.ExpectedGeneration+1;return database.RequestUpgrade{Header:nodeHeader(inv,p.ApprovalRef),Upgrade:p.Upgrade},nil})
}
