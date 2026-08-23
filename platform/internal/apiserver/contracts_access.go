package apiserver

import (
	"context"
	"net/http"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type FileListPayload struct{Root access.SiteRoot `json:"root"`;Directory access.RelativePath `json:"directory"`;Page access.PageRequest `json:"page"`}
type FileReadPayload struct{Source access.FileLocator `json:"source"`;Condition access.WriteCondition `json:"condition"`}
type FileMutatePayload struct{Kind access.FileOperationKind `json:"kind"`;Source access.FileLocator `json:"source"`;Destination access.FileLocator `json:"destination"`;Metadata access.FileMetadata `json:"metadata"`;Content []byte `json:"content,omitempty"`;Condition access.WriteCondition `json:"condition"`;SymlinkTarget access.RelativePath `json:"symlink_target"`}

func registerAccessContracts(registry *Registry)error{
	operations:=[]Operation{
		{Name:"access.files.list",Permission:identity.MustPermission("file:read"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:false,NewPayload:func()any{return &FileListPayload{}},ResolveScope:siteScope},
		{Name:"access.files.read_editor",Permission:identity.MustPermission("file:read"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:false,MaximumResponseBytes:access.MaxEditorBytes+65536,NewPayload:func()any{return &FileReadPayload{}},ResolveScope:siteScope},
		{Name:"access.files.mutate",Permission:identity.MustPermission("file:write"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,MaximumBodyBytes:access.MaxEditorBytes+65536,NewPayload:func()any{return &FileMutatePayload{}},ResolveScope:siteScope},
	}
	for _,operation:=range operations{if err:=register(registry,operation);err!=nil{return err}}
	return nil
}

func bindAccess(registry *Registry,services DomainServices)error{
	if services.Files==nil{return nil}
	checkSite:=func(request RequestEnvelope,roots ...access.SiteRoot)error{for _,root:=range roots{if string(root.SiteID)!=request.ResourceID{return ErrForbidden};if err:=root.Validate();err!=nil{return ErrInvalidRequest}};return nil}
	if err:=registry.Bind("access.files.list",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){p:=value.(*FileListPayload);if err:=checkSite(inv.Request,p.Root);err!=nil{return OperationResult{},err};page,err:=services.Files.List(ctx,p.Root,p.Directory,p.Page);if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:page},nil});err!=nil{return err}
	if err:=registry.Bind("access.files.read_editor",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){p:=value.(*FileReadPayload);if err:=checkSite(inv.Request,p.Source.Root);err!=nil{return OperationResult{},err};content,entry,err:=services.Files.ReadEditor(ctx,p.Source,p.Condition);if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Content []byte `json:"content"`;Entry access.FileEntry `json:"entry"`}{content,entry}},nil});err!=nil{return err}
	return registry.Bind("access.files.mutate",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){p:=value.(*FileMutatePayload);var roots []access.SiteRoot;switch p.Kind{case access.FileCreateDirectory,access.FileCreate,access.FileWrite,access.FileCreateSymlink:roots=[]access.SiteRoot{p.Destination.Root};case access.FileMove,access.FileCopy:roots=[]access.SiteRoot{p.Source.Root,p.Destination.Root};case access.FileSetMetadata:roots=[]access.SiteRoot{p.Source.Root};default:return OperationResult{},ErrInvalidRequest};if err:=checkSite(inv.Request,roots...);err!=nil{return OperationResult{},err};actor:=access.AuditActor{TenantID:access.TenantID(inv.Request.TenantID),PrincipalID:access.PrincipalID(inv.Actor.PrincipalID.String()),SourceIP:inv.Meta.ClientIP.String()};mutation:=access.Mutation{CommandID:access.CommandID(commandID(inv)),Actor:actor,At:time.Now().UTC()};operation:=access.FileOperation{ID:access.FileOperationID(effectID(inv)),Mutation:mutation,Kind:p.Kind,Source:p.Source,Destination:p.Destination,State:access.OperationAdmitted,StartedAt:time.Now().UTC()};receipt,err:=services.Files.Mutate(ctx,access.FileMutationCall{Operation:operation,Metadata:p.Metadata,Content:p.Content,Condition:p.Condition,SymlinkTarget:p.SymlinkTarget});for index:=range p.Content{p.Content[index]=0};if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:receipt},nil})
}
