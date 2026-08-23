package apiserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type AuditQueryPayload struct{Query audit.Query `json:"query"`}
type AuditEventQueryPayload struct{Cursor string `json:"cursor,omitempty"`;Limit uint32 `json:"limit,omitempty"`;ActorID string `json:"actor_id,omitempty"`;TargetKind string `json:"target_kind,omitempty"`;TargetID string `json:"target_id,omitempty"`;Action string `json:"action,omitempty"`;EffectID string `json:"effect_id,omitempty"`;TraceID string `json:"trace_id,omitempty"`;Classes []audit.EventClass `json:"classes,omitempty"`;Outcomes []audit.Outcome `json:"outcomes,omitempty"`;From time.Time `json:"from,omitempty"`;To time.Time `json:"to,omitempty"`}
type AuditEventPageResult struct{Items []audit.Record `json:"items"`;NextCursor string `json:"next_cursor,omitempty"`}
type AuditExportPayload struct{Query audit.Query `json:"query"`;Format audit.ExportFormat `json:"format"`;IncludeCheckpoint bool `json:"include_checkpoint"`;MaximumRecords uint32 `json:"maximum_records"`}
type AuditExportResult struct{Manifest audit.ExportManifest `json:"manifest"`;ContentBase64 string `json:"content_base64"`}

func registerAuditContracts(registry *Registry)error{
	read:=identity.MustPermission("audit:read");manage:=identity.MustPermission("audit:manage")
	definitions:=[]Operation{
		{Name:"audit.event.list",Permission:read,Assurance:identity.AssuranceMFA,Auth:AuthRequired,NewPayload:func()any{return &AuditQueryPayload{}},ValidatePayload:validateAuditQuery,ResolveScope:tenantScope},
		{Name:"audit.event.query",Permission:read,Assurance:identity.AssuranceMFA,Auth:AuthRequired,NewPayload:func()any{return &AuditEventQueryPayload{}},ValidatePayload:validateAuditEventQuery,ResolveScope:tenantScope},
		{Name:"audit.export.create",Permission:read,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,MaximumResponseBytes:8<<20,NewPayload:func()any{return &AuditExportPayload{}},ValidatePayload:validateAuditExport,ResolveScope:tenantScope},
		{Name:"audit.export",Permission:read,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,MaximumResponseBytes:8<<20,NewPayload:func()any{return &AuditExportPayload{}},ValidatePayload:validateAuditExport,ResolveScope:tenantScope},
		{Name:"audit.checkpoint.create",Permission:manage,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:tenantScope},
		{Name:"audit.integrity.verify",Permission:manage,Assurance:identity.AssuranceMFA,Auth:AuthRequired,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:tenantScope},
		{Name:"audit.verify",Permission:manage,Assurance:identity.AssuranceMFA,Auth:AuthRequired,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:tenantScope},
	}
	for _,definition:=range definitions{if err:=register(registry,definition);err!=nil{return err}}
	return nil
}

func validateAuditQuery(value any)error{return validateAuditQueryValue(value.(*AuditQueryPayload).Query)}
func validateAuditEventQuery(value any)error{payload:=value.(*AuditEventQueryPayload);if payload.Limit==0{payload.Limit=100};if payload.Limit>1000||payload.Cursor!=""&&!canonicalAuditCursor(payload.Cursor){return invalid("audit cursor")};return validateAuditQueryValue(audit.Query{ActorID:payload.ActorID,TargetKind:payload.TargetKind,TargetID:payload.TargetID,Action:payload.Action,EffectID:payload.EffectID,TraceID:payload.TraceID,Classes:payload.Classes,Outcomes:payload.Outcomes,From:payload.From,To:payload.To,Limit:payload.Limit})}
func validateAuditQueryValue(query audit.Query)error{if query.Limit>1000||len(query.Classes)>16||len(query.Outcomes)>16||query.To.Before(query.From)&&!query.To.IsZero()||!safeAuditFilter(query.ActorID)||!safeAuditFilter(query.TargetKind)||!safeAuditFilter(query.TargetID)||!safeAuditFilter(query.Action)||!safeAuditFilter(query.EffectID)||!safeAuditFilter(query.TraceID){return invalid("audit query")};return nil}
func validateAuditExport(value any)error{payload:=value.(*AuditExportPayload);if payload.MaximumRecords==0{payload.MaximumRecords=1000};if payload.Format==""{payload.Format=audit.ExportJSONLines};if validateAuditQueryValue(payload.Query)!=nil||payload.MaximumRecords>1000||(payload.Format!=audit.ExportJSONLines&&payload.Format!=audit.ExportCanonicalJSON){return invalid("audit export")};return nil}
func safeAuditFilter(value string)bool{return value==""||len(value)<=192&&!strings.ContainsAny(value,"\x00\r\n\t")}
func canonicalAuditCursor(value string)bool{sequence,err:=strconv.ParseUint(value,10,64);return err==nil&&strconv.FormatUint(sequence,10)==value}

func bindAudit(registry *Registry,services DomainServices)error{
	if services.Audit==nil||services.Audit.Writer==nil{return nil}
	if err:=registry.Bind("audit.event.list",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){query:=value.(*AuditQueryPayload).Query;query.TenantID=inv.Request.TenantID;if query.Limit==0{query.Limit=100};records,err:=services.Audit.Writer.Query(ctx,query);if err!=nil{return OperationResult{},mapAuditError(err)};return OperationResult{Status:http.StatusOK,Value:records},nil});err!=nil{return err}
	if err:=registry.Bind("audit.event.query",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*AuditEventQueryPayload);after:=uint64(0);if payload.Cursor!=""{after,_=strconv.ParseUint(payload.Cursor,10,64)};query:=audit.Query{TenantID:inv.Request.TenantID,ActorID:payload.ActorID,TargetKind:payload.TargetKind,TargetID:payload.TargetID,Action:payload.Action,EffectID:payload.EffectID,TraceID:payload.TraceID,Classes:payload.Classes,Outcomes:payload.Outcomes,From:payload.From,To:payload.To,AfterSequence:after,Limit:payload.Limit};records,err:=services.Audit.Writer.Query(ctx,query);if err!=nil{return OperationResult{},mapAuditError(err)};next:="";if len(records)==int(payload.Limit)&&len(records)>0{next=strconv.FormatUint(records[len(records)-1].Sequence,10)};return OperationResult{Status:http.StatusOK,Value:AuditEventPageResult{Items:records,NextCursor:next}},nil});err!=nil{return err}
	export:=func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*AuditExportPayload);payload.Query.TenantID=inv.Request.TenantID;buffer:=&boundedAuditBuffer{maximum:5<<20};manifest,err:=services.Audit.Writer.Export(ctx,audit.ExportRequest{Query:payload.Query,Format:payload.Format,IncludeCheckpoint:payload.IncludeCheckpoint,MaximumRecords:payload.MaximumRecords},buffer);if err!=nil{return OperationResult{},mapAuditError(err)};encoded:=base64.RawStdEncoding.EncodeToString(buffer.Bytes());buffer.Reset();return OperationResult{Status:http.StatusCreated,Value:AuditExportResult{Manifest:manifest,ContentBase64:encoded}},nil}
	if err:=registry.Bind("audit.export.create",export);err!=nil{return err};if err:=registry.Bind("audit.export",export);err!=nil{return err}
	if err:=registry.Bind("audit.checkpoint.create",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){checkpoint,err:=services.Audit.Writer.Checkpoint(ctx);if err!=nil{return OperationResult{},mapAuditError(err)};return OperationResult{Status:http.StatusCreated,Value:checkpoint},nil});err!=nil{return err}
	verify:=func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){checkpoint,err:=services.Audit.Writer.Verify(ctx);if err!=nil{return OperationResult{},mapAuditError(err)};return OperationResult{Status:http.StatusOK,Value:checkpoint},nil};if err:=registry.Bind("audit.integrity.verify",verify);err!=nil{return err};return registry.Bind("audit.verify",verify)
}

type boundedAuditBuffer struct{buffer bytes.Buffer;maximum int}
func (writer *boundedAuditBuffer)Write(value []byte)(int,error){if writer.buffer.Len()+len(value)>writer.maximum{return 0,ErrResponseTooLarge};return writer.buffer.Write(value)}
func (writer *boundedAuditBuffer)Bytes()[]byte{return writer.buffer.Bytes()}
func (writer *boundedAuditBuffer)Reset(){content:=writer.buffer.Bytes();clearSecret(content);writer.buffer.Reset()}
func mapAuditError(err error)error{switch{case err==nil:return nil;case errors.Is(err,audit.ErrInvalid):return ErrInvalidRequest;case errors.Is(err,audit.ErrNotFound):return ErrNotFound;case errors.Is(err,audit.ErrConflict):return ErrConflict;case errors.Is(err,audit.ErrIntegrity):return ErrUnavailable;case errors.Is(err,audit.ErrCapacity):return ErrResponseTooLarge;default:return err}}
