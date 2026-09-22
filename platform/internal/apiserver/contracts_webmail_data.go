package apiserver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	securewebmail "github.com/aonsyed/cyberpanel/platform/internal/webmail"
	"github.com/aonsyed/cyberpanel/platform/internal/webmaildata"
)

type WebmailDataSessionPayload struct { WebmailEpochPayload; MailboxID mail.MailboxID `json:"mailbox_id"` }
type WebmailDataContactPagePayload struct { WebmailDataSessionPayload; Search string `json:"search,omitempty"`; Cursor string `json:"cursor,omitempty"`; Limit uint16 `json:"limit,omitempty"` }
type WebmailDataContactPayload struct { WebmailDataSessionPayload; Contact webmaildata.Contact `json:"contact"`; Mask webmaildata.FieldMask `json:"field_mask,omitempty"` }
type WebmailDataContactDeletePayload struct { WebmailDataSessionPayload; RetainSeconds uint64 `json:"retain_seconds"` }
type WebmailDataContactMergePayload struct { WebmailDataSessionPayload; Request webmaildata.MergeContactRequest `json:"request"` }
type WebmailDataContactImportPayload struct { WebmailDataSessionPayload; SourceRef string `json:"source_ref"`; Format webmaildata.InterchangeFormat `json:"format"`; Mapping map[string]string `json:"mapping,omitempty"`; PreviewOnly bool `json:"preview_only"`; DuplicatePolicy webmaildata.DuplicatePolicy `json:"duplicate_policy"` }
type WebmailDataContactExportPayload struct { WebmailDataSessionPayload; Format webmaildata.InterchangeFormat `json:"format"`; MaximumRows int `json:"maximum_rows"`; MaximumBytes int64 `json:"maximum_bytes"` }
type WebmailDataGroupPagePayload struct { WebmailDataSessionPayload; Cursor string `json:"cursor,omitempty"`; Limit uint16 `json:"limit,omitempty"` }
type WebmailDataGroupPayload struct { WebmailDataSessionPayload; Group webmaildata.ContactGroup `json:"group"` }
type WebmailDataIdentityPayload struct { WebmailDataSessionPayload; Identity webmaildata.Identity `json:"identity"` }
type WebmailDataPreferencesPayload struct { WebmailDataSessionPayload; Preferences webmaildata.WebmailPreferences `json:"preferences"` }
type WebmailDataSievePayload struct { WebmailDataSessionPayload; Rule webmaildata.SieveRule `json:"rule"`; Enabled *bool `json:"enabled,omitempty"` }
type WebmailDataSieveOrderPayload struct { WebmailDataSessionPayload; OrderedIDs []string `json:"ordered_ids"`; Expected map[string]uint64 `json:"expected_revisions"` }
type WebmailDataSieveValidationPayload struct { WebmailDataSessionPayload; Rules []webmaildata.SieveRule `json:"rules,omitempty"`; ExpertText string `json:"expert_text,omitempty"` }
type WebmailDataSieveExpertPayload struct { WebmailDataSessionPayload; Text string `json:"text"`; Expected map[string]uint64 `json:"expected_revisions"` }
type WebmailDataSieveTestPayload struct { WebmailDataSessionPayload; Message webmaildata.SieveTestMessage `json:"message"` }
type WebmailDataVacationPayload struct { WebmailDataSessionPayload; Request webmaildata.VacationRequest `json:"request"`; Enabled *bool `json:"enabled,omitempty"` }
type WebmailDataVacationListPayload struct { WebmailDataSessionPayload; Cursor string `json:"cursor,omitempty"` }
type WebmailDataBackupExportPayload struct { WebmailDataSessionPayload; MaximumObjects int `json:"maximum_objects"`; MaximumBytes int64 `json:"maximum_bytes"` }
type WebmailDataBackupRestorePayload struct { WebmailDataSessionPayload; SourceRef string `json:"source_ref"`; Manifest webmaildata.BackupManifest `json:"manifest"`; ExpectedCurrent webmaildata.BackupPreconditions `json:"expected_current"`; Mode webmaildata.RestoreMode `json:"mode"` }

type WebmailDataBlob struct { Reference string `json:"reference"`; ContentType string `json:"content_type"`; Bytes int64 `json:"bytes"` }
type WebmailDataImportSource interface { io.ReadCloser; io.Seeker }
type WebmailDataExportSink interface { io.WriteCloser; Commit(context.Context) (WebmailDataBlob, error); Abort(context.Context) error }
type WebmailDataBlobStore interface {
	OpenWebmailDataImport(context.Context, webmaildata.Scope, string, string, int64) (WebmailDataImportSource, error)
	CreateWebmailDataExport(context.Context, webmaildata.Scope, string, string) (WebmailDataExportSink, error)
}

type WebmailDataMutation[T any] struct { OperationID string `json:"operation_id"`; Revision uint64 `json:"revision,omitempty"`; Resource T `json:"resource"` }
type WebmailDataSieveList struct { Rules []webmaildata.SieveRule `json:"rules"`; Active webmaildata.SieveActivation `json:"active"` }
type WebmailDataIdentityList struct { Identities []webmaildata.Identity `json:"identities"`; PreferencesRevision uint64 `json:"preferences_revision"` }
type WebmailDataSieveValidationResult struct { Rules []webmaildata.SieveRule `json:"rules"`; Program webmaildata.SieveProgram `json:"program"` }
type WebmailDataExportResult struct { Blob WebmailDataBlob `json:"blob"`; Contacts int `json:"contacts,omitempty"`; Manifest *webmaildata.BackupManifest `json:"manifest,omitempty"` }

func registerWebmailDataContracts(registry *Registry) error {
	manage := identity.MustPermission("mail:manage")
	password, mfa := identity.AssurancePassword, identity.AssuranceMFA
	definitions := []Operation{
		{Name:"webmail.data.contact.list",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataContactPagePayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.contact.get",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataSessionPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.contact.create",Permission:manage,Assurance:password,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataContactPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.contact.update",Permission:manage,Assurance:password,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataContactPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.contact.merge",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataContactMergePayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.contact.delete",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataContactDeletePayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.contact.import",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataContactImportPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.contact.export",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataContactExportPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.group.list",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataGroupPagePayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.group.get",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataSessionPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.group.save",Permission:manage,Assurance:password,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataGroupPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.group.delete",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataSessionPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.identity.list",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataSessionPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.identity.save",Permission:manage,Assurance:password,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataIdentityPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.identity.delete",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataSessionPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.preferences.get",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataSessionPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.preferences.save",Permission:manage,Assurance:password,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataPreferencesPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.sieve.list",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataSessionPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.sieve.get",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataSessionPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.sieve.save",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataSievePayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.sieve.delete",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataSessionPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.sieve.enabled",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataSievePayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.sieve.order",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataSieveOrderPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.sieve.validate",Permission:manage,Assurance:mfa,Auth:AuthRequired,MaximumBodyBytes:int64(webmaildata.MaximumSieveTextBytes+(64<<10)),NewPayload:func()any{return &WebmailDataSieveValidationPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.sieve.expert.replace",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,MaximumBodyBytes:int64(webmaildata.MaximumSieveTextBytes+(64<<10)),NewPayload:func()any{return &WebmailDataSieveExpertPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.sieve.test",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataSieveTestPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.vacation.list",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataVacationListPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.vacation.get",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataVacationPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.vacation.create",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataVacationPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.vacation.update",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataVacationPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.vacation.enabled",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataVacationPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.vacation.delete",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataVacationPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.backup.export",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataBackupExportPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.backup.preconditions",Permission:manage,Assurance:password,Auth:AuthRequired,NewPayload:func()any{return &WebmailDataSessionPayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
		{Name:"webmail.data.backup.restore",Permission:manage,Assurance:mfa,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebmailDataBackupRestorePayload{}},ValidatePayload:validateWebmailDataPayload,ResolveScope:tenantScope},
	}
	for _, definition := range definitions { definition.ResolveScope = webmailDataScope; if err := register(registry, definition); err != nil { return err } }
	return nil
}

func bindWebmailDataContracts(registry *Registry, services DomainServices) error {
	provider,ok:=services.WebmailEdge.(interface{SecureWebmail() *securewebmail.Service})
	if services.WebmailData == nil || !ok || provider.SecureWebmail()==nil { return nil }
	bind := func(name string, handler func(context.Context, Invocation, any, webmaildata.Call) (OperationResult, error)) error {
		return registry.Bind(name, func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
			sessionPayload, ok := webmailDataSession(value); if !ok { return OperationResult{}, ErrInvalidRequest }
			call,err:=secureWebmailDataCall(ctx,provider.SecureWebmail(),invocation,*sessionPayload);if err!=nil{return OperationResult{},err}
			return handler(ctx, invocation, value, call)
		})
	}
	if err := bind("webmail.data.contact.list", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){p:=value.(*WebmailDataContactPagePayload);page,err:=services.WebmailData.ListContacts(ctx,call,p.Search,p.Cursor,int(p.Limit));return OperationResult{Status:http.StatusOK,Value:page},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.contact.get", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.InspectContact(ctx,call,inv.Request.ResourceID);return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Revision},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.contact.create", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.CreateContact(ctx,call,value.(*WebmailDataContactPayload).Contact);return webmailDataResult(http.StatusCreated,call,result,result.Revision,err)});err!=nil{return err}
	if err := bind("webmail.data.contact.update", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){p:=value.(*WebmailDataContactPayload);result,err:=services.WebmailData.UpdateContact(ctx,call,inv.Request.ResourceID,inv.Request.ExpectedGeneration,p.Contact,p.Mask);return webmailDataResult(http.StatusOK,call,result,result.Revision,err)});err!=nil{return err}
	if err := bind("webmail.data.contact.merge", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.MergeContacts(ctx,call,value.(*WebmailDataContactMergePayload).Request);return webmailDataResult(http.StatusOK,call,result,result.Revision,err)});err!=nil{return err}
	if err := bind("webmail.data.contact.delete", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){p:=value.(*WebmailDataContactDeletePayload);err:=services.WebmailData.DeleteContact(ctx,call,inv.Request.ResourceID,inv.Request.ExpectedGeneration,time.Duration(p.RetainSeconds)*time.Second);return OperationResult{Status:http.StatusNoContent},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.contact.import", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){if services.WebmailDataBlobs==nil{return OperationResult{},ErrUnavailable};p:=value.(*WebmailDataContactImportPayload);source,err:=services.WebmailDataBlobs.OpenWebmailDataImport(ctx,call.Scope,call.ActorID,p.SourceRef,64<<20);if err!=nil{return OperationResult{},mapWebmailDataError(err)};defer source.Close();request:=webmaildata.ImportRequest{Format:p.Format,Reader:source,Mapping:p.Mapping,Limits:webmaildata.DefaultStreamLimits(),PreviewOnly:p.PreviewOnly,DuplicatePolicy:p.DuplicatePolicy,ImportedAt:time.Now().UTC()};result,err:=services.WebmailData.ImportContacts(ctx,call,request);return OperationResult{Status:http.StatusOK,Value:result},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.contact.export", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){if services.WebmailDataBlobs==nil{return OperationResult{},ErrUnavailable};p:=value.(*WebmailDataContactExportPayload);contentType:="text/csv";if p.Format==webmaildata.FormatVCard{contentType="text/vcard"};sink,err:=services.WebmailDataBlobs.CreateWebmailDataExport(ctx,call.Scope,call.ActorID,contentType);if err!=nil{return OperationResult{},mapWebmailDataError(err)};committed:=false;defer func(){if !committed{_ = sink.Abort(ctx)}}();limits:=webmaildata.DefaultStreamLimits();limits.MaximumRows=p.MaximumRows;limits.MaximumBytes=p.MaximumBytes;count,_,err:=services.WebmailData.ExportContacts(ctx,call,p.Format,sink,limits);if err!=nil{sink.Close();return OperationResult{},mapWebmailDataError(err)};if err=sink.Close();err!=nil{return OperationResult{},err};blob,err:=sink.Commit(ctx);committed=err==nil;return OperationResult{Status:http.StatusCreated,Value:WebmailDataExportResult{Blob:blob,Contacts:count}},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.group.list", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){p:=value.(*WebmailDataGroupPagePayload);items,next,err:=services.WebmailData.ListGroups(ctx,call,p.Cursor,int(p.Limit));return OperationResult{Status:http.StatusOK,Value:map[string]any{"items":items,"next_cursor":next}},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.group.get", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.InspectGroup(ctx,call,inv.Request.ResourceID);return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Revision},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.group.save", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.SaveGroup(ctx,call,value.(*WebmailDataGroupPayload).Group,inv.Request.ExpectedGeneration);return webmailDataResult(http.StatusOK,call,result,result.Revision,err)});err!=nil{return err}
	if err := bind("webmail.data.group.delete", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){err:=services.WebmailData.DeleteGroup(ctx,call,inv.Request.ResourceID,inv.Request.ExpectedGeneration);return OperationResult{Status:http.StatusNoContent},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.identity.list", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){items,revision,err:=services.WebmailData.ListIdentities(ctx,call);return OperationResult{Status:http.StatusOK,Value:WebmailDataIdentityList{Identities:items,PreferencesRevision:revision},Generation:revision},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.identity.save", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){identityValue,revision,err:=services.WebmailData.SaveIdentity(ctx,call,value.(*WebmailDataIdentityPayload).Identity,inv.Request.ExpectedGeneration);return webmailDataResult(http.StatusOK,call,identityValue,revision,err)});err!=nil{return err}
	if err := bind("webmail.data.identity.delete", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){revision,err:=services.WebmailData.DeleteIdentity(ctx,call,inv.Request.ResourceID,inv.Request.ExpectedGeneration);return OperationResult{Status:http.StatusOK,Generation:revision,Value:map[string]uint64{"preferences_revision":revision}},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.preferences.get", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.GetPreferences(ctx,call);return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Revision},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.preferences.save", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.SavePreferences(ctx,call,value.(*WebmailDataPreferencesPayload).Preferences,inv.Request.ExpectedGeneration);return webmailDataResult(http.StatusOK,call,result,result.Revision,err)});err!=nil{return err}
	if err := bind("webmail.data.sieve.list", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){rules,active,err:=services.WebmailData.ListSieveRules(ctx,call);return OperationResult{Status:http.StatusOK,Value:WebmailDataSieveList{Rules:rules,Active:active},Generation:active.Generation},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.sieve.get", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.GetSieveRule(ctx,call,inv.Request.ResourceID);return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Revision},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.sieve.save", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){rule,active,err:=services.WebmailData.SaveSieveRule(ctx,call,value.(*WebmailDataSievePayload).Rule,inv.Request.ExpectedGeneration);return OperationResult{Status:http.StatusOK,Value:map[string]any{"rule":rule,"active":active},Generation:rule.Revision},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.sieve.delete", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){active,err:=services.WebmailData.DeleteSieveRule(ctx,call,inv.Request.ResourceID,inv.Request.ExpectedGeneration);return OperationResult{Status:http.StatusOK,Value:active,Generation:active.Generation},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.sieve.enabled", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){p:=value.(*WebmailDataSievePayload);if p.Enabled==nil{return OperationResult{},ErrInvalidRequest};rule,active,err:=services.WebmailData.SetSieveRuleEnabled(ctx,call,inv.Request.ResourceID,inv.Request.ExpectedGeneration,*p.Enabled);return OperationResult{Status:http.StatusOK,Value:map[string]any{"rule":rule,"active":active},Generation:rule.Revision},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.sieve.order", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){p:=value.(*WebmailDataSieveOrderPayload);active,err:=services.WebmailData.ReorderSieveRules(ctx,call,p.OrderedIDs,p.Expected);return OperationResult{Status:http.StatusOK,Value:active,Generation:active.Generation},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.sieve.validate", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){p:=value.(*WebmailDataSieveValidationPayload);if p.ExpertText!=""{rules,program,err:=services.WebmailData.ValidateExpertSieve(ctx,call,p.ExpertText);return OperationResult{Status:http.StatusOK,Value:WebmailDataSieveValidationResult{Rules:rules,Program:program}},mapWebmailDataError(err)};program,err:=services.WebmailData.ValidateSieveRules(ctx,call,p.Rules);return OperationResult{Status:http.StatusOK,Value:WebmailDataSieveValidationResult{Rules:program.Rules,Program:program}},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.sieve.expert.replace", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){p:=value.(*WebmailDataSieveExpertPayload);rules,active,err:=services.WebmailData.SubmitExpertSieve(ctx,call,p.Text,p.Expected);return OperationResult{Status:http.StatusOK,Value:WebmailDataSieveList{Rules:rules,Active:active},Generation:active.Generation},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.sieve.test", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.TestSieve(ctx,call,value.(*WebmailDataSieveTestPayload).Message);return OperationResult{Status:http.StatusOK,Value:result},mapWebmailDataError(err)});err!=nil{return err}
	if err:=bind("webmail.data.vacation.list",func(ctx context.Context,inv Invocation,value any,call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.DiscoverVacation(ctx,call,value.(*WebmailDataVacationListPayload).Cursor);return OperationResult{Status:http.StatusOK,Value:result,Generation:result.MailboxGeneration},mapWebmailDataError(err)});err!=nil{return err}
	for name, action := range map[string]string{"webmail.data.vacation.get":"get","webmail.data.vacation.create":"create","webmail.data.vacation.update":"update","webmail.data.vacation.enabled":"enabled","webmail.data.vacation.delete":"delete"} { name,action:=name,action;if err:=bind(name,func(ctx context.Context,inv Invocation,value any,call webmaildata.Call)(OperationResult,error){p:=value.(*WebmailDataVacationPayload);switch action{case"get":result,err:=services.WebmailData.InspectVacation(ctx,call,p.Request);return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Generation},mapWebmailDataError(err);case"create":result,err:=services.WebmailData.CreateVacation(ctx,call,p.Request);return OperationResult{Status:http.StatusCreated,Value:result,Generation:result.Generation},mapWebmailDataError(err);case"update":result,err:=services.WebmailData.UpdateVacation(ctx,call,p.Request);return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Generation},mapWebmailDataError(err);case"enabled":if p.Enabled==nil{return OperationResult{},ErrInvalidRequest};result,err:=services.WebmailData.SetVacationEnabled(ctx,call,p.Request,*p.Enabled);return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Generation},mapWebmailDataError(err);default:err:=services.WebmailData.DeleteVacation(ctx,call,p.Request);return OperationResult{Status:http.StatusNoContent},mapWebmailDataError(err)}});err!=nil{return err} }
	if err := bind("webmail.data.backup.export", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){if services.WebmailDataBlobs==nil{return OperationResult{},ErrUnavailable};p:=value.(*WebmailDataBackupExportPayload);sink,err:=services.WebmailDataBlobs.CreateWebmailDataExport(ctx,call.Scope,call.ActorID,"application/x-ndjson");if err!=nil{return OperationResult{},err};committed:=false;defer func(){if !committed{_ = sink.Abort(ctx)}}();manifest,err:=services.WebmailData.ExportSettingsBackup(ctx,call,sink,p.MaximumObjects,p.MaximumBytes);if err!=nil{sink.Close();return OperationResult{},mapWebmailDataError(err)};if err=sink.Close();err!=nil{return OperationResult{},err};blob,err:=sink.Commit(ctx);committed=err==nil;return OperationResult{Status:http.StatusCreated,Value:WebmailDataExportResult{Blob:blob,Manifest:&manifest}},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.backup.preconditions", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){result,err:=services.WebmailData.CurrentBackupPreconditions(ctx,call);return OperationResult{Status:http.StatusOK,Value:result,Generation:result.ActiveSieveGeneration},mapWebmailDataError(err)});err!=nil{return err}
	if err := bind("webmail.data.backup.restore", func(ctx context.Context, inv Invocation, value any, call webmaildata.Call)(OperationResult,error){if services.WebmailDataBlobs==nil{return OperationResult{},ErrUnavailable};p:=value.(*WebmailDataBackupRestorePayload);source,err:=services.WebmailDataBlobs.OpenWebmailDataImport(ctx,call.Scope,call.ActorID,p.SourceRef,p.Manifest.Bytes);if err!=nil{return OperationResult{},err};defer source.Close();err=services.WebmailData.RestoreSettingsBackup(ctx,webmaildata.RestoreRequest{Call:call,Reader:source,Manifest:p.Manifest,ExpectedCurrent:p.ExpectedCurrent,Mode:p.Mode});return OperationResult{Status:http.StatusOK,Value:p.Manifest},mapWebmailDataError(err)});err!=nil{return err}
	return nil
}

func webmailDataScope(request RequestEnvelope, value any) (identity.Scope, error) {
	scope, err := tenantScope(request, value); if err != nil { return identity.Scope{}, err }
	invalidScope := func() (identity.Scope, error) { return identity.Scope{}, invalid("webmail data resource scope") }
	empty := request.ResourceID == "" && request.ExpectedGeneration == 0
	safe := safeMailOpaque(request.ResourceID)
	switch request.Operation {
	case "webmail.data.vacation.list":
		if !empty { return invalidScope() }
	case "webmail.data.contact.list", "webmail.data.contact.export", "webmail.data.group.list", "webmail.data.identity.list", "webmail.data.preferences.get", "webmail.data.sieve.list", "webmail.data.sieve.validate", "webmail.data.sieve.test", "webmail.data.backup.export", "webmail.data.backup.preconditions":
		if !empty { return invalidScope() }
	case "webmail.data.contact.import":
		if request.ExpectedGeneration != 0 || request.ResourceID != value.(*WebmailDataContactImportPayload).SourceRef || !validEdgeID(request.ResourceID) { return invalidScope() }
	case "webmail.data.backup.restore":
		if request.ExpectedGeneration != 0 || request.ResourceID != value.(*WebmailDataBackupRestorePayload).SourceRef || !validEdgeID(request.ResourceID) { return invalidScope() }
	case "webmail.data.contact.get", "webmail.data.group.get", "webmail.data.sieve.get":
		if !safe || request.ExpectedGeneration != 0 { return invalidScope() }
	case "webmail.data.contact.delete", "webmail.data.group.delete", "webmail.data.identity.delete", "webmail.data.sieve.delete", "webmail.data.sieve.enabled":
		if !safe || request.ExpectedGeneration == 0 { return invalidScope() }
	case "webmail.data.contact.create":
		if !safe || request.ExpectedGeneration != 0 || value.(*WebmailDataContactPayload).Contact.ID != request.ResourceID { return invalidScope() }
	case "webmail.data.contact.update":
		contact := value.(*WebmailDataContactPayload).Contact
		if !safe || request.ExpectedGeneration == 0 || contact.ID != "" && contact.ID != request.ResourceID { return invalidScope() }
	case "webmail.data.contact.merge":
		merge := value.(*WebmailDataContactMergePayload).Request
		if !safe || request.ExpectedGeneration == 0 || merge.TargetID != request.ResourceID || merge.TargetRevision != request.ExpectedGeneration { return invalidScope() }
	case "webmail.data.group.save":
		if !safe || value.(*WebmailDataGroupPayload).Group.ID != request.ResourceID { return invalidScope() }
	case "webmail.data.identity.save":
		if !safe || request.ExpectedGeneration == 0 || value.(*WebmailDataIdentityPayload).Identity.ID != request.ResourceID { return invalidScope() }
	case "webmail.data.preferences.save":
		if request.ResourceID != "preferences" { return invalidScope() }
	case "webmail.data.sieve.save":
		if !safe || value.(*WebmailDataSievePayload).Rule.ID != request.ResourceID { return invalidScope() }
	case "webmail.data.sieve.order":
		if request.ResourceID != "order" || request.ExpectedGeneration != 0 { return invalidScope() }
	case "webmail.data.sieve.expert.replace":
		if request.ResourceID != "expert" || request.ExpectedGeneration != 0 { return invalidScope() }
	case "webmail.data.vacation.create":
		vacation := value.(*WebmailDataVacationPayload).Request
		if !safe || request.ExpectedGeneration != 0 || vacation.ExpectedGeneration != 0 || string(vacation.RuleID) != request.ResourceID { return invalidScope() }
	case "webmail.data.vacation.get", "webmail.data.vacation.update", "webmail.data.vacation.enabled", "webmail.data.vacation.delete":
		vacation := value.(*WebmailDataVacationPayload).Request
		if !safe || request.ExpectedGeneration == 0 || vacation.ExpectedGeneration != request.ExpectedGeneration || string(vacation.RuleID) != request.ResourceID { return invalidScope() }
	default:
		return invalidScope()
	}
	return scope, nil
}

func validateWebmailDataPayload(value any) error {
	session, ok := webmailDataSession(value); if !ok || !validWebmailEpoch(session.AuthorizationEpoch) || !safeMailOpaque(string(session.MailboxID)) { return invalid("webmail data mailbox authorization") }
	switch payload := value.(type) {
	case *WebmailDataVacationListPayload: if payload.Cursor!=""&&!safeMailOpaque(payload.Cursor){return invalid("vacation cursor")}
	case *WebmailDataContactPagePayload: if payload.Limit == 0 { payload.Limit = 100 }; if payload.Limit > webmaildata.MaximumPageSize || len(payload.Cursor) > 2048 || len(payload.Search) > 512 { return invalid("contact page") }
	case *WebmailDataContactDeletePayload: if payload.RetainSeconds < 86400 || payload.RetainSeconds > 315360000 { return invalid("contact retention") }
	case *WebmailDataContactImportPayload: if !validEdgeID(payload.SourceRef) || payload.Format != webmaildata.FormatCSV && payload.Format != webmaildata.FormatVCard || payload.DuplicatePolicy != webmaildata.DuplicateReject && payload.DuplicatePolicy != webmaildata.DuplicateSkip && payload.DuplicatePolicy != webmaildata.DuplicateMerge || len(payload.Mapping) > 128 { return invalid("contact import") }
	case *WebmailDataContactExportPayload: if payload.Format != webmaildata.FormatCSV && payload.Format != webmaildata.FormatVCard || payload.MaximumRows < 1 || payload.MaximumRows > webmaildata.MaximumBackupObjects || payload.MaximumBytes < 1 || payload.MaximumBytes > webmaildata.MaximumBackupBytes { return invalid("contact export") }
	case *WebmailDataGroupPagePayload: if payload.Limit == 0 { payload.Limit = 100 }; if payload.Limit > webmaildata.MaximumPageSize || len(payload.Cursor) > 128 { return invalid("group page") }
	case *WebmailDataSieveOrderPayload: if len(payload.OrderedIDs) == 0 || len(payload.OrderedIDs) > webmaildata.MaximumSieveRules || len(payload.Expected) != len(payload.OrderedIDs) { return invalid("sieve order") }
	case *WebmailDataSieveValidationPayload: if (len(payload.Rules) == 0) == (payload.ExpertText == "") || len(payload.Rules) > webmaildata.MaximumSieveRules || len(payload.ExpertText) > webmaildata.MaximumSieveTextBytes { return invalid("sieve validation") }
	case *WebmailDataSieveExpertPayload: if payload.Text == "" || len(payload.Text) > webmaildata.MaximumSieveTextBytes || len(payload.Expected) > webmaildata.MaximumSieveRules { return invalid("expert sieve") }
	case *WebmailDataBackupExportPayload: if payload.MaximumObjects < 1 || payload.MaximumObjects > webmaildata.MaximumBackupObjects || payload.MaximumBytes < 1 || payload.MaximumBytes > webmaildata.MaximumBackupBytes { return invalid("webmail backup") }
	case *WebmailDataBackupRestorePayload: if !validEdgeID(payload.SourceRef) || payload.Manifest.Bytes < 0 || payload.Manifest.Bytes > webmaildata.MaximumBackupBytes { return invalid("webmail restore") }
	}
	return nil
}

func webmailDataSession(value any) (*WebmailDataSessionPayload, bool) {
	switch payload := value.(type) {
	case *WebmailDataVacationListPayload: return &payload.WebmailDataSessionPayload,true
	case *WebmailDataSessionPayload:return payload,true
	case *WebmailDataContactPagePayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataContactPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataContactDeletePayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataContactMergePayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataContactImportPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataContactExportPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataGroupPagePayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataGroupPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataIdentityPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataPreferencesPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataSievePayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataSieveOrderPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataSieveValidationPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataSieveExpertPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataSieveTestPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataVacationPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataBackupExportPayload:return &payload.WebmailDataSessionPayload,true
	case *WebmailDataBackupRestorePayload:return &payload.WebmailDataSessionPayload,true
	default:return nil,false
	}
}

type webmailDataMailboxAuthority interface { AuthorizeMailboxScope(context.Context,securewebmail.Principal,string,string,uint64)error }
func secureWebmailDataCall(ctx context.Context,authority webmailDataMailboxAuthority,invocation Invocation,payload WebmailDataSessionPayload)(webmaildata.Call,error) {
	principal,err:=secureWebmailPrincipal(invocation);if err!=nil{return webmaildata.Call{},err}
	if authority==nil||!validWebmailEpoch(payload.AuthorizationEpoch)||!safeMailOpaque(string(payload.MailboxID)){return webmaildata.Call{},ErrInvalidRequest}
	if err=authority.AuthorizeMailboxScope(ctx,principal,invocation.Request.TenantID,string(payload.MailboxID),payload.AuthorizationEpoch);err!=nil{return webmaildata.Call{},mapSecureWebmailError(err)}
	edge:=edgeCall(invocation)
	return webmaildata.Call{ActorID:principal.UserID,OperationID:edge.CommandID,Scope:webmaildata.Scope{TenantID:invocation.Request.TenantID,UserID:principal.UserID,MailboxID:string(payload.MailboxID)},StepUpProof:edge.CredentialID},nil
}
func webmailDataResult[T any](status int, call webmaildata.Call, resource T, revision uint64, err error)(OperationResult,error){if err!=nil{return OperationResult{},mapWebmailDataError(err)};return OperationResult{Status:status,Value:WebmailDataMutation[T]{OperationID:call.OperationID,Revision:revision,Resource:resource},Generation:revision},nil}
func mapWebmailDataError(err error) error { switch { case err==nil:return nil;case errors.Is(err,webmaildata.ErrInvalid),errors.Is(err,webmaildata.ErrLimit),errors.Is(err,mail.ErrInvalidCommand):return ErrInvalidRequest;case errors.Is(err,webmaildata.ErrUnauthorized),errors.Is(err,mail.ErrUnauthorized):return ErrForbidden;case errors.Is(err,webmaildata.ErrStepUp):return ErrAssuranceRequired;case errors.Is(err,webmaildata.ErrNotFound),errors.Is(err,mail.ErrNotFound):return ErrNotFound;case errors.Is(err,webmaildata.ErrConflict),errors.Is(err,webmaildata.ErrDuplicate),errors.Is(err,webmaildata.ErrRetained),errors.Is(err,mail.ErrConflict):return ErrConflict;case errors.Is(err,mail.ErrRateLimited):return ErrRateLimited;case errors.Is(err,webmaildata.ErrActivation),errors.Is(err,webmaildata.ErrIntegrity),errors.Is(err,mail.ErrAmbiguous),errors.Is(err,mail.ErrInvalidReceipt):return ErrUnavailable;default:return err} }
