package apiserver

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type CertificatePagePayload struct{Limit uint16 `json:"limit"`;Cursor string `json:"cursor,omitempty"`}
type CertificatePageResult struct{Items any `json:"items"`;NextCursor string `json:"next_cursor,omitempty"`}
type CertificateAccountPayload struct{Account certificates.AccountSpec `json:"account"`}
type CertificatePolicyPayload struct{Policy certificates.CertificatePolicy `json:"policy"`}
type CertificateIssuePayload struct{PolicyID certificates.PolicyID `json:"policy_id"`;IssuanceID string `json:"issuance_id"`}
type CertificateDeployPayload struct{CertificateID certificates.CertificateID `json:"certificate_id"`;Consumer string `json:"consumer"`}

func registerCertificateContracts(registry *Registry)error{
	manage:=identity.MustPermission("certificate:manage")
	definitions:=[]Operation{
		{Name:"certificate.account.list",Permission:manage,Assurance:identity.AssurancePassword,Auth:AuthRequired,NewPayload:func()any{return &CertificatePagePayload{}},ValidatePayload:validateCertificatePage,ResolveScope:tenantScope},
		{Name:"certificate.account.get",Permission:manage,Assurance:identity.AssurancePassword,Auth:AuthRequired,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:certificateResourceScope},
		{Name:"certificate.account.put",Permission:manage,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &CertificateAccountPayload{}},ValidatePayload:validateCertificateAccount,ResolveScope:certificateResourceScope},
		{Name:"certificate.policy.list",Permission:manage,Assurance:identity.AssurancePassword,Auth:AuthRequired,NewPayload:func()any{return &CertificatePagePayload{}},ValidatePayload:validateCertificatePage,ResolveScope:tenantScope},
		{Name:"certificate.policy.get",Permission:manage,Assurance:identity.AssurancePassword,Auth:AuthRequired,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:certificateResourceScope},
		{Name:"certificate.policy.put",Permission:manage,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &CertificatePolicyPayload{}},ValidatePayload:validateCertificatePolicy,ResolveScope:certificateResourceScope},
		{Name:"certificate.issuance.list",Permission:manage,Assurance:identity.AssurancePassword,Auth:AuthRequired,NewPayload:func()any{return &CertificatePagePayload{}},ValidatePayload:validateCertificatePage,ResolveScope:tenantScope},
		{Name:"certificate.list",Permission:manage,Assurance:identity.AssurancePassword,Auth:AuthRequired,NewPayload:func()any{return &CertificatePagePayload{}},ValidatePayload:validateCertificatePage,ResolveScope:tenantScope},
		{Name:"certificate.issuance.get",Permission:manage,Assurance:identity.AssurancePassword,Auth:AuthRequired,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:certificateResourceScope},
		{Name:"certificate.issuance.issue",Permission:manage,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &CertificateIssuePayload{}},ValidatePayload:validateCertificateIssue,ResolveScope:tenantScope},
		{Name:"certificate.renew",Permission:manage,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:certificateResourceScope},
		{Name:"certificate.revoke",Permission:manage,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:certificateResourceScope},
		{Name:"certificate.deployment.create",Permission:manage,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &CertificateDeployPayload{}},ValidatePayload:validateCertificateDeploy,ResolveScope:siteScope},
	}
	for _,definition:=range definitions{if err:=register(registry,definition);err!=nil{return err}}
	return nil
}

func validateCertificatePage(value any)error{payload:=value.(*CertificatePagePayload);if payload.Limit>500||(payload.Cursor!=""&&!safeMailOpaque(payload.Cursor)){return invalid("certificate page")};return nil}
func validateCertificateAccount(value any)error{account:=value.(*CertificateAccountPayload).Account;if !safeMailOpaque(string(account.ID))||!safeMailOpaque(account.AccountKeyRef)||len(account.Contact)==0||len(account.Contact)>10||account.AcceptedTermsAt.IsZero(){return invalid("ACME account")};production,err:=url.Parse(account.Directory.ProductionURL);if err!=nil||production.Scheme!="https"||production.User!=nil||production.Hostname()==""{return invalid("ACME directory")};staging,err:=url.Parse(account.Directory.StagingURL);if err!=nil||staging.Scheme!="https"||staging.User!=nil||staging.Hostname()==""{return invalid("ACME directory")};return nil}
func validateCertificatePolicy(value any)error{policy:=value.(*CertificatePolicyPayload).Policy;if !safeMailOpaque(string(policy.ID))||!safeMailOpaque(string(policy.AccountID))||len(policy.Names)==0||len(policy.Names)>100||policy.RenewBefore<24*time.Hour||policy.RenewBefore>90*24*time.Hour{return invalid("certificate policy")};for _,name:=range policy.Names{base:=strings.TrimPrefix(name,"*.");if !validMailHostname(base){return invalid("certificate name")}};return nil}
func validateCertificateIssue(value any)error{payload:=value.(*CertificateIssuePayload);if !safeMailOpaque(string(payload.PolicyID))||!safeMailOpaque(payload.IssuanceID){return invalid("certificate issuance")};return nil}
func validateCertificateDeploy(value any)error{payload:=value.(*CertificateDeployPayload);if !safeMailOpaque(string(payload.CertificateID))||(payload.Consumer!="webengine"&&payload.Consumer!="panel"&&payload.Consumer!="mail"){return invalid("certificate deployment")};return nil}
func certificateResourceScope(request RequestEnvelope,value any)(identity.Scope,error){if !safeMailOpaque(request.ResourceID){return identity.Scope{},invalid("certificate resource")};return tenantScope(request,value)}

func bindCertificates(registry *Registry,services DomainServices)error{
	store:=services.CertificateStore;if store==nil&&services.CertificateIssuance!=nil{store=&services.CertificateIssuance.Store}
	if store!=nil&&store.DB!=nil{
		if err:=registry.Bind("certificate.account.list",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){page:=value.(*CertificatePagePayload);items,next,err:=store.Accounts(ctx,inv.Request.TenantID,page.Cursor,int(page.Limit));if err!=nil{return OperationResult{},mapCertificateError(err)};for index:=range items{items[index].AccountKeyRef="";items[index].EABKeyRef=""};return OperationResult{Status:http.StatusOK,Value:CertificatePageResult{Items:items,NextCursor:next}},nil});err!=nil{return err}
		if err:=registry.Bind("certificate.account.get",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){account,err:=store.Account(ctx,inv.Request.TenantID,certificates.AccountID(inv.Request.ResourceID));if err!=nil{return OperationResult{},mapCertificateError(err)};account.AccountKeyRef="";account.EABKeyRef="";return OperationResult{Status:http.StatusOK,Value:account},nil});err!=nil{return err}
		if err:=registry.Bind("certificate.account.put",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){account:=value.(*CertificateAccountPayload).Account;if string(account.ID)!=inv.Request.ResourceID{return OperationResult{},ErrInvalidRequest};account.TenantID=inv.Request.TenantID;if err:=store.PutAccount(ctx,account);err!=nil{return OperationResult{},mapCertificateError(err)};account.AccountKeyRef="";account.EABKeyRef="";return OperationResult{Status:http.StatusOK,Value:account},nil});err!=nil{return err}
		if err:=registry.Bind("certificate.policy.list",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){page:=value.(*CertificatePagePayload);items,next,err:=store.Policies(ctx,inv.Request.TenantID,page.Cursor,int(page.Limit));if err!=nil{return OperationResult{},mapCertificateError(err)};return OperationResult{Status:http.StatusOK,Value:CertificatePageResult{Items:items,NextCursor:next}},nil});err!=nil{return err}
		if err:=registry.Bind("certificate.policy.get",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){policy,err:=store.Policy(ctx,inv.Request.TenantID,certificates.PolicyID(inv.Request.ResourceID));if err!=nil{return OperationResult{},mapCertificateError(err)};return OperationResult{Status:http.StatusOK,Value:policy,Generation:policy.Generation},nil});err!=nil{return err}
		if err:=registry.Bind("certificate.policy.put",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){policy:=value.(*CertificatePolicyPayload).Policy;if string(policy.ID)!=inv.Request.ResourceID{return OperationResult{},ErrInvalidRequest};policy.TenantID=inv.Request.TenantID;policy.Generation=inv.Request.ExpectedGeneration+1;if err:=store.PutPolicy(ctx,policy,inv.Request.ExpectedGeneration);err!=nil{return OperationResult{},mapCertificateError(err)};return OperationResult{Status:http.StatusOK,Value:policy,Generation:policy.Generation},nil});err!=nil{return err}
		listIssuances:=func(ctx context.Context,inv Invocation,value any)(OperationResult,error){page:=value.(*CertificatePagePayload);items,next,err:=store.Issuances(ctx,inv.Request.TenantID,page.Cursor,int(page.Limit));if err!=nil{return OperationResult{},mapCertificateError(err)};for index:=range items{items[index].Certificate.PrivateKeyRef=""};return OperationResult{Status:http.StatusOK,Value:CertificatePageResult{Items:items,NextCursor:next}},nil}
		if err:=registry.Bind("certificate.issuance.list",listIssuances);err!=nil{return err};if err:=registry.Bind("certificate.list",listIssuances);err!=nil{return err}
		if err:=registry.Bind("certificate.issuance.get",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){issuance,err:=store.Issuance(ctx,inv.Request.TenantID,inv.Request.ResourceID);if err!=nil{return OperationResult{},mapCertificateError(err)};issuance.Certificate.PrivateKeyRef="";return OperationResult{Status:http.StatusOK,Value:issuance,Generation:issuance.PolicyGeneration},nil});err!=nil{return err}
	}
	if services.CertificateIssuance!=nil&&services.CertificateIssuance.Store.DB!=nil&&services.CertificateIssuance.ACME!=nil&&services.CertificateIssuance.Signer!=nil&&services.CertificateIssuance.Validator!=nil{
		if err:=registry.Bind("certificate.issuance.issue",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*CertificateIssuePayload);issuance,err:=services.CertificateIssuance.Issue(ctx,inv.Request.TenantID,payload.PolicyID,payload.IssuanceID,"api_"+inv.IdempotencyKey);if err!=nil{return OperationResult{},mapCertificateError(err)};issuance.Certificate.PrivateKeyRef="";return OperationResult{Status:http.StatusCreated,Value:issuance,Generation:issuance.PolicyGeneration},nil});err!=nil{return err}
		if err:=registry.Bind("certificate.renew",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){prior,err:=services.CertificateIssuance.Store.Issuance(ctx,inv.Request.TenantID,inv.Request.ResourceID);if err!=nil{return OperationResult{},mapCertificateError(err)};if inv.Request.ExpectedGeneration!=0&&prior.PolicyGeneration!=inv.Request.ExpectedGeneration{return OperationResult{},ErrConflict};issuance,err:=services.CertificateIssuance.Issue(ctx,inv.Request.TenantID,prior.PolicyID,effectID(inv),"api_"+inv.IdempotencyKey);if err!=nil{return OperationResult{},mapCertificateError(err)};issuance.Certificate.PrivateKeyRef="";return OperationResult{Status:http.StatusCreated,Value:issuance,Generation:issuance.PolicyGeneration},nil});err!=nil{return err}
	}
	if services.CertificateIssuance!=nil&&services.CertificateIssuance.Store.DB!=nil&&services.CertificateIssuance.ACME!=nil{if err:=registry.Bind("certificate.revoke",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){issuance,err:=services.CertificateIssuance.Revoke(ctx,inv.Request.TenantID,inv.Request.ResourceID,"api_"+inv.IdempotencyKey);if err!=nil{return OperationResult{},mapCertificateError(err)};return OperationResult{Status:http.StatusOK,Value:issuance,Generation:issuance.PolicyGeneration},nil});err!=nil{return err}}
	if services.CertificateDeployment!=nil&&services.CertificateDeployment.Target!=nil&&store!=nil&&store.DB!=nil{
		return registry.Bind("certificate.deployment.create",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*CertificateDeployPayload);material,err:=store.Material(ctx,inv.Request.TenantID,payload.CertificateID);if err!=nil{return OperationResult{},mapCertificateError(err)};consumer:=payload.Consumer+"/"+inv.Request.ResourceID;deployment,err:=services.CertificateDeployment.Deploy(ctx,consumer,material,effectID(inv));if err!=nil{return OperationResult{},mapCertificateError(err)};return OperationResult{Status:http.StatusCreated,Value:deployment},nil})
	}
	return nil
}

func mapCertificateError(err error)error{switch{case err==nil:return nil;case errors.Is(err,sql.ErrNoRows):return ErrNotFound;case errors.Is(err,certificates.ErrInvalidCertificate):return ErrInvalidRequest;case errors.Is(err,certificates.ErrCertificateConflict):return ErrConflict;case errors.Is(err,certificates.ErrCertificateAmbiguous):return ErrUnavailable;default:return err}}
