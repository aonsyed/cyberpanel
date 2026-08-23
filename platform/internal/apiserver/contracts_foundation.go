package apiserver

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
)

type DNSApplyPayload struct{Zone dns.Zone `json:"zone"`;Change dns.Change `json:"change"`}
type CertificateChallengePayload struct{Challenge certificates.Challenge `json:"challenge"`}
type MailProvisionPayload struct{Domain mail.Domain `json:"domain"`;Policy mail.Policy `json:"policy"`;Mailboxes []mail.Mailbox `json:"mailboxes"`;Aliases []mail.Alias `json:"aliases"`}
type BackupCapturePayload struct{Policy backup.Policy `json:"policy"`;Repository backup.Repository `json:"repository"`;RecoveryPoint backup.RecoveryPoint `json:"recovery_point"`;Artifacts []backup.Artifact `json:"artifacts"`}
type BackupRestorePayload struct{Plan backup.RestorePlan `json:"plan"`}
type BackupTransferPayload struct{Transfer backup.Transfer `json:"transfer"`}

func registerFoundationContracts(registry *Registry)error{
	operations:=[]Operation{
		{Name:"dns.rrset.apply",Permission:identity.MustPermission("dns:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DNSApplyPayload{}},ValidatePayload:func(value any)error{p:=value.(*DNSApplyPayload);if p.Zone.ID==""||p.Change.ID==""||p.Change.Key==""||p.Change.Zone!=p.Zone.ID{return invalid("DNS change")};return nil},ResolveScope:tenantScope},
		{Name:"certificate.challenge.present",Permission:identity.MustPermission("certificate:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &CertificateChallengePayload{}},ResolveScope:siteScope},
		{Name:"certificate.challenge.remove",Permission:identity.MustPermission("certificate:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &CertificateChallengePayload{}},ResolveScope:siteScope},
		{Name:"mail.domain.provision",Permission:identity.MustPermission("mail:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &MailProvisionPayload{}},ValidatePayload:func(value any)error{p:=value.(*MailProvisionPayload);if p.Domain.ID==""||p.Policy.ID==""||len(p.Mailboxes)>10000||len(p.Aliases)>10000{return invalid("mail provisioning")};return nil},ResolveScope:tenantScope},
		{Name:"backup.recovery_point.capture",Permission:identity.MustPermission("backup:create"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,MaximumBodyBytes:8<<20,NewPayload:func()any{return &BackupCapturePayload{}},ValidatePayload:validateBackupCapture,ResolveScope:tenantScope},
		{Name:"backup.restore.execute",Permission:identity.MustPermission("backup:restore"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &BackupRestorePayload{}},ValidatePayload:func(value any)error{p:=value.(*BackupRestorePayload);if p.Plan.ID==""||p.Plan.RecoveryPoint==""||!safeOpaqueReference(p.Plan.Target){return invalid("backup restore")};return nil},ResolveScope:tenantScope},
		{Name:"backup.transfer.execute",Permission:identity.MustPermission("backup:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &BackupTransferPayload{}},ValidatePayload:func(value any)error{p:=value.(*BackupTransferPayload);if p.Transfer.ID==""||!safeOpaqueReference(p.Transfer.Source)||!safeOpaqueReference(p.Transfer.Target){return invalid("backup transfer")};return nil},ResolveScope:tenantScope},
	}
	for _,operation:=range operations{if err:=register(registry,operation);err!=nil{return err}}
	return nil
}

func validateBackupCapture(value any)error{p:=value.(*BackupCapturePayload);if p.Policy.ID==""||p.Repository.ID==""||p.RecoveryPoint.ID==""||len(p.Artifacts)>100000||!safeOpaqueReference(string(p.Repository.ID))||!safeOpaqueReference(p.Repository.Bucket)||!safeOpaqueReference(p.Repository.CredentialRef){return invalid("backup capture")};if p.Repository.Endpoint!=""{endpoint,err:=url.Parse(p.Repository.Endpoint);if err!=nil||endpoint.Scheme!="https"||endpoint.Host==""||endpoint.User!=nil||endpoint.Fragment!=""{return invalid("backup repository endpoint")}};for _,artifact:=range p.Artifacts{if artifact.ID==""||artifact.Size<0||artifact.Size>1<<50||artifact.Digest==""||!safeObjectReference(artifact.Object){return invalid("backup artifact")}};return nil}
func safeOpaqueReference(value string)bool{return value!=""&&len(value)<=256&&!strings.ContainsAny(value,"\x00\r\n\t /\\")&&!strings.Contains(value,"..")}
func safeObjectReference(value string)bool{if value==""||len(value)>1024||strings.HasPrefix(value,"/")||strings.ContainsAny(value,"\x00\r\n\t\\") {return false};for _,part:=range strings.Split(value,"/"){if part==""||part=="."||part==".."{return false}};return true}

func bindFoundation(registry *Registry,services DomainServices)error{
	if services.DNSRepository!=nil&&services.DNSProvider!=nil{if err:=registry.Bind("dns.rrset.apply",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){p:=value.(*DNSApplyPayload);p.Change.Key=inv.IdempotencyKey;if err:=services.DNSRepository.Apply(ctx,services.DNSProvider,p.Zone,p.Change);err!=nil{return OperationResult{},err};return OperationResult{Status:http.StatusOK,Value:p.Change},nil});err!=nil{return err}}
	if services.HTTP01!=nil||services.DNS01!=nil{
		if err:=registry.Bind("certificate.challenge.present",func(ctx context.Context,_ Invocation,value any)(OperationResult,error){p:=value.(*CertificateChallengePayload);if err:=certificates.PresentChallenge(ctx,p.Challenge,services.HTTP01,services.DNS01);err!=nil{return OperationResult{},err};return OperationResult{Status:http.StatusOK,Value:p.Challenge},nil});err!=nil{return err}
		if err:=registry.Bind("certificate.challenge.remove",func(ctx context.Context,_ Invocation,value any)(OperationResult,error){p:=value.(*CertificateChallengePayload);if err:=certificates.RemoveChallenge(ctx,p.Challenge,services.HTTP01,services.DNS01);err!=nil{return OperationResult{},err};return OperationResult{Status:http.StatusOK,Value:p.Challenge},nil});err!=nil{return err}
	}
	if services.Mail!=nil{if err:=registry.Bind("mail.domain.provision",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){p:=value.(*MailProvisionPayload);p.Domain.Tenant=inv.Request.TenantID;if err:=services.Mail.Provision(ctx,p.Domain,p.Policy,p.Mailboxes,p.Aliases);err!=nil{return OperationResult{},err};return OperationResult{Status:http.StatusOK,Value:p.Domain},nil});err!=nil{return err}}
	if services.Backup!=nil{
		if err:=registry.Bind("backup.recovery_point.capture",func(ctx context.Context,_ Invocation,value any)(OperationResult,error){p:=value.(*BackupCapturePayload);manifest,err:=services.Backup.Capture(ctx,p.Policy,p.Repository,p.RecoveryPoint,p.Artifacts);if err!=nil{return OperationResult{},err};return OperationResult{Status:http.StatusCreated,Value:manifest},nil});err!=nil{return err}
		if services.BackupPromoter!=nil{if err:=registry.Bind("backup.restore.execute",func(ctx context.Context,_ Invocation,value any)(OperationResult,error){p:=value.(*BackupRestorePayload);if err:=services.Backup.Restore(ctx,p.Plan,services.BackupPromoter);err!=nil{return OperationResult{},err};return OperationResult{Status:http.StatusOK,Value:p.Plan},nil});err!=nil{return err}}
		if services.BackupMover!=nil{if err:=registry.Bind("backup.transfer.execute",func(ctx context.Context,_ Invocation,value any)(OperationResult,error){p:=value.(*BackupTransferPayload);if err:=services.Backup.Transfer(ctx,p.Transfer,services.BackupMover);err!=nil{return OperationResult{},err};return OperationResult{Status:http.StatusOK,Value:p.Transfer},nil});err!=nil{return err}}
	}
	return nil
}
