package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	DKIMMinimumOverlap = 5 * time.Minute
	DKIMDefaultOverlap = 24 * time.Hour
	DKIMMaximumOverlap = 7 * 24 * time.Hour
	dkimRotationAdapterID = "mail.opendkim.private-key"
	dkimRotationAdapterVersion = "linux-opendkim-v1"
)

type DKIMRotationState string

const (
	DKIMRotationPrepared DKIMRotationState = "prepared"
	DKIMRotationOverlap DKIMRotationState = "overlap"
	DKIMRotationComplete DKIMRotationState = "complete"
)

type DKIMSecretProof struct {
	Version uint64
	BindingDigest string
	ResourceGeneration uint64
}

type DKIMPrepareRequest struct {
	TenantID string
	DomainID DomainID
	ExpectedGeneration uint64
	OperationID string
	Overlap time.Duration
	CurrentSecret *DKIMSecretProof
}

type DKIMActivateRequest struct {
	TenantID string
	DomainID DomainID
	ExpectedGeneration uint64
	ConfirmPrevious bool
}

type DKIMRotationStatus struct {
	State DKIMRotationState `json:"state"`
	DomainID DomainID `json:"domain_id"`
	DomainName string `json:"domain_name"`
	BoundGeneration uint64 `json:"bound_generation"`
	CurrentGeneration uint64 `json:"current_generation"`
	PendingSelector string `json:"pending_selector"`
	TXTName string `json:"txt_name"`
	TXTValue string `json:"txt_value"`
	DNSObserved bool `json:"dns_observed"`
	DNSMatched bool `json:"dns_matched"`
	DNSProofDigest string `json:"dns_proof_digest,omitempty"`
	DNSObservedAt *time.Time `json:"dns_observed_at,omitempty"`
	PreviousSelector string `json:"previous_selector,omitempty"`
	OverlapUntil *time.Time `json:"overlap_until,omitempty"`
	PreviousRevocationRequired bool `json:"previous_revocation_required"`
	PreviousRevokedAt *time.Time `json:"previous_revoked_at,omitempty"`
	MailGenerationDigest string `json:"mail_generation_digest,omitempty"`
	OpenDKIMReloadDigest string `json:"opendkim_reload_digest,omitempty"`
	OpenDKIMProbeDigest string `json:"opendkim_probe_digest,omitempty"`
	LiveSelectorProofDigest string `json:"live_selector_proof_digest,omitempty"`
	PreparedAt time.Time `json:"prepared_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
}

type DKIMRuntimeReceipt struct {
	Effect EffectReceipt
	GenerationDigest string
	OpenDKIMReloadDigest string
	OpenDKIMProbeDigest string
	OpenDKIMActive bool
	RolledBack bool
}

type DKIMRotationRuntime interface {
	ApplyDKIMGeneration(context.Context, EffectRequest, ConfigGeneration) (DKIMRuntimeReceipt, error)
}

type DKIMRotationSecrets interface {
	Put(context.Context, secrets.PutRequest) (secrets.Metadata, error)
	Revoke(context.Context, secrets.RevokeRequest) (secrets.Metadata, error)
}

type DKIMTXTObserver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type SystemDKIMTXTObserver struct{ Resolver *net.Resolver }

func (observer SystemDKIMTXTObserver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	resolver := observer.Resolver
	if resolver == nil { resolver = net.DefaultResolver }
	return resolver.LookupTXT(ctx, name)
}

type DKIMRotationRepository interface {
	Load(context.Context, string, ResourceKind, string) (ResourceEnvelope, bool, error)
	LoadDKIMRotation(context.Context, string, DomainID) (dkimRotationRecord, bool, error)
	SavePreparedDKIMRotation(context.Context, dkimRotationRecord, uint64) error
	ActivateDKIMRotation(context.Context, dkimRotationRecord, ResourceEnvelope, uint64) error
	CompleteDKIMRotation(context.Context, dkimRotationRecord, uint64) error
}

type dkimSecretLease struct {
	ID secrets.ID `json:"id"`
	OwnerTenantID secrets.ID `json:"owner_tenant_id"`
	Version uint64 `json:"version"`
	BindingDigest string `json:"binding_digest"`
	Audience secrets.AudienceBinding `json:"audience"`
}

type dkimRotationRecord struct {
	TenantID string `json:"tenant_id"`
	DomainID DomainID `json:"domain_id"`
	DomainName string `json:"domain_name"`
	PrepareToken string `json:"prepare_token"`
	BoundGeneration uint64 `json:"bound_generation"`
	ActiveGeneration uint64 `json:"active_generation,omitempty"`
	State DKIMRotationState `json:"state"`
	Pending DKIM `json:"pending"`
	PendingSecret dkimSecretLease `json:"pending_secret"`
	Previous DKIM `json:"previous"`
	PreviousSecret *dkimSecretLease `json:"previous_secret,omitempty"`
	TXTName string `json:"txt_name"`
	TXTValue string `json:"txt_value"`
	Overlap time.Duration `json:"overlap"`
	PreparedAt time.Time `json:"prepared_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	OverlapUntil *time.Time `json:"overlap_until,omitempty"`
	PreviousRevokedAt *time.Time `json:"previous_revoked_at,omitempty"`
	DNSProofDigest string `json:"dns_proof_digest,omitempty"`
	DNSObservedAt *time.Time `json:"dns_observed_at,omitempty"`
	MailGenerationDigest string `json:"mail_generation_digest,omitempty"`
	OpenDKIMReloadDigest string `json:"opendkim_reload_digest,omitempty"`
	OpenDKIMProbeDigest string `json:"opendkim_probe_digest,omitempty"`
	LiveSelectorProofDigest string `json:"live_selector_proof_digest,omitempty"`
}

type DKIMRotationService struct {
	Store DKIMRotationRepository
	Projector SnapshotProjector
	Runtime DKIMRotationRuntime
	Secrets DKIMRotationSecrets
	Observer DKIMTXTObserver
	ConsumerReleaseDigest string
	Now func() time.Time
	mu sync.Mutex
}

func NewDKIMRotationService(store DKIMRotationRepository, projector SnapshotProjector, runtime DKIMRotationRuntime, secretManager DKIMRotationSecrets, observer DKIMTXTObserver, releaseDigest string, now func() time.Time) (*DKIMRotationService, error) {
	if store == nil || projector == nil || runtime == nil || secretManager == nil || observer == nil || !validRotationDigest(releaseDigest) { return nil, ErrInvalidCommand }
	return &DKIMRotationService{Store:store,Projector:projector,Runtime:runtime,Secrets:secretManager,Observer:observer,ConsumerReleaseDigest:strings.ToLower(releaseDigest),Now:now},nil
}

func (service *DKIMRotationService) Prepare(ctx context.Context, request DKIMPrepareRequest) (DKIMRotationStatus, error) {
	if service == nil || ctx == nil || !validOpaque(request.TenantID) || !validOpaque(string(request.DomainID)) || request.ExpectedGeneration == 0 || !validOpaque(request.OperationID) { return DKIMRotationStatus{}, ErrInvalidCommand }
	if request.Overlap == 0 { request.Overlap = DKIMDefaultOverlap }
	if request.Overlap < DKIMMinimumOverlap || request.Overlap > DKIMMaximumOverlap { return DKIMRotationStatus{}, ErrInvalidCommand }
	service.mu.Lock(); defer service.mu.Unlock()
	resource, domain, err := service.domain(ctx,request.TenantID,request.DomainID,request.ExpectedGeneration);if err!=nil{return DKIMRotationStatus{},err}
	prepareToken:=rotationDigest("prepare",request.TenantID,string(request.DomainID),fmt.Sprint(request.ExpectedGeneration),request.OperationID)
	prior,found,err:=service.Store.LoadDKIMRotation(ctx,request.TenantID,request.DomainID);if err!=nil{return DKIMRotationStatus{},err}
	if found&&prior.State==DKIMRotationPrepared { if prior.BoundGeneration==request.ExpectedGeneration&&prior.PrepareToken==prepareToken{return service.publicStatus(ctx,prior,resource.Generation),nil};return DKIMRotationStatus{},ErrConflict }
	if found&&prior.State==DKIMRotationOverlap{return DKIMRotationStatus{},ErrConflict}
	previousSecret,err:=service.previousSecret(domain,prior,found,request.CurrentSecret);if err!=nil{return DKIMRotationStatus{},err}
	selectorSeed:=rotationDigest("selector",request.TenantID,domain.Name,fmt.Sprint(request.ExpectedGeneration),request.OperationID)
	selector:=fmt.Sprintf("cp%d-%s",request.ExpectedGeneration+1,selectorSeed[:12]);if !validDKIMSelector(selector)||selector==domain.DKIM.Selector{return DKIMRotationStatus{},ErrInvalidCommand}
	owner:=rotationMaterialID("mailtenant",request.TenantID);audience:=service.audience(request.TenantID,domain.Name,selector,request.ExpectedGeneration)
	privateKey,keyErr:=rsa.GenerateKey(rand.Reader,2048);if keyErr!=nil{return DKIMRotationStatus{},keyErr};defer wipeRotationRSAKey(privateKey);if privateKey.N.BitLen()!=2048||privateKey.E!=65537||privateKey.Validate()!=nil{return DKIMRotationStatus{},ErrInvalidCommand}
	privateDER,keyErr:=x509.MarshalPKCS8PrivateKey(privateKey);if keyErr!=nil{return DKIMRotationStatus{},keyErr};defer wipeRotationBytes(privateDER)
	privatePEM:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:privateDER});defer wipeRotationBytes(privatePEM)
	publicDER,keyErr:=x509.MarshalPKIXPublicKey(&privateKey.PublicKey);if keyErr!=nil{return DKIMRotationStatus{},keyErr}
	publicTXT:="v=DKIM1; k=rsa; p="+base64.StdEncoding.EncodeToString(publicDER);wipeRotationBytes(publicDER)
	privateRef:="dkim_"+rotationDigest("private-ref",request.TenantID,domain.Name,selector,publicTXT)[:48];secretID:=rotationMaterialID("dkimkey",privateRef)
	metadata,err:=service.Secrets.Put(ctx,secrets.PutRequest{ID:secretID,OwnerTenantID:owner,Purpose:secrets.PurposeDKIMKey,Audience:audience,Plaintext:privatePEM});if err!=nil{return DKIMRotationStatus{},mapRotationSecretError(err)}
	lease:=leaseFromMetadata(metadata);if !leaseMatches(lease,secretID,owner,audience){return DKIMRotationStatus{},ErrInvalidReceipt}
	now:=service.now();record:=dkimRotationRecord{TenantID:request.TenantID,DomainID:request.DomainID,DomainName:domain.Name,PrepareToken:prepareToken,BoundGeneration:request.ExpectedGeneration,State:DKIMRotationPrepared,Pending:DKIM{Selector:selector,PublicKey:publicTXT,PrivateKeyRef:privateRef,Enabled:true},PendingSecret:lease,Previous:domain.DKIM,PreviousSecret:previousSecret,TXTName:selector+"._domainkey."+domain.Name,TXTValue:publicTXT,Overlap:request.Overlap,PreparedAt:now}
	if err=service.Store.SavePreparedDKIMRotation(ctx,record,request.ExpectedGeneration);err!=nil{_,revokeErr:=service.Secrets.Revoke(ctx,revokeRequest(lease));return DKIMRotationStatus{},errors.Join(err,revokeErr)}
	return service.publicStatus(ctx,record,resource.Generation),nil
}

func (service *DKIMRotationService) Status(ctx context.Context, tenant string, domainID DomainID) (DKIMRotationStatus, error) {
	if service==nil||ctx==nil||!validOpaque(tenant)||!validOpaque(string(domainID)){return DKIMRotationStatus{},ErrInvalidCommand}
	record,found,err:=service.Store.LoadDKIMRotation(ctx,tenant,domainID);if err!=nil{return DKIMRotationStatus{},err};if !found{return DKIMRotationStatus{},ErrNotFound}
	resource,found,err:=service.Store.Load(ctx,tenant,ResourceDomain,string(domainID));if err!=nil{return DKIMRotationStatus{},err};if !found{return DKIMRotationStatus{},ErrNotFound}
	return service.publicStatus(ctx,record,resource.Generation),nil
}

func (service *DKIMRotationService) Activate(ctx context.Context, request DKIMActivateRequest) (DKIMRotationStatus, error) {
	if service==nil||ctx==nil||!validOpaque(request.TenantID)||!validOpaque(string(request.DomainID))||request.ExpectedGeneration==0{return DKIMRotationStatus{},ErrInvalidCommand}
	service.mu.Lock();defer service.mu.Unlock()
	if request.ConfirmPrevious{return service.confirmPrevious(ctx,request)}
	resource,domain,err:=service.domain(ctx,request.TenantID,request.DomainID,request.ExpectedGeneration);if err!=nil{return DKIMRotationStatus{},err}
	record,found,err:=service.Store.LoadDKIMRotation(ctx,request.TenantID,request.DomainID);if err!=nil{return DKIMRotationStatus{},err};if !found{return DKIMRotationStatus{},ErrNotFound}
	if record.State!=DKIMRotationPrepared||record.BoundGeneration!=request.ExpectedGeneration||record.DomainName!=domain.Name{return DKIMRotationStatus{},ErrConflict}
	matched,dnsDigest,observedAt,dnsErr:=service.observeTXT(ctx,record);if dnsErr!=nil{return DKIMRotationStatus{},dnsErr};if !matched{return DKIMRotationStatus{},ErrConflict}
	desiredDomain:=domain;desiredDomain.DKIM=record.Pending;desired:=resource;desired.Generation++;desired.State=StatePending;desired.UpdatedAt=service.now();desired.Spec,err=json.Marshal(desiredDomain);if err!=nil{return DKIMRotationStatus{},err}
	newEffect:=rotationEffect("activate",resource,desired);newGeneration,err:=service.render(ctx,newEffect);if err!=nil{return DKIMRotationStatus{},err};if !generationBindsDKIM(newGeneration,desiredDomain){return DKIMRotationStatus{},ErrInvalidReceipt}
	oldEffect:=rotationEffect("restore",resource,resource);oldGeneration,err:=service.render(ctx,oldEffect);if err!=nil{return DKIMRotationStatus{},err}
	runtimeReceipt,err:=service.Runtime.ApplyDKIMGeneration(ctx,newEffect,newGeneration);if err!=nil||!validDKIMRuntimeReceipt(runtimeReceipt,newEffect){return DKIMRotationStatus{},service.restoreAfterFailure(ctx,oldEffect,oldGeneration,errors.Join(err,ErrInvalidReceipt))}
	now:=service.now();record.ActiveGeneration=desired.Generation;record.Previous=domain.DKIM;record.State=DKIMRotationComplete;record.ActivatedAt=&now;record.DNSProofDigest=dnsDigest;record.DNSObservedAt=&observedAt;record.MailGenerationDigest=runtimeReceipt.GenerationDigest;record.OpenDKIMReloadDigest=runtimeReceipt.OpenDKIMReloadDigest;record.OpenDKIMProbeDigest=runtimeReceipt.OpenDKIMProbeDigest;record.LiveSelectorProofDigest=rotationDigest(record.Pending.Selector,runtimeReceipt.GenerationDigest,runtimeReceipt.OpenDKIMReloadDigest,runtimeReceipt.OpenDKIMProbeDigest)
	if record.Previous.Enabled { until:=now.Add(record.Overlap);record.OverlapUntil=&until;record.State=DKIMRotationOverlap }
	desired.State=StateActive
	if err=service.Store.ActivateDKIMRotation(ctx,record,desired,request.ExpectedGeneration);err!=nil{return DKIMRotationStatus{},service.restoreAfterFailure(ctx,oldEffect,oldGeneration,err)}
	return service.publicStatus(ctx,record,desired.Generation),nil
}

func (service *DKIMRotationService) confirmPrevious(ctx context.Context, request DKIMActivateRequest) (DKIMRotationStatus,error) {
	resource,domain,err:=service.domain(ctx,request.TenantID,request.DomainID,request.ExpectedGeneration);if err!=nil{return DKIMRotationStatus{},err}
	record,found,err:=service.Store.LoadDKIMRotation(ctx,request.TenantID,request.DomainID);if err!=nil{return DKIMRotationStatus{},err};if !found{return DKIMRotationStatus{},ErrNotFound}
	if record.State!=DKIMRotationOverlap||record.ActiveGeneration!=request.ExpectedGeneration||record.OverlapUntil==nil||service.now().Before(*record.OverlapUntil)||!sameDKIM(domain.DKIM,record.Pending)||record.PreviousSecret==nil{return DKIMRotationStatus{},ErrConflict}
	matched,dnsDigest,observedAt,dnsErr:=service.observeTXT(ctx,record);if dnsErr!=nil{return DKIMRotationStatus{},dnsErr};if !matched{return DKIMRotationStatus{},ErrConflict}
	effect:=rotationEffect("confirm",resource,resource);generation,err:=service.render(ctx,effect);if err!=nil{return DKIMRotationStatus{},err};if !generationBindsDKIM(generation,domain){return DKIMRotationStatus{},ErrInvalidReceipt}
	runtimeReceipt,err:=service.Runtime.ApplyDKIMGeneration(ctx,effect,generation);if err!=nil||!validDKIMRuntimeReceipt(runtimeReceipt,effect){return DKIMRotationStatus{},errors.Join(err,ErrInvalidReceipt)}
	metadata,err:=service.Secrets.Revoke(ctx,revokeRequest(*record.PreviousSecret));if err!=nil{return DKIMRotationStatus{},mapRotationSecretError(err)};if metadata.State!=secrets.StateRevoked||metadata.ID!=record.PreviousSecret.ID||metadata.Version!=record.PreviousSecret.Version{return DKIMRotationStatus{},ErrInvalidReceipt}
	now:=service.now();record.State=DKIMRotationComplete;record.PreviousRevokedAt=&now;record.DNSProofDigest=dnsDigest;record.DNSObservedAt=&observedAt;record.MailGenerationDigest=runtimeReceipt.GenerationDigest;record.OpenDKIMReloadDigest=runtimeReceipt.OpenDKIMReloadDigest;record.OpenDKIMProbeDigest=runtimeReceipt.OpenDKIMProbeDigest;record.LiveSelectorProofDigest=rotationDigest(record.Pending.Selector,runtimeReceipt.GenerationDigest,runtimeReceipt.OpenDKIMReloadDigest,runtimeReceipt.OpenDKIMProbeDigest)
	if err=service.Store.CompleteDKIMRotation(ctx,record,request.ExpectedGeneration);err!=nil{return DKIMRotationStatus{},err}
	return service.publicStatus(ctx,record,resource.Generation),nil
}

func (service *DKIMRotationService) domain(ctx context.Context,tenant string,id DomainID,expected uint64)(ResourceEnvelope,Domain,error){resource,found,err:=service.Store.Load(ctx,tenant,ResourceDomain,string(id));if err!=nil{return ResourceEnvelope{},Domain{},err};if !found{return ResourceEnvelope{},Domain{},ErrNotFound};if resource.Generation!=expected{return ResourceEnvelope{},Domain{},ErrConflict};var domain Domain;if decodeRotationJSON(resource.Spec,&domain)!=nil||domain.ID!=id||domain.Tenant!=tenant||!validHostname(domain.Name){return ResourceEnvelope{},Domain{},ErrInvalidReceipt};return resource,domain,nil}

func (service *DKIMRotationService) previousSecret(domain Domain,prior dkimRotationRecord,found bool,proof *DKIMSecretProof)(*dkimSecretLease,error){if !domain.DKIM.Enabled{if proof!=nil{return nil,ErrInvalidCommand};return nil,nil};if !validDKIMSelector(domain.DKIM.Selector)||!validOpaque(domain.DKIM.PrivateKeyRef){return nil,ErrInvalidReceipt};if found&&prior.State==DKIMRotationComplete&&sameDKIM(prior.Pending,domain.DKIM){lease:=prior.PendingSecret;if proof!=nil&&(proof.Version!=lease.Version||proof.BindingDigest!=lease.BindingDigest||proof.ResourceGeneration!=lease.Audience.ResourceGeneration){return nil,ErrConflict};return &lease,nil};if proof==nil||proof.Version==0||proof.ResourceGeneration==0||!validRotationDigest(proof.BindingDigest){return nil,ErrInvalidCommand};audience:=service.audience(domain.Tenant,domain.Name,domain.DKIM.Selector,proof.ResourceGeneration);lease:=dkimSecretLease{ID:rotationMaterialID("dkimkey",domain.DKIM.PrivateKeyRef),OwnerTenantID:rotationMaterialID("mailtenant",domain.Tenant),Version:proof.Version,BindingDigest:strings.ToLower(proof.BindingDigest),Audience:audience};return &lease,nil}

func (service *DKIMRotationService) audience(tenant,domain,selector string,generation uint64)secrets.AudienceBinding{return secrets.AudienceBinding{AdapterID:dkimRotationAdapterID,AdapterVersion:dkimRotationAdapterVersion,Account:"mail-domain",Origin:"local://panel-execd/opendkim",ResourceKind:"mail_domain_dkim",ResourceID:rotationMaterialID("dkimaudience",tenant,domain,selector),ResourceGeneration:generation,Operations:[]secrets.Operation{secrets.OperationRead},ConsumerReleaseDigest:service.ConsumerReleaseDigest}}

func (service *DKIMRotationService) render(ctx context.Context,effect EffectRequest)(ConfigGeneration,error){snapshot,err:=service.Projector.ProjectMail(ctx,effect);if err!=nil{return ConfigGeneration{},err};return (ConfigRenderer{}).Render(snapshot)}

func (service *DKIMRotationService) restoreAfterFailure(ctx context.Context,effect EffectRequest,generation ConfigGeneration,cause error)error{receipt,err:=service.Runtime.ApplyDKIMGeneration(ctx,effect,generation);if err!=nil||!validDKIMRuntimeReceipt(receipt,effect){return errors.Join(ErrAmbiguous,cause,err)};return cause}

func (service *DKIMRotationService) publicStatus(ctx context.Context,record dkimRotationRecord,current uint64)DKIMRotationStatus{status:=DKIMRotationStatus{State:record.State,DomainID:record.DomainID,DomainName:record.DomainName,BoundGeneration:record.BoundGeneration,CurrentGeneration:current,PendingSelector:record.Pending.Selector,TXTName:record.TXTName,TXTValue:record.TXTValue,PreviousSelector:record.Previous.Selector,OverlapUntil:record.OverlapUntil,PreviousRevocationRequired:record.State==DKIMRotationOverlap&&record.PreviousSecret!=nil,PreviousRevokedAt:record.PreviousRevokedAt,MailGenerationDigest:record.MailGenerationDigest,OpenDKIMReloadDigest:record.OpenDKIMReloadDigest,OpenDKIMProbeDigest:record.OpenDKIMProbeDigest,LiveSelectorProofDigest:record.LiveSelectorProofDigest,PreparedAt:record.PreparedAt,ActivatedAt:record.ActivatedAt};matched,digest,at,err:=service.observeTXT(ctx,record);if err==nil{status.DNSObserved=true;status.DNSMatched=matched;status.DNSProofDigest=digest;status.DNSObservedAt=&at};return status}

func (service *DKIMRotationService) observeTXT(ctx context.Context,record dkimRotationRecord)(bool,string,time.Time,error){values,err:=service.Observer.LookupTXT(ctx,record.TXTName);at:=service.now();if err!=nil{return false,"",at,err};sort.Strings(values);matched:=false;expected,err:=canonicalRotationTXT(record.TXTValue);if err!=nil{return false,"",at,err};for _,value:=range values{canonical,canonicalErr:=canonicalRotationTXT(value);if canonicalErr==nil&&canonical==expected{matched=true}};return matched,rotationDigest(append([]string{record.TXTName,record.TXTValue},values...)...),at,nil}

func rotationEffect(label string,previous,desired ResourceEnvelope)EffectRequest{raw,_:=json.Marshal(desired);desiredSum:=sha256.Sum256(raw);desiredDigest:=hex.EncodeToString(desiredSum[:]);identity:=rotationDigest(label,desired.TenantID,desired.ID,fmt.Sprint(desired.Generation),desiredDigest);copyPrevious:=previous;copyDesired:=desired;return EffectRequest{EffectID:"mailfx_"+identity[:48],CommandID:"dkimcmd_"+identity[:48],CommandDigest:identity,TenantID:desired.TenantID,Kind:ResourceDomain,ResourceID:desired.ID,Generation:desired.Generation,Action:ActionRotateCredential,Desired:&copyDesired,Previous:&copyPrevious,DesiredDigest:desiredDigest}}

func generationBindsDKIM(generation ConfigGeneration,domain Domain)bool{found:=false;for _,projection:=range generation.Snapshot.Domains{if projection.Domain.Tenant==domain.Tenant&&projection.Domain.ID==domain.ID{found=sameDKIM(projection.Domain.DKIM,domain.DKIM)}};if !found{return false};expected:=fmt.Sprintf("%s._domainkey.%s %s:%s:/var/lib/cyberpanel/mail/current/opendkim/keys/%s/%s/private.key\n",domain.DKIM.Selector,domain.Name,domain.Name,domain.DKIM.Selector,domain.Name,domain.DKIM.Selector);for _,artifact:=range generation.Artifacts{if artifact.Role==ArtifactOpenDKIMKeyTable{return bytes.Contains(artifact.Content,[]byte(expected))}};return false}

func validDKIMRuntimeReceipt(receipt DKIMRuntimeReceipt,effect EffectRequest)bool{return validEffect(receipt.Effect,effect)&&receipt.Effect.Outcome==EffectConfirmed&&!receipt.RolledBack&&receipt.OpenDKIMActive&&validRotationDigest(receipt.GenerationDigest)&&receipt.Effect.AppliedGeneration==receipt.GenerationDigest&&validRotationDigest(receipt.OpenDKIMReloadDigest)&&validRotationDigest(receipt.OpenDKIMProbeDigest)}

func leaseFromMetadata(metadata secrets.Metadata)dkimSecretLease{return dkimSecretLease{ID:metadata.ID,OwnerTenantID:metadata.OwnerTenantID,Version:metadata.Version,BindingDigest:metadata.BindingDigest,Audience:metadata.Audience}}
func leaseMatches(lease dkimSecretLease,id,owner secrets.ID,audience secrets.AudienceBinding)bool{return lease.ID==id&&lease.OwnerTenantID==owner&&lease.Version==1&&validRotationDigest(lease.BindingDigest)&&sameRotationJSON(lease.Audience,audience)}
func revokeRequest(lease dkimSecretLease)secrets.RevokeRequest{return secrets.RevokeRequest{ID:lease.ID,OwnerTenantID:lease.OwnerTenantID,Purpose:secrets.PurposeDKIMKey,Audience:lease.Audience,ExpectedVersion:lease.Version,ExpectedBindingDigest:lease.BindingDigest}}
func sameDKIM(left,right DKIM)bool{return left.Selector==right.Selector&&left.PublicKey==right.PublicKey&&left.PrivateKeyRef==right.PrivateKeyRef&&left.Enabled==right.Enabled}

func validDKIMRotationRecord(record dkimRotationRecord)bool{if !validOpaque(record.TenantID)||!validOpaque(string(record.DomainID))||!validHostname(record.DomainName)||!validRotationDigest(record.PrepareToken)||record.BoundGeneration==0||record.Overlap<DKIMMinimumOverlap||record.Overlap>DKIMMaximumOverlap||record.PreparedAt.IsZero()||!record.Pending.Enabled||!validDKIMSelector(record.Pending.Selector)||!validOpaque(record.Pending.PrivateKeyRef)||record.Pending.PublicKey!=record.TXTValue||record.TXTName!=record.Pending.Selector+"._domainkey."+record.DomainName||canonicalTXTInvalid(record.TXTValue)||!validDKIMLease(record.PendingSecret){return false};if record.Previous.Enabled{if !validDKIMSelector(record.Previous.Selector)||!validOpaque(record.Previous.PrivateKeyRef)||record.PreviousSecret==nil||!validDKIMLease(*record.PreviousSecret){return false}}else if record.PreviousSecret!=nil{return false};for _,digest:=range []string{record.DNSProofDigest,record.MailGenerationDigest,record.OpenDKIMReloadDigest,record.OpenDKIMProbeDigest,record.LiveSelectorProofDigest}{if digest!=""&&!validRotationDigest(digest){return false}};switch record.State{case DKIMRotationPrepared:return record.ActiveGeneration==0&&record.ActivatedAt==nil&&record.OverlapUntil==nil&&record.PreviousRevokedAt==nil;case DKIMRotationOverlap:return record.ActiveGeneration==record.BoundGeneration+1&&record.ActivatedAt!=nil&&!record.ActivatedAt.IsZero()&&record.OverlapUntil!=nil&&record.OverlapUntil.After(*record.ActivatedAt)&&record.Previous.Enabled&&record.PreviousRevokedAt==nil;case DKIMRotationComplete:if record.ActiveGeneration!=record.BoundGeneration+1||record.ActivatedAt==nil||record.ActivatedAt.IsZero(){return false};if record.Previous.Enabled{return record.PreviousRevokedAt!=nil};return true;default:return false}}
func validDKIMLease(lease dkimSecretLease)bool{return lease.ID.Valid()&&lease.OwnerTenantID.Valid()&&lease.Version>0&&validRotationDigest(lease.BindingDigest)&&lease.Audience.Validate()==nil}
func canonicalTXTInvalid(value string)bool{_,err:=canonicalRotationTXT(value);return err!=nil}

func canonicalRotationTXT(value string)(string,error){tags:=map[string]string{};for _,part:=range strings.Split(value,";"){part=strings.TrimSpace(part);if part==""{continue};fields:=strings.SplitN(part,"=",2);if len(fields)!=2{return "",ErrInvalidCommand};key:=strings.ToLower(strings.TrimSpace(fields[0]));if key!="v"&&key!="k"&&key!="p"||tags[key]!=""{return "",ErrInvalidCommand};tags[key]=strings.TrimSpace(fields[1])};if !strings.EqualFold(tags["v"],"DKIM1")||!strings.EqualFold(tags["k"],"rsa")||tags["p"]==""{return "",ErrInvalidCommand};decoded,err:=base64.StdEncoding.DecodeString(tags["p"]);if err!=nil||len(decoded)<256{wipeRotationBytes(decoded);return "",ErrInvalidCommand};wipeRotationBytes(decoded);return "v=DKIM1;k=rsa;p="+tags["p"],nil}

func rotationMaterialID(prefix string,values ...string)secrets.ID{hash:=sha256.New();_,_=hash.Write([]byte(prefix));for _,value:=range values{_,_=hash.Write([]byte{0});_,_=hash.Write([]byte(value))};identifier,_:=secrets.NewID(prefix+"_"+hex.EncodeToString(hash.Sum(nil))[:48]);return identifier}
func rotationDigest(values ...string)string{hash:=sha256.New();for _,value:=range values{_,_=hash.Write([]byte(fmt.Sprintf("%d:",len(value))));_,_=hash.Write([]byte(value))};return hex.EncodeToString(hash.Sum(nil))}
func validRotationDigest(value string)bool{if len(value)!=64||value!=strings.ToLower(value){return false};_,err:=hex.DecodeString(value);return err==nil}
func sameRotationJSON(left,right any)bool{a,aErr:=json.Marshal(left);b,bErr:=json.Marshal(right);return aErr==nil&&bErr==nil&&bytes.Equal(a,b)}
func decodeRotationJSON(raw []byte,target any)error{decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil{return err};if err:=decoder.Decode(&struct{}{});!errors.Is(err,io.EOF){return ErrInvalidReceipt};return nil}
func mapRotationSecretError(err error)error{switch{case errors.Is(err,secrets.ErrConflict):return ErrConflict;case errors.Is(err,secrets.ErrForbidden):return ErrUnauthorized;case errors.Is(err,secrets.ErrNotFound),errors.Is(err,secrets.ErrRevoked):return ErrNotFound;case errors.Is(err,secrets.ErrInvalid):return ErrInvalidCommand;default:return err}}
func (service *DKIMRotationService)now()time.Time{if service.Now!=nil{return service.Now().UTC()};return time.Now().UTC()}
func wipeRotationBytes(values ...[]byte){for _,value:=range values{for index:=range value{value[index]=0};runtime.KeepAlive(value)}}
func wipeRotationRSAKey(key *rsa.PrivateKey){if key==nil{return};if key.D!=nil{key.D.SetInt64(0)};for _,prime:=range key.Primes{if prime!=nil{prime.SetInt64(0)}};if key.Precomputed.Dp!=nil{key.Precomputed.Dp.SetInt64(0)};if key.Precomputed.Dq!=nil{key.Precomputed.Dq.SetInt64(0)};if key.Precomputed.Qinv!=nil{key.Precomputed.Qinv.SetInt64(0)};runtime.KeepAlive(key)}
