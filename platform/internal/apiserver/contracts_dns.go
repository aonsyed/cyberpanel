package apiserver

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"net/http"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type DNSAuthorityService interface{
	ApplyZoneForTenant(context.Context,string,string,dns.ZoneSpec,[]dns.RecordSet,[]dns.TransferPeerSpec)(dns.AuthorityReceipt,error)
	DeleteZoneForTenant(context.Context,string,string,dns.ZoneSpec)(dns.AuthorityReceipt,error)
	Zone(context.Context,string,dns.ZoneID)(dns.ZoneSpec,error)
	ListZones(context.Context,string,int,string)([]dns.ZoneSpec,string,error)
	ListRecordSetsForTenant(context.Context,string,dns.ZoneSpec,int,string)([]dns.RecordSet,string,error)
}

type DNSZoneApplyPayload struct{Zone dns.ZoneSpec `json:"zone"`;RecordSets []dns.RecordSet `json:"record_sets"`;TransferPeers []dns.TransferPeerSpec `json:"transfer_peers"`}
type DNSZonePayload struct{Zone dns.ZoneSpec `json:"zone"`}
type DNSZoneDeletePayload struct{Zone dns.ZoneSpec `json:"zone"`}
type DNSZoneCreatePayload struct{Name string `json:"name"`;Mode dns.ZoneMode `json:"mode"`;PrimaryAddresses []netip.Addr `json:"primary_addresses,omitempty"`}
type DNSZonePagePayload struct{Limit uint16 `json:"limit"`;Cursor string `json:"cursor,omitempty"`}
type DNSZonePage struct{Items []dns.ZoneSpec `json:"items"`;NextCursor string `json:"next_cursor,omitempty"`}
type DNSRecordSetPagePayload struct{Zone dns.ZoneSpec `json:"zone"`;Limit uint16 `json:"limit"`;Cursor string `json:"cursor,omitempty"`}
type DNSRecordSetPage struct{Items []dns.RecordSet `json:"items"`;NextCursor string `json:"next_cursor,omitempty"`}
type DNSSECEnablePayload struct{Zone dns.ZoneSpec `json:"zone"`;Policy dns.DNSSECPolicy `json:"policy"`}

func registerDNSContracts(registry *Registry)error{
	permission:=identity.MustPermission("dns:manage")
	definitions:=[]Operation{
		{Name:"dns.zone.list",Permission:permission,Assurance:identity.AssurancePassword,Auth:AuthRequired,NewPayload:func()any{return &DNSZonePagePayload{}},ValidatePayload:validateDNSZonePage,ResolveScope:tenantScope},
		{Name:"dns.zone.create",Permission:permission,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DNSZoneCreatePayload{}},ValidatePayload:validateDNSZoneCreate,ResolveScope:tenantScope},
		{Name:"dns.zone.apply",Permission:permission,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DNSZoneApplyPayload{}},ValidatePayload:validateDNSZoneApply,ResolveScope:dnsExistingOrCreateScope},
		{Name:"dns.zone.delete",Permission:permission,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DNSZoneDeletePayload{}},ValidatePayload:validateDNSZoneDelete,ResolveScope:mailExistingScope},
		{Name:"dns.recordset.list",Permission:permission,Assurance:identity.AssurancePassword,Auth:AuthRequired,NewPayload:func()any{return &DNSRecordSetPagePayload{}},ValidatePayload:validateDNSRecordSetPage,ResolveScope:mailGetScope},
		{Name:"dns.dnssec.status",Permission:permission,Assurance:identity.AssurancePassword,Auth:AuthRequired,NewPayload:func()any{return &EmptyPayload{}},ResolveScope:mailGetScope},
		{Name:"dns.dnssec.enable",Permission:permission,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DNSSECEnablePayload{}},ValidatePayload:validateDNSSECEnable,ResolveScope:dnsExistingOrCreateScope},
		{Name:"dns.dnssec.confirm",Permission:permission,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DNSZonePayload{}},ValidatePayload:validateDNSZonePayload,ResolveScope:mailExistingScope},
		{Name:"dns.dnssec.rollover_start",Permission:permission,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DNSZonePayload{}},ValidatePayload:validateDNSZonePayload,ResolveScope:mailExistingScope},
		{Name:"dns.dnssec.rollover_finish",Permission:permission,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DNSZonePayload{}},ValidatePayload:validateDNSZonePayload,ResolveScope:mailExistingScope},
		{Name:"dns.dnssec.disable",Permission:permission,Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &DNSZonePayload{}},ValidatePayload:validateDNSZonePayload,ResolveScope:mailExistingScope},
	}
	for _,definition:=range definitions{if err:=register(registry,definition);err!=nil{return err}}
	return nil
}

func validateDNSZoneApply(value any)error{payload:=value.(*DNSZoneApplyPayload);if validateDNSZone(payload.Zone)!=nil||len(payload.RecordSets)>10000||len(payload.TransferPeers)>1000{return invalid("DNS zone")};for _,set:=range payload.RecordSets{if set.Validate(payload.Zone.Name)!=nil{return invalid("DNS record set")}};return nil}
func validateDNSZoneCreate(value any)error{payload:=value.(*DNSZoneCreatePayload);name,err:=dns.ParseName(payload.Name);if err!=nil||name.String()=="@"||(payload.Mode!=dns.ZoneNative&&payload.Mode!=dns.ZonePrimary&&payload.Mode!=dns.ZoneSecondary)||payload.Mode==dns.ZoneSecondary&&len(payload.PrimaryAddresses)==0||payload.Mode!=dns.ZoneSecondary&&len(payload.PrimaryAddresses)!=0{return invalid("DNS zone")};for _,address:=range payload.PrimaryAddresses{if !address.IsValid()||address.IsUnspecified()||address.IsMulticast(){return invalid("DNS primary")}};payload.Name=name.String();return nil}
func validateDNSZonePage(value any)error{payload:=value.(*DNSZonePagePayload);if payload.Limit>500{return invalid("DNS zone page")};if payload.Cursor!=""{name,err:=dns.ParseName(payload.Cursor);if err!=nil||name.String()=="@"{return invalid("DNS zone cursor")};payload.Cursor=name.String()};return nil}
func validateDNSZonePayload(value any)error{return validateDNSZone(value.(*DNSZonePayload).Zone)}
func validateDNSZoneDelete(value any)error{zone:=value.(*DNSZoneDeletePayload).Zone;if zone.ID!=""&&validateDNSZone(zone)!=nil{return invalid("DNS zone")};return nil}
func validateDNSRecordSetPage(value any)error{payload:=value.(*DNSRecordSetPagePayload);if payload.Zone.ID!=""&&validateDNSZone(payload.Zone)!=nil||payload.Limit>1000||len(payload.Cursor)>1024||strings.ContainsAny(payload.Cursor,"\x00\r\n"){return invalid("DNS record page")};return nil}
func validateDNSSECEnable(value any)error{payload:=value.(*DNSSECEnablePayload);if validateDNSZone(payload.Zone)!=nil{return invalid("DNSSEC zone")};if payload.Policy.Algorithm!=dns.DNSSECECDSAP256SHA256&&payload.Policy.Algorithm!=dns.DNSSECEd25519{return invalid("DNSSEC algorithm")};if payload.Policy.SignatureValidity<24*time.Hour||payload.Policy.SignatureValidity>90*24*time.Hour||payload.Policy.RolloverAfter<7*24*time.Hour||payload.Policy.PrepublishFor<time.Hour||payload.Policy.PrepublishFor>=payload.Policy.RolloverAfter{return invalid("DNSSEC policy")};return nil}
func validateDNSZone(zone dns.ZoneSpec)error{if !safeMailOpaque(string(zone.ID))||zone.Name.String()==""||!safeMailOpaque(zone.Account)||zone.Generation>1<<62{return invalid("DNS zone")};switch zone.Mode{case dns.ZoneNative,dns.ZonePrimary,dns.ZoneSecondary:default:return invalid("DNS zone mode")};if zone.SOA.Primary.String()==""||zone.SOA.Hostmaster.String()==""||zone.SOA.Refresh<300||zone.SOA.Retry<60||zone.SOA.Expire<86400||zone.SOA.Minimum<30||zone.SOA.DefaultTTL<30{return invalid("DNS SOA")};for _,address:=range zone.PrimaryAddresses{if !address.IsValid()||address.IsUnspecified()||address.IsMulticast(){return invalid("DNS primary")}};return nil}
func dnsExistingOrCreateScope(request RequestEnvelope,value any)(identity.Scope,error){if !safeMailOpaque(request.ResourceID){return identity.Scope{},invalid("DNS resource")};return tenantScope(request,value)}

func bindDNS(registry *Registry,services DomainServices)error{
	if services.DNSAuthority!=nil{
		if err:=registry.Bind("dns.zone.list",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){page:=value.(*DNSZonePagePayload);items,next,err:=services.DNSAuthority.ListZones(ctx,inv.Request.TenantID,int(page.Limit),page.Cursor);if err!=nil{return OperationResult{},mapDNSError(err)};return OperationResult{Status:http.StatusOK,Value:DNSZonePage{Items:items,NextCursor:next}},nil});err!=nil{return err}
		if err:=registry.Bind("dns.zone.create",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*DNSZoneCreatePayload);name,err:=dns.ParseName(payload.Name);if err!=nil{return OperationResult{},ErrInvalidRequest};primary,_:=dns.ParseName("ns1."+name.String());hostmaster,_:=dns.ParseName("hostmaster."+name.String());zone:=dns.ZoneSpec{ID:dns.ZoneID(effectID(inv)),TenantID:inv.Request.TenantID,Name:name,Mode:payload.Mode,SOA:dns.SOAConfig{Primary:primary,Hostmaster:hostmaster,Refresh:3600,Retry:600,Expire:1209600,Minimum:300,DefaultTTL:3600},PrimaryAddresses:append([]netip.Addr(nil),payload.PrimaryAddresses...),Account:inv.Request.TenantID,Generation:1};receipt,err:=services.DNSAuthority.ApplyZoneForTenant(ctx,inv.Request.TenantID,effectID(inv),zone,nil,nil);if err!=nil{return OperationResult{},mapDNSError(err)};return OperationResult{Status:http.StatusCreated,Value:map[string]any{"zone":zone,"receipt":receipt},Generation:zone.Generation},nil});err!=nil{return err}
		if err:=registry.Bind("dns.zone.apply",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*DNSZoneApplyPayload);if string(payload.Zone.ID)!=inv.Request.ResourceID{return OperationResult{},invalid("DNS zone identity")};payload.Zone.TenantID=inv.Request.TenantID;payload.Zone.Generation=inv.Request.ExpectedGeneration+1;for index:=range payload.RecordSets{payload.RecordSets[index].ZoneID=payload.Zone.ID};for index:=range payload.TransferPeers{payload.TransferPeers[index].ZoneID=payload.Zone.ID};receipt,err:=services.DNSAuthority.ApplyZoneForTenant(ctx,inv.Request.TenantID,effectID(inv),payload.Zone,payload.RecordSets,payload.TransferPeers);if err!=nil{return OperationResult{},mapDNSError(err)};return OperationResult{Status:http.StatusOK,Value:receipt,Generation:payload.Zone.Generation},nil});err!=nil{return err}
		if err:=registry.Bind("dns.zone.delete",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*DNSZoneDeletePayload);stored,err:=services.DNSAuthority.Zone(ctx,inv.Request.TenantID,dns.ZoneID(inv.Request.ResourceID));if err!=nil{return OperationResult{},mapDNSError(err)};if payload.Zone.ID!=""&&(payload.Zone.ID!=stored.ID||payload.Zone.Name.String()!=stored.Name.String()){return OperationResult{},ErrConflict};stored.Generation=inv.Request.ExpectedGeneration;receipt,err:=services.DNSAuthority.DeleteZoneForTenant(ctx,inv.Request.TenantID,effectID(inv),stored);if err!=nil{return OperationResult{},mapDNSError(err)};return OperationResult{Status:http.StatusOK,Value:receipt},nil});err!=nil{return err}
		if err:=registry.Bind("dns.recordset.list",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*DNSRecordSetPagePayload);stored,err:=services.DNSAuthority.Zone(ctx,inv.Request.TenantID,dns.ZoneID(inv.Request.ResourceID));if err!=nil{return OperationResult{},mapDNSError(err)};if payload.Zone.ID!=""&&(payload.Zone.ID!=stored.ID||payload.Zone.Name.String()!=stored.Name.String()){return OperationResult{},ErrConflict};items,next,err:=services.DNSAuthority.ListRecordSetsForTenant(ctx,inv.Request.TenantID,stored,int(payload.Limit),payload.Cursor);if err!=nil{return OperationResult{},mapDNSError(err)};return OperationResult{Status:http.StatusOK,Value:DNSRecordSetPage{Items:items,NextCursor:next}},nil});err!=nil{return err}
	}
	if services.DNSSEC!=nil{
		if err:=registry.Bind("dns.dnssec.status",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){status,found,err:=services.DNSSEC.Store.Load(ctx,inv.Request.TenantID,dns.ZoneID(inv.Request.ResourceID));if err!=nil{return OperationResult{},mapDNSError(err)};if !found{return OperationResult{},ErrNotFound};return OperationResult{Status:http.StatusOK,Value:status,Generation:status.Generation},nil});err!=nil{return err}
		if err:=registry.Bind("dns.dnssec.enable",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*DNSSECEnablePayload);zone,err:=storedDNSZone(ctx,services,inv,payload.Zone);if err!=nil{return OperationResult{},err};status,err:=services.DNSSEC.Enable(ctx,zone,payload.Policy,effectID(inv));if err!=nil{return OperationResult{},mapDNSError(err)};return OperationResult{Status:http.StatusOK,Value:status,Generation:status.Generation},nil});err!=nil{return err}
		bindings:=[]struct{name string;invoke func(context.Context,dns.ZoneSpec,uint64,string)(dns.DNSSECStatus,error)}{{"dns.dnssec.confirm",func(ctx context.Context,zone dns.ZoneSpec,expected uint64,_ string)(dns.DNSSECStatus,error){return services.DNSSEC.Confirm(ctx,zone,expected)}},{"dns.dnssec.rollover_start",services.DNSSEC.StartRollover},{"dns.dnssec.rollover_finish",services.DNSSEC.FinishRollover},{"dns.dnssec.disable",services.DNSSEC.Disable}}
		for _,binding:=range bindings{binding:=binding;if err:=registry.Bind(binding.name,func(ctx context.Context,inv Invocation,value any)(OperationResult,error){zone,err:=storedDNSZone(ctx,services,inv,value.(*DNSZonePayload).Zone);if err!=nil{return OperationResult{},err};status,err:=binding.invoke(ctx,zone,inv.Request.ExpectedGeneration,effectID(inv));if err!=nil{return OperationResult{},mapDNSError(err)};return OperationResult{Status:http.StatusOK,Value:status,Generation:status.Generation},nil});err!=nil{return err}}
	}
	return nil
}

func boundDNSSECZone(inv Invocation,zone dns.ZoneSpec)(dns.ZoneSpec,error){if string(zone.ID)!=inv.Request.ResourceID{return dns.ZoneSpec{},invalid("DNS zone identity")};zone.TenantID=inv.Request.TenantID;if zone.Generation==0{zone.Generation=1};return zone,nil}
func storedDNSZone(ctx context.Context,services DomainServices,inv Invocation,provided dns.ZoneSpec)(dns.ZoneSpec,error){if services.DNSAuthority==nil{return dns.ZoneSpec{},ErrUnavailable};stored,err:=services.DNSAuthority.Zone(ctx,inv.Request.TenantID,dns.ZoneID(inv.Request.ResourceID));if err!=nil{return dns.ZoneSpec{},mapDNSError(err)};if provided.ID!=stored.ID||provided.Name.String()!=stored.Name.String(){return dns.ZoneSpec{},ErrConflict};return stored,nil}
func mapDNSError(err error)error{switch{case err==nil:return nil;case errors.Is(err,dns.ErrInvalidDNS):return ErrInvalidRequest;case errors.Is(err,dns.ErrDNSConflict):return ErrConflict;case errors.Is(err,sql.ErrNoRows):return ErrNotFound;default:return err}}
