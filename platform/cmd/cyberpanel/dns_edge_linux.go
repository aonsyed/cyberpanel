//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
)

// dnsEdge is the browser-oriented adapter over the same generation-guarded
// PowerDNS authority used by the canonical API. It contains no second DNS
// implementation and never edits provider files or invokes a native command.
type dnsEdge struct {
	authority interface {
		Zone(context.Context,string,dns.ZoneID)(dns.ZoneSpec,error)
		ImportRecordSets(context.Context,string,dns.ZoneSpec,[]dns.RecordSet,bool)(dns.AuthorityReceipt,error)
	}
	dnssec *dns.DNSSECCoordinator
}

func newDNSEdge(authority *dns.PowerDNSControlClient, dnssec *dns.DNSSECCoordinator) (apiserver.DNSEdgeService,error) {
	if authority==nil||dnssec==nil{return nil,errors.New("DNS edge dependencies required")}
	return &dnsEdge{authority:authority,dnssec:dnssec},nil
}

func (edge *dnsEdge) ImportZone(ctx context.Context,call apiserver.EdgeCall,payload apiserver.DNSZoneImportPayload)(apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection],error){
	if edge==nil||edge.authority==nil||ctx==nil||call.TenantID==""||call.ResourceID==""{return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},dns.ErrInvalidDNS}
	zone,err:=edge.authority.Zone(ctx,call.TenantID,dns.ZoneID(call.ResourceID));if err!=nil{return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},err}
	if call.ExpectedGeneration!=0&&zone.Generation!=call.ExpectedGeneration{return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},dns.ErrDNSConflict}
	sets:=make([]dns.RecordSet,0,len(payload.RecordSets));byKey:=make(map[string]dns.RecordSet,len(payload.RecordSets))
	for _,input:=range payload.RecordSets{owner,parseErr:=dns.ParseName(input.Name);if parseErr!=nil{return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},parseErr};set:=dns.RecordSet{ZoneID:zone.ID,Owner:owner,Kind:dns.RRKind(strings.ToUpper(input.Type)),TTL:input.TTL,Records:append([]string(nil),input.Values...)};canonical,canonicalErr:=set.Canonical(zone.Name);if canonicalErr!=nil{return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},canonicalErr};byKey[canonical.Owner.String()+"|"+string(canonical.Kind)]=canonical}
	sets=sets[:0];keys:=make([]string,0,len(byKey));for key:=range byKey{keys=append(keys,key)};sort.Strings(keys);for _,key:=range keys{sets=append(sets,byKey[key])}
	zone.Generation++;receipt,err:=edge.authority.ImportRecordSets(ctx,dnsEdgeEffect(call,"import"),zone,sets,payload.Replace);if err!=nil{return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},err}
	state:=edge.dnssecState(ctx,zone);projection:=apiserver.DNSZoneMutationProjection{ID:string(zone.ID),Name:zone.Name.String(),Serial:receipt.Serial,DNSSEC:state,Generation:zone.Generation}
	return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{OperationID:receipt.EffectID,State:"applied",Generation:zone.Generation,Resource:projection},nil
}

func (edge *dnsEdge) ConfigureDNSSEC(ctx context.Context,call apiserver.EdgeCall,payload apiserver.DNSSECConfigurePayload)(apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection],error){
	if edge==nil||edge.authority==nil||edge.dnssec==nil||ctx==nil||call.TenantID==""||call.ResourceID==""{return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},dns.ErrInvalidDNS}
	zone,err:=edge.authority.Zone(ctx,call.TenantID,dns.ZoneID(call.ResourceID));if err!=nil{return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},err}
	status,found,err:=edge.dnssec.Store.Load(ctx,call.TenantID,zone.ID);if err!=nil{return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},err}
	if call.ExpectedGeneration!=0&&zone.Generation!=call.ExpectedGeneration&&(!found||status.Generation!=call.ExpectedGeneration){return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},dns.ErrDNSConflict}
	effect:=dnsEdgeEffect(call,"dnssec")
	if payload.Enabled{
		if !found||status.Phase==dns.DNSSECDisabled||status.Phase==dns.DNSSECFailed{algorithm:=dns.DNSSECECDSAP256SHA256;if payload.Algorithm=="ed25519"{algorithm=dns.DNSSECEd25519};status,err=edge.dnssec.Enable(ctx,zone,dns.DNSSECPolicy{Algorithm:algorithm,SplitKeys:false,SignatureValidity:payload.SignatureValidity,RolloverAfter:payload.RolloverAfter,PrepublishFor:payload.PrepublishFor},effect)}
	}else if found&&status.Phase!=dns.DNSSECDisabled{status,err=edge.dnssec.Disable(ctx,zone,status.Generation,effect)}else{status=dns.DNSSECStatus{ZoneID:zone.ID,TenantID:zone.TenantID,Phase:dns.DNSSECDisabled}}
	if err!=nil{return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{},err}
	projection:=apiserver.DNSZoneMutationProjection{ID:string(zone.ID),Name:zone.Name.String(),DNSSEC:string(status.Phase),Generation:status.Generation}
	return apiserver.EdgeMutation[apiserver.DNSZoneMutationProjection]{OperationID:effect,State:"applied",Generation:status.Generation,Resource:projection},nil
}

func(edge *dnsEdge)dnssecState(ctx context.Context,zone dns.ZoneSpec)string{status,found,err:=edge.dnssec.Store.Load(ctx,zone.TenantID,zone.ID);if err!=nil||!found{return string(dns.DNSSECDisabled)};return string(status.Phase)}
func dnsEdgeEffect(call apiserver.EdgeCall,purpose string)string{sum:=sha256.Sum256([]byte("dns-edge-v1\x00"+call.TenantID+"\x00"+call.ResourceID+"\x00"+call.CommandID+"\x00"+call.IdempotencyKey+"\x00"+purpose));return "dnsedge_"+hex.EncodeToString(sum[:])}

var _ apiserver.DNSEdgeService=(*dnsEdge)(nil)
