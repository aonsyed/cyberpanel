//go:build linux

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	hostingservice "github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

func migrationDNSIntent(scope migration.RuntimeScope,intent migration.ImportIntent)(dns.ZoneSpec,[]dns.RecordSet,error){
	var source migration.DNSZone;if json.Unmarshal(intent.Payload,&source)!=nil||source.SourceID!=intent.SourceID||source.Mode!="native"||source.DNSSEC||len(intent.Chunks)!=0||len(intent.SecretIDs)!=0{return dns.ZoneSpec{},nil,migration.ErrBlocked};name,err:=dns.ParseName(source.Name);if err!=nil{return dns.ZoneSpec{},nil,err}
	zone:=dns.ZoneSpec{ID:dns.ZoneID(intent.TargetID),TenantID:scope.TenantID,Name:name,Mode:dns.ZoneNative,Account:scope.TenantID,Generation:1};sets:=[]dns.RecordSet{};soa:=false;keys:=map[string]bool{}
	for _,record:=range source.RecordSets{owner,parseErr:=dns.ParseName(record.Name);if parseErr!=nil{return zone,nil,parseErr};if strings.EqualFold(record.Type,"SOA"){
		if soa||len(record.Values)!=1||(owner.String()!="@"&&owner.String()!=name.String()){return zone,nil,migration.ErrInvalid};fields:=strings.Fields(record.Values[0]);if len(fields)!=7{return zone,nil,migration.ErrInvalid};primary,parseErr:=dns.ParseName(fields[0]);if parseErr!=nil{return zone,nil,parseErr};hostmaster,parseErr:=dns.ParseName(fields[1]);if parseErr!=nil{return zone,nil,parseErr};values:=make([]uint32,4);for index:=range values{parsed,parseErr:=strconv.ParseUint(fields[index+3],10,32);if parseErr!=nil{return zone,nil,parseErr};values[index]=uint32(parsed)};if values[0]<300||values[1]<60||values[2]<86400||values[3]<30||record.TTL<30{return zone,nil,migration.ErrInvalid};zone.SOA=dns.SOAConfig{Primary:primary,Hostmaster:hostmaster,Refresh:values[0],Retry:values[1],Expire:values[2],Minimum:values[3],DefaultTTL:record.TTL};soa=true;continue
		};set,canonicalErr:=(dns.RecordSet{ZoneID:zone.ID,Owner:owner,Kind:dns.RRKind(strings.ToUpper(record.Type)),TTL:record.TTL,Records:append([]string(nil),record.Values...)}).Canonical(zone.Name);if canonicalErr!=nil{return zone,nil,canonicalErr};key:=set.Owner.String()+"|"+string(set.Kind);if keys[key]{return zone,nil,migration.ErrInvalid};keys[key]=true;sets=append(sets,set)
	}
	if !soa{return zone,nil,migration.ErrBlocked};sort.Slice(sets,func(i,j int)bool{return sets[i].Owner.String()+string(sets[i].Kind)<sets[j].Owner.String()+string(sets[j].Kind)});return zone,sets,nil
}

func (target *migrationHostTarget) stageDNS(ctx context.Context,scope migration.RuntimeScope,intent migration.ImportIntent)(migration.ImportEffect,error){
	zone,sets,err:=migrationDNSIntent(scope,intent);if err!=nil{return migration.ImportEffect{},err};proof,err:=target.observeDNS(ctx,scope,intent,false);if err!=nil{return migration.ImportEffect{},err}
	// This receipt describes validated desired state, explicitly not publication.
	// The actual PowerDNS broker is called only by activateEntries after fencing.
	effect:=migrationHostEffect(intent,struct{State string;Zone dns.ZoneSpec;Sets []dns.RecordSet;Absence string}{"dns-staged-unpublished",zone,sets,proof},1,0,uint64(len(sets)));effect.ErrorCode="DNS_STAGED_NOT_PUBLISHED";return effect,nil
}

func (target *migrationHostTarget) observeDNS(ctx context.Context,scope migration.RuntimeScope,intent migration.ImportIntent,active bool)(string,error){
	wanted,sets,err:=migrationDNSIntent(scope,intent);if err!=nil{return "",err}
	if !active{cursor:="";for{zones,next,listErr:=target.dns.ListZones(ctx,scope.TenantID,500,cursor);if listErr!=nil{return "",listErr};for _,candidate:=range zones{if candidate.ID==wanted.ID||candidate.Name==wanted.Name{return "",migration.ErrConflict}};if next==""{break};if next==cursor{return "",migration.ErrConflict};cursor=next};return migrationHostDigest(struct{Tenant,ID,State string}{scope.TenantID,string(wanted.ID),"not-published"}),nil}
	zone,err:=target.dns.Zone(ctx,scope.TenantID,wanted.ID)
	if err!=nil{return "",err};if zone.Name!=wanted.Name||zone.TenantID!=wanted.TenantID||zone.Mode!=wanted.Mode||zone.Generation!=1||zone.SOA!=wanted.SOA{return "",migration.ErrConflict}
	observed:=[]dns.RecordSet{};cursor:="";for{page,next,listErr:=target.dns.ListRecordSets(ctx,zone,500,cursor);if listErr!=nil{return "",listErr};observed=append(observed,page...);if len(observed)>100000{return "",migration.ErrCapacity};if next==""{break};if next==cursor{return "",migration.ErrConflict};cursor=next}
	canonical:=func(values []dns.RecordSet)(string,error){for index:=range values{value,err:=values[index].Canonical(zone.Name);if err!=nil{return "",err};sort.Strings(value.Records);values[index]=value};sort.Slice(values,func(i,j int)bool{return values[i].Owner.String()+string(values[i].Kind)<values[j].Owner.String()+string(values[j].Kind)});return migrationHostDigest(values),nil};left,err:=canonical(sets);if err!=nil{return "",err};right,err:=canonical(observed);if err!=nil||left!=right{return "",errors.Join(migration.ErrConflict,err)};return migrationHostDigest(struct{Zone dns.ZoneSpec;RecordDigest string}{zone,right}),nil
}

func (target *migrationHostTarget) activateEntries(ctx context.Context,value migration.Migration,plan migration.Plan,scope migration.RuntimeScope,entries []migration.ImportIntent)(migration.ActivationReceipt,error){
	var raw []byte;var state,planDigest string;var fence uint64;err:=target.db.QueryRowContext(ctx,`SELECT state,plan_digest,fence,receipt_json FROM panel_migration_host_activations WHERE migration_id=?`,value.ID.String()).Scan(&state,&planDigest,&fence,&raw)
	if err==nil{if planDigest!=plan.DryRunDigest||fence!=value.Fence{return migration.ActivationReceipt{},migration.ErrConflict};if state!="active"{return migration.ActivationReceipt{},migration.ErrAmbiguous};var receipt migration.ActivationReceipt;if json.Unmarshal(raw,&receipt)!=nil{return receipt,migration.ErrConflict};return receipt,nil};if !errors.Is(err,sql.ErrNoRows){return migration.ActivationReceipt{},err}
	// Preflight every staged effect before routing or DNS changes. The durable
	// activating marker makes a crash conservative: observe, never blind replay.
	for _,intent:=range entries{switch intent.Kind{case migration.ImportSite:if _,err=target.probeSite(ctx,scope,intent,false);err!=nil{return migration.ActivationReceipt{},err};case migration.ImportDNSZone:if _,err=target.observeDNS(ctx,scope,intent,false);err!=nil{return migration.ActivationReceipt{},err};case migration.ImportDatabase:effect,observeErr:=target.observeDatabase(ctx,intent);if observeErr!=nil||effect.Status!=migration.ImportEffectApplied{return migration.ActivationReceipt{},errors.Join(migration.ErrBlocked,observeErr)};default:return migration.ActivationReceipt{},migration.ErrBlocked}}
	if _,err=target.db.ExecContext(ctx,`INSERT INTO panel_migration_host_activations(migration_id,plan_digest,fence,state,receipt_json) VALUES(?,?,?,'activating','{}')`,value.ID.String(),plan.DryRunDigest,value.Fence);err!=nil{return migration.ActivationReceipt{},err}
	routing:=[]string{};dnsProofs:=[]string{}
	for _,intent:=range entries{if intent.Kind!=migration.ImportSite{continue};if err=target.sourceFence(ctx,value);err!=nil{return migration.ActivationReceipt{},errors.Join(migration.ErrAmbiguous,err)};tenant,_:=site.NewTenantID(scope.TenantID);id,_:=site.NewSiteID(intent.TargetID.String());aggregate,loadErr:=target.sites.Load(ctx,tenant,id);if loadErr!=nil{return migration.ActivationReceipt{},errors.Join(migration.ErrAmbiguous,loadErr)};receipt,applyErr:=target.hosting.Handle(ctx,hostingservice.MarkProvisioned{CommandID:"migration-activate-"+intent.EffectID,Actor:hostingservice.Actor{TenantID:tenant},TenantID:tenant,SiteID:id,ExpectedGeneration:aggregate.Generation()});if applyErr!=nil||receipt.Effect.Outcome!=hostingservice.EffectConfirmed||receipt.Effect.ProbeDigest==""{return migration.ActivationReceipt{},errors.Join(migration.ErrAmbiguous,applyErr)};proof,probeErr:=target.probeSite(ctx,scope,intent,true);if probeErr!=nil{return migration.ActivationReceipt{},errors.Join(migration.ErrAmbiguous,probeErr)};routing=append(routing,receipt.Effect.ProbeDigest,proof)}
	for _,intent:=range entries{if intent.Kind!=migration.ImportDNSZone{continue};if err=target.sourceFence(ctx,value);err!=nil{return migration.ActivationReceipt{},errors.Join(migration.ErrAmbiguous,err)};zone,sets,parseErr:=migrationDNSIntent(scope,intent);if parseErr!=nil{return migration.ActivationReceipt{},errors.Join(migration.ErrAmbiguous,parseErr)};receipt,applyErr:=target.dns.ApplyZone(ctx,"migration-dns-"+intent.EffectID,zone,sets,nil);if applyErr!=nil||receipt.EffectID!="migration-dns-"+intent.EffectID||receipt.ZoneID!=zone.ID||receipt.Serial==0||receipt.ObservedAt.IsZero(){return migration.ActivationReceipt{},errors.Join(migration.ErrAmbiguous,applyErr)};proof,probeErr:=target.observeDNS(ctx,scope,intent,true);if probeErr!=nil{return migration.ActivationReceipt{},errors.Join(migration.ErrAmbiguous,probeErr)};dnsProofs=append(dnsProofs,migrationHostDigest(receipt),proof)}
	receipt:=migration.ActivationReceipt{MigrationID:value.ID,TargetGeneration:value.TargetGeneration+1,RoutingDigest:migrationHostDigest(routing),DNSDigest:migrationHostDigest(dnsProofs),ActivatedAt:time.Now().UTC()};receipt.EvidenceDigest=migrationHostDigest(receipt);raw,err=json.Marshal(receipt);if err!=nil{return receipt,errors.Join(migration.ErrAmbiguous,err)}
	transaction,err:=target.db.BeginTx(ctx,nil);if err!=nil{return receipt,errors.Join(migration.ErrAmbiguous,err)};defer transaction.Rollback();if _,err=transaction.ExecContext(ctx,`UPDATE panel_migration_host_effects SET state='active' WHERE migration_id=? AND state='dark'`,value.ID.String());err!=nil{return receipt,errors.Join(migration.ErrAmbiguous,err)};if _,err=transaction.ExecContext(ctx,`UPDATE panel_migration_host_activations SET state='active',receipt_json=? WHERE migration_id=? AND state='activating'`,raw,value.ID.String());err!=nil{return receipt,errors.Join(migration.ErrAmbiguous,err)};return receipt,transaction.Commit()
}

func (target *migrationHostTarget) VerifyActive(ctx context.Context,value migration.Migration,plan migration.Plan,receipt migration.ActivationReceipt)(migration.Verification,error){
	target.mu.Lock();defer target.mu.Unlock();if receipt.MigrationID!=value.ID||receipt.EvidenceDigest==""{return migration.Verification{},migration.ErrInvalid};entries,err:=target.entries(ctx,value,plan);if err!=nil{return migration.Verification{},err};scope,err:=target.scopes.LoadByMigration(ctx,value.ID);if err!=nil{return migration.Verification{},err};proofs:=[]string{};for _,intent:=range entries{switch intent.Kind{case migration.ImportSite:proof,probeErr:=target.probeSite(ctx,scope,intent,true);if probeErr!=nil{return migration.Verification{},probeErr};proofs=append(proofs,proof);case migration.ImportDNSZone:proof,probeErr:=target.observeDNS(ctx,scope,intent,true);if probeErr!=nil{return migration.Verification{},probeErr};proofs=append(proofs,proof);case migration.ImportDatabase:effect,probeErr:=target.observeDatabase(ctx,intent);if probeErr!=nil||effect.Status!=migration.ImportEffectApplied{return migration.Verification{},errors.Join(migration.ErrBlocked,probeErr)};proofs=append(proofs,effect.EvidenceDigest)}}
	proofs=append(proofs,migrationHostDigest(struct{Root,AbsentDomains string}{value.ManifestRoot,"mail,certificates,access_credentials,cron,repositories,containers,backups"}));verification:=migration.Verification{HTTP:true,Files:true,Database:true,DNS:true,Mail:true,Cron:true,Containers:true,Backups:true,EvidenceDigest:migrationHostDigest(proofs),ObservedAt:time.Now().UTC()}
	if target.applicationProbe==nil{return verification,migration.ErrBlocked};application,err:=target.applicationProbe.VerifyActive(ctx,value,plan,receipt);if err!=nil||!application.HTTP||!application.PHP||!application.TLS||application.EvidenceDigest==""{return verification,errors.Join(migration.ErrBlocked,err)};verification.PHP=true;verification.TLS=true;verification.EvidenceDigest=migrationHostDigest([]string{verification.EvidenceDigest,application.EvidenceDigest});return verification,nil
}

func (target *migrationHostTarget) DeactivateMigration(context.Context,migration.ActivationReceipt)error{
	// The existing host gateway exposes no write-watermark observation. Once a
	// public route may have served writes, automatic rollback must not erase them.
	return migration.ErrWriteFrontier
}
