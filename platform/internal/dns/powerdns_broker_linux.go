//go:build linux

package dns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const PowerDNSDaemonSocketPath = "/run/cyberpanel/pdnsd.sock"
const powerDNSDaemonLockPath = "/run/cyberpanel/pdnsd.lock"
const powerDNSBrokerFrameLimit = 64 << 20

var (
	ErrPowerDNSDaemonUnauthorized = errors.New("PowerDNS daemon peer is unauthorized")
	ErrPowerDNSDaemonProtocol = errors.New("PowerDNS daemon protocol failure")
	ErrPowerDNSDaemonOperation = errors.New("PowerDNS daemon operation failed")
)

type PowerDNSBrokerOperation string

const (
	PowerDNSBrokerApplyConfiguration PowerDNSBrokerOperation = "apply_configuration"
	PowerDNSBrokerApplyZone PowerDNSBrokerOperation = "apply_zone"
	PowerDNSBrokerDeleteZone PowerDNSBrokerOperation = "delete_zone"
	PowerDNSBrokerReload PowerDNSBrokerOperation = "reload"
	PowerDNSBrokerProbe PowerDNSBrokerOperation = "probe"
	PowerDNSBrokerRediscover PowerDNSBrokerOperation = "rediscover"
	PowerDNSBrokerNotifyZone PowerDNSBrokerOperation = "notify_zone"
	PowerDNSBrokerGetZone PowerDNSBrokerOperation = "get_zone"
	PowerDNSBrokerListZones PowerDNSBrokerOperation = "list_zones"
	PowerDNSBrokerListRecordSets PowerDNSBrokerOperation = "list_record_sets"
	PowerDNSBrokerImportRecordSets PowerDNSBrokerOperation = "import_record_sets"
	PowerDNSBrokerPresentACMETXT PowerDNSBrokerOperation = "present_acme_txt"
	PowerDNSBrokerRemoveACMETXT PowerDNSBrokerOperation = "remove_acme_txt"
	PowerDNSBrokerDNSSECGenerate PowerDNSBrokerOperation = "dnssec_generate"
	PowerDNSBrokerDNSSECRetire PowerDNSBrokerOperation = "dnssec_retire"
	PowerDNSBrokerDNSSECRemove PowerDNSBrokerOperation = "dnssec_remove"
	PowerDNSBrokerDNSSECProve PowerDNSBrokerOperation = "dnssec_prove"
)

type PowerDNSBrokerOutcome string

const (
	PowerDNSBrokerConfirmed PowerDNSBrokerOutcome = "confirmed"
	PowerDNSBrokerRejected PowerDNSBrokerOutcome = "rejected"
	PowerDNSBrokerUnknown PowerDNSBrokerOutcome = "unknown"
)

type PowerDNSBrokerRequest struct {
	Version uint8 `json:"version"`
	RequestID string `json:"request_id"`
	Operation PowerDNSBrokerOperation `json:"operation"`
	Deadline time.Time `json:"deadline"`
	EffectID string `json:"effect_id,omitempty"`
	Configuration *PowerDNSConfigSnapshot `json:"configuration,omitempty"`
	Zone *ZoneSpec `json:"zone,omitempty"`
	Delete *PowerDNSDeleteSpec `json:"delete,omitempty"`
	RecordSets []RecordSet `json:"record_sets,omitempty"`
	TransferPeers []TransferPeerSpec `json:"transfer_peers,omitempty"`
	NotifyName *DNSName `json:"notify_name,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	ZoneID ZoneID `json:"zone_id,omitempty"`
	Limit uint32 `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	Replace bool `json:"replace,omitempty"`
	ACMEOwner string `json:"acme_owner,omitempty"`
	ACMEValue string `json:"acme_value,omitempty"`
	DNSSECPolicy *DNSSECPolicy `json:"dnssec_policy,omitempty"`
	DNSSECKeys []DNSSECKeyDescriptor `json:"dnssec_keys,omitempty"`
	DNSSECDS []DSRecord `json:"dnssec_ds,omitempty"`
}

type PowerDNSDeleteSpec struct {
	ID ZoneID `json:"id"`
	TenantID string `json:"tenant_id"`
	Name string `json:"name,omitempty"`
	Generation uint64 `json:"generation"`
}

func (request PowerDNSBrokerRequest) Validate(now time.Time) error {
	if request.Version != 1 || !validPowerDNSBrokerID(request.RequestID) || request.Deadline.Before(now.Add(-time.Second)) || request.Deadline.After(now.Add(5*time.Minute)) {
		return ErrPowerDNSDaemonProtocol
	}
	if request.Operation!=PowerDNSBrokerPresentACMETXT&&request.Operation!=PowerDNSBrokerRemoveACMETXT&&(request.ACMEOwner!=""||request.ACMEValue!=""){return ErrPowerDNSDaemonProtocol}
	if !powerDNSBrokerDNSSECOperation(request.Operation)&&(request.DNSSECPolicy!=nil||len(request.DNSSECKeys)!=0||len(request.DNSSECDS)!=0){return ErrPowerDNSDaemonProtocol}
	if request.Operation!=PowerDNSBrokerImportRecordSets&&request.Replace{return ErrPowerDNSDaemonProtocol}
	switch request.Operation {
	case PowerDNSBrokerApplyConfiguration:
		if request.Configuration == nil || request.Zone != nil || request.Delete != nil || request.NotifyName != nil || request.EffectID != "" || len(request.RecordSets) != 0 || len(request.TransferPeers) != 0 || request.Configuration.NodeID == "" || request.Configuration.Generation == 0 || request.Configuration.Database.Fingerprint == "" {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerApplyZone:
		if request.Zone == nil || request.Configuration != nil || request.Delete != nil || request.NotifyName != nil || !validPowerDNSEffectID(request.EffectID) || validateZoneSpec(*request.Zone, request.RecordSets, request.TransferPeers) != nil {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerDeleteZone:
		if request.Delete == nil || request.Configuration != nil || request.Zone != nil || request.NotifyName != nil || len(request.RecordSets) != 0 || len(request.TransferPeers) != 0 || !validPowerDNSEffectID(request.EffectID) || request.Delete.ID == "" || request.Delete.TenantID == "" || request.Delete.Generation == 0 {
			return ErrPowerDNSDaemonProtocol
		}
		if request.Delete.Name != "" {
			name, err := ParseName(request.Delete.Name)
			if err != nil || !validPowerDNSZoneName(name) || name.String() != request.Delete.Name {
				return ErrPowerDNSDaemonProtocol
			}
		}
	case PowerDNSBrokerNotifyZone:
		if request.NotifyName == nil || request.Configuration != nil || request.Zone != nil || request.Delete != nil || request.EffectID != "" || len(request.RecordSets) != 0 || len(request.TransferPeers) != 0 || !validPowerDNSZoneName(*request.NotifyName) {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerReload, PowerDNSBrokerProbe, PowerDNSBrokerRediscover:
		if request.Configuration != nil || request.Zone != nil || request.Delete != nil || request.NotifyName != nil || request.EffectID != "" || len(request.RecordSets) != 0 || len(request.TransferPeers) != 0 {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerGetZone:
		if !validPowerDNSIdentityValue(request.TenantID,512)||request.ZoneID==""||request.Limit!=0||request.Cursor!=""||request.Configuration!=nil||request.Zone!=nil||request.Delete!=nil||request.NotifyName!=nil||request.EffectID!=""||len(request.RecordSets)!=0||len(request.TransferPeers)!=0{return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerListZones:
		if !validPowerDNSIdentityValue(request.TenantID,512)||request.ZoneID!=""||request.Limit==0||request.Limit>500||len(request.Cursor)>253||request.Configuration!=nil||request.Zone!=nil||request.Delete!=nil||request.NotifyName!=nil||request.EffectID!=""||len(request.RecordSets)!=0||len(request.TransferPeers)!=0{return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerListRecordSets:
		if !validPowerDNSIdentityValue(request.TenantID,512)||request.ZoneID==""||request.Limit==0||request.Limit>1000||len(request.Cursor)>1024||request.Configuration!=nil||request.Zone!=nil||request.Delete!=nil||request.NotifyName!=nil||request.EffectID!=""||len(request.RecordSets)!=0||len(request.TransferPeers)!=0{return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerImportRecordSets:
		if request.Zone==nil||validatePowerDNSDNSSECZone(*request.Zone)!=nil||!validPowerDNSEffectID(request.EffectID)||len(request.RecordSets)==0||len(request.RecordSets)>10000||request.Configuration!=nil||request.Delete!=nil||request.NotifyName!=nil||request.TenantID!=""||request.ZoneID!=""||request.Limit!=0||request.Cursor!=""||len(request.TransferPeers)!=0{return ErrPowerDNSDaemonProtocol};for _,set:=range request.RecordSets{if set.ZoneID!=request.Zone.ID||set.Validate(request.Zone.Name)!=nil{return ErrPowerDNSDaemonProtocol}}
	case PowerDNSBrokerPresentACMETXT,PowerDNSBrokerRemoveACMETXT:
		owner,err:=ParseName(request.ACMEOwner);if err!=nil||!strings.HasPrefix(owner.String(),"_acme-challenge.")||!validPowerDNSIdentityValue(request.TenantID,512)||!validPowerDNSEffectID(request.EffectID)||request.ACMEValue==""||len(request.ACMEValue)>128||request.Configuration!=nil||request.Zone!=nil||request.Delete!=nil||request.NotifyName!=nil||request.ZoneID!=""||request.Limit!=0||request.Cursor!=""||len(request.RecordSets)!=0||len(request.TransferPeers)!=0{return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerDNSSECGenerate:
		if request.Zone==nil||request.DNSSECPolicy==nil||validatePowerDNSDNSSECZone(*request.Zone)!=nil||validateDNSSECPolicy(*request.DNSSECPolicy)!=nil||!validPowerDNSEffectID(request.EffectID)||!emptyPowerDNSBrokerRequestExceptDNSSEC(request)||len(request.DNSSECKeys)!=0||len(request.DNSSECDS)!=0{return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerDNSSECRetire:
		if request.Zone==nil||request.DNSSECPolicy!=nil||validatePowerDNSDNSSECZone(*request.Zone)!=nil||!validPowerDNSEffectID(request.EffectID)||!emptyPowerDNSBrokerRequestExceptDNSSEC(request)||!validPowerDNSDNSSECKeys(request.DNSSECKeys)||len(request.DNSSECDS)!=0{return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerDNSSECRemove:
		if request.Zone==nil||request.DNSSECPolicy!=nil||validatePowerDNSDNSSECZone(*request.Zone)!=nil||!validPowerDNSEffectID(request.EffectID)||!emptyPowerDNSBrokerRequestExceptDNSSEC(request)||len(request.DNSSECKeys)!=0||len(request.DNSSECDS)!=0{return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerDNSSECProve:
		if request.Zone==nil||request.DNSSECPolicy!=nil||validatePowerDNSDNSSECZone(*request.Zone)!=nil||request.EffectID!=""||!emptyPowerDNSBrokerRequestExceptDNSSEC(request)||!validPowerDNSDNSSECKeys(request.DNSSECKeys)||!validPowerDNSDSRecords(request.DNSSECDS){return ErrPowerDNSDaemonProtocol}
	default:
		return ErrPowerDNSDaemonProtocol
	}
	return nil
}

func powerDNSBrokerDNSSECOperation(operation PowerDNSBrokerOperation)bool{switch operation{case PowerDNSBrokerDNSSECGenerate,PowerDNSBrokerDNSSECRetire,PowerDNSBrokerDNSSECRemove,PowerDNSBrokerDNSSECProve:return true};return false}
func emptyPowerDNSBrokerRequestExceptDNSSEC(request PowerDNSBrokerRequest)bool{return request.Configuration==nil&&request.Delete==nil&&request.NotifyName==nil&&request.TenantID==""&&request.ZoneID==""&&request.Limit==0&&request.Cursor==""&&request.ACMEOwner==""&&request.ACMEValue==""&&len(request.RecordSets)==0&&len(request.TransferPeers)==0}
func validPowerDNSDNSSECKeys(keys []DNSSECKeyDescriptor)bool{if len(keys)==0||len(keys)>8{return false};seen:=map[string]bool{};for _,key:=range keys{if key.ID==""||key.KeyTag==0||key.PublicDNSKEY==""||!validPowerDNSKeyHandle(key.PrivateHandle)||key.CreatedAt.IsZero()||(key.Role!="ksk"&&key.Role!="zsk"&&key.Role!="csk")||seen[key.PrivateHandle]{return false};if _,err:=canonicalDNSKEY(key.PublicDNSKEY);err!=nil{return false};seen[key.PrivateHandle]=true};return true}
func validPowerDNSDSRecords(records []DSRecord)bool{if len(records)==0||len(records)>8{return false};for _,record:=range records{if record.KeyTag==0||record.Algorithm==0||(record.DigestType!=1&&record.DigestType!=2&&record.DigestType!=4)||len(record.Digest)<40||len(record.Digest)>128{ return false };if _,err:=hex.DecodeString(record.Digest);err!=nil{return false}};return true}

type PowerDNSZoneBrokerReceipt struct {
	Authority AuthorityReceipt `json:"authority"`
	Rediscover PowerDNSRuntimeReceipt `json:"rediscover"`
	Notify PowerDNSRuntimeReceipt `json:"notify"`
	Probe PowerDNSRuntimeReceipt `json:"probe"`
	DatabaseCommitted bool `json:"database_committed"`
}

type PowerDNSBrokerResponse struct {
	Version uint8 `json:"version"`
	RequestID string `json:"request_id"`
	Operation PowerDNSBrokerOperation `json:"operation"`
	Outcome PowerDNSBrokerOutcome `json:"outcome"`
	FailureCode string `json:"failure_code,omitempty"`
	Activation PowerDNSActivationReceipt `json:"activation,omitempty"`
	Zone PowerDNSZoneBrokerReceipt `json:"zone,omitempty"`
	Runtime PowerDNSRuntimeReceipt `json:"runtime,omitempty"`
	ZoneSpec ZoneSpec `json:"zone_spec,omitempty"`
	Zones []ZoneSpec `json:"zones,omitempty"`
	RecordSetPage []RecordSet `json:"record_set_page,omitempty"`
	NextCursor string `json:"next_cursor,omitempty"`
	DNSSECActivation KeyActivationReceipt `json:"dnssec_activation,omitempty"`
	DNSSECProof DNSSECProof `json:"dnssec_proof,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

func (response PowerDNSBrokerResponse) Validate(request PowerDNSBrokerRequest, now time.Time) error {
	if response.Version != 1 || response.RequestID != request.RequestID || response.Operation != request.Operation || response.ObservedAt.IsZero() || response.ObservedAt.After(now.Add(time.Minute)) {
		return ErrPowerDNSDaemonProtocol
	}
	switch response.Outcome {
	case PowerDNSBrokerConfirmed:
		if response.FailureCode != "" {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerRejected, PowerDNSBrokerUnknown:
		if !validPowerDNSFailureCode(response.FailureCode) {
			return ErrPowerDNSDaemonProtocol
		}
	default:
		return ErrPowerDNSDaemonProtocol
	}
	switch request.Operation {
	case PowerDNSBrokerApplyConfiguration:
		if response.Activation.DatabaseFingerprint != "" && response.Activation.DatabaseFingerprint != request.Configuration.Database.Fingerprint {
			return ErrPowerDNSDaemonProtocol
		}
		if response.Outcome == PowerDNSBrokerConfirmed {
			if !validPowerDNSActivationReceipt(response.Activation, *request.Configuration, now) {
				return ErrPowerDNSDaemonProtocol
			}
		} else if !validOptionalPowerDNSActivationReceipt(response.Activation, now) {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerApplyZone, PowerDNSBrokerDeleteZone:
		if response.Zone.DatabaseCommitted {
			if !validPowerDNSAuthorityReceipt(response.Zone.Authority, request, now) || !validPowerDNSRuntimeReceipt(response.Zone.Rediscover, PowerDNSRediscoverZones, now) || !validPowerDNSRuntimeReceipt(response.Zone.Probe, PowerDNSProbeService, now) {
				return ErrPowerDNSDaemonProtocol
			}
			if request.Operation == PowerDNSBrokerApplyZone && request.Zone.Mode == ZonePrimary && !validPowerDNSRuntimeReceipt(response.Zone.Notify, PowerDNSNotifyZone, now) {
				return ErrPowerDNSDaemonProtocol
			}
			if response.Outcome == PowerDNSBrokerRejected {
				return ErrPowerDNSDaemonProtocol
			}
		} else if response.Outcome != PowerDNSBrokerRejected {
			return ErrPowerDNSDaemonProtocol
		}
		if response.Outcome == PowerDNSBrokerConfirmed && (!response.Zone.Rediscover.Success || !response.Zone.Probe.Success || request.Operation == PowerDNSBrokerApplyZone && request.Zone.Mode == ZonePrimary && !response.Zone.Notify.Success) {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerImportRecordSets:
		if response.Zone.DatabaseCommitted{if !validPowerDNSAuthorityReceipt(response.Zone.Authority,request,now)||!validPowerDNSRuntimeReceipt(response.Zone.Rediscover,PowerDNSRediscoverZones,now)||!validPowerDNSRuntimeReceipt(response.Zone.Probe,PowerDNSProbeService,now){return ErrPowerDNSDaemonProtocol};if request.Zone.Mode==ZonePrimary&&!validPowerDNSRuntimeReceipt(response.Zone.Notify,PowerDNSNotifyZone,now){return ErrPowerDNSDaemonProtocol}}else if response.Outcome!=PowerDNSBrokerRejected{return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerReload:
		if response.Outcome == PowerDNSBrokerConfirmed && !validSuccessfulPowerDNSRuntime(response.Runtime, PowerDNSReloadService, now) || response.Outcome != PowerDNSBrokerConfirmed && !validOptionalPowerDNSRuntime(response.Runtime, PowerDNSReloadService, now) {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerProbe:
		if response.Outcome == PowerDNSBrokerConfirmed && (!validSuccessfulPowerDNSRuntime(response.Runtime, PowerDNSProbeService, now) || !response.Runtime.Healthy) || response.Outcome != PowerDNSBrokerConfirmed && !validOptionalPowerDNSRuntime(response.Runtime, PowerDNSProbeService, now) {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerRediscover:
		if response.Outcome == PowerDNSBrokerConfirmed && !validSuccessfulPowerDNSRuntime(response.Runtime, PowerDNSRediscoverZones, now) || response.Outcome != PowerDNSBrokerConfirmed && !validOptionalPowerDNSRuntime(response.Runtime, PowerDNSRediscoverZones, now) {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerNotifyZone:
		if response.Outcome == PowerDNSBrokerConfirmed && !validSuccessfulPowerDNSRuntime(response.Runtime, PowerDNSNotifyZone, now) || response.Outcome != PowerDNSBrokerConfirmed && !validOptionalPowerDNSRuntime(response.Runtime, PowerDNSNotifyZone, now) {
			return ErrPowerDNSDaemonProtocol
		}
	case PowerDNSBrokerGetZone:
		if response.Outcome==PowerDNSBrokerConfirmed&&(response.ZoneSpec.ID!=request.ZoneID||response.ZoneSpec.TenantID!=request.TenantID||validateZoneSpec(response.ZoneSpec,nil,nil)!=nil){return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerListZones:
		if response.Outcome==PowerDNSBrokerConfirmed{if uint32(len(response.Zones))>request.Limit||len(response.NextCursor)>253{return ErrPowerDNSDaemonProtocol};for _,zone:=range response.Zones{if zone.TenantID!=request.TenantID||validateZoneSpec(zone,nil,nil)!=nil{return ErrPowerDNSDaemonProtocol}}}
	case PowerDNSBrokerListRecordSets:
		if response.Outcome==PowerDNSBrokerConfirmed{if uint32(len(response.RecordSetPage))>request.Limit||len(response.NextCursor)>1024{return ErrPowerDNSDaemonProtocol};for _,set:=range response.RecordSetPage{if set.ZoneID!=request.ZoneID{return ErrPowerDNSDaemonProtocol}}}
	case PowerDNSBrokerPresentACMETXT,PowerDNSBrokerRemoveACMETXT:
		if response.Outcome==PowerDNSBrokerConfirmed{if response.Zone.Authority.EffectID!=request.EffectID||response.Zone.Authority.ZoneID==""||response.Zone.Authority.Serial==0||response.Zone.Authority.ObservedAt.IsZero()||!response.Zone.DatabaseCommitted||!validPowerDNSRuntimeReceipt(response.Zone.Notify,PowerDNSNotifyZone,now)||!validPowerDNSRuntimeReceipt(response.Zone.Probe,PowerDNSProbeService,now)||!response.Zone.Notify.Success||!response.Zone.Probe.Success{return ErrPowerDNSDaemonProtocol}}
	case PowerDNSBrokerDNSSECGenerate:
		if response.Outcome==PowerDNSBrokerConfirmed&&!validKeyReceipt(response.DNSSECActivation,request.EffectID){return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerDNSSECRetire,PowerDNSBrokerDNSSECRemove:
		if response.Outcome==PowerDNSBrokerConfirmed&&response.FailureCode!=""{return ErrPowerDNSDaemonProtocol}
	case PowerDNSBrokerDNSSECProve:
		if response.Outcome==PowerDNSBrokerConfirmed&&(!validDNSSECProof(response.DNSSECProof)||response.DNSSECProof.DNSKEYDigest!=digestDNSSECPublicKeys(request.DNSSECKeys)||response.DNSSECProof.DSDigest!=digestPowerDNSDS(request.DNSSECDS)){return ErrPowerDNSDaemonProtocol}
	}
	return nil
}

type PowerDNSBrokerTransport interface {
	RoundTrip(context.Context, PowerDNSBrokerRequest) (PowerDNSBrokerResponse, error)
}

type PowerDNSDaemonClient struct {
	Transport PowerDNSBrokerTransport
	Now func() time.Time
}

func NewLocalPowerDNSDaemonClient() *PowerDNSDaemonClient {
	return &PowerDNSDaemonClient{Transport: PowerDNSFramedTransport{Dialer: PowerDNSUnixDialer{}}}
}

func (client *PowerDNSDaemonClient) now() time.Time {
	if client.Now != nil {
		return client.Now().UTC()
	}
	return time.Now().UTC()
}

func (client *PowerDNSDaemonClient) request(ctx context.Context, request PowerDNSBrokerRequest) (PowerDNSBrokerResponse, error) {
	if client == nil || client.Transport == nil || ctx == nil {
		return PowerDNSBrokerResponse{}, ErrPowerDNSDaemonProtocol
	}
	requestID, err := newPowerDNSBrokerID()
	if err != nil {
		return PowerDNSBrokerResponse{}, err
	}
	request.Version = 1
	request.RequestID = requestID
	request.Deadline = client.now().Add(2 * time.Minute)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(request.Deadline) {
		request.Deadline = deadline
	}
	if err = request.Validate(client.now()); err != nil {
		return PowerDNSBrokerResponse{}, err
	}
	response, err := client.Transport.RoundTrip(ctx, request)
	if err != nil {
		return PowerDNSBrokerResponse{}, err
	}
	if err = response.Validate(request, client.now()); err != nil {
		return PowerDNSBrokerResponse{}, err
	}
	return response, powerDNSBrokerOutcomeError(response)
}

func (client *PowerDNSDaemonClient) ApplyConfiguration(ctx context.Context, snapshot PowerDNSConfigSnapshot) (PowerDNSActivationReceipt, error) {
	response, err := client.request(ctx, PowerDNSBrokerRequest{Operation: PowerDNSBrokerApplyConfiguration, Configuration: &snapshot})
	return response.Activation, err
}

func (client *PowerDNSDaemonClient) ApplyZone(ctx context.Context, effectID string, spec ZoneSpec, sets []RecordSet, peers []TransferPeerSpec) (PowerDNSZoneBrokerReceipt, error) {
	response, err := client.request(ctx, PowerDNSBrokerRequest{Operation: PowerDNSBrokerApplyZone, EffectID: effectID, Zone: &spec, RecordSets: sets, TransferPeers: peers})
	return response.Zone, err
}

func (client *PowerDNSDaemonClient) DeleteZone(ctx context.Context, effectID string, spec ZoneSpec) (PowerDNSZoneBrokerReceipt, error) {
	deletion := PowerDNSDeleteSpec{ID: spec.ID, TenantID: spec.TenantID, Name: spec.Name.String(), Generation: spec.Generation}
	response, err := client.request(ctx, PowerDNSBrokerRequest{Operation: PowerDNSBrokerDeleteZone, EffectID: effectID, Delete: &deletion})
	return response.Zone, err
}

func (client *PowerDNSDaemonClient) Reload(ctx context.Context) (PowerDNSRuntimeReceipt, error) {
	response, err := client.request(ctx, PowerDNSBrokerRequest{Operation: PowerDNSBrokerReload})
	return response.Runtime, err
}

func (client *PowerDNSDaemonClient) Probe(ctx context.Context) (PowerDNSRuntimeReceipt, error) {
	response, err := client.request(ctx, PowerDNSBrokerRequest{Operation: PowerDNSBrokerProbe})
	return response.Runtime, err
}

func (client *PowerDNSDaemonClient) Rediscover(ctx context.Context) (PowerDNSRuntimeReceipt, error) {
	response, err := client.request(ctx, PowerDNSBrokerRequest{Operation: PowerDNSBrokerRediscover})
	return response.Runtime, err
}

func (client *PowerDNSDaemonClient) NotifyZone(ctx context.Context, zone DNSName) (PowerDNSRuntimeReceipt, error) {
	response, err := client.request(ctx, PowerDNSBrokerRequest{Operation: PowerDNSBrokerNotifyZone, NotifyName: &zone})
	return response.Runtime, err
}

func (client *PowerDNSDaemonClient) Zone(ctx context.Context,tenant string,id ZoneID)(ZoneSpec,error){response,err:=client.request(ctx,PowerDNSBrokerRequest{Operation:PowerDNSBrokerGetZone,TenantID:tenant,ZoneID:id});return response.ZoneSpec,err}
func (client *PowerDNSDaemonClient) ListZones(ctx context.Context,tenant string,limit int,cursor string)([]ZoneSpec,string,error){response,err:=client.request(ctx,PowerDNSBrokerRequest{Operation:PowerDNSBrokerListZones,TenantID:tenant,Limit:uint32(limit),Cursor:cursor});return response.Zones,response.NextCursor,err}
func (client *PowerDNSDaemonClient) ListRecordSets(ctx context.Context,zone ZoneSpec,limit int,cursor string)([]RecordSet,string,error){if zone.ID==""||zone.TenantID==""{return nil,"",ErrInvalidDNS};response,err:=client.request(ctx,PowerDNSBrokerRequest{Operation:PowerDNSBrokerListRecordSets,TenantID:zone.TenantID,ZoneID:zone.ID,Limit:uint32(limit),Cursor:cursor});return response.RecordSetPage,response.NextCursor,err}
func(client *PowerDNSDaemonClient)ImportRecordSets(ctx context.Context,effectID string,zone ZoneSpec,sets []RecordSet,replace bool)(AuthorityReceipt,error){response,err:=client.request(ctx,PowerDNSBrokerRequest{Operation:PowerDNSBrokerImportRecordSets,EffectID:effectID,Zone:&zone,RecordSets:sets,Replace:replace});return response.Zone.Authority,err}
func(client *PowerDNSDaemonClient)MutateACMETXT(ctx context.Context,tenant,owner,value,effectID string,remove bool)(AuthorityReceipt,error){operation:=PowerDNSBrokerPresentACMETXT;if remove{operation=PowerDNSBrokerRemoveACMETXT};response,err:=client.request(ctx,PowerDNSBrokerRequest{Operation:operation,TenantID:tenant,ACMEOwner:owner,ACMEValue:value,EffectID:effectID});return response.Zone.Authority,err}
func(client *PowerDNSDaemonClient)GenerateAndPublish(ctx context.Context,zone ZoneSpec,policy DNSSECPolicy,effectID string)(KeyActivationReceipt,error){response,err:=client.request(ctx,PowerDNSBrokerRequest{Operation:PowerDNSBrokerDNSSECGenerate,Zone:&zone,DNSSECPolicy:&policy,EffectID:effectID});return response.DNSSECActivation,err}
func(client *PowerDNSDaemonClient)Retire(ctx context.Context,zone ZoneSpec,keys []DNSSECKeyDescriptor,effectID string)error{_,err:=client.request(ctx,PowerDNSBrokerRequest{Operation:PowerDNSBrokerDNSSECRetire,Zone:&zone,DNSSECKeys:keys,EffectID:effectID});return err}
func(client *PowerDNSDaemonClient)Remove(ctx context.Context,zone ZoneSpec,effectID string)error{_,err:=client.request(ctx,PowerDNSBrokerRequest{Operation:PowerDNSBrokerDNSSECRemove,Zone:&zone,EffectID:effectID});return err}
func(client *PowerDNSDaemonClient)Prove(ctx context.Context,zone ZoneSpec,keys []DNSSECKeyDescriptor,records []DSRecord)(DNSSECProof,error){response,err:=client.request(ctx,PowerDNSBrokerRequest{Operation:PowerDNSBrokerDNSSECProve,Zone:&zone,DNSSECKeys:keys,DNSSECDS:records});return response.DNSSECProof,err}

type PowerDNSControlClient struct{Daemon *PowerDNSDaemonClient}
func NewLocalPowerDNSControlClient()*PowerDNSControlClient{return &PowerDNSControlClient{Daemon:NewLocalPowerDNSDaemonClient()}}
func (client *PowerDNSControlClient)ApplyZone(ctx context.Context,effectID string,spec ZoneSpec,sets []RecordSet,peers []TransferPeerSpec)(AuthorityReceipt,error){if client==nil||client.Daemon==nil{return AuthorityReceipt{},ErrInvalidDNS};receipt,err:=client.Daemon.ApplyZone(ctx,effectID,spec,sets,peers);return receipt.Authority,err}
func (client *PowerDNSControlClient)DeleteZone(ctx context.Context,effectID string,spec ZoneSpec)(AuthorityReceipt,error){if client==nil||client.Daemon==nil{return AuthorityReceipt{},ErrInvalidDNS};receipt,err:=client.Daemon.DeleteZone(ctx,effectID,spec);return receipt.Authority,err}
func (client *PowerDNSControlClient)Zone(ctx context.Context,tenant string,id ZoneID)(ZoneSpec,error){if client==nil||client.Daemon==nil{return ZoneSpec{},ErrInvalidDNS};return client.Daemon.Zone(ctx,tenant,id)}
func (client *PowerDNSControlClient)ListZones(ctx context.Context,tenant string,limit int,cursor string)([]ZoneSpec,string,error){if client==nil||client.Daemon==nil{return nil,"",ErrInvalidDNS};return client.Daemon.ListZones(ctx,tenant,limit,cursor)}
func (client *PowerDNSControlClient)ListRecordSets(ctx context.Context,zone ZoneSpec,limit int,cursor string)([]RecordSet,string,error){if client==nil||client.Daemon==nil{return nil,"",ErrInvalidDNS};return client.Daemon.ListRecordSets(ctx,zone,limit,cursor)}
func(client *PowerDNSControlClient)ImportRecordSets(ctx context.Context,effectID string,zone ZoneSpec,sets []RecordSet,replace bool)(AuthorityReceipt,error){if client==nil||client.Daemon==nil{return AuthorityReceipt{},ErrInvalidDNS};return client.Daemon.ImportRecordSets(ctx,effectID,zone,sets,replace)}
func(client *PowerDNSControlClient)PresentACMETXT(ctx context.Context,tenant,owner,value,effectID string)error{if client==nil||client.Daemon==nil{return ErrInvalidDNS};_,err:=client.Daemon.MutateACMETXT(ctx,tenant,owner,value,effectID,false);return err}
func(client *PowerDNSControlClient)RemoveACMETXT(ctx context.Context,tenant,owner,value,effectID string)error{if client==nil||client.Daemon==nil{return ErrInvalidDNS};_,err:=client.Daemon.MutateACMETXT(ctx,tenant,owner,value,effectID,true);return err}
func(client *PowerDNSControlClient)GenerateAndPublish(ctx context.Context,zone ZoneSpec,policy DNSSECPolicy,effectID string)(KeyActivationReceipt,error){if client==nil||client.Daemon==nil{return KeyActivationReceipt{},ErrInvalidDNS};return client.Daemon.GenerateAndPublish(ctx,zone,policy,effectID)}
func(client *PowerDNSControlClient)Retire(ctx context.Context,zone ZoneSpec,keys []DNSSECKeyDescriptor,effectID string)error{if client==nil||client.Daemon==nil{return ErrInvalidDNS};return client.Daemon.Retire(ctx,zone,keys,effectID)}
func(client *PowerDNSControlClient)Remove(ctx context.Context,zone ZoneSpec,effectID string)error{if client==nil||client.Daemon==nil{return ErrInvalidDNS};return client.Daemon.Remove(ctx,zone,effectID)}
func(client *PowerDNSControlClient)Prove(ctx context.Context,zone ZoneSpec,keys []DNSSECKeyDescriptor,records []DSRecord)(DNSSECProof,error){if client==nil||client.Daemon==nil{return DNSSECProof{},ErrInvalidDNS};return client.Daemon.Prove(ctx,zone,keys,records)}

type PowerDNSUnixDialer struct{}

func (PowerDNSUnixDialer) DialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", PowerDNSDaemonSocketPath)
}

type PowerDNSConnectionDialer interface {
	DialContext(context.Context) (net.Conn, error)
}

type PowerDNSFramedTransport struct {
	Dialer PowerDNSConnectionDialer
}

func (transport PowerDNSFramedTransport) RoundTrip(ctx context.Context, request PowerDNSBrokerRequest) (PowerDNSBrokerResponse, error) {
	if transport.Dialer == nil {
		return PowerDNSBrokerResponse{}, ErrPowerDNSDaemonProtocol
	}
	connection, err := transport.Dialer.DialContext(ctx)
	if err != nil {
		return PowerDNSBrokerResponse{}, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	if err = connection.SetDeadline(request.Deadline); err != nil {
		return PowerDNSBrokerResponse{}, err
	}
	if err = writePowerDNSBrokerFrame(connection, request); err != nil {
		return PowerDNSBrokerResponse{}, err
	}
	var reply powerDNSWireReply
	if err = readPowerDNSBrokerFrame(connection, &reply); err != nil {
		return PowerDNSBrokerResponse{}, err
	}
	if reply.ProtocolError != "" {
		return PowerDNSBrokerResponse{}, ErrPowerDNSDaemonProtocol
	}
	return reply.Response, nil
}

type PowerDNSDaemonPeerPolicy struct {
	AllowedUIDs map[uint32]bool
}

func NewPowerDNSDaemonPeerPolicy(controlUID uint32) (*PowerDNSDaemonPeerPolicy, error) {
	if controlUID == 0 {
		return nil, ErrInvalidDNS
	}
	return &PowerDNSDaemonPeerPolicy{AllowedUIDs: map[uint32]bool{0: true, controlUID: true}}, nil
}

func (policy *PowerDNSDaemonPeerPolicy) Authorize(connection net.Conn) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || policy == nil {
		return ErrPowerDNSDaemonUnauthorized
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return ErrPowerDNSDaemonUnauthorized
	}
	var credential *syscall.Ucred
	var credentialErr error
	if err = raw.Control(func(fd uintptr) {
		credential, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credentialErr != nil || credential == nil || credential.Pid <= 1 || !policy.AllowedUIDs[credential.Uid] {
		return ErrPowerDNSDaemonUnauthorized
	}
	return nil
}

type PowerDNSUnixListener struct {
	*net.UnixListener
	lock *os.File
	once sync.Once
}

func ListenPowerDNSDaemon(controlGID uint32) (*PowerDNSUnixListener, error) {
	if controlGID == 0 {
		return nil, ErrInvalidDNS
	}
	directory := filepath.Dir(PowerDNSDaemonSocketPath)
	if err := os.MkdirAll(directory, 0750); err != nil {
		return nil, err
	}
	if err := validatePowerDNSBrokerDirectory(directory); err != nil {
		return nil, err
	}
	lock, err := acquirePowerDNSDaemonLock()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*PowerDNSUnixListener, error) {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
		return nil, cause
	}
	if existing, statErr := os.Lstat(PowerDNSDaemonSocketPath); statErr == nil {
		metadata, ok := existing.Sys().(*syscall.Stat_t)
		if existing.Mode()&os.ModeSocket == 0 || !ok || metadata.Uid != 0 {
			return fail(ErrPowerDNSDaemonUnauthorized)
		}
		if err = os.Remove(PowerDNSDaemonSocketPath); err != nil {
			return fail(err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fail(statErr)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: PowerDNSDaemonSocketPath, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chown(PowerDNSDaemonSocketPath, 0, int(controlGID)); err == nil {
		err = os.Chmod(PowerDNSDaemonSocketPath, 0660)
	}
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(PowerDNSDaemonSocketPath)
		return fail(err)
	}
	return &PowerDNSUnixListener{UnixListener: listener, lock: lock}, nil
}

func (listener *PowerDNSUnixListener) Close() error {
	if listener == nil {
		return nil
	}
	var result error
	listener.once.Do(func() {
		if listener.UnixListener != nil {
			result = listener.UnixListener.Close()
		}
		if err := os.Remove(PowerDNSDaemonSocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
		if listener.lock != nil {
			result = errors.Join(result, syscall.Flock(int(listener.lock.Fd()), syscall.LOCK_UN), listener.lock.Close())
		}
	})
	return result
}

func acquirePowerDNSDaemonLock() (*os.File, error) {
	fd, err := syscall.Open(powerDNSDaemonLockPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), powerDNSDaemonLockPath)
	info, err := lock.Stat()
	metadata, ok := infoSyscallStat(info)
	if err != nil || info == nil || !info.Mode().IsRegular() || !ok || metadata.Uid != 0 || info.Mode().Perm()&0077 != 0 {
		_ = lock.Close()
		return nil, ErrPowerDNSDaemonUnauthorized
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func infoSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	return metadata, ok
}

func validatePowerDNSBrokerDirectory(directory string) error {
	if directory != "/run/cyberpanel" {
		return ErrPowerDNSDaemonUnauthorized
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.Join(ErrPowerDNSDaemonUnauthorized, err)
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		return ErrPowerDNSDaemonUnauthorized
	}
	return nil
}

type PowerDNSDaemonServer struct {
	Host *LinuxPowerDNSHost
	Authority *SecuredPowerDNSAuthority
	Peer *PowerDNSDaemonPeerPolicy
	MaximumConcurrent uint32
	Now func() time.Time
	once sync.Once
	semaphore chan struct{}
	operationMu sync.Mutex
}

func NewPowerDNSDaemonServer(host *LinuxPowerDNSHost, authority *SecuredPowerDNSAuthority, peer *PowerDNSDaemonPeerPolicy) (*PowerDNSDaemonServer, error) {
	if host == nil || authority == nil || peer == nil || !powerDNSSHA256(authority.DatabaseIdentity().Fingerprint) || !powerDNSSHA256(host.ControlDatabaseFingerprint) {
		return nil, ErrInvalidDNS
	}
	return &PowerDNSDaemonServer{Host: host, Authority: authority, Peer: peer}, nil
}

func (server *PowerDNSDaemonServer) Serve(listener net.Listener) error {
	if server == nil || server.Host == nil || server.Authority == nil || server.Peer == nil || listener == nil {
		return ErrInvalidDNS
	}
	identity := server.Authority.DatabaseIdentity()
	if identity.Purpose != PowerDNSAuthoritativePurpose || !powerDNSSHA256(identity.Fingerprint) {
		return ErrPowerDNSDatabaseIsolation
	}
	server.once.Do(func() {
		maximum := server.MaximumConcurrent
		if maximum == 0 {
			maximum = 8
		}
		if maximum > 32 {
			maximum = 32
		}
		server.semaphore = make(chan struct{}, maximum)
	})
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case server.semaphore <- struct{}{}:
			go func(connection net.Conn) {
				defer func() { <-server.semaphore; _ = connection.Close() }()
				server.serve(connection)
			}(connection)
		default:
			_ = connection.Close()
		}
	}
}

func (server *PowerDNSDaemonServer) serve(connection net.Conn) {
	if server.Peer.Authorize(connection) != nil {
		return
	}
	now := time.Now().UTC()
	if server.Now != nil {
		now = server.Now().UTC()
	}
	_ = connection.SetReadDeadline(now.Add(15 * time.Second))
	var request PowerDNSBrokerRequest
	if readPowerDNSBrokerFrame(connection, &request) != nil || request.Validate(now) != nil {
		_ = writePowerDNSBrokerFrame(connection, powerDNSWireReply{ProtocolError: "invalid_request"})
		return
	}
	_ = connection.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
	defer cancel()
	server.operationMu.Lock()
	defer server.operationMu.Unlock()
	response := server.dispatch(ctx, request)
	if response.Validate(request, time.Now().UTC()) != nil {
		_ = writePowerDNSBrokerFrame(connection, powerDNSWireReply{ProtocolError: "invalid_response"})
		return
	}
	_ = writePowerDNSBrokerFrame(connection, powerDNSWireReply{Response: response})
}

func (server *PowerDNSDaemonServer) dispatch(ctx context.Context, request PowerDNSBrokerRequest) PowerDNSBrokerResponse {
	response := PowerDNSBrokerResponse{Version: 1, RequestID: request.RequestID, Operation: request.Operation, ObservedAt: time.Now().UTC()}
	if server.Now != nil {
		response.ObservedAt = server.Now().UTC()
	}
	var err error
	switch request.Operation {
	case PowerDNSBrokerApplyConfiguration:
		identity := server.Authority.DatabaseIdentity()
		if request.Configuration.Database.Fingerprint != identity.Fingerprint {
			err = ErrPowerDNSDatabaseIsolation
		} else {
			response.Activation, err = server.Host.ApplyConfiguration(ctx, *request.Configuration)
		}
	case PowerDNSBrokerApplyZone:
		response.Zone.Authority, err = server.Authority.ApplyZone(ctx, request.EffectID, *request.Zone, request.RecordSets, request.TransferPeers)
		if err == nil {
			response.Zone.DatabaseCommitted = true
			response.Zone.Rediscover, err = server.Host.Rediscover(ctx)
			response.Zone.Rediscover = completePowerDNSRuntimeReceipt(response.Zone.Rediscover, PowerDNSRediscoverZones, err, response.ObservedAt)
			var notifyErr error
			if request.Zone.Mode == ZonePrimary {
				response.Zone.Notify, notifyErr = server.Host.NotifyZone(ctx, request.Zone.Name)
				response.Zone.Notify = completePowerDNSRuntimeReceipt(response.Zone.Notify, PowerDNSNotifyZone, notifyErr, response.ObservedAt)
			}
			response.Zone.Probe, probeErr := server.Host.Probe(ctx)
			response.Zone.Probe = completePowerDNSRuntimeReceipt(response.Zone.Probe, PowerDNSProbeService, probeErr, response.ObservedAt)
			err = errors.Join(err, notifyErr, probeErr)
		}
	case PowerDNSBrokerDeleteZone:
		deletion := ZoneSpec{ID: request.Delete.ID, TenantID: request.Delete.TenantID, Generation: request.Delete.Generation}
		if request.Delete.Name != "" {
			deletion.Name, _ = ParseName(request.Delete.Name)
		}
		response.Zone.Authority, err = server.Authority.DeleteZone(ctx, request.EffectID, deletion)
		if err == nil {
			response.Zone.DatabaseCommitted = true
			response.Zone.Rediscover, err = server.Host.Rediscover(ctx)
			response.Zone.Rediscover = completePowerDNSRuntimeReceipt(response.Zone.Rediscover, PowerDNSRediscoverZones, err, response.ObservedAt)
			response.Zone.Probe, probeErr := server.Host.Probe(ctx)
			response.Zone.Probe = completePowerDNSRuntimeReceipt(response.Zone.Probe, PowerDNSProbeService, probeErr, response.ObservedAt)
			err = errors.Join(err, probeErr)
		}
	case PowerDNSBrokerReload:
		response.Runtime, err = server.Host.Reload(ctx)
	case PowerDNSBrokerProbe:
		response.Runtime, err = server.Host.Probe(ctx)
	case PowerDNSBrokerRediscover:
		response.Runtime, err = server.Host.Rediscover(ctx)
	case PowerDNSBrokerNotifyZone:
		response.Runtime, err = server.Host.NotifyZone(ctx, *request.NotifyName)
	case PowerDNSBrokerGetZone:
		response.ZoneSpec,err=server.Authority.Zone(ctx,request.TenantID,request.ZoneID)
	case PowerDNSBrokerListZones:
		response.Zones,response.NextCursor,err=server.Authority.ListZones(ctx,request.TenantID,int(request.Limit),request.Cursor)
	case PowerDNSBrokerListRecordSets:
		var zone ZoneSpec;zone,err=server.Authority.Zone(ctx,request.TenantID,request.ZoneID);if err==nil{response.RecordSetPage,response.NextCursor,err=server.Authority.ListRecordSets(ctx,zone,int(request.Limit),request.Cursor)}
	case PowerDNSBrokerImportRecordSets:
		response.Zone.Authority,err=server.Authority.ImportRecordSets(ctx,request.EffectID,*request.Zone,request.RecordSets,request.Replace);if err==nil{response.Zone.DatabaseCommitted=true;response.Zone.Rediscover,err=server.Host.Rediscover(ctx);response.Zone.Rediscover=completePowerDNSRuntimeReceipt(response.Zone.Rediscover,PowerDNSRediscoverZones,err,response.ObservedAt);var notifyErr error;if request.Zone.Mode==ZonePrimary{response.Zone.Notify,notifyErr=server.Host.NotifyZone(ctx,request.Zone.Name);response.Zone.Notify=completePowerDNSRuntimeReceipt(response.Zone.Notify,PowerDNSNotifyZone,notifyErr,response.ObservedAt)};response.Zone.Probe,probeErr:=server.Host.Probe(ctx);response.Zone.Probe=completePowerDNSRuntimeReceipt(response.Zone.Probe,PowerDNSProbeService,probeErr,response.ObservedAt);err=errors.Join(err,notifyErr,probeErr)}
	case PowerDNSBrokerPresentACMETXT,PowerDNSBrokerRemoveACMETXT:
		response.Zone.Authority,err=server.Authority.MutateACMETXT(ctx,request.EffectID,request.TenantID,request.ACMEOwner,request.ACMEValue,request.Operation==PowerDNSBrokerRemoveACMETXT)
		if err==nil{response.Zone.DatabaseCommitted=true;zone,zoneErr:=server.Authority.Zone(ctx,request.TenantID,response.Zone.Authority.ZoneID);if zoneErr!=nil{err=zoneErr}else{response.Zone.Notify,zoneErr=server.Host.NotifyZone(ctx,zone.Name);response.Zone.Notify=completePowerDNSRuntimeReceipt(response.Zone.Notify,PowerDNSNotifyZone,zoneErr,response.ObservedAt);response.Zone.Probe,probeErr:=server.Host.Probe(ctx);response.Zone.Probe=completePowerDNSRuntimeReceipt(response.Zone.Probe,PowerDNSProbeService,probeErr,response.ObservedAt);err=errors.Join(zoneErr,probeErr)}}
	case PowerDNSBrokerDNSSECGenerate:
		response.DNSSECActivation,err=server.Host.GenerateAndPublishDNSSEC(ctx,*request.Zone,*request.DNSSECPolicy,request.EffectID)
	case PowerDNSBrokerDNSSECRetire:
		err=server.Host.RetireDNSSEC(ctx,*request.Zone,request.DNSSECKeys,request.EffectID)
	case PowerDNSBrokerDNSSECRemove:
		err=server.Host.RemoveDNSSEC(ctx,*request.Zone,request.EffectID)
	case PowerDNSBrokerDNSSECProve:
		response.DNSSECProof,err=server.Host.ProveDNSSEC(ctx,*request.Zone,request.DNSSECKeys,request.DNSSECDS)
	default:
		err = ErrPowerDNSDaemonProtocol
	}
	if err == nil {
		response.Outcome = PowerDNSBrokerConfirmed
		return response
	}
	response.FailureCode = powerDNSBrokerFailureCode(err)
	configurationMayBeActive := request.Operation == PowerDNSBrokerApplyConfiguration && !response.Activation.RolledBack && (response.Activation.Reload.Operation != "" || response.Activation.Probe.Operation != "")
	dnssecMayHaveChanged:=request.Operation==PowerDNSBrokerDNSSECGenerate||request.Operation==PowerDNSBrokerDNSSECRetire||request.Operation==PowerDNSBrokerDNSSECRemove
	if configurationMayBeActive || dnssecMayHaveChanged || (request.Operation == PowerDNSBrokerApplyZone || request.Operation == PowerDNSBrokerDeleteZone || request.Operation==PowerDNSBrokerImportRecordSets) && response.Zone.DatabaseCommitted {
		response.Outcome = PowerDNSBrokerUnknown
	} else {
		response.Outcome = PowerDNSBrokerRejected
	}
	return response
}

type powerDNSWireReply struct {
	Response PowerDNSBrokerResponse `json:"response"`
	ProtocolError string `json:"protocol_error,omitempty"`
}

func writePowerDNSBrokerFrame(writer io.Writer, value any) error {
	content, err := json.Marshal(value)
	if err != nil || len(content) == 0 || len(content) > powerDNSBrokerFrameLimit {
		return ErrPowerDNSDaemonProtocol
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(content)))
	if err = writePowerDNSBrokerBytes(writer, header[:]); err != nil {
		return err
	}
	return writePowerDNSBrokerBytes(writer, content)
}

func writePowerDNSBrokerBytes(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func readPowerDNSBrokerFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > powerDNSBrokerFrameLimit {
		return ErrPowerDNSDaemonProtocol
	}
	content := make([]byte, size)
	if _, err := io.ReadFull(reader, content); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrPowerDNSDaemonProtocol
	}
	return nil
}

func newPowerDNSBrokerID() (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", err
	}
	return "pdnsreq_" + hex.EncodeToString(raw[:]), nil
}

func validPowerDNSBrokerID(value string) bool {
	if len(value) < 24 || len(value) > 80 {
		return false
	}
	for _, character := range value {
		if !(character == '_' || character == '-' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z') {
			return false
		}
	}
	return true
}

func validPowerDNSFailureCode(value string) bool {
	switch value {
	case "invalid", "conflict", "database_isolation", "credential_unavailable", "ambiguous", "deadline", "operation_failed":
		return true
	default:
		return false
	}
}

func powerDNSBrokerFailureCode(err error) string {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, ErrDNSConflict):
		return "conflict"
	case errors.Is(err, ErrPowerDNSDatabaseIsolation):
		return "database_isolation"
	case errors.Is(err, ErrPowerDNSConfigCredential), errors.Is(err, ErrPowerDNSAuthoritativeCredential), errors.Is(err, ErrPowerDNSTSIGSecret):
		return "credential_unavailable"
	case errors.Is(err, ErrPowerDNSAmbiguous):
		return "ambiguous"
	case errors.Is(err, ErrInvalidDNS), errors.Is(err, ErrPowerDNSDaemonProtocol):
		return "invalid"
	default:
		return "operation_failed"
	}
}

func powerDNSBrokerOutcomeError(response PowerDNSBrokerResponse) error {
	if response.Outcome == PowerDNSBrokerConfirmed {
		return nil
	}
	var cause error
	switch response.FailureCode {
	case "invalid":
		cause = ErrInvalidDNS
	case "conflict":
		cause = ErrDNSConflict
	case "database_isolation":
		cause = ErrPowerDNSDatabaseIsolation
	case "credential_unavailable":
		cause = ErrPowerDNSAuthoritativeCredential
	case "ambiguous":
		cause = ErrPowerDNSAmbiguous
	case "deadline":
		cause = context.DeadlineExceeded
	default:
		cause = ErrPowerDNSDaemonOperation
	}
	if response.Outcome == PowerDNSBrokerUnknown {
		return errors.Join(ErrPowerDNSAmbiguous, cause)
	}
	return cause
}

func completePowerDNSRuntimeReceipt(receipt PowerDNSRuntimeReceipt, operation PowerDNSRuntimeOperation, operationErr error, observedAt time.Time) PowerDNSRuntimeReceipt {
	if receipt.Operation != "" {
		return receipt
	}
	receipt.Operation = operation
	receipt.ObservedAt = observedAt
	receipt.EvidenceDigest = digestPowerDNSEvidence("broker-runtime-preflight", powerDNSBrokerFailureCode(operationErr))
	return receipt
}

func validPowerDNSActivationReceipt(receipt PowerDNSActivationReceipt, snapshot PowerDNSConfigSnapshot, now time.Time) bool {
	if receipt.GenerationID == "" || !powerDNSSHA256(receipt.SnapshotDigest) || !powerDNSSHA256(receipt.GenerationDigest) || receipt.DatabaseFingerprint != snapshot.Database.Fingerprint || receipt.ObservedAt.IsZero() || receipt.ObservedAt.After(now.Add(time.Minute)) {
		return false
	}
	if !validPowerDNSRuntimeReceipt(receipt.Probe, PowerDNSProbeService, now) || !receipt.Probe.Success || !receipt.Probe.Healthy {
		return false
	}
	return validOptionalPowerDNSRuntime(receipt.Validation, PowerDNSValidateConfiguration, now) && validOptionalPowerDNSRuntime(receipt.Reload, PowerDNSReloadService, now) && validOptionalPowerDNSRuntime(receipt.Rollback, PowerDNSRollbackConfiguration, now)
}

func validOptionalPowerDNSActivationReceipt(receipt PowerDNSActivationReceipt, now time.Time) bool {
	if receipt.GenerationID == "" {
		return receipt.ObservedAt.IsZero() || !receipt.ObservedAt.After(now.Add(time.Minute))
	}
	if !powerDNSSHA256(receipt.SnapshotDigest) || !powerDNSSHA256(receipt.GenerationDigest) || receipt.ObservedAt.IsZero() || receipt.ObservedAt.After(now.Add(time.Minute)) {
		return false
	}
	return validOptionalPowerDNSRuntime(receipt.Validation, PowerDNSValidateConfiguration, now) && validOptionalPowerDNSRuntime(receipt.Reload, PowerDNSReloadService, now) && validOptionalPowerDNSRuntime(receipt.Probe, PowerDNSProbeService, now) && validOptionalPowerDNSRuntime(receipt.Rollback, PowerDNSRollbackConfiguration, now)
}

func validPowerDNSAuthorityReceipt(receipt AuthorityReceipt, request PowerDNSBrokerRequest, now time.Time) bool {
	expectedZone := ZoneID("")
	if request.Zone != nil {
		expectedZone = request.Zone.ID
	} else if request.Delete != nil {
		expectedZone = request.Delete.ID
	}
	if receipt.EffectID != request.EffectID || receipt.ZoneID != expectedZone || receipt.ObservedAt.IsZero() || receipt.ObservedAt.After(now.Add(time.Minute)) {
		return false
	}
	if request.Operation == PowerDNSBrokerApplyZone {
		return receipt.Serial > 0 && receipt.AppliedSets == uint32(len(request.RecordSets)+1)
	}
	return true
}

func validSuccessfulPowerDNSRuntime(receipt PowerDNSRuntimeReceipt, operation PowerDNSRuntimeOperation, now time.Time) bool {
	return validPowerDNSRuntimeReceipt(receipt, operation, now) && receipt.Success
}

func validOptionalPowerDNSRuntime(receipt PowerDNSRuntimeReceipt, operation PowerDNSRuntimeOperation, now time.Time) bool {
	if receipt.Operation == "" {
		return receipt.EvidenceDigest == "" && receipt.ObservedAt.IsZero()
	}
	return validPowerDNSRuntimeReceipt(receipt, operation, now)
}

func validPowerDNSRuntimeReceipt(receipt PowerDNSRuntimeReceipt, operation PowerDNSRuntimeOperation, now time.Time) bool {
	return receipt.Operation == operation && (receipt.GenerationID != "" || !receipt.Success || operation == PowerDNSRollbackConfiguration) && powerDNSSHA256(receipt.EvidenceDigest) && !receipt.ObservedAt.IsZero() && !receipt.ObservedAt.After(now.Add(time.Minute))
}
