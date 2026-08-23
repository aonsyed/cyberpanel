//go:build linux

package integrations

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	ProviderWorkerAdapterID      = "cyberpanel-provider-worker"
	ProviderWorkerAdapterVersion = "1"
)

type ProviderSecretReader struct {
	Client   *secrets.MaterialClient
	Profiles map[ProviderKind]SecretConsumerProfile
}

func (reader ProviderSecretReader) Read(ctx context.Context, binding ProviderBinding) ([]byte, func(), error) {
	if reader.Client == nil || binding.Validate() != nil {
		return nil, func(){}, ErrInvalid
	}
	profile, ok := reader.Profiles[binding.Kind]
	if !ok || profile.validate() != nil || profile.Origin != binding.Endpoint.URL {
		return nil, func(){}, ErrPolicyDenied
	}
	secretID, err := secrets.NewID(string(binding.SecretRef))
	if err != nil {
		return nil, func(){}, ErrIntegrity
	}
	ownerRaw:=string(binding.TenantID);if ownerRaw==""{ownerRaw="installation"}
	owner:=integrationSecretID("owner",ownerRaw)
	resource:=integrationSecretID("binding",string(binding.ID))
	purpose,err:=integrationSecretPurpose(binding.Purpose);if err!=nil{return nil,func(){},err}
	response,err:=reader.Client.Read(ctx,secrets.MaterialRequest{SecretID:secretID,OwnerTenantID:owner,Purpose:purpose,Operation:secrets.OperationAuthenticate,AdapterID:profile.AdapterID,AdapterVersion:profile.AdapterVersion,ResourceID:resource})
	if err!=nil{return nil,func(){},err}
	if response.SecretVersion!=binding.SecretVersion||response.BindingDigest!=binding.SecretBindingDigest{wipeIntegrationSecret(response.Material);return nil,func(){},ErrIntegrity}
	material:=response.Material
	return material,func(){wipeIntegrationSecret(material)},nil
}

type RemoteProviderAdapter struct {
	Kind    ProviderKind
	Secrets ProviderSecretReader
	Client  *http.Client
	Now     func() time.Time
}

func NewRemoteProviderAdapter(kind ProviderKind, reader ProviderSecretReader) (*RemoteProviderAdapter,error) {
	if reader.Client==nil{return nil,ErrInvalid}
	switch kind{case ProviderCloudflare,ProviderAWSS3,ProviderWasabi,ProviderBackblaze:default:return nil,ErrUnsupported}
	return &RemoteProviderAdapter{Kind:kind,Secrets:reader,Client:boundedProviderHTTPClient(),Now:time.Now},nil
}

func (adapter *RemoteProviderAdapter) now()time.Time{if adapter.Now!=nil{return adapter.Now().UTC()};return time.Now().UTC()}

func (adapter *RemoteProviderAdapter) DiscoverCapabilities(ctx context.Context,binding ProviderBinding)(CapabilitySet,error){if err:=adapter.ValidateCredential(ctx,binding);err!=nil{return CapabilitySet{},err};capabilities:=[]Capability{CapabilityHealth};version:="provider-worker-v1";switch adapter.Kind{case ProviderCloudflare:capabilities=append(capabilities,CapabilityDNSZones,CapabilityDNSRRsets,CapabilityDNSProxy,CapabilityDNSChallenge,CapabilityObserveApply);version="cloudflare-v4";case ProviderAWSS3,ProviderWasabi,ProviderBackblaze:capabilities=append(capabilities,CapabilityObjectList,CapabilityObjectMultipart,CapabilityObjectResume,CapabilityObjectChecksum);version="s3-sigv4";default:return CapabilitySet{},ErrUnsupported};now:=adapter.now();return CapabilitySet{SchemaVersion:1,ProviderVersion:version,Capabilities:capabilities,DiscoveredAt:now,Digest:capabilityDigest(capabilities)},nil}

func (adapter *RemoteProviderAdapter) Health(ctx context.Context,binding ProviderBinding)(ProviderHealth,error){started:=adapter.now();capabilities:=adapter.capabilities(binding);err:=adapter.ValidateCredential(ctx,binding);observed:=adapter.now();health:=ProviderHealth{BindingID:binding.ID,State:HealthHealthy,Latency:observed.Sub(started),CredentialValid:err==nil,CapabilitiesDigest:capabilities.Digest,RateLimitRemaining:-1,ObservedAt:observed,StaleAfter:observed.Add(5*time.Minute)};if err!=nil{health.State=HealthUnavailable;health.Reason="provider credential validation failed";return health,err};return health,nil}

func (adapter *RemoteProviderAdapter) ValidateCredential(ctx context.Context,binding ProviderBinding)error{if adapter==nil||adapter.Kind!=binding.Kind||binding.Endpoint.Validate()!=nil||validateProviderEndpoint(binding.Kind,binding.Endpoint)!=nil{return ErrPolicyDenied};material,cleanup,err:=adapter.Secrets.Read(ctx,binding);if err!=nil{return err};defer cleanup();switch adapter.Kind{case ProviderCloudflare:_,err=adapter.cloudflareVerify(ctx,binding,material);case ProviderAWSS3,ProviderWasabi,ProviderBackblaze:err=adapter.s3Verify(ctx,binding,material);default:err=ErrUnsupported};return err}

func (adapter *RemoteProviderAdapter) RevokeCredential(ctx context.Context,binding ProviderBinding)error{if adapter==nil||adapter.Kind!=binding.Kind{return ErrInvalid};material,cleanup,err:=adapter.Secrets.Read(ctx,binding);if err!=nil{return err};defer cleanup();if adapter.Kind==ProviderCloudflare{tokenID,verifyErr:=adapter.cloudflareVerify(ctx,binding,material);if verifyErr!=nil{return verifyErr};return adapter.cloudflareRevoke(ctx,binding,material,tokenID)};switch adapter.Kind{case ProviderAWSS3,ProviderWasabi,ProviderBackblaze:// S3 has no credential-revocation API. Disconnect is enforced by broker revocation.
		return nil;default:return ErrUnsupported}}

func (adapter *RemoteProviderAdapter) capabilities(binding ProviderBinding)CapabilitySet{capabilities:=[]Capability{CapabilityHealth};version:="provider-worker-v1";switch adapter.Kind{case ProviderCloudflare:capabilities=append(capabilities,CapabilityDNSZones,CapabilityDNSRRsets,CapabilityDNSProxy,CapabilityDNSChallenge,CapabilityObserveApply);version="cloudflare-v4";case ProviderAWSS3,ProviderWasabi,ProviderBackblaze:capabilities=append(capabilities,CapabilityObjectList,CapabilityObjectMultipart,CapabilityObjectResume,CapabilityObjectChecksum);version="s3-sigv4"};return CapabilitySet{SchemaVersion:1,ProviderVersion:version,Capabilities:capabilities,DiscoveredAt:adapter.now(),Digest:capabilityDigest(capabilities)}}

type cloudflareToken struct{Token string `json:"token"`}
type cloudflareEnvelope struct{Success bool `json:"success"`;Result struct{ID string `json:"id"`;Status string `json:"status"`} `json:"result"`;Errors []struct{Code int `json:"code"`;Message string `json:"message"`} `json:"errors"`}

func cloudflareCredential(material []byte)(string,error){token:=strings.TrimSpace(string(material));var document cloudflareToken;if len(material)>0&&material[0]=='{'{decoder:=json.NewDecoder(strings.NewReader(string(material)));decoder.DisallowUnknownFields();if decoder.Decode(&document)!=nil||decoder.Decode(&struct{}{})!=io.EOF{return "",ErrInvalid};token=strings.TrimSpace(document.Token)};if len(token)<20||len(token)>4096||strings.ContainsAny(token,"\x00\r\n\t "){return "",ErrInvalid};return token,nil}

func (adapter *RemoteProviderAdapter) cloudflareVerify(ctx context.Context,binding ProviderBinding,material []byte)(string,error){token,err:=cloudflareCredential(material);if err!=nil{return "",err};endpoint:=strings.TrimSuffix(binding.Endpoint.URL,"/")+"/client/v4/user/tokens/verify";request,err:=http.NewRequestWithContext(ctx,http.MethodGet,endpoint,nil);if err!=nil{return "",err};request.Header.Set("Authorization","Bearer "+token);response,err:=adapter.Client.Do(request);if err!=nil{return "",providerNetworkError("cloudflare.verify",err)};defer response.Body.Close();raw,readErr:=io.ReadAll(io.LimitReader(response.Body,64<<10));if readErr!=nil||len(raw)>=64<<10{return "",ErrIntegrity};var envelope cloudflareEnvelope;if json.Unmarshal(raw,&envelope)!=nil{return "",ErrIntegrity};if response.StatusCode==429{return "",ErrRateLimited};if response.StatusCode==401||response.StatusCode==403||!envelope.Success||envelope.Result.Status!="active"||!validID(envelope.Result.ID){return "",ErrUnauthorized};return envelope.Result.ID,nil}

func (adapter *RemoteProviderAdapter) cloudflareRevoke(ctx context.Context,binding ProviderBinding,material []byte,tokenID string)error{token,err:=cloudflareCredential(material);if err!=nil{return err};if !validID(tokenID){return ErrIntegrity};endpoint:=strings.TrimSuffix(binding.Endpoint.URL,"/")+"/client/v4/user/tokens/"+url.PathEscape(tokenID);request,err:=http.NewRequestWithContext(ctx,http.MethodDelete,endpoint,nil);if err!=nil{return err};request.Header.Set("Authorization","Bearer "+token);response,err:=adapter.Client.Do(request);if err!=nil{return providerNetworkError("cloudflare.revoke",err)};defer response.Body.Close();raw,readErr:=io.ReadAll(io.LimitReader(response.Body,64<<10));if readErr!=nil||len(raw)>=64<<10{return ErrIntegrity};var envelope cloudflareEnvelope;if json.Unmarshal(raw,&envelope)!=nil{return ErrIntegrity};if response.StatusCode==429{return ErrRateLimited};if response.StatusCode==401||response.StatusCode==403{return ErrUnauthorized};if response.StatusCode<200||response.StatusCode>=300||!envelope.Success{return ErrUnavailable};return nil}

type s3Credential struct{AccessKeyID string `json:"access_key_id"`;SecretAccessKey string `json:"secret_access_key"`;SessionToken string `json:"session_token,omitempty"`;Region string `json:"region"`}
func parseS3Credential(material []byte)(s3Credential,error){var credential s3Credential;decoder:=json.NewDecoder(strings.NewReader(string(material)));decoder.DisallowUnknownFields();if decoder.Decode(&credential)!=nil||decoder.Decode(&struct{}{})!=io.EOF||credential.AccessKeyID==""||credential.SecretAccessKey==""||credential.Region==""||len(credential.AccessKeyID)>256||len(credential.SecretAccessKey)>4096||len(credential.SessionToken)>8192||len(credential.Region)>64||strings.ContainsAny(credential.Region,"/ \t\r\n\x00"){return s3Credential{},ErrInvalid};return credential,nil}
type s3ListBuckets struct{XMLName xml.Name `xml:"ListAllMyBucketsResult"`;Owner struct{ID string `xml:"ID"`} `xml:"Owner"`}

func (adapter *RemoteProviderAdapter) s3Verify(ctx context.Context,binding ProviderBinding,material []byte)error{credential,err:=parseS3Credential(material);if err!=nil{return err};endpoint:=strings.TrimSuffix(binding.Endpoint.URL,"/")+"/";request,err:=http.NewRequestWithContext(ctx,http.MethodGet,endpoint,nil);if err!=nil{return err};signS3ProviderRequest(request,credential,adapter.now());response,err:=adapter.Client.Do(request);if err!=nil{return providerNetworkError("s3.list_buckets",err)};defer response.Body.Close();raw,readErr:=io.ReadAll(io.LimitReader(response.Body,1<<20));if readErr!=nil||len(raw)>=1<<20{return ErrIntegrity};if response.StatusCode==429||response.StatusCode==503{return ErrRateLimited};if response.StatusCode==401||response.StatusCode==403{return ErrUnauthorized};if response.StatusCode<200||response.StatusCode>=300{return ErrUnavailable};var document s3ListBuckets;if xml.Unmarshal(raw,&document)!=nil||document.XMLName.Local!="ListAllMyBucketsResult"{return ErrIntegrity};return nil}

func signS3ProviderRequest(request *http.Request,credential s3Credential,now time.Time){empty:=sha256.Sum256(nil);payloadDigest:=hex.EncodeToString(empty[:]);timestamp:=now.UTC().Format("20060102T150405Z");date:=now.UTC().Format("20060102");request.Header.Set("X-Amz-Date",timestamp);request.Header.Set("X-Amz-Content-Sha256",payloadDigest);if credential.SessionToken!=""{request.Header.Set("X-Amz-Security-Token",credential.SessionToken)};headers:=[]string{"host","x-amz-content-sha256","x-amz-date"};if credential.SessionToken!=""{headers=append(headers,"x-amz-security-token")};sort.Strings(headers);var canonical strings.Builder;for _,name:=range headers{value:=request.URL.Host;if name!="host"{value=request.Header.Get(http.CanonicalHeaderKey(name))};canonical.WriteString(name);canonical.WriteByte(':');canonical.WriteString(strings.TrimSpace(value));canonical.WriteByte('\n')};signed:=strings.Join(headers,";");canonicalRequest:=request.Method+"\n/\n\n"+canonical.String()+"\n"+signed+"\n"+payloadDigest;requestHash:=sha256.Sum256([]byte(canonicalRequest));scope:=date+"/"+credential.Region+"/s3/aws4_request";stringToSign:="AWS4-HMAC-SHA256\n"+timestamp+"\n"+scope+"\n"+hex.EncodeToString(requestHash[:]);dateKey:=hmacSHA256Provider([]byte("AWS4"+credential.SecretAccessKey),date);regionKey:=hmacSHA256Provider(dateKey,credential.Region);serviceKey:=hmacSHA256Provider(regionKey,"s3");signingKey:=hmacSHA256Provider(serviceKey,"aws4_request");signature:=hex.EncodeToString(hmacSHA256Provider(signingKey,stringToSign));request.Header.Set("Authorization","AWS4-HMAC-SHA256 Credential="+credential.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+signature)}
func hmacSHA256Provider(key []byte,value string)[]byte{hash:=hmac.New(sha256.New,key);_,_=io.WriteString(hash,value);return hash.Sum(nil)}

func boundedProviderHTTPClient()*http.Client{dialer:=&net.Dialer{Timeout:5*time.Second,KeepAlive:30*time.Second};transport:=&http.Transport{Proxy:nil,DisableCompression:true,ForceAttemptHTTP2:true,MaxIdleConns:32,MaxIdleConnsPerHost:8,IdleConnTimeout:30*time.Second,TLSHandshakeTimeout:5*time.Second,ResponseHeaderTimeout:15*time.Second,TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},DialContext:func(ctx context.Context,network,address string)(net.Conn,error){host,port,err:=net.SplitHostPort(address);if err!=nil{return nil,err};addresses,err:=net.DefaultResolver.LookupNetIP(ctx,"ip",host);if err!=nil{return nil,err};for _,candidate:=range addresses{if !publicProviderAddress(candidate){continue};connection,dialErr:=dialer.DialContext(ctx,network,net.JoinHostPort(candidate.String(),port));if dialErr==nil{return connection,nil}};return nil,ErrPolicyDenied}};return &http.Client{Transport:transport,Timeout:30*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}}
func publicProviderAddress(address netip.Addr)bool{return address.IsValid()&&!address.IsPrivate()&&!address.IsLoopback()&&!address.IsLinkLocalUnicast()&&!address.IsLinkLocalMulticast()&&!address.IsMulticast()&&!address.IsUnspecified()}
func providerNetworkError(operation string,err error)error{if errors.Is(err,context.DeadlineExceeded){return &ProviderError{Class:ErrorUnavailable,Operation:operation,Code:"timeout",Cause:err}};return &ProviderError{Class:ErrorUnavailable,Operation:operation,Code:"network",Cause:err}}

var _ Provider=(*RemoteProviderAdapter)(nil)
var _=fmt.Sprintf
