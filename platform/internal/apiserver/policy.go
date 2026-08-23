package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ForwardedMode string
const (
	ForwardedDisabled ForwardedMode = "disabled"
	ForwardedRFC7239 ForwardedMode = "rfc7239"
)

type GatewayPolicy struct {
	AllowedHosts []string
	AllowedOrigins []string
	TrustedProxies []netip.Prefix
	ForwardedMode ForwardedMode
	AllowPlaintextLoopback bool
	SessionCookieName string
	RequestTimeout time.Duration
	RatePerSecond float64
	RateBurst float64
}

type compiledPolicy struct {
	hosts map[string]bool
	origins map[string]bool
	proxies []netip.Prefix
	forwarded ForwardedMode
	allowPlaintextLoopback bool
	cookieName string
	timeout time.Duration
}

func (policy GatewayPolicy) compile() (compiledPolicy, error) {
	compiled := compiledPolicy{hosts:map[string]bool{},origins:map[string]bool{},proxies:append([]netip.Prefix(nil),policy.TrustedProxies...),forwarded:policy.ForwardedMode,allowPlaintextLoopback:policy.AllowPlaintextLoopback,cookieName:policy.SessionCookieName,timeout:policy.RequestTimeout}
	if compiled.forwarded==""{compiled.forwarded=ForwardedDisabled};if compiled.forwarded!=ForwardedDisabled&&compiled.forwarded!=ForwardedRFC7239{return compiled,invalid("forwarded mode")}
	for _,host:=range policy.AllowedHosts{normalized,err:=normalizeHost(host);if err!=nil{return compiled,err};compiled.hosts[normalized]=true}
	if len(compiled.hosts)==0{return compiled,invalid("allowed hosts")}
	for _,origin:=range policy.AllowedOrigins{normalized,err:=normalizeOrigin(origin);if err!=nil{return compiled,err};compiled.origins[normalized]=true}
	for _,prefix:=range compiled.proxies{if !prefix.IsValid(){return compiled,invalid("trusted proxy")}}
	if compiled.cookieName==""{compiled.cookieName="panel_session"};if !tokenName(compiled.cookieName){return compiled,invalid("session cookie name")}
	if compiled.timeout<=0{compiled.timeout=30*time.Second};if compiled.timeout>5*time.Minute{return compiled,invalid("request timeout")}
	return compiled,nil
}

func (policy compiledPolicy) metadata(request *http.Request) (RequestMeta,error) {
	remote,err:=remoteAddress(request.RemoteAddr);if err!=nil{return RequestMeta{},invalid("remote address")}
	effectiveIP:=remote;tls:=request.TLS!=nil;host:=request.Host;forwardedBy:=""
	forwardedPresent:=request.Header.Get("Forwarded")!=""||request.Header.Get("X-Forwarded-For")!=""||request.Header.Get("X-Forwarded-Proto")!=""||request.Header.Get("X-Forwarded-Host")!=""
	trusted:=containsAddress(policy.proxies,remote)
	if forwardedPresent&&!trusted{return RequestMeta{},invalid("forwarded headers from untrusted peer")}
	if trusted&&policy.forwarded==ForwardedDisabled&&forwardedPresent{return RequestMeta{},invalid("forwarded headers are disabled")}
	if trusted&&policy.forwarded==ForwardedRFC7239{
		if request.Header.Get("X-Forwarded-For")!=""||request.Header.Get("X-Forwarded-Proto")!=""||request.Header.Get("X-Forwarded-Host")!=""{return RequestMeta{},invalid("legacy forwarded headers")}
		client,proto,forwardedHost,parseErr:=parseForwarded(request.Header.Get("Forwarded"));if parseErr!=nil{return RequestMeta{},parseErr};effectiveIP=client;tls=proto=="https";if forwardedHost!=""{host=forwardedHost};forwardedBy=remote.String()
	}
	normalizedHost,err:=normalizeHost(host);if err!=nil||!policy.hosts[normalizedHost]{return RequestMeta{},invalid("host")}
	if !tls&&!(policy.allowPlaintextLoopback&&effectiveIP.IsLoopback()){return RequestMeta{},invalid("TLS is required")}
	origin:=request.Header.Get("Origin");if origin!=""{origin,err=normalizeOrigin(origin);if err!=nil||!policy.origins[origin]{return RequestMeta{},ErrForbidden}}
	if strings.EqualFold(request.Header.Get("Sec-Fetch-Site"),"cross-site"){return RequestMeta{},ErrForbidden}
	digest:=sha256.Sum256([]byte(request.UserAgent()))
	return RequestMeta{ClientIP:effectiveIP,UserAgentDigest:hex.EncodeToString(digest[:]),Origin:origin,Host:normalizedHost,TLS:tls,ForwardedBy:forwardedBy},nil
}

func normalizeHost(value string)(string,error){value=strings.TrimSpace(strings.ToLower(value));if strings.ContainsAny(value,"\x00\r\n\t /\\@")||value==""{return "",invalid("host")};host:=value;if parsed,port,err:=net.SplitHostPort(value);err==nil{number,parseErr:=strconv.ParseUint(port,10,16);if parseErr!=nil||number==0{return "",invalid("host port")};host=parsed}else if strings.HasPrefix(value,"[")&&strings.HasSuffix(value,"]"){host=strings.TrimSuffix(strings.TrimPrefix(value,"["),"]")}else if strings.Contains(value,":"){address,parseErr:=netip.ParseAddr(value);if parseErr!=nil{return "",invalid("host port")};return address.String(),nil};host=strings.TrimSuffix(host,".");if address,err:=netip.ParseAddr(host);err==nil{return address.String(),nil};if host==""||len(host)>253{return "",invalid("host")};labels:=strings.Split(host,".");for _,label:=range labels{if label==""||len(label)>63||!alphaNumericASCII(label[0])||!alphaNumericASCII(label[len(label)-1]){return "",invalid("host")};for index:=range label{if !alphaNumericASCII(label[index])&&label[index]!='-'{return "",invalid("host")}}};return host,nil}
func alphaNumericASCII(value byte)bool{return value>='a'&&value<='z'||value>='0'&&value<='9'}
func normalizeOrigin(value string)(string,error){parsed,err:=url.Parse(value);if err!=nil||parsed.Scheme==""||parsed.Host==""||parsed.User!=nil||parsed.RawQuery!=""||parsed.Fragment!=""||(parsed.Path!=""&&parsed.Path!="/"){return "",invalid("origin")};scheme:=strings.ToLower(parsed.Scheme);if scheme!="https"&&scheme!="http"{return "",invalid("origin scheme")};host,err:=normalizeHost(parsed.Hostname());if err!=nil{return "",err};port:=parsed.Port();if port!=""{number,parseErr:=strconv.ParseUint(port,10,16);if parseErr!=nil||number==0{return "",invalid("origin port")};if !(scheme=="https"&&number==443)&&!(scheme=="http"&&number==80){if strings.Contains(host,":"){host="["+host+"]"};host=host+":"+port}};return scheme+"://"+host,nil}
func remoteAddress(value string)(netip.Addr,error){host,_,err:=net.SplitHostPort(value);if err!=nil{return netip.Addr{},err};return netip.ParseAddr(strings.Trim(host,"[]"))}
func containsAddress(prefixes []netip.Prefix,address netip.Addr)bool{for _,prefix:=range prefixes{if prefix.Contains(address){return true}};return false}
func tokenName(value string)bool{if value==""||len(value)>64{return false};for _,character:=range value{if !(character>='a'&&character<='z'||character>='A'&&character<='Z'||character>='0'&&character<='9'||strings.ContainsRune("!#$%&'*+-.^_`|~",character)){return false}};return true}

func parseForwarded(value string)(netip.Addr,string,string,error){if value==""||len(value)>2048||strings.Contains(value,","){return netip.Addr{},"","",invalid("forwarded header")};items:=strings.Split(value,";");fields:=map[string]string{};for _,item:=range items{pair:=strings.SplitN(strings.TrimSpace(item),"=",2);if len(pair)!=2{return netip.Addr{},"","",invalid("forwarded header")};key:=strings.ToLower(pair[0]);raw:=strings.Trim(pair[1],`"`);if fields[key]!=""||strings.ContainsAny(raw,"\r\n\t"){return netip.Addr{},"","",invalid("forwarded header")};fields[key]=raw};if fields["for"]==""||fields["proto"]==""{return netip.Addr{},"","",invalid("forwarded header")};clientText:=strings.Trim(fields["for"],"[]");if host,_,err:=net.SplitHostPort(fields["for"]);err==nil{clientText=strings.Trim(host,"[]")};client,err:=netip.ParseAddr(clientText);if err!=nil||client.IsUnspecified(){return netip.Addr{},"","",invalid("forwarded client")};proto:=strings.ToLower(fields["proto"]);if proto!="http"&&proto!="https"{return netip.Addr{},"","",invalid("forwarded protocol")};return client,proto,fields["host"],nil}

type tokenBucket struct{tokens float64;updated time.Time}
type RateLimiter struct{mutex sync.Mutex;buckets map[netip.Addr]tokenBucket;rate,burst float64;clock func()time.Time;maximumBuckets int;retention time.Duration;lastSweep time.Time}
func NewRateLimiter(rate,burst float64)*RateLimiter{if rate<=0{rate=20};if burst<rate{burst=40};retention:=15*time.Minute;if refill:=time.Duration((burst/rate)*2*float64(time.Second));refill>retention{retention=refill};return &RateLimiter{buckets:map[netip.Addr]tokenBucket{},rate:rate,burst:burst,clock:time.Now,maximumBuckets:65536,retention:retention}}
func(limiter *RateLimiter)Allow(address netip.Addr,cost float64)bool{if limiter==nil||!address.IsValid(){return false};if cost<=0{cost=1};limiter.mutex.Lock();defer limiter.mutex.Unlock();now:=limiter.clock().UTC();if limiter.lastSweep.IsZero()||now.Sub(limiter.lastSweep)>=time.Minute||len(limiter.buckets)>=limiter.maximumBuckets{limiter.expire(now)};bucket,ok:=limiter.buckets[address];if !ok{if len(limiter.buckets)>=limiter.maximumBuckets{return false};bucket=tokenBucket{tokens:limiter.burst,updated:now}};elapsed:=now.Sub(bucket.updated).Seconds();if elapsed>0{bucket.tokens+=elapsed*limiter.rate};if bucket.tokens>limiter.burst{bucket.tokens=limiter.burst};bucket.updated=now;if bucket.tokens<cost{limiter.buckets[address]=bucket;return false};bucket.tokens-=cost;limiter.buckets[address]=bucket;return true}
func(limiter *RateLimiter)expire(now time.Time){cutoff:=now.Add(-limiter.retention);for address,bucket:=range limiter.buckets{if bucket.updated.Before(cutoff){delete(limiter.buckets,address)}};limiter.lastSweep=now}
