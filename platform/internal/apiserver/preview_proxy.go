package apiserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/preview"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

const (
	DefaultPreviewMaximumRequestBytes  int64 = 64 << 20
	DefaultPreviewMaximumResponseBytes int64 = 128 << 20
)

type previewResolutionContextKey struct{}

// PreviewProxy is a fixed-destination reverse proxy. The public request can
// select only an admitted opaque hostname; it can never select an address,
// port, scheme, target Host, or redirect-follow policy.
type PreviewProxy struct {
	domain               string
	panelCookieName      string
	resolver             PreviewCoreTransport
	upstream             *url.URL
	proxy                *httputil.ReverseProxy
	maximumRequestBytes  int64
	maximumResponseBytes int64
}

func NewPreviewProxy(resolver PreviewCoreTransport, previewDomain, upstream, panelCookieName string, maximumRequestBytes, maximumResponseBytes int64) (*PreviewProxy, error) {
	previewDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(previewDomain), "."))
	if resolver == nil || panelCookieName == "" || !tokenName(panelCookieName) { return nil, invalid("preview proxy") }
	parsedDomain, err := site.ParseHostname(previewDomain)
	if err != nil || parsedDomain.String() != previewDomain { return nil, invalid("preview domain") }
	target, err := url.Parse(upstream)
	if err != nil || target.Scheme != "http" || target.User != nil || target.Path != "" && target.Path != "/" || target.RawQuery != "" || target.Fragment != "" { return nil, invalid("preview upstream") }
	address, err := netip.ParseAddr(target.Hostname())
	if err != nil || !address.IsLoopback() || target.Port() == "" { return nil, invalid("preview upstream") }
	if maximumRequestBytes <= 0 || maximumRequestBytes > 1<<30 { maximumRequestBytes = DefaultPreviewMaximumRequestBytes }
	if maximumResponseBytes <= 0 || maximumResponseBytes > 1<<30 { maximumResponseBytes = DefaultPreviewMaximumResponseBytes }
	value := &PreviewProxy{domain:previewDomain,panelCookieName:panelCookieName,resolver:resolver,upstream:target,maximumRequestBytes:maximumRequestBytes,maximumResponseBytes:maximumResponseBytes}
	transport := &http.Transport{Proxy:nil,DisableCompression:false,ForceAttemptHTTP2:false,MaxIdleConns:128,MaxIdleConnsPerHost:128,IdleConnTimeout:30*time.Second,ResponseHeaderTimeout:30*time.Second,ExpectContinueTimeout:time.Second}
	value.proxy = &httputil.ReverseProxy{Director:value.direct,Transport:transport,ModifyResponse:value.modifyResponse,ErrorHandler:value.proxyError,FlushInterval:50*time.Millisecond}
	return value,nil
}

func (proxy *PreviewProxy) MatchesHost(rawHost string) bool {
	if proxy == nil { return false }
	host := requestHostname(rawHost)
	return host != "" && strings.HasSuffix(host, "."+proxy.domain)
}

func (proxy *PreviewProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setPreviewIsolationHeaders(writer)
	if proxy == nil || proxy.proxy == nil || request == nil || !proxy.MatchesHost(request.Host) || request.Method == http.MethodConnect || request.Method == http.MethodTrace || !loopbackRemote(request.RemoteAddr) {
		http.Error(writer,"preview unavailable",http.StatusNotFound)
		return
	}
	if forwarded := strings.ToLower(strings.TrimSpace(request.Header.Get("X-Forwarded-Proto"))); forwarded != "" && forwarded != "https" {
		http.Error(writer,"TLS required",http.StatusUpgradeRequired)
		return
	}
	hostname := requestHostname(request.Host)
	if !samePreviewOrigin(request.Header.Get("Origin"), hostname) {
		http.Error(writer,"cross-origin preview request denied",http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	resolution, err := proxy.resolver.ResolvePreview(ctx, hostname)
	cancel()
	if err != nil {
		status := http.StatusGone
		if errors.Is(err,ErrUnavailable) { status = http.StatusServiceUnavailable }
		http.Error(writer,"preview unavailable",status)
		return
	}
	request.Body = http.MaxBytesReader(writer,request.Body,proxy.maximumRequestBytes)
	request = request.WithContext(context.WithValue(request.Context(),previewResolutionContextKey{},resolution))
	proxy.proxy.ServeHTTP(writer,request)
}

func (proxy *PreviewProxy) direct(request *http.Request) {
	resolution, ok := request.Context().Value(previewResolutionContextKey{}).(preview.Resolution)
	if !ok { return }
	request.URL.Scheme = proxy.upstream.Scheme
	request.URL.Host = proxy.upstream.Host
	request.Host = resolution.TargetHostname
	request.RequestURI = ""
	for _, header := range []string{"Authorization","Proxy-Authorization","Forwarded","X-Forwarded-For","X-Forwarded-Host","X-Forwarded-Proto","X-Forwarded-Port","X-Real-IP","X-Panel-Authorization","X-CSRF-Token"} { request.Header.Del(header) }
	request.Header["X-Forwarded-For"] = nil
	request.Header.Set("X-Forwarded-Proto","https")
	request.Header.Set("X-Forwarded-Host",resolution.PreviewHostname)
	request.Header.Set("X-Content-Type-Options","nosniff")
	stripPanelCookies(request,proxy.panelCookieName)
}

func (proxy *PreviewProxy) modifyResponse(response *http.Response) error {
	if response == nil { return errors.New("empty preview response") }
	if response.ContentLength > proxy.maximumResponseBytes { return fmt.Errorf("preview response exceeds bound") }
	for _, header := range []string{"Access-Control-Allow-Credentials","Access-Control-Allow-Origin","Access-Control-Expose-Headers","Server","X-Powered-By"} { response.Header.Del(header) }
	response.Header.Set("Cache-Control","private, no-store, max-age=0")
	response.Header.Set("Referrer-Policy","no-referrer")
	response.Header.Set("X-Content-Type-Options","nosniff")
	response.Header.Set("X-Frame-Options","DENY")
	response.Header.Set("Cross-Origin-Opener-Policy","same-origin")
	response.Header.Set("Cross-Origin-Resource-Policy","same-origin")
	response.Header.Add("Content-Security-Policy","frame-ancestors 'none'; base-uri 'self'")
	sanitizePreviewCookies(response.Header,proxy.panelCookieName)
	if response.Body != nil { response.Body = &boundedPreviewBody{source:response.Body,remaining:proxy.maximumResponseBytes} }
	return nil
}

func (proxy *PreviewProxy) proxyError(writer http.ResponseWriter, _ *http.Request, _ error) {
	setPreviewIsolationHeaders(writer)
	http.Error(writer,"preview upstream unavailable",http.StatusBadGateway)
}

type boundedPreviewBody struct { source io.ReadCloser; remaining int64; checked bool }

func (body *boundedPreviewBody) Read(target []byte) (int,error) {
	if body.remaining > 0 {
		if int64(len(target)) > body.remaining { target = target[:body.remaining] }
		n, err := body.source.Read(target)
		body.remaining -= int64(n)
		return n,err
	}
	if body.checked { return 0,io.EOF }
	body.checked = true
	var one [1]byte
	n, err := body.source.Read(one[:])
	if n > 0 { return 0,errors.New("preview response exceeded configured bound") }
	return 0,err
}

func (body *boundedPreviewBody) Close() error { return body.source.Close() }

func sanitizePreviewCookies(header http.Header, panelCookieName string) {
	values := header.Values("Set-Cookie")
	header.Del("Set-Cookie")
	if len(values)>64 { values=values[:64] }
	for _, raw := range values {
		if len(raw)>4096 { continue }
		cookie, err := http.ParseSetCookie(raw)
		if err != nil || cookie.Name == panelCookieName || cookie.Name == panelCookieName+"_csrf" { continue }
		cookie.Domain = ""
		cookie.Secure = true
		if cookie.Path == "" { cookie.Path = "/" }
		if cookie.SameSite == http.SameSiteDefaultMode { cookie.SameSite = http.SameSiteLaxMode }
		if encoded := cookie.String(); encoded != "" { header.Add("Set-Cookie",encoded) }
	}
}

func stripPanelCookies(request *http.Request, panelCookieName string) {
	values := request.Cookies()
	request.Header.Del("Cookie")
	for _, cookie := range values {
		if cookie.Name == panelCookieName || cookie.Name == panelCookieName+"_csrf" { continue }
		request.AddCookie(&http.Cookie{Name:cookie.Name,Value:cookie.Value})
	}
}

func samePreviewOrigin(raw, hostname string) bool {
	if strings.TrimSpace(raw)=="" { return true }
	parsed, err := url.Parse(raw)
	return err==nil && parsed.Scheme=="https" && parsed.User==nil && parsed.Path=="" && parsed.RawQuery=="" && parsed.Fragment=="" && parsed.Port()=="" && strings.EqualFold(parsed.Hostname(),hostname)
}

func requestHostname(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if host,_,err:=net.SplitHostPort(raw);err==nil{return strings.TrimSuffix(host,".")}
	if strings.Contains(raw,":") { return "" }
	return strings.TrimSuffix(raw,".")
}

func loopbackRemote(raw string) bool { host,_,err:=net.SplitHostPort(raw);if err!=nil{return false};address,err:=netip.ParseAddr(host);return err==nil&&address.IsLoopback() }
func setPreviewIsolationHeaders(writer http.ResponseWriter) { writer.Header().Set("Cache-Control","private, no-store, max-age=0");writer.Header().Set("Referrer-Policy","no-referrer");writer.Header().Set("X-Content-Type-Options","nosniff");writer.Header().Set("X-Frame-Options","DENY");writer.Header().Set("Cross-Origin-Opener-Policy","same-origin");writer.Header().Set("Cross-Origin-Resource-Policy","same-origin") }
