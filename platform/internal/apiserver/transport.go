package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/preview"
)

type CoreTransport interface { Invoke(context.Context, CoreRequest) (CoreResponse, error); Health(context.Context) error }
type CoreCatalogTransport interface{Catalog(context.Context)(CoreCatalog,error)}
type PreviewCoreTransport interface{ResolvePreview(context.Context,string)(preview.Resolution,error)}

type UnixCoreTransport struct { socketPath string; client *http.Client }

func NewUnixCoreTransport(socketPath string) (*UnixCoreTransport, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath { return nil, invalid("core socket path") }
	dialer := &net.Dialer{Timeout: 3*time.Second, KeepAlive: 30*time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn,error) { return dialer.DialContext(ctx,"unix",socketPath) }, DisableCompression:true, MaxIdleConns:32, MaxIdleConnsPerHost:32, IdleConnTimeout:60*time.Second, ResponseHeaderTimeout:30*time.Second}
	return &UnixCoreTransport{socketPath:socketPath,client:&http.Client{Transport:transport}},nil
}

func (transport *UnixCoreTransport) Invoke(ctx context.Context, request CoreRequest) (CoreResponse, error) {
	var response CoreResponse
	content, err := json.Marshal(request); if err != nil { return response, err }
	httpRequest, err := http.NewRequestWithContext(ctx,http.MethodPost,"http://panel-core/internal/v1/invoke",bytes.NewReader(content)); if err != nil { return response,err }
	httpRequest.Header.Set("Content-Type",ContentTypeJSON); httpRequest.Header.Set("X-Request-ID",request.Request.RequestID)
	httpResponse, err := transport.client.Do(httpRequest); if err != nil { return response,fmtUnavailable(err) }; defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK { return response,ErrUnavailable }
	body, err := io.ReadAll(io.LimitReader(httpResponse.Body,DefaultMaximumResponseBytes+65537)); if err != nil || len(body)>DefaultMaximumResponseBytes+65536 { return response,ErrUnavailable }
	if err=decodeStrict(body,&response);err!=nil{return response,ErrUnavailable}
	if response.ProtocolVersion!=InternalProtocolVersion||response.Status<200||response.Status>599||(response.Envelope==nil)==(response.Problem==nil){return CoreResponse{},ErrUnavailable}
	if response.Envelope!=nil&&(response.Envelope.APIVersion!=APIVersion||response.Envelope.RequestID!=request.Request.RequestID||response.Envelope.Operation!=request.Request.Operation||response.Envelope.CompletedAt.IsZero()){return CoreResponse{},ErrUnavailable}
	if response.Problem!=nil&&response.Problem.RequestID!=""&&response.Problem.RequestID!=request.Request.RequestID{return CoreResponse{},ErrUnavailable}
	return response,nil
}

func (transport *UnixCoreTransport) Health(ctx context.Context) error {
	request,err:=http.NewRequestWithContext(ctx,http.MethodGet,"http://panel-core/internal/v1/health",nil);if err!=nil{return err}
	response,err:=transport.client.Do(request);if err!=nil{return fmtUnavailable(err)};defer response.Body.Close();if response.StatusCode!=http.StatusOK{return ErrUnavailable};content,err:=io.ReadAll(io.LimitReader(response.Body,(1<<20)+1));if err!=nil||len(content)>1<<20{return ErrUnavailable};return nil
}

func (transport *UnixCoreTransport)Catalog(ctx context.Context)(CoreCatalog,error){var catalog CoreCatalog;request,err:=http.NewRequestWithContext(ctx,http.MethodGet,"http://panel-core/internal/v1/catalog",nil);if err!=nil{return catalog,err};response,err:=transport.client.Do(request);if err!=nil{return catalog,fmtUnavailable(err)};defer response.Body.Close();if response.StatusCode!=http.StatusOK{return catalog,ErrUnavailable};content,err:=io.ReadAll(io.LimitReader(response.Body,DefaultMaximumResponseBytes+1));if err!=nil||len(content)>DefaultMaximumResponseBytes{return catalog,ErrUnavailable};if err=decodeStrict(content,&catalog);err!=nil||catalog.ProtocolVersion!=InternalProtocolVersion||catalog.APIVersion!=APIVersion{return CoreCatalog{},ErrUnavailable};return catalog,nil}

func (transport *UnixCoreTransport) ResolvePreview(ctx context.Context, hostname string) (preview.Resolution, error) {
	var resolution preview.Resolution
	content, err := json.Marshal(previewConsumeRequest{Hostname:hostname})
	if err != nil { return resolution, err }
	request, err := http.NewRequestWithContext(ctx,http.MethodPost,"http://panel-core/internal/v1/preview/consume",bytes.NewReader(content))
	if err != nil { return resolution, err }
	request.Header.Set("Content-Type",ContentTypeJSON)
	response, err := transport.client.Do(request)
	if err != nil { return resolution, fmtUnavailable(err) }
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body,(1<<20)+1))
	if err != nil || len(body)>1<<20 { return resolution, ErrUnavailable }
	if response.StatusCode != http.StatusOK {
		var problem Problem
		if decodeStrict(body,&problem)!=nil { return resolution, ErrUnavailable }
		return resolution, problemError(problem)
	}
	if decodeStrict(body,&resolution)!=nil || resolution.SessionID=="" || resolution.PreviewHostname!=hostname || resolution.TargetHostname=="" || resolution.SiteGeneration==0 || !resolution.ExpiresAt.After(time.Now().UTC()) { return preview.Resolution{}, ErrUnavailable }
	return resolution,nil
}

func fmtUnavailable(err error) error { if err==nil{return ErrUnavailable};return errors.Join(ErrUnavailable,err) }
