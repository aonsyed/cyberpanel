package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

type ClientConfig struct{BaseURL string;UnixSocket string;APIKey string;SessionID string;SessionToken string;CSRFToken string;SessionCookieName string;HTTPClient *http.Client;MaximumResponseBytes int64}
type Client struct{base *url.URL;http *http.Client;apiKey,sessionID,sessionToken,csrf,cookieName,origin string;maximum int64}

func NewClient(config ClientConfig)(*Client,error){base,err:=url.Parse(config.BaseURL);if err!=nil||base.Scheme==""||base.Host==""||base.User!=nil||base.RawQuery!=""||base.Fragment!=""{return nil,invalid("API base URL")};if base.Scheme!="https"&&!(base.Scheme=="http"&&config.UnixSocket!=""){return nil,invalid("API transport")};if strings.TrimRight(base.Path,"/")!=""{return nil,invalid("API base path")};client:=config.HTTPClient;if config.UnixSocket!=""{if !filepath.IsAbs(config.UnixSocket)||filepath.Clean(config.UnixSocket)!=config.UnixSocket{return nil,invalid("API Unix socket")};dialer:=&net.Dialer{Timeout:3*time.Second};transport:=&http.Transport{DialContext:func(ctx context.Context,_,_ string)(net.Conn,error){return dialer.DialContext(ctx,"unix",config.UnixSocket)},DisableCompression:true,ResponseHeaderTimeout:30*time.Second};client=&http.Client{Transport:transport,Timeout:2*time.Minute,CheckRedirect:rejectRedirect}};if client==nil{client=&http.Client{Timeout:2*time.Minute,CheckRedirect:rejectRedirect}};maximum:=config.MaximumResponseBytes;if maximum<=0||maximum>DefaultMaximumResponseBytes{maximum=DefaultMaximumResponseBytes};if config.APIKey!=""&&(config.SessionID!=""||config.SessionToken!=""){return nil,invalid("multiple API credentials")};if (config.SessionID=="")!=(config.SessionToken==""){return nil,invalid("incomplete session credential")};cookieName:=config.SessionCookieName;if cookieName==""{cookieName="panel_session"};if !tokenName(cookieName){return nil,invalid("session cookie name")};origin:=base.Scheme+"://"+base.Host;return &Client{base:base,http:client,apiKey:config.APIKey,sessionID:config.SessionID,sessionToken:config.SessionToken,csrf:config.CSRFToken,cookieName:cookieName,origin:origin,maximum:maximum},nil}

func(client *Client)Invoke(ctx context.Context,request RequestEnvelope,idempotencyKey string)(ResponseEnvelope,error){var response ResponseEnvelope;if request.RequestID==""{id,err:=opaqueID("request",16);if err!=nil{return response,err};request.RequestID=id};request.APIVersion=APIVersion;if err:=request.Validate();err!=nil{return response,err};content,err:=json.Marshal(request);if err!=nil{return response,err};endpoint:=*client.base;endpoint.Path="/api/v1/operations";httpRequest,err:=http.NewRequestWithContext(ctx,http.MethodPost,endpoint.String(),bytes.NewReader(content));if err!=nil{return response,err};httpRequest.Header.Set("Content-Type",ContentTypeJSON);httpRequest.Header.Set("Accept",ContentTypeJSON+", "+ContentTypeProblem);httpRequest.Header.Set("X-Request-ID",request.RequestID);if idempotencyKey!=""{httpRequest.Header.Set("Idempotency-Key",idempotencyKey)};if client.apiKey!=""{httpRequest.Header.Set("Authorization","Bearer "+client.apiKey)}else if client.sessionID!=""{httpRequest.AddCookie(&http.Cookie{Name:client.cookieName,Value:client.sessionID+"."+client.sessionToken});httpRequest.Header.Set("Origin",client.origin);if client.csrf!=""{httpRequest.Header.Set("X-CSRF-Token",client.csrf)}};httpResponse,err:=client.http.Do(httpRequest);if err!=nil{return response,err};defer httpResponse.Body.Close();body,err:=io.ReadAll(io.LimitReader(httpResponse.Body,client.maximum+1));if err!=nil||int64(len(body))>client.maximum{return response,ErrResponseTooLarge};contentType:=strings.Split(httpResponse.Header.Get("Content-Type"),";")[0];if contentType==ContentTypeProblem||httpResponse.StatusCode<200||httpResponse.StatusCode>299{var problem Problem;if decodeStrict(body,&problem)!=nil{return response,ErrUnavailable};return response,problem};if contentType!=ContentTypeJSON{return response,ErrUnavailable};if err=decodeStrict(body,&response);err!=nil{return response,err};if response.APIVersion!=APIVersion||response.RequestID!=request.RequestID||response.Operation!=request.Operation{return ResponseEnvelope{},ErrUnavailable};return response,nil}

func rejectRedirect(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}

func ReadAPIKeyFile(path string)(string,error){content,err:=readSecretFile(path,8192);if err!=nil{return "",err};value:=strings.TrimSpace(string(content));for index:=range content{content[index]=0};if len(value)<24||len(value)>4096||strings.ContainsAny(value,"\r\n\t "){return "",ErrUnauthenticated};return value,nil}

func DecodeResult(response ResponseEnvelope,target any)error{if target==nil{return invalid("result target")};if err:=decodeStrict(response.Result,target);err!=nil{return err};return nil}
