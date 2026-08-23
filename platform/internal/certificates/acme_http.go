package certificates

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	LetsEncryptProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"
	maximumACMEResponse = 8 << 20
)

type ACMEKeySource interface {
	AccountSigner(context.Context, AccountSpec) (crypto.Signer, error)
	ExternalAccountKey(context.Context, AccountSpec) ([]byte, error)
}

type HTTPACMEClient struct {
	HTTP *http.Client
	Keys ACMEKeySource
	Staging bool
	mu sync.Mutex
	directories map[string]acmeDirectory
	accounts map[AccountID]string
	nonces map[string][]string
}

type acmeDirectory struct {
	NewNonce string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
}

type acmeProblem struct { Type string `json:"type"`; Detail string `json:"detail"`; Status int `json:"status"` }
type acmeOrderDocument struct { Status string `json:"status"`; Authorizations []string `json:"authorizations"`; Finalize string `json:"finalize"`; Certificate string `json:"certificate"`; Error *acmeProblem `json:"error,omitempty"` }
type acmeAuthorizationDocument struct { Status string `json:"status"`; Identifier struct { Type string `json:"type"`; Value string `json:"value"` } `json:"identifier"`; Challenges []struct { Type string `json:"type"`; URL string `json:"url"`; Status string `json:"status"`; Token string `json:"token"` } `json:"challenges"`; Wildcard bool `json:"wildcard"`; Expires time.Time `json:"expires"` }

func NewHTTPACMEClient(client *http.Client, keys ACMEKeySource, staging bool) (*HTTPACMEClient, error) {
	if client == nil || keys == nil { return nil, ErrInvalidCertificate }
	clone := *client
	if clone.Transport == nil { clone.Transport = http.DefaultTransport }
	if clone.Timeout == 0 || clone.Timeout > 2*time.Minute { clone.Timeout = 90*time.Second }
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPACMEClient{HTTP:&clone,Keys:keys,Staging:staging,directories:map[string]acmeDirectory{},accounts:map[AccountID]string{},nonces:map[string][]string{}},nil
}

func (client *HTTPACMEClient) EnsureAccount(ctx context.Context, account AccountSpec, _ string) (string, error) {
	directoryURL, directory, err := client.directory(ctx, account)
	if err != nil { return "", err }
	client.mu.Lock(); cached := client.accounts[account.ID]; client.mu.Unlock()
	if cached != "" { return cached, nil }
	signer, err := client.Keys.AccountSigner(ctx, account)
	if err != nil { return "", err }
	payload := map[string]any{"contact":account.Contact,"termsOfServiceAgreed":true}
	if account.Directory.RequiresEAB {
		binding, bindingErr := client.externalAccountBinding(ctx, account, signer.Public(), directory.NewAccount)
		if bindingErr != nil { return "", bindingErr }
		payload["externalAccountBinding"] = binding
	}
	response, _, err := client.signed(ctx, account, directoryURL, directory.NewAccount, "", signer, payload)
	if err != nil { return "", err }
	defer response.Body.Close()
	location := response.Header.Get("Location")
	if location == "" || client.validateRemoteURL(account, directoryURL, location) != nil { return "", ErrInvalidCertificate }
	client.mu.Lock(); client.accounts[account.ID] = location; client.mu.Unlock()
	return location, nil
}

func (client *HTTPACMEClient) NewOrder(ctx context.Context, account AccountSpec, policy CertificatePolicy, _ string) (RemoteOrder, error) {
	directoryURL, directory, err := client.directory(ctx, account)
	if err != nil { return RemoteOrder{}, err }
	kid, err := client.EnsureAccount(ctx, account, "")
	if err != nil { return RemoteOrder{}, err }
	signer, err := client.Keys.AccountSigner(ctx, account)
	if err != nil { return RemoteOrder{}, err }
	identifiers := make([]map[string]string, 0, len(policy.Names))
	for _, name := range policy.Names { identifiers = append(identifiers,map[string]string{"type":"dns","value":strings.TrimPrefix(name,"*.")}) }
	response, body, err := client.signed(ctx, account, directoryURL, directory.NewOrder, kid, signer, map[string]any{"identifiers":identifiers})
	if err != nil { return RemoteOrder{}, err }
	defer response.Body.Close()
	var document acmeOrderDocument
	if json.Unmarshal(body,&document)!=nil { return RemoteOrder{},ErrInvalidCertificate }
	orderURL:=response.Header.Get("Location")
	if orderURL==""||client.validateRemoteURL(account,directoryURL,orderURL)!=nil||client.validateRemoteURL(account,directoryURL,document.Finalize)!=nil{return RemoteOrder{},ErrInvalidCertificate}
	order:=RemoteOrder{URL:orderURL,Status:document.Status,FinalizeURL:document.Finalize,CertificateURL:document.Certificate,RetryAfter:retryAfter(response.Header,time.Now())}
	localOrderID:=OrderID(acmeOpaqueID("order",orderURL))
	thumbprint, err := jwkThumbprint(signer.Public()); if err != nil { return RemoteOrder{},err }
	for _, authorizationURL := range document.Authorizations {
		if client.validateRemoteURL(account,directoryURL,authorizationURL)!=nil{return RemoteOrder{},ErrInvalidCertificate}
		authorization, authErr := client.authorization(ctx,account,directoryURL,kid,signer,authorizationURL,policy.PreferredChallenge,policy.TenantID,thumbprint)
		if authErr != nil { return RemoteOrder{},authErr }
		authorization.Challenge.Order=localOrderID
		order.Authorizations=append(order.Authorizations,authorization)
	}
	return order,nil
}

func (client *HTTPACMEClient) AcceptChallenge(ctx context.Context, account AccountSpec, _ RemoteOrder, authorization Authorization, _ string) error {
	if authorization.Challenge.URL=="" { return ErrInvalidCertificate }
	directoryURL,_,err:=client.directory(ctx,account);if err!=nil{return err}
	kid,err:=client.EnsureAccount(ctx,account,"");if err!=nil{return err}
	signer,err:=client.Keys.AccountSigner(ctx,account);if err!=nil{return err}
	response,_,err:=client.signed(ctx,account,directoryURL,authorization.Challenge.URL,kid,signer,map[string]any{})
	if response!=nil { response.Body.Close() }
	return err
}

func (client *HTTPACMEClient) PollAuthorization(ctx context.Context, account AccountSpec, authorization Authorization) (Authorization,error) {
	directoryURL,_,err:=client.directory(ctx,account);if err!=nil{return Authorization{},err}
	kid,err:=client.EnsureAccount(ctx,account,"");if err!=nil{return Authorization{},err}
	signer,err:=client.Keys.AccountSigner(ctx,account);if err!=nil{return Authorization{},err}
	return client.authorization(ctx,account,directoryURL,kid,signer,authorization.URL,authorization.Challenge.Kind,authorization.Challenge.TenantID,mustJWKThumbprint(signer.Public()))
}

func (client *HTTPACMEClient) FinalizeOrder(ctx context.Context, account AccountSpec, order RemoteOrder, csr CSRMaterial, _ string) (RemoteOrder,error) {
	if len(csr.DER)==0||order.FinalizeURL==""{return RemoteOrder{},ErrInvalidCertificate}
	directoryURL,_,err:=client.directory(ctx,account);if err!=nil{return RemoteOrder{},err}
	kid,err:=client.EnsureAccount(ctx,account,"");if err!=nil{return RemoteOrder{},err};signer,err:=client.Keys.AccountSigner(ctx,account);if err!=nil{return RemoteOrder{},err}
	response,body,err:=client.signed(ctx,account,directoryURL,order.FinalizeURL,kid,signer,map[string]string{"csr":base64.RawURLEncoding.EncodeToString(csr.DER)})
	if err!=nil{return RemoteOrder{},err};response.Body.Close()
	current,err:=client.orderFromDocument(account,directoryURL,order.URL,response,body);if err!=nil{return RemoteOrder{},err}
	for attempts:=0;attempts<30&&current.Status!="valid";attempts++{
		if current.Status=="invalid"||current.Status=="expired"||current.Status=="revoked"{return RemoteOrder{},ErrInvalidCertificate}
		delay:=current.RetryAfter;if delay<time.Second{delay=time.Second};if delay>30*time.Second{delay=30*time.Second}
		timer:=time.NewTimer(delay);select{case<-ctx.Done():timer.Stop();return RemoteOrder{},ctx.Err();case<-timer.C:}
		response,body,err=client.signed(ctx,account,directoryURL,order.URL,kid,signer,nil);if err!=nil{return RemoteOrder{},err};response.Body.Close()
		current,err=client.orderFromDocument(account,directoryURL,order.URL,response,body);if err!=nil{return RemoteOrder{},err}
	}
	if current.Status!="valid"||current.CertificateURL==""{return RemoteOrder{},ErrCertificateAmbiguous};return current,nil
}

func (client *HTTPACMEClient) DownloadCertificate(ctx context.Context, account AccountSpec, order RemoteOrder) (CertificateMaterial,error) {
	if order.CertificateURL==""{return CertificateMaterial{},ErrInvalidCertificate}
	directoryURL,_,err:=client.directory(ctx,account);if err!=nil{return CertificateMaterial{},err};if client.validateRemoteURL(account,directoryURL,order.CertificateURL)!=nil{return CertificateMaterial{},ErrInvalidCertificate}
	kid,err:=client.EnsureAccount(ctx,account,"");if err!=nil{return CertificateMaterial{},err};signer,err:=client.Keys.AccountSigner(ctx,account);if err!=nil{return CertificateMaterial{},err}
	response,body,err:=client.signed(ctx,account,directoryURL,order.CertificateURL,kid,signer,nil);if err!=nil{return CertificateMaterial{},err};response.Body.Close()
	return certificateMaterialFromPEM(body)
}

func (client *HTTPACMEClient) RevokeCertificate(ctx context.Context, account AccountSpec, material CertificateMaterial, _ string) error {
	directoryURL,directory,err:=client.directory(ctx,account);if err!=nil{return err};if directory.RevokeCert==""{return ErrInvalidCertificate}
	block,_:=pem.Decode(material.LeafPEM);if block==nil||block.Type!="CERTIFICATE"{return ErrInvalidCertificate}
	kid,err:=client.EnsureAccount(ctx,account,"");if err!=nil{return err};signer,err:=client.Keys.AccountSigner(ctx,account);if err!=nil{return err}
	response,_,err:=client.signed(ctx,account,directoryURL,directory.RevokeCert,kid,signer,map[string]any{"certificate":base64.RawURLEncoding.EncodeToString(block.Bytes)});if response!=nil{response.Body.Close()};return err
}

func (client *HTTPACMEClient) authorization(ctx context.Context,account AccountSpec,directoryURL,kid string,signer crypto.Signer,authorizationURL string,kind ChallengeKind,tenant,thumbprint string)(Authorization,error){
	response,body,err:=client.signed(ctx,account,directoryURL,authorizationURL,kid,signer,nil);if err!=nil{return Authorization{},err};response.Body.Close();var document acmeAuthorizationDocument;if json.Unmarshal(body,&document)!=nil||document.Identifier.Type!="dns"||!validCertificateName(document.Identifier.Value){return Authorization{},ErrInvalidCertificate}
	challengeType:=string(kind);for _,candidate:=range document.Challenges{if candidate.Type!=challengeType{continue};if client.validateRemoteURL(account,directoryURL,candidate.URL)!=nil||candidate.Token==""{return Authorization{},ErrInvalidCertificate};keyAuthorization:=candidate.Token+"."+thumbprint;digest:=sha256.Sum256([]byte(keyAuthorization));challenge:=Challenge{ID:ChallengeID(acmeOpaqueID("challenge",candidate.URL)),Kind:kind,Name:document.Identifier.Value,Token:candidate.Token,URL:candidate.URL,KeyAuthorization:keyAuthorization,TenantID:tenant,State:candidate.Status};if kind==DNS01{challenge.DNSValue=base64.RawURLEncoding.EncodeToString(digest[:])};return Authorization{ID:acmeOpaqueID("authorization",authorizationURL),Name:document.Identifier.Value,Wildcard:document.Wildcard,URL:authorizationURL,Challenge:challenge,Status:document.Status,ExpiresAt:document.Expires},nil};return Authorization{},ErrInvalidCertificate
}

func (client *HTTPACMEClient) directory(ctx context.Context,account AccountSpec)(string,acmeDirectory,error){
	if validateAccount(account)!=nil{return "",acmeDirectory{},ErrInvalidCertificate};directoryURL:=account.Directory.ProductionURL;if client.Staging{directoryURL=account.Directory.StagingURL};if account.Directory.Kind==IssuerLetsEncrypt{if account.Directory.ProductionURL!=LetsEncryptProductionDirectory||account.Directory.StagingURL!=LetsEncryptStagingDirectory{return "",acmeDirectory{},ErrInvalidCertificate};expected:=LetsEncryptProductionDirectory;if client.Staging{expected=LetsEncryptStagingDirectory};if directoryURL!=expected{return "",acmeDirectory{},ErrInvalidCertificate}}
	if client.validateRemoteURL(account,directoryURL,directoryURL)!=nil{return "",acmeDirectory{},ErrInvalidCertificate};client.mu.Lock();cached,ok:=client.directories[directoryURL];client.mu.Unlock();if ok{return directoryURL,cached,nil}
	request,err:=http.NewRequestWithContext(ctx,http.MethodGet,directoryURL,nil);if err!=nil{return "",acmeDirectory{},err};request.Header.Set("Accept","application/json");response,err:=client.HTTP.Do(request);if err!=nil{return "",acmeDirectory{},err};body,err:=readACMEBody(response);response.Body.Close();if err!=nil{return "",acmeDirectory{},err};if json.Unmarshal(body,&cached)!=nil||cached.NewNonce==""||cached.NewAccount==""||cached.NewOrder==""{return "",acmeDirectory{},ErrInvalidCertificate};for _,endpoint:=range []string{cached.NewNonce,cached.NewAccount,cached.NewOrder,cached.RevokeCert}{if endpoint!=""&&client.validateRemoteURL(account,directoryURL,endpoint)!=nil{return "",acmeDirectory{},ErrInvalidCertificate}};client.mu.Lock();client.directories[directoryURL]=cached;client.mu.Unlock();return directoryURL,cached,nil
}

func(client *HTTPACMEClient)signed(ctx context.Context,account AccountSpec,directoryURL,target,kid string,signer crypto.Signer,payload any)(*http.Response,[]byte,error){
	if client.validateRemoteURL(account,directoryURL,target)!=nil{return nil,nil,ErrInvalidCertificate};encodedPayload:="";if payload!=nil{raw,err:=json.Marshal(payload);if err!=nil{return nil,nil,err};encodedPayload=base64.RawURLEncoding.EncodeToString(raw)}
	for attempt:=0;attempt<2;attempt++{nonce,err:=client.nonce(ctx,account,directoryURL);if err!=nil{return nil,nil,err};protected:=map[string]any{"alg":jwsAlgorithm(signer.Public()),"nonce":nonce,"url":target};if kid!=""{protected["kid"]=kid}else{jwk,err:=publicJWK(signer.Public());if err!=nil{return nil,nil,err};protected["jwk"]=jwk};protectedRaw,_:=json.Marshal(protected);protected64:=base64.RawURLEncoding.EncodeToString(protectedRaw);signature,err:=signJWS(signer,[]byte(protected64+"."+encodedPayload));if err!=nil{return nil,nil,err};message,_:=json.Marshal(map[string]string{"protected":protected64,"payload":encodedPayload,"signature":base64.RawURLEncoding.EncodeToString(signature)});request,err:=http.NewRequestWithContext(ctx,http.MethodPost,target,bytes.NewReader(message));if err!=nil{return nil,nil,err};request.Header.Set("Content-Type","application/jose+json");request.Header.Set("Accept","application/json, application/pem-certificate-chain");response,err:=client.HTTP.Do(request);if err!=nil{return nil,nil,err};client.storeNonce(directoryURL,response.Header.Get("Replay-Nonce"));body,readErr:=readACMEBody(response);if readErr!=nil{response.Body.Close();return nil,nil,readErr};if response.StatusCode>=200&&response.StatusCode<300{return response,body,nil};var problem acmeProblem;_ = json.Unmarshal(body,&problem);response.Body.Close();if attempt==0&&strings.HasSuffix(problem.Type,":badNonce"){continue};if problem.Detail==""{problem.Detail=http.StatusText(response.StatusCode)};return nil,nil,fmt.Errorf("acme %s: %s",problem.Type,problem.Detail)};return nil,nil,ErrCertificateAmbiguous
}

func(client *HTTPACMEClient)nonce(ctx context.Context,account AccountSpec,directoryURL string)(string,error){client.mu.Lock();values:=client.nonces[directoryURL];if len(values)>0{value:=values[len(values)-1];client.nonces[directoryURL]=values[:len(values)-1];client.mu.Unlock();return value,nil};client.mu.Unlock();_,directory,err:=client.directory(ctx,account);if err!=nil{return "",err};request,err:=http.NewRequestWithContext(ctx,http.MethodHead,directory.NewNonce,nil);if err!=nil{return "",err};response,err:=client.HTTP.Do(request);if err!=nil{return "",err};io.Copy(io.Discard,io.LimitReader(response.Body,4096));response.Body.Close();nonce:=response.Header.Get("Replay-Nonce");if response.StatusCode<200||response.StatusCode>=400||nonce==""{return "",ErrInvalidCertificate};return nonce,nil}
func(client *HTTPACMEClient)storeNonce(directoryURL,nonce string){if nonce==""{return};client.mu.Lock();defer client.mu.Unlock();values:=client.nonces[directoryURL];if len(values)<16{client.nonces[directoryURL]=append(values,nonce)}}
func(client *HTTPACMEClient)validateRemoteURL(account AccountSpec,directoryURL,target string)error{base,err:=url.Parse(directoryURL);if err!=nil||base.Scheme!="https"||base.User!=nil||base.Hostname()==""{return ErrInvalidCertificate};candidate,err:=url.Parse(target);if err!=nil||candidate.Scheme!="https"||candidate.User!=nil||candidate.Hostname()==""||candidate.Fragment!=""{return ErrInvalidCertificate};origin:=strings.ToLower(candidate.Scheme+"://"+candidate.Host);expected:=strings.TrimSuffix(strings.ToLower(account.Directory.PinnedOrigin),"/");if expected==""{expected=strings.ToLower(base.Scheme+"://"+base.Host)};if origin!=expected{return ErrInvalidCertificate};return nil}

func(client *HTTPACMEClient)externalAccountBinding(ctx context.Context,account AccountSpec,public crypto.PublicKey,target string)(map[string]string,error){key,err:=client.Keys.ExternalAccountKey(ctx,account);if err!=nil{return nil,err};defer wipeCertificateBytes(key);jwk,err:=publicJWK(public);if err!=nil{return nil,err};payload,_:=json.Marshal(jwk);protected,_:=json.Marshal(map[string]string{"alg":"HS256","kid":account.EABKeyID,"url":target});protected64:=base64.RawURLEncoding.EncodeToString(protected);payload64:=base64.RawURLEncoding.EncodeToString(payload);signature:=hmacSHA256(key,[]byte(protected64+"."+payload64));return map[string]string{"protected":protected64,"payload":payload64,"signature":base64.RawURLEncoding.EncodeToString(signature)},nil}

func(client *HTTPACMEClient)orderFromDocument(account AccountSpec,directoryURL,orderURL string,response *http.Response,body []byte)(RemoteOrder,error){var document acmeOrderDocument;if json.Unmarshal(body,&document)!=nil{return RemoteOrder{},ErrInvalidCertificate};if document.Finalize==""||client.validateRemoteURL(account,directoryURL,document.Finalize)!=nil{return RemoteOrder{},ErrInvalidCertificate};if document.Certificate!=""&&client.validateRemoteURL(account,directoryURL,document.Certificate)!=nil{return RemoteOrder{},ErrInvalidCertificate};return RemoteOrder{URL:orderURL,Status:document.Status,FinalizeURL:document.Finalize,CertificateURL:document.Certificate,RetryAfter:retryAfter(response.Header,time.Now())},nil}
func readACMEBody(response *http.Response)([]byte,error){if response==nil||response.Body==nil{return nil,ErrInvalidCertificate};body,err:=io.ReadAll(io.LimitReader(response.Body,maximumACMEResponse+1));if err!=nil||len(body)>maximumACMEResponse{return nil,ErrInvalidCertificate};return body,nil}
func retryAfter(header http.Header,now time.Time)time.Duration{value:=header.Get("Retry-After");if seconds,err:=strconv.Atoi(value);err==nil&&seconds>=0{return time.Duration(seconds)*time.Second};if parsed,err:=http.ParseTime(value);err==nil&&parsed.After(now){return parsed.Sub(now)};return time.Second}
func acmeOpaqueID(prefix,value string)string{sum:=sha256.Sum256([]byte(prefix+"\x00"+value));return prefix+"_"+hex.EncodeToString(sum[:])[:48]}

func publicJWK(public crypto.PublicKey)(map[string]string,error){switch key:=public.(type){case *ecdsa.PublicKey:if key.Curve.Params().Name!="P-256"{return nil,ErrInvalidCertificate};size:=(key.Curve.Params().BitSize+7)/8;x:=key.X.FillBytes(make([]byte,size));y:=key.Y.FillBytes(make([]byte,size));return map[string]string{"crv":"P-256","kty":"EC","x":base64.RawURLEncoding.EncodeToString(x),"y":base64.RawURLEncoding.EncodeToString(y)},nil;case *rsa.PublicKey:if key.N.BitLen()<2048||key.E!=65537{return nil,ErrInvalidCertificate};return map[string]string{"e":base64.RawURLEncoding.EncodeToString([]byte{1,0,1}),"kty":"RSA","n":base64.RawURLEncoding.EncodeToString(key.N.Bytes())},nil;default:return nil,ErrInvalidCertificate}}
func jwkThumbprint(public crypto.PublicKey)(string,error){jwk,err:=publicJWK(public);if err!=nil{return "",err};raw,err:=json.Marshal(jwk);if err!=nil{return "",err};sum:=sha256.Sum256(raw);return base64.RawURLEncoding.EncodeToString(sum[:]),nil}
func mustJWKThumbprint(public crypto.PublicKey)string{value,_:=jwkThumbprint(public);return value}
func jwsAlgorithm(public crypto.PublicKey)string{switch public.(type){case *ecdsa.PublicKey:return "ES256";case *rsa.PublicKey:return "RS256"};return ""}
func signJWS(signer crypto.Signer,input []byte)([]byte,error){digest:=sha256.Sum256(input);signature,err:=signer.Sign(rand.Reader,digest[:],crypto.SHA256);if err!=nil{return nil,err};if key,ok:=signer.Public().(*ecdsa.PublicKey);ok{r,s,parseErr:=parseECDSASignature(signature);if parseErr!=nil{return nil,parseErr};size:=(key.Curve.Params().BitSize+7)/8;raw:=make([]byte,size*2);r.FillBytes(raw[:size]);s.FillBytes(raw[size:]);return raw,nil};return signature,nil}
func parseECDSASignature(value []byte)(*big.Int,*big.Int,error){var signature struct{R,S *big.Int};rest,err:=asn1.Unmarshal(value,&signature);if err!=nil||len(rest)!=0||signature.R==nil||signature.S==nil||signature.R.Sign()<=0||signature.S.Sign()<=0{return nil,nil,ErrInvalidCertificate};return signature.R,signature.S,nil}
func hmacSHA256(key,message []byte)[]byte{mac:=hmac.New(sha256.New,key);_,_=mac.Write(message);return mac.Sum(nil)}

func certificateMaterialFromPEM(content []byte)(CertificateMaterial,error){var blocks [][]byte;rest:=content;var leaf *x509.Certificate;for len(rest)>0{block,next:=pem.Decode(rest);if block==nil{if strings.TrimSpace(string(rest))!=""{return CertificateMaterial{},ErrInvalidCertificate};break};if block.Type!="CERTIFICATE"||len(block.Headers)!=0{return CertificateMaterial{},ErrInvalidCertificate};certificate,err:=x509.ParseCertificate(block.Bytes);if err!=nil{return CertificateMaterial{},ErrInvalidCertificate};if leaf==nil{leaf=certificate};blocks=append(blocks,pem.EncodeToMemory(block));rest=next};if leaf==nil||len(blocks)==0{return CertificateMaterial{},ErrInvalidCertificate};leafPEM:=append([]byte(nil),blocks[0]...);chain:=bytes.Join(blocks[1:],nil);fullchain:=bytes.Join(blocks,nil);sum:=sha256.Sum256(leaf.Raw);names:=append([]string(nil),leaf.DNSNames...);identifier:=CertificateID("cert_"+hex.EncodeToString(sum[:])[:48]);return CertificateMaterial{ID:identifier,LeafPEM:leafPEM,ChainPEM:chain,FullChainPEM:fullchain,Names:names,Serial:leaf.SerialNumber.Text(16),FingerprintSHA256:hex.EncodeToString(sum[:]),NotBefore:leaf.NotBefore.UTC(),NotAfter:leaf.NotAfter.UTC(),Issuer:leaf.Issuer.String()},nil}

func wipeCertificateBytes(values ...[]byte){for _,value:=range values{for index:=range value{value[index]=0}}}

var _ ACMEClient = (*HTTPACMEClient)(nil)
var _ = errors.Is
