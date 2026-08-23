package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type InstallationClaimPayload struct{ClaimToken string `json:"claim_token"`;PrincipalID identity.ID `json:"principal_id"`;TenantID identity.ID `json:"tenant_id"`;MembershipID identity.ID `json:"membership_id"`;RoleID identity.ID `json:"role_id"`;BindingID identity.ID `json:"binding_id"`;PlanID identity.ID `json:"plan_id"`;Username string `json:"username"`;Email string `json:"email"`;DisplayName string `json:"display_name"`;Locale string `json:"locale"`;Password string `json:"password"`;Quota identity.ResourceQuota `json:"quota"`}
type InstallationClaimResult struct{Principal identity.Principal `json:"principal"`;CSRFToken string `json:"csrf_token"`;ExpiresAt time.Time `json:"expires_at"`;Session *SessionDelivery `json:"-"`}
type RecoveryHealth struct{Status string `json:"status"`;CoreReachable bool `json:"core_reachable"`;TrustReadable bool `json:"trust_readable"`;SignerReadable bool `json:"signer_readable"`;At time.Time `json:"at"`}
type TrustRotationResult struct{KeyID string `json:"key_id"`;RotatedAt time.Time `json:"rotated_at"`}

type ClaimTokenStore interface{Verify(string)error;Consume(string)error}
type FileClaimTokenStore struct{path string}
func NewFileClaimTokenStore(path string)(*FileClaimTokenStore,error){if !filepath.IsAbs(path)||filepath.Clean(path)!=path{return nil,invalid("claim token path")};return &FileClaimTokenStore{path:path},nil}
func(store *FileClaimTokenStore)Verify(token string)error{if len(token)<32||len(token)>1024{return ErrUnauthenticated};content,err:=readSecretFile(store.path,2048);if err!=nil{return ErrUnauthenticated};expected:=sha256.Sum256(bytes.TrimSpace(content));actual:=sha256.Sum256([]byte(token));for index:=range content{content[index]=0};if subtle.ConstantTimeCompare(expected[:],actual[:])!=1{return ErrUnauthenticated};return nil}
func(store *FileClaimTokenStore)Consume(token string)error{if err:=store.Verify(token);err!=nil{return err};sum:=sha256.Sum256([]byte(token));consumed:=store.path+".consumed-"+hex.EncodeToString(sum[:8]);if _,err:=os.Lstat(consumed);err==nil{return ErrConflict}else if !errors.Is(err,os.ErrNotExist){return err};return os.Rename(store.path,consumed)}

type RecoveryController struct{Identity *identity.Service;Claims ClaimTokenStore;Core CoreTransport;TrustPaths TrustPaths;Clock func()time.Time}
func(controller *RecoveryController)Claim(ctx context.Context,payload *InstallationClaimPayload)(InstallationClaimResult,error){if controller==nil||controller.Identity==nil||controller.Claims==nil||payload==nil{return InstallationClaimResult{},ErrUnavailable};if err:=controller.Claims.Verify(payload.ClaimToken);err!=nil{return InstallationClaimResult{},err};claimPassword:=[]byte(payload.Password);loginPassword:=append([]byte(nil),claimPassword...);payload.Password="";principal,err:=controller.Identity.ClaimInstallation(ctx,identity.InstallationClaim{PrincipalID:payload.PrincipalID,TenantID:payload.TenantID,MembershipID:payload.MembershipID,RoleID:payload.RoleID,BindingID:payload.BindingID,PlanID:payload.PlanID,Username:payload.Username,Email:payload.Email,DisplayName:payload.DisplayName,Locale:payload.Locale,Password:claimPassword,Quota:payload.Quota});clearSecret(claimPassword);if err!=nil{clearSecret(loginPassword);return InstallationClaimResult{},mapIdentityError(err)};if err=controller.Claims.Consume(payload.ClaimToken);err!=nil{clearSecret(loginPassword);return InstallationClaimResult{Principal:principal},errors.Join(ErrUnavailable,err)};payload.ClaimToken="";ua:=sha256.Sum256([]byte("panel-recovery-claim"));login,err:=controller.Identity.AuthenticatePassword(ctx,identity.LoginRequest{Username:payload.Username,Password:loginPassword,Source:netip.MustParseAddr("127.0.0.1"),UserAgentDigest:hex.EncodeToString(ua[:]),SessionTTL:30*time.Minute,AbsoluteTTL:12*time.Hour});clearSecret(loginPassword);if err!=nil{return InstallationClaimResult{Principal:principal},mapIdentityError(err)};delivery:=&SessionDelivery{SessionID:login.Session.ID.String(),SessionToken:base64.RawURLEncoding.EncodeToString(login.SessionToken),CSRFToken:base64.RawURLEncoding.EncodeToString(login.CSRFToken),ExpiresAt:login.Session.ExpiresAt};return InstallationClaimResult{Principal:principal,CSRFToken:delivery.CSRFToken,ExpiresAt:delivery.ExpiresAt,Session:delivery},nil}
func(controller *RecoveryController)Health(ctx context.Context)RecoveryHealth{now:=time.Now().UTC();if controller.Clock!=nil{now=controller.Clock().UTC()};health:=RecoveryHealth{Status:"degraded",At:now};if controller.Core!=nil{health.CoreReachable=controller.Core.Health(ctx)==nil};_,trustErr:=loadTrustDocument(controller.TrustPaths.TrustPath);health.TrustReadable=trustErr==nil;_,signerErr:=LoadSigner(controller.TrustPaths.SignerPath);health.SignerReadable=signerErr==nil;if health.CoreReachable&&health.TrustReadable&&health.SignerReadable{health.Status="healthy"};return health}
func(controller *RecoveryController)RotateTrust() (TrustRotationResult,error){now:=time.Now().UTC();if controller.Clock!=nil{now=controller.Clock().UTC()};keyID,err:=RotateLocalTrust(controller.TrustPaths,now);return TrustRotationResult{KeyID:keyID,RotatedAt:now},err}

type RecoveryServer struct{Controller *RecoveryController;MaximumBodyBytes int64}
func(server *RecoveryServer)Handler()http.Handler{mux:=http.NewServeMux();mux.HandleFunc("GET /recovery/v1/health",server.health);mux.HandleFunc("POST /recovery/v1/claim",server.claim);mux.HandleFunc("POST /recovery/v1/trust/rotate",server.rotate);return http.HandlerFunc(func(writer http.ResponseWriter,request *http.Request){writer.Header().Set("Cache-Control","no-store");writer.Header().Set("X-Content-Type-Options","nosniff");mux.ServeHTTP(writer,request)})}
func(server *RecoveryServer)health(writer http.ResponseWriter,request *http.Request){ctx,cancel:=context.WithTimeout(request.Context(),3*time.Second);defer cancel();_ = writeJSON(writer,http.StatusOK,server.Controller.Health(ctx),1<<20)}
func(server *RecoveryServer)claim(writer http.ResponseWriter,request *http.Request){var payload InstallationClaimPayload;maximum:=server.MaximumBodyBytes;if maximum<=0||maximum>1<<20{maximum=1<<20};if err:=readJSON(request,maximum,&payload);err!=nil{writeProblem(writer,classifyError(err,""),1<<20);return};result,err:=server.Controller.Claim(request.Context(),&payload);if err!=nil{writeProblem(writer,classifyError(err,""),1<<20);return};if result.CSRFToken!=""{writer.Header().Set("X-CSRF-Token",result.CSRFToken)};_ = writeJSON(writer,http.StatusCreated,result,1<<20)}
func(server *RecoveryServer)rotate(writer http.ResponseWriter,_ *http.Request){result,err:=server.Controller.RotateTrust();if err!=nil{writeProblem(writer,classifyError(err,""),1<<20);return};_ = writeJSON(writer,http.StatusOK,result,1<<20)}

type RecoveryClient struct{client *http.Client}
func NewRecoveryClient(socketPath string)(*RecoveryClient,error){if !filepath.IsAbs(socketPath)||filepath.Clean(socketPath)!=socketPath{return nil,invalid("recovery socket")};dialer:=&net.Dialer{Timeout:3*time.Second};transport:=&http.Transport{DialContext:func(ctx context.Context,_,_ string)(net.Conn,error){return dialer.DialContext(ctx,"unix",socketPath)},DisableCompression:true,ResponseHeaderTimeout:30*time.Second};return &RecoveryClient{client:&http.Client{Transport:transport}},nil}
func(client *RecoveryClient)request(ctx context.Context,method,path string,input,target any)error{var body io.Reader;if input!=nil{content,err:=json.Marshal(input);if err!=nil{return err};body=bytes.NewReader(content)};request,err:=http.NewRequestWithContext(ctx,method,"http://panel-core"+path,body);if err!=nil{return err};if input!=nil{request.Header.Set("Content-Type",ContentTypeJSON)};response,err:=client.client.Do(request);if err!=nil{return err};defer response.Body.Close();content,err:=io.ReadAll(io.LimitReader(response.Body,(1<<20)+1));if err!=nil||len(content)>1<<20{return ErrResponseTooLarge};if response.StatusCode<200||response.StatusCode>299{var problem Problem;if decodeStrict(content,&problem)!=nil{return ErrUnavailable};return problem};return decodeStrict(content,target)}
func(client *RecoveryClient)Health(ctx context.Context)(RecoveryHealth,error){var result RecoveryHealth;err:=client.request(ctx,http.MethodGet,"/recovery/v1/health",nil,&result);return result,err}
func(client *RecoveryClient)Claim(ctx context.Context,payload InstallationClaimPayload)(InstallationClaimResult,error){var result InstallationClaimResult;err:=client.request(ctx,http.MethodPost,"/recovery/v1/claim",payload,&result);payload.Password="";payload.ClaimToken="";return result,err}
func(client *RecoveryClient)RotateTrust(ctx context.Context)(TrustRotationResult,error){var result TrustRotationResult;err:=client.request(ctx,http.MethodPost,"/recovery/v1/trust/rotate",struct{}{},&result);return result,err}
