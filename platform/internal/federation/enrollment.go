package federation

import(
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type EnrollmentToken struct{ID ID;PeerID ID;NodeID ID;TokenDigest,CAFingerprint,Endpoint string;ExpiresAt time.Time;ConsumedAt *time.Time}
type EnrollmentStore interface{Create(context.Context,EnrollmentToken)error;Consume(context.Context,ID,string,time.Time)(EnrollmentToken,error)}
type NodeKeyStore interface{CreateSigningIdentity(context.Context,ID)(publicKey []byte,keyRef string,err error);CreateHPKEIdentity(context.Context,ID)(publicKey []byte,keyRef string,err error);Destroy(context.Context,string)error}
type EnrollmentExchange interface{Enroll(context.Context,EnrollmentRequest)(EnrollmentResponse,error)}
type EnrollmentRequest struct{TokenID ID;Token []byte;NodeID ID;SigningPublicKey,HPKEPublicKey []byte;CapabilityDigest,CAFingerprint string}
type EnrollmentResponse struct{PeerID ID;PeerSigningKeys map[string][]byte;NodeCertificate []byte;NodeCertificateRef string;CertificateExpiresAt time.Time;AuthorityEpoch uint64}
type CertificateStore interface{StoreNodeCertificate(context.Context,ID,[]byte,time.Time)(string,error)}
type EnrollmentService struct{tokens EnrollmentStore;keys NodeKeyStore;certificates CertificateStore;exchange EnrollmentExchange;federation *Store;clock func()time.Time}
func NewEnrollmentService(tokens EnrollmentStore,keys NodeKeyStore,certificates CertificateStore,exchange EnrollmentExchange,store *Store)(*EnrollmentService,error){if tokens==nil||keys==nil||certificates==nil||exchange==nil||store==nil{return nil,ErrInvalid};return &EnrollmentService{tokens:tokens,keys:keys,certificates:certificates,exchange:exchange,federation:store,clock:time.Now},nil}
func(s *EnrollmentService)Prepare(ctx context.Context,id,peer,node ID,rawToken []byte,caFingerprint,endpoint string,ttl time.Duration)(EnrollmentToken,error){defer wipe(rawToken);if ttl<=0||ttl>time.Hour||len(rawToken)<32||len(caFingerprint)!=64||!strings.HasPrefix(endpoint,"https://"){return EnrollmentToken{},ErrInvalid};token:=EnrollmentToken{ID:id,PeerID:peer,NodeID:node,TokenDigest:digestBytes(rawToken),CAFingerprint:caFingerprint,Endpoint:endpoint,ExpiresAt:s.clock().UTC().Add(ttl)};return token,s.tokens.Create(ctx,token)}
func(s *EnrollmentService)Enroll(ctx context.Context,tokenID ID,rawToken []byte,capabilities CapabilitySet)(Peer,error){defer wipe(rawToken);token,err:=s.tokens.Consume(ctx,tokenID,digestBytes(rawToken),s.clock().UTC());if err!=nil{return Peer{},err};if capabilities.NodeID!=token.NodeID||capabilities.CanonicalDigest()!=capabilities.Digest{return Peer{},ErrConflict};signingPublic,signingRef,err:=s.keys.CreateSigningIdentity(ctx,token.NodeID);if err!=nil{return Peer{},err};hpkePublic,hpkeRef,err:=s.keys.CreateHPKEIdentity(ctx,token.NodeID);if err!=nil{_ = s.keys.Destroy(ctx,signingRef);return Peer{},err};response,err:=s.exchange.Enroll(ctx,EnrollmentRequest{TokenID:token.ID,Token:rawToken,NodeID:token.NodeID,SigningPublicKey:signingPublic,HPKEPublicKey:hpkePublic,CapabilityDigest:capabilities.Digest,CAFingerprint:token.CAFingerprint});if err!=nil{_ = s.keys.Destroy(ctx,signingRef);_ = s.keys.Destroy(ctx,hpkeRef);return Peer{},err};if response.PeerID!=token.PeerID||response.AuthorityEpoch==0||response.AuthorityEpoch!=capabilities.AuthorityEpoch||!response.CertificateExpiresAt.After(s.clock().UTC())||len(response.PeerSigningKeys)==0{return Peer{},ErrForbidden};certificateRef,err:=s.certificates.StoreNodeCertificate(ctx,token.NodeID,response.NodeCertificate,response.CertificateExpiresAt);if err!=nil{return Peer{},err};now:=s.clock().UTC();peer:=Peer{ID:response.PeerID,State:"active",CAFingerprint:token.CAFingerprint,SigningKeys:response.PeerSigningKeys,NodeCertificateRef:certificateRef,HPKEKeyRef:hpkeRef,CreatedAt:now,UpdatedAt:now};if err=s.federation.ActivateEnrollment(ctx,token.NodeID,capabilities.AuthorityEpoch,peer);err!=nil{return Peer{},err};return peer,nil}
func digestBytes(value []byte)string{sum:=sha256.Sum256(value);return hex.EncodeToString(sum[:])}
func wipe(value []byte){for index:=range value{value[index]=0}}
var _=errors.Is
