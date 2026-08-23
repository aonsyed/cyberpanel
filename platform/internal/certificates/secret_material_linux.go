//go:build linux

package certificates

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	CertificateSecretAdapterID = "certificates.acme"
	CertificateSecretAdapterVersion = "linux-acme-v1"
)

type SecretMaterialRuntime struct { Material *secrets.MaterialClient; Management *secrets.ManagementClient; ConsumerReleaseDigest string }

func NewSecretMaterialRuntime(material *secrets.MaterialClient,management *secrets.ManagementClient,releaseDigest string)(*SecretMaterialRuntime,error){if material==nil||management==nil||len(releaseDigest)!=64{return nil,ErrInvalidCertificate};if _,err:=hex.DecodeString(releaseDigest);err!=nil{return nil,ErrInvalidCertificate};return &SecretMaterialRuntime{Material:material,Management:management,ConsumerReleaseDigest:strings.ToLower(releaseDigest)},nil}

func NewLocalSecretMaterialRuntime(releaseDigest string)(*SecretMaterialRuntime,error){material,err:=secrets.NewLocalMaterialClient();if err!=nil{return nil,err};management,err:=secrets.NewLocalManagementClient();if err!=nil{return nil,err};return NewSecretMaterialRuntime(material,management,releaseDigest)}

func(runtime *SecretMaterialRuntime)AccountSigner(ctx context.Context,account AccountSpec)(crypto.Signer,error){if runtime==nil||account.AccountKeyRef==""||account.TenantID==""||account.ID==""{return nil,ErrInvalidCertificate};payload,err:=runtime.read(ctx,account.AccountKeyRef,certificateTenantID(account.TenantID),secrets.PurposeACME,secrets.OperationSign,certificateResourceID(string(account.ID)));if err!=nil{return nil,err};defer wipeCertificateBytes(payload);return parseCertificateSigner(payload)}
func(runtime *SecretMaterialRuntime)ExternalAccountKey(ctx context.Context,account AccountSpec)([]byte,error){if runtime==nil||!account.Directory.RequiresEAB||account.EABKeyRef==""{return nil,ErrInvalidCertificate};payload,err:=runtime.read(ctx,account.EABKeyRef,certificateTenantID(account.TenantID),secrets.PurposeACME,secrets.OperationAuthenticate,certificateResourceID(string(account.ID)));if err!=nil{return nil,err};if len(payload)<16||len(payload)>4096{wipeCertificateBytes(payload);return nil,ErrInvalidCertificate};return payload,nil}

// EnsureAccountKey creates a purpose-bound ACME account signer when the
// tenant's default account is first used. The returned value is an opaque
// reference; the private key never crosses the protected secret boundary.
func(runtime *SecretMaterialRuntime)EnsureAccountKey(ctx context.Context,tenant string,accountID AccountID)(string,error){if runtime==nil||runtime.Management==nil||ctx==nil||tenant==""||accountID==""{return "",ErrInvalidCertificate};owner:=certificateTenantID(tenant);resource:=certificateResourceID(string(accountID));sum:=sha256.Sum256([]byte("acme-account-key-v1\x00"+tenant+"\x00"+string(accountID)));secretID,err:=secrets.NewID("acme_"+hex.EncodeToString(sum[:])[:48]);if err!=nil{return "",err};key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{return "",err};encoded,err:=x509.MarshalPKCS8PrivateKey(key);if err!=nil{return "",err};privatePEM:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:encoded});metadata,putErr:=runtime.Management.Put(ctx,secrets.PutRequest{ID:secretID,OwnerTenantID:owner,Purpose:secrets.PurposeACME,Audience:secrets.AudienceBinding{AdapterID:CertificateSecretAdapterID,AdapterVersion:CertificateSecretAdapterVersion,Account:"certificate-runtime",Origin:"local://panel-core/certificates",ResourceKind:"acme_account",ResourceID:resource,ResourceGeneration:1,Operations:[]secrets.Operation{secrets.OperationSign},ConsumerReleaseDigest:runtime.ConsumerReleaseDigest},Plaintext:privatePEM});wipeCertificateBytes(encoded,privatePEM);if putErr!=nil{return "",putErr};return string(metadata.ID),nil}

func(runtime *SecretMaterialRuntime)CreateCSR(ctx context.Context,request CSRRequest)(CSRMaterial,error){
	if runtime==nil||request.TenantID==""||request.ResourceID==""||len(request.Names)==0{return CSRMaterial{},ErrInvalidCertificate};for _,name:=range request.Names{if !validCertificateName(strings.TrimPrefix(name,"*.")){return CSRMaterial{},ErrInvalidCertificate}}
	var signer crypto.Signer;var err error
	if request.ExistingKeyRef!=""{payload,readErr:=runtime.TLSPrivateKeyPEM(ctx,request.ExistingKeyRef);if readErr!=nil{return CSRMaterial{},readErr};signer,err=parseCertificateSigner(payload);wipeCertificateBytes(payload)}else{switch request.KeyAlgorithm{case "ecdsa-p256":signer,err=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);case "rsa-3072":signer,err=rsa.GenerateKey(rand.Reader,3072);case "rsa-4096":signer,err=rsa.GenerateKey(rand.Reader,4096);default:return CSRMaterial{},ErrInvalidCertificate}}
	if err!=nil{return CSRMaterial{},err};publicDER,err:=x509.MarshalPKIXPublicKey(signer.Public());if err!=nil{return CSRMaterial{},err};publicDigest:=sha256.Sum256(publicDER)
	generation:=request.ResourceGeneration;if generation==0{generation=1};secretRef:=request.ExistingKeyRef;if secretRef==""{secretID,_:=secrets.NewID("tls_"+hex.EncodeToString(publicDigest[:])[:48]);owner:=certificateTenantID(request.TenantID);resource:=certificateResourceID(request.ResourceID);encoded,marshalErr:=x509.MarshalPKCS8PrivateKey(signer);if marshalErr!=nil{return CSRMaterial{},marshalErr};privatePEM:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:encoded});metadata,putErr:=runtime.Management.Put(ctx,secrets.PutRequest{ID:secretID,OwnerTenantID:owner,Purpose:secrets.PurposeTLSKey,Audience:secrets.AudienceBinding{AdapterID:CertificateSecretAdapterID,AdapterVersion:CertificateSecretAdapterVersion,Account:"certificate-runtime",Origin:"local://panel-core/certificates",ResourceKind:"certificate_policy",ResourceID:resource,ResourceGeneration:generation,Operations:[]secrets.Operation{secrets.OperationRead,secrets.OperationSign},ConsumerReleaseDigest:runtime.ConsumerReleaseDigest},Plaintext:privatePEM});wipeCertificateBytes(encoded,privatePEM);if putErr!=nil{return CSRMaterial{},putErr};secretRef=encodeCertificateKeyReference(metadata.ID,owner,resource)}
	template:=x509.CertificateRequest{Subject:pkix.Name{CommonName:request.Names[0]},DNSNames:append([]string(nil),request.Names...),SignatureAlgorithm:signatureAlgorithm(signer)};if request.MustStaple{value,_:=asn1.Marshal([]int{5});template.ExtraExtensions=append(template.ExtraExtensions,pkix.Extension{Id:asn1.ObjectIdentifier{1,3,6,1,5,5,7,1,24},Value:value})};der,err:=x509.CreateCertificateRequest(rand.Reader,&template,signer);if err!=nil{return CSRMaterial{},err};parsed,err:=x509.ParseCertificateRequest(der);if err!=nil||parsed.CheckSignature()!=nil{return CSRMaterial{},ErrInvalidCertificate};return CSRMaterial{DER:der,PrivateKeyRef:secretRef,PublicKeyDigest:hex.EncodeToString(publicDigest[:])},nil
}

func(runtime *SecretMaterialRuntime)PrivateKey(ctx context.Context,reference string,policy CertificatePolicy)(crypto.Signer,error){secretID,owner,resource,err:=decodeCertificateKeyReference(reference);if err!=nil{if policy.TenantID==""||policy.ID==""{return nil,ErrInvalidCertificate};secretID,err=secrets.NewID(reference);owner=certificateTenantID(policy.TenantID);resource=certificateResourceID(string(policy.ID));if err!=nil{return nil,ErrInvalidCertificate}};payload,err:=runtime.readID(ctx,secretID,owner,secrets.PurposeTLSKey,secrets.OperationSign,resource);if err!=nil{return nil,err};defer wipeCertificateBytes(payload);return parseCertificateSigner(payload)}

func(runtime *SecretMaterialRuntime)TLSPrivateKeyPEM(ctx context.Context,reference string)([]byte,error){secretID,owner,resource,err:=decodeCertificateKeyReference(reference);if err!=nil{return nil,err};payload,err:=runtime.readID(ctx,secretID,owner,secrets.PurposeTLSKey,secrets.OperationRead,resource);if err!=nil{return nil,err};if _,parseErr:=parseCertificateSigner(payload);parseErr!=nil{wipeCertificateBytes(payload);return nil,parseErr};return payload,nil}

func(runtime *SecretMaterialRuntime)read(ctx context.Context,reference string,owner secrets.ID,purpose secrets.Purpose,operation secrets.Operation,resource secrets.ID)([]byte,error){secretID,err:=secrets.NewID(reference);if err!=nil{return nil,ErrInvalidCertificate};return runtime.readID(ctx,secretID,owner,purpose,operation,resource)}
func(runtime *SecretMaterialRuntime)readID(ctx context.Context,secretID,owner secrets.ID,purpose secrets.Purpose,operation secrets.Operation,resource secrets.ID)([]byte,error){if runtime==nil||runtime.Material==nil||!secretID.Valid()||!owner.Valid()||!resource.Valid(){return nil,ErrInvalidCertificate};response,err:=runtime.Material.Read(ctx,secrets.MaterialRequest{SecretID:secretID,OwnerTenantID:owner,Purpose:purpose,Operation:operation,AdapterID:CertificateSecretAdapterID,AdapterVersion:CertificateSecretAdapterVersion,ResourceID:resource});if err!=nil{return nil,err};if len(response.Material)==0||len(response.Material)>1<<20{wipeCertificateBytes(response.Material);return nil,ErrInvalidCertificate};return response.Material,nil}

func parseCertificateSigner(content []byte)(crypto.Signer,error){block,rest:=pem.Decode(content);if block==nil||len(strings.TrimSpace(string(rest)))!=0||len(block.Headers)!=0{return nil,ErrInvalidCertificate};var key any;var err error;switch block.Type{case "PRIVATE KEY":key,err=x509.ParsePKCS8PrivateKey(block.Bytes);case "EC PRIVATE KEY":key,err=x509.ParseECPrivateKey(block.Bytes);case "RSA PRIVATE KEY":key,err=x509.ParsePKCS1PrivateKey(block.Bytes);default:return nil,ErrInvalidCertificate};if err!=nil{return nil,ErrInvalidCertificate};signer,ok:=key.(crypto.Signer);if !ok{return nil,ErrInvalidCertificate};switch public:=signer.Public().(type){case *ecdsa.PublicKey:if public.Curve!=elliptic.P256(){return nil,ErrInvalidCertificate};case *rsa.PublicKey:if public.N.BitLen()<3072||public.E!=65537{return nil,ErrInvalidCertificate};default:return nil,ErrInvalidCertificate};return signer,nil}
func signatureAlgorithm(signer crypto.Signer)x509.SignatureAlgorithm{switch signer.Public().(type){case *ecdsa.PublicKey:return x509.ECDSAWithSHA256;case *rsa.PublicKey:return x509.SHA256WithRSA};return x509.UnknownSignatureAlgorithm}
func certificateTenantID(value string)secrets.ID{return certificateSecretID("tenant",value)}
func certificateResourceID(value string)secrets.ID{return certificateSecretID("resource",value)}
func certificateSecretID(prefix,value string)secrets.ID{if result,err:=secrets.NewID(value);err==nil{return result};sum:=sha256.Sum256([]byte(prefix+"\x00"+value));result,_:=secrets.NewID(prefix+"_"+hex.EncodeToString(sum[:])[:48]);return result}
type certificateKeyReference struct{SecretID secrets.ID `json:"s"`;OwnerID secrets.ID `json:"o"`;ResourceID secrets.ID `json:"r"`}
func encodeCertificateKeyReference(secretID,ownerID,resourceID secrets.ID)string{raw,_:=json.Marshal(certificateKeyReference{SecretID:secretID,OwnerID:ownerID,ResourceID:resourceID});return "keyref_v1."+base64.RawURLEncoding.EncodeToString(raw)}
func decodeCertificateKeyReference(value string)(secrets.ID,secrets.ID,secrets.ID,error){if !strings.HasPrefix(value,"keyref_v1."){return "","","",ErrInvalidCertificate};raw,err:=base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value,"keyref_v1."));if err!=nil||len(raw)>1024{return "","","",ErrInvalidCertificate};var reference certificateKeyReference;if json.Unmarshal(raw,&reference)!=nil||!reference.SecretID.Valid()||!reference.OwnerID.Valid()||!reference.ResourceID.Valid(){return "","","",ErrInvalidCertificate};return reference.SecretID,reference.OwnerID,reference.ResourceID,nil}

var _ ACMEKeySource = (*SecretMaterialRuntime)(nil)
var _ CSRSigner = (*SecretMaterialRuntime)(nil)
var _ CertificatePrivateKeySource = (*SecretMaterialRuntime)(nil)
var _ = errors.Is
