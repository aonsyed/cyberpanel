package certificates

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/asn1"
	"encoding/pem"
	"sort"
	"strings"
	"time"
)

type CertificatePrivateKeySource interface { PrivateKey(context.Context,string,CertificatePolicy) (crypto.Signer,error) }

type X509MaterialValidator struct { Keys CertificatePrivateKeySource; Now func()time.Time }

func (validator X509MaterialValidator) Validate(ctx context.Context, material CertificateMaterial, policy CertificatePolicy) error {
	if ctx==nil||material.ID==""||material.PrivateKeyRef==""||len(material.LeafPEM)==0||len(material.FullChainPEM)==0||validatePolicy(policy)!=nil{return ErrInvalidCertificate}
	leaf,leafBlock,err:=oneCertificate(material.LeafPEM);if err!=nil{return err}
	certificates,encoded,err:=certificateChain(material.FullChainPEM);if err!=nil||len(certificates)==0||!bytes.Equal(certificates[0].Raw,leaf.Raw)||!bytes.Equal(encoded[0],leafBlock){return ErrInvalidCertificate}
	chainCertificates,chainEncoded,err:=certificateChain(material.ChainPEM);if err!=nil{return err};if len(chainCertificates)!=len(certificates)-1{return ErrInvalidCertificate};for index:=range chainCertificates{if !bytes.Equal(chainCertificates[index].Raw,certificates[index+1].Raw)||!bytes.Equal(chainEncoded[index],encoded[index+1]){return ErrInvalidCertificate}}
	if leaf.IsCA||leaf.SerialNumber==nil||leaf.SerialNumber.Sign()<=0||leaf.SignatureAlgorithm==x509.UnknownSignatureAlgorithm||leaf.PublicKeyAlgorithm==x509.UnknownPublicKeyAlgorithm{return ErrInvalidCertificate}
	switch key:=leaf.PublicKey.(type){case *ecdsa.PublicKey:if policy.KeyAlgorithm!="ecdsa-p256"||key.Curve!=elliptic.P256(){return ErrInvalidCertificate};case *rsa.PublicKey:expected:=3072;if policy.KeyAlgorithm=="rsa-4096"{expected=4096}else if policy.KeyAlgorithm!="rsa-3072"{return ErrInvalidCertificate};if key.N.BitLen()!=expected||key.E!=65537{return ErrInvalidCertificate};default:return ErrInvalidCertificate}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature==0{return ErrInvalidCertificate};serverAuth:=false;for _,usage:=range leaf.ExtKeyUsage{if usage==x509.ExtKeyUsageServerAuth{serverAuth=true}};if !serverAuth{return ErrInvalidCertificate}
	now:=time.Now().UTC();if validator.Now!=nil{now=validator.Now().UTC()};if leaf.NotBefore.After(now.Add(10*time.Minute))||!leaf.NotAfter.After(now)||leaf.NotAfter.Sub(leaf.NotBefore)>400*24*time.Hour{return ErrInvalidCertificate}
	expected:=canonicalCertificateNames(policy.Names);actual:=canonicalCertificateNames(leaf.DNSNames);if len(expected)!=len(actual){return ErrInvalidCertificate};for index:=range expected{if expected[index]!=actual[index]{return ErrInvalidCertificate};hostname:=expected[index];if strings.HasPrefix(hostname,"*."){hostname="acme-validation."+strings.TrimPrefix(hostname,"*.")};if leaf.VerifyHostname(hostname)!=nil{return ErrInvalidCertificate}}
	for index:=0;index<len(certificates)-1;index++{issuer:=certificates[index+1];if !issuer.IsCA||issuer.KeyUsage&x509.KeyUsageCertSign==0||issuer.NotBefore.After(now)||!issuer.NotAfter.After(now)||certificates[index].CheckSignatureFrom(issuer)!=nil{return ErrInvalidCertificate}}
	intermediates:=x509.NewCertPool();for _,certificate:=range certificates[1:]{intermediates.AddCert(certificate)};verifyName:=expected[0];if strings.HasPrefix(verifyName,"*."){verifyName="acme-validation."+strings.TrimPrefix(verifyName,"*.")};if _,verifyErr:=leaf.Verify(x509.VerifyOptions{DNSName:verifyName,Intermediates:intermediates,CurrentTime:now,KeyUsages:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}});verifyErr!=nil{return ErrInvalidCertificate}
	if policy.MustStaple&&!certificateMustStaple(leaf){return ErrInvalidCertificate}
	sum:=sha256.Sum256(leaf.Raw);if material.FingerprintSHA256!=hex.EncodeToString(sum[:])||material.ID!=CertificateID("cert_"+hex.EncodeToString(sum[:])[:48])||!strings.EqualFold(material.Serial,leaf.SerialNumber.Text(16))||!material.NotBefore.Equal(leaf.NotBefore.UTC())||!material.NotAfter.Equal(leaf.NotAfter.UTC())||material.Issuer!=leaf.Issuer.String(){return ErrInvalidCertificate}
	if canonical:=canonicalCertificateNames(material.Names);len(canonical)!=len(actual){return ErrInvalidCertificate}else{for index:=range actual{if canonical[index]!=actual[index]{return ErrInvalidCertificate}}}
	if validator.Keys!=nil{signer,resolveErr:=validator.Keys.PrivateKey(ctx,material.PrivateKeyRef,policy);if resolveErr!=nil{return resolveErr};publicDER,marshalErr:=x509.MarshalPKIXPublicKey(signer.Public());if marshalErr!=nil{return ErrInvalidCertificate};leafDER,marshalErr:=x509.MarshalPKIXPublicKey(leaf.PublicKey);if marshalErr!=nil||!bytes.Equal(publicDER,leafDER){return ErrInvalidCertificate}}
	return nil
}

func oneCertificate(content []byte)(*x509.Certificate,[]byte,error){block,rest:=pem.Decode(content);if block==nil||block.Type!="CERTIFICATE"||len(block.Headers)!=0||len(bytes.TrimSpace(rest))!=0{return nil,nil,ErrInvalidCertificate};certificate,err:=x509.ParseCertificate(block.Bytes);if err!=nil{return nil,nil,ErrInvalidCertificate};return certificate,pem.EncodeToMemory(block),nil}
func certificateChain(content []byte)([]*x509.Certificate,[][]byte,error){if len(bytes.TrimSpace(content))==0{return nil,nil,nil};certificates:=[]*x509.Certificate{};encoded:=[][]byte{};rest:=content;for len(bytes.TrimSpace(rest))>0{block,next:=pem.Decode(rest);if block==nil||block.Type!="CERTIFICATE"||len(block.Headers)!=0{return nil,nil,ErrInvalidCertificate};certificate,err:=x509.ParseCertificate(block.Bytes);if err!=nil{return nil,nil,ErrInvalidCertificate};certificates=append(certificates,certificate);encoded=append(encoded,pem.EncodeToMemory(block));rest=next};return certificates,encoded,nil}
func canonicalCertificateNames(values []string)[]string{result:=make([]string,len(values));for index,value:=range values{result[index]=strings.ToLower(strings.TrimSuffix(value,"."))};sort.Strings(result);return result}
func certificateMustStaple(certificate *x509.Certificate)bool{oid:=asn1.ObjectIdentifier{1,3,6,1,5,5,7,1,24};for _,extension:=range certificate.Extensions{if !extension.Id.Equal(oid){continue};var features []int;rest,err:=asn1.Unmarshal(extension.Value,&features);if err!=nil||len(rest)!=0{return false};for _,feature:=range features{if feature==5{return true}}};return false}

var _ MaterialValidator = X509MaterialValidator{}
