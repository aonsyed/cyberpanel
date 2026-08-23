//go:build linux

package certificates

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// LinuxClientRuntime contains only panel-core-side clients. Root filesystem
// mutation and service reloads remain behind CertificateBrokerClient.
type LinuxClientRuntime struct {
	Secrets *SecretMaterialRuntime
	ACME *HTTPACMEClient
	Validator X509MaterialValidator
	HTTP01 *CertificateBrokerClient
	DNS01 *PowerDNSDNS01Presenter
	DeploymentTarget *CertificateBrokerClient
}

func NewLocalLinuxClientRuntime(httpClient *http.Client,releaseDigest string,staging bool,dnsAuthority DNSChallengeAuthority)(*LinuxClientRuntime,error){
	if httpClient==nil{httpClient=DefaultACMEHTTPClient()}
	secretRuntime,err:=NewLocalSecretMaterialRuntime(releaseDigest);if err!=nil{return nil,err}
	acme,err:=NewHTTPACMEClient(httpClient,secretRuntime,staging);if err!=nil{return nil,err}
	broker,err:=NewLocalCertificateBrokerClient(secretRuntime);if err!=nil{return nil,err}
	dnsPresenter,err:=NewPowerDNSDNS01Presenter(dnsAuthority);if err!=nil{return nil,err}
	return &LinuxClientRuntime{Secrets:secretRuntime,ACME:acme,Validator:X509MaterialValidator{Keys:secretRuntime},HTTP01:broker,DNS01:dnsPresenter,DeploymentTarget:broker},nil
}

func NewLocalLinuxClientRuntimeForCurrentExecutable(httpClient *http.Client,staging bool,dnsAuthority DNSChallengeAuthority)(*LinuxClientRuntime,error){digest,err:=CurrentExecutableDigest();if err!=nil{return nil,err};return NewLocalLinuxClientRuntime(httpClient,digest,staging,dnsAuthority)}
func CurrentExecutableDigest()(string,error){file,err:=os.Open("/proc/self/exe");if err!=nil{return "",err};defer file.Close();hash:=sha256.New();copied,err:=io.Copy(hash,io.LimitReader(file,1<<30));if err!=nil||copied<=0||copied>=1<<30{return "",ErrInvalidCertificate};return hex.EncodeToString(hash.Sum(nil)),nil}
func DefaultACMEHTTPClient()*http.Client{dialer:=&net.Dialer{Timeout:15*time.Second,KeepAlive:30*time.Second};transport:=&http.Transport{Proxy:nil,DialContext:dialer.DialContext,ForceAttemptHTTP2:true,MaxIdleConns:8,MaxIdleConnsPerHost:4,IdleConnTimeout:30*time.Second,TLSHandshakeTimeout:15*time.Second,ResponseHeaderTimeout:30*time.Second,ExpectContinueTimeout:time.Second,TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12}};return &http.Client{Transport:transport,Timeout:90*time.Second}}

func(runtime *LinuxClientRuntime)Issuance(store IssuanceStore)*IssuanceCoordinator{if runtime==nil{return nil};return &IssuanceCoordinator{Store:store,ACME:runtime.ACME,Signer:runtime.Secrets,Validator:runtime.Validator,HTTP:runtime.HTTP01,DNS:runtime.DNS01}}
func(runtime *LinuxClientRuntime)Deployment(store Repository)*DeploymentCoordinator{if runtime==nil{return nil};return &DeploymentCoordinator{Store:store,Target:runtime.DeploymentTarget}}
