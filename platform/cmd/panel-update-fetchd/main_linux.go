//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/productupdate"
)

const (
	feedConfigPath = "/etc/cyberpanel/product-update/feed.json"
	feedSpoolRoot = "/var/lib/cyberpanel/product-update-spool"
	feedSlotRoot = "/opt/cyberpanel/slots"
)

type feedPolicyDocument struct {
	Version uint16 `json:"version"`
	IndexURL string `json:"index_url"`
	CABundlePEM string `json:"ca_bundle_pem"`
	SPKISHA256 []string `json:"spki_sha256"`
	IntervalSeconds int64 `json:"interval_seconds"`
	RequestTimeoutSeconds int64 `json:"request_timeout_seconds"`
	MaximumIndexBytes int64 `json:"maximum_index_bytes"`
	MaximumManifestBytes int64 `json:"maximum_manifest_bytes"`
	MaximumArtifactBytes int64 `json:"maximum_artifact_bytes"`
	MaximumTotalBytes int64 `json:"maximum_total_bytes"`
}

type feedRuntime struct {
	policy feedPolicyDocument
	index *url.URL
	client *http.Client
}

func main(){
	log.SetFlags(0)
	if os.Geteuid()==0||len(os.Args)!=1{log.Fatal("panel-update-fetchd must run unprivileged without arguments")}
	runtime,err:=newFeedRuntime();if err!=nil{log.Fatalf("initialize update feed: %v",err)}
	ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM);defer cancel()
	for{if err=runtime.runOnce(ctx);err!=nil&&ctx.Err()==nil{log.Printf("update feed cycle failed: %v",err)};timer:=time.NewTimer(time.Duration(runtime.policy.IntervalSeconds)*time.Second);select{case <-ctx.Done():timer.Stop();return;case <-timer.C:}}
}

func newFeedRuntime()(*feedRuntime,error){
	document,roots,pins,index,err:=loadFeedPolicy();if err!=nil{return nil,err}
	runtime:=&feedRuntime{policy:document,index:index}
	tlsConfig:=&tls.Config{MinVersion:tls.VersionTLS12,RootCAs:roots,ServerName:index.Hostname(),Renegotiation:tls.RenegotiateNever}
	tlsConfig.VerifyConnection=func(state tls.ConnectionState)error{if len(state.PeerCertificates)==0{return errors.New("missing feed certificate")};digest:=sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo);if _,ok:=pins[hex.EncodeToString(digest[:])];!ok{return errors.New("feed SPKI pin mismatch")};return nil}
	transport:=&http.Transport{Proxy:nil,DialContext:runtime.dialContext,ForceAttemptHTTP2:true,DisableCompression:true,TLSClientConfig:tlsConfig,TLSHandshakeTimeout:15*time.Second,ResponseHeaderTimeout:time.Duration(document.RequestTimeoutSeconds)*time.Second,IdleConnTimeout:30*time.Second,MaxIdleConns:2,MaxIdleConnsPerHost:2,MaxConnsPerHost:2,MaxResponseHeaderBytes:64<<10}
	runtime.client=&http.Client{Transport:transport,Timeout:time.Duration(document.RequestTimeoutSeconds)*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return errors.New("feed redirects disabled")}}
	return runtime,nil
}

func loadFeedPolicy()(feedPolicyDocument,*x509.CertPool,map[string]struct{},*url.URL,error){
	var empty feedPolicyDocument
	info,err:=os.Lstat(feedConfigPath);if err!=nil||info.Mode()&os.ModeSymlink==0{return empty,nil,nil,nil,errors.New("feed policy is not a managed link")}
	target,err:=filepath.EvalSymlinks(feedConfigPath);if err!=nil||!strings.HasPrefix(target,feedSlotRoot+string(os.PathSeparator)){return empty,nil,nil,nil,errors.New("feed policy is outside immutable slots")}
	targetInfo,err:=os.Lstat(target);if err!=nil{return empty,nil,nil,nil,err};metadata,ok:=targetInfo.Sys().(*syscall.Stat_t)
	if !ok||metadata.Uid!=0||int(metadata.Gid)!=os.Getegid()||metadata.Nlink!=1||!targetInfo.Mode().IsRegular()||targetInfo.Mode()&os.ModeSymlink!=0||targetInfo.Mode().Perm()!=0640||targetInfo.Size()<=0||targetInfo.Size()>1<<20{return empty,nil,nil,nil,errors.New("invalid feed policy ownership")}
	file,err:=os.OpenFile(target,os.O_RDONLY|syscall.O_NOFOLLOW,0);if err!=nil{return empty,nil,nil,nil,err};raw,readErr:=io.ReadAll(io.LimitReader(file,1<<20+1));closeErr:=file.Close();if readErr!=nil||closeErr!=nil{return empty,nil,nil,nil,errors.Join(readErr,closeErr)}
	decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();var document feedPolicyDocument;if decoder.Decode(&document)!=nil||decoder.Decode(&struct{}{})!=io.EOF{return empty,nil,nil,nil,errors.New("invalid feed policy JSON")}
	index,err:=url.Parse(document.IndexURL);if err!=nil||index.Scheme!="https"||index.User!=nil||index.Hostname()==""||(index.Port()!=""&&index.Port()!="443")||index.RawPath!=""||index.RawQuery!=""||index.Fragment!=""||path.Clean(index.Path)!=index.Path||!strings.HasSuffix(index.Path,"/index.json"){return empty,nil,nil,nil,errors.New("invalid fixed feed URL")}
	if document.Version!=1||document.IntervalSeconds<60||document.IntervalSeconds>86400||document.RequestTimeoutSeconds<10||document.RequestTimeoutSeconds>1800||document.MaximumIndexBytes<=0||document.MaximumIndexBytes>1<<20||document.MaximumManifestBytes<=0||document.MaximumManifestBytes>16<<20||document.MaximumArtifactBytes<=0||document.MaximumArtifactBytes>4<<30||document.MaximumTotalBytes<document.MaximumArtifactBytes||document.MaximumTotalBytes>16<<30||len(document.SPKISHA256)==0||len(document.SPKISHA256)>8{return empty,nil,nil,nil,errors.New("invalid feed bounds")}
	roots,err:=parseFeedCAs([]byte(document.CABundlePEM),time.Now().UTC());if err!=nil{return empty,nil,nil,nil,err};pins:=map[string]struct{}{}
	for _,encoded:=range document.SPKISHA256{decoded,decodeErr:=decodeFeedDigest(encoded);if decodeErr!=nil{return empty,nil,nil,nil,decodeErr};value:=hex.EncodeToString(decoded);if _,exists:=pins[value];exists{return empty,nil,nil,nil,errors.New("duplicate feed SPKI pin")};pins[value]=struct{}{}}
	return document,roots,pins,index,nil
}

func parseFeedCAs(content []byte,now time.Time)(*x509.CertPool,error){
	if len(content)==0||len(content)>1<<20{return nil,errors.New("invalid feed CA bundle")};pool:=x509.NewCertPool();count:=0
	for len(bytes.TrimSpace(content))!=0{block,rest:=pem.Decode(content);if block==nil||block.Type!="CERTIFICATE"||len(block.Headers)!=0||len(rest)>=len(content)||count==16{return nil,errors.New("invalid feed CA bundle")};certificate,err:=x509.ParseCertificate(block.Bytes);if err!=nil||!certificate.IsCA||!certificate.BasicConstraintsValid||certificate.KeyUsage&x509.KeyUsageCertSign==0||now.Before(certificate.NotBefore)||!now.Before(certificate.NotAfter){return nil,errors.New("invalid feed CA certificate")};pool.AddCert(certificate);content=rest;count++}
	if count==0{return nil,errors.New("empty feed CA bundle")};return pool,nil
}

func decodeFeedDigest(value string)([]byte,error){value=strings.TrimSpace(value);for _,encoding:=range []*base64.Encoding{base64.RawURLEncoding,base64.URLEncoding,base64.RawStdEncoding,base64.StdEncoding}{if decoded,err:=encoding.DecodeString(value);err==nil&&len(decoded)==sha256.Size{return decoded,nil}};decoded,err:=hex.DecodeString(value);if err!=nil||len(decoded)!=sha256.Size{return nil,errors.New("invalid feed SPKI digest")};return decoded,nil}

func (runtime *feedRuntime)dialContext(ctx context.Context,network,address string)(net.Conn,error){
	host,port,err:=net.SplitHostPort(address);if err!=nil||host!=runtime.index.Hostname()||(port!="443"&&port!=runtime.index.Port()){return nil,errors.New("feed dial target rejected")}
	addresses,err:=net.DefaultResolver.LookupIPAddr(ctx,host);if err!=nil{return nil,err};dialer:=net.Dialer{Timeout:15*time.Second,KeepAlive:30*time.Second}
	for _,candidate:=range addresses{if !publicFeedAddress(candidate.IP){continue};connection,dialErr:=dialer.DialContext(ctx,network,net.JoinHostPort(candidate.IP.String(),port));if dialErr==nil{return connection,nil}}
	return nil,errors.New("feed host has no public address")
}

var nonPublicFeedPrefixes=[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"),netip.MustParsePrefix("100.64.0.0/10"),netip.MustParsePrefix("127.0.0.0/8"),netip.MustParsePrefix("169.254.0.0/16"),netip.MustParsePrefix("192.0.0.0/24"),netip.MustParsePrefix("192.0.2.0/24"),netip.MustParsePrefix("198.18.0.0/15"),netip.MustParsePrefix("198.51.100.0/24"),netip.MustParsePrefix("203.0.113.0/24"),netip.MustParsePrefix("224.0.0.0/4"),netip.MustParsePrefix("240.0.0.0/4"),netip.MustParsePrefix("2001:2::/48"),netip.MustParsePrefix("2001:db8::/32")}
func publicFeedAddress(ip net.IP)bool{address,ok:=netip.AddrFromSlice(ip);if !ok{return false};address=address.Unmap();if !address.IsGlobalUnicast()||address.IsPrivate()||address.IsLoopback()||address.IsLinkLocalUnicast()||address.IsLinkLocalMulticast()||address.IsMulticast()||address.IsUnspecified(){return false};for _,prefix:=range nonPublicFeedPrefixes{if prefix.Contains(address){return false}};return true}

func (runtime *feedRuntime)runOnce(ctx context.Context)error{
	if err:=verifyFeedSpoolDirectories();err!=nil{return err};if err:=cleanupFeedPartials();err!=nil{return err};if err:=runtime.importReady(ctx);err!=nil{return err}
	indexRaw,err:=runtime.fetchBytes(ctx,runtime.index,runtime.policy.MaximumIndexBytes);if err!=nil{return err};var index operations.ProductUpdateFeedIndex
	if decodeFeedJSON(indexRaw,&index)!=nil{return errors.New("invalid channel index")};index,err=operations.CanonicalProductUpdateFeedIndex(index,time.Now().UTC());if err!=nil{return err};if lastFeedIndex()==index.Digest{return nil}
	claim,err:=runtime.fetchRelease(ctx,index,indexRaw);if err!=nil{return err};return runtime.importClaim(ctx,claim)
}

func (runtime *feedRuntime)importReady(ctx context.Context)error{
	root:=filepath.Join(feedSpoolRoot,"ready");entries,err:=os.ReadDir(root);if err!=nil{return err};if len(entries)>8{return errors.New("feed spool generation bound exceeded")};sort.Slice(entries,func(i,j int)bool{return entries[i].Name()<entries[j].Name()})
	for _,entry:=range entries{name:=entry.Name();if !entry.IsDir()||len(name)!=69||!strings.HasPrefix(name,"feed-"){return errors.New("invalid feed spool entry")};digest:=strings.TrimPrefix(name,"feed-");if _,err=hex.DecodeString(digest);err!=nil{return errors.New("invalid feed spool digest")};if err=runtime.importClaim(ctx,operations.ProductUpdateFeedImport{Version:1,SpoolID:name,IndexDigest:digest});err!=nil{return err}}
	return nil
}

func (runtime *feedRuntime)importClaim(ctx context.Context,claim operations.ProductUpdateFeedImport)error{
	client,err:=operations.NewLocalProductUpdateClient();if err!=nil{return err};importContext,cancel:=context.WithTimeout(ctx,30*time.Minute);defer cancel();receipt,err:=client.ImportFeed(importContext,claim);if err!=nil{return err};if receipt.IndexDigest!=claim.IndexDigest{return errors.New("updater import receipt mismatch")}
	if err=removeFeedSpool(claim.SpoolID);err!=nil{return err};return writeLastFeedIndex(claim.IndexDigest)
}

func (runtime *feedRuntime)fetchRelease(ctx context.Context,index operations.ProductUpdateFeedIndex,indexRaw []byte)(operations.ProductUpdateFeedImport,error){
	manifestURL:=runtime.childURL("manifests",index.Manifest.ID+".json");manifestRaw,err:=runtime.fetchBytes(ctx,manifestURL,runtime.policy.MaximumManifestBytes);if err!=nil{return operations.ProductUpdateFeedImport{},err}
	if int64(len(manifestRaw))!=index.Manifest.Size||digestBytes(manifestRaw)!=index.Manifest.SHA256{return operations.ProductUpdateFeedImport{},errors.New("manifest transport digest mismatch")}
	var manifest productupdate.ReleaseManifest;if decodeFeedJSON(manifestRaw,&manifest)!=nil{return operations.ProductUpdateFeedImport{},errors.New("invalid release manifest")};manifest,err=productupdate.CanonicalManifest(manifest);if err!=nil{return operations.ProductUpdateFeedImport{},err}
	if manifest.ID!=index.Manifest.ID||manifest.Sequence!=index.Manifest.Sequence||manifest.Digest!=index.Manifest.Digest||manifest.Platform!=index.Platform||len(manifest.Artifacts)!=len(index.Manifest.Artifacts){return operations.ProductUpdateFeedImport{},errors.New("index manifest mismatch")}
	var total int64;for position,artifact:=range manifest.Artifacts{reference:=index.Manifest.Artifacts[position];if artifact.ID!=reference.ID||artifact.Digest!=reference.Digest||artifact.Size!=reference.Size||artifact.Size>runtime.policy.MaximumArtifactBytes||total>runtime.policy.MaximumTotalBytes-artifact.Size{return operations.ProductUpdateFeedImport{},errors.New("index artifact mismatch")};total+=artifact.Size}
	temporary,err:=os.MkdirTemp(feedSpoolRoot,".fetch-");if err!=nil{return operations.ProductUpdateFeedImport{},err};complete:=false;defer func(){if !complete{_ = os.RemoveAll(temporary)}}()
	artifactRoot:=filepath.Join(temporary,"artifacts");if err=os.Mkdir(artifactRoot,0700);err!=nil{return operations.ProductUpdateFeedImport{},err};if err=writeFeedFile(filepath.Join(temporary,"index.json"),indexRaw);err!=nil{return operations.ProductUpdateFeedImport{},err};if err=writeFeedFile(filepath.Join(temporary,"manifest.json"),manifestRaw);err!=nil{return operations.ProductUpdateFeedImport{},err}
	for _,artifact:=range manifest.Artifacts{if err=runtime.fetchArtifact(ctx,runtime.childURL("artifacts",artifact.Digest+".tar"),filepath.Join(artifactRoot,artifact.Digest+".tar"),artifact.Size,artifact.Digest);err!=nil{return operations.ProductUpdateFeedImport{},err}}
	if err=syncFeedDirectory(artifactRoot);err!=nil{return operations.ProductUpdateFeedImport{},err};if err=syncFeedDirectory(temporary);err!=nil{return operations.ProductUpdateFeedImport{},err}
	spoolID:="feed-"+index.Digest;destination:=filepath.Join(feedSpoolRoot,"ready",spoolID);if err=os.Rename(temporary,destination);err!=nil{if _,statErr:=os.Lstat(destination);statErr==nil{complete=true;_ = os.RemoveAll(temporary);return operations.ProductUpdateFeedImport{Version:1,SpoolID:spoolID,IndexDigest:index.Digest},nil};return operations.ProductUpdateFeedImport{},err};complete=true;if err=syncFeedDirectory(filepath.Dir(destination));err!=nil{return operations.ProductUpdateFeedImport{},err}
	return operations.ProductUpdateFeedImport{Version:1,SpoolID:spoolID,IndexDigest:index.Digest},nil
}

func (runtime *feedRuntime)childURL(directory,name string)*url.URL{child:=*runtime.index;child.Path=path.Join(path.Dir(runtime.index.Path),directory,name);child.RawPath="";return &child}

func (runtime *feedRuntime)fetchBytes(ctx context.Context,target *url.URL,maximum int64)([]byte,error){response,err:=runtime.get(ctx,target);if err!=nil{return nil,err};defer response.Body.Close();if response.ContentLength>maximum{return nil,errors.New("feed response too large")};raw,err:=io.ReadAll(io.LimitReader(response.Body,maximum+1));if err!=nil||int64(len(raw))>maximum{return nil,errors.New("feed response bound exceeded")};return raw,nil}

func (runtime *feedRuntime)fetchArtifact(ctx context.Context,target *url.URL,destination string,size int64,digest string)error{
	response,err:=runtime.get(ctx,target);if err!=nil{return err};defer response.Body.Close();if response.ContentLength>=0&&response.ContentLength!=size{return errors.New("artifact content length mismatch")}
	file,err:=os.OpenFile(destination,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,0400);if err!=nil{return err};hasher:=sha256.New();written,copyErr:=io.Copy(io.MultiWriter(file,hasher),io.LimitReader(response.Body,size+1));joined:=errors.Join(copyErr,file.Sync(),file.Chmod(0400),file.Close());if joined!=nil||written!=size||hex.EncodeToString(hasher.Sum(nil))!=digest{_ = os.Remove(destination);return errors.Join(joined,errors.New("artifact digest mismatch"))};return nil
}

func (runtime *feedRuntime)get(ctx context.Context,target *url.URL)(*http.Response,error){if target.Scheme!="https"||target.Host!=runtime.index.Host{return nil,errors.New("feed origin changed")};request,err:=http.NewRequestWithContext(ctx,http.MethodGet,target.String(),nil);if err!=nil{return nil,err};request.Header.Set("Accept","application/octet-stream, application/json");request.Header.Set("User-Agent","CyberPanel-Update-Fetch/1");response,err:=runtime.client.Do(request);if err!=nil{return nil,err};if response.StatusCode!=http.StatusOK{_ = response.Body.Close();return nil,fmt.Errorf("feed HTTP status %d",response.StatusCode)};return response,nil}

func decodeFeedJSON(raw []byte,target any)error{decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil{return err};if decoder.Decode(&struct{}{})!=io.EOF{return errors.New("trailing feed JSON")};return nil}
func digestBytes(content []byte)string{sum:=sha256.Sum256(content);return hex.EncodeToString(sum[:])}

func verifyFeedSpoolDirectories()error{for _,directory:=range []string{feedSpoolRoot,filepath.Join(feedSpoolRoot,"ready")}{info,err:=os.Lstat(directory);if err!=nil{return err};metadata,ok:=info.Sys().(*syscall.Stat_t);if !ok||int(metadata.Uid)!=os.Geteuid()||int(metadata.Gid)!=os.Getegid()||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=0700{return errors.New("invalid feed spool ownership")};resolved,err:=filepath.EvalSymlinks(directory);if err!=nil||resolved!=directory{return errors.New("invalid feed spool path")}};return nil}
func cleanupFeedPartials()error{entries,err:=os.ReadDir(feedSpoolRoot);if err!=nil{return err};changed:=false;for _,entry:=range entries{if !strings.HasPrefix(entry.Name(),".fetch-"){continue};target:=filepath.Join(feedSpoolRoot,entry.Name());info,statErr:=os.Lstat(target);if statErr!=nil{return statErr};metadata,ok:=info.Sys().(*syscall.Stat_t);if !ok||int(metadata.Uid)!=os.Geteuid()||!info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("invalid partial feed spool")};if err=os.RemoveAll(target);err!=nil{return err};changed=true};if changed{return syncFeedDirectory(feedSpoolRoot)};return nil}
func writeFeedFile(name string,content []byte)error{file,err:=os.OpenFile(name,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,0400);if err!=nil{return err};_,writeErr:=file.Write(content);return errors.Join(writeErr,file.Sync(),file.Chmod(0400),file.Close())}
func syncFeedDirectory(name string)error{directory,err:=os.Open(name);if err!=nil{return err};return errors.Join(directory.Sync(),directory.Close())}
func lastFeedIndex()string{content,err:=os.ReadFile(filepath.Join(feedSpoolRoot,"accepted-index"));if err!=nil{return ""};value:=strings.TrimSpace(string(content));if len(value)!=64{return ""};if _,err=hex.DecodeString(value);err!=nil{return ""};return value}
func writeLastFeedIndex(digest string)error{temporary:=filepath.Join(feedSpoolRoot,"accepted-index.new");_ = os.Remove(temporary);if err:=writeFeedFile(temporary,[]byte(digest+"\n"));err!=nil{return err};if err:=os.Rename(temporary,filepath.Join(feedSpoolRoot,"accepted-index"));err!=nil{return err};return syncFeedDirectory(feedSpoolRoot)}
func removeFeedSpool(spoolID string)error{target:=filepath.Join(feedSpoolRoot,"ready",spoolID);if filepath.Dir(target)!=filepath.Join(feedSpoolRoot,"ready"){return errors.New("invalid spool removal")};info,err:=os.Lstat(target);if err!=nil{return err};metadata,ok:=info.Sys().(*syscall.Stat_t);if !ok||int(metadata.Uid)!=os.Geteuid()||!info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("invalid spool removal")};return os.RemoveAll(target)}
