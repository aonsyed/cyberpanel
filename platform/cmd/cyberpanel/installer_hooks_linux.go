//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
)

const hookRoot = "/var/lib/cyberpanel/installer-hooks"
var hookToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var hookDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type hookInvocation struct { Verb,Release,Component,Hook,ReceiptDigest string }
type hookJournal struct {
	Version uint32 `json:"version"`
	Verb string `json:"verb"`
	Release string `json:"release"`
	Component string `json:"component"`
	ReceiptDigest string `json:"receipt_digest"`
	Response string `json:"response"`
	Changed []string `json:"changed"`
	State string `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func runInstallerHook(arguments []string) error {
	if os.Geteuid()!=0||os.Getenv("CYBERPANEL_INSTALLER")!="1" { return errors.New("installer hooks require the local root installer ceremony") }
	invocation,err:=parseHookInvocation(arguments);if err!=nil{return err}
	if err=ensureHookDirectory();err!=nil{return err}
	lock,err:=os.OpenFile(filepath.Join(hookRoot,"lock"),os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW,0600);if err!=nil{return err};defer lock.Close()
	if err=syscall.Flock(int(lock.Fd()),syscall.LOCK_EX);err!=nil{return err};defer syscall.Flock(int(lock.Fd()),syscall.LOCK_UN)
	if invocation.Verb=="rollback" { return rollbackInstallerHook(invocation) }
	indexPath:=filepath.Join(hookRoot,"by-hook",invocation.Verb+"-"+invocation.Release+"-"+invocation.Component+".json")
	// Reconcile live authority even when this release already has a receipt.
	// A receipt cannot prove the broker still holds the matching signing key.
	if invocation.Verb=="reconcile-services" { if err=reconcileWebEngineAuthority();err!=nil{return err};if err=reconcileDNSAuthority();err!=nil{return err};if err=reconcileMailAuthority();err!=nil{return err};if _,err=reconcileMalwareApprovalTrust();err!=nil{return err} }
	var containerPolicyPath string
	if invocation.Verb=="initialize-authority"||invocation.Verb=="migrate-authority" { if err=validatePackagedContainerRecipes();err!=nil{return err};containerPolicyPath,err=containers.ProvisionRootlessContainerPolicy(context.Background());if err!=nil{return err} }
	if existing,loadErr:=readHookJournal(indexPath);loadErr==nil { if invocation.Verb=="initialize-authority"||invocation.Verb=="migrate-authority"{manifest,validateErr:=apps.ValidateLinuxApplicationCatalog(context.Background(),"",time.Now().UTC());if validateErr!=nil||manifest.ReleaseID!=invocation.Release{return errors.Join(errors.New("application catalog no longer matches installer receipt"),validateErr)}};_,err=io.WriteString(os.Stdout,existing.Response);return err } else if !errors.Is(loadErr,os.ErrNotExist){return loadErr}
	changed,err:=applyHook(invocation);if err!=nil{return err}
	if containerPolicyPath!="" { changed=append(changed,containerPolicyPath) }
	responseValue:=struct{Version uint32 `json:"version"`;Hook,Release,Component,State string}{1,invocation.Verb,invocation.Release,invocation.Component,"applied"}
	response,err:=json.Marshal(responseValue);if err!=nil{return err};response=append(response,'\n');sum:=sha256.Sum256(response);receiptDigest:=hex.EncodeToString(sum[:])
	now:=time.Now().UTC();journal:=hookJournal{Version:1,Verb:invocation.Verb,Release:invocation.Release,Component:invocation.Component,ReceiptDigest:receiptDigest,Response:string(response),Changed:changed,State:"applied",CreatedAt:now,UpdatedAt:now}
	if err=writeHookJournal(filepath.Join(hookRoot,"receipts",receiptDigest+".json"),journal);err!=nil{return err}
	if err=writeHookJournal(indexPath,journal);err!=nil{return err}
	_,err=os.Stdout.Write(response);return err
}

func parseHookInvocation(arguments []string)(hookInvocation,error){
	var result hookInvocation;if len(arguments)==0{return result,errors.New("missing installer hook")};result.Verb=arguments[0]
	allowed:=map[string]bool{"initialize-authority":true,"migrate-authority":true,"bootstrap-secrets":true,"bootstrap-authn":true,"bootstrap-database":true,"bootstrap-dns":true,"bootstrap-mail":true,"reconcile-services":true,"rollback":true};if !allowed[result.Verb]{return result,errors.New("unsupported installer hook")}
	values:=map[string]string{};for index:=1;index<len(arguments);index+=2{if index+1>=len(arguments){return result,errors.New("incomplete installer hook argument")};name:=arguments[index];if name!="--release"&&name!="--component"&&name!="--hook"&&name!="--receipt-digest"{return result,errors.New("unknown installer hook argument")};if values[name]!=""{return result,errors.New("duplicate installer hook argument")};values[name]=arguments[index+1]}
	result.Release,result.Component,result.Hook,result.ReceiptDigest=values["--release"],values["--component"],values["--hook"],values["--receipt-digest"]
	if !hookToken.MatchString(result.Release){return result,errors.New("invalid installer release")}
	if result.Verb=="rollback"{if !hookToken.MatchString(result.Hook)||!hookDigest.MatchString(result.ReceiptDigest)||result.Component!=""{return result,errors.New("invalid rollback hook")};return result,nil}
	if !hookToken.MatchString(result.Component)||result.Hook!=""||result.ReceiptDigest!=""{return result,errors.New("invalid installer hook scope")};return result,nil
}

func applyHook(invocation hookInvocation)([]string,error){
	switch invocation.Verb {
	case "initialize-authority":changed,err:=initializeAuthority();if err!=nil{return nil,err};catalog,err:=provisionApplicationCatalog(invocation.Release);return append(changed,catalog...),err
	case "migrate-authority":changed,err:=migrateAuthority();if err!=nil{return nil,err};catalog,err:=provisionApplicationCatalog(invocation.Release);return append(changed,catalog...),err
	case "bootstrap-secrets":return bootstrapSecrets()
	case "bootstrap-authn":return bootstrapAuthn()
	case "bootstrap-database":return bootstrapDatabaseAuthority()
	case "bootstrap-dns":return bootstrapDNSAuthority()
	case "bootstrap-mail":return bootstrapMailAuthority()
	case "reconcile-services":return reconcileServiceAuthority()
	default:return nil,errors.New("unsupported installer hook")
	}
}

func provisionApplicationCatalog(releaseID string)([]string,error){
	if err:=validatePackagedContainerRecipes();err!=nil{return nil,err}
	executable,err:=os.Executable();if err!=nil{return nil,err};executable,err=filepath.EvalSymlinks(executable);if err!=nil{return nil,err}
	source:=filepath.Join(filepath.Dir(executable),"application-catalog")
	receipt,err:=apps.ProvisionLinuxApplicationCatalog(context.Background(),apps.LinuxApplicationCatalogProvisionRequest{SourceRoot:source,DestinationRoot:apps.DefaultApplicationCatalogRoot,ReleaseID:releaseID});if err!=nil{return nil,err}
	return []string{receipt.CandidateGeneration,receipt.RollbackManifest,apps.DefaultApplicationCatalogRoot},nil
}

func validatePackagedContainerRecipes() error {
	verifier, err := containers.LoadDefaultLinuxRecipeVerifier()
	if err != nil { return err }
	n8nRecipe, err := containers.ReadPackagedN8NRecipe(context.Background(), verifier)
	if err != nil { return err }
	if err = integrations.ValidateN8NApplicationRecipe(n8nRecipe); err != nil { return err }
	hermesRecipe, err := containers.ReadPackagedHermesRecipe(context.Background(), verifier)
	if err != nil { return err }
	return integrations.ValidateHermesApplicationRecipe(hermesRecipe)
}

func initializeAuthority()([]string,error){
	uid,gid,err:=lookupIdentity("cyberpanel");if err!=nil{return nil,err};paths:=[]string{"/var/lib/cyberpanel/control","/var/lib/cyberpanel/control/runtime","/var/lib/cyberpanel/control/trust","/var/lib/cyberpanel/control/recovery","/var/lib/cyberpanel/audit","/var/lib/cyberpanel/audit/segments","/var/lib/cyberpanel/audit/emergency","/var/lib/cyberpanel/backup-spool","/var/lib/cyberpanel/migration","/var/lib/cyberpanel/migration/chunks"}
	backupRoot,repositoryRoot:="/var/backups/cyberpanel","/var/backups/cyberpanel/repositories"
	if err=ensureOwnedDirectory(backupRoot,0750,0,gid);err!=nil{return nil,err}
	if err=ensureOwnedDirectory(repositoryRoot,0700,uid,gid);err!=nil{return nil,err}
	for _,path:=range paths{if err=ensureOwnedDirectory(path,0700,uid,gid);err!=nil{return nil,err}}
	databasePath:="/var/lib/cyberpanel/control/control.db";created,err:=ensureOwnedFile(databasePath,0600,uid,gid,nil);if err!=nil{return nil,err}
	changed:=append([]string{backupRoot,repositoryRoot},paths...);if created{changed=append(changed,databasePath)}
	claimPath:="/var/lib/cyberpanel/control/recovery/claim.token";if _,statErr:=os.Lstat(claimPath);errors.Is(statErr,os.ErrNotExist){token:=make([]byte,32);if _,err=io.ReadFull(rand.Reader,token);err!=nil{return nil,err};encoded:=[]byte(base64.RawURLEncoding.EncodeToString(token)+"\n");wipeBytes(token);if _,err=ensureOwnedFile(claimPath,0600,uid,gid,encoded);err!=nil{return nil,err};changed=append(changed,claimPath)}else if statErr!=nil{return nil,statErr}
	return changed,nil
}

func migrateAuthority()([]string,error){
	uid,gid,err:=lookupIdentity("cyberpanel");if err!=nil{return nil,err};path:="/var/lib/cyberpanel/control/control.db";if _,err=ensureOwnedFile(path,0600,uid,gid,nil);err!=nil{return nil,err};return []string{path},nil
}

func bootstrapSecrets()([]string,error){
	uid,gid,err:=lookupIdentity("cyberpanel");if err!=nil{return nil,err}
	secretUID,secretGID,err:=lookupIdentity("cyberpanel-secrets");if err!=nil{return nil,err}
	trustRoot:="/var/lib/cyberpanel/control/trust";if err=ensureOwnedDirectory(trustRoot,0700,uid,gid);err!=nil{return nil,err}
	paths:=apiserver.TrustPaths{SignerPath:filepath.Join(trustRoot,"gateway-signer.json"),TrustPath:filepath.Join(trustRoot,"gateway-public.json")}
	if _,signerErr:=os.Lstat(paths.SignerPath);errors.Is(signerErr,os.ErrNotExist){if _,err=apiserver.RotateLocalTrust(paths,time.Now().UTC());err!=nil{return nil,err}}else if signerErr!=nil{return nil,signerErr}
	for _,path:=range []string{paths.SignerPath,paths.TrustPath}{if err=os.Chown(path,uid,gid);err!=nil{return nil,err}}
	secretRoot:="/etc/cyberpanel/secrets";if err=ensureOwnedDirectory(secretRoot,0700,0,0);err!=nil{return nil,err}
	malwarePaths,err:=bootstrapMalwareWorkerTrust(secretRoot);if err!=nil{return nil,err}
	auditKey:=filepath.Join(secretRoot,"audit-signing.key");if _,err=ensureRandomFile(auditKey,ed25519.PrivateKeySize,0600,0,0,func()([]byte,error){_,private,keyErr:=ed25519.GenerateKey(rand.Reader);return private,keyErr});err!=nil{return nil,err}
	webmailSessionKey:=filepath.Join(secretRoot,"webmail-session.key");if _,err=ensureRandomFile(webmailSessionKey,32,0600,0,0,nil);err!=nil{return nil,err}
	marketingUnsubscribeKey:=filepath.Join(secretRoot,"marketing-unsubscribe.key");if _,err=ensureRandomFile(marketingUnsubscribeKey,32,0600,0,0,nil);err!=nil{return nil,err}
	webmailMaster:=filepath.Join(secretRoot,"mail-webmail-master");if _,err=ensureRandomFile(webmailMaster,91,0400,0,0,func()([]byte,error){raw:=make([]byte,48);if _,readErr:=io.ReadFull(rand.Reader,raw);readErr!=nil{return nil,readErr};encoded:=base64.RawURLEncoding.EncodeToString(raw);wipeBytes(raw);return []byte("cyberpanel-webmail:{PLAIN}"+encoded+"\n"),nil});err!=nil{return nil,err}
	secretKey:=filepath.Join(secretRoot,"wrapping.key");if _,err=ensureRandomFile(secretKey,32,0400,secretUID,secretGID,nil);err!=nil{return nil,err}
	secretStateRoot:="/var/lib/cyberpanel-secrets";if err=ensureOwnedDirectory(secretStateRoot,0700,secretUID,secretGID);err!=nil{return nil,err}
	secretDatabase:=filepath.Join(secretStateRoot,"secrets.db");if _,err=ensureOwnedFile(secretDatabase,0600,secretUID,secretGID,nil);err!=nil{return nil,err}
	secretEpoch:=filepath.Join(secretStateRoot,"key-epoch");if _,err=ensureOwnedFile(secretEpoch,0400,secretUID,secretGID,[]byte("1\n"));err!=nil{return nil,err}
	authRoot:="/etc/cyberpanel/authn";if err=ensureOwnedDirectory(authRoot,0700,0,0);err!=nil{return nil,err}
	for _,path:=range []string{filepath.Join(authRoot,"wrapping.key"),filepath.Join(authRoot,"lookup.pepper")}{if _,err=ensureRandomFile(path,32,0400,0,0,nil);err!=nil{return nil,err}}
	defaultCertificatePaths,err:=bootstrapDefaultWebCertificate();if err!=nil{return nil,err}
	changed:=[]string{paths.SignerPath,paths.TrustPath,auditKey,webmailSessionKey,marketingUnsubscribeKey,webmailMaster,secretKey,secretDatabase,secretEpoch,filepath.Join(authRoot,"wrapping.key"),filepath.Join(authRoot,"lookup.pepper")}
	changed=append(changed,malwarePaths...)
	return append(changed,defaultCertificatePaths...),nil
}

func bootstrapMalwareWorkerTrust(secretRoot string)([]string,error){
	stateRoot,quarantineRoot:="/var/lib/cyberpanel/site-taskd-malware","/var/lib/cyberpanel/malware-quarantine"
	for _,path:=range []string{stateRoot,quarantineRoot}{if err:=ensureOwnedDirectory(path,0700,0,0);err!=nil{return nil,err}}
	trustRoot:="/etc/cyberpanel/trust";if err:=ensureOwnedDirectory(trustRoot,0755,0,0);err!=nil{return nil,err}
	privatePath,publicPath:=filepath.Join(secretRoot,"site-taskd-malware-signing.key"),filepath.Join(trustRoot,"site-taskd-malware.pub")
	if _,privateErr:=os.Lstat(privatePath);errors.Is(privateErr,os.ErrNotExist){if _,publicErr:=os.Lstat(publicPath);publicErr==nil{return nil,errors.New("malware worker public key exists without its signing key")}else if !errors.Is(publicErr,os.ErrNotExist){return nil,publicErr}}else if privateErr!=nil{return nil,privateErr}
	if _,err:=ensureRandomFile(privatePath,ed25519.PrivateKeySize,0400,0,0,func()([]byte,error){_,private,keyErr:=ed25519.GenerateKey(rand.Reader);return private,keyErr});err!=nil{return nil,err}
	private,err:=os.ReadFile(privatePath);if err!=nil{return nil,err};defer wipeBytes(private)
	if len(private)!=ed25519.PrivateKeySize{return nil,errors.New("malware worker signing key has invalid size")}
	public,ok:=ed25519.PrivateKey(private).Public().(ed25519.PublicKey);if !ok||len(public)!=ed25519.PublicKeySize{return nil,errors.New("malware worker signing key is invalid")}
	if _,err=ensureOwnedFile(publicPath,0444,0,0,public);err!=nil{return nil,err}
	installed,err:=os.ReadFile(publicPath);if err!=nil||!bytes.Equal(installed,public){return nil,errors.Join(errors.New("malware worker trust key does not match signing key"),err)}
	return []string{stateRoot,quarantineRoot,trustRoot,privatePath,publicPath},nil
}

// bootstrapDefaultWebCertificate creates the root-owned fallback identity
// referenced by the immutable web-engine configuration. Real site and panel
// names still receive their own ACME-managed certificates; this certificate
// exists only so a fresh OLS/LSE listener never starts with a dangling key
// reference before the first tenant certificate is deployed.
func bootstrapDefaultWebCertificate()([]string,error){
	return bootstrapDefaultCertificate("webengine","preview-default")
}

func bootstrapDefaultCertificate(consumer,slot string)([]string,error){
	root:="/var/lib/cyberpanel/certificates";generationParent:=filepath.Join(root,"generations",consumer,slot);consumerRoot:=filepath.Join(root,"consumers",consumer,slot);current:=filepath.Join(consumerRoot,"current")
	for _,directory:=range []struct{path string;mode os.FileMode}{{root,0711},{filepath.Join(root,"generations"),0711},{filepath.Join(root,"generations",consumer),0711},{generationParent,0711},{filepath.Join(root,"consumers"),0711},{filepath.Join(root,"consumers",consumer),0711},{consumerRoot,0750}}{if err:=ensureOwnedDirectory(directory.path,directory.mode,0,0);err!=nil{return nil,err}}
	if paths,found,err:=existingDefaultWebCertificate(current,generationParent);err!=nil{return nil,err}else if found{return paths,nil}
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{return nil,err}
	maximum:=new(big.Int).Lsh(big.NewInt(1),128);serial,err:=rand.Int(rand.Reader,maximum);if err!=nil||serial.Sign()==0{if err==nil{err=errors.New("zero certificate serial")};return nil,err}
	now:=time.Now().UTC();template:=x509.Certificate{SerialNumber:serial,Subject:pkix.Name{CommonName:"CyberPanel bootstrap fallback"},DNSNames:[]string{"cyberpanel.invalid"},NotBefore:now.Add(-5*time.Minute),NotAfter:now.AddDate(10,0,0),KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},BasicConstraintsValid:true}
	der,err:=x509.CreateCertificate(rand.Reader,&template,&template,&key.PublicKey,key);if err!=nil{return nil,err};certificatePEM:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der});keyDER,err:=x509.MarshalPKCS8PrivateKey(key);if err!=nil{return nil,err};privateKeyPEM:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:keyDER});if _,err=tls.X509KeyPair(certificatePEM,privateKeyPEM);err!=nil{return nil,err}
	digest:=sha256.Sum256(der);candidate:=filepath.Join(generationParent,"bootstrap-"+hex.EncodeToString(digest[:16]));if err=ensureOwnedDirectory(candidate,0750,0,0);err!=nil{return nil,err}
	files:=[]struct{name string;content []byte}{{"certificate.pem",certificatePEM},{"chain.pem",nil},{"fullchain.pem",certificatePEM},{"private.key",privateKeyPEM}};changed:=[]string{candidate};for _,item:=range files{path:=filepath.Join(candidate,item.name);if _,err=ensureOwnedFile(path,0440,0,0,item.content);err!=nil{return nil,err};changed=append(changed,path)}
	if err=installDefaultCertificateLink(current,candidate);err!=nil{return nil,err};changed=append(changed,current);return changed,nil
}

func existingDefaultWebCertificate(current,generationParent string)([]string,bool,error){
	info,err:=os.Lstat(current);if errors.Is(err,os.ErrNotExist){return nil,false,nil};if err!=nil{return nil,false,err};if info.Mode()&os.ModeSymlink==0{return nil,false,errors.New("default certificate current path is not a symlink")}
	target,err:=os.Readlink(current);if err!=nil{return nil,false,err};if !filepath.IsAbs(target){target=filepath.Join(filepath.Dir(current),target)};target=filepath.Clean(target);relative,err:=filepath.Rel(generationParent,target);if err!=nil||relative=="."||relative==".."||strings.HasPrefix(relative,".."+string(os.PathSeparator)){return nil,false,errors.New("default certificate target escaped its generation")}
	certificatePath:=filepath.Join(target,"fullchain.pem");keyPath:=filepath.Join(target,"private.key");certificatePEM,err:=readRootCertificateFile(certificatePath);if err!=nil{return nil,false,err};privateKeyPEM,err:=readRootCertificateFile(keyPath);if err!=nil{return nil,false,err};pair,err:=tls.X509KeyPair(certificatePEM,privateKeyPEM);if err!=nil||len(pair.Certificate)==0{return nil,false,errors.New("invalid default web certificate")};certificate,err:=x509.ParseCertificate(pair.Certificate[0]);if err!=nil||!time.Now().UTC().Before(certificate.NotAfter){return nil,false,errors.New("expired default web certificate")}
	return []string{target,certificatePath,keyPath,current},true,nil
}

func readRootCertificateFile(path string)([]byte,error){info,err:=os.Lstat(path);if err!=nil||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=0440||info.Size()<=0||info.Size()>1<<20{return nil,errors.New("unsafe default certificate material")};stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||stat.Uid!=0||stat.Gid!=0||stat.Nlink!=1{return nil,errors.New("unsafe default certificate ownership")};return os.ReadFile(path)}

func installDefaultCertificateLink(path,target string)error{random:=make([]byte,8);if _,err:=io.ReadFull(rand.Reader,random);err!=nil{return err};temporary:=path+".new-"+hex.EncodeToString(random);if err:=os.Symlink(target,temporary);err!=nil{return err};if err:=os.Lchown(temporary,0,0);err!=nil{_=os.Remove(temporary);return err};if err:=os.Rename(temporary,path);err!=nil{_=os.Remove(temporary);return err};directory,err:=os.Open(filepath.Dir(path));if err!=nil{return err};defer directory.Close();return directory.Sync()}

func bootstrapAuthn()([]string,error){uid,gid,err:=lookupIdentity("cyberpanel-auth");if err!=nil{return nil,err};root:="/var/lib/cyberpanel-auth";if err=ensureOwnedDirectory(root,0700,uid,gid);err!=nil{return nil,err};database:=filepath.Join(root,"authn.db");if _,err=ensureOwnedFile(database,0600,uid,gid,nil);err!=nil{return nil,err};return []string{root,database},nil}
func bootstrapDatabaseAuthority()([]string,error){return ensureAuthorityMarker("database","mariadb-local-v1")}
func bootstrapDNSAuthority()([]string,error){return ensureAuthorityMarker("dns","powerdns-mariadb-v1")}
func bootstrapMailAuthority()([]string,error){return ensureAuthorityMarker("mail","postfix-dovecot-rspamd-v1")}
func reconcileServiceAuthority()([]string,error){changed,err:=ensureAuthorityMarker("services","reconcile-v1");return append(changed,malwareApprovalTrustPath),err}

func ensureAuthorityMarker(name,value string)([]string,error){uid,gid,err:=lookupIdentity("cyberpanel");if err!=nil{return nil,err};root:="/var/lib/cyberpanel/control/bootstrap";if err=ensureOwnedDirectory(root,0700,uid,gid);err!=nil{return nil,err};path:=filepath.Join(root,name+".json");payload,_:=json.Marshal(struct{Version uint32 `json:"version"`;Kind,Contract string;CreatedAt time.Time `json:"created_at"`}{1,name,value,time.Now().UTC()});if _,err=ensureOwnedFile(path,0600,uid,gid,payload);err!=nil{return nil,err};return []string{path},nil}

func rollbackInstallerHook(invocation hookInvocation)error{
	path:=filepath.Join(hookRoot,"receipts",invocation.ReceiptDigest+".json");journal,err:=readHookJournal(path);if err!=nil{return err};if journal.Verb!=strings.ReplaceAll(invocation.Hook,"_","-")&&journal.Verb!=invocation.Hook{return errors.New("rollback hook receipt mismatch")};if journal.Release!=invocation.Release{return errors.New("rollback release mismatch")};if journal.State=="rolled_back"{_,err=io.WriteString(os.Stdout,"{\"version\":1,\"state\":\"rolled_back\"}\n");return err};if journal.Verb=="initialize-authority"||journal.Verb=="migrate-authority"{if err=apps.RollbackLinuxApplicationCatalog(context.Background(),"",journal.Release,time.Now().UTC());err!=nil{return err}};journal.State="rolled_back";journal.UpdatedAt=time.Now().UTC();if err=writeHookJournal(path,journal);err!=nil{return err};_,err=io.WriteString(os.Stdout,"{\"version\":1,\"state\":\"rolled_back\"}\n");return err
}

func ensureHookDirectory()error{for _,path:=range []string{hookRoot,filepath.Join(hookRoot,"receipts"),filepath.Join(hookRoot,"by-hook")}{if err:=ensureOwnedDirectory(path,0700,0,0);err!=nil{return err}};return nil}
func lookupIdentity(name string)(int,int,error){account,err:=user.Lookup(name);if err!=nil{return 0,0,err};uid,err:=strconv.Atoi(account.Uid);if err!=nil||uid<=0{return 0,0,errors.New("invalid service UID")};gid,err:=strconv.Atoi(account.Gid);if err!=nil||gid<=0{return 0,0,errors.New("invalid service GID")};return uid,gid,nil}

func ensureOwnedDirectory(path string,mode os.FileMode,uid,gid int)error{if !filepath.IsAbs(path)||filepath.Clean(path)!=path||mode.Perm()&0002!=0{return errors.New("unsafe authority directory")};if err:=os.MkdirAll(path,mode);err!=nil{return err};info,err:=os.Lstat(path);if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("unsafe authority directory")};if err=os.Chown(path,uid,gid);err!=nil{return err};return os.Chmod(path,mode)}
func ensureOwnedFile(path string,mode os.FileMode,uid,gid int,content []byte)(bool,error){if !filepath.IsAbs(path)||filepath.Clean(path)!=path||mode.Perm()&0002!=0{return false,errors.New("unsafe authority file")};if info,err:=os.Lstat(path);err==nil{stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||int(stat.Uid)!=uid||int(stat.Gid)!=gid||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=mode.Perm(){return false,errors.New("unsafe existing authority file")};return false,nil}else if !errors.Is(err,os.ErrNotExist){return false,err};temporary:=path+".new";file,err:=os.OpenFile(temporary,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,mode);if err!=nil{return false,err};if len(content)>0{_,err=file.Write(content)};if err==nil{err=file.Sync()};if err==nil{err=file.Chown(uid,gid)};closeErr:=file.Close();if err==nil{err=closeErr};if err!=nil{_=os.Remove(temporary);return false,err};if err=os.Rename(temporary,path);err!=nil{_=os.Remove(temporary);return false,err};directory,err:=os.Open(filepath.Dir(path));if err!=nil{return false,err};syncErr:=directory.Sync();directory.Close();return true,syncErr}
func ensureRandomFile(path string,size int,mode os.FileMode,uid,gid int,generator func()([]byte,error))(bool,error){if info,err:=os.Lstat(path);err==nil{stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||int(stat.Uid)!=uid||int(stat.Gid)!=gid||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=mode.Perm()||info.Size()!=int64(size){return false,errors.New("unsafe existing secret")};return false,nil}else if !errors.Is(err,os.ErrNotExist){return false,err};var content []byte;var err error;if generator!=nil{content,err=generator()}else{content=make([]byte,size);_,err=io.ReadFull(rand.Reader,content)};if err!=nil{return false,err};defer wipeBytes(content);if len(content)!=size{return false,errors.New("generated secret has invalid size")};return ensureOwnedFile(path,mode,uid,gid,content)}

func readHookJournal(path string)(hookJournal,error){var journal hookJournal;content,err:=os.ReadFile(path);if err!=nil{return journal,err};if len(content)>1<<20{return journal,errors.New("oversized hook journal")};decoder:=json.NewDecoder(&sliceReader{value:content});decoder.DisallowUnknownFields();if err=decoder.Decode(&journal);err!=nil{return journal,err};if decoder.Decode(&struct{}{})!=io.EOF||journal.Version!=1||!hookDigest.MatchString(journal.ReceiptDigest)||journal.Response==""{return hookJournal{},errors.New("invalid hook journal")};return journal,nil}
func writeHookJournal(path string,journal hookJournal)error{payload,err:=json.Marshal(journal);if err!=nil{return err};temporary:=path+".new";file,err:=os.OpenFile(temporary,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,0600);if errors.Is(err,os.ErrExist){_=os.Remove(temporary);file,err=os.OpenFile(temporary,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,0600)};if err!=nil{return err};_,writeErr:=file.Write(payload);syncErr:=file.Sync();closeErr:=file.Close();if err=errors.Join(writeErr,syncErr,closeErr);err!=nil{_=os.Remove(temporary);return err};if err=os.Rename(temporary,path);err!=nil{return err};directory,err:=os.Open(filepath.Dir(path));if err!=nil{return err};defer directory.Close();return directory.Sync()}
