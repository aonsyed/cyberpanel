//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
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
	if existing,loadErr:=readHookJournal(indexPath);loadErr==nil { _,err=io.WriteString(os.Stdout,existing.Response);return err } else if !errors.Is(loadErr,os.ErrNotExist){return loadErr}
	changed,err:=applyHook(invocation);if err!=nil{return err}
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
	case "initialize-authority":return initializeAuthority()
	case "migrate-authority":return migrateAuthority()
	case "bootstrap-secrets":return bootstrapSecrets()
	case "bootstrap-authn":return bootstrapAuthn()
	case "bootstrap-database":return bootstrapDatabaseAuthority()
	case "bootstrap-dns":return bootstrapDNSAuthority()
	case "bootstrap-mail":return bootstrapMailAuthority()
	case "reconcile-services":return reconcileServiceAuthority()
	default:return nil,errors.New("unsupported installer hook")
	}
}

func initializeAuthority()([]string,error){
	uid,gid,err:=lookupIdentity("cyberpanel");if err!=nil{return nil,err};paths:=[]string{"/var/lib/cyberpanel/control","/var/lib/cyberpanel/control/runtime","/var/lib/cyberpanel/control/trust","/var/lib/cyberpanel/control/recovery","/var/lib/cyberpanel/audit","/var/lib/cyberpanel/audit/segments","/var/lib/cyberpanel/audit/emergency","/var/lib/cyberpanel/backup-spool","/var/backups/cyberpanel/repositories"}
	if err=ensureOwnedDirectory("/var/backups/cyberpanel",0750,0,gid);err!=nil{return nil,err}
	for _,path:=range paths{if err=ensureOwnedDirectory(path,0700,uid,gid);err!=nil{return nil,err}}
	databasePath:="/var/lib/cyberpanel/control/control.db";created,err:=ensureOwnedFile(databasePath,0600,uid,gid,nil);if err!=nil{return nil,err}
	changed:=append([]string{"/var/backups/cyberpanel"},paths...);if created{changed=append(changed,databasePath)}
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
	auditKey:=filepath.Join(secretRoot,"audit-signing.key");if _,err=ensureRandomFile(auditKey,ed25519.PrivateKeySize,0600,0,0,func()([]byte,error){_,private,keyErr:=ed25519.GenerateKey(rand.Reader);return private,keyErr});err!=nil{return nil,err}
	webmailSessionKey:=filepath.Join(secretRoot,"webmail-session.key");if _,err=ensureRandomFile(webmailSessionKey,32,0600,0,0,nil);err!=nil{return nil,err}
	webmailMaster:=filepath.Join(secretRoot,"mail-webmail-master");if _,err=ensureRandomFile(webmailMaster,91,0400,0,0,func()([]byte,error){raw:=make([]byte,48);if _,readErr:=io.ReadFull(rand.Reader,raw);readErr!=nil{return nil,readErr};encoded:=base64.RawURLEncoding.EncodeToString(raw);wipeBytes(raw);return []byte("cyberpanel-webmail:{PLAIN}"+encoded+"\n"),nil});err!=nil{return nil,err}
	secretKey:=filepath.Join(secretRoot,"wrapping.key");if _,err=ensureRandomFile(secretKey,32,0400,secretUID,secretGID,nil);err!=nil{return nil,err}
	secretStateRoot:="/var/lib/cyberpanel-secrets";if err=ensureOwnedDirectory(secretStateRoot,0700,secretUID,secretGID);err!=nil{return nil,err}
	secretDatabase:=filepath.Join(secretStateRoot,"secrets.db");if _,err=ensureOwnedFile(secretDatabase,0600,secretUID,secretGID,nil);err!=nil{return nil,err}
	secretEpoch:=filepath.Join(secretStateRoot,"key-epoch");if _,err=ensureOwnedFile(secretEpoch,0400,secretUID,secretGID,[]byte("1\n"));err!=nil{return nil,err}
	authRoot:="/etc/cyberpanel/authn";if err=ensureOwnedDirectory(authRoot,0700,0,0);err!=nil{return nil,err}
	for _,path:=range []string{filepath.Join(authRoot,"wrapping.key"),filepath.Join(authRoot,"lookup.pepper")}{if _,err=ensureRandomFile(path,32,0400,0,0,nil);err!=nil{return nil,err}}
	return []string{paths.SignerPath,paths.TrustPath,auditKey,webmailSessionKey,webmailMaster,secretKey,secretDatabase,secretEpoch,filepath.Join(authRoot,"wrapping.key"),filepath.Join(authRoot,"lookup.pepper")},nil
}

func bootstrapAuthn()([]string,error){uid,gid,err:=lookupIdentity("cyberpanel-auth");if err!=nil{return nil,err};root:="/var/lib/cyberpanel-auth";if err=ensureOwnedDirectory(root,0700,uid,gid);err!=nil{return nil,err};database:=filepath.Join(root,"authn.db");if _,err=ensureOwnedFile(database,0600,uid,gid,nil);err!=nil{return nil,err};return []string{root,database},nil}
func bootstrapDatabaseAuthority()([]string,error){return ensureAuthorityMarker("database","mariadb-local-v1")}
func bootstrapDNSAuthority()([]string,error){return ensureAuthorityMarker("dns","powerdns-mariadb-v1")}
func bootstrapMailAuthority()([]string,error){return ensureAuthorityMarker("mail","postfix-dovecot-rspamd-v1")}
func reconcileServiceAuthority()([]string,error){return ensureAuthorityMarker("services","reconcile-v1")}

func ensureAuthorityMarker(name,value string)([]string,error){uid,gid,err:=lookupIdentity("cyberpanel");if err!=nil{return nil,err};root:="/var/lib/cyberpanel/control/bootstrap";if err=ensureOwnedDirectory(root,0700,uid,gid);err!=nil{return nil,err};path:=filepath.Join(root,name+".json");payload,_:=json.Marshal(struct{Version uint32 `json:"version"`;Kind,Contract string;CreatedAt time.Time `json:"created_at"`}{1,name,value,time.Now().UTC()});if _,err=ensureOwnedFile(path,0600,uid,gid,payload);err!=nil{return nil,err};return []string{path},nil}

func rollbackInstallerHook(invocation hookInvocation)error{
	path:=filepath.Join(hookRoot,"receipts",invocation.ReceiptDigest+".json");journal,err:=readHookJournal(path);if err!=nil{return err};if journal.Verb!=strings.ReplaceAll(invocation.Hook,"_","-")&&journal.Verb!=invocation.Hook{return errors.New("rollback hook receipt mismatch")};if journal.Release!=invocation.Release{return errors.New("rollback release mismatch")};if journal.State=="rolled_back"{_,err=io.WriteString(os.Stdout,"{\"version\":1,\"state\":\"rolled_back\"}\n");return err};journal.State="rolled_back";journal.UpdatedAt=time.Now().UTC();if err=writeHookJournal(path,journal);err!=nil{return err};_,err=io.WriteString(os.Stdout,"{\"version\":1,\"state\":\"rolled_back\"}\n");return err
}

func ensureHookDirectory()error{for _,path:=range []string{hookRoot,filepath.Join(hookRoot,"receipts"),filepath.Join(hookRoot,"by-hook")}{if err:=ensureOwnedDirectory(path,0700,0,0);err!=nil{return err}};return nil}
func lookupIdentity(name string)(int,int,error){account,err:=user.Lookup(name);if err!=nil{return 0,0,err};uid,err:=strconv.Atoi(account.Uid);if err!=nil||uid<=0{return 0,0,errors.New("invalid service UID")};gid,err:=strconv.Atoi(account.Gid);if err!=nil||gid<=0{return 0,0,errors.New("invalid service GID")};return uid,gid,nil}

func ensureOwnedDirectory(path string,mode os.FileMode,uid,gid int)error{if !filepath.IsAbs(path)||filepath.Clean(path)!=path||mode.Perm()&0002!=0{return errors.New("unsafe authority directory")};if err:=os.MkdirAll(path,mode);err!=nil{return err};info,err:=os.Lstat(path);if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("unsafe authority directory")};if err=os.Chown(path,uid,gid);err!=nil{return err};return os.Chmod(path,mode)}
func ensureOwnedFile(path string,mode os.FileMode,uid,gid int,content []byte)(bool,error){if !filepath.IsAbs(path)||filepath.Clean(path)!=path||mode.Perm()&0002!=0{return false,errors.New("unsafe authority file")};if info,err:=os.Lstat(path);err==nil{stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||int(stat.Uid)!=uid||int(stat.Gid)!=gid||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=mode.Perm(){return false,errors.New("unsafe existing authority file")};return false,nil}else if !errors.Is(err,os.ErrNotExist){return false,err};temporary:=path+".new";file,err:=os.OpenFile(temporary,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,mode);if err!=nil{return false,err};if len(content)>0{_,err=file.Write(content)};if err==nil{err=file.Sync()};if err==nil{err=file.Chown(uid,gid)};closeErr:=file.Close();if err==nil{err=closeErr};if err!=nil{_=os.Remove(temporary);return false,err};if err=os.Rename(temporary,path);err!=nil{_=os.Remove(temporary);return false,err};directory,err:=os.Open(filepath.Dir(path));if err!=nil{return false,err};syncErr:=directory.Sync();directory.Close();return true,syncErr}
func ensureRandomFile(path string,size int,mode os.FileMode,uid,gid int,generator func()([]byte,error))(bool,error){if info,err:=os.Lstat(path);err==nil{stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||int(stat.Uid)!=uid||int(stat.Gid)!=gid||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=mode.Perm()||info.Size()!=int64(size){return false,errors.New("unsafe existing secret")};return false,nil}else if !errors.Is(err,os.ErrNotExist){return false,err};var content []byte;var err error;if generator!=nil{content,err=generator()}else{content=make([]byte,size);_,err=io.ReadFull(rand.Reader,content)};if err!=nil{return false,err};defer wipeBytes(content);if len(content)!=size{return false,errors.New("generated secret has invalid size")};return ensureOwnedFile(path,mode,uid,gid,content)}

func readHookJournal(path string)(hookJournal,error){var journal hookJournal;content,err:=os.ReadFile(path);if err!=nil{return journal,err};if len(content)>1<<20{return journal,errors.New("oversized hook journal")};decoder:=json.NewDecoder(&sliceReader{value:content});decoder.DisallowUnknownFields();if err=decoder.Decode(&journal);err!=nil{return journal,err};if decoder.Decode(&struct{}{})!=io.EOF||journal.Version!=1||!hookDigest.MatchString(journal.ReceiptDigest)||journal.Response==""{return hookJournal{},errors.New("invalid hook journal")};return journal,nil}
func writeHookJournal(path string,journal hookJournal)error{payload,err:=json.Marshal(journal);if err!=nil{return err};temporary:=path+".new";file,err:=os.OpenFile(temporary,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,0600);if errors.Is(err,os.ErrExist){_=os.Remove(temporary);file,err=os.OpenFile(temporary,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,0600)};if err!=nil{return err};_,writeErr:=file.Write(payload);syncErr:=file.Sync();closeErr:=file.Close();if err=errors.Join(writeErr,syncErr,closeErr);err!=nil{_=os.Remove(temporary);return err};if err=os.Rename(temporary,path);err!=nil{return err};directory,err:=os.Open(filepath.Dir(path));if err!=nil{return err};defer directory.Close();return directory.Sync()}
