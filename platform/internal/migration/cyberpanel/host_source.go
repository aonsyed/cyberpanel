package cyberpanel

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

type DatabaseDumpRequest struct { SourceID,SiteSourceID,Name,Charset,Collation string }
type DatabaseDumper interface { WriteLogicalDump(context.Context,DatabaseDumpRequest,io.Writer)(uint64,error) }
type ContainerArtifactRequest struct { SourceID,SiteSourceID,SourceName,RecipeVolume string; ArtifactID ArtifactID; Kind string }
type ContainerSnapshotter interface { WriteContainerArtifact(context.Context,ContainerArtifactRequest,io.Writer)(uint64,error) }

type HostSourceConfig struct {
	Collector Collector
	Artifacts *MaterializedCatalog
	HomeRoot string
	MailRoot string
	DatabaseDumper DatabaseDumper
	ContainerSnapshotter ContainerSnapshotter
}

type HostSource struct { collector Collector; artifacts *MaterializedCatalog; homeRoot,mailRoot string; databaseDumper DatabaseDumper; containerSnapshotter ContainerSnapshotter }

func NewHostSource(config HostSourceConfig)(*HostSource,error){if config.Collector==nil||config.Artifacts==nil||!secureRootPath(config.HomeRoot)||!secureRootPath(config.MailRoot){return nil,ErrInvalid};return &HostSource{collector:config.Collector,artifacts:config.Artifacts,homeRoot:config.HomeRoot,mailRoot:config.MailRoot,databaseDumper:config.DatabaseDumper,containerSnapshotter:config.ContainerSnapshotter},nil}

func(s *HostSource)Collect(ctx context.Context,request CollectRequest)(Snapshot,error){if s==nil||ctx==nil{return Snapshot{},ErrInvalid};snapshot,err:=s.collector.Collect(ctx,request);if err!=nil{return Snapshot{},err};hostnames:=map[string]string{};for _,site:=range snapshot.Sites{hostnames[site.SourceID]=site.PrimaryHostname};if request.Selection.Sites{for _,site:=range snapshot.Sites{root,err:=siteContentRoot(s.homeRoot,site,hostnames);if err!=nil{return Snapshot{},err};root,err=existingDirectoryWithin(s.homeRoot,root);if err!=nil{return Snapshot{},err};source,err:=OpenDirectoryTreeSource(root,"application/vnd.cyberpanel.migration.site-tree+tar","site-content");if err!=nil{return Snapshot{},err};if err:=s.artifacts.Register(site.ContentArtifact,source);err!=nil{source.Close();return Snapshot{},err}}};if request.Selection.Databases{if s.databaseDumper==nil&&len(snapshot.Databases)>0{return Snapshot{},ErrDenied};for _,database:=range snapshot.Databases{value:=database;source,err:=NewStreamArtifactSource("application/sql","identity","database-dump",func(callCtx context.Context,destination io.Writer)(uint64,error){return s.databaseDumper.WriteLogicalDump(callCtx,DatabaseDumpRequest{SourceID:value.SourceID,SiteSourceID:value.SiteSourceID,Name:value.Name,Charset:value.Charset,Collation:value.Collation},destination)});if err!=nil{return Snapshot{},err};if err:=s.artifacts.Register(database.DumpArtifact,source);err!=nil{return Snapshot{},err}}};if request.Selection.Mail{for domainIndex:=range snapshot.MailDomains{domain:=&snapshot.MailDomains[domainIndex];for mailboxIndex:=range domain.Mailboxes{mailbox:=&domain.Mailboxes[mailboxIndex];local,ok:=mailboxLocalPart(mailbox.Address,domain.Name);if !ok{return Snapshot{},ErrInvalid};root,err:=fixedJoin(s.mailRoot,domain.Name,local);if err!=nil{return Snapshot{},err};root,err=existingDirectoryWithin(s.mailRoot,root);if errors.Is(err,os.ErrNotExist){mailbox.DataArtifact="";continue};if err!=nil{return Snapshot{},err};source,err:=OpenDirectoryTreeSource(root,"application/vnd.cyberpanel.migration.mailbox-"+mailbox.Format+"+tar","mailbox-data");if err!=nil{return Snapshot{},err};if err:=s.artifacts.Register(mailbox.DataArtifact,source);err!=nil{source.Close();return Snapshot{},err}}}};if request.Selection.Containers{if s.containerSnapshotter==nil&&len(snapshot.Containers)>0{return Snapshot{},ErrDenied};for _,container:=range snapshot.Containers{value:=container;if !validSourceID(value.SourceID)||!validSourceID(value.SiteSourceID)||!migration.ID(value.RecipeID).Valid()||value.RecipeVersion==""||value.DescriptorArtifact!=""||len(value.VolumeArtifacts)!=0||len(value.Volumes)!=1||len(value.Secrets)!=0||len(value.SecretBindings)!=0{return Snapshot{},ErrInvalid};volume:=value.Volumes[0];if !containerVolumeNamePattern.MatchString(volume.SourceName)||!containerVolumeNamePattern.MatchString(volume.RecipeVolume)||!volume.Artifact.Valid(){return Snapshot{},ErrInvalid};id:=volume.Artifact;sourceName,recipeVolume:=volume.SourceName,volume.RecipeVolume;source,err:=NewStreamArtifactSource("application/vnd.cyberpanel.migration.container-volume+tar","tar","container-volume",func(callCtx context.Context,destination io.Writer)(uint64,error){return s.containerSnapshotter.WriteContainerArtifact(callCtx,ContainerArtifactRequest{SourceID:value.SourceID,SiteSourceID:value.SiteSourceID,SourceName:sourceName,RecipeVolume:recipeVolume,ArtifactID:id,Kind:"volume"},destination)});if err!=nil{return Snapshot{},err};if err:=s.artifacts.Register(id,source);err!=nil{return Snapshot{},err}}};return snapshot,nil}

type HostSupplementalConfig struct { Artifacts *MaterializedCatalog; HomeRoot,CertificateRoot,DKIMRoot,CronRoot,DebianCronRoot string; Clock func()time.Time }
type HostSupplemental struct { artifacts *MaterializedCatalog; homeRoot,certificateRoot,dkimRoot,cronRoot,debianCronRoot string; clock func()time.Time; mu sync.RWMutex; secrets map[SecretRef][]byte }
func NewHostSupplemental(config HostSupplementalConfig)(*HostSupplemental,error){if config.Artifacts==nil||!secureRootPath(config.HomeRoot)||!secureRootPath(config.CertificateRoot)||!secureRootPath(config.DKIMRoot)||!secureRootPath(config.CronRoot)||!secureRootPath(config.DebianCronRoot){return nil,ErrInvalid};if config.Clock==nil{config.Clock=time.Now};return &HostSupplemental{artifacts:config.Artifacts,homeRoot:config.HomeRoot,certificateRoot:config.CertificateRoot,dkimRoot:config.DKIMRoot,cronRoot:config.CronRoot,debianCronRoot:config.DebianCronRoot,clock:config.Clock,secrets:map[SecretRef][]byte{}},nil}
func(s *HostSupplemental)Close()error{if s==nil{return nil};s.mu.Lock();defer s.mu.Unlock();for ref,value:=range s.secrets{wipe(value);delete(s.secrets,ref)};return nil}

func(s *HostSupplemental)CollectCertificates(ctx context.Context,sites []SiteRecord)([]CertificateRecord,error){
	if s==nil||ctx==nil{return nil,ErrInvalid}
	values:=[]CertificateRecord{}
	newSecrets:=map[SecretRef][]byte{}
	installed:=false
	defer func(){if !installed{wipeSecretMap(newSecrets)}}()
	for _,site:=range sites{
		hostname:=normalizeHostname(site.PrimaryHostname)
		directory,err:=fixedJoin(s.certificateRoot,hostname)
		if err!=nil{return nil,err}
		fullchain:=filepath.Join(directory,"fullchain.pem")
		raw,err:=readStableRegularFollowing(ctx,fullchain,filepath.Dir(s.certificateRoot),16<<20)
		if errors.Is(err,os.ErrNotExist){continue}
		if err!=nil{return nil,err}
		certificate,err:=firstCertificate(raw)
		if err!=nil{return nil,err}
		privateKey,err:=readStableRegularFollowing(ctx,filepath.Join(directory,"privkey.pem"),filepath.Dir(s.certificateRoot),16<<20)
		if err!=nil{return nil,err}
		if err:=privateKeyMatchesCertificate(privateKey,certificate);err!=nil{wipe(privateKey);return nil,err}
		artifactID:=ArtifactID("certificate-public:"+safeOpaqueID(site.SourceID))
		source:=&immutableArtifactSource{value:append([]byte(nil),raw...),mediaType:"application/pem-certificate-chain",encryptionDomain:"certificate-public"}
		if err:=s.artifacts.Register(artifactID,source);err!=nil{wipe(privateKey);return nil,err}
		privateRef:=SecretRef("tls-private-key:"+hostname)
		if _,duplicate:=newSecrets[privateRef];duplicate{wipe(privateKey);return nil,ErrInvalid}
		newSecrets[privateRef]=privateKey
		names,err:=ConcreteCertificateNames(certificate,hostname)
		if err!=nil{return nil,err}
		values=append(values,CertificateRecord{SourceID:"certificate:"+safeOpaqueID(site.SourceID),Names:names,CertificateArtifact:artifactID,PrivateKey:privateRef,Issuer:certificate.Issuer.String(),NotAfter:certificate.NotAfter})
	}
	s.replaceSecretFamily("tls-private-key:",newSecrets)
	installed=true
	return values,nil
}

func(s *HostSupplemental)CollectCredentials(ctx context.Context,sites []SiteRecord,existing []CredentialRecord)([]CredentialRecord,error){if s==nil||ctx==nil{return nil,ErrInvalid};values:=append([]CredentialRecord(nil),existing...);for _,site:=range sites{if site.ParentSourceID!=""{continue};home,err:=fixedJoin(s.homeRoot,site.PrimaryHostname);if err!=nil{return nil,err};home,err=existingDirectoryWithin(s.homeRoot,home);if errors.Is(err,os.ErrNotExist){continue};if err!=nil{return nil,err};path,err:=fixedJoin(home,".ssh","authorized_keys");if err!=nil{return nil,err};raw,readErr:=readStableRegularFollowing(ctx,path,home,8<<20);if errors.Is(readErr,os.ErrNotExist){continue};if readErr!=nil{return nil,readErr};keys,err:=ParseAuthorizedKeys(raw);if err!=nil{return nil,err};for _,key:=range keys{label:=key.Label;if label==""{label=firstNonEmptyString(site.RuntimeUser,key.Fingerprint[:16])};values=append(values,CredentialRecord{SourceID:"ssh-key:"+safeOpaqueID(site.SourceID)+":"+key.Fingerprint[:32],SiteSourceID:site.SourceID,Kind:"ssh-public-key",Label:label,RootRelative:site.DocumentRootRelative,PublicKey:key.PublicKey})}};return values,nil}

func(s *HostSupplemental)CollectSchedules(ctx context.Context,sites []SiteRecord)([]ScheduleRecord,error){if s==nil||ctx==nil{return nil,ErrInvalid};values:=[]ScheduleRecord{};for _,site:=range sites{if site.RuntimeUser==""{continue};path,err:=fixedJoin(s.cronRoot,site.RuntimeUser);if err!=nil{return nil,err};raw,readErr:=readStableRegular(ctx,path,8<<20);if errors.Is(readErr,os.ErrNotExist){path,err=fixedJoin(s.debianCronRoot,site.RuntimeUser);if err!=nil{return nil,err};raw,readErr=readStableRegular(ctx,path,8<<20)};if errors.Is(readErr,os.ErrNotExist){continue};if readErr!=nil{return nil,readErr};scanner:=bufio.NewScanner(bytes.NewReader(raw));scanner.Buffer(make([]byte,4096),1<<20);counter:=0;timezone:="source-local";for scanner.Scan(){line:=strings.TrimSpace(scanner.Text());if line==""||strings.HasPrefix(line,"#"){continue};if value,present:=cronEnvironmentValue(line,"CRON_TZ");present{timezone=value;continue};if cronEnvironment(line){continue};expression,command,present,parseErr:=ParseLegacyCronEntry(line);if parseErr!=nil{return nil,parseErr};if !present{continue};sum:=sha256.Sum256([]byte(command));counter++;values=append(values,ScheduleRecord{SourceID:"cron:"+safeOpaqueID(site.SourceID)+":"+hex.EncodeToString(sum[:8])+":"+safeCounter(counter),SiteSourceID:site.SourceID,Kind:"legacy-command",Expression:expression,Timezone:timezone,InvocationID:"legacy_invocation_"+hex.EncodeToString(sum[:16]),Enabled:true})};if err:=scanner.Err();err!=nil{return nil,err}};return values,nil}

func(s *HostSupplemental)CollectRepositories(ctx context.Context,sites []SiteRecord)([]RepositoryRecord,error){
	if s==nil||ctx==nil{return nil,ErrInvalid}
	values:=[]RepositoryRecord{}
	newSecrets:=map[SecretRef][]byte{}
	installed:=false
	defer func(){if !installed{for ref,value:=range newSecrets{wipe(value);delete(newSecrets,ref)}}}()
	hostnames:=map[string]string{}
	for _,site:=range sites{hostnames[site.SourceID]=site.PrimaryHostname}
	for _,site:=range sites{
		root,err:=siteContentRoot(s.homeRoot,site,hostnames)
		if err!=nil{return nil,err}
		root,err=existingDirectoryWithin(s.homeRoot,root)
		if errors.Is(err,os.ErrNotExist){continue}
		if err!=nil{return nil,err}
		configPath:=filepath.Join(root,".git","config")
		raw,readErr:=readStableRegularFollowing(ctx,configPath,root,2<<20)
		if errors.Is(readErr,os.ErrNotExist){continue}
		if readErr!=nil{return nil,readErr}
		origin,branch,credential:=parseGitConfig(raw)
		if origin==""{wipe(credential);continue}
		credentialRef:=SecretRef("")
		if len(credential)>0{
			credentialRef=SecretRef("repository-credential:"+safeOpaqueID(site.SourceID))
			newSecrets[credentialRef]=append([]byte(nil),credential...)
			wipe(credential)
		}
		values=append(values,RepositoryRecord{SourceID:"repository:"+safeOpaqueID(site.SourceID),SiteSourceID:site.SourceID,Provider:repositoryProvider(origin),Origin:origin,Branch:branch,Credential:credentialRef})
	}
	s.replaceSecretFamily("repository-credential:",newSecrets)
	installed=true
	return values,nil
}
func(s *HostSupplemental)CollectMailExtensions(ctx context.Context,domains []MailDomainRecord)([]MailDomainRecord,error){
	if s==nil||ctx==nil{return nil,ErrInvalid}
	values:=append([]MailDomainRecord(nil),domains...)
	newSecrets:=map[SecretRef][]byte{}
	installed:=false
	defer func(){if !installed{wipeSecretMap(newSecrets)}}()
	for index:=range values{
		domain:=normalizeHostname(values[index].Name)
		path,err:=fixedJoin(s.dkimRoot,domain,"default.private")
		if err!=nil{return nil,err}
		privateKey,readErr:=readStableRegularFollowing(ctx,path,s.dkimRoot,16<<20)
		if errors.Is(readErr,os.ErrNotExist){continue}
		if readErr!=nil{return nil,readErr}
		if _,parseErr:=parsePrivateSigner(privateKey);parseErr!=nil{wipe(privateKey);return nil,parseErr}
		ref:=SecretRef("dkim-private:"+domain)
		if _,duplicate:=newSecrets[ref];duplicate{wipe(privateKey);return nil,ErrInvalid}
		newSecrets[ref]=privateKey
		values[index].DKIMPrivateKey=ref
	}
	s.replaceSecretFamily("dkim-private:",newSecrets)
	installed=true
	return values,nil
}
func(s *HostSupplemental)ReadSecret(ctx context.Context,ref SecretRef)([]byte,error){if s==nil||ctx==nil||!ref.Valid(){return nil,ErrInvalid};s.mu.RLock();value,exists:=s.secrets[ref];if exists{value=append([]byte(nil),value...)};s.mu.RUnlock();if !exists{return nil,migration.ErrNotFound};return value,nil}

func(s *HostSupplemental)replaceSecretFamily(prefix string,newSecrets map[SecretRef][]byte){s.mu.Lock();for ref,value:=range s.secrets{if strings.HasPrefix(string(ref),prefix){wipe(value);delete(s.secrets,ref)}};for ref,value:=range newSecrets{s.secrets[ref]=value;delete(newSecrets,ref)};s.mu.Unlock()}
func wipeSecretMap(values map[SecretRef][]byte){for ref,value:=range values{wipe(value);delete(values,ref)}}

type HostSecretSource struct { database SecretSource; certificateRoot,dkimRoot string }
func NewHostSecretSource(database SecretSource,certificateRoot,dkimRoot string)(*HostSecretSource,error){if database==nil||!secureRootPath(certificateRoot)||!secureRootPath(dkimRoot){return nil,ErrInvalid};return &HostSecretSource{database:database,certificateRoot:certificateRoot,dkimRoot:dkimRoot},nil}
func(s *HostSecretSource)ReadSecret(ctx context.Context,ref SecretRef)([]byte,error){if s==nil||ctx==nil||!ref.Valid(){return nil,ErrInvalid};value:=string(ref);if strings.HasPrefix(value,"tls-private-key:"){hostname:=strings.TrimPrefix(value,"tls-private-key:");if !validHostname(hostname){return nil,ErrDenied};directory,err:=fixedJoin(s.certificateRoot,hostname);if err!=nil{return nil,err};privateKey,err:=readStableRegularFollowing(ctx,filepath.Join(directory,"privkey.pem"),filepath.Dir(s.certificateRoot),16<<20);if err!=nil{return nil,err};certificateRaw,err:=readStableRegularFollowing(ctx,filepath.Join(directory,"fullchain.pem"),filepath.Dir(s.certificateRoot),16<<20);if err!=nil{wipe(privateKey);return nil,err};certificate,err:=firstCertificate(certificateRaw);if err!=nil{wipe(privateKey);return nil,err};if err:=privateKeyMatchesCertificate(privateKey,certificate);err!=nil{wipe(privateKey);return nil,err};return privateKey,nil};if strings.HasPrefix(value,"dkim-private:"){domain:=strings.TrimPrefix(value,"dkim-private:");if !validHostname(domain){return nil,ErrDenied};path,err:=fixedJoin(s.dkimRoot,domain,"default.private");if err!=nil{return nil,err};privateKey,err:=readStableRegularFollowing(ctx,path,s.dkimRoot,16<<20);if err!=nil{return nil,err};if _,parseErr:=parsePrivateSigner(privateKey);parseErr!=nil{wipe(privateKey);return nil,parseErr};return privateKey,nil};return s.database.ReadSecret(ctx,ref)}

func siteContentRoot(homeRoot string,site SiteRecord,hostnames map[string]string)(string,error){owner:=site.PrimaryHostname;if site.ParentSourceID!=""{owner=hostnames[site.ParentSourceID]};if !validHostname(owner)||site.DocumentRootRelative==""||strings.Contains(site.DocumentRootRelative,".."){return "",ErrInvalid};parts:=append([]string{owner},strings.Split(filepath.ToSlash(site.DocumentRootRelative),"/")...);return fixedJoin(homeRoot,parts...)}
func fixedJoin(root string,segments ...string)(string,error){if !secureRootPath(root){return "",ErrInvalid};value:=root;for _,segment:=range segments{if segment==""||segment=="."||segment==".."||strings.ContainsAny(segment,"/\\\x00"){return "",ErrInvalid};value=filepath.Join(value,segment)};relative,err:=filepath.Rel(root,value);if err!=nil||relative==".."||strings.HasPrefix(relative,".."+string(filepath.Separator)){return "",ErrDenied};return value,nil}
func secureRootPath(value string)bool{return value!=""&&filepath.IsAbs(value)&&filepath.Clean(value)==value}
func existingDirectoryWithin(approvedRoot,path string)(string,error){if !secureRootPath(approvedRoot)||!secureRootPath(path){return "",ErrInvalid};resolvedRoot,err:=filepath.EvalSymlinks(approvedRoot);if err!=nil{return "",err};resolvedPath,err:=filepath.EvalSymlinks(path);if err!=nil{return "",err};relative,err:=filepath.Rel(resolvedRoot,resolvedPath);if err!=nil||relative==".."||strings.HasPrefix(relative,".."+string(filepath.Separator)){return "",ErrDenied};info,err:=os.Stat(resolvedPath);if err!=nil{return "",err};if !info.IsDir(){return "",ErrDenied};return filepath.Clean(resolvedPath),nil}
func mailboxLocalPart(address,domain string)(string,bool){suffix:="@"+strings.ToLower(domain);address=strings.ToLower(address);if !strings.HasSuffix(address,suffix){return "",false};local:=strings.TrimSuffix(address,suffix);return local,validSafeToken(local)}
func validSafeToken(value string)bool{if len(value)<1||len(value)>191{return false};for _,character:=range value{if(character<'a'||character>'z')&&(character<'A'||character>'Z')&&(character<'0'||character>'9')&&character!='.'&&character!='@'&&character!='-'&&character!='_'{return false}};return !strings.Contains(value,"..")}
func safeOpaqueID(value string)string{canonical:=strings.TrimSpace(value);normalized:=strings.ToLower(canonical);var output strings.Builder;for _,character:=range normalized{if(character>='a'&&character<='z')||(character>='0'&&character<='9')||character=='.'||character=='-'||character=='_'{output.WriteRune(character)}else{output.WriteByte('-')}};slug:=strings.Trim(output.String(),"-.");if len(slug)>48{slug=slug[:48]};if len(slug)<3{slug="id"};sum:=sha256.Sum256([]byte(canonical));return slug+"-"+hex.EncodeToString(sum[:16])}
func readStableRegular(ctx context.Context,path string,limit int64)([]byte,error){if ctx==nil||path==""||limit<1{return nil,ErrInvalid};before,err:=os.Lstat(path);if err!=nil{return nil,err};if !before.Mode().IsRegular()||before.Size()<0||before.Size()>limit{return nil,ErrDenied};file,err:=os.Open(path);if err!=nil{return nil,err};defer file.Close();after,err:=file.Stat();if err!=nil||!os.SameFile(before,after)||!after.Mode().IsRegular(){return nil,ErrChanged};select{case<-ctx.Done():return nil,ctx.Err();default:};raw,err:=io.ReadAll(io.LimitReader(file,limit+1));if err!=nil||int64(len(raw))!=after.Size(){return nil,errors.Join(err,ErrChanged)};final,err:=file.Stat();if err!=nil||!os.SameFile(after,final){return nil,ErrChanged};return raw,nil}
func readStableRegularFollowing(ctx context.Context,path,allowedRoot string,limit int64)([]byte,error){resolvedRoot,err:=filepath.EvalSymlinks(allowedRoot);if err!=nil{return nil,err};resolved,err:=filepath.EvalSymlinks(path);if err!=nil{return nil,err};resolved=filepath.Clean(resolved);relative,err:=filepath.Rel(resolvedRoot,resolved);if err!=nil||relative==".."||strings.HasPrefix(relative,".."+string(filepath.Separator)){return nil,ErrDenied};before,err:=os.Stat(resolved);if err!=nil||!before.Mode().IsRegular()||before.Size()<0||before.Size()>limit{return nil,errors.Join(err,ErrDenied)};file,err:=os.Open(resolved);if err!=nil{return nil,err};defer file.Close();after,err:=file.Stat();if err!=nil||!os.SameFile(before,after)||!after.Mode().IsRegular(){return nil,ErrChanged};select{case<-ctx.Done():return nil,ctx.Err();default:};raw,err:=io.ReadAll(io.LimitReader(file,limit+1));if err!=nil||int64(len(raw))!=after.Size(){return nil,errors.Join(err,ErrChanged)};final,err:=file.Stat();if err!=nil||!sameFileState(after,final){return nil,ErrChanged};return raw,nil}
type immutableArtifactSource struct{value []byte;mediaType,encryptionDomain string}
func(s *immutableArtifactSource)MediaType()string{return s.mediaType};func(s *immutableArtifactSource)Compression()string{return"identity"};func(s *immutableArtifactSource)EncryptionDomain()string{return s.encryptionDomain};func(s *immutableArtifactSource)WriteSnapshot(ctx context.Context,destination io.Writer)(uint64,error){if s==nil||ctx==nil||destination==nil||len(s.value)==0{return 0,ErrInvalid};select{case<-ctx.Done():return 0,ctx.Err();default:};count,err:=destination.Write(s.value);if err!=nil{return 0,err};if count!=len(s.value){return 0,io.ErrShortWrite};return 1,nil}
func firstCertificate(raw []byte)(*x509.Certificate,error){var first *x509.Certificate;for len(raw)>0{block,remaining:=pem.Decode(raw);if block==nil{if strings.TrimSpace(string(raw))!=""{return nil,ErrInvalid};break};raw=remaining;if block.Type!="CERTIFICATE"{return nil,ErrInvalid};certificate,err:=x509.ParseCertificate(block.Bytes);if err!=nil{return nil,err};if first==nil{first=certificate}};if first==nil{return nil,ErrInvalid};return first,nil}
func ConcreteCertificateNames(certificate *x509.Certificate,assignedHostname string)([]string,error){assignedHostname=normalizeHostname(assignedHostname);if certificate==nil||!validHostname(assignedHostname)||certificate.VerifyHostname(assignedHostname)!=nil{return nil,ErrInvalid};values:=[]string{};seen:=map[string]struct{}{};for _,name:=range certificate.DNSNames{name=normalizeHostname(name);if !validHostname(name){continue};if _,duplicate:=seen[name];duplicate{continue};seen[name]=struct{}{};values=append(values,name)};if _,present:=seen[assignedHostname];!present{values=append(values,assignedHostname)};sort.Strings(values);return values,nil}
func parsePrivateSigner(raw []byte)(crypto.Signer,error){var signer crypto.Signer;for len(raw)>0{block,remaining:=pem.Decode(raw);if block==nil{if strings.TrimSpace(string(raw))!=""{return nil,ErrInvalid};break};raw=remaining;var value any;var err error;switch block.Type{case"RSA PRIVATE KEY":value,err=x509.ParsePKCS1PrivateKey(block.Bytes);case"EC PRIVATE KEY":value,err=x509.ParseECPrivateKey(block.Bytes);case"PRIVATE KEY":value,err=x509.ParsePKCS8PrivateKey(block.Bytes);case"ENCRYPTED PRIVATE KEY":return nil,ErrDenied;default:return nil,ErrInvalid};if err!=nil{return nil,err};parsed,ok:=value.(crypto.Signer);if !ok||signer!=nil{return nil,ErrInvalid};signer=parsed};if signer==nil{return nil,ErrInvalid};return signer,nil}
func privateKeyMatchesCertificate(raw []byte,certificate *x509.Certificate)error{if certificate==nil{return ErrInvalid};signer,err:=parsePrivateSigner(raw);if err!=nil{return err};left,err:=x509.MarshalPKIXPublicKey(signer.Public());if err!=nil{return err};right,err:=x509.MarshalPKIXPublicKey(certificate.PublicKey);if err!=nil{return err};if !bytes.Equal(left,right){return ErrChanged};return nil}
func ValidatePrivateKeyForCertificate(raw []byte,certificate *x509.Certificate)error{return privateKeyMatchesCertificate(raw,certificate)}
func cronEnvironment(value string)bool{equals:=strings.IndexByte(value,'=');space:=strings.IndexAny(value," \t");return equals>0&&(space<0||equals<space)}
func safeCounter(value int)string{digits:="0123456789abcdefghijklmnopqrstuvwxyz";if value<=0{return"0"};output:="";for value>0{output=string(digits[value%len(digits)])+output;value/=len(digits)};return output}
func parseGitConfig(raw []byte)(string,string,[]byte){scanner:=bufio.NewScanner(bytes.NewReader(raw));section:="";origin,branch:="","";for scanner.Scan(){line:=strings.TrimSpace(scanner.Text());if line==""||strings.HasPrefix(line,"#")||strings.HasPrefix(line,";"){continue};if strings.HasPrefix(line,"[")&&strings.HasSuffix(line,"]"){section=strings.ToLower(strings.Trim(line,"[] \t"));continue};parts:=strings.SplitN(line,"=",2);if len(parts)!=2{continue};key,value:=strings.ToLower(strings.TrimSpace(parts[0])),strings.TrimSpace(parts[1]);if section==`remote "origin"`&&key=="url"{origin=value};if strings.HasPrefix(section,`branch "`)&&key=="merge"&&branch==""{branch=strings.TrimPrefix(value,"refs/heads/")}};if branch==""{branch="HEAD"};parsed,err:=url.Parse(origin);if err!=nil||parsed.User==nil{return origin,branch,nil};username:=parsed.User.Username();password,present:=parsed.User.Password();credential,_:=json.Marshal(struct{Username,Password string}{Username:username,Password:password});if !present&&username==""{credential=nil};parsed.User=nil;return parsed.String(),branch,credential}
func repositoryProvider(origin string)string{lower:=strings.ToLower(origin);switch{case strings.Contains(lower,"github.com"):return"github";case strings.Contains(lower,"gitlab.com"):return"gitlab";case strings.Contains(lower,"bitbucket.org"):return"bitbucket";default:return"git"}}
func firstNonEmptyString(values ...string)string{for _,value:=range values{if strings.TrimSpace(value)!=""{return value}};return"source-credential"}

var _ Collector=(*HostSource)(nil)
var _ SupplementalCollector=(*HostSupplemental)(nil)
var _ SecretSource=(*HostSupplemental)(nil)
var _ SecretSource=(*HostSecretSource)(nil)
