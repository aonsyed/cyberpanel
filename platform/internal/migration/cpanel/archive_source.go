package cpanel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanel"
)

var (
	ErrInvalid=errors.New("cpanel extractor: invalid value")
	ErrDenied=errors.New("cpanel extractor: archive not locally approved")
	ErrArchiveChanged=errors.New("cpanel extractor: archive changed while reading")
)

type ArchiveLimits struct {
	MaximumEntries uint64
	MaximumExpandedBytes uint64
	MaximumMetadataBytes uint64
}

type ArchiveSourceConfig struct {
	InstallationID string
	Accounts map[string]string
	Artifacts *cyberpanel.MaterializedCatalog
	Limits ArchiveLimits
	Clock func()time.Time
}

type approvedArchive struct { accountID string; path string; identity os.FileInfo }

type ArchiveSource struct {
	installationID string
	accounts map[string]approvedArchive
	artifacts *cyberpanel.MaterializedCatalog
	limits ArchiveLimits
	clock func()time.Time
	mu sync.RWMutex
	secrets map[SecretRef][]byte
}

func NewArchiveSource(config ArchiveSourceConfig)(*ArchiveSource,error){
	if strings.TrimSpace(config.InstallationID)==""||len(config.Accounts)==0||config.Artifacts==nil{return nil,ErrInvalid}
	if config.Limits.MaximumEntries==0{config.Limits.MaximumEntries=2_000_000};if config.Limits.MaximumExpandedBytes==0{config.Limits.MaximumExpandedBytes=1<<40};if config.Limits.MaximumMetadataBytes==0{config.Limits.MaximumMetadataBytes=64<<20};if config.Limits.MaximumEntries<1||config.Limits.MaximumExpandedBytes<1<<20||config.Limits.MaximumMetadataBytes<1<<20{return nil,ErrInvalid}
	if config.Clock==nil{config.Clock=time.Now}
	accounts:=make(map[string]approvedArchive,len(config.Accounts));for accountID,path:=range config.Accounts{if !validAccountID(accountID)||path==""||!filepath.IsAbs(path)||filepath.Clean(path)!=path{return nil,ErrInvalid};info,err:=os.Lstat(path);if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()&0o022!=0{return nil,ErrDenied};parent,err:=os.Lstat(filepath.Dir(path));if err!=nil||!parent.IsDir()||parent.Mode().Perm()&0o022!=0{return nil,ErrDenied};accounts[accountID]=approvedArchive{accountID:accountID,path:path,identity:info}}
	return &ArchiveSource{installationID:config.InstallationID,accounts:accounts,artifacts:config.Artifacts,limits:config.Limits,clock:config.Clock,secrets:map[SecretRef][]byte{}},nil
}

func(s *ArchiveSource)Close()error{if s==nil{return nil};s.mu.Lock();defer s.mu.Unlock();for ref,value:=range s.secrets{wipe(value);delete(s.secrets,ref)};return nil}

func(s *ArchiveSource)Collect(ctx context.Context,request cyberpanel.CollectRequest)(Snapshot,error){
	if s==nil||ctx==nil||!request.MigrationID.Valid()||!selectionAny(request.Selection){return Snapshot{},ErrInvalid}
	accountIDs,err:=s.selectedAccounts(request.SiteSourceIDs);if err!=nil{return Snapshot{},err}
	snapshot:=Snapshot{InstallationID:s.installationID,ObservedAt:s.clock().UTC()};revisionHash:=sha256.New();newSecrets:=map[SecretRef][]byte{}
	installed:=false;defer func(){if !installed{for ref,value:=range newSecrets{wipe(value);delete(newSecrets,ref)}}}()
	for _,accountID:=range accountIDs{archive:=s.accounts[accountID];accountSnapshot,revision,secrets,err:=s.collectAccount(ctx,archive,request.Selection);if err!=nil{return Snapshot{},err};revisionHash.Write([]byte(accountID+"\x00"+revision+"\x00"));snapshot.Sites=append(snapshot.Sites,accountSnapshot.Sites...);snapshot.Databases=append(snapshot.Databases,accountSnapshot.Databases...);snapshot.DNSZones=append(snapshot.DNSZones,accountSnapshot.DNSZones...);snapshot.MailDomains=append(snapshot.MailDomains,accountSnapshot.MailDomains...);snapshot.Certificates=append(snapshot.Certificates,accountSnapshot.Certificates...);snapshot.Credentials=append(snapshot.Credentials,accountSnapshot.Credentials...);snapshot.Schedules=append(snapshot.Schedules,accountSnapshot.Schedules...);snapshot.Repositories=append(snapshot.Repositories,accountSnapshot.Repositories...);snapshot.Containers=append(snapshot.Containers,accountSnapshot.Containers...);snapshot.BackupPolicies=append(snapshot.BackupPolicies,accountSnapshot.BackupPolicies...);for ref:=range secrets{if _,duplicate:=newSecrets[ref];duplicate{for secretRef,value:=range secrets{wipe(value);delete(secrets,secretRef)};return Snapshot{},ErrInvalid}};for ref,value:=range secrets{newSecrets[ref]=value;delete(secrets,ref)}}
	snapshot.Revision=hex.EncodeToString(revisionHash.Sum(nil));s.mu.Lock();for ref,value:=range s.secrets{wipe(value);delete(s.secrets,ref)};for ref,value:=range newSecrets{s.secrets[ref]=append([]byte(nil),value...);wipe(value)};s.mu.Unlock();installed=true;return snapshot,nil
}

func(s *ArchiveSource)Describe(ctx context.Context,id ArtifactID)(migration.Chunk,error){return s.artifacts.Describe(ctx,id)}
func(s *ArchiveSource)Open(ctx context.Context,id ArtifactID)(io.ReadCloser,error){return s.artifacts.Open(ctx,id)}
func(s *ArchiveSource)ReadSecret(ctx context.Context,ref SecretRef)([]byte,error){if s==nil||ctx==nil||!ref.Valid(){return nil,ErrInvalid};select{case<-ctx.Done():return nil,ctx.Err();default:};s.mu.RLock();value,exists:=s.secrets[ref];if exists{value=append([]byte(nil),value...)};s.mu.RUnlock();if !exists{return nil,migration.ErrNotFound};return value,nil}

func(s *ArchiveSource)selectedAccounts(selected []string)([]string,error){if len(selected)==0{values:=make([]string,0,len(s.accounts));for id:=range s.accounts{values=append(values,id)};sort.Strings(values);return values,nil};set:=map[string]struct{}{};for _,sourceID:=range selected{accountID:=accountFromSourceID(sourceID);if accountID==""||sourceID!=accountID{return nil,ErrDenied};if _,approved:=s.accounts[accountID];!approved{return nil,ErrDenied};set[accountID]=struct{}{}};values:=make([]string,0,len(set));for id:=range set{values=append(values,id)};sort.Strings(values);return values,nil}

type archiveIndex struct { entries []archiveEntry; metadata map[string][]byte; revision string }
type archiveEntry struct { logicalName string; typeflag byte; size int64; mode int64; linkname string }

func(s *ArchiveSource)collectAccount(ctx context.Context,archive approvedArchive,selection ResourceSelection)(Snapshot,string,map[SecretRef][]byte,error){
	index,err:=s.indexArchive(ctx,archive);if err!=nil{return Snapshot{},"",nil,err};defer func(){for name,value:=range index.metadata{wipe(value);delete(index.metadata,name)}}();cache:=index.metadata["userdata/cache.json"];if len(cache)==0{return Snapshot{},"",nil,errors.Join(ErrInvalid,errors.New("missing userdata/cache.json"))}
	sites,accountUser,err:=parseUserdataCache(archive.accountID,cache);if err!=nil{return Snapshot{},"",nil,err};snapshot:=Snapshot{Sites:sites};secrets:=map[SecretRef][]byte{}
	keepSecrets:=false;defer func(){if !keepSecrets{for ref,value:=range secrets{wipe(value);delete(secrets,ref)}}}()
	if selection.Sites{for _,site:=range snapshot.Sites{artifactID:=ArtifactID("cpanel-site-content:"+safeOpaque(site.SourceID));prefix:="homedir/"+site.DocumentRootRelative+"/";if site.ParentSourceID==""&&site.DocumentRootRelative=="public_html"{prefix="homedir/public_html/"};source:=&archiveArtifactSource{archive:archive,spec:archiveArtifactSpec{prefix:prefix,tree:true,mediaType:"application/vnd.cyberpanel.migration.site-tree+tar",encryptionDomain:"site-content"},limits:s.limits};if err:=s.artifacts.Register(artifactID,source);err!=nil{return Snapshot{},"",nil,err};for index:=range snapshot.Sites{if snapshot.Sites[index].SourceID==site.SourceID{snapshot.Sites[index].ContentArtifact=artifactID}}}}
	if selection.Databases{snapshot.Databases,err=s.collectDatabases(archive,index,snapshot.Sites,secrets);if err!=nil{return Snapshot{},"",nil,err}}
	if selection.DNS{snapshot.DNSZones,err=collectDNSZones(archive.accountID,index);if err!=nil{return Snapshot{},"",nil,err}}
	if selection.Mail{snapshot.MailDomains,err=s.collectMail(archive,index,snapshot.Sites,secrets);if err!=nil{return Snapshot{},"",nil,err}}
	if selection.Certificates{snapshot.Certificates,err=s.collectCertificates(archive.accountID,index,snapshot.Sites,secrets);if err!=nil{return Snapshot{},"",nil,err}}
	if selection.Schedules{snapshot.Schedules,err=collectCronSchedules(archive.accountID,index,snapshot.Sites);if err!=nil{return Snapshot{},"",nil,err}}
	if selection.Credentials{snapshot.Credentials,err=collectCPanelCredentials(archive.accountID,index,snapshot.Sites,accountUser,secrets);if err!=nil{return Snapshot{},"",nil,err}}
	keepSecrets=true;return snapshot,index.revision,secrets,nil
}

func(s *ArchiveSource)indexArchive(ctx context.Context,archive approvedArchive)(archiveIndex,error){
	reader,closeReader,before,err:=openApprovedArchive(archive);if err!=nil{return archiveIndex{},err};defer closeReader();hash:=sha256.New();index:=archiveIndex{metadata:map[string][]byte{}};seen:=map[string]struct{}{};var entries,total,metadataBytes uint64
	for{select{case<-ctx.Done():return archiveIndex{},ctx.Err();default:};header,err:=reader.Next();if errors.Is(err,io.EOF){break};if err!=nil{return archiveIndex{},err};logical,err:=logicalArchiveName(header.Name);if err!=nil{return archiveIndex{},err};if logical==""{continue};if _,duplicate:=seen[logical];duplicate{return archiveIndex{},ErrInvalid};seen[logical]=struct{}{};entries++;if entries>s.limits.MaximumEntries{return archiveIndex{},migration.ErrCapacity};if header.Size<0||header.Mode<0||header.Mode&0o6000!=0{return archiveIndex{},ErrInvalid};switch header.Typeflag{case tar.TypeReg,tar.TypeRegA,tar.TypeDir:case tar.TypeSymlink:if !safeArchiveSymlink(logical,header.Linkname){return archiveIndex{},ErrDenied};default:return archiveIndex{},ErrDenied};if uint64(header.Size)>s.limits.MaximumExpandedBytes-total{return archiveIndex{},migration.ErrCapacity};total+=uint64(header.Size);entry:=archiveEntry{logicalName:logical,typeflag:header.Typeflag,size:header.Size,mode:header.Mode,linkname:header.Linkname};index.entries=append(index.entries,entry);hash.Write([]byte(logical));hash.Write([]byte{0,header.Typeflag});hash.Write([]byte(strconv.FormatInt(header.Size,10)));if metadataArchiveEntry(logical,header.Typeflag){if uint64(header.Size)>s.limits.MaximumMetadataBytes-metadataBytes{return archiveIndex{},migration.ErrCapacity};value,readErr:=io.ReadAll(io.LimitReader(reader,header.Size+1));if readErr!=nil||int64(len(value))!=header.Size{return archiveIndex{},errors.Join(readErr,io.ErrUnexpectedEOF)};metadataBytes+=uint64(len(value));index.metadata[logical]=value;sum:=sha256.Sum256(value);hash.Write(sum[:])}}
	final,err:=os.Lstat(archive.path);if err!=nil||!sameFileSnapshot(before,final){return archiveIndex{},ErrArchiveChanged};index.revision=hex.EncodeToString(hash.Sum(nil));return index,nil
}

func openApprovedArchive(archive approvedArchive)(*tar.Reader,func()error,os.FileInfo,error){before,err:=os.Lstat(archive.path);if err!=nil||!before.Mode().IsRegular()||before.Mode().Perm()&0o022!=0||archive.identity==nil||!sameFileSnapshot(archive.identity,before){return nil,nil,nil,ErrDenied};file,err:=os.Open(archive.path);if err!=nil{return nil,nil,nil,err};after,err:=file.Stat();if err!=nil||!sameFileSnapshot(before,after)||!after.Mode().IsRegular(){file.Close();return nil,nil,nil,ErrArchiveChanged};gzipReader,zipErr:=gzip.NewReader(file);if zipErr==nil{return tar.NewReader(gzipReader),func()error{return errors.Join(gzipReader.Close(),file.Close())},before,nil};if _,err:=file.Seek(0,io.SeekStart);err!=nil{file.Close();return nil,nil,nil,err};return tar.NewReader(file),file.Close,before,nil}

func sameFileSnapshot(left,right os.FileInfo)bool{return left!=nil&&right!=nil&&os.SameFile(left,right)&&left.Size()==right.Size()&&left.ModTime().Equal(right.ModTime())}

func logicalArchiveName(value string)(string,error){if value==""||len(value)>8192||strings.ContainsRune(value,'\x00')||strings.Contains(value,"\\")||strings.HasPrefix(value,"/"){return "",ErrInvalid};for _,part:=range strings.Split(value,"/"){if part==".."||len(part)>255{return "",ErrInvalid}};clean:=filepath.ToSlash(filepath.Clean(value));if clean=="."{return "",nil};if clean==".."||strings.HasPrefix(clean,"../"){return "",ErrInvalid};parts:=strings.Split(clean,"/");if len(parts)>128{return "",ErrInvalid};for index,part:=range parts{switch part{case"userdata","homedir","mysql","dnszones","cron","apache_tls":return strings.Join(parts[index:],"/"),nil;case"mysql.sql":return strings.Join(parts[index:],"/"),nil}};return "",nil}

func safeArchiveSymlink(logical,target string)bool{if target==""||len(target)>4096||strings.ContainsRune(target,'\x00')||strings.Contains(target,"\\")||filepath.IsAbs(target){return false};for _,part:=range strings.Split(filepath.ToSlash(target),"/"){if len(part)>255{return false}};resolved:=filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(logical),filepath.FromSlash(target))));if resolved==".."||strings.HasPrefix(resolved,"../")||strings.HasPrefix(resolved,"/"){return false};root:=strings.SplitN(logical,"/",2)[0];return resolved==root||strings.HasPrefix(resolved,root+"/")}

func metadataArchiveEntry(name string,typeflag byte)bool{if typeflag!=tar.TypeReg&&typeflag!=tar.TypeRegA{return false};if name=="userdata/cache.json"||name=="mysql.sql"{return true};if strings.HasPrefix(name,"userdata/")||strings.HasPrefix(name,"dnszones/")||strings.HasPrefix(name,"cron/")||strings.HasPrefix(name,"apache_tls/"){return true};if strings.HasPrefix(name,"homedir/etc/")&&strings.HasSuffix(name,"/shadow"){return true};if name=="homedir/mail/mailbox_format.cpanel"||name=="homedir/.ssh/authorized_keys"||name=="homedir/.ssh/authorized_keys2"{return true};return false}

func validAccountID(value string)bool{if !strings.HasPrefix(value,"account:")||len(value)<11||len(value)>120{return false};for _,character:=range strings.TrimPrefix(value,"account:"){if(character<'a'||character>'z')&&(character<'0'||character>'9')&&character!='-'&&character!='_'&&character!='.'{return false}};return true}
func accountFromSourceID(value string)string{parts:=strings.Split(value,":");if len(parts)<2||parts[0]!="account"{return ""};candidate:="account:"+parts[1];if !validAccountID(candidate){return ""};return candidate}

type cacheValue []json.RawMessage
func parseUserdataCache(accountID string,raw []byte)([]cyberpanel.SiteRecord,string,error){decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.UseNumber();var values map[string]cacheValue;if err:=decoder.Decode(&values);err!=nil{return nil,"",ErrInvalid};var trailing any;if err:=decoder.Decode(&trailing);!errors.Is(err,io.EOF){return nil,"",ErrInvalid};keys:=make([]string,0,len(values));for key:=range values{keys=append(keys,key)};sort.Strings(keys);sites:=[]cyberpanel.SiteRecord{};accountUser:="";mainID:=accountID;mainHostname:="";for _,key:=range keys{value:=values[key];kind:=cacheString(value,2);domain:=normalizeHostname(firstNonEmpty(cacheString(value,3),key));if domain==""{return nil,"",ErrInvalid};if kind!="main"{continue};if mainHostname!=""{return nil,"",ErrInvalid};username:=cacheString(value,0);accountUser=username;mainHostname=domain;relative,ok:=cpanelDocumentRoot(username,cacheString(value,4));if !ok{relative="public_html"};sites=append(sites,cyberpanel.SiteRecord{SourceID:mainID,PrimaryHostname:domain,PHPVersion:normalizePHP(cacheString(value,9)),DocumentRootRelative:relative,RuntimeKind:"php_lsapi",RuntimeUser:accountUser,Enabled:true})}
	if mainHostname==""{return nil,"",ErrInvalid};for _,key:=range keys{value:=values[key];if cacheString(value,2)=="main"{continue};domain:=normalizeHostname(firstNonEmpty(cacheString(value,3),key));username:=firstNonEmpty(cacheString(value,0),accountUser);relative,ok:=cpanelDocumentRoot(username,cacheString(value,4));if !ok{relative="public_html/"+safeOpaque(domain)};sites=append(sites,cyberpanel.SiteRecord{SourceID:"cpanel-domain:"+safeOpaque(accountID)+":"+safeOpaque(domain),ParentSourceID:mainID,PrimaryHostname:domain,PHPVersion:normalizePHP(cacheString(value,9)),DocumentRootRelative:relative,RuntimeKind:"php_lsapi",RuntimeUser:accountUser,Enabled:true});sites[0].ChildHostnames=append(sites[0].ChildHostnames,domain)};sort.Slice(sites,func(i,j int)bool{return sites[i].SourceID<sites[j].SourceID});return sites,accountUser,nil}
func cacheString(value cacheValue,index int)string{if index<0||index>=len(value){return ""};var output string;if err:=json.Unmarshal(value[index],&output);err==nil{return strings.TrimSpace(output)};return ""}
func cpanelDocumentRoot(username,path string)(string,bool){path=filepath.ToSlash(filepath.Clean(path));prefixes:=[]string{"/home/"+username+"/","/home2/"+username+"/"};for _,prefix:=range prefixes{if strings.HasPrefix(path,prefix){relative:=strings.Trim(strings.TrimPrefix(path,prefix),"/");if relative!=""&&!strings.Contains(relative,".."){return relative,true}}};return "",false}
func normalizePHP(value string)string{value=strings.ToLower(strings.TrimSpace(value));if value==""||value=="inherit"{return"8.3"};digits:=[]rune{};for _,character:=range value{if character>='0'&&character<='9'{digits=append(digits,character)}};if len(digits)>=2{return string(digits[0])+"."+string(digits[1:])};return value}
func normalizeHostname(value string)string{return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)),".")}
func firstNonEmpty(values ...string)string{for _,value:=range values{if strings.TrimSpace(value)!=""{return value}};return ""}
func safeOpaque(value string)string{canonical:=strings.TrimSpace(value);normalized:=strings.ToLower(canonical);var output strings.Builder;for _,character:=range normalized{if(character>='a'&&character<='z')||(character>='0'&&character<='9')||character=='.'||character=='@'||character=='-'||character=='_'{output.WriteRune(character)}else{output.WriteByte('-')}};slug:=strings.Trim(output.String(),"-.");if len(slug)>48{slug=slug[:48]};if len(slug)<3{slug="id"};sum:=sha256.Sum256([]byte(canonical));return slug+"-"+hex.EncodeToString(sum[:16])}
func selectionAny(value ResourceSelection)bool{return value.Sites||value.Databases||value.DNS||value.Mail||value.Certificates||value.Credentials||value.Schedules||value.Repositories||value.Containers||value.BackupPolicies}
func wipe(value []byte){for index:=range value{value[index]=0}}

var _ cyberpanel.Collector=(*ArchiveSource)(nil)
var _ cyberpanel.ArtifactCatalog=(*ArchiveSource)(nil)
var _ cyberpanel.SecretSource=(*ArchiveSource)(nil)
