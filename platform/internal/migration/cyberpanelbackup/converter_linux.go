//go:build linux

package cyberpanelbackup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	legacy "github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanel"
)

const (
	DefaultRawArtifactPath = "/var/lib/cyberpanel/migration/cyberpanel-backup-raw"
	DefaultConverterStatePath = "/var/lib/cyberpanel/migration/cyberpanel-backup-converter"
	DefaultConverterSocketPath = "/run/cyberpanel-backup-convert/converter.sock"
	DefaultConverterConfigPath = "/etc/cyberpanel/cyberpanel-backup-convert.json"
	DefaultSigningKeyPath = "/run/credentials/cyberpanel-backup-convert.service/manifest-signing.key"
	DefaultSealingKeyPath = "/run/credentials/cyberpanel-backup-convert.service/target-sealing-public.key"
	ConverterProtocolVersion uint32 = 1
	maximumConverterFrame = 16 << 10
	maximumConversionTime = 15 * time.Minute
	maximumConvertedChunkBytes = uint64(64 << 30)
)

type ConverterConfig struct {
	TargetInstallationID string `json:"target_installation_id"`
	ManifestSigningKeyID string `json:"manifest_signing_key_id"`
	TargetSealingKeyID string `json:"target_sealing_key_id"`
	MaximumConcurrent uint8 `json:"maximum_concurrent"`
}

type ConvertRequest struct {
	Version uint32 `json:"version"`
	RequestID string `json:"request_id"`
	ArtifactID string `json:"artifact_id"`
	TenantID string `json:"tenant_id"`
	TargetInstallationID string `json:"target_installation_id"`
	Deadline time.Time `json:"deadline"`
}
type ConvertResponse struct {
	Version uint32 `json:"version"`
	RequestID string `json:"request_id"`
	Succeeded bool `json:"succeeded"`
	MigrationID migration.ID `json:"migration_id,omitempty"`
	BundleEndpoint string `json:"bundle_endpoint,omitempty"`
	ManifestRoot string `json:"manifest_root,omitempty"`
	EvidenceDigest string `json:"evidence_digest,omitempty"`
	Failure string `json:"failure,omitempty"`
}
type Conversion struct { MigrationID migration.ID; BundleEndpoint,ManifestRoot,EvidenceDigest string }

type conversionReceipt struct {
	Version uint32 `json:"version"`; RequestDigest string `json:"request_digest"`; ArtifactID string `json:"artifact_id"`; TenantID string `json:"tenant_id"`; TargetInstallationID string `json:"target_installation_id"`
	ArchiveDigest string `json:"archive_digest"`; MigrationID migration.ID `json:"migration_id"`; ManifestRoot string `json:"manifest_root"`; EvidenceDigest string `json:"evidence_digest"`; PublishedAt time.Time `json:"published_at"`
}

type Converter struct {
	config ConverterConfig
	signingKey ed25519.PrivateKey
	sealer *legacy.X25519Sealer
	verifier migration.ManifestVerifier
	clock func() time.Time
	mu sync.Mutex
}

func LoadConverterConfig(value string)(ConverterConfig,error){raw,_,err:=readOwnedConfig(value,1<<20);if err!=nil{return ConverterConfig{},err};decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();var config ConverterConfig;if err=decoder.Decode(&config);err!=nil{return ConverterConfig{},migration.ErrInvalid};if err=decoder.Decode(&struct{}{});!errors.Is(err,io.EOF){return ConverterConfig{},migration.ErrInvalid};return normalizeConverterConfig(config)}
func LoadProvisionedConverterKeys()(ed25519.PrivateKey,[]byte,error){signing,err:=readHexCredential(DefaultSigningKeyPath,ed25519.PrivateKeySize);if err!=nil{return nil,nil,err};sealing,err:=readHexCredential(DefaultSealingKeyPath,32);if err!=nil{wipe(signing);return nil,nil,err};return ed25519.PrivateKey(signing),sealing,nil}

func NewConverter(config ConverterConfig, signingKey ed25519.PrivateKey, targetPublicKey []byte)(*Converter,error){config,err:=normalizeConverterConfig(config);if err!=nil||len(signingKey)!=ed25519.PrivateKeySize||len(targetPublicKey)!=32{return nil,migration.ErrInvalid};if err=validateConverterRoots();err!=nil{return nil,err};sealer,err:=legacy.NewX25519Sealer(config.TargetSealingKeyID,targetPublicKey);if err!=nil{return nil,err};publicKey:=append(ed25519.PublicKey(nil),signingKey.Public().(ed25519.PublicKey)...);verifier,err:=migration.NewSignedManifestVerifier(migration.ManifestTrustPolicy{TargetInstallationID:config.TargetInstallationID,SchemaHashes:map[string]struct{}{legacy.CanonicalManifestSchemaHash():{}},Keys:map[string]ed25519.PublicKey{config.ManifestSigningKeyID:publicKey}});if err!=nil{return nil,err};return &Converter{config:config,signingKey:append(ed25519.PrivateKey(nil),signingKey...),sealer:sealer,verifier:verifier,clock:time.Now},nil}

func (converter *Converter) Convert(ctx context.Context, request ConvertRequest)(Conversion,error){
	if converter==nil||ctx==nil||request.validate(converter.clock().UTC(),converter.config.TargetInstallationID)!=nil{return Conversion{},migration.ErrInvalid};ctx,cancel:=context.WithDeadline(ctx,request.Deadline);defer cancel();converter.mu.Lock();defer converter.mu.Unlock();if len(converter.signingKey)!=ed25519.PrivateKeySize{return Conversion{},migration.ErrBlocked}
	rawPath:=filepath.Join(DefaultRawArtifactPath,request.ArtifactID+".tar.gz");index,metadata,err:=auditArchive(ctx,rawPath);if err!=nil{return Conversion{},err};defer metadata.clearSecrets();defer index.clearMetadata()
	requestDigest:=conversionRequestDigest(request);migrationID:=conversionMigrationID(request,index.digest);publishedPath:=filepath.Join(DefaultIntakePath,migrationID.String());receiptPath:=filepath.Join(DefaultConverterStatePath,"receipts",digestText(request.TenantID+"\x00"+request.RequestID)+".json")
	if receipt,readErr:=readConversionReceipt(receiptPath);readErr==nil{return converter.resumeReceipt(ctx,request,index,receipt,publishedPath)}else if !errors.Is(readErr,os.ErrNotExist){return Conversion{},readErr}
	if info,statErr:=os.Lstat(publishedPath);statErr==nil{if !ownedDirectory(info){return Conversion{},migration.ErrAmbiguous};return converter.recoverPublished(ctx,request,index,migrationID,requestDigest,publishedPath,receiptPath)}else if !errors.Is(statErr,os.ErrNotExist){return Conversion{},statErr}
	jobPath:=filepath.Join(DefaultConverterStatePath,"jobs",requestDigest);bundlePath:=filepath.Join(jobPath,"bundle")
	if info,statErr:=os.Lstat(jobPath);statErr==nil{if !ownedDirectory(info){return Conversion{},migration.ErrAmbiguous};manifest,verifyErr:=converter.verifyBundle(ctx,bundlePath);if verifyErr==nil&&manifest.MigrationID==migrationID{return converter.publish(ctx,request,index,requestDigest,jobPath,bundlePath,publishedPath,receiptPath,manifest)};if err=ctx.Err();err!=nil{return Conversion{},err};if err=discardIncompleteJob(jobPath);err!=nil{return Conversion{},err}}else if !errors.Is(statErr,os.ErrNotExist){return Conversion{},statErr}
	if err=os.Mkdir(jobPath,0o700);err!=nil{return Conversion{},err};if err=os.Mkdir(bundlePath,0o700);err!=nil{return Conversion{},err}
	manifest,err:=converter.buildBundle(ctx,request,index,metadata,rawPath,jobPath,bundlePath,migrationID);if err!=nil{return Conversion{},err}
	verified,err:=converter.verifyBundle(ctx,bundlePath);if err!=nil||verified.MerkleRoot!=manifest.MerkleRoot||verified.MigrationID!=migrationID{return Conversion{},errors.Join(migration.ErrAmbiguous,err)}
	return converter.publish(ctx,request,index,requestDigest,jobPath,bundlePath,publishedPath,receiptPath,verified)
}

func (converter *Converter) publish(ctx context.Context,request ConvertRequest,index archiveIndex,requestDigest,jobPath,bundlePath,publishedPath,receiptPath string,manifest migration.Manifest)(Conversion,error){if err:=ctx.Err();err!=nil{return Conversion{},err};if err:=os.Rename(bundlePath,publishedPath);err!=nil{return Conversion{},err};if err:=syncDirectory(DefaultIntakePath);err!=nil{return Conversion{},errors.Join(migration.ErrAmbiguous,err)};_ = os.Remove(jobPath);evidence:=digestText("cyberpanel-backup-conversion-v1\x00"+requestDigest+"\x00"+index.digest+"\x00"+manifest.MerkleRoot);receipt:=conversionReceipt{Version:1,RequestDigest:requestDigest,ArtifactID:request.ArtifactID,TenantID:request.TenantID,TargetInstallationID:request.TargetInstallationID,ArchiveDigest:index.digest,MigrationID:manifest.MigrationID,ManifestRoot:manifest.MerkleRoot,EvidenceDigest:evidence,PublishedAt:converter.clock().UTC()};if err:=writeConversionReceipt(receiptPath,receipt);err!=nil{return Conversion{},errors.Join(migration.ErrAmbiguous,err)};return receipt.conversion(),nil}
func (converter *Converter) recoverPublished(ctx context.Context,request ConvertRequest,index archiveIndex,migrationID migration.ID,requestDigest,publishedPath,receiptPath string)(Conversion,error){manifest,err:=converter.verifyBundle(ctx,publishedPath);if err!=nil||manifest.MigrationID!=migrationID{return Conversion{},errors.Join(migration.ErrAmbiguous,err)};evidence:=digestText("cyberpanel-backup-conversion-v1\x00"+requestDigest+"\x00"+index.digest+"\x00"+manifest.MerkleRoot);receipt:=conversionReceipt{Version:1,RequestDigest:requestDigest,ArtifactID:request.ArtifactID,TenantID:request.TenantID,TargetInstallationID:request.TargetInstallationID,ArchiveDigest:index.digest,MigrationID:migrationID,ManifestRoot:manifest.MerkleRoot,EvidenceDigest:evidence,PublishedAt:converter.clock().UTC()};if err=writeConversionReceipt(receiptPath,receipt);err!=nil{return Conversion{},errors.Join(migration.ErrAmbiguous,err)};return receipt.conversion(),nil}
func (converter *Converter) resumeReceipt(ctx context.Context,request ConvertRequest,index archiveIndex,receipt conversionReceipt,publishedPath string)(Conversion,error){
	if receipt.validate(request,index.digest,conversionRequestDigest(request))!=nil{return Conversion{},migration.ErrConflict}
	manifest,err:=converter.verifyBundle(ctx,publishedPath)
	if errors.Is(err,os.ErrNotExist){
		claim:=filepath.Join(DefaultQuarantinePath,receipt.ManifestRoot);admission,readErr:=readReceipt(filepath.Join(claim,"admission.json"))
		if readErr!=nil||admission.TenantID!=request.TenantID||admission.MigrationID!=receipt.MigrationID||admission.ManifestRoot!=receipt.ManifestRoot||admission.SourcePathDigest!=pathDigest(publishedPath){return Conversion{},errors.Join(migration.ErrAmbiguous,readErr)}
		publishedPath=filepath.Join(claim,"bundle");manifest,err=converter.verifyBundle(ctx,publishedPath)
	}
	if err!=nil||manifest.MigrationID!=receipt.MigrationID||manifest.MerkleRoot!=receipt.ManifestRoot{return Conversion{},errors.Join(migration.ErrAmbiguous,err)}
	result:=receipt.conversion();result.BundleEndpoint=fileEndpoint(publishedPath);return result,nil
}
func (converter *Converter) verifyBundle(ctx context.Context,value string)(migration.Manifest,error){intake:=&Intake{verifier:converter.verifier,clock:converter.clock};bundle,err:=intake.verifyBundle(ctx,value);if err!=nil{return migration.Manifest{},err};return bundle.manifest,nil}

type chunkArtifacts struct{site migration.Chunk;mail *migration.Chunk;direct map[string]migration.Chunk}
type treeArtifact struct{path string;file *os.File;writer *tar.Writer;digest hash.Hash;objects uint64}
type limitedChunkWriter struct{writer io.Writer;remaining uint64}
func (writer *limitedChunkWriter) Write(value []byte)(int,error){if uint64(len(value))>writer.remaining{return 0,migration.ErrCapacity};count,err:=writer.writer.Write(value);writer.remaining-=uint64(count);return count,err}
func newTreeArtifact(value string)(*treeArtifact,error){file,err:=os.OpenFile(value,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0o600);if err!=nil{return nil,err};digest:=sha256.New();bounded:=&limitedChunkWriter{writer:file,remaining:maximumConvertedChunkBytes};return &treeArtifact{path:value,file:file,writer:tar.NewWriter(io.MultiWriter(bounded,digest)),digest:digest},nil}
func (artifact *treeArtifact) addHeader(header *tar.Header,prefix string)error{relative:=strings.TrimPrefix(header.Name,"./");relative=strings.TrimSuffix(relative,"/");if relative==prefix{return nil};relative=strings.TrimPrefix(relative,prefix+"/");if relative==""{return migration.ErrInvalid};canonical:=&tar.Header{Name:relative,Mode:header.Mode&0o777,Typeflag:header.Typeflag,Size:header.Size,Linkname:header.Linkname,ModTime:time.Unix(0,0).UTC(),Format:tar.FormatPAX};if header.Typeflag==tar.TypeDir{canonical.Name+="/"};if err:=artifact.writer.WriteHeader(canonical);err!=nil{return err};artifact.objects++;return nil}
func (artifact *treeArtifact) addRegular(ctx context.Context,header *tar.Header,prefix string,source io.Reader)(string,error){if err:=artifact.addHeader(header,prefix);err!=nil{return "",err};digest:=sha256.New();written,err:=copyContext(ctx,io.MultiWriter(artifact.writer,digest),source);if err!=nil||written!=header.Size{return "",errors.Join(migration.ErrInvalid,err)};return hex.EncodeToString(digest.Sum(nil)),nil}
func (artifact *treeArtifact) finish(ctx context.Context,store *migration.ChunkStore,mediaType,domain string)(migration.Chunk,error){if err:=artifact.writer.Close();err!=nil{artifact.file.Close();return migration.Chunk{},err};if err:=artifact.file.Sync();err!=nil{artifact.file.Close();return migration.Chunk{},err};if err:=artifact.file.Chmod(0o400);err!=nil{artifact.file.Close();return migration.Chunk{},err};if err:=artifact.file.Close();err!=nil{return migration.Chunk{},err};info,err:=os.Lstat(artifact.path);if err!=nil||!ownedFile(info)||info.Size()<=0{return migration.Chunk{},errors.Join(migration.ErrInvalid,err)};descriptor:=migration.Chunk{Digest:hex.EncodeToString(artifact.digest.Sum(nil)),Size:uint64(info.Size()),MediaType:mediaType,Compression:"tar",EncryptionDomain:domain,ObjectCount:artifact.objects+1};source,err:=os.Open(artifact.path);if err!=nil{return migration.Chunk{},err};err=store.Put(ctx,descriptor,source);err=errors.Join(err,source.Close());if err==nil{err=os.Remove(artifact.path)};return descriptor,err}
func (artifact *treeArtifact) abort(){if artifact==nil{return};if artifact.writer!=nil{_ = artifact.writer.Close()};if artifact.file!=nil{_ = artifact.file.Close()}}

func (converter *Converter) buildBundle(ctx context.Context,request ConvertRequest,index archiveIndex,metadata backupMetadata,rawPath,jobPath,bundlePath string,migrationID migration.ID)(migration.Manifest,error){if err:=copyRawArtifact(ctx,rawPath,filepath.Join(bundlePath,"source.tar.gz"),index.digest);err!=nil{return migration.Manifest{},err};chunksPath:=filepath.Join(bundlePath,"chunks");if err:=os.Mkdir(chunksPath,0o700);err!=nil{return migration.Manifest{},err};store,err:=migration.OpenChunkStore(chunksPath,maximumConvertedChunkBytes);if err!=nil{return migration.Manifest{},err};artifacts,err:=materializeArchive(ctx,rawPath,index,jobPath,store);if err!=nil{store.Close();return migration.Manifest{},err};manifest,err:=converter.makeManifest(ctx,request,index,metadata,migrationID,artifacts);if err==nil{manifest,err=migration.SignManifest(manifest,converter.config.ManifestSigningKeyID,converter.signingKey)};err=errors.Join(err,store.Close());if err!=nil{return migration.Manifest{},err};if err=writeCanonicalManifest(filepath.Join(bundlePath,migrationID.String()+".manifest.json"),manifest);err!=nil{return migration.Manifest{},err};if err=syncDirectory(bundlePath);err!=nil{return migration.Manifest{},err};return manifest,nil}

func materializeArchive(ctx context.Context,rawPath string,index archiveIndex,jobPath string,store *migration.ChunkStore)(chunkArtifacts,error){result:=chunkArtifacts{direct:map[string]migration.Chunk{}};site,err:=newTreeArtifact(filepath.Join(jobPath,"site-content.tar"));if err!=nil{return result,err};defer site.abort();var mail *treeArtifact;if _,present:=index.directories["vmail"];present{mail,err=newTreeArtifact(filepath.Join(jobPath,"mail-data.tar"));if err!=nil{return result,err};defer mail.abort()}
	before,err:=os.Lstat(rawPath);if err!=nil||!trustedArchiveFile(before){return result,errors.Join(migration.ErrBlocked,err)};file,err:=os.Open(rawPath);if err!=nil{return result,err};defer file.Close();opened,err:=file.Stat();if err!=nil||!sameArchiveFile(before,opened){return result,errors.Join(migration.ErrConflict,err)};rawHash:=sha256.New();buffered:=bufio.NewReader(io.TeeReader(file,rawHash));gzipReader,err:=gzip.NewReader(buffered);if err!=nil{return result,migration.ErrInvalid};if gzipReader.Name!=""||gzipReader.Comment!=""||len(gzipReader.Extra)!=0{gzipReader.Close();return result,migration.ErrInvalid};gzipReader.Multistream(false);expanded:=&boundedExpandedReader{source:gzipReader};reader:=tar.NewReader(expanded);seen:=map[string]struct{}{};entries:=0
	for{if err=ctx.Err();err!=nil{gzipReader.Close();return result,err};header,nextErr:=reader.Next();if errors.Is(nextErr,io.EOF){break};if nextErr!=nil{gzipReader.Close();return result,migration.ErrInvalid};entries++;if entries>maximumArchiveEntries||header==nil||header.Size<0||header.Mode&0o7000!=0||len(header.PAXRecords)!=0||len(header.Xattrs)!=0{gzipReader.Close();return result,migration.ErrCapacity};name,nameErr:=archiveName(header.Name);if nameErr!=nil||!allowedMember(name){gzipReader.Close();return result,migration.ErrInvalid};if _,duplicate:=seen[name];duplicate{gzipReader.Close();return result,migration.ErrInvalid};seen[name]=struct{}{}
		switch header.Typeflag{case tar.TypeDir:if _,expected:=index.directories[name];!expected||header.Size!=0{return result,migration.ErrConflict};if strings.HasPrefix(name,"public_html"){if err=site.addHeader(header,"public_html");err!=nil{return result,err}}else if mail!=nil&&strings.HasPrefix(name,"vmail"){if err=mail.addHeader(header,"vmail");err!=nil{return result,err}}
		case tar.TypeSymlink:if index.links[name]!=header.Linkname||header.Size!=0||!safeArchiveLink(name,header.Linkname){return result,migration.ErrConflict};if strings.HasPrefix(name,"public_html/"){if err=site.addHeader(header,"public_html");err!=nil{return result,err}}else if mail!=nil&&strings.HasPrefix(name,"vmail/"){if err=mail.addHeader(header,"vmail");err!=nil{return result,err}}
		case tar.TypeReg,tar.TypeRegA:evidence,expected:=index.files[name];if !expected||uint64(header.Size)!=evidence.size{return result,migration.ErrConflict};var digest string;if strings.HasPrefix(name,"public_html/"){digest,err=site.addRegular(ctx,header,"public_html",reader)}else if mail!=nil&&strings.HasPrefix(name,"vmail/"){digest,err=mail.addRegular(ctx,header,"vmail",reader)}else if descriptor,material:=directChunk(name,evidence);material{hashValue:=sha256.New();err=store.Put(ctx,descriptor,io.TeeReader(reader,hashValue));if err==nil{_,err=copyContext(ctx,hashValue,reader)};digest=hex.EncodeToString(hashValue.Sum(nil));result.direct[name]=descriptor}else{hashValue:=sha256.New();_,err=copyContext(ctx,hashValue,reader);digest=hex.EncodeToString(hashValue.Sum(nil))};if err!=nil||digest!=evidence.digest{return result,errors.Join(migration.ErrConflict,err)}
		default:return result,migration.ErrBlocked}}
	_,drainErr:=copyContext(ctx,io.Discard,expanded);closeErr:=gzipReader.Close();_,trailingErr:=buffered.Peek(1);if errors.Is(trailingErr,io.EOF){trailingErr=nil}else{trailingErr=migration.ErrInvalid};final,statErr:=file.Stat();if drainErr!=nil||closeErr!=nil||trailingErr!=nil||statErr!=nil||!sameArchiveFile(opened,final)||hex.EncodeToString(rawHash.Sum(nil))!=index.digest||len(seen)!=len(index.files)+len(index.directories)+len(index.links){return result,errors.Join(migration.ErrConflict,drainErr,closeErr,trailingErr,statErr)}
	result.site,err=site.finish(ctx,store,"application/vnd.cyberpanel.migration.directory+tar","site-content");if err!=nil{return result,err};site=nil;if mail!=nil{value,finishErr:=mail.finish(ctx,store,"application/vnd.cyberpanel.migration.maildir+tar","mail-data");if finishErr!=nil{return result,finishErr};result.mail=&value;mail=nil};return result,nil}

func directChunk(name string,evidence fileEvidence)(migration.Chunk,bool){descriptor:=migration.Chunk{Digest:evidence.digest,Size:evidence.size,Compression:"identity",ObjectCount:1};switch{case strings.HasSuffix(name,".sql.gz"):descriptor.MediaType="application/sql";descriptor.Compression="gzip";descriptor.EncryptionDomain="database-dump";return descriptor,true;case strings.HasSuffix(name,".sql"):descriptor.MediaType="application/sql";descriptor.EncryptionDomain="database-dump";return descriptor,true;case strings.HasSuffix(name,".cert.pem")||strings.HasSuffix(name,".fullchain.pem"):descriptor.MediaType="application/pem-certificate-chain";descriptor.EncryptionDomain="certificate-public";return descriptor,true};return migration.Chunk{},false}

// makeManifest maps evidence, never source authority. Admin hashes and tokens
// are deliberately absent; legacy cron invocations are inert identifiers.
func (converter *Converter) makeManifest(ctx context.Context, request ConvertRequest, index archiveIndex, metadata backupMetadata, id migration.ID, artifacts chunkArtifacts) (migration.Manifest, error) {
	manifest := migration.Manifest{SchemaVersion:1, MigrationID:id, Source:migration.SourceCyberPanelBackup, SourceInstallationID:installationID(metadata.MasterDomain,schemaFingerprint(metadata)), TargetInstallationID:request.TargetInstallationID, SourceGeneration:index.generation, CreatedAt:converter.clock().UTC(), SchemaHash:legacy.CanonicalManifestSchemaHash()}
	if err:=validateArchiveMembers(index,metadata);err!=nil{return manifest,err}
	objectID:=func(kind, value string)migration.ID{return migration.ID(kind+"_"+digestText(id.String()+"\x00"+kind+"\x00"+value)[:32])}
	provenance:=func(location string)[]migration.Provenance{return []migration.Provenance{{SourceKind:string(migration.SourceCyberPanelBackup),SourceLocation:"cyberpanel_backup:"+location,ExtractorVersion:"cyberpanel-backup-intake-v1:"+schemaFingerprint(metadata),ObservedAt:manifest.CreatedAt,Digest:index.digest,Confidence:"authoritative",Authoritative:true}}}
	seal:=func(purpose,locator string,plaintext []byte)(string,error){
		if len(plaintext)==0||len(plaintext)>900<<10{return "",migration.ErrCapacity}
		material:=legacy.SecretMaterial{Ref:legacy.SecretRef("backup_"+digestText(purpose+"\x00"+locator)[:32]),Purpose:purpose,AudienceDigest:audienceDigest(manifest,purpose,locator)}
		envelope,err:=converter.sealer.Seal(ctx,id,material,plaintext);if err!=nil{return "",err};manifest.Secrets=append(manifest.Secrets,envelope);return envelope.SecretID,nil
	}
	mainID:=objectID("site",metadata.MasterDomain)
	main:=migration.Site{SourceID:mainID,PrimaryHostname:metadata.MasterDomain,Aliases:append([]string(nil),metadata.Aliases...),PHPVersion:metadata.PHP,DocumentRootRelative:"public_html",RuntimeKind:"php_lsapi",Content:[]migration.Chunk{artifacts.site},Provenance:provenance("meta.xml:masterDomain")}
	for _,child:=range metadata.Children{main.Children=append(main.Children,child.Domain);manifest.Sites=append(manifest.Sites,migration.Site{SourceID:objectID("site",child.Domain),PrimaryHostname:child.Domain,PHPVersion:child.PHP,DocumentRootRelative:childRelativePath(metadata.MasterDomain,child.Path),RuntimeKind:"php_lsapi",Content:[]migration.Chunk{artifacts.site},Provenance:provenance("meta.xml:ChildDomains:"+child.Domain)})}
	for _,source:=range metadata.Databases{
		evidence,compression,err:=databaseEvidence(index,source.Name);if err!=nil{return manifest,err};name:=source.Name+".sql";if compression=="gzip"{name+=".gz"};chunk,found:=artifacts.direct[name];if !found||chunk.Digest!=evidence.digest{return manifest,migration.ErrInvalid}
		database:=migration.Database{SourceID:objectID("database",source.Name),SiteID:mainID,Name:source.Name,Charset:"utf8mb4",Collation:"utf8mb4_unicode_ci",Dump:[]migration.Chunk{chunk},Provenance:provenance("meta.xml:Databases:"+source.Name)}
		users:=map[string][]backupDatabaseUser{};for _,user:=range source.Users{key:=strings.ToLower(user.Name);users[key]=append(users[key],user)}
		keys:=sortedKeys(users);for _,key:=range keys{values:=users[key];principal:=migration.DatabasePrincipal{Name:values[0].Name,CredentialDisposition:migration.CredentialPreserved};for _,value:=range values{principal.GrantSets=append(principal.GrantSets,"legacy-database-owner@"+value.Host)};sort.Strings(principal.GrantSets);principal.SecretID,err=seal("database-principal","database:"+database.SourceID.String()+":"+principal.Name,values[0].Password);if err!=nil{return manifest,err};database.Principals=append(database.Principals,principal)}
		manifest.Databases=append(manifest.Databases,database);main.DatabaseIDs=append(main.DatabaseIDs,database.SourceID)
	}
	zone:=migration.DNSZone{SourceID:objectID("dns",metadata.MasterDomain),Name:metadata.MasterDomain,Mode:"native",Provenance:provenance("meta.xml:dnsrecords")};sets:=map[string]migration.DNSRecordSet{}
	for _,record:=range metadata.DNS{key:=record.Name+"\x00"+record.Type;set:=sets[key];set.Name=record.Name;set.Type=record.Type;set.TTL=3600;value:=record.Content;if record.Type=="MX"||record.Type=="SRV"{priority,_:=strconv.ParseUint(record.Priority,10,16);value=strconv.FormatUint(priority,10)+" "+value};set.Values=append(set.Values,value);sets[key]=set};for _,key:=range sortedKeys(sets){set:=sets[key];sort.Strings(set.Values);zone.RecordSets=append(zone.RecordSets,set)};manifest.DNSZones=[]migration.DNSZone{zone}
	mail:=migration.MailDomain{SourceID:objectID("mail",metadata.MasterDomain),SiteID:mainID,Name:metadata.MasterDomain,Provenance:provenance("meta.xml:emails")};if artifacts.mail!=nil{mail.MailData=[]migration.Chunk{*artifacts.mail}}
	for _,source:=range metadata.Emails{mailbox:=migration.Mailbox{SourceID:objectID("mailbox",source.Address),Address:source.Address,CredentialDisposition:migration.CredentialPreserved};secretID,err:=seal("mailbox-credential","mailbox:"+mailbox.SourceID.String(),source.Password);if err!=nil{return manifest,err};mailbox.CredentialSecretID=secretID;mail.Mailboxes=append(mail.Mailboxes,mailbox)};manifest.MailDomains=[]migration.MailDomain{mail};main.MailDomainIDs=[]migration.ID{mail.SourceID}
	for _,name:=range sortedKeys(index.files){if !strings.HasSuffix(name,".cert.pem"){continue};host:=strings.TrimSuffix(name,".cert.pem");parsed,err:=firstCertificate(index.metadata[name]);if err!=nil{return manifest,err};key:=index.metadata[host+".privkey.pem"];if err=legacy.ValidatePrivateKeyForCertificate(key,parsed);err!=nil{return manifest,err};names,err:=legacy.ConcreteCertificateNames(parsed,host);if err!=nil{return manifest,err};certificate:=migration.Certificate{SourceID:objectID("certificate",host),Names:names,Certificate:[]migration.Chunk{artifacts.direct[name]},Chain:[]migration.Chunk{artifacts.direct[host+".fullchain.pem"]},Issuer:parsed.Issuer.String(),NotAfter:parsed.NotAfter,Provenance:provenance(name)};certificate.PrivateKeySecretID,err=seal("tls-private-key","certificate:"+certificate.SourceID.String(),key);if err!=nil{return manifest,err};manifest.Certificates=append(manifest.Certificates,certificate)}
	admin:=migration.AccessCredential{SourceID:objectID("credential","admin"),SiteID:mainID,Kind:"legacy-admin",Label:metadata.UserName,RootRelative:"public_html",CredentialDisposition:migration.CredentialResetRequired,Provenance:provenance("meta.xml:userName")};manifest.Credentials=append(manifest.Credentials,admin);main.CredentialIDs=append(main.CredentialIDs,admin.SourceID)
	for _,name:=range []string{"public_html/.ssh/authorized_keys","public_html/.ssh/authorized_keys2"}{if len(index.metadata[name])==0{continue};keys,err:=legacy.ParseAuthorizedKeys(index.metadata[name]);if err!=nil{return manifest,err};for _,key:=range keys{label:=key.Label;if label==""{label=metadata.UserName};credential:=migration.AccessCredential{SourceID:objectID("credential",key.PublicKey),SiteID:mainID,Kind:"ssh-public-key",Label:label,RootRelative:"public_html",PublicKey:key.PublicKey,CredentialDisposition:migration.CredentialPublicOnly,Provenance:provenance(name)};manifest.Credentials=append(manifest.Credentials,credential);main.CredentialIDs=append(main.CredentialIDs,credential.SourceID)}}
	rawCron:=index.metadata["cron"];if len(rawCron)==0{rawCron=index.metadata["crontab"]};schedules,err:=parseCron(rawCron);if err!=nil{return manifest,err};for position,source:=range schedules{schedule:=migration.Schedule{SourceID:objectID("schedule",strconv.Itoa(position)),SiteID:mainID,Kind:"legacy-command",Expression:source.expression,Timezone:source.timezone,InvocationID:source.invocation,Enabled:true,Provenance:provenance("cron:"+strconv.Itoa(position))};manifest.Schedules=append(manifest.Schedules,schedule);main.CronIDs=append(main.CronIDs,schedule.SourceID)}
	manifest.Sites=append([]migration.Site{main},manifest.Sites...)
	catalog:=map[string]migration.Chunk{};add:=func(chunk migration.Chunk)error{if previous,found:=catalog[chunk.Digest];found&&previous!=chunk{return migration.ErrConflict};catalog[chunk.Digest]=chunk;return nil};if err=add(artifacts.site);err!=nil{return manifest,err};if artifacts.mail!=nil{if err=add(*artifacts.mail);err!=nil{return manifest,err}};for _,chunk:=range artifacts.direct{if err=add(chunk);err!=nil{return manifest,err}};for _,digest:=range sortedKeys(catalog){manifest.Chunks=append(manifest.Chunks,catalog[digest])}
	if err=validateMapping(index,metadata,manifest);err!=nil{return manifest,err};return manifest,nil
}

func sortedKeys[T any](values map[string]T)[]string{keys:=make([]string,0,len(values));for key:=range values{keys=append(keys,key)};sort.Strings(keys);return keys}
func digestText(value string)string{sum:=sha256.Sum256([]byte(value));return hex.EncodeToString(sum[:])}
func conversionRequestDigest(request ConvertRequest)string{return digestText("cyberpanel-backup-convert-v1\x00"+request.RequestID+"\x00"+request.ArtifactID+"\x00"+request.TenantID+"\x00"+request.TargetInstallationID)}
func conversionMigrationID(request ConvertRequest,archiveDigest string)migration.ID{return migration.ID("backup_"+digestText(conversionRequestDigest(request)+"\x00"+archiveDigest)[:48])}
func (request ConvertRequest) validate(now time.Time,target string)error{if request.Version!=ConverterProtocolVersion||!migration.ID(request.RequestID).Valid()||!migration.ID(request.ArtifactID).Valid()||!scopeText(request.TenantID)||request.TargetInstallationID!=target||!request.Deadline.After(now)||request.Deadline.After(now.Add(maximumConversionTime)){return migration.ErrInvalid};return nil}
func normalizeConverterConfig(config ConverterConfig)(ConverterConfig,error){if !scopeText(config.TargetInstallationID)||strings.HasPrefix(config.TargetInstallationID,"PROVISION_")||!safeIdentity(config.ManifestSigningKeyID)||!safeIdentity(config.TargetSealingKeyID){return config,migration.ErrInvalid};if config.MaximumConcurrent==0{config.MaximumConcurrent=1};if config.MaximumConcurrent!=1{return config,migration.ErrInvalid};return config,nil}

func validateConverterRoots()error{
	for _,value:=range []string{DefaultConverterStatePath,filepath.Join(DefaultConverterStatePath,"jobs"),filepath.Join(DefaultConverterStatePath,"receipts"),DefaultIntakePath}{if err:=ensureRoot(value);err!=nil{return err}}
	raw,err:=os.Lstat(DefaultRawArtifactPath);stat,ok:=fileStat(raw);if err!=nil||!ok||!raw.IsDir()||stat.Uid!=0||int(stat.Gid)!=os.Getegid()||raw.Mode().Perm()!=0o750{return errors.Join(migration.ErrBlocked,err)};resolved,err:=filepath.EvalSymlinks(DefaultRawArtifactPath);if err!=nil||resolved!=DefaultRawArtifactPath{return migration.ErrBlocked}
	state,err:=os.Lstat(DefaultConverterStatePath);if err!=nil{return err};intake,err:=os.Lstat(DefaultIntakePath);if err!=nil||!sameFilesystem(state,intake){return errors.Join(migration.ErrBlocked,err)};return nil
}

func copyContext(ctx context.Context,destination io.Writer,source io.Reader)(int64,error){buffer:=make([]byte,128<<10);var total int64;for{if err:=ctx.Err();err!=nil{return total,err};count,readErr:=source.Read(buffer);if count>0{if err:=writeAll(destination,buffer[:count]);err!=nil{return total,err};total+=int64(count)};if errors.Is(readErr,io.EOF){return total,nil};if readErr!=nil{return total,readErr};if count==0{return total,io.ErrNoProgress}}}
func copyRawArtifact(ctx context.Context,sourcePath,targetPath,expected string)error{
	before,err:=os.Lstat(sourcePath);if err!=nil||!trustedArchiveFile(before){return errors.Join(migration.ErrBlocked,err)};source,err:=os.Open(sourcePath);if err!=nil{return err};defer source.Close();opened,err:=source.Stat();if err!=nil||!sameArchiveFile(before,opened){return migration.ErrConflict};target,err:=os.OpenFile(targetPath,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0o600);if err!=nil{return err};defer target.Close();digest:=sha256.New();count,err:=copyContext(ctx,io.MultiWriter(target,digest),io.LimitReader(source,maximumCompressedBytes+1));if err!=nil||count!=opened.Size()||hex.EncodeToString(digest.Sum(nil))!=expected{return errors.Join(migration.ErrConflict,err)};final,err:=source.Stat();if err!=nil||!sameArchiveFile(opened,final){return migration.ErrConflict};if err=target.Sync();err!=nil{return err};return target.Chmod(0o400)
}
func writeCanonicalManifest(value string,manifest migration.Manifest)error{raw,err:=json.Marshal(manifest);if err!=nil||int64(len(raw))>=maximumManifestBytes{return errors.Join(migration.ErrCapacity,err)};return writeImmutable(value,append(raw,'\n'))}
func writeImmutable(value string,raw []byte)error{file,err:=os.OpenFile(value,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0o600);if err!=nil{return err};if err=writeAll(file,raw);err==nil{err=file.Chmod(0o400)};if err==nil{err=file.Sync()};return errors.Join(err,file.Close())}
func writeConversionReceipt(value string,receipt conversionReceipt)error{raw,err:=json.Marshal(receipt);if err!=nil{return err};nonce:=make([]byte,16);if _,err=rand.Read(nonce);err!=nil{return err};temporary:=value+"."+hex.EncodeToString(nonce)+".tmp";if err=writeImmutable(temporary,append(raw,'\n'));err!=nil{return err};defer os.Remove(temporary);if _,err=os.Lstat(value);err==nil{return migration.ErrConflict}else if !errors.Is(err,os.ErrNotExist){return err};if err=os.Rename(temporary,value);err!=nil{return err};return syncDirectory(filepath.Dir(value))}
func readConversionReceipt(value string)(conversionReceipt,error){var receipt conversionReceipt;raw,_,err:=readOwnedFile(value,maximumConverterFrame);if err!=nil{return receipt,err};decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();if err=decoder.Decode(&receipt);err!=nil{return receipt,migration.ErrInvalid};if err=decoder.Decode(&struct{}{});!errors.Is(err,io.EOF){return receipt,migration.ErrInvalid};return receipt,nil}
func (receipt conversionReceipt) validate(request ConvertRequest,archiveDigest,requestDigest string)error{if receipt.Version!=1||receipt.RequestDigest!=requestDigest||receipt.ArtifactID!=request.ArtifactID||receipt.TenantID!=request.TenantID||receipt.TargetInstallationID!=request.TargetInstallationID||receipt.ArchiveDigest!=archiveDigest||receipt.MigrationID!=conversionMigrationID(request,archiveDigest)||!isDigest(receipt.ManifestRoot)||receipt.PublishedAt.IsZero()||receipt.EvidenceDigest!=digestText("cyberpanel-backup-conversion-v1\x00"+requestDigest+"\x00"+archiveDigest+"\x00"+receipt.ManifestRoot){return migration.ErrConflict};return nil}
func (receipt conversionReceipt) conversion()Conversion{return Conversion{MigrationID:receipt.MigrationID,BundleEndpoint:fileEndpoint(filepath.Join(DefaultIntakePath,receipt.MigrationID.String())),ManifestRoot:receipt.ManifestRoot,EvidenceDigest:receipt.EvidenceDigest}}

// Only converter-owned scratch below a validated fixed job ID may be discarded.
// Published bundles and receipts are never removed by restart recovery.
func discardIncompleteJob(value string)error{jobs:=filepath.Join(DefaultConverterStatePath,"jobs");if filepath.Dir(value)!=jobs||!isDigest(filepath.Base(value)){return migration.ErrBlocked};if err:=filepath.WalkDir(value,func(_ string,entry os.DirEntry,walkErr error)error{if walkErr!=nil{return walkErr};info,err:=entry.Info();stat,ok:=fileStat(info);if err!=nil||!ok||int(stat.Uid)!=os.Geteuid()||info.Mode()&os.ModeSymlink!=0||(!info.IsDir()&&!info.Mode().IsRegular()){return migration.ErrBlocked};return nil});err!=nil{return err};root,err:=os.OpenRoot(jobs);if err!=nil{return err};defer root.Close();if err=root.RemoveAll(filepath.Base(value));err!=nil{return err};return syncDirectory(jobs)}

func readOwnedConfig(value string,maximum int64)([]byte,os.FileInfo,error){before,err:=os.Lstat(value);stat,ok:=fileStat(before);if err!=nil||!ok||!before.Mode().IsRegular()||stat.Uid!=0||stat.Nlink!=1||before.Mode().Perm()&0o022!=0||before.Size()<1||before.Size()>maximum{return nil,nil,errors.Join(migration.ErrBlocked,err)};resolved,err:=filepath.EvalSymlinks(value);if err!=nil||resolved!=value{return nil,nil,migration.ErrBlocked};file,err:=os.Open(value);if err!=nil{return nil,nil,err};defer file.Close();opened,err:=file.Stat();if err!=nil||!os.SameFile(before,opened){return nil,nil,migration.ErrConflict};raw,err:=io.ReadAll(io.LimitReader(file,maximum+1));final,statErr:=file.Stat();if err!=nil||statErr!=nil||int64(len(raw))!=before.Size()||!os.SameFile(before,final)||!before.ModTime().Equal(final.ModTime()){return nil,nil,migration.ErrConflict};return raw,final,nil}
func readHexCredential(value string,size int)([]byte,error){before,err:=os.Lstat(value);stat,ok:=fileStat(before);if err!=nil||!ok||!before.Mode().IsRegular()||before.Mode().Perm()&0o077!=0||(stat.Uid!=0&&int(stat.Uid)!=os.Geteuid())||before.Size()>int64(size*2+1){return nil,migration.ErrBlocked};file,err:=os.Open(value);if err!=nil{return nil,err};defer file.Close();opened,err:=file.Stat();if err!=nil||!os.SameFile(before,opened){return nil,migration.ErrConflict};raw,err:=io.ReadAll(io.LimitReader(file,int64(size*2+2)));if err!=nil{return nil,err};defer wipe(raw);decoded,err:=hex.DecodeString(strings.TrimSuffix(string(raw),"\n"));if err!=nil||len(decoded)!=size{wipe(decoded);return nil,migration.ErrInvalid};return decoded,nil}

func (converter *Converter) Close()error{if converter==nil{return nil};converter.mu.Lock();defer converter.mu.Unlock();wipe(converter.signingKey);converter.signingKey=nil;return nil}

// Serve accepts one bounded, strict JSON frame from a local root administrator.
// No network address, archive member, command or host path exists in the API.
func (converter *Converter) Serve(ctx context.Context)error{
	if converter==nil||ctx==nil{return migration.ErrInvalid};socketRoot:=filepath.Dir(DefaultConverterSocketPath);if err:=ensureRoot(socketRoot);err!=nil{return err}
	lock,err:=os.OpenFile(filepath.Join(socketRoot,"converter.lock"),os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW,0o600);if err!=nil{return err};defer lock.Close();if err=syscall.Flock(int(lock.Fd()),syscall.LOCK_EX|syscall.LOCK_NB);err!=nil{return migration.ErrConflict};defer syscall.Flock(int(lock.Fd()),syscall.LOCK_UN)
	if info,statErr:=os.Lstat(DefaultConverterSocketPath);statErr==nil{stat,ok:=fileStat(info);if !ok||info.Mode()&os.ModeSocket==0||int(stat.Uid)!=os.Geteuid(){return migration.ErrBlocked};if err=os.Remove(DefaultConverterSocketPath);err!=nil{return err}}else if !errors.Is(statErr,os.ErrNotExist){return statErr}
	listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:DefaultConverterSocketPath,Net:"unix"});if err!=nil{return err};defer listener.Close();if err=os.Chmod(DefaultConverterSocketPath,0o600);err!=nil{return err};done:=make(chan struct{});defer close(done);go func(){select{case<-ctx.Done():listener.Close();case<-done:}}()
	for{connection,acceptErr:=listener.AcceptUnix();if acceptErr!=nil{if ctx.Err()!=nil{return ctx.Err()};return acceptErr};converter.serveConnection(ctx,connection);connection.Close()}
}
func (converter *Converter) serveConnection(ctx context.Context,connection *net.UnixConn){
	raw,err:=connection.SyscallConn();if err!=nil{return};authorized:=false;if err=raw.Control(func(fd uintptr){peer,peerErr:=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED);authorized=peerErr==nil&&peer.Uid==0});err!=nil||!authorized{return}
	_ = connection.SetDeadline(time.Now().Add(5*time.Second));payload,err:=readConverterFrame(connection);if err!=nil{return};decoder:=json.NewDecoder(bytes.NewReader(payload));decoder.DisallowUnknownFields();var request ConvertRequest;if err=decoder.Decode(&request);err!=nil{return};if err=decoder.Decode(&struct{}{});!errors.Is(err,io.EOF){return};if request.validate(converter.clock().UTC(),converter.config.TargetInstallationID)!=nil{return};_ = connection.SetDeadline(request.Deadline);jobCtx,cancel:=context.WithDeadline(ctx,request.Deadline);defer cancel();conversion,err:=converter.Convert(jobCtx,request);response:=ConvertResponse{Version:1,RequestID:request.RequestID};if err!=nil{response.Failure="conversion_rejected";if errors.Is(err,migration.ErrConflict){response.Failure="conflict"}else if errors.Is(err,migration.ErrAmbiguous){response.Failure="ambiguous"}else if errors.Is(err,context.DeadlineExceeded)||errors.Is(err,context.Canceled){response.Failure="deadline"}}else{response.Succeeded=true;response.MigrationID=conversion.MigrationID;response.BundleEndpoint=conversion.BundleEndpoint;response.ManifestRoot=conversion.ManifestRoot;response.EvidenceDigest=conversion.EvidenceDigest};encoded,err:=json.Marshal(response);if err==nil{_ = writeConverterFrame(connection,encoded)}
}
func readConverterFrame(reader io.Reader)([]byte,error){var header [4]byte;if _,err:=io.ReadFull(reader,header[:]);err!=nil{return nil,err};size:=binary.BigEndian.Uint32(header[:]);if size==0||size>maximumConverterFrame{return nil,migration.ErrCapacity};payload:=make([]byte,size);_,err:=io.ReadFull(reader,payload);return payload,err}
func writeConverterFrame(writer io.Writer,payload []byte)error{if len(payload)==0||len(payload)>maximumConverterFrame{return migration.ErrCapacity};var header [4]byte;binary.BigEndian.PutUint32(header[:],uint32(len(payload)));if err:=writeAll(writer,header[:]);err!=nil{return err};return writeAll(writer,payload)}

// ConvertLocal is the typed operator client. The socket location is fixed.
func ConvertLocal(ctx context.Context,request ConvertRequest)(ConvertResponse,error){var response ConvertResponse;if ctx==nil||request.validate(time.Now().UTC(),request.TargetInstallationID)!=nil||!scopeText(request.TargetInstallationID){return response,migration.ErrInvalid};dialer:=net.Dialer{};connection,err:=dialer.DialContext(ctx,"unix",DefaultConverterSocketPath);if err!=nil{return response,err};defer connection.Close();_ = connection.SetDeadline(request.Deadline);done:=make(chan struct{});defer close(done);go func(){select{case<-ctx.Done():connection.Close();case<-done:}}();payload,err:=json.Marshal(request);if err!=nil{return response,err};if err=writeConverterFrame(connection,payload);err!=nil{return response,err};payload,err=readConverterFrame(connection);if err!=nil{return response,err};decoder:=json.NewDecoder(bytes.NewReader(payload));decoder.DisallowUnknownFields();if err=decoder.Decode(&response);err!=nil{return response,migration.ErrInvalid};if err=decoder.Decode(&struct{}{});!errors.Is(err,io.EOF){return response,migration.ErrInvalid};if response.Version!=1||response.RequestID!=request.RequestID{return response,migration.ErrConflict};if !response.Succeeded{return response,migration.ErrBlocked};if !response.MigrationID.Valid()||!isDigest(response.ManifestRoot)||!isDigest(response.EvidenceDigest){return response,migration.ErrInvalid};return response,nil}
