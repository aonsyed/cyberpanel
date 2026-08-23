// Package providers contains concrete storage implementations for the backup
// workflow. Provider clients expose only object and repository operations;
// credentials and arbitrary transport commands never cross the boundary.
package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/backup"
)

var(ErrInvalid=errors.New("backup provider: invalid resource");ErrIntegrity=errors.New("backup provider: integrity failure");ErrConflict=errors.New("backup provider: conflict");ErrNotFound=errors.New("backup provider: not found");ErrAmbiguous=errors.New("backup provider: ambiguous effect");ErrCredential=errors.New("backup provider: credential unavailable"))

type ObjectSource interface{OpenObject(context.Context,backup.ObjectDescriptor,string,uint64)(io.ReadCloser,error)}
type SecretResolver interface{ResolveBackupCredential(context.Context,string,string)([]byte,error)}

type UploadPart struct{Number uint32 `json:"number"`;Offset uint64 `json:"offset"`;Size uint64 `json:"size"`;Digest string `json:"digest"`;ETag string `json:"etag"`;CompletedAt time.Time `json:"completed_at"`}
type UploadSession struct{ID string `json:"id"`;RepositoryID backup.RepositoryID `json:"repository_id"`;EffectID string `json:"effect_id"`;ObjectKey string `json:"object_key"`;ObjectDigest string `json:"object_digest"`;ObjectSize uint64 `json:"object_size"`;ProviderUploadID string `json:"provider_upload_id"`;PartSize uint64 `json:"part_size"`;Parts []UploadPart `json:"parts"`;State string `json:"state"`;Generation uint64 `json:"generation"`;CreatedAt time.Time `json:"created_at"`;UpdatedAt time.Time `json:"updated_at"`}
func (session UploadSession)Validate()error{if !safeID(session.ID)||session.RepositoryID==""||session.EffectID==""||len(session.EffectID)>1024||session.ObjectKey==""||!digest(session.ObjectDigest)||session.ObjectSize==0||session.ProviderUploadID==""||session.PartSize<5<<20||session.Generation==0||session.CreatedAt.IsZero()||session.UpdatedAt.IsZero(){return ErrInvalid};seen:=map[uint32]bool{};for _,part:=range session.Parts{if part.Number==0||seen[part.Number]||part.Size==0||!digest(part.Digest)||part.ETag==""||part.CompletedAt.IsZero(){return ErrInvalid};seen[part.Number]=true};return nil}
type UploadJournal interface{LoadUpload(context.Context,string)(UploadSession,error);CreateUpload(context.Context,UploadSession)error;SaveUpload(context.Context,UploadSession,uint64)error;DeleteUpload(context.Context,string,uint64)error}

type SFTPEndpoint struct{RepositoryID backup.RepositoryID `json:"repository_id"`;Host string `json:"host"`;Port uint16 `json:"port"`;User string `json:"user"`;Root string `json:"root"`;HostKeySHA256 string `json:"host_key_sha256"`;CredentialRef string `json:"credential_ref"`;MaximumPacketBytes uint32 `json:"maximum_packet_bytes"`}
func (endpoint SFTPEndpoint)Validate()error{if endpoint.RepositoryID==""||endpoint.Host==""||endpoint.Port==0||endpoint.User==""||!absoluteRemoteRoot(endpoint.Root)||!digest(endpoint.HostKeySHA256)||endpoint.CredentialRef==""||endpoint.MaximumPacketBytes<32<<10||endpoint.MaximumPacketBytes>16<<20{return ErrInvalid};if ip:=net.ParseIP(endpoint.Host);ip!=nil&&(ip.IsUnspecified()||ip.IsMulticast()){return ErrInvalid};return nil}
type RemoteFileInfo struct{Path string;Size uint64;Digest string;Regular bool;ModifiedAt time.Time}
type SFTPWriter interface{Write([]byte)(int,error);Sync()error;Close()error}
type SFTPReader interface{Read([]byte)(int,error);Close()error}
type SFTPClient interface{EnsureDirectory(context.Context,string,uint32)error;Stat(context.Context,string)(RemoteFileInfo,error);OpenWriter(context.Context,string,uint64,uint32)(SFTPWriter,error);OpenReader(context.Context,string,uint64)(SFTPReader,error);RenameNoReplace(context.Context,string,string)error;WriteFileExclusive(context.Context,string,[]byte,uint32)error;ReadFile(context.Context,string,uint64)([]byte,error);RemoveFile(context.Context,string)error;RemoveEmptyDirectory(context.Context,string)error;Close()error}
type SFTPConnector interface{Connect(context.Context,SFTPEndpoint,[]byte)(SFTPClient,error)}

type S3Credentials struct{AccessKeyID string `json:"access_key_id"`;SecretAccessKey string `json:"secret_access_key"`;SessionToken string `json:"session_token,omitempty"`;ExpiresAt time.Time `json:"expires_at,omitempty"`}
func (credentials S3Credentials)Validate(now time.Time)error{if credentials.AccessKeyID==""||credentials.SecretAccessKey==""||len(credentials.AccessKeyID)>256||len(credentials.SecretAccessKey)>4096{return ErrCredential};if !credentials.ExpiresAt.IsZero()&&!now.Before(credentials.ExpiresAt){return ErrCredential};return nil}
type S3CredentialResolver interface{ResolveS3(context.Context,string,backup.RepositoryID)(S3Credentials,error)}
type AddressingStyle string
const(AddressingVirtual AddressingStyle="virtual_host";AddressingPath AddressingStyle="path")
type S3Target struct{RepositoryID backup.RepositoryID `json:"repository_id"`;Provider backup.ProviderKind `json:"provider"`;Endpoint string `json:"endpoint"`;Region string `json:"region"`;Bucket string `json:"bucket"`;Prefix string `json:"prefix"`;Addressing AddressingStyle `json:"addressing"`;CredentialRef string `json:"credential_ref"`;PinnedCARef string `json:"pinned_ca_ref,omitempty"`;AllowPrivateEndpoint bool `json:"allow_private_endpoint"`;PartSize uint64 `json:"part_size"`;MaximumConcurrency uint16 `json:"maximum_concurrency"`}
func (target S3Target)Validate()error{if target.RepositoryID==""||target.Region==""||target.Bucket==""||target.CredentialRef==""||target.PartSize<5<<20||target.PartSize>5<<30||target.MaximumConcurrency==0||target.MaximumConcurrency>64{return ErrInvalid};parsed,err:=url.Parse(target.Endpoint);if err!=nil||parsed.Scheme!="https"||parsed.Hostname()==""||parsed.User!=nil||parsed.Fragment!=""||parsed.RawQuery!=""||(parsed.Path!=""&&parsed.Path!="/"){return ErrInvalid};if target.Addressing!=AddressingVirtual&&target.Addressing!=AddressingPath{return ErrInvalid};if !bucketPattern.MatchString(target.Bucket)||!safePrefix(target.Prefix){return ErrInvalid};if err:=validatePresetHost(target.Provider,parsed.Hostname(),target.AllowPrivateEndpoint);err!=nil{return err};return nil}
type S3Preset struct{Kind backup.ProviderKind;Endpoint string;Region string;Addressing AddressingStyle;AllowPrivate bool}
func Preset(kind backup.ProviderKind,region string)(S3Preset,error){switch kind{case backup.AWS:if region==""{return S3Preset{},ErrInvalid};return S3Preset{kind,"https://s3."+region+".amazonaws.com",region,AddressingVirtual,false},nil;case backup.Wasabi:if region==""{return S3Preset{},ErrInvalid};return S3Preset{kind,"https://s3."+region+".wasabisys.com",region,AddressingVirtual,false},nil;case backup.Backblaze:if region==""{return S3Preset{},ErrInvalid};return S3Preset{kind,"https://s3."+region+".backblazeb2.com",region,AddressingVirtual,false},nil;case backup.DigitalOceanSpaces:if region==""{return S3Preset{},ErrInvalid};return S3Preset{kind,"https://"+region+".digitaloceanspaces.com",region,AddressingVirtual,false},nil;case backup.MinIO:return S3Preset{kind,"","us-east-1",AddressingPath,true},nil;case backup.S3:return S3Preset{kind,"","us-east-1",AddressingPath,false},nil};return S3Preset{},ErrInvalid}

type DriveTarget struct{RepositoryID backup.RepositoryID `json:"repository_id"`;FolderID string `json:"folder_id"`;DriveID string `json:"drive_id,omitempty"`;CredentialRef string `json:"credential_ref"`;ChunkBytes uint64 `json:"chunk_bytes"`}
func (target DriveTarget)Validate()error{if target.RepositoryID==""||target.FolderID==""||target.CredentialRef==""||target.ChunkBytes<256<<10||target.ChunkBytes>256<<20||target.ChunkBytes%(256<<10)!=0{return ErrInvalid};return nil}
type DriveFile struct{ID string;Name string;Size uint64;Digest string;Revision string;Committed bool}
type DriveSession struct{ID string;FileName string;Offset uint64;ExpiresAt time.Time}
type DriveClient interface{Find(context.Context,DriveTarget,string)(*DriveFile,error);BeginUpload(context.Context,DriveTarget,string,uint64,string,string)(DriveSession,error);ResumeUpload(context.Context,DriveTarget,DriveSession,uint64,[]byte,string)(DriveSession,error);CommitUpload(context.Context,DriveTarget,DriveSession)(DriveFile,error);Read(context.Context,DriveTarget,string,uint64,uint64)([]byte,error);WriteSmallExclusive(context.Context,DriveTarget,string,[]byte,string)(DriveFile,error);Delete(context.Context,DriveTarget,string,string)error;Close()error}
type DriveConnector interface{Connect(context.Context,DriveTarget,[]byte)(DriveClient,error)}

func stageToken(repository backup.RepositoryID,point backup.RecoveryPointID,effect string)string{return "stg_"+hashText(string(repository)+"\x00"+string(point)+"\x00"+effect)[:48]}
func copyID(repository backup.RepositoryID,point backup.RecoveryPointID)backup.CopyID{return backup.CopyID("copy_"+hashText(string(repository)+"\x00"+string(point))[:48])}
func objectPath(descriptor backup.ObjectDescriptor)string{return "blobs/"+descriptor.Digest[:2]+"/"+descriptor.Digest}
func manifestBytes(manifest backup.RecoveryPointManifest)([]byte,error){return canonicalJSON(manifest)}
func commitBytes(manifest backup.RecoveryPointManifest,repository backup.RepositoryID,effect string,now time.Time)([]byte,string,error){_ = now;marker:=struct{Version uint8 `json:"version"`;RecoveryPointID backup.RecoveryPointID `json:"recovery_point_id"`;RepositoryID backup.RepositoryID `json:"repository_id"`;ManifestDigest string `json:"manifest_digest"`;Objects uint64 `json:"objects"`;Bytes uint64 `json:"bytes"`;EffectID string `json:"effect_id"`;CommittedAt time.Time `json:"committed_at"`}{Version:1,RecoveryPointID:manifest.RecoveryPointID,RepositoryID:repository,ManifestDigest:manifest.ManifestDigest,EffectID:effect,CommittedAt:manifest.CreatedAt.UTC()};for _,artifact:=range manifest.Artifacts{marker.Objects+=artifact.ObjectCount;marker.Bytes+=artifact.Bytes};payload,err:=canonicalJSON(marker);if err!=nil{return nil,"",err};return payload,hashBytes(payload),nil}
func validateSpec(spec backup.RepositorySpec,kind backup.ProviderKind)error{if spec.Repository.ID==""||spec.Repository.Kind!=kind||spec.TenantID==""||spec.FailureDomain==""||spec.EncryptionDomain==""||spec.Repository.CredentialRef==""||spec.MaximumConcurrency==0||spec.MaximumConcurrency>64||spec.MaximumPartBytes<spec.MinimumPartBytes{return ErrInvalid};return nil}
func validateManifest(manifest backup.RecoveryPointManifest)error{if manifest.RecoveryPointID==""||manifest.PolicyID==""||manifest.TenantID==""||manifest.Scope==""||manifest.WriteFrontier==0||manifest.SourceGeneration==0||!digest(manifest.ManifestDigest)||manifest.CreatedAt.IsZero()||len(manifest.Artifacts)==0{return ErrInvalid};seen:=map[string]bool{};for _,artifact:=range manifest.Artifacts{for _,object:=range artifact.Objects{if object.Key==""||!digest(object.Digest)||seen[object.Key]{return ErrInvalid};seen[object.Key]=true}};return nil}
func validateObject(object backup.ObjectDescriptor)error{if object.Key==""||len(object.Key)>4096||!digest(object.Digest){return ErrInvalid};return nil}
func hashBytes(value []byte)string{sum:=sha256.Sum256(value);return hex.EncodeToString(sum[:])}
func hashText(value string)string{return hashBytes([]byte(value))}
func digest(value string)bool{if len(value)!=64||value!=strings.ToLower(value){return false};_,err:=hex.DecodeString(value);return err==nil}
func safeID(value string)bool{return idPattern.MatchString(value)}
func safePrefix(value string)bool{if value==""{return true};clean:=path.Clean(value);return clean==value&&!strings.HasPrefix(clean,"/")&&!strings.HasPrefix(clean,"../")&&!strings.Contains(clean,"//")}
func absoluteRemoteRoot(value string)bool{clean:=path.Clean(value);return strings.HasPrefix(clean,"/")&&clean==value&&clean!="/"&&!strings.Contains(clean,"//")}
func canonicalJSON(value any)([]byte,error){return jsonMarshal(value)}
func jsonMarshal(value any)([]byte,error){return json.Marshal(value)}
func verifyReader(reader io.Reader,expected string,size uint64)(uint64,error){hasher:=sha256.New();written,err:=io.Copy(hasher,io.LimitReader(reader,int64(size)+1));if err!=nil{return uint64(written),err};if uint64(written)!=size||hex.EncodeToString(hasher.Sum(nil))!=expected{return uint64(written),ErrIntegrity};return uint64(written),nil}
func sortedParts(parts []UploadPart)[]UploadPart{result:=append([]UploadPart(nil),parts...);sort.Slice(result,func(i,j int)bool{return result[i].Number<result[j].Number});return result}
func validatePresetHost(kind backup.ProviderKind,host string,allowPrivate bool)error{host=strings.ToLower(host);suffix:=func(domain string)bool{return host==domain||strings.HasSuffix(host,"."+domain)};switch kind{case backup.AWS:if !suffix("amazonaws.com"){return ErrInvalid};case backup.Wasabi:if !suffix("wasabisys.com"){return ErrInvalid};case backup.Backblaze:if !suffix("backblazeb2.com"){return ErrInvalid};case backup.DigitalOceanSpaces:if !suffix("digitaloceanspaces.com"){return ErrInvalid};case backup.MinIO:if !allowPrivate{return ErrInvalid};case backup.S3:if allowPrivate||host=="localhost"||strings.HasSuffix(host,".localhost")||strings.HasSuffix(host,".local"){return ErrInvalid};if ip:=net.ParseIP(host);ip!=nil&&(ip.IsPrivate()||ip.IsLoopback()||ip.IsLinkLocalUnicast()||ip.IsUnspecified()||ip.IsMulticast()){return ErrInvalid};default:return ErrInvalid};return nil}
func joinRemote(root,relative string)(string,error){if !absoluteRemoteRoot(root)||!safePrefix(relative){return "",ErrInvalid};joined:=path.Join(root,relative);if joined!=root&&!strings.HasPrefix(joined,root+"/"){return "",ErrInvalid};return joined,nil}
func receiptMatches(spec backup.RepositorySpec,manifest backup.RecoveryPointManifest,receipt backup.CopyReceipt)bool{return receipt.RecoveryPointID==manifest.RecoveryPointID&&receipt.RepositoryID==spec.Repository.ID&&receipt.ManifestDigest==manifest.ManifestDigest&&receipt.Status==backup.CopyVerified&&receipt.CommitMarker!=""&&!receipt.VerifiedAt.IsZero()}
func objectInManifest(manifest backup.RecoveryPointManifest,object backup.ObjectDescriptor)bool{if validateObject(object)!=nil{return false};for _,artifact:=range manifest.Artifacts{for _,candidate:=range artifact.Objects{if candidate.Key==object.Key&&candidate.Digest==object.Digest&&candidate.Size==object.Size&&candidate.Mode==object.Mode{return true}}};return false}
func equalBytes(left,right []byte)bool{if len(left)!=len(right){return false};var different byte;for index:=range left{different|=left[index]^right[index]};return different==0}
func manifestTotals(manifest backup.RecoveryPointManifest)(uint64,uint64){var objects,bytes uint64;for _,artifact:=range manifest.Artifacts{objects+=artifact.ObjectCount;bytes+=artifact.Bytes};return objects,bytes}

var idPattern=regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var bucketPattern=regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
