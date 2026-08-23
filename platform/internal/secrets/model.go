package secrets

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var(ErrInvalid=errors.New("secrets: invalid value");ErrNotFound=errors.New("secrets: not found");ErrForbidden=errors.New("secrets: forbidden");ErrConflict=errors.New("secrets: conflict");ErrExpired=errors.New("secrets: expired");ErrRevoked=errors.New("secrets: revoked");ErrRollback=errors.New("secrets: version rollback"))
var idPattern=regexp.MustCompile(`^[a-z][a-z0-9_-]{2,95}$`)
type ID string
func NewID(value string)(ID,error){value=strings.TrimSpace(value);if !idPattern.MatchString(value){return "",fmt.Errorf("%w: id",ErrInvalid)};return ID(value),nil}
func(id ID)Valid()bool{return idPattern.MatchString(string(id))}
func(id ID)String()string{return string(id)}
type Purpose string
const(PurposeDatabase Purpose="database";PurposeDNSProvider Purpose="dns_provider";PurposeACME Purpose="acme";PurposeMailRelay Purpose="mail_relay";PurposeBackupRepository Purpose="backup_repository";PurposeRegistry Purpose="registry";PurposeGit Purpose="git";PurposeTLSKey Purpose="tls_key";PurposeDKIMKey Purpose="dkim_key";PurposeFederation Purpose="federation";PurposeAuthentication Purpose="authentication";PurposeMalwareApproval Purpose="malware_approval")
type State string
const(StateActive State="active";StateRetiring State="retiring";StateRevoked State="revoked";StateDestroyed State="destroyed")
type Operation string
const(OperationAuthenticate Operation="authenticate";OperationRead Operation="read";OperationWrite Operation="write";OperationSign Operation="sign";OperationEncrypt Operation="encrypt";OperationDecrypt Operation="decrypt";OperationRotate Operation="rotate")
type AudienceBinding struct{AdapterID,AdapterVersion,Account,Origin,RedirectSetDigest,ResourceKind string;ResourceID ID;ResourceGeneration uint64;Operations []Operation;ConsumerReleaseDigest string}
func(b AudienceBinding)Validate()error{if strings.TrimSpace(b.AdapterID)==""||strings.TrimSpace(b.AdapterVersion)==""||strings.TrimSpace(b.Account)==""||strings.TrimSpace(b.Origin)==""||strings.TrimSpace(b.ResourceKind)==""||!b.ResourceID.Valid()||b.ResourceGeneration==0||len(b.ConsumerReleaseDigest)!=64||len(b.Operations)==0{return ErrInvalid};seen:=map[Operation]bool{};for _,operation:=range b.Operations{if operation!=OperationAuthenticate&&operation!=OperationRead&&operation!=OperationWrite&&operation!=OperationSign&&operation!=OperationEncrypt&&operation!=OperationDecrypt&&operation!=OperationRotate{return ErrInvalid};if seen[operation]{return ErrConflict};seen[operation]=true};return nil}
type Metadata struct{ID,OwnerTenantID ID;Purpose Purpose;Version,KeyEpoch uint64;State State;Audience AudienceBinding;Algorithm,WrappedDEKDigest,CiphertextDigest,BindingDigest string;CreatedAt time.Time;RetireAt,RevokedAt,DestroyedAt *time.Time}
func(m Metadata)Validate()error{if !m.ID.Valid()||!m.OwnerTenantID.Valid()||!validPurpose(m.Purpose)||m.Version==0||m.KeyEpoch==0||(m.State!=StateActive&&m.State!=StateRetiring&&m.State!=StateRevoked&&m.State!=StateDestroyed)||m.Audience.Validate()!=nil||m.Algorithm!="AES-256-GCM"||len(m.WrappedDEKDigest)!=64||len(m.CiphertextDigest)!=64||len(m.BindingDigest)!=64||m.CreatedAt.IsZero(){return ErrInvalid};if m.State==StateRevoked&&(m.RevokedAt==nil||m.RevokedAt.IsZero()){return ErrInvalid};if m.State==StateDestroyed&&(m.DestroyedAt==nil||m.DestroyedAt.IsZero()){return ErrInvalid};return nil}
type SecretRecord struct{Metadata Metadata;Nonce,WrappedDEK,Ciphertext []byte;AAD []byte}
type ConsumerIdentity struct{ID ID;PID uint32;ProcessStart uint64;ExecutableDigest,ReleaseDigest string;TenantID ID;AdapterID,AdapterVersion string}
func(c ConsumerIdentity)Validate()error{if !c.ID.Valid()||c.PID==0||c.ProcessStart==0||len(c.ExecutableDigest)!=64||len(c.ReleaseDigest)!=64||!c.TenantID.Valid()||c.AdapterID==""||c.AdapterVersion==""{return ErrInvalid};return nil}
type DeliveryGrant struct{ID,SecretID,TenantID ID;SecretVersion uint64;Operation Operation;Consumer ConsumerIdentity;AudienceDigest,RequestDigest string;ExpiresAt time.Time;ConsumedAt *time.Time}
func(g DeliveryGrant)Validate()error{if !g.ID.Valid()||!g.SecretID.Valid()||!g.TenantID.Valid()||g.SecretVersion==0||g.Consumer.Validate()!=nil||len(g.AudienceDigest)!=64||len(g.RequestDigest)!=64||g.ExpiresAt.IsZero(){return ErrInvalid};return nil}
func validPurpose(value Purpose)bool{switch value{case PurposeDatabase,PurposeDNSProvider,PurposeACME,PurposeMailRelay,PurposeBackupRepository,PurposeRegistry,PurposeGit,PurposeTLSKey,PurposeDKIMKey,PurposeFederation,PurposeAuthentication,PurposeMalwareApproval:return true};return false}
func canonicalOperations(values []Operation)[]Operation{out:=append([]Operation(nil),values...);sort.Slice(out,func(i,j int)bool{return out[i]<out[j]});return out}
