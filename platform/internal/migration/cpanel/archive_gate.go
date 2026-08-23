package cpanel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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

const archiveGateTokenDomain="cpanel-immutable-archive-gate-v1"

type ArchiveGateConfig struct {
	Source *ArchiveSource
	AuthenticationKey []byte
	LeaseDuration time.Duration
	Clock func()time.Time
}

type ArchiveGate struct {
	source *ArchiveSource
	key []byte
	leaseDuration time.Duration
	clock func()time.Time
	mu sync.RWMutex
}

type archiveGateToken struct {
	Version uint32 `json:"version"`
	MigrationID migration.ID `json:"migration_id"`
	SourceInstallationID string `json:"source_installation_id"`
	AccountIDs []string `json:"account_ids"`
	ExpectedFence uint64 `json:"expected_fence"`
	TargetPlanDigest string `json:"target_plan_digest"`
	ApprovalDigest string `json:"approval_digest"`
	ArchiveEvidence string `json:"archive_evidence"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature string `json:"signature"`
}

func NewArchiveGate(config ArchiveGateConfig)(*ArchiveGate,error){
	if config.Source==nil||len(config.AuthenticationKey)<32{return nil,ErrInvalid}
	if config.LeaseDuration==0{config.LeaseDuration=15*time.Minute}
	if config.LeaseDuration<time.Minute||config.LeaseDuration>24*time.Hour{return nil,ErrInvalid}
	if config.Clock==nil{config.Clock=time.Now}
	return &ArchiveGate{source:config.Source,key:append([]byte(nil),config.AuthenticationKey...),leaseDuration:config.LeaseDuration,clock:config.Clock},nil
}

func(g *ArchiveGate)Close()error{if g==nil{return nil};g.mu.Lock();defer g.mu.Unlock();wipe(g.key);g.key=nil;return nil}

func(g *ArchiveGate)Freeze(ctx context.Context,scope cyberpanel.GateScope)(cyberpanel.ComponentLease,error){
	if g==nil||g.source==nil||ctx==nil||!scope.MigrationID.Valid()||scope.SourceInstallationID!=g.source.installationID||scope.ExpectedFence==0||!digestValue(scope.TargetPlanDigest)||!digestValue(scope.ApprovalDigest)||(scope.Mode!="write_fence"&&scope.Mode!="service_fence"){return cyberpanel.ComponentLease{},ErrInvalid}
	accountIDs,err:=g.source.selectedAccounts(scope.SiteSourceIDs)
	if err!=nil{return cyberpanel.ComponentLease{},err}
	evidence,err:=g.source.archiveEvidence(ctx,accountIDs)
	if err!=nil{return cyberpanel.ComponentLease{},err}
	now:=g.clock().UTC()
	token:=archiveGateToken{Version:1,MigrationID:scope.MigrationID,SourceInstallationID:scope.SourceInstallationID,AccountIDs:accountIDs,ExpectedFence:scope.ExpectedFence,TargetPlanDigest:scope.TargetPlanDigest,ApprovalDigest:scope.ApprovalDigest,ArchiveEvidence:evidence,IssuedAt:now,ExpiresAt:now.Add(g.leaseDuration)}
	encoded,err:=g.encode(token)
	if err!=nil{return cyberpanel.ComponentLease{},err}
	return cyberpanel.ComponentLease{Token:encoded,EvidenceDigest:evidence,ExpiresAt:token.ExpiresAt},nil
}

func(g *ArchiveGate)Verify(ctx context.Context,action cyberpanel.ComponentAction)error{return g.verifyAction(ctx,action,true,true)}
func(g *ArchiveGate)Thaw(ctx context.Context,action cyberpanel.ComponentAction)error{return g.verifyAction(ctx,action,false,false)}
func(g *ArchiveGate)Commit(ctx context.Context,action cyberpanel.ComponentAction)error{return g.verifyAction(ctx,action,true,true)}
func(g *ArchiveGate)Rollback(ctx context.Context,action cyberpanel.ComponentAction)error{return g.verifyAction(ctx,action,false,false)}

func(g *ArchiveGate)verifyAction(ctx context.Context,action cyberpanel.ComponentAction,requireLive,requireArchiveEvidence bool)error{
	if g==nil||g.source==nil||ctx==nil||!action.MigrationID.Valid()||action.ExpectedFence==0||strings.TrimSpace(action.Token)==""{return ErrInvalid}
	token,err:=g.decode(action.Token)
	if err!=nil{return err}
	if token.MigrationID!=action.MigrationID||token.SourceInstallationID!=g.source.installationID||token.ExpectedFence!=action.ExpectedFence{return ErrDenied}
	accounts,err:=g.source.selectedAccounts(action.SiteSourceIDs)
	if err!=nil{return err}
	if !equalStrings(token.AccountIDs,accounts){return ErrDenied}
	if requireLive&&(!g.clock().UTC().Before(token.ExpiresAt)||action.SourceGeneration==0||!digestValue(action.FenceDigest)){return ErrDenied}
	if !requireArchiveEvidence{return nil}
	evidence,err:=g.source.archiveEvidence(ctx,accounts)
	if err!=nil{return err}
	if !hmac.Equal([]byte(evidence),[]byte(token.ArchiveEvidence)){return ErrArchiveChanged}
	return nil
}

func(g *ArchiveGate)encode(token archiveGateToken)(string,error){
	g.mu.RLock();defer g.mu.RUnlock()
	if len(g.key)<32{return "",ErrDenied}
	token.Signature=""
	message,err:=archiveGateMessage(token)
	if err!=nil{return "",err}
	signature:=hmac.New(sha256.New,g.key);_,_=signature.Write(message);token.Signature=hex.EncodeToString(signature.Sum(nil))
	raw,err:=json.Marshal(token)
	if err!=nil{return "",err}
	if len(raw)>64<<10{return "",ErrInvalid}
	return base64.RawURLEncoding.EncodeToString(raw),nil
}

func(g *ArchiveGate)decode(value string)(archiveGateToken,error){
	if len(value)==0||len(value)>128<<10{return archiveGateToken{},ErrInvalid}
	raw,err:=base64.RawURLEncoding.DecodeString(value)
	if err!=nil||len(raw)>64<<10{return archiveGateToken{},ErrInvalid}
	decoder:=json.NewDecoder(strings.NewReader(string(raw)));decoder.DisallowUnknownFields()
	var token archiveGateToken
	if err:=decoder.Decode(&token);err!=nil{return archiveGateToken{},ErrInvalid}
	var trailing any
	if err:=decoder.Decode(&trailing);!errors.Is(err,io.EOF){return archiveGateToken{},ErrInvalid}
	if token.Version!=1||!token.MigrationID.Valid()||token.SourceInstallationID==""||len(token.AccountIDs)==0||token.ExpectedFence==0||!digestValue(token.TargetPlanDigest)||!digestValue(token.ApprovalDigest)||!digestValue(token.ArchiveEvidence)||token.IssuedAt.IsZero()||token.ExpiresAt.IsZero()||!token.ExpiresAt.After(token.IssuedAt)||len(token.Signature)!=64{return archiveGateToken{},ErrInvalid}
	if !sort.StringsAreSorted(token.AccountIDs){return archiveGateToken{},ErrInvalid}
	for index,accountID:=range token.AccountIDs{if !validAccountID(accountID)||(index>0&&accountID==token.AccountIDs[index-1]){return archiveGateToken{},ErrInvalid}}
	signatureBytes,err:=hex.DecodeString(token.Signature)
	if err!=nil||len(signatureBytes)!=sha256.Size{return archiveGateToken{},ErrInvalid}
	unsigned:=token;unsigned.Signature=""
	message,err:=archiveGateMessage(unsigned)
	if err!=nil{return archiveGateToken{},err}
	g.mu.RLock();defer g.mu.RUnlock()
	if len(g.key)<32{return archiveGateToken{},ErrDenied}
	expected:=hmac.New(sha256.New,g.key);_,_=expected.Write(message)
	if !hmac.Equal(signatureBytes,expected.Sum(nil)){return archiveGateToken{},ErrDenied}
	return token,nil
}

func(s *ArchiveSource)archiveEvidence(ctx context.Context,accountIDs []string)(string,error){
	if s==nil||ctx==nil||len(accountIDs)==0{return "",ErrInvalid}
	hash:=sha256.New();_,_=hash.Write([]byte(archiveGateTokenDomain+"\x00"+s.installationID+"\x00"))
	for _,accountID:=range accountIDs{
		select{case<-ctx.Done():return "",ctx.Err();default:}
		archive,approved:=s.accounts[accountID]
		if !approved{return "",ErrDenied}
		info,err:=os.Lstat(archive.path)
		if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()&0o022!=0||!sameFileSnapshot(archive.identity,info){return "",errors.Join(err,ErrArchiveChanged)}
		parent,err:=os.Lstat(filepath.Dir(archive.path))
		if err!=nil||!parent.IsDir()||parent.Mode().Perm()&0o022!=0{return "",errors.Join(err,ErrDenied)}
		file,err:=os.Open(archive.path)
		if err!=nil{return "",err}
		after,err:=file.Stat()
		if err!=nil||!sameFileSnapshot(info,after){file.Close();return "",errors.Join(err,ErrArchiveChanged)}
		contentDigest,err:=hashArchiveContent(ctx,file)
		if err!=nil{file.Close();return "",err}
		final,err:=file.Stat();closeErr:=file.Close()
		if err!=nil||closeErr!=nil||!sameFileSnapshot(after,final){return "",errors.Join(err,closeErr,ErrArchiveChanged)}
		_,_=hash.Write([]byte(accountID+"\x00"+strconv.FormatInt(info.Size(),10)+"\x00"+info.ModTime().UTC().Format(time.RFC3339Nano)+"\x00"+strconv.FormatUint(uint64(info.Mode().Perm()),8)+"\x00"+contentDigest+"\x00"))
	}
	return hex.EncodeToString(hash.Sum(nil)),nil
}

func hashArchiveContent(ctx context.Context,source io.Reader)(string,error){if ctx==nil||source==nil{return "",ErrInvalid};hash:=sha256.New();buffer:=make([]byte,256<<10);defer wipe(buffer);for{select{case<-ctx.Done():return "",ctx.Err();default:};count,readErr:=source.Read(buffer);if count>0{_,_=hash.Write(buffer[:count])};if errors.Is(readErr,io.EOF){break};if readErr!=nil{return "",readErr};if count==0{return "",io.ErrNoProgress}};return hex.EncodeToString(hash.Sum(nil)),nil}

func archiveGateMessage(token archiveGateToken)([]byte,error){token.Signature="";raw,err:=json.Marshal(token);if err!=nil{return nil,err};return append([]byte(archiveGateTokenDomain+"\x00"),raw...),nil}
func equalStrings(left,right []string)bool{if len(left)!=len(right){return false};for index:=range left{if left[index]!=right[index]{return false}};return true}
func digestValue(value string)bool{if len(value)!=64||strings.ToLower(value)!=value{return false};decoded,err:=hex.DecodeString(value);return err==nil&&len(decoded)==sha256.Size}
var _ cyberpanel.ComponentGate=(*ArchiveGate)(nil)
