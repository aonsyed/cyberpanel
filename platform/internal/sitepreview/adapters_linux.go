//go:build linux

package sitepreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	DefaultLinuxRouteRoot       = "/var/lib/cyberpanel/sitepreview/routes"
	DefaultLinuxArtifactRoot    = "/var/lib/cyberpanel/sitepreview/artifacts"
	DefaultLinuxRouteHelper     = "/usr/libexec/cyberpanel-sitepreview-route"
	DefaultLinuxChromiumHelper  = "/usr/libexec/cyberpanel-sitepreview-chromium"
	linuxAdapterProtocolVersion = uint16(1)
)

type LinuxRouteRuntime struct {
	root   string
	helper string
	mutex  sync.Mutex
}

func NewLinuxRouteRuntime(root, helper string) (*LinuxRouteRuntime, error) {
	if root == "" { root = DefaultLinuxRouteRoot }
	if helper == "" { helper = DefaultLinuxRouteHelper }
	if root != DefaultLinuxRouteRoot || helper != DefaultLinuxRouteHelper || ensureLinuxPrivateDirectory(root) != nil || validateRootHelper(helper) != nil {
		return nil, ErrPolicyDenied
	}
	return &LinuxRouteRuntime{root:root,helper:helper},nil
}

type linuxRouteManifest struct {
	Version uint16    `json:"version"`
	Digest  string    `json:"digest"`
	Spec    RouteSpec `json:"spec"`
}
type linuxRouteHelperRequest struct {
	Version     uint16     `json:"version"`
	Operation   string     `json:"operation"`
	ManifestRef string     `json:"manifest_ref"`
	SpecDigest  string     `json:"spec_digest"`
	Lease       RouteLease `json:"lease,omitempty"`
}

func (runtime *LinuxRouteRuntime) InstallExactPreview(ctx context.Context, spec RouteSpec) (RouteEffectReceipt,error) {
	return runtime.apply(ctx,"install",spec,RouteLease{})
}
func (runtime *LinuxRouteRuntime) ObserveExactPreview(ctx context.Context, spec RouteSpec, lease RouteLease) (RouteEffectReceipt,error) {
	return runtime.apply(ctx,"observe",spec,lease)
}
func (runtime *LinuxRouteRuntime) ExpireExactPreview(ctx context.Context, spec RouteSpec, lease RouteLease) (RouteEffectReceipt,error) {
	return runtime.apply(ctx,"expire",spec,lease)
}
func (runtime *LinuxRouteRuntime) RollbackExactPreview(ctx context.Context, spec RouteSpec, lease RouteLease) (RouteEffectReceipt,error) {
	return runtime.apply(ctx,"rollback",spec,lease)
}

func (runtime *LinuxRouteRuntime) apply(ctx context.Context, operation string, spec RouteSpec, lease RouteLease) (RouteEffectReceipt,error) {
	if runtime==nil||ctx==nil||spec.Validate()!=nil||!validRouteOperation(operation) { return RouteEffectReceipt{},ErrInvalid }
	if operation!="install" { if lease.Validate()!=nil||lease.SessionID!=spec.SessionID||lease.SpecDigest!=digestJSON("cyberpanel:sitepreview:route:v1",spec){return RouteEffectReceipt{},ErrInvalid} } else if lease!=(RouteLease{}) { return RouteEffectReceipt{},ErrInvalid }
	runtime.mutex.Lock();defer runtime.mutex.Unlock()
	if ensureLinuxPrivateDirectory(runtime.root)!=nil||validateRootHelper(runtime.helper)!=nil{return RouteEffectReceipt{},ErrPolicyDenied}
	specDigest:=digestJSON("cyberpanel:sitepreview:route:v1",spec)
	manifest:=linuxRouteManifest{Version:linuxAdapterProtocolVersion,Digest:specDigest,Spec:spec}
	if err:=stageRouteManifest(runtime.root,manifest);err!=nil{return RouteEffectReceipt{},err}
	request:=linuxRouteHelperRequest{Version:linuxAdapterProtocolVersion,Operation:operation,ManifestRef:"route-"+specDigest,SpecDigest:specDigest,Lease:lease}
	var receipt RouteEffectReceipt
	if err:=invokeFixedHelper(ctx,runtime.helper,request,&receipt,256<<10);err!=nil{return RouteEffectReceipt{Outcome:RouteAmbiguous},errors.Join(ErrAmbiguous,err)}
	if receipt.Validate(spec)!=nil{return RouteEffectReceipt{Outcome:RouteAmbiguous},ErrIntegrity}
	switch operation {
	case "install","observe":if receipt.Outcome!=RouteApplied&&receipt.Outcome!=RouteAmbiguous{return RouteEffectReceipt{},ErrIntegrity}
	case "expire":if receipt.Outcome!=RouteAbsent&&receipt.Outcome!=RouteAmbiguous{return RouteEffectReceipt{},ErrIntegrity}
	case "rollback":if receipt.Outcome!=RouteRolledBack&&receipt.Outcome!=RouteAmbiguous{return RouteEffectReceipt{},ErrIntegrity}
	}
	if receipt.Outcome==RouteApplied&&(!receipt.Lease.ExpiresAt.Equal(spec.ExpiresAt)||receipt.Lease.RollbackUntil.Before(spec.ExpiresAt)){return RouteEffectReceipt{},ErrIntegrity}
	return receipt,nil
}

func validRouteOperation(value string) bool { return value=="install"||value=="observe"||value=="expire"||value=="rollback" }

func stageRouteManifest(root string, manifest linuxRouteManifest) error {
	if manifest.Version!=linuxAdapterProtocolVersion||!validDigest(manifest.Digest)||manifest.Spec.Validate()!=nil||manifest.Digest!=digestJSON("cyberpanel:sitepreview:route:v1",manifest.Spec){return ErrInvalid}
	directory:=filepath.Join(root,"generations");if err:=ensureLinuxPrivateDirectory(directory);err!=nil{return err}
	encoded,err:=json.Marshal(manifest);if err!=nil||len(encoded)==0||len(encoded)>128<<10{return ErrInvalid}
	path:=filepath.Join(directory,"route-"+manifest.Digest+".json")
	if existing,readErr:=os.ReadFile(path);readErr==nil{if bytes.Equal(existing,encoded){return nil};return ErrIntegrity}else if !errors.Is(readErr,fs.ErrNotExist){return readErr}
	temporary:=path+".staging";file,err:=os.OpenFile(temporary,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0o600);if err!=nil{return err}
	ok:=false;defer func(){_ = file.Close();if !ok{_ = os.Remove(temporary)}}()
	if _,err=file.Write(encoded);err!=nil{return err};if err=file.Sync();err!=nil{return err};if err=file.Close();err!=nil{return err}
	if err=os.Link(temporary,path);err!=nil{if errors.Is(err,fs.ErrExist){existing,readErr:=os.ReadFile(path);if readErr!=nil||!bytes.Equal(existing,encoded){return ErrIntegrity}}else{return err}}
	if err=os.Remove(temporary);err!=nil{return err};ok=true;return syncDirectory(directory)
}

type LinuxChromeNamespace struct{ helper string }

func NewLinuxChromeNamespace(helper string) (*LinuxChromeNamespace,error) {
	if helper==""{helper=DefaultLinuxChromiumHelper};if helper!=DefaultLinuxChromiumHelper||validateRootHelper(helper)!=nil{return nil,ErrPolicyDenied};return &LinuxChromeNamespace{helper:helper},nil
}
type linuxChromeHelperRequest struct{ Version uint16 `json:"version"`; Launch ChromeLaunch `json:"launch"` }

func (namespace *LinuxChromeNamespace) RunIsolatedChrome(ctx context.Context, launch ChromeLaunch) (NavigationReceipt,error) {
	if namespace==nil||ctx==nil||launch.Validate()!=nil||validateRootHelper(namespace.helper)!=nil{return NavigationReceipt{},ErrInvalid}
	var receipt NavigationReceipt
	if err:=invokeFixedHelper(ctx,namespace.helper,linuxChromeHelperRequest{Version:linuxAdapterProtocolVersion,Launch:launch},&receipt,512<<10);err!=nil{return NavigationReceipt{},err}
	if receipt.JobID!=launch.JobID||!receipt.ProfileIsolated||!receipt.ExtensionsOff||!receipt.DownloadsOff||!receipt.CredentialsOff||!receipt.FileURLsOff||!receipt.DataURLsOff||!validDigest(receipt.EvidenceDigest)||
		receipt.StartedAt.IsZero()||receipt.FinishedAt.Before(receipt.StartedAt)||receipt.FinishedAt.After(launch.Deadline)||receipt.ResponseBytes==0||receipt.ResponseBytes>launch.MaximumResponseBytes||len(receipt.Hops)==0||len(receipt.Hops)>int(launch.MaximumRedirects)+1{return NavigationReceipt{},ErrIntegrity}
	for _,hop:=range receipt.Hops{if hop.ResolvedAddress.Unmap()!=launch.AllowedEndpoint.Addr().Unmap(){return NavigationReceipt{},ErrPolicyDenied}}
	return receipt,nil
}

type LinuxArtifactStore struct{ root string; mutex sync.Mutex }

func NewLinuxArtifactStore(root string) (*LinuxArtifactStore,error) {
	if root==""{root=DefaultLinuxArtifactRoot};if root!=DefaultLinuxArtifactRoot||ensureLinuxPrivateDirectory(root)!=nil{return nil,ErrPolicyDenied};return &LinuxArtifactStore{root:root},nil
}

func (store *LinuxArtifactStore) PutScreenshot(ctx context.Context, job ScreenshotJob, mediaType string, source io.Reader, maximum uint64) (ArtifactStorageReceipt,error) {
	if store==nil||ctx==nil||job.Validate()!=nil||mediaType!="image/png"||source==nil||maximum==0||maximum>MaximumScreenshotBytes{return ArtifactStorageReceipt{},ErrInvalid}
	store.mutex.Lock();defer store.mutex.Unlock()
	if err:=ensureLinuxPrivateDirectory(store.root);err!=nil{return ArtifactStorageReceipt{},err}
	tenantDirectory:=filepath.Join(store.root,string(job.TenantID));if err:=ensureLinuxPrivateDirectory(tenantDirectory);err!=nil{return ArtifactStorageReceipt{},err}
	temporary:=filepath.Join(tenantDirectory,"job-"+string(job.ID)+"-g"+fmt.Sprint(job.Generation)+".part")
	file,err:=os.OpenFile(temporary,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0o600);if err!=nil{return ArtifactStorageReceipt{},err}
	keep:=false;defer func(){_ = file.Close();if !keep{_ = os.Remove(temporary)}}()
	hasher:=sha256.New();limited:=&io.LimitedReader{R:source,N:int64(maximum)+1};written,err:=io.Copy(io.MultiWriter(file,hasher),limited);if err!=nil{return ArtifactStorageReceipt{},err};if written<=0||uint64(written)>maximum{return ArtifactStorageReceipt{},ErrPolicyDenied}
	if err=file.Sync();err!=nil{return ArtifactStorageReceipt{},err};if err=file.Close();err!=nil{return ArtifactStorageReceipt{},err}
	digest:=hex.EncodeToString(hasher.Sum(nil));reference:=artifactStorageReference(job,digest);final:=filepath.Join(tenantDirectory,reference+".png")
	if err=os.Link(temporary,final);err!=nil{return ArtifactStorageReceipt{},err};if err=os.Remove(temporary);err!=nil{return ArtifactStorageReceipt{},err};keep=true
	if err=syncDirectory(tenantDirectory);err!=nil{return ArtifactStorageReceipt{},err};return ArtifactStorageReceipt{StorageRef:reference,ByteSize:uint64(written),Digest:digest},nil
}

func (store *LinuxArtifactStore) DiscardScreenshot(ctx context.Context, job ScreenshotJob, receipt ArtifactStorageReceipt) error {
	if store==nil||ctx==nil||job.Validate()!=nil||receipt.Validate(job.Limits.MaximumBytes)!=nil||receipt.StorageRef!=artifactStorageReference(job,receipt.Digest){return ErrInvalid}
	store.mutex.Lock();defer store.mutex.Unlock();if err:=ctx.Err();err!=nil{return err}
	directory:=filepath.Join(store.root,string(job.TenantID));if ensureLinuxPrivateDirectory(directory)!=nil{return ErrPolicyDenied};path:=filepath.Join(directory,receipt.StorageRef+".png")
	info,err:=os.Lstat(path);if errors.Is(err,fs.ErrNotExist){return nil};if err!=nil{return err};if !info.Mode().IsRegular()||info.Mode().Perm()!=0o600{return ErrIntegrity};if err=os.Remove(path);err!=nil{return err};return syncDirectory(directory)
}

func artifactStorageReference(job ScreenshotJob, digest string) string {
	sum:=sha256.Sum256([]byte("cyberpanel:sitepreview:artifact-storage:v1\x00"+string(job.TenantID)+"\x00"+string(job.ID)+"\x00"+digest));return "png-"+hex.EncodeToString(sum[:])
}

func invokeFixedHelper(ctx context.Context, helper string, request any, response any, maximum int) error {
	if ctx==nil||validateRootHelper(helper)!=nil||response==nil||maximum<1024||maximum>1<<20{return ErrInvalid}
	encoded,err:=json.Marshal(request);if err!=nil||len(encoded)==0||len(encoded)>256<<10{return ErrInvalid}
	output:=&limitedBuffer{maximum:maximum};command:=exec.CommandContext(ctx,helper);command.Stdin=bytes.NewReader(encoded);command.Stdout=output;command.Stderr=io.Discard
	if err=command.Run();err!=nil{return err};if output.overflow{return ErrIntegrity};if err=decodeStored(output.content,response);err!=nil{return err};return nil
}

type limitedBuffer struct{ content []byte; maximum int; overflow bool }
func (buffer *limitedBuffer) Write(content []byte)(int,error){if buffer.overflow{return 0,ErrIntegrity};if len(buffer.content)+len(content)>buffer.maximum{buffer.overflow=true;return 0,ErrIntegrity};buffer.content=append(buffer.content,content...);return len(content),nil}

func validateRootHelper(path string) error {
	if path==""||!filepath.IsAbs(path)||filepath.Clean(path)!=path||(path!=DefaultLinuxRouteHelper&&path!=DefaultLinuxChromiumHelper){return ErrPolicyDenied}
	info,err:=os.Lstat(path);if err!=nil{return err};if !info.Mode().IsRegular()||info.Mode().Perm()&0o022!=0{return ErrPolicyDenied};stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||stat.Uid!=0{return ErrPolicyDenied};return nil
}

func ensureLinuxPrivateDirectory(path string) error {
	if path==""||!filepath.IsAbs(path)||filepath.Clean(path)!=path||(!withinLinuxRoot(path,DefaultLinuxRouteRoot)&&!withinLinuxRoot(path,DefaultLinuxArtifactRoot)){return ErrPolicyDenied}
	if err:=os.MkdirAll(path,0o700);err!=nil{return err};info,err:=os.Lstat(path);if err!=nil{return err};if !info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=0o700{return ErrPolicyDenied};resolved,err:=filepath.EvalSymlinks(path);if err!=nil||resolved!=path{return ErrPolicyDenied};return nil
}

func withinLinuxRoot(path,root string)bool{return path==root||strings.HasPrefix(path,root+string(os.PathSeparator))}

func syncDirectory(path string) error { directory,err:=os.Open(path);if err!=nil{return err};defer directory.Close();return directory.Sync() }
