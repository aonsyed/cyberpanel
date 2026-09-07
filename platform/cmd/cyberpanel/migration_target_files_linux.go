//go:build linux

package main

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	hostingservice "github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

type migrationFile struct{ Path string; Size int64; Mode uint32; Directory bool; Digest string }
type migrationChunkReader struct{ctx context.Context;chunks *migration.ChunkStore;chunk migration.Chunk;offset uint64}
func (reader *migrationChunkReader)Read(buffer []byte)(int,error){if reader.offset==reader.chunk.Size{return 0,io.EOF};length:=uint64(len(buffer));if length>1<<20{length=1<<20};if length>reader.chunk.Size-reader.offset{length=reader.chunk.Size-reader.offset};value,err:=reader.chunks.ReadRange(reader.ctx,reader.chunk.Digest,reader.offset,length);if err!=nil{return 0,err};if len(value)==0{return 0,io.ErrNoProgress};count:=copy(buffer,value);reader.offset+=uint64(count);return count,nil}

func (target *migrationHostTarget) sitePayload(intent migration.ImportIntent)(migration.Site,error){
	var source migration.Site;if json.Unmarshal(intent.Payload,&source)!=nil||source.SourceID!=intent.SourceID||source.DocumentRootRelative!="public_html"||source.RuntimeKind!="php_lsapi"||len(source.Content)!=1||len(intent.Chunks)!=1||len(source.Children)!=0||len(source.Redirects)!=0||len(source.ResourceProfile)!=0||len(source.RepositoryIDs)!=0||len(source.ContainerApplicationIDs)!=0||source.Content[0]!=intent.Chunks[0]{return source,migration.ErrBlocked}
	chunk:=source.Content[0];if chunk.Compression!="tar"||chunk.MediaType!="application/vnd.cyberpanel.migration.directory+tar"||chunk.Size==0||chunk.Size>64<<30{return source,migration.ErrBlocked}
	if _,err:=migrationPHPProfile(source.PHPVersion);err!=nil{return source,err};return source,nil
}

// Only the source-neutral canonical tar stream is parsed here, never a legacy
// archive. Validate the entire stream before provisioning a site or writing.
func (target *migrationHostTarget) inventoryFiles(ctx context.Context,chunk migration.Chunk)([]migrationFile,error){
	if err:=target.chunks.Verify(ctx,chunk);err!=nil{return nil,err};stream:=&migrationChunkReader{ctx:ctx,chunks:target.chunks,chunk:chunk};reader:=tar.NewReader(stream);files:=[]migrationFile{};seen:=map[string]bool{};directories:=map[string]bool{};buffer:=make([]byte,128<<10)
	for{header,err:=reader.Next();if errors.Is(err,io.EOF){break};if err!=nil{return nil,err};if len(files)>=250000||header.Size<0||header.Mode&0o7000!=0||len(header.Xattrs)!=0{return nil,migration.ErrBlocked};name:=strings.TrimSuffix(header.Name,"/");relative,err:=access.ParseRelativePath(name);if err!=nil||relative.IsRoot()||seen[name]||len(strings.Split(name,"/"))>64{return nil,migration.ErrBlocked};seen[name]=true
		entry:=migrationFile{Path:name,Size:header.Size,Mode:uint32(header.Mode)&0o775}
		switch header.Typeflag{case tar.TypeDir:if header.Size!=0{return nil,migration.ErrInvalid};entry.Directory=true;case tar.TypeReg,tar.TypeRegA:digest:=sha256.New();written,copyErr:=io.CopyBuffer(digest,reader,buffer);if copyErr!=nil||written!=header.Size{return nil,errors.Join(migration.ErrInvalid,copyErr)};entry.Digest=hex.EncodeToString(digest.Sum(nil));default:return nil,migration.ErrBlocked}
		directories[name]=entry.Directory;files=append(files,entry)
	}
	// Reject hidden second archives or nonzero bytes after the tar end marker.
	for{count,err:=stream.Read(buffer);for _,value:=range buffer[:count]{if value!=0{return nil,migration.ErrInvalid}};if errors.Is(err,io.EOF){break};if err!=nil{return nil,err}}
	for _,file:=range files{for parent:=path.Dir(file.Path);parent!=".";parent=path.Dir(parent){if directory,present:=directories[parent];present&&!directory{return nil,migration.ErrInvalid}}}
	return files,nil
}

func (target *migrationHostTarget) importSite(ctx context.Context,scope migration.RuntimeScope,intent migration.ImportIntent)(migration.ImportEffect,error){
	source,err:=target.sitePayload(intent);if err!=nil{return migration.ImportEffect{},err};files,err:=target.inventoryFiles(ctx,source.Content[0]);if err!=nil{return migration.ImportEffect{},err}
	tenant,err:=site.NewTenantID(scope.TenantID);if err!=nil{return migration.ImportEffect{},err};identifier,err:=site.NewSiteID(intent.TargetID.String());if err!=nil{return migration.ImportEffect{},err};project,err:=site.NewProjectID("migration-"+intent.MigrationID.String());if err!=nil{return migration.ImportEffect{},err};hostname,err:=site.ParseHostname(source.PrimaryHostname);if err!=nil{return migration.ImportEffect{},err};profile,err:=migrationPHPProfile(source.PHPVersion);if err!=nil{return migration.ImportEffect{},err}
	// The project is target-owned migration grouping, never the legacy project.
	receipt,err:=target.hosting.Handle(ctx,hostingservice.CreateSite{CommandID:"migration-create-"+intent.EffectID,Actor:hostingservice.Actor{TenantID:tenant},TenantID:tenant,Site:site.CreateInput{ID:identifier,TenantID:tenant,ProjectID:project,PrimaryHostname:hostname,PHPProfile:profile}});if err!=nil{return migration.ImportEffect{},err};if receipt.Status!=hostingservice.OperationApplied||receipt.Effect.Outcome!=hostingservice.EffectConfirmed||receipt.Effect.ProbeDigest==""{return migration.ImportEffect{},migration.ErrAmbiguous}
	aggregate,err:=target.sites.Load(ctx,tenant,identifier);if err!=nil{return migration.ImportEffect{},err};if aggregate.Lifecycle()!=site.LifecycleProvisioning||aggregate.ProjectID()!=project||aggregate.PHPProfile()!=profile{return migration.ImportEffect{},migration.ErrConflict}
	for _,alias:=range source.Aliases{aliasHost,parseErr:=site.ParseHostname(alias);if parseErr!=nil{return migration.ImportEffect{},parseErr};present:=false;for _,binding:=range aggregate.Bindings(){if binding.Hostname==aliasHost{present=binding.Kind==site.BindingAlias;if !present{return migration.ImportEffect{},migration.ErrConflict}}};if present{continue};receipt,err=target.hosting.Handle(ctx,hostingservice.AttachDomainBinding{CommandID:"migration-alias-"+migrationHostDigest(alias+intent.EffectID),Actor:hostingservice.Actor{TenantID:tenant},TenantID:tenant,SiteID:identifier,ExpectedGeneration:aggregate.Generation(),Binding:site.DomainBinding{Hostname:aliasHost,Kind:site.BindingAlias}});if err!=nil||receipt.Effect.Outcome!=hostingservice.EffectConfirmed{return migration.ImportEffect{},errors.Join(migration.ErrAmbiguous,err)};aggregate,err=target.sites.Load(ctx,tenant,identifier);if err!=nil{return migration.ImportEffect{},err}}
	binding,err:=target.scopeBinding(ctx,intent.MigrationID);if err!=nil{return migration.ImportEffect{},err};root:=access.SiteRoot{SiteID:access.SiteID(identifier.String()),Kind:access.RootPublic};evidence:=[]string{receipt.Effect.ProbeDigest,binding};bytesWritten:=uint64(0)
	for _,file:=range files{if err=target.ensureMigrationDirectories(ctx,root,path.Dir(file.Path));err!=nil{return migration.ImportEffect{},err};if file.Directory{if err=target.ensureMigrationDirectories(ctx,root,file.Path);err!=nil{return migration.ImportEffect{},err}}}
	stream:=&migrationChunkReader{ctx:ctx,chunks:target.chunks,chunk:source.Content[0]};reader:=tar.NewReader(stream)
	for _,file:=range files{header,nextErr:=reader.Next();if nextErr!=nil||strings.TrimSuffix(header.Name,"/")!=file.Path{return migration.ImportEffect{},errors.Join(migration.ErrConflict,nextErr)};if file.Directory{continue};relative,_:=access.ParseRelativePath(file.Path);locator:=access.FileLocator{Root:root,Path:relative}
		proof,verifyErr:=target.verifyMigrationFile(ctx,locator,file);if verifyErr==nil{evidence=append(evidence,proof);bytesWritten+=uint64(file.Size);continue};if !errors.Is(verifyErr,access.ErrNotFound)&&!errors.Is(verifyErr,os.ErrNotExist){return migration.ImportEffect{},verifyErr}
		proof,err=target.uploadMigrationFile(ctx,scope,intent,locator,file,reader);if err!=nil{return migration.ImportEffect{},err};evidence=append(evidence,proof);bytesWritten+=uint64(file.Size)
	}
	return migrationHostEffect(intent,evidence,aggregate.Generation(),bytesWritten,uint64(len(files))),nil
}

func (target *migrationHostTarget) ensureMigrationDirectories(ctx context.Context,root access.SiteRoot,directory string)error{
	if directory=="."||directory==""{return nil};parts:=strings.Split(directory,"/");for index:=range parts{name:=strings.Join(parts[:index+1],"/");relative,err:=access.ParseRelativePath(name);if err!=nil{return err};locator:=access.FileLocator{Root:root,Path:relative};entry,err:=target.files.Executor.Stat(ctx,locator);if err==nil{if entry.Kind!=access.EntryDirectory{return migration.ErrConflict};continue};if !errors.Is(err,access.ErrNotFound)&&!errors.Is(err,os.ErrNotExist){return err};receipt,err:=target.files.Executor.CreateDirectory(ctx,locator,access.FileMetadata{Mode:0o750,Ownership:access.OwnershipSiteUser});if err!=nil||receipt.ExecutorReceipt==""{return errors.Join(migration.ErrAmbiguous,err)}};return nil
}

func (target *migrationHostTarget) verifyMigrationFile(ctx context.Context,locator access.FileLocator,file migrationFile)(string,error){
	entry,err:=target.files.Executor.Stat(ctx,locator);if err!=nil{return "",err};if entry.Kind!=access.EntryRegular||entry.Size!=file.Size{return "",migration.ErrConflict};digest:=sha256.New();for offset:=int64(0);offset<file.Size;{length:=int64(1<<20);if length>file.Size-offset{length=file.Size-offset};value,_,readErr:=target.files.Executor.ReadRange(ctx,locator,offset,length);if readErr!=nil||int64(len(value))!=length{return "",errors.Join(migration.ErrConflict,readErr)};digest.Write(value);offset+=length};if hex.EncodeToString(digest.Sum(nil))!=file.Digest{return "",migration.ErrConflict};after,err:=target.files.Executor.Stat(ctx,locator);if err!=nil||after.ETag!=entry.ETag||after.Size!=entry.Size{return "",errors.Join(migration.ErrConflict,err)};return migrationHostDigest(struct{Entry access.FileEntry;Digest string}{after,file.Digest}),nil
}

func (target *migrationHostTarget) uploadMigrationFile(ctx context.Context,scope migration.RuntimeScope,intent migration.ImportIntent,locator access.FileLocator,file migrationFile,reader io.Reader)(string,error){
	nonce:=make([]byte,16);if _,err:=rand.Read(nonce);err!=nil{return "",err};id:=access.UploadID("migration-"+hex.EncodeToString(nonce));now:=time.Now().UTC()
	session,err:=target.files.BeginUpload(ctx,access.UploadSession{ID:id,Mutation:access.Mutation{CommandID:access.CommandID(id),Actor:access.AuditActor{TenantID:access.TenantID(scope.TenantID),PrincipalID:access.PrincipalID("migration-"+scope.MigrationID.String())},At:now},Destination:locator,Integrity:access.Integrity{Algorithm:"sha256",Digest:file.Digest,Size:file.Size},Condition:access.WriteCondition{IfNoneMatch:true},State:access.UploadOpen,Generation:1,ExpiresAt:now.Add(time.Hour)});if err!=nil{return "",err};complete:=false;defer func(){if !complete{cleanup,cancel:=context.WithTimeout(context.WithoutCancel(ctx),5*time.Second);defer cancel();_ = target.files.AbortUpload(cleanup,session.ID)}}()
	buffer:=make([]byte,1<<20);offset:=int64(0);for offset<file.Size{length:=int64(len(buffer));if length>file.Size-offset{length=file.Size-offset};count,readErr:=io.ReadFull(reader,buffer[:length]);if readErr!=nil{return "",readErr};digest:=sha256.Sum256(buffer[:count]);if _,err=target.files.AppendUpload(ctx,id,access.UploadChunk{Offset:offset,Data:buffer[:count],SHA256:hex.EncodeToString(digest[:])});err!=nil{return "",err};offset+=int64(count)}
	receipt,err:=target.files.CommitUpload(ctx,id);if err!=nil||receipt.ExecutorReceipt==""{return "",errors.Join(migration.ErrAmbiguous,err)};complete=true
	metadata,err:=target.files.Executor.SetMetadata(ctx,locator,access.FileMetadata{Mode:file.Mode,Ownership:access.OwnershipSiteUser},access.WriteCondition{IfMatch:receipt.ETag});if err!=nil||metadata.ExecutorReceipt==""{return "",errors.Join(migration.ErrAmbiguous,err)};proof,err:=target.verifyMigrationFile(ctx,locator,file);if err!=nil{return "",err};return migrationHostDigest([]string{receipt.ExecutorReceipt,metadata.ExecutorReceipt,proof}),nil
}

func (target *migrationHostTarget) probeSite(ctx context.Context,scope migration.RuntimeScope,intent migration.ImportIntent,active bool)(string,error){
	source,err:=target.sitePayload(intent);if err!=nil{return "",err};tenant,err:=site.NewTenantID(scope.TenantID);if err!=nil{return "",err};id,err:=site.NewSiteID(intent.TargetID.String());if err!=nil{return "",err};aggregate,err:=target.sites.Load(ctx,tenant,id);if err!=nil{return "",err};if active&&aggregate.Lifecycle()!=site.LifecycleActive||!active&&aggregate.Lifecycle()!=site.LifecycleProvisioning{return "",migration.ErrConflict}
	files,err:=target.inventoryFiles(ctx,source.Content[0]);if err!=nil{return "",err};proofs:=[]string{};root:=access.SiteRoot{SiteID:access.SiteID(id.String()),Kind:access.RootPublic};for _,file:=range files{relative,_:=access.ParseRelativePath(file.Path);locator:=access.FileLocator{Root:root,Path:relative};if file.Directory{entry,statErr:=target.files.Executor.Stat(ctx,locator);if statErr!=nil||entry.Kind!=access.EntryDirectory{return "",errors.Join(migration.ErrConflict,statErr)};proofs=append(proofs,migrationHostDigest(entry));continue};proof,readErr:=target.verifyMigrationFile(ctx,locator,file);if readErr!=nil{return "",readErr};proofs=append(proofs,proof)}
	if !active{return migrationHostDigest(struct{Files []string;Lifecycle site.Lifecycle;Generation uint64}{proofs,aggregate.Lifecycle(),aggregate.Generation()}),nil}
	transport:=&http.Transport{Proxy:nil,DialContext:func(call context.Context,_,_ string)(net.Conn,error){return (&net.Dialer{Timeout:5*time.Second}).DialContext(call,"tcp","127.0.0.1:80")},DisableKeepAlives:true};defer transport.CloseIdleConnections();client:=&http.Client{Transport:transport,Timeout:10*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
	request,err:=http.NewRequestWithContext(ctx,http.MethodGet,"http://127.0.0.1/",nil);if err!=nil{return "",err};request.Host=source.PrimaryHostname;response,err:=client.Do(request);if err!=nil{return "",err};defer response.Body.Close();body,err:=io.ReadAll(io.LimitReader(response.Body,64<<10));if err!=nil{return "",err}
	if active{if response.StatusCode<200||response.StatusCode>=400{return "",migration.ErrBlocked}}else if response.StatusCode!=http.StatusServiceUnavailable{return "",migration.ErrBlocked}
	proofs=append(proofs,migrationHostDigest(struct{Host string;Status int;Body string}{source.PrimaryHostname,response.StatusCode,migrationHostDigest(body)}));return migrationHostDigest(proofs),nil
}
