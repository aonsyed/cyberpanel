package cyberpanel

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

type ArtifactSource interface {
	MediaType() string
	Compression() string
	EncryptionDomain() string
	WriteSnapshot(context.Context, io.Writer) (uint64, error)
}

type MaterializedCatalog struct {
	root *os.Root
	sources map[ArtifactID]ArtifactSource
	current map[ArtifactID]materializedArtifact
	maximumArtifactBytes uint64
	mu sync.Mutex
}

type materializedArtifact struct {
	name string
	descriptor migration.Chunk
}

func OpenMaterializedCatalog(rootPath string, sources map[ArtifactID]ArtifactSource, maximumArtifactBytes uint64) (*MaterializedCatalog, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(rootPath)
	if err != nil || !before.IsDir() || before.Mode().Perm()&0o077 != 0 {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil { return nil, err }
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, ErrInvalid
	}
	if maximumArtifactBytes == 0 { maximumArtifactBytes = 64 << 30 }
	if maximumArtifactBytes < 1<<20 { root.Close(); return nil, ErrInvalid }
	copySources := make(map[ArtifactID]ArtifactSource, len(sources))
	for id, source := range sources {
		if !id.Valid() || source == nil || strings.TrimSpace(source.MediaType()) == "" {
			root.Close()
			return nil, ErrInvalid
		}
		copySources[id] = source
	}
	return &MaterializedCatalog{root: root, sources: copySources, current: map[ArtifactID]materializedArtifact{}, maximumArtifactBytes: maximumArtifactBytes}, nil
}

func (c *MaterializedCatalog) Close() error {
	if c == nil || c.root == nil { return nil }
	c.mu.Lock();defer c.mu.Unlock();var failures []error;for _,source:=range c.sources{if closer,ok:=source.(io.Closer);ok{failures=append(failures,closer.Close())}};failures=append(failures,c.root.Close());return errors.Join(failures...)
}

// Register is used only by a local typed collector to bind an opaque artifact
// identifier to a source discovered in an already approved account. It is not
// part of the extractor's remote SourceReader surface.
func (c *MaterializedCatalog) Register(id ArtifactID, source ArtifactSource) error {
	if c==nil||c.root==nil||!id.Valid()||source==nil||strings.TrimSpace(source.MediaType())==""{return ErrInvalid}
	c.mu.Lock();defer c.mu.Unlock();if previous:=c.sources[id];previous!=nil{if closer,ok:=previous.(io.Closer);ok{_ = closer.Close()}};c.sources[id]=source;delete(c.current,id);return nil
}

func (c *MaterializedCatalog) Describe(ctx context.Context, id ArtifactID) (migration.Chunk, error) {
	if c == nil || c.root == nil || ctx == nil || !id.Valid() { return migration.Chunk{}, ErrInvalid }
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.materialize(ctx, id)
}

func (c *MaterializedCatalog) Open(ctx context.Context, id ArtifactID) (io.ReadCloser, error) {
	if c == nil || c.root == nil || ctx == nil || !id.Valid() { return nil, ErrInvalid }
	c.mu.Lock()
	defer c.mu.Unlock()
	current, exists := c.current[id]
	if !exists { return nil, migration.ErrNotFound }
	before, err := c.root.Lstat(current.name)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 || uint64(before.Size()) != current.descriptor.Size { return nil, ErrChanged }
	file, err := c.root.Open(current.name)
	if err != nil { return nil, err }
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o400 { file.Close(); return nil, ErrChanged }
	return file, nil
}

func (c *MaterializedCatalog) materialize(ctx context.Context, id ArtifactID) (migration.Chunk, error) {
	source := c.sources[id]
	if source == nil { return migration.Chunk{}, migration.ErrNotFound }
	temporary, err := randomArtifactName(id)
	if err != nil { return migration.Chunk{}, err }
	file, err := c.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil { return migration.Chunk{}, err }
	keep := true
	defer func(){ file.Close(); if keep { _ = c.root.Remove(temporary) } }()
	hash := sha256.New()
	limited := &boundedWriter{destination: io.MultiWriter(file, hash), remaining: c.maximumArtifactBytes}
	objects, err := source.WriteSnapshot(ctx, limited)
	if err != nil { return migration.Chunk{}, err }
	if limited.written == 0 || objects == 0 { return migration.Chunk{}, ErrInvalid }
	if err := file.Sync(); err != nil { return migration.Chunk{}, err }
	if err := file.Chmod(0o400); err != nil { return migration.Chunk{}, err }
	if err := file.Close(); err != nil { return migration.Chunk{}, err }
	digest := hex.EncodeToString(hash.Sum(nil))
	final := "artifact-"+digest
	if err := c.root.Link(temporary, final); err != nil {
		if !errors.Is(err, os.ErrExist) { return migration.Chunk{}, err }
		if verifyErr := c.verify(final, digest, limited.written); verifyErr != nil { return migration.Chunk{}, verifyErr }
	}
	if err := c.root.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) { return migration.Chunk{}, err }
	keep = false
	descriptor := migration.Chunk{Digest: digest, Size: limited.written, MediaType: source.MediaType(), Compression: source.Compression(), EncryptionDomain: source.EncryptionDomain(), ObjectCount: objects}
	c.current[id] = materializedArtifact{name: final, descriptor: descriptor}
	return descriptor, nil
}

func (c *MaterializedCatalog) verify(name, digest string, size uint64) error {
	file, err := c.root.Open(name)
	if err != nil { return err }
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || info.Size() < 0 || uint64(info.Size()) != size { return ErrChanged }
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil { return err }
	expected, _ := hex.DecodeString(digest)
	if subtle.ConstantTimeCompare(hash.Sum(nil), expected) != 1 { return ErrChanged }
	return nil
}

type boundedWriter struct { destination io.Writer; remaining uint64; written uint64 }
func (w *boundedWriter) Write(value []byte)(int,error){if uint64(len(value))>w.remaining{return 0,migration.ErrCapacity};count,err:=w.destination.Write(value);w.remaining-=uint64(count);w.written+=uint64(count);return count,err}

type RegularFileSource struct {
	root *os.Root
	name string
	mediaType string
	encryptionDomain string
}

func OpenRegularFileSource(rootPath, relativeName, mediaType, encryptionDomain string)(*RegularFileSource,error){
	if rootPath==""||!filepath.IsAbs(rootPath)||filepath.Clean(rootPath)!=rootPath||!safeRelativeName(relativeName)||strings.TrimSpace(mediaType)==""{return nil,ErrInvalid};before,err:=os.Lstat(rootPath);if err!=nil||!before.IsDir(){return nil,ErrInvalid};root,err:=os.OpenRoot(rootPath);if err!=nil{return nil,err};after,err:=root.Stat(".");if err!=nil||!os.SameFile(before,after){root.Close();return nil,ErrInvalid};return &RegularFileSource{root:root,name:relativeName,mediaType:mediaType,encryptionDomain:encryptionDomain},nil
}
func(s *RegularFileSource)Close()error{if s==nil||s.root==nil{return nil};return s.root.Close()}
func(s *RegularFileSource)MediaType()string{return s.mediaType}
func(s *RegularFileSource)Compression()string{return "identity"}
func(s *RegularFileSource)EncryptionDomain()string{return s.encryptionDomain}
func(s *RegularFileSource)WriteSnapshot(ctx context.Context,destination io.Writer)(uint64,error){if s==nil||s.root==nil||ctx==nil||destination==nil{return 0,ErrInvalid};before,err:=s.root.Lstat(s.name);if err!=nil||!before.Mode().IsRegular(){return 0,err};file,err:=s.root.Open(s.name);if err!=nil{return 0,err};defer file.Close();after,err:=file.Stat();if err!=nil||!sameFileState(before,after)||!after.Mode().IsRegular(){return 0,ErrChanged};_,err=copyWithContext(ctx,destination,file);if err!=nil{return 0,err};final,err:=file.Stat();if err!=nil||!sameFileState(after,final){return 0,ErrChanged};return 1,nil}

type DirectoryTreeSource struct { root *os.Root; rootPath string; mediaType string; encryptionDomain string }
func OpenDirectoryTreeSource(rootPath,mediaType,encryptionDomain string)(*DirectoryTreeSource,error){if rootPath==""||!filepath.IsAbs(rootPath)||filepath.Clean(rootPath)!=rootPath||strings.TrimSpace(mediaType)==""{return nil,ErrInvalid};before,err:=os.Lstat(rootPath);if err!=nil||!before.IsDir(){return nil,ErrInvalid};root,err:=os.OpenRoot(rootPath);if err!=nil{return nil,err};after,err:=root.Stat(".");if err!=nil||!os.SameFile(before,after){root.Close();return nil,ErrInvalid};return &DirectoryTreeSource{root:root,rootPath:rootPath,mediaType:mediaType,encryptionDomain:encryptionDomain},nil}
func(s *DirectoryTreeSource)Close()error{if s==nil||s.root==nil{return nil};return s.root.Close()}
func(s *DirectoryTreeSource)MediaType()string{return s.mediaType}
func(s *DirectoryTreeSource)Compression()string{return "tar"}
func(s *DirectoryTreeSource)EncryptionDomain()string{return s.encryptionDomain}
func(s *DirectoryTreeSource)WriteSnapshot(ctx context.Context,destination io.Writer)(uint64,error){if s==nil||s.root==nil||ctx==nil||destination==nil{return 0,ErrInvalid};writer:=tar.NewWriter(destination);objects,err:=s.writeDirectory(ctx,writer,".");closeErr:=writer.Close();return objects+1,errors.Join(err,closeErr)}
func(s *DirectoryTreeSource)writeDirectory(ctx context.Context,writer *tar.Writer,directory string)(uint64,error){select{case<-ctx.Done():return 0,ctx.Err();default:};handle,err:=s.root.Open(directory);if err!=nil{return 0,err};entries,err:=handle.ReadDir(-1);handle.Close();if err!=nil{return 0,err};sort.Slice(entries,func(i,j int)bool{return entries[i].Name()<entries[j].Name()});var objects uint64;for _,entry:=range entries{name:=entry.Name();if name==""||name=="."||name==".."||strings.ContainsAny(name,"/\\"){return objects,ErrInvalid};relative:=name;if directory!="."{relative=directory+"/"+name};info,err:=s.root.Lstat(relative);if err!=nil{return objects,err};header:=&tar.Header{Name:relative,Mode:int64(info.Mode().Perm()),ModTime:time.Unix(0,0),AccessTime:time.Unix(0,0),ChangeTime:time.Unix(0,0),Uid:0,Gid:0,Uname:"",Gname:""};switch{case info.IsDir():header.Typeflag=tar.TypeDir;header.Name+="/";if err:=writer.WriteHeader(header);err!=nil{return objects,err};objects++;childCount,err:=s.writeDirectory(ctx,writer,relative);objects+=childCount;if err!=nil{return objects,err};case info.Mode().IsRegular():header.Typeflag=tar.TypeReg;header.Size=info.Size();if header.Size<0{return objects,ErrInvalid};if err:=writer.WriteHeader(header);err!=nil{return objects,err};file,err:=s.root.Open(relative);if err!=nil{return objects,err};after,err:=file.Stat();if err!=nil||!sameFileState(info,after)||!after.Mode().IsRegular(){file.Close();return objects,ErrChanged};written,copyErr:=copyWithContext(ctx,writer,file);final,statErr:=file.Stat();closeErr:=file.Close();if copyErr!=nil||statErr!=nil||closeErr!=nil{return objects,errors.Join(copyErr,statErr,closeErr)};if written!=info.Size()||!sameFileState(after,final){return objects,ErrChanged};objects++;case info.Mode()&os.ModeSymlink!=0:linkPath:=filepath.Join(s.rootPath,filepath.FromSlash(relative));target,readErr:=os.Readlink(linkPath);if readErr!=nil{return objects,readErr};after,statErr:=os.Lstat(linkPath);if statErr!=nil||!sameFileState(info,after){return objects,ErrChanged};if filepath.IsAbs(target){return objects,ErrDenied};clean:=filepath.Clean(filepath.Join(filepath.Dir(relative),target));if clean==".."||strings.HasPrefix(clean,"../"){return objects,ErrDenied};header.Typeflag=tar.TypeSymlink;header.Linkname=target;if err:=writer.WriteHeader(header);err!=nil{return objects,err};objects++;default:return objects,ErrDenied}}
	return objects,nil}

type StreamArtifactSource struct { mediaType,compression,encryptionDomain string; write func(context.Context,io.Writer)(uint64,error) }
func NewStreamArtifactSource(mediaType,compression,encryptionDomain string,write func(context.Context,io.Writer)(uint64,error))(*StreamArtifactSource,error){if strings.TrimSpace(mediaType)==""||write==nil{return nil,ErrInvalid};return &StreamArtifactSource{mediaType:mediaType,compression:compression,encryptionDomain:encryptionDomain,write:write},nil}
func(s *StreamArtifactSource)MediaType()string{return s.mediaType};func(s *StreamArtifactSource)Compression()string{return s.compression};func(s *StreamArtifactSource)EncryptionDomain()string{return s.encryptionDomain};func(s *StreamArtifactSource)WriteSnapshot(ctx context.Context,w io.Writer)(uint64,error){return s.write(ctx,w)}

func randomArtifactName(id ArtifactID)(string,error){random:=make([]byte,16);if _,err:=rand.Read(random);err!=nil{return "",err};sum:=sha256.Sum256([]byte(id));return ".tmp-"+hex.EncodeToString(sum[:8])+"-"+hex.EncodeToString(random),nil}
func safeRelativeName(value string)bool{return value!=""&&!filepath.IsAbs(value)&&filepath.Clean(value)==value&&value!=".."&&!strings.HasPrefix(value,"../")&&!strings.Contains(value,"\\")}
func copyWithContext(ctx context.Context,destination io.Writer,source io.Reader)(int64,error){buffer:=make([]byte,128<<10);var written int64;for{select{case<-ctx.Done():return written,ctx.Err();default:};count,readErr:=source.Read(buffer);if count>0{output,writeErr:=destination.Write(buffer[:count]);written+=int64(output);if writeErr!=nil{return written,writeErr};if output!=count{return written,io.ErrShortWrite}};if errors.Is(readErr,io.EOF){return written,nil};if readErr!=nil{return written,readErr};if count==0{return written,io.ErrNoProgress}}}
func sameFileState(left,right os.FileInfo)bool{return left!=nil&&right!=nil&&os.SameFile(left,right)&&left.Size()==right.Size()&&left.ModTime().Equal(right.ModTime())}

var _ ArtifactCatalog=(*MaterializedCatalog)(nil)
