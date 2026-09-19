package cpanel

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

type archiveArtifactSpec struct {
	exact string
	prefix string
	tree bool
	mediaType string
	encryptionDomain string
}

type archiveArtifactSource struct {
	archive approvedArchive
	spec archiveArtifactSpec
	limits ArchiveLimits
}

func(s *archiveArtifactSource)MediaType()string{if s.spec.encryptionDomain=="mailbox-data"&&strings.Contains(s.spec.mediaType,"mailbox-maildir+"){return migration.MaildirV1MediaType};return s.spec.mediaType}
func(s *archiveArtifactSource)Compression()string{if s.spec.tree{return"tar"};return"identity"}
func(s *archiveArtifactSource)EncryptionDomain()string{return s.spec.encryptionDomain}
func(s *archiveArtifactSource)WriteSnapshot(ctx context.Context,destination io.Writer)(uint64,error){if s==nil||ctx==nil||destination==nil||(s.spec.exact=="")==(!s.spec.tree)||(s.spec.tree&&s.spec.prefix==""){return 0,ErrInvalid};reader,closeReader,before,err:=openApprovedArchive(s.archive);if err!=nil{return 0,err};defer closeReader();if !s.spec.tree{return s.writeExact(ctx,reader,destination,before)};if s.MediaType()==migration.MaildirV1MediaType{return s.writeMaildirTree(ctx,reader,destination,before)};return s.writeTree(ctx,reader,destination,before)}

func(s *archiveArtifactSource)writeExact(ctx context.Context,reader *tar.Reader,destination io.Writer,before os.FileInfo)(uint64,error){found:=false;for{select{case<-ctx.Done():return 0,ctx.Err();default:};header,err:=reader.Next();if errors.Is(err,io.EOF){break};if err!=nil{return 0,err};logical,err:=logicalArchiveName(header.Name);if err!=nil{return 0,err};if logical!=s.spec.exact{continue};if found||header.Typeflag!=tar.TypeReg&&header.Typeflag!=tar.TypeRegA||header.Size<=0||uint64(header.Size)>s.limits.MaximumExpandedBytes{return 0,ErrInvalid};written,err:=copyBounded(ctx,destination,reader,uint64(header.Size));if err!=nil||written!=uint64(header.Size){return 0,errors.Join(err,io.ErrUnexpectedEOF)};found=true};if !found{return 0,migrationNotFound()};if err:=archiveUnchanged(s.archive.path,before);err!=nil{return 0,err};return 1,nil}

func(s *archiveArtifactSource)writeTree(ctx context.Context,reader *tar.Reader,destination io.Writer,before os.FileInfo)(uint64,error){writer:=tar.NewWriter(destination);closed:=false;defer func(){if !closed{_ = writer.Close()}}();seen:=map[string]struct{}{};objects:=uint64(1);expanded:=uint64(0);for{select{case<-ctx.Done():return 0,ctx.Err();default:};header,err:=reader.Next();if errors.Is(err,io.EOF){break};if err!=nil{return 0,err};logical,err:=logicalArchiveName(header.Name);if err!=nil{return 0,err};if !strings.HasPrefix(logical,s.spec.prefix){continue};relative:=strings.TrimPrefix(logical,s.spec.prefix);relative=strings.TrimPrefix(relative,"/");if relative==""{continue};relative=filepath.ToSlash(filepath.Clean(relative));if relative=="."||relative==".."||strings.HasPrefix(relative,"../")||strings.HasPrefix(relative,"/"){return 0,ErrInvalid};if _,duplicate:=seen[relative];duplicate{return 0,ErrInvalid};seen[relative]=struct{}{};canonical:=&tar.Header{Name:relative,Mode:header.Mode&0o777,Uid:0,Gid:0,Uname:"",Gname:"",ModTime:time.Unix(0,0),AccessTime:time.Unix(0,0),ChangeTime:time.Unix(0,0)};switch header.Typeflag{case tar.TypeDir:canonical.Typeflag=tar.TypeDir;canonical.Name=strings.TrimSuffix(relative,"/")+"/";case tar.TypeReg,tar.TypeRegA:if header.Size<0||uint64(header.Size)>s.limits.MaximumExpandedBytes-expanded{return 0,migrationCapacity()};expanded+=uint64(header.Size);canonical.Typeflag=tar.TypeReg;canonical.Size=header.Size;case tar.TypeSymlink:target:=filepath.ToSlash(filepath.Clean(header.Linkname));if filepath.IsAbs(target){return 0,ErrDenied};resolved:=filepath.Clean(filepath.Join(filepath.Dir(relative),target));if resolved==".."||strings.HasPrefix(resolved,"../"){return 0,ErrDenied};canonical.Typeflag=tar.TypeSymlink;canonical.Linkname=target;default:return 0,ErrDenied};if err:=writer.WriteHeader(canonical);err!=nil{return 0,err};if canonical.Typeflag==tar.TypeReg{written,err:=copyBounded(ctx,writer,reader,uint64(header.Size));if err!=nil||written!=uint64(header.Size){return 0,errors.Join(err,io.ErrUnexpectedEOF)}};objects++;if objects>s.limits.MaximumEntries{return 0,migrationCapacity()}};if err:=writer.Close();err!=nil{return 0,err};closed=true;if err:=archiveUnchanged(s.archive.path,before);err!=nil{return 0,err};return objects,nil}

type bytesArtifactSource struct{value []byte;mediaType string;encryptionDomain string}
func(s *bytesArtifactSource)MediaType()string{return s.mediaType};func(s *bytesArtifactSource)Compression()string{return"identity"};func(s *bytesArtifactSource)EncryptionDomain()string{return s.encryptionDomain};func(s *bytesArtifactSource)WriteSnapshot(ctx context.Context,destination io.Writer)(uint64,error){if s==nil||ctx==nil||destination==nil||len(s.value)==0{return 0,ErrInvalid};select{case<-ctx.Done():return 0,ctx.Err();default:};written,err:=destination.Write(s.value);if err!=nil{return 0,err};if written!=len(s.value){return 0,io.ErrShortWrite};return 1,nil}

func archiveUnchanged(path string,before os.FileInfo)error{after,err:=os.Lstat(path);if err!=nil||!sameFileSnapshot(before,after){return ErrArchiveChanged};return nil}
func copyBounded(ctx context.Context,destination io.Writer,source io.Reader,size uint64)(uint64,error){buffer:=make([]byte,128<<10);var written uint64;for written<size{select{case<-ctx.Done():return written,ctx.Err();default:};remaining:=size-written;window:=len(buffer);if uint64(window)>remaining{window=int(remaining)};count,readErr:=source.Read(buffer[:window]);if count>0{output,writeErr:=destination.Write(buffer[:count]);written+=uint64(output);if writeErr!=nil{return written,writeErr};if output!=count{return written,io.ErrShortWrite}};if readErr!=nil{return written,readErr};if count==0{return written,io.ErrNoProgress}};return written,nil}

func migrationNotFound()error{return migration.ErrNotFound}
func migrationCapacity()error{return migration.ErrCapacity}
