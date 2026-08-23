//go:build linux

package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/backup"
)

// LocalCaptureSpool is the narrow handoff between component capturers and
// repository providers. Every operation stays below a fixed service-owned
// root, traverses directories by descriptor, and addresses payloads by
// SHA-256.
type LocalCaptureSpool struct{Root string;rootFD int}
func OpenLocalCaptureSpool(root string)(*LocalCaptureSpool,error){base:="/var/lib/cyberpanel/backup-spool";if !filepath.IsAbs(root)||filepath.Clean(root)!=root||(root!=base&&!strings.HasPrefix(root,base+"/")){return nil,ErrInvalid};fd,err:=openRootOwnedTree(root);if err!=nil{return nil,err};spool:=&LocalCaptureSpool{Root:root,rootFD:fd};if directory,openErr:=spool.openEffectRoot(true);openErr!=nil{spool.Close();return nil,openErr}else{syscall.Close(directory)};return spool,nil}
func (spool *LocalCaptureSpool)Close()error{if spool.rootFD<0{return nil};err:=syscall.Close(spool.rootFD);spool.rootFD=-1;return err}
func (spool *LocalCaptureSpool)PutCaptureObject(ctx context.Context,session backup.CaptureSession,object backup.CaptureObject,reader backup.ReadCloser,effect string)(backup.ObjectDescriptor,error){if spool==nil||spool.rootFD<0||session.ID==""||object.LogicalKey==""||effect==""||reader==nil{return backup.ObjectDescriptor{},ErrInvalid};select{case <-ctx.Done():return backup.ObjectDescriptor{},ctx.Err();default:};effectDirectory,err:=spool.openEffect(effect,true);if err!=nil{return backup.ObjectDescriptor{},err};defer syscall.Close(effectDirectory);partial:="partial-"+hashText(session.ID+"\x00"+object.LogicalKey)[:48];fd,err:=syscall.Openat(effectDirectory,partial,syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0600);if errors.Is(err,syscall.EEXIST){_ = unlinkAt(effectDirectory,partial,false);fd,err=syscall.Openat(effectDirectory,partial,syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0600)};if err!=nil{return backup.ObjectDescriptor{},err};file:=os.NewFile(uintptr(fd),partial);hasher:=sha256.New();written,copyErr:=io.Copy(io.MultiWriter(file,hasher),io.LimitReader(reader,int64(object.Size)+1));syncErr:=file.Sync();closeErr:=file.Close();if copyErr!=nil||syncErr!=nil||closeErr!=nil||uint64(written)!=object.Size{_ = unlinkAt(effectDirectory,partial,false);return backup.ObjectDescriptor{},errors.Join(ErrIntegrity,copyErr,syncErr,closeErr)};digestValue:=hex.EncodeToString(hasher.Sum(nil));final:="object-"+digestValue;if err=renameNoReplace(effectDirectory,partial,effectDirectory,final);err!=nil{valid,verifyErr:=verifyRegularAt(effectDirectory,final,digestValue,object.Size);_ = unlinkAt(effectDirectory,partial,false);if verifyErr!=nil||!valid{return backup.ObjectDescriptor{},errors.Join(err,verifyErr)}};return backup.ObjectDescriptor{Key:object.LogicalKey,Digest:digestValue,Size:object.Size,Mode:object.Mode},nil}
func (spool *LocalCaptureSpool)OpenObject(ctx context.Context,object backup.ObjectDescriptor,effect string,offset uint64)(io.ReadCloser,error){if spool==nil||spool.rootFD<0||effect==""||validateObject(object)!=nil||offset>object.Size{return nil,ErrInvalid};select{case <-ctx.Done():return nil,ctx.Err();default:};directory,err:=spool.openEffect(effect,false);if err!=nil{return nil,err};fd,err:=syscall.Openat(directory,"object-"+object.Digest,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0);syscall.Close(directory);if errors.Is(err,syscall.ENOENT){return nil,ErrNotFound};if err!=nil{return nil,err};file:=os.NewFile(uintptr(fd),object.Digest);info,err:=file.Stat();if err!=nil||!info.Mode().IsRegular()||uint64(info.Size())!=object.Size{file.Close();return nil,ErrIntegrity};if _,err=file.Seek(int64(offset),io.SeekStart);err!=nil{file.Close();return nil,err};return file,nil}
func (spool *LocalCaptureSpool)DiscardEffect(ctx context.Context,effect string)error{if spool==nil||spool.rootFD<0||effect==""{return ErrInvalid};select{case <-ctx.Done():return ctx.Err();default:};directory,err:=spool.openEffect(effect,false);if errors.Is(err,ErrNotFound){return nil};if err!=nil{return err};effectDirectory:=os.NewFile(uintptr(directory),"effect");entries,err:=effectDirectory.ReadDir(-1);if err!=nil{effectDirectory.Close();return err};for _,entry:=range entries{if entry.IsDir()||!strings.HasPrefix(entry.Name(),"object-")&&!strings.HasPrefix(entry.Name(),"partial-"){effectDirectory.Close();return ErrIntegrity};if err=unlinkAt(directory,entry.Name(),false);err!=nil&&!errors.Is(err,ErrNotFound){effectDirectory.Close();return err}};if err=effectDirectory.Close();err!=nil{return err};effects,err:=spool.openEffectRoot(false);if err!=nil{return err};err=unlinkAt(effects,spool.effectName(effect),true);syscall.Close(effects);if errors.Is(err,ErrNotFound){return nil};return err}
func (spool *LocalCaptureSpool)openEffectRoot(create bool)(int,error){if spool.rootFD<0{return -1,ErrInvalid};repository:=LocalRepository{rootFD:spool.rootFD};return repository.openDir("effects",create)}
func (spool *LocalCaptureSpool)openEffect(effect string,create bool)(int,error){root,err:=spool.openEffectRoot(create);if err!=nil{return -1,err};defer syscall.Close(root);name:=spool.effectName(effect);fd,err:=syscall.Openat(root,name,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0);if err!=nil&&create&&errors.Is(err,syscall.ENOENT){if mkdirErr:=syscall.Mkdirat(root,name,0700);mkdirErr!=nil&&!errors.Is(mkdirErr,syscall.EEXIST){return -1,mkdirErr};fd,err=syscall.Openat(root,name,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)};if errors.Is(err,syscall.ENOENT){return -1,ErrNotFound};return fd,err}
func (spool *LocalCaptureSpool)effectName(effect string)string{return "effect-"+hashText(effect)[:48]}
