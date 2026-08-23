package apiserver

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type SocketOptions struct{Path string;DirectoryMode os.FileMode;SocketMode os.FileMode;UID int;GID int}
func ListenUnix(options SocketOptions)(*net.UnixListener,error){if !filepath.IsAbs(options.Path)||filepath.Clean(options.Path)!=options.Path{return nil,invalid("Unix socket path")};if options.DirectoryMode==0{options.DirectoryMode=0710};if options.SocketMode==0{options.SocketMode=0660};if options.DirectoryMode.Perm()&0002!=0||options.SocketMode.Perm()&0007!=0{return nil,invalid("Unix socket permissions")};directory:=filepath.Dir(options.Path);if err:=os.MkdirAll(directory,options.DirectoryMode);err!=nil{return nil,err};info,err:=os.Lstat(directory);if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0002!=0{return nil,invalid("Unix socket directory")};if existing,statErr:=os.Lstat(options.Path);statErr==nil{if existing.Mode()&os.ModeSocket==0{return nil,fmt.Errorf("socket path exists and is not a socket")};connection,dialErr:=net.DialTimeout("unix",options.Path,250000000);if dialErr==nil{_ = connection.Close();return nil,fmt.Errorf("%w: Unix socket is already active",ErrConflict)};if err=os.Remove(options.Path);err!=nil{return nil,err}}else if !errors.Is(statErr,os.ErrNotExist){return nil,statErr};listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:options.Path,Net:"unix"});if err!=nil{return nil,err};if options.UID>=0||options.GID>=0{if err=os.Chown(options.Path,options.UID,options.GID);err!=nil{listener.Close();return nil,err}};if err=os.Chmod(options.Path,options.SocketMode);err!=nil{listener.Close();return nil,err};return listener,nil}

type StaticPeerPolicy struct{AllowedUIDs map[uint32]struct{}}
func NewStaticPeerPolicy(values ...uint32)(*StaticPeerPolicy,error){allowed:=map[uint32]struct{}{};for _,value:=range values{allowed[value]=struct{}{}};if len(allowed)==0{return nil,invalid("peer UID policy")};return &StaticPeerPolicy{AllowedUIDs:allowed},nil}
