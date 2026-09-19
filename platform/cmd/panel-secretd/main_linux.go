//go:build linux

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	_ "modernc.org/sqlite"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	secretDatabasePath = "/var/lib/cyberpanel-secrets/secrets.db"
	secretEpochPath    = "/var/lib/cyberpanel-secrets/key-epoch"
	secretKeyPath      = "/run/credentials/panel-secretd.service/wrapping.key"
)

func main(){if err:=run();err!=nil{log.Fatal(err)}}

func run()error{
	if os.Geteuid()==0{return errors.New("panel-secretd refuses to run as root")}
	ownerUID:=os.Geteuid();controlUID,controlGID,err:=lookupIdentity("cyberpanel");if err!=nil{return err}
	database,err:=openSecretDatabase(secretDatabasePath,ownerUID);if err!=nil{return err};defer database.Close()
	store,err:=secrets.NewStore(database);if err!=nil{return err};ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM);defer cancel();if err=store.Bootstrap(ctx);err!=nil{return err}
	epoch,err:=readKeyEpoch(secretEpochPath,ownerUID);if err!=nil{return err};key,err:=secrets.NewSystemdCredentialKEK(secretKeyPath,epoch);if err!=nil{return err};broker,err:=secrets.NewBroker(store,key,secrets.LinuxConsumerRegistry{});if err!=nil{return err}
	materialPolicy,err:=secrets.NewLinuxMaterialPeerAuthorizer(0,uint32(controlUID));if err!=nil{return err}
	managementPolicy,err:=secrets.NewLinuxManagementPeerAuthorizer(0,uint32(controlUID));if err!=nil{return err}
	materialListener,err:=secrets.ListenMaterialBroker(ownerUID,controlGID);if err!=nil{return err};defer materialListener.Close()
	managementListener,err:=secrets.ListenManagementBroker(ownerUID,controlGID);if err!=nil{return err};defer managementListener.Close()
	materialServer:=&secrets.MaterialServer{Authorizer:materialPolicy,Broker:broker,MaximumConcurrent:64}
	managementServer:=&secrets.ManagementServer{Authorizer:managementPolicy,Broker:broker,MaximumConcurrent:8}
	serveErrors:=make(chan error,2)
	go func(){serveErrors<-materialServer.Serve(materialListener)}()
	go func(){serveErrors<-managementServer.Serve(managementListener)}()
	select{case <-ctx.Done():case err=<-serveErrors:}
	_ = materialListener.Close();_ = managementListener.Close()
	for remaining:=0;remaining<2;remaining++{select{case serveErr:=<-serveErrors:if serveErr!=nil&&!errors.Is(serveErr,net.ErrClosed){err=errors.Join(err,serveErr)};default:}}
	return err
}

func openSecretDatabase(path string,ownerUID int)(*sql.DB,error){info,err:=os.Lstat(path);if err!=nil{return nil,err};stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=0600||int(stat.Uid)!=ownerUID{return nil,errors.New("unsafe secret database")};handle,err:=sql.Open("sqlite","file:"+path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=trusted_schema(0)");if err!=nil{return nil,err};handle.SetMaxOpenConns(1);handle.SetMaxIdleConns(1);if err=handle.Ping();err!=nil{handle.Close();return nil,err};opened,err:=os.Stat(path);if err!=nil||!os.SameFile(info,opened){handle.Close();return nil,errors.New("secret database changed while opening")};return handle,nil}
func readKeyEpoch(path string,ownerUID int)(uint64,error){info,err:=os.Lstat(path);if err!=nil{return 0,err};stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=0400||int(stat.Uid)!=ownerUID||info.Size()>32{return 0,errors.New("unsafe secret key epoch")};raw,err:=os.ReadFile(path);if err!=nil{return 0,err};value,err:=strconv.ParseUint(strings.TrimSpace(string(raw)),10,64);for index:=range raw{raw[index]=0};if err!=nil||value==0{return 0,errors.New("invalid secret key epoch")};return value,nil}
func lookupIdentity(name string)(int,int,error){account,err:=user.Lookup(name);if err!=nil{return 0,0,err};uid,err:=strconv.Atoi(account.Uid);if err!=nil||uid<=0{return 0,0,fmt.Errorf("invalid %s UID",name)};gid,err:=strconv.Atoi(account.Gid);if err!=nil||gid<=0{return 0,0,fmt.Errorf("invalid %s GID",name)};return uid,gid,nil}
