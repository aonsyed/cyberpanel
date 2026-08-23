//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

func main(){if err:=run();err!=nil{log.Fatal(err)}}

func run()error{
	if os.Geteuid()==0{return errors.New("panel-providerd refuses to run as root")}
	account,err:=user.Lookup("cyberpanel");if err!=nil{return err};uid,err:=strconv.Atoi(account.Uid);if err!=nil||uid<=0||uid!=os.Geteuid(){return errors.New("panel-providerd must run as cyberpanel")};gid,err:=strconv.Atoi(account.Gid);if err!=nil||gid<=0||gid!=os.Getegid(){return errors.New("panel-providerd has an unexpected primary group")}
	releaseDigest,err:=integrations.ProviderWorkerReleaseDigest("/proc/self/exe");if err!=nil{return fmt.Errorf("digest provider worker: %w",err)}
	profiles,err:=integrations.DefaultProviderWorkerSecretProfiles(releaseDigest);if err!=nil{return fmt.Errorf("construct provider secret profiles: %w",err)}
	material,err:=secrets.NewLocalMaterialClient();if err!=nil{return fmt.Errorf("connect protected secret broker: %w",err)}
	reader:=integrations.ProviderSecretReader{Client:material,Profiles:profiles};providers:=map[integrations.ProviderKind]integrations.Provider{}
	for _,kind:=range []integrations.ProviderKind{integrations.ProviderCloudflare,integrations.ProviderAWSS3,integrations.ProviderWasabi,integrations.ProviderBackblaze}{adapter,adapterErr:=integrations.NewRemoteProviderAdapter(kind,reader);if adapterErr!=nil{return fmt.Errorf("initialize %s provider: %w",kind,adapterErr)};providers[kind]=adapter}
	listener,err:=integrations.ListenProviderWorker(uid,gid);if err!=nil{return fmt.Errorf("listen for provider work: %w",err)};defer listener.Close()
	ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM);defer cancel();go func(){<-ctx.Done();_=listener.Close()}()
	server:=&integrations.ProviderWorkerServer{Authorizer:integrations.ProviderWorkerPeerPolicy{AllowedUID:uint32(uid)},Providers:providers,MaximumConcurrent:32}
	err=server.Serve(listener);if ctx.Err()!=nil{return nil};return err
}
