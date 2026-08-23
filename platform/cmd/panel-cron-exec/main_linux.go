//go:build linux

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
)

func main(){if os.Geteuid()!=0{log.Fatal("panel-cron-exec must run as root")};manifest:=flag.String("manifest","","root-owned cron manifest");job:=flag.String("job","","cron job identifier");flag.Parse();if *manifest==""||*job==""||flag.NArg()!=0{log.Fatal("manifest and job are required")};ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGTERM,syscall.SIGINT);defer cancel();if err:=access.RunLinuxCronManifestJob(ctx,*manifest,access.CronJobID(*job));err!=nil{log.Fatalf("run cron job: %v",err)}}
