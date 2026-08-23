//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	installer "github.com/aonsyed/cyberpanel/platform/internal/install"
)

func main(){log.SetFlags(0);if os.Geteuid()!=0{log.Fatal("panel-install must run as root")};ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM);defer cancel();store,err:=installer.NewFileStore();if err!=nil{log.Fatalf("open installer authority: %v",err)};host:=installer.NewLinuxHost();watchdog:=installer.SystemdWatchdog{};if len(os.Args)<2{usage()};switch os.Args[1]{case "install":runTransaction(ctx,store,host,watchdog,installer.TransactionInstall,os.Args[2:]);case "upgrade":runTransaction(ctx,store,host,watchdog,installer.TransactionUpgrade,os.Args[2:]);case "rollback":runTransaction(ctx,store,host,watchdog,installer.TransactionRollback,os.Args[2:]);case "uninstall":runTransaction(ctx,store,host,watchdog,installer.TransactionUninstall,os.Args[2:]);case "status":runStatus(ctx,store,os.Args[2:]);case "watchdog":rolledBack,err:=watchdog.RunExpired(ctx,host);if err!=nil{log.Fatalf("activation watchdog: %v",err)};if rolledBack{log.Print("candidate release rolled back")};default:usage()}}

func runTransaction(ctx context.Context,store installer.FileStore,host *installer.LinuxHost,watchdog installer.SystemdWatchdog,kind installer.TransactionKind,arguments []string){flags:=flag.NewFlagSet(string(kind),flag.ExitOnError);catalogPath:=flags.String("catalog","","absolute path to the signed component catalog");transactionID:=flags.String("transaction","","stable transaction identifier");commandID:=flags.String("command","","stable command identifier");releaseID:=flags.String("release","","target immutable release identifier");editionValue:=flags.String("edition","","openlitespeed or litespeed_enterprise; defaults to installed edition or openlitespeed");licenseSource:=flags.String("enterprise-license-source","","fixed root-owned LiteSpeed license or serial input path");licenseKind:=flags.String("enterprise-license-kind","license_key","license_key or serial");licenseDigest:=flags.String("enterprise-license-sha256","","SHA-256 of LiteSpeed license input");exportPath:=flags.String("export","","uninstall export under /var/backups/cyberpanel/exports");purgeAfterValue:=flags.String("purge-after","","RFC3339 retention deadline for uninstall tombstone");_ = flags.Parse(arguments);if flags.NArg()!=0{log.Fatal("positional arguments are not accepted")};if *catalogPath==""||*transactionID==""||*commandID==""{log.Fatal("--catalog, --transaction, and --command are required")};edition:=installer.EditionOpenLiteSpeed;if *editionValue!=""{edition=installer.WebEdition(*editionValue);if edition!=installer.EditionOpenLiteSpeed&&edition!=installer.EditionLiteSpeedEnterprise{log.Fatal("unsupported --edition")}};installed,installedErr:=store.LoadInstalled(ctx);if installedErr==nil{if *editionValue!=""&&installer.WebEdition(*editionValue)!=installed.Tuple.Edition{log.Fatal("--edition does not match installed edition")};edition=installed.Tuple.Edition}else if !errors.Is(installedErr,installer.ErrNotFound){log.Fatalf("load installed state: %v",installedErr)};facts,err:=host.Probe(ctx,edition);if err!=nil{log.Fatalf("probe host: %v",err)};ring,err:=installer.LoadRootOwnedKeyRing("/etc/cyberpanel/installer/trust.d",time.Now().UTC());if err!=nil{log.Fatalf("load catalog trust: %v",err)};catalog,err:=installer.LoadCatalog(*catalogPath,ring,time.Now().UTC());if err!=nil{log.Fatalf("verify catalog: %v",err)};request:=installer.Request{TransactionID:*transactionID,CommandID:*commandID,Kind:kind,Tuple:facts.Tuple,TargetReleaseID:*releaseID,ExportPath:*exportPath};if kind==installer.TransactionInstall||kind==installer.TransactionUpgrade{if *releaseID==""{log.Fatal("--release is required")}};if edition==installer.EditionLiteSpeedEnterprise&&(kind==installer.TransactionInstall||kind==installer.TransactionUpgrade){license:=&installer.EnterpriseLicenseRef{SourcePath:*licenseSource,Kind:*licenseKind,Digest:*licenseDigest};if err:=license.Validate();err!=nil{log.Fatalf("enterprise license reference: %v",err)};request.EnterpriseLicense=license};if kind==installer.TransactionUninstall{deadline,err:=time.Parse(time.RFC3339,*purgeAfterValue);if err!=nil{log.Fatal("--purge-after must be RFC3339")};request.PurgeAfter=deadline.UTC()};orchestrator:=installer.Orchestrator{Store:store,Host:host,State:installer.LocalStateInitializer{},Watchdog:watchdog};plan,err:=orchestrator.Execute(ctx,request,catalog);writeJSON(plan);if err!=nil{log.Fatalf("%s transaction: %v",kind,err)}}

func runStatus(ctx context.Context,store installer.FileStore,arguments []string){flags:=flag.NewFlagSet("status",flag.ExitOnError);transactionID:=flags.String("transaction","","optional transaction identifier");_ = flags.Parse(arguments);if flags.NArg()!=0{log.Fatal("positional arguments are not accepted")};if *transactionID!=""{plan,err:=store.LoadPlan(ctx,*transactionID);if err!=nil{log.Fatalf("load transaction: %v",err)};writeJSON(plan);return};state,err:=store.LoadInstalled(ctx);if err!=nil{if errors.Is(err,installer.ErrNotFound){writeJSON(map[string]string{"state":"not_installed"});return};log.Fatalf("load installed state: %v",err)};writeJSON(state)}
func writeJSON(value any){encoder:=json.NewEncoder(os.Stdout);encoder.SetEscapeHTML(false);encoder.SetIndent("","  ");if err:=encoder.Encode(value);err!=nil{log.Fatalf("encode result: %v",err)}}
func usage(){message:=strings.TrimSpace(`panel-install <command> [options]

Commands:
  install     install a signed release into slot A
  upgrade     stage and promote a signed release into the inactive slot
  rollback    promote the retained previous slot under watchdog protection
  uninstall   export state, deactivate services, and create a retention tombstone
  status      print installed or transaction state
  watchdog    internal systemd activation watchdog entrypoint`);fmt.Fprintln(os.Stderr,message);os.Exit(2)}
