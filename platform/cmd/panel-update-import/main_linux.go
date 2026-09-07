//go:build linux

// panel-update-import admits an operator-delivered signed release without any
// network access or automatic apply. Place a complete directory at:
// /var/lib/cyberpanel/product-updater/inbox/ready/feed-<index digest>/
// containing index.json, manifest.json, and artifacts/<sha256>.tar. Directories
// must be root-owned 0700; files must be root-owned regular files with one link
// and no group/other write access. Publish the directory into ready atomically.
// Invoke this installed executable by its absolute path, passing only its
// feed-<index digest> ID. Retry the same ID after interruption. Accepted bundles
// and their receipt.json remain under inbox/accepted; retention is manual.
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/operations"
)

func main() {
	log.SetFlags(0)
	if os.Getuid()!=0 || os.Geteuid()!=0 || len(os.Args)!=2 {
		log.Fatal("usage (root only): /usr/local/libexec/cyberpanel/panel-update-import feed-<64 lowercase hex index digest>")
	}
	client,err:=operations.NewLocalProductUpdateClient()
	if err!=nil { log.Fatalf("connect to product updater: %v",err) }
	signalContext,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
	defer stop()
	ctx,cancel:=context.WithTimeout(signalContext,30*time.Minute)
	defer cancel()
	receipt,err:=client.ImportOffline(ctx,os.Args[1])
	if err!=nil { log.Fatalf("offline import failed (retry the same bundle ID after correcting the cause): %v",err) }
	if err=json.NewEncoder(os.Stdout).Encode(receipt);err!=nil { log.Fatalf("write import receipt: %v",err) }
}
