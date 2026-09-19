//go:build linux

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/sitepreview"
	_ "modernc.org/sqlite"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) != 1 {
		log.Fatal("cyberpanel-sitepreview-route accepts no arguments")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := sitepreview.RunLinuxRouteHelper(ctx, os.Stdin, os.Stdout); err != nil {
		log.Fatalf("site preview route effect: %v", err)
	}
}
