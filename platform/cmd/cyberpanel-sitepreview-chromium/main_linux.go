//go:build linux

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/sitepreview"
)

func main() {
	log.SetFlags(0)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := sitepreview.RunLinuxChromiumHelperCommand(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		log.Fatalf("isolated site preview render: %v", err)
	}
}
