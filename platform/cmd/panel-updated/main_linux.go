//go:build linux

package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/operations"
)

func main() {
	log.SetFlags(0)
	if os.Geteuid() != 0 {
		log.Fatal("panel-updated must run as root")
	}
	updater, err := operations.NewLinuxProductUpdater()
	if err != nil {
		log.Fatalf("initialize product updater: %v", err)
	}
	recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), 10*time.Minute)
	err = updater.RecoverPending(recoveryContext)
	cancelRecovery()
	if err != nil {
		log.Fatalf("recover product update: %v", err)
	}
	listener, err := operations.ListenProductUpdater()
	if err != nil {
		log.Fatalf("listen on product updater socket: %v", err)
	}
	defer listener.Close()
	server := &operations.ProductUpdaterServer{Updater: updater}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	select {
	case <-ctx.Done():
		_ = listener.Close()
		if serveErr := <-serveErrors; serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
			log.Printf("product updater stopped: %v", serveErr)
		}
	case serveErr := <-serveErrors:
		if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
			log.Fatalf("product updater failed: %v", serveErr)
		}
		log.Fatal("product updater stopped unexpectedly")
	}
}
