//go:build linux

package main

import (
	"context"
	"errors"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	if os.Geteuid() != 0 {
		return errors.New("peer inspector requires its constrained root service")
	}
	account, err := user.Lookup("cyberpanel-secrets")
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return secrets.ErrInvalid
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid <= 0 {
		return secrets.ErrInvalid
	}
	listener, err := secrets.ListenMaterialInspector(gid)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() { <-ctx.Done(); listener.Close() }()
	err = secrets.ServeMaterialInspector(listener, uint32(uid))
	if errors.Is(err, net.ErrClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}
