//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/migration/cpanel"
)

func main() {
	log.SetFlags(0)
	flags := flag.NewFlagSet("cpanel-archive-migrator", flag.ExitOnError)
	configPath := flags.String("config", "", "absolute path to the local archive migration configuration")
	_ = flags.Parse(os.Args[1:])
	if flags.NArg() != 0 || *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: cpanel-archive-migrator -config /absolute/path/config.json")
		os.Exit(2)
	}
	config, err := cpanel.LoadArchiveRuntimeConfig(*configPath)
	if err != nil {
		log.Fatalf("load local archive configuration: %v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	result, err := cpanel.RunArchive(ctx, config)
	if err != nil {
		log.Fatalf("extract local cPanel archive: %v", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(result); err != nil {
		log.Fatalf("encode archive result: %v", err)
	}
}
