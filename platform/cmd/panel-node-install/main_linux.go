//go:build linux

// panel-node-install verifies, stages, activates, and reconciles a signed local
// node release. It contains no network client and invokes only dpkg/rpm on the
// exact package files carried by the verified bundle.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/noderelease"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	installer, err := noderelease.NewInstaller()
	if err != nil {
		log.Fatalf("initialize offline node installer: %v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	switch os.Args[1] {
	case "apply":
		flags := flag.NewFlagSet("apply", flag.ExitOnError)
		bundle := flags.String("bundle", "", "absolute path to the root-owned signed release tar")
		_ = flags.Parse(os.Args[2:])
		if flags.NArg() != 0 || *bundle == "" {
			usage()
		}
		receipt, applyErr := installer.Apply(ctx, *bundle)
		writeJSON(receipt)
		if applyErr != nil {
			log.Fatalf("apply offline node release %s: %v", *bundle, applyErr)
		}
	case "reconcile":
		if len(os.Args) != 2 {
			usage()
		}
		receipts, reconcileErr := installer.Reconcile(ctx)
		writeJSON(receipts)
		if reconcileErr != nil {
			log.Fatalf("reconcile durable node release journal under %s: %v", noderelease.JournalRoot, reconcileErr)
		}
	case "status":
		if len(os.Args) != 2 {
			usage()
		}
		status, statusErr := installer.InspectStatus()
		if statusErr != nil {
			log.Fatalf("read offline node release status: %v", statusErr)
		}
		writeJSON(status)
	case "reconcile-secrets":
		if len(os.Args) != 2 {
			usage()
		}
		if err := installer.ReconcileSecretConsumers(ctx); err != nil {
			log.Fatalf("reconcile signed consumer authority: %v", err)
		}
		writeJSON(map[string]string{"state": "reconciled"})
	case "prune-staging":
		if len(os.Args) != 2 {
			usage()
		}
		if err := installer.PruneInstalledStaging(ctx); err != nil {
			log.Fatalf("prune verified redundant staging: %v", err)
		}
		writeJSON(map[string]string{"state": "pruned"})
	case "paths":
		if len(os.Args) != 2 {
			usage()
		}
		writeJSON(map[string]string{
			"trust": noderelease.TrustRoot, "state": noderelease.StateRoot, "journal": noderelease.JournalRoot,
			"frontier": noderelease.FrontierPath, "staging": noderelease.StagingRoot,
			"releases": noderelease.ReleaseRoot, "active": noderelease.ActiveRelease,
		})
	default:
		usage()
	}
}

func writeJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		log.Fatalf("encode result: %v", err)
	}
}

func usage() {
	message := strings.TrimSpace(`panel-node-install <command>

Commands:
  apply --bundle /absolute/release.tar  verify every member before mutation, then install or resume
  reconcile                            converge or roll back every durable incomplete operation
  reconcile-secrets                    authorize consumers from verified current/previous releases
  prune-staging                        remove duplicate staging after verifying retained releases
  status                               print the installed frontier and journals
  paths                                print the fixed trust, state, staging, release, and active paths

Supported targets are exactly Ubuntu 24.04 noble and AlmaLinux 9 (amd64/arm64).
Trust must be provisioned under /etc/cyberpanel/node-release/trust.d before apply.
The installer never downloads artifacts or resolves packages from a repository.`)
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
