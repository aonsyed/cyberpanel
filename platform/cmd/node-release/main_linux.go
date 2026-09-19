//go:build linux

// node-release is the release-engineering side of the offline node installer.
// It reads only an explicit source tree and signing key and produces one
// deterministic tar bundle; it never resolves or downloads a dependency.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/noderelease"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 || os.Args[1] != "assemble" {
		usage()
	}
	flags := flag.NewFlagSet("assemble", flag.ExitOnError)
	specPath := flags.String("spec", "", "absolute path to node-release-spec.json")
	sourceRoot := flags.String("source-root", "", "absolute root containing every local source named by the spec")
	privateKey := flags.String("private-key", "", "absolute path to a mode-0600 hex Ed25519 seed/private key (never packaged)")
	outputPath := flags.String("output", "", "new absolute .tar output path")
	_ = flags.Parse(os.Args[2:])
	if flags.NArg() != 0 || *specPath == "" || *sourceRoot == "" || *privateKey == "" || *outputPath == "" {
		usage()
	}
	spec, err := noderelease.ReadBuildSpec(*specPath)
	if err != nil {
		log.Fatalf("read offline node release inputs: %v", err)
	}
	receipt, err := noderelease.AssembleBundle(spec, *sourceRoot, *privateKey, *outputPath)
	if err != nil {
		log.Fatalf("assemble offline node release from source tree %s: %v", *sourceRoot, err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(receipt); err != nil {
		log.Fatalf("encode release receipt: %v", err)
	}
}

func usage() {
	message := strings.TrimSpace(`node-release assemble --spec /absolute/node-release-spec.json \
  --source-root /absolute/prebuilt-source-tree \
  --private-key /absolute/release-signing-key.hex \
  --output /absolute/cyberpanel-node-<version>-<target>.tar

The source tree must already contain every Go/tool binary, config, systemd unit,
and Ubuntu noble .deb or AlmaLinux 9 .rpm named by the spec. No network or
dependency resolution is attempted. The output layout is release.json followed
by payload/<artifact-id> members in the signed install_order.`)
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
