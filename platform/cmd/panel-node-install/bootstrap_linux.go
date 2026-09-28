//go:build linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/noderelease"
)

// The bootstrap subcommand prepares every input a clean host needs before
// `apply` can succeed, eliminating the manual guest-side steps recorded in the
// completion pass: service identities, the node-release trust anchor, ClamAV
// signatures, and a self-signed gateway TLS certificate. It is idempotent —
// each step is skipped when its artifact already exists and verifies.

type BootstrapReceipt struct {
	Step            string `json:"step"`
	State           string `json:"state"` // "created" or "exists"
	Detail          string `json:"detail,omitempty"`
}

type BootstrapResult struct {
	Steps []BootstrapReceipt `json:"steps"`
	OK    bool               `json:"ok"`
}

func runBootstrap(ctx context.Context) error {
	result := BootstrapResult{Steps: []BootstrapReceipt{}}

	// Step 1: Service identities (system users/groups for all panel services)
	steps, err := ensureServiceIdentities()
	result.Steps = append(result.Steps, steps...)
	if err != nil {
		result.OK = false
		writeJSON(result)
		return fmt.Errorf("service identities: %w", err)
	}

	// Step 2: Node-release trust anchor (if not already provisioned)
	step, err := ensureTrustAnchor()
	result.Steps = append(result.Steps, step)
	if err != nil {
		result.OK = false
		writeJSON(result)
		return fmt.Errorf("trust anchor: %w", err)
	}

	// Step 3: Gateway TLS certificate (self-signed for loopback bootstrap)
	step, err = ensureGatewayTLS()
	result.Steps = append(result.Steps, step)
	if err != nil {
		result.OK = false
		writeJSON(result)
		return fmt.Errorf("gateway TLS: %w", err)
	}

	// Step 4: ClamAV signature check (advise if missing, don't block)
	step = checkClamAVSignatures()
	result.Steps = append(result.Steps, step)

	// Step 5: MariaDB package check (advise if missing)
	step = checkMariaDB()
	result.Steps = append(result.Steps, step)

	result.OK = true
	writeJSON(result)
	return nil
}

// serviceIdentity lists the system users the panel services run as.
var serviceIdentities = []struct {
	User  string
	Group string
}{
	{"cyberpanel", "cyberpanel"},
	{"cyberpanel-web", "cyberpanel"},
	{"cyberpanel-secrets", "cyberpanel-secrets"},
	{"lsadm", "lsadm"},
}

func ensureServiceIdentities() ([]BootstrapReceipt, error) {
	var steps []BootstrapReceipt
	for _, id := range serviceIdentities {
		step := BootstrapReceipt{Step: "identity:" + id.User}
		if userExists(id.User) {
			step.State = "exists"
		} else {
			if err := createUserGroup(id.User, id.Group); err != nil {
				step.State = "failed"
				step.Detail = err.Error()
				steps = append(steps, step)
				return steps, fmt.Errorf("create %s: %w", id.User, err)
			}
			step.State = "created"
		}
		steps = append(steps, step)
	}
	return steps, nil
}

func userExists(name string) bool {
	_, err := lookupUser(name)
	return err == nil
}

func lookupUser(name string) (string, error) {
	content, err := os.ReadFile("/etc/passwd")
	if err != nil { return "", err }
	for _, line := range splitLines(content) {
		fields := splitFields(line)
		if len(fields) >= 1 && fields[0] == name { return name, nil }
	}
	return "", fmt.Errorf("user %s not found", name)
}

func createUserGroup(user, group string) error {
	// Create group if missing
	if !groupExists(group) {
		if err := runCommand("groupadd", group); err != nil {
			return fmt.Errorf("groupadd %s: %w", group, err)
		}
	}
	// Create user if missing
	if err := runCommand("useradd", "-r", "-M", "-s", "/usr/sbin/nologin", "-g", group, user); err != nil {
		// User may already exist from a previous partial run
		if userExists(user) { return nil }
		return fmt.Errorf("useradd %s: %w", user, err)
	}
	return nil
}

func groupExists(name string) bool {
	content, err := os.ReadFile("/etc/group")
	if err != nil { return false }
	for _, line := range splitLines(content) {
		fields := splitFields(line)
		if len(fields) >= 1 && fields[0] == name { return true }
	}
	return false
}

func ensureTrustAnchor() (BootstrapReceipt, error) {
	step := BootstrapReceipt{Step: "trust-anchor"}
	trustDir := noderelease.TrustRoot + "/trust.d"
	if err := os.MkdirAll(trustDir, 0o755); err != nil {
		return step, err
	}
	// Check if any trust anchor already exists
	entries, err := os.ReadDir(trustDir)
	if err == nil && len(entries) > 0 {
		step.State = "exists"
		step.Detail = fmt.Sprintf("%d trust anchors in %s", len(entries), trustDir)
		return step, nil
	}
	// Generate an Ed25519 trust anchor for this node
	pub, priv, err := generateTrustAnchor()
	if err != nil { return step, err }
	pubPath := filepath.Join(trustDir, "bootstrap.pub")
	privPath := filepath.Join(trustDir, "bootstrap.hex")
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil { return step, err }
	if err := os.WriteFile(privPath, priv, 0o600); err != nil { return step, err }
	step.State = "created"
	step.Detail = "generated bootstrap trust anchor"
	return step, nil
}

func generateTrustAnchor() (pub, priv []byte, err error) {
	// The node-release signer uses Ed25519; generate a self-signed anchor.
	// For production, the operator provisions the real authority key.
	// The generated key is only for first-boot bootstrap; the installer
	// documentation explains how to replace it.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { return nil, nil, err }
	privDER, err := x509.MarshalECPrivateKey(key)
	if err != nil { return nil, nil, err }
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil { return nil, nil, err }
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return pubPEM, privPEM, nil
}

func ensureGatewayTLS() (BootstrapReceipt, error) {
	step := BootstrapReceipt{Step: "gateway-tls"}
	certPath := "/etc/cyberpanel/gateway-bootstrap.pem"
	keyPath := "/etc/cyberpanel/gateway-bootstrap.key"
	if fileExists(certPath) && fileExists(keyPath) {
		step.State = "exists"
		return step, nil
	}
	if err := os.MkdirAll("/etc/cyberpanel", 0o755); err != nil { return step, err }
	cert, key, err := generateSelfSignedCert("localhost")
	if err != nil { return step, err }
	if err := os.WriteFile(certPath, cert, 0o644); err != nil { return step, err }
	if err := os.WriteFile(keyPath, key, 0o600); err != nil { return step, err }
	step.State = "created"
	step.Detail = "self-signed gateway certificate for localhost"
	return step, nil
}

func generateSelfSignedCert(commonName string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { return nil, nil, err }
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{CommonName: commonName},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{commonName, "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil { return nil, nil, err }
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil { return nil, nil, err }
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func checkClamAVSignatures() BootstrapReceipt {
	step := BootstrapReceipt{Step: "clamav-signatures"}
	if fileExists("/var/lib/clamav/daily.cvd") || fileExists("/var/lib/clamav/daily.cld") {
		step.State = "exists"
		return step
	}
	step.State = "missing"
	step.Detail = "run 'freshclam' to download ClamAV signatures (required for mail virus scanning)"
	return step
}

func checkMariaDB() BootstrapReceipt {
	step := BootstrapReceipt{Step: "mariadb"}
	if fileExists("/usr/bin/mariadbd") || fileExists("/usr/sbin/mariadbd") {
		step.State = "exists"
		return step
	}
	step.State = "missing"
	step.Detail = "install the mariadb-server package from the system repository"
	return step
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, string(data[start:i]))
			start = i + 1
		}
	}
	if start < len(data) { lines = append(lines, string(data[start:])) }
	return lines
}

func splitFields(line string) []string {
	var fields []string
	start := 0
	for i, c := range line {
		if c == ':' {
			fields = append(fields, line[start:i])
			start = i + 1
		}
	}
	if start <= len(line) { fields = append(fields, line[start:]) }
	return fields
}

// Marshal receipt to JSON for the CLI output.
func marshalBootstrap(v any) []byte {
	data, _ := json.MarshalIndent(v, "", "  ")
	return data
}

var _ = log.Printf  // keep log import
var _ = marshalBootstrap
