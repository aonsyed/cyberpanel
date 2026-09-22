//go:build linux

package certificates

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type mailIdentityRunner struct{}

func (mailIdentityRunner) Run(context.Context, string, ...string) error { return nil }

func mailIdentityFixture(t *testing.T, bootstrap bool) (CertificateMaterial, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	name, common := "mail.example.invalid", "mail.example.invalid"
	if bootstrap {
		name, common = "cyberpanel.invalid", "CyberPanel bootstrap fallback"
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: common}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	material, err := certificateMaterialFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return material, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func TestQEMULocalMailTLSIdentity(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_TLS") != "1" {
		t.Skip("requires installed QEMU mail TLS endpoint")
	}
	source, err := filepath.EvalSymlinks("/var/lib/cyberpanel/mail/tls/default/certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := readMailPublicIdentity(source, 0440)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mail.pem")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0444); err != nil {
		t.Fatal(err)
	}
	config, err := localMailTLSConfig(path, "mail.cyberpanel.invalid")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "127.0.0.1:993", config)
	if err != nil {
		t.Fatal("managed bootstrap TLS verification", err)
	}
	connection.Close()
	other, _ := mailIdentityFixture(t, true)
	if err = os.WriteFile(path, other.LeafPEM, 0444); err != nil {
		t.Fatal(err)
	}
	config, err = localMailTLSConfig(path, "mail.cyberpanel.invalid")
	if err != nil {
		t.Fatal(err)
	}
	connection, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "127.0.0.1:993", config)
	if err == nil {
		connection.Close()
		t.Fatal("unrelated bootstrap anchor trusted installed peer")
	}
}

func TestLocalMailIdentityRotationRollback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned QEMU fixtures with TMPDIR=/root")
	}
	root := t.TempDir()
	host := &LinuxCertificateHost{CertificateRoot: root, Runner: mailIdentityRunner{}}
	path := filepath.Join(root, "public", "mail-default.pem")
	ctx := context.Background()
	first, key := mailIdentityFixture(t, true)
	_, candidate, err := host.StageCertificate(ctx, "mail/default", first, key, "mail-test-first")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = host.ActivateCertificate(ctx, "mail/default", candidate, "mail-test-first"); err != nil {
		t.Fatal(err)
	}
	config, err := localMailTLSConfig(path, "mail.example.invalid")
	if err != nil || config.ServerName != "cyberpanel.invalid" || config.InsecureSkipVerify {
		t.Fatal("bootstrap identity", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, first.LeafPEM) || bytes.Contains(data, []byte("PRIVATE")) {
		t.Fatal("public-only mirror", err)
	}
	keyInfo, err := os.Stat(filepath.Join(candidate, "private.key"))
	if err != nil || keyInfo.Mode().Perm() != 0400 {
		t.Fatal("private permissions changed")
	}
	second, key := mailIdentityFixture(t, false)
	previous, candidate2, err := host.StageCertificate(ctx, "mail/default", second, key, "mail-test-second")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = host.ActivateCertificate(ctx, "mail/default", candidate2, "mail-test-second"); err != nil {
		t.Fatal(err)
	}
	rotated, err := localMailTLSConfig(path, "mail.example.invalid")
	if err != nil || rotated.ServerName != "mail.example.invalid" {
		t.Fatal("rotated identity", err)
	}
	leaf, err := readMailPublicIdentity(path, 0444)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: config.RootCAs, DNSName: rotated.ServerName}); err == nil {
		t.Fatal("old anchor trusts rotated identity")
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: rotated.RootCAs, DNSName: rotated.ServerName}); err != nil {
		t.Fatal("selected identity not trusted", err)
	}
	if _, err = localMailTLSConfig(path, "wrong.example.invalid"); err == nil {
		t.Fatal("normal certificate hostname mismatch accepted")
	}
	if err = host.RestoreCertificate(ctx, "mail/default", previous, "mail-test-second"); err != nil {
		t.Fatal(err)
	}
	rolled, err := localMailTLSConfig(path, "mail.example.invalid")
	if err != nil || rolled.ServerName != "cyberpanel.invalid" {
		t.Fatal("rollback mirror", err)
	}
	if err = host.RestoreCertificate(ctx, "mail/default", "", "mail-test-first"); err != nil {
		t.Fatal(err)
	}
	if _, err = localMailTLSConfig(path, "mail.example.invalid"); err == nil {
		t.Fatal("missing identity accepted")
	}
}

func TestLocalMailIdentityRejectsUnsafeMirror(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned QEMU fixtures with TMPDIR=/root")
	}
	for _, variant := range []string{"writable", "symlink", "hardlink", "owner", "private-key", "ancestor"} {
		t.Run(variant, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "mail.pem")
			material, key := mailIdentityFixture(t, false)
			data := material.LeafPEM
			if variant == "private-key" {
				data = key
			}
			if err := os.WriteFile(path, data, 0444); err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "writable":
				if err := os.Chmod(path, 0664); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "owner":
				if err := os.Chown(path, 1234, 1234); err != nil {
					t.Fatal(err)
				}
			case "ancestor":
				if err := os.Chmod(root, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := localMailTLSConfig(path, "mail.example.invalid"); err == nil {
				t.Fatal("unsafe identity accepted")
			}
		})
	}
}
