//go:build linux

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestQEMUMailFallbackCertificate(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_TLS") != "1" {
		t.Skip("explicit QEMU mail fallback identity initialization")
	}
	if err := bootstrapDefaultMailCertificate(); err != nil {
		t.Fatal(err)
	}
	const base = "/var/lib/cyberpanel/mail/tls/default/"
	before, err := os.ReadFile(base + "fullchain.pem")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(base+"fullchain.pem", base+"private.key")
	if err != nil || len(pair.Certificate) == 0 {
		t.Fatal("mail key pair", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatal("fallback is not self-signed", err)
	}
	web, err := os.ReadFile("/var/lib/cyberpanel/certificates/consumers/webengine/preview-default/current/fullchain.pem")
	if err != nil || bytes.Equal(before, web) {
		t.Fatal("mail reused web identity", err)
	}
	block, _ := pem.Decode(web)
	if block == nil {
		t.Fatal("invalid web certificate")
	}
	webCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || bytes.Equal(cert.RawSubjectPublicKeyInfo, webCertificate.RawSubjectPublicKeyInfo) {
		t.Fatal("mail reused web key", err)
	}
	if err := bootstrapDefaultMailCertificate(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(base + "fullchain.pem")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("fallback rotated during replay", err)
	}
	info, err := os.Stat(base + "private.key")
	if err != nil || info.Mode().Perm() != 0440 {
		t.Fatal("private key mode", err)
	}
}
