//go:build linux

package apps

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func applicationClientCertificateFixture(t *testing.T, usage x509.ExtKeyUsage, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeLinuxApplicationBytes(encoded)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func TestApplicationDatabaseClientIdentityValidation(t *testing.T) {
	now := time.Now().UTC()
	certificate, key := applicationClientCertificateFixture(t, x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour))
	defer wipeLinuxApplicationBytes(key)
	if err := validateApplicationDatabaseClientIdentity(certificate, key, now); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		usage         x509.ExtKeyUsage
		before, after time.Time
	}{
		{"server-only", x509.ExtKeyUsageServerAuth, now.Add(-time.Hour), now.Add(time.Hour)},
		{"expired", x509.ExtKeyUsageClientAuth, now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		{"future", x509.ExtKeyUsageClientAuth, now.Add(time.Hour), now.Add(2 * time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, k := applicationClientCertificateFixture(t, test.usage, test.before, test.after)
			defer wipeLinuxApplicationBytes(k)
			if validateApplicationDatabaseClientIdentity(c, k, now) == nil {
				t.Fatal("invalid client identity accepted")
			}
		})
	}
	_, otherKey := applicationClientCertificateFixture(t, x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour))
	defer wipeLinuxApplicationBytes(otherKey)
	if validateApplicationDatabaseClientIdentity(certificate, otherKey, now) == nil {
		t.Fatal("mismatched key accepted")
	}
	if validateApplicationDatabaseClientIdentity(nil, key, now) == nil {
		t.Fatal("empty certificate accepted")
	}
}
