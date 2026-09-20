//go:build linux

package database

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type liveTLSSecrets struct {
	LinuxMariaDBSecretSource
	ca, password                 []byte
	clientCertificate, clientKey []byte
}

func (source *liveTLSSecrets) ExternalAdministrator(context.Context, SecretRef, ResourceID, ResourceID) (MariaDBAdministrator, error) {
	username, _ := ParseSQLIdentifier("qemu_tls")
	return MariaDBAdministrator{Username: username, Password: append([]byte(nil), source.password...), ClientCertificatePEM: append([]byte(nil), source.clientCertificate...), ClientKeyPEM: append([]byte(nil), source.clientKey...)}, nil
}
func (source *liveTLSSecrets) PinnedCertificateAuthority(context.Context, SecretRef, ResourceID) ([]byte, error) {
	return append([]byte(nil), source.ca...), nil
}

func liveTLSCertificate(t *testing.T) (ca, certificate, key, clientCertificate, clientKey []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "QEMU disposable CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, issuer, issuer, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "QEMU disposable server"}, NotBefore: issuer.NotBefore, NotAfter: issuer.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, issuer, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "QEMU disposable client"}, NotBefore: issuer.NotBefore, NotAfter: issuer.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, err := x509.CreateCertificate(rand.Reader, client, issuer, &clientPrivate.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})
}

func TestQEMULiveMariaDBExternalTLS(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_MARIADB") != "1" {
		t.Skip("requires disposable QEMU MariaDB guest")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture requires QEMU root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	account, err := user.Lookup("mysql")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/var/tmp", "cyberpanel-mariadb-tls-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chown(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	ca, certificate, key, clientCertificate, clientKey := liveTLSCertificate(t)
	defer wipeBytes(key, clientKey)
	for name, payload := range map[string][]byte{"ca.pem": ca, "server.pem": certificate, "server.key": key} {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, payload, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	data := filepath.Join(root, "data")
	initialize := exec.CommandContext(ctx, "/usr/bin/mariadb-install-db", "--no-defaults", "--user=mysql", "--datadir="+data, "--auth-root-authentication-method=socket", "--skip-test-db")
	initialize.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "TMPDIR=" + root}
	if output, err := initialize.CombinedOutput(); err != nil {
		t.Fatalf("initialize fixture: %v: %s", err, output)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	socket := filepath.Join(root, "mariadb.sock")
	log, err := os.OpenFile(filepath.Join(root, "server.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	server := exec.CommandContext(ctx, "/usr/sbin/mariadbd", "--no-defaults", "--user=mysql", "--datadir="+data, "--socket="+socket, "--pid-file="+filepath.Join(root, "server.pid"), "--bind-address=127.0.0.1", "--port="+strconv.Itoa(port), "--skip-name-resolve", "--ssl-ca="+filepath.Join(root, "ca.pem"), "--ssl-cert="+filepath.Join(root, "server.pem"), "--ssl-key="+filepath.Join(root, "server.key"), "--require-secure-transport=ON")
	server.Stdout, server.Stderr = log, log
	server.Env = initialize.Env
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Wait() }()
	t.Cleanup(func() {
		_ = server.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = server.Process.Kill()
			<-done
		}
	})
	rootQuery := func(query string) ([]byte, error) {
		command := exec.CommandContext(ctx, "/usr/bin/mariadb", "--no-defaults", "--protocol=socket", "--socket="+socket, "--user=root", "--batch", "--skip-column-names")
		command.Stdin = strings.NewReader(query)
		return command.Output()
	}
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		if _, err := rootQuery("SELECT 1;"); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		payload, _ := os.ReadFile(filepath.Join(root, "server.log"))
		t.Fatalf("fixture did not start: %s", payload)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	password := []byte(hex.EncodeToString(random))
	wipeBytes(random)
	defer wipeBytes(password)
	// Hex-only generated credential stays on stdin, never argv or diagnostics.
	if _, err := rootQuery("CREATE USER 'qemu_tls'@'127.0.0.1' IDENTIFIED BY '" + string(password) + "' REQUIRE SSL;"); err != nil {
		t.Fatalf("create TLS fixture account: %v", err)
	}
	source := &liveTLSSecrets{ca: ca, password: password}
	distribution, err := DetectLinuxMariaDBDistribution()
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewLinuxMariaDBExecutor(source, distribution, nil)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := DefaultLocalInstance()
	if err != nil {
		t.Fatal(err)
	}
	instance.ID, _ = NewResourceID("qemu-external-tls")
	instance.Placement, instance.LocalServiceRef = PlacementExternal, ResourceID{}
	ref, _ := NewSecretRef("qemu-tls-fixture")
	instance.External = &ExternalInstance{Endpoint: Endpoint{Host: "127.0.0.1", Port: uint16(port)}, ServerName: "127.0.0.1", PinnedCASecretRef: ref, AdminSecretRef: ref, CredentialAudience: instance.ID, RequiredTLS: TLSRequired}
	query := func(target DatabaseInstance) ([]byte, error) {
		connection, cleanup, err := executor.connection(ctx, target)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		return connection.query(ctx, sqlObserveStatus)
	}
	rejectTLS := func(target DatabaseInstance) {
		t.Helper()
		connection, cleanup, err := executor.connection(ctx, target)
		if err != nil {
			t.Fatalf("TLS rejection fixture could not construct connection: %v", err)
		}
		defer cleanup()
		if _, err := connection.query(ctx, sqlObserveStatus); err == nil {
			t.Fatal("untrusted TLS peer accepted")
		}
		// Confirm the live rejection is a TLS error, not a disconnected server or
		// invalid account. Production deliberately returns a redacted client error.
		command := exec.CommandContext(ctx, "/usr/bin/mariadb", connection.arguments...)
		command.Stdin = strings.NewReader("SELECT 1;")
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "ERROR 2026") {
			t.Fatalf("expected MariaDB TLS error 2026: %v, output=%q", err, output)
		}
	}
	if output, err := query(instance); err != nil || !strings.Contains(string(output), "MariaDB") {
		t.Fatalf("valid TLS connection: %v, output=%q", err, output)
	}
	wrongCA, _, wrongKey, wrongClientCertificate, wrongClientKey := liveTLSCertificate(t)
	wipeBytes(wrongKey)
	defer wipeBytes(wrongClientKey)
	source.ca = wrongCA
	rejectTLS(instance)
	source.ca = ca
	wrongName := instance
	wrongIdentity := *instance.External
	wrongIdentity.Endpoint.Host, wrongIdentity.ServerName = "localhost", "localhost"
	wrongName.External = &wrongIdentity
	rejectTLS(wrongName)
	if _, err := query(instance); err != nil {
		t.Fatalf("positive control after rejection: %v", err)
	}
	liveExternalWorkspaceExport(t, ctx, instance, source, rootQuery)
	if _, err := rootQuery("ALTER USER 'qemu_tls'@'127.0.0.1' REQUIRE X509;"); err != nil {
		t.Fatalf("require client certificate: %v", err)
	}
	if _, err := query(instance); err == nil {
		t.Fatal("server accepted account without required client certificate")
	}
	instance.External.RequiredTLS = TLSMutual
	source.clientCertificate, source.clientKey = clientCertificate, clientKey
	if _, err := query(instance); err != nil {
		t.Fatalf("trusted mutual TLS connection failed: %v", err)
	}
	source.clientCertificate, source.clientKey = wrongClientCertificate, wrongClientKey
	rejectTLS(instance)
	source.clientCertificate, source.clientKey = clientCertificate, clientKey
	if _, err := query(instance); err != nil {
		t.Fatalf("mutual TLS positive control after rejection: %v", err)
	}
	if os.Getenv("CYBERPANEL_QEMU_LIVE_WORDPRESS_TLS") == "1" {
		if _, err := rootQuery("CREATE DATABASE qemu_wordpress; GRANT ALL ON qemu_wordpress.* TO 'qemu_tls'@'127.0.0.1'; ALTER USER 'qemu_tls'@'127.0.0.1' REQUIRE SSL;"); err != nil {
			t.Fatal(err)
		}
		wordpressRoot := filepath.Join(root, "wordpress")
		privateRoot := filepath.Join(root, "wordpress-private")
		if err := os.Mkdir(privateRoot, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(wordpressRoot, 0700); err != nil {
			t.Fatal(err)
		}
		dropin, err := os.ReadFile("../apps/wordpress_db_tls.php")
		if err != nil {
			t.Fatal(err)
		}
		dropin = bytes.Replace(dropin, []byte("__CYBERPANEL_PRIVATE_DIRECTORY_BASE64__"), []byte(base64.StdEncoding.EncodeToString([]byte(privateRoot))), 1)
		if err := os.WriteFile(filepath.Join(wordpressRoot, "db.php"), dropin, 0600); err != nil {
			t.Fatal(err)
		}
		check := func(name, host string, authority, clientCert, privateKey []byte, mutual, accept, tlsError bool) {
			t.Helper()
			configuration, err := json.Marshal(map[string]any{"version": 1, "host": host, "port": port, "mutual": mutual})
			if err != nil {
				t.Fatal(err)
			}
			for file, value := range map[string][]byte{".cyberpanel-db-tls.json": configuration, ".cyberpanel-db-ca.pem": authority, ".cyberpanel-db-client.pem": clientCert, ".cyberpanel-db-client.key": privateKey} {
				if err := os.WriteFile(filepath.Join(privateRoot, file), value, 0600); err != nil {
					t.Fatal(err)
				}
			}
			input, err := json.Marshal(map[string]any{"password": string(password), "host": host, "port": port, "accept": accept, "tls_error": tlsError, "wpdb": "/home/harness/class-wpdb-7.1.php", "dropin": filepath.Join(wordpressRoot, "db.php")})
			if err != nil {
				t.Fatal(err)
			}
			defer wipeBytes(input)
			command := exec.CommandContext(ctx, "/usr/bin/php8.3", "../apps/testdata/wordpress_db_tls_check.php")
			command.Stdin = strings.NewReader(string(input))
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("WordPress %s: %v: %s", name, err, output)
			}
			t.Logf("WordPress %s: %s", name, strings.TrimSpace(string(output)))
			if os.Getenv("CYBERPANEL_QEMU_LIVE_WORDPRESS_CLI") == "1" {
				checkQEMUWordPressDatabaseCLI(t, ctx, root, privateRoot, host, port, password, mutual, accept, tlsError, rootQuery)
			}
		}
		check("trusted TLS", "127.0.0.1", ca, nil, nil, false, true, false)
		check("wrong CA", "127.0.0.1", wrongCA, nil, nil, false, false, true)
		check("wrong identity", "127.1", ca, nil, nil, false, false, true)
		if _, err := rootQuery("ALTER USER 'qemu_tls'@'127.0.0.1' REQUIRE X509;"); err != nil {
			t.Fatal(err)
		}
		check("missing client identity", "127.0.0.1", ca, nil, nil, false, false, false)
		check("trusted mutual TLS", "127.0.0.1", ca, clientCertificate, clientKey, true, true, false)
		check("wrong client identity", "127.0.0.1", ca, wrongClientCertificate, wrongClientKey, true, false, true)
	}
	t.Log("actual MariaDB TCP TLS and mutual TLS: valid identities accepted; wrong CA, wrong hostname, missing and untrusted client identities rejected")
}
