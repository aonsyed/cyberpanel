//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/controlplane"
	"github.com/aonsyed/cyberpanel/platform/internal/federation"
	_ "modernc.org/sqlite"
)

const (
	configPath                  = "/etc/cyberpanel/panel-central.json"
	databasePath                = "/var/lib/cyberpanel-central/controlplane.db"
	credentialRoot              = "/run/credentials/panel-central.service"
	serverCertificatePath       = credentialRoot + "/server.crt"
	serverPrivateKeyPath        = credentialRoot + "/server.key"
	clientCAPath                = credentialRoot + "/client-ca.pem"
	operatorCAPath              = credentialRoot + "/operator-ca.pem"
	enrollmentCAKeyPath         = credentialRoot + "/enrollment-ca.key"
	intentSigningKeyPath        = credentialRoot + "/intent-signing.key"
	revocationSigningKeyPath    = credentialRoot + "/revocation-signing.key"
	enrollmentBundlePath        = credentialRoot + "/enrollments.json"
	maximumConfigurationBytes   = int64(1 << 20)
	maximumCertificateBytes     = int64(256 << 10)
	maximumEnrollmentBytes      = int64(4 << 20)
)

type configuration struct {
	Enabled                    bool   `json:"enabled"`
	Listen                     string `json:"listen"`
	DatabasePath               string `json:"database_path"`
	PeerID                     string `json:"peer_id"`
	IntentSigningKeyID         string `json:"intent_signing_key_id"`
	RevocationSigningKeyID     string `json:"revocation_signing_key_id"`
	ClientCAFingerprintSHA256  string `json:"client_ca_fingerprint_sha256"`
	OperatorEnabled            bool   `json:"operator_enabled"`
	OperatorListen             string `json:"operator_listen"`
	OperatorCAFingerprintSHA256 string `json:"operator_ca_fingerprint_sha256"`
	EnrollmentEnabled          bool   `json:"enrollment_enabled"`
	EnrollmentListen           string `json:"enrollment_listen"`
	EnrollmentCertificateTTLSeconds uint32 `json:"enrollment_certificate_ttl_seconds"`
	MaximumSessions            uint32 `json:"maximum_sessions"`
	ShutdownTimeoutSeconds     uint32 `json:"shutdown_timeout_seconds"`
}

type enrollmentBundle struct {
	Version     uint32                                   `json:"version"`
	Enrollments []controlplane.ProvisionedEnrollment    `json:"enrollments"`
	OperatorGrants []controlplane.OperatorGrant          `json:"operator_grants"`
	EnrollmentTokens []controlplane.ProvisionedEnrollmentToken `json:"enrollment_tokens"`
}

func main() {
	flags := flag.NewFlagSet("panel-central", flag.ExitOnError)
	path := flags.String("config", configPath, "central federation configuration")
	_ = flags.Parse(os.Args[1:])
	if flags.NArg() != 0 {
		log.Fatal("panel-central accepts no positional arguments")
	}
	config, err := loadConfiguration(*path)
	if err != nil {
		log.Fatalf("load central configuration: %v", err)
	}
	if err = run(config); err != nil {
		log.Fatal(err)
	}
}

func run(config configuration) error {
	if !config.Enabled {
		return nil
	}
	if os.Geteuid() == 0 {
		return errors.New("panel-central refuses to run as root")
	}
	database, err := openDatabase(config.DatabasePath)
	if err != nil {
		return fmt.Errorf("open central database: %w", err)
	}
	defer database.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	store, err := controlplane.NewStore(database)
	if err != nil {
		return err
	}
	if err = store.Bootstrap(ctx); err != nil {
		return fmt.Errorf("migrate central database: %w", err)
	}
	peerID, _ := federation.NewID(config.PeerID)
	bundle, err := loadEnrollmentBundle()
	if err != nil {
		return fmt.Errorf("load enrollment trust: %w", err)
	}
	provisionedNodes := make(map[federation.ID]struct{}, len(bundle.Enrollments))
	for _, enrollment := range bundle.Enrollments {
		if enrollment.Grant.PeerID != peerID {
			return fmt.Errorf("enrollment for %s names a different central peer", enrollment.Node.ID)
		}
		if _, duplicate := provisionedNodes[enrollment.Node.ID]; duplicate {
			return fmt.Errorf("duplicate enrollment for %s", enrollment.Node.ID)
		}
		provisionedNodes[enrollment.Node.ID] = struct{}{}
		if err = store.ProvisionEnrollment(ctx, enrollment); err != nil {
			return fmt.Errorf("persist enrollment for %s: %w", enrollment.Node.ID, err)
		}
	}
	if config.EnrollmentEnabled {
		if err = store.BootstrapEnrollment(ctx); err != nil {
			return fmt.Errorf("migrate enrollment authority: %w", err)
		}
		if len(bundle.EnrollmentTokens) == 0 {
			return errors.New("enrollment listener requires at least one provisioned token digest")
		}
		for _, token := range bundle.EnrollmentTokens {
			if _, static := provisionedNodes[token.NodeID]; static {
				return fmt.Errorf("node %s cannot be both statically enrolled and token-enrollable", token.NodeID)
			}
		}
		if err = store.ProvisionEnrollmentTokens(ctx, bundle.EnrollmentTokens, peerID, config.ClientCAFingerprintSHA256); err != nil {
			return fmt.Errorf("persist enrollment token bindings: %w", err)
		}
	}
	var serviceAuthorizer controlplane.Authorizer = denyAuthorizer{}
	var serviceAudit controlplane.Audit = discardAudit{}
	var operatorAuthority *controlplane.OperatorAuthority
	var operatorAudit *controlplane.OperatorAudit
	if config.OperatorEnabled {
		if err = store.BootstrapOperator(ctx); err != nil {
			return fmt.Errorf("migrate operator authority: %w", err)
		}
		if len(bundle.OperatorGrants) == 0 {
			return errors.New("operator listener requires at least one provisioned grant")
		}
		if err = store.ProvisionOperatorGrants(ctx, bundle.OperatorGrants); err != nil {
			return fmt.Errorf("persist operator grants: %w", err)
		}
		operatorAuthority, err = controlplane.NewOperatorAuthority(store)
		if err != nil {
			return err
		}
		operatorAudit, err = controlplane.NewOperatorAudit(store)
		if err != nil {
			return err
		}
		serviceAuthorizer = operatorAuthority
		serviceAudit = operatorAudit
	}
	intentKey, err := loadEd25519PrivateKey(intentSigningKeyPath)
	if err != nil {
		return fmt.Errorf("load intent signing key: %w", err)
	}
	defer clear(intentKey)
	revocationKey, err := loadEd25519PrivateKey(revocationSigningKeyPath)
	if err != nil {
		return fmt.Errorf("load revocation signing key: %w", err)
	}
	defer clear(revocationKey)
	signer, err := controlplane.NewEd25519IntentSigner(config.IntentSigningKeyID, config.RevocationSigningKeyID, map[string]ed25519.PrivateKey{
		config.IntentSigningKeyID: intentKey,
		config.RevocationSigningKeyID: revocationKey,
	})
	if err != nil {
		return fmt.Errorf("assemble central signer: %w", err)
	}
	verifier, err := controlplane.NewEd25519ReceiptVerifier(store)
	if err != nil {
		return fmt.Errorf("assemble node evidence verifier: %w", err)
	}
	service, err := controlplane.NewService(store, serviceAuthorizer, signer, randomIDGenerator{}, serviceAudit, peerID)
	if err != nil {
		return fmt.Errorf("assemble control-plane service: %w", err)
	}
	service.WithEvidenceVerifier(verifier)
	endpoint, err := controlplane.NewEndpoint(service)
	if err != nil {
		return fmt.Errorf("assemble federation endpoint: %w", err)
	}
	tlsConfig, err := loadTLSConfiguration(clientCAPath, config.ClientCAFingerprintSHA256, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("load federation TLS policy: %w", err)
	}
	server, err := controlplane.NewTLSServer(endpoint, tlsConfig, config.MaximumSessions, time.Duration(config.ShutdownTimeoutSeconds)*time.Second)
	if err != nil {
		return fmt.Errorf("assemble federation listener: %w", err)
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return fmt.Errorf("listen for federation nodes: %w", err)
	}
	defer listener.Close()
	listeners := []centralListener{{listener: listener, serve: server.Serve}}
	if config.OperatorEnabled {
		operatorTLS, loadErr := loadTLSConfiguration(operatorCAPath, config.OperatorCAFingerprintSHA256, time.Now().UTC())
		if loadErr != nil {
			return fmt.Errorf("load operator TLS policy: %w", loadErr)
		}
		operatorAPI, apiErr := controlplane.NewOperatorAPI(service, store, operatorAuthority, operatorAudit)
		if apiErr != nil {
			return fmt.Errorf("assemble operator API: %w", apiErr)
		}
		operatorServer, serverErr := controlplane.NewOperatorServer(operatorAPI, operatorTLS, config.MaximumSessions, time.Duration(config.ShutdownTimeoutSeconds)*time.Second)
		if serverErr != nil {
			return fmt.Errorf("assemble operator listener: %w", serverErr)
		}
		operatorListener, listenErr := net.Listen("tcp", config.OperatorListen)
		if listenErr != nil {
			return fmt.Errorf("listen for central operators: %w", listenErr)
		}
		defer operatorListener.Close()
		listeners = append(listeners, centralListener{listener: operatorListener, serve: operatorServer.Serve})
	}
	if config.EnrollmentEnabled {
		caPEM, readErr := readProtectedFile(clientCAPath, maximumCertificateBytes, false)
		if readErr != nil {
			return fmt.Errorf("load enrollment CA certificate: %w", readErr)
		}
		caKey, readErr := readProtectedFile(enrollmentCAKeyPath, ed25519.PrivateKeySize, true)
		if readErr != nil {
			return fmt.Errorf("load enrollment CA key: %w", readErr)
		}
		defer clear(caKey)
		intentPublic := intentKey.Public().(ed25519.PublicKey)
		revocationPublic := revocationKey.Public().(ed25519.PublicKey)
		issuer, issuerErr := controlplane.NewEnrollmentIssuer(caPEM, caKey, config.ClientCAFingerprintSHA256, peerID, map[string][]byte{config.IntentSigningKeyID: intentPublic, config.RevocationSigningKeyID: revocationPublic}, time.Duration(config.EnrollmentCertificateTTLSeconds)*time.Second)
		if issuerErr != nil {
			return fmt.Errorf("assemble enrollment certificate issuer: %w", issuerErr)
		}
		defer issuer.Close()
		enrollmentAPI, apiErr := controlplane.NewEnrollmentAPI(store, issuer)
		if apiErr != nil {
			return fmt.Errorf("assemble enrollment API: %w", apiErr)
		}
		enrollmentServer, serverErr := controlplane.NewEnrollmentServer(enrollmentAPI, tlsConfig, config.MaximumSessions, time.Duration(config.ShutdownTimeoutSeconds)*time.Second)
		if serverErr != nil {
			return fmt.Errorf("assemble enrollment listener: %w", serverErr)
		}
		enrollmentListener, listenErr := net.Listen("tcp", config.EnrollmentListen)
		if listenErr != nil {
			return fmt.Errorf("listen for node enrollment: %w", listenErr)
		}
		defer enrollmentListener.Close()
		listeners = append(listeners, centralListener{listener: enrollmentListener, serve: enrollmentServer.Serve})
	}
	return serveCentralListeners(ctx, cancel, listeners)
}

func loadConfiguration(path string) (configuration, error) {
	var config configuration
	if path != configPath {
		return config, errors.New("central configuration path is not registered")
	}
	content, err := readProtectedFile(path, maximumConfigurationBytes, false)
	if err != nil {
		return config, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return configuration{}, errors.New("invalid central configuration")
	}
	if config.DatabasePath != databasePath || config.Listen == "" || config.Listen != strings.TrimSpace(config.Listen) {
		return configuration{}, errors.New("central configuration contains an unregistered path or listener")
	}
	host, port, err := net.SplitHostPort(config.Listen)
	if err != nil || host == "" || port == "" {
		return configuration{}, errors.New("invalid central listener")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return configuration{}, errors.New("invalid central listener port")
	}
	if !config.Enabled {
		if config.OperatorEnabled || config.EnrollmentEnabled {
			return configuration{}, errors.New("additional listeners require central runtime enablement")
		}
		return config, nil
	}
	peerID, peerErr := federation.NewID(config.PeerID)
	intentID, intentErr := federation.NewID(config.IntentSigningKeyID)
	revocationID, revocationErr := federation.NewID(config.RevocationSigningKeyID)
	if peerErr != nil || intentErr != nil || revocationErr != nil || peerID == intentID || peerID == revocationID || intentID == revocationID || !validSHA256(config.ClientCAFingerprintSHA256) || config.MaximumSessions == 0 || config.MaximumSessions > 4096 || config.ShutdownTimeoutSeconds < 5 || config.ShutdownTimeoutSeconds > 120 {
		return configuration{}, errors.New("invalid enabled central trust policy")
	}
	if config.OperatorEnabled {
		host, port, listenErr := net.SplitHostPort(config.OperatorListen)
		parsedPort, portErr := strconv.ParseUint(port, 10, 16)
		if listenErr != nil || host == "" || port == "" || portErr != nil || parsedPort == 0 || config.OperatorListen == config.Listen || !validSHA256(config.OperatorCAFingerprintSHA256) {
			return configuration{}, errors.New("invalid operator listener trust policy")
		}
	}
	if config.EnrollmentEnabled {
		host, port, listenErr := net.SplitHostPort(config.EnrollmentListen)
		parsedPort, portErr := strconv.ParseUint(port, 10, 16)
		if listenErr != nil || host == "" || port == "" || portErr != nil || parsedPort == 0 || config.EnrollmentListen == config.Listen || config.EnrollmentListen == config.OperatorListen && config.OperatorEnabled || config.EnrollmentCertificateTTLSeconds < 300 || config.EnrollmentCertificateTTLSeconds > 23*60*60 {
			return configuration{}, errors.New("invalid enrollment listener trust policy")
		}
	}
	return config, nil
}

type centralListener struct {
	listener net.Listener
	serve    func(context.Context, net.Listener) error
}

func serveCentralListeners(ctx context.Context, cancel context.CancelFunc, listeners []centralListener) error {
	if ctx == nil || cancel == nil || len(listeners) == 0 {
		return errors.New("invalid central listeners")
	}
	errorsChannel := make(chan error, len(listeners))
	for _, listener := range listeners {
		go func(current centralListener) { errorsChannel <- current.serve(ctx, current.listener) }(listener)
	}
	received := 0
	var first error
	select {
	case <-ctx.Done():
	case first = <-errorsChannel:
		received = 1
		if first == nil && ctx.Err() == nil {
			first = errors.New("central listener stopped unexpectedly")
		} else if ctx.Err() != nil && (errors.Is(first, context.Canceled) || errors.Is(first, net.ErrClosed)) {
			first = nil
		}
		cancel()
	}
	for _, listener := range listeners {
		_ = listener.listener.Close()
	}
	for received < len(listeners) {
		err := <-errorsChannel
		received++
		if first == nil && err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			first = err
		}
	}
	return first
}

func openDatabase(path string) (*sql.DB, error) {
	if path != databasePath {
		return nil, errors.New("unregistered central database path")
	}
	directory := filepath.Dir(path)
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	directoryStat, ok := directoryInfo.Sys().(*syscall.Stat_t)
	if !ok || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm() != 0700 || int(directoryStat.Uid) != os.Geteuid() {
		return nil, errors.New("unsafe central state directory")
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return nil, createErr
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, closeErr
		}
		before, err = os.Lstat(path)
	}
	if err != nil {
		return nil, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0600 || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("unsafe central database")
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=trusted_schema(0)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(4)
	database.SetMaxIdleConns(4)
	database.SetConnMaxLifetime(0)
	pingContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = database.PingContext(pingContext); err != nil {
		_ = database.Close()
		return nil, err
	}
	opened, err := os.Stat(path)
	if err != nil || !os.SameFile(before, opened) {
		_ = database.Close()
		return nil, errors.New("central database changed while opening")
	}
	return database, nil
}

func loadEnrollmentBundle() (enrollmentBundle, error) {
	var bundle enrollmentBundle
	content, err := readProtectedFile(enrollmentBundlePath, maximumEnrollmentBytes, true)
	if err != nil {
		return bundle, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&bundle); err != nil || decoder.Decode(&struct{}{}) != io.EOF || bundle.Version != 1 || len(bundle.Enrollments) > 10000 || len(bundle.EnrollmentTokens) > 10000 {
		return enrollmentBundle{}, errors.New("invalid enrollment trust bundle")
	}
	return bundle, nil
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	content, err := readProtectedFile(path, ed25519.PrivateKeySize, true)
	if err != nil {
		return nil, err
	}
	if len(content) != ed25519.PrivateKeySize {
		clear(content)
		return nil, errors.New("central signing key must contain 64 raw bytes")
	}
	return ed25519.PrivateKey(content), nil
}

func loadTLSConfiguration(caPath, expectedFingerprint string, now time.Time) (*tls.Config, error) {
	certificatePEM, err := readProtectedFile(serverCertificatePath, maximumCertificateBytes, false)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := readProtectedFile(serverPrivateKeyPath, maximumCertificateBytes, true)
	if err != nil {
		return nil, err
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("invalid central server identity")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !allowsUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return nil, errors.New("central server certificate is not valid for server authentication")
	}
	certificate.Leaf = leaf
	caPEM, err := readProtectedFile(caPath, maximumCertificateBytes, false)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("client CA credential must contain exactly one certificate")
	}
	clientCA, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !clientCA.IsCA || clientCA.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(clientCA.NotBefore) || !now.Before(clientCA.NotAfter) {
		return nil, errors.New("invalid federation client CA")
	}
	fingerprint := sha256.Sum256(clientCA.Raw)
	expected, _ := hex.DecodeString(expectedFingerprint)
	if subtle.ConstantTimeCompare(fingerprint[:], expected) != 1 {
		return nil, errors.New("federation client CA fingerprint mismatch")
	}
	pool := x509.NewCertPool()
	pool.AddCert(clientCA)
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{certificate},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              pool,
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
				return controlplane.ErrForbidden
			}
			for _, chain := range state.VerifiedChains {
				if len(chain) == 0 {
					continue
				}
				rootFingerprint := sha256.Sum256(chain[len(chain)-1].Raw)
				if subtle.ConstantTimeCompare(rootFingerprint[:], fingerprint[:]) == 1 {
					return nil
				}
			}
			return controlplane.ErrForbidden
		},
	}, nil
}

func readProtectedFile(path string, maximum int64, secret bool) ([]byte, error) {
	registered := path == configPath || path == serverCertificatePath || path == serverPrivateKeyPath || path == clientCAPath || path == operatorCAPath || path == enrollmentCAKeyPath || path == intentSigningKeyPath || path == revocationSigningKeyPath || path == enrollmentBundlePath
	if !registered || maximum <= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("unregistered protected file")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maximum || before.Mode().Perm()&0022 != 0 || secret && before.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe protected file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("protected file changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		clear(content)
		return nil, errors.New("protected file exceeds limit")
	}
	return content, nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func allowsUsage(certificate *x509.Certificate, wanted x509.ExtKeyUsage) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == wanted {
			return true
		}
	}
	return false
}

type denyAuthorizer struct{}

func (denyAuthorizer) Authorize(context.Context, controlplane.Operator, string, federation.ID, string, string) error {
	return controlplane.ErrForbidden
}

type discardAudit struct{}

func (discardAudit) Record(context.Context, string, controlplane.Operator, federation.ID, string, string, string) error {
	return nil
}

type randomIDGenerator struct{}

func (randomIDGenerator) New(ctx context.Context, namespace string) (federation.ID, error) {
	if ctx == nil || namespace == "" {
		return "", controlplane.ErrInvalid
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	random := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}
	return federation.NewID(namespace + "_" + hex.EncodeToString(random))
}
