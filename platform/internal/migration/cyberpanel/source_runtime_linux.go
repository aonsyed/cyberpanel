//go:build linux

package cyberpanel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

const (
	SourceAgentVersion = "cyberpanel-source-migrator/v1"
	maximumSourceAgentConfigBytes = int64(1 << 20)
	defaultSourceAgentArtifactBytes = uint64(256 << 30)
	defaultSourceAgentChunkBytes = uint64(64 << 30)
	maximumSourceAgentStoredBytes = uint64(2 << 40)
	cutoverHelperProtocolVersion = uint32(1)
)

// SourceAgentConfig contains only source-local authorities and public target
// trust material. Unknown fields are rejected so a target password, token,
// private key, or generic remote command cannot be smuggled into this process.
type SourceAgentConfig struct {
	SourceInstallationID string `json:"source_installation_id"`
	ListenAddress string `json:"listen_address"`
	PlanDirectory string `json:"plan_directory"`
	GrantDirectory string `json:"grant_directory"`
	SessionDirectory string `json:"session_directory"`
	ArtifactDirectory string `json:"artifact_directory"`
	ChunkDirectory string `json:"chunk_directory"`
	HomeRoot string `json:"home_root"`
	MailRoot string `json:"mail_root"`
	CertificateRoot string `json:"certificate_root"`
	DKIMRoot string `json:"dkim_root"`
	CronRoot string `json:"cron_root"`
	DebianCronRoot string `json:"debian_cron_root"`
	TLSCertificatePath string `json:"tls_certificate_path"`
	TLSPrivateKeyPath string `json:"tls_private_key_path"`
	TargetClientCAPath string `json:"target_client_ca_path"`
	AllowedTargetClientSPKI []string `json:"allowed_target_client_spki"`
	ApprovalKeys map[string]string `json:"approval_keys"`
	AllowedTargetInstallationIDs []string `json:"allowed_target_installation_ids"`
	MaximumPlanLifetimeSeconds uint64 `json:"maximum_plan_lifetime_seconds"`
	ManifestSigningKeyID string `json:"manifest_signing_key_id"`
	ManifestSigningPrivateKeyPath string `json:"manifest_signing_private_key_path"`
	TargetSealingKeyID string `json:"target_sealing_key_id"`
	TargetSealingPublicKey string `json:"target_sealing_public_key"`
	CutoverHelperSocket string `json:"cutover_helper_socket,omitempty"`
	MaximumArtifactBytes uint64 `json:"maximum_artifact_bytes"`
	MaximumChunkBytes uint64 `json:"maximum_chunk_bytes"`
	MaximumConnections int `json:"maximum_connections"`
}

func LoadSourceAgentConfig(path string) (SourceAgentConfig, error) {
	var config SourceAgentConfig
	raw, err := readSourceAgentFile(path, maximumSourceAgentConfigBytes, false)
	if err != nil {
		return config, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil {
		return SourceAgentConfig{}, errors.Join(ErrInvalid, err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SourceAgentConfig{}, ErrInvalid
	}
	return normalizeSourceAgentConfig(config)
}

func RunSourceAgent(ctx context.Context, config SourceAgentConfig, collector Collector) (err error) {
	if ctx == nil || collector == nil {
		return ErrInvalid
	}
	if os.Geteuid() == 0 {
		return errors.Join(ErrDenied, errors.New("source migrator refuses to run as root"))
	}
	config, err = normalizeSourceAgentConfig(config)
	if err != nil {
		return err
	}
	artifacts, err := OpenMaterializedCatalog(config.ArtifactDirectory, nil, config.MaximumArtifactBytes)
	if err != nil {
		return fmt.Errorf("open artifact catalog: %w", err)
	}
	defer joinSourceAgentClose(&err, artifacts.Close)
	chunks, err := migration.OpenChunkStore(config.ChunkDirectory, config.MaximumChunkBytes)
	if err != nil {
		return fmt.Errorf("open chunk store: %w", err)
	}
	defer joinSourceAgentClose(&err, chunks.Close)

	supplemental, err := NewHostSupplemental(HostSupplementalConfig{
		Artifacts: artifacts,
		HomeRoot: config.HomeRoot,
		CertificateRoot: config.CertificateRoot,
		DKIMRoot: config.DKIMRoot,
		CronRoot: config.CronRoot,
		DebianCronRoot: config.DebianCronRoot,
	})
	if err != nil {
		return fmt.Errorf("initialize host inventory: %w", err)
	}
	defer joinSourceAgentClose(&err, supplemental.Close)
	var databaseDumper DatabaseDumper
	var containerSnapshotter ContainerSnapshotter
	var secrets SecretSource = supplemental
	if sqlCollector, ok := collector.(*SQLCollector); ok {
		if sqlCollector.database == nil || sqlCollector.installationID != config.SourceInstallationID || sqlCollector.supplemental != nil {
			return ErrInvalid
		}
		sqlCollector.supplemental = supplemental
		databaseDumper, err = NewSQLLogicalDumper(sqlCollector.database, 0, 0, 0)
		if err != nil {
			return fmt.Errorf("initialize database dumper: %w", err)
		}
		containerSnapshotter, err = NewSQLContainerSnapshotter(sqlCollector.database, config.MaximumArtifactBytes)
		if err != nil {
			return fmt.Errorf("initialize container snapshotter: %w", err)
		}
		databaseSecrets, sourceErr := NewSQLSecretSource(sqlCollector.database)
		if sourceErr != nil {
			return fmt.Errorf("initialize source secret reader: %w", sourceErr)
		}
		secrets, err = NewCompositeSecretSource(databaseSecrets, supplemental)
		if err != nil {
			return fmt.Errorf("initialize source secret catalog: %w", err)
		}
	}
	hostSource, err := NewHostSource(HostSourceConfig{
		Collector: collector,
		Artifacts: artifacts,
		HomeRoot: config.HomeRoot,
		MailRoot: config.MailRoot,
		DatabaseDumper: databaseDumper,
		ContainerSnapshotter: containerSnapshotter,
	})
	if err != nil {
		return fmt.Errorf("initialize source collector: %w", err)
	}
	plans, err := OpenFilePlanStore(config.PlanDirectory)
	if err != nil {
		return fmt.Errorf("open approved plans: %w", err)
	}
	defer joinSourceAgentClose(&err, plans.Close)
	approvalKeys, err := sourceAgentApprovalKeys(config.ApprovalKeys)
	if err != nil {
		return err
	}
	allowedTargets := make(map[string]struct{}, len(config.AllowedTargetInstallationIDs))
	for _, target := range config.AllowedTargetInstallationIDs {
		allowedTargets[target] = struct{}{}
	}
	verifier, err := NewLocalApprovalVerifier(LocalApprovalPolicy{
		SourceInstallationID: config.SourceInstallationID,
		Keys: approvalKeys,
		MaximumLifetime: time.Duration(config.MaximumPlanLifetimeSeconds) * time.Second,
		AllowedTargets: allowedTargets,
		AllowedSchemaHashes: map[string]struct{}{CanonicalManifestSchemaHash(): {}},
	})
	if err != nil {
		return fmt.Errorf("initialize local approval verifier: %w", err)
	}
	binder, err := OpenFileSessionGrantBinder(config.GrantDirectory, config.SessionDirectory, plans, verifier)
	if err != nil {
		return fmt.Errorf("open one-time migration grants: %w", err)
	}
	defer joinSourceAgentClose(&err, binder.Close)

	signingKey, err := readSourceAgentHexKey(config.ManifestSigningPrivateKeyPath, ed25519.PrivateKeySize)
	if err != nil {
		return fmt.Errorf("load manifest signing key: %w", err)
	}
	defer wipe(signingKey)
	targetSealingKey, err := decodeSourceAgentHex(config.TargetSealingPublicKey, 32)
	if err != nil {
		return fmt.Errorf("load target sealing public key: %w", err)
	}
	sealer, err := NewX25519Sealer(config.TargetSealingKeyID, targetSealingKey)
	if err != nil {
		return fmt.Errorf("initialize secret sealer: %w", err)
	}
	extractor, err := NewExtractor(ExtractorConfig{
		PlanStore: plans,
		PlanVerifier: verifier,
		Collector: hostSource,
		Artifacts: artifacts,
		Secrets: secrets,
		Sealer: sealer,
		Chunks: chunks,
		SigningKeyID: config.ManifestSigningKeyID,
		SigningKey: ed25519.PrivateKey(signingKey),
		ExtractorVersion: SourceAgentVersion,
	})
	if err != nil {
		return fmt.Errorf("initialize extractor: %w", err)
	}
	defer joinSourceAgentClose(&err, extractor.Close)

	var cutover migration.CutoverSource
	if config.CutoverHelperSocket != "" {
		controller, controllerErr := NewUnixFenceController(config.CutoverHelperSocket)
		if controllerErr != nil {
			return fmt.Errorf("initialize cutover helper: %w", controllerErr)
		}
		generationRoot, rootErr := openPrivateRoot(config.SessionDirectory)
		if rootErr != nil {
			return fmt.Errorf("open cutover generation receipts: %w", rootErr)
		}
		defer joinSourceAgentClose(&err, generationRoot.Close)
		generationController := &generationFenceController{controller: controller, extractor: extractor, plans: plans, verifier: verifier, root: generationRoot, clock: time.Now}
		cutover, err = NewCutover(plans, verifier, generationController, extractor)
		if err != nil {
			return fmt.Errorf("initialize cutover coordinator: %w", err)
		}
	}
	tlsConfiguration, err := sourceAgentTLSConfiguration(config)
	if err != nil {
		return fmt.Errorf("initialize pinned mutual TLS: %w", err)
	}
	baseListener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for migration target: %w", err)
	}
	listener := tls.NewListener(baseListener, tlsConfiguration)
	authorizer, err := NewPinnedTLSAuthorizer(config.AllowedTargetClientSPKI)
	if err != nil {
		listener.Close()
		return fmt.Errorf("initialize target pinning: %w", err)
	}
	server, err := NewServer(ServerConfig{
		Listener: listener,
		Source: extractor,
		Cutover: cutover,
		Authorizer: authorizer,
		SessionGrants: binder,
		MaximumConnections: config.MaximumConnections,
	})
	if err != nil {
		listener.Close()
		return fmt.Errorf("initialize source protocol: %w", err)
	}
	defer joinSourceAgentClose(&err, server.Close)
	if err = server.Serve(ctx); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("serve source protocol: %w", err)
	}
	return nil
}

func normalizeSourceAgentConfig(config SourceAgentConfig) (SourceAgentConfig, error) {
	if !boundedSourceAgentText(config.SourceInstallationID, 256) || !validKeyID(config.ManifestSigningKeyID) || !validKeyID(config.TargetSealingKeyID) || len(config.ApprovalKeys) == 0 || len(config.ApprovalKeys) > 64 || len(config.AllowedTargetInstallationIDs) == 0 || len(config.AllowedTargetInstallationIDs) > 64 || len(config.AllowedTargetClientSPKI) == 0 || len(config.AllowedTargetClientSPKI) > 64 {
		return SourceAgentConfig{}, ErrInvalid
	}
	address, err := netip.ParseAddrPort(config.ListenAddress)
	if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() {
		return SourceAgentConfig{}, ErrInvalid
	}
	paths := []string{
		config.PlanDirectory,
		config.GrantDirectory,
		config.SessionDirectory,
		config.ArtifactDirectory,
		config.ChunkDirectory,
		config.HomeRoot,
		config.MailRoot,
		config.CertificateRoot,
		config.DKIMRoot,
		config.CronRoot,
		config.DebianCronRoot,
		config.TLSCertificatePath,
		config.TLSPrivateKeyPath,
		config.TargetClientCAPath,
		config.ManifestSigningPrivateKeyPath,
	}
	for _, path := range paths {
		if !canonicalSourceAgentPath(path) {
			return SourceAgentConfig{}, ErrInvalid
		}
	}
	if config.CutoverHelperSocket != "" && !canonicalSourceAgentPath(config.CutoverHelperSocket) {
		return SourceAgentConfig{}, ErrInvalid
	}
	mutable := []string{config.SessionDirectory, config.ArtifactDirectory, config.ChunkDirectory}
	for index, left := range mutable {
		for _, right := range mutable[index+1:] {
			if left == right {
				return SourceAgentConfig{}, ErrInvalid
			}
		}
		if err := validateSourceAgentDirectory(left); err != nil {
			return SourceAgentConfig{}, err
		}
	}
	if _, err = sourceAgentApprovalKeys(config.ApprovalKeys); err != nil {
		return SourceAgentConfig{}, err
	}
	targets := make(map[string]struct{}, len(config.AllowedTargetInstallationIDs))
	for _, target := range config.AllowedTargetInstallationIDs {
		if !boundedSourceAgentText(target, 256) {
			return SourceAgentConfig{}, ErrInvalid
		}
		if _, duplicate := targets[target]; duplicate {
			return SourceAgentConfig{}, ErrInvalid
		}
		targets[target] = struct{}{}
	}
	pins := make(map[string]struct{}, len(config.AllowedTargetClientSPKI))
	for index, digest := range config.AllowedTargetClientSPKI {
		digest = strings.ToLower(strings.TrimSpace(digest))
		if !isDigest(digest) {
			return SourceAgentConfig{}, ErrInvalid
		}
		if _, duplicate := pins[digest]; duplicate {
			return SourceAgentConfig{}, ErrInvalid
		}
		pins[digest] = struct{}{}
		config.AllowedTargetClientSPKI[index] = digest
	}
	if _, err = decodeSourceAgentHex(config.TargetSealingPublicKey, 32); err != nil {
		return SourceAgentConfig{}, err
	}
	if config.MaximumPlanLifetimeSeconds == 0 {
		config.MaximumPlanLifetimeSeconds = uint64((24 * time.Hour) / time.Second)
	}
	if config.MaximumPlanLifetimeSeconds < 60 || config.MaximumPlanLifetimeSeconds > uint64((30*24*time.Hour)/time.Second) {
		return SourceAgentConfig{}, ErrInvalid
	}
	if config.MaximumArtifactBytes == 0 {
		config.MaximumArtifactBytes = defaultSourceAgentArtifactBytes
	}
	if config.MaximumChunkBytes == 0 {
		config.MaximumChunkBytes = defaultSourceAgentChunkBytes
	}
	if config.MaximumArtifactBytes < 1<<20 || config.MaximumArtifactBytes > maximumSourceAgentStoredBytes || config.MaximumChunkBytes < 1<<20 || config.MaximumChunkBytes > maximumSourceAgentStoredBytes {
		return SourceAgentConfig{}, ErrInvalid
	}
	if config.MaximumConnections == 0 {
		config.MaximumConnections = 32
	}
	if config.MaximumConnections < 1 || config.MaximumConnections > 256 {
		return SourceAgentConfig{}, ErrInvalid
	}
	return config, nil
}

func sourceAgentTLSConfiguration(config SourceAgentConfig) (*tls.Config, error) {
	certificatePEM, err := readSourceAgentFile(config.TLSCertificatePath, 1<<20, false)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := readSourceAgentFile(config.TLSPrivateKeyPath, 1<<20, true)
	if err != nil {
		return nil, err
	}
	defer wipe(privateKeyPEM)
	identity, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(identity.Certificate) == 0 {
		return nil, ErrInvalid
	}
	clientCA, err := readSourceAgentFile(config.TargetClientCAPath, 1<<20, false)
	if err != nil {
		return nil, err
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(clientCA) {
		return nil, ErrInvalid
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{identity},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientRoots,
		NextProtos: []string{"cyberpanel-migration/1"},
		SessionTicketsDisabled: true,
	}, nil
}

func sourceAgentApprovalKeys(encoded map[string]string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for keyID, value := range encoded {
		if !validKeyID(keyID) {
			return nil, ErrInvalid
		}
		raw, err := decodeSourceAgentHex(value, ed25519.PublicKeySize)
		if err != nil {
			return nil, err
		}
		keys[keyID] = ed25519.PublicKey(raw)
	}
	return keys, nil
}

func decodeSourceAgentHex(value string, size int) ([]byte, error) {
	value = strings.TrimSpace(value)
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != size || strings.ToLower(value) != value {
		wipe(raw)
		return nil, ErrInvalid
	}
	return raw, nil
}

func readSourceAgentHexKey(path string, size int) ([]byte, error) {
	raw, err := readSourceAgentFile(path, int64(size*2+2), true)
	if err != nil {
		return nil, err
	}
	defer wipe(raw)
	return decodeSourceAgentHex(strings.TrimSpace(string(raw)), size)
}

func readSourceAgentFile(path string, maximum int64, private bool) ([]byte, error) {
	if !canonicalSourceAgentPath(path) || maximum < 1 {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximum || before.Mode().Perm()&0o022 != 0 || private && before.Mode().Perm()&0o077 != 0 {
		return nil, ErrDenied
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return nil, ErrChanged
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != after.Size() {
		wipe(raw)
		return nil, errors.Join(err, ErrChanged)
	}
	final, err := file.Stat()
	if err != nil || !sameFileState(after, final) {
		wipe(raw)
		return nil, ErrChanged
	}
	return raw, nil
}

func validateSourceAgentDirectory(path string) error {
	if !canonicalSourceAgentPath(path) {
		return ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o077 != 0 {
		return errors.Join(err, ErrInvalid)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.Join(err, ErrDenied)
	}
	return nil
}

func canonicalSourceAgentPath(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func boundedSourceAgentText(value string, maximum int) bool {
	return strings.TrimSpace(value) == value && value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func joinSourceAgentClose(result *error, close func() error) {
	if close == nil {
		return
	}
	*result = errors.Join(*result, close())
}

// CutoverGenerationReceipt is written by the unprivileged source agent just
// before it asks the root helper to fence a locally approved migration. The
// helper trusts the peer UID for the observation, but re-verifies the signed
// plan, site scope, and approval digest independently.
type CutoverGenerationReceipt struct {
	Version uint32 `json:"version"`
	MigrationID migration.ID `json:"migration_id"`
	SourceInstallationID string `json:"source_installation_id"`
	SiteSourceIDs []string `json:"site_source_ids"`
	ApprovedPlanDigest string `json:"approved_plan_digest"`
	SourceGeneration uint64 `json:"source_generation"`
	ObservedAt time.Time `json:"observed_at"`
}

func ApprovedSourcePlanDigest(approved ApprovedPlan) (string, error) { return approvedPlanDigest(approved) }

type generationFenceController struct {
	controller FenceController
	extractor *Extractor
	plans PlanStore
	verifier PlanVerifier
	root *os.Root
	clock func() time.Time
}

func (c *generationFenceController) BeginQuiesce(ctx context.Context, request QuiesceRequest) (QuiesceObservation, error) {
	if c == nil || c.controller == nil || c.extractor == nil || c.plans == nil || c.verifier == nil || c.root == nil || ctx == nil {
		return QuiesceObservation{}, ErrInvalid
	}
	approved, err := c.plans.ApprovedPlan(ctx, request.MigrationID)
	if err != nil {
		return QuiesceObservation{}, err
	}
	now := c.clock().UTC()
	if err = c.verifier.VerifyApprovedPlan(ctx, approved, now); err != nil {
		return QuiesceObservation{}, err
	}
	digest, err := approvedPlanDigest(approved)
	if err != nil || approved.Plan.SourceInstallationID != request.SourceInstallationID || !sameStringSequence(approved.Plan.SiteSourceIDs, request.SiteSourceIDs) || digest != request.ApprovalDigest {
		return QuiesceObservation{}, errors.Join(err, ErrDenied)
	}
	generation, err := c.extractor.Generation(ctx, request.MigrationID)
	if err != nil || generation == 0 {
		return QuiesceObservation{}, errors.Join(err, ErrChanged)
	}
	receipt := CutoverGenerationReceipt{Version: 1, MigrationID: request.MigrationID, SourceInstallationID: request.SourceInstallationID, SiteSourceIDs: append([]string(nil), request.SiteSourceIDs...), ApprovedPlanDigest: digest, SourceGeneration: generation, ObservedAt: c.clock().UTC()}
	if err = writeCutoverGenerationReceipt(c.root, request.MigrationID.String()+".generation.json", receipt); err != nil {
		return QuiesceObservation{}, err
	}
	return c.controller.BeginQuiesce(ctx, request)
}

func (c *generationFenceController) BindFence(ctx context.Context, handle string, fence migration.SourceFence) error { return c.controller.BindFence(ctx, handle, fence) }
func (c *generationFenceController) AbortUnbound(ctx context.Context, handle string) error { return c.controller.AbortUnbound(ctx, handle) }
func (c *generationFenceController) AssertQuiesced(ctx context.Context, command FenceCommand) error { return c.controller.AssertQuiesced(ctx, command) }
func (c *generationFenceController) Unquiesce(ctx context.Context, command FenceCommand) error { return c.controller.Unquiesce(ctx, command) }
func (c *generationFenceController) Commit(ctx context.Context, command FenceCommand) error { return c.controller.Commit(ctx, command) }
func (c *generationFenceController) Rollback(ctx context.Context, command FenceCommand) error { return c.controller.Rollback(ctx, command) }

func writeCutoverGenerationReceipt(root *os.Root, name string, receipt CutoverGenerationReceipt) error {
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) == 0 || len(encoded) > 1<<20 {
		return errors.Join(err, ErrInvalid)
	}
	nonce := make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	temporary := ".generation-" + hex.EncodeToString(nonce)
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	chmodErr := file.Chmod(0o400)
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, chmodErr, closeErr); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	if err = root.Rename(temporary, name); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	err = directory.Sync()
	return errors.Join(err, directory.Close())
}

var _ FenceController = (*generationFenceController)(nil)

type UnixFenceController struct {
	socketPath string
	timeout time.Duration
}

type cutoverHelperOperation string

const (
	helperBeginQuiesce cutoverHelperOperation = "begin_quiesce"
	helperBindFence cutoverHelperOperation = "bind_fence"
	helperAbortUnbound cutoverHelperOperation = "abort_unbound"
	helperAssertQuiesced cutoverHelperOperation = "assert_quiesced"
	helperUnquiesce cutoverHelperOperation = "unquiesce"
	helperCommit cutoverHelperOperation = "commit"
	helperRollback cutoverHelperOperation = "rollback"
)

type cutoverHelperRequest struct {
	Version uint32 `json:"version"`
	RequestID string `json:"request_id"`
	Operation cutoverHelperOperation `json:"operation"`
	Quiesce *QuiesceRequest `json:"quiesce,omitempty"`
	HandleID string `json:"handle_id,omitempty"`
	Fence *migration.SourceFence `json:"fence,omitempty"`
	Command *FenceCommand `json:"command,omitempty"`
}

type cutoverHelperResponse struct {
	Version uint32 `json:"version"`
	RequestID string `json:"request_id"`
	Observation *QuiesceObservation `json:"observation,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

func NewUnixFenceController(socketPath string) (*UnixFenceController, error) {
	if !canonicalSourceAgentPath(socketPath) {
		return nil, ErrInvalid
	}
	return &UnixFenceController{socketPath: socketPath, timeout: 5 * time.Minute}, nil
}

func (c *UnixFenceController) BeginQuiesce(ctx context.Context, request QuiesceRequest) (QuiesceObservation, error) {
	response, err := c.call(ctx, cutoverHelperRequest{Operation: helperBeginQuiesce, Quiesce: &request})
	if err != nil {
		return QuiesceObservation{}, err
	}
	if response.Observation == nil {
		return QuiesceObservation{}, ErrInvalid
	}
	return *response.Observation, nil
}

func (c *UnixFenceController) BindFence(ctx context.Context, handleID string, fence migration.SourceFence) error {
	if !validHandle(handleID) {
		return ErrInvalid
	}
	response, err := c.call(ctx, cutoverHelperRequest{Operation: helperBindFence, HandleID: handleID, Fence: &fence})
	return emptyCutoverHelperResponse(response, err)
}

func (c *UnixFenceController) AbortUnbound(ctx context.Context, handleID string) error {
	if !validHandle(handleID) {
		return ErrInvalid
	}
	response, err := c.call(ctx, cutoverHelperRequest{Operation: helperAbortUnbound, HandleID: handleID})
	return emptyCutoverHelperResponse(response, err)
}

func (c *UnixFenceController) AssertQuiesced(ctx context.Context, command FenceCommand) error {
	response, err := c.call(ctx, cutoverHelperRequest{Operation: helperAssertQuiesced, Command: &command})
	return emptyCutoverHelperResponse(response, err)
}

func (c *UnixFenceController) Unquiesce(ctx context.Context, command FenceCommand) error {
	response, err := c.call(ctx, cutoverHelperRequest{Operation: helperUnquiesce, Command: &command})
	return emptyCutoverHelperResponse(response, err)
}

func (c *UnixFenceController) Commit(ctx context.Context, command FenceCommand) error {
	response, err := c.call(ctx, cutoverHelperRequest{Operation: helperCommit, Command: &command})
	return emptyCutoverHelperResponse(response, err)
}

func (c *UnixFenceController) Rollback(ctx context.Context, command FenceCommand) error {
	response, err := c.call(ctx, cutoverHelperRequest{Operation: helperRollback, Command: &command})
	return emptyCutoverHelperResponse(response, err)
}

func (c *UnixFenceController) call(ctx context.Context, request cutoverHelperRequest) (cutoverHelperResponse, error) {
	if c == nil || ctx == nil || !canonicalSourceAgentPath(c.socketPath) {
		return cutoverHelperResponse{}, ErrInvalid
	}
	request.Version = cutoverHelperProtocolVersion
	requestID, err := newSourceAgentRequestID()
	if err != nil {
		return cutoverHelperResponse{}, err
	}
	request.RequestID = requestID
	callContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	connection, err := dialRootCutoverHelper(callContext, c.socketPath)
	if err != nil {
		return cutoverHelperResponse{}, err
	}
	defer connection.Close()
	deadline, _ := callContext.Deadline()
	_ = connection.SetDeadline(deadline)
	raw, err := json.Marshal(request)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return cutoverHelperResponse{}, ErrInvalid
	}
	writer := bufio.NewWriterSize(connection, 64<<10)
	if err = writeFrame(writer, raw); err != nil {
		return cutoverHelperResponse{}, err
	}
	if err = writer.Flush(); err != nil {
		return cutoverHelperResponse{}, err
	}
	encoded, err := readFrame(bufio.NewReaderSize(connection, 1<<20), 1<<20)
	if err != nil {
		return cutoverHelperResponse{}, err
	}
	var response cutoverHelperResponse
	if err = decodeStrict(encoded, &response); err != nil || response.Version != cutoverHelperProtocolVersion || response.RequestID != request.RequestID {
		return cutoverHelperResponse{}, ErrInvalid
	}
	if response.ErrorCode != "" {
		return cutoverHelperResponse{}, cutoverHelperError(response.ErrorCode)
	}
	return response, nil
}

func emptyCutoverHelperResponse(response cutoverHelperResponse, err error) error {
	if err != nil {
		return err
	}
	if response.Observation != nil {
		return ErrInvalid
	}
	return nil
}

func dialRootCutoverHelper(ctx context.Context, path string) (net.Conn, error) {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSocket == 0 || before.Mode().Perm()&0o002 != 0 {
		return nil, errors.Join(err, ErrDenied)
	}
	connection, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Mode()&os.ModeSocket == 0 {
		connection.Close()
		return nil, errors.Join(err, ErrChanged)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, ErrDenied
	}
	rawConnection, err := unixConnection.SyscallConn()
	if err != nil {
		connection.Close()
		return nil, err
	}
	var credentials *syscall.Ucred
	var credentialErr error
	if err = rawConnection.Control(func(descriptor uintptr) {
		credentials, credentialErr = syscall.GetsockoptUcred(int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credentialErr != nil || credentials == nil || credentials.Uid != 0 || credentials.Pid <= 0 {
		connection.Close()
		return nil, errors.Join(err, credentialErr, ErrDenied)
	}
	return connection, nil
}

func newSourceAgentRequestID() (string, error) {
	value := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return "helper_" + hex.EncodeToString(value), nil
}

func cutoverHelperError(code string) error {
	switch code {
	case "INVALID_REQUEST":
		return ErrInvalid
	case "DENIED":
		return ErrDenied
	case "CHANGED":
		return ErrChanged
	case "NOT_FOUND":
		return migration.ErrNotFound
	default:
		return errors.New("source cutover helper operation failed")
	}
}

var _ FenceController = (*UnixFenceController)(nil)
