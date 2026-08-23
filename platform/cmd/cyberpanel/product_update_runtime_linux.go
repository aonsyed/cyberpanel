//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/maintenance"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/productupdate"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	productUpdateReleaseRoot = "/var/lib/cyberpanel/product-updates"
	productUpdateTrustPath = "/etc/cyberpanel/product-update/trust.json"
	productUpdateStagingRoot = "/var/lib/cyberpanel/control/product-update-staging"
	productUpdateAuthorizationAdapterID = "productupdate.authorization"
	productUpdateAuthorizationAdapterVersion = "linux-local-v1"
	productUpdateAuthorizationOwner = secrets.ID("product_update_authority")
	productUpdateAuthorizationDomain = "cyberpanel-product-update-authorization-v1\n"
	productUpdateAuthorizationProofDomain = "cyberpanel-product-update-authorization-proof-v1\n"
	productUpdateMaximumAuthorizationBytes = 1 << 20
)

type productUpdateTrustDocument struct {
	CurrentEpoch uint64 `json:"current_epoch"`
	Threshold uint16 `json:"threshold"`
	MaximumClockSkewSeconds int64 `json:"maximum_clock_skew_seconds"`
	MaximumLifetimeSeconds int64 `json:"maximum_lifetime_seconds"`
	MaximumManifestBytes int64 `json:"maximum_manifest_bytes"`
	ManifestRoots []productUpdateManifestRootDocument `json:"manifest_roots"`
	AuthorizationRootsPEM string `json:"authorization_roots_pem"`
	Staging productUpdateStagingLimitsDocument `json:"staging"`
}

type productUpdateManifestRootDocument struct {
	KeyID string `json:"key_id"`
	Epoch uint64 `json:"epoch"`
	PublicKey string `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	NotAfter time.Time `json:"not_after"`
	Revoked bool `json:"revoked"`
}

type productUpdateStagingLimitsDocument struct {
	MaximumArtifactBytes int64 `json:"maximum_artifact_bytes"`
	MaximumTotalBytes int64 `json:"maximum_total_bytes"`
	MaximumExtractedBytes int64 `json:"maximum_extracted_bytes"`
	MaximumFileBytes int64 `json:"maximum_file_bytes"`
	MaximumFiles int `json:"maximum_files"`
	MaximumPathBytes int `json:"maximum_path_bytes"`
}

type productUpdateAuthorizationEnvelope struct {
	Authorization productupdate.UpdateAuthorization `json:"authorization"`
	CertificateChainPEM string `json:"certificate_chain_pem"`
	Signature string `json:"signature"`
}

type localProtectedProductUpdateSource struct {
	root string
	maximumManifestBytes int64
}

type signedProductUpdateAuthority struct {
	material *secrets.MaterialClient
	roots *x509.CertPool
	now func() time.Time
}

type productUpdateAuditSink struct{ service *audit.Service }

// productUpdateCatalogEffects is the fail-closed fallback used until every
// apply dependency, including the independently hosted self-updater, proves
// readiness through the typed operations boundary.
type productUpdateCatalogEffects struct{}

type productUpdateApplyAdapters struct {
	executor *operations.OperationsBrokerClient
	authority *signedProductUpdateAuthority
	maintenance *maintenance.Evaluator
	occurrences *maintenance.Repository
	nodeID string
}

func assembleProductUpdateEdge(ctx context.Context, db *sql.DB, auditService *audit.Service, clock runtimeClock) (apiserver.ProductUpdateEdgeService, error) {
	if ctx == nil || db == nil || auditService == nil || auditService.Writer == nil {
		return nil, productupdate.ErrInvalid
	}
	configured, err := productUpdateRuntimeConfigured()
	if err != nil || !configured {
		return nil, err
	}
	verifier, authorizationRoots, limits, maximumManifestBytes, err := loadProductUpdateTrust(productUpdateTrustPath, clock.Now())
	if err != nil {
		return nil, fmt.Errorf("load product-update trust: %w", err)
	}
	releases, err := newLocalProtectedProductUpdateSource(productUpdateReleaseRoot, maximumManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("open product-update release source: %w", err)
	}
	inventory, err := releases.loadInventory(ctx)
	if err != nil {
		return nil, fmt.Errorf("load product-update inventory: %w", err)
	}
	material, err := secrets.NewLocalMaterialClient()
	if err != nil {
		return nil, fmt.Errorf("connect product-update authorization broker: %w", err)
	}
	authority, err := newSignedProductUpdateAuthority(material, authorizationRoots, clock.Now)
	if err != nil {
		return nil, fmt.Errorf("initialize product-update authorization: %w", err)
	}
	if err = ensureProductUpdateStagingRoot(productUpdateStagingRoot); err != nil {
		return nil, fmt.Errorf("open product-update staging root: %w", err)
	}
	stager, err := productupdate.NewStager(productUpdateStagingRoot, limits)
	if err != nil {
		return nil, fmt.Errorf("initialize product-update stager: %w", err)
	}
	repository, err := productupdate.NewRepository(db)
	if err != nil {
		return nil, fmt.Errorf("open product-update repository: %w", err)
	}
	if err = repository.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap product-update repository: %w", err)
	}
	effects := productUpdateCatalogEffects{}
	var maintenanceGate productupdate.MaintenanceGate = effects
	var migrations productupdate.MigrationExecutor = effects
	var platform productupdate.PlatformExecutor = effects
	var health productupdate.HealthProber = effects
	applyReady := false
	if adapters, ready := newProductUpdateApplyAdapters(ctx, db, authority, inventory.NodeID); ready {
		maintenanceGate, migrations, platform, health = adapters, adapters, adapters, adapters
		applyReady = true
	}
	coordinator, err := productupdate.NewCoordinator(repository, verifier, stager, releases, authority, maintenanceGate,
		productUpdateAuditSink{service:auditService}, migrations, platform, health, clock)
	if err != nil {
		return nil, fmt.Errorf("initialize product-update coordinator: %w", err)
	}
	executableDigest, err := certificates.CurrentExecutableDigest()
	if err != nil {
		return nil, fmt.Errorf("digest product-update controller: %w", err)
	}
	edge, err := newProductUpdateLinuxEdge(coordinator, repository, releases, releases, authority, inventory.NodeID,
		"panel-core-"+executableDigest[:32], clock.Now)
	if err != nil {
		return nil, fmt.Errorf("initialize product-update catalog edge: %w", err)
	}
	edge.capabilities = apiserver.ProductUpdateEdgeCapabilities{List:true, Check:true, Plan:true, Apply:applyReady}
	return edge, nil
}

func productUpdateRuntimeConfigured() (bool, error) {
	rootInfo, rootErr := os.Lstat(productUpdateReleaseRoot)
	trustInfo, trustErr := os.Lstat(productUpdateTrustPath)
	rootMissing := errors.Is(rootErr, os.ErrNotExist)
	trustMissing := errors.Is(trustErr, os.ErrNotExist)
	if rootMissing && trustMissing {
		return false, nil
	}
	if rootErr != nil || trustErr != nil || rootInfo == nil || trustInfo == nil {
		return false, fmt.Errorf("product-update deployment material is incomplete")
	}
	return true, nil
}

func loadProductUpdateTrust(path string, now time.Time) (*productupdate.Verifier, *x509.CertPool, productupdate.StagingLimits, int64, error) {
	if path != productUpdateTrustPath || now.IsZero() {
		return nil, nil, productupdate.StagingLimits{}, 0, productupdate.ErrInvalid
	}
	if err := requireRootOwnedProductUpdateDirectory(filepath.Dir(path)); err != nil {
		return nil, nil, productupdate.StagingLimits{}, 0, err
	}
	raw, err := readRootOwnedProductUpdateFile(path, 1<<20)
	if err != nil {
		return nil, nil, productupdate.StagingLimits{}, 0, err
	}
	var document productUpdateTrustDocument
	if err = decodeProductUpdateJSON(raw, &document); err != nil {
		return nil, nil, productupdate.StagingLimits{}, 0, err
	}
	if document.Threshold < 2 || document.MaximumClockSkewSeconds < 0 || document.MaximumClockSkewSeconds > 600 ||
		document.MaximumLifetimeSeconds <= 0 || document.MaximumLifetimeSeconds > int64((366*24*time.Hour)/time.Second) ||
		document.MaximumManifestBytes <= 0 || document.MaximumManifestBytes > 16<<20 || len(document.ManifestRoots) < int(document.Threshold) {
		return nil, nil, productupdate.StagingLimits{}, 0, productupdate.ErrInvalid
	}
	roots := make([]productupdate.TrustRoot, 0, len(document.ManifestRoots))
	active := 0
	for _, entry := range document.ManifestRoots {
		publicKey, decodeErr := decodeProductUpdatePublicKey(entry.PublicKey)
		if decodeErr != nil {
			return nil, nil, productupdate.StagingLimits{}, 0, decodeErr
		}
		root := productupdate.TrustRoot{KeyID:entry.KeyID, Epoch:entry.Epoch, PublicKey:publicKey,
			NotBefore:entry.NotBefore.UTC(), NotAfter:entry.NotAfter.UTC(), Revoked:entry.Revoked}
		if !root.Revoked && root.Epoch == document.CurrentEpoch && !now.Before(root.NotBefore) && now.Before(root.NotAfter) {
			active++
		}
		roots = append(roots, root)
	}
	if active < int(document.Threshold) {
		return nil, nil, productupdate.StagingLimits{}, 0, productupdate.ErrUnauthorized
	}
	verifier, err := productupdate.NewVerifier(productupdate.TrustPolicy{Roots:roots, Threshold:document.Threshold,
		CurrentEpoch:document.CurrentEpoch, MaximumClockSkew:time.Duration(document.MaximumClockSkewSeconds)*time.Second,
		MaximumLifetime:time.Duration(document.MaximumLifetimeSeconds)*time.Second, MaximumBytes:document.MaximumManifestBytes})
	if err != nil {
		return nil, nil, productupdate.StagingLimits{}, 0, err
	}
	authorizationRoots, err := parseProductUpdateAuthorizationRoots([]byte(document.AuthorizationRootsPEM), now)
	if err != nil {
		return nil, nil, productupdate.StagingLimits{}, 0, err
	}
	limits := productupdate.StagingLimits{MaximumArtifactBytes:document.Staging.MaximumArtifactBytes,
		MaximumTotalBytes:document.Staging.MaximumTotalBytes, MaximumExtractedBytes:document.Staging.MaximumExtractedBytes,
		MaximumFileBytes:document.Staging.MaximumFileBytes, MaximumFiles:document.Staging.MaximumFiles,
		MaximumPathBytes:document.Staging.MaximumPathBytes}
	return verifier, authorizationRoots, limits, document.MaximumManifestBytes, nil
}

func decodeProductUpdatePublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil {
		decoded, err = hex.DecodeString(value)
	}
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, productupdate.ErrInvalid
	}
	return ed25519.PublicKey(decoded), nil
}

func parseProductUpdateAuthorizationRoots(content []byte, now time.Time) (*x509.CertPool, error) {
	if len(content) == 0 || len(content) > 1<<20 || now.IsZero() {
		return nil, productupdate.ErrInvalid
	}
	pool := x509.NewCertPool()
	rest := content
	count := 0
	for len(bytes.TrimSpace(rest)) != 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(next) >= len(rest) || count == 16 {
			return nil, productupdate.ErrInvalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) || certificate.CheckSignatureFrom(certificate) != nil {
			return nil, productupdate.ErrUnauthorized
		}
		pool.AddCert(certificate)
		count++
		rest = next
	}
	if count == 0 {
		return nil, productupdate.ErrInvalid
	}
	return pool, nil
}

func newLocalProtectedProductUpdateSource(root string, maximumManifestBytes int64) (*localProtectedProductUpdateSource, error) {
	if root != productUpdateReleaseRoot || maximumManifestBytes <= 0 || maximumManifestBytes > 16<<20 {
		return nil, productupdate.ErrInvalid
	}
	for _, directory := range []string{root, filepath.Join(root, "manifests"), filepath.Join(root, "artifacts")} {
		if err := requireRootOwnedProductUpdateDirectory(directory); err != nil {
			return nil, err
		}
	}
	return &localProtectedProductUpdateSource{root:root, maximumManifestBytes:maximumManifestBytes}, nil
}

func (source *localProtectedProductUpdateSource) Manifest(ctx context.Context, manifestID string) (productupdate.ReleaseManifest, error) {
	if source == nil || ctx == nil || !validProductUpdateRuntimeID(manifestID) {
		return productupdate.ReleaseManifest{}, productupdate.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return productupdate.ReleaseManifest{}, err
	}
	path := filepath.Join(source.root, "manifests", manifestID+".json")
	raw, err := readRootOwnedProductUpdateFile(path, source.maximumManifestBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) { return productupdate.ReleaseManifest{}, productupdate.ErrNotFound }
		return productupdate.ReleaseManifest{}, err
	}
	var manifest productupdate.ReleaseManifest
	if err = decodeProductUpdateJSON(raw, &manifest); err != nil {
		return productupdate.ReleaseManifest{}, err
	}
	manifest, err = productupdate.CanonicalManifest(manifest)
	if err != nil || manifest.ID != manifestID {
		if err != nil { return productupdate.ReleaseManifest{}, err }
		return productupdate.ReleaseManifest{}, productupdate.ErrIntegrity
	}
	return manifest, nil
}

func (source *localProtectedProductUpdateSource) OpenArtifact(ctx context.Context, manifestID, artifactID string) (io.ReadCloser, error) {
	if source == nil || ctx == nil || !validProductUpdateRuntimeID(artifactID) {
		return nil, productupdate.ErrInvalid
	}
	manifest, err := source.Manifest(ctx, manifestID)
	if err != nil {
		return nil, err
	}
	var selected *productupdate.Artifact
	for index := range manifest.Artifacts {
		if manifest.Artifacts[index].ID == artifactID {
			selected = &manifest.Artifacts[index]
			break
		}
	}
	if selected == nil {
		return nil, productupdate.ErrNotFound
	}
	path := filepath.Join(source.root, "artifacts", selected.Digest+".tar")
	file, info, err := openRootOwnedProductUpdateFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) { return nil, productupdate.ErrNotFound }
		return nil, err
	}
	if info.Size() != selected.Size {
		_ = file.Close()
		return nil, productupdate.ErrIntegrity
	}
	return file, nil
}

func (source *localProtectedProductUpdateSource) InstalledInventory(ctx context.Context, nodeID string) (productupdate.InstalledInventory, error) {
	inventory, err := source.loadInventory(ctx)
	if err != nil {
		return productupdate.InstalledInventory{}, err
	}
	if nodeID != "" && inventory.NodeID != nodeID {
		return productupdate.InstalledInventory{}, productupdate.ErrIntegrity
	}
	return inventory, nil
}

func (source *localProtectedProductUpdateSource) loadInventory(ctx context.Context) (productupdate.InstalledInventory, error) {
	if source == nil || ctx == nil {
		return productupdate.InstalledInventory{}, productupdate.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return productupdate.InstalledInventory{}, err
	}
	raw, err := readRootOwnedProductUpdateFile(filepath.Join(source.root, "inventory.json"), 1<<20)
	if err != nil {
		return productupdate.InstalledInventory{}, err
	}
	var inventory productupdate.InstalledInventory
	if err = decodeProductUpdateJSON(raw, &inventory); err != nil {
		return productupdate.InstalledInventory{}, err
	}
	return productupdate.CanonicalInventory(inventory)
}

func newSignedProductUpdateAuthority(material *secrets.MaterialClient, roots *x509.CertPool, now func() time.Time) (*signedProductUpdateAuthority, error) {
	if material == nil || roots == nil {
		return nil, productupdate.ErrInvalid
	}
	if now == nil { now = time.Now }
	return &signedProductUpdateAuthority{material:material, roots:roots, now:now}, nil
}

func (authority *signedProductUpdateAuthority) AuthorizeProductUpdate(ctx context.Context, request productUpdateAuthorizationRequest) (productupdate.UpdateAuthorization, error) {
	if authority == nil || ctx == nil || request.Call.PrincipalID == "" || request.Call.CredentialID == "" || request.Call.AuthzEpoch == 0 ||
		request.Call.Assurance < identity.AssuranceMFA || request.State.NodeID == "" || request.State.ManifestDigest != request.Manifest.Digest {
		return productupdate.UpdateAuthorization{}, productupdate.ErrUnauthorized
	}
	if productUpdateApplyAction(request.Action) && request.Call.Assurance < identity.AssurancePhishingResistant {
		return productupdate.UpdateAuthorization{}, productupdate.ErrUnauthorized
	}
	now := authority.now().UTC()
	envelope, err := authority.loadEnvelope(ctx, request.Manifest.Digest, request.State.NodeID, request.Action, request.Call.PrincipalID)
	if err != nil {
		return productupdate.UpdateAuthorization{}, err
	}
	authorization, err := authority.verifyEnvelope(envelope, now)
	if err != nil {
		return productupdate.UpdateAuthorization{}, err
	}
	authorization, err = productupdate.CanonicalAuthorization(authorization, request.Manifest, request.State.NodeID, request.Action, now)
	if err != nil || authorization.Subject != request.Call.PrincipalID {
		if err != nil { return productupdate.UpdateAuthorization{}, err }
		return productupdate.UpdateAuthorization{}, productupdate.ErrUnauthorized
	}
	return authorization, nil
}

func (authority *signedProductUpdateAuthority) VerifyUpdateAuthorization(ctx context.Context, authorization productupdate.UpdateAuthorization) error {
	if authority == nil || ctx == nil {
		return productupdate.ErrUnauthorized
	}
	envelope, err := authority.loadEnvelope(ctx, authorization.ManifestDigest, authorization.NodeID, authorization.Action, authorization.Subject)
	if err != nil {
		return err
	}
	stored, err := authority.verifyEnvelope(envelope, authority.now().UTC())
	if err != nil {
		return err
	}
	if stored.Digest != authorization.Digest || stored.ProofDigest != authorization.ProofDigest || stored.ID != authorization.ID {
		return productupdate.ErrUnauthorized
	}
	return nil
}

func (authority *signedProductUpdateAuthority) loadEnvelope(ctx context.Context, manifestDigest, nodeID string, action productupdate.UpdateAction, subject string) (productUpdateAuthorizationEnvelope, error) {
	secretID, resourceID, err := productUpdateAuthorizationBinding(manifestDigest, nodeID, action, subject)
	if err != nil {
		return productUpdateAuthorizationEnvelope{}, err
	}
	response, err := authority.material.Read(ctx, secrets.MaterialRequest{SecretID:secretID, OwnerTenantID:productUpdateAuthorizationOwner,
		Purpose:secrets.PurposeAuthentication, Operation:secrets.OperationRead, AdapterID:productUpdateAuthorizationAdapterID,
		AdapterVersion:productUpdateAuthorizationAdapterVersion, ResourceID:resourceID})
	if err != nil {
		switch {
		case errors.Is(err, secrets.ErrNotFound), errors.Is(err, secrets.ErrForbidden), errors.Is(err, secrets.ErrExpired),
			errors.Is(err, secrets.ErrRevoked), errors.Is(err, secrets.ErrInvalid):
			return productUpdateAuthorizationEnvelope{}, productupdate.ErrUnauthorized
		default:
			return productUpdateAuthorizationEnvelope{}, productupdate.ErrIntegrity
		}
	}
	defer wipeProductUpdateBytes(response.Material)
	if len(response.Material) == 0 || len(response.Material) > productUpdateMaximumAuthorizationBytes {
		return productUpdateAuthorizationEnvelope{}, productupdate.ErrIntegrity
	}
	var envelope productUpdateAuthorizationEnvelope
	if err = decodeProductUpdateJSON(response.Material, &envelope); err != nil {
		return productUpdateAuthorizationEnvelope{}, productupdate.ErrIntegrity
	}
	return envelope, nil
}

func (authority *signedProductUpdateAuthority) verifyEnvelope(envelope productUpdateAuthorizationEnvelope, now time.Time) (productupdate.UpdateAuthorization, error) {
	certificates, err := parseProductUpdateAuthorizationChain([]byte(envelope.CertificateChainPEM))
	if err != nil {
		return productupdate.UpdateAuthorization{}, err
	}
	leaf := certificates[0]
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] { intermediates.AddCert(certificate) }
	if _, err = leaf.Verify(x509.VerifyOptions{Roots:authority.roots, Intermediates:intermediates, CurrentTime:now,
		KeyUsages:[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		!productUpdateCertificateAllowsCodeSigning(leaf) || envelope.Authorization.IssuedAt.Before(leaf.NotBefore) || envelope.Authorization.ExpiresAt.After(leaf.NotAfter) {
		return productupdate.UpdateAuthorization{}, productupdate.ErrUnauthorized
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return productupdate.UpdateAuthorization{}, productupdate.ErrUnauthorized
	}
	payload, err := productUpdateAuthorizationSigningPayload(envelope.Authorization)
	if err != nil {
		return productupdate.UpdateAuthorization{}, err
	}
	signature, err := decodeProductUpdateSignature(envelope.Signature)
	if err != nil || !ed25519.Verify(publicKey, append([]byte(productUpdateAuthorizationDomain), payload...), signature) {
		return productupdate.UpdateAuthorization{}, productupdate.ErrUnauthorized
	}
	proof := sha256.New()
	_, _ = proof.Write([]byte(productUpdateAuthorizationProofDomain))
	_, _ = proof.Write(leaf.RawSubjectPublicKeyInfo)
	_, _ = proof.Write([]byte{0})
	_, _ = proof.Write(signature)
	_, _ = proof.Write([]byte{0})
	_, _ = proof.Write(payload)
	if envelope.Authorization.ProofDigest != hex.EncodeToString(proof.Sum(nil)) ||
		envelope.Authorization.Issuer != productUpdateAuthorizationKeyID(leaf) || !validProductUpdateDigest(envelope.Authorization.Digest) {
		return productupdate.UpdateAuthorization{}, productupdate.ErrIntegrity
	}
	candidate := envelope.Authorization
	claimed := candidate.Digest
	candidate.Digest = ""
	raw, err := json.Marshal(candidate)
	if err != nil {
		return productupdate.UpdateAuthorization{}, err
	}
	digest := sha256.Sum256(raw)
	if claimed != hex.EncodeToString(digest[:]) {
		return productupdate.UpdateAuthorization{}, productupdate.ErrIntegrity
	}
	return envelope.Authorization, nil
}

func productUpdateAuthorizationBinding(manifestDigest, nodeID string, action productupdate.UpdateAction, subject string) (secrets.ID, secrets.ID, error) {
	if !validProductUpdateDigest(manifestDigest) || !validProductUpdateRuntimeID(nodeID) || !validProductUpdateRuntimeID(subject) || !validProductUpdateAction(action) {
		return "", "", productupdate.ErrInvalid
	}
	sum := sha256.Sum256([]byte("cyberpanel-product-update-authorization-binding-v1\x00" + manifestDigest + "\x00" + nodeID + "\x00" + string(action) + "\x00" + subject))
	encoded := hex.EncodeToString(sum[:])[:48]
	secretID, secretErr := secrets.NewID("updateauth_" + encoded)
	resourceID, resourceErr := secrets.NewID("updatescope_" + encoded)
	if secretErr != nil || resourceErr != nil {
		return "", "", productupdate.ErrInvalid
	}
	return secretID, resourceID, nil
}

func productUpdateAuthorizationSigningPayload(authorization productupdate.UpdateAuthorization) ([]byte, error) {
	authorization.ProofDigest = ""
	authorization.Digest = ""
	return json.Marshal(authorization)
}

func productUpdateAuthorizationKeyID(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return "update-authority-" + hex.EncodeToString(sum[:])[:32]
}

func productUpdateApplyAction(action productupdate.UpdateAction) bool {
	switch action {
	case productupdate.ActionPreflight, productupdate.ActionSwitch, productupdate.ActionProbe, productupdate.ActionFinalize,
		productupdate.ActionCommit, productupdate.ActionRollback, productupdate.ActionFail, productupdate.ActionFence:
		return true
	default:
		return false
	}
}

func validProductUpdateAction(action productupdate.UpdateAction) bool {
	switch action {
	case productupdate.ActionVerify, productupdate.ActionFence, productupdate.ActionStage, productupdate.ActionPreflight,
		productupdate.ActionSwitch, productupdate.ActionProbe, productupdate.ActionFinalize, productupdate.ActionCommit,
		productupdate.ActionRollback, productupdate.ActionFail:
		return true
	default:
		return false
	}
}

func productUpdateCertificateAllowsCodeSigning(certificate *x509.Certificate) bool {
	if certificate == nil || len(certificate.ExtKeyUsage) == 0 {
		return false
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning { return true }
	}
	return false
}

func parseProductUpdateAuthorizationChain(content []byte) ([]*x509.Certificate, error) {
	if len(content) == 0 || len(content) > 1<<20 {
		return nil, productupdate.ErrInvalid
	}
	result := make([]*x509.Certificate, 0, 4)
	rest := content
	for len(bytes.TrimSpace(rest)) != 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(next) >= len(rest) || len(result) == 8 {
			return nil, productupdate.ErrInvalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, productupdate.ErrInvalid
		}
		result = append(result, certificate)
		rest = next
	}
	if len(result) == 0 {
		return nil, productupdate.ErrInvalid
	}
	return result, nil
}

func decodeProductUpdateSignature(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) == ed25519.SignatureSize { return decoded, nil }
	}
	return nil, productupdate.ErrInvalid
}

func (sink productUpdateAuditSink) RecordProductUpdate(ctx context.Context, record productupdate.AuditRecord) error {
	if sink.service == nil || sink.service.Writer == nil || ctx == nil || !validProductUpdateDigest(record.Digest) {
		return productupdate.ErrIntegrity
	}
	attributes := map[string]string{"manifest_id":record.ManifestID, "node_id":record.NodeID,
		"authorization_digest":record.AuthorizationDigest, "intent_digest":record.IntentDigest,
		"fence":strconv.FormatUint(record.Fence, 10)}
	if record.MaintenanceEvidence != "" { attributes["maintenance_evidence"] = record.MaintenanceEvidence }
	event := audit.Event{ID:record.ID, Class:audit.ClassAuthorization, Action:"product_update."+string(record.Action),
		Actor:audit.Actor{ServiceID:"panel-core-product-update"},
		Target:audit.Target{Kind:"product_update", ID:record.ManifestID, Generation:strconv.FormatUint(record.Generation, 10)},
		Outcome:audit.OutcomeAllowed, RequestDigest:record.Digest, DecisionDigest:record.AuthorizationDigest,
		EffectID:record.ID, Attributes:attributes, OccurredAt:record.At.UTC()}
	if _, err := sink.service.RecordDecision(ctx, event, nil); err != nil {
		return productupdate.ErrIntegrity
	}
	return nil
}

func newProductUpdateApplyAdapters(ctx context.Context, db *sql.DB, authority *signedProductUpdateAuthority, nodeID string) (*productUpdateApplyAdapters, bool) {
	if ctx == nil || db == nil || authority == nil || !validProductUpdateRuntimeID(nodeID) { return nil, false }
	repository, err := maintenance.NewRepository(db)
	if err != nil || repository.Bootstrap(ctx) != nil { return nil, false }
	evaluator, err := maintenance.NewEvaluator(repository, maintenance.EvaluatorConfig{})
	if err != nil { return nil, false }
	executor, err := operations.NewLocalOperationsClient()
	if err != nil { return nil, false }
	adapters := &productUpdateApplyAdapters{executor:executor, authority:authority, maintenance:evaluator, occurrences:repository, nodeID:nodeID}
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateReadiness}, nil)
	if err != nil || result.Readiness == nil || !result.Readiness.Complete { return nil, false }
	active, err := adapters.CurrentRelease(ctx, nodeID)
	if err != nil || active.Validate() != nil { return nil, false }
	baseline, err := adapters.CaptureBaseline(ctx, nodeID)
	if err != nil || baseline.NodeID != nodeID || baseline.ActiveReleaseDigest != active.Digest || !validProductUpdateDigest(baseline.EvidenceDigest) ||
		baseline.ObservedAt.IsZero() || !validProductUpdateDigest(baseline.Digest) { return nil, false }
	claimed := baseline.Digest
	baseline.Digest = ""
	baseline.ObservedAt = baseline.ObservedAt.UTC()
	if claimed != productUpdateRuntimeJSONDigest(baseline) { return nil, false }
	return adapters, true
}

func (adapters *productUpdateApplyAdapters) execute(ctx context.Context, effect operations.ProductUpdateEffect, authorization *productupdate.UpdateAuthorization) (operations.ProductUpdateResult, error) {
	if adapters == nil || adapters.executor == nil || adapters.authority == nil || ctx == nil { return operations.ProductUpdateResult{}, productupdate.ErrIntegrity }
	effect.NodeID = adapters.nodeID
	if authorization == nil {
		switch effect.Action {
		case operations.ProductUpdateReadiness, operations.ProductUpdateCurrent, operations.ProductUpdateCaptureBaseline:
			effect.ObservedAt = adapters.authority.now().UTC()
		}
	}
	if authorization != nil {
		if authorization.NodeID != adapters.nodeID { return operations.ProductUpdateResult{}, productupdate.ErrUnauthorized }
		envelope, err := adapters.authority.loadEnvelope(ctx, authorization.ManifestDigest, authorization.NodeID, authorization.Action, authorization.Subject)
		if err != nil { return operations.ProductUpdateResult{}, err }
		now := adapters.authority.now().UTC()
		verified, err := adapters.authority.verifyEnvelope(envelope, now)
		if err == nil {
			verified, err = productupdate.CanonicalAuthorization(verified, productupdate.ReleaseManifest{Digest:authorization.ManifestDigest},
				authorization.NodeID, authorization.Action, now)
		}
		if err != nil || verified != *authorization {
			return operations.ProductUpdateResult{}, productupdate.ErrUnauthorized
		}
		effect.Authorization = &operations.ProductUpdateSignedAuthorization{Authorization:*authorization,
			CertificateChainPEM:envelope.CertificateChainPEM, Signature:envelope.Signature}
	}
	request, err := operations.NewProductUpdateEffectRequest(effect)
	if err != nil { return operations.ProductUpdateResult{}, productupdate.ErrIntegrity }
	receipt, err := adapters.executor.ObserveOrApply(ctx, request)
	if err != nil || receipt.Outcome != operations.EffectConfirmed || receipt.Result.ProductUpdate == nil {
		return operations.ProductUpdateResult{}, productupdate.ErrIntegrity
	}
	return *receipt.Result.ProductUpdate, nil
}

func (adapters *productUpdateApplyAdapters) AdmitProductUpdate(ctx context.Context, request productupdate.MaintenanceRequest) (productupdate.MaintenanceAdmission, error) {
	if adapters == nil || adapters.maintenance == nil || adapters.occurrences == nil || ctx == nil || request.NodeID != adapters.nodeID ||
		(request.Action != productupdate.ActionPreflight && request.Action != productupdate.ActionSwitch) || !validProductUpdateDigest(request.ManifestDigest) ||
		!validProductUpdateRuntimeID(request.ManifestID) || request.Fence == 0 || request.ExpectedDuration < time.Second || request.Digest == "" {
		return productupdate.MaintenanceAdmission{}, productupdate.ErrInvalid
	}
	claimed := request.Digest
	request.Digest = ""
	if claimed != productUpdateRuntimeJSONDigest(request) { return productupdate.MaintenanceAdmission{}, productupdate.ErrIntegrity }
	decision, err := adapters.maintenance.Admit(ctx, maintenance.AdmissionRequest{ID:"product-update-" + claimed[:32],
		Target:maintenance.Target{TenantID:"installation", NodeID:request.NodeID, ResourceKind:"product_update", ResourceID:request.ManifestID},
		OperationClass:maintenance.OperationUpgrade, ExpectedDuration:request.ExpectedDuration, At:request.RequestedAt.UTC()})
	if err != nil || decision.Kind != maintenance.DecisionAllow || !validProductUpdateRuntimeID(decision.OccurrenceID) {
		return productupdate.MaintenanceAdmission{}, productupdate.ErrConflict
	}
	occurrence, err := adapters.occurrences.LoadOccurrence(ctx, decision.OccurrenceID)
	if err != nil || occurrence.ID != decision.OccurrenceID || occurrence.EndsAt.Before(request.RequestedAt.Add(request.ExpectedDuration)) {
		return productupdate.MaintenanceAdmission{}, productupdate.ErrConflict
	}
	evidence := productUpdateRuntimeJSONDigest(struct {
		RequestDigest string `json:"request_digest"`
		DecisionEvidence string `json:"decision_evidence"`
		OccurrenceDigest string `json:"occurrence_digest"`
	}{claimed, decision.EvidenceDigest, occurrence.Digest})
	admission := productupdate.MaintenanceAdmission{Allowed:true, OccurrenceID:occurrence.ID, OccurrenceDigest:occurrence.Digest,
		EndsAt:occurrence.EndsAt.UTC(), EvidenceDigest:evidence}
	admission.Digest = productUpdateRuntimeJSONDigest(admission)
	return admission, nil
}

func (adapters *productUpdateApplyAdapters) PreflightMigration(ctx context.Context, operation productupdate.MigrationOperation) (productupdate.MigrationAssessment, error) {
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateMigrationPreflight, Migration:&operation}, &operation.Authorization)
	if err != nil || result.MigrationAssessment == nil { return productupdate.MigrationAssessment{}, productupdate.ErrIntegrity }
	return *result.MigrationAssessment, nil
}

func (adapters *productUpdateApplyAdapters) OnlineBackup(ctx context.Context, operation productupdate.BackupOperation) (productupdate.EffectReceipt, error) {
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateMigrationBackup, Backup:&operation}, &operation.Migration.Authorization)
	if err != nil || result.Effect == nil { return productupdate.EffectReceipt{}, productupdate.ErrIntegrity }
	return *result.Effect, nil
}

func (adapters *productUpdateApplyAdapters) ApplyMigration(ctx context.Context, operation productupdate.MigrationOperation) (productupdate.EffectReceipt, error) {
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateMigrationApply, Migration:&operation}, &operation.Authorization)
	if err != nil || result.Effect == nil { return productupdate.EffectReceipt{}, productupdate.ErrIntegrity }
	return *result.Effect, nil
}

func (adapters *productUpdateApplyAdapters) RollbackMigration(ctx context.Context, operation productupdate.MigrationRollbackOperation) (productupdate.EffectReceipt, error) {
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateMigrationRollback, MigrationRollback:&operation}, &operation.Migration.Authorization)
	if err != nil || result.Effect == nil { return productupdate.EffectReceipt{}, productupdate.ErrIntegrity }
	return *result.Effect, nil
}

func (adapters *productUpdateApplyAdapters) CurrentRelease(ctx context.Context, nodeID string) (productupdate.ActiveRelease, error) {
	if adapters == nil || nodeID != adapters.nodeID { return productupdate.ActiveRelease{}, productupdate.ErrIntegrity }
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateCurrent}, nil)
	if err != nil || result.ActiveRelease == nil { return productupdate.ActiveRelease{}, productupdate.ErrIntegrity }
	return *result.ActiveRelease, nil
}

func (adapters *productUpdateApplyAdapters) InspectRollback(ctx context.Context, operation productupdate.RollbackInspection) (productupdate.RollbackProof, error) {
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateInspectRollback, RollbackInspection:&operation}, &operation.Authorization)
	if err != nil || result.RollbackProof == nil { return productupdate.RollbackProof{}, productupdate.ErrIntegrity }
	return *result.RollbackProof, nil
}

func (adapters *productUpdateApplyAdapters) AtomicSwitch(ctx context.Context, operation productupdate.SwitchOperation) (productupdate.EffectReceipt, error) {
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateSwitch, Switch:&operation}, &operation.Authorization)
	if err != nil || result.Effect == nil { return productupdate.EffectReceipt{}, productupdate.ErrIntegrity }
	return *result.Effect, nil
}

func (adapters *productUpdateApplyAdapters) CommitSwitch(ctx context.Context, operation productupdate.FinalizeOperation) (productupdate.EffectReceipt, error) {
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateCommit, Finalize:&operation}, &operation.Authorization)
	if err != nil || result.Effect == nil { return productupdate.EffectReceipt{}, productupdate.ErrIntegrity }
	return *result.Effect, nil
}

func (adapters *productUpdateApplyAdapters) AtomicRollback(ctx context.Context, operation productupdate.FinalizeOperation) (productupdate.EffectReceipt, error) {
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateRollback, Finalize:&operation}, &operation.Authorization)
	if err != nil || result.Effect == nil { return productupdate.EffectReceipt{}, productupdate.ErrIntegrity }
	return *result.Effect, nil
}

func (adapters *productUpdateApplyAdapters) CaptureBaseline(ctx context.Context, nodeID string) (productupdate.HealthSnapshot, error) {
	if adapters == nil || nodeID != adapters.nodeID { return productupdate.HealthSnapshot{}, productupdate.ErrIntegrity }
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateCaptureBaseline}, nil)
	if err != nil || result.Health == nil { return productupdate.HealthSnapshot{}, productupdate.ErrIntegrity }
	return *result.Health, nil
}

func (adapters *productUpdateApplyAdapters) ProbeRelease(ctx context.Context, operation productupdate.ProbeOperation) (productupdate.HealthSnapshot, error) {
	result, err := adapters.execute(ctx, operations.ProductUpdateEffect{Action:operations.ProductUpdateProbe, Probe:&operation}, &operation.Authorization)
	if err != nil || result.Health == nil { return productupdate.HealthSnapshot{}, productupdate.ErrIntegrity }
	return *result.Health, nil
}

func productUpdateRuntimeJSONDigest(value any) string {
	raw, err := json.Marshal(value)
	if err != nil { return "" }
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (productUpdateCatalogEffects) AdmitProductUpdate(context.Context, productupdate.MaintenanceRequest) (productupdate.MaintenanceAdmission, error) {
	return productupdate.MaintenanceAdmission{}, productupdate.ErrConflict
}

func (productUpdateCatalogEffects) PreflightMigration(context.Context, productupdate.MigrationOperation) (productupdate.MigrationAssessment, error) {
	return productupdate.MigrationAssessment{}, productupdate.ErrIntegrity
}

func (productUpdateCatalogEffects) OnlineBackup(context.Context, productupdate.BackupOperation) (productupdate.EffectReceipt, error) {
	return productupdate.EffectReceipt{}, productupdate.ErrIntegrity
}

func (productUpdateCatalogEffects) ApplyMigration(context.Context, productupdate.MigrationOperation) (productupdate.EffectReceipt, error) {
	return productupdate.EffectReceipt{}, productupdate.ErrIntegrity
}

func (productUpdateCatalogEffects) RollbackMigration(context.Context, productupdate.MigrationRollbackOperation) (productupdate.EffectReceipt, error) {
	return productupdate.EffectReceipt{}, productupdate.ErrIntegrity
}

func (productUpdateCatalogEffects) CurrentRelease(context.Context, string) (productupdate.ActiveRelease, error) {
	return productupdate.ActiveRelease{}, productupdate.ErrIntegrity
}

func (productUpdateCatalogEffects) InspectRollback(context.Context, productupdate.RollbackInspection) (productupdate.RollbackProof, error) {
	return productupdate.RollbackProof{}, productupdate.ErrIntegrity
}

func (productUpdateCatalogEffects) AtomicSwitch(context.Context, productupdate.SwitchOperation) (productupdate.EffectReceipt, error) {
	return productupdate.EffectReceipt{}, productupdate.ErrIntegrity
}

func (productUpdateCatalogEffects) CommitSwitch(context.Context, productupdate.FinalizeOperation) (productupdate.EffectReceipt, error) {
	return productupdate.EffectReceipt{}, productupdate.ErrIntegrity
}

func (productUpdateCatalogEffects) AtomicRollback(context.Context, productupdate.FinalizeOperation) (productupdate.EffectReceipt, error) {
	return productupdate.EffectReceipt{}, productupdate.ErrIntegrity
}

func (productUpdateCatalogEffects) CaptureBaseline(context.Context, string) (productupdate.HealthSnapshot, error) {
	return productupdate.HealthSnapshot{}, productupdate.ErrIntegrity
}

func (productUpdateCatalogEffects) ProbeRelease(context.Context, productupdate.ProbeOperation) (productupdate.HealthSnapshot, error) {
	return productupdate.HealthSnapshot{}, productupdate.ErrIntegrity
}

func ensureProductUpdateStagingRoot(path string) error {
	if path != productUpdateStagingRoot {
		return productupdate.ErrInvalid
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(path, 0700); err != nil { return err }
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return productupdate.ErrIntegrity
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(metadata.Uid) != os.Geteuid() {
		return productupdate.ErrIntegrity
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return productupdate.ErrIntegrity
	}
	return nil
}

func requireRootOwnedProductUpdateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return productupdate.ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return productupdate.ErrIntegrity
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return productupdate.ErrIntegrity
	}
	return nil
}

func openRootOwnedProductUpdateFile(path string) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, productupdate.ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	metadata, ok := before.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || metadata.Nlink != 1 || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0022 != 0 {
		return nil, nil, productupdate.ErrIntegrity
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, productupdate.ErrIntegrity
	}
	return file, opened, nil
}

func readRootOwnedProductUpdateFile(path string, maximum int64) ([]byte, error) {
	if maximum <= 0 {
		return nil, productupdate.ErrInvalid
	}
	file, info, err := openRootOwnedProductUpdateFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info.Size() <= 0 || info.Size() > maximum {
		return nil, productupdate.ErrIntegrity
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != info.Size() || int64(len(raw)) > maximum {
		wipeProductUpdateBytes(raw)
		return nil, productupdate.ErrIntegrity
	}
	return raw, nil
}

func decodeProductUpdateJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return productupdate.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return productupdate.ErrInvalid
	}
	return nil
}

func validProductUpdateDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func wipeProductUpdateBytes(value []byte) {
	for index := range value { value[index] = 0 }
}

var _ productUpdateReleaseSource = (*localProtectedProductUpdateSource)(nil)
var _ productupdate.InventorySource = (*localProtectedProductUpdateSource)(nil)
var _ productUpdateAuthorizationSource = (*signedProductUpdateAuthority)(nil)
var _ productupdate.AuthorizationVerifier = (*signedProductUpdateAuthority)(nil)
var _ productupdate.MaintenanceGate = productUpdateCatalogEffects{}
var _ productupdate.AuditSink = productUpdateAuditSink{}
var _ productupdate.MigrationExecutor = productUpdateCatalogEffects{}
var _ productupdate.PlatformExecutor = productUpdateCatalogEffects{}
var _ productupdate.HealthProber = productUpdateCatalogEffects{}
var _ productupdate.MaintenanceGate = (*productUpdateApplyAdapters)(nil)
var _ productupdate.MigrationExecutor = (*productUpdateApplyAdapters)(nil)
var _ productupdate.PlatformExecutor = (*productUpdateApplyAdapters)(nil)
var _ productupdate.HealthProber = (*productUpdateApplyAdapters)(nil)
