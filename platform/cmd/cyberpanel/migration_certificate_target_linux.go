//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// The normal site catalog must bind (and observe) this owned TLS material.
// A certificate directory alone is not evidence of a serving listener.
type migrationCertificateBinding interface {
	Activate(context.Context, migration.ImportIntent, string, string, uint64, []string) (string, error)
	Observe(context.Context, migration.ImportIntent, string, string, uint64, []string) (string, error)
}

type migrationCertificateTarget struct {
	db *sql.DB
	chunks *migration.ChunkStore
	scopes *migration.RuntimeScopeStore
	materials *certificates.MaterialService
	runtime *certificates.SecretMaterialRuntime
	deployment *certificates.DeploymentCoordinator
	secrets *migrationSecretTarget
	binding migrationCertificateBinding
	mu sync.Mutex
}

const migrationCertificateSchema = `CREATE TABLE IF NOT EXISTS panel_migration_certificate_targets (
 migration_id TEXT NOT NULL, target_id TEXT NOT NULL, effect_id TEXT NOT NULL UNIQUE,
 intent_digest TEXT NOT NULL, tenant_id TEXT NOT NULL, resource_id TEXT NOT NULL,
 fingerprint TEXT NOT NULL, material_id TEXT NOT NULL, state TEXT NOT NULL,
 binding_evidence TEXT NOT NULL, PRIMARY KEY(migration_id,target_id)
);`

func newMigrationCertificateTarget(ctx context.Context, db *sql.DB, chunks *migration.ChunkStore, scopes *migration.RuntimeScopeStore, materials *certificates.MaterialService, runtime *certificates.SecretMaterialRuntime, deployment *certificates.DeploymentCoordinator, secretTarget *migrationSecretTarget, binding migrationCertificateBinding) (*migrationCertificateTarget, error) {
	if ctx == nil || db == nil || chunks == nil || scopes == nil || materials == nil || materials.Repository.DB == nil || materials.Audit == nil || runtime == nil || deployment == nil || deployment.Target == nil || secretTarget == nil { return nil, migration.ErrBlocked }
	if _, err := db.ExecContext(ctx, migrationCertificateSchema); err != nil { return nil, err }
	return &migrationCertificateTarget{db: db, chunks: chunks, scopes: scopes, materials: materials, runtime: runtime, deployment: deployment, secrets: secretTarget, binding: binding}, nil
}

func migrationCertificateResource(mid, target migration.ID) string {
	sum := sha256.Sum256([]byte("migration-certificate-v1\x00"+mid.String()+"\x00"+target.String()))
	return "migcert_"+hex.EncodeToString(sum[:])[:48]
}

func (target *migrationSecretTarget) resourceAudience(ctx context.Context, manifest migration.Manifest, plan migration.Plan, scope migration.RuntimeScope, envelope migration.SecretEnvelope) (secrets.ID, secrets.Purpose, secrets.AudienceBinding, error) {
	if envelope.Purpose != "tls-private-key" { return target.databaseAudience(ctx, manifest, plan, scope, envelope) }
	var resource string
	for _, value := range manifest.Certificates {
		if value.PrivateKeySecretID != envelope.SecretID { continue }
		if resource != "" { return "", "", secrets.AudienceBinding{}, migration.ErrBlocked }
		mapped, err := migrationCertificateMapping(manifest, plan, value)
		if err != nil { return "", "", secrets.AudienceBinding{}, err }
		resource = migrationCertificateResource(manifest.MigrationID, mapped)
	}
	if resource == "" { return "", "", secrets.AudienceBinding{}, migration.ErrBlocked }
	release, err := certificates.CurrentExecutableDigest()
	if err != nil { return "", "", secrets.AudienceBinding{}, err }
	owner, audience, err := certificates.MigrationPrivateKeyAudience(scope.TenantID, resource, release)
	return owner, secrets.PurposeTLSKey, audience, err
}

// This slice supports one exact DNS name belonging to one newly-created site.
// Wildcards, shared/multi-name certs, panel/mail certs and account reuse are not
// inferred from names or a legacy certificate directory.
func migrationCertificateMapping(manifest migration.Manifest, plan migration.Plan, value migration.Certificate) (migration.ID, error) {
	if len(value.Names) != 1 || value.Names[0] != strings.ToLower(value.Names[0]) || strings.Contains(value.Names[0], "*") || value.PrivateKeySecretID == "" { return "", migration.ErrBlocked }
	var siteID, targetID migration.ID
	for _, site := range manifest.Sites {
		if site.PrimaryHostname != value.Names[0] { continue }
		if siteID != "" || len(site.Aliases) != 0 || len(site.Redirects) != 0 || len(site.Children) != 0 { return "", migration.ErrBlocked }
		siteID = site.SourceID
	}
	if siteID == "" { return "", migration.ErrBlocked }
	siteMapped := false
	for _, item := range plan.Mappings {
		if item.SourceKind == string(migration.ImportSite) && item.SourceID == siteID {
			if siteMapped || item.Disposition != migration.DispositionCreate || !item.TargetID.Valid() { return "", migration.ErrBlocked }; siteMapped = true
		}
		if item.SourceKind == string(migration.ImportCertificate) && item.SourceID == value.SourceID {
			if targetID != "" || item.Disposition != migration.DispositionCreate || !item.TargetID.Valid() { return "", migration.ErrBlocked }; targetID = item.TargetID
		}
	}
	if !siteMapped || targetID == "" { return "", migration.ErrBlocked }
	return targetID, nil
}

type migrationCertificateAdmission struct {
	value migration.Certificate
	scope migration.RuntimeScope
	resource, fingerprint, materialID, intentDigest string
	chain []byte
}

func (target *migrationCertificateTarget) admit(ctx context.Context, intent migration.ImportIntent, cleanup bool) (migrationCertificateAdmission, error) {
	var admission migrationCertificateAdmission
	if !intent.MigrationID.Valid() || !intent.TargetID.Valid() || intent.Kind != migration.ImportCertificate || intent.Disposition != migration.DispositionCreate || !intent.Dark || len(intent.InputDigest) != 64 || len(intent.EffectID) < 8 { return admission, migration.ErrBlocked }
	if len(intent.Payload) > 1<<20 || json.Unmarshal(intent.Payload, &admission.value) != nil || admission.value.SourceID != intent.SourceID || len(intent.SecretIDs) != 1 || intent.SecretIDs[0] != admission.value.PrivateKeySecretID { return admission, migration.ErrInvalid }
	current, err := target.secrets.repository.Migration(ctx, intent.MigrationID)
	if err != nil { return admission, err }
	manifest, err := target.secrets.repository.Manifest(ctx, current.ManifestRoot)
	if err != nil { return admission, err }
	var envelope migration.SecretEnvelope
	for _, candidate := range manifest.Secrets { if candidate.SecretID == admission.value.PrivateKeySecretID { envelope = candidate } }
	verified := manifest
	var scope migration.RuntimeScope
	if cleanup {
		// Rollback/cancel may have already closed secret enrollment. Cleanup
		// still verifies the signed manifest, scope, plan and creation journal;
		// it never needs to reopen or decrypt a revoked secret.
		verifier, verifierErr := migrationTargetSecretVerifier()
		if verifierErr != nil { return admission, verifierErr }
		if err = verifier.Verify(ctx, manifest); err != nil { return admission, err }
		scope, err = target.scopes.LoadByMigration(ctx, intent.MigrationID)
	} else {
		verified, scope, _, err = target.secrets.approved(ctx, intent.MigrationID, envelope)
	}
	if err != nil || scope.MigrationID != intent.MigrationID || verified.MigrationID != intent.MigrationID { return admission, errors.Join(migration.ErrBlocked, err) }; admission.scope = scope
	plan, err := target.secrets.repository.Plan(ctx, current.PlanDigest)
	if err != nil || plan.MigrationID != intent.MigrationID || plan.ApprovedAt == nil { return admission, errors.Join(migration.ErrBlocked, err) }
	found := false
	for _, value := range verified.Certificates {
		if value.SourceID != intent.SourceID { continue }
		expected, _ := json.Marshal(value); actual, _ := json.Marshal(admission.value)
		mapped, mappingErr := migrationCertificateMapping(verified, plan, value)
		if found || !bytes.Equal(expected, actual) || mappingErr != nil || mapped != intent.TargetID { return admission, migration.ErrBlocked }; found = true
	}
	if !found || current.SourceGeneration != intent.SourceGeneration { return admission, migration.ErrConflict }
	allChunks := append(append([]migration.Chunk(nil), admission.value.Certificate...), admission.value.Chain...)
	expected, _ := json.Marshal(allChunks); actual, _ := json.Marshal(intent.Chunks)
	if !bytes.Equal(expected, actual) || len(allChunks) == 0 || len(allChunks) > 64 { return admission, migration.ErrInvalid }
	for _, chunk := range allChunks {
		if chunk.Compression != "" && chunk.Compression != "none" || chunk.Size == 0 || chunk.Size > 1<<20 || len(admission.chain)+int(chunk.Size) > 1<<20 || chunk.MediaType != "application/pem-certificate-chain" || chunk.EncryptionDomain != "certificate-public" { return admission, migration.ErrBlocked }
		content, err := target.chunks.ReadRange(ctx, chunk.Digest, 0, chunk.Size)
		if err != nil { return admission, err }; sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != chunk.Digest { return admission, migration.ErrConflict }
		admission.chain = append(admission.chain, content...)
	}
	block, _ := pem.Decode(admission.chain)
	if block == nil || block.Type != "CERTIFICATE" { return admission, migration.ErrInvalid }
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !leaf.NotAfter.Equal(admission.value.NotAfter) || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != admission.value.Names[0] { return admission, migration.ErrBlocked }
	sum := sha256.Sum256(leaf.Raw); admission.fingerprint = hex.EncodeToString(sum[:])
	admission.resource = migrationCertificateResource(intent.MigrationID, intent.TargetID)
	admission.materialID, err = certificates.NewManagedMaterialID(scope.TenantID, admission.resource, admission.fingerprint)
	if err != nil { return admission, err }
	admission.intentDigest, _, err = migrationSecretDigest(intent)
	return admission, err
}

type migrationCertificateAuthorizer struct { tenant, resource, subject string }
func (authority migrationCertificateAuthorizer) AuthorizeMaterial(_ context.Context, principal certificates.MaterialPrincipal, action certificates.MaterialAction, scope certificates.MaterialScope) error {
	if principal.TenantID != authority.tenant || principal.SubjectID != authority.subject || scope.TenantID != authority.tenant || scope.ResourceID != authority.resource || action != certificates.MaterialActionImport { return certificates.ErrMaterialUnauthorized }
	return nil
}

func (target *migrationCertificateTarget) Apply(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	target.mu.Lock(); defer target.mu.Unlock()
	admission, err := target.admit(ctx, intent, false)
	if err != nil { return migration.ImportEffect{}, err }
	// Recording an activation owner is mandatory even for dark import. Factory
	// leaves this kind blocked until the normal site binding adapter is installed.
	if target.binding == nil { return migration.ImportEffect{}, migration.ErrBlocked }
	state, err := target.state(ctx, intent, admission)
	if errors.Is(err, sql.ErrNoRows) {
		if _, existingErr := target.materials.Repository.Get(ctx, admission.scope.TenantID, admission.resource, admission.materialID); !errors.Is(existingErr, certificates.ErrMaterialNotFound) { return migration.ImportEffect{}, migration.ErrConflict }
		_, err = target.db.ExecContext(ctx, `INSERT INTO panel_migration_certificate_targets VALUES(?,?,?,?,?,?,?,?,'pending','')`, intent.MigrationID.String(), intent.TargetID.String(), intent.EffectID, admission.intentDigest, admission.scope.TenantID, admission.resource, admission.fingerprint, admission.materialID)
		state = "pending"
	}
	if err != nil { return migration.ImportEffect{}, err }
	if state == "canceled" || state == "canceling" { return migration.ImportEffect{}, migration.ErrBlocked }
	if state == "pending" {
		metadata, err := target.secrets.Resolve(ctx, intent.MigrationID, admission.value.PrivateKeySecretID)
		if err != nil { return migration.ImportEffect{}, err }
		material, err := target.runtime.OpenMigrationMaterial(metadata, admission.scope.TenantID, admission.resource, admission.chain)
		if err != nil { return migration.ImportEffect{}, err }
		service := *target.materials
		subject := "migration-"+intent.MigrationID.String()
		service.Authorizer = migrationCertificateAuthorizer{admission.scope.TenantID, admission.resource, subject}
		inspection, err := service.Import(ctx, certificates.MaterialPrincipal{TenantID: admission.scope.TenantID, SubjectID: subject}, certificates.ImportMaterialRequest{
			TenantID: admission.scope.TenantID, ResourceID: admission.resource, DisplayLabel: "Migration "+intent.MigrationID.String(), DNSNames: admission.value.Names,
			ExpectedCertificateGeneration: 0, IdempotencyKey: intent.EffectID, Material: material})
		if err != nil { return migration.ImportEffect{}, err }
		if inspection.ID != admission.materialID { return migration.ImportEffect{}, migration.ErrConflict }
		generation, err := target.ownedMaterial(ctx, intent, admission)
		if err != nil { return migration.ImportEffect{}, err }
		if len(generation.Consumers) == 0 {
			_, err = target.materials.Repository.UpdateOperationalCAS(ctx, admission.scope.TenantID, admission.resource, admission.materialID, certificates.MaterialOperationalUpdate{
				ExpectedRecordGeneration: generation.RecordGeneration, State: certificates.MaterialStateStaged,
				Consumers: []certificates.MaterialConsumerBinding{{ConsumerID: admission.resource, ConsumerKind: "migration_webengine", ConsumerGeneration: 1, Bound: true, DeploymentReasonCode: "awaiting_source_fence"}}, ObservedAt: time.Now().UTC()})
			if err != nil { return migration.ImportEffect{}, err }
		}
		if _, err := target.db.ExecContext(ctx, `UPDATE panel_migration_certificate_targets SET state='staged' WHERE migration_id=? AND target_id=? AND state='pending'`, intent.MigrationID.String(), intent.TargetID.String()); err != nil { return migration.ImportEffect{}, err }
	}
	return target.observe(ctx, intent, admission)
}

func (target *migrationCertificateTarget) state(ctx context.Context, intent migration.ImportIntent, admission migrationCertificateAdmission) (string, error) {
	var effect, digest, tenant, resource, fingerprint, material, state string
	err := target.db.QueryRowContext(ctx, `SELECT effect_id,intent_digest,tenant_id,resource_id,fingerprint,material_id,state FROM panel_migration_certificate_targets WHERE migration_id=? AND target_id=?`, intent.MigrationID.String(), intent.TargetID.String()).Scan(&effect,&digest,&tenant,&resource,&fingerprint,&material,&state)
	if err != nil { return "", err }
	if effect != intent.EffectID || digest != admission.intentDigest || tenant != admission.scope.TenantID || resource != admission.resource || fingerprint != admission.fingerprint || material != admission.materialID { return "", migration.ErrConflict }
	return state, nil
}

func (target *migrationCertificateTarget) ownedMaterial(ctx context.Context, intent migration.ImportIntent, admission migrationCertificateAdmission) (certificates.ManagedCertificateGeneration, error) {
	var recorded string
	err := target.materials.Repository.DB.QueryRowContext(ctx, `SELECT material_id FROM managed_certificate_material_idempotency_v1 WHERE tenant_id=? AND resource_id=? AND operation='import' AND idempotency_key=?`, admission.scope.TenantID, admission.resource, intent.EffectID).Scan(&recorded)
	if err != nil || recorded != admission.materialID { return certificates.ManagedCertificateGeneration{}, errors.Join(migration.ErrConflict, err) }
	generation, err := target.materials.Repository.Get(ctx, admission.scope.TenantID, admission.resource, admission.materialID)
	if err != nil || generation.LeafFingerprintSHA256 != admission.fingerprint || generation.CertificateGeneration != 1 || generation.Source != certificates.MaterialSourceImport { return generation, errors.Join(migration.ErrConflict, err) }
	return generation, nil
}

func (target *migrationCertificateTarget) Observe(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	target.mu.Lock(); defer target.mu.Unlock()
	admission, err := target.admit(ctx, intent, false); if err != nil { return migration.ImportEffect{}, err }
	return target.observe(ctx, intent, admission)
}

func (target *migrationCertificateTarget) observe(ctx context.Context, intent migration.ImportIntent, admission migrationCertificateAdmission) (migration.ImportEffect, error) {
	state, err := target.state(ctx, intent, admission); if err != nil { return migration.ImportEffect{}, err }
	if state != "staged" && state != "active" { return migration.ImportEffect{}, migration.ErrBlocked }
	generation, err := target.ownedMaterial(ctx, intent, admission)
	if err != nil || generation.State == certificates.MaterialStateRetired || len(generation.Consumers) != 1 || generation.Consumers[0].ConsumerID != admission.resource || !generation.Consumers[0].Bound { return migration.ImportEffect{}, errors.Join(migration.ErrConflict, err) }
	evidence := generation.RecordDigest
	if state == "active" {
		if target.binding == nil { return migration.ImportEffect{}, migration.ErrBlocked }
		binding, err := target.binding.Observe(ctx, intent, admission.scope.TenantID, admission.resource, 1, admission.value.Names)
		if err != nil || len(binding) != 64 { return migration.ImportEffect{}, errors.Join(migration.ErrBlocked, err) }
		if err := migrationCertificateSNI(ctx, admission.value.Names[0], admission.fingerprint); err != nil { return migration.ImportEffect{}, err }
		evidence, _, err = migrationSecretDigest([]string{generation.RecordDigest, binding, admission.fingerprint})
		if err != nil { return migration.ImportEffect{}, err }
	}
	return migration.ImportEffect{EffectID: intent.EffectID, InputDigest: intent.InputDigest, OutputDigest: generation.IdentityDigest,
		Status: migration.ImportEffectApplied, TargetGeneration: generation.CertificateGeneration, BytesWritten: uint64(len(admission.chain)), ObjectsWritten: 1, EvidenceDigest: evidence, AppliedAt: time.Now().UTC()}, nil
}

func (target *migrationCertificateTarget) fence(ctx context.Context, intent migration.ImportIntent) error {
	value, err := target.secrets.repository.Migration(ctx, intent.MigrationID)
	if err != nil { return err }
	if (value.Phase != migration.PhaseFinalSync && value.Phase != migration.PhaseCutoverCommitting) || value.SourceGeneration != intent.SourceGeneration || value.Fence != intent.Fence || intent.Fence == 0 { return migration.ErrBlocked }
	var fence migration.SourceFence
	if err := target.secrets.repository.Receipt(ctx, intent.MigrationID, "source_fence", &fence); err != nil { return err }
	if fence.MigrationID != intent.MigrationID || fence.Generation != intent.SourceGeneration || fence.Fence != intent.Fence || len(fence.Digest) != 64 || !fence.ExpiresAt.After(time.Now().UTC()) { return migration.ErrBlocked }
	return nil
}

func (target *migrationCertificateTarget) Activate(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	target.mu.Lock(); defer target.mu.Unlock()
	if target.binding == nil { return migration.ImportEffect{}, migration.ErrBlocked }
	admission, err := target.admit(ctx, intent, false); if err != nil { return migration.ImportEffect{}, err }
	if err := target.fence(ctx, intent); err != nil { return migration.ImportEffect{}, err }
	state, err := target.state(ctx, intent, admission)
	if err != nil || state != "staged" && state != "activating" && state != "active" { return migration.ImportEffect{}, errors.Join(migration.ErrBlocked, err) }
	if state == "active" { return target.observe(ctx, intent, admission) }
	generation, err := target.ownedMaterial(ctx, intent, admission); if err != nil { return migration.ImportEffect{}, err }
	material, err := certificates.MigrationDeploymentMaterial(generation); if err != nil { return migration.ImportEffect{}, err }
	consumer := "webengine/"+admission.resource
	previous, candidate, err := target.deployment.Target.StageCertificate(ctx, consumer, material, intent.EffectID)
	if err != nil { return migration.ImportEffect{}, err }
	if state == "staged" && previous != "" { return migration.ImportEffect{}, migration.ErrConflict }
	if state == "activating" && previous != "" && previous != candidate { return migration.ImportEffect{}, migration.ErrConflict }
	if _, err := target.db.ExecContext(ctx, `UPDATE panel_migration_certificate_targets SET state='activating' WHERE migration_id=? AND target_id=? AND state='staged'`, intent.MigrationID.String(), intent.TargetID.String()); err != nil { return migration.ImportEffect{}, err }
	if err := target.fence(ctx, intent); err != nil { return migration.ImportEffect{}, err }
	activation, err := target.deployment.Target.ActivateCertificate(ctx, consumer, candidate, intent.EffectID)
	if err != nil { return migration.ImportEffect{}, err }
	if err := target.fence(ctx, intent); err != nil { return migration.ImportEffect{}, err }
	binding, err := target.binding.Activate(ctx, intent, admission.scope.TenantID, admission.resource, 1, admission.value.Names)
	if err != nil || len(binding) != 64 { return migration.ImportEffect{}, errors.Join(migration.ErrBlocked, err) }
	if err := migrationCertificateSNI(ctx, admission.value.Names[0], admission.fingerprint); err != nil { return migration.ImportEffect{}, err }
	observed, err := target.deployment.Target.ProbeCertificate(ctx, consumer, material)
	if err != nil || observed != admission.fingerprint { return migration.ImportEffect{}, errors.Join(migration.ErrBlocked, err) }
	prior, err := target.deployment.Store.CurrentDeployment(ctx, consumer)
	if errors.Is(err, sql.ErrNoRows) {
		err = target.deployment.Store.Deploy(ctx, certificates.Deployment{ID: certificates.DeploymentID("deploy_"+admission.resource), Consumer: consumer, Generation: material.ID, ImmutablePath: activation, DeployedAt: time.Now().UTC()})
	} else if err == nil && (prior.Generation != material.ID || prior.ImmutablePath != activation) { err = migration.ErrConflict }
	if err != nil { return migration.ImportEffect{}, err }
	_, err = target.materials.Repository.UpdateOperationalCAS(ctx, admission.scope.TenantID, admission.resource, admission.materialID, certificates.MaterialOperationalUpdate{
		ExpectedRecordGeneration: generation.RecordGeneration, State: certificates.MaterialStateActive,
		Consumers: []certificates.MaterialConsumerBinding{{ConsumerID: admission.resource, ConsumerKind: "migration_webengine", ConsumerGeneration: 1, Bound: true, DeployedFingerprint: admission.fingerprint, DeploymentGeneration: 1, DeploymentObservedAt: time.Now().UTC()}}, ObservedAt: time.Now().UTC()})
	if err != nil { return migration.ImportEffect{}, err }
	if _, err := target.db.ExecContext(ctx, `UPDATE panel_migration_certificate_targets SET state='active',binding_evidence=? WHERE migration_id=? AND target_id=? AND state='activating'`, binding, intent.MigrationID.String(), intent.TargetID.String()); err != nil { return migration.ImportEffect{}, err }
	return target.observe(ctx, intent, admission)
}

func migrationCertificateSNI(ctx context.Context, hostname, fingerprint string) error {
	// Address is fixed loopback; the approved hostname controls only SNI and
	// X.509 hostname verification. No manifest-selected network destination.
	probe, cancel := context.WithTimeout(ctx, 10*time.Second); defer cancel()
	connection, err := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname}}).DialContext(probe, "tcp", "127.0.0.1:443")
	if err != nil { return err }; defer connection.Close()
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok || len(tlsConnection.ConnectionState().PeerCertificates) == 0 { return migration.ErrBlocked }
	sum := sha256.Sum256(tlsConnection.ConnectionState().PeerCertificates[0].Raw)
	if hex.EncodeToString(sum[:]) != fingerprint { return migration.ErrConflict }
	return nil
}

func (target *migrationCertificateTarget) Compensate(ctx context.Context, intent migration.ImportIntent, effect migration.ImportEffect) (migration.ImportEffect, error) {
	target.mu.Lock(); defer target.mu.Unlock()
	admission, err := target.admit(ctx, intent, true); if err != nil { return migration.ImportEffect{}, err }
	if effect.EffectID != intent.EffectID || effect.InputDigest != intent.InputDigest { return migration.ImportEffect{}, migration.ErrConflict }
	state, err := target.state(ctx, intent, admission); if err != nil { return migration.ImportEffect{}, err }
	// Never delete or retire a resource once listener activation may have run.
	// Active/ambiguous activation requires the normal site rollback authority.
	if state != "staged" && state != "canceling" && state != "canceled" { return migration.ImportEffect{}, migration.ErrBlocked }
	generation, err := target.ownedMaterial(ctx, intent, admission); if err != nil { return migration.ImportEffect{}, err }
	if state != "canceled" {
		if _, err := target.db.ExecContext(ctx, `UPDATE panel_migration_certificate_targets SET state='canceling' WHERE migration_id=? AND target_id=? AND state='staged'`, intent.MigrationID.String(), intent.TargetID.String()); err != nil { return migration.ImportEffect{}, err }
		if generation.State != certificates.MaterialStateRetired {
			if len(generation.Consumers) != 0 {
				generation, err = target.materials.Repository.UpdateOperationalCAS(ctx, admission.scope.TenantID, admission.resource, admission.materialID, certificates.MaterialOperationalUpdate{ExpectedRecordGeneration: generation.RecordGeneration, State: certificates.MaterialStateStaged, ObservedAt: time.Now().UTC()})
				if err != nil { return migration.ImportEffect{}, err }
			}
			_, _, err = target.materials.Repository.RetireCAS(ctx, admission.scope.TenantID, admission.resource, admission.materialID, intent.EffectID+"_cancel", admission.intentDigest, generation.RecordGeneration, time.Now().UTC())
			if err != nil { return migration.ImportEffect{}, err }
		}
		if _, err := target.db.ExecContext(ctx, `UPDATE panel_migration_certificate_targets SET state='canceled' WHERE migration_id=? AND target_id=? AND state='canceling'`, intent.MigrationID.String(), intent.TargetID.String()); err != nil { return migration.ImportEffect{}, err }
	}
	effect.Status = migration.ImportEffectCompensated; effect.AppliedAt = time.Now().UTC()
	return effect, nil
}

var _ migration.CanonicalImportHandler = (*migrationCertificateTarget)(nil)
