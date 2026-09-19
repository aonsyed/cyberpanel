//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

type migrationMailTarget struct {
	host        *migrationHostTarget
	chunks      *migration.ChunkStore
	coordinator mail.MigrationCoordinator
	runtime     *mail.MailDaemonClient
	secrets     *migrationSecretTarget
}

type migrationMailAdmission struct {
	source     migration.MailDomain
	scope      migration.RuntimeScope
	bundle     mail.MigrationBundle
	generation mail.ConfigGeneration
	staging    []migrationMailboxTransfer
	bytes      uint64
	objects    uint64
}

func newMigrationMailTarget(ctx context.Context, host *migrationHostTarget, chunks *migration.ChunkStore, control mail.SQLControlRepository, projector mail.RepositorySnapshotProjector, runtime *mail.MailDaemonClient, secretTarget *migrationSecretTarget) (*migrationMailTarget, error) {
	if ctx == nil || host == nil || chunks == nil || control.DB == nil || projector.Store == nil || runtime == nil || secretTarget == nil {
		return nil, migration.ErrBlocked
	}
	if err := control.Bootstrap(ctx); err != nil {
		return nil, err
	}
	return &migrationMailTarget{host: host, chunks: chunks, coordinator: mail.MigrationCoordinator{DB: control.DB, Projector: projector}, runtime: runtime, secrets: secretTarget}, nil
}

func migrationMailID(prefix string, values ...string) string {
	hash := sha256.New()
	hash.Write([]byte("cyberpanel-migration-mail-v1\x00" + prefix))
	for _, value := range values {
		hash.Write([]byte{0})
		hash.Write([]byte(value))
	}
	return prefix + "_" + hex.EncodeToString(hash.Sum(nil))[:48]
}

func migrationMailboxID(migrationID migration.ID, domain migration.ID, mailbox migration.ID) mail.MailboxID {
	return mail.MailboxID(migrationMailID("migmbx", migrationID.String(), domain.String(), mailbox.String()))
}
func migrationMailPolicyID(migrationID migration.ID, domain migration.ID) mail.PolicyID {
	return mail.PolicyID(migrationMailID("migpol", migrationID.String(), domain.String()))
}
func migrationAliasID(migrationID migration.ID, domain migration.ID, value string) mail.AliasID {
	return mail.AliasID(migrationMailID("migalias", migrationID.String(), domain.String(), value))
}
func migrationMailImportID(intent migration.ImportIntent) string {
	return migrationMailID("migmail", intent.MigrationID.String(), intent.TargetID.String(), intent.EffectID)
}

func migrationMailMapping(manifest migration.Manifest, plan migration.Plan, value migration.MailDomain) (migration.ID, migration.ID, error) {
	var domainTarget, siteTarget migration.ID
	for _, mapping := range plan.Mappings {
		if mapping.SourceKind == string(migration.ImportMailDomain) && mapping.SourceID == value.SourceID {
			if domainTarget != "" || mapping.Disposition != migration.DispositionCreate || !mapping.TargetID.Valid() {
				return "", "", migration.ErrBlocked
			}
			domainTarget = mapping.TargetID
		}
		if mapping.SourceKind == string(migration.ImportSite) && mapping.SourceID == value.SiteID {
			if siteTarget != "" || mapping.Disposition != migration.DispositionCreate || !mapping.TargetID.Valid() {
				return "", "", migration.ErrBlocked
			}
			siteTarget = mapping.TargetID
		}
	}
	if domainTarget == "" || siteTarget == "" || manifest.MigrationID != plan.MigrationID {
		return "", "", migration.ErrBlocked
	}
	return domainTarget, siteTarget, nil
}

func (target *migrationSecretTarget) mailAudience(ctx context.Context, manifest migration.Manifest, plan migration.Plan, scope migration.RuntimeScope, envelope migration.SecretEnvelope) (secrets.ID, secrets.Purpose, secrets.AudienceBinding, error) {
	if err := ctx.Err(); err != nil {
		return "", "", secrets.AudienceBinding{}, err
	}
	release, err := webEngineExecutableDigest("/usr/local/libexec/cyberpanel/panel-execd")
	if err != nil {
		return "", "", secrets.AudienceBinding{}, err
	}
	var owner secrets.ID
	var audience secrets.AudienceBinding
	matched := false
	for _, domain := range manifest.MailDomains {
		domainTarget, _, mappingErr := migrationMailMapping(manifest, plan, domain)
		if mappingErr != nil {
			continue
		}
		if envelope.Purpose == "mail-dkim-private-key" && domain.DKIMSecretID == envelope.SecretID {
			if matched {
				return "", "", secrets.AudienceBinding{}, migration.ErrConflict
			}
			owner, audience, err = mail.DKIMCredentialAudience(scope.TenantID, domain.Name, "default", release)
			matched = err == nil
		}
		for _, mailbox := range domain.Mailboxes {
			if envelope.Purpose == "mailbox-credential" && mailbox.CredentialSecretID == envelope.SecretID {
				if matched || mailbox.CredentialDisposition != migration.CredentialPreserved {
					return "", "", secrets.AudienceBinding{}, migration.ErrConflict
				}
				owner, audience, err = mail.MailboxCredentialAudience(scope.TenantID, mail.DomainID(domainTarget.String()), migrationMailboxID(manifest.MigrationID, domainTarget, mailbox.SourceID), release)
				matched = err == nil
			}
		}
	}
	if err != nil || !matched {
		return "", "", secrets.AudienceBinding{}, errors.Join(migration.ErrBlocked, err)
	}
	if envelope.Purpose == "mail-dkim-private-key" {
		return owner, secrets.PurposeDKIMKey, audience, nil
	}
	return owner, secrets.PurposeAuthentication, audience, nil
}

func (target *migrationSecretTarget) migrationDKIMPublicBinding(ctx context.Context, id migration.ID, envelopeID string) (string, error) {
	target.mu.Lock()
	defer target.mu.Unlock()
	row, err := target.load(ctx, id, envelopeID)
	if err != nil || row.state != "enrolled" {
		return "", errors.Join(migration.ErrBlocked, err)
	}
	var envelope migration.SecretEnvelope
	if json.Unmarshal(row.envelope, &envelope) != nil || envelope.SecretID != envelopeID || envelope.Purpose != "mail-dkim-private-key" {
		return "", migration.ErrConflict
	}
	if _, _, _, err = target.approved(ctx, id, envelope); err != nil {
		return "", err
	}
	plaintext, err := target.decrypt(ctx, id, row.targetInstallation, envelope)
	if err != nil {
		return "", err
	}
	defer wipeBytes(plaintext)
	return mail.DKIMPublicBindingFromPrivateKey(plaintext)
}

func (target *migrationMailTarget) admit(ctx context.Context, intent migration.ImportIntent) (migrationMailAdmission, error) {
	var admission migrationMailAdmission
	if migration.ValidateCanonicalImportIntent(intent) != nil || intent.Kind != migration.ImportMailDomain || intent.Disposition != migration.DispositionCreate || !intent.Dark {
		return admission, migration.ErrBlocked
	}
	if len(intent.Payload) == 0 || len(intent.Payload) > 2<<20 || json.Unmarshal(intent.Payload, &admission.source) != nil || admission.source.SourceID != intent.SourceID || admission.source.TargetID != "" && admission.source.TargetID != intent.TargetID || len(admission.source.MailData) != 0 {
		return admission, migration.ErrInvalid
	}
	current, err := target.host.repository.Migration(ctx, intent.MigrationID)
	if err != nil {
		return admission, err
	}
	manifest, err := target.host.repository.Manifest(ctx, current.ManifestRoot)
	if err != nil {
		return admission, err
	}
	verifier, err := migrationTargetSecretVerifier()
	if err != nil {
		return admission, err
	}
	if err = verifier.Verify(ctx, manifest); err != nil {
		return admission, err
	}
	plan, err := target.host.repository.Plan(ctx, current.PlanDigest)
	if err != nil || plan.ApprovedAt == nil || plan.ApprovalDigest == "" {
		return admission, errors.Join(migration.ErrBlocked, err)
	}
	domainTarget, siteTarget, err := migrationMailMapping(manifest, plan, admission.source)
	if err != nil || domainTarget != intent.TargetID {
		return admission, errors.Join(migration.ErrBlocked, err)
	}
	matched := false
	for _, value := range manifest.MailDomains {
		if value.SourceID == intent.SourceID {
			left, _ := json.Marshal(value)
			right, _ := json.Marshal(admission.source)
			if matched || !bytes.Equal(left, right) {
				return admission, migration.ErrConflict
			}
			matched = true
		}
	}
	if !matched || manifest.SourceGeneration != intent.SourceGeneration || current.SourceGeneration < intent.SourceGeneration || current.Fence < intent.Fence {
		return admission, migration.ErrConflict
	}
	admission.scope, err = target.host.scopes.LoadByMigration(ctx, intent.MigrationID)
	if err != nil {
		return admission, err
	}
	domainID := mail.DomainID(intent.TargetID.String())
	policyID := migrationMailPolicyID(intent.MigrationID, intent.TargetID)
	projection := mail.DomainProjection{Domain: mail.Domain{ID: domainID, Name: strings.ToLower(admission.source.Name), Tenant: admission.scope.TenantID, Policy: policyID, StaticRoutes: true}, Policy: mail.Policy{ID: policyID, MaxMailboxBytes: 1 << 50, MaxRecipients: 1000, SpamThreshold: 6, RetainDays: 30, Log: mail.LogPolicy{RetainDays: 30, RedactBodies: true, AuditDeliveries: true}}, TLS: mail.TLSMaterial{Key: "mail-" + string(domainID), Hostnames: []string{strings.ToLower(admission.source.Name), "mail." + strings.ToLower(admission.source.Name)}}}
	if admission.source.DKIMSecretID != "" {
		metadata, resolveErr := target.secrets.Resolve(ctx, intent.MigrationID, admission.source.DKIMSecretID)
		if resolveErr != nil {
			return admission, resolveErr
		}
		public, publicErr := target.secrets.migrationDKIMPublicBinding(ctx, intent.MigrationID, admission.source.DKIMSecretID)
		if publicErr != nil {
			return admission, publicErr
		}
		projection.Domain.DKIM = mail.DKIM{Selector: "default", PublicKey: public, PrivateKeyRef: string(metadata.ID), Enabled: true}
	}
	mailboxes := append([]migration.Mailbox(nil), admission.source.Mailboxes...)
	sort.Slice(mailboxes, func(i, j int) bool { return mailboxes[i].Address < mailboxes[j].Address })
	for _, source := range mailboxes {
		if source.CredentialDisposition != migration.CredentialPreserved || source.CredentialSecretID == "" || len(source.Data) > 1 {
			return admission, fmt.Errorf("%w: mailboxes require a typed preserved bcrypt credential and at most one canonical Maildir artifact", migration.ErrBlocked)
		}
		local, ok := migrationMailboxLocal(source.Address, admission.source.Name)
		if !ok {
			return admission, migration.ErrInvalid
		}
		metadata, resolveErr := target.secrets.Resolve(ctx, intent.MigrationID, source.CredentialSecretID)
		if resolveErr != nil {
			return admission, resolveErr
		}
		mailboxID := migrationMailboxID(intent.MigrationID, intent.TargetID, source.SourceID)
		credentialRef := mail.MailboxCredentialRef(string(metadata.ID))
		quota := source.QuotaBytes
		if quota == 0 {
			quota = 1 << 50
		}
		projection.Mailboxes = append(projection.Mailboxes, mail.Mailbox{ID: mailboxID, Domain: domainID, SiteID: siteTarget.String(), Local: local, QuotaBytes: quota, Enabled: true, CredentialRef: credentialRef})
		transfer, transferErr := target.mailboxTransfer(ctx, source.Data)
		if transferErr != nil {
			return admission, transferErr
		}
		if transfer.manifest.TotalBytes > quota {
			return admission, migration.ErrCapacity
		}
		request := mail.MaildirImportRequest{Operation: "observe", ImportID: migrationMailImportID(intent), TenantID: admission.scope.TenantID, SiteID: siteTarget.String(), DomainID: domainID, MailboxID: mailboxID, Domain: projection.Domain.Name, Local: local, CredentialRef: credentialRef, QuotaBytes: quota, SourceDigest: transfer.sourceDigest, ManifestRoot: transfer.manifest.RootDigest}
		if request.Validate() != nil {
			return admission, migration.ErrInvalid
		}
		transfer.request = request
		admission.staging = append(admission.staging, transfer)
		if transfer.manifest.TotalBytes > ^uint64(0)-admission.bytes || transfer.manifest.TotalFiles > ^uint64(0)-admission.objects {
			return admission, migration.ErrCapacity
		}
		admission.bytes += transfer.manifest.TotalBytes
		admission.objects += transfer.manifest.TotalFiles
	}
	aliases, err := migrationMailAliases(intent, admission.source, domainID)
	if err != nil {
		return admission, err
	}
	projection.Aliases = aliases
	bundle := mail.MigrationBundle{ID: migrationMailImportID(intent), Domain: projection}
	for _, transfer := range admission.staging {
		bundle.Maildirs = append(bundle.Maildirs, transfer.request)
	}
	admission.bundle = bundle
	admission.generation, err = target.coordinator.Prepare(ctx, bundle)
	if err != nil {
		return admission, err
	}
	return admission, nil
}

func migrationMailboxLocal(address, domain string) (string, bool) {
	address = strings.ToLower(strings.TrimSpace(address))
	suffix := "@" + strings.ToLower(domain)
	if !strings.HasSuffix(address, suffix) {
		return "", false
	}
	local := strings.TrimSuffix(address, suffix)
	if local == "" || strings.ContainsAny(local, "@/\\\x00\r\n") || strings.Contains(local, "..") {
		return "", false
	}
	return local, true
}

func migrationMailAliases(intent migration.ImportIntent, source migration.MailDomain, domainID mail.DomainID) ([]mail.Alias, error) {
	values := append(append([]string(nil), source.Aliases...), source.Forwarders...)
	if len(source.CatchAll) != 0 {
		return nil, fmt.Errorf("%w: catch-all import requires the typed routing-policy path", migration.ErrBlocked)
	}
	aliases := make([]mail.Alias, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if strings.HasPrefix(value, "prefix:") || strings.HasPrefix(value, "suffix:") || strings.HasPrefix(value, "pipe:") {
			return nil, fmt.Errorf("%w: pattern and pipe routes are not static migration aliases", migration.ErrBlocked)
		}
		parts := strings.SplitN(value, " -> ", 2)
		if len(parts) != 2 {
			return nil, migration.ErrInvalid
		}
		sourceAddress := mail.Address(strings.ToLower(strings.TrimSpace(parts[0])))
		if mail.ValidateAddress(sourceAddress) != nil || !strings.HasSuffix(string(sourceAddress), "@"+strings.ToLower(source.Name)) || seen[string(sourceAddress)] {
			return nil, migration.ErrInvalid
		}
		rawTargets := strings.Split(parts[1], ",")
		targets := make([]mail.Address, 0, len(rawTargets))
		for _, raw := range rawTargets {
			target := mail.Address(strings.ToLower(strings.TrimSpace(raw)))
			if mail.ValidateAddress(target) != nil {
				return nil, migration.ErrInvalid
			}
			targets = append(targets, target)
		}
		if len(targets) == 0 {
			return nil, migration.ErrInvalid
		}
		seen[string(sourceAddress)] = true
		aliases = append(aliases, mail.Alias{ID: migrationAliasID(intent.MigrationID, intent.TargetID, value), Domain: domainID, Source: sourceAddress, Targets: targets})
	}
	sort.Slice(aliases, func(i, j int) bool { return aliases[i].Source < aliases[j].Source })
	return aliases, nil
}

func (target *migrationMailTarget) Apply(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	admission, err := target.admit(ctx, intent)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	observed, observeErr := target.runtime.PublishMigration(ctx, mail.MailPublicationRequest{Operation: "observe", Bundle: admission.bundle, Generation: admission.generation})
	if observeErr == nil {
		if observed.State == "active" {
			if err = target.coordinator.Complete(ctx, admission.bundle, observed); err != nil {
				return migration.ImportEffect{}, err
			}
			if err = target.coordinator.Observe(ctx, admission.bundle); err != nil {
				return migration.ImportEffect{}, err
			}
		}
		effect := migrationMailEffect(intent, admission, observed, []string{observed.EvidenceDigest})
		if observed.State == "dark" {
			effect.ErrorCode = "MAIL_STAGED_NOT_PUBLISHED"
		}
		return effect, nil
	}
	if !errors.Is(observeErr, mail.ErrNotFound) {
		return migration.ImportEffect{}, observeErr
	}
	proofs := []string{}
	for index := range admission.staging {
		receipt, stageErr := target.stageMailboxTransfer(ctx, admission.staging[index])
		if stageErr != nil {
			return migration.ImportEffect{}, stageErr
		}
		proofs = append(proofs, receipt.EvidenceDigest)
	}
	receipt, err := target.runtime.PublishMigration(ctx, mail.MailPublicationRequest{Operation: "stage", Bundle: admission.bundle, Generation: admission.generation})
	if err != nil || receipt.State != "dark" {
		return migration.ImportEffect{}, errors.Join(migration.ErrBlocked, err)
	}
	proofs = append(proofs, receipt.EvidenceDigest)
	effect := migrationMailEffect(intent, admission, receipt, proofs)
	effect.ErrorCode = "MAIL_STAGED_NOT_PUBLISHED"
	return effect, nil
}

func (target *migrationMailTarget) Observe(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	admission, err := target.admit(ctx, intent)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	receipt, err := target.runtime.PublishMigration(ctx, mail.MailPublicationRequest{Operation: "observe", Bundle: admission.bundle, Generation: admission.generation})
	if err != nil {
		return migration.ImportEffect{}, err
	}
	if receipt.State == "active" {
		if err = target.coordinator.Complete(ctx, admission.bundle, receipt); err != nil {
			return migration.ImportEffect{}, err
		}
		if err = target.coordinator.Observe(ctx, admission.bundle); err != nil {
			return migration.ImportEffect{}, err
		}
	}
	effect := migrationMailEffect(intent, admission, receipt, []string{receipt.EvidenceDigest})
	if receipt.State == "dark" {
		effect.ErrorCode = "MAIL_STAGED_NOT_PUBLISHED"
	}
	return effect, nil
}

func (target *migrationMailTarget) Activate(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	admission, err := target.admit(ctx, intent)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	if err = target.coordinator.MarkActivating(ctx, admission.bundle.ID); err != nil {
		return migration.ImportEffect{}, err
	}
	value, err := target.host.repository.Migration(ctx, intent.MigrationID)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	if err = target.host.sourceFence(ctx, value); err != nil {
		return migration.ImportEffect{}, err
	}
	var fence migration.SourceFence
	if err = target.host.repository.Receipt(ctx, intent.MigrationID, "source_fence", &fence); err != nil {
		return migration.ImportEffect{}, err
	}
	// This is deliberately the last control-plane read before the privileged
	// daemon enters maintenance and publishes the complete mail generation.
	if err = target.host.sourceFence(ctx, value); err != nil {
		return migration.ImportEffect{}, err
	}
	receipt, publishErr := target.runtime.PublishMigration(ctx, mail.MailPublicationRequest{Operation: "activate", Bundle: admission.bundle, Generation: admission.generation, SourceFenceDigest: fence.Digest})
	if publishErr != nil {
		return migration.ImportEffect{}, publishErr
	}
	if receipt.State != "active" {
		return migration.ImportEffect{}, migration.ErrAmbiguous
	}
	if err = target.coordinator.Complete(ctx, admission.bundle, receipt); err != nil {
		return migration.ImportEffect{}, errors.Join(migration.ErrAmbiguous, err)
	}
	if err = target.coordinator.Observe(ctx, admission.bundle); err != nil {
		return migration.ImportEffect{}, errors.Join(migration.ErrAmbiguous, err)
	}
	return migrationMailEffect(intent, admission, receipt, []string{receipt.EvidenceDigest}), nil
}

func (target *migrationMailTarget) Compensate(ctx context.Context, intent migration.ImportIntent, effect migration.ImportEffect) (migration.ImportEffect, error) {
	admission, err := target.admit(ctx, intent)
	if err != nil {
		return migration.ImportEffect{}, err
	}
	receipt, cancelErr := target.runtime.PublishMigration(ctx, mail.MailPublicationRequest{Operation: "cancel", Bundle: admission.bundle, Generation: admission.generation})
	if cancelErr != nil && !errors.Is(cancelErr, mail.ErrNotFound) {
		return migration.ImportEffect{}, cancelErr
	}
	proofs := []string{}
	if receipt.EvidenceDigest != "" {
		proofs = append(proofs, receipt.EvidenceDigest)
	}
	for _, transfer := range admission.staging {
		discarded, discardErr := target.discardMailboxTransfer(ctx, transfer)
		if discardErr != nil && !errors.Is(discardErr, mail.ErrNotFound) {
			return migration.ImportEffect{}, discardErr
		}
		if discarded.EvidenceDigest != "" {
			proofs = append(proofs, discarded.EvidenceDigest)
		}
	}
	if err = target.coordinator.Cancel(ctx, admission.bundle.ID); err != nil {
		return migration.ImportEffect{}, err
	}
	effect = migrationMailEffect(intent, admission, receipt, proofs)
	effect.Status = migration.ImportEffectCompensated
	effect.TargetGeneration = 0
	effect.ErrorCode = ""
	effect.AppliedAt = time.Now().UTC()
	return effect, nil
}

func migrationMailEffect(intent migration.ImportIntent, admission migrationMailAdmission, receipt mail.MailPublicationReceipt, proofs []string) migration.ImportEffect {
	evidence := migrationHostDigest(struct {
		Publication mail.MailPublicationReceipt
		Proofs      []string
	}{receipt, proofs})
	return migration.ImportEffect{EffectID: intent.EffectID, InputDigest: intent.InputDigest, OutputDigest: admission.generation.Digest, Status: migration.ImportEffectApplied, TargetGeneration: 1, BytesWritten: admission.bytes, ObjectsWritten: admission.objects + uint64(len(admission.bundle.Domain.Mailboxes)+len(admission.bundle.Domain.Aliases)+2), EvidenceDigest: evidence, AppliedAt: time.Now().UTC()}
}

func (target *migrationHostTarget) observeMail(ctx context.Context, intent migration.ImportIntent) (migration.ImportEffect, error) {
	origin, err := target.auxiliaryOrigin(ctx, intent)
	if err != nil || target.mail == nil {
		return migration.ImportEffect{}, errors.Join(migration.ErrBlocked, err)
	}
	return target.mail.Observe(ctx, origin)
}
func (target *migrationHostTarget) mailProofs(ctx context.Context, entries []migration.ImportIntent, active bool) ([]string, error) {
	proofs := []string{}
	for _, intent := range entries {
		if intent.Kind != migration.ImportMailDomain {
			continue
		}
		effect, err := target.observeMail(ctx, intent)
		if err != nil || effect.Status != migration.ImportEffectApplied || effect.EvidenceDigest == "" || active && effect.ErrorCode != "" || !active && effect.ErrorCode == "" {
			return nil, errors.Join(migration.ErrBlocked, err)
		}
		proofs = append(proofs, effect.EvidenceDigest)
	}
	return proofs, nil
}

var _ migration.CanonicalImportHandler = (*migrationMailTarget)(nil)
