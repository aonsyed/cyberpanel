//go:build linux

package main

import (
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/mailtelemetry"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
)

const mailTelemetryStateRoot = "/var/lib/cyberpanel/control/mail-telemetry"

type mailTelemetryHealth struct {
	State       string
	Reason      string
	ObservedAt  time.Time
	LastSuccess time.Time
}

type mailEdge struct {
	store     mail.SQLControlRepository
	runtime   *mail.MailDaemonClient
	telemetry *mailTelemetryRuntime
	healthMu  sync.RWMutex
	health    mailTelemetryHealth
}

type mailTelemetryRuntime struct {
	repository *mailtelemetry.SQLiteRepository
	ingestor   *mailtelemetry.LinuxIngestor
	exporter   *mailtelemetry.Exporter
	abuse      *mailtelemetry.AbuseCoordinator
	correlator *mailTelemetryCorrelator
	firewall   *mailFirewallAuthority
	sources    []mailtelemetry.SourceDescriptor
}

func newMailEdge(store mail.SQLControlRepository, runtime *mail.MailDaemonClient) (*mailEdge, error) {
	if store.DB == nil || runtime == nil { return nil, errors.New("mail edge dependencies required") }
	return &mailEdge{store: store, runtime: runtime, health: mailTelemetryHealth{State: "unavailable", Reason: "telemetry_not_initialized"}}, nil
}

func (edge *mailEdge) enableTelemetry(ctx context.Context, operationsRepository *operations.SQLRepository, operationsCoordinator operations.Coordinator, auditService *audit.Service) error {
	if edge == nil || edge.store.DB == nil || ctx == nil || operationsRepository == nil || auditService == nil { return errors.New("mail telemetry dependencies required") }
	authorization := mailTelemetryAuthorization{}
	auditor := mailTelemetryAudit{service: auditService}
	repository, err := mailtelemetry.NewSQLiteRepository(edge.store.DB, authorization, auditor)
	if err != nil { return err }
	if err = repository.Bootstrap(ctx); err != nil { return err }
	key, err := loadMailTelemetryKey(mailTelemetryStateRoot)
	if err != nil { return err }
	defer clearMailTelemetryBytes(key)
	pseudonyms, err := mailtelemetry.NewPseudonymizer(key)
	if err != nil { return err }
	correlator := &mailTelemetryCorrelator{store: edge.store, domains: map[string]mailtelemetry.Correlation{}, mailboxes: map[string]mailtelemetry.Correlation{}, queues: map[string]mailtelemetry.Correlation{}}
	protector := &mailTelemetrySourceProtector{repository: repository, key: append([]byte(nil), key...)}
	normalizer, err := mailtelemetry.NewNormalizer(correlator, repository, pseudonyms, nil, protector)
	if err != nil { return err }
	sources := defaultMailTelemetrySources()
	ingestor, err := mailtelemetry.NewLinuxIngestor(sources, normalizer, repository)
	if err != nil { return err }
	sink, err := newMailTelemetryArtifactSink(filepath.Join(mailTelemetryStateRoot, "exports"))
	if err != nil { return err }
	exporter, err := mailtelemetry.NewExporter(repository, sink)
	if err != nil { return err }
	firewall := &mailFirewallAuthority{database: edge.store.DB, repository: operationsRepository, coordinator: operationsCoordinator, sources: repository}
	abuse, err := mailtelemetry.NewAbuseCoordinator(repository, authorization, authorization, firewall, auditor)
	if err != nil { return err }
	edge.telemetry = &mailTelemetryRuntime{repository: repository, ingestor: ingestor, exporter: exporter, abuse: abuse, correlator: correlator, firewall: firewall, sources: sources}
	edge.setTelemetryHealth("unavailable", "ingestion_not_observed", time.Time{})
	return nil
}

func (edge *mailEdge) setTelemetryUnavailable(reason string) { edge.setTelemetryHealth("unavailable", reason, time.Time{}) }
func (edge *mailEdge) setTelemetryHealth(state, reason string, lastSuccess time.Time) {
	edge.healthMu.Lock()
	defer edge.healthMu.Unlock()
	if lastSuccess.IsZero() { lastSuccess = edge.health.LastSuccess }
	edge.health = mailTelemetryHealth{State: state, Reason: reason, ObservedAt: time.Now().UTC(), LastSuccess: lastSuccess.UTC()}
}
func (edge *mailEdge) telemetryHealth() apiserver.MailTelemetryHealth {
	edge.healthMu.RLock()
	defer edge.healthMu.RUnlock()
	return apiserver.MailTelemetryHealth{State: edge.health.State, UnavailableReason: edge.health.Reason, ObservedAt: edge.health.ObservedAt, LastIngestAt: edge.health.LastSuccess}
}
func (edge *mailEdge) requireTelemetry() (*mailTelemetryRuntime, error) {
	if edge == nil || edge.telemetry == nil { return nil, mail.ErrAmbiguous }
	return edge.telemetry, nil
}

func defaultMailTelemetrySources() []mailtelemetry.SourceDescriptor {
	return []mailtelemetry.SourceDescriptor{
		{ID: "postfix-journal", Kind: mailtelemetry.SourcePostfix, Generation: 1, Backend: mailtelemetry.BackendJournal, JournalUnit: "postfix.service"},
		{ID: "dovecot-journal", Kind: mailtelemetry.SourceDovecot, Generation: 1, Backend: mailtelemetry.BackendJournal, JournalUnit: "dovecot.service"},
		{ID: "rspamd-journal", Kind: mailtelemetry.SourceRspamd, Generation: 1, Backend: mailtelemetry.BackendJournal, JournalUnit: "rspamd.service"},
		{ID: "clamav-journal", Kind: mailtelemetry.SourceClamAV, Generation: 1, Backend: mailtelemetry.BackendJournal, JournalUnit: "clamav-daemon.service"},
		{ID: "dkim-journal", Kind: mailtelemetry.SourceDKIM, Generation: 1, Backend: mailtelemetry.BackendJournal, JournalUnit: "opendkim.service"},
		{ID: "policy-journal", Kind: mailtelemetry.SourcePolicy, Generation: 1, Backend: mailtelemetry.BackendJournal, JournalUnit: "postfix-policy.service"},
		{ID: "delivery-journal", Kind: mailtelemetry.SourceDelivery, Generation: 1, Backend: mailtelemetry.BackendJournal, JournalUnit: "panel-mail-delivery.service"},
		{ID: "authentication-journal", Kind: mailtelemetry.SourceAuthentication, Generation: 1, Backend: mailtelemetry.BackendJournal, JournalUnit: "dovecot.service"},
	}
}

func loadMailTelemetryKey(root string) ([]byte, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root { return nil, errors.New("invalid mail telemetry state root") }
	if err := os.MkdirAll(root, 0700); err != nil { return nil, err }
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 { return nil, errors.New("unsafe mail telemetry state root") }
	path := filepath.Join(root, "pseudonym.key")
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() != 32 { return nil, errors.New("unsafe mail telemetry pseudonym key") }
		file, openErr := os.Open(path)
		if openErr != nil { return nil, openErr }
		defer file.Close()
		opened, openStatErr := file.Stat()
		if openStatErr != nil || !os.SameFile(info, opened) { return nil, errors.New("mail telemetry pseudonym key changed while opening") }
		key, readErr := io.ReadAll(io.LimitReader(file, 33))
		if readErr != nil || len(key) != 32 { clearMailTelemetryBytes(key); return nil, errors.New("invalid mail telemetry pseudonym key") }
		return key, nil
	}
	if !errors.Is(statErr, os.ErrNotExist) { return nil, statErr }
	key := make([]byte, 32)
	if _, err = crand.Read(key); err != nil { return nil, err }
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) { clearMailTelemetryBytes(key); return loadMailTelemetryKey(root) }
	if err != nil { clearMailTelemetryBytes(key); return nil, err }
	if _, err = file.Write(key); err == nil { err = file.Sync() }
	closeErr := file.Close()
	if err == nil { err = closeErr }
	if err != nil { clearMailTelemetryBytes(key); return nil, err }
	return key, nil
}
func clearMailTelemetryBytes(value []byte) { for index := range value { value[index] = 0 } }

type mailTelemetryAuthorization struct{}
func (mailTelemetryAuthorization) AuthorizePolicy(_ context.Context, actor mailtelemetry.Actor, tenant mailtelemetry.TenantID, _ mailtelemetry.DomainID, _ mailtelemetry.MailboxID, mutation bool) error { if actor.TenantID != tenant || mutation && actor.StepUpAt.IsZero() { return mailtelemetry.ErrUnauthorized }; return nil }
func (mailTelemetryAuthorization) AuthorizeTelemetry(_ context.Context, actor mailtelemetry.Actor, tenant mailtelemetry.TenantID, _ mailtelemetry.DomainID, _ mailtelemetry.MailboxID, _ bool) error { if actor.TenantID != tenant { return mailtelemetry.ErrUnauthorized }; return nil }
func (mailTelemetryAuthorization) AuthorizeExport(_ context.Context, actor mailtelemetry.Actor, policy mailtelemetry.Policy, format string) error { if actor.TenantID != policy.TenantID || actor.StepUpAt.IsZero() || format != "jsonl-v1" { return mailtelemetry.ErrUnauthorized }; return nil }
func (mailTelemetryAuthorization) AuthorizeMailAbuseIntent(_ context.Context, actor mailtelemetry.Actor, intent mailtelemetry.AbuseIntent, mutation bool) error { if actor.TenantID != intent.TenantID || mutation && actor.StepUpAt.IsZero() { return mailtelemetry.ErrUnauthorized }; return nil }
func (mailTelemetryAuthorization) VerifyMailAbuseApproval(_ context.Context, intent mailtelemetry.AbuseIntent, approval mailtelemetry.AbuseApproval) error { if approval.ApprovedDigest != intent.BodyDigest || approval.ReviewerID == intent.ProposedBy { return mailtelemetry.ErrUnauthorized }; return nil }

type mailTelemetryAudit struct{ service *audit.Service }
func (sink mailTelemetryAudit) RecordMailTelemetryAudit(ctx context.Context, record mailtelemetry.AuditRecord) error {
	if sink.service == nil { return errors.New("mail telemetry audit unavailable") }
	class := audit.ClassMutation
	if strings.Contains(record.Action, "export") { class = audit.ClassSensitiveRead }
	outcome := audit.OutcomeApplied
	if record.Outcome == "authorized" { outcome = audit.OutcomeAllowed } else if record.Outcome == "rejected" { outcome = audit.OutcomeRejected }
	event := audit.Event{ID: "mailtelemetry-" + mailEdgeDigest(record.Action, record.ResourceID, record.EvidenceDigest)[:32], Class: class, Action: record.Action, Actor: audit.Actor{PrincipalID: record.Actor.SubjectID, SessionID: record.Actor.SessionID, TenantID: string(record.Actor.TenantID), AuthzEpoch: record.Actor.AuthzEpoch}, Target: audit.Target{Kind: "mail_telemetry", ID: record.ResourceID, TenantID: string(record.TenantID)}, Outcome: outcome, RequestDigest: record.RequestDigest, Attributes: map[string]string{"evidence_digest": record.EvidenceDigest}, OccurredAt: record.At.UTC()}
	_, err := sink.service.Writer.Append(ctx, event)
	return err
}
func (sink mailTelemetryAudit) RecordMailAbuseAudit(ctx context.Context, record mailtelemetry.AbuseAuditRecord) error {
	if sink.service == nil { return errors.New("mail abuse audit unavailable") }
	outcome := audit.OutcomeAllowed
	if record.Outcome == "applied" { outcome = audit.OutcomeApplied } else if record.Outcome == "rejected" { outcome = audit.OutcomeRejected }
	event := audit.Event{ID: "mailabuse-" + mailEdgeDigest(record.IntentID, record.Outcome, record.ReceiptDigest)[:32], Class: audit.ClassSecurity, Action: "mail_abuse." + string(record.Action), Actor: audit.Actor{PrincipalID: record.ReviewerID, TenantID: string(record.TenantID)}, Target: audit.Target{Kind: "mail_abuse_intent", ID: record.IntentID, TenantID: string(record.TenantID)}, Outcome: outcome, RequestDigest: record.BodyDigest, Attributes: map[string]string{"proposed_by": record.ActorID, "receipt_digest": record.ReceiptDigest}, OccurredAt: record.At.UTC()}
	_, err := sink.service.RecordDecision(ctx, event, nil)
	return err
}

type mailTelemetrySourceProtector struct{ repository *mailtelemetry.SQLiteRepository; key []byte }
func (protector *mailTelemetrySourceProtector) ProtectMailSource(ctx context.Context, tenant mailtelemetry.TenantID, source netip.Addr) (string, error) {
	if protector == nil || protector.repository == nil || len(protector.key) < 32 { return "", mailtelemetry.ErrProtected }
	source = source.Unmap()
	mac := hmac.New(sha256.New, protector.key)
	mac.Write([]byte("mail-protected-source-v1\x00")); mac.Write([]byte(tenant)); mac.Write([]byte{0}); mac.Write([]byte(source.String()))
	reference := "source-ref-" + hex.EncodeToString(mac.Sum(nil))
	if err := protector.repository.StoreProtectedSource(ctx, tenant, reference, source); err != nil { return "", err }
	return reference, nil
}

type mailTelemetryCorrelator struct {
	store mail.SQLControlRepository
	refreshMu sync.Mutex
	mu sync.RWMutex
	loadedAt time.Time
	domains map[string]mailtelemetry.Correlation
	mailboxes map[string]mailtelemetry.Correlation
	queues map[string]mailtelemetry.Correlation
	tenants []mailtelemetry.TenantID
}
func (correlator *mailTelemetryCorrelator) refresh(ctx context.Context) error {
	correlator.refreshMu.Lock()
	defer correlator.refreshMu.Unlock()
	correlator.mu.RLock(); fresh := time.Since(correlator.loadedAt) < time.Minute; correlator.mu.RUnlock()
	if fresh { return nil }
	domains := map[string]mailtelemetry.Correlation{}; domainNames := map[string]string{}; tenants := map[mailtelemetry.TenantID]struct{}{}
	cursor := ""; count := 0
	for {
		resources, next, err := correlator.store.ListAll(ctx, mail.ResourceDomain, 500, cursor); if err != nil { return err }
		for _, resource := range resources {
			count++; if count > 10000 { return mailtelemetry.ErrLimit }
			var domain mail.Domain
			if json.Unmarshal(resource.Spec, &domain) != nil || string(domain.ID) != resource.ID || domain.Tenant != resource.TenantID { return mailtelemetry.ErrIntegrity }
			name := strings.ToLower(strings.TrimSuffix(domain.Name, ".")); candidate := mailtelemetry.Correlation{TenantID: mailtelemetry.TenantID(resource.TenantID), DomainID: mailtelemetry.DomainID(domain.ID), Direction: mailtelemetry.DirectionUnknown}
			if existing, exists := domains[name]; exists && existing != candidate { return mailtelemetry.ErrConflict }
			domains[name] = candidate; domainNames[resource.TenantID+"\x00"+string(domain.ID)] = name; tenants[candidate.TenantID] = struct{}{}
		}
		if next == "" { break }; cursor = next
	}
	mailboxes := map[string]mailtelemetry.Correlation{}; cursor = ""; count = 0
	for {
		resources, next, err := correlator.store.ListAll(ctx, mail.ResourceMailbox, 500, cursor); if err != nil { return err }
		for _, resource := range resources {
			count++; if count > 50000 { return mailtelemetry.ErrLimit }
			var mailbox mail.Mailbox
			if json.Unmarshal(resource.Spec, &mailbox) != nil || string(mailbox.ID) != resource.ID { return mailtelemetry.ErrIntegrity }
			domainName := domainNames[resource.TenantID+"\x00"+string(mailbox.Domain)]; if domainName == "" { continue }
			address := strings.ToLower(mailbox.Local + "@" + domainName)
			mailboxes[address] = mailtelemetry.Correlation{TenantID: mailtelemetry.TenantID(resource.TenantID), DomainID: mailtelemetry.DomainID(mailbox.Domain), MailboxID: mailtelemetry.MailboxID(mailbox.ID), Direction: mailtelemetry.DirectionUnknown}
		}
		if next == "" { break }; cursor = next
	}
	tenantValues := make([]mailtelemetry.TenantID, 0, len(tenants)); for tenant := range tenants { tenantValues = append(tenantValues, tenant) }; sort.Slice(tenantValues, func(left, right int) bool { return tenantValues[left] < tenantValues[right] })
	correlator.mu.Lock(); correlator.domains, correlator.mailboxes, correlator.tenants, correlator.loadedAt = domains, mailboxes, tenantValues, time.Now().UTC(); correlator.mu.Unlock()
	return nil
}
func (correlator *mailTelemetryCorrelator) ResolveMailCorrelation(ctx context.Context, input mailtelemetry.CorrelationInput) (mailtelemetry.Correlation, error) {
	if correlator == nil || ctx == nil { return mailtelemetry.Correlation{}, mailtelemetry.ErrInvalid }
	if err := correlator.refresh(ctx); err != nil { return mailtelemetry.Correlation{}, err }
	correlator.mu.Lock(); defer correlator.mu.Unlock()
	queued, queueFound := correlator.queues[input.QueueHint]; selected := mailtelemetry.Correlation{}; selectedIndex := -1
	for index, address := range input.Addresses {
		address = strings.ToLower(strings.TrimSpace(address)); candidate, found := correlator.mailboxes[address]
		if !found { parts := strings.SplitN(address, "@", 2); if len(parts) == 2 { candidate, found = correlator.domains[parts[1]] } }
		if !found { continue }
		if selected.TenantID != "" && (selected.TenantID != candidate.TenantID || selected.DomainID != candidate.DomainID) { return mailtelemetry.Correlation{}, mailtelemetry.ErrConflict }
		if selected.MailboxID == "" || candidate.MailboxID != "" { selected, selectedIndex = candidate, index }
	}
	if selected.TenantID == "" { if !queueFound { return mailtelemetry.Correlation{}, mailtelemetry.ErrNotFound }; return queued, nil }
	if queueFound && (queued.TenantID != selected.TenantID || queued.DomainID != selected.DomainID) { return mailtelemetry.Correlation{}, mailtelemetry.ErrConflict }
	switch {
	case input.Source == mailtelemetry.SourceDelivery: selected.Direction = mailtelemetry.DirectionOutbound
	case input.Source == mailtelemetry.SourceDovecot || input.Source == mailtelemetry.SourceAuthentication: selected.Direction = mailtelemetry.DirectionInbound
	case len(input.Addresses) > 1 && selectedIndex == len(input.Addresses)-1: selected.Direction = mailtelemetry.DirectionInbound
	case len(input.Addresses) > 1 && selectedIndex == 0: selected.Direction = mailtelemetry.DirectionOutbound
	case queueFound: selected.Direction = queued.Direction
	default: selected.Direction = mailtelemetry.DirectionUnknown
	}
	if input.QueueHint != "" { if len(correlator.queues) >= 50000 { correlator.queues = map[string]mailtelemetry.Correlation{} }; correlator.queues[input.QueueHint] = selected }
	return selected, nil
}
func (correlator *mailTelemetryCorrelator) Tenants(ctx context.Context) ([]mailtelemetry.TenantID, error) { if err := correlator.refresh(ctx); err != nil { return nil, err }; correlator.mu.RLock(); defer correlator.mu.RUnlock(); return append([]mailtelemetry.TenantID(nil), correlator.tenants...), nil }

type mailTelemetryArtifactSink struct{ root string }
type mailTelemetryArtifactStream struct{ file *os.File; temporary, final, manifest string; hasher hash.Hash; bytes int64; closed bool }
func newMailTelemetryArtifactSink(root string) (*mailTelemetryArtifactSink, error) { if !filepath.IsAbs(root) || filepath.Clean(root) != root { return nil, mailtelemetry.ErrInvalid }; if err := os.MkdirAll(root, 0700); err != nil { return nil, err }; info, err := os.Lstat(root); if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 { return nil, mailtelemetry.ErrIntegrity }; return &mailTelemetryArtifactSink{root: root}, nil }
func (sink *mailTelemetryArtifactSink) OpenMailTelemetryArtifact(_ context.Context, _ mailtelemetry.TenantID, exportID mailtelemetry.ExportID, _ string) (mailtelemetry.ArtifactStream, error) { name := string(exportID); temporary := filepath.Join(sink.root, "."+name+".part"); file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); if err != nil { return nil, err }; return &mailTelemetryArtifactStream{file: file, temporary: temporary, final: filepath.Join(sink.root, name+".jsonl"), manifest: filepath.Join(sink.root, name+".manifest.json"), hasher: sha256.New()}, nil }
func (stream *mailTelemetryArtifactStream) WriteArtifactChunk(ctx context.Context, value []byte) error { if stream == nil || stream.file == nil || stream.closed { return mailtelemetry.ErrInvalid }; select { case <-ctx.Done(): return ctx.Err(); default: }; written, err := stream.file.Write(value); if err != nil || written != len(value) { return errors.Join(io.ErrShortWrite, err) }; stream.hasher.Write(value); stream.bytes += int64(written); return nil }
func (stream *mailTelemetryArtifactStream) CommitArtifact(_ context.Context, manifest mailtelemetry.ArtifactManifest) (mailtelemetry.ArtifactReceipt, error) {
	if stream == nil || stream.file == nil || stream.closed || manifest.Bytes != stream.bytes || manifest.ContentDigest != hex.EncodeToString(stream.hasher.Sum(nil)) { return mailtelemetry.ArtifactReceipt{}, mailtelemetry.ErrIntegrity }
	if err := stream.file.Sync(); err != nil { return mailtelemetry.ArtifactReceipt{}, err }; if err := stream.file.Close(); err != nil { return mailtelemetry.ArtifactReceipt{}, err }; stream.closed = true
	raw, err := json.Marshal(manifest); if err != nil { return mailtelemetry.ArtifactReceipt{}, err }; sum := sha256.Sum256(raw); manifestTemporary := stream.manifest+".part"; manifestFile, err := os.OpenFile(manifestTemporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); if err != nil { return mailtelemetry.ArtifactReceipt{}, err }
	if _, err = manifestFile.Write(raw); err == nil { err = manifestFile.Sync() }; closeErr := manifestFile.Close(); if err == nil { err = closeErr }; if err != nil { return mailtelemetry.ArtifactReceipt{}, err }
	if err = os.Rename(stream.temporary, stream.final); err != nil { return mailtelemetry.ArtifactReceipt{}, err }; if err = os.Rename(manifestTemporary, stream.manifest); err != nil { return mailtelemetry.ArtifactReceipt{}, err }; directory, err := os.Open(filepath.Dir(stream.final)); if err == nil { err = directory.Sync(); directory.Close() }; if err != nil { return mailtelemetry.ArtifactReceipt{}, err }
	return mailtelemetry.ArtifactReceipt{ArtifactID: "artifact-"+mailEdgeDigest(string(manifest.ExportID))[:32], ManifestDigest: hex.EncodeToString(sum[:])}, nil
}
func (stream *mailTelemetryArtifactStream) AbortArtifact(_ context.Context) error { if stream == nil { return nil }; if !stream.closed && stream.file != nil { _ = stream.file.Close(); stream.closed = true }; err := os.Remove(stream.temporary); if errors.Is(err, os.ErrNotExist) { return nil }; return err }

type mailFirewallAuthority struct{ database *sql.DB; repository *operations.SQLRepository; coordinator operations.Coordinator; sources *mailtelemetry.SQLiteRepository }
func (authority *mailFirewallAuthority) RequestMailAbuseMutation(ctx context.Context, request mailtelemetry.FirewallMutationRequest) (mailtelemetry.FirewallMutationReceipt, error) { return authority.apply(ctx, request, "reviewed") }
func (authority *mailFirewallAuthority) expire(ctx context.Context, intent mailtelemetry.AbuseIntent) error { mode := "expire_ban"; if intent.Action == mailtelemetry.AbuseAllowlist { mode = "expire_allow" }; reviewer := intent.ProposedBy; if intent.Approval != nil { reviewer = intent.Approval.ReviewerID }; request := mailtelemetry.FirewallMutationRequest{RequestID: "expiry-"+intent.ID, TenantID: intent.TenantID, DomainID: intent.DomainID, MailboxID: intent.MailboxID, Action: mailtelemetry.AbuseReleaseBan, ProtectedSourceRef: intent.Source.ProtectedRef, SourcePseudonym: intent.Source.Pseudonym, ReasonCode: "approved_expiry", EvidenceDigest: intent.EvidenceDigest, RequestedBy: intent.ProposedBy, ApprovedBy: reviewer, ExpiresAt: intent.ExpiresAt.UTC()}; _, err := authority.apply(ctx, request, mode); return err }
func (authority *mailFirewallAuthority) apply(ctx context.Context, request mailtelemetry.FirewallMutationRequest, mode string) (mailtelemetry.FirewallMutationReceipt, error) {
	if authority == nil || authority.database == nil || authority.repository == nil || authority.sources == nil || ctx == nil || request.RequestID == "" || request.ApprovedBy == "" || mode == "reviewed" && !request.ExpiresAt.After(time.Now().UTC()) { return mailtelemetry.FirewallMutationReceipt{}, mailtelemetry.ErrInvalid }
	source, err := authority.sources.ResolveProtectedSource(ctx, request.TenantID, request.ProtectedSourceRef); if err != nil { return mailtelemetry.FirewallMutationReceipt{}, err }
	policy, err := authority.loadPolicy(ctx); if err != nil { return mailtelemetry.FirewallMutationReceipt{}, err }
	if len(request.SourcePseudonym) < 24 { return mailtelemetry.FirewallMutationReceipt{}, mailtelemetry.ErrIntegrity }
	banID, _ := operations.NewResourceID("mail-ban-"+request.SourcePseudonym[:24]); allowID, _ := operations.NewResourceID("mail-allow-"+request.SourcePseudonym[:24]); banIndex, allowIndex := -1, -1
	for index, rule := range policy.Rules { if rule.ID == banID { banIndex = index }; if rule.ID == allowID { allowIndex = index } }
	changed := false
	remove := func(id operations.ResourceID) { filtered := policy.Rules[:0]; for _, rule := range policy.Rules { if rule.ID == id { changed = true; continue }; filtered = append(filtered, rule) }; policy.Rules = filtered }
	prefix := netip.PrefixFrom(source, 128); family := operations.FamilyIPv6; if source.Is4() { prefix = netip.PrefixFrom(source, 32); family = operations.FamilyIPv4 }
	switch mode {
	case "expire_ban": remove(banID)
	case "expire_allow": remove(allowID)
	case "reviewed":
		switch request.Action {
		case mailtelemetry.AbuseBan:
			if allowIndex >= 0 { return mailtelemetry.FirewallMutationReceipt{}, mailtelemetry.ErrConflict }
			if banIndex < 0 { priority, priorityErr := availableFirewallPriority(policy.Rules, 40000, request.SourcePseudonym); if priorityErr != nil { return mailtelemetry.FirewallMutationReceipt{}, priorityErr }; policy.Rules = append(policy.Rules, operations.FirewallRule{ID: banID, Priority: priority, Family: family, Protocol: operations.ProtocolTCP, Sources: []netip.Prefix{prefix}, DestinationPorts: mailServicePorts(), Action: operations.FirewallDrop, Log: true}); changed = true }
		case mailtelemetry.AbuseAllowlist:
			remove(banID); if allowIndex < 0 { priority, priorityErr := availableFirewallPriority(policy.Rules, 30000, request.SourcePseudonym); if priorityErr != nil { return mailtelemetry.FirewallMutationReceipt{}, priorityErr }; policy.Rules = append(policy.Rules, operations.FirewallRule{ID: allowID, Priority: priority, Family: family, Protocol: operations.ProtocolTCP, Sources: []netip.Prefix{prefix}, DestinationPorts: mailServicePorts(), Action: operations.FirewallAccept}); changed = true }
		case mailtelemetry.AbuseReleaseBan: remove(banID)
		default: return mailtelemetry.FirewallMutationReceipt{}, mailtelemetry.ErrInvalid
		}
	default: return mailtelemetry.FirewallMutationReceipt{}, mailtelemetry.ErrInvalid
	}
	now := time.Now().UTC(); ownerID := "mailfw-"+mailEdgeDigest(mode, request.RequestID, strconv.FormatUint(policy.Generation, 10))[:32]; evidence := mailEdgeDigest(request.EvidenceDigest, mode, request.SourcePseudonym)
	if !changed { return mailtelemetry.FirewallMutationReceipt{RequestID: request.RequestID, OwnerReceiptID: ownerID, AlreadyApplied: true, AppliedUntil: request.ExpiresAt.UTC(), EvidenceDigest: evidence, CompletedAt: now}, nil }
	principal, err := operations.NewResourceID(request.ApprovedBy); if err != nil { return mailtelemetry.FirewallMutationReceipt{}, err }; proof, _ := operations.NewResourceID("mfa-"+mailEdgeDigest(request.RequestID, request.ApprovedBy)[:24]); approval, _ := operations.NewResourceID("approval-"+mailEdgeDigest(request.RequestID, request.EvidenceDigest)[:24]); policy.Generation++
	header := operations.CommandHeader{CommandID: ownerID, NodeID: policy.NodeID, Actor: operations.Actor{PrincipalID: principal, Capabilities: []operations.Capability{operations.CapabilityNodeSecurity}, MFAProofRef: proof}, RequestedAt: now, Deadline: now.Add(2*time.Minute), ApprovalRef: approval}
	receipt, err := authority.coordinator.Handle(ctx, operations.ReplaceFirewallPolicy{Header: header, Policy: policy, ExpectedGeneration: policy.Generation-1}); if err != nil { return mailtelemetry.FirewallMutationReceipt{}, err }; if receipt.Status != operations.OperationApplied || receipt.Effect.ProofDigest == "" { return mailtelemetry.FirewallMutationReceipt{}, mailtelemetry.ErrIntegrity }
	return mailtelemetry.FirewallMutationReceipt{RequestID: request.RequestID, OwnerReceiptID: ownerID, AppliedUntil: request.ExpiresAt.UTC(), EvidenceDigest: receipt.Effect.ProofDigest, CompletedAt: receipt.Effect.CompletedAt.UTC()}, nil
}
func (authority *mailFirewallAuthority) loadPolicy(ctx context.Context) (operations.FirewallPolicy, error) { rows, err := authority.database.QueryContext(ctx, `SELECT resource_id FROM panel_operation_resources WHERE kind=? AND physical_key='firewall' ORDER BY resource_id LIMIT 2`, operations.KindFirewallPolicy); if err != nil { return operations.FirewallPolicy{}, err }; defer rows.Close(); ids := []string{}; for rows.Next() { var id string; if rows.Scan(&id) != nil { return operations.FirewallPolicy{}, mailtelemetry.ErrIntegrity }; ids = append(ids, id) }; if rows.Err() != nil { return operations.FirewallPolicy{}, rows.Err() }; if len(ids) == 0 { return operations.FirewallPolicy{}, mailtelemetry.ErrNotFound }; if len(ids) != 1 { return operations.FirewallPolicy{}, mailtelemetry.ErrConflict }; id, err := operations.NewResourceID(ids[0]); if err != nil { return operations.FirewallPolicy{}, mailtelemetry.ErrIntegrity }; envelope, err := authority.repository.LoadResource(ctx, operations.KindFirewallPolicy, id); if err != nil { return operations.FirewallPolicy{}, err }; resource, err := operations.DecodeResource(envelope); if err != nil { return operations.FirewallPolicy{}, err }; policy, ok := resource.(*operations.FirewallPolicy); if !ok || policy.Status.Lifecycle != operations.LifecycleReady || policy.Status.Reconciliation != operations.ReconciliationInSync { return operations.FirewallPolicy{}, mailtelemetry.ErrConflict }; return *policy, nil }
func availableFirewallPriority(rules []operations.FirewallRule, base uint16, seed string) (uint16, error) { used := map[uint16]struct{}{}; for _, rule := range rules { used[rule.Priority] = struct{}{} }; sum := sha256.Sum256([]byte(seed)); start := base+uint16(sum[0])%1000; for value := start; value < base+5000; value++ { if _, exists := used[value]; !exists { return value, nil } }; return 0, mailtelemetry.ErrLimit }
func mailServicePorts() []operations.PortRange { return []operations.PortRange{{From:25, To:25}, {From:110, To:110}, {From:143, To:143}, {From:465, To:465}, {From:587, To:587}, {From:993, To:993}, {From:995, To:995}} }

func (edge *mailEdge) ListRoutes(ctx context.Context, call apiserver.EdgeCall, page apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.MailRouteProjection], error) { if edge == nil || edge.store.DB == nil || ctx == nil || call.TenantID == "" { return apiserver.EdgePage[apiserver.MailRouteProjection]{}, mail.ErrInvalidCommand }; limit := int(page.Limit); if limit == 0 { limit = 100 }; resources, next, err := edge.store.List(ctx, call.TenantID, mail.ResourceAlias, limit, page.Cursor); if err != nil { return apiserver.EdgePage[apiserver.MailRouteProjection]{}, err }; items := make([]apiserver.MailRouteProjection, 0, len(resources)); for _, resource := range resources { var alias mail.Alias; if json.Unmarshal(resource.Spec, &alias) != nil || string(alias.ID) != resource.ID { return apiserver.EdgePage[apiserver.MailRouteProjection]{}, mail.ErrInvalidReceipt }; targets := make([]string, len(alias.Targets)); for index, target := range alias.Targets { targets[index] = string(target) }; kind := "alias"; if alias.CatchAll { kind = "catch_all" }; if alias.PipeRef != "" { kind = "pipe" }; items = append(items, apiserver.MailRouteProjection{ID:resource.ID, DomainID:string(alias.Domain), Source:string(alias.Source), Targets:targets, Kind:kind, State:string(resource.State), Generation:resource.Generation, UpdatedAt:resource.UpdatedAt}) }; return apiserver.EdgePage[apiserver.MailRouteProjection]{Items:items, NextCursor:next}, nil }
func (edge *mailEdge) RunDiagnostic(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MailDiagnosticPayload) (apiserver.EdgeMutation[apiserver.MailDiagnosticProjection], error) { if edge == nil || edge.runtime == nil || ctx == nil || call.TenantID == "" || call.ResourceID == "" { return apiserver.EdgeMutation[apiserver.MailDiagnosticProjection]{}, mail.ErrInvalidCommand }; services := []mail.MailService{mail.ServicePostfix, mail.ServiceDovecot}; if payload.Depth == "deep" { services = append(services, mail.ServiceRspamd, mail.ServiceOpenDKIM, mail.ServiceRedis, mail.ServiceClamAV) }; checks := make([]string, 0, len(services)); findings := []string{}; for _, service := range services { receipt, err := edge.runtime.ControlService(ctx, service, mail.ServiceProbe); if err != nil { return apiserver.EdgeMutation[apiserver.MailDiagnosticProjection]{}, err }; checks = append(checks, string(service)+":"+receipt.EvidenceDigest); if !receipt.Active { findings = append(findings, string(service)+":unhealthy") } }; state := "healthy"; if len(findings) > 0 { state = "degraded" }; completed := time.Now().UTC(); operationID := mailEdgeID(call, "diagnostic"); projection := apiserver.MailDiagnosticProjection{ID:operationID, ResourceID:call.ResourceID, State:state, Checks:checks, Findings:findings, CompletedAt:completed}; return apiserver.EdgeMutation[apiserver.MailDiagnosticProjection]{OperationID:operationID, State:"applied", Generation:1, Resource:projection}, nil }

func mailTelemetryActor(call apiserver.EdgeCall) mailtelemetry.Actor { session := "session-"+mailEdgeDigest(call.PrincipalID, call.CredentialID)[:24]; stepUp := time.Time{}; if call.Assurance >= identity.AssuranceMFA { stepUp = time.Now().UTC() }; return mailtelemetry.Actor{SubjectID:call.PrincipalID, TenantID:mailtelemetry.TenantID(call.TenantID), SessionID:session, AuthzEpoch:call.AuthzEpoch, StepUpAt:stepUp} }
func mailTelemetrySystemActor(tenant mailtelemetry.TenantID) mailtelemetry.Actor { return mailtelemetry.Actor{SubjectID:"mail-telemetry-runtime", TenantID:tenant, SessionID:"mail-telemetry-runtime", AuthzEpoch:1} }
func mailEdgeDigest(parts ...string) string { value := sha256.New(); for _, part := range parts { value.Write([]byte{0}); value.Write([]byte(part)) }; return hex.EncodeToString(value.Sum(nil)) }
func mailEdgeID(call apiserver.EdgeCall, purpose string) string { return "mailedge_"+mailEdgeDigest(call.TenantID, call.ResourceID, call.CommandID, call.IdempotencyKey, purpose) }

func (edge *mailEdge) validateTelemetryScope(ctx context.Context, tenant, domainID, mailboxID string, requireActive bool) error {
	if domainID == "" { if mailboxID != "" { return mailtelemetry.ErrInvalid }; return nil }
	domainResource, found, err := edge.store.Load(ctx, tenant, mail.ResourceDomain, domainID)
	if err != nil { return err }
	if !found || requireActive && domainResource.State != mail.StateActive { return mailtelemetry.ErrNotFound }
	var domain mail.Domain
	if json.Unmarshal(domainResource.Spec, &domain) != nil || string(domain.ID) != domainID || domain.Tenant != tenant { return mailtelemetry.ErrIntegrity }
	if mailboxID == "" { return nil }
	mailboxResource, found, err := edge.store.Load(ctx, tenant, mail.ResourceMailbox, mailboxID)
	if err != nil { return err }
	if !found || requireActive && mailboxResource.State != mail.StateActive { return mailtelemetry.ErrNotFound }
	var mailbox mail.Mailbox
	if json.Unmarshal(mailboxResource.Spec, &mailbox) != nil || string(mailbox.ID) != mailboxID || string(mailbox.Domain) != domainID { return mailtelemetry.ErrIntegrity }
	return nil
}

func telemetryCursor(at time.Time, id string) string { if id == "" { return "" }; return base64.RawURLEncoding.EncodeToString([]byte(at.UTC().Format(time.RFC3339Nano)+"\x00"+id)) }
func decodeTelemetryCursor(value string) (time.Time, string, error) { if value == "" { return time.Time{}, "", nil }; raw, err := base64.RawURLEncoding.DecodeString(value); if err != nil || len(raw) > 512 { return time.Time{}, "", mailtelemetry.ErrInvalid }; parts := strings.SplitN(string(raw), "\x00", 2); if len(parts) != 2 { return time.Time{}, "", mailtelemetry.ErrInvalid }; at, err := time.Parse(time.RFC3339Nano, parts[0]); if err != nil || parts[1] == "" { return time.Time{}, "", mailtelemetry.ErrInvalid }; return at.UTC(), parts[1], nil }
func opaqueTelemetryCursor(value string) string { if value == "" { return "" }; return base64.RawURLEncoding.EncodeToString([]byte(value)) }
func decodeOpaqueTelemetryCursor(value string) (string, error) { if value == "" { return "", nil }; raw, err := base64.RawURLEncoding.DecodeString(value); if err != nil || len(raw) > 160 || len(raw) == 0 { return "", mailtelemetry.ErrInvalid }; return string(raw), nil }

func (edge *mailEdge) telemetryQuery(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MailTelemetryQueryPayload) (mailtelemetry.Actor, mailtelemetry.EventQuery, error) { actor := mailTelemetryActor(call); if err := edge.validateTelemetryScope(ctx, call.TenantID, payload.DomainID, payload.MailboxID, false); err != nil { return actor, mailtelemetry.EventQuery{}, err }; end := payload.End.UTC(); if end.IsZero() { end = time.Now().UTC() }; start := payload.Start.UTC(); if start.IsZero() { start = end.Add(-24*time.Hour) }; limit := payload.Limit; if limit == 0 { limit = 100 }; afterAt, afterID, err := decodeTelemetryCursor(payload.Cursor); if err != nil { return actor, mailtelemetry.EventQuery{}, err }; query := mailtelemetry.EventQuery{TenantID:mailtelemetry.TenantID(call.TenantID), DomainID:mailtelemetry.DomainID(payload.DomainID), MailboxID:mailtelemetry.MailboxID(payload.MailboxID), Categories:append([]mailtelemetry.Category(nil), payload.Categories...), Start:start, End:end, AfterAt:afterAt, AfterID:mailtelemetry.EventID(afterID), Limit:limit}; return actor, query, nil }
func (edge *mailEdge) SearchTelemetry(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MailTelemetryQueryPayload) (apiserver.MailTelemetryEventPage, error) { runtime, err := edge.requireTelemetry(); if err != nil { return apiserver.MailTelemetryEventPage{Health:edge.telemetryHealth()}, nil }; actor, query, err := edge.telemetryQuery(ctx, call, payload); if err != nil { return apiserver.MailTelemetryEventPage{}, err }; page, err := runtime.repository.SearchEvents(ctx, actor, query); if err != nil { return apiserver.MailTelemetryEventPage{}, err }; health := edge.telemetryHealth(); items := make([]apiserver.MailTelemetryEventProjection, 0, len(page.Events)); for _, event := range page.Events { items = append(items, apiserver.MailTelemetryEventProjection{Event:event, IngestionState:health.State}) }; return apiserver.MailTelemetryEventPage{Items:items, NextCursor:telemetryCursor(page.NextAt, string(page.NextEventID)), Missing:page.Missing, Health:health}, nil }

type telemetryCollectSink struct{ events []mailtelemetry.Event; gaps []mailtelemetry.ParseGap; summary mailtelemetry.StreamSummary }
func (sink *telemetryCollectSink) WriteMailTelemetryEvent(_ context.Context, event mailtelemetry.Event) error { sink.events = append(sink.events, event); return nil }
func (sink *telemetryCollectSink) WriteMailTelemetryGap(_ context.Context, gap mailtelemetry.ParseGap) error { sink.gaps = append(sink.gaps, gap); return nil }
func (sink *telemetryCollectSink) CloseMailTelemetryStream(_ context.Context, summary mailtelemetry.StreamSummary) error { sink.summary = summary; return nil }
func (edge *mailEdge) StreamTelemetry(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MailTelemetryQueryPayload) (apiserver.MailTelemetryEventPage, error) { runtime, err := edge.requireTelemetry(); if err != nil { return apiserver.MailTelemetryEventPage{Health:edge.telemetryHealth()}, nil }; actor, query, err := edge.telemetryQuery(ctx, call, payload); if err != nil { return apiserver.MailTelemetryEventPage{}, err }; maximum := uint32(payload.MaximumRows); if maximum == 0 { maximum = 250 }; sink := &telemetryCollectSink{}; summary, err := runtime.repository.StreamEvents(ctx, actor, query, maximum, sink); if err != nil { return apiserver.MailTelemetryEventPage{}, err }; health := edge.telemetryHealth(); items := make([]apiserver.MailTelemetryEventProjection, 0, len(sink.events)); for _, event := range sink.events { items = append(items, apiserver.MailTelemetryEventProjection{Event:event, IngestionState:health.State}) }; return apiserver.MailTelemetryEventPage{Items:items, NextCursor:telemetryCursor(summary.NextAt, string(summary.NextEventID)), Missing:sink.gaps, Truncated:summary.Truncated, Health:health}, nil }
func (edge *mailEdge) TelemetryStatistics(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MailTelemetryStatisticsPayload) (apiserver.MailTelemetryStatisticsResult, error) { runtime, err := edge.requireTelemetry(); if err != nil { return apiserver.MailTelemetryStatisticsResult{Health:edge.telemetryHealth()}, nil }; if err = edge.validateTelemetryScope(ctx, call.TenantID, payload.DomainID, payload.MailboxID, false); err != nil { return apiserver.MailTelemetryStatisticsResult{}, err }; actor := mailTelemetryActor(call); end := payload.End.UTC(); if end.IsZero() { end = time.Now().UTC().Truncate(time.Hour).Add(time.Hour) }; start := payload.Start.UTC(); if start.IsZero() { start = end.Add(-24*time.Hour) }; statistics, err := runtime.repository.Statistics(ctx, actor, mailtelemetry.TenantID(call.TenantID), mailtelemetry.DomainID(payload.DomainID), mailtelemetry.MailboxID(payload.MailboxID), start, end); if err != nil { return apiserver.MailTelemetryStatisticsResult{}, err }; return apiserver.MailTelemetryStatisticsResult{Statistics:statistics, Health:edge.telemetryHealth()}, nil }

func policyProjection(policy mailtelemetry.Policy) apiserver.MailTelemetryPolicyProjection { state := "disabled"; if policy.Enabled { state = "enabled" }; return apiserver.MailTelemetryPolicyProjection{ID:string(policy.ID), DomainID:string(policy.DomainID), MailboxID:string(policy.MailboxID), State:state, RetentionDays:uint32(policy.Retention.Ordinary/(24*time.Hour)), ProviderRetentionDays:uint32(policy.Retention.Provider/(24*time.Hour)), SecurityRetentionDays:uint32(policy.Retention.SecurityFloor/(24*time.Hour)), AuditRetentionDays:uint32(policy.Retention.AuditFloor/(24*time.Hour)), StorageBytes:policy.Retention.StorageBytes, ExportAllowed:policy.Transfer.ExportAllowed, BackupHistory:policy.Transfer.BackupHistory, MigrationHistory:policy.Transfer.MigrationHistory, Generation:policy.Revision, UpdatedAt:policy.UpdatedAt} }
func (edge *mailEdge) ListTelemetryPolicies(ctx context.Context, call apiserver.EdgeCall, page apiserver.EdgePagePayload) (apiserver.MailTelemetryPolicyPage, error) { runtime, err := edge.requireTelemetry(); if err != nil { return apiserver.MailTelemetryPolicyPage{Health:edge.telemetryHealth()}, nil }; after, err := decodeOpaqueTelemetryCursor(page.Cursor); if err != nil { return apiserver.MailTelemetryPolicyPage{}, err }; values, err := runtime.repository.ListPolicies(ctx, mailTelemetryActor(call), mailtelemetry.TenantID(call.TenantID), mailtelemetry.PolicyID(after), page.Limit); if err != nil { return apiserver.MailTelemetryPolicyPage{}, err }; items := make([]apiserver.MailTelemetryPolicyProjection, 0, len(values.Policies)); for _, policy := range values.Policies { items = append(items, policyProjection(policy)) }; return apiserver.MailTelemetryPolicyPage{Items:items, NextCursor:opaqueTelemetryCursor(string(values.NextPolicyID)), Health:edge.telemetryHealth()}, nil }
func (edge *mailEdge) GetTelemetryPolicy(ctx context.Context, call apiserver.EdgeCall) (apiserver.MailTelemetryPolicyProjection, error) { runtime, err := edge.requireTelemetry(); if err != nil { return apiserver.MailTelemetryPolicyProjection{}, err }; policy, err := runtime.repository.GetPolicy(ctx, mailTelemetryActor(call), mailtelemetry.TenantID(call.TenantID), mailtelemetry.PolicyID(call.ResourceID)); if err != nil { return apiserver.MailTelemetryPolicyProjection{}, err }; return policyProjection(policy), nil }
func configureTelemetryPolicy(policy *mailtelemetry.Policy, payload apiserver.MailTelemetryPolicyMutationPayload) { if payload.RetentionDays > 0 { policy.Retention.Ordinary = time.Duration(payload.RetentionDays)*24*time.Hour }; if payload.ProviderRetentionDays > 0 { policy.Retention.Provider = time.Duration(payload.ProviderRetentionDays)*24*time.Hour }; if policy.Retention.Provider < policy.Retention.Ordinary { policy.Retention.Provider = policy.Retention.Ordinary }; if payload.StorageBytes > 0 { policy.Retention.StorageBytes = payload.StorageBytes }; if payload.ExportAllowed != nil { policy.Transfer.ExportAllowed = *payload.ExportAllowed; if *payload.ExportAllowed { policy.Transfer.AllowedExportFormats = []string{"jsonl-v1"} } else { policy.Transfer.AllowedExportFormats = nil } }; if payload.BackupHistory != nil { policy.Transfer.BackupHistory = *payload.BackupHistory }; if payload.MigrationHistory != nil { policy.Transfer.MigrationHistory = *payload.MigrationHistory } }
func (edge *mailEdge) MutateTelemetryPolicy(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MailTelemetryPolicyMutationPayload) (apiserver.EdgeMutation[apiserver.MailTelemetryPolicyProjection], error) { runtime, err := edge.requireTelemetry(); if err != nil { return apiserver.EdgeMutation[apiserver.MailTelemetryPolicyProjection]{}, err }; actor := mailTelemetryActor(call); now := time.Now().UTC(); var policy mailtelemetry.Policy; expected := call.ExpectedGeneration; switch payload.Action { case "create": if err = edge.validateTelemetryScope(ctx, call.TenantID, payload.DomainID, payload.MailboxID, true); err != nil { break }; id := payload.PolicyID; if id == "" { id = "policy-"+mailEdgeDigest(call.CommandID, call.TenantID, payload.DomainID, payload.MailboxID)[:24] }; policy, err = mailtelemetry.DefaultPolicy(mailtelemetry.PolicyID(id), mailtelemetry.TenantID(call.TenantID), mailtelemetry.DomainID(payload.DomainID), mailtelemetry.MailboxID(payload.MailboxID), now); expected = 0; case "update", "enable", "disable": policy, err = runtime.repository.GetPolicy(ctx, actor, mailtelemetry.TenantID(call.TenantID), mailtelemetry.PolicyID(call.ResourceID)); if err == nil && policy.Revision != expected { err = mailtelemetry.ErrConflict }; if err == nil { policy.Revision = expected+1; policy.UpdatedAt = now; if payload.Action == "enable" { policy.Enabled = true } else if payload.Action == "disable" { policy.Enabled = false } }; default: err = mailtelemetry.ErrInvalid }; if err != nil { return apiserver.EdgeMutation[apiserver.MailTelemetryPolicyProjection]{}, err }; configureTelemetryPolicy(&policy, payload); if err = runtime.repository.PutPolicy(ctx, actor, policy, expected); err != nil { return apiserver.EdgeMutation[apiserver.MailTelemetryPolicyProjection]{}, err }; projection := policyProjection(policy); return apiserver.EdgeMutation[apiserver.MailTelemetryPolicyProjection]{OperationID:mailEdgeID(call, "telemetry-policy-"+payload.Action), State:"applied", Generation:policy.Revision, Resource:projection}, nil }
func (edge *mailEdge) ExportTelemetry(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MailTelemetryQueryPayload) (apiserver.EdgeMutation[mailtelemetry.ExportJob], error) { runtime, err := edge.requireTelemetry(); if err != nil { return apiserver.EdgeMutation[mailtelemetry.ExportJob]{}, err }; actor, query, err := edge.telemetryQuery(ctx, call, payload); if err != nil { return apiserver.EdgeMutation[mailtelemetry.ExportJob]{}, err }; policy, err := runtime.repository.GetPolicy(ctx, actor, mailtelemetry.TenantID(call.TenantID), mailtelemetry.PolicyID(call.ResourceID)); if err != nil || policy.Revision != call.ExpectedGeneration { if err == nil { err = mailtelemetry.ErrConflict }; return apiserver.EdgeMutation[mailtelemetry.ExportJob]{}, err }; id := mailtelemetry.ExportID("export-"+mailEdgeDigest(call.TenantID, call.CommandID, call.IdempotencyKey)[:24]); if existing, loadErr := runtime.repository.GetExportJob(ctx, actor, actor.TenantID, id); loadErr == nil { return apiserver.EdgeMutation[mailtelemetry.ExportJob]{OperationID:string(id), State:string(existing.State), Generation:existing.Revision, Resource:existing}, nil } else if !errors.Is(loadErr, mailtelemetry.ErrNotFound) { return apiserver.EdgeMutation[mailtelemetry.ExportJob]{}, loadErr }; job, err := runtime.exporter.Export(ctx, actor, mailtelemetry.ExportRequest{ID:id, PolicyID:policy.ID, Format:"jsonl-v1", Query:query}); if err != nil { return apiserver.EdgeMutation[mailtelemetry.ExportJob]{}, err }; return apiserver.EdgeMutation[mailtelemetry.ExportJob]{OperationID:string(id), State:string(job.State), Generation:job.Revision, Resource:job}, nil }
func (edge *mailEdge) PurgeTelemetry(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MailTelemetryPurgePayload) (apiserver.EdgeMutation[mailtelemetry.PurgeReceipt], error) { runtime, err := edge.requireTelemetry(); if err != nil { return apiserver.EdgeMutation[mailtelemetry.PurgeReceipt]{}, err }; actor := mailTelemetryActor(call); policy, err := runtime.repository.GetPolicy(ctx, actor, mailtelemetry.TenantID(call.TenantID), mailtelemetry.PolicyID(call.ResourceID)); if err != nil || policy.Revision != call.ExpectedGeneration { if err == nil { err = mailtelemetry.ErrConflict }; return apiserver.EdgeMutation[mailtelemetry.PurgeReceipt]{}, err }; plan, err := runtime.repository.BuildPurgePlan(ctx, actor, policy, time.Now().UTC(), payload.Limit); if err != nil { return apiserver.EdgeMutation[mailtelemetry.PurgeReceipt]{}, err }; receipt, err := runtime.repository.ApplyPurgePlan(ctx, actor, plan); if err != nil { return apiserver.EdgeMutation[mailtelemetry.PurgeReceipt]{}, err }; return apiserver.EdgeMutation[mailtelemetry.PurgeReceipt]{OperationID:"purge-"+plan.Digest[:24], State:"applied", Generation:policy.Revision, Resource:receipt}, nil }

func abuseFindingProjection(finding mailtelemetry.AbuseFinding) apiserver.MailAbuseProjection { state := "evidence_only"; if finding.ActionEligible { state = "action_eligible" }; return apiserver.MailAbuseProjection{ID:finding.ID, Kind:"finding", DomainID:string(finding.DomainID), MailboxID:string(finding.MailboxID), Pattern:string(finding.Pattern), State:state, SourcePseudonym:finding.Source.Pseudonym, ProtectedSourceRef:finding.Source.ProtectedRef, Observed:uint64(finding.Observed), DistinctTargets:uint64(finding.DistinctTargets), EvidenceDigest:finding.EvidenceDigest, MissingData:finding.MissingData, Generation:1, OccurredAt:finding.DetectedAt} }
func abuseIntentProjection(intent mailtelemetry.AbuseIntent) apiserver.MailAbuseProjection { state := string(intent.State); if intent.State == mailtelemetry.IntentApplied && !time.Now().UTC().Before(intent.ExpiresAt) { state = "expired" }; approvedBy := ""; if intent.Approval != nil { approvedBy = intent.Approval.ReviewerID }; return apiserver.MailAbuseProjection{ID:intent.ID, Kind:"intent", DomainID:string(intent.DomainID), MailboxID:string(intent.MailboxID), Action:string(intent.Action), State:state, SourcePseudonym:intent.Source.Pseudonym, ProtectedSourceRef:intent.Source.ProtectedRef, EvidenceDigest:intent.EvidenceDigest, BodyDigest:intent.BodyDigest, ProposedBy:intent.ProposedBy, ApprovedBy:approvedBy, OwnerReceiptID:intent.OwnerReceiptID, Generation:intent.Revision, OccurredAt:intent.CreatedAt, ExpiresAt:intent.ExpiresAt} }
func (edge *mailEdge) ListMailAbuse(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MailAbusePagePayload) (apiserver.MailAbusePage, error) { runtime, err := edge.requireTelemetry(); if err != nil { return apiserver.MailAbusePage{Health:edge.telemetryHealth()}, nil }; actor := mailTelemetryActor(call); items := []apiserver.MailAbuseProjection{}; next := ""; if payload.Kind == "findings" { at, id, decodeErr := decodeTelemetryCursor(payload.Cursor); if decodeErr != nil { return apiserver.MailAbusePage{}, decodeErr }; page, listErr := runtime.repository.ListAbuseFindings(ctx, actor, actor.TenantID, at, id, payload.Limit); if listErr != nil { return apiserver.MailAbusePage{}, listErr }; for _, finding := range page.Findings { items = append(items, abuseFindingProjection(finding)) }; next = telemetryCursor(page.NextAt, page.NextID) } else { after, decodeErr := decodeOpaqueTelemetryCursor(payload.Cursor); if decodeErr != nil { return apiserver.MailAbusePage{}, decodeErr }; page, listErr := runtime.repository.ListAbuseIntents(ctx, actor, actor.TenantID, after, payload.Limit); if listErr != nil { return apiserver.MailAbusePage{}, listErr }; for _, intent := range page.Intents { items = append(items, abuseIntentProjection(intent)) }; next = opaqueTelemetryCursor(page.NextID) }; return apiserver.MailAbusePage{Items:items, NextCursor:next, Health:edge.telemetryHealth()}, nil }
func (edge *mailEdge) InspectMailAbuse(ctx context.Context, call apiserver.EdgeCall) (apiserver.MailAbuseProjection, error) { runtime, err := edge.requireTelemetry(); if err != nil { return apiserver.MailAbuseProjection{}, err }; intent, err := runtime.abuse.InspectIntent(ctx, mailTelemetryActor(call), mailtelemetry.TenantID(call.TenantID), call.ResourceID); if err != nil { return apiserver.MailAbuseProjection{}, err }; return abuseIntentProjection(intent), nil }
func (edge *mailEdge) ReviewMailAbuse(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MailAbuseReviewPayload) (apiserver.EdgeMutation[apiserver.MailAbuseProjection], error) {
	runtime, err := edge.requireTelemetry()
	if err != nil { return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{}, err }
	actor := mailTelemetryActor(call)
	var intent mailtelemetry.AbuseIntent
	switch payload.Action {
	case "approve":
		current, inspectErr := runtime.abuse.InspectIntent(ctx, actor, actor.TenantID, call.ResourceID)
		if inspectErr != nil { return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{}, inspectErr }
		expected := call.ExpectedGeneration
		now := time.Now().UTC()
		approval := mailtelemetry.AbuseApproval{ID:"approval-"+mailEdgeDigest(call.CommandID, call.PrincipalID)[:24], ReviewerID:call.PrincipalID, ApprovedDigest:payload.ApprovedDigest, EvidenceRef:payload.EvidenceRef, IssuedAt:now, ExpiresAt:now.Add(10*time.Minute)}
		if current.State == mailtelemetry.IntentSubmitting && current.Revision == call.ExpectedGeneration+1 && current.Approval != nil {
			if current.Approval.ReviewerID != call.PrincipalID || current.Approval.ApprovedDigest != payload.ApprovedDigest || current.Approval.EvidenceRef != payload.EvidenceRef { return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{}, mailtelemetry.ErrConflict }
			approval, expected = *current.Approval, current.Revision
		} else if current.State == mailtelemetry.IntentApplied && current.Revision == call.ExpectedGeneration+2 && current.Approval != nil {
			if current.Approval.ReviewerID != call.PrincipalID || current.Approval.ApprovedDigest != payload.ApprovedDigest || current.Approval.EvidenceRef != payload.EvidenceRef { return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{}, mailtelemetry.ErrConflict }
			intent = current
		} else if current.State != mailtelemetry.IntentProposed || current.Revision != call.ExpectedGeneration {
			return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{}, mailtelemetry.ErrConflict
		}
		if intent.ID == "" { intent, err = runtime.abuse.ApproveAndSubmit(ctx, actor, actor.TenantID, call.ResourceID, expected, approval) }
	case "recover":
		original, inspectErr := runtime.abuse.InspectIntent(ctx, actor, actor.TenantID, call.ResourceID)
		if inspectErr != nil { return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{}, inspectErr }
		if original.Revision != call.ExpectedGeneration { return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{}, mailtelemetry.ErrConflict }
		recoveryID := payload.RecoveryIntentID
		if recoveryID == "" { recoveryID = "recovery-"+mailEdgeDigest(call.CommandID, call.ResourceID, payload.ReasonDigest)[:24] }
		existing, existingErr := runtime.abuse.InspectIntent(ctx, actor, actor.TenantID, recoveryID)
		if existingErr == nil {
			sameFindings := len(existing.FindingIDs) == len(original.FindingIDs)
			for index := range existing.FindingIDs { if !sameFindings || existing.FindingIDs[index] != original.FindingIDs[index] { sameFindings = false; break } }
			if existing.Action != mailtelemetry.AbuseAllowlist || existing.DomainID != original.DomainID || existing.MailboxID != original.MailboxID || existing.Source != original.Source || !sameFindings || existing.EvidenceDigest != mailEdgeDigest(original.EvidenceDigest, payload.ReasonDigest) || existing.ProposedBy != call.PrincipalID || existing.ReasonCode != "false_positive_recovery" || !existing.ExpiresAt.Equal(payload.AllowUntil.UTC()) { return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{}, mailtelemetry.ErrConflict }
			intent = existing
		} else if !errors.Is(existingErr, mailtelemetry.ErrNotFound) {
			return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{}, existingErr
		} else {
			intent, _, err = runtime.abuse.ProposeFalsePositiveRecovery(ctx, actor, actor.TenantID, call.ResourceID, recoveryID, payload.ReasonDigest, payload.AllowUntil.UTC())
		}
	default:
		err = mailtelemetry.ErrInvalid
	}
	if err != nil { return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{}, err }
	projection := abuseIntentProjection(intent)
	return apiserver.EdgeMutation[apiserver.MailAbuseProjection]{OperationID:mailEdgeID(call, "mail-abuse-"+payload.Action), State:string(intent.State), Generation:intent.Revision, Resource:projection}, nil
}

func (edge *mailEdge) RunMailTelemetry(ctx context.Context, interval time.Duration) { if edge == nil || edge.telemetry == nil || ctx == nil || interval < time.Second { return }; edge.ingestMailTelemetry(ctx); ticker := time.NewTicker(interval); defer ticker.Stop(); for { select { case <-ctx.Done(): return; case <-ticker.C: edge.ingestMailTelemetry(ctx) } } }
func (edge *mailEdge) ingestMailTelemetry(ctx context.Context) { runtime := edge.telemetry; if runtime == nil { return }; successful, stored := 0, uint32(0); reason := ""; lastSuccess := time.Time{}; for _, source := range runtime.sources { summary, err := runtime.ingestor.Ingest(ctx, mailtelemetry.IngestQuery{SourceID:source.ID, LineLimit:2500, ByteLimit:8<<20, Duration:2*time.Second}); if err == nil { successful++; stored += summary.Stored; lastSuccess = time.Now().UTC() } else if ctx.Err() == nil { reason = mailTelemetryFailureCode(err) } }; state := "available"; if successful == 0 { state = "unavailable"; if reason == "" { reason = "all_sources_unavailable" } } else if successful < len(runtime.sources) { state = "degraded"; if reason == "" { reason = "partial_source_failure" } }; if stored > 0 { if err := edge.analyzeMailAbuse(ctx); err != nil && ctx.Err() == nil { state, reason = "degraded", mailTelemetryFailureCode(err) } }; if err := edge.expireMailAbuse(ctx); err != nil && ctx.Err() == nil { state, reason = "degraded", mailTelemetryFailureCode(err) }; edge.setTelemetryHealth(state, reason, lastSuccess) }
func (edge *mailEdge) analyzeMailAbuse(ctx context.Context) error { runtime := edge.telemetry; tenants, err := runtime.correlator.Tenants(ctx); if err != nil { return err }; config := mailtelemetry.DefaultAbuseConfig(); now := time.Now().UTC(); for _, tenant := range tenants { actor := mailTelemetrySystemActor(tenant); sink := &telemetryCollectSink{}; query := mailtelemetry.EventQuery{TenantID:tenant, Start:now.Add(-config.Window), End:now.Add(time.Nanosecond), Limit:mailtelemetry.MaximumPageSize}; if _, err = runtime.repository.StreamEvents(ctx, actor, query, mailtelemetry.MaximumAbuseEvents, sink); err != nil { return err }; if len(sink.events) == 0 { continue }; analysis, analysisErr := mailtelemetry.AnalyzeAbuse(sink.events, sink.gaps, config, now); if analysisErr != nil { return analysisErr }; if err = runtime.abuse.PersistAnalysis(ctx, analysis); err != nil { return err } }; return nil }
func (edge *mailEdge) expireMailAbuse(ctx context.Context) error { runtime := edge.telemetry; tenants, err := runtime.correlator.Tenants(ctx); if err != nil { return err }; now := time.Now().UTC(); for _, tenant := range tenants { actor := mailTelemetrySystemActor(tenant); after := ""; for { page, listErr := runtime.repository.ListAbuseIntents(ctx, actor, tenant, after, mailtelemetry.MaximumPageSize); if listErr != nil { return listErr }; for _, intent := range page.Intents { if intent.State == mailtelemetry.IntentApplied && !now.Before(intent.ExpiresAt) { if err = runtime.firewall.expire(ctx, intent); err != nil { return err } } }; if page.NextID == "" { break }; after = page.NextID } }; return nil }
func mailTelemetryFailureCode(err error) string { switch { case errors.Is(err, mailtelemetry.ErrGap): return "source_gap"; case errors.Is(err, mailtelemetry.ErrIntegrity): return "integrity_failure"; case errors.Is(err, mailtelemetry.ErrLimit): return "bounded_limit"; case errors.Is(err, mailtelemetry.ErrProtected): return "protected_source_unavailable"; case errors.Is(err, operations.ErrConflict): return "firewall_authority_conflict"; default: return "source_unavailable" } }

var _ apiserver.MailEdgeService = (*mailEdge)(nil)
var _ mailtelemetry.SourceProtector = (*mailTelemetrySourceProtector)(nil)
var _ mailtelemetry.Correlator = (*mailTelemetryCorrelator)(nil)
var _ mailtelemetry.ArtifactSink = (*mailTelemetryArtifactSink)(nil)
var _ mailtelemetry.FirewallAuthority = (*mailFirewallAuthority)(nil)
