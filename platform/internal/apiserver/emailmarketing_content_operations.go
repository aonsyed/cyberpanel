package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	marketing "github.com/aonsyed/cyberpanel/platform/internal/emailmarketing"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

const (
	emailMarketingArtifactMaximumLifetime = 24 * time.Hour
	emailMarketingTemplateBodyMaximum     = int64(1 << 20)
	emailMarketingVerificationHourlyLimit = uint32(60)
)

type MarketingArtifactDescriptor struct {
	ID            string    `json:"id"`
	Handle        string    `json:"handle"`
	TenantID      string    `json:"tenant_id"`
	Kind          string    `json:"kind"`
	Scope         string    `json:"scope"`
	Generation    uint64    `json:"generation"`
	MediaType     string    `json:"media_type"`
	Digest        string    `json:"digest"`
	Bytes         int64     `json:"bytes"`
	PrivacyPolicy string    `json:"privacy_policy"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type MarketingCSVPreviewResult struct {
	ListID        string                     `json:"list_id"`
	ListGeneration uint64                    `json:"list_generation"`
	UploadID      string                     `json:"upload_id"`
	UploadDigest  string                     `json:"upload_digest"`
	HeaderDigest  string                     `json:"header_digest"`
	PreviewBinding string                    `json:"preview_binding"`
	RowsRead      uint64                     `json:"rows_read"`
	ValidRows     uint64                     `json:"valid_rows"`
	InvalidRows   uint64                     `json:"invalid_rows"`
	DuplicateRows uint64                     `json:"duplicate_rows"`
	Truncated     bool                       `json:"truncated"`
	Samples       []marketing.CSVErrorSample `json:"error_samples"`
	Rows          []marketing.CSVPreviewRow  `json:"rows"`
	ExpiresAt     time.Time                  `json:"expires_at"`
}

type MarketingCSVImportResult struct {
	ListID        string                     `json:"list_id"`
	BatchID       string                     `json:"batch_id"`
	HeaderDigest  string                     `json:"header_digest"`
	RowsSeen      uint64                     `json:"rows_seen"`
	RowsCommitted uint64                     `json:"rows_committed"`
	InvalidRows   uint64                     `json:"invalid_rows"`
	DuplicateRows uint64                     `json:"duplicate_rows"`
	Resumed       bool                       `json:"resumed"`
	Completed     bool                       `json:"completed"`
	Samples       []marketing.CSVErrorSample `json:"error_samples"`
}

type MarketingCSVExportResult struct {
	ListID        string                      `json:"list_id"`
	ListGeneration uint64                     `json:"list_generation"`
	Rows          uint64                      `json:"rows"`
	Bytes         int64                       `json:"bytes"`
	Artifact      MarketingArtifactDescriptor `json:"artifact"`
}

type MarketingVerificationJob struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	ListID             string    `json:"list_id"`
	SubscriberID       string    `json:"subscriber_id"`
	State              string    `json:"state"`
	Mode               string    `json:"mode"`
	ProviderRef        string    `json:"provider_ref"`
	Egress             string    `json:"egress"`
	EgressAcknowledged bool      `json:"egress_acknowledged"`
	Provenance         string    `json:"provenance,omitempty"`
	Certainty          string    `json:"certainty"`
	EvidenceDigest     string    `json:"evidence_digest,omitempty"`
	RateRemaining      int64     `json:"rate_remaining"`
	RateReset          time.Time `json:"rate_reset"`
	Applied            bool      `json:"applied"`
	Generation         uint64    `json:"generation"`
	StartedAt          time.Time `json:"started_at"`
	CompletedAt        time.Time `json:"completed_at"`
}

type MarketingTemplateVersionResult struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Lifecycle      string    `json:"state"`
	Generation     uint64    `json:"generation"`
	Version        uint64    `json:"version"`
	VersionDigest  string    `json:"version_digest"`
	TextDigest     string    `json:"text_digest"`
	HTMLDigest     string    `json:"html_digest,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type MarketingTemplatePreviewResult struct {
	TemplateID     string                      `json:"template_id"`
	Generation     uint64                      `json:"generation"`
	Version        uint64                      `json:"version"`
	RequestDigest  string                      `json:"request_digest"`
	TemplateDigest string                      `json:"template_digest"`
	Subject        string                      `json:"subject"`
	From           string                      `json:"from"`
	ReplyTo        string                      `json:"reply_to,omitempty"`
	RenderedAt     time.Time                   `json:"rendered_at"`
	Artifact       MarketingArtifactDescriptor `json:"artifact"`
}

type MarketingTemplateTestSendResult struct {
	TemplateID       string        `json:"template_id"`
	Version          uint64        `json:"version"`
	ProviderRef      string        `json:"provider_ref"`
	Disposition      string        `json:"disposition"`
	ProviderMessageID string       `json:"provider_message_id,omitempty"`
	Reason           string        `json:"reason,omitempty"`
	RetryAfterSeconds uint64       `json:"retry_after_seconds,omitempty"`
	Definitive       bool          `json:"definitive"`
}

type emailMarketingUploadDescriptor struct {
	ID        string
	Digest    string
	Bytes     int64
	ExpiresAt time.Time
}

type emailMarketingArtifactRequest struct {
	ID            string
	TenantID      string
	Kind          string
	Scope         string
	Generation    uint64
	MediaType     string
	PrivacyPolicy string
	MaximumBytes  int64
	ExpiresAt     time.Time
}

type emailMarketingArtifactWriter interface {
	io.Writer
	Commit() (MarketingArtifactDescriptor, error)
	Abort() error
}

type emailMarketingArtifactStore interface {
	OpenUpload(context.Context, string, string, string, int64) (io.ReadCloser, emailMarketingUploadDescriptor, error)
	Create(emailMarketingArtifactRequest) (emailMarketingArtifactWriter, error)
	SealBinding([]byte) string
	OpenBinding(string) ([]byte, error)
}

type emailMarketingLocalArtifactStore struct {
	files *access.FileService
	root  string
	key   []byte
	now   func() time.Time
}

func newEmailMarketingLocalArtifactStore(files *access.FileService, root string, key []byte, now func() time.Time) (*emailMarketingLocalArtifactStore, error) {
	if files == nil || files.Store == nil || files.Executor == nil || !filepath.IsAbs(root) || len(key) < sha256.Size || now == nil {
		return nil, marketing.ErrInvalid
	}
	directory := filepath.Join(root, "artifacts")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, marketing.ErrIntegrity
	}
	return &emailMarketingLocalArtifactStore{files: files, root: directory, key: append([]byte(nil), key...), now: now}, nil
}

func (store *emailMarketingLocalArtifactStore) OpenUpload(ctx context.Context, tenant, actor, handle string, maximum int64) (io.ReadCloser, emailMarketingUploadDescriptor, error) {
	if store == nil || store.files == nil || !safeMailOpaque(handle) || maximum < 1 {
		return nil, emailMarketingUploadDescriptor{}, marketing.ErrInvalid
	}
	session, err := store.files.Store.LoadUpload(ctx, access.UploadID(handle))
	if err != nil {
		return nil, emailMarketingUploadDescriptor{}, marketing.ErrNotFound
	}
	if session.State != access.UploadCommitted || session.Mutation.Actor.TenantID != access.TenantID(tenant) || session.Mutation.Actor.PrincipalID != access.PrincipalID(actor) || !session.ExpiresAt.After(store.now()) {
		return nil, emailMarketingUploadDescriptor{}, marketing.ErrUnauthorized
	}
	if session.Integrity.Validate() != nil || session.Integrity.Size < 1 || session.Integrity.Size > maximum || session.Destination.Validate() != nil {
		return nil, emailMarketingUploadDescriptor{}, marketing.ErrInvalid
	}
	entry, err := store.files.Executor.Stat(ctx, session.Destination)
	if err != nil {
		return nil, emailMarketingUploadDescriptor{}, err
	}
	if entry.Kind != access.EntryRegular || entry.Size != session.Integrity.Size || session.Receipt != "fs-"+entry.ETag {
		return nil, emailMarketingUploadDescriptor{}, marketing.ErrIntegrity
	}
	reader := &emailMarketingUploadReader{ctx: ctx, executor: store.files.Executor, source: session.Destination, etag: entry.ETag, size: entry.Size}
	return reader, emailMarketingUploadDescriptor{ID: handle, Digest: session.Integrity.Digest, Bytes: session.Integrity.Size, ExpiresAt: session.ExpiresAt.UTC()}, nil
}

func (store *emailMarketingLocalArtifactStore) Create(request emailMarketingArtifactRequest) (emailMarketingArtifactWriter, error) {
	if store == nil || store.now == nil {
		return nil, marketing.ErrInvalid
	}
	now := store.now().UTC()
	if !safeMailOpaque(request.ID) || !safeMailOpaque(request.TenantID) || !safeMailOpaque(request.Kind) || !safeMarketingIdentifier(request.Scope) || request.Generation == 0 || request.MediaType == "" || len(request.MediaType) > 128 || strings.ContainsAny(request.MediaType, "\x00\r\n") || !safeMailOpaque(request.PrivacyPolicy) || request.MaximumBytes < 1 || request.MaximumBytes > 1<<30 || !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(emailMarketingArtifactMaximumLifetime)) {
		return nil, marketing.ErrInvalid
	}
	finalPath := filepath.Join(store.root, request.ID+".artifact")
	partialPath := finalPath + ".partial"
	file, err := os.OpenFile(partialPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &emailMarketingLocalArtifactWriter{store: store, request: request, file: file, partialPath: partialPath, finalPath: finalPath, hash: sha256.New(), remaining: request.MaximumBytes}, nil
}

func (store *emailMarketingLocalArtifactStore) SealBinding(raw []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, store.key)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (store *emailMarketingLocalArtifactStore) OpenBinding(binding string) ([]byte, error) {
	if len(binding) < 32 || len(binding) > 8192 || strings.ContainsAny(binding, "\x00\r\n\t ") {
		return nil, marketing.ErrUnauthorized
	}
	parts := strings.Split(binding, ".")
	if len(parts) != 2 {
		return nil, marketing.ErrUnauthorized
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, marketing.ErrUnauthorized
	}
	mac := hmac.New(sha256.New, store.key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, marketing.ErrUnauthorized
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(raw) > 6144 {
		return nil, marketing.ErrUnauthorized
	}
	return raw, nil
}

type emailMarketingUploadReader struct {
	ctx      context.Context
	executor access.FileExecutor
	source   access.FileLocator
	etag     string
	size     int64
	offset   int64
	closed   bool
}

func (reader *emailMarketingUploadReader) Read(buffer []byte) (int, error) {
	if reader.closed {
		return 0, os.ErrClosed
	}
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if reader.offset == reader.size {
		return 0, io.EOF
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	entry, err := reader.executor.Stat(reader.ctx, reader.source)
	if err != nil || entry.Kind != access.EntryRegular || entry.Size != reader.size || entry.ETag != reader.etag {
		return 0, marketing.ErrIntegrity
	}
	length := int64(len(buffer))
	if length > access.MaxUploadChunk {
		length = access.MaxUploadChunk
	}
	if remaining := reader.size - reader.offset; length > remaining {
		length = remaining
	}
	content, integrity, err := reader.executor.ReadRange(reader.ctx, reader.source, reader.offset, length)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(content)
	if int64(len(content)) != length || integrity.Size != length || integrity.Algorithm != "sha256" || integrity.Digest != hex.EncodeToString(sum[:]) {
		clearSecret(content)
		return 0, marketing.ErrIntegrity
	}
	count := copy(buffer, content)
	clearSecret(content)
	reader.offset += int64(count)
	return count, nil
}

func (reader *emailMarketingUploadReader) Close() error {
	reader.closed = true
	return nil
}

type emailMarketingLocalArtifactWriter struct {
	store       *emailMarketingLocalArtifactStore
	request     emailMarketingArtifactRequest
	file        *os.File
	partialPath string
	finalPath   string
	hash        hash.Hash
	remaining   int64
	written     int64
	closed      bool
}

func (writer *emailMarketingLocalArtifactWriter) Write(content []byte) (int, error) {
	if writer.closed || writer.file == nil {
		return 0, os.ErrClosed
	}
	if int64(len(content)) > writer.remaining {
		return 0, marketing.ErrInvalid
	}
	count, err := writer.file.Write(content)
	if count > 0 {
		_, _ = writer.hash.Write(content[:count])
		writer.remaining -= int64(count)
		writer.written += int64(count)
	}
	return count, err
}

func (writer *emailMarketingLocalArtifactWriter) Commit() (MarketingArtifactDescriptor, error) {
	if writer.closed || writer.file == nil || writer.written == 0 {
		return MarketingArtifactDescriptor{}, marketing.ErrInvalid
	}
	if err := writer.file.Sync(); err != nil {
		_ = writer.Abort()
		return MarketingArtifactDescriptor{}, err
	}
	if err := writer.file.Close(); err != nil {
		writer.closed = true
		_ = os.Remove(writer.partialPath)
		return MarketingArtifactDescriptor{}, err
	}
	writer.closed = true
	if err := os.Rename(writer.partialPath, writer.finalPath); err != nil {
		_ = os.Remove(writer.partialPath)
		return MarketingArtifactDescriptor{}, err
	}
	digest := hex.EncodeToString(writer.hash.Sum(nil))
	descriptor := MarketingArtifactDescriptor{ID: writer.request.ID, TenantID: writer.request.TenantID, Kind: writer.request.Kind, Scope: writer.request.Scope, Generation: writer.request.Generation, MediaType: writer.request.MediaType, Digest: digest, Bytes: writer.written, PrivacyPolicy: writer.request.PrivacyPolicy, ExpiresAt: writer.request.ExpiresAt.UTC()}
	raw, _ := json.Marshal(descriptor)
	descriptor.Handle = writer.store.SealBinding(raw)
	return descriptor, nil
}

func (writer *emailMarketingLocalArtifactWriter) Abort() error {
	if !writer.closed && writer.file != nil {
		_ = writer.file.Close()
		writer.closed = true
	}
	err := os.Remove(writer.partialPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type emailMarketingCSVPreviewClaims struct {
	Version        uint8                `json:"version"`
	TenantID       string               `json:"tenant_id"`
	ListID         string               `json:"list_id"`
	ListGeneration uint64               `json:"list_generation"`
	UploadID       string               `json:"upload_id"`
	UploadDigest   string               `json:"upload_digest"`
	UploadBytes    int64                `json:"upload_bytes"`
	HeaderDigest   string               `json:"header_digest"`
	MappingDigest  string               `json:"mapping_digest"`
	ExpiresAt      time.Time            `json:"expires_at"`
}

func (operations *EmailMarketingOperations) ConfigureContentRuntime(files *access.FileService, delivery marketing.DeliveryProvider, masterKey []byte) error {
	if operations == nil || operations.Now == nil || delivery == nil || len(masterKey) != sha256.Size {
		return marketing.ErrInvalid
	}
	artifacts, err := newEmailMarketingLocalArtifactStore(files, operations.ArchiveRoot, deriveEmailMarketingKey(masterKey, "content-artifacts"), operations.Now)
	if err != nil {
		return err
	}
	operations.Artifacts = artifacts
	operations.LocalDelivery = delivery
	operations.DeliveryProviders = make(map[string]marketing.DeliveryProvider)
	operations.VerificationProviders = map[string]EmailMarketingVerificationProvider{"local": &emailMarketingLocalVerificationProvider{resolver: net.DefaultResolver}}
	operations.verificationRates = make(map[marketing.TenantID]emailMarketingVerificationRate)
	return nil
}

func (operations *EmailMarketingOperations) PreviewCSV(ctx context.Context, invocation Invocation, listID marketing.ListID, uploadHandle string, mapping marketing.CSVMapping, previewRows int) (MarketingCSVPreviewResult, error) {
	if operations == nil || operations.Artifacts == nil {
		return MarketingCSVPreviewResult{}, ErrOperationUnavailable
	}
	authorization := operations.authority(invocation, identity.AssurancePassword)
	request := marketing.AuthorizationRequest{TenantID: marketing.TenantID(invocation.Request.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.csv.preview", Resource: string(listID), DataClass: "contact_and_consent"}
	if authorization.Authorize(ctx, request) != nil {
		return MarketingCSVPreviewResult{}, marketing.ErrUnauthorized
	}
	list, err := operations.Repository.GetList(ctx, request.TenantID, listID)
	if err != nil || list.Lifecycle != marketing.LifecycleActive {
		return MarketingCSVPreviewResult{}, errOrConflict(err)
	}
	limits := marketing.DefaultCSVLimits()
	if previewRows > 0 {
		limits.PreviewRows = previewRows
	}
	reader, upload, err := operations.Artifacts.OpenUpload(ctx, invocation.Request.TenantID, invocation.Actor.PrincipalID.String(), uploadHandle, limits.MaxBytes)
	if err != nil {
		return MarketingCSVPreviewResult{}, err
	}
	preview, previewErr := marketing.PreviewCSV(ctx, reader, mapping, limits)
	closeErr := reader.Close()
	if previewErr != nil || closeErr != nil {
		return MarketingCSVPreviewResult{}, errors.Join(previewErr, closeErr)
	}
	expires := upload.ExpiresAt
	if maximum := operations.Now().Add(30 * time.Minute); expires.After(maximum) {
		expires = maximum
	}
	claims := emailMarketingCSVPreviewClaims{Version: 1, TenantID: invocation.Request.TenantID, ListID: string(listID), ListGeneration: list.Generation, UploadID: upload.ID, UploadDigest: upload.Digest, UploadBytes: upload.Bytes, HeaderDigest: preview.HeaderDigest, MappingDigest: digestEmailMarketingValue(mapping), ExpiresAt: expires.UTC()}
	raw, _ := json.Marshal(claims)
	result := MarketingCSVPreviewResult{ListID: string(listID), ListGeneration: list.Generation, UploadID: upload.ID, UploadDigest: upload.Digest, HeaderDigest: preview.HeaderDigest, PreviewBinding: operations.Artifacts.SealBinding(raw), RowsRead: preview.RowsRead, ValidRows: preview.ValidRows, InvalidRows: preview.InvalidRows, DuplicateRows: preview.DuplicateRows, Truncated: preview.Truncated, Samples: preview.Samples, Rows: preview.Rows, ExpiresAt: expires.UTC()}
	if err = operations.auditSink(invocation).RecordAudit(ctx, marketing.AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: "read", EvidenceDigest: digestEmailMarketingValue(claims), OccurredAt: operations.Now()}); err != nil {
		return MarketingCSVPreviewResult{}, err
	}
	return result, nil
}

func (operations *EmailMarketingOperations) ImportCSV(ctx context.Context, invocation Invocation, listID marketing.ListID, uploadHandle, previewBinding string, mapping marketing.CSVMapping, batchID marketing.BatchID, purpose string) (MarketingCSVImportResult, error) {
	if operations == nil || operations.Artifacts == nil {
		return MarketingCSVImportResult{}, ErrOperationUnavailable
	}
	list, err := operations.Repository.GetList(ctx, marketing.TenantID(invocation.Request.TenantID), listID)
	if err != nil || list.Lifecycle != marketing.LifecycleActive {
		return MarketingCSVImportResult{}, errOrConflict(err)
	}
	limits := marketing.DefaultCSVLimits()
	reader, upload, err := operations.Artifacts.OpenUpload(ctx, invocation.Request.TenantID, invocation.Actor.PrincipalID.String(), uploadHandle, limits.MaxBytes)
	if err != nil {
		return MarketingCSVImportResult{}, err
	}
	claims, err := operations.verifyCSVPreviewBinding(previewBinding, list, upload, mapping)
	if err != nil {
		_ = reader.Close()
		return MarketingCSVImportResult{}, err
	}
	preflight, preflightErr := marketing.PreviewCSV(ctx, reader, mapping, limits)
	closeErr := reader.Close()
	if preflightErr != nil || closeErr != nil || preflight.HeaderDigest != claims.HeaderDigest {
		return MarketingCSVImportResult{}, errors.Join(marketing.ErrIntegrity, preflightErr, closeErr)
	}
	reader, reopened, err := operations.Artifacts.OpenUpload(ctx, invocation.Request.TenantID, invocation.Actor.PrincipalID.String(), uploadHandle, limits.MaxBytes)
	if err != nil || reopened != upload {
		if reader != nil {
			_ = reader.Close()
		}
		return MarketingCSVImportResult{}, errors.Join(marketing.ErrIntegrity, err)
	}
	service := marketing.Service{Repository: operations.Repository, Authorizer: operations.authority(invocation, identity.AssuranceMFA), StepUp: operations.authority(invocation, identity.AssuranceMFA), Audit: operations.auditSink(invocation), Now: operations.Now}
	summary, importErr := service.ImportCSV(ctx, marketingAccess(invocation), invocation.Request.RequestID, reader, marketing.CSVImportRequest{TenantID: marketing.TenantID(invocation.Request.TenantID), ListID: listID, BatchID: batchID, Purpose: purpose, Mapping: mapping, Limits: limits, AffirmativeConsent: true}, operations.Repository)
	closeErr = reader.Close()
	if importErr != nil || closeErr != nil {
		return MarketingCSVImportResult{}, errors.Join(importErr, closeErr)
	}
	return MarketingCSVImportResult{ListID: string(listID), BatchID: string(batchID), HeaderDigest: summary.HeaderDigest, RowsSeen: summary.RowsSeen, RowsCommitted: summary.RowsCommitted, InvalidRows: summary.InvalidRows, DuplicateRows: summary.DuplicateRows, Resumed: summary.Resumed, Completed: summary.Completed, Samples: summary.Samples}, nil
}

func (operations *EmailMarketingOperations) verifyCSVPreviewBinding(binding string, list marketing.List, upload emailMarketingUploadDescriptor, mapping marketing.CSVMapping) (emailMarketingCSVPreviewClaims, error) {
	raw, err := operations.Artifacts.OpenBinding(binding)
	if err != nil {
		return emailMarketingCSVPreviewClaims{}, err
	}
	var claims emailMarketingCSVPreviewClaims
	if decodeStrict(raw, &claims) != nil || claims.Version != 1 || claims.TenantID != string(list.TenantID) || claims.ListID != string(list.ID) || claims.ListGeneration != list.Generation || claims.UploadID != upload.ID || claims.UploadDigest != upload.Digest || claims.UploadBytes != upload.Bytes || claims.MappingDigest != digestEmailMarketingValue(mapping) || !claims.ExpiresAt.After(operations.Now()) {
		return emailMarketingCSVPreviewClaims{}, marketing.ErrUnauthorized
	}
	return claims, nil
}

func (operations *EmailMarketingOperations) ExportCSV(ctx context.Context, invocation Invocation, listID marketing.ListID, privacyPolicy, purpose string, retention time.Duration, maximumRows uint64, maximumBytes int64) (MarketingCSVExportResult, error) {
	if operations == nil || operations.Artifacts == nil || retention < time.Hour || retention > emailMarketingArtifactMaximumLifetime {
		return MarketingCSVExportResult{}, marketing.ErrInvalid
	}
	list, err := operations.Repository.GetList(ctx, marketing.TenantID(invocation.Request.TenantID), listID)
	if err != nil || list.Lifecycle == marketing.LifecycleDeleted {
		return MarketingCSVExportResult{}, errOrConflict(err)
	}
	writer, err := operations.Artifacts.Create(emailMarketingArtifactRequest{ID: effectID(invocation) + "_export", TenantID: invocation.Request.TenantID, Kind: "subscriber_export", Scope: string(listID), Generation: list.Generation, MediaType: "text/csv", PrivacyPolicy: privacyPolicy, MaximumBytes: maximumBytes, ExpiresAt: operations.Now().Add(retention)})
	if err != nil {
		return MarketingCSVExportResult{}, err
	}
	service := marketing.Service{Repository: operations.Repository, Authorizer: operations.authority(invocation, identity.AssurancePhishingResistant), StepUp: operations.authority(invocation, identity.AssurancePhishingResistant), Audit: operations.auditSink(invocation), Now: operations.Now}
	summary, exportErr := service.ExportCSV(ctx, marketingAccess(invocation), invocation.Request.RequestID, writer, marketing.CSVExportRequest{TenantID: marketing.TenantID(invocation.Request.TenantID), ListID: listID, MaxRows: maximumRows, MaxBytes: maximumBytes}, operations.Repository)
	if exportErr != nil {
		_ = writer.Abort()
		return MarketingCSVExportResult{}, exportErr
	}
	descriptor, err := writer.Commit()
	if err != nil || descriptor.Bytes != summary.Bytes {
		return MarketingCSVExportResult{}, errors.Join(marketing.ErrIntegrity, err)
	}
	policyEvidence := digestEmailMarketingValue(struct{ Policy, Purpose, Artifact string }{privacyPolicy, purpose, descriptor.Digest})
	if err = operations.auditSink(invocation).RecordAudit(ctx, marketing.AuditRecord{TenantID: marketing.TenantID(invocation.Request.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.csv.export.policy", Resource: string(listID), Outcome: "committed", EvidenceDigest: policyEvidence, OccurredAt: operations.Now()}); err != nil {
		return MarketingCSVExportResult{}, err
	}
	return MarketingCSVExportResult{ListID: string(listID), ListGeneration: list.Generation, Rows: summary.Rows, Bytes: summary.Bytes, Artifact: descriptor}, nil
}

type EmailMarketingVerificationRequest struct {
	TenantID    marketing.TenantID
	ListID      marketing.ListID
	Subscriber  marketing.Subscriber
	ProviderRef string
	EffectID    string
}

type EmailMarketingVerificationProviderResult struct {
	Verification  marketing.Verification
	Egress        string
	Uncertain     bool
	RateRemaining int64
	RateReset     time.Time
}

type EmailMarketingVerificationProvider interface {
	Verify(context.Context, EmailMarketingVerificationRequest) (EmailMarketingVerificationProviderResult, error)
}

type emailMarketingLocalVerificationProvider struct{ resolver interface{ LookupMX(context.Context, string) ([]*net.MX, error) } }

func (provider *emailMarketingLocalVerificationProvider) Verify(ctx context.Context, request EmailMarketingVerificationRequest) (EmailMarketingVerificationProviderResult, error) {
	if provider == nil || provider.resolver == nil || request.ProviderRef != "local" {
		return EmailMarketingVerificationProviderResult{}, marketing.ErrInvalid
	}
	parts := strings.SplitN(request.Subscriber.Address.Normalized, "@", 2)
	if len(parts) != 2 {
		return EmailMarketingVerificationProviderResult{}, marketing.ErrInvalid
	}
	records, err := provider.resolver.LookupMX(ctx, parts[1])
	if err != nil || len(records) == 0 {
		evidence := digestEmailMarketingValue(struct{ Domain, State string }{parts[1], "mx_uncertain"})
		return EmailMarketingVerificationProviderResult{Verification: marketing.Verification{Provenance: marketing.VerificationProvider, Certainty: marketing.CertaintyUnknown, EvidenceDigest: evidence, ProviderRef: "local"}, Egress: "domain_dns", Uncertain: true, RateRemaining: -1}, nil
	}
	values := make([]string, 0, len(records))
	for _, record := range records {
		if record != nil && record.Host != "" {
			values = append(values, strings.ToLower(strings.TrimSuffix(record.Host, ".")))
		}
	}
	if len(values) == 0 {
		return EmailMarketingVerificationProviderResult{}, marketing.ErrIntegrity
	}
	sort.Strings(values)
	evidence := digestEmailMarketingValue(struct{ Domain string; MX []string }{parts[1], values})
	return EmailMarketingVerificationProviderResult{Verification: marketing.Verification{Provenance: marketing.VerificationProvider, Certainty: marketing.CertaintyInferred, EvidenceDigest: evidence, ProviderRef: "local"}, Egress: "domain_dns", RateRemaining: -1}, nil
}

type emailMarketingVerificationRate struct {
	Window time.Time
	Used   uint32
}

func (operations *EmailMarketingOperations) takeVerificationRate(tenant marketing.TenantID, now time.Time) (bool, int64, time.Time) {
	operations.verificationMu.Lock()
	defer operations.verificationMu.Unlock()
	window := now.UTC().Truncate(time.Hour)
	rate := operations.verificationRates[tenant]
	if rate.Window != window {
		rate = emailMarketingVerificationRate{Window: window}
	}
	reset := window.Add(time.Hour)
	if rate.Used >= emailMarketingVerificationHourlyLimit {
		operations.verificationRates[tenant] = rate
		return false, 0, reset
	}
	rate.Used++
	operations.verificationRates[tenant] = rate
	return true, int64(emailMarketingVerificationHourlyLimit - rate.Used), reset
}

func (operations *EmailMarketingOperations) VerifySubscriber(ctx context.Context, invocation Invocation, listID marketing.ListID, subscriberID marketing.SubscriberID, expected uint64, mode, providerRef string, acknowledged bool) (MarketingVerificationJob, error) {
	if operations == nil || operations.Artifacts == nil || operations.verificationRates == nil {
		return MarketingVerificationJob{}, ErrOperationUnavailable
	}
	now := operations.Now().UTC()
	request := marketing.AuthorizationRequest{TenantID: marketing.TenantID(invocation.Request.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.subscriber.verify", Resource: string(subscriberID), DataClass: "contact_and_verification"}
	if operations.authority(invocation, identity.AssuranceMFA).Authorize(ctx, request) != nil {
		return MarketingVerificationJob{}, marketing.ErrUnauthorized
	}
	list, err := operations.Repository.GetList(ctx, request.TenantID, listID)
	if err != nil || list.Lifecycle != marketing.LifecycleActive {
		return MarketingVerificationJob{}, errOrConflict(err)
	}
	subscriber, err := operations.Repository.GetSubscriber(ctx, request.TenantID, subscriberID)
	if err != nil || subscriber.Generation != expected || subscriber.Lifecycle != marketing.LifecycleActive {
		return MarketingVerificationJob{}, errOrConflict(err)
	}
	var membership string
	if err = operations.DB.QueryRowContext(ctx, `SELECT status FROM email_marketing_memberships_v1 WHERE tenant_id=? AND list_id=? AND subscriber_id=?`, request.TenantID, listID, subscriberID).Scan(&membership); err != nil || membership != string(marketing.MembershipSubscribed) {
		return MarketingVerificationJob{}, marketing.ErrUnauthorized
	}
	job := MarketingVerificationJob{ID: effectID(invocation), TenantID: invocation.Request.TenantID, ListID: string(listID), SubscriberID: string(subscriberID), State: "running", Mode: mode, ProviderRef: providerRef, EgressAcknowledged: acknowledged, RateRemaining: -1, Generation: subscriber.Generation, StartedAt: now}
	allowed, remaining, reset := operations.takeVerificationRate(request.TenantID, now)
	job.RateRemaining, job.RateReset = remaining, reset
	if !allowed {
		job.State, job.Certainty, job.CompletedAt = "rate_limited", string(marketing.CertaintyUnknown), now
		if err = operations.auditSink(invocation).RecordAudit(ctx, marketing.AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: "waiting", EvidenceDigest: digestEmailMarketingValue(struct{ State string; Reset time.Time }{job.State, job.RateReset}), OccurredAt: now}); err != nil {
			return MarketingVerificationJob{}, err
		}
		return job, nil
	}
	provider := operations.VerificationProviders[providerRef]
	expectedEgress := "domain_dns"
	if mode == "local" {
		if providerRef != "local" || acknowledged {
			return MarketingVerificationJob{}, marketing.ErrInvalid
		}
	} else if mode == "provider" {
		if providerRef == "local" || !acknowledged {
			return MarketingVerificationJob{}, marketing.ErrUnauthorized
		}
		expectedEgress = "full_address_provider"
	} else {
		return MarketingVerificationJob{}, marketing.ErrInvalid
	}
	if provider == nil {
		return MarketingVerificationJob{}, ErrOperationUnavailable
	}
	providerResult, err := provider.Verify(ctx, EmailMarketingVerificationRequest{TenantID: request.TenantID, ListID: listID, Subscriber: subscriber, ProviderRef: providerRef, EffectID: job.ID})
	if err != nil {
		return MarketingVerificationJob{}, err
	}
	verification := providerResult.Verification
	if verification.Provenance != marketing.VerificationProvider || verification.ProviderRef != providerRef || !validMarketingDigest(verification.EvidenceDigest) || providerResult.Egress != expectedEgress || providerResult.RateRemaining < -1 || verification.Certainty != marketing.CertaintyExact && verification.Certainty != marketing.CertaintyInferred && verification.Certainty != marketing.CertaintyUnknown || providerResult.Uncertain && verification.Certainty != marketing.CertaintyUnknown {
		return MarketingVerificationJob{}, marketing.ErrIntegrity
	}
	job.Egress, job.Provenance, job.Certainty, job.EvidenceDigest = providerResult.Egress, string(verification.Provenance), string(verification.Certainty), verification.EvidenceDigest
	if providerResult.RateRemaining >= 0 {
		job.RateRemaining = providerResult.RateRemaining
	}
	if !providerResult.RateReset.IsZero() {
		job.RateReset = providerResult.RateReset.UTC()
	}
	if providerResult.Uncertain || verification.Certainty == marketing.CertaintyUnknown {
		job.State, job.CompletedAt = "uncertain", operations.Now().UTC()
		if err = operations.auditSink(invocation).RecordAudit(ctx, marketing.AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: "waiting", EvidenceDigest: verification.EvidenceDigest, OccurredAt: job.CompletedAt}); err != nil {
			return MarketingVerificationJob{}, err
		}
		return job, nil
	}
	verifiedAt := operations.Now().UTC()
	verification.VerifiedAt = &verifiedAt
	if subscriber.Verification.Certainty != marketing.CertaintyExact && subscriber.Verification.Provenance != marketing.VerificationDoubleOptIn {
		subscriber.Verification = verification
		subscriber.Generation++
		subscriber.UpdatedAt = verifiedAt
		if err = operations.Repository.PutSubscriber(ctx, subscriber, expected); err != nil {
			return MarketingVerificationJob{}, err
		}
		job.Applied, job.Generation = true, subscriber.Generation
	}
	job.State, job.CompletedAt = "succeeded", verifiedAt
	if err = operations.auditSink(invocation).RecordAudit(ctx, marketing.AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: "committed", EvidenceDigest: verification.EvidenceDigest, OccurredAt: verifiedAt}); err != nil {
		return MarketingVerificationJob{}, err
	}
	return job, nil
}

type EmailMarketingTemplateVersionInput struct {
	ID               marketing.TemplateID
	Name             string
	Subject          string
	From             string
	ReplyTo          string
	TextUploadHandle string
	HTMLUploadHandle string
	Variables        []string
}

func (operations *EmailMarketingOperations) PutTemplateVersion(ctx context.Context, invocation Invocation, input EmailMarketingTemplateVersionInput, expected uint64) (MarketingTemplateVersionResult, error) {
	if operations == nil || operations.Artifacts == nil {
		return MarketingTemplateVersionResult{}, ErrOperationUnavailable
	}
	now := operations.Now().UTC()
	textBody, textUpload, err := operations.readTemplateUpload(ctx, invocation, input.TextUploadHandle, true)
	if err != nil {
		return MarketingTemplateVersionResult{}, err
	}
	htmlBody, htmlUpload, err := operations.readTemplateUpload(ctx, invocation, input.HTMLUploadHandle, false)
	if err != nil {
		return MarketingTemplateVersionResult{}, err
	}
	template := marketing.MessageTemplate{TenantID: marketing.TenantID(invocation.Request.TenantID), ID: input.ID, Name: input.Name, Lifecycle: marketing.TemplateActive, LatestVersion: 1, Generation: 1, CreatedAt: now, UpdatedAt: now}
	if expected > 0 {
		current, loadErr := operations.Repository.GetMessageTemplate(ctx, template.TenantID, template.ID)
		if loadErr != nil || current.Generation != expected || current.Lifecycle != marketing.TemplateActive {
			return MarketingTemplateVersionResult{}, errOrConflict(loadErr)
		}
		template = current
		template.Name, template.LatestVersion, template.Generation, template.UpdatedAt = input.Name, current.LatestVersion+1, expected+1, now
	}
	version := marketing.MessageTemplateVersion{TenantID: template.TenantID, TemplateID: template.ID, Version: template.LatestVersion, Subject: input.Subject, From: input.From, ReplyTo: input.ReplyTo, TextBody: textBody, HTMLBody: htmlBody, Variables: input.Variables, CreatedAt: now}
	service := operations.campaignService(invocation, identity.AssuranceMFA)
	if err = service.PutTemplate(ctx, marketingAccess(invocation), template, expected, &version); err != nil {
		return MarketingTemplateVersionResult{}, err
	}
	return MarketingTemplateVersionResult{ID: string(template.ID), Name: template.Name, Lifecycle: string(template.Lifecycle), Generation: template.Generation, Version: version.Version, VersionDigest: version.Digest, TextDigest: textUpload.Digest, HTMLDigest: htmlUpload.Digest, CreatedAt: template.CreatedAt, UpdatedAt: template.UpdatedAt}, nil
}

func (operations *EmailMarketingOperations) readTemplateUpload(ctx context.Context, invocation Invocation, handle string, required bool) (string, emailMarketingUploadDescriptor, error) {
	if handle == "" && !required {
		return "", emailMarketingUploadDescriptor{}, nil
	}
	reader, upload, err := operations.Artifacts.OpenUpload(ctx, invocation.Request.TenantID, invocation.Actor.PrincipalID.String(), handle, emailMarketingTemplateBodyMaximum)
	if err != nil {
		return "", emailMarketingUploadDescriptor{}, err
	}
	content, readErr := io.ReadAll(io.LimitReader(reader, emailMarketingTemplateBodyMaximum+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || int64(len(content)) != upload.Bytes || !utf8.Valid(content) || strings.IndexByte(string(content), 0) >= 0 || required && len(content) == 0 {
		clearSecret(content)
		return "", emailMarketingUploadDescriptor{}, errors.Join(marketing.ErrInvalid, readErr, closeErr)
	}
	value := string(content)
	clearSecret(content)
	return value, upload, nil
}

func (operations *EmailMarketingOperations) PreviewTemplate(ctx context.Context, invocation Invocation, templateID marketing.TemplateID, expected, version uint64, variables map[string]string, purpose string) (MarketingTemplatePreviewResult, error) {
	if operations == nil || operations.Artifacts == nil {
		return MarketingTemplatePreviewResult{}, ErrOperationUnavailable
	}
	template, err := operations.Repository.GetMessageTemplate(ctx, marketing.TenantID(invocation.Request.TenantID), templateID)
	if err != nil || template.Generation != expected || template.Lifecycle != marketing.TemplateActive || version == 0 || version > template.LatestVersion {
		return MarketingTemplatePreviewResult{}, errOrConflict(err)
	}
	service := operations.campaignService(invocation, identity.AssurancePassword)
	preview, err := service.PreviewTemplate(ctx, marketingAccess(invocation), marketing.TemplateRenderRequest{TenantID: template.TenantID, TemplateID: templateID, TemplateVersion: version, Variables: variables, RequestedBy: marketing.ActorID(invocation.Actor.PrincipalID.String()), RequestedAt: operations.Now(), Purpose: purpose})
	if err != nil {
		return MarketingTemplatePreviewResult{}, err
	}
	writer, err := operations.Artifacts.Create(emailMarketingArtifactRequest{ID: effectID(invocation) + "_preview", TenantID: invocation.Request.TenantID, Kind: "template_preview", Scope: string(templateID), Generation: template.Generation, MediaType: "application/vnd.cyberpanel.template-preview+json", PrivacyPolicy: "message_content_preview", MaximumBytes: 3 << 20, ExpiresAt: operations.Now().Add(15 * time.Minute)})
	if err != nil {
		return MarketingTemplatePreviewResult{}, err
	}
	artifactBody := struct {
		Text string `json:"text"`
		HTML string `json:"html,omitempty"`
	}{preview.TextBody, preview.HTMLBody}
	if err = json.NewEncoder(writer).Encode(artifactBody); err != nil {
		_ = writer.Abort()
		return MarketingTemplatePreviewResult{}, err
	}
	descriptor, err := writer.Commit()
	if err != nil {
		return MarketingTemplatePreviewResult{}, err
	}
	return MarketingTemplatePreviewResult{TemplateID: string(templateID), Generation: template.Generation, Version: version, RequestDigest: preview.RequestDigest, TemplateDigest: preview.TemplateDigest, Subject: preview.Subject, From: preview.From, ReplyTo: preview.ReplyTo, RenderedAt: preview.RenderedAt, Artifact: descriptor}, nil
}

func (operations *EmailMarketingOperations) TestSendTemplate(ctx context.Context, invocation Invocation, templateID marketing.TemplateID, expected, version uint64, variables map[string]string, purpose, recipient, providerRef, verifiedDomain, senderDigest, reason string) (MarketingTemplateTestSendResult, error) {
	if operations == nil || operations.LocalDelivery == nil {
		return MarketingTemplateTestSendResult{}, ErrOperationUnavailable
	}
	template, err := operations.Repository.GetMessageTemplate(ctx, marketing.TenantID(invocation.Request.TenantID), templateID)
	if err != nil || template.Generation != expected || template.Lifecycle != marketing.TemplateActive || version == 0 || version > template.LatestVersion {
		return MarketingTemplateTestSendResult{}, errOrConflict(err)
	}
	profiles := &emailMarketingProfilePolicy{db: operations.DB, now: operations.Now}
	capacity, err := profiles.capacity(ctx, template.TenantID, providerRef)
	if err != nil {
		return MarketingTemplateTestSendResult{}, err
	}
	provider := operations.LocalDelivery
	if capacity.Kind == marketing.CapacityProvider {
		provider = operations.DeliveryProviders[providerRef]
	}
	if provider == nil {
		return MarketingTemplateTestSendResult{}, ErrOperationUnavailable
	}
	provider = emailMarketingBoundDeliveryProvider{DeliveryProvider: provider, idempotencyKey: "test_" + effectID(invocation)}
	service := operations.campaignService(invocation, identity.AssuranceMFA)
	result, err := service.TestSend(ctx, marketingAccess(invocation), marketing.TestSendRequest{RenderRequest: marketing.TemplateRenderRequest{TenantID: template.TenantID, TemplateID: templateID, TemplateVersion: version, Variables: variables, RequestedBy: marketing.ActorID(invocation.Actor.PrincipalID.String()), RequestedAt: operations.Now(), Purpose: purpose}, Recipient: recipient, ProviderRef: providerRef, VerifiedSenderDomain: strings.ToLower(verifiedDomain), SenderVerificationDigest: senderDigest, Reason: reason, StepUpProof: invocation.Request.RequestID}, provider)
	if err != nil {
		return MarketingTemplateTestSendResult{}, err
	}
	retry := uint64(0)
	if result.RetryAfter > 0 {
		retry = uint64(result.RetryAfter / time.Second)
	}
	return MarketingTemplateTestSendResult{TemplateID: string(templateID), Version: version, ProviderRef: providerRef, Disposition: string(result.Disposition), ProviderMessageID: result.ProviderMessageID, Reason: result.Reason, RetryAfterSeconds: retry, Definitive: result.Definitive}, nil
}

func (operations *EmailMarketingOperations) campaignService(invocation Invocation, assurance identity.AssuranceLevel) marketing.CampaignService {
	return marketing.CampaignService{Repository: operations.Repository, Authorizer: operations.authority(invocation, assurance), StepUp: operations.authority(invocation, assurance), Audit: operations.auditSink(invocation), Senders: operations.Policy.Senders, Profiles: &emailMarketingProfilePolicy{db: operations.DB, now: operations.Now}, Now: operations.Now}
}

type emailMarketingProfilePolicy struct {
	db  *sql.DB
	now func() time.Time
}

func (policy *emailMarketingProfilePolicy) AuthorizeCampaignProfile(ctx context.Context, tenant marketing.TenantID, profile string) error {
	_, err := policy.capacity(ctx, tenant, profile)
	return err
}

func (policy *emailMarketingProfilePolicy) capacity(ctx context.Context, tenant marketing.TenantID, profile string) (marketing.CampaignDeliveryCapacity, error) {
	if policy == nil || policy.db == nil || policy.now == nil || !safeMailOpaque(string(tenant)) || !safeMarketingIdentifier(profile) {
		return marketing.CampaignDeliveryCapacity{}, marketing.ErrUnauthorized
	}
	var capacityGeneration uint64
	var capacityDocument, policyDocument []byte
	err := policy.db.QueryRowContext(ctx, `SELECT c.generation,c.document,p.document FROM email_marketing_delivery_capacity_v1 c JOIN email_marketing_tenant_policy_v1 p ON p.tenant_id=c.tenant_id WHERE c.tenant_id=? AND c.profile_ref=?`, tenant, profile).Scan(&capacityGeneration, &capacityDocument, &policyDocument)
	if errors.Is(err, sql.ErrNoRows) {
		return marketing.CampaignDeliveryCapacity{}, marketing.ErrUnauthorized
	}
	if err != nil {
		return marketing.CampaignDeliveryCapacity{}, err
	}
	var capacity marketing.CampaignDeliveryCapacity
	var tenantPolicy marketing.TenantCampaignPolicy
	if json.Unmarshal(capacityDocument, &capacity) != nil || json.Unmarshal(policyDocument, &tenantPolicy) != nil || capacity.TenantID != tenant || capacity.ProfileRef != profile || capacity.Generation != capacityGeneration || tenantPolicy.TenantID != tenant || tenantPolicy.CapacityMaximumAge <= 0 || !capacity.Online || capacity.ObservedAt.Add(tenantPolicy.CapacityMaximumAge).Before(policy.now()) {
		return marketing.CampaignDeliveryCapacity{}, marketing.ErrUnauthorized
	}
	return capacity, nil
}

type emailMarketingBoundDeliveryProvider struct {
	marketing.DeliveryProvider
	idempotencyKey string
}

func (provider emailMarketingBoundDeliveryProvider) Send(ctx context.Context, envelope marketing.DeliveryEnvelope) (marketing.ProviderResult, error) {
	if provider.DeliveryProvider == nil || !safeMailOpaque(provider.idempotencyKey) {
		return marketing.ProviderResult{}, marketing.ErrInvalid
	}
	envelope.IdempotencyKey = provider.idempotencyKey
	return provider.DeliveryProvider.Send(ctx, envelope)
}

func errOrConflict(err error) error {
	if err != nil {
		return err
	}
	return marketing.ErrConflict
}
