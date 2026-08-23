package emailmarketing

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type CSVField string

const (
	CSVEmail           CSVField = "email"
	CSVTags            CSVField = "tags"
	CSVConsentTime     CSVField = "consent_time"
	CSVConsentEvidence CSVField = "consent_evidence"
)

type CSVMapping map[CSVField]string

type CSVLimits struct {
	MaxBytes        int64
	MaxRows         uint64
	MaxFields       int
	MaxFieldBytes   int
	MaxHeaderBytes  int
	MaxErrorSamples int
	PreviewRows     int
	BatchRows       int
}

func DefaultCSVLimits() CSVLimits {
	return CSVLimits{
		MaxBytes:        64 << 20,
		MaxRows:         1_000_000,
		MaxFields:       64,
		MaxFieldBytes:   8 << 10,
		MaxHeaderBytes:  32 << 10,
		MaxErrorSamples: 100,
		PreviewRows:     1_000,
		BatchRows:       500,
	}
}

func (limits CSVLimits) validate() error {
	if limits.MaxBytes < 1 || limits.MaxBytes > 1<<30 || limits.MaxRows < 1 || limits.MaxRows > 10_000_000 ||
		limits.MaxFields < 1 || limits.MaxFields > 256 || limits.MaxFieldBytes < 1 || limits.MaxFieldBytes > 1<<20 ||
		limits.MaxHeaderBytes < 1 || limits.MaxHeaderBytes > 1<<20 || limits.MaxErrorSamples < 0 || limits.MaxErrorSamples > 1_000 ||
		limits.PreviewRows < 1 || limits.PreviewRows > 10_000 || limits.BatchRows < 1 || limits.BatchRows > maxBulkMutations {
		return ErrInvalid
	}
	return nil
}

type CSVErrorSample struct {
	Row    uint64
	Column CSVField
	Code   string
}

type CSVPreviewRow struct {
	Row           uint64
	AddressDigest string
	TagCount      int
}

type CSVPreview struct {
	HeaderDigest string
	RowsRead     uint64
	ValidRows    uint64
	InvalidRows  uint64
	DuplicateRows uint64
	Truncated    bool
	Samples      []CSVErrorSample
	Rows         []CSVPreviewRow
}

func PreviewCSV(ctx context.Context, input io.Reader, mapping CSVMapping, limits CSVLimits) (CSVPreview, error) {
	reader, indexes, headerDigest, err := newCSVReader(input, mapping, limits)
	if err != nil {
		return CSVPreview{}, err
	}
	result := CSVPreview{HeaderDigest: headerDigest, Rows: make([]CSVPreviewRow, 0, limits.PreviewRows)}
	seen := make(map[string]struct{}, limits.PreviewRows)
	for result.RowsRead < uint64(limits.PreviewRows) {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			return result, nil
		}
		if readErr != nil {
			return result, fmt.Errorf("emailmarketing: CSV row %d: %w", result.RowsRead+2, readErr)
		}
		result.RowsRead++
		parsed, sample := parseCSVRecord(record, result.RowsRead+1, indexes, limits)
		if sample.Code != "" {
			result.InvalidRows++
			appendCSVSample(&result.Samples, sample, limits.MaxErrorSamples)
			continue
		}
		if _, duplicate := seen[parsed.Address.Digest]; duplicate {
			result.DuplicateRows++
			continue
		}
		seen[parsed.Address.Digest] = struct{}{}
		result.ValidRows++
		result.Rows = append(result.Rows, CSVPreviewRow{Row: result.RowsRead + 1, AddressDigest: parsed.Address.Digest, TagCount: len(parsed.Tags)})
	}
	result.Truncated = true
	return result, nil
}

type CSVImportRepository interface {
	GetImportCheckpoint(context.Context, TenantID, ListID, BatchID) (ImportCheckpoint, error)
	ApplyImportBatch(context.Context, uint64, []BulkMutation, ImportCheckpoint) (bool, error)
}

type CSVImporter struct {
	Repository CSVImportRepository
	Now        func() time.Time
}

type CSVImportRequest struct {
	TenantID          TenantID
	ListID            ListID
	BatchID           BatchID
	ActorID           ActorID
	Purpose           string
	Mapping           CSVMapping
	Limits            CSVLimits
	AffirmativeConsent bool
}

type CSVImportSummary struct {
	HeaderDigest  string
	RowsSeen      uint64
	RowsCommitted uint64
	InvalidRows   uint64
	DuplicateRows uint64
	Resumed       bool
	Completed     bool
	Samples       []CSVErrorSample
}

func (importer CSVImporter) Import(ctx context.Context, input io.Reader, request CSVImportRequest) (CSVImportSummary, error) {
	if importer.Repository == nil || importer.Now == nil || validateImportRequest(request) != nil {
		return CSVImportSummary{}, ErrInvalid
	}
	reader, indexes, headerDigest, err := newCSVReader(input, request.Mapping, request.Limits)
	if err != nil {
		return CSVImportSummary{}, err
	}
	if request.AffirmativeConsent && (indexes[CSVConsentTime] < 0 || indexes[CSVConsentEvidence] < 0) {
		return CSVImportSummary{}, errors.New("emailmarketing: affirmative CSV consent requires time and evidence mappings")
	}
	summary := CSVImportSummary{HeaderDigest: headerDigest}
	checkpoint, err := importer.Repository.GetImportCheckpoint(ctx, request.TenantID, request.ListID, request.BatchID)
	if err == nil {
		if checkpoint.HeaderDigest != headerDigest {
			return summary, ErrIntegrity
		}
		summary.Resumed = true
		if checkpoint.Completed {
			summary.RowsSeen, summary.RowsCommitted, summary.Completed = checkpoint.RowsSeen, checkpoint.RowsCommitted, true
			return summary, nil
		}
	} else if !errors.Is(err, ErrNotFound) {
		return summary, err
	} else {
		checkpoint = ImportCheckpoint{TenantID: request.TenantID, ListID: request.ListID, BatchID: request.BatchID, HeaderDigest: headerDigest}
	}
	prefix := sha256.New()
	batch := make([]BulkMutation, 0, request.Limits.BatchRows)
	batchIndex := checkpoint.BatchIndex
	committed := checkpoint.RowsCommitted
	seenInBatch := make(map[string]struct{}, request.Limits.BatchRows)
	for {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			if summary.RowsSeen < checkpoint.RowsSeen {
				return summary, ErrIntegrity
			}
			now := importer.Now().UTC()
			next := ImportCheckpoint{TenantID: request.TenantID, ListID: request.ListID, BatchID: request.BatchID, BatchIndex: batchIndex + 1, HeaderDigest: headerDigest, RowsSeen: summary.RowsSeen, RowsCommitted: committed + uint64(len(batch)), PrefixDigest: hex.EncodeToString(prefix.Sum(nil)), Completed: true, UpdatedAt: now}
			if _, err := importer.Repository.ApplyImportBatch(ctx, committed, batch, next); err != nil {
				return summary, err
			}
			summary.RowsCommitted, summary.Completed = next.RowsCommitted, true
			return summary, nil
		}
		if readErr != nil {
			return summary, fmt.Errorf("emailmarketing: CSV row %d: %w", summary.RowsSeen+2, readErr)
		}
		summary.RowsSeen++
		if summary.RowsSeen > request.Limits.MaxRows {
			return summary, errors.New("emailmarketing: CSV row limit exceeded")
		}
		writeCanonicalRecord(prefix, record)
		if summary.RowsSeen <= checkpoint.RowsSeen {
			if summary.RowsSeen == checkpoint.RowsSeen && hex.EncodeToString(prefix.Sum(nil)) != checkpoint.PrefixDigest {
				return summary, ErrIntegrity
			}
			continue
		}
		parsed, sample := parseCSVRecord(record, summary.RowsSeen+1, indexes, request.Limits)
		if sample.Code != "" {
			summary.InvalidRows++
			appendCSVSample(&summary.Samples, sample, request.Limits.MaxErrorSamples)
		} else if _, duplicate := seenInBatch[parsed.Address.Digest]; duplicate {
			summary.DuplicateRows++
		} else {
			seenInBatch[parsed.Address.Digest] = struct{}{}
			mutation, mutationErr := csvMutation(request, parsed, summary.RowsSeen, importer.Now().UTC())
			if mutationErr != nil {
				summary.InvalidRows++
				appendCSVSample(&summary.Samples, CSVErrorSample{Row: summary.RowsSeen + 1, Code: "invalid_consent"}, request.Limits.MaxErrorSamples)
			} else {
				batch = append(batch, mutation)
			}
		}
		if len(batch) < request.Limits.BatchRows {
			continue
		}
		now := importer.Now().UTC()
		batchIndex++
		next := ImportCheckpoint{TenantID: request.TenantID, ListID: request.ListID, BatchID: request.BatchID, BatchIndex: batchIndex, HeaderDigest: headerDigest, RowsSeen: summary.RowsSeen, RowsCommitted: committed + uint64(len(batch)), PrefixDigest: hex.EncodeToString(prefix.Sum(nil)), UpdatedAt: now}
		if _, err := importer.Repository.ApplyImportBatch(ctx, committed, batch, next); err != nil {
			return summary, err
		}
		committed = next.RowsCommitted
		batch = batch[:0]
		seenInBatch = make(map[string]struct{}, request.Limits.BatchRows)
	}
}

type CSVExportRepository interface {
	ListSubscribers(context.Context, TenantID, ListID, string, int) (SubscriberPage, error)
	LatestConsent(context.Context, TenantID, ListID, SubscriberID) (ConsentRecord, error)
	ActiveSuppressions(context.Context, TenantID, string) ([]SuppressionRecord, error)
}

type CSVExporter struct{ Repository CSVExportRepository }

type CSVExportRequest struct {
	TenantID TenantID
	ListID   ListID
	MaxRows  uint64
	MaxBytes int64
}

type CSVExportSummary struct {
	Rows  uint64
	Bytes int64
}

func (exporter CSVExporter) Export(ctx context.Context, output io.Writer, request CSVExportRequest) (CSVExportSummary, error) {
	if exporter.Repository == nil || output == nil || validateIdentifier(string(request.TenantID)) != nil || validateIdentifier(string(request.ListID)) != nil || request.MaxRows < 1 || request.MaxRows > 10_000_000 || request.MaxBytes < 1 || request.MaxBytes > 1<<30 {
		return CSVExportSummary{}, ErrInvalid
	}
	bounded := &boundedWriter{writer: output, remaining: request.MaxBytes}
	writer := csv.NewWriter(bounded)
	header := []string{"email", "subscriber_id", "tag_ids", "verification_provenance", "verification_certainty", "verification_evidence_digest", "consent_source", "consent_time", "consent_evidence_digest", "suppression"}
	if err := writer.Write(header); err != nil {
		return CSVExportSummary{}, err
	}
	var summary CSVExportSummary
	var cursor string
	for summary.Rows < request.MaxRows {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		limit := maxPageSize
		if remaining := request.MaxRows - summary.Rows; remaining < uint64(limit) {
			limit = int(remaining)
		}
		page, err := exporter.Repository.ListSubscribers(ctx, request.TenantID, request.ListID, cursor, limit)
		if err != nil {
			return summary, err
		}
		if len(page.Subscribers) == 0 {
			break
		}
		for _, subscriber := range page.Subscribers {
			consent, consentErr := exporter.Repository.LatestConsent(ctx, request.TenantID, request.ListID, subscriber.ID)
			if consentErr != nil && !errors.Is(consentErr, ErrNotFound) {
				return summary, consentErr
			}
			suppressions, err := exporter.Repository.ActiveSuppressions(ctx, request.TenantID, subscriber.Address.Digest)
			if err != nil {
				return summary, err
			}
			tags := make([]string, len(subscriber.TagIDs))
			for i := range subscriber.TagIDs {
				tags[i] = string(subscriber.TagIDs[i])
			}
			row := []string{subscriber.Address.Normalized, string(subscriber.ID), strings.Join(tags, ";"), string(subscriber.Verification.Provenance), string(subscriber.Verification.Certainty), subscriber.Verification.EvidenceDigest, string(consent.Source), optionalCSVTime(consent.CapturedAt), consent.EvidenceDigest, suppressionProjection(suppressions)}
			if err := writer.Write(row); err != nil {
				return summary, err
			}
			summary.Rows++
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return summary, err
		}
		if page.NextDigest == "" || page.NextDigest == cursor {
			return summary, ErrIntegrity
		}
		cursor = page.NextDigest
		if len(page.Subscribers) < limit {
			break
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return summary, err
	}
	summary.Bytes = bounded.written
	return summary, nil
}

type csvIndexes map[CSVField]int

type parsedCSVRow struct {
	Address         AddressIdentity
	Tags            []TagID
	ConsentTime     time.Time
	ConsentEvidence string
}

func newCSVReader(input io.Reader, mapping CSVMapping, limits CSVLimits) (*csv.Reader, csvIndexes, string, error) {
	if input == nil || limits.validate() != nil {
		return nil, nil, "", ErrInvalid
	}
	limited := &boundedReader{reader: input, remaining: limits.MaxBytes}
	reader := csv.NewReader(limited)
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true
	header, err := reader.Read()
	if err != nil {
		return nil, nil, "", fmt.Errorf("emailmarketing: CSV header: %w", err)
	}
	if len(header) == 0 || len(header) > limits.MaxFields {
		return nil, nil, "", errors.New("emailmarketing: invalid CSV header field count")
	}
	header[0] = strings.TrimPrefix(header[0], "\ufeff")
	totalBytes := 0
	positions := make(map[string]int, len(header))
	for index, name := range header {
		totalBytes += len(name)
		if name == "" || !utf8.ValidString(name) || len(name) > limits.MaxFieldBytes {
			return nil, nil, "", errors.New("emailmarketing: invalid CSV header")
		}
		if _, duplicate := positions[name]; duplicate {
			return nil, nil, "", errors.New("emailmarketing: duplicate CSV header")
		}
		positions[name] = index
	}
	if totalBytes > limits.MaxHeaderBytes {
		return nil, nil, "", errors.New("emailmarketing: CSV header too large")
	}
	indexes := csvIndexes{CSVEmail: -1, CSVTags: -1, CSVConsentTime: -1, CSVConsentEvidence: -1}
	usedColumns := make(map[int]struct{}, len(mapping))
	for field, name := range mapping {
		switch field {
		case CSVEmail, CSVTags, CSVConsentTime, CSVConsentEvidence:
		default:
			return nil, nil, "", errors.New("emailmarketing: unknown CSV mapping field")
		}
		index, ok := positions[name]
		if !ok {
			return nil, nil, "", fmt.Errorf("emailmarketing: mapped header %q not found", name)
		}
		if _, duplicate := usedColumns[index]; duplicate {
			return nil, nil, "", errors.New("emailmarketing: a CSV column cannot map to multiple fields")
		}
		usedColumns[index] = struct{}{}
		indexes[field] = index
	}
	if indexes[CSVEmail] < 0 {
		return nil, nil, "", errors.New("emailmarketing: email mapping is required")
	}
	reader.FieldsPerRecord = len(header)
	hasher := sha256.New()
	writeCanonicalRecord(hasher, header)
	return reader, indexes, hex.EncodeToString(hasher.Sum(nil)), nil
}

func parseCSVRecord(record []string, row uint64, indexes csvIndexes, limits CSVLimits) (parsedCSVRow, CSVErrorSample) {
	for _, value := range record {
		if !utf8.ValidString(value) || len(value) > limits.MaxFieldBytes {
			return parsedCSVRow{}, CSVErrorSample{Row: row, Code: "invalid_encoding_or_field_size"}
		}
	}
	identity, err := NormalizeAddress(record[indexes[CSVEmail]])
	if err != nil {
		return parsedCSVRow{}, CSVErrorSample{Row: row, Column: CSVEmail, Code: "invalid_email"}
	}
	parsed := parsedCSVRow{Address: identity}
	if index := indexes[CSVTags]; index >= 0 && strings.TrimSpace(record[index]) != "" {
		parts := strings.Split(record[index], ";")
		parsed.Tags = make([]TagID, 0, len(parts))
		for _, part := range parts {
			parsed.Tags = append(parsed.Tags, TagID(strings.TrimSpace(part)))
		}
		parsed.Tags, err = normalizeTags(parsed.Tags)
		if err != nil {
			return parsedCSVRow{}, CSVErrorSample{Row: row, Column: CSVTags, Code: "invalid_tags"}
		}
	}
	if index := indexes[CSVConsentTime]; index >= 0 && strings.TrimSpace(record[index]) != "" {
		parsed.ConsentTime, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(record[index]))
		if err != nil {
			return parsedCSVRow{}, CSVErrorSample{Row: row, Column: CSVConsentTime, Code: "invalid_consent_time"}
		}
	}
	if index := indexes[CSVConsentEvidence]; index >= 0 && record[index] != "" {
		parsed.ConsentEvidence = DigestEvidence([]byte(record[index]))
	}
	return parsed, CSVErrorSample{}
}

func csvMutation(request CSVImportRequest, parsed parsedCSVRow, row uint64, now time.Time) (BulkMutation, error) {
	subscriberID := SubscriberID("sub:" + parsed.Address.Digest[:40])
	subscriber := Subscriber{TenantID: request.TenantID, ID: subscriberID, Address: parsed.Address, Verification: Verification{Provenance: VerificationMigrated, Certainty: CertaintyInferred}, TagIDs: parsed.Tags, Lifecycle: LifecycleActive, Generation: 1, CreatedAt: now, UpdatedAt: now}
	membership := Membership{TenantID: request.TenantID, ListID: request.ListID, SubscriberID: subscriberID, Status: MembershipSubscribed, Generation: 1, CreatedAt: now, UpdatedAt: now}
	mutation := BulkMutation{Subscriber: subscriber, Membership: membership}
	if request.AffirmativeConsent {
		if parsed.ConsentTime.IsZero() || parsed.ConsentEvidence == "" || parsed.ConsentTime.After(now.Add(5*time.Minute)) {
			return BulkMutation{}, ErrInvalid
		}
		idDigest := DigestEvidence([]byte(string(request.TenantID) + "\x00" + string(request.ListID) + "\x00" + string(request.BatchID) + "\x00" + strconv.FormatUint(row, 10)))
		consent := ConsentRecord{ID: "cons:" + idDigest[:40], TenantID: request.TenantID, ListID: request.ListID, SubscriberID: subscriberID, Source: ConsentCSV, Purpose: request.Purpose, Affirmative: true, CapturedAt: parsed.ConsentTime.UTC(), RecordedAt: now, EvidenceDigest: parsed.ConsentEvidence, EvidenceRef: "csv:" + string(request.BatchID), Verification: Verification{Provenance: VerificationMigrated, Certainty: CertaintyInferred, EvidenceDigest: parsed.ConsentEvidence}, ActorID: request.ActorID}
		mutation.Consent = &consent
	}
	return mutation, nil
}

func validateImportRequest(request CSVImportRequest) error {
	if validateIdentifier(string(request.TenantID)) != nil || validateIdentifier(string(request.ListID)) != nil || validateIdentifier(string(request.BatchID)) != nil || validateIdentifier(string(request.ActorID)) != nil || request.Purpose == "" || len(request.Purpose) > maxPurposeBytes || request.Limits.validate() != nil {
		return ErrInvalid
	}
	return nil
}

func writeCanonicalRecord(hasher hash.Hash, record []string) {
	var size [8]byte
	for _, value := range record {
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		hasher.Write(size[:])
		hasher.Write([]byte(value))
	}
}

func appendCSVSample(samples *[]CSVErrorSample, sample CSVErrorSample, limit int) {
	if len(*samples) < limit {
		*samples = append(*samples, sample)
	}
}

func optionalCSVTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func suppressionProjection(records []SuppressionRecord) string {
	values := make([]string, 0, len(records))
	for _, record := range records {
		values = append(values, string(record.Scope)+":"+string(record.Reason)+":"+record.OccurredAt.UTC().Format(time.RFC3339Nano))
	}
	sort.Strings(values)
	return strings.Join(values, ";")
}

type boundedReader struct {
	reader    io.Reader
	remaining int64
}

func (reader *boundedReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if reader.remaining < 0 {
		return 0, errors.New("emailmarketing: CSV byte limit exceeded")
	}
	if reader.remaining == 0 {
		n, err := reader.reader.Read(buffer[:1])
		if n > 0 {
			return n, errors.New("emailmarketing: CSV byte limit exceeded")
		}
		return n, err
	}
	if int64(len(buffer)) > reader.remaining+1 {
		buffer = buffer[:reader.remaining+1]
	}
	n, err := reader.reader.Read(buffer)
	reader.remaining -= int64(n)
	if reader.remaining < 0 {
		return n, errors.New("emailmarketing: CSV byte limit exceeded")
	}
	return n, err
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
	written   int64
}

func (writer *boundedWriter) Write(buffer []byte) (int, error) {
	if int64(len(buffer)) > writer.remaining {
		return 0, errors.New("emailmarketing: CSV export byte limit exceeded")
	}
	n, err := writer.writer.Write(buffer)
	writer.remaining -= int64(n)
	writer.written += int64(n)
	return n, err
}
