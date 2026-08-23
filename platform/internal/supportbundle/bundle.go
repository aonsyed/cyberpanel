package supportbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
)

type Builder struct {
	Collectors   Collectors
	Fingerprints SecretFingerprintSource
	Signer       Signer
	Clock        func() time.Time
}

type bundleEntry struct {
	name    string
	content []byte
	records uint32
}

type dataset[T any] struct {
	Schema  string `json:"schema"`
	Records []T    `json:"records"`
}

type collectionResult[T any] struct {
	values []T
	err    error
}

func awaitCollection[T any](ctx context.Context, function func(context.Context) ([]T, error)) ([]T, error) {
	result := make(chan collectionResult[T], 1)
	go func() {
		values, err := function(ctx)
		result <- collectionResult[T]{values: values, err: err}
	}()
	select {
	case value := <-result:
		return value.values, value.err
	case <-ctx.Done():
		return nil, errors.Join(ErrLimit, ctx.Err())
	}
}

type valueResult[T any] struct {
	value T
	err   error
}

func awaitValue[T any](ctx context.Context, function func(context.Context) (T, error)) (T, error) {
	result := make(chan valueResult[T], 1)
	go func() {
		value, err := function(ctx)
		result <- valueResult[T]{value: value, err: err}
	}()
	select {
	case value := <-result:
		return value.value, value.err
	case <-ctx.Done():
		var zero T
		return zero, errors.Join(ErrLimit, ctx.Err())
	}
}

func recordBudget(remaining uint32) uint32 {
	if remaining == 0 {
		return 1
	}
	return remaining
}

func stableTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func validVersion(value VersionRecord) bool {
	return value.Component != "" && value.Version != "" && !value.ObservedAt.IsZero() && boundedFields(value.Component, value.Version, value.Build, value.Compatibility)
}

func validHealth(value FunctionalHealthRecord) bool {
	return value.Component != "" && value.Check != "" && value.Status != "" && !value.ObservedAt.IsZero() && boundedFields(value.Component, value.Check, value.Status, value.ReasonCode, value.Summary)
}

func validFinding(value ValidationFinding) bool {
	return value.Code != "" && value.Severity != "" && value.Scope != "" && value.Summary != "" && !value.ObservedAt.IsZero() && boundedFields(value.Code, value.Severity, value.Scope, value.ResourceKind, value.ResourceID, value.Summary)
}

func validFailure(value FailedOperationReceipt) bool {
	return value.OperationID != "" && value.OperationKind != "" && value.FailureCode != "" && !value.FailedAt.IsZero() && (value.ReceiptDigest == "" || validSHA256(value.ReceiptDigest)) && boundedFields(value.OperationID, value.OperationKind, value.ResourceKind, value.ResourceID, value.FailureCode, value.ReceiptDigest)
}

func validCondition(value ResourceCondition) bool {
	return value.ResourceKind != "" && value.ResourceID != "" && value.Type != "" && value.Status != "" && !value.ObservedAt.IsZero() && boundedFields(value.ResourceKind, value.ResourceID, value.Type, value.Status, value.ReasonCode, value.Summary)
}

func validAudit(value AuditContinuityStatus) bool {
	if value.CheckedAt.IsZero() || !validSHA256(value.HeadDigest) || !boundedFields(value.HeadDigest, value.CheckpointReference, value.CheckpointDigest, value.CheckpointKeyID) {
		return false
	}
	if value.CheckpointReference == "" {
		return value.CheckpointDigest == "" && value.CheckpointKeyID == ""
	}
	return validSHA256(value.CheckpointDigest) && value.CheckpointKeyID != ""
}

func sortVersions(values []VersionRecord) {
	sort.SliceStable(values, func(left, right int) bool {
		a, b := values[left], values[right]
		return strings.Join([]string{a.Component, a.Version, a.Build, a.Compatibility, stableTime(a.ObservedAt)}, "\x00") < strings.Join([]string{b.Component, b.Version, b.Build, b.Compatibility, stableTime(b.ObservedAt)}, "\x00")
	})
}

func sortHealth(values []FunctionalHealthRecord) {
	sort.SliceStable(values, func(left, right int) bool {
		a, b := values[left], values[right]
		return strings.Join([]string{a.Component, a.Check, a.Status, a.ReasonCode, a.Summary, stableTime(a.ObservedAt)}, "\x00") < strings.Join([]string{b.Component, b.Check, b.Status, b.ReasonCode, b.Summary, stableTime(b.ObservedAt)}, "\x00")
	})
}

func sortFindings(values []ValidationFinding) {
	sort.SliceStable(values, func(left, right int) bool {
		a, b := values[left], values[right]
		return strings.Join([]string{a.Severity, a.Code, a.Scope, a.ResourceKind, a.ResourceID, a.Summary, stableTime(a.ObservedAt)}, "\x00") < strings.Join([]string{b.Severity, b.Code, b.Scope, b.ResourceKind, b.ResourceID, b.Summary, stableTime(b.ObservedAt)}, "\x00")
	})
}

func sortFailures(values []FailedOperationReceipt) {
	sort.SliceStable(values, func(left, right int) bool {
		a, b := values[left], values[right]
		return strings.Join([]string{stableTime(a.FailedAt), a.OperationID, a.OperationKind, a.ResourceKind, a.ResourceID, a.FailureCode, a.ReceiptDigest}, "\x00") < strings.Join([]string{stableTime(b.FailedAt), b.OperationID, b.OperationKind, b.ResourceKind, b.ResourceID, b.FailureCode, b.ReceiptDigest}, "\x00")
	})
}

func sortConditions(values []ResourceCondition) {
	sort.SliceStable(values, func(left, right int) bool {
		a, b := values[left], values[right]
		return strings.Join([]string{a.ResourceKind, a.ResourceID, a.Type, a.Status, a.ReasonCode, a.Summary, stableTime(a.ObservedAt)}, "\x00") < strings.Join([]string{b.ResourceKind, b.ResourceID, b.Type, b.Status, b.ReasonCode, b.Summary, stableTime(b.ObservedAt)}, "\x00")
	})
}

type buildState struct {
	redactor     *boundaryRedactor
	limits       Limits
	entries      []bundleEntry
	omissions    []Omission
	truncations  []Truncation
	records      uint32
	payloadBytes int64
	audit        AuditContinuityStatus
	auditPresent bool
}

func (state *buildState) omit(name, reason string) {
	state.omissions = append(state.omissions, Omission{Entry: name, Reason: reason})
}

func (state *buildState) canCollect(name string) bool {
	if len(state.entries) >= int(state.limits.MaximumEntries)-1 {
		state.omit(name, "entry_limit")
		return false
	}
	if state.records >= state.limits.MaximumRecords {
		state.omit(name, "record_limit")
		return false
	}
	return true
}

func (state *buildState) appendDataset(name string, records uint32, document func(uint32) any) error {
	requested := records
	remainingRecords := state.limits.MaximumRecords - state.records
	if records > remainingRecords {
		records = remainingRecords
	}
	reserve := int64(128 << 10)
	if reserve > state.limits.MaximumEntryBytes {
		reserve = state.limits.MaximumEntryBytes
	}
	available := state.limits.MaximumUncompressedBytes - state.payloadBytes - reserve
	maximumBytes := state.limits.MaximumEntryBytes
	if available < maximumBytes {
		maximumBytes = available
	}
	if maximumBytes < 128 {
		state.omit(name, "uncompressed_byte_limit")
		return nil
	}
	encode := func(count uint32) ([]byte, error) { return state.redactor.canonicalJSON(document(count)) }
	content, err := encode(records)
	if err != nil {
		return err
	}
	if int64(len(content)) > maximumBytes {
		low, high := uint32(0), records
		var fitted []byte
		for low <= high {
			middle := low + (high-low)/2
			candidate, encodeErr := encode(middle)
			if encodeErr != nil {
				return encodeErr
			}
			if int64(len(candidate)) <= maximumBytes {
				fitted = candidate
				low = middle + 1
			} else {
				if middle == 0 {
					break
				}
				high = middle - 1
			}
		}
		if fitted == nil {
			state.omit(name, "entry_byte_limit")
			return nil
		}
		content = fitted
		records = high
	}
	if requested > records {
		state.truncations = append(state.truncations, Truncation{Entry: name, Included: records, Omitted: requested - records, Reason: "record_or_byte_limit"})
	}
	state.entries = append(state.entries, bundleEntry{name: name, content: content, records: records})
	state.records += records
	state.payloadBytes += int64(len(content))
	return nil
}

func (builder *Builder) now() time.Time {
	if builder.Clock == nil {
		return time.Now().UTC()
	}
	return builder.Clock().UTC()
}

func (builder *Builder) Build(ctx context.Context, request BuildRequest) (Bundle, error) {
	if builder == nil || ctx == nil || builder.Fingerprints == nil || builder.Signer == nil {
		return Bundle{}, ErrInvalid
	}
	limits, err := request.Limits.normalized()
	if err != nil {
		return Bundle{}, err
	}
	scopes, err := normalizeScopes(request.Scopes)
	if err != nil {
		return Bundle{}, err
	}
	expiresIn := request.ExpiresIn
	if expiresIn == 0 {
		expiresIn = DefaultExpiry
	}
	if expiresIn <= 0 || expiresIn > AbsoluteMaximumExpiry {
		return Bundle{}, ErrLimit
	}
	createdAt := builder.now()
	boundedContext, cancel := context.WithTimeout(ctx, limits.MaximumDuration)
	defer cancel()
	redactor, err := awaitValue(boundedContext, func(callContext context.Context) (*boundaryRedactor, error) {
		return newBoundaryRedactor(callContext, builder.Fingerprints)
	})
	if err != nil {
		return Bundle{}, err
	}
	state := &buildState{redactor: redactor, limits: limits}
	collection := CollectionRequest{Scopes: scopes, MaximumRecords: limits.MaximumRecords, Deadline: createdAt.Add(limits.MaximumDuration)}

	if builder.Collectors.Versions == nil {
		state.omit("versions.json", "collector_unavailable")
	} else if state.canCollect("versions.json") {
		values, collectErr := awaitCollection(boundedContext, func(callContext context.Context) ([]VersionRecord, error) { return builder.Collectors.Versions.CollectVersions(callContext, collection) })
		if collectErr != nil && !errors.Is(collectErr, ErrLimit) {
			state.omit("versions.json", "collection_failed")
		} else if collectErr != nil {
			return Bundle{}, collectErr
		} else {
			for index := range values { values[index].ObservedAt = values[index].ObservedAt.UTC(); if !validVersion(values[index]) { return Bundle{}, ErrInvalid } }
			sortVersions(values)
			err = state.appendDataset("versions.json", uint32(len(values)), func(count uint32) any { return dataset[VersionRecord]{Schema: SchemaVersion + ".versions", Records: values[:min(int(count), len(values))]} })
		}
	}
	if err != nil { return Bundle{}, err }

	if builder.Collectors.FunctionalHealth == nil {
		state.omit("functional_health.json", "collector_unavailable")
	} else if state.canCollect("functional_health.json") {
		values, collectErr := awaitCollection(boundedContext, func(callContext context.Context) ([]FunctionalHealthRecord, error) { return builder.Collectors.FunctionalHealth.CollectFunctionalHealth(callContext, collection) })
		if collectErr != nil && !errors.Is(collectErr, ErrLimit) { state.omit("functional_health.json", "collection_failed") } else if collectErr != nil { return Bundle{}, collectErr } else {
			for index := range values { values[index].ObservedAt = values[index].ObservedAt.UTC(); if !validHealth(values[index]) { return Bundle{}, ErrInvalid } }
			sortHealth(values)
			err = state.appendDataset("functional_health.json", uint32(len(values)), func(count uint32) any { return dataset[FunctionalHealthRecord]{Schema: SchemaVersion + ".functional-health", Records: values[:min(int(count), len(values))]} })
		}
	}
	if err != nil { return Bundle{}, err }

	if builder.Collectors.Validation == nil {
		state.omit("validation_findings.json", "collector_unavailable")
	} else if state.canCollect("validation_findings.json") {
		values, collectErr := awaitCollection(boundedContext, func(callContext context.Context) ([]ValidationFinding, error) { return builder.Collectors.Validation.CollectValidationFindings(callContext, collection) })
		if collectErr != nil && !errors.Is(collectErr, ErrLimit) { state.omit("validation_findings.json", "collection_failed") } else if collectErr != nil { return Bundle{}, collectErr } else {
			for index := range values { values[index].ObservedAt = values[index].ObservedAt.UTC(); if !validFinding(values[index]) { return Bundle{}, ErrInvalid } }
			sortFindings(values)
			err = state.appendDataset("validation_findings.json", uint32(len(values)), func(count uint32) any { return dataset[ValidationFinding]{Schema: SchemaVersion + ".validation-findings", Records: values[:min(int(count), len(values))]} })
		}
	}
	if err != nil { return Bundle{}, err }

	if builder.Collectors.FailedOperations == nil {
		state.omit("recent_failed_operation_receipts.json", "collector_unavailable")
	} else if state.canCollect("recent_failed_operation_receipts.json") {
		values, collectErr := awaitCollection(boundedContext, func(callContext context.Context) ([]FailedOperationReceipt, error) { return builder.Collectors.FailedOperations.CollectRecentFailedOperationReceipts(callContext, collection) })
		if collectErr != nil && !errors.Is(collectErr, ErrLimit) { state.omit("recent_failed_operation_receipts.json", "collection_failed") } else if collectErr != nil { return Bundle{}, collectErr } else {
			for index := range values { values[index].FailedAt = values[index].FailedAt.UTC(); if !validFailure(values[index]) { return Bundle{}, ErrInvalid } }
			sortFailures(values)
			err = state.appendDataset("recent_failed_operation_receipts.json", uint32(len(values)), func(count uint32) any { return dataset[FailedOperationReceipt]{Schema: SchemaVersion + ".recent-failed-operation-receipts", Records: values[:min(int(count), len(values))]} })
		}
	}
	if err != nil { return Bundle{}, err }

	if builder.Collectors.ResourceConditions == nil {
		state.omit("resource_conditions.json", "collector_unavailable")
	} else if state.canCollect("resource_conditions.json") {
		values, collectErr := awaitCollection(boundedContext, func(callContext context.Context) ([]ResourceCondition, error) { return builder.Collectors.ResourceConditions.CollectResourceConditions(callContext, collection) })
		if collectErr != nil && !errors.Is(collectErr, ErrLimit) { state.omit("resource_conditions.json", "collection_failed") } else if collectErr != nil { return Bundle{}, collectErr } else {
			for index := range values { values[index].ObservedAt = values[index].ObservedAt.UTC(); if !validCondition(values[index]) { return Bundle{}, ErrInvalid } }
			sortConditions(values)
			err = state.appendDataset("resource_conditions.json", uint32(len(values)), func(count uint32) any { return dataset[ResourceCondition]{Schema: SchemaVersion + ".resource-conditions", Records: values[:min(int(count), len(values))]} })
		}
	}
	if err != nil { return Bundle{}, err }

	if builder.Collectors.AuditContinuity == nil {
		state.omit("audit_continuity.json", "collector_unavailable")
	} else if state.canCollect("audit_continuity.json") {
		value, collectErr := awaitValue(boundedContext, func(callContext context.Context) (AuditContinuityStatus, error) { return builder.Collectors.AuditContinuity.CollectAuditContinuity(callContext, collection) })
		if collectErr != nil && !errors.Is(collectErr, ErrLimit) { state.omit("audit_continuity.json", "collection_failed") } else if collectErr != nil { return Bundle{}, collectErr } else {
			value.CheckedAt = value.CheckedAt.UTC()
			if !validAudit(value) { return Bundle{}, ErrInvalid }
			state.audit, state.auditPresent = value, true
			err = state.appendDataset("audit_continuity.json", 1, func(count uint32) any {
				values := []AuditContinuityStatus{}
				if count == 1 { values = append(values, value) }
				return dataset[AuditContinuityStatus]{Schema: SchemaVersion + ".audit-continuity", Records: values}
			})
		}
	}
	if err != nil { return Bundle{}, err }
	if err = boundedContext.Err(); err != nil { return Bundle{}, errors.Join(ErrLimit, err) }

	sort.Slice(state.omissions, func(left, right int) bool { return state.omissions[left].Entry < state.omissions[right].Entry })
	sort.Slice(state.truncations, func(left, right int) bool { return state.truncations[left].Entry < state.truncations[right].Entry })
	entryMetadata := make([]EntryMetadata, 0, len(state.entries))
	for _, entry := range state.entries {
		digest := sha256.Sum256(entry.content)
		entryMetadata = append(entryMetadata, EntryMetadata{Name: entry.name, SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(entry.content)), Records: entry.records})
	}
	manifest := Manifest{Schema: SchemaVersion, Scopes: scopes, Omissions: state.omissions, Truncations: state.truncations, Entries: entryMetadata, CreatedAt: createdAt, ExpiresAt: createdAt.Add(expiresIn)}
	if state.auditPresent {
		manifest.AuditCheckpointReference = state.audit.CheckpointReference
		manifest.AuditCheckpointDigest = state.audit.CheckpointDigest
		manifest.AuditContinuityVerified = state.audit.Continuous
	}
	commitment := struct {
		Schema string `json:"schema"`; Scopes []Scope `json:"scopes"`; Omissions []Omission `json:"omissions"`; Truncations []Truncation `json:"truncations"`; Entries []EntryMetadata `json:"entries"`; AuditCheckpointReference string `json:"audit_checkpoint_reference,omitempty"`; AuditCheckpointDigest string `json:"audit_checkpoint_digest,omitempty"`; AuditContinuityVerified bool `json:"audit_continuity_verified"`; CreatedAt time.Time `json:"created_at"`; ExpiresAt time.Time `json:"expires_at"`
	}{manifest.Schema, manifest.Scopes, manifest.Omissions, manifest.Truncations, manifest.Entries, manifest.AuditCheckpointReference, manifest.AuditCheckpointDigest, manifest.AuditContinuityVerified, manifest.CreatedAt, manifest.ExpiresAt}
	commitmentJSON, err := redactor.canonicalJSON(commitment)
	if err != nil { return Bundle{}, err }
	digest := sha256.Sum256(commitmentJSON)
	manifest.BundleDigest = hex.EncodeToString(digest[:])
	unsignedJSON, err := redactor.canonicalJSON(manifest)
	if err != nil { return Bundle{}, err }
	if err = json.Unmarshal(unsignedJSON, &manifest); err != nil { return Bundle{}, errors.Join(ErrIntegrity, err) }
	signature, err := awaitValue(boundedContext, func(callContext context.Context) (Signature, error) { return builder.Signer.SignSupportBundle(callContext, manifest.BundleDigest, unsignedJSON) })
	if err != nil { return Bundle{}, err }
	if !validSignature(signature) { return Bundle{}, ErrIntegrity }
	manifest.SignerKeyID, manifest.Signature = signature.KeyID, signature.Value
	manifestJSON, err := redactor.canonicalJSON(manifest)
	if err != nil { return Bundle{}, err }
	var verifiedManifest Manifest
	if json.Unmarshal(manifestJSON, &verifiedManifest) != nil || verifiedManifest.SignerKeyID != signature.KeyID || verifiedManifest.Signature != signature.Value || verifiedManifest.BundleDigest != manifest.BundleDigest {
		return Bundle{}, ErrSecret
	}
	manifest = verifiedManifest
	if int64(len(manifestJSON)) > limits.MaximumEntryBytes { return Bundle{}, ErrLimit }
	state.entries = append(state.entries, bundleEntry{name: "manifest.json", content: manifestJSON})
	content, err := encodeArchive(boundedContext, state.entries, limits)
	if err != nil { return Bundle{}, err }
	archiveDigest := sha256.Sum256(content)
	return Bundle{Manifest: manifest, Content: content, ArchiveSHA256: hex.EncodeToString(archiveDigest[:])}, nil
}

func validSignature(signature Signature) bool {
	if !opaquePattern.MatchString(signature.KeyID) || len(signature.Value) < 16 || len(signature.Value) > 8192 {
		return false
	}
	for _, character := range signature.Value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._~+/=-", character)) {
			return false
		}
	}
	return true
}

type limitWriter struct {
	writer io.Writer
	limit  int64
	count  int64
}

func (writer *limitWriter) Write(content []byte) (int, error) {
	if int64(len(content)) > writer.limit-writer.count {
		return 0, ErrLimit
	}
	written, err := writer.writer.Write(content)
	writer.count += int64(written)
	return written, err
}

func encodeArchive(ctx context.Context, entries []bundleEntry, limits Limits) ([]byte, error) {
	if len(entries) == 0 || len(entries) > int(limits.MaximumEntries) {
		return nil, ErrLimit
	}
	var compressed bytes.Buffer
	compressedLimit := &limitWriter{writer: &compressed, limit: limits.MaximumCompressedBytes}
	gzipWriter, err := gzip.NewWriterLevel(compressedLimit, gzip.BestSpeed)
	if err != nil { return nil, err }
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	uncompressedLimit := &limitWriter{writer: gzipWriter, limit: limits.MaximumUncompressedBytes}
	archive := tar.NewWriter(uncompressedLimit)
	closed := false
	defer func() { if !closed { _ = archive.Close(); _ = gzipWriter.Close() } }()
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if err = ctx.Err(); err != nil { return nil, errors.Join(ErrLimit, err) }
		if _, exists := seen[entry.name]; exists || !strings.HasSuffix(entry.name, ".json") || strings.ContainsAny(entry.name, "/\\\x00") || int64(len(entry.content)) > limits.MaximumEntryBytes || !json.Valid(entry.content) {
			return nil, ErrIntegrity
		}
		seen[entry.name] = struct{}{}
		header := &tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.content)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0).UTC(), AccessTime: time.Unix(0, 0).UTC(), ChangeTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}
		if err = archive.WriteHeader(header); err == nil { _, err = archive.Write(entry.content) }
		if err != nil { return nil, err }
	}
	if err = archive.Close(); err != nil { return nil, err }
	if err = gzipWriter.Close(); err != nil { return nil, err }
	closed = true
	if compressedLimit.count > limits.MaximumCompressedBytes || uncompressedLimit.count > limits.MaximumUncompressedBytes { return nil, ErrLimit }
	return append([]byte(nil), compressed.Bytes()...), nil
}
