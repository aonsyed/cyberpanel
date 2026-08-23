//go:build linux

package integrations

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	s3StorageMaximumObjectBytes  int64  = 5 << 40
	s3StorageMinimumPartBytes    int64  = 5 << 20
	s3StoragePreferredPartBytes  int64  = 8 << 20
	s3StorageMaximumPartBytes    int64  = 5 << 30
	s3StorageMaximumRangeBytes   int64  = 64 << 20
	s3StorageMaximumParts        uint32 = 10000
	s3StorageMaximumListResponse int64  = 8 << 20
	s3StorageMaximumXMLResponse  int64  = 1 << 20
	s3StorageMaximumResponse     int64  = 64 << 10
)

type s3StorageListResult struct {
	XMLName              xml.Name               `xml:"ListBucketResult"`
	Name                 string                 `xml:"Name"`
	Prefix               string                 `xml:"Prefix"`
	KeyCount             int                    `xml:"KeyCount"`
	MaxKeys              int                    `xml:"MaxKeys"`
	IsTruncated          bool                   `xml:"IsTruncated"`
	NextContinuationToken string                `xml:"NextContinuationToken"`
	Contents             []s3StorageListObject  `xml:"Contents"`
}

type s3StorageListObject struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

type s3StorageMultipartStarted struct {
	XMLName xml.Name `xml:"InitiateMultipartUploadResult"`
	Bucket  string   `xml:"Bucket"`
	Key     string   `xml:"Key"`
	UploadID string  `xml:"UploadId"`
}

type s3StorageMultipartCompleted struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
	VersionID string  `xml:"VersionId"`
}

type s3StorageErrorDocument struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
}

type s3StorageRetention struct {
	XMLName        xml.Name `xml:"Retention"`
	XMLNS          string   `xml:"xmlns,attr,omitempty"`
	Mode           string   `xml:"Mode"`
	RetainUntilDate string  `xml:"RetainUntilDate"`
}

func (adapter *RemoteProviderAdapter) ListObjects(ctx context.Context, binding ProviderBinding, storage StorageBinding, prefix ObjectKey, page PageRequest) ([]ObjectMetadata, string, error) {
	if page.Validate() != nil || !validS3StorageCursor(page.Cursor) {
		return nil, "", ErrInvalid
	}
	physicalPrefix, err := s3StoragePhysicalKey(storage, prefix)
	if err != nil {
		return nil, "", err
	}
	credential, cleanup, err := adapter.s3StorageCredential(ctx, binding, storage, CapabilityObjectList, CapabilityObjectChecksum)
	if err != nil {
		return nil, "", err
	}
	defer func() { credential = s3Credential{}; cleanup() }()
	query := url.Values{
		"list-type": []string{"2"},
		"max-keys":  []string{strconv.FormatUint(uint64(page.Limit), 10)},
		"prefix":    []string{physicalPrefix},
	}
	if page.Cursor != "" {
		query.Set("continuation-token", page.Cursor)
	}
	response, err := adapter.s3StorageRequest(ctx, storage, credential, "s3.list_objects", http.MethodGet, "", query, nil, nil)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "", s3StorageResponseError("s3.list_objects", response)
	}
	raw, err := readS3StorageResponse(response, s3StorageMaximumListResponse)
	if err != nil {
		return nil, "", err
	}
	var document s3StorageListResult
	if decodeS3StorageXML(raw, &document) != nil || document.XMLName.Local != "ListBucketResult" || document.Name != storage.Bucket || document.Prefix != physicalPrefix || document.KeyCount != len(document.Contents) || document.MaxKeys != int(page.Limit) || len(document.Contents) > int(page.Limit) {
		return nil, "", ErrIntegrity
	}
	if document.IsTruncated != (document.NextContinuationToken != "") || !validS3StorageCursor(document.NextContinuationToken) {
		return nil, "", ErrIntegrity
	}
	objects := make([]ObjectMetadata, 0, len(document.Contents))
	for _, listed := range document.Contents {
		key, keyErr := s3StorageLogicalKey(storage, listed.Key)
		listedETag, etagOK := normalizeS3StorageETag(listed.ETag)
		modified, timeErr := time.Parse(time.RFC3339Nano, listed.LastModified)
		if keyErr != nil || !strings.HasPrefix(listed.Key, physicalPrefix) || listed.Size < 0 || listed.Size > s3StorageMaximumObjectBytes || !etagOK || timeErr != nil {
			return nil, "", ErrIntegrity
		}
		metadata, statErr := adapter.s3StorageStat(ctx, storage, credential, key)
		if statErr != nil {
			return nil, "", statErr
		}
		if metadata.Size != listed.Size || metadata.ETag != listedETag || !metadata.ModifiedAt.Equal(modified.UTC()) {
			return nil, "", ErrConflict
		}
		objects = append(objects, metadata)
	}
	return objects, document.NextContinuationToken, nil
}

func (adapter *RemoteProviderAdapter) StatObject(ctx context.Context, binding ProviderBinding, storage StorageBinding, key ObjectKey) (ObjectMetadata, error) {
	credential, cleanup, err := adapter.s3StorageCredential(ctx, binding, storage, CapabilityObjectList, CapabilityObjectChecksum)
	if err != nil {
		return ObjectMetadata{}, err
	}
	defer func() { credential = s3Credential{}; cleanup() }()
	return adapter.s3StorageStat(ctx, storage, credential, key)
}

func (adapter *RemoteProviderAdapter) BeginUpload(ctx context.Context, binding ProviderBinding, storage StorageBinding, key ObjectKey, size int64, digest string, effect EffectID) (MultipartSession, error) {
	if size <= 0 || size > s3StorageMaximumObjectBytes || !validDigest(digest) || !validID(string(effect)) {
		return MultipartSession{}, ErrInvalid
	}
	physicalKey, err := s3StoragePhysicalKey(storage, key)
	if err != nil {
		return MultipartSession{}, err
	}
	partSize, err := s3StoragePartSize(size)
	if err != nil {
		return MultipartSession{}, err
	}
	credential, cleanup, err := adapter.s3StorageCredential(ctx, binding, storage, CapabilityObjectMultipart, CapabilityObjectResume, CapabilityObjectChecksum)
	if err != nil {
		return MultipartSession{}, err
	}
	defer func() { credential = s3Credential{}; cleanup() }()
	headers := http.Header{
		"Content-Type":             []string{"application/octet-stream"},
		"X-Amz-Checksum-Algorithm": []string{"SHA256"},
		"X-Amz-Meta-Effect-Id":     []string{string(effect)},
		"X-Amz-Meta-Sha256":        []string{digest},
		"X-Amz-Meta-Size":          []string{strconv.FormatInt(size, 10)},
	}
	response, err := adapter.s3StorageRequest(ctx, storage, credential, "s3.begin_multipart", http.MethodPost, physicalKey, url.Values{"uploads": []string{""}}, nil, headers)
	if err != nil {
		return MultipartSession{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return MultipartSession{}, s3StorageResponseError("s3.begin_multipart", response)
	}
	raw, err := readS3StorageResponse(response, s3StorageMaximumXMLResponse)
	if err != nil {
		return MultipartSession{}, err
	}
	var document s3StorageMultipartStarted
	if decodeS3StorageXML(raw, &document) != nil || document.XMLName.Local != "InitiateMultipartUploadResult" || document.Bucket != storage.Bucket || document.Key != physicalKey || !validS3StorageOpaque(document.UploadID, 4096) {
		return MultipartSession{}, ErrIntegrity
	}
	now := adapter.now()
	session := MultipartSession{
		ID:        s3StorageSessionID(binding, storage, key, document.UploadID, digest, size),
		Key:       key,
		UploadID:  document.UploadID,
		PartSize:  partSize,
		ExpiresAt: now.Add(24 * time.Hour),
	}
	if _, _, err = validateS3StorageSession(binding, storage, session); err != nil {
		return MultipartSession{}, ErrIntegrity
	}
	return session, nil
}

func (adapter *RemoteProviderAdapter) UploadPart(ctx context.Context, binding ProviderBinding, storage StorageBinding, session MultipartSession, number uint32, data []byte, digest string) (UploadedPart, error) {
	expectedDigest, expectedSize, err := validateS3StorageSession(binding, storage, session)
	if err != nil || session.ExpiresAt.Before(adapter.now()) || number == 0 || number > s3StorageMaximumParts || !validDigest(digest) {
		return UploadedPart{}, ErrInvalid
	}
	_ = expectedDigest
	partOffset := int64(number-1) * session.PartSize
	if partOffset < 0 || partOffset >= expectedSize {
		return UploadedPart{}, ErrInvalid
	}
	expectedPartSize := session.PartSize
	if remaining := expectedSize - partOffset; remaining < expectedPartSize {
		expectedPartSize = remaining
	}
	if int64(len(data)) != expectedPartSize {
		return UploadedPart{}, ErrInvalid
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return UploadedPart{}, ErrIntegrity
	}
	credential, cleanup, err := adapter.s3StorageCredential(ctx, binding, storage, CapabilityObjectMultipart, CapabilityObjectResume, CapabilityObjectChecksum)
	if err != nil {
		return UploadedPart{}, err
	}
	defer func() { credential = s3Credential{}; cleanup() }()
	physicalKey, _ := s3StoragePhysicalKey(storage, session.Key)
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	headers := http.Header{
		"Content-Type":          []string{"application/octet-stream"},
		"X-Amz-Checksum-Sha256": []string{checksum},
	}
	query := url.Values{
		"partNumber": []string{strconv.FormatUint(uint64(number), 10)},
		"uploadId":   []string{session.UploadID},
	}
	response, err := adapter.s3StorageRequest(ctx, storage, credential, "s3.upload_part", http.MethodPut, physicalKey, query, data, headers)
	if err != nil {
		return UploadedPart{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return UploadedPart{}, s3StorageResponseError("s3.upload_part", response)
	}
	if _, err = readS3StorageResponse(response, s3StorageMaximumResponse); err != nil {
		return UploadedPart{}, err
	}
	etag, ok := normalizeS3StorageETag(response.Header.Get("ETag"))
	if !ok || response.Header.Get("X-Amz-Checksum-Sha256") != checksum {
		return UploadedPart{}, ErrIntegrity
	}
	return UploadedPart{Number: number, Size: int64(len(data)), Digest: digest, ETag: etag}, nil
}

func (adapter *RemoteProviderAdapter) CompleteUpload(ctx context.Context, binding ProviderBinding, storage StorageBinding, session MultipartSession, parts []UploadedPart) (ObjectMetadata, error) {
	expectedDigest, expectedSize, err := validateS3StorageSession(binding, storage, session)
	if err != nil || session.ExpiresAt.Before(adapter.now()) {
		return ObjectMetadata{}, ErrInvalid
	}
	expectedParts := uint32((expectedSize + session.PartSize - 1) / session.PartSize)
	if len(parts) == 0 || len(parts) != int(expectedParts) || len(parts) > int(s3StorageMaximumParts) {
		return ObjectMetadata{}, ErrInvalid
	}
	ordered := append([]UploadedPart(nil), parts...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Number < ordered[right].Number })
	type completedPart struct {
		ChecksumSHA256 string `xml:"ChecksumSHA256"`
		ETag           string `xml:"ETag"`
		PartNumber     uint32 `xml:"PartNumber"`
	}
	document := struct {
		XMLName xml.Name        `xml:"CompleteMultipartUpload"`
		XMLNS   string          `xml:"xmlns,attr"`
		Parts   []completedPart `xml:"Part"`
	}{XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/"}
	var total int64
	for index, part := range ordered {
		if part.Number != uint32(index+1) || part.Size <= 0 || part.Size > session.PartSize || !validDigest(part.Digest) {
			return ObjectMetadata{}, ErrInvalid
		}
		if index < len(ordered)-1 && part.Size < s3StorageMinimumPartBytes || index < len(ordered)-1 && part.Size != session.PartSize {
			return ObjectMetadata{}, ErrInvalid
		}
		etag, ok := normalizeS3StorageETag(part.ETag)
		decoded, digestErr := hex.DecodeString(part.Digest)
		if !ok || digestErr != nil {
			return ObjectMetadata{}, ErrInvalid
		}
		total += part.Size
		if total < 0 || total > expectedSize {
			return ObjectMetadata{}, ErrInvalid
		}
		document.Parts = append(document.Parts, completedPart{ChecksumSHA256: base64.StdEncoding.EncodeToString(decoded), ETag: "\"" + etag + "\"", PartNumber: part.Number})
	}
	if total != expectedSize {
		return ObjectMetadata{}, ErrIntegrity
	}
	payload, err := xml.Marshal(document)
	if err != nil {
		return ObjectMetadata{}, err
	}
	credential, cleanup, err := adapter.s3StorageCredential(ctx, binding, storage, CapabilityObjectMultipart, CapabilityObjectResume, CapabilityObjectChecksum)
	if err != nil {
		return ObjectMetadata{}, err
	}
	defer func() { credential = s3Credential{}; cleanup() }()
	physicalKey, _ := s3StoragePhysicalKey(storage, session.Key)
	response, err := adapter.s3StorageRequest(ctx, storage, credential, "s3.complete_multipart", http.MethodPost, physicalKey, url.Values{"uploadId": []string{session.UploadID}}, payload, http.Header{"Content-Type": []string{"application/xml"}})
	if err != nil {
		return ObjectMetadata{}, err
	}
	defer response.Body.Close()
	raw, readErr := readS3StorageResponse(response, s3StorageMaximumXMLResponse)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ObjectMetadata{}, s3StorageRawResponseError("s3.complete_multipart", response.StatusCode, response.Header, raw, readErr)
	}
	if readErr != nil {
		return ObjectMetadata{}, readErr
	}
	var completed s3StorageMultipartCompleted
	if decodeS3StorageXML(raw, &completed) != nil || completed.XMLName.Local != "CompleteMultipartUploadResult" || completed.Bucket != storage.Bucket || completed.Key != physicalKey {
		return ObjectMetadata{}, ErrIntegrity
	}
	completedETag, ok := normalizeS3StorageETag(completed.ETag)
	if !ok || completed.VersionID != "" && !validS3StorageOpaque(completed.VersionID, 2048) {
		return ObjectMetadata{}, ErrIntegrity
	}
	metadata, err := adapter.s3StorageStat(ctx, storage, credential, session.Key)
	if err != nil {
		return ObjectMetadata{}, errors.Join(ErrAmbiguous, err)
	}
	if metadata.Size != expectedSize || metadata.Digest != expectedDigest || metadata.ETag != completedETag || completed.VersionID != "" && metadata.VersionID != completed.VersionID {
		return ObjectMetadata{}, ErrIntegrity
	}
	return metadata, nil
}

func (adapter *RemoteProviderAdapter) AbortUpload(ctx context.Context, binding ProviderBinding, storage StorageBinding, session MultipartSession) error {
	if _, _, err := validateS3StorageSession(binding, storage, session); err != nil {
		return err
	}
	credential, cleanup, err := adapter.s3StorageCredential(ctx, binding, storage, CapabilityObjectMultipart)
	if err != nil {
		return err
	}
	defer func() { credential = s3Credential{}; cleanup() }()
	physicalKey, _ := s3StoragePhysicalKey(storage, session.Key)
	response, err := adapter.s3StorageRequest(ctx, storage, credential, "s3.abort_multipart", http.MethodDelete, physicalKey, url.Values{"uploadId": []string{session.UploadID}}, nil, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		_, _ = readS3StorageResponse(response, s3StorageMaximumResponse)
		return nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return s3StorageResponseError("s3.abort_multipart", response)
	}
	_, err = readS3StorageResponse(response, s3StorageMaximumResponse)
	return err
}

func (adapter *RemoteProviderAdapter) ReadRange(ctx context.Context, binding ProviderBinding, storage StorageBinding, key ObjectKey, version string, offset, length int64) ([]byte, error) {
	if offset < 0 || offset > s3StorageMaximumObjectBytes || length <= 0 || length > s3StorageMaximumRangeBytes || offset > s3StorageMaximumObjectBytes-length || version == "" && storage.VersioningRequired || version != "" && !validS3StorageOpaque(version, 2048) {
		return nil, ErrInvalid
	}
	physicalKey, err := s3StoragePhysicalKey(storage, key)
	if err != nil {
		return nil, err
	}
	credential, cleanup, err := adapter.s3StorageCredential(ctx, binding, storage, CapabilityObjectResume, CapabilityObjectChecksum)
	if err != nil {
		return nil, err
	}
	defer func() { credential = s3Credential{}; cleanup() }()
	query := url.Values{}
	if version != "" {
		query.Set("versionId", version)
	}
	headers := http.Header{"Range": []string{fmt.Sprintf("bytes=%d-%d", offset, offset+length-1)}}
	response, err := adapter.s3StorageRequest(ctx, storage, credential, "s3.read_range", http.MethodGet, physicalKey, query, nil, headers)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusPartialContent {
		return nil, s3StorageResponseError("s3.read_range", response)
	}
	start, end, total, ok := parseS3StorageContentRange(response.Header.Get("Content-Range"))
	if !ok || start != offset || end < start || end >= offset+length || total <= end || total > s3StorageMaximumObjectBytes {
		return nil, ErrIntegrity
	}
	expectedLength := end - start + 1
	if response.ContentLength >= 0 && response.ContentLength != expectedLength {
		return nil, ErrIntegrity
	}
	if version != "" && response.Header.Get("X-Amz-Version-Id") != version {
		return nil, ErrIntegrity
	}
	payload, err := readS3StorageResponse(response, length)
	if err != nil || int64(len(payload)) != expectedLength {
		if err != nil {
			return nil, err
		}
		return nil, ErrIntegrity
	}
	return payload, nil
}

func (adapter *RemoteProviderAdapter) DeleteVersion(ctx context.Context, binding ProviderBinding, storage StorageBinding, key ObjectKey, version string, effect EffectID) error {
	if !validS3StorageOpaque(version, 2048) || !validID(string(effect)) {
		return ErrInvalid
	}
	physicalKey, err := s3StoragePhysicalKey(storage, key)
	if err != nil {
		return err
	}
	credential, cleanup, err := adapter.s3StorageCredential(ctx, binding, storage, CapabilityObjectVersioning)
	if err != nil {
		return err
	}
	defer func() { credential = s3Credential{}; cleanup() }()
	response, err := adapter.s3StorageRequest(ctx, storage, credential, "s3.delete_version", http.MethodDelete, physicalKey, url.Values{"versionId": []string{version}}, nil, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return s3StorageResponseError("s3.delete_version", response)
	}
	if observed := response.Header.Get("X-Amz-Version-Id"); observed != "" && observed != version {
		return ErrIntegrity
	}
	_, err = readS3StorageResponse(response, s3StorageMaximumResponse)
	return err
}

func (adapter *RemoteProviderAdapter) ApplyRetention(ctx context.Context, binding ProviderBinding, storage StorageBinding, key ObjectKey, version string, until time.Time, effect EffectID) error {
	if !storage.ObjectLockRequired || !storage.VersioningRequired || !validS3StorageOpaque(version, 2048) || !validID(string(effect)) || until.IsZero() || !until.After(adapter.now()) {
		return ErrInvalid
	}
	physicalKey, err := s3StoragePhysicalKey(storage, key)
	if err != nil {
		return err
	}
	document := s3StorageRetention{XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/", Mode: "COMPLIANCE", RetainUntilDate: until.UTC().Format(time.RFC3339Nano)}
	payload, err := xml.Marshal(document)
	if err != nil {
		return err
	}
	md5Sum := md5.Sum(payload)
	shaSum := sha256.Sum256(payload)
	headers := http.Header{
		"Content-MD5":            []string{base64.StdEncoding.EncodeToString(md5Sum[:])},
		"Content-Type":           []string{"application/xml"},
		"X-Amz-Checksum-Sha256": []string{base64.StdEncoding.EncodeToString(shaSum[:])},
	}
	credential, cleanup, err := adapter.s3StorageCredential(ctx, binding, storage, CapabilityObjectLock, CapabilityObjectVersioning)
	if err != nil {
		return err
	}
	defer func() { credential = s3Credential{}; cleanup() }()
	query := url.Values{"retention": []string{""}, "versionId": []string{version}}
	response, err := adapter.s3StorageRequest(ctx, storage, credential, "s3.apply_retention", http.MethodPut, physicalKey, query, payload, headers)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return s3StorageResponseError("s3.apply_retention", response)
	}
	if _, err = readS3StorageResponse(response, s3StorageMaximumResponse); err != nil {
		return err
	}
	observed, err := adapter.s3StorageRequest(ctx, storage, credential, "s3.read_retention", http.MethodGet, physicalKey, query, nil, nil)
	if err != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	defer observed.Body.Close()
	if observed.StatusCode != http.StatusOK {
		return errors.Join(ErrAmbiguous, s3StorageResponseError("s3.read_retention", observed))
	}
	raw, err := readS3StorageResponse(observed, s3StorageMaximumXMLResponse)
	if err != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	var retention s3StorageRetention
	if decodeS3StorageXML(raw, &retention) != nil || retention.XMLName.Local != "Retention" || retention.Mode != "COMPLIANCE" {
		return ErrIntegrity
	}
	observedUntil, timeErr := time.Parse(time.RFC3339Nano, retention.RetainUntilDate)
	if timeErr != nil || observedUntil.Before(until.UTC()) {
		return ErrIntegrity
	}
	return nil
}

func (adapter *RemoteProviderAdapter) s3StorageCredential(ctx context.Context, binding ProviderBinding, storage StorageBinding, required ...Capability) (s3Credential, func(), error) {
	if err := validateS3StorageTarget(adapter, binding, storage); err != nil {
		return s3Credential{}, func() {}, err
	}
	for _, capability := range required {
		if !binding.Capabilities.Has(capability) {
			return s3Credential{}, func() {}, ErrUnsupported
		}
	}
	material, cleanup, err := adapter.Secrets.Read(ctx, binding)
	if err != nil {
		return s3Credential{}, func() {}, err
	}
	credential, err := parseS3Credential(material)
	if err != nil || credential.Region != storage.Region {
		cleanup()
		if err != nil {
			return s3Credential{}, func() {}, err
		}
		return s3Credential{}, func() {}, ErrPolicyDenied
	}
	return credential, cleanup, nil
}

func validateS3StorageTarget(adapter *RemoteProviderAdapter, binding ProviderBinding, storage StorageBinding) error {
	if adapter == nil || adapter.Client == nil || adapter.Kind != binding.Kind || binding.State != BindingActive || storage.BindingID != binding.ID || storage.Preset != binding.Kind || binding.Purpose != PurposeBackup {
		return ErrPolicyDenied
	}
	switch adapter.Kind {
	case ProviderAWSS3, ProviderWasabi, ProviderBackblaze:
	default:
		return ErrUnsupported
	}
	if binding.Validate() != nil || storage.Validate(binding.Capabilities) != nil || storage.AddressingStyle != "virtual_host" || !validS3StorageBucket(storage.Bucket) || !validS3StoragePrefix(storage.Prefix) || !validS3StorageRegion(storage.Region) {
		return ErrInvalid
	}
	policy := storage.Endpoint
	parsed, err := url.Parse(policy.URL)
	if err != nil || policy.Validate() != nil || validateProviderEndpoint(adapter.Kind, policy) != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" || parsed.Path != "" && parsed.Path != "/" {
		return ErrPolicyDenied
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || parsed.Hostname() != host || strings.ToLower(policy.ServerName) != host || policy.MaximumRedirects != 0 || !policy.AllowPublicInternet || !policy.DenyPrivateRanges || len(policy.AllowedCIDRs) != 0 || policy.PinnedCARef != "" || policy.PinnedPublicKey != "" {
		return ErrPolicyDenied
	}
	return nil
}

func (adapter *RemoteProviderAdapter) s3StorageStat(ctx context.Context, storage StorageBinding, credential s3Credential, key ObjectKey) (ObjectMetadata, error) {
	physicalKey, err := s3StoragePhysicalKey(storage, key)
	if err != nil {
		return ObjectMetadata{}, err
	}
	response, err := adapter.s3StorageRequest(ctx, storage, credential, "s3.stat_object", http.MethodHead, physicalKey, nil, nil, nil)
	if err != nil {
		return ObjectMetadata{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ObjectMetadata{}, s3StorageResponseError("s3.stat_object", response)
	}
	if response.ContentLength < 0 || response.ContentLength > s3StorageMaximumObjectBytes {
		return ObjectMetadata{}, ErrIntegrity
	}
	digest := strings.ToLower(strings.TrimSpace(response.Header.Get("X-Amz-Meta-Sha256")))
	metadataSize, sizeErr := strconv.ParseInt(response.Header.Get("X-Amz-Meta-Size"), 10, 64)
	etag, etagOK := normalizeS3StorageETag(response.Header.Get("ETag"))
	modified, timeErr := http.ParseTime(response.Header.Get("Last-Modified"))
	version := response.Header.Get("X-Amz-Version-Id")
	if !validDigest(digest) || sizeErr != nil || metadataSize != response.ContentLength || !etagOK || timeErr != nil || version != "" && !validS3StorageOpaque(version, 2048) {
		return ObjectMetadata{}, ErrIntegrity
	}
	return ObjectMetadata{Key: key, Size: response.ContentLength, Digest: digest, VersionID: version, ETag: etag, ModifiedAt: modified.UTC()}, nil
}

func (adapter *RemoteProviderAdapter) s3StorageRequest(ctx context.Context, storage StorageBinding, credential s3Credential, operation, method, physicalKey string, query url.Values, payload []byte, headers http.Header) (*http.Response, error) {
	target, err := s3StorageURL(storage, physicalKey, query)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, err
	}
	request.ContentLength = int64(len(payload))
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	sum := sha256.Sum256(payload)
	if err = signS3StorageRequest(request, credential, hex.EncodeToString(sum[:]), adapter.now()); err != nil {
		return nil, err
	}
	client := *adapter.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, providerNetworkError(operation, err)
	}
	return response, nil
}

func signS3StorageRequest(request *http.Request, credential s3Credential, payloadDigest string, now time.Time) error {
	if request == nil || request.URL == nil || !validDigest(payloadDigest) || credential.AccessKeyID == "" || credential.SecretAccessKey == "" || !validS3StorageRegion(credential.Region) {
		return ErrInvalid
	}
	timestamp := now.UTC().Format("20060102T150405Z")
	date := now.UTC().Format("20060102")
	request.Header.Set("X-Amz-Date", timestamp)
	request.Header.Set("X-Amz-Content-Sha256", payloadDigest)
	if credential.SessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", credential.SessionToken)
	}
	request.URL.RawQuery = canonicalS3StorageQuery(request.URL.Query())
	canonicalHeaders, signedHeaders := canonicalS3StorageHeaders(request)
	canonicalRequest := request.Method + "\n" + request.URL.EscapedPath() + "\n" + request.URL.RawQuery + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadDigest
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + credential.Region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(requestHash[:])
	dateKey := hmacSHA256Provider([]byte("AWS4"+credential.SecretAccessKey), date)
	regionKey := hmacSHA256Provider(dateKey, credential.Region)
	serviceKey := hmacSHA256Provider(regionKey, "s3")
	signingKey := hmacSHA256Provider(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256Provider(signingKey, stringToSign))
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+credential.AccessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
	return nil
}

func canonicalS3StorageHeaders(request *http.Request) (string, string) {
	values := map[string][]string{"host": []string{request.URL.Host}}
	for name, current := range request.Header {
		lower := strings.ToLower(name)
		switch lower {
		case "authorization", "accept-encoding", "connection", "content-length", "expect", "transfer-encoding", "user-agent":
			continue
		}
		for _, value := range current {
			values[lower] = append(values[lower], strings.Join(strings.Fields(value), " "))
		}
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteByte(':')
		canonical.WriteString(strings.Join(values[name], ","))
		canonical.WriteByte('\n')
	}
	return canonical.String(), strings.Join(names, ";")
}

func canonicalS3StorageQuery(values url.Values) string {
	type pair struct{ key, value string }
	pairs := make([]pair, 0, len(values))
	for key, current := range values {
		if len(current) == 0 {
			current = []string{""}
		}
		for _, value := range current {
			pairs = append(pairs, pair{s3StorageEscape(key, true), s3StorageEscape(value, true)})
		}
	}
	sort.Slice(pairs, func(left, right int) bool {
		if pairs[left].key == pairs[right].key {
			return pairs[left].value < pairs[right].value
		}
		return pairs[left].key < pairs[right].key
	})
	var result strings.Builder
	for index, current := range pairs {
		if index > 0 {
			result.WriteByte('&')
		}
		result.WriteString(current.key)
		result.WriteByte('=')
		result.WriteString(current.value)
	}
	return result.String()
}

func s3StorageURL(storage StorageBinding, physicalKey string, query url.Values) (*url.URL, error) {
	endpoint, err := url.Parse(storage.Endpoint.URL)
	if err != nil {
		return nil, ErrInvalid
	}
	endpoint.Host = storage.Bucket + "." + endpoint.Host
	endpoint.Path = "/"
	endpoint.RawPath = "/"
	if physicalKey != "" {
		endpoint.Path += physicalKey
		endpoint.RawPath += s3StorageEscape(physicalKey, false)
	}
	endpoint.RawQuery = canonicalS3StorageQuery(query)
	return endpoint, nil
}

func s3StorageEscape(value string, encodeSlash bool) string {
	const hexadecimal = "0123456789ABCDEF"
	var escaped strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '.' || character == '_' || character == '~' || character == '/' && !encodeSlash {
			escaped.WriteByte(character)
			continue
		}
		escaped.WriteByte('%')
		escaped.WriteByte(hexadecimal[character>>4])
		escaped.WriteByte(hexadecimal[character&15])
	}
	return escaped.String()
}

func s3StoragePhysicalKey(storage StorageBinding, key ObjectKey) (string, error) {
	raw := key.String()
	parsed, err := ParseObjectKey(raw)
	if err != nil || parsed.String() != raw || !validS3StorageText(raw) || strings.Contains(raw, "//") {
		return "", ErrInvalid
	}
	prefix := strings.TrimSuffix(storage.Prefix, "/")
	physical := prefix + "/" + raw
	if len(physical) > 1024 {
		return "", ErrInvalid
	}
	return physical, nil
}

func s3StorageLogicalKey(storage StorageBinding, physical string) (ObjectKey, error) {
	prefix := strings.TrimSuffix(storage.Prefix, "/") + "/"
	if !strings.HasPrefix(physical, prefix) {
		return ObjectKey{}, ErrIntegrity
	}
	key, err := ParseObjectKey(strings.TrimPrefix(physical, prefix))
	if err != nil {
		return ObjectKey{}, ErrIntegrity
	}
	if rebuilt, rebuildErr := s3StoragePhysicalKey(storage, key); rebuildErr != nil || rebuilt != physical {
		return ObjectKey{}, ErrIntegrity
	}
	return key, nil
}

func validS3StorageBucket(bucket string) bool {
	if len(bucket) < 3 || len(bucket) > 63 || strings.Contains(bucket, ".") || net.ParseIP(bucket) != nil {
		return false
	}
	for index, character := range bucket {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' && index > 0 && index < len(bucket)-1 {
			continue
		}
		return false
	}
	return true
}

func validS3StoragePrefix(prefix string) bool {
	return prefix != "" && len(prefix) <= 512 && validS3StorageText(prefix) && !strings.HasPrefix(prefix, "/") && !strings.Contains(prefix, "..") && !strings.Contains(prefix, "//") && !strings.Contains(prefix, "\\") && strings.TrimSuffix(prefix, "/") != ""
}

func validS3StorageRegion(region string) bool {
	return region != "" && len(region) <= 64 && validS3StorageText(region) && !strings.ContainsAny(region, "/ \\")
}

func validS3StorageText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validS3StorageOpaque(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && validS3StorageText(value)
}

func validS3StorageCursor(value string) bool {
	return value == "" || validS3StorageOpaque(value, 2048)
}

func normalizeS3StorageETag(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return value, value != "" && len(value) <= 1024 && validS3StorageText(value) && !strings.ContainsAny(value, "\"\\")
}

func s3StoragePartSize(size int64) (int64, error) {
	if size <= 0 || size > s3StorageMaximumObjectBytes {
		return 0, ErrInvalid
	}
	partSize := s3StoragePreferredPartBytes
	minimum := (size + int64(s3StorageMaximumParts) - 1) / int64(s3StorageMaximumParts)
	if minimum > partSize {
		const mebibyte = int64(1 << 20)
		partSize = ((minimum + mebibyte - 1) / mebibyte) * mebibyte
	}
	if partSize > s3StorageMaximumPartBytes {
		return 0, ErrUnsupported
	}
	return partSize, nil
}

func s3StorageSessionID(binding ProviderBinding, storage StorageBinding, key ObjectKey, uploadID, digest string, size int64) string {
	value := string(binding.ID) + "\x00" + storage.Bucket + "\x00" + storage.Prefix + "\x00" + key.String() + "\x00" + uploadID + "\x00" + digest + "\x00" + strconv.FormatInt(size, 10)
	sum := sha256.Sum256([]byte(value))
	return "mpu_" + digest + "_" + strconv.FormatInt(size, 10) + "_" + hex.EncodeToString(sum[:8])
}

func validateS3StorageSession(binding ProviderBinding, storage StorageBinding, session MultipartSession) (string, int64, error) {
	if !validID(session.ID) || !validS3StorageOpaque(session.UploadID, 4096) || session.PartSize < s3StorageMinimumPartBytes || session.PartSize > s3StorageMaximumPartBytes || session.ExpiresAt.IsZero() {
		return "", 0, ErrInvalid
	}
	if _, err := s3StoragePhysicalKey(storage, session.Key); err != nil {
		return "", 0, err
	}
	parts := strings.Split(session.ID, "_")
	if len(parts) != 4 || parts[0] != "mpu" || !validDigest(parts[1]) || len(parts[3]) != 16 {
		return "", 0, ErrInvalid
	}
	size, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || size <= 0 || size > s3StorageMaximumObjectBytes {
		return "", 0, ErrInvalid
	}
	if session.ID != s3StorageSessionID(binding, storage, session.Key, session.UploadID, parts[1], size) {
		return "", 0, ErrIntegrity
	}
	expectedParts := (size + session.PartSize - 1) / session.PartSize
	if expectedParts <= 0 || expectedParts > int64(s3StorageMaximumParts) {
		return "", 0, ErrInvalid
	}
	return parts[1], size, nil
}

func parseS3StorageContentRange(value string) (int64, int64, int64, bool) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, false
	}
	ranges := strings.Split(strings.TrimPrefix(value, "bytes "), "/")
	if len(ranges) != 2 {
		return 0, 0, 0, false
	}
	bounds := strings.Split(ranges[0], "-")
	if len(bounds) != 2 {
		return 0, 0, 0, false
	}
	start, startErr := strconv.ParseInt(bounds[0], 10, 64)
	end, endErr := strconv.ParseInt(bounds[1], 10, 64)
	total, totalErr := strconv.ParseInt(ranges[1], 10, 64)
	return start, end, total, startErr == nil && endErr == nil && totalErr == nil && start >= 0 && end >= start && total > end
}

func readS3StorageResponse(response *http.Response, maximum int64) ([]byte, error) {
	if response == nil || response.Body == nil || maximum < 0 || response.ContentLength > maximum {
		return nil, ErrIntegrity
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(payload)) > maximum || response.ContentLength >= 0 && int64(len(payload)) != response.ContentLength {
		if err != nil {
			return nil, err
		}
		return nil, ErrIntegrity
	}
	return payload, nil
}

func decodeS3StorageXML(payload []byte, value any) error {
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra struct{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrIntegrity
	}
	return nil
}

func s3StorageResponseError(operation string, response *http.Response) error {
	if response == nil {
		return &ProviderError{Class: ErrorAmbiguous, Operation: operation, Code: "missing_response", Cause: ErrAmbiguous}
	}
	raw, err := readS3StorageResponse(response, s3StorageMaximumResponse)
	return s3StorageRawResponseError(operation, response.StatusCode, response.Header, raw, err)
}

func s3StorageRawResponseError(operation string, status int, headers http.Header, raw []byte, readErr error) error {
	code := "http_" + strconv.Itoa(status)
	var document s3StorageErrorDocument
	if readErr == nil && len(raw) > 0 && decodeS3StorageXML(raw, &document) == nil && document.XMLName.Local == "Error" && validID(document.Code) {
		code = strings.ToLower(document.Code)
	}
	class, cause := ErrorUnavailable, ErrUnavailable
	switch {
	case status >= 300 && status < 400:
		class, cause, code = ErrorInvalid, ErrPolicyDenied, "redirect_denied"
	case status == http.StatusBadRequest || status == http.StatusRequestedRangeNotSatisfiable || status == http.StatusUnprocessableEntity:
		class, cause = ErrorInvalid, ErrInvalid
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		class, cause = ErrorUnauthorized, ErrUnauthorized
	case status == http.StatusNotFound:
		class, cause = ErrorPermanent, ErrNotFound
	case status == http.StatusConflict || status == http.StatusPreconditionFailed:
		class, cause = ErrorConflict, ErrConflict
	case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
		class, cause = ErrorRateLimited, ErrRateLimited
	case status >= 500:
		class, cause = ErrorUnavailable, ErrUnavailable
	}
	if readErr != nil {
		class, cause, code = ErrorAmbiguous, ErrIntegrity, "invalid_response"
	}
	return &ProviderError{Class: class, Operation: operation, Code: code, RetryAfter: s3StorageRetryAfter(headers), Cause: cause}
}

func s3StorageRetryAfter(headers http.Header) time.Duration {
	if headers == nil {
		return 0
	}
	seconds, err := strconv.ParseUint(headers.Get("Retry-After"), 10, 31)
	if err != nil {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

var _ StorageProvider = (*RemoteProviderAdapter)(nil)
