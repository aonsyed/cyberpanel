package artifactguard

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
)

var streamMagic = [8]byte{'A', 'G', 'A', 'E', 'A', 'D', '0', '1'}

const (
	streamVersion       = uint16(1)
	maximumHeaderBytes  = 64 << 10
	frameFixedBytes     = 8 + 1 + 4 + 4
)

type KeyResolver interface {
	// ResolveKey returns a caller-owned 32-byte key buffer. The service always
	// cleans that buffer before returning.
	ResolveKey(context.Context, string, uint64) ([]byte, error)
}

// PlaintextCleanup is called for every plaintext/key buffer owned by the
// encryption service. Implementations may add platform-specific memory hygiene.
type PlaintextCleanup interface {
	Clean([]byte)
}

type ZeroingCleanup struct{}

func (ZeroingCleanup) Clean(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type ExactObjectWrite struct {
	TenantID          TenantID
	ObjectID          ObjectID
	ExpectedGeneration uint64
	ArtifactID        ArtifactID
	ArtifactDigest    string
}

type ObjectCommit struct {
	CiphertextDigest string
	CiphertextBytes  int64
}

type StoredObject struct {
	ObjectID   ObjectID
	Generation uint64
	Digest     string
	Size       int64
}

type AtomicObjectWriter interface {
	io.Writer
	Commit(context.Context, ObjectCommit) (StoredObject, error)
	Abort(context.Context) error
}

type ExactObjectRead struct {
	TenantID          TenantID
	ObjectID          ObjectID
	ExpectedGeneration uint64
	ExpectedDigest    string
}

type ExactObjectDelete struct {
	TenantID          TenantID
	ObjectID          ObjectID
	ExpectedGeneration uint64
	ExpectedDigest    string
}

type ExactDeleteStatus string

const (
	ExactDeleted       ExactDeleteStatus = "deleted"
	ExactAlreadyAbsent ExactDeleteStatus = "already_absent"
	ExactDeleteUnknown ExactDeleteStatus = "ambiguous"
)

type ExactDeleteResult struct {
	ObjectID   ObjectID
	Generation uint64
	Digest     string
	Status     ExactDeleteStatus
}

// AtomicObjectStore deliberately exposes exact opaque object identifiers, not
// paths, prefixes, wildcards, buckets, or directory deletion primitives.
type AtomicObjectStore interface {
	BeginExact(context.Context, ExactObjectWrite) (AtomicObjectWriter, error)
	OpenExact(context.Context, ExactObjectRead) (io.ReadCloser, error)
	DeleteExact(context.Context, ExactObjectDelete) (ExactDeleteResult, error)
}

type PlaintextCommit struct {
	ContentDigest string
	ContentBytes  int64
}

// AtomicPlaintextSink prevents a corrupted or incomplete decryption from being
// published. Abort must remove all plaintext owned by the sink.
type AtomicPlaintextSink interface {
	io.Writer
	Commit(context.Context, PlaintextCommit) error
	Abort(context.Context) error
}

type CryptoLimits struct {
	MaximumPlaintextBytes  int64
	MaximumCiphertextBytes int64
	MaximumChunks          uint64
}

func DefaultCryptoLimits() CryptoLimits {
	return CryptoLimits{
		MaximumPlaintextBytes:  512 << 20,
		MaximumCiphertextBytes: 544 << 20,
		MaximumChunks:          65536,
	}
}

func (l CryptoLimits) validate() error {
	if l.MaximumPlaintextBytes <= 0 || l.MaximumPlaintextBytes > 16<<30 ||
		l.MaximumCiphertextBytes <= l.MaximumPlaintextBytes || l.MaximumCiphertextBytes > 17<<30 ||
		l.MaximumChunks < 2 || l.MaximumChunks > 1000000 {
		return fmt.Errorf("%w: crypto limits", ErrInvalid)
	}
	return nil
}

type EncryptionService struct {
	Keys    KeyResolver
	Objects AtomicObjectStore
	Cleanup PlaintextCleanup
	Limits  CryptoLimits
}

type authenticatedMetadata struct {
	ArtifactID      ArtifactID     `json:"artifact_id"`
	TenantID        TenantID       `json:"tenant_id"`
	NodeID          NodeID         `json:"node_id"`
	ObjectID        ObjectID       `json:"object_id"`
	Purpose         Purpose        `json:"purpose"`
	DataClass       DataClass      `json:"data_class"`
	Source          ArtifactSource `json:"source"`
	ContentDigest   string         `json:"content_digest"`
	ContentSize     int64          `json:"content_size"`
	KeyReference    string         `json:"key_reference"`
	KeyVersion      uint64         `json:"key_version"`
	RedactionDigest string         `json:"redaction_digest"`
}

type streamHeader struct {
	Version    uint16                `json:"version"`
	Algorithm  string                `json:"algorithm"`
	ChunkBytes uint32                `json:"chunk_bytes"`
	Metadata   authenticatedMetadata `json:"metadata"`
}

func (s EncryptionService) Seal(
	ctx context.Context,
	artifact Artifact,
	plaintext io.Reader,
) (StoredObject, error) {
	if s.Keys == nil || s.Objects == nil || plaintext == nil {
		return StoredObject{}, fmt.Errorf("%w: encryption service dependencies", ErrInvalid)
	}
	limits := s.Limits
	if limits == (CryptoLimits{}) {
		limits = DefaultCryptoLimits()
	}
	if err := limits.validate(); err != nil {
		return StoredObject{}, err
	}
	cleanup := s.Cleanup
	if cleanup == nil {
		cleanup = ZeroingCleanup{}
	}
	if err := validateSealArtifact(artifact, limits); err != nil {
		return StoredObject{}, err
	}

	header, headerBytes, headerDigest, err := buildStreamHeader(artifact)
	if err != nil {
		return StoredObject{}, err
	}
	key, err := s.Keys.ResolveKey(ctx, header.Metadata.KeyReference, header.Metadata.KeyVersion)
	if err != nil {
		return StoredObject{}, fmt.Errorf("artifactguard: resolve encryption key: %w", err)
	}
	defer cleanup.Clean(key)
	aead, err := makeAEAD(key)
	if err != nil {
		return StoredObject{}, err
	}

	atomicWriter, err := s.Objects.BeginExact(ctx, ExactObjectWrite{
		TenantID:           artifact.TenantID,
		ObjectID:           artifact.ObjectID,
		ExpectedGeneration: artifact.ObjectGeneration,
		ArtifactID:         artifact.ID,
		ArtifactDigest:     artifact.Digest,
	})
	if err != nil {
		return StoredObject{}, fmt.Errorf("artifactguard: begin exact object: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = atomicWriter.Abort(context.WithoutCancel(ctx))
		}
	}()
	wire := &boundedCiphertextWriter{
		Writer:  atomicWriter,
		Hash:    sha256.New(),
		Maximum: limits.MaximumCiphertextBytes,
	}
	if err := writeStreamHeader(wire, headerBytes); err != nil {
		return StoredObject{}, err
	}

	plainHash := sha256.New()
	plainLimit := &io.LimitedReader{R: plaintext, N: limits.MaximumPlaintextBytes + 1}
	buffer := make([]byte, int(header.ChunkBytes))
	defer cleanup.Clean(buffer)
	nonces := make(map[string]struct{})
	var plainBytes int64
	var index uint64
	for {
		if err := ctx.Err(); err != nil {
			return StoredObject{}, err
		}
		n, readErr := io.ReadFull(plainLimit, buffer)
		if n > 0 {
			plainBytes += int64(n)
			if plainBytes > limits.MaximumPlaintextBytes || plainBytes > artifact.ContentSize {
				return StoredObject{}, ErrLimit
			}
			if index+1 >= limits.MaximumChunks {
				return StoredObject{}, ErrLimit
			}
			_, _ = plainHash.Write(buffer[:n])
			if err := writeEncryptedFrame(wire, aead, headerDigest, index, false, buffer[:n], nonces); err != nil {
				return StoredObject{}, err
			}
			cleanup.Clean(buffer[:n])
			index++
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
				break
			}
			return StoredObject{}, fmt.Errorf("artifactguard: read plaintext: %w", readErr)
		}
	}
	plainDigest := hex.EncodeToString(plainHash.Sum(nil))
	if plainBytes != artifact.ContentSize || plainDigest != artifact.ContentDigest {
		return StoredObject{}, ErrIntegrity
	}
	if err := writeEncryptedFrame(wire, aead, headerDigest, index, true, nil, nonces); err != nil {
		return StoredObject{}, err
	}
	cipherDigest := hex.EncodeToString(wire.Hash.Sum(nil))
	stored, err := atomicWriter.Commit(ctx, ObjectCommit{
		CiphertextDigest: cipherDigest,
		CiphertextBytes:  wire.Count,
	})
	if err != nil {
		return StoredObject{}, fmt.Errorf("artifactguard: commit exact object: %w", err)
	}
	committed = true
	if stored.ObjectID != artifact.ObjectID || stored.Generation == 0 ||
		stored.Digest != cipherDigest || stored.Size != wire.Count {
		return StoredObject{}, ErrIntegrity
	}
	return stored, nil
}

func (s EncryptionService) Open(
	ctx context.Context,
	artifact Artifact,
	sink AtomicPlaintextSink,
) error {
	if s.Keys == nil || s.Objects == nil || sink == nil {
		return fmt.Errorf("%w: decryption service dependencies", ErrInvalid)
	}
	limits := s.Limits
	if limits == (CryptoLimits{}) {
		limits = DefaultCryptoLimits()
	}
	if err := limits.validate(); err != nil {
		return err
	}
	cleanup := s.Cleanup
	if cleanup == nil {
		cleanup = ZeroingCleanup{}
	}
	if err := artifact.Validate(); err != nil {
		return err
	}
	if artifact.Lifecycle != LifecycleAvailable || artifact.Integrity != IntegrityVerified ||
		artifact.ContentSize > limits.MaximumPlaintextBytes ||
		requiredChunkCount(artifact.ContentSize, artifact.Encryption.ChunkBytes) > limits.MaximumChunks {
		return fmt.Errorf("%w: artifact unavailable for decryption", ErrInvalid)
	}

	source, err := s.Objects.OpenExact(ctx, ExactObjectRead{
		TenantID:           artifact.TenantID,
		ObjectID:           artifact.ObjectID,
		ExpectedGeneration: artifact.ObjectGeneration,
		ExpectedDigest:     artifact.ObjectDigest,
	})
	if err != nil {
		return fmt.Errorf("artifactguard: open exact object: %w", err)
	}
	defer source.Close()
	committed := false
	defer func() {
		if !committed {
			_ = sink.Abort(context.WithoutCancel(ctx))
		}
	}()

	cipherHash := sha256.New()
	ciphertext := &boundedCiphertextReader{
		Reader:  io.TeeReader(source, cipherHash),
		Maximum: limits.MaximumCiphertextBytes,
	}
	header, headerBytes, err := readStreamHeader(ciphertext)
	if err != nil {
		return err
	}
	expectedHeader, expectedHeaderBytes, headerDigest, err := buildStreamHeader(artifact)
	if err != nil {
		return err
	}
	if header != expectedHeader || !bytes.Equal(headerBytes, expectedHeaderBytes) {
		return ErrIntegrity
	}
	key, err := s.Keys.ResolveKey(ctx, header.Metadata.KeyReference, header.Metadata.KeyVersion)
	if err != nil {
		return fmt.Errorf("artifactguard: resolve decryption key: %w", err)
	}
	defer cleanup.Clean(key)
	aead, err := makeAEAD(key)
	if err != nil {
		return err
	}

	plainHash := sha256.New()
	nonces := make(map[string]struct{})
	var plainBytes int64
	var expectedIndex uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if expectedIndex >= limits.MaximumChunks {
			return ErrLimit
		}
		plaintext, final, err := readEncryptedFrame(
			ciphertext,
			aead,
			headerDigest,
			expectedIndex,
			header.ChunkBytes,
			nonces,
		)
		if err != nil {
			return err
		}
		if final {
			cleanup.Clean(plaintext)
			break
		}
		plainBytes += int64(len(plaintext))
		if plainBytes > limits.MaximumPlaintextBytes || plainBytes > artifact.ContentSize {
			cleanup.Clean(plaintext)
			return ErrLimit
		}
		_, _ = plainHash.Write(plaintext)
		n, writeErr := sink.Write(plaintext)
		cleanup.Clean(plaintext)
		if writeErr != nil {
			return fmt.Errorf("artifactguard: write plaintext sink: %w", writeErr)
		}
		if n != len(plaintext) {
			return io.ErrShortWrite
		}
		expectedIndex++
	}
	var trailing [1]byte
	if n, readErr := ciphertext.Read(trailing[:]); n != 0 || !errors.Is(readErr, io.EOF) {
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("artifactguard: read trailing ciphertext: %w", readErr)
		}
		return ErrIntegrity
	}
	if hex.EncodeToString(cipherHash.Sum(nil)) != artifact.ObjectDigest {
		return ErrIntegrity
	}
	plainDigest := hex.EncodeToString(plainHash.Sum(nil))
	if plainBytes != artifact.ContentSize || plainDigest != artifact.ContentDigest {
		return ErrIntegrity
	}
	if err := sink.Commit(ctx, PlaintextCommit{
		ContentDigest: plainDigest,
		ContentBytes:  plainBytes,
	}); err != nil {
		return fmt.Errorf("artifactguard: commit plaintext sink: %w", err)
	}
	committed = true
	return nil
}

func validateSealArtifact(artifact Artifact, limits CryptoLimits) error {
	if err := artifact.Validate(); err != nil {
		return err
	}
	if artifact.Lifecycle != LifecycleStaging || artifact.Integrity != IntegrityPending ||
		artifact.ContentSize < 0 || artifact.ContentSize > limits.MaximumPlaintextBytes ||
		!validDigest(artifact.ContentDigest) || artifact.ObjectGeneration != 0 ||
		artifact.ObjectDigest != "" {
		return fmt.Errorf("%w: staging artifact", ErrInvalid)
	}
	if !validLocalID(string(artifact.ID)) || !validLocalID(string(artifact.TenantID)) ||
		!validLocalID(string(artifact.NodeID)) || !validLocalID(string(artifact.ObjectID)) ||
		!artifact.Purpose.valid() || !artifact.DataClass.valid() || !artifact.Source.Kind.valid() ||
		!validLocalID(artifact.Source.ID) || artifact.Source.Generation == 0 ||
		artifact.Encryption.Algorithm != "AES-256-GCM-CHUNKED" ||
		artifact.Encryption.ChunkBytes < MinimumChunkBytes ||
		artifact.Encryption.ChunkBytes > MaximumChunkBytes ||
		!validLocalID(artifact.Encryption.KeyReference) || artifact.Encryption.KeyVersion == 0 {
		return fmt.Errorf("%w: artifact encryption metadata", ErrInvalid)
	}
	if err := artifact.Redaction.Validate(); err != nil {
		return err
	}
	if artifact.Redaction.Truncated || artifact.Redaction.OutputDigest != artifact.ContentDigest ||
		artifact.Redaction.OutputBytes != artifact.ContentSize {
		return ErrTruncated
	}
	if requiredChunkCount(artifact.ContentSize, artifact.Encryption.ChunkBytes) > limits.MaximumChunks {
		return ErrLimit
	}
	return nil
}

func requiredChunkCount(contentBytes int64, chunkBytes uint32) uint64 {
	if contentBytes <= 0 {
		return 1
	}
	dataChunks := uint64(contentBytes) / uint64(chunkBytes)
	if uint64(contentBytes)%uint64(chunkBytes) != 0 {
		dataChunks++
	}
	return dataChunks + 1
}

func buildStreamHeader(artifact Artifact) (streamHeader, []byte, [sha256.Size]byte, error) {
	redactionDigest, err := canonicalDigest(artifact.Redaction)
	if err != nil {
		return streamHeader{}, nil, [sha256.Size]byte{}, err
	}
	header := streamHeader{
		Version:    streamVersion,
		Algorithm:  "AES-256-GCM-CHUNKED",
		ChunkBytes: artifact.Encryption.ChunkBytes,
		Metadata: authenticatedMetadata{
			ArtifactID:      artifact.ID,
			TenantID:        artifact.TenantID,
			NodeID:          artifact.NodeID,
			ObjectID:        artifact.ObjectID,
			Purpose:         artifact.Purpose,
			DataClass:       artifact.DataClass,
			Source:          artifact.Source,
			ContentDigest:   artifact.ContentDigest,
			ContentSize:     artifact.ContentSize,
			KeyReference:    artifact.Encryption.KeyReference,
			KeyVersion:      artifact.Encryption.KeyVersion,
			RedactionDigest: redactionDigest,
		},
	}
	encoded, err := json.Marshal(header)
	if err != nil || len(encoded) > maximumHeaderBytes {
		return streamHeader{}, nil, [sha256.Size]byte{}, fmt.Errorf("%w: stream header", ErrInvalid)
	}
	digestInput := make([]byte, 0, len(streamMagic)+len(encoded))
	digestInput = append(digestInput, streamMagic[:]...)
	digestInput = append(digestInput, encoded...)
	digest := sha256.Sum256(digestInput)
	return header, encoded, digest, nil
}

func makeAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: AES-256 key length", ErrInvalid)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("artifactguard: initialize AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("artifactguard: initialize GCM: %w", err)
	}
	return aead, nil
}

func writeStreamHeader(writer io.Writer, encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > maximumHeaderBytes {
		return fmt.Errorf("%w: stream header size", ErrInvalid)
	}
	if err := writeAll(writer, streamMagic[:]); err != nil {
		return err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
	if err := writeAll(writer, length[:]); err != nil {
		return err
	}
	return writeAll(writer, encoded)
}

func readStreamHeader(reader io.Reader) (streamHeader, []byte, error) {
	var magic [len(streamMagic)]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil {
		return streamHeader{}, nil, fmt.Errorf("artifactguard: read stream magic: %w", err)
	}
	if magic != streamMagic {
		return streamHeader{}, nil, ErrIntegrity
	}
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return streamHeader{}, nil, fmt.Errorf("artifactguard: read stream header length: %w", err)
	}
	headerLength := binary.BigEndian.Uint32(length[:])
	if headerLength == 0 || headerLength > maximumHeaderBytes {
		return streamHeader{}, nil, ErrLimit
	}
	encoded := make([]byte, int(headerLength))
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return streamHeader{}, nil, fmt.Errorf("artifactguard: read stream header: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var header streamHeader
	if err := decoder.Decode(&header); err != nil {
		return streamHeader{}, nil, ErrIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return streamHeader{}, nil, ErrIntegrity
	}
	if header.Version != streamVersion || header.Algorithm != "AES-256-GCM-CHUNKED" ||
		header.ChunkBytes < MinimumChunkBytes || header.ChunkBytes > MaximumChunkBytes {
		return streamHeader{}, nil, ErrIntegrity
	}
	return header, encoded, nil
}

func writeEncryptedFrame(
	writer io.Writer,
	aead cipher.AEAD,
	headerDigest [sha256.Size]byte,
	index uint64,
	final bool,
	plaintext []byte,
	nonces map[string]struct{},
) error {
	if final && len(plaintext) != 0 {
		return fmt.Errorf("%w: non-empty final frame", ErrInvalid)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("artifactguard: generate frame nonce: %w", err)
	}
	nonceID := string(nonce)
	if _, duplicate := nonces[nonceID]; duplicate {
		return ErrIntegrity
	}
	nonces[nonceID] = struct{}{}
	flag := byte(0)
	if final {
		flag = 1
	}
	aad := frameAAD(headerDigest, index, flag, uint32(len(plaintext)))
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	if uint64(len(ciphertext)) > uint64(^uint32(0)) {
		return ErrLimit
	}
	header := make([]byte, frameFixedBytes)
	binary.BigEndian.PutUint64(header[0:8], index)
	header[8] = flag
	binary.BigEndian.PutUint32(header[9:13], uint32(len(plaintext)))
	binary.BigEndian.PutUint32(header[13:17], uint32(len(ciphertext)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	if err := writeAll(writer, nonce); err != nil {
		return err
	}
	return writeAll(writer, ciphertext)
}

func readEncryptedFrame(
	reader io.Reader,
	aead cipher.AEAD,
	headerDigest [sha256.Size]byte,
	expectedIndex uint64,
	chunkBytes uint32,
	nonces map[string]struct{},
) ([]byte, bool, error) {
	header := make([]byte, frameFixedBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, false, fmt.Errorf("artifactguard: read encrypted frame: %w", err)
	}
	index := binary.BigEndian.Uint64(header[0:8])
	flag := header[8]
	plainLength := binary.BigEndian.Uint32(header[9:13])
	cipherLength := binary.BigEndian.Uint32(header[13:17])
	if index != expectedIndex || flag > 1 || plainLength > chunkBytes ||
		cipherLength != plainLength+uint32(aead.Overhead()) ||
		(flag == 1 && plainLength != 0) || (flag == 0 && plainLength == 0) {
		return nil, false, ErrIntegrity
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return nil, false, fmt.Errorf("artifactguard: read frame nonce: %w", err)
	}
	nonceID := string(nonce)
	if _, duplicate := nonces[nonceID]; duplicate {
		return nil, false, ErrIntegrity
	}
	nonces[nonceID] = struct{}{}
	ciphertext := make([]byte, int(cipherLength))
	if _, err := io.ReadFull(reader, ciphertext); err != nil {
		return nil, false, fmt.Errorf("artifactguard: read frame ciphertext: %w", err)
	}
	aad := frameAAD(headerDigest, index, flag, plainLength)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	for index := range ciphertext {
		ciphertext[index] = 0
	}
	if err != nil {
		return nil, false, ErrIntegrity
	}
	return plaintext, flag == 1, nil
}

func frameAAD(headerDigest [sha256.Size]byte, index uint64, flag byte, plainLength uint32) []byte {
	aad := make([]byte, sha256.Size+8+1+4)
	copy(aad, headerDigest[:])
	binary.BigEndian.PutUint64(aad[sha256.Size:sha256.Size+8], index)
	aad[sha256.Size+8] = flag
	binary.BigEndian.PutUint32(aad[sha256.Size+9:], plainLength)
	return aad
}

type boundedCiphertextWriter struct {
	Writer  io.Writer
	Hash    hash.Hash
	Maximum int64
	Count   int64
}

func (w *boundedCiphertextWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > w.Maximum-w.Count {
		return 0, ErrLimit
	}
	n, err := w.Writer.Write(value)
	if n > 0 {
		_, _ = w.Hash.Write(value[:n])
		w.Count += int64(n)
	}
	if err == nil && n != len(value) {
		err = io.ErrShortWrite
	}
	return n, err
}

type boundedCiphertextReader struct {
	Reader  io.Reader
	Maximum int64
	Count   int64
}

func (r *boundedCiphertextReader) Read(value []byte) (int, error) {
	if r.Count >= r.Maximum {
		var probe [1]byte
		n, err := r.Reader.Read(probe[:])
		if n != 0 {
			return 0, ErrLimit
		}
		return 0, err
	}
	if int64(len(value)) > r.Maximum-r.Count {
		value = value[:r.Maximum-r.Count]
	}
	n, err := r.Reader.Read(value)
	r.Count += int64(n)
	return n, err
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		n, err := writer.Write(value)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(value) {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}
