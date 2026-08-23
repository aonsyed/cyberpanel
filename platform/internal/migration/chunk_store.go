package migration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	defaultMaximumChunkSize = uint64(64 << 30)
	maximumRangeRead        = uint64(16 << 20)
)

// ChunkStore is a local content-addressed staging repository. It never accepts
// a caller path: the only addressing input is a verified SHA-256 digest.
type ChunkStore struct {
	root         *os.Root
	rootPath     string
	maximumBytes uint64
	mu           sync.Mutex
}

func OpenChunkStore(rootPath string, maximumBytes uint64) (*ChunkStore, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(rootPath)
	if err != nil || !before.IsDir() || before.Mode().Perm()&0o077 != 0 {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, ErrInvalid
	}
	if maximumBytes == 0 {
		maximumBytes = defaultMaximumChunkSize
	}
	if maximumBytes < 1<<20 || maximumBytes > uint64(math.MaxInt64) {
		root.Close()
		return nil, ErrInvalid
	}
	store := &ChunkStore{root: root, rootPath: rootPath, maximumBytes: maximumBytes}
	if err := store.ensureDirectory("sha256"); err != nil {
		root.Close()
		return nil, err
	}
	return store, nil
}

func (s *ChunkStore) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.Close()
}

func (s *ChunkStore) Put(ctx context.Context, descriptor Chunk, source io.Reader) error {
	if s == nil || s.root == nil || ctx == nil || source == nil || !validChunk(descriptor, s.maximumBytes) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix, final, err := chunkNames(descriptor.Digest)
	if err != nil {
		return err
	}
	if err := s.ensureDirectory(prefix); err != nil {
		return err
	}
	if present, err := s.verifyExisting(ctx, final, descriptor); err != nil || present {
		return err
	}
	temporary, err := temporaryName(prefix, descriptor.Digest)
	if err != nil {
		return err
	}
	file, err := s.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	keepTemporary := true
	defer func() {
		file.Close()
		if keepTemporary {
			_ = s.root.Remove(temporary)
		}
	}()
	hash := sha256.New()
	written, err := copyContext(ctx, io.MultiWriter(file, hash), io.LimitReader(source, int64(descriptor.Size)+1))
	if err != nil {
		return err
	}
	if uint64(written) != descriptor.Size || subtle.ConstantTimeCompare(hash.Sum(nil), mustDecodeDigest(descriptor.Digest)) != 1 {
		return errors.Join(ErrInvalid, errors.New("chunk digest or size mismatch"))
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Chmod(0o400); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := s.root.Link(temporary, final); err != nil {
		if present, verifyErr := s.verifyExisting(ctx, final, descriptor); verifyErr != nil || !present {
			return errors.Join(err, verifyErr)
		}
	}
	if err := s.root.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	keepTemporary = false
	return s.syncDirectory(prefix)
}

func (s *ChunkStore) Has(ctx context.Context, descriptor Chunk) (bool, error) {
	if s == nil || s.root == nil || ctx == nil || !validChunk(descriptor, s.maximumBytes) {
		return false, ErrInvalid
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	_, final, err := chunkNames(descriptor.Digest)
	if err != nil {
		return false, err
	}
	return s.verifyExisting(ctx, final, descriptor)
}

func (s *ChunkStore) ReadRange(ctx context.Context, digest string, offset, length uint64) ([]byte, error) {
	if s == nil || s.root == nil || ctx == nil || !isDigest(digest) || length == 0 || length > maximumRangeRead || offset > ^uint64(0)-length {
		return nil, ErrInvalid
	}
	_, name, err := chunkNames(digest)
	if err != nil {
		return nil, err
	}
	file, err := s.openRegular(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || offset+length > uint64(info.Size()) {
		return nil, ErrInvalid
	}
	buffer := make([]byte, length)
	read := 0
	for read < len(buffer) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		count, readErr := file.ReadAt(buffer[read:], int64(offset)+int64(read))
		read += count
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, readErr
		}
		if count == 0 {
			return nil, io.ErrUnexpectedEOF
		}
	}
	return buffer, nil
}

func (s *ChunkStore) Verify(ctx context.Context, descriptor Chunk) error {
	if s == nil || s.root == nil || ctx == nil || !validChunk(descriptor, s.maximumBytes) {
		return ErrInvalid
	}
	_, name, err := chunkNames(descriptor.Digest)
	if err != nil {
		return err
	}
	file, err := s.openRegular(name)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || uint64(info.Size()) != descriptor.Size {
		return ErrInvalid
	}
	hash := sha256.New()
	if _, err := copyContext(ctx, hash, io.LimitReader(file, int64(descriptor.Size)+1)); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), mustDecodeDigest(descriptor.Digest)) != 1 {
		return ErrInvalid
	}
	return nil
}

// deleteQuarantined removes only the canonical path derived from digest. The
// caller may allow an absent path solely when it has already persisted a
// deletion intent or when the object was never confirmed as materialized.
func (s *ChunkStore) deleteQuarantined(ctx context.Context, digest string, size uint64, allowMissing bool) error {
	if s == nil || s.root == nil || ctx == nil || !isDigest(digest) || size > s.maximumBytes {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	prefix, name, err := chunkNames(digest)
	if err != nil {
		return err
	}
	descriptor := Chunk{Digest: digest, Size: size}
	present, err := s.verifyExisting(ctx, name, descriptor)
	if err != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	if !present {
		if !allowMissing {
			return errors.Join(ErrAmbiguous, ErrNotFound)
		}
		if err := s.syncDirectory(prefix); err != nil {
			return errors.Join(ErrAmbiguous, err)
		}
		return nil
	}
	if err := s.root.Remove(name); err != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	if err := s.syncDirectory(prefix); err != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	if _, err := s.root.Lstat(name); err == nil {
		return ErrAmbiguous
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrAmbiguous, err)
	}
	return nil
}

func (s *ChunkStore) inspectForGarbageCollection(ctx context.Context, digest string, size uint64, allowMissing bool) error {
	if s == nil || s.root == nil || ctx == nil || !isDigest(digest) || size > s.maximumBytes {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, name, err := chunkNames(digest)
	if err != nil {
		return err
	}
	present, err := s.verifyExisting(ctx, name, Chunk{Digest: digest, Size: size})
	if err != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	if !present && !allowMissing {
		return errors.Join(ErrAmbiguous, ErrNotFound)
	}
	return nil
}

func (s *ChunkStore) verifyExisting(ctx context.Context, name string, descriptor Chunk) (bool, error) {
	file, err := s.openRegular(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || uint64(info.Size()) != descriptor.Size || info.Mode().Perm() != 0o400 {
		return false, ErrConflict
	}
	hash := sha256.New()
	if _, err := copyContext(ctx, hash, io.LimitReader(file, int64(descriptor.Size)+1)); err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), mustDecodeDigest(descriptor.Digest)) != 1 {
		return false, ErrConflict
	}
	return true, nil
}

func (s *ChunkStore) openRegular(name string) (*os.File, error) {
	if !validChunkPath(name) {
		return nil, ErrInvalid
	}
	before, err := s.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 {
		return nil, ErrInvalid
	}
	file, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o400 {
		file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

func (s *ChunkStore) ensureDirectory(name string) error {
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || strings.Contains(name, "..") {
		return ErrInvalid
	}
	if err := s.root.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := s.root.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrInvalid
	}
	return s.syncDirectory(filepath.Dir(name))
}

func (s *ChunkStore) syncDirectory(name string) error {
	if name == "." {
		name = "."
	}
	directory, err := s.root.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func chunkNames(digest string) (string, string, error) {
	if !isDigest(digest) {
		return "", "", ErrInvalid
	}
	prefix := filepath.Join("sha256", digest[:2])
	name := filepath.Join(prefix, digest)
	if !validChunkPath(prefix) || !validChunkPath(name) {
		return "", "", ErrInvalid
	}
	return prefix, name, nil
}

func validChunkPath(name string) bool {
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name {
		return false
	}
	separator := string(filepath.Separator)
	return name == "sha256" || strings.HasPrefix(name, "sha256"+separator) && !strings.Contains(name, "..")
}

func temporaryName(prefix, digest string) (string, error) {
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}
	return filepath.Join(prefix, fmt.Sprintf(".%s.incoming-%s", digest, hex.EncodeToString(random))), nil
}

func validChunk(value Chunk, maximum uint64) bool {
	return isDigest(value.Digest) && value.Size <= maximum && value.MediaType != "" && len(value.MediaType) <= 255 && len(value.Compression) <= 64 && len(value.EncryptionDomain) <= 128
}

func mustDecodeDigest(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 256<<10)
	var total int64
	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
		if read == 0 {
			return total, io.ErrNoProgress
		}
	}
}
