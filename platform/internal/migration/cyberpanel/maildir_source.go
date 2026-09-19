package cyberpanel

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

// MaildirTreeSource emits a canonical v1 artifact containing only safe,
// single-link regular messages in cur/ and new/. Its manifest is appended to
// the tar so every file and transport chunk is hashed from the same snapshot.
type MaildirTreeSource struct {
	root *os.Root
}

func OpenMaildirTreeSource(rootPath string) (*MaildirTreeSource, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, ErrInvalid
	}
	maildirPath := rootPath
	if _, err := os.Lstat(filepath.Join(maildirPath, "cur")); errors.Is(err, os.ErrNotExist) {
		maildirPath = filepath.Join(rootPath, "Maildir")
	}
	before, err := os.Lstat(maildirPath)
	if err != nil || !before.IsDir() {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(maildirPath)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, ErrChanged
	}
	return &MaildirTreeSource{root: root}, nil
}

func (source *MaildirTreeSource) Close() error {
	if source == nil || source.root == nil {
		return nil
	}
	return source.root.Close()
}

func (*MaildirTreeSource) MediaType() string        { return migration.MaildirV1MediaType }
func (*MaildirTreeSource) Compression() string      { return "tar" }
func (*MaildirTreeSource) EncryptionDomain() string { return "mailbox-data" }

func (source *MaildirTreeSource) WriteSnapshot(ctx context.Context, destination io.Writer) (uint64, error) {
	if source == nil || source.root == nil || ctx == nil || destination == nil {
		return 0, ErrInvalid
	}
	rootBefore, err := source.root.Stat(".")
	if err != nil {
		return 0, err
	}
	writer := tar.NewWriter(destination)
	closed := false
	defer func() {
		if !closed {
			_ = writer.Close()
		}
	}()
	files := make([]migration.MaildirManifestFile, 0)
	for _, directory := range []string{"cur", "new"} {
		directoryBefore, err := source.root.Lstat(directory)
		if err != nil || !directoryBefore.IsDir() || directoryBefore.Mode()&os.ModeSymlink != 0 {
			return 0, errors.Join(ErrDenied, err)
		}
		handle, err := source.root.Open(directory)
		if err != nil {
			return 0, err
		}
		directoryOpened, err := handle.Stat()
		if err != nil || !sameFileState(directoryBefore, directoryOpened) {
			handle.Close()
			return 0, errors.Join(ErrChanged, err)
		}
		names := make([]string, 0)
		for {
			entries, readErr := handle.ReadDir(4096)
			for _, entry := range entries {
				name := directory + "/" + entry.Name()
				if !migration.ValidMaildirPath(name) {
					handle.Close()
					return 0, ErrDenied
				}
				names = append(names, name)
				if len(names)+len(files) > migration.MaildirManifestMaxFiles {
					handle.Close()
					return 0, migration.ErrCapacity
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				handle.Close()
				return 0, readErr
			}
			if len(entries) == 0 {
				handle.Close()
				return 0, io.ErrNoProgress
			}
		}
		handle.Close()
		sort.Strings(names)
		for _, name := range names {
			if err = ctx.Err(); err != nil {
				return 0, err
			}
			info, err := source.root.Lstat(name)
			if err != nil || !info.Mode().IsRegular() || !singleLink(info) || info.Size() < 0 {
				return 0, errors.Join(ErrDenied, err)
			}
			header := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0600, Size: info.Size(), ModTime: time.Unix(0, 0), AccessTime: time.Unix(0, 0), ChangeTime: time.Unix(0, 0), Format: tar.FormatGNU}
			if err = writer.WriteHeader(header); err != nil {
				return 0, err
			}
			manifestFile, err := source.writeMessage(ctx, writer, name, info)
			if err != nil {
				return 0, err
			}
			files = append(files, manifestFile)
			if len(files) > migration.MaildirManifestMaxFiles {
				return 0, migration.ErrCapacity
			}
		}
		directoryAfter, err := source.root.Lstat(directory)
		if err != nil || !sameFileState(directoryBefore, directoryAfter) {
			return 0, errors.Join(ErrChanged, err)
		}
	}
	rootAfter, err := source.root.Stat(".")
	if err != nil || !sameFileState(rootBefore, rootAfter) {
		return 0, errors.Join(ErrChanged, err)
	}
	manifest, err := migration.SealMaildirManifest(files)
	if err != nil {
		return 0, err
	}
	raw, err := json.Marshal(manifest)
	if err != nil || len(raw) > migration.MaildirManifestMaxBytes {
		return 0, errors.Join(migration.ErrCapacity, err)
	}
	header := &tar.Header{Name: migration.MaildirManifestName, Typeflag: tar.TypeReg, Mode: 0400, Size: int64(len(raw)), ModTime: time.Unix(0, 0), AccessTime: time.Unix(0, 0), ChangeTime: time.Unix(0, 0), Format: tar.FormatGNU}
	if err = writer.WriteHeader(header); err == nil {
		var count int
		count, err = writer.Write(raw)
		if err == nil && count != len(raw) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = writer.Close()
		closed = true
	}
	if err != nil {
		return 0, err
	}
	return uint64(len(files) + 1), nil
}

func (source *MaildirTreeSource) writeMessage(ctx context.Context, destination io.Writer, name string, before os.FileInfo) (migration.MaildirManifestFile, error) {
	file, err := source.root.Open(name)
	if err != nil {
		return migration.MaildirManifestFile{}, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !sameFileState(before, after) || !after.Mode().IsRegular() || !singleLink(after) {
		return migration.MaildirManifestFile{}, ErrChanged
	}
	entry := migration.MaildirManifestFile{Path: name, Size: uint64(after.Size())}
	whole := sha256.New()
	chunk := sha256.New()
	var chunkOffset uint64
	var chunkSize uint32
	buffer := make([]byte, 128<<10)
	defer wipe(buffer)
	for {
		if err = ctx.Err(); err != nil {
			return entry, err
		}
		count, readErr := file.Read(buffer)
		for consumed := 0; consumed < count; {
			remaining := int(migration.MaildirTransportChunkMax - chunkSize)
			window := count - consumed
			if window > remaining {
				window = remaining
			}
			part := buffer[consumed : consumed+window]
			if count, writeErr := destination.Write(part); writeErr != nil || count != len(part) {
				err = errors.Join(writeErr, io.ErrShortWrite)
				return entry, err
			}
			_, _ = whole.Write(part)
			_, _ = chunk.Write(part)
			chunkSize += uint32(window)
			consumed += window
			if chunkSize == migration.MaildirTransportChunkMax {
				entry.ChunkDigests = append(entry.ChunkDigests, finishMaildirChunk(chunk))
				chunkOffset += uint64(chunkSize)
				chunk = sha256.New()
				chunkSize = 0
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return entry, readErr
		}
		if count == 0 {
			return entry, io.ErrNoProgress
		}
	}
	if chunkSize != 0 {
		entry.ChunkDigests = append(entry.ChunkDigests, finishMaildirChunk(chunk))
	}
	entry.Digest = hex.EncodeToString(whole.Sum(nil))
	final, err := file.Stat()
	if err != nil || !sameFileState(after, final) || !singleLink(final) || chunkOffset+uint64(chunkSize) != entry.Size {
		return entry, ErrChanged
	}
	return entry, nil
}

func finishMaildirChunk(value hash.Hash) string {
	return hex.EncodeToString(value.Sum(nil))
}

func singleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

var _ ArtifactSource = (*MaildirTreeSource)(nil)
