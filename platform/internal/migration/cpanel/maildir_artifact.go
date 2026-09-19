package cpanel

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
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

func (source *archiveArtifactSource) writeMaildirTree(ctx context.Context, reader *tar.Reader, destination io.Writer, before os.FileInfo) (uint64, error) {
	writer := tar.NewWriter(destination)
	closed := false
	defer func() {
		if !closed {
			_ = writer.Close()
		}
	}()
	seen := map[string]bool{}
	files := make([]migration.MaildirManifestFile, 0)
	var expanded uint64
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		logical, err := logicalArchiveName(header.Name)
		if err != nil {
			return 0, err
		}
		if !strings.HasPrefix(logical, source.spec.prefix) {
			continue
		}
		relative := strings.TrimPrefix(strings.TrimPrefix(logical, source.spec.prefix), "/")
		relative = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(relative)), "Maildir/")
		if relative == "" || relative == "." || relative == "cur" || relative == "new" || relative == "tmp" {
			if header.Typeflag != tar.TypeDir && relative != "" && relative != "." {
				return 0, ErrDenied
			}
			continue
		}
		parts := strings.Split(relative, "/")
		insideMessages := len(parts) > 0 && (parts[0] == "cur" || parts[0] == "new")
		if !insideMessages {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || !migration.ValidMaildirPath(relative) || header.Size < 0 || seen[relative] || expanded > source.limits.MaximumExpandedBytes || uint64(header.Size) > source.limits.MaximumExpandedBytes-expanded {
			return 0, ErrDenied
		}
		seen[relative] = true
		expanded += uint64(header.Size)
		canonical := &tar.Header{Name: relative, Typeflag: tar.TypeReg, Mode: 0600, Size: header.Size, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0), AccessTime: time.Unix(0, 0), ChangeTime: time.Unix(0, 0), Format: tar.FormatGNU}
		if err = writer.WriteHeader(canonical); err != nil {
			return 0, err
		}
		entry, err := copyMaildirArchiveMessage(ctx, writer, reader, relative, uint64(header.Size))
		if err != nil {
			return 0, err
		}
		files = append(files, entry)
		if len(files) > migration.MaildirManifestMaxFiles || uint64(len(files)+1) > source.limits.MaximumEntries {
			return 0, migrationCapacity()
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	manifest, err := migration.SealMaildirManifest(files)
	if err != nil {
		return 0, err
	}
	raw, err := json.Marshal(manifest)
	if err != nil || len(raw) > migration.MaildirManifestMaxBytes {
		return 0, errors.Join(migrationCapacity(), err)
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
	if err = archiveUnchanged(source.archive.path, before); err != nil {
		return 0, err
	}
	return uint64(len(files) + 1), nil
}

func copyMaildirArchiveMessage(ctx context.Context, destination io.Writer, source io.Reader, name string, size uint64) (migration.MaildirManifestFile, error) {
	entry := migration.MaildirManifestFile{Path: name, Size: size}
	whole := sha256.New()
	chunk := sha256.New()
	var chunkSize uint32
	buffer := make([]byte, 128<<10)
	defer wipe(buffer)
	var written uint64
	for written < size {
		if err := ctx.Err(); err != nil {
			return entry, err
		}
		window := uint64(len(buffer))
		if window > size-written {
			window = size - written
		}
		count, readErr := source.Read(buffer[:window])
		for consumed := 0; consumed < count; {
			available := int(migration.MaildirTransportChunkMax - chunkSize)
			partSize := count - consumed
			if partSize > available {
				partSize = available
			}
			part := buffer[consumed : consumed+partSize]
			if output, err := destination.Write(part); err != nil || output != len(part) {
				return entry, errors.Join(err, io.ErrShortWrite)
			}
			_, _ = whole.Write(part)
			_, _ = chunk.Write(part)
			chunkSize += uint32(partSize)
			consumed += partSize
			written += uint64(partSize)
			if chunkSize == migration.MaildirTransportChunkMax {
				entry.ChunkDigests = append(entry.ChunkDigests, archiveMaildirChunk(chunk))
				chunk, chunkSize = sha256.New(), 0
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return entry, readErr
		}
		if count == 0 {
			return entry, io.ErrUnexpectedEOF
		}
	}
	if chunkSize != 0 {
		entry.ChunkDigests = append(entry.ChunkDigests, archiveMaildirChunk(chunk))
	}
	entry.Digest = hex.EncodeToString(whole.Sum(nil))
	return entry, nil
}

func archiveMaildirChunk(value hash.Hash) string {
	return hex.EncodeToString(value.Sum(nil))
}
