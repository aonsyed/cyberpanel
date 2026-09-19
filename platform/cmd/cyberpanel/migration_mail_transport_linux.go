//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"sort"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

type migrationMailboxTransfer struct {
	request      mail.MaildirImportRequest
	artifact     *migration.Chunk
	manifest     migration.MaildirManifest
	chunkOffsets []uint64
	sourceDigest string
}

type migrationMailChunkReader struct {
	ctx        context.Context
	store      *migration.ChunkStore
	descriptor migration.Chunk
	offset     uint64
	digest     hash.Hash
}

func (reader *migrationMailChunkReader) Read(destination []byte) (int, error) {
	if reader.offset == reader.descriptor.Size {
		return 0, io.EOF
	}
	if len(destination) == 0 {
		return 0, nil
	}
	length := uint64(len(destination))
	if length > uint64(migration.MaildirTransportChunkMax) {
		length = uint64(migration.MaildirTransportChunkMax)
	}
	if length > reader.descriptor.Size-reader.offset {
		length = reader.descriptor.Size - reader.offset
	}
	content, err := reader.store.ReadRange(reader.ctx, reader.descriptor.Digest, reader.offset, length)
	if err != nil {
		return 0, err
	}
	if uint64(len(content)) != length {
		wipeBytes(content)
		return 0, migration.ErrConflict
	}
	_, _ = reader.digest.Write(content)
	count := copy(destination, content)
	wipeBytes(content)
	reader.offset += uint64(count)
	return count, nil
}

func (target *migrationMailTarget) mailboxTransfer(ctx context.Context, chunks []migration.Chunk) (migrationMailboxTransfer, error) {
	if len(chunks) == 0 {
		manifest, err := migration.SealMaildirManifest(nil)
		if err != nil {
			return migrationMailboxTransfer{}, err
		}
		sum := sha256.Sum256([]byte("cyberpanel-empty-maildir-v1\x00" + manifest.RootDigest))
		return migrationMailboxTransfer{manifest: manifest, sourceDigest: hex.EncodeToString(sum[:])}, nil
	}
	if len(chunks) != 1 {
		return migrationMailboxTransfer{}, migration.ErrBlocked
	}
	descriptor := chunks[0]
	if descriptor.Size < 1024 || descriptor.MediaType != migration.MaildirV1MediaType || descriptor.Compression != "tar" || descriptor.EncryptionDomain != "mailbox-data" || descriptor.ObjectCount == 0 || descriptor.ObjectCount > migration.MaildirManifestMaxFiles+1 {
		return migrationMailboxTransfer{}, migration.ErrBlocked
	}
	reader := &migrationMailChunkReader{ctx: ctx, store: target.chunks, descriptor: descriptor, digest: sha256.New()}
	archive := tar.NewReader(reader)
	generated := make([]migration.MaildirManifestFile, 0)
	offsets := map[string][]uint64{}
	seen := map[string]bool{}
	var embedded migration.MaildirManifest
	manifestSeen := false
	for {
		if err := ctx.Err(); err != nil {
			return migrationMailboxTransfer{}, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Size < 0 || header.Linkname != "" || header.Uname != "" || header.Gname != "" || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
			return migrationMailboxTransfer{}, errors.Join(migration.ErrInvalid, err)
		}
		if header.Name == migration.MaildirManifestName {
			if manifestSeen || header.Typeflag != tar.TypeReg || header.Size == 0 || header.Size > migration.MaildirManifestMaxBytes || header.Mode != 0400 || header.Uid != 0 || header.Gid != 0 || !header.ModTime.Equal(time.Unix(0, 0)) {
				return migrationMailboxTransfer{}, migration.ErrInvalid
			}
			raw, readErr := io.ReadAll(io.LimitReader(archive, header.Size+1))
			decodeErr := json.Unmarshal(raw, &embedded)
			canonicalRaw, marshalErr := json.Marshal(embedded)
			if readErr != nil || int64(len(raw)) != header.Size || decodeErr != nil || marshalErr != nil || embedded.Validate() != nil || !bytes.Equal(raw, canonicalRaw) {
				wipeBytes(raw)
				return migrationMailboxTransfer{}, errors.Join(migration.ErrInvalid, readErr, decodeErr, marshalErr)
			}
			wipeBytes(raw)
			manifestSeen = true
			continue
		}
		if manifestSeen || header.Typeflag != tar.TypeReg || !migration.ValidMaildirPath(header.Name) || seen[header.Name] || header.Mode != 0600 || header.Uid != 0 || header.Gid != 0 || !header.ModTime.Equal(time.Unix(0, 0)) {
			return migrationMailboxTransfer{}, migration.ErrInvalid
		}
		seen[header.Name] = true
		entry, entryOffsets, readErr := readMaildirArtifactEntry(ctx, archive, reader.offset, header.Name, uint64(header.Size))
		if readErr != nil {
			return migrationMailboxTransfer{}, readErr
		}
		generated = append(generated, entry)
		offsets[entry.Path] = entryOffsets
		if len(generated) > migration.MaildirManifestMaxFiles {
			return migrationMailboxTransfer{}, migration.ErrCapacity
		}
	}
	if !manifestSeen || descriptor.ObjectCount != uint64(len(generated)+1) {
		return migrationMailboxTransfer{}, migration.ErrInvalid
	}
	trailing := make([]byte, 128<<10)
	defer wipeBytes(trailing)
	for {
		count, err := reader.Read(trailing)
		for _, value := range trailing[:count] {
			if value != 0 {
				return migrationMailboxTransfer{}, migration.ErrInvalid
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return migrationMailboxTransfer{}, err
		}
	}
	if reader.offset != descriptor.Size || hex.EncodeToString(reader.digest.Sum(nil)) != descriptor.Digest {
		return migrationMailboxTransfer{}, migration.ErrConflict
	}
	sort.Slice(generated, func(i, j int) bool { return generated[i].Path < generated[j].Path })
	canonical, err := migration.SealMaildirManifest(generated)
	if err != nil {
		return migrationMailboxTransfer{}, err
	}
	left, _ := json.Marshal(canonical)
	right, _ := json.Marshal(embedded)
	if !bytes.Equal(left, right) {
		return migrationMailboxTransfer{}, migration.ErrConflict
	}
	flatOffsets := make([]uint64, 0, canonical.ChunkCount())
	for _, file := range canonical.Files {
		if len(offsets[file.Path]) != len(file.ChunkDigests) {
			return migrationMailboxTransfer{}, migration.ErrConflict
		}
		flatOffsets = append(flatOffsets, offsets[file.Path]...)
	}
	copyDescriptor := descriptor
	return migrationMailboxTransfer{artifact: &copyDescriptor, manifest: canonical, chunkOffsets: flatOffsets, sourceDigest: descriptor.Digest}, nil
}

func readMaildirArtifactEntry(ctx context.Context, archive io.Reader, dataOffset uint64, name string, size uint64) (migration.MaildirManifestFile, []uint64, error) {
	entry := migration.MaildirManifestFile{Path: name, Size: size}
	offsets := make([]uint64, 0)
	whole := sha256.New()
	chunk := sha256.New()
	var chunkOffset uint64
	var chunkSize uint32
	buffer := make([]byte, 128<<10)
	defer wipeBytes(buffer)
	var read uint64
	for read < size {
		if err := ctx.Err(); err != nil {
			return entry, nil, err
		}
		window := uint64(len(buffer))
		if window > size-read {
			window = size - read
		}
		count, readErr := archive.Read(buffer[:window])
		for consumed := 0; consumed < count; {
			available := int(migration.MaildirTransportChunkMax - chunkSize)
			partSize := count - consumed
			if partSize > available {
				partSize = available
			}
			part := buffer[consumed : consumed+partSize]
			_, _ = whole.Write(part)
			_, _ = chunk.Write(part)
			chunkSize += uint32(partSize)
			consumed += partSize
			read += uint64(partSize)
			if chunkSize == migration.MaildirTransportChunkMax {
				entry.ChunkDigests = append(entry.ChunkDigests, hex.EncodeToString(chunk.Sum(nil)))
				offsets = append(offsets, dataOffset+chunkOffset)
				chunkOffset += uint64(chunkSize)
				chunk, chunkSize = sha256.New(), 0
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return entry, nil, readErr
		}
		if count == 0 {
			return entry, nil, io.ErrUnexpectedEOF
		}
	}
	if chunkSize != 0 {
		entry.ChunkDigests = append(entry.ChunkDigests, hex.EncodeToString(chunk.Sum(nil)))
		offsets = append(offsets, dataOffset+chunkOffset)
	}
	entry.Digest = hex.EncodeToString(whole.Sum(nil))
	return entry, offsets, nil
}

func (target *migrationMailTarget) stageMailboxTransfer(ctx context.Context, transfer migrationMailboxTransfer) (mail.MaildirImportReceipt, error) {
	request := transfer.request
	request.Operation = "observe"
	receipt, err := target.runtime.ImportMaildir(ctx, request)
	if errors.Is(err, mail.ErrNotFound) {
		request.Operation = "begin"
		manifest := transfer.manifest
		request.Manifest = &manifest
		receipt, err = target.runtime.ImportMaildir(ctx, request)
		request.Manifest = nil
	}
	if err != nil {
		return receipt, err
	}
	if !mailboxTransferReceiptMatches(receipt, transfer) {
		return receipt, migration.ErrConflict
	}
	if receipt.State == "sealed" {
		if receipt.NextChunk != transfer.manifest.ChunkCount() {
			return receipt, migration.ErrConflict
		}
		return receipt, nil
	}
	if receipt.State != "receiving" || int(receipt.NextChunk) > len(transfer.chunkOffsets) {
		return receipt, migration.ErrConflict
	}
	for sequence := receipt.NextChunk; sequence < transfer.manifest.ChunkCount(); sequence++ {
		if transfer.artifact == nil {
			return receipt, migration.ErrConflict
		}
		_, expected, ok := transfer.manifest.Chunk(sequence)
		if !ok {
			return receipt, migration.ErrConflict
		}
		content, readErr := target.chunks.ReadRange(ctx, transfer.artifact.Digest, transfer.chunkOffsets[sequence], uint64(expected.Size))
		if readErr != nil {
			return receipt, readErr
		}
		request.Operation = "chunk"
		request.Sequence = sequence
		request.ChunkDigest = expected.Digest
		request.Data = content
		receipt, err = target.runtime.ImportMaildir(ctx, request)
		wipeBytes(content)
		request.Data = nil
		if err != nil || !mailboxTransferReceiptMatches(receipt, transfer) || receipt.State != "receiving" || receipt.NextChunk != sequence+1 {
			return receipt, errors.Join(migration.ErrConflict, err)
		}
	}
	request.Operation = "seal"
	request.Sequence = 0
	request.ChunkDigest = ""
	receipt, err = target.runtime.ImportMaildir(ctx, request)
	if err != nil || !mailboxTransferReceiptMatches(receipt, transfer) || receipt.State != "sealed" || receipt.NextChunk != transfer.manifest.ChunkCount() {
		return receipt, errors.Join(migration.ErrBlocked, err)
	}
	return receipt, nil
}

func mailboxTransferReceiptMatches(receipt mail.MaildirImportReceipt, transfer migrationMailboxTransfer) bool {
	return receipt.SourceDigest == transfer.sourceDigest && receipt.ManifestRoot == transfer.manifest.RootDigest && receipt.Bytes == transfer.manifest.TotalBytes && receipt.Objects == transfer.manifest.TotalFiles && receipt.NextChunk <= transfer.manifest.ChunkCount()
}

func (target *migrationMailTarget) discardMailboxTransfer(ctx context.Context, transfer migrationMailboxTransfer) (mail.MaildirImportReceipt, error) {
	request := transfer.request
	request.Operation = "discard"
	receipt, err := target.runtime.ImportMaildir(ctx, request)
	if err == nil && (!mailboxTransferReceiptMatches(receipt, transfer) || receipt.State != "discarded") {
		err = migration.ErrConflict
	}
	return receipt, err
}
