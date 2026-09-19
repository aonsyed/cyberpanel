//go:build linux

package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

func maildirBinding(request MaildirImportRequest) maildirImportBinding {
	return maildirImportBinding{ImportID: request.ImportID, TenantID: request.TenantID, SiteID: request.SiteID, DomainID: request.DomainID, MailboxID: request.MailboxID, Domain: request.Domain, Local: request.Local, CredentialRef: request.CredentialRef, QuotaBytes: request.QuotaBytes, SourceDigest: request.SourceDigest, ManifestRoot: request.ManifestRoot}
}

func (host *LinuxMailHost) beginMaildirTransfer(ctx context.Context, directory int, request MaildirImportRequest, identity siteops.RuntimeBinding) (MaildirImportReceipt, error) {
	binding := maildirBinding(request)
	encoded, _ := json.Marshal(binding)
	if prior, err := readMailImportFile(directory, "binding.json", 16<<10); err == nil {
		defer wipeMailBytes(prior)
		if !bytes.Equal(prior, encoded) {
			return MaildirImportReceipt{}, ErrConflict
		}
	} else if errors.Is(err, syscall.ENOENT) {
		if err = writeMailImportFile(directory, "binding.json", encoded); err != nil {
			return MaildirImportReceipt{}, err
		}
	} else {
		return MaildirImportReceipt{}, err
	}
	sealed := maildirManifest{Version: 1, Binding: binding, Manifest: *request.Manifest, UID: identity.UID, GID: identity.GID}
	manifestRaw, err := json.Marshal(sealed)
	if err != nil || len(manifestRaw) > migration.MaildirManifestMaxBytes+16<<10 {
		return MaildirImportReceipt{}, errors.Join(ErrInvalidCommand, err)
	}
	if prior, readErr := readMailImportFile(directory, "manifest.json", int64(migration.MaildirManifestMaxBytes+16<<10)); readErr == nil {
		defer wipeMailBytes(prior)
		if !bytes.Equal(prior, manifestRaw) {
			return MaildirImportReceipt{}, ErrConflict
		}
	} else if errors.Is(readErr, syscall.ENOENT) {
		if err = writeMailImportFile(directory, "manifest.json", manifestRaw); err != nil {
			return MaildirImportReceipt{}, err
		}
	} else {
		return MaildirImportReceipt{}, readErr
	}
	for _, name := range []string{"Maildir", "Maildir/cur", "Maildir/new", "Maildir/tmp", "chunks"} {
		fd, directoryErr := mailDirectory(directory, name, true)
		if directoryErr != nil {
			return MaildirImportReceipt{}, directoryErr
		}
		syscall.Close(fd)
	}
	journal, journalErr := loadMaildirTransferJournal(directory)
	if errors.Is(journalErr, syscall.ENOENT) {
		journal = maildirTransferJournal{Version: 1, State: "receiving", UID: identity.UID, GID: identity.GID, UpdatedAt: host.now()}
		journalErr = saveMaildirTransferJournal(directory, journal)
	}
	if journalErr != nil {
		return MaildirImportReceipt{}, journalErr
	}
	sealed, journal, err = loadMaildirTransfer(directory, request, identity)
	if err != nil {
		return MaildirImportReceipt{}, err
	}
	return host.observeLoadedMaildirTransfer(ctx, directory, request, identity, sealed, journal)
}

func (host *LinuxMailHost) mutateMaildirTransfer(ctx context.Context, directory int, request MaildirImportRequest, identity siteops.RuntimeBinding) (MaildirImportReceipt, error) {
	manifest, journal, err := loadMaildirTransfer(directory, request, identity)
	if err != nil {
		return MaildirImportReceipt{}, err
	}
	switch request.Operation {
	case "observe":
		return host.observeLoadedMaildirTransfer(ctx, directory, request, identity, manifest, journal)
	case "chunk":
		_, expected, ok := manifest.Manifest.Chunk(request.Sequence)
		if !ok || expected.Digest != request.ChunkDigest || uint32(len(request.Data)) != expected.Size {
			return MaildirImportReceipt{}, ErrConflict
		}
		if journal.State == "sealed" {
			return host.observeLoadedMaildirTransfer(ctx, directory, request, identity, manifest, journal)
		}
		if journal.State != "receiving" || request.Sequence > journal.NextChunk {
			return MaildirImportReceipt{}, ErrConflict
		}
		chunks, openErr := mailDirectory(directory, "chunks", false)
		if openErr != nil {
			return MaildirImportReceipt{}, openErr
		}
		if openErr = cleanupMaildirTemporaries(chunks); openErr != nil {
			syscall.Close(chunks)
			return MaildirImportReceipt{}, openErr
		}
		name := maildirChunkName(request.Sequence)
		writeErr := writeMailImportFile(chunks, name, request.Data)
		syscall.Close(chunks)
		if writeErr != nil {
			return MaildirImportReceipt{}, writeErr
		}
		if request.Sequence == journal.NextChunk {
			journal.NextChunk++
			journal.UpdatedAt = host.now()
			if err = saveMaildirTransferJournal(directory, journal); err != nil {
				return MaildirImportReceipt{}, err
			}
		}
		return maildirTransferReceipt(request, manifest.Manifest, journal), nil
	case "seal":
		if journal.State == "sealed" {
			return host.observeLoadedMaildirTransfer(ctx, directory, request, identity, manifest, journal)
		}
		if journal.State != "receiving" && journal.State != "sealing" || journal.NextChunk != manifest.Manifest.ChunkCount() {
			return MaildirImportReceipt{}, ErrConflict
		}
		journal.State = "sealing"
		journal.UpdatedAt = host.now()
		if err = saveMaildirTransferJournal(directory, journal); err != nil {
			return MaildirImportReceipt{}, err
		}
		if err = sealMaildirPayload(ctx, directory, manifest); err != nil {
			return maildirTransferReceipt(request, manifest.Manifest, journal), errors.Join(ErrAmbiguous, err)
		}
		if err = verifyMaildirPayload(ctx, directory, manifest, identity.UID, identity.GID, false); err != nil {
			return maildirTransferReceipt(request, manifest.Manifest, journal), errors.Join(ErrAmbiguous, err)
		}
		journal.State = "sealed"
		journal.UpdatedAt = host.now()
		if err = saveMaildirTransferJournal(directory, journal); err != nil {
			return MaildirImportReceipt{}, err
		}
		cleanupErr := cleanupMaildirChunks(directory, manifest.Manifest)
		return maildirTransferReceipt(request, manifest.Manifest, journal), cleanupErr
	case "discard":
		if journal.State == "discarded" {
			return maildirTransferReceipt(request, manifest.Manifest, journal), discardMaildirPayload(directory, manifest.Manifest)
		}
		if journal.State != "receiving" && journal.State != "sealing" && journal.State != "sealed" {
			return MaildirImportReceipt{}, ErrConflict
		}
		journal.State = "discarded"
		journal.UpdatedAt = host.now()
		if err = saveMaildirTransferJournal(directory, journal); err != nil {
			return MaildirImportReceipt{}, err
		}
		cleanupErr := discardMaildirPayload(directory, manifest.Manifest)
		return maildirTransferReceipt(request, manifest.Manifest, journal), cleanupErr
	default:
		return MaildirImportReceipt{}, ErrInvalidCommand
	}
}

func (host *LinuxMailHost) observeLoadedMaildirTransfer(ctx context.Context, directory int, request MaildirImportRequest, identity siteops.RuntimeBinding, manifest maildirManifest, journal maildirTransferJournal) (MaildirImportReceipt, error) {
	if err := ctx.Err(); err != nil {
		return MaildirImportReceipt{}, err
	}
	switch journal.State {
	case "receiving", "sealing":
		if err := verifyMaildirChunks(ctx, directory, manifest.Manifest, journal.NextChunk); err != nil {
			return MaildirImportReceipt{}, err
		}
	case "sealed":
		if err := verifyMaildirPayload(ctx, directory, manifest, identity.UID, identity.GID, false); err != nil {
			return MaildirImportReceipt{}, err
		}
		if err := cleanupMaildirChunks(directory, manifest.Manifest); err != nil {
			return maildirTransferReceipt(request, manifest.Manifest, journal), err
		}
	case "discarded":
		if err := discardMaildirPayload(directory, manifest.Manifest); err != nil {
			return maildirTransferReceipt(request, manifest.Manifest, journal), err
		}
	}
	return maildirTransferReceipt(request, manifest.Manifest, journal), nil
}

func loadMaildirTransfer(directory int, request MaildirImportRequest, identity siteops.RuntimeBinding) (maildirManifest, maildirTransferJournal, error) {
	var manifest maildirManifest
	bindingRaw, err := readMailImportFile(directory, "binding.json", 16<<10)
	if err != nil {
		return manifest, maildirTransferJournal{}, err
	}
	defer wipeMailBytes(bindingRaw)
	expected, _ := json.Marshal(maildirBinding(request))
	if !bytes.Equal(bindingRaw, expected) {
		return manifest, maildirTransferJournal{}, ErrConflict
	}
	manifestRaw, err := readMailImportFile(directory, "manifest.json", int64(migration.MaildirManifestMaxBytes+16<<10))
	if err != nil {
		return manifest, maildirTransferJournal{}, err
	}
	defer wipeMailBytes(manifestRaw)
	if json.Unmarshal(manifestRaw, &manifest) != nil || manifest.Version != 1 || manifest.Manifest.Validate() != nil || manifest.Manifest.RootDigest != request.ManifestRoot || manifest.Binding != maildirBinding(request) || manifest.UID != identity.UID || manifest.GID != identity.GID || manifest.Manifest.TotalBytes > request.QuotaBytes {
		return manifest, maildirTransferJournal{}, ErrConflict
	}
	journal, err := loadMaildirTransferJournal(directory)
	if err != nil || journal.Version != 1 || journal.UID != identity.UID || journal.GID != identity.GID || journal.NextChunk > manifest.Manifest.ChunkCount() || journal.State != "receiving" && journal.State != "sealing" && journal.State != "sealed" && journal.State != "discarded" {
		return manifest, journal, errors.Join(ErrConflict, err)
	}
	return manifest, journal, nil
}

func loadMaildirTransferJournal(directory int) (maildirTransferJournal, error) {
	var journal maildirTransferJournal
	raw, err := readMailImportFile(directory, "transfer.json", 16<<10)
	if err != nil {
		return journal, err
	}
	defer wipeMailBytes(raw)
	if json.Unmarshal(raw, &journal) != nil || journal.UpdatedAt.IsZero() {
		return journal, ErrConflict
	}
	return journal, nil
}

func saveMaildirTransferJournal(directory int, journal maildirTransferJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return replaceMailImportFile(directory, "transfer.json", raw)
}

func maildirTransferReceipt(request MaildirImportRequest, manifest migration.MaildirManifest, journal maildirTransferJournal) MaildirImportReceipt {
	state := journal.State
	if state == "sealing" {
		state = "receiving"
	}
	receipt := MaildirImportReceipt{ImportID: request.ImportID, SourceDigest: request.SourceDigest, ManifestRoot: request.ManifestRoot, State: state, NextChunk: journal.NextChunk, Bytes: manifest.TotalBytes, Objects: manifest.TotalFiles, ObservedAt: journal.UpdatedAt}
	receipt.EvidenceDigest = digestMailEvidence(receipt.ImportID, request.TenantID, request.SiteID, string(request.DomainID), string(request.MailboxID), request.Domain, request.Local, string(request.CredentialRef), fmt.Sprint(request.QuotaBytes), fmt.Sprint(journal.UID), fmt.Sprint(journal.GID), receipt.SourceDigest, receipt.ManifestRoot, receipt.State, fmt.Sprint(receipt.NextChunk), fmt.Sprint(receipt.Bytes), fmt.Sprint(receipt.Objects), receipt.ObservedAt.UTC().Format(time.RFC3339Nano))
	return receipt
}

func maildirChunkName(sequence uint64) string { return fmt.Sprintf("%020d.chunk", sequence) }

func sealMaildirPayload(ctx context.Context, directory int, sealed maildirManifest) error {
	chunks, err := mailDirectory(directory, "chunks", false)
	if err != nil {
		return err
	}
	defer syscall.Close(chunks)
	maildir, err := mailDirectory(directory, "Maildir", false)
	if err != nil {
		return err
	}
	defer syscall.Close(maildir)
	temporaryDirectory, err := mailDirectory(maildir, "tmp", false)
	if err != nil {
		return err
	}
	defer syscall.Close(temporaryDirectory)
	var sequence uint64
	for _, entry := range sealed.Manifest.Files {
		if err = ctx.Err(); err != nil {
			return err
		}
		parts := strings.Split(entry.Path, "/")
		parent, openErr := mailDirectory(maildir, parts[0], false)
		if openErr != nil {
			return openErr
		}
		if digest, size, verifyErr := hashMailFile(ctx, parent, parts[1], 0, 0, false); verifyErr == nil {
			syscall.Close(parent)
			if digest != entry.Digest || size != entry.Size {
				return ErrConflict
			}
			if unlinkErr := syscall.Unlinkat(temporaryDirectory, ".seal-"+entry.Digest[:24]); unlinkErr != nil && !errors.Is(unlinkErr, syscall.ENOENT) {
				return unlinkErr
			}
			sequence += uint64(len(entry.ChunkDigests))
			continue
		} else if !errors.Is(verifyErr, syscall.ENOENT) {
			syscall.Close(parent)
			return verifyErr
		}
		if err = assembleMaildirFile(ctx, parent, temporaryDirectory, chunks, parts[1], entry, &sequence); err != nil {
			syscall.Close(parent)
			return err
		}
		syscall.Close(parent)
	}
	if sequence != sealed.Manifest.ChunkCount() {
		return ErrConflict
	}
	return errors.Join(syscall.Fsync(temporaryDirectory), syscall.Fsync(maildir))
}

func assembleMaildirFile(ctx context.Context, parent, temporaryDirectory, chunks int, name string, entry migration.MaildirManifestFile, sequence *uint64) error {
	temporary := ".seal-" + entry.Digest[:24]
	if err := syscall.Unlinkat(temporaryDirectory, temporary); err != nil && !errors.Is(err, syscall.ENOENT) {
		return err
	}
	fd, err := mailOpenAt(temporaryDirectory, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600, false)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "maildir-seal")
	whole := sha256.New()
	var written uint64
	for _, expectedDigest := range entry.ChunkDigests {
		if err = ctx.Err(); err != nil {
			break
		}
		expectedSize := entry.Size - written
		if expectedSize > uint64(migration.MaildirTransportChunkMax) {
			expectedSize = uint64(migration.MaildirTransportChunkMax)
		}
		content, readErr := readMailImportFile(chunks, maildirChunkName(*sequence), int64(migration.MaildirTransportChunkMax))
		if readErr != nil {
			err = readErr
			break
		}
		sum := sha256.Sum256(content)
		if uint64(len(content)) != expectedSize || hex.EncodeToString(sum[:]) != expectedDigest {
			wipeMailBytes(content)
			err = ErrConflict
			break
		}
		count, writeErr := file.Write(content)
		_, _ = whole.Write(content)
		wipeMailBytes(content)
		if writeErr != nil || uint64(count) != expectedSize {
			err = errors.Join(writeErr, io.ErrShortWrite)
			break
		}
		written += uint64(count)
		(*sequence)++
	}
	if err == nil && (written != entry.Size || hex.EncodeToString(whole.Sum(nil)) != entry.Digest) {
		err = ErrConflict
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = syscall.Renameat(temporaryDirectory, temporary, parent, name)
	}
	if err != nil {
		_ = syscall.Unlinkat(temporaryDirectory, temporary)
		return err
	}
	return errors.Join(syscall.Fsync(temporaryDirectory), syscall.Fsync(parent))
}

func verifyMaildirPayload(ctx context.Context, directory int, sealed maildirManifest, uid, gid uint32, live bool) error {
	maildir, err := mailDirectory(directory, "Maildir", false)
	if err != nil {
		return err
	}
	defer syscall.Close(maildir)
	return verifyMaildirAt(ctx, maildir, sealed.Manifest, uid, gid, live)
}

func verifyMaildirAt(ctx context.Context, maildir int, manifest migration.MaildirManifest, uid, gid uint32, owned bool) error {
	var rootStat syscall.Stat_t
	if err := syscall.Fstat(maildir, &rootStat); err != nil || rootStat.Mode&0777 != 0700 || owned && (rootStat.Uid != uid || rootStat.Gid != gid) || !owned && (rootStat.Uid != 0 || rootStat.Gid != 0) {
		return errors.Join(ErrUnauthorized, err)
	}
	if owned {
		return verifyOwnedMaildirAt(ctx, maildir, manifest, uid, gid)
	}
	var rootEntries uint8
	if err := walkDirectoryNames(maildir, func(name string) error {
		switch name {
		case "cur":
			rootEntries |= 1
		case "new":
			rootEntries |= 2
		case "tmp":
			rootEntries |= 4
		default:
			return ErrConflict
		}
		return nil
	}); err != nil || rootEntries != 7 {
		return errors.Join(ErrConflict, err)
	}
	var seen uint64
	for _, subdirectory := range []string{"cur", "new", "tmp"} {
		child, openErr := mailOpenAt(maildir, subdirectory, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
		if openErr != nil {
			return openErr
		}
		var childStat syscall.Stat_t
		if statErr := syscall.Fstat(child, &childStat); statErr != nil || childStat.Mode&0777 != 0700 || owned && (childStat.Uid != uid || childStat.Gid != gid) || !owned && (childStat.Uid != 0 || childStat.Gid != 0) {
			syscall.Close(child)
			return errors.Join(ErrUnauthorized, statErr)
		}
		walkErr := walkDirectoryNames(child, func(name string) error {
			if err = ctx.Err(); err != nil {
				return err
			}
			if subdirectory == "tmp" {
				return ErrConflict
			}
			path := subdirectory + "/" + name
			index := sort.Search(len(manifest.Files), func(index int) bool { return manifest.Files[index].Path >= path })
			if index == len(manifest.Files) || manifest.Files[index].Path != path {
				return ErrConflict
			}
			entry := manifest.Files[index]
			digest, size, hashErr := hashMailFile(ctx, child, name, uid, gid, owned)
			if hashErr != nil || digest != entry.Digest || size != entry.Size {
				return errors.Join(ErrConflict, hashErr)
			}
			seen++
			return nil
		})
		syscall.Close(child)
		if walkErr != nil {
			return walkErr
		}
	}
	return nilOrConflict(seen == manifest.TotalFiles)
}

func verifyOwnedMaildirAt(ctx context.Context, maildir int, manifest migration.MaildirManifest, uid, gid uint32) error {
	directories := map[string]int{}
	for _, name := range []string{"cur", "new", "tmp"} {
		directory, err := mailOpenAt(maildir, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
		if err != nil {
			for _, opened := range directories {
				syscall.Close(opened)
			}
			return err
		}
		var stat syscall.Stat_t
		if err = syscall.Fstat(directory, &stat); err != nil || stat.Mode&0777 != 0700 || stat.Uid != uid || stat.Gid != gid {
			syscall.Close(directory)
			for _, opened := range directories {
				syscall.Close(opened)
			}
			return errors.Join(ErrUnauthorized, err)
		}
		directories[name] = directory
	}
	defer func() {
		for _, directory := range directories {
			syscall.Close(directory)
		}
	}()
	for _, entry := range manifest.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		parts := strings.Split(entry.Path, "/")
		directory, ok := directories[parts[0]]
		if len(parts) != 2 || !ok {
			return ErrConflict
		}
		digest, size, err := hashMailFile(ctx, directory, parts[1], uid, gid, true)
		if err != nil || digest != entry.Digest || size != entry.Size {
			return errors.Join(ErrConflict, err)
		}
	}
	return nil
}

func hashMailFile(ctx context.Context, directory int, name string, uid, gid uint32, owned bool) (string, uint64, error) {
	fd, err := mailOpenAt(directory, name, syscall.O_RDONLY, 0, false)
	if err != nil {
		return "", 0, err
	}
	file := os.NewFile(uintptr(fd), "maildir-message")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Nlink != 1 || owned && (stat.Uid != uid || stat.Gid != gid) || !owned && (stat.Uid != 0 || stat.Gid != 0) || info.Size() < 0 {
		return "", 0, ErrUnauthorized
	}
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	defer wipeMailBytes(buffer)
	var size uint64
	for {
		if err = ctx.Err(); err != nil {
			return "", 0, err
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			_, _ = hash.Write(buffer[:count])
			size += uint64(count)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", 0, readErr
		}
		if count == 0 {
			return "", 0, io.ErrNoProgress
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func cleanupMaildirChunks(directory int, manifest migration.MaildirManifest) error {
	chunks, err := mailDirectory(directory, "chunks", false)
	if err != nil {
		return err
	}
	defer syscall.Close(chunks)
	if err = cleanupMaildirTemporaries(chunks); err != nil {
		return err
	}
	for sequence := uint64(0); sequence < manifest.ChunkCount(); sequence++ {
		if err = syscall.Unlinkat(chunks, maildirChunkName(sequence)); err != nil && !errors.Is(err, syscall.ENOENT) {
			return err
		}
	}
	err = walkDirectoryNames(chunks, func(string) error { return ErrConflict })
	if err != nil {
		return errors.Join(ErrConflict, err)
	}
	return syscall.Fsync(chunks)
}

func verifyMaildirChunks(ctx context.Context, directory int, manifest migration.MaildirManifest, next uint64) error {
	chunks, err := mailDirectory(directory, "chunks", false)
	if err != nil {
		return err
	}
	defer syscall.Close(chunks)
	if err = cleanupMaildirTemporaries(chunks); err != nil {
		return err
	}
	var accepted uint64
	optional := false
	err = walkDirectoryNames(chunks, func(name string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(name) != 26 || !strings.HasSuffix(name, ".chunk") {
			return ErrConflict
		}
		sequence, parseErr := strconv.ParseUint(strings.TrimSuffix(name, ".chunk"), 10, 64)
		if parseErr != nil || name != maildirChunkName(sequence) || sequence > next || sequence == next && next == manifest.ChunkCount() {
			return errors.Join(ErrConflict, parseErr)
		}
		_, expected, ok := manifest.Chunk(sequence)
		if !ok {
			return ErrConflict
		}
		content, readErr := readMailImportFile(chunks, name, int64(migration.MaildirTransportChunkMax))
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(content)
		size := uint32(len(content))
		wipeMailBytes(content)
		if size != expected.Size || hex.EncodeToString(sum[:]) != expected.Digest {
			return ErrConflict
		}
		if sequence < next {
			accepted++
		} else if optional {
			return ErrConflict
		} else {
			optional = true
		}
		return nil
	})
	if err != nil || accepted != next {
		return errors.Join(ErrConflict, err)
	}
	return nil
}

func discardMaildirPayload(directory int, manifest migration.MaildirManifest) error {
	var failures []error
	maildir, err := mailDirectory(directory, "Maildir", false)
	if err == nil {
		temporaryDirectory, temporaryErr := mailDirectory(maildir, "tmp", false)
		if temporaryErr != nil {
			failures = append(failures, temporaryErr)
		}
		for _, entry := range manifest.Files {
			parts := strings.Split(entry.Path, "/")
			parent, openErr := mailDirectory(maildir, parts[0], false)
			if openErr == nil {
				unlinkErr := syscall.Unlinkat(parent, parts[1])
				if unlinkErr != nil && !errors.Is(unlinkErr, syscall.ENOENT) {
					failures = append(failures, unlinkErr)
				}
				failures = append(failures, syscall.Fsync(parent))
				syscall.Close(parent)
			}
			if temporaryDirectory >= 0 {
				temporaryErr = syscall.Unlinkat(temporaryDirectory, ".seal-"+entry.Digest[:24])
				if temporaryErr != nil && !errors.Is(temporaryErr, syscall.ENOENT) {
					failures = append(failures, temporaryErr)
				}
			}
		}
		if temporaryDirectory >= 0 {
			failures = append(failures, syscall.Fsync(temporaryDirectory))
			syscall.Close(temporaryDirectory)
		}
		failures = append(failures, verifyDiscardedMaildir(maildir))
		failures = append(failures, syscall.Fsync(maildir))
		syscall.Close(maildir)
	} else {
		failures = append(failures, err)
	}
	failures = append(failures, cleanupMaildirChunks(directory, manifest))
	return errors.Join(failures...)
}

func verifyDiscardedMaildir(maildir int) error {
	var rootEntries uint8
	if err := walkDirectoryNames(maildir, func(name string) error {
		switch name {
		case "cur":
			rootEntries |= 1
		case "new":
			rootEntries |= 2
		case "tmp":
			rootEntries |= 4
		default:
			return ErrConflict
		}
		return nil
	}); err != nil || rootEntries != 7 {
		return errors.Join(ErrConflict, err)
	}
	for _, name := range []string{"cur", "new", "tmp"} {
		child, err := mailDirectory(maildir, name, false)
		if err != nil {
			return err
		}
		err = walkDirectoryNames(child, func(string) error { return ErrConflict })
		syscall.Close(child)
		if err != nil {
			return errors.Join(ErrConflict, err)
		}
	}
	return nil
}

func walkDirectoryNames(directory int, visit func(string) error) error {
	duplicate, err := mailOpenAt(directory, ".", syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(duplicate), "maildir-directory")
	defer file.Close()
	for {
		names, readErr := file.Readdirnames(1024)
		for _, name := range names {
			if err = visit(name); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		if len(names) == 0 {
			return io.ErrNoProgress
		}
	}
}

func cleanupMaildirTemporaries(directory int) error {
	for {
		removed := false
		err := walkDirectoryNames(directory, func(name string) error {
			if !maildirTemporaryName(name, ".import-") && !maildirTemporaryName(name, ".journal-") {
				return nil
			}
			if unlinkErr := syscall.Unlinkat(directory, name); unlinkErr != nil && !errors.Is(unlinkErr, syscall.ENOENT) {
				return unlinkErr
			}
			removed = true
			return nil
		})
		if err != nil || !removed {
			return err
		}
		if err = syscall.Fsync(directory); err != nil {
			return err
		}
	}
}

func maildirTemporaryName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	value := strings.TrimPrefix(name, prefix)
	if len(value) != 32 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func nilOrConflict(ok bool) error {
	if ok {
		return nil
	}
	return ErrConflict
}
