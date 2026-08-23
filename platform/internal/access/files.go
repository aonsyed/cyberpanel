package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxEditorBytes = int64(8 << 20)
	MaxUploadChunk = 8 << 20
	MaxBatchPaths  = 1000
)

type FileLocator struct {
	Root SiteRoot     `json:"root"`
	Path RelativePath `json:"path"`
}

func (locator FileLocator) Validate() error { return locator.Root.Validate() }

type FileOperationKind string

const (
	FileCreateDirectory FileOperationKind = "create_directory"
	FileCreate          FileOperationKind = "create_file"
	FileWrite           FileOperationKind = "write_file"
	FileMove            FileOperationKind = "move"
	FileCopy            FileOperationKind = "copy"
	FileTrash           FileOperationKind = "trash"
	FileRestore         FileOperationKind = "restore"
	FilePurge           FileOperationKind = "purge"
	FileSetMetadata     FileOperationKind = "set_metadata"
	FileCreateSymlink   FileOperationKind = "create_symlink"
	FileArchive         FileOperationKind = "archive"
	FileExtract         FileOperationKind = "extract"
)

type FileOperation struct {
	ID         FileOperationID `json:"id"`
	Mutation   Mutation        `json:"mutation"`
	Kind       FileOperationKind `json:"kind"`
	Source     FileLocator     `json:"source"`
	Destination FileLocator   `json:"destination"`
	State      OperationState  `json:"state"`
	Receipt    string          `json:"receipt,omitempty"`
	ErrorCode  string          `json:"error_code,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at,omitempty"`
}

type FileMutationReceipt struct {
	OperationID FileOperationID `json:"operation_id"`
	ETag        string          `json:"etag,omitempty"`
	Size        int64           `json:"size,omitempty"`
	ExecutorReceipt string      `json:"executor_receipt"`
	CommittedAt time.Time       `json:"committed_at"`
}

type FileMetadata struct {
	Mode      uint32 `json:"mode"`
	Ownership OwnershipProfile `json:"ownership"`
}

type OwnershipProfile string

const (
	OwnershipSiteUser OwnershipProfile = "site_user"
	OwnershipRuntime  OwnershipProfile = "runtime"
)

func (metadata FileMetadata) Validate() error {
	if metadata.Mode > 0777 || metadata.Mode&0002 != 0 {
		return fmt.Errorf("unsafe file mode")
	}
	if metadata.Ownership != OwnershipSiteUser && metadata.Ownership != OwnershipRuntime {
		return fmt.Errorf("invalid ownership profile")
	}
	return nil
}

type UploadState string

const (
	UploadOpen       UploadState = "open"
	UploadCommitting UploadState = "committing"
	UploadCommitted  UploadState = "committed"
	UploadAborted    UploadState = "aborted"
	UploadFailed     UploadState = "failed"
)

type UploadSession struct {
	ID          UploadID       `json:"id"`
	Mutation    Mutation       `json:"mutation"`
	Destination FileLocator    `json:"destination"`
	Integrity   Integrity      `json:"integrity"`
	Condition   WriteCondition `json:"condition"`
	State       UploadState    `json:"state"`
	Offset      int64          `json:"offset"`
	Handle      string         `json:"handle"`
	Generation  uint64         `json:"generation"`
	ExpiresAt   time.Time      `json:"expires_at"`
	Receipt     string         `json:"receipt,omitempty"`
}

type UploadChunk struct {
	Offset int64  `json:"offset"`
	Data   []byte `json:"data"`
	SHA256 string `json:"sha256"`
}

func (chunk UploadChunk) Validate() error {
	if chunk.Offset < 0 || len(chunk.Data) == 0 || len(chunk.Data) > MaxUploadChunk {
		return fmt.Errorf("invalid upload chunk")
	}
	digest := sha256.Sum256(chunk.Data)
	if !strings.EqualFold(chunk.SHA256, hex.EncodeToString(digest[:])) {
		return ErrIntegrity
	}
	return nil
}

type DownloadLease struct {
	ID        DownloadID    `json:"id"`
	Actor     AuditActor    `json:"actor"`
	Source    FileLocator   `json:"source"`
	Handle    string        `json:"handle"`
	Integrity Integrity     `json:"integrity"`
	ExpiresAt time.Time     `json:"expires_at"`
}

type TrashEntry struct {
	ID          TrashEntryID `json:"id"`
	SiteID      SiteID       `json:"site_id"`
	Original    FileLocator  `json:"original"`
	StoredToken string       `json:"stored_token"`
	Kind        EntryKind    `json:"kind"`
	Size        int64        `json:"size"`
	DeletedBy   PrincipalID  `json:"deleted_by"`
	DeletedAt   time.Time    `json:"deleted_at"`
	PurgeAfter  time.Time    `json:"purge_after"`
	State       ResourceState `json:"state"`
	Generation  uint64       `json:"generation"`
}

type ArchiveFormat string

const (
	ArchiveZIP    ArchiveFormat = "zip"
	ArchiveTarGZ  ArchiveFormat = "tar_gzip"
	ArchiveTarZST ArchiveFormat = "tar_zstd"
)

type Archive struct {
	ID          ArchiveID     `json:"id"`
	SiteID      SiteID        `json:"site_id"`
	Format      ArchiveFormat `json:"format"`
	Sources     []FileLocator `json:"sources"`
	Destination FileLocator   `json:"destination"`
	State       OperationState `json:"state"`
	Integrity   Integrity     `json:"integrity"`
	CreatedAt   time.Time     `json:"created_at"`
	Receipt     string        `json:"receipt,omitempty"`
}

type ExtractPolicy struct {
	Overwrite       bool  `json:"overwrite"`
	StripComponents uint8 `json:"strip_components"`
	MaxFiles        uint32 `json:"max_files"`
	MaxBytes        int64 `json:"max_bytes"`
	MaxRatio        uint32 `json:"max_compression_ratio"`
}

func (policy ExtractPolicy) normalized() (ExtractPolicy, error) {
	if policy.MaxFiles == 0 { policy.MaxFiles = 100000 }
	if policy.MaxBytes == 0 { policy.MaxBytes = 20 << 30 }
	if policy.MaxRatio == 0 { policy.MaxRatio = 200 }
	if policy.MaxFiles > 1000000 || policy.MaxBytes < 0 || policy.MaxBytes > 1<<50 || policy.MaxRatio > 10000 {
		return ExtractPolicy{}, ErrLimitExceeded
	}
	return policy, nil
}

// FileExecutor is the complete privileged file protocol. Implementations must
// resolve all paths beneath the supplied SiteRoot with openat2-style beneath,
// no-magic-link, and no-follow semantics. Host paths never cross this boundary.
type FileExecutor interface {
	List(context.Context, SiteRoot, RelativePath, PageRequest) (FilePage, error)
	Stat(context.Context, FileLocator) (FileEntry, error)
	ReadRange(context.Context, FileLocator, int64, int64) ([]byte, Integrity, error)
	CreateDirectory(context.Context, FileLocator, FileMetadata) (FileMutationReceipt, error)
	CreateFile(context.Context, FileLocator, []byte, FileMetadata, WriteCondition) (FileMutationReceipt, error)
	ReplaceFile(context.Context, FileLocator, []byte, FileMetadata, WriteCondition) (FileMutationReceipt, error)
	Move(context.Context, FileLocator, FileLocator, WriteCondition) (FileMutationReceipt, error)
	Copy(context.Context, FileLocator, FileLocator, WriteCondition) (FileMutationReceipt, error)
	SetMetadata(context.Context, FileLocator, FileMetadata, WriteCondition) (FileMutationReceipt, error)
	CreateSymlink(context.Context, FileLocator, RelativePath, WriteCondition) (FileMutationReceipt, error)
	MoveToTrash(context.Context, FileLocator, TrashEntryID) (TrashEntry, FileMutationReceipt, error)
	RestoreTrash(context.Context, TrashEntry, FileLocator, WriteCondition) (FileMutationReceipt, error)
	PurgeTrash(context.Context, TrashEntry) (FileMutationReceipt, error)
	BeginUpload(context.Context, UploadSession) (string, error)
	AppendUpload(context.Context, string, UploadChunk) error
	CommitUpload(context.Context, UploadSession) (FileMutationReceipt, error)
	AbortUpload(context.Context, string) error
	OpenDownload(context.Context, DownloadLease) (DownloadLease, error)
	ReadDownload(context.Context, DownloadLease, int64, int64) ([]byte, error)
	CloseDownload(context.Context, DownloadLease) error
	CreateArchive(context.Context, Archive) (Archive, error)
	ExtractArchive(context.Context, FileLocator, FileLocator, ExtractPolicy) (FileMutationReceipt, error)
}

type FileStore interface {
	AdmitFileOperation(context.Context, FileOperation) error
	FinishFileOperation(context.Context, FileOperationID, OperationState, string, string, time.Time) error
	CreateUpload(context.Context, UploadSession) error
	LoadUpload(context.Context, UploadID) (UploadSession, error)
	AdvanceUpload(context.Context, UploadSession, uint64) error
	SaveDownload(context.Context, DownloadLease) error
	LoadDownload(context.Context, DownloadID) (DownloadLease, error)
	DeleteDownload(context.Context, DownloadID) error
	SaveTrash(context.Context, TrashEntry) error
	LoadTrash(context.Context, TrashEntryID) (TrashEntry, error)
	AdvanceTrash(context.Context, TrashEntry, uint64) error
	SaveArchive(context.Context, Archive) error
}

type FileService struct {
	Executor FileExecutor
	Store    FileStore
	Now      func() time.Time
}

func (service FileService) now() time.Time {
	if service.Now != nil { return service.Now().UTC() }
	return time.Now().UTC()
}

func (service FileService) require() error {
	if service.Executor == nil || service.Store == nil { return errors.New("file executor and store are required") }
	return nil
}

func (service FileService) List(ctx context.Context, root SiteRoot, directory RelativePath, page PageRequest) (FilePage, error) {
	if err := service.require(); err != nil { return FilePage{}, err }
	if err := root.Validate(); err != nil { return FilePage{}, err }
	normalized, err := page.normalized(); if err != nil { return FilePage{}, err }
	return service.Executor.List(ctx, root, directory, normalized)
}

func (service FileService) ReadEditor(ctx context.Context, source FileLocator, condition WriteCondition) ([]byte, FileEntry, error) {
	if err := service.require(); err != nil { return nil, FileEntry{}, err }
	if err := source.Validate(); err != nil { return nil, FileEntry{}, err }
	entry, err := service.Executor.Stat(ctx, source); if err != nil { return nil, FileEntry{}, err }
	if entry.Kind != EntryRegular || entry.Size > MaxEditorBytes { return nil, FileEntry{}, ErrLimitExceeded }
	if condition.IfMatch != "" && entry.ETag != condition.IfMatch { return nil, FileEntry{}, ErrConflict }
	content, integrity, err := service.Executor.ReadRange(ctx, source, 0, entry.Size)
	if err != nil { return nil, FileEntry{}, err }
	if int64(len(content)) != integrity.Size || !utf8.Valid(content) || strings.IndexByte(string(content), 0) >= 0 { return nil, FileEntry{}, ErrIntegrity }
	return content, entry, nil
}

type FileMutationCall struct {
	Operation FileOperation
	Metadata  FileMetadata
	Content   []byte
	Condition WriteCondition
	SymlinkTarget RelativePath
}

func (service FileService) Mutate(ctx context.Context, call FileMutationCall) (FileMutationReceipt, error) {
	if err := service.require(); err != nil { return FileMutationReceipt{}, err }
	if err := validateFileOperation(call.Operation); err != nil { return FileMutationReceipt{}, err }
	if call.Operation.StartedAt.IsZero() { call.Operation.StartedAt = service.now() }
	if err := service.Store.AdmitFileOperation(ctx, call.Operation); err != nil { return FileMutationReceipt{}, err }
	started := call.Operation
	started.State = OperationExecuting
	_ = service.Store.FinishFileOperation(ctx, started.ID, OperationExecuting, "", "", time.Time{})
	var receipt FileMutationReceipt
	var err error
	switch call.Operation.Kind {
	case FileCreateDirectory:
		if metadataErr := call.Metadata.Validate(); metadataErr != nil { err = metadataErr } else { receipt, err = service.Executor.CreateDirectory(ctx, call.Operation.Destination, call.Metadata) }
	case FileCreate:
		if metadataErr := call.Metadata.Validate(); metadataErr != nil { err = metadataErr } else { receipt, err = service.Executor.CreateFile(ctx, call.Operation.Destination, call.Content, call.Metadata, call.Condition) }
	case FileWrite:
		if int64(len(call.Content)) > MaxEditorBytes { err = ErrLimitExceeded } else if metadataErr := call.Metadata.Validate(); metadataErr != nil { err = metadataErr } else { receipt, err = service.Executor.ReplaceFile(ctx, call.Operation.Destination, call.Content, call.Metadata, call.Condition) }
	case FileMove:
		receipt, err = service.Executor.Move(ctx, call.Operation.Source, call.Operation.Destination, call.Condition)
	case FileCopy:
		receipt, err = service.Executor.Copy(ctx, call.Operation.Source, call.Operation.Destination, call.Condition)
	case FileSetMetadata:
		if metadataErr := call.Metadata.Validate(); metadataErr != nil { err = metadataErr } else { receipt, err = service.Executor.SetMetadata(ctx, call.Operation.Source, call.Metadata, call.Condition) }
	case FileCreateSymlink:
		receipt, err = service.Executor.CreateSymlink(ctx, call.Operation.Destination, call.SymlinkTarget, call.Condition)
	default:
		err = fmt.Errorf("unsupported direct file mutation %q", call.Operation.Kind)
	}
	finished := service.now()
	if err != nil {
		_ = service.Store.FinishFileOperation(ctx, call.Operation.ID, OperationFailed, "", classifyError(err), finished)
		return FileMutationReceipt{}, err
	}
	receipt.OperationID, receipt.CommittedAt = call.Operation.ID, finished
	if persistErr := service.Store.FinishFileOperation(ctx, call.Operation.ID, OperationCommitted, receipt.ExecutorReceipt, "", finished); persistErr != nil { return FileMutationReceipt{}, persistErr }
	return receipt, nil
}

func validateFileOperation(operation FileOperation) error {
	if err := requireID("file operation", string(operation.ID)); err != nil { return err }
	if err := operation.Mutation.Validate(); err != nil { return err }
	if operation.State != OperationAdmitted { return ErrInvalidState }
	switch operation.Kind {
	case FileCreateDirectory, FileCreate, FileWrite, FileCreateSymlink:
		return operation.Destination.Validate()
	case FileMove, FileCopy:
		if err := operation.Source.Validate(); err != nil { return err }
		if err := operation.Destination.Validate(); err != nil { return err }
		if operation.Source.Root.SiteID != operation.Destination.Root.SiteID { return ErrUnauthorized }
		return nil
	case FileSetMetadata:
		return operation.Source.Validate()
	default:
		return fmt.Errorf("invalid file operation kind")
	}
}

func (service FileService) BeginUpload(ctx context.Context, session UploadSession) (UploadSession, error) {
	if err := service.require(); err != nil { return UploadSession{}, err }
	if err := requireID("upload", string(session.ID)); err != nil { return UploadSession{}, err }
	if err := session.Mutation.Validate(); err != nil { return UploadSession{}, err }
	if err := session.Destination.Validate(); err != nil { return UploadSession{}, err }
	if err := session.Integrity.Validate(); err != nil { return UploadSession{}, err }
	if session.State != UploadOpen || session.Offset != 0 || session.Generation != 1 { return UploadSession{}, ErrInvalidState }
	if session.ExpiresAt.IsZero() || !session.ExpiresAt.After(service.now()) || session.ExpiresAt.After(service.now().Add(24*time.Hour)) { return UploadSession{}, fmt.Errorf("invalid upload expiry") }
	handle, err := service.Executor.BeginUpload(ctx, session); if err != nil { return UploadSession{}, err }
	if handle == "" || len(handle) > 512 { _ = service.Executor.AbortUpload(ctx, handle); return UploadSession{}, ErrIntegrity }
	session.Handle = handle
	if err = service.Store.CreateUpload(ctx, session); err != nil { _ = service.Executor.AbortUpload(ctx, handle); return UploadSession{}, err }
	return session, nil
}

func (service FileService) AppendUpload(ctx context.Context, id UploadID, chunk UploadChunk) (UploadSession, error) {
	if err := service.require(); err != nil { return UploadSession{}, err }
	if err := chunk.Validate(); err != nil { return UploadSession{}, err }
	session, err := service.Store.LoadUpload(ctx, id); if err != nil { return UploadSession{}, err }
	if session.State != UploadOpen || session.ExpiresAt.Before(service.now()) || chunk.Offset != session.Offset || chunk.Offset+int64(len(chunk.Data)) > session.Integrity.Size { return UploadSession{}, ErrInvalidState }
	if err = service.Executor.AppendUpload(ctx, session.Handle, chunk); err != nil { return UploadSession{}, err }
	previous := session.Generation
	session.Offset += int64(len(chunk.Data)); session.Generation++
	if err = service.Store.AdvanceUpload(ctx, session, previous); err != nil { return UploadSession{}, err }
	return session, nil
}

func (service FileService) CommitUpload(ctx context.Context, id UploadID) (FileMutationReceipt, error) {
	if err := service.require(); err != nil { return FileMutationReceipt{}, err }
	session, err := service.Store.LoadUpload(ctx, id); if err != nil { return FileMutationReceipt{}, err }
	if session.State != UploadOpen || session.Offset != session.Integrity.Size || session.ExpiresAt.Before(service.now()) { return FileMutationReceipt{}, ErrInvalidState }
	previous := session.Generation; session.State = UploadCommitting; session.Generation++
	if err = service.Store.AdvanceUpload(ctx, session, previous); err != nil { return FileMutationReceipt{}, err }
	receipt, err := service.Executor.CommitUpload(ctx, session)
	previous = session.Generation; session.Generation++
	if err != nil { session.State = UploadFailed; _ = service.Store.AdvanceUpload(ctx, session, previous); return FileMutationReceipt{}, err }
	session.State, session.Receipt = UploadCommitted, receipt.ExecutorReceipt
	if err = service.Store.AdvanceUpload(ctx, session, previous); err != nil { return FileMutationReceipt{}, err }
	return receipt, nil
}

func (service FileService) AbortUpload(ctx context.Context, id UploadID) error {
	if err := service.require(); err != nil { return err }
	session, err := service.Store.LoadUpload(ctx, id); if err != nil { return err }
	if session.State != UploadOpen && session.State != UploadFailed { return ErrInvalidState }
	if err = service.Executor.AbortUpload(ctx, session.Handle); err != nil { return err }
	previous := session.Generation; session.Generation++; session.State = UploadAborted
	return service.Store.AdvanceUpload(ctx, session, previous)
}

func (service FileService) OpenDownload(ctx context.Context, lease DownloadLease) (DownloadLease, error) {
	if err := service.require(); err != nil { return DownloadLease{}, err }
	if err := requireID("download", string(lease.ID)); err != nil { return DownloadLease{}, err }
	if err := lease.Actor.Validate(); err != nil { return DownloadLease{}, err }
	if err := lease.Source.Validate(); err != nil { return DownloadLease{}, err }
	if lease.ExpiresAt.Before(service.now()) || lease.ExpiresAt.After(service.now().Add(time.Hour)) { return DownloadLease{}, fmt.Errorf("invalid download expiry") }
	opened, err := service.Executor.OpenDownload(ctx, lease); if err != nil { return DownloadLease{}, err }
	if err = opened.Integrity.Validate(); err != nil { _ = service.Executor.CloseDownload(ctx, opened); return DownloadLease{}, err }
	if err = service.Store.SaveDownload(ctx, opened); err != nil { _ = service.Executor.CloseDownload(ctx, opened); return DownloadLease{}, err }
	return opened, nil
}

func (service FileService) ReadDownload(ctx context.Context, lease DownloadLease, offset, length int64) ([]byte, error) {
	if lease.ExpiresAt.Before(service.now()) || offset < 0 || length <= 0 || length > MaxUploadChunk || offset+length > lease.Integrity.Size { return nil, ErrInvalidState }
	return service.Executor.ReadDownload(ctx, lease, offset, length)
}

func (service FileService) CloseDownload(ctx context.Context, lease DownloadLease) error {
	if err := service.Executor.CloseDownload(ctx, lease); err != nil { return err }
	return service.Store.DeleteDownload(ctx, lease.ID)
}

func (service FileService) Trash(ctx context.Context, mutation Mutation, operationID FileOperationID, entryID TrashEntryID, source FileLocator, purgeAfter time.Time) (TrashEntry, error) {
	if err := service.require(); err != nil { return TrashEntry{}, err }
	if err := mutation.Validate(); err != nil { return TrashEntry{}, err }
	if err := requireID("trash entry", string(entryID)); err != nil { return TrashEntry{}, err }
	if err := source.Validate(); err != nil { return TrashEntry{}, err }
	if source.Path.IsRoot() || purgeAfter.Before(service.now()) { return TrashEntry{}, ErrInvalidPath }
	operation := FileOperation{ID: operationID, Mutation: mutation, Kind: FileTrash, Source: source, State: OperationAdmitted, StartedAt: service.now()}
	if err := service.Store.AdmitFileOperation(ctx, operation); err != nil { return TrashEntry{}, err }
	entry, receipt, err := service.Executor.MoveToTrash(ctx, source, entryID)
	if err != nil { _ = service.Store.FinishFileOperation(ctx, operationID, OperationFailed, "", classifyError(err), service.now()); return TrashEntry{}, err }
	entry.ID, entry.SiteID, entry.Original, entry.DeletedBy, entry.DeletedAt, entry.PurgeAfter = entryID, source.Root.SiteID, source, mutation.Actor.PrincipalID, service.now(), purgeAfter
	entry.State, entry.Generation = StateActive, 1
	if err = service.Store.SaveTrash(ctx, entry); err != nil { return TrashEntry{}, err }
	if err = service.Store.FinishFileOperation(ctx, operationID, OperationCommitted, receipt.ExecutorReceipt, "", service.now()); err != nil { return TrashEntry{}, err }
	return entry, nil
}

func (service FileService) RestoreTrash(ctx context.Context, id TrashEntryID, destination FileLocator, condition WriteCondition) (FileMutationReceipt, error) {
	entry, err := service.Store.LoadTrash(ctx, id); if err != nil { return FileMutationReceipt{}, err }
	if entry.State != StateActive || destination.Root.SiteID != entry.SiteID { return FileMutationReceipt{}, ErrInvalidState }
	receipt, err := service.Executor.RestoreTrash(ctx, entry, destination, condition); if err != nil { return FileMutationReceipt{}, err }
	previous := entry.Generation; entry.State = StateDeleted; entry.Generation++
	if err = service.Store.AdvanceTrash(ctx, entry, previous); err != nil { return FileMutationReceipt{}, err }
	return receipt, nil
}

func (service FileService) PurgeTrash(ctx context.Context, id TrashEntryID, force bool) (FileMutationReceipt, error) {
	entry, err := service.Store.LoadTrash(ctx, id); if err != nil { return FileMutationReceipt{}, err }
	if entry.State != StateActive || !force && entry.PurgeAfter.After(service.now()) { return FileMutationReceipt{}, ErrInvalidState }
	receipt, err := service.Executor.PurgeTrash(ctx, entry); if err != nil { return FileMutationReceipt{}, err }
	previous := entry.Generation; entry.State = StateDeleted; entry.Generation++
	if err = service.Store.AdvanceTrash(ctx, entry, previous); err != nil { return FileMutationReceipt{}, err }
	return receipt, nil
}

func (service FileService) CreateArchive(ctx context.Context, archive Archive) (Archive, error) {
	if err := service.require(); err != nil { return Archive{}, err }
	if err := requireID("archive", string(archive.ID)); err != nil { return Archive{}, err }
	if len(archive.Sources) == 0 || len(archive.Sources) > MaxBatchPaths { return Archive{}, ErrLimitExceeded }
	if err := archive.Destination.Validate(); err != nil { return Archive{}, err }
	for _, source := range archive.Sources { if err := source.Validate(); err != nil { return Archive{}, err }; if source.Root.SiteID != archive.Destination.Root.SiteID { return Archive{}, ErrUnauthorized } }
	if archive.Format != ArchiveZIP && archive.Format != ArchiveTarGZ && archive.Format != ArchiveTarZST { return Archive{}, fmt.Errorf("invalid archive format") }
	archive.SiteID, archive.State, archive.CreatedAt = archive.Destination.Root.SiteID, OperationExecuting, service.now()
	if err := service.Store.SaveArchive(ctx, archive); err != nil { return Archive{}, err }
	created, err := service.Executor.CreateArchive(ctx, archive); if err != nil { archive.State = OperationFailed; _ = service.Store.SaveArchive(ctx, archive); return Archive{}, err }
	if err = created.Integrity.Validate(); err != nil { return Archive{}, err }
	created.State = OperationCommitted
	if err = service.Store.SaveArchive(ctx, created); err != nil { return Archive{}, err }
	return created, nil
}

func (service FileService) ExtractArchive(ctx context.Context, source, destination FileLocator, policy ExtractPolicy) (FileMutationReceipt, error) {
	if err := source.Validate(); err != nil { return FileMutationReceipt{}, err }
	if err := destination.Validate(); err != nil { return FileMutationReceipt{}, err }
	if source.Root.SiteID != destination.Root.SiteID { return FileMutationReceipt{}, ErrUnauthorized }
	normalized, err := policy.normalized(); if err != nil { return FileMutationReceipt{}, err }
	return service.Executor.ExtractArchive(ctx, source, destination, normalized)
}

func classifyError(err error) string {
	switch {
	case errors.Is(err, ErrInvalidPath): return "invalid_path"
	case errors.Is(err, ErrConflict): return "conflict"
	case errors.Is(err, ErrUnauthorized): return "unauthorized"
	case errors.Is(err, ErrIntegrity): return "integrity"
	case errors.Is(err, ErrLimitExceeded): return "limit"
	default: return "executor"
	}
}
