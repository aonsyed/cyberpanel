//go:build linux

package durablespool

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	LinuxSpoolRoot       = "/var/lib/cyberpanel/durable-spool"
	recordDiskHeadroom   = uint64(8192)
	minimumRecordInodes  = uint64(2)
)

type LinuxSpool struct {
	rootFD       int
	device       uint64
	policy       Policy
	records      map[RecordID]*diskRecord
	highSequence uint64
	now          func() time.Time
	ready        bool
	failed       bool
	mu           sync.Mutex
}

func NewLinuxSpool(policy Policy) (*LinuxSpool, error) {
	if policy == (Policy{}) {
		policy = DefaultPolicy()
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	parent := filepath.Dir(LinuxSpoolRoot)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !secureDirectory(parentInfo, false) {
		return nil, errors.Join(ErrIntegrity, err)
	}
	rootInfo, err := os.Lstat(LinuxSpoolRoot)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(LinuxSpoolRoot, 0700); err != nil {
			return nil, err
		}
		if err = os.Chmod(LinuxSpoolRoot, 0700); err != nil {
			return nil, err
		}
		rootInfo, err = os.Lstat(LinuxSpoolRoot)
	}
	if err != nil || !secureDirectory(rootInfo, true) {
		return nil, errors.Join(ErrIntegrity, err)
	}
	rootFD, err := syscall.Open(LinuxSpoolRoot, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var stat syscall.Stat_t
	if err = syscall.Fstat(rootFD, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || stat.Mode&0777 != 0700 || stat.Uid != 0 {
		syscall.Close(rootFD)
		return nil, errors.Join(ErrIntegrity, err)
	}
	store := &LinuxSpool{
		rootFD: rootFD, device: uint64(stat.Dev), policy: policy,
		records: make(map[RecordID]*diskRecord), now: time.Now, ready: true,
	}
	if err = store.reconstructLocked(); err != nil {
		syscall.Close(rootFD)
		return nil, err
	}
	return store, nil
}

func secureDirectory(info os.FileInfo, exactMode bool) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	if exactMode {
		return info.Mode().Perm() == 0700
	}
	return info.Mode().Perm()&0022 == 0
}

func (store *LinuxSpool) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.ready {
		return nil
	}
	err := syscall.Close(store.rootFD)
	store.rootFD, store.ready = -1, false
	return err
}

func (store *LinuxSpool) checkLocked(ctx context.Context) error {
	if store == nil || !store.ready || store.failed || store.rootFD < 0 || ctx == nil {
		return ErrInvalid
	}
	return ctx.Err()
}

func validTemporaryLeaf(leaf string) bool {
	if !strings.HasPrefix(leaf, ".tmp-") || len(leaf) != len(".tmp-")+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(leaf, ".tmp-"))
	return err == nil
}

func temporaryLeaf() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return ".tmp-" + hex.EncodeToString(value[:]), nil
}

func (store *LinuxSpool) regularLeafLocked(leaf string, maximum uint64) (*os.File, uint64, error) {
	if leaf == "" || strings.ContainsAny(leaf, "/\x00") || maximum == 0 {
		return nil, 0, ErrInvalid
	}
	fd, err := syscall.Openat(store.rootFD, leaf, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	file := os.NewFile(uintptr(fd), leaf)
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != 0 || stat.Nlink != 1 || uint64(stat.Dev) != store.device || stat.Size < 0 || uint64(stat.Size) > maximum {
		file.Close()
		return nil, 0, errors.Join(ErrIntegrity, err)
	}
	return file, uint64(stat.Size), nil
}

func (store *LinuxSpool) readLeafLocked(leaf string, maximum uint64) ([]byte, error) {
	file, size, err := store.regularLeafLocked(leaf, maximum)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || uint64(len(content)) != size {
		return nil, errors.Join(ErrIntegrity, err)
	}
	return content, nil
}

func (store *LinuxSpool) atomicWriteLocked(leaf string, content []byte) error {
	if leaf == "" || strings.ContainsAny(leaf, "/\x00") || len(content) == 0 {
		return ErrInvalid
	}
	temporary, err := temporaryLeaf()
	if err != nil {
		return err
	}
	fd, err := syscall.Openat(store.rootFD, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	cleanup := true
	defer func() {
		file.Close()
		if cleanup {
			_ = syscall.Unlinkat(store.rootFD, temporary)
		}
	}()
	if err = syscall.Fchmod(fd, 0600); err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(content) {
		return errors.Join(writeErr, syncErr, closeErr)
	}
	if err = syscall.Renameat(store.rootFD, temporary, store.rootFD, leaf); err != nil {
		return err
	}
	cleanup = false
	if err = syscall.Fsync(store.rootFD); err != nil {
		store.failed = true
		return err
	}
	return nil
}

func (store *LinuxSpool) unlinkLocked(leaf string) error {
	if leaf == "" || strings.ContainsAny(leaf, "/\x00") {
		return ErrInvalid
	}
	if err := syscall.Unlinkat(store.rootFD, leaf); err != nil {
		return err
	}
	if err := syscall.Fsync(store.rootFD); err != nil {
		store.failed = true
		return err
	}
	return nil
}

func (store *LinuxSpool) directoryEntriesLocked() ([]os.FileInfo, error) {
	fd, err := syscall.Dup(store.rootFD)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), LinuxSpoolRoot)
	entries, readErr := directory.Readdir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	return entries, nil
}

func (store *LinuxSpool) reconstructLocked() error {
	entries, err := store.directoryEntriesLocked()
	if err != nil {
		return err
	}
	manifestLeaves := make(map[uint64]string)
	payloadLeaves := make(map[uint64]string)
	temporaryLeaves := make([]string, 0)
	hasIndex := false
	for _, entry := range entries {
		leaf := entry.Name()
		switch {
		case leaf == indexLeaf:
			hasIndex = true
		case validTemporaryLeaf(leaf):
			temporaryLeaves = append(temporaryLeaves, leaf)
		case strings.HasSuffix(leaf, ".manifest.json"):
			sequence, ok := parseRecordLeaf(leaf, ".manifest.json")
			if !ok {
				return ErrIntegrity
			}
			manifestLeaves[sequence] = leaf
		case strings.HasSuffix(leaf, ".payload"):
			sequence, ok := parseRecordLeaf(leaf, ".payload")
			if !ok {
				return ErrIntegrity
			}
			payloadLeaves[sequence] = leaf
		default:
			return ErrIntegrity
		}
	}
	var index diskIndex
	if hasIndex {
		encoded, readErr := store.readLeafLocked(indexLeaf, maximumManifestBytes)
		if readErr != nil || decodeCanonical(encoded, &index) != nil || index.Schema != indexSchema {
			return errors.Join(ErrIntegrity, readErr)
		}
	}
	for _, leaf := range temporaryLeaves {
		file, _, openErr := store.regularLeafLocked(leaf, store.policy.MaximumRecordBytes+recordDiskHeadroom)
		if openErr != nil {
			return openErr
		}
		file.Close()
	}
	sequences := make([]uint64, 0, len(manifestLeaves))
	for sequence := range manifestLeaves {
		sequences = append(sequences, sequence)
	}
	sort.Slice(sequences, func(left, right int) bool { return sequences[left] < sequences[right] })
	records := make(map[RecordID]*diskRecord, len(sequences))
	var highest uint64
	for _, sequence := range sequences {
		payloadLeaf, exists := payloadLeaves[sequence]
		if !exists {
			return ErrIntegrity
		}
		encoded, readErr := store.readLeafLocked(manifestLeaves[sequence], maximumManifestBytes)
		if readErr != nil {
			return readErr
		}
		var manifest diskRecord
		if decodeCanonical(encoded, &manifest) != nil || !validDiskRecord(manifest) || manifest.Record.Sequence != sequence || manifest.PayloadLeaf != payloadLeaf || manifest.Record.PayloadSize > store.policy.MaximumRecordBytes {
			return ErrIntegrity
		}
		payload, readErr := store.readLeafLocked(payloadLeaf, store.policy.MaximumRecordBytes)
		if readErr != nil || uint64(len(payload)) != manifest.Record.PayloadSize || digestPayload(payload) != manifest.Record.SHA256 {
			return errors.Join(ErrIntegrity, readErr)
		}
		if _, duplicate := records[manifest.Record.ID]; duplicate {
			return ErrIntegrity
		}
		copy := manifest
		records[manifest.Record.ID] = &copy
		if sequence > highest {
			highest = sequence
		}
	}
	usage, err := usageFor(records)
	if err != nil || !store.usageWithinPolicy(usage) {
		return ErrIntegrity
	}
	for sequence, leaf := range payloadLeaves {
		if _, committed := manifestLeaves[sequence]; committed {
			continue
		}
		file, _, openErr := store.regularLeafLocked(leaf, store.policy.MaximumRecordBytes)
		if openErr != nil {
			return openErr
		}
		file.Close()
		if err = store.unlinkLocked(leaf); err != nil {
			return err
		}
	}
	for _, leaf := range temporaryLeaves {
		if err = store.unlinkLocked(leaf); err != nil {
			return err
		}
	}
	store.records = records
	store.highSequence = index.HighSequence
	if highest > store.highSequence {
		store.highSequence = highest
	}
	if !hasIndex || index.HighSequence != store.highSequence {
		return store.writeIndexLocked()
	}
	return nil
}

func (store *LinuxSpool) usageWithinPolicy(usage Usage) bool {
	if usage.TotalPayloadBytes > store.policy.MaximumPayloadBytes || usage.TotalRecords > store.policy.MaximumRecords {
		return false
	}
	for _, class := range []RecordClass{ClassTerminalReceipt, ClassAuditCheckpoint, ClassSecurityCheckpoint, ClassOrdinaryEvent} {
		classUsage, limit := usage.For(class), store.policy.Classes.For(class)
		if classUsage.PayloadBytes > limit.MaximumPayloadBytes || classUsage.Records > limit.MaximumRecords {
			return false
		}
	}
	return true
}

func (store *LinuxSpool) writeIndexLocked() error {
	encoded, err := encodeCanonical(diskIndex{Schema: indexSchema, HighSequence: store.highSequence})
	if err != nil {
		return err
	}
	return store.atomicWriteLocked(indexLeaf, encoded)
}

func multiply(value, size uint64) (uint64, error) {
	if size != 0 && value > math.MaxUint64/size {
		return 0, ErrIntegrity
	}
	return value * size, nil
}

func (store *LinuxSpool) pressureLocked() (FilesystemPressure, error) {
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(store.rootFD, &stat); err != nil {
		return FilesystemPressure{}, err
	}
	if stat.Bsize <= 0 || stat.Files == 0 {
		return FilesystemPressure{}, ErrIntegrity
	}
	blockSize := uint64(stat.Bsize)
	total, err := multiply(stat.Blocks, blockSize)
	if err != nil {
		return FilesystemPressure{}, err
	}
	free, err := multiply(stat.Bfree, blockSize)
	if err != nil {
		return FilesystemPressure{}, err
	}
	var reservedBlocks uint64
	if stat.Bfree > stat.Bavail {
		reservedBlocks = stat.Bfree - stat.Bavail
	}
	reserved, err := multiply(reservedBlocks, blockSize)
	if err != nil {
		return FilesystemPressure{}, err
	}
	return FilesystemPressure{
		BytesTotal: total, BytesFree: free, BytesReserved: reserved,
		InodesTotal: stat.Files, InodesFree: stat.Ffree, InodesReserved: 0,
		ObservedAt: store.now().UTC(),
	}, nil
}

func (store *LinuxSpool) FilesystemPressure(ctx context.Context) (FilesystemPressure, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkLocked(ctx); err != nil {
		return FilesystemPressure{}, err
	}
	return store.pressureLocked()
}

func (store *LinuxSpool) Usage() Usage {
	if store == nil {
		return Usage{}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	usage, _ := usageFor(store.records)
	return usage
}

func (store *LinuxSpool) admissionLocked() (AdmissionState, error) {
	observation, err := store.pressureLocked()
	if err != nil {
		return AdmissionState{}, err
	}
	usage, err := usageFor(store.records)
	if err != nil {
		return AdmissionState{}, err
	}
	return store.policy.AdmissionFor(observation, usage)
}

func (store *LinuxSpool) Admission(ctx context.Context) (AdmissionState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkLocked(ctx); err != nil {
		return AdmissionState{}, err
	}
	return store.admissionLocked()
}

func (store *LinuxSpool) removeRecordLocked(manifest *diskRecord) error {
	manifestLeaf, payloadLeaf := recordLeaves(manifest.Record.Sequence)
	if err := store.unlinkLocked(manifestLeaf); err != nil {
		return err
	}
	delete(store.records, manifest.Record.ID)
	if err := store.unlinkLocked(payloadLeaf); err != nil {
		return err
	}
	return nil
}

func (store *LinuxSpool) makeRoomLocked(payloadBytes, diskBytes, diskInodes uint64) error {
	usage, err := usageFor(store.records)
	if err != nil {
		return err
	}
	requestedBytes, ok := add(usage.TotalPayloadBytes, payloadBytes)
	if !ok {
		return ErrLimit
	}
	needBytes := uint64(0)
	if requestedBytes > store.policy.MaximumPayloadBytes {
		needBytes = requestedBytes - store.policy.MaximumPayloadBytes
	}
	if diskBytes > needBytes {
		needBytes = diskBytes
	}
	needRecords := uint64(0)
	if usage.TotalRecords+1 > store.policy.MaximumRecords {
		needRecords = usage.TotalRecords + 1 - store.policy.MaximumRecords
	}
	if needBytes == 0 && needRecords == 0 && diskInodes == 0 {
		return nil
	}
	candidates := make([]*diskRecord, 0)
	for _, candidate := range stableRecords(store.records) {
		if candidate.Record.Class == ClassOrdinaryEvent && candidate.Record.Disposable && candidate.Record.State == StateQueued {
			candidates = append(candidates, candidate)
		}
	}
	sort.Slice(candidates, func(left, right int) bool { return candidates[left].Record.Sequence < candidates[right].Record.Sequence })
	selected := make([]*diskRecord, 0)
	var freedBytes, freedRecords, freedInodes uint64
	for _, candidate := range candidates {
		selected = append(selected, candidate)
		freedBytes += candidate.Record.PayloadSize
		freedRecords++
		freedInodes += minimumRecordInodes
		if freedBytes >= needBytes && freedRecords >= needRecords && freedInodes >= diskInodes {
			break
		}
	}
	if freedBytes < needBytes || freedRecords < needRecords || freedInodes < diskInodes {
		return ErrLimit
	}
	for _, candidate := range selected {
		if err = store.removeRecordLocked(candidate); err != nil {
			return err
		}
	}
	return nil
}

func (store *LinuxSpool) reserveSequenceLocked() (uint64, error) {
	if store.highSequence == math.MaxUint64 {
		return 0, ErrLimit
	}
	store.highSequence++
	if err := store.writeIndexLocked(); err != nil {
		return 0, err
	}
	return store.highSequence, nil
}

func (store *LinuxSpool) Append(ctx context.Context, request AppendRequest) (Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkLocked(ctx); err != nil {
		return Record{}, err
	}
	if !request.Class.valid() || len(request.Payload) == 0 || uint64(len(request.Payload)) > store.policy.MaximumRecordBytes || request.Disposable && request.Class != ClassOrdinaryEvent {
		return Record{}, ErrInvalid
	}
	payload := append([]byte(nil), request.Payload...)
	now := store.now().UTC()
	availableAt, err := normalizeAvailable(now, request.AvailableAt)
	if err != nil {
		return Record{}, err
	}
	admission, err := store.admissionLocked()
	if err != nil {
		return Record{}, err
	}
	if request.Class == ClassOrdinaryEvent && !admission.AllowOrdinaryEvents {
		return Record{}, ErrPressure
	}
	usage, err := usageFor(store.records)
	if err != nil {
		return Record{}, err
	}
	classUsage, classLimit := usage.For(request.Class), store.policy.Classes.For(request.Class)
	classBytes, ok := add(classUsage.PayloadBytes, uint64(len(payload)))
	if !ok || classBytes > classLimit.MaximumPayloadBytes || classUsage.Records >= classLimit.MaximumRecords {
		return Record{}, ErrLimit
	}
	if request.Class == ClassOrdinaryEvent {
		totalBytes, bytesOK := add(usage.TotalPayloadBytes, uint64(len(payload)), store.policy.EssentialReserveBytes)
		totalRecords, recordsOK := add(usage.TotalRecords, 1, store.policy.EssentialReserveCount)
		if !bytesOK || !recordsOK || totalBytes > store.policy.MaximumPayloadBytes || totalRecords > store.policy.MaximumRecords {
			return Record{}, ErrPressure
		}
	}
	observation, err := store.pressureLocked()
	if err != nil {
		return Record{}, err
	}
	requiredBytes, ok := add(uint64(len(payload)), recordDiskHeadroom)
	if !ok {
		return Record{}, ErrLimit
	}
	if request.Class == ClassOrdinaryEvent {
		if admission.EffectiveFreeBytes < requiredBytes || admission.EffectiveFreeInodes < minimumRecordInodes {
			return Record{}, ErrPressure
		}
	} else {
		physicalBytes := remaining(observation.BytesFree, observation.BytesReserved)
		physicalInodes := remaining(observation.InodesFree, observation.InodesReserved)
		diskBytes := remaining(requiredBytes, physicalBytes)
		diskInodes := remaining(minimumRecordInodes, physicalInodes)
		if err = store.makeRoomLocked(uint64(len(payload)), diskBytes, diskInodes); err != nil {
			return Record{}, err
		}
		observation, err = store.pressureLocked()
		if err != nil {
			return Record{}, err
		}
	}
	physicalBytes := remaining(observation.BytesFree, observation.BytesReserved)
	physicalInodes := remaining(observation.InodesFree, observation.InodesReserved)
	if physicalBytes < requiredBytes || physicalInodes < minimumRecordInodes {
		return Record{}, ErrPressure
	}
	sequence, err := store.reserveSequenceLocked()
	if err != nil {
		return Record{}, err
	}
	digest := digestPayload(payload)
	record := Record{
		ID: recordID(sequence, request.Class, digest), Sequence: sequence,
		Class: request.Class, Priority: priorityFor(request.Class), Disposable: request.Disposable,
		PayloadSize: uint64(len(payload)), SHA256: digest,
		CreatedAt: now, AvailableAt: availableAt, State: StateQueued,
	}
	manifestLeaf, payloadLeaf := recordLeaves(sequence)
	manifest := diskRecord{Schema: recordSchema, Record: record, PayloadLeaf: payloadLeaf}
	encoded, err := encodeCanonical(manifest)
	if err != nil {
		return Record{}, err
	}
	if err = store.atomicWriteLocked(payloadLeaf, payload); err != nil {
		return Record{}, err
	}
	if err = store.atomicWriteLocked(manifestLeaf, encoded); err != nil {
		return Record{}, err
	}
	store.records[record.ID] = &manifest
	return record, nil
}

func (store *LinuxSpool) readPayloadLocked(manifest *diskRecord) ([]byte, error) {
	payload, err := store.readLeafLocked(manifest.PayloadLeaf, store.policy.MaximumRecordBytes)
	if err != nil || uint64(len(payload)) != manifest.Record.PayloadSize || digestPayload(payload) != manifest.Record.SHA256 {
		return nil, errors.Join(ErrIntegrity, err)
	}
	return payload, nil
}

func (store *LinuxSpool) persistRecordLocked(manifest diskRecord) error {
	if !validDiskRecord(manifest) {
		return ErrInvalid
	}
	encoded, err := encodeCanonical(manifest)
	if err != nil {
		return err
	}
	manifestLeaf, _ := recordLeaves(manifest.Record.Sequence)
	return store.atomicWriteLocked(manifestLeaf, encoded)
}

func (store *LinuxSpool) Lease(ctx context.Context, request LeaseRequest) ([]LeasedRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkLocked(ctx); err != nil {
		return nil, err
	}
	if request.Owner == "" || len(request.Owner) > MaximumOwnerBytes || !opaqueValuePattern.MatchString(request.Owner) || request.Limit == 0 || request.Limit > MaximumLeaseBatch {
		return nil, ErrInvalid
	}
	if request.Duration == 0 {
		request.Duration = store.policy.DefaultLease
	}
	if request.Duration <= 0 || request.Duration > store.policy.MaximumLease {
		return nil, ErrInvalid
	}
	now := store.now().UTC()
	leaseUntil := now.Add(request.Duration)
	if !leaseUntil.After(now) {
		return nil, ErrInvalid
	}
	result := make([]LeasedRecord, 0, request.Limit)
	for _, current := range stableRecords(store.records) {
		if len(result) >= int(request.Limit) {
			break
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if current.Record.AvailableAt.After(now) || current.Record.State == StateLeased && current.Record.LeaseUntil.After(now) {
			continue
		}
		if current.Record.Fence == math.MaxUint64 || current.Record.Attempts == math.MaxUint32 {
			return result, ErrLimit
		}
		payload, err := store.readPayloadLocked(current)
		if err != nil {
			return result, err
		}
		updated := *current
		updated.Record.State = StateLeased
		updated.Record.LeaseOwner = request.Owner
		updated.Record.LeaseUntil = leaseUntil
		updated.Record.Fence++
		updated.Record.Attempts++
		updated.Record.RetryReason = ""
		if err = store.persistRecordLocked(updated); err != nil {
			return result, err
		}
		store.records[updated.Record.ID] = &updated
		result = append(result, LeasedRecord{Record: updated.Record, Payload: payload})
	}
	return result, nil
}

func (store *LinuxSpool) leasedRecordLocked(id RecordID, fence uint64) (*diskRecord, error) {
	if !id.valid() || fence == 0 {
		return nil, ErrInvalid
	}
	manifest, exists := store.records[id]
	if !exists {
		return nil, ErrNotFound
	}
	if manifest.Record.State != StateLeased || manifest.Record.Fence != fence || !manifest.Record.LeaseUntil.After(store.now().UTC()) {
		return nil, ErrStaleFence
	}
	return manifest, nil
}

func (store *LinuxSpool) Ack(ctx context.Context, request AckRequest) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkLocked(ctx); err != nil {
		return err
	}
	manifest, err := store.leasedRecordLocked(request.ID, request.Fence)
	if err != nil {
		return err
	}
	return store.removeRecordLocked(manifest)
}

func (store *LinuxSpool) Retry(ctx context.Context, request RetryRequest) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkLocked(ctx); err != nil {
		return err
	}
	if request.ReasonCode != "" && (len(request.ReasonCode) > MaximumReasonBytes || !opaqueValuePattern.MatchString(request.ReasonCode)) {
		return ErrInvalid
	}
	manifest, err := store.leasedRecordLocked(request.ID, request.Fence)
	if err != nil {
		return err
	}
	availableAt, err := normalizeAvailable(store.now().UTC(), request.AvailableAt)
	if err != nil {
		return err
	}
	updated := *manifest
	updated.Record.State = StateQueued
	updated.Record.AvailableAt = availableAt
	updated.Record.LeaseOwner = ""
	updated.Record.LeaseUntil = time.Time{}
	updated.Record.RetryReason = request.ReasonCode
	if err = store.persistRecordLocked(updated); err != nil {
		return err
	}
	store.records[updated.Record.ID] = &updated
	return nil
}
