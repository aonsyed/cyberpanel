package mailtelemetry

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const journalctlPath = "/usr/bin/journalctl"

type SourceBackend string

const (
	BackendJournal SourceBackend = "journal"
	BackendOwnedFile SourceBackend = "owned_file"
)

type OwnedLogIdentity struct {
	Path string
	OwnerUID uint32
	OwnerGID uint32
	Device uint64
	Inode uint64
}

type SourceDescriptor struct {
	ID SourceID
	Kind SourceKind
	Generation uint64
	Backend SourceBackend
	JournalUnit string
	File *OwnedLogIdentity
}

var allowedJournalUnits = map[SourceKind]map[string]struct{}{
	SourcePostfix: {"postfix.service": {}},
	SourceDovecot: {"dovecot.service": {}},
	SourceRspamd: {"rspamd.service": {}},
	SourceClamAV: {"clamav-daemon.service": {}, "clamd@scan.service": {}, "clamd@cyberpanel.service": {}},
	SourceDKIM: {"opendkim.service": {}, "rspamd.service": {}},
	SourcePolicy: {"postfix-policyd.service": {}, "postfix-policy.service": {}},
	SourceDelivery: {"panel-mail-delivery.service": {}, "postfix.service": {}},
	SourceAuthentication: {"dovecot.service": {}, "postfix.service": {}},
}

var allowedOwnedFiles = map[SourceKind]map[string]struct{}{
	SourcePostfix: {"/var/log/mail.log": {}, "/var/log/maillog": {}},
	SourceDovecot: {"/var/log/mail.log": {}, "/var/log/maillog": {}, "/var/log/dovecot.log": {}},
	SourceRspamd: {"/var/log/rspamd/rspamd.log": {}},
	SourceClamAV: {"/var/log/clamav/clamav.log": {}, "/var/log/clamav/clamd.log": {}},
	SourceDKIM: {"/var/log/mail.log": {}, "/var/log/maillog": {}, "/var/log/opendkim.log": {}},
	SourcePolicy: {"/var/log/mail.log": {}, "/var/log/maillog": {}},
	SourceDelivery: {"/var/log/cyberpanel/mail-delivery.log": {}},
	SourceAuthentication: {"/var/log/mail.log": {}, "/var/log/maillog": {}, "/var/log/dovecot.log": {}},
}

func (source SourceDescriptor) valid() bool {
	if !validID(string(source.ID)) || !source.Kind.Valid() || source.Generation == 0 || source.Generation > MaximumRevision { return false }
	switch source.Backend {
	case BackendJournal:
		_, allowed := allowedJournalUnits[source.Kind][source.JournalUnit]
		return allowed && source.File == nil
	case BackendOwnedFile:
		if source.JournalUnit != "" || source.File == nil || source.File.Path == "" || source.File.Path[0] != '/' || source.File.Device == 0 || source.File.Inode == 0 { return false }
		_, allowed := allowedOwnedFiles[source.Kind][source.File.Path]
		return allowed
	default:
		return false
	}
}

type IngestQuery struct {
	SourceID SourceID
	Backfill bool
	Since time.Time
	Until time.Time
	LineLimit uint32
	ByteLimit int64
	Duration time.Duration
}

func (query IngestQuery) valid() bool {
	if !validID(string(query.SourceID)) || query.LineLimit == 0 || query.LineLimit > MaximumIngestLines || query.ByteLimit <= 0 || query.ByteLimit > MaximumIngestBytes || query.Duration <= 0 || query.Duration > MaximumIngestDuration { return false }
	if query.Backfill { return !query.Since.IsZero() && query.Until.After(query.Since) && query.Until.Sub(query.Since) <= MaximumSearchWindow }
	return query.Since.IsZero() && query.Until.IsZero()
}

type IngestSummary struct {
	SourceID SourceID
	Scanned uint32
	Stored uint32
	Duplicates uint32
	Gaps uint32
	Bytes int64
	Truncated bool
	Backfill bool
	CheckpointRevision uint64
}

type ingestionStore interface {
	LoadCheckpoint(context.Context, SourceID) (CursorCheckpoint, error)
	PutCheckpoint(context.Context, CursorCheckpoint, uint64) error
	PutEvent(context.Context, Event) (bool, error)
	PutGap(context.Context, ParseGap) error
}

type LinuxIngestor struct {
	sources map[SourceID]SourceDescriptor
	normalizer *Normalizer
	store ingestionStore
	now func() time.Time
}

func NewLinuxIngestor(sources []SourceDescriptor, normalizer *Normalizer, store ingestionStore) (*LinuxIngestor, error) {
	if len(sources) == 0 || len(sources) > 64 || normalizer == nil || store == nil { return nil, ErrInvalid }
	ingestor := &LinuxIngestor{sources: make(map[SourceID]SourceDescriptor, len(sources)), normalizer: normalizer, store: store, now: time.Now}
	for _, source := range sources {
		if !source.valid() { return nil, ErrInvalid }
		if _, exists := ingestor.sources[source.ID]; exists { return nil, ErrConflict }
		copySource := source
		if source.File != nil { identity := *source.File; copySource.File = &identity }
		ingestor.sources[source.ID] = copySource
	}
	return ingestor, nil
}

type journalEntry struct {
	Cursor string `json:"__CURSOR"`
	Realtime string `json:"__REALTIME_TIMESTAMP"`
	Message string `json:"MESSAGE"`
}

func strictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return err }
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF { return ErrIntegrity }
	return nil
}

func parseJournalTime(value string) (time.Time, error) {
	microseconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || microseconds <= 0 || microseconds > math.MaxInt64/int64(time.Microsecond) { return time.Time{}, ErrIntegrity }
	return time.Unix(0, microseconds*int64(time.Microsecond)).UTC(), nil
}

func validJournalCursor(value string) bool {
	if value == "" || len(value) > MaximumCursorBytes { return false }
	for _, character := range value { if character < 0x21 || character > 0x7e { return false } }
	return true
}

type boundedBuffer struct { data []byte; limit int }

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	remaining := buffer.limit-len(buffer.data)
	if remaining > 0 { if len(value) < remaining { remaining = len(value) }; buffer.data = append(buffer.data, value[:remaining]...) }
	return len(value), nil
}

func journalArguments(source SourceDescriptor, query IngestQuery, checkpoint CursorCheckpoint) []string {
	arguments := []string{"--no-pager", "--quiet", "--output=json", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE", "--unit=" + source.JournalUnit}
	if query.Backfill {
		arguments = append(arguments, "--since="+query.Since.UTC().Format(time.RFC3339Nano), "--until="+query.Until.UTC().Format(time.RFC3339Nano))
	} else if checkpoint.JournalCursor != "" {
		arguments = append(arguments, "--after-cursor="+checkpoint.JournalCursor)
	}
	return arguments
}

type observedRecord struct { cursor string; occurredAt time.Time; message []byte; fileOffset int64; device uint64; inode uint64 }

func (ingestor *LinuxIngestor) persistRecord(ctx context.Context, source SourceDescriptor, record observedRecord, checkpoint *CursorCheckpoint, summary *IngestSummary) error {
	input := InputRecord{Source: source.Kind, SourceID: source.ID, SourceGeneration: source.Generation, Cursor: record.cursor, OccurredAt: record.occurredAt, ObservedAt: ingestor.now().UTC(), Message: record.message}
	normalized, err := ingestor.normalizer.Normalize(ctx, input)
	if err != nil { return err }
	if normalized.Gap != nil {
		if err = ingestor.store.PutGap(ctx, *normalized.Gap); err != nil { return err }
		summary.Gaps++
	}
	if normalized.Event != nil && normalized.Retain {
		inserted, putErr := ingestor.store.PutEvent(ctx, *normalized.Event)
		if errors.Is(putErr, ErrLimit) {
			gap := sourceGap(source, GapSource, record.occurredAt, record.occurredAt, normalized.Event.Provenance.RecordDigest)
			gap.TenantID = normalized.Event.TenantID
			if gapErr := ingestor.store.PutGap(ctx, gap); gapErr != nil { return gapErr }
			summary.Gaps++
		} else if putErr != nil { return putErr }
		if putErr == nil {
			if inserted { summary.Stored++ } else { summary.Duplicates++ }
		}
	}
	if !summary.Backfill {
		digestBytes := sha256.Sum256(record.message)
		next := CursorCheckpoint{SourceID: source.ID, SourceGeneration: source.Generation, JournalCursor: record.cursor, FileOffset: record.fileOffset, Device: record.device, Inode: record.inode, LastRecordDigest: hex.EncodeToString(digestBytes[:]), LastOccurredAt: record.occurredAt.UTC(), Revision: checkpoint.Revision+1, UpdatedAt: ingestor.now().UTC()}
		if source.Backend == BackendOwnedFile { next.JournalCursor = "" }
		if err = ingestor.store.PutCheckpoint(ctx, next, checkpoint.Revision); err != nil { return err }
		*checkpoint = next
		summary.CheckpointRevision = next.Revision
	}
	return nil
}

func (ingestor *LinuxIngestor) Ingest(ctx context.Context, query IngestQuery) (IngestSummary, error) {
	if ingestor == nil || ctx == nil || !query.valid() { return IngestSummary{}, ErrInvalid }
	source, exists := ingestor.sources[query.SourceID]
	if !exists { return IngestSummary{}, ErrNotFound }
	if query.Backfill && source.Backend != BackendJournal { return IngestSummary{}, ErrInvalid }
	checkpoint := CursorCheckpoint{}
	if !query.Backfill {
		loaded, err := ingestor.store.LoadCheckpoint(ctx, source.ID)
		if err == nil {
			checkpoint = loaded
			if checkpoint.SourceGeneration != source.Generation {
				gap := sourceGap(source, GapRotated, checkpoint.LastOccurredAt, ingestor.now().UTC(), checkpoint.LastRecordDigest)
				if putErr := ingestor.store.PutGap(ctx, gap); putErr != nil { return IngestSummary{}, putErr }
				return IngestSummary{SourceID: source.ID, Gaps: 1}, ErrGap
			}
		} else if !errors.Is(err, ErrNotFound) { return IngestSummary{}, err }
	}
	bounded, cancel := context.WithTimeout(ctx, query.Duration)
	defer cancel()
	summary := IngestSummary{SourceID: source.ID, Backfill: query.Backfill, CheckpointRevision: checkpoint.Revision}
	var err error
	if source.Backend == BackendJournal { err = ingestor.ingestJournal(bounded, source, query, &checkpoint, &summary) } else { err = ingestor.ingestFile(bounded, source, query, &checkpoint, &summary) }
	if errors.Is(bounded.Err(), context.DeadlineExceeded) && ctx.Err() == nil { summary.Truncated = true; err = nil }
	if summary.Truncated {
		gap := sourceGap(source, GapTruncated, ingestor.now().UTC(), ingestor.now().UTC(), digestParts(string(source.ID), fmt.Sprint(summary.Scanned), fmt.Sprint(summary.Bytes)))
		if gapErr := ingestor.store.PutGap(ctx, gap); gapErr != nil { return summary, gapErr }
		summary.Gaps++
	}
	return summary, err
}

func sourceGap(source SourceDescriptor, code GapCode, first, last time.Time, evidence string) ParseGap {
	if first.IsZero() { first = last }
	if last.Before(first) { last = first }
	if !validDigest(evidence) { evidence = digestParts(evidence) }
	return ParseGap{ID: "gap-"+digestParts(string(source.ID), fmt.Sprint(source.Generation), string(code), repositoryTime(first), evidence)[:24], SourceID: source.ID, SourceGeneration: source.Generation, Code: code, Count: 1, FirstAt: first.UTC(), LastAt: last.UTC(), EvidenceDigest: evidence}
}

func (ingestor *LinuxIngestor) ingestJournal(ctx context.Context, source SourceDescriptor, query IngestQuery, checkpoint *CursorCheckpoint, summary *IngestSummary) error {
	processContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(processContext, journalctlPath, journalArguments(source, query, *checkpoint)...)
	command.Dir = "/"
	command.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin", "SYSTEMD_PAGER=cat", "PAGER=cat"}
	stdout, err := command.StdoutPipe()
	if err != nil { return err }
	stderr := &boundedBuffer{limit: 32<<10}
	command.Stderr = stderr
	if err = command.Start(); err != nil { return err }
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), MaximumRecordBytes+64<<10)
	for scanner.Scan() {
		raw := append([]byte(nil), scanner.Bytes()...)
		if summary.Scanned == query.LineLimit || summary.Bytes+int64(len(raw)) > query.ByteLimit { summary.Truncated = true; cancel(); break }
		summary.Scanned++
		summary.Bytes += int64(len(raw))
		var entry journalEntry
		if strictJSON(raw, &entry) != nil || !validJournalCursor(entry.Cursor) || len(entry.Message) == 0 || len(entry.Message) > MaximumRecordBytes {
			cancel()
			err = ErrIntegrity
			break
		}
		occurredAt, parseErr := parseJournalTime(entry.Realtime)
		if parseErr != nil { cancel(); err = parseErr; break }
		if persistErr := ingestor.persistRecord(ctx, source, observedRecord{cursor: entry.Cursor, occurredAt: occurredAt, message: []byte(entry.Message)}, checkpoint, summary); persistErr != nil { cancel(); err = persistErr; break }
	}
	if scanErr := scanner.Err(); scanErr != nil && err == nil && !summary.Truncated { err = scanErr }
	waitErr := command.Wait()
	if err == nil && waitErr != nil && !summary.Truncated {
		failure := strings.ToLower(string(stderr.data))
		if strings.Contains(failure, "cursor") {
			gap := sourceGap(source, GapRotated, ingestor.now().UTC(), ingestor.now().UTC(), digestParts(failure))
			if gapErr := ingestor.store.PutGap(context.WithoutCancel(ctx), gap); gapErr != nil { return gapErr }
			summary.Gaps++
			return ErrGap
		}
		return ErrIntegrity
	}
	return err
}

func openOwnedLog(identity OwnedLogIdentity) (*os.File, error) {
	fd, err := syscall.Open(identity.Path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil { return nil, err }
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil { syscall.Close(fd); return nil, err }
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || uint64(stat.Dev) != identity.Device || stat.Ino != identity.Inode || stat.Uid != identity.OwnerUID || stat.Gid != identity.OwnerGID { syscall.Close(fd); return nil, ErrIntegrity }
	return os.NewFile(uintptr(fd), identity.Path), nil
}

func parseSyslogLine(raw []byte, now time.Time) (time.Time, []byte, error) {
	if len(raw) < 18 || len(raw) > MaximumRecordBytes { return time.Time{}, nil, ErrIntegrity }
	prefix := string(raw[:15])
	at, err := time.ParseInLocation("Jan _2 15:04:05", prefix, time.UTC)
	if err != nil { return time.Time{}, nil, ErrIntegrity }
	at = time.Date(now.Year(), at.Month(), at.Day(), at.Hour(), at.Minute(), at.Second(), 0, time.UTC)
	if at.After(now.Add(24*time.Hour)) { at = at.AddDate(-1, 0, 0) }
	remainder := raw[16:]
	space := bytes.IndexByte(remainder, ' ')
	if space <= 0 || space == len(remainder)-1 { return time.Time{}, nil, ErrIntegrity }
	message := bytes.TrimSpace(remainder[space+1:])
	if len(message) == 0 { return time.Time{}, nil, ErrIntegrity }
	return at, append([]byte(nil), message...), nil
}

func (ingestor *LinuxIngestor) ingestFile(ctx context.Context, source SourceDescriptor, query IngestQuery, checkpoint *CursorCheckpoint, summary *IngestSummary) error {
	file, err := openOwnedLog(*source.File)
	if err != nil { return err }
	defer file.Close()
	offset := int64(0)
	if checkpoint.Revision > 0 {
		if checkpoint.Device != source.File.Device || checkpoint.Inode != source.File.Inode { return ErrGap }
		offset = checkpoint.FileOffset
	}
	stat, err := file.Stat()
	if err != nil { return err }
	if offset > stat.Size() {
		gap := sourceGap(source, GapRotated, checkpoint.LastOccurredAt, ingestor.now().UTC(), checkpoint.LastRecordDigest)
		if err = ingestor.store.PutGap(ctx, gap); err != nil { return err }
		summary.Gaps++
		return ErrGap
	}
	if _, err = file.Seek(offset, io.SeekStart); err != nil { return err }
	reader := bufio.NewReaderSize(file, 64<<10)
	for {
		if ctx.Err() != nil { return ctx.Err() }
		raw, readErr := reader.ReadBytes('\n')
		if errors.Is(readErr, io.EOF) && len(raw) == 0 { return nil }
		if len(raw) > MaximumRecordBytes { return ErrLimit }
		if summary.Scanned == query.LineLimit || summary.Bytes+int64(len(raw)) > query.ByteLimit { summary.Truncated = true; return nil }
		summary.Scanned++
		summary.Bytes += int64(len(raw))
		offset += int64(len(raw))
		occurredAt, message, parseErr := parseSyslogLine(bytes.TrimSuffix(raw, []byte{'\n'}), ingestor.now().UTC())
		if parseErr != nil { return parseErr }
		cursor := fmt.Sprintf("file:%d:%d:%d", source.File.Device, source.File.Inode, offset)
		if err = ingestor.persistRecord(ctx, source, observedRecord{cursor: cursor, occurredAt: occurredAt, message: message, fileOffset: offset, device: source.File.Device, inode: source.File.Inode}, checkpoint, summary); err != nil { return err }
		if errors.Is(readErr, io.EOF) { return nil }
		if readErr != nil { return readErr }
	}
}
