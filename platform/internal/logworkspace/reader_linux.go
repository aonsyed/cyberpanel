package logworkspace

import (
	"bufio"
	"context"
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
	"unicode/utf8"
)

const (
	journalctlPath   = "/usr/bin/journalctl"
	maximumStderr    = 32 << 10
	journalLineExtra = 64 << 10
)

type DescriptorRoot struct {
	ID     RootID
	FD     int
	Device uint64
}

type linuxRoot struct {
	fd     int
	device uint64
}

type LinuxReader struct {
	registry   *Registry
	roots      map[RootID]linuxRoot
	cursors    *CursorCodec
	authorizer ReadAuthorizer
	redactor   Redactor
	timestamps TimestampExtractor
	now        func() time.Time
}

func NewLinuxReader(registry *Registry, bindings []DescriptorRoot, cursors *CursorCodec, authorizer ReadAuthorizer, redactor Redactor, timestamps TimestampExtractor) (*LinuxReader, error) {
	if registry == nil || len(bindings) > MaximumSources || cursors == nil || authorizer == nil || redactor == nil || timestamps == nil {
		return nil, ErrInvalid
	}
	reader := &LinuxReader{
		registry: registry, roots: make(map[RootID]linuxRoot, len(bindings)), cursors: cursors,
		authorizer: authorizer, redactor: redactor, timestamps: timestamps, now: time.Now,
	}
	for _, binding := range bindings {
		if !opaquePattern.MatchString(string(binding.ID)) || binding.FD < 0 {
			reader.Close()
			return nil, ErrInvalid
		}
		if _, approved := registry.roots[binding.ID]; !approved {
			reader.Close()
			return nil, ErrUnauthorized
		}
		duplicated, err := syscall.Dup(binding.FD)
		if err != nil {
			reader.Close()
			return nil, err
		}
		syscall.CloseOnExec(duplicated)
		var stat syscall.Stat_t
		if err = syscall.Fstat(duplicated, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || binding.Device != 0 && uint64(stat.Dev) != binding.Device {
			syscall.Close(duplicated)
			reader.Close()
			return nil, ErrIntegrity
		}
		if _, exists := reader.roots[binding.ID]; exists {
			syscall.Close(duplicated)
			reader.Close()
			return nil, ErrConflict
		}
		reader.roots[binding.ID] = linuxRoot{fd: duplicated, device: uint64(stat.Dev)}
	}
	return reader, nil
}

func (reader *LinuxReader) Close() error {
	if reader == nil {
		return nil
	}
	var result error
	for id, root := range reader.roots {
		if err := syscall.Close(root.fd); err != nil {
			result = errors.Join(result, err)
		}
		delete(reader.roots, id)
	}
	return result
}

type streamProgress struct {
	lines         uint32
	bytes         int64
	scannedLines  uint32
	scannedBytes  int64
	truncated     bool
	journalCursor string
	fileOffset    int64
	device        uint64
	inode         uint64
}

func (reader *LinuxReader) Stream(ctx context.Context, actor Actor, query Query, sink RecordSink) (ProjectionSummary, error) {
	if reader == nil || ctx == nil || sink == nil || !actor.valid() || query.Validate() != nil {
		return ProjectionSummary{}, ErrInvalid
	}
	source, err := reader.registry.Resolve(query.SourceID)
	if err != nil {
		return ProjectionSummary{}, err
	}
	if source.Scope.TenantID != "" && source.Scope.TenantID != actor.TenantID {
		return ProjectionSummary{}, ErrUnauthorized
	}
	if err = reader.authorizer.AuthorizeLogRead(ctx, actor, source, query); err != nil {
		return ProjectionSummary{}, ErrUnauthorized
	}
	digest, err := queryDigest(query)
	if err != nil {
		return ProjectionSummary{}, err
	}
	var search *compiledSearch
	if query.Projection == ProjectionSearch {
		search, err = compileSearch(query.Search)
		if err != nil {
			return ProjectionSummary{}, err
		}
	}
	var cursor CursorState
	if query.Projection == ProjectionCursor {
		cursor, err = reader.cursors.Decode(ctx, query.Cursor)
		if err != nil {
			return ProjectionSummary{}, err
		}
		if cursor.SourceID != source.ID || cursor.Generation != source.Generation || cursor.Backend != source.Backend {
			condition := StreamCondition{Code: ConditionRotatedGap, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()}
			if conditionErr := sink.WriteCondition(ctx, condition); conditionErr != nil {
				return ProjectionSummary{}, conditionErr
			}
			summary := ProjectionSummary{SourceID: source.ID, Generation: source.Generation}
			return summary, errors.Join(ErrGap, sink.Close(ctx, summary))
		}
	}
	boundedContext, cancel := context.WithTimeout(ctx, query.Limits.Duration)
	defer cancel()
	progress := streamProgress{}
	if query.Projection == ProjectionCursor && source.Backend == BackendJournal {
		progress.journalCursor = cursor.JournalCursor
	}
	if source.Backend == BackendFile && source.File != nil {
		progress.device = source.File.Device
		progress.inode = source.File.Inode
	}
	var regexExpires time.Time
	if search != nil && search.regex != nil {
		regexExpires = reader.now().UTC().Add(query.Search.RegexTimeout)
	}
	switch source.Backend {
	case BackendJournal:
		err = reader.streamJournal(boundedContext, source, query, cursor, search, regexExpires, sink, &progress)
	case BackendFile:
		err = reader.streamFile(boundedContext, source, query, cursor, search, regexExpires, sink, &progress)
	default:
		err = ErrIntegrity
	}
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		progress.truncated = true
		conditionErr := sink.WriteCondition(ctx, StreamCondition{Code: ConditionTruncated, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()})
		if conditionErr != nil {
			err = conditionErr
		} else {
			err = nil
		}
	}
	summary := ProjectionSummary{SourceID: source.ID, Generation: source.Generation, Lines: progress.lines, Bytes: progress.bytes, Truncated: progress.truncated}
	if err == nil && (progress.journalCursor != "" || source.Backend == BackendFile) {
		state := CursorState{
			SourceID: source.ID, Generation: source.Generation, Backend: source.Backend,
			JournalCursor: progress.journalCursor, FileOffset: progress.fileOffset,
			Device: progress.device, Inode: progress.inode, QueryDigest: digest,
		}
		summary.NextCursor, err = reader.cursors.Encode(ctx, state, 15*time.Minute)
	}
	closeErr := sink.Close(ctx, summary)
	if err != nil {
		return summary, err
	}
	if closeErr != nil {
		return summary, closeErr
	}
	return summary, nil
}

type cappedWriter struct {
	data  []byte
	limit int
}

func (writer *cappedWriter) Write(value []byte) (int, error) {
	remaining := writer.limit - len(writer.data)
	if remaining > 0 {
		if len(value) < remaining {
			remaining = len(value)
		}
		writer.data = append(writer.data, value[:remaining]...)
	}
	return len(value), nil
}

type journalRecord struct {
	Cursor    string          `json:"__CURSOR"`
	Realtime  json.RawMessage `json:"__REALTIME_TIMESTAMP"`
	Message   json.RawMessage `json:"MESSAGE"`
}

func journalTimestamp(raw json.RawMessage) (time.Time, error) {
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil || encoded == "" {
		return time.Time{}, ErrIntegrity
	}
	microseconds, err := strconv.ParseInt(encoded, 10, 64)
	if err != nil || microseconds <= 0 || microseconds > math.MaxInt64/int64(time.Microsecond) {
		return time.Time{}, ErrIntegrity
	}
	return time.Unix(0, microseconds*int64(time.Microsecond)).UTC(), nil
}

func journalMessage(raw json.RawMessage) ([]byte, error) {
	var message string
	if err := json.Unmarshal(raw, &message); err != nil || len(message) > MaximumRecordBytes {
		return nil, ErrIntegrity
	}
	return []byte(message), nil
}

func journalArguments(source Source, query Query, cursor CursorState) []string {
	arguments := []string{"--no-pager", "--quiet", "--output=json", "--unit", string(source.Unit)}
	if query.Projection == ProjectionCursor {
		arguments = append(arguments, "--after-cursor", cursor.JournalCursor)
	}
	if query.Projection == ProjectionTail {
		lines := query.TailLines
		if lines > query.Limits.Lines {
			lines = query.Limits.Lines
		}
		arguments = append(arguments, "--lines", strconv.FormatUint(uint64(lines), 10))
	}
	if !query.Since.IsZero() {
		arguments = append(arguments, "--since", query.Since.UTC().Format(time.RFC3339Nano))
	}
	if !query.Until.IsZero() {
		arguments = append(arguments, "--until", query.Until.UTC().Format(time.RFC3339Nano))
	}
	return arguments
}

func (reader *LinuxReader) streamJournal(ctx context.Context, source Source, query Query, cursor CursorState, search *compiledSearch, regexExpires time.Time, sink RecordSink, progress *streamProgress) error {
	processContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(processContext, journalctlPath, journalArguments(source, query, cursor)...)
	command.Dir = "/"
	command.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin", "SYSTEMD_PAGER=cat", "PAGER=cat"}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	stderr := &cappedWriter{limit: maximumStderr}
	command.Stderr = stderr
	if err = command.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), MaximumRecordBytes+journalLineExtra)
	for scanner.Scan() {
		if err = ctx.Err(); err != nil {
			cancel()
			break
		}
		var entry journalRecord
		if strictDecode(scanner.Bytes(), &entry) != nil || !validBackendCursor(entry.Cursor) {
			cancel()
			err = ErrIntegrity
			break
		}
		observedAt, parseErr := journalTimestamp(entry.Realtime)
		if parseErr != nil {
			cancel()
			err = parseErr
			break
		}
		message, parseErr := journalMessage(entry.Message)
		if parseErr != nil {
			cancel()
			err = parseErr
			break
		}
		progress.journalCursor = entry.Cursor
		stop, emitErr := reader.emit(ctx, source, query, search, regexExpires, observedAt, 0, int64(len(scanner.Bytes())), message, sink, progress)
		if emitErr != nil {
			cancel()
			err = emitErr
			break
		}
		if stop {
			cancel()
			break
		}
	}
	if scanErr := scanner.Err(); scanErr != nil && err == nil && !progress.truncated {
		err = scanErr
	}
	waitErr := command.Wait()
	if progress.truncated {
		return nil
	}
	if err != nil {
		return err
	}
	if waitErr != nil {
		failure := strings.ToLower(string(stderr.data))
		if query.Projection == ProjectionCursor && strings.Contains(failure, "cursor") {
			condition := StreamCondition{Code: ConditionRotatedGap, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()}
			if conditionErr := sink.WriteCondition(ctx, condition); conditionErr != nil {
				return conditionErr
			}
			return ErrGap
		}
		return fmt.Errorf("journal reader failed: %w", ErrIntegrity)
	}
	return nil
}

func (reader *LinuxReader) openOwnedFile(source Source) (*os.File, error) {
	if source.File == nil {
		return nil, ErrIntegrity
	}
	root, ok := reader.roots[source.File.Root]
	if !ok {
		return nil, ErrIntegrity
	}
	current := root.fd
	ownedCurrent := false
	closeCurrent := func() {
		if ownedCurrent {
			syscall.Close(current)
		}
	}
	for _, segment := range source.File.Segments[:len(source.File.Segments)-1] {
		next, err := syscall.Openat(current, segment, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
		if err != nil {
			closeCurrent()
			if errors.Is(err, syscall.ENOENT) {
				return nil, ErrNotFound
			}
			return nil, ErrIntegrity
		}
		var stat syscall.Stat_t
		if err = syscall.Fstat(next, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || uint64(stat.Dev) != root.device {
			syscall.Close(next)
			closeCurrent()
			return nil, ErrIntegrity
		}
		closeCurrent()
		current = next
		ownedCurrent = true
	}
	finalName := source.File.Segments[len(source.File.Segments)-1]
	fd, err := syscall.Openat(current, finalName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	closeCurrent()
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, ErrNotFound
		}
		return nil, ErrIntegrity
	}
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 || uint64(stat.Dev) != root.device || uint64(stat.Dev) != source.File.Device || stat.Ino != source.File.Inode || stat.Uid != source.File.OwnerUID || stat.Gid != source.File.OwnerGID {
		syscall.Close(fd)
		return nil, ErrGap
	}
	return os.NewFile(uintptr(fd), "log-source"), nil
}

func tailOffset(file *os.File, tailLines uint32, maximumBytes int64) (int64, bool, error) {
	end, err := file.Seek(0, io.SeekEnd)
	if err != nil || end == 0 {
		return 0, false, err
	}
	const chunkSize int64 = 32 << 10
	position := end
	remaining := maximumBytes
	var lines uint32
	skipTerminalNewline := true
	buffer := make([]byte, chunkSize)
	for position > 0 && remaining > 0 {
		amount := chunkSize
		if amount > position {
			amount = position
		}
		if amount > remaining {
			amount = remaining
		}
		position -= amount
		read, readErr := file.ReadAt(buffer[:amount], position)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return 0, false, readErr
		}
		for index := read - 1; index >= 0; index-- {
			if buffer[index] != '\n' {
				skipTerminalNewline = false
				continue
			}
			if skipTerminalNewline {
				skipTerminalNewline = false
				continue
			}
			lines++
			if lines == tailLines {
				return position + int64(index) + 1, false, nil
			}
		}
		remaining -= int64(read)
	}
	return position, position > 0, nil
}

func (reader *LinuxReader) streamFile(ctx context.Context, source Source, query Query, cursor CursorState, search *compiledSearch, regexExpires time.Time, sink RecordSink, progress *streamProgress) error {
	file, err := reader.openOwnedFile(source)
	if err != nil {
		code := ConditionRotatedGap
		if errors.Is(err, ErrNotFound) {
			code = ConditionMissing
		}
		if conditionErr := sink.WriteCondition(ctx, StreamCondition{Code: code, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()}); conditionErr != nil {
			return conditionErr
		}
		return err
	}
	defer file.Close()
	start := int64(0)
	if query.Projection == ProjectionCursor {
		if cursor.Device != source.File.Device || cursor.Inode != source.File.Inode || cursor.FileOffset < 0 {
			if err = sink.WriteCondition(ctx, StreamCondition{Code: ConditionRotatedGap, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()}); err != nil {
				return err
			}
			return ErrGap
		}
		start = cursor.FileOffset
	} else if query.Projection == ProjectionTail {
		start, progress.truncated, err = tailOffset(file, query.TailLines, query.Limits.Bytes)
		if err != nil {
			return err
		}
		if progress.truncated {
			if err = sink.WriteCondition(ctx, StreamCondition{Code: ConditionTruncated, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()}); err != nil {
				return err
			}
		}
	}
	end, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if start > end {
		if err = sink.WriteCondition(ctx, StreamCondition{Code: ConditionRotatedGap, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()}); err != nil {
			return err
		}
		return ErrGap
	}
	if _, err = file.Seek(start, io.SeekStart); err != nil {
		return err
	}
	progress.fileOffset = start
	buffer := bufio.NewReaderSize(file, MaximumRecordBytes+1)
	if progress.truncated && start > 0 {
		discarded, discardErr := buffer.ReadSlice('\n')
		progress.fileOffset += int64(len(discarded))
		if errors.Is(discardErr, bufio.ErrBufferFull) {
			return ErrLimit
		}
		if discardErr != nil && !errors.Is(discardErr, io.EOF) {
			return discardErr
		}
	}
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		line, readErr := buffer.ReadSlice('\n')
		if errors.Is(readErr, bufio.ErrBufferFull) {
			return ErrLimit
		}
		if len(line) > 0 {
			lineOffset := progress.fileOffset
			scanBytes := int64(len(line))
			progress.fileOffset += int64(len(line))
			line = append([]byte(nil), line...)
			line = []byte(strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"))
			observedAt, timestampErr := reader.timestamps.Timestamp(ctx, source, line)
			if timestampErr != nil || observedAt.IsZero() {
				return ErrIntegrity
			}
			stop, emitErr := reader.emit(ctx, source, query, search, regexExpires, observedAt.UTC(), lineOffset, scanBytes, line, sink, progress)
			if emitErr != nil {
				return emitErr
			}
			if stop {
				return nil
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (reader *LinuxReader) emit(ctx context.Context, source Source, query Query, search *compiledSearch, regexExpires time.Time, observedAt time.Time, offset, scanBytes int64, raw []byte, sink RecordSink, progress *streamProgress) (bool, error) {
	if len(raw) > MaximumRecordBytes || scanBytes <= 0 || scanBytes > int64(MaximumRecordBytes+journalLineExtra) {
		return false, ErrLimit
	}
	if progress.scannedLines == query.Limits.Lines || progress.scannedBytes+scanBytes > query.Limits.Bytes {
		if !progress.truncated {
			if err := sink.WriteCondition(ctx, StreamCondition{Code: ConditionTruncated, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()}); err != nil {
				return false, err
			}
		}
		progress.truncated = true
		return true, nil
	}
	progress.scannedLines++
	progress.scannedBytes += scanBytes
	if !query.Since.IsZero() && observedAt.Before(query.Since) || !query.Until.IsZero() && !observedAt.Before(query.Until) {
		return false, nil
	}
	redacted, changed, err := reader.redactor.RedactLogRecord(ctx, source, append([]byte(nil), raw...))
	if err != nil || redacted == nil || len(redacted) > MaximumRecordBytes || !utf8.Valid(redacted) {
		return false, ErrIntegrity
	}
	if search != nil {
		if !regexExpires.IsZero() && !reader.now().UTC().Before(regexExpires) {
			if err = sink.WriteCondition(ctx, StreamCondition{Code: ConditionSearchTimeout, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()}); err != nil {
				return false, err
			}
			progress.truncated = true
			return true, nil
		}
		if !search.match(string(redacted)) {
			return false, nil
		}
		if !regexExpires.IsZero() && !reader.now().UTC().Before(regexExpires) {
			if err = sink.WriteCondition(ctx, StreamCondition{Code: ConditionSearchTimeout, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()}); err != nil {
				return false, err
			}
			progress.truncated = true
			return true, nil
		}
	}
	if progress.lines == query.Limits.Lines || progress.bytes+int64(len(redacted)) > query.Limits.Bytes {
		if !progress.truncated {
			if err = sink.WriteCondition(ctx, StreamCondition{Code: ConditionTruncated, SourceID: source.ID, Generation: source.Generation, At: reader.now().UTC()}); err != nil {
				return false, err
			}
		}
		progress.truncated = true
		return true, nil
	}
	record := LogRecord{
		SourceID: source.ID, Generation: source.Generation, Sequence: uint64(progress.lines) + 1,
		Offset: offset, ObservedAt: observedAt, Text: append([]byte(nil), redacted...), Redacted: changed,
	}
	if err = sink.WriteRecord(ctx, record); err != nil {
		return false, err
	}
	progress.lines++
	progress.bytes += int64(len(redacted))
	return false, nil
}
