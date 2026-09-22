//go:build linux

package database

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	mariaDBDumpBinary       = "/usr/bin/mariadb-dump"
	mariaDBClientBinary     = "/usr/bin/mariadb"
	transferConfigDirectory = "/run/cyberpanel/database-transfer/"
	transferSQLMagic        = "-- cyberpanel-mariadb-transfer-v1\n"
	transferCheckpointBytes = 1 << 20
)

type TransferArtifactReader interface {
	io.ReadCloser
	Descriptor() TransferArtifactDescriptor
}

type TransferArtifactWriter interface {
	io.WriteCloser
	Commit(context.Context, string, uint64, uint64) (TransferArtifactDescriptor, error)
	Abort(context.Context) error
}

type TransferArtifactStore interface {
	OpenTransferArtifact(context.Context, TransferArtifactIdentity) (TransferArtifactReader, error)
	BeginTransferArtifact(context.Context, TransferArtifactIdentity, TransferFormat, TransferCompression, TransferRetention) (TransferArtifactWriter, error)
}

type TransferClientConfigDescriptor struct {
	Path    string
	Token   ResourceID
	Database SQLIdentifier
	Direction TransferDirection
	ReadOnly bool
	ExpiresAt time.Time
	// Context carries native writer-authority cancellation, never caller input.
	Context context.Context
	Release func() error
	// Set only by the protected workspace credential resolver, never wire input.
	transportArguments []string
	checkExportSchema func(context.Context) error
}

type MariaDBTransferClientConfigs interface {
	TransferClientConfig(context.Context, TransferJob, SQLIdentifier) (TransferClientConfigDescriptor, error)
}

type TransferStreamProgress struct {
	Bytes     uint64
	Rows      uint64
	SafePoint bool
}

type TransferCheckpoint func(TransferStreamProgress) error

type LinuxTransferBackend struct {
	artifacts TransferArtifactStore
	configs   MariaDBTransferClientConfigs
	now       func() time.Time
}

func NewLinuxTransferBackend(artifacts TransferArtifactStore, configs MariaDBTransferClientConfigs, now func() time.Time) (*LinuxTransferBackend, error) {
	if artifacts == nil || configs == nil { return nil, ErrTransferInvalid }
	if now == nil { now = time.Now }
	return &LinuxTransferBackend{artifacts: artifacts, configs: configs, now: now}, nil
}

func (backend *LinuxTransferBackend) Export(ctx context.Context, job TransferJob, database SQLIdentifier, checkpoint TransferCheckpoint) (TransferProcessReceipt, error) {
	if backend == nil || job.Validate() != nil || job.Direction != TransferExport || database.IsZero() || checkpoint == nil { return TransferProcessReceipt{}, ErrTransferInvalid }
	descriptor, err := backend.configs.TransferClientConfig(ctx, job, database)
	if err != nil { return TransferProcessReceipt{}, err }
	if err = validateTransferClientConfig(descriptor, job, database); err != nil { releaseTransferConfig(descriptor); return TransferProcessReceipt{}, err }
	defer releaseTransferConfig(descriptor)
	if job.Selection.Schema {
		if descriptor.checkExportSchema == nil { return TransferProcessReceipt{}, ErrTransferUnsupportedObjects }
		if err = descriptor.checkExportSchema(ctx); err != nil { return TransferProcessReceipt{}, err }
	}
	if !descriptor.ExpiresAt.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, descriptor.ExpiresAt)
		defer cancel()
	}
	writer, err := backend.artifacts.BeginTransferArtifact(ctx, *job.Destination, job.Format, job.Compression, job.Retention)
	if err != nil { return TransferProcessReceipt{}, err }
	committed := false
	defer func() { if !committed { _ = writer.Abort(context.WithoutCancel(ctx)) } }()
	arguments := transferDumpArguments(descriptor.Path, database, job.Selection, descriptor.transportArguments...)
	processContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(processContext, mariaDBDumpBinary, arguments...)
	command.Env = transferEnvironment()
	stdout, err := command.StdoutPipe()
	if err != nil { return TransferProcessReceipt{}, err }
	stderr := newTransferLimitedBuffer(MaximumTransferStderrBytes)
	command.Stderr = stderr
	if err = command.Start(); err != nil { return TransferProcessReceipt{}, err }
	artifactOutput := newTransferBoundedWriter(writer, job.Limits.MaximumBytes, nil)
	var compressed io.WriteCloser
	var dumpDestination io.Writer = artifactOutput
	if job.Compression == TransferCompressionGzip {
		gzipWriter := gzip.NewWriter(artifactOutput)
		compressed = gzipWriter
		dumpDestination = gzipWriter
	}
	rowCounter := &transferDumpRows{maximum:job.Limits.MaximumRows}
	rawOutput := newTransferBoundedWriter(dumpDestination, job.Limits.MaximumBytes, func(bytes uint64) error {
		return checkpoint(TransferStreamProgress{Bytes: bytes, Rows: rowCounter.rows, SafePoint: false})
	})
	rowCounter.destination=rawOutput
	_, headerErr := rawOutput.Write([]byte(transferSQLMagic))
	_, copyErr := io.CopyBuffer(rowCounter, stdout, make([]byte, 64<<10))
	if copyErr==nil{copyErr=rowCounter.finish()}
	if headerErr != nil || copyErr != nil { cancel() }
	if compressed != nil {
		if closeErr := compressed.Close(); copyErr == nil { copyErr = closeErr }
	}
	waitErr := command.Wait()
	if closeErr := writer.Close(); copyErr == nil { copyErr = closeErr }
	exitCode := transferExitCode(waitErr)
	receipt := SealTransferProcessReceipt(TransferProcessReceipt{ExitCode: exitCode, Partial: waitErr != nil || headerErr != nil || copyErr != nil,
		BytesProcessed: artifactOutput.count, RowsProcessed: rowCounter.rows, StderrDigest: stderr.Digest(), StderrBytes: stderr.Size(), StderrTruncated: stderr.Truncated(), CompletedAt: backend.now().UTC()})
	if waitErr != nil || headerErr != nil || copyErr != nil {
		if errors.Is(headerErr, ErrTransferCancelled) || errors.Is(copyErr, ErrTransferCancelled) || errors.Is(ctx.Err(), context.Canceled) { return receipt, ErrTransferCancelled }
		if errors.Is(headerErr, ErrTransferLimit) || errors.Is(copyErr, ErrTransferLimit) { return receipt, ErrTransferLimit }
		return receipt, ErrTransferStale
	}
	if job.Selection.Schema {
		if err = descriptor.checkExportSchema(ctx); err != nil { receipt.Partial = true; return SealTransferProcessReceipt(receipt), err }
	}
	artifact, err := writer.Commit(ctx, artifactOutput.Digest(), artifactOutput.count, rowCounter.rows)
	if err != nil { receipt.Partial = true; receipt = SealTransferProcessReceipt(receipt); return receipt, err }
	if artifact.Validate() != nil || artifact.Identity != *job.Destination || artifact.Digest != artifactOutput.Digest() || artifact.Bytes != artifactOutput.count || artifact.Rows != rowCounter.rows ||
		artifact.Format != job.Format || artifact.Compression != job.Compression { receipt.Partial = true; receipt = SealTransferProcessReceipt(receipt); return receipt, ErrTransferInvalid }
	committed = true
	receipt.Artifact = &artifact
	receipt.Partial = false
	receipt = SealTransferProcessReceipt(receipt)
	if receipt.Validate(job) != nil { return TransferProcessReceipt{}, ErrTransferInvalid }
	return receipt, nil
}

func (backend *LinuxTransferBackend) Import(ctx context.Context, job TransferJob, database SQLIdentifier, checkpoint TransferCheckpoint) (TransferProcessReceipt, error) {
	if backend == nil || job.Validate() != nil || job.Direction != TransferImport || database.IsZero() || checkpoint == nil { return TransferProcessReceipt{}, ErrTransferInvalid }
	artifactReader, err := backend.artifacts.OpenTransferArtifact(ctx, job.Source.Identity)
	if err != nil { return TransferProcessReceipt{}, err }
	defer artifactReader.Close()
	if !sameTransferArtifact(artifactReader.Descriptor(), *job.Source) { return TransferProcessReceipt{}, ErrTransferStale }
	descriptor, err := backend.configs.TransferClientConfig(ctx, job, database)
	if err != nil { return TransferProcessReceipt{}, err }
	if err = validateTransferClientConfig(descriptor, job, database); err != nil { releaseTransferConfig(descriptor); return TransferProcessReceipt{}, err }
	defer releaseTransferConfig(descriptor)
	if descriptor.Context != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		stop := context.AfterFunc(descriptor.Context, cancel)
		defer stop(); defer cancel()
		if descriptor.Context.Err() != nil { return TransferProcessReceipt{}, ErrTransferCancelled }
	}
	if !descriptor.ExpiresAt.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, descriptor.ExpiresAt)
		defer cancel()
	}
	verifiedInput := newTransferDigestReader(artifactReader, job.Source.Bytes, job.Source.Digest, job.Limits.MaximumBytes, func(bytes uint64) error {
		return checkpoint(TransferStreamProgress{Bytes: bytes, Rows: 0, SafePoint: false})
	})
	bufferedInput := bufio.NewReaderSize(verifiedInput, 64<<10)
	var sqlStream io.Reader = bufferedInput
	var gzipReader *gzip.Reader
	if job.Compression == TransferCompressionGzip {
		magic, peekErr := bufferedInput.Peek(2)
		if peekErr != nil || len(magic) != 2 || magic[0] != 0x1f || magic[1] != 0x8b { return transferInputFailure(job, backend.now, verifiedInput, nil), ErrTransferInvalid }
		gzipReader, err = gzip.NewReader(bufferedInput)
		if err != nil { return transferInputFailure(job, backend.now, verifiedInput, nil), ErrTransferInvalid }
		defer gzipReader.Close()
		sqlStream = gzipReader
	}
	decompressed := newTransferBoundedReader(sqlStream, job.Limits.MaximumBytes)
	sqlBuffered := bufio.NewReaderSize(decompressed, 64<<10)
	// Ordinary single-database SQL dumps do not carry our export comment. It
	// is not an authorization boundary: validate every statement regardless
	// of provenance. A UTF-8 BOM is an encoding marker, not SQL or identity.
	if prefix, _ := sqlBuffered.Peek(3); bytes.Equal(prefix, []byte{0xef, 0xbb, 0xbf}) {
		_, _ = sqlBuffered.Discard(3)
	}
	lastSafeBytes := uint64(0)
	constrained := newConstrainedTransferSQLReader(sqlBuffered, func() error {
		if verifiedInput.count-lastSafeBytes < transferCheckpointBytes { return nil }
		lastSafeBytes = verifiedInput.count
		return checkpoint(TransferStreamProgress{Bytes: verifiedInput.count, Rows: 0, SafePoint: true})
	})
	arguments := []string{"--defaults-file=" + descriptor.Path, "--protocol=socket", "--socket=" + mariaDBSocket, "--skip-auto-rehash", "--binary-mode=1", "--local-infile=0", "--database=" + database.String()}
	processContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(processContext, mariaDBClientBinary, arguments...)
	command.Env = transferEnvironment()
	command.Stdin = constrained
	stdout, stderr := newTransferLimitedBuffer(MaximumTransferStderrBytes), newTransferLimitedBuffer(MaximumTransferStderrBytes)
	command.Stdout, command.Stderr = stdout, stderr
	commandErr := command.Run()
	exitCode := transferExitCode(commandErr)
	runErr := commandErr
	if constrained.Error() != nil { runErr = constrained.Error() }
	if gzipReader != nil {
		if closeErr := gzipReader.Close(); runErr == nil { runErr = closeErr }
	}
	if verifyErr := verifiedInput.Verify(); runErr == nil { runErr = verifyErr }
	operationContextErr := ctx.Err()
	// A successful import must not conceal a leaked credential/account.
	if descriptor.Release != nil {
		if cleanupErr := descriptor.Release(); cleanupErr != nil { runErr = ErrAmbiguous }
	}
	receipt := SealTransferProcessReceipt(TransferProcessReceipt{ExitCode: exitCode, Partial: runErr != nil, BytesProcessed: verifiedInput.count, RowsProcessed: job.Source.Rows,
		StderrDigest: stderr.Digest(), StderrBytes: stderr.Size(), StderrTruncated: stderr.Truncated(), InputVerified: runErr == nil && verifiedInput.verified, CompletedAt: backend.now().UTC()})
	if runErr != nil {
		if errors.Is(runErr, ErrAmbiguous) { return receipt, ErrAmbiguous }
		if errors.Is(runErr, ErrTransferUnsafeSQL) { return receipt, ErrTransferUnsafeSQL }
		if errors.Is(runErr, ErrTransferLimit) { return receipt, ErrTransferLimit }
		if errors.Is(runErr, ErrTransferCancelled) || errors.Is(operationContextErr, context.Canceled) { return receipt, ErrTransferCancelled }
		return receipt, ErrTransferStale
	}
	if receipt.Validate(job) != nil { return TransferProcessReceipt{}, ErrTransferInvalid }
	return receipt, nil
}

func transferDumpArguments(configPath string, database SQLIdentifier, selection TransferSelection, transport ...string) []string {
	if len(transport) == 0 { transport = []string{"--protocol=socket", "--socket=" + mariaDBSocket} }
	arguments := append([]string{"--defaults-file=" + configPath}, transport...)
	arguments = append(arguments, "--single-transaction", "--quick", "--skip-lock-tables",
		"--skip-comments", "--skip-dump-date", "--hex-blob", "--skip-triggers", "--skip-events", "--skip-extended-insert", "--skip-add-locks", "--skip-disable-keys")
	if !selection.Schema { arguments = append(arguments, "--no-create-info") }
	if !selection.Data { arguments = append(arguments, "--no-data") }
	arguments = append(arguments, database.String())
	for _, table := range selection.Tables { arguments = append(arguments, table.String()) }
	return arguments
}

func transferEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/nonexistent", "TMPDIR=/run/cyberpanel/database-transfer"}
}

func sameTransferArtifact(left, right TransferArtifactDescriptor) bool {
	return left.Identity == right.Identity && left.Format == right.Format && left.Compression == right.Compression && left.Bytes == right.Bytes && left.Rows == right.Rows &&
		left.Digest == right.Digest && left.CreatedAt.Equal(right.CreatedAt) && left.ExpiresAt.Equal(right.ExpiresAt)
}

func validateTransferClientConfig(descriptor TransferClientConfigDescriptor, job TransferJob, database SQLIdentifier) error {
	clean := filepath.Clean(descriptor.Path)
	if descriptor.Token.IsZero() || descriptor.Release == nil || descriptor.Database != database || descriptor.Direction != job.Direction || descriptor.ReadOnly != (job.Direction == TransferExport) ||
		clean != descriptor.Path || !validTransferConfigPath(clean) || !strings.HasPrefix(clean, transferConfigDirectory) || clean == strings.TrimSuffix(transferConfigDirectory, "/") { return ErrTransferInvalid }
	info, err := os.Lstat(clean)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 { return ErrUnauthorized }
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != 0 { return ErrUnauthorized }
	return nil
}

func validTransferConfigPath(path string) bool {
	if len(path) < len(transferConfigDirectory)+1 || len(path) > 256 { return false }
	for _, character := range path {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '/' || character == '.' || character == '_' || character == '-' { continue }
		return false
	}
	return true
}

func releaseTransferConfig(descriptor TransferClientConfigDescriptor) { if descriptor.Release != nil { _ = descriptor.Release() } }

type transferBoundedWriter struct {
	writer io.Writer
	maximum uint64
	count uint64
	hash hash.Hash
	checkpoint func(uint64) error
	nextCheckpoint uint64
}

func newTransferBoundedWriter(writer io.Writer, maximum uint64, checkpoint func(uint64) error) *transferBoundedWriter {
	return &transferBoundedWriter{writer: writer, maximum: maximum, hash: sha256.New(), checkpoint: checkpoint, nextCheckpoint: transferCheckpointBytes}
}

func (writer *transferBoundedWriter) Write(value []byte) (int, error) {
	if uint64(len(value)) > writer.maximum-writer.count { return 0, ErrTransferLimit }
	written, err := writer.writer.Write(value)
	if written > 0 { _, _ = writer.hash.Write(value[:written]); writer.count += uint64(written) }
	if err == nil && written != len(value) { err = io.ErrShortWrite }
	if err == nil && writer.checkpoint != nil && writer.count >= writer.nextCheckpoint {
		err = writer.checkpoint(writer.count)
		writer.nextCheckpoint = writer.count + transferCheckpointBytes
	}
	return written, err
}

func (writer *transferBoundedWriter) Digest() string { return hex.EncodeToString(writer.hash.Sum(nil)) }

type transferLimitedBuffer struct {
	mutex sync.Mutex
	buffer bytes.Buffer
	maximum int
	truncated bool
}

func newTransferLimitedBuffer(maximum int) *transferLimitedBuffer { return &transferLimitedBuffer{maximum: maximum} }

func (buffer *transferLimitedBuffer) Write(value []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	remaining := buffer.maximum - buffer.buffer.Len()
	if remaining > 0 { _, _ = buffer.buffer.Write(value[:minTransferInt(len(value), remaining)]) }
	if len(value) > remaining { buffer.truncated = true }
	return len(value), nil
}

func (buffer *transferLimitedBuffer) Digest() string { buffer.mutex.Lock(); defer buffer.mutex.Unlock(); return transferDigest(buffer.buffer.Bytes()) }
func (buffer *transferLimitedBuffer) Size() uint32 { buffer.mutex.Lock(); defer buffer.mutex.Unlock(); return uint32(buffer.buffer.Len()) }
func (buffer *transferLimitedBuffer) Truncated() bool { buffer.mutex.Lock(); defer buffer.mutex.Unlock(); return buffer.truncated }

type transferDigestReader struct {
	reader io.Reader
	expectedBytes uint64
	expectedDigest string
	maximum uint64
	count uint64
	hash hash.Hash
	checkpoint func(uint64) error
	nextCheckpoint uint64
	verified bool
	error error
}

func newTransferDigestReader(reader io.Reader, expectedBytes uint64, expectedDigest string, maximum uint64, checkpoint func(uint64) error) *transferDigestReader {
	return &transferDigestReader{reader: reader, expectedBytes: expectedBytes, expectedDigest: expectedDigest, maximum: maximum, hash: sha256.New(), checkpoint: checkpoint, nextCheckpoint: transferCheckpointBytes}
}

func (reader *transferDigestReader) Read(value []byte) (int, error) {
	if reader.error != nil { return 0, reader.error }
	maximumRead := reader.maximum - reader.count
	if maximumRead == 0 {
		var extra [1]byte
		read, err := reader.reader.Read(extra[:])
		if read > 0 { reader.error = ErrTransferLimit; return 0, reader.error }
		if errors.Is(err, io.EOF) {
			reader.error = reader.verifyAtEOF()
			if reader.error != nil { return 0, reader.error }
			reader.verified = true
		}
		return 0, err
	}
	if uint64(len(value)) > maximumRead { value = value[:maximumRead] }
	read, err := reader.reader.Read(value)
	if read > 0 { _, _ = reader.hash.Write(value[:read]); reader.count += uint64(read) }
	if reader.count > reader.expectedBytes { reader.error = ErrTransferInvalid; return read, reader.error }
	if reader.checkpoint != nil && reader.count >= reader.nextCheckpoint {
		if checkpointErr := reader.checkpoint(reader.count); checkpointErr != nil { reader.error = checkpointErr; return read, checkpointErr }
		reader.nextCheckpoint = reader.count + transferCheckpointBytes
	}
	if errors.Is(err, io.EOF) {
		reader.error = reader.verifyAtEOF()
		if reader.error != nil { return read, reader.error }
		reader.verified = true
	}
	return read, err
}

func (reader *transferDigestReader) verifyAtEOF() error {
	if reader.count != reader.expectedBytes || hex.EncodeToString(reader.hash.Sum(nil)) != reader.expectedDigest { return ErrTransferInvalid }
	return nil
}

func (reader *transferDigestReader) Verify() error {
	if reader.verified { return nil }
	buffer := make([]byte, 64<<10)
	for {
		_, err := reader.Read(buffer)
		if errors.Is(err, io.EOF) { return nil }
		if err != nil { return err }
	}
}

type transferBoundedReader struct { reader io.Reader; maximum, count uint64 }

func newTransferBoundedReader(reader io.Reader, maximum uint64) *transferBoundedReader { return &transferBoundedReader{reader: reader, maximum: maximum} }

func (reader *transferBoundedReader) Read(value []byte) (int, error) {
	if reader.count == reader.maximum {
		var extra [1]byte
		read, err := reader.reader.Read(extra[:])
		if read > 0 { return 0, ErrTransferLimit }
		return 0, err
	}
	if uint64(len(value)) > reader.maximum-reader.count { value = value[:reader.maximum-reader.count] }
	read, err := reader.reader.Read(value)
	reader.count += uint64(read)
	return read, err
}

type constrainedTransferSQLReader struct {
	reader *bufio.Reader
	ready []byte
	error error
	onSafe func() error
}

func newConstrainedTransferSQLReader(reader *bufio.Reader, onSafe func() error) *constrainedTransferSQLReader {
	return &constrainedTransferSQLReader{reader: reader, onSafe: onSafe}
}

func (reader *constrainedTransferSQLReader) Read(value []byte) (int, error) {
	if len(reader.ready) == 0 && reader.error == nil {
		reader.ready, reader.error = reader.nextStatement()
		if reader.error == nil && len(reader.ready) > 0 && reader.onSafe != nil { reader.error = reader.onSafe() }
	}
	if reader.error != nil && !errors.Is(reader.error, io.EOF) { reader.ready = nil; return 0, reader.error }
	if len(reader.ready) == 0 { return 0, reader.error }
	read := copy(value, reader.ready)
	reader.ready = reader.ready[read:]
	return read, nil
}

func (reader *constrainedTransferSQLReader) Error() error {
	if errors.Is(reader.error, io.EOF) { return nil }
	return reader.error
}

func (reader *constrainedTransferSQLReader) nextStatement() ([]byte, error) {
	statement := make([]byte, 0, 64<<10)
	var quote byte
	escaped, lineComment, blockComment := false, false, false
	previous := byte(0)
	for {
		character, err := reader.reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(bytes.TrimSpace(statement)) > 0 {
				return prepareTransferSQLStatement(statement)
			}
			return nil, err
		}
		statement = append(statement, character)
		if len(statement) > MaximumTransferStatementBytes { return nil, ErrTransferLimit }
		if lineComment {
			if character == '\n' { lineComment = false }
			previous = character
			continue
		}
		if blockComment {
			if previous == '*' && character == '/' { blockComment = false }
			previous = character
			continue
		}
		if quote != 0 {
			if escaped { escaped = false } else if character == '\\' { escaped = true } else if character == quote { quote = 0 }
			previous = character
			continue
		}
		// Client metacommands are not SQL. Never forward an unquoted escape
		// even when the enclosing statement starts with an allowed SQL token.
		if character == '\\' { return nil, ErrTransferUnsafeSQL }
		if previous == '-' && character == '-' || character == '#' { lineComment = true }
		if previous == '/' && character == '*' { blockComment = true }
		if character == '\'' || character == '"' || character == '`' { quote = character }
		if character == ';' {
			return prepareTransferSQLStatement(statement)
		}
		previous = character
	}
}

func validateTransferSQLStatement(statement []byte) error {
	normalized := normalizeTransferSQL(statement)
	fields := strings.Fields(normalized)
	if len(fields) == 0 { return nil }
	for _, forbidden := range []string{"OUTFILE", "DUMPFILE", "LOAD_FILE", "INFILE", "LOAD", "INSTALL", "UNINSTALL", "PLUGIN", "SONAME", "GRANT", "REVOKE", "SHUTDOWN", "MASTER", "SLAVE", "REPLICA", "SYSTEM", "DELIMITER", "TRIGGER", "PROCEDURE", "EVENT", "FEDERATED", "CONNECT", "SPIDER", "PREPARE", "EXECUTE", "DEALLOCATE", "CALL", "HANDLER", "SELECT"} {
		if containsTransferToken(fields, forbidden) { return ErrTransferUnsafeSQL }
	}
	if containsTransferPair(fields, "DATA", "DIRECTORY") || containsTransferPair(fields, "INDEX", "DIRECTORY") || containsTransferPair(fields, "CREATE", "FUNCTION") ||
		containsTransferPair(fields, "CREATE", "DATABASE") || containsTransferPair(fields, "DROP", "DATABASE") || containsTransferPair(fields, "SET", "GLOBAL") ||
		containsTransferToken(fields, "@@GLOBAL") || containsTransferToken(fields, "PERSIST") || containsTransferToken(fields, "PERSIST_ONLY") || containsTransferToken(fields, "SQL_LOG_BIN") { return ErrTransferUnsafeSQL }
	if fields[0] == "SET" && bytes.Contains(statement, []byte("(")) { return ErrTransferUnsafeSQL }
	allowed := fields[0] == "SET" || fields[0] == "COMMIT" || len(fields) >= 2 && ((fields[0] == "CREATE" && (fields[1] == "TABLE" || fields[1] == "INDEX")) ||
		(fields[0] == "DROP" && (fields[1] == "TABLE" || fields[1] == "VIEW" || fields[1] == "INDEX")) || fields[0] == "ALTER" && fields[1] == "TABLE" ||
		transferDataStatement(fields) || fields[0] == "LOCK" && fields[1] == "TABLES" || fields[0] == "UNLOCK" && fields[1] == "TABLES" ||
		fields[0] == "START" && fields[1] == "TRANSACTION")
	if !allowed { return ErrTransferUnsafeSQL }
	return nil
}

// Standard dump forms still run only under the isolated database loader's
// scoped grants. The common SELECT/file/client-command bans above also apply.
func transferDataStatement(fields []string) bool {
	if len(fields) < 2 { return false }
	if (fields[0] == "INSERT" || fields[0] == "REPLACE") && fields[1] == "INTO" { return true }
	return len(fields) >= 3 && fields[0] == "INSERT" && fields[1] == "IGNORE" && fields[2] == "INTO"
}

func normalizeTransferSQL(statement []byte) string {
	result := make([]byte, 0, len(statement))
	var quote byte
	escaped, lineComment, blockComment, executableComment, executablePrefix := false, false, false, false, false
	for index := 0; index < len(statement); index++ {
		character := statement[index]
		if lineComment { if character == '\n' { lineComment = false; result = append(result, ' ') }; continue }
		if blockComment {
			if character == '*' && index+1 < len(statement) && statement[index+1] == '/' { blockComment = false; executableComment = false; executablePrefix = false; result = append(result, ' '); index++; continue }
			if executableComment {
				if executablePrefix && (character >= '0' && character <= '9' || character == ' ' || character == '\t' || character == '\r' || character == '\n') { continue }
				executablePrefix = false
				result = appendTransferSQLCharacter(result, character)
			}
			continue
		}
		if quote != 0 {
			if escaped { escaped = false } else if character == '\\' { escaped = true } else if character == quote { quote = 0 }
			result = append(result, ' ')
			continue
		}
		if character == '\'' || character == '"' || character == '`' { quote = character; result = append(result, ' '); continue }
		if character == '#' || character == '-' && index+1 < len(statement) && statement[index+1] == '-' { lineComment = true; index++; continue }
		if character == '/' && index+1 < len(statement) && statement[index+1] == '*' {
			// Native mariadb-dump emits this exact protective client preamble.
			// Preserve its bytes but do not classify it as executable SQL. No
			// other MariaDB executable comment is exempt from validation.
			const sandboxHeader = "/*M!999999\\- enable the sandbox mode */"
			if bytes.HasPrefix(statement[index:], []byte(sandboxHeader)) {
				index += len(sandboxHeader)-1
				result = append(result, ' ')
				continue
			}
			mariaDBComment := index+3 < len(statement) && statement[index+2] == 'M' && statement[index+3] == '!'
			executableComment = index+2 < len(statement) && statement[index+2] == '!' || mariaDBComment
			executablePrefix = executableComment
			blockComment = true
			if mariaDBComment { index += 3 } else if executableComment { index += 2 } else { index++ }
			continue
		}
		result = appendTransferSQLCharacter(result, character)
	}
	return strings.ToUpper(string(result))
}

func appendTransferSQLCharacter(result []byte, character byte) []byte {
	if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '@' { return append(result, character) }
	return append(result, ' ')
}

func containsTransferToken(fields []string, token string) bool { for _, field := range fields { if field == token { return true } }; return false }
func containsTransferPair(fields []string, first, second string) bool { for index := 1; index < len(fields); index++ { if fields[index-1] == first && fields[index] == second { return true } }; return false }

func transferInputFailure(job TransferJob, now func() time.Time, input *transferDigestReader, stderr *transferLimitedBuffer) TransferProcessReceipt {
	stderrDigest, stderrBytes, truncated := transferDigest(nil), uint32(0), false
	if stderr != nil { stderrDigest, stderrBytes, truncated = stderr.Digest(), stderr.Size(), stderr.Truncated() }
	return SealTransferProcessReceipt(TransferProcessReceipt{ExitCode: -1, Partial: input.count > 0, BytesProcessed: input.count, RowsProcessed: 0,
		StderrDigest: stderrDigest, StderrBytes: stderrBytes, StderrTruncated: truncated, CompletedAt: now().UTC()})
}

func transferExitCode(err error) int {
	if err == nil { return 0 }
	var exitError *exec.ExitError
	if errors.As(err, &exitError) { return exitError.ExitCode() }
	return -1
}

func minTransferInt(left, right int) int { if left < right { return left }; return right }
