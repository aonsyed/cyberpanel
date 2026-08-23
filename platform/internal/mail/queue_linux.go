//go:build linux

package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	queuePostqueuePath = "/usr/sbin/postqueue"
	queuePostcatPath   = "/usr/sbin/postcat"
	queuePostsuperPath = "/usr/sbin/postsuper"
	queueSnapshotBytes = 16 << 20
	queueHeaderBytes   = 256 << 10
	queueStderrBytes   = 64 << 10
	queueMaximumParsedRecipients = 100000
)

type LinuxQueueAdminBackend struct {
	Now func() time.Time
}

func NewLinuxQueueAdminBackend(now func() time.Time) *LinuxQueueAdminBackend {
	if now == nil {
		now = time.Now
	}
	return &LinuxQueueAdminBackend{Now: now}
}

func (backend *LinuxQueueAdminBackend) Snapshot(ctx context.Context) (QueueBackendSnapshot, error) {
	if backend == nil || backend.Now == nil || ctx == nil {
		return QueueBackendSnapshot{}, ErrInvalidCommand
	}
	result, err := backend.run(ctx, 10*time.Second, queueSnapshotBytes, queueStderrBytes, queuePostqueuePath, "-j")
	if err != nil {
		wipeQueueCommandResult(&result)
		return QueueBackendSnapshot{}, err
	}
	defer wipeQueueCommandResult(&result)
	if result.Overflow {
		return QueueBackendSnapshot{}, ErrRateLimited
	}
	if result.ExitCode != 0 {
		return QueueBackendSnapshot{}, ErrAmbiguous
	}
	records, err := parsePostqueueJSON(result.Stdout)
	if err != nil {
		return QueueBackendSnapshot{}, err
	}
	return QueueBackendSnapshot{Records: records, EvidenceDigest: queueCommandDigest(queuePostqueuePath, []string{"-j"}, result), ObservedAt: result.ObservedAt}, nil
}

func (backend *LinuxQueueAdminBackend) Headers(ctx context.Context, id QueueID) (QueueBackendHeaders, error) {
	if backend == nil || backend.Now == nil || ctx == nil || !validQueueAdminID(id) {
		return QueueBackendHeaders{}, ErrInvalidCommand
	}
	arguments := []string{"-q", "-h", string(id)}
	result, err := backend.run(ctx, 10*time.Second, queueHeaderBytes, queueStderrBytes, queuePostcatPath, arguments...)
	if err != nil {
		wipeQueueCommandResult(&result)
		return QueueBackendHeaders{}, err
	}
	defer wipeQueueCommandResult(&result)
	evidence := queueCommandDigest(queuePostcatPath, arguments, result)
	if result.Overflow {
		return QueueBackendHeaders{}, ErrRateLimited
	}
	if exactQueueNotFound(id, result.Stdout, result.Stderr) {
		return QueueBackendHeaders{}, ErrNotFound
	}
	if result.ExitCode != 0 {
		return QueueBackendHeaders{}, ErrAmbiguous
	}
	headers, err := parseRedactedPostcatHeaders(result.Stdout)
	if err != nil {
		return QueueBackendHeaders{}, err
	}
	return QueueBackendHeaders{QueueID: id, Headers: headers, EvidenceDigest: evidence, ObservedAt: result.ObservedAt}, nil
}

func (backend *LinuxQueueAdminBackend) Body(ctx context.Context, id QueueID, maximum uint32) (QueueBackendBody, error) {
	if backend == nil || backend.Now == nil || ctx == nil || !validQueueAdminID(id) || maximum == 0 || maximum > QueueAdminMaximumBodyBytes {
		return QueueBackendBody{}, ErrInvalidCommand
	}
	arguments := []string{"-q", "-b", string(id)}
	result, err := backend.run(ctx, 10*time.Second, int(maximum), queueStderrBytes, queuePostcatPath, arguments...)
	if err != nil {
		wipeQueueCommandResult(&result)
		return QueueBackendBody{}, err
	}
	if result.Overflow {
		wipeQueueCommandResult(&result)
		return QueueBackendBody{}, ErrRateLimited
	}
	if result.ExitCode != 0 {
		notFound := exactQueueNotFound(id, result.Stdout, result.Stderr)
		wipeQueueCommandResult(&result)
		if notFound {
			return QueueBackendBody{}, ErrNotFound
		}
		return QueueBackendBody{}, ErrAmbiguous
	}
	wipeQueueBytes(result.Stderr)
	result.Stderr = nil
	digest := sha256.Sum256(result.Stdout)
	return QueueBackendBody{QueueID: id, Content: result.Stdout, ContentDigest: hex.EncodeToString(digest[:]), ObservedAt: result.ObservedAt}, nil
}

func (backend *LinuxQueueAdminBackend) Apply(ctx context.Context, action QueueAdminAction, id QueueID) (QueueBackendActionResult, error) {
	result := QueueBackendActionResult{QueueID: id, Outcome: QueueActionAmbiguous}
	if backend == nil || backend.Now == nil || ctx == nil || !validQueueAdminAction(action) || !validQueueAdminID(id) {
		return result, ErrInvalidCommand
	}
	executable := queuePostsuperPath
	arguments := []string{"", string(id)}
	switch action {
	case QueueAdminRetry:
		executable = queuePostqueuePath
		arguments[0] = "-i"
	case QueueAdminHold:
		arguments[0] = "-h"
	case QueueAdminRelease:
		arguments[0] = "-H"
	case QueueAdminDelete:
		arguments[0] = "-d"
	default:
		return result, ErrInvalidCommand
	}
	command, err := backend.run(ctx, 15*time.Second, queueStderrBytes, queueStderrBytes, executable, arguments...)
	if err != nil {
		wipeQueueCommandResult(&command)
		result.EvidenceDigest = emptyQueueEvidenceDigest()
		result.ObservedAt = backend.now()
		return result, err
	}
	defer wipeQueueCommandResult(&command)
	result.EvidenceDigest = queueCommandDigest(executable, arguments, command)
	result.ObservedAt = command.ObservedAt
	if command.Overflow {
		return result, ErrAmbiguous
	}
	result.Outcome = classifyQueueAction(action, id, command.ExitCode, command.Stdout, command.Stderr)
	if result.Outcome == QueueActionAmbiguous {
		return result, ErrAmbiguous
	}
	return result, nil
}

func (backend *LinuxQueueAdminBackend) Flush(ctx context.Context) (QueueBackendActionResult, error) {
	result := QueueBackendActionResult{Outcome: QueueActionAmbiguous}
	if backend == nil || backend.Now == nil || ctx == nil {
		return result, ErrInvalidCommand
	}
	arguments := []string{"-f"}
	command, err := backend.run(ctx, 30*time.Second, queueStderrBytes, queueStderrBytes, queuePostqueuePath, arguments...)
	if err != nil {
		wipeQueueCommandResult(&command)
		result.EvidenceDigest = emptyQueueEvidenceDigest()
		result.ObservedAt = backend.now()
		return result, err
	}
	defer wipeQueueCommandResult(&command)
	result.EvidenceDigest = queueCommandDigest(queuePostqueuePath, arguments, command)
	result.ObservedAt = command.ObservedAt
	if command.Overflow || command.ExitCode != 0 {
		return result, ErrAmbiguous
	}
	result.Outcome = QueueActionApplied
	return result, nil
}

type queueCommandResult struct {
	Stdout     []byte
	Stderr     []byte
	ExitCode   int
	Overflow   bool
	ObservedAt time.Time
}

type queueBoundedWriter struct {
	Buffer   bytes.Buffer
	Limit    int
	Overflow bool
}

func (writer *queueBoundedWriter) Write(content []byte) (int, error) {
	original := len(content)
	remaining := writer.Limit - writer.Buffer.Len()
	if remaining <= 0 {
		writer.Overflow = writer.Overflow || len(content) != 0
		return original, nil
	}
	if len(content) > remaining {
		content = content[:remaining]
		writer.Overflow = true
	}
	_, _ = writer.Buffer.Write(content)
	return original, nil
}

func (backend *LinuxQueueAdminBackend) run(ctx context.Context, timeout time.Duration, stdoutLimit, stderrLimit int, executable string, arguments ...string) (queueCommandResult, error) {
	result := queueCommandResult{ExitCode: -1, ObservedAt: backend.now()}
	if ctx == nil || timeout <= 0 || timeout > 30*time.Second || stdoutLimit <= 0 || stdoutLimit > queueSnapshotBytes || stderrLimit <= 0 || stderrLimit > queueSnapshotBytes || !fixedQueueCommand(executable, arguments) {
		return result, ErrInvalidCommand
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout := &queueBoundedWriter{Limit: stdoutLimit}
	stderr := &queueBoundedWriter{Limit: stderrLimit}
	command := exec.CommandContext(commandContext, executable, arguments...)
	command.Env = []string{"HOME=/", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/bin", "TZ=UTC"}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	result.Stdout = stdout.Buffer.Bytes()
	result.Stderr = stderr.Buffer.Bytes()
	result.Overflow = stdout.Overflow || stderr.Overflow
	result.ObservedAt = backend.now()
	if err == nil {
		result.ExitCode = 0
		return result, nil
	}
	if commandContext.Err() != nil {
		return result, commandContext.Err()
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	return result, ErrAmbiguous
}

func (backend *LinuxQueueAdminBackend) now() time.Time {
	return backend.Now().UTC().Truncate(time.Second)
}

func fixedQueueCommand(executable string, arguments []string) bool {
	switch executable {
	case queuePostqueuePath:
		if len(arguments) == 1 {
			return arguments[0] == "-j" || arguments[0] == "-f"
		}
		return len(arguments) == 2 && arguments[0] == "-i" && validQueueAdminID(QueueID(arguments[1]))
	case queuePostcatPath:
		return len(arguments) == 3 && arguments[0] == "-q" && (arguments[1] == "-h" || arguments[1] == "-b") && validQueueAdminID(QueueID(arguments[2]))
	case queuePostsuperPath:
		return len(arguments) == 2 && (arguments[0] == "-h" || arguments[0] == "-H" || arguments[0] == "-d") && validQueueAdminID(QueueID(arguments[1]))
	default:
		return false
	}
}

func parsePostqueueJSON(content []byte) ([]QueueBackendRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	records := make([]QueueBackendRecord, 0)
	totalRecipients := 0
	for {
		var raw struct {
			QueueName  *string      `json:"queue_name"`
			QueueID    *string      `json:"queue_id"`
			ArrivalTime *json.Number `json:"arrival_time"`
			MessageSize *json.Number `json:"message_size"`
			Sender      *string      `json:"sender"`
			Recipients  *[]struct {
				Address     *string `json:"address"`
				DelayReason string  `json:"delay_reason"`
			} `json:"recipients"`
		}
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || raw.QueueName == nil || raw.QueueID == nil || raw.ArrivalTime == nil || raw.MessageSize == nil || raw.Sender == nil || raw.Recipients == nil || len(*raw.Recipients) == 0 {
			return nil, ErrInvalidReceipt
		}
		if len(records) >= int(QueueAdminMaximumBackendRecords) {
			return nil, ErrRateLimited
		}
		arrival, err := strconv.ParseInt(raw.ArrivalTime.String(), 10, 64)
		if err != nil || arrival <= 0 {
			return nil, ErrInvalidReceipt
		}
		size, err := strconv.ParseUint(raw.MessageSize.String(), 10, 64)
		if err != nil || size > queueAdminMaximumMessageBytes || !validQueueName(*raw.QueueName) || !validQueueAdminID(QueueID(*raw.QueueID)) {
			return nil, ErrInvalidReceipt
		}
		sender := Address(strings.ToLower(strings.TrimSpace(*raw.Sender)))
		if sender == "" {
			sender = "<>"
		}
		if !canonicalQueueAddress(sender, true) {
			return nil, ErrInvalidReceipt
		}
		record := QueueBackendRecord{QueueID: QueueID(*raw.QueueID), QueueName: *raw.QueueName, Sender: sender, MessageBytes: size, ArrivedAt: time.Unix(arrival, 0).UTC()}
		for _, rawRecipient := range *raw.Recipients {
			if rawRecipient.Address == nil || len(rawRecipient.DelayReason) > 4096 || strings.ContainsRune(rawRecipient.DelayReason, '\x00') {
				return nil, ErrInvalidReceipt
			}
			address := Address(strings.ToLower(strings.TrimSpace(*rawRecipient.Address)))
			if !canonicalQueueAddress(address, false) {
				return nil, ErrInvalidReceipt
			}
			record.Recipients = append(record.Recipients, QueueBackendRecipient{Address: address, DelayReason: rawRecipient.DelayReason})
			totalRecipients++
			if totalRecipients > queueMaximumParsedRecipients {
				return nil, ErrRateLimited
			}
		}
		records = append(records, record)
	}
	return records, nil
}

func parseRedactedPostcatHeaders(content []byte) ([]QueueHeaderProjection, error) {
	lines := bytes.Split(bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n")), []byte("\n"))
	headers := make([]QueueHeaderProjection, 0)
	started := false
	for _, line := range lines {
		if len(line) > 16<<10 {
			return nil, ErrInvalidReceipt
		}
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("***")) {
			if started && bytes.Contains(trimmed, []byte("MESSAGE FILE END")) {
				break
			}
			continue
		}
		if len(trimmed) == 0 {
			if started {
				break
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if !started {
				return nil, ErrInvalidReceipt
			}
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			if started {
				return nil, ErrInvalidReceipt
			}
			continue
		}
		name := string(line[:colon])
		if !validQueueHeaderName(name) {
			return nil, ErrInvalidReceipt
		}
		headers = append(headers, QueueHeaderProjection{Name: name, ValueClass: "redacted"})
		started = true
		if len(headers) > int(QueueAdminMaximumRecipients) {
			return nil, ErrRateLimited
		}
	}
	return headers, nil
}

func classifyQueueAction(action QueueAdminAction, id QueueID, exitCode int, stdout, stderr []byte) QueueActionOutcome {
	if exactQueueNotFound(id, stdout, stderr) {
		return QueueActionNotFound
	}
	if exitCode == 0 {
		if action == QueueAdminHold && exactQueueLine(stdout, stderr, "postsuper: "+string(id)+": already on hold") || action == QueueAdminRelease && exactQueueLine(stdout, stderr, "postsuper: "+string(id)+": not on hold") {
			return QueueActionAlreadySatisfied
		}
		return QueueActionApplied
	}
	return QueueActionAmbiguous
}

func exactQueueNotFound(id QueueID, outputs ...[]byte) bool {
	known := []string{
		"postsuper: " + string(id) + ": not found",
		"postqueue: fatal: Queue ID " + string(id) + " not found",
		"postqueue: fatal: " + string(id) + ": queue file not found",
		"postcat: fatal: " + string(id) + ": queue file not found",
	}
	for _, output := range outputs {
		for _, line := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
			line = strings.TrimSpace(line)
			for _, expected := range known {
				if line == expected {
					return true
				}
			}
		}
	}
	return false
}

func exactQueueLine(stdout, stderr []byte, expected string) bool {
	for _, output := range [][]byte{stdout, stderr} {
		for _, line := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
			if strings.TrimSpace(line) == expected {
				return true
			}
		}
	}
	return false
}

func queueCommandDigest(executable string, arguments []string, result queueCommandResult) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("mail-queue-command-v1\x00"))
	_, _ = digest.Write([]byte(executable))
	for _, argument := range arguments {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(argument))
	}
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(result.Stdout)
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(result.Stderr)
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(strconv.Itoa(result.ExitCode)))
	return hex.EncodeToString(digest.Sum(nil))
}

func wipeQueueCommandResult(result *queueCommandResult) {
	if result == nil {
		return
	}
	wipeQueueBytes(result.Stdout)
	wipeQueueBytes(result.Stderr)
	result.Stdout = nil
	result.Stderr = nil
}
