package sshactivity

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
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	sshJournalctlPath     = "/usr/bin/journalctl"
	sshLoginctlPath       = "/usr/bin/loginctl"
	sshJournalSource      = SourceID("openssh-journal")
	sshLoginSource        = SourceID("logind-sessions")
	maximumCommandStderr  = 16 << 10
	maximumLoginctlOutput = 256 << 10
	maximumProcBytes      = 64 << 10
	sshCursorLifetime     = 30 * time.Minute
)

var authenticationLine = regexp.MustCompile(`^(Accepted|Failed) (publickey|password|keyboard-interactive(?:/pam)?|hostbased) for (?:invalid user )?([A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}) from ([^ ]+) port ([0-9]{1,5})(?: ssh2(?:: ([A-Za-z0-9@._+-]+) (SHA256:[A-Za-z0-9+/]{16,96}={0,2}))?)?(?: |$)`)
var invalidUserLine = regexp.MustCompile(`^Invalid user ([A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}) from ([^ ]+) port ([0-9]{1,5})(?: |$)`)

type boundedWriter struct {
	data  []byte
	limit int
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	remaining := writer.limit - len(writer.data)
	if remaining > 0 {
		if len(value) < remaining {
			remaining = len(value)
		}
		writer.data = append(writer.data, value[:remaining]...)
	}
	return len(value), nil
}

type LinuxObserver struct {
	resolver   IdentityResolver
	authorizer ObservationAuthorizer
	cursors    *CursorCodec
	now        func() time.Time
}

func NewLinuxObserver(resolver IdentityResolver, authorizer ObservationAuthorizer, cursors *CursorCodec) (*LinuxObserver, error) {
	if resolver == nil || authorizer == nil || cursors == nil {
		return nil, ErrInvalid
	}
	return &LinuxObserver{resolver: resolver, authorizer: authorizer, cursors: cursors, now: time.Now}, nil
}

type journalAuthentication struct {
	Cursor     string `json:"__CURSOR"`
	Realtime   string `json:"__REALTIME_TIMESTAMP"`
	BootID     string `json:"_BOOT_ID"`
	PID        string `json:"_PID"`
	Identifier string `json:"SYSLOG_IDENTIFIER"`
	Message    string `json:"MESSAGE"`
}

type parsedAuthentication struct {
	outcome     AuthenticationOutcome
	method      AuthenticationMethod
	user        string
	source      SourceIdentity
	algorithm   string
	fingerprint string
}

func normalizeRemoteAddress(value string) (netip.Addr, error) {
	value = strings.Trim(value, "[]")
	if percent := strings.LastIndexByte(value, '%'); percent >= 0 {
		value = value[:percent]
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.IsValid() || address.IsUnspecified() {
		return netip.Addr{}, ErrInvalid
	}
	return address.Unmap(), nil
}

func parseAuthenticationMessage(message string) (parsedAuthentication, bool) {
	if message == "" || len(message) > MaximumRecordBytes || strings.ContainsRune(message, '\x00') {
		return parsedAuthentication{}, false
	}
	if matches := authenticationLine.FindStringSubmatch(message); matches != nil {
		address, err := normalizeRemoteAddress(matches[4])
		port, portErr := strconv.ParseUint(matches[5], 10, 16)
		if err != nil || portErr != nil || port == 0 {
			return parsedAuthentication{}, false
		}
		outcome := OutcomeFailed
		if matches[1] == "Accepted" {
			outcome = OutcomeSucceeded
		}
		method := MethodUnknown
		switch matches[2] {
		case "publickey":
			method = MethodPublicKey
		case "password":
			method = MethodPassword
		case "keyboard-interactive", "keyboard-interactive/pam":
			method = MethodKeyboardInteractive
		case "hostbased":
			method = MethodHostBased
		}
		algorithm, fingerprint := matches[6], matches[7]
		if method == MethodPublicKey {
			if algorithm == "" || fingerprint == "" {
				return parsedAuthentication{}, false
			}
			if strings.Contains(strings.ToLower(algorithm), "cert") {
				method = MethodCertificate
			}
		}
		return parsedAuthentication{outcome: outcome, method: method, user: matches[3], source: SourceIdentity{Address: address, Port: uint16(port)}, algorithm: algorithm, fingerprint: fingerprint}, true
	}
	if matches := invalidUserLine.FindStringSubmatch(message); matches != nil {
		address, err := normalizeRemoteAddress(matches[2])
		port, portErr := strconv.ParseUint(matches[3], 10, 16)
		if err != nil || portErr != nil || port == 0 {
			return parsedAuthentication{}, false
		}
		return parsedAuthentication{outcome: OutcomeFailed, method: MethodUnknown, user: matches[1], source: SourceIdentity{Address: address, Port: uint16(port)}}, true
	}
	return parsedAuthentication{}, false
}

func looksLikeAuthentication(message string) bool {
	return strings.HasPrefix(message, "Accepted ") || strings.HasPrefix(message, "Failed ") || strings.HasPrefix(message, "Invalid user ")
}

func parseJournalTime(value string) (time.Time, error) {
	microseconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || microseconds <= 0 || microseconds > math.MaxInt64/int64(time.Microsecond) {
		return time.Time{}, ErrIntegrity
	}
	return time.UnixMicro(microseconds).UTC(), nil
}

func unknownUser(name string) UserIdentity {
	return UserIdentity{ID: UserID("user-" + digestParts(name)[:24]), Name: name}
}

func unknownKey(algorithm, fingerprint string) KeyIdentity {
	return KeyIdentity{ID: KeyID("key-" + digestParts(algorithm, fingerprint)[:24]), Algorithm: algorithm, Fingerprint: fingerprint}
}

func (observer *LinuxObserver) resolveIdentities(ctx context.Context, parsed parsedAuthentication, at time.Time) (UserIdentity, *KeyIdentity, AssuranceIdentity, bool, error) {
	partial := false
	user, err := observer.resolver.ResolveSSHUser(ctx, parsed.user, at)
	if errors.Is(err, ErrNotFound) {
		user, err, partial = unknownUser(parsed.user), nil, true
	}
	if err != nil || !user.valid() {
		return UserIdentity{}, nil, AssuranceIdentity{}, true, ErrIntegrity
	}
	var key *KeyIdentity
	if parsed.method == MethodPublicKey || parsed.method == MethodCertificate {
		resolved, keyErr := observer.resolver.ResolveSSHKey(ctx, parsed.algorithm, parsed.fingerprint, at)
		if errors.Is(keyErr, ErrNotFound) {
			resolved, keyErr, partial = unknownKey(parsed.algorithm, parsed.fingerprint), nil, true
		}
		if keyErr != nil || !resolved.valid() {
			return UserIdentity{}, nil, AssuranceIdentity{}, true, ErrIntegrity
		}
		key = &resolved
	}
	assurance, assuranceErr := observer.resolver.ClassifySSHAssurance(ctx, user, key, parsed.method, at)
	if assuranceErr != nil {
		assurance = AssuranceIdentity{Level: AssuranceUnknown, ClassifiedAt: at}
		partial = true
	}
	if !assurance.valid() {
		return UserIdentity{}, nil, AssuranceIdentity{}, true, ErrIntegrity
	}
	return user, key, assurance, partial, nil
}

func journalArguments(query AuthenticationQuery, cursor CursorState) []string {
	arguments := []string{
		"--no-pager", "--quiet", "--output=json",
		"--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_PID,SYSLOG_IDENTIFIER,MESSAGE",
		"--since=" + query.Start.UTC().Format(time.RFC3339Nano), "--until=" + query.End.UTC().Format(time.RFC3339Nano),
		"--unit=sshd.service", "--unit=ssh.service",
	}
	if query.Cursor != "" {
		arguments = append(arguments, "--after-cursor="+cursor.JournalCursor)
	}
	return arguments
}

func (observer *LinuxObserver) QueryAuthentication(ctx context.Context, actor Actor, query AuthenticationQuery, sink AuthenticationSink) (AuthenticationSummary, error) {
	if observer == nil || ctx == nil || sink == nil || !actor.valid() || query.Validate() != nil {
		return AuthenticationSummary{}, ErrInvalid
	}
	if observer.authorizer.AuthorizeSSHAuthenticationQuery(ctx, actor, query) != nil {
		return AuthenticationSummary{}, ErrUnauthorized
	}
	queryDigest, err := authenticationQueryDigest(query)
	if err != nil {
		return AuthenticationSummary{}, err
	}
	var cursor CursorState
	if query.Cursor != "" {
		cursor, err = observer.cursors.Decode(ctx, query.Cursor)
		if err != nil || cursor.SourceID != sshJournalSource || cursor.QueryDigest != queryDigest {
			return AuthenticationSummary{}, ErrIntegrity
		}
	}
	boundedContext, cancel := context.WithTimeout(ctx, query.Duration)
	defer cancel()
	processContext, stopProcess := context.WithCancel(boundedContext)
	defer stopProcess()
	command := exec.CommandContext(processContext, sshJournalctlPath, journalArguments(query, cursor)...)
	command.Dir = "/"
	command.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin", "SYSTEMD_PAGER=cat", "PAGER=cat"}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return AuthenticationSummary{}, err
	}
	stderr := &boundedWriter{limit: maximumCommandStderr}
	command.Stderr = stderr
	if err = command.Start(); err != nil {
		return AuthenticationSummary{}, err
	}
	summary := AuthenticationSummary{NextCursor: query.Cursor}
	rejectedDigests := make([]string, 0, 32)
	identityGaps := uint32(0)
	clockGaps := uint32(0)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 16<<10), MaximumRecordBytes)
	for scanner.Scan() {
		raw := append([]byte(nil), scanner.Bytes()...)
		if summary.Scanned == query.ScanLimit || summary.Bytes+int64(len(raw)) > query.MaximumBytes {
			summary.Truncated = true
			stopProcess()
			break
		}
		summary.Scanned++
		summary.Bytes += int64(len(raw))
		recordDigestBytes := sha256.Sum256(raw)
		recordDigest := hex.EncodeToString(recordDigestBytes[:])
		var entry journalAuthentication
		decoded := strictJSON(raw, MaximumRecordBytes, &entry) == nil
		boot := BootIdentity{BootID: entry.BootID}
		previousCursor := summary.NextCursor
		eventCursor := ""
		if decoded && validJournalCursor(entry.Cursor) && boot.valid() {
			state := CursorState{SourceID: sshJournalSource, Boot: boot, JournalCursor: entry.Cursor, QueryDigest: queryDigest}
			eventCursor, err = observer.cursors.Encode(boundedContext, state, sshCursorLifetime)
			if err != nil {
				stopProcess()
				break
			}
			summary.NextCursor = eventCursor
		}
		parsed, parsedOK := parsedAuthentication{}, false
		if decoded && (entry.Identifier == "sshd" || entry.Identifier == "ssh" || entry.Identifier == "sshd-session") {
			parsed, parsedOK = parseAuthenticationMessage(entry.Message)
		}
		at, timeErr := parseJournalTime(entry.Realtime)
		if !parsedOK || timeErr != nil || !boot.valid() || eventCursor == "" {
			if !looksLikeAuthentication(entry.Message) && decoded && validJournalCursor(entry.Cursor) && boot.valid() {
				continue
			}
			summary.Rejected++
			if len(rejectedDigests) < 128 {
				rejectedDigests = append(rejectedDigests, recordDigest)
			}
			continue
		}
		if query.Source != nil && !query.Source.Contains(parsed.source.Address) || query.UserName != "" && query.UserName != parsed.user || query.Outcome != "" && query.Outcome != parsed.outcome {
			continue
		}
		user, key, assurance, partial, identityErr := observer.resolveIdentities(boundedContext, parsed, at)
		if identityErr != nil {
			summary.Rejected++
			identityGaps++
			continue
		}
		var process *ProcessIdentity
		if pid, pidErr := strconv.ParseUint(entry.PID, 10, 32); pidErr == nil && pid > 1 {
			if identity, identityErr := readProcessIdentity(uint32(pid), boot); identityErr == nil {
				process = &identity
			}
		}
		completeness := EvidenceComplete
		if partial {
			completeness = EvidencePartial
			identityGaps++
		}
		observedAt := observer.now().UTC()
		if at.After(observedAt.Add(time.Minute)) {
			summary.Rejected++
			clockGaps++
			continue
		}
		event := AuthenticationEvent{
			ID: EventID("event-" + digestParts(entry.Cursor, recordDigest)[:24]), Cursor: eventCursor, At: at, Outcome: parsed.outcome,
			Source: parsed.source, User: user, Key: key, Method: parsed.method, Assurance: assurance, Process: process, Boot: boot,
			Evidence: EvidenceIntegrity{SourceID: sshJournalSource, SourceDigest: digestParts(string(sshJournalSource), boot.BootID), RecordDigest: recordDigest, Parser: "openssh-v1", Completeness: completeness, ObservedAt: observedAt},
		}
		if !event.valid() {
			summary.Rejected++
			continue
		}
		if summary.Events == query.Limit {
			summary.NextCursor = previousCursor
			summary.Truncated = true
			stopProcess()
			break
		}
		if err = sink.WriteAuthenticationEvent(boundedContext, event); err != nil {
			stopProcess()
			break
		}
		summary.Events++
		summary.NextCursor = eventCursor
	}
	if scanErr := scanner.Err(); scanErr != nil && err == nil && !summary.Truncated {
		err = scanErr
	}
	waitErr := command.Wait()
	if err == nil && boundedContext.Err() != nil && ctx.Err() == nil {
		summary.Truncated = true
	} else if err == nil && waitErr != nil && !summary.Truncated {
		failure := strings.ToLower(string(stderr.data))
		if query.Cursor != "" && strings.Contains(failure, "cursor") {
			gap := ObservationGap{Code: GapRotated, SourceID: sshJournalSource, Count: 1, EvidenceDigest: digestParts(string(stderr.data))}
			if gapErr := sink.WriteObservationGap(ctx, gap); gapErr != nil {
				err = gapErr
			} else {
				err = ErrConflict
			}
		} else {
			err = fmt.Errorf("ssh journal observation: %w", ErrIntegrity)
		}
	}
	if summary.Truncated {
		gap := ObservationGap{Code: GapTruncated, SourceID: sshJournalSource, Count: 1, EvidenceDigest: digestParts(summary.NextCursor, strconv.FormatUint(uint64(summary.Scanned), 10))}
		if gapErr := sink.WriteObservationGap(ctx, gap); err == nil && gapErr != nil {
			err = gapErr
		}
	}
	if summary.Rejected > 0 {
		gap := ObservationGap{Code: GapParserRejected, SourceID: sshJournalSource, Count: summary.Rejected, EvidenceDigest: digestParts(rejectedDigests...)}
		if gapErr := sink.WriteObservationGap(ctx, gap); err == nil && gapErr != nil {
			err = gapErr
		}
	}
	if identityGaps > 0 {
		gap := ObservationGap{Code: GapIdentityUnknown, SourceID: sshJournalSource, Count: identityGaps, EvidenceDigest: digestParts(queryDigest, strconv.FormatUint(uint64(identityGaps), 10))}
		if gapErr := sink.WriteObservationGap(ctx, gap); err == nil && gapErr != nil {
			err = gapErr
		}
	}
	if clockGaps > 0 {
		gap := ObservationGap{Code: GapClockUncertain, SourceID: sshJournalSource, Count: clockGaps, EvidenceDigest: digestParts(queryDigest, strconv.FormatUint(uint64(clockGaps), 10))}
		if gapErr := sink.WriteObservationGap(ctx, gap); err == nil && gapErr != nil {
			err = gapErr
		}
	}
	closeErr := sink.CloseAuthenticationQuery(ctx, summary)
	if err != nil {
		return summary, err
	}
	if closeErr != nil {
		return summary, closeErr
	}
	return summary, nil
}

func runBoundedCommand(ctx context.Context, path string, maximum int64, arguments ...string) ([]byte, bool, error) {
	if ctx == nil || path == "" || maximum <= 0 || maximum > MaximumQueryBytes {
		return nil, false, ErrInvalid
	}
	commandContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(commandContext, path, arguments...)
	command.Dir = "/"
	command.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin", "SYSTEMD_PAGER=cat", "PAGER=cat"}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	stderr := &boundedWriter{limit: maximumCommandStderr}
	command.Stderr = stderr
	if err = command.Start(); err != nil {
		return nil, false, err
	}
	output, readErr := io.ReadAll(io.LimitReader(stdout, maximum+1))
	truncated := int64(len(output)) > maximum
	if truncated {
		output = output[:maximum]
		cancel()
	}
	waitErr := command.Wait()
	if readErr != nil {
		return nil, false, readErr
	}
	if truncated {
		return output, true, nil
	}
	if waitErr != nil {
		return output, truncated, fmt.Errorf("fixed observation command: %w", ErrIntegrity)
	}
	return output, truncated, nil
}

func parseProperties(output []byte, allowed map[string]struct{}) (map[string]string, error) {
	if len(output) == 0 || len(output) > maximumLoginctlOutput || bytes.IndexByte(output, 0) >= 0 {
		return nil, ErrIntegrity
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, ErrIntegrity
		}
		if _, ok := allowed[parts[0]]; !ok {
			return nil, ErrIntegrity
		}
		if _, duplicate := values[parts[0]]; duplicate || len(parts[1]) > 4<<10 {
			return nil, ErrIntegrity
		}
		values[parts[0]] = parts[1]
	}
	return values, nil
}

func readProcFile(path string, maximum int64) ([]byte, error) {
	if maximum <= 0 || maximum > maximumProcBytes || !strings.HasPrefix(path, "/proc/") || strings.Contains(path, "..") {
		return nil, ErrInvalid
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "proc-evidence")
	if file == nil {
		syscall.Close(fd)
		return nil, ErrIntegrity
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, ErrIntegrity
	}
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > maximum {
		return nil, ErrLimit
	}
	return value, nil
}

func currentBootIdentity() (BootIdentity, error) {
	value, err := readProcFile("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return BootIdentity{}, err
	}
	identity := BootIdentity{BootID: strings.TrimSpace(string(value))}
	if !identity.valid() {
		return BootIdentity{}, ErrIntegrity
	}
	return identity, nil
}

func parseProcStat(value []byte) (uint32, uint64, string, error) {
	if len(value) == 0 || len(value) > maximumProcBytes || bytes.IndexByte(value, 0) >= 0 {
		return 0, 0, "", ErrIntegrity
	}
	left := bytes.IndexByte(value, '(')
	right := bytes.LastIndexByte(value, ')')
	if left <= 0 || right <= left || right+2 >= len(value) {
		return 0, 0, "", ErrIntegrity
	}
	command := string(value[left+1 : right])
	fields := strings.Fields(string(value[right+2:]))
	if len(fields) <= 19 || len(command) == 0 || len(command) > 128 {
		return 0, 0, "", ErrIntegrity
	}
	parent, parentErr := strconv.ParseUint(fields[1], 10, 32)
	started, startErr := strconv.ParseUint(fields[19], 10, 64)
	if parentErr != nil || startErr != nil || parent == 0 || started == 0 {
		return 0, 0, "", ErrIntegrity
	}
	return uint32(parent), started, command, nil
}

func readProcessIdentity(pid uint32, boot BootIdentity) (ProcessIdentity, error) {
	if pid <= 1 || !boot.valid() {
		return ProcessIdentity{}, ErrInvalid
	}
	current, err := currentBootIdentity()
	if err != nil || current != boot {
		return ProcessIdentity{}, ErrConflict
	}
	stat, err := readProcFile("/proc/"+strconv.FormatUint(uint64(pid), 10)+"/stat", maximumProcBytes)
	if err != nil {
		return ProcessIdentity{}, err
	}
	_, started, _, err := parseProcStat(stat)
	if err != nil {
		return ProcessIdentity{}, err
	}
	return ProcessIdentity{PID: pid, StartTimeTicks: started, Boot: boot}, nil
}

func readProcessSnapshot(pid uint32, boot BootIdentity) (ProcessSnapshot, error) {
	identity, err := readProcessIdentity(pid, boot)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	pidText := strconv.FormatUint(uint64(pid), 10)
	stat, err := readProcFile("/proc/"+pidText+"/stat", maximumProcBytes)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	parent, started, command, err := parseProcStat(stat)
	if err != nil || started != identity.StartTimeTicks {
		return ProcessSnapshot{}, ErrConflict
	}
	status, err := readProcFile("/proc/"+pidText+"/status", maximumProcBytes)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	var effectiveUID uint64
	uidFound := false
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 5 {
			return ProcessSnapshot{}, ErrIntegrity
		}
		effectiveUID, err = strconv.ParseUint(fields[2], 10, 32)
		uidFound = err == nil
		break
	}
	if !uidFound {
		return ProcessSnapshot{}, ErrIntegrity
	}
	arguments, argumentsErr := readProcFile("/proc/"+pidText+"/cmdline", 16<<10)
	argumentsDigest := ""
	if argumentsErr == nil {
		digest := sha256.Sum256(arguments)
		argumentsDigest = hex.EncodeToString(digest[:])
	}
	snapshot := ProcessSnapshot{Identity: identity, ParentPID: parent, EffectiveUID: uint32(effectiveUID), Command: command, ArgumentsDigest: argumentsDigest}
	if !snapshot.valid() {
		return ProcessSnapshot{}, ErrIntegrity
	}
	return snapshot, nil
}

func DigestProcessSnapshot(snapshot ProcessSnapshot) (string, error) {
	if !snapshot.valid() {
		return "", ErrInvalid
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > MaximumMetadataJSON {
		return "", ErrLimit
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

var sessionProperties = map[string]struct{}{
	"Id": {}, "Name": {}, "Remote": {}, "RemoteHost": {}, "Service": {}, "Type": {}, "Class": {}, "Leader": {},
	"TimestampUSec": {}, "IdleSinceHintUSec": {}, "State": {}, "TTY": {},
}

func parseMicroseconds(value string) (time.Time, error) {
	microseconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || microseconds <= 0 || microseconds > math.MaxInt64/int64(time.Microsecond) {
		return time.Time{}, ErrIntegrity
	}
	return time.UnixMicro(microseconds).UTC(), nil
}

func (observer *LinuxObserver) observeSession(ctx context.Context, rawID string, boot BootIdentity) (ActiveSession, error) {
	if _, err := strconv.ParseUint(rawID, 10, 32); err != nil || len(rawID) > 20 {
		return ActiveSession{}, ErrInvalid
	}
	arguments := []string{"show-session", rawID, "--no-pager"}
	for _, property := range []string{"Id", "Name", "Remote", "RemoteHost", "Service", "Type", "Class", "Leader", "TimestampUSec", "IdleSinceHintUSec", "State", "TTY"} {
		arguments = append(arguments, "--property="+property)
	}
	output, truncated, err := runBoundedCommand(ctx, sshLoginctlPath, maximumLoginctlOutput, arguments...)
	if err != nil || truncated {
		return ActiveSession{}, ErrIntegrity
	}
	values, err := parseProperties(output, sessionProperties)
	if err != nil || values["Id"] != rawID || values["Remote"] != "yes" || values["RemoteHost"] == "" || values["Name"] == "" || values["State"] == "" || values["Service"] != "sshd" && values["Service"] != "ssh" {
		return ActiveSession{}, ErrInvalid
	}
	address, err := normalizeRemoteAddress(values["RemoteHost"])
	if err != nil {
		return ActiveSession{}, err
	}
	started, err := parseMicroseconds(values["TimestampUSec"])
	if err != nil {
		return ActiveSession{}, err
	}
	lastActivity, idleErr := parseMicroseconds(values["IdleSinceHintUSec"])
	if idleErr != nil || lastActivity.Before(started) {
		lastActivity = started
	}
	user, err := observer.resolver.ResolveSSHUser(ctx, values["Name"], started)
	if err != nil || !user.valid() {
		return ActiveSession{}, ErrIntegrity
	}
	leaderPID, leaderErr := strconv.ParseUint(values["Leader"], 10, 32)
	var leader *ProcessSnapshot
	var leaderIdentity *ProcessIdentity
	if leaderErr == nil && leaderPID > 1 {
		if snapshot, snapshotErr := readProcessSnapshot(uint32(leaderPID), boot); snapshotErr == nil {
			leader = &snapshot
			identity := snapshot.Identity
			leaderIdentity = &identity
		}
	}
	digest := sha256.Sum256(output)
	observedAt := observer.now().UTC()
	session := ActiveSession{
		Identity: SessionIdentity{ID: SessionID("logind-" + rawID), Boot: boot, StartedAt: started, Leader: leaderIdentity},
		User: user, Source: SourceIdentity{Address: address}, TTY: values["TTY"], State: values["State"], LastActivityAt: lastActivity, Leader: leader,
		Evidence: EvidenceIntegrity{SourceID: sshLoginSource, SourceDigest: digestParts(string(sshLoginSource), boot.BootID), RecordDigest: hex.EncodeToString(digest[:]), Parser: "logind-v1", Completeness: EvidenceComplete, ObservedAt: observedAt},
	}
	if leader == nil {
		session.Evidence.Completeness = EvidencePartial
	}
	if !session.valid() {
		return ActiveSession{}, ErrIntegrity
	}
	return session, nil
}

func (observer *LinuxObserver) QuerySessions(ctx context.Context, actor Actor, query SessionQuery, sink SessionSink) (SessionSummary, error) {
	if observer == nil || ctx == nil || sink == nil || !actor.valid() || query.Validate() != nil {
		return SessionSummary{}, ErrInvalid
	}
	if observer.authorizer.AuthorizeSSHSessionQuery(ctx, actor, query) != nil {
		return SessionSummary{}, ErrUnauthorized
	}
	boundedContext, cancel := context.WithTimeout(ctx, query.Duration)
	defer cancel()
	boot, err := currentBootIdentity()
	if err != nil {
		return SessionSummary{}, err
	}
	output, truncated, err := runBoundedCommand(boundedContext, sshLoginctlPath, maximumLoginctlOutput, "list-sessions", "--no-legend", "--no-pager")
	if err != nil {
		return SessionSummary{}, err
	}
	summary := SessionSummary{Truncated: truncated}
	rejected := uint32(0)
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || len(fields) > 8 {
			rejected++
			continue
		}
		if summary.Scanned == query.Limit {
			summary.Truncated = true
			break
		}
		summary.Scanned++
		session, sessionErr := observer.observeSession(boundedContext, fields[0], boot)
		if errors.Is(sessionErr, ErrInvalid) {
			continue
		}
		if sessionErr != nil {
			rejected++
			continue
		}
		if err = sink.WriteActiveSession(boundedContext, session); err != nil {
			break
		}
		summary.Sessions++
	}
	if summary.Truncated {
		gap := ObservationGap{Code: GapTruncated, SourceID: sshLoginSource, Count: 1, EvidenceDigest: digestParts(boot.BootID, strconv.FormatUint(uint64(summary.Scanned), 10))}
		if gapErr := sink.WriteObservationGap(ctx, gap); err == nil && gapErr != nil {
			err = gapErr
		}
	}
	if rejected > 0 {
		gap := ObservationGap{Code: GapParserRejected, SourceID: sshLoginSource, Count: rejected, EvidenceDigest: digestParts(boot.BootID, strconv.FormatUint(uint64(rejected), 10))}
		if gapErr := sink.WriteObservationGap(ctx, gap); err == nil && gapErr != nil {
			err = gapErr
		}
	}
	closeErr := sink.CloseSessionQuery(ctx, summary)
	if err != nil {
		return summary, err
	}
	if closeErr != nil {
		return summary, closeErr
	}
	return summary, nil
}

const (
	syscallPIDFDOpen       = 434
	syscallPIDFDSendSignal = 424
)

type LinuxProcessController struct{}

func NewLinuxProcessController() *LinuxProcessController { return &LinuxProcessController{} }

func pidfdSignal(pidfd int, signal syscall.Signal) error {
	_, _, errno := syscall.Syscall6(syscallPIDFDSendSignal, uintptr(pidfd), uintptr(signal), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (controller *LinuxProcessController) TerminateSSHProcess(ctx context.Context, _ PlanID, target ProcessTarget, grace time.Duration) (ResponseEffect, error) {
	if controller == nil || ctx == nil || !target.Identity.valid() || grace <= 0 || grace > MaximumProcessGrace {
		return ResponseEffect{}, ErrInvalid
	}
	snapshot, err := readProcessSnapshot(target.Identity.PID, target.Identity.Boot)
	snapshotDigest, digestErr := DigestProcessSnapshot(snapshot)
	if err != nil || digestErr != nil || snapshot.Identity != target.Identity || snapshotDigest != target.SnapshotDigest || snapshot.EffectiveUID != target.ExpectedUID || snapshot.Command != target.ExpectedCommand {
		return ResponseEffect{}, ErrConflict
	}
	pidfd, _, errno := syscall.Syscall(syscallPIDFDOpen, uintptr(target.Identity.PID), 0, 0)
	if errno != 0 {
		return ResponseEffect{}, errno
	}
	defer syscall.Close(int(pidfd))
	snapshot, err = readProcessSnapshot(target.Identity.PID, target.Identity.Boot)
	snapshotDigest, digestErr = DigestProcessSnapshot(snapshot)
	if err != nil || digestErr != nil || snapshot.Identity != target.Identity || snapshotDigest != target.SnapshotDigest || snapshot.EffectiveUID != target.ExpectedUID || snapshot.Command != target.ExpectedCommand {
		return ResponseEffect{}, ErrConflict
	}
	if err := pidfdSignal(int(pidfd), syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return ResponseEffect{AlreadyApplied: true, EvidenceDigest: digestParts("process-gone", target.Identity.Boot.BootID, strconv.FormatUint(uint64(target.Identity.PID), 10))}, nil
		}
		return ResponseEffect{}, err
	}
	effect := ResponseEffect{Changed: true, TermSent: true, EvidenceDigest: digestParts("term-sent", target.Identity.Boot.BootID, strconv.FormatUint(uint64(target.Identity.PID), 10), strconv.FormatUint(target.Identity.StartTimeTicks, 10))}
	deadline := time.NewTimer(grace)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return effect, ctx.Err()
		case <-ticker.C:
			if err := pidfdSignal(int(pidfd), 0); errors.Is(err, syscall.ESRCH) {
				effect.Exited = true
				effect.EvidenceDigest = digestParts("term-exited", target.Identity.Boot.BootID, strconv.FormatUint(uint64(target.Identity.PID), 10), strconv.FormatUint(target.Identity.StartTimeTicks, 10))
				return effect, nil
			} else if err != nil {
				return effect, err
			}
		case <-deadline.C:
			if err := pidfdSignal(int(pidfd), syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				return effect, err
			}
			effect.KillSent = true
			effect.EvidenceDigest = digestParts("term-kill", target.Identity.Boot.BootID, strconv.FormatUint(uint64(target.Identity.PID), 10), strconv.FormatUint(target.Identity.StartTimeTicks, 10))
			return effect, nil
		}
	}
}

type LinuxSessionController struct {
	observer *LinuxObserver
}

func NewLinuxSessionController(observer *LinuxObserver) (*LinuxSessionController, error) {
	if observer == nil {
		return nil, ErrInvalid
	}
	return &LinuxSessionController{observer: observer}, nil
}

func (controller *LinuxSessionController) RevokeSSHSession(ctx context.Context, _ PlanID, target SessionTarget) (ResponseEffect, error) {
	if controller == nil || controller.observer == nil || ctx == nil || !target.Identity.valid() || !strings.HasPrefix(string(target.Identity.ID), "logind-") {
		return ResponseEffect{}, ErrInvalid
	}
	rawID := strings.TrimPrefix(string(target.Identity.ID), "logind-")
	current, err := controller.observer.observeSession(ctx, rawID, target.Identity.Boot)
	if errors.Is(err, ErrInvalid) || errors.Is(err, os.ErrNotExist) {
		return ResponseEffect{AlreadyApplied: true, EvidenceDigest: digestParts("session-gone", string(target.Identity.ID))}, nil
	}
	if err != nil || !sameSessionIdentity(current.Identity, target.Identity) || current.User.ID != target.UserID || current.Source.Address != target.Source {
		return ResponseEffect{}, ErrConflict
	}
	_, _, err = runBoundedCommand(ctx, sshLoginctlPath, 16<<10, "terminate-session", rawID)
	if err != nil {
		return ResponseEffect{}, err
	}
	return ResponseEffect{Changed: true, EvidenceDigest: digestParts("session-revoked", string(target.Identity.ID), target.Identity.Boot.BootID)}, nil
}
