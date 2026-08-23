package artifactguard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

const ScannerVersion = "artifactguard-redactor-v1"

var errStructuredLimit = errors.New("artifactguard: structured input limit")

type ScanLimits struct {
	MaximumInputBytes      int64
	MaximumOutputBytes     int64
	MaximumLineBytes       int
	MaximumTokenBytes      int
	MaximumStructuredNodes int
	MaximumFindings        uint64
}

func DefaultScanLimits() ScanLimits {
	return ScanLimits{
		MaximumInputBytes:      256 << 20,
		MaximumOutputBytes:     256 << 20,
		MaximumLineBytes:       1 << 20,
		MaximumTokenBytes:      64 << 10,
		MaximumStructuredNodes: 4096,
		MaximumFindings:        100000,
	}
}

func (l ScanLimits) validate() error {
	if l.MaximumInputBytes <= 0 || l.MaximumInputBytes > 16<<30 ||
		l.MaximumOutputBytes <= 0 || l.MaximumOutputBytes > 16<<30 ||
		l.MaximumLineBytes < 256 || l.MaximumLineBytes > 8<<20 ||
		l.MaximumTokenBytes < 64 || l.MaximumTokenBytes > l.MaximumLineBytes ||
		l.MaximumStructuredNodes < 16 || l.MaximumStructuredNodes > 100000 ||
		l.MaximumFindings < 16 || l.MaximumFindings > 1000000 {
		return fmt.Errorf("%w: scan limits", ErrInvalid)
	}
	return nil
}

type StreamingRedactor struct {
	Limits ScanLimits
}

// Redact copies a deterministic, redacted representation of input to output.
// completedAt is supplied by the caller so the resulting manifest is stable.
// Any ErrTruncated result makes all emitted bytes unusable and they must be
// discarded; the encrypted storage pipeline commits only successful streams.
func (r StreamingRedactor) Redact(
	ctx context.Context,
	input io.Reader,
	output io.Writer,
	completedAt time.Time,
) (RedactionManifest, error) {
	if input == nil || output == nil || completedAt.IsZero() {
		return RedactionManifest{}, fmt.Errorf("%w: redaction arguments", ErrInvalid)
	}
	limits := r.Limits
	if limits == (ScanLimits{}) {
		limits = DefaultScanLimits()
	}
	if err := limits.validate(); err != nil {
		return RedactionManifest{}, err
	}

	inputHash := sha256.New()
	limited := &io.LimitedReader{R: input, N: limits.MaximumInputBytes + 1}
	countedInput := &countingReader{Reader: io.TeeReader(limited, inputHash)}
	reader := bufio.NewReaderSize(countedInput, limits.MaximumLineBytes+1)
	outputHash := sha256.New()
	countedOutput := &boundedHashWriter{
		Writer:  output,
		Hash:    outputHash,
		Maximum: limits.MaximumOutputBytes,
	}
	findings := newFindingTracker(limits.MaximumFindings)
	var lines uint64
	privateKeyBlock := false
	var terminalErr error

	for {
		if err := ctx.Err(); err != nil {
			terminalErr = err
			break
		}
		line, readErr := reader.ReadSlice('\n')
		if countedInput.Count > limits.MaximumInputBytes {
			findings.force(FindingInputTruncated)
			terminalErr = ErrTruncated
			break
		}
		if errors.Is(readErr, bufio.ErrBufferFull) || len(line) > limits.MaximumLineBytes {
			lines++
			findings.force(FindingLineTooLong)
			_ = countedOutput.writeMarker(FindingLineTooLong, true)
			terminalErr = ErrTruncated
			break
		}
		if len(line) != 0 {
			lines++
			if tokenExceedsLimit(line, limits.MaximumTokenBytes) {
				findings.force(FindingTokenTooLong)
				_ = countedOutput.writeMarker(FindingTokenTooLong, hasLineEnding(line))
				terminalErr = ErrTruncated
				break
			}

			if privateKeyBlock {
				if privateKeyEndPattern.Match(line) {
					privateKeyBlock = false
				}
			} else if privateKeyBeginPattern.Match(line) {
				if !findings.add(FindingPrivateKey, 1) {
					_ = countedOutput.writeMarker(FindingFindingLimit, hasLineEnding(line))
					terminalErr = ErrTruncated
					break
				}
				if err := countedOutput.writeMarker(FindingPrivateKey, hasLineEnding(line)); err != nil {
					findings.force(FindingInputTruncated)
					terminalErr = ErrTruncated
					break
				}
				privateKeyBlock = !privateKeyEndPattern.Match(line)
			} else {
				redacted, redactErr := redactLine(line, limits, findings)
				if redactErr != nil {
					_ = countedOutput.writeMarker(FindingFindingLimit, hasLineEnding(line))
					terminalErr = redactErr
					break
				}
				if _, err := countedOutput.Write(redacted); err != nil {
					findings.force(FindingInputTruncated)
					terminalErr = ErrTruncated
					break
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			findings.force(FindingInputTruncated)
			terminalErr = fmt.Errorf("artifactguard: read redaction input: %w", readErr)
			break
		}
	}
	if privateKeyBlock && terminalErr == nil {
		findings.force(FindingInputTruncated)
		terminalErr = ErrTruncated
	}
	if findings.overflow && terminalErr == nil {
		terminalErr = ErrTruncated
	}

	manifest := RedactionManifest{
		ScannerVersion: ScannerVersion,
		InputDigest:    hex.EncodeToString(inputHash.Sum(nil)),
		OutputDigest:   hex.EncodeToString(outputHash.Sum(nil)),
		InputBytes:     countedInput.Count,
		OutputBytes:    countedOutput.Count,
		Lines:          lines,
		Findings:       sortedFindingCounts(findings.counts),
		Truncated:      terminalErr != nil,
		CompletedAt:    canonicalTime(completedAt),
	}
	if validationErr := manifest.Validate(); validationErr != nil {
		return manifest, validationErr
	}
	return manifest, terminalErr
}

type countingReader struct {
	Reader io.Reader
	Count  int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.Reader.Read(buffer)
	r.Count += int64(n)
	return n, err
}

type boundedHashWriter struct {
	Writer  io.Writer
	Hash    hash.Hash
	Maximum int64
	Count   int64
}

func (w *boundedHashWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > w.Maximum-w.Count {
		return 0, ErrLimit
	}
	n, err := w.Writer.Write(value)
	if n > 0 {
		_, _ = w.Hash.Write(value[:n])
		w.Count += int64(n)
	}
	if err == nil && n != len(value) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (w *boundedHashWriter) writeMarker(code FindingCode, newline bool) error {
	marker := []byte("[REDACTED:" + string(code) + "]")
	if newline {
		marker = append(marker, '\n')
	}
	_, err := w.Write(marker)
	return err
}

type findingTracker struct {
	maximum  uint64
	total    uint64
	counts   map[FindingCode]uint64
	overflow bool
}

func newFindingTracker(maximum uint64) *findingTracker {
	return &findingTracker{maximum: maximum, counts: make(map[FindingCode]uint64)}
}

func (t *findingTracker) add(code FindingCode, count uint64) bool {
	if count == 0 {
		return true
	}
	if !code.valid() || count > t.maximum-t.total {
		t.force(FindingFindingLimit)
		t.overflow = true
		return false
	}
	t.counts[code] += count
	t.total += count
	return true
}

func (t *findingTracker) force(code FindingCode) {
	if t.counts[code] == 0 {
		t.counts[code] = 1
	}
}

var (
	privateKeyBeginPattern = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)
	privateKeyEndPattern   = regexp.MustCompile(`-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)
	jwtPattern             = regexp.MustCompile(`\b[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b`)
	urlUserInfoPattern     = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]{1,15}://)[^\s/@:]+:[^\s/@]+@`)
	cookiePattern          = regexp.MustCompile(`(?i)^(\s*(?:set-cookie|cookie)\s*:\s*).*$`)
	cookieAssignmentPattern = regexp.MustCompile(`(?i)((?:["'])?\b(?:cookie|session[_-]?cookie|session[_-]?id)\b(?:["'])?\s*(?::|=)\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
	authorizationPattern   = regexp.MustCompile(`(?i)^(\s*(?:authorization|proxy-authorization)\s*:\s*).*$`)
	credentialPattern      = regexp.MustCompile(`(?i)((?:["'])?\b(?:password|passwd|pwd|secret|token|credential|api[_-]?key|authorization|client[_-]?secret|access[_-]?key|refresh[_-]?token|aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\b(?:["'])?\s*(?::|=)\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
	credentialLiteralPattern = regexp.MustCompile(`\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,255}|xox[baprs]-[A-Za-z0-9-]{10,255}|sk_(?:live|test)_[A-Za-z0-9]{16,255})\b`)
)

func redactLine(line []byte, limits ScanLimits, findings *findingTracker) ([]byte, error) {
	ending := lineEnding(line)
	body := bytes.TrimSuffix(line, ending)
	structuredChanged := false
	if structured, changed, count, err := redactStructuredJSON(body, limits); err != nil {
		if errors.Is(err, errStructuredLimit) {
			findings.force(FindingStructuredLimit)
		} else {
			findings.force(FindingTokenTooLong)
		}
		return nil, ErrTruncated
	} else if changed {
		if !findings.add(FindingStructuredSecretKey, count) {
			return nil, ErrTruncated
		}
		body = structured
		structuredChanged = true
	}

	text := string(body)
	var ok bool
	text, ok = replacePattern(text, cookiePattern, "$1[REDACTED]")
	if ok && !findings.add(FindingCookie, 1) {
		return nil, ErrTruncated
	}
	if !structuredChanged && !ok {
		var cookieCount uint64
		text, cookieCount = replaceAllCount(text, cookieAssignmentPattern, "$1[REDACTED]")
		if !findings.add(FindingCookie, cookieCount) {
			return nil, ErrTruncated
		}
	}
	authorization := false
	if !structuredChanged {
		text, authorization = replacePattern(text, authorizationPattern, "$1[REDACTED]")
		if authorization && !findings.add(FindingCredential, 1) {
			return nil, ErrTruncated
		}
	}
	var count uint64
	text, count = replaceAllCount(text, urlUserInfoPattern, "$1[REDACTED]@")
	if !findings.add(FindingURLUserInfo, count) {
		return nil, ErrTruncated
	}
	if !authorization && !structuredChanged {
		text, count = replaceAllCount(text, credentialPattern, "$1[REDACTED]")
		if !findings.add(FindingCredential, count) {
			return nil, ErrTruncated
		}
	}
	text, count = replaceAllCount(text, credentialLiteralPattern, "[REDACTED]")
	if !findings.add(FindingCredential, count) {
		return nil, ErrTruncated
	}
	text, count = replaceAllCount(text, jwtPattern, "[REDACTED]")
	if !findings.add(FindingJWT, count) {
		return nil, ErrTruncated
	}
	result := make([]byte, 0, len(text)+len(ending))
	result = append(result, text...)
	result = append(result, ending...)
	return result, nil
}

func redactStructuredJSON(
	line []byte,
	limits ScanLimits,
) (encoded []byte, changed bool, findingCount uint64, err error) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, false, 0, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var value any
	if decodeErr := decoder.Decode(&value); decodeErr != nil {
		return nil, false, 0, nil
	}
	var trailing any
	if decodeErr := decoder.Decode(&trailing); !errors.Is(decodeErr, io.EOF) {
		return nil, false, 0, nil
	}
	nodes := 0
	count, walkErr := redactStructuredValue(&value, limits, 0, &nodes)
	if walkErr != nil {
		return nil, false, 0, walkErr
	}
	if count == 0 {
		return nil, false, 0, nil
	}
	encoded, err = json.Marshal(value)
	if err != nil {
		return nil, false, 0, fmt.Errorf("%w: structured redaction", ErrInvalid)
	}
	return encoded, true, count, nil
}

func redactStructuredValue(
	value *any,
	limits ScanLimits,
	depth int,
	nodes *int,
) (uint64, error) {
	if depth > 32 {
		return 0, errStructuredLimit
	}
	(*nodes)++
	if *nodes > limits.MaximumStructuredNodes {
		return 0, errStructuredLimit
	}
	switch typed := (*value).(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var findings uint64
		for _, key := range keys {
			if len(key) > limits.MaximumTokenBytes {
				return 0, ErrLimit
			}
			child := typed[key]
			if sensitiveStructuredKey(key) {
				typed[key] = "[REDACTED]"
				findings++
				continue
			}
			count, err := redactStructuredValue(&child, limits, depth+1, nodes)
			if err != nil {
				return 0, err
			}
			typed[key] = child
			findings += count
		}
		return findings, nil
	case []any:
		var findings uint64
		for index := range typed {
			child := typed[index]
			count, err := redactStructuredValue(&child, limits, depth+1, nodes)
			if err != nil {
				return 0, err
			}
			typed[index] = child
			findings += count
		}
		return findings, nil
	case string:
		if len(typed) > limits.MaximumTokenBytes {
			return 0, ErrLimit
		}
	}
	return 0, nil
}

func sensitiveStructuredKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(strings.ToLower(key))
	switch normalized {
	case "password", "passwd", "pwd", "secret", "token", "apikey", "authorization",
		"clientsecret", "accesskey", "secretaccesskey", "refreshtoken", "accesstoken",
		"privatekey", "cookie", "setcookie", "session", "sessionid", "credential",
		"awsaccesskeyid", "awssecretaccesskey":
		return true
	default:
		return false
	}
}

func replacePattern(value string, pattern *regexp.Regexp, replacement string) (string, bool) {
	if !pattern.MatchString(value) {
		return value, false
	}
	return pattern.ReplaceAllString(value, replacement), true
}

func replaceAllCount(value string, pattern *regexp.Regexp, replacement string) (string, uint64) {
	matches := pattern.FindAllStringIndex(value, -1)
	if len(matches) == 0 {
		return value, 0
	}
	return pattern.ReplaceAllString(value, replacement), uint64(len(matches))
}

func tokenExceedsLimit(value []byte, maximum int) bool {
	run := 0
	inQuoted := byte(0)
	escaped := false
	for _, current := range value {
		if inQuoted != 0 {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == inQuoted {
				inQuoted = 0
			}
			run++
		} else if current == '"' || current == '\'' {
			inQuoted = current
			run = 1
		} else if current == ' ' || current == '\t' || current == '\r' || current == '\n' ||
			current == ',' || current == ':' || current == '=' || current == ';' ||
			current == '{' || current == '}' || current == '[' || current == ']' {
			run = 0
		} else {
			run++
		}
		if run > maximum {
			return true
		}
	}
	return false
}

func lineEnding(value []byte) []byte {
	if bytes.HasSuffix(value, []byte{'\r', '\n'}) {
		return []byte{'\r', '\n'}
	}
	if bytes.HasSuffix(value, []byte{'\n'}) {
		return []byte{'\n'}
	}
	return nil
}

func hasLineEnding(value []byte) bool { return len(lineEnding(value)) != 0 }
