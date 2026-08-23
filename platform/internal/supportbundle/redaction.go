package supportbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
)

const redactionMarker = "[REDACTED]"

var (
	privateKeyPattern = regexp.MustCompile(`(?is)-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----.*?-----END[ A-Z0-9_-]*PRIVATE KEY-----`)
	bearerPattern     = regexp.MustCompile(`(?i)\bbearer[ \t]+[a-z0-9._~+/=-]{8,}`)
	jwtPattern        = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b`)
	accessKeyPattern  = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	githubKeyPattern  = regexp.MustCompile(`\bgh[pousr]_[a-zA-Z0-9_]{20,}\b`)
	openAIKeyPattern  = regexp.MustCompile(`\bsk-[a-zA-Z0-9_-]{20,}\b`)
	vendorKeyPattern  = regexp.MustCompile(`\b(?:xox[baprs]-[a-zA-Z0-9-]{16,}|glpat-[a-zA-Z0-9_-]{16,}|sk_live_[a-zA-Z0-9]{16,})\b`)
	assignmentPattern = regexp.MustCompile(`(?i)\b(password|passwd|passphrase|secret|token|api[_-]?key|authorization|cookie)([ \t]*[:=][ \t]*)([^,;\s]+)`)
	urlSecretPattern  = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^:/\s@]+:)[^@\s/]+@`)
)

var sensitiveJSONKeys = map[string]struct{}{
	"access_token": {}, "api_key": {}, "apikey": {}, "authorization": {}, "client_secret": {},
	"cookie": {}, "credential": {}, "credentials": {}, "password": {}, "passphrase": {},
	"private_key": {}, "private_key_pem": {}, "refresh_token": {}, "secret": {},
	"session_token": {}, "token": {},
}

type boundaryRedactor struct {
	fingerprints []string
}

func newBoundaryRedactor(ctx context.Context, source SecretFingerprintSource) (*boundaryRedactor, error) {
	if ctx == nil || source == nil {
		return nil, ErrSecret
	}
	values, err := source.SupportBundleSecretFingerprints(ctx)
	if err != nil {
		return nil, errors.Join(ErrSecret, err)
	}
	if len(values) > MaximumFingerprintCount {
		return nil, ErrLimit
	}
	seen := make(map[string]struct{}, len(values))
	fingerprints := make([]string, 0, len(values))
	total := 0
	for _, value := range values {
		fingerprint := value.Fingerprint
		if !opaquePattern.MatchString(value.ID) || len(fingerprint) < 8 || len(fingerprint) > MaximumRecordFieldBytes || strings.Contains(fingerprint, redactionMarker) || strings.IndexByte(fingerprint, 0) >= 0 {
			return nil, ErrSecret
		}
		total += len(fingerprint)
		if total > MaximumFingerprintBytes {
			return nil, ErrLimit
		}
		if _, exists := seen[fingerprint]; exists {
			continue
		}
		seen[fingerprint] = struct{}{}
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Slice(fingerprints, func(left, right int) bool {
		if len(fingerprints[left]) != len(fingerprints[right]) {
			return len(fingerprints[left]) > len(fingerprints[right])
		}
		return fingerprints[left] < fingerprints[right]
	})
	return &boundaryRedactor{fingerprints: fingerprints}, nil
}

func normalizedSecretKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "-", "_")
	return key
}

func sensitiveJSONKey(key string) bool {
	key = normalizedSecretKey(key)
	if _, sensitive := sensitiveJSONKeys[key]; sensitive {
		return true
	}
	return strings.HasSuffix(key, "_password") || strings.HasSuffix(key, "_passphrase") || strings.HasSuffix(key, "_secret") || strings.HasSuffix(key, "_token") || strings.HasSuffix(key, "_private_key")
}

func (redactor *boundaryRedactor) redactString(value string) string {
	for _, fingerprint := range redactor.fingerprints {
		value = strings.ReplaceAll(value, fingerprint, redactionMarker)
	}
	value = privateKeyPattern.ReplaceAllString(value, redactionMarker)
	value = bearerPattern.ReplaceAllString(value, "Bearer "+redactionMarker)
	value = jwtPattern.ReplaceAllString(value, redactionMarker)
	value = accessKeyPattern.ReplaceAllString(value, redactionMarker)
	value = githubKeyPattern.ReplaceAllString(value, redactionMarker)
	value = openAIKeyPattern.ReplaceAllString(value, redactionMarker)
	value = vendorKeyPattern.ReplaceAllString(value, redactionMarker)
	value = assignmentPattern.ReplaceAllString(value, "$1$2"+redactionMarker)
	value = urlSecretPattern.ReplaceAllString(value, "$1"+redactionMarker+"@")
	return value
}

func (redactor *boundaryRedactor) redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitiveJSONKey(key) {
				typed[key] = redactionMarker
				continue
			}
			typed[key] = redactor.redactValue(child)
		}
		return typed
	case []any:
		for index := range typed {
			typed[index] = redactor.redactValue(typed[index])
		}
		return typed
	case string:
		return redactor.redactString(typed)
	default:
		return value
	}
}

func (redactor *boundaryRedactor) verify(content []byte) error {
	text := string(content)
	for _, fingerprint := range redactor.fingerprints {
		if strings.Contains(text, fingerprint) {
			return ErrSecret
		}
	}
	if redactor.redactString(text) != text {
		return ErrSecret
	}
	return nil
}

func (redactor *boundaryRedactor) canonicalJSON(value any) ([]byte, error) {
	if redactor == nil {
		return nil, ErrSecret
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err = decoder.Decode(&document); err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	document = redactor.redactValue(document)
	canonical, err := json.Marshal(document)
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	if err = redactor.verify(canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}
