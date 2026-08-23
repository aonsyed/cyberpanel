package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maximumSessionFile = 16 << 10

type gatewaySession struct {
	CookieName   string
	SessionID    string
	SessionToken string
	CSRFToken    string
}

type gatewaySessionDocument struct {
	SessionCookie string `json:"session_cookie"`
	CSRFToken     string `json:"csrf_token"`
}

func readGatewaySessionFile(path string) (gatewaySession, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return gatewaySession{}, errors.New("unsafe gateway session file path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return gatewaySession{}, err
	}
	if !safeGatewaySessionFile(info) {
		return gatewaySession{}, errors.New("gateway session file must be a non-empty owner-only regular file owned by the current user")
	}
	file, err := os.Open(path)
	if err != nil {
		return gatewaySession{}, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) || !safeGatewaySessionFile(opened) || info.Size() != opened.Size() {
		_ = file.Close()
		return gatewaySession{}, errors.New("gateway session file changed while opening")
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maximumSessionFile+1))
	closeErr := file.Close()
	defer wipe(content)
	if readErr != nil {
		return gatewaySession{}, readErr
	}
	if closeErr != nil {
		return gatewaySession{}, closeErr
	}
	if len(content) == 0 || len(content) > maximumSessionFile {
		return gatewaySession{}, errors.New("gateway session file exceeds its size bound")
	}

	document, err := decodeGatewaySessionDocument(content)
	if err != nil {
		return gatewaySession{}, err
	}
	return parseGatewaySession(document)
}

func decodeGatewaySessionDocument(content []byte) (gatewaySessionDocument, error) {
	var document gatewaySessionDocument
	decoder := json.NewDecoder(bytes.NewReader(content))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return document, errors.New("gateway session file must contain exactly one strict JSON object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, ok := nextJSONKey(decoder)
		if !ok || seen[key] {
			return gatewaySessionDocument{}, errors.New("gateway session file contains an unknown or duplicate field")
		}
		seen[key] = true
		switch key {
		case "session_cookie":
			err = decoder.Decode(&document.SessionCookie)
		case "csrf_token":
			err = decoder.Decode(&document.CSRFToken)
		default:
			return gatewaySessionDocument{}, errors.New("gateway session file contains an unknown or duplicate field")
		}
		if err != nil {
			return gatewaySessionDocument{}, errors.New("gateway session file fields must be JSON strings")
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF || !seen["session_cookie"] || !seen["csrf_token"] {
		return gatewaySessionDocument{}, errors.New("gateway session file must contain exactly one strict JSON object")
	}
	return document, nil
}

func nextJSONKey(decoder *json.Decoder) (string, bool) {
	token, err := decoder.Token()
	key, ok := token.(string)
	return key, err == nil && ok
}

func safeGatewaySessionFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0077 == 0 && info.Size() > 0 && info.Size() <= maximumSessionFile && uint64(stat.Uid) == uint64(os.Geteuid())
}

func parseGatewaySession(document gatewaySessionDocument) (gatewaySession, error) {
	separator := strings.IndexByte(document.SessionCookie, '=')
	if separator <= 0 || strings.IndexByte(document.SessionCookie[separator+1:], '=') >= 0 {
		return gatewaySession{}, errors.New("invalid gateway session file")
	}
	cookieName, cookieValue := document.SessionCookie[:separator], document.SessionCookie[separator+1:]
	parts := strings.Split(cookieValue, ".")
	if !validCookieName(cookieName) || len(parts) != 2 || !validSessionID(parts[0]) || !validEncodedCredential(parts[1]) || !validEncodedCredential(document.CSRFToken) {
		return gatewaySession{}, errors.New("invalid gateway session file")
	}
	return gatewaySession{CookieName: cookieName, SessionID: parts[0], SessionToken: parts[1], CSRFToken: document.CSRFToken}, nil
}

func validCookieName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", character)) {
			return false
		}
	}
	return true
}

func validSessionID(value string) bool {
	if len(value) < 3 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validEncodedCredential(value string) bool {
	if len(value) < 16 || len(value) > 8192 || strings.ContainsAny(value, "\r\n\t ") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	valid := err == nil && len(decoded) >= 16 && len(decoded) <= 4096
	wipe(decoded)
	return valid
}
