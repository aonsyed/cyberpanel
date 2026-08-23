package logworkspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"regexp/syntax"
	"time"
)

type CursorSigner interface {
	ActiveCursorKey(context.Context) (string, error)
	SignCursor(context.Context, string, []byte) ([]byte, error)
	VerifyCursor(context.Context, string, []byte, []byte) error
}

type CursorState struct {
	Version       uint8       `json:"version"`
	SourceID      SourceID    `json:"source_id"`
	Generation    uint64      `json:"generation"`
	Backend       BackendKind `json:"backend"`
	JournalCursor string      `json:"journal_cursor,omitempty"`
	FileOffset    int64       `json:"file_offset,omitempty"`
	Device        uint64      `json:"device,omitempty"`
	Inode         uint64      `json:"inode,omitempty"`
	QueryDigest   string      `json:"query_digest"`
	IssuedUnixNS  int64       `json:"issued_unix_ns"`
	ExpiresUnixNS int64       `json:"expires_unix_ns"`
}

type cursorEnvelope struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type CursorCodec struct {
	signer CursorSigner
	now    func() time.Time
}

func NewCursorCodec(signer CursorSigner) (*CursorCodec, error) {
	if signer == nil {
		return nil, ErrInvalid
	}
	return &CursorCodec{signer: signer, now: time.Now}, nil
}

func validBackendCursor(value string) bool {
	if value == "" || len(value) > MaximumOpaqueBytes {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func (state CursorState) valid(now time.Time) bool {
	if state.Version != 1 || !opaquePattern.MatchString(string(state.SourceID)) || state.Generation == 0 || state.Generation > MaximumGeneration || len(state.QueryDigest) != sha256.Size*2 || state.IssuedUnixNS <= 0 || state.ExpiresUnixNS <= state.IssuedUnixNS {
		return false
	}
	if _, err := hex.DecodeString(state.QueryDigest); err != nil {
		return false
	}
	issued := time.Unix(0, state.IssuedUnixNS)
	expires := time.Unix(0, state.ExpiresUnixNS)
	if expires.Sub(issued) > MaximumCursorLifetime || now.Before(issued.Add(-time.Minute)) || !now.Before(expires) {
		return false
	}
	switch state.Backend {
	case BackendJournal:
		return validBackendCursor(state.JournalCursor) && state.FileOffset == 0 && state.Device == 0 && state.Inode == 0
	case BackendFile:
		return state.JournalCursor == "" && state.FileOffset >= 0 && state.Device != 0 && state.Inode != 0
	default:
		return false
	}
}

func strictDecode(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrIntegrity
	}
	return nil
}

func (codec *CursorCodec) Encode(ctx context.Context, state CursorState, lifetime time.Duration) (string, error) {
	if codec == nil || codec.signer == nil || ctx == nil || lifetime <= 0 || lifetime > MaximumCursorLifetime {
		return "", ErrInvalid
	}
	now := codec.now().UTC()
	state.Version = 1
	state.IssuedUnixNS = now.UnixNano()
	state.ExpiresUnixNS = now.Add(lifetime).UnixNano()
	if !state.valid(now) {
		return "", ErrInvalid
	}
	payload, err := json.Marshal(state)
	if err != nil || len(payload) > MaximumOpaqueBytes {
		return "", ErrLimit
	}
	keyID, err := codec.signer.ActiveCursorKey(ctx)
	if err != nil {
		return "", err
	}
	if !opaquePattern.MatchString(keyID) {
		return "", ErrIntegrity
	}
	signature, err := codec.signer.SignCursor(ctx, keyID, payload)
	if err != nil {
		return "", err
	}
	if len(signature) < 16 || len(signature) > 512 {
		return "", ErrIntegrity
	}
	envelope := cursorEnvelope{
		KeyID: keyID,
		Payload: base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > MaximumOpaqueBytes {
		return "", ErrLimit
	}
	token := base64.RawURLEncoding.EncodeToString(encoded)
	if len(token) > MaximumOpaqueBytes {
		return "", ErrLimit
	}
	return token, nil
}

func (codec *CursorCodec) Decode(ctx context.Context, token string) (CursorState, error) {
	if codec == nil || codec.signer == nil || ctx == nil || token == "" || len(token) > MaximumOpaqueBytes {
		return CursorState{}, ErrInvalid
	}
	encoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(encoded) > MaximumOpaqueBytes {
		return CursorState{}, ErrIntegrity
	}
	var envelope cursorEnvelope
	if strictDecode(encoded, &envelope) != nil || !opaquePattern.MatchString(envelope.KeyID) || len(envelope.Payload) > MaximumOpaqueBytes || len(envelope.Signature) > 1024 {
		return CursorState{}, ErrIntegrity
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) > MaximumOpaqueBytes {
		return CursorState{}, ErrIntegrity
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) < 16 || len(signature) > 512 {
		return CursorState{}, ErrIntegrity
	}
	if err = codec.signer.VerifyCursor(ctx, envelope.KeyID, payload, signature); err != nil {
		return CursorState{}, ErrIntegrity
	}
	var state CursorState
	if strictDecode(payload, &state) != nil || !state.valid(codec.now().UTC()) {
		return CursorState{}, ErrIntegrity
	}
	return state, nil
}

type queryBinding struct {
	SourceID   SourceID       `json:"source_id"`
	Projection ProjectionKind `json:"projection"`
	SinceNS    int64          `json:"since_ns"`
	UntilNS    int64          `json:"until_ns"`
	TailLines  uint32         `json:"tail_lines"`
	Search     SearchSpec     `json:"search"`
	Limits     QueryLimits    `json:"limits"`
}

func queryDigest(query Query) (string, error) {
	if query.Validate() != nil {
		return "", ErrInvalid
	}
	var sinceNS, untilNS int64
	if !query.Since.IsZero() {
		sinceNS = query.Since.UTC().UnixNano()
	}
	if !query.Until.IsZero() {
		untilNS = query.Until.UTC().UnixNano()
	}
	binding := queryBinding{
		SourceID: query.SourceID,
		Projection: query.Projection,
		SinceNS: sinceNS,
		UntilNS: untilNS,
		TailLines: query.TailLines,
		Search: query.Search,
		Limits: query.Limits,
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

type compiledSearch struct {
	literal       string
	caseSensitive bool
	regex         *regexp.Regexp
}

func compileSearch(spec SearchSpec) (*compiledSearch, error) {
	if spec.Literal == "" || len(spec.Literal) > MaximumSearchLiteral || len(spec.Regex) > MaximumRegexBytes {
		return nil, ErrInvalid
	}
	search := &compiledSearch{literal: spec.Literal, caseSensitive: spec.CaseSensitive}
	if spec.Regex == "" {
		return search, nil
	}
	expression := spec.Regex
	if !spec.CaseSensitive {
		expression = "(?i:" + expression + ")"
	}
	parsed, err := syntax.Parse(expression, syntax.Perl)
	if err != nil {
		return nil, ErrInvalid
	}
	program, err := syntax.Compile(parsed.Simplify())
	if err != nil || len(program.Inst) > MaximumRegexInstructions {
		return nil, ErrLimit
	}
	search.regex, err = regexp.Compile(expression)
	if err != nil {
		return nil, ErrInvalid
	}
	return search, nil
}

// match deliberately applies the cheap literal predicate before the bounded RE2
// program. The caller owns the explicit query and regex deadlines.
func (search *compiledSearch) match(value string) bool {
	if search == nil || !literalMatch(value, search.literal, search.caseSensitive) {
		return false
	}
	return search.regex == nil || search.regex.MatchString(value)
}
