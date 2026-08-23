package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	DefaultHostFilesystemAbsoluteTTL = 15 * time.Minute
	DefaultHostFilesystemIdleTTL     = 5 * time.Minute
	MaximumHostFilesystemAbsoluteTTL = 30 * time.Minute
	MaximumHostFilesystemIdleTTL     = 10 * time.Minute
	MaximumHostFilesystemMFAAge      = 10 * time.Minute
	DefaultHostFilesystemByteLimit   = 16 << 20
	MaximumHostFilesystemByteLimit   = 64 << 20
	MaximumHostFilesystemReadBytes   = 1 << 20
	MaximumHostFilesystemPageSize    = 200
)

type HostFilesystemSessionID string
type HostFilesystemRootID string

const (
	HostFilesystemRootSystemConfiguration HostFilesystemRootID = "system_configuration"
	HostFilesystemRootSystemLogs          HostFilesystemRootID = "system_logs"
)

func validHostFilesystemOpaque(value string) bool {
	if value == "" || len(value) > 128 || !asciiAlphaNumeric(value[0]) || !asciiAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character > 127 || !(asciiAlphaNumeric(character) || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func (id HostFilesystemSessionID) Validate() error {
	if !validHostFilesystemOpaque(string(id)) {
		return ErrInvalidID
	}
	return nil
}

func (id HostFilesystemRootID) Validate() error {
	if !validHostFilesystemOpaque(string(id)) {
		return ErrInvalidID
	}
	return nil
}

// HostFilesystemPath is a canonical path relative to an approved, pre-opened
// host root. Host paths and dot segments never enter the broker protocol.
type HostFilesystemPath struct{ value string }

func ParseHostFilesystemPath(raw string) (HostFilesystemPath, error) {
	if len(raw) > 4096 || !utf8.ValidString(raw) || strings.IndexByte(raw, 0) >= 0 || strings.Contains(raw, "\\") || strings.HasPrefix(raw, "/") {
		return HostFilesystemPath{}, ErrInvalidPath
	}
	if raw == "" {
		return HostFilesystemPath{}, nil
	}
	clean, err := ParseRelativePath(raw)
	if err != nil {
		return HostFilesystemPath{}, err
	}
	for _, character := range raw {
		if character < 0x20 || character == 0x7f {
			return HostFilesystemPath{}, ErrInvalidPath
		}
	}
	return HostFilesystemPath{value: clean.String()}, nil
}

func (path HostFilesystemPath) String() string { return path.value }
func (path HostFilesystemPath) IsRoot() bool   { return path.value == "" }

func (path HostFilesystemPath) Join(name string) (HostFilesystemPath, error) {
	if path.IsRoot() {
		return ParseHostFilesystemPath(name)
	}
	return ParseHostFilesystemPath(path.value + "/" + name)
}

func (path HostFilesystemPath) MarshalJSON() ([]byte, error) { return json.Marshal(path.value) }

func (path *HostFilesystemPath) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	parsed, err := ParseHostFilesystemPath(raw)
	if err != nil {
		return err
	}
	*path = parsed
	return nil
}

type HostFilesystemEntry struct {
	Root       HostFilesystemRootID `json:"root"`
	Path       HostFilesystemPath   `json:"path"`
	Kind       EntryKind            `json:"kind"`
	Size       int64                `json:"size"`
	Mode       uint32               `json:"mode"`
	UID        uint32               `json:"uid"`
	GID        uint32               `json:"gid"`
	ModifiedAt time.Time            `json:"modified_at"`
	ETag       string               `json:"etag"`
}

type HostFilesystemPageRequest struct {
	Limit  uint16 `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

func (page HostFilesystemPageRequest) normalized() (HostFilesystemPageRequest, error) {
	if page.Limit == 0 {
		page.Limit = 100
	}
	if page.Limit > MaximumHostFilesystemPageSize || len(page.Cursor) > 255 || strings.Contains(page.Cursor, "/") {
		return HostFilesystemPageRequest{}, ErrLimitExceeded
	}
	if page.Cursor != "" {
		if _, err := ParseHostFilesystemPath(page.Cursor); err != nil {
			return HostFilesystemPageRequest{}, err
		}
	}
	return page, nil
}

type HostFilesystemPage struct {
	Entries    []HostFilesystemEntry `json:"entries"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type HostFilesystemRead struct {
	Entry   HostFilesystemEntry `json:"entry"`
	Offset  int64               `json:"offset"`
	Content []byte              `json:"content"`
	SHA256  string              `json:"sha256"`
	EOF     bool                `json:"eof"`
}

// HostFilesystemBroker is deliberately read-only. Implementations receive a
// root capability and a relative path, never a shell string or absolute path.
type HostFilesystemBroker interface {
	AllowedRoots() []HostFilesystemRootID
	List(context.Context, HostFilesystemRootID, HostFilesystemPath, HostFilesystemPageRequest) (HostFilesystemPage, error)
	Stat(context.Context, HostFilesystemRootID, HostFilesystemPath) (HostFilesystemEntry, error)
	Read(context.Context, HostFilesystemRootID, HostFilesystemPath, int64, int64) (HostFilesystemRead, error)
}

type HostFilesystemAuthorization struct {
	PrincipalID    PrincipalID `json:"principal_id"`
	SessionID      string      `json:"identity_session_id"`
	CredentialID   string      `json:"credential_id"`
	AuthzEpoch     uint64      `json:"authz_epoch"`
	Assurance      uint8       `json:"assurance"`
	SourceIP       netip.Addr  `json:"source_ip"`
	MFAVerifiedAt  time.Time   `json:"mfa_verified_at"`
	LocalConsole   bool        `json:"local_console"`
}

func (authorization HostFilesystemAuthorization) validate(now time.Time) error {
	if !validID(string(authorization.PrincipalID)) || !validHostFilesystemOpaque(authorization.SessionID) || !validHostFilesystemOpaque(authorization.CredentialID) || authorization.AuthzEpoch == 0 || authorization.Assurance < 2 || !authorization.SourceIP.IsValid() || authorization.MFAVerifiedAt.IsZero() {
		return ErrUnauthorized
	}
	if authorization.MFAVerifiedAt.After(now.Add(30*time.Second)) || now.Sub(authorization.MFAVerifiedAt) > MaximumHostFilesystemMFAAge {
		return ErrUnauthorized
	}
	return nil
}

type HostFilesystemAuthorizationRequest struct {
	Authorization HostFilesystemAuthorization
	Operation     string
	SessionID     HostFilesystemSessionID
}

type HostFilesystemReauthorizer interface {
	ReauthorizeHostFilesystem(context.Context, HostFilesystemAuthorizationRequest) error
}

type HostFilesystemReauthorizerFunc func(context.Context, HostFilesystemAuthorizationRequest) error

func (function HostFilesystemReauthorizerFunc) ReauthorizeHostFilesystem(ctx context.Context, request HostFilesystemAuthorizationRequest) error {
	return function(ctx, request)
}

type HostFilesystemAccessPolicy struct {
	ManagementNetworks []netip.Prefix
	AllowLocalConsole  bool
}

func DefaultHostFilesystemAccessPolicy() HostFilesystemAccessPolicy {
	return HostFilesystemAccessPolicy{
		ManagementNetworks: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
		},
		AllowLocalConsole: true,
	}
}

func (policy HostFilesystemAccessPolicy) validate() error {
	if !policy.AllowLocalConsole && len(policy.ManagementNetworks) == 0 {
		return ErrInvalidState
	}
	for _, prefix := range policy.ManagementNetworks {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return ErrInvalidState
		}
	}
	return nil
}

func (policy HostFilesystemAccessPolicy) allows(authorization HostFilesystemAuthorization) bool {
	if policy.AllowLocalConsole && authorization.LocalConsole && authorization.SourceIP.IsLoopback() {
		return true
	}
	for _, prefix := range policy.ManagementNetworks {
		if prefix.Contains(authorization.SourceIP) {
			return true
		}
	}
	return false
}

type HostFilesystemIssueRequest struct {
	ID          HostFilesystemSessionID
	Reason      string
	Roots       []HostFilesystemRootID
	AbsoluteTTL time.Duration
	IdleTTL     time.Duration
	ByteLimit   int64
}

type HostFilesystemSession struct {
	ID                HostFilesystemSessionID `json:"id"`
	PrincipalID       PrincipalID             `json:"principal_id"`
	IdentitySessionID string                  `json:"identity_session_id"`
	CredentialID      string                  `json:"credential_id"`
	AuthzEpoch        uint64                  `json:"authz_epoch"`
	Reason            string                  `json:"reason"`
	Roots             []HostFilesystemRootID  `json:"roots"`
	ReadOnly          bool                    `json:"read_only"`
	SourceIP          string                  `json:"source_ip"`
	IssuedAt          time.Time               `json:"issued_at"`
	LastUsedAt        time.Time               `json:"last_used_at"`
	IdleExpiresAt     time.Time               `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time               `json:"absolute_expires_at"`
	ByteLimit         int64                   `json:"byte_limit"`
	BytesRead         int64                   `json:"bytes_read"`
	AuditDigest       string                  `json:"audit_digest"`
	idleTTL           time.Duration
}

func hostFilesystemReason(raw string) (string, error) {
	reason := strings.TrimSpace(raw)
	if len(reason) < 12 || len(reason) > 512 || !utf8.ValidString(reason) || strings.IndexByte(reason, 0) >= 0 {
		return "", ErrInvalidState
	}
	for _, character := range reason {
		if character < 0x20 && character != '\t' {
			return "", ErrInvalidState
		}
	}
	return reason, nil
}

func hostFilesystemAuditDigest(session HostFilesystemSession) string {
	values := make([]string, len(session.Roots))
	for index, root := range session.Roots {
		values[index] = string(root)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"cyberpanel-host-filesystem-session-v1",
		string(session.ID), string(session.PrincipalID), session.IdentitySessionID,
		session.CredentialID, fmt.Sprint(session.AuthzEpoch), session.Reason,
		strings.Join(values, ","), session.SourceIP, session.IssuedAt.Format(time.RFC3339Nano),
		session.AbsoluteExpiresAt.Format(time.RFC3339Nano), fmt.Sprint(session.ByteLimit), "read_only",
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

type HostFilesystemService struct {
	Broker       HostFilesystemBroker
	Reauthorizer HostFilesystemReauthorizer
	Policy       HostFilesystemAccessPolicy
	Now          func() time.Time

	mu       sync.Mutex
	sessions map[HostFilesystemSessionID]HostFilesystemSession
}

func NewHostFilesystemService(broker HostFilesystemBroker, reauthorizer HostFilesystemReauthorizer, policy HostFilesystemAccessPolicy) (*HostFilesystemService, error) {
	if broker == nil || reauthorizer == nil || policy.validate() != nil || len(broker.AllowedRoots()) == 0 {
		return nil, ErrInvalidState
	}
	return &HostFilesystemService{Broker: broker, Reauthorizer: reauthorizer, Policy: policy, Now: time.Now, sessions: map[HostFilesystemSessionID]HostFilesystemSession{}}, nil
}

func (service *HostFilesystemService) now() time.Time {
	if service.Now == nil {
		return time.Now().UTC()
	}
	return service.Now().UTC()
}

func (service *HostFilesystemService) Issue(ctx context.Context, authorization HostFilesystemAuthorization, request HostFilesystemIssueRequest) (HostFilesystemSession, error) {
	if service == nil || service.Broker == nil || service.Reauthorizer == nil || ctx == nil || request.ID.Validate() != nil {
		return HostFilesystemSession{}, ErrInvalidState
	}
	now := service.now()
	if authorization.validate(now) != nil || !service.Policy.allows(authorization) {
		return HostFilesystemSession{}, ErrUnauthorized
	}
	if err := service.Reauthorizer.ReauthorizeHostFilesystem(ctx, HostFilesystemAuthorizationRequest{Authorization: authorization, Operation: "issue", SessionID: request.ID}); err != nil {
		return HostFilesystemSession{}, ErrUnauthorized
	}
	reason, err := hostFilesystemReason(request.Reason)
	if err != nil {
		return HostFilesystemSession{}, err
	}
	absoluteTTL := request.AbsoluteTTL
	if absoluteTTL == 0 {
		absoluteTTL = DefaultHostFilesystemAbsoluteTTL
	}
	idleTTL := request.IdleTTL
	if idleTTL == 0 {
		idleTTL = DefaultHostFilesystemIdleTTL
	}
	byteLimit := request.ByteLimit
	if byteLimit == 0 {
		byteLimit = DefaultHostFilesystemByteLimit
	}
	if absoluteTTL <= 0 || absoluteTTL > MaximumHostFilesystemAbsoluteTTL || idleTTL <= 0 || idleTTL > MaximumHostFilesystemIdleTTL || idleTTL > absoluteTTL || byteLimit <= 0 || byteLimit > MaximumHostFilesystemByteLimit {
		return HostFilesystemSession{}, ErrLimitExceeded
	}
	approved := make(map[HostFilesystemRootID]struct{})
	for _, root := range service.Broker.AllowedRoots() {
		approved[root] = struct{}{}
	}
	if len(request.Roots) == 0 || len(request.Roots) > len(approved) {
		return HostFilesystemSession{}, ErrUnauthorized
	}
	roots := append([]HostFilesystemRootID(nil), request.Roots...)
	sort.Slice(roots, func(left, right int) bool { return roots[left] < roots[right] })
	for index, root := range roots {
		if root.Validate() != nil {
			return HostFilesystemSession{}, ErrInvalidID
		}
		if _, exists := approved[root]; !exists || index > 0 && roots[index-1] == root {
			return HostFilesystemSession{}, ErrUnauthorized
		}
	}
	idleExpiry := now.Add(idleTTL)
	absoluteExpiry := now.Add(absoluteTTL)
	if idleExpiry.After(absoluteExpiry) {
		idleExpiry = absoluteExpiry
	}
	session := HostFilesystemSession{
		ID: request.ID, PrincipalID: authorization.PrincipalID, IdentitySessionID: authorization.SessionID,
		CredentialID: authorization.CredentialID, AuthzEpoch: authorization.AuthzEpoch, Reason: reason,
		Roots: roots, ReadOnly: true, SourceIP: authorization.SourceIP.String(), IssuedAt: now,
		LastUsedAt: now, IdleExpiresAt: idleExpiry, AbsoluteExpiresAt: absoluteExpiry,
		ByteLimit: byteLimit, idleTTL: idleTTL,
	}
	session.AuditDigest = hostFilesystemAuditDigest(session)
	service.mu.Lock()
	defer service.mu.Unlock()
	if _, exists := service.sessions[session.ID]; exists {
		return HostFilesystemSession{}, ErrConflict
	}
	service.sessions[session.ID] = session
	return session, nil
}

func hostFilesystemSessionRoot(session HostFilesystemSession, root HostFilesystemRootID) bool {
	index := sort.Search(len(session.Roots), func(index int) bool { return session.Roots[index] >= root })
	return index < len(session.Roots) && session.Roots[index] == root
}

func (service *HostFilesystemService) authorize(ctx context.Context, authorization HostFilesystemAuthorization, id HostFilesystemSessionID, operation string, root HostFilesystemRootID, requestedBytes int64) (HostFilesystemSession, error) {
	if service == nil || service.Broker == nil || service.Reauthorizer == nil || ctx == nil || id.Validate() != nil || root.Validate() != nil {
		return HostFilesystemSession{}, ErrUnauthorized
	}
	now := service.now()
	if authorization.validate(now) != nil || !service.Policy.allows(authorization) {
		return HostFilesystemSession{}, ErrUnauthorized
	}
	service.mu.Lock()
	session, exists := service.sessions[id]
	if !exists || !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		delete(service.sessions, id)
		service.mu.Unlock()
		return HostFilesystemSession{}, ErrUnauthorized
	}
	validBinding := session.ReadOnly && session.PrincipalID == authorization.PrincipalID && session.IdentitySessionID == authorization.SessionID && session.CredentialID == authorization.CredentialID && session.AuthzEpoch == authorization.AuthzEpoch && session.SourceIP == authorization.SourceIP.String() && session.AuditDigest == hostFilesystemAuditDigest(session) && hostFilesystemSessionRoot(session, root)
	if requestedBytes < 0 || requestedBytes > session.ByteLimit-session.BytesRead {
		validBinding = false
	}
	service.mu.Unlock()
	if !validBinding {
		return HostFilesystemSession{}, ErrUnauthorized
	}
	if err := service.Reauthorizer.ReauthorizeHostFilesystem(ctx, HostFilesystemAuthorizationRequest{Authorization: authorization, Operation: operation, SessionID: id}); err != nil {
		return HostFilesystemSession{}, ErrUnauthorized
	}
	return session, nil
}

func (service *HostFilesystemService) touch(id HostFilesystemSessionID, authorization HostFilesystemAuthorization, bytesRead int64) error {
	now := service.now()
	service.mu.Lock()
	defer service.mu.Unlock()
	session, exists := service.sessions[id]
	if !exists || session.PrincipalID != authorization.PrincipalID || session.IdentitySessionID != authorization.SessionID || session.AuthzEpoch != authorization.AuthzEpoch || !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) || bytesRead < 0 || bytesRead > session.ByteLimit-session.BytesRead {
		return ErrUnauthorized
	}
	session.BytesRead += bytesRead
	session.LastUsedAt = now
	session.IdleExpiresAt = now.Add(session.idleTTL)
	if session.IdleExpiresAt.After(session.AbsoluteExpiresAt) {
		session.IdleExpiresAt = session.AbsoluteExpiresAt
	}
	service.sessions[id] = session
	return nil
}

func (service *HostFilesystemService) List(ctx context.Context, authorization HostFilesystemAuthorization, id HostFilesystemSessionID, root HostFilesystemRootID, path HostFilesystemPath, page HostFilesystemPageRequest) (HostFilesystemPage, error) {
	if _, err := service.authorize(ctx, authorization, id, "list", root, 0); err != nil {
		return HostFilesystemPage{}, err
	}
	page, err := page.normalized()
	if err != nil {
		return HostFilesystemPage{}, err
	}
	result, err := service.Broker.List(ctx, root, path, page)
	if err != nil {
		return HostFilesystemPage{}, err
	}
	if err = service.touch(id, authorization, 0); err != nil {
		return HostFilesystemPage{}, err
	}
	return result, nil
}

func (service *HostFilesystemService) Stat(ctx context.Context, authorization HostFilesystemAuthorization, id HostFilesystemSessionID, root HostFilesystemRootID, path HostFilesystemPath) (HostFilesystemEntry, error) {
	if _, err := service.authorize(ctx, authorization, id, "stat", root, 0); err != nil {
		return HostFilesystemEntry{}, err
	}
	result, err := service.Broker.Stat(ctx, root, path)
	if err != nil {
		return HostFilesystemEntry{}, err
	}
	if err = service.touch(id, authorization, 0); err != nil {
		return HostFilesystemEntry{}, err
	}
	return result, nil
}

func (service *HostFilesystemService) Read(ctx context.Context, authorization HostFilesystemAuthorization, id HostFilesystemSessionID, root HostFilesystemRootID, path HostFilesystemPath, offset, length int64) (HostFilesystemRead, error) {
	if length <= 0 || length > MaximumHostFilesystemReadBytes || offset < 0 {
		return HostFilesystemRead{}, ErrLimitExceeded
	}
	if _, err := service.authorize(ctx, authorization, id, "read", root, length); err != nil {
		return HostFilesystemRead{}, err
	}
	result, err := service.Broker.Read(ctx, root, path, offset, length)
	if err != nil {
		return HostFilesystemRead{}, err
	}
	if err = service.touch(id, authorization, int64(len(result.Content))); err != nil {
		for index := range result.Content {
			result.Content[index] = 0
		}
		return HostFilesystemRead{}, err
	}
	return result, nil
}
