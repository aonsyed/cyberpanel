// Package access owns site-scoped file, developer, and interactive access.
//
// The package deliberately never accepts host paths or shell command strings.
// Every privileged operation is expressed in terms of a validated site root,
// a canonical relative path, and a closed executor operation.
package access

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalidID         = errors.New("invalid access resource identifier")
	ErrInvalidPath       = errors.New("invalid site-relative path")
	ErrInvalidState      = errors.New("invalid access resource state")
	ErrInvalidTransition = errors.New("invalid access resource transition")
	ErrStaleGeneration   = errors.New("stale access resource generation")
	ErrNotFound          = errors.New("access resource not found")
	ErrConflict          = errors.New("access resource conflict")
	ErrLimitExceeded     = errors.New("access resource limit exceeded")
	ErrUnauthorized      = errors.New("access authorization rejected")
	ErrIntegrity         = errors.New("access data integrity failure")
)

type SiteID string
type TenantID string
type PrincipalID string
type CommandID string
type FileOperationID string
type UploadID string
type DownloadID string
type TrashEntryID string
type ArchiveID string
type FTPSAccountID string
type SSHKeyID string
type AccessGrantID string
type TerminalSessionID string
type CronJobID string
type GitRepositoryID string
type DeployKeyID string
type WebhookID string
type DeploymentID string
type StagingSyncID string

func validID(raw string) bool {
	if raw == "" || len(raw) > 128 || !asciiAlphaNumeric(raw[0]) || !asciiAlphaNumeric(raw[len(raw)-1]) {
		return false
	}
	for index := 0; index < len(raw); index++ {
		character := raw[index]
		if character > 127 || !(asciiAlphaNumeric(character) || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func requireID(kind, raw string) error {
	if !validID(raw) {
		return fmt.Errorf("%w: %s", ErrInvalidID, kind)
	}
	return nil
}

type RootKind string

const (
	RootSite    RootKind = "site"
	RootPublic  RootKind = "public"
	RootPrivate RootKind = "private"
	RootLogs    RootKind = "logs"
	RootStaging RootKind = "staging"
)

type SiteRoot struct {
	SiteID SiteID   `json:"site_id"`
	Kind   RootKind `json:"kind"`
}

func (root SiteRoot) Validate() error {
	if err := requireID("site", string(root.SiteID)); err != nil {
		return err
	}
	switch root.Kind {
	case RootSite, RootPublic, RootPrivate, RootLogs, RootStaging:
		return nil
	default:
		return fmt.Errorf("unsupported site root %q", root.Kind)
	}
}

// RelativePath is canonical and cannot name anything above its SiteRoot.
// The empty value names the root itself.
type RelativePath struct{ value string }

func ParseRelativePath(raw string) (RelativePath, error) {
	if len(raw) > 4096 || !utf8.ValidString(raw) || strings.IndexByte(raw, 0) >= 0 || strings.Contains(raw, "\\") || strings.HasPrefix(raw, "/") {
		return RelativePath{}, ErrInvalidPath
	}
	if raw == "" {
		return RelativePath{}, nil
	}
	if path.Clean(raw) != raw || raw == "." {
		return RelativePath{}, ErrInvalidPath
	}
	for _, segment := range strings.Split(raw, "/") {
		if segment == "" || segment == "." || segment == ".." || len(segment) > 255 {
			return RelativePath{}, ErrInvalidPath
		}
	}
	return RelativePath{value: raw}, nil
}

func (value RelativePath) String() string { return value.value }
func (value RelativePath) IsRoot() bool   { return value.value == "" }

func (value RelativePath) Join(name string) (RelativePath, error) {
	if value.value == "" {
		return ParseRelativePath(name)
	}
	return ParseRelativePath(value.value + "/" + name)
}

func (value RelativePath) MarshalJSON() ([]byte, error) { return json.Marshal(value.value) }

func (value *RelativePath) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	parsed, err := ParseRelativePath(raw)
	if err != nil {
		return err
	}
	*value = parsed
	return nil
}

type EntryKind string

const (
	EntryRegular   EntryKind = "regular"
	EntryDirectory EntryKind = "directory"
	EntrySymlink   EntryKind = "symlink"
)

type FileEntry struct {
	Path       RelativePath `json:"path"`
	Kind       EntryKind    `json:"kind"`
	Size       int64        `json:"size"`
	Mode       uint32       `json:"mode"`
	Owner      string       `json:"owner"`
	Group      string       `json:"group"`
	ModifiedAt time.Time    `json:"modified_at"`
	ETag       string       `json:"etag"`
	LinkTarget string       `json:"link_target,omitempty"`
}

type PageRequest struct {
	Limit  uint32 `json:"limit"`
	Cursor string `json:"cursor,omitempty"`
}

func (page PageRequest) normalized() (PageRequest, error) {
	if page.Limit == 0 {
		page.Limit = 200
	}
	if page.Limit > 1000 || len(page.Cursor) > 1024 {
		return PageRequest{}, ErrLimitExceeded
	}
	return page, nil
}

type FilePage struct {
	Entries    []FileEntry `json:"entries"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

type WriteCondition struct {
	IfMatch     string `json:"if_match,omitempty"`
	IfNoneMatch bool   `json:"if_none_match,omitempty"`
}

type Integrity struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

func (integrity Integrity) Validate() error {
	if integrity.Algorithm != "sha256" || integrity.Size < 0 || len(integrity.Digest) != sha256.Size*2 || integrity.Digest != strings.ToLower(integrity.Digest) {
		return ErrIntegrity
	}
	if _, err := hex.DecodeString(integrity.Digest); err != nil {
		return ErrIntegrity
	}
	return nil
}

type OperationState string

const (
	OperationAdmitted   OperationState = "admitted"
	OperationExecuting  OperationState = "executing"
	OperationCommitted  OperationState = "committed"
	OperationFailed     OperationState = "failed"
	OperationCompensated OperationState = "compensated"
)

type ResourceState string

const (
	StatePending   ResourceState = "pending"
	StateActive    ResourceState = "active"
	StateDisabled  ResourceState = "disabled"
	StateDeleting  ResourceState = "deleting"
	StateDeleted   ResourceState = "deleted"
	StateFailed    ResourceState = "failed"
)

func validResourceTransition(from, to ResourceState) bool {
	switch from {
	case StatePending:
		return to == StateActive || to == StateFailed || to == StateDeleting
	case StateActive:
		return to == StateDisabled || to == StateDeleting || to == StateFailed
	case StateDisabled:
		return to == StateActive || to == StateDeleting
	case StateFailed:
		return to == StatePending || to == StateDeleting
	case StateDeleting:
		return to == StateDeleted || to == StateFailed
	default:
		return false
	}
}

type CIDRSet []string

func (set CIDRSet) Validate() error {
	seen := make(map[string]struct{}, len(set))
	for _, raw := range set {
		_, network, err := net.ParseCIDR(raw)
		if err != nil || network.String() != raw {
			return fmt.Errorf("invalid canonical CIDR %q", raw)
		}
		if _, exists := seen[raw]; exists {
			return fmt.Errorf("duplicate CIDR %q", raw)
		}
		seen[raw] = struct{}{}
	}
	return nil
}

type AuditActor struct {
	TenantID    TenantID    `json:"tenant_id"`
	PrincipalID PrincipalID `json:"principal_id"`
	SourceIP    string      `json:"source_ip,omitempty"`
}

func (actor AuditActor) Validate() error {
	if err := requireID("tenant", string(actor.TenantID)); err != nil {
		return err
	}
	if err := requireID("principal", string(actor.PrincipalID)); err != nil {
		return err
	}
	if actor.SourceIP != "" && net.ParseIP(actor.SourceIP) == nil {
		return fmt.Errorf("invalid source IP")
	}
	return nil
}

type Mutation struct {
	CommandID CommandID  `json:"command_id"`
	Actor     AuditActor `json:"actor"`
	At        time.Time  `json:"at"`
}

func (mutation Mutation) Validate() error {
	if err := requireID("command", string(mutation.CommandID)); err != nil {
		return err
	}
	if err := mutation.Actor.Validate(); err != nil {
		return err
	}
	if mutation.At.IsZero() {
		return fmt.Errorf("mutation timestamp is required")
	}
	return nil
}
