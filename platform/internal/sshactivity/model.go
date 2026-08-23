package sshactivity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid      = errors.New("ssh activity: invalid input")
	ErrUnauthorized = errors.New("ssh activity: unauthorized")
	ErrNotFound     = errors.New("ssh activity: not found")
	ErrConflict     = errors.New("ssh activity: revision conflict")
	ErrLimit        = errors.New("ssh activity: bounded limit exceeded")
	ErrIntegrity    = errors.New("ssh activity: evidence integrity failure")
	ErrProtected    = errors.New("ssh activity: protected target")
)

const (
	MaximumEvents             = 5_000
	MaximumScanRecords        = 10_000
	MaximumSessions           = 512
	MaximumQueryBytes   int64 = 8 << 20
	MaximumRecordBytes        = 64 << 10
	MaximumQueryDuration      = 20 * time.Second
	MaximumQueryWindow        = 31 * 24 * time.Hour
	MaximumCursorBytes        = 4 << 10
	MaximumRelatedCursors     = 128
	MaximumRiskFindings       = 1_024
	MaximumRepositoryPage     = 100
	MaximumMetadataJSON       = 32 << 10
	MaximumRiskJSON           = 128 << 10
	MaximumPlanJSON           = 128 << 10
	MaximumReceiptJSON        = 64 << 10
	MaximumRevision    uint64 = 1<<63 - 1
)

var (
	opaquePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)
	userPattern        = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$`)
	fingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{16,96}={0,2}$`)
)

type EventID string
type SourceID string
type UserID string
type KeyID string
type SessionID string
type PlanID string
type IncidentID string

func validOpaque(value string) bool { return opaquePattern.MatchString(value) }

func digestParts(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type BootIdentity struct {
	BootID string `json:"boot_id"`
}

func (identity BootIdentity) valid() bool {
	return len(identity.BootID) >= 16 && len(identity.BootID) <= 64 && validOpaque(identity.BootID)
}

type ProcessIdentity struct {
	PID            uint32       `json:"pid"`
	StartTimeTicks uint64       `json:"start_time_ticks"`
	Boot           BootIdentity `json:"boot"`
}

func (identity ProcessIdentity) valid() bool {
	return identity.PID > 1 && identity.StartTimeTicks > 0 && identity.Boot.valid()
}

type ProcessSnapshot struct {
	Identity       ProcessIdentity `json:"identity"`
	ParentPID      uint32          `json:"parent_pid"`
	EffectiveUID   uint32          `json:"effective_uid"`
	Command        string          `json:"command"`
	ArgumentsDigest string         `json:"arguments_digest,omitempty"`
}

func (snapshot ProcessSnapshot) valid() bool {
	return snapshot.Identity.valid() && snapshot.ParentPID > 0 && len(snapshot.Command) > 0 && len(snapshot.Command) <= 128 &&
		(snapshot.ArgumentsDigest == "" || validDigest(snapshot.ArgumentsDigest))
}

type SourceIdentity struct {
	Address netip.Addr `json:"address"`
	Port    uint16     `json:"port,omitempty"`
}

func (identity SourceIdentity) valid() bool {
	return identity.Address.IsValid() && !identity.Address.IsUnspecified()
}

type UserIdentity struct {
	ID                UserID `json:"id"`
	Name              string `json:"name"`
	UID               uint32 `json:"uid,omitempty"`
	AccountGeneration uint64 `json:"account_generation,omitempty"`
	Exists            bool   `json:"exists"`
	Disabled          bool   `json:"disabled"`
	Privileged        bool   `json:"privileged"`
}

func (identity UserIdentity) valid() bool {
	if !userPattern.MatchString(identity.Name) || !validOpaque(string(identity.ID)) {
		return false
	}
	if !identity.Exists {
		return identity.UID == 0 && identity.AccountGeneration == 0 && !identity.Disabled && !identity.Privileged
	}
	return identity.AccountGeneration > 0 && identity.AccountGeneration <= MaximumRevision && identity.Privileged == (identity.UID == 0 || identity.Name == "root")
}

type KeyIdentity struct {
	ID                 KeyID  `json:"id"`
	Fingerprint        string `json:"fingerprint"`
	Algorithm          string `json:"algorithm"`
	RegistryGeneration uint64 `json:"registry_generation,omitempty"`
	Known              bool   `json:"known"`
	Revoked            bool   `json:"revoked"`
}

func (identity KeyIdentity) valid() bool {
	if !validOpaque(string(identity.ID)) || !fingerprintPattern.MatchString(identity.Fingerprint) || !validOpaque(identity.Algorithm) {
		return false
	}
	return identity.Known == (identity.RegistryGeneration > 0) && identity.RegistryGeneration <= MaximumRevision && (!identity.Revoked || identity.Known)
}

type AuthenticationMethod string

const (
	MethodPublicKey           AuthenticationMethod = "public_key"
	MethodCertificate         AuthenticationMethod = "certificate"
	MethodPassword            AuthenticationMethod = "password"
	MethodKeyboardInteractive AuthenticationMethod = "keyboard_interactive"
	MethodHostBased           AuthenticationMethod = "host_based"
	MethodUnknown             AuthenticationMethod = "unknown"
)

func (method AuthenticationMethod) valid() bool {
	switch method {
	case MethodPublicKey, MethodCertificate, MethodPassword, MethodKeyboardInteractive, MethodHostBased, MethodUnknown:
		return true
	default:
		return false
	}
}

type AssuranceLevel string

const (
	AssuranceUnknown  AssuranceLevel = "unknown"
	AssuranceSingle   AssuranceLevel = "single_factor"
	AssuranceMultiple AssuranceLevel = "multi_factor"
	AssuranceHardware AssuranceLevel = "hardware_backed"
)

type AssuranceIdentity struct {
	Level        AssuranceLevel `json:"level"`
	PolicyID     string         `json:"policy_id,omitempty"`
	Factors      uint8          `json:"factors"`
	ClassifiedAt time.Time      `json:"classified_at"`
}

func (identity AssuranceIdentity) valid() bool {
	if identity.ClassifiedAt.IsZero() || identity.PolicyID != "" && !validOpaque(identity.PolicyID) {
		return false
	}
	switch identity.Level {
	case AssuranceUnknown:
		return identity.Factors == 0
	case AssuranceSingle:
		return identity.Factors == 1
	case AssuranceMultiple, AssuranceHardware:
		return identity.Factors >= 2 && identity.Factors <= 8
	default:
		return false
	}
}

type AuthenticationOutcome string

const (
	OutcomeSucceeded AuthenticationOutcome = "succeeded"
	OutcomeFailed    AuthenticationOutcome = "failed"
)

type EvidenceCompleteness string

const (
	EvidenceComplete EvidenceCompleteness = "complete"
	EvidencePartial  EvidenceCompleteness = "partial"
)

type EvidenceIntegrity struct {
	SourceID     SourceID             `json:"source_id"`
	SourceDigest string               `json:"source_digest"`
	RecordDigest string               `json:"record_digest"`
	Parser       string               `json:"parser"`
	Completeness EvidenceCompleteness `json:"completeness"`
	ObservedAt   time.Time            `json:"observed_at"`
}

func (evidence EvidenceIntegrity) valid() bool {
	return validOpaque(string(evidence.SourceID)) && validDigest(evidence.SourceDigest) && validDigest(evidence.RecordDigest) && validOpaque(evidence.Parser) &&
		(evidence.Completeness == EvidenceComplete || evidence.Completeness == EvidencePartial) && !evidence.ObservedAt.IsZero()
}

type AuthenticationEvent struct {
	ID        EventID               `json:"id"`
	Cursor    string                `json:"cursor"`
	At        time.Time             `json:"at"`
	Outcome   AuthenticationOutcome `json:"outcome"`
	Source    SourceIdentity        `json:"source"`
	User      UserIdentity          `json:"user"`
	Key       *KeyIdentity          `json:"key,omitempty"`
	Method    AuthenticationMethod  `json:"method"`
	Assurance AssuranceIdentity     `json:"assurance"`
	Process   *ProcessIdentity      `json:"process,omitempty"`
	Boot      BootIdentity          `json:"boot"`
	Evidence  EvidenceIntegrity     `json:"evidence"`
}

func (event AuthenticationEvent) valid() bool {
	if !validOpaque(string(event.ID)) || event.Cursor == "" || len(event.Cursor) > MaximumCursorBytes || event.At.IsZero() || event.Outcome != OutcomeSucceeded && event.Outcome != OutcomeFailed || !event.Source.valid() || !event.User.valid() || !event.Method.valid() || !event.Assurance.valid() || !event.Boot.valid() || !event.Evidence.valid() {
		return false
	}
	if event.Process != nil && (!event.Process.valid() || event.Process.Boot != event.Boot) {
		return false
	}
	if event.Key != nil && !event.Key.valid() || event.Key == nil && (event.Method == MethodPublicKey || event.Method == MethodCertificate) {
		return false
	}
	return event.Evidence.ObservedAt.Equal(event.At) || event.Evidence.ObservedAt.After(event.At)
}

type SessionIdentity struct {
	ID        SessionID       `json:"id"`
	Boot      BootIdentity    `json:"boot"`
	StartedAt time.Time       `json:"started_at"`
	Leader    *ProcessIdentity `json:"leader,omitempty"`
}

func (identity SessionIdentity) valid() bool {
	return validOpaque(string(identity.ID)) && identity.Boot.valid() && !identity.StartedAt.IsZero() && (identity.Leader == nil || identity.Leader.valid() && identity.Leader.Boot == identity.Boot)
}

type ActiveSession struct {
	Identity       SessionIdentity   `json:"identity"`
	User           UserIdentity      `json:"user"`
	Source         SourceIdentity    `json:"source"`
	TTY            string            `json:"tty,omitempty"`
	State          string            `json:"state"`
	LastActivityAt time.Time         `json:"last_activity_at"`
	Leader         *ProcessSnapshot  `json:"leader,omitempty"`
	Evidence       EvidenceIntegrity `json:"evidence"`
}

func (session ActiveSession) valid() bool {
	return session.Identity.valid() && session.User.valid() && session.Source.valid() && len(session.TTY) <= 64 && validOpaque(session.State) && !session.LastActivityAt.Before(session.Identity.StartedAt) &&
		(session.Leader == nil) == (session.Identity.Leader == nil) &&
		(session.Leader == nil || session.Leader.valid() && session.Leader.Identity == *session.Identity.Leader) && session.Evidence.valid()
}

type GapCode string

const (
	GapSourceUnavailable GapCode = "source_unavailable"
	GapTruncated         GapCode = "bounded_truncation"
	GapRotated           GapCode = "cursor_rotated"
	GapParserRejected    GapCode = "parser_rejected"
	GapIdentityUnknown   GapCode = "identity_unknown"
	GapClockUncertain    GapCode = "clock_uncertain"
)

type ObservationGap struct {
	Code       GapCode  `json:"code"`
	SourceID   SourceID `json:"source_id"`
	Count      uint32   `json:"count"`
	FirstAt    time.Time `json:"first_at,omitempty"`
	LastAt     time.Time `json:"last_at,omitempty"`
	EvidenceDigest string `json:"evidence_digest,omitempty"`
}

func (gap ObservationGap) valid() bool {
	switch gap.Code {
	case GapSourceUnavailable, GapTruncated, GapRotated, GapParserRejected, GapIdentityUnknown, GapClockUncertain:
	default:
		return false
	}
	return validOpaque(string(gap.SourceID)) && gap.Count > 0 && (gap.EvidenceDigest == "" || validDigest(gap.EvidenceDigest))
}

type AuthenticationQuery struct {
	Start       time.Time
	End         time.Time
	Source      *netip.Prefix
	UserName    string
	Outcome     AuthenticationOutcome
	Cursor      string
	Limit       uint32
	ScanLimit   uint32
	MaximumBytes int64
	Duration    time.Duration
}

func (query AuthenticationQuery) Validate() error {
	if query.Start.IsZero() || !query.End.After(query.Start) || query.End.Sub(query.Start) > MaximumQueryWindow || query.Limit == 0 || query.Limit > MaximumEvents || query.ScanLimit < query.Limit || query.ScanLimit > MaximumScanRecords || query.MaximumBytes <= 0 || query.MaximumBytes > MaximumQueryBytes || query.Duration <= 0 || query.Duration > MaximumQueryDuration || len(query.Cursor) > MaximumCursorBytes {
		return ErrInvalid
	}
	if query.Source != nil && (!query.Source.IsValid() || query.Source.Bits() == 0) || query.UserName != "" && !userPattern.MatchString(query.UserName) || query.Outcome != "" && query.Outcome != OutcomeSucceeded && query.Outcome != OutcomeFailed {
		return ErrInvalid
	}
	return nil
}

type SessionQuery struct {
	Limit    uint16
	Duration time.Duration
}

func (query SessionQuery) Validate() error {
	if query.Limit == 0 || query.Limit > MaximumSessions || query.Duration <= 0 || query.Duration > MaximumQueryDuration {
		return ErrInvalid
	}
	return nil
}

type Actor struct {
	SubjectID        string
	SessionID        string
	AuthzEpoch       uint64
	RecoverySession  SessionID
	RecoveryProcess  *ProcessIdentity
}

func (actor Actor) valid() bool {
	return validOpaque(actor.SubjectID) && validOpaque(actor.SessionID) && actor.AuthzEpoch > 0 && (actor.RecoverySession == "" || validOpaque(string(actor.RecoverySession))) && (actor.RecoveryProcess == nil || actor.RecoveryProcess.valid())
}

type ObservationAuthorizer interface {
	AuthorizeSSHAuthenticationQuery(context.Context, Actor, AuthenticationQuery) error
	AuthorizeSSHSessionQuery(context.Context, Actor, SessionQuery) error
}

type IdentityResolver interface {
	ResolveSSHUser(context.Context, string, time.Time) (UserIdentity, error)
	ResolveSSHKey(context.Context, string, string, time.Time) (KeyIdentity, error)
	ClassifySSHAssurance(context.Context, UserIdentity, *KeyIdentity, AuthenticationMethod, time.Time) (AssuranceIdentity, error)
}

type AuthenticationSink interface {
	WriteAuthenticationEvent(context.Context, AuthenticationEvent) error
	WriteObservationGap(context.Context, ObservationGap) error
	CloseAuthenticationQuery(context.Context, AuthenticationSummary) error
}

type SessionSink interface {
	WriteActiveSession(context.Context, ActiveSession) error
	WriteObservationGap(context.Context, ObservationGap) error
	CloseSessionQuery(context.Context, SessionSummary) error
}

type AuthenticationSummary struct {
	Events      uint32
	Scanned     uint32
	Bytes       int64
	NextCursor  string
	Truncated   bool
	Rejected    uint32
}

type SessionSummary struct {
	Sessions  uint16
	Scanned   uint16
	Truncated bool
}

type Observer interface {
	QueryAuthentication(context.Context, Actor, AuthenticationQuery, AuthenticationSink) (AuthenticationSummary, error)
	QuerySessions(context.Context, Actor, SessionQuery, SessionSink) (SessionSummary, error)
}

func stableEvents(events []AuthenticationEvent) []AuthenticationEvent {
	result := append([]AuthenticationEvent(nil), events...)
	sort.Slice(result, func(left, right int) bool {
		if !result[left].At.Equal(result[right].At) {
			return result[left].At.Before(result[right].At)
		}
		return strings.Compare(string(result[left].ID), string(result[right].ID)) < 0
	})
	return result
}
