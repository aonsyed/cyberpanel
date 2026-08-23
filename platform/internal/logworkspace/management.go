package logworkspace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"time"
)

const (
	lifecycleJournalctlPath   = "/usr/bin/journalctl"
	logrotatePath             = "/usr/sbin/logrotate"
	maximumPlanLifetime       = 10 * time.Minute
	maximumStepUpAge          = 10 * time.Minute
	maximumLifecycleDuration  = 30 * time.Second
	maximumLifecycleStderr    = 32 << 10
	maximumImpactFiles uint32 = 100_000
)

type lifecycleCappedWriter struct {
	data []byte
}

func (writer *lifecycleCappedWriter) Write(value []byte) (int, error) {
	remaining := maximumLifecycleStderr - len(writer.data)
	if remaining > 0 {
		if len(value) < remaining {
			remaining = len(value)
		}
		writer.data = append(writer.data, value[:remaining]...)
	}
	return len(value), nil
}

type LifecycleKind string

const (
	LifecycleRotate    LifecycleKind = "rotate"
	LifecycleRetention LifecycleKind = "retention"
	LifecycleClear     LifecycleKind = "clear"
)

func (kind LifecycleKind) valid() bool {
	return kind == LifecycleRotate || kind == LifecycleRetention || kind == LifecycleClear
}

type RetentionPolicy struct {
	JournalMaxAgeDays uint16 `json:"journal_max_age_days,omitempty"`
}

type ImpactPreview struct {
	SourceID       SourceID `json:"source_id"`
	Generation     uint64   `json:"generation"`
	EstimatedBytes int64    `json:"estimated_bytes"`
	EstimatedFiles uint32   `json:"estimated_files"`
	SystemWide     bool     `json:"system_wide"`
	Irreversible   bool     `json:"irreversible"`
}

func (preview ImpactPreview) valid(source Source, kind LifecycleKind) bool {
	return preview.SourceID == source.ID && preview.Generation == source.Generation && preview.EstimatedBytes >= 0 && preview.EstimatedFiles <= maximumImpactFiles &&
		preview.SystemWide == (source.Backend == BackendJournal) && preview.Irreversible == (kind == LifecycleClear)
}

type LifecyclePlan struct {
	ID                 string          `json:"id"`
	SourceID           SourceID        `json:"source_id"`
	Kind               LifecycleKind   `json:"kind"`
	ExpectedGeneration uint64          `json:"expected_generation"`
	Retention          RetentionPolicy `json:"retention"`
	Impact             ImpactPreview   `json:"impact"`
	CreatedAt          time.Time       `json:"created_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
	Digest             string          `json:"digest"`
}

func lifecyclePlanDigest(plan LifecyclePlan) (string, error) {
	plan.Digest = ""
	encoded, err := json.Marshal(plan)
	if err != nil || len(encoded) > MaximumReceiptJSONBytes {
		return "", ErrLimit
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (plan LifecyclePlan) valid(source Source, now time.Time) bool {
	if !opaquePattern.MatchString(plan.ID) || plan.SourceID != source.ID || !plan.Kind.valid() || plan.ExpectedGeneration != source.Generation || plan.ExpectedGeneration >= MaximumGeneration || source.Protected || plan.CreatedAt.IsZero() || plan.ExpiresAt.IsZero() || plan.ExpiresAt.Sub(plan.CreatedAt) <= 0 || plan.ExpiresAt.Sub(plan.CreatedAt) > maximumPlanLifetime || now.Before(plan.CreatedAt.Add(-time.Minute)) || !now.Before(plan.ExpiresAt) || !plan.Impact.valid(source, plan.Kind) {
		return false
	}
	if source.Backend == BackendJournal {
		if plan.Kind != LifecycleRotate || plan.Retention.JournalMaxAgeDays != 0 {
			return false
		}
	} else if plan.Retention.JournalMaxAgeDays != 0 || source.RotationProfile == "" {
		return false
	}
	digest, err := lifecyclePlanDigest(plan)
	return err == nil && digest == plan.Digest
}

type ImpactInspector interface {
	PreviewLogLifecycle(context.Context, Source, LifecycleKind, RetentionPolicy) (ImpactPreview, error)
	VerifyLogLifecycle(context.Context, Source, LifecyclePlan) error
}

type StepUpGrant struct {
	GrantID    string
	SessionID  string
	VerifiedAt time.Time
	ExpiresAt  time.Time
	AuthzEpoch uint64
}

func (grant StepUpGrant) valid(actor Actor, now time.Time) bool {
	return opaquePattern.MatchString(grant.GrantID) && grant.SessionID == actor.SessionID && grant.AuthzEpoch == actor.AuthzEpoch && !grant.VerifiedAt.IsZero() &&
		!grant.ExpiresAt.IsZero() && !now.Before(grant.VerifiedAt) && now.Sub(grant.VerifiedAt) <= maximumStepUpAge && now.Before(grant.ExpiresAt)
}

type LifecycleAuthorizer interface {
	AuthorizeLogLifecycle(context.Context, Actor, LifecyclePlan, StepUpGrant) error
}

type AuditOutcome string

const (
	AuditStarted AuditOutcome = "started"
	AuditSucceeded AuditOutcome = "succeeded"
	AuditFailed AuditOutcome = "failed"
)

type LifecycleAuditRecord struct {
	PlanID       string
	PlanDigest   string
	SourceID     SourceID
	Generation   uint64
	Kind         LifecycleKind
	ActorID      string
	AuthzEpoch   uint64
	StepUpGrantID string
	Outcome      AuditOutcome
	ReasonCode   string
	ReceiptDigest string
	RecordedAt   time.Time
}

type LifecycleAuditor interface {
	RecordLogLifecycle(context.Context, LifecycleAuditRecord) error
}

type ReceiptStatus string

const (
	ReceiptSucceeded ReceiptStatus = "succeeded"
	ReceiptFailed    ReceiptStatus = "failed"
)

type LifecycleReceipt struct {
	ID               string        `json:"id"`
	PlanID           string        `json:"plan_id"`
	PlanDigest       string        `json:"plan_digest"`
	SourceID         SourceID      `json:"source_id"`
	Kind             LifecycleKind `json:"kind"`
	BeforeGeneration uint64        `json:"before_generation"`
	AfterGeneration  uint64        `json:"after_generation"`
	Status           ReceiptStatus `json:"status"`
	ReasonCode       string        `json:"reason_code"`
	CommandDigest    string        `json:"command_digest"`
	CompletedAt      time.Time     `json:"completed_at"`
	Digest           string        `json:"digest"`
}

func lifecycleReceiptDigest(receipt LifecycleReceipt) (string, error) {
	receipt.Digest = ""
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaximumReceiptJSONBytes {
		return "", ErrLimit
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (receipt LifecycleReceipt) valid() bool {
	if !opaquePattern.MatchString(receipt.ID) || receipt.PlanID != receipt.ID || len(receipt.PlanDigest) != sha256.Size*2 || !opaquePattern.MatchString(string(receipt.SourceID)) || !receipt.Kind.valid() || !opaquePattern.MatchString(receipt.ReasonCode) || receipt.BeforeGeneration == 0 || receipt.BeforeGeneration >= MaximumGeneration || len(receipt.CommandDigest) != sha256.Size*2 || receipt.CompletedAt.IsZero() || receipt.Status != ReceiptSucceeded && receipt.Status != ReceiptFailed {
		return false
	}
	if _, err := hex.DecodeString(receipt.PlanDigest); err != nil {
		return false
	}
	if _, err := hex.DecodeString(receipt.CommandDigest); err != nil {
		return false
	}
	if receipt.Status == ReceiptSucceeded && receipt.AfterGeneration != receipt.BeforeGeneration+1 || receipt.Status == ReceiptFailed && receipt.AfterGeneration != receipt.BeforeGeneration {
		return false
	}
	digest, err := lifecycleReceiptDigest(receipt)
	return err == nil && digest == receipt.Digest
}

type ReceiptStore interface {
	InsertLifecycleReceipt(context.Context, LifecycleReceipt) error
}

type LifecycleManager struct {
	registry   *Registry
	inspector  ImpactInspector
	authorizer LifecycleAuthorizer
	auditor    LifecycleAuditor
	receipts   ReceiptStore
	now        func() time.Time
}

func NewLifecycleManager(registry *Registry, inspector ImpactInspector, authorizer LifecycleAuthorizer, auditor LifecycleAuditor, receipts ReceiptStore) (*LifecycleManager, error) {
	if registry == nil || inspector == nil || authorizer == nil || auditor == nil || receipts == nil {
		return nil, ErrInvalid
	}
	return &LifecycleManager{registry: registry, inspector: inspector, authorizer: authorizer, auditor: auditor, receipts: receipts, now: time.Now}, nil
}

func (manager *LifecycleManager) Plan(ctx context.Context, planID string, sourceID SourceID, kind LifecycleKind, expectedGeneration uint64, retention RetentionPolicy) (LifecyclePlan, error) {
	if manager == nil || ctx == nil || !opaquePattern.MatchString(planID) || !kind.valid() || expectedGeneration == 0 || expectedGeneration >= MaximumGeneration {
		return LifecyclePlan{}, ErrInvalid
	}
	source, err := manager.registry.Resolve(sourceID)
	if err != nil {
		return LifecyclePlan{}, err
	}
	if source.Protected {
		return LifecyclePlan{}, ErrProtected
	}
	// The system journal is a shared security boundary: per-unit vacuuming is not
	// available, so retention and clear must fail closed instead of touching audit data.
	if source.Backend == BackendJournal && kind != LifecycleRotate {
		return LifecyclePlan{}, ErrProtected
	}
	if source.Generation != expectedGeneration {
		return LifecyclePlan{}, ErrConflict
	}
	if source.Backend == BackendJournal {
		if retention.JournalMaxAgeDays != 0 {
			return LifecyclePlan{}, ErrInvalid
		}
	} else if retention.JournalMaxAgeDays != 0 || source.RotationProfile == "" {
		return LifecyclePlan{}, ErrInvalid
	}
	impact, err := manager.inspector.PreviewLogLifecycle(ctx, source, kind, retention)
	if err != nil {
		return LifecyclePlan{}, err
	}
	if !impact.valid(source, kind) {
		return LifecyclePlan{}, ErrIntegrity
	}
	now := manager.now().UTC()
	plan := LifecyclePlan{
		ID: planID, SourceID: source.ID, Kind: kind, ExpectedGeneration: source.Generation,
		Retention: retention, Impact: impact, CreatedAt: now, ExpiresAt: now.Add(maximumPlanLifetime),
	}
	plan.Digest, err = lifecyclePlanDigest(plan)
	if err != nil {
		return LifecyclePlan{}, err
	}
	return plan, nil
}

var fixedProfileConfigurations = map[RotationProfileID]map[LifecycleKind]string{
	"panel": fixedProfilePaths("panel"), "engine": fixedProfilePaths("engine"),
	"site": fixedProfilePaths("site"), "database": fixedProfilePaths("database"),
	"dns": fixedProfilePaths("dns"), "mail": fixedProfilePaths("mail"),
	"ftp": fixedProfilePaths("ftp"), "waf": fixedProfilePaths("waf"),
	"scanner": fixedProfilePaths("scanner"), "container": fixedProfilePaths("container"),
	"operation": fixedProfilePaths("operation"),
}

func fixedProfilePaths(profile string) map[LifecycleKind]string {
	base := "/etc/cyberpanel/logworkspace/" + profile
	return map[LifecycleKind]string{
		LifecycleRotate: base + "-rotate.conf", LifecycleRetention: base + "-retention.conf", LifecycleClear: base + "-clear.conf",
	}
}

func lifecycleCommand(source Source, plan LifecyclePlan) (string, []string, error) {
	if source.Backend == BackendJournal {
		return lifecycleJournalctlPath, []string{"--rotate"}, nil
	}
	configurations, ok := fixedProfileConfigurations[source.RotationProfile]
	configuration, allowed := configurations[plan.Kind]
	if !ok || !allowed {
		return "", nil, ErrProtected
	}
	return logrotatePath, []string{"--force", configuration}, nil
}

func commandDigest(path string, arguments []string) string {
	hash := sha256.New()
	hash.Write([]byte(path))
	for _, argument := range arguments {
		hash.Write([]byte{0})
		hash.Write([]byte(argument))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (manager *LifecycleManager) Execute(ctx context.Context, actor Actor, plan LifecyclePlan, grant StepUpGrant) (LifecycleReceipt, error) {
	if manager == nil || ctx == nil || !actor.valid() {
		return LifecycleReceipt{}, ErrInvalid
	}
	if runtime.GOOS != "linux" {
		return LifecycleReceipt{}, ErrProtected
	}
	now := manager.now().UTC()
	source, err := manager.registry.Resolve(plan.SourceID)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	if source.Protected {
		return LifecycleReceipt{}, ErrProtected
	}
	if !plan.valid(source, now) {
		if source.Generation != plan.ExpectedGeneration {
			return LifecycleReceipt{}, ErrConflict
		}
		return LifecycleReceipt{}, ErrIntegrity
	}
	if err = manager.inspector.VerifyLogLifecycle(ctx, source, plan); err != nil {
		return LifecycleReceipt{}, ErrConflict
	}
	if !grant.valid(actor, now) || manager.authorizer.AuthorizeLogLifecycle(ctx, actor, plan, grant) != nil {
		return LifecycleReceipt{}, ErrUnauthorized
	}
	path, arguments, err := lifecycleCommand(source, plan)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	commandHash := commandDigest(path, arguments)
	started := LifecycleAuditRecord{
		PlanID: plan.ID, PlanDigest: plan.Digest, SourceID: source.ID, Generation: source.Generation,
		Kind: plan.Kind, ActorID: actor.SubjectID, AuthzEpoch: actor.AuthzEpoch, StepUpGrantID: grant.GrantID,
		Outcome: AuditStarted, ReasonCode: "authorized", RecordedAt: now,
	}
	if err = manager.auditor.RecordLogLifecycle(ctx, started); err != nil {
		return LifecycleReceipt{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, maximumLifecycleDuration)
	defer cancel()
	command := exec.CommandContext(operationContext, path, arguments...)
	command.Dir = "/"
	command.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin"}
	command.Stdout = io.Discard
	command.Stderr = &lifecycleCappedWriter{}
	runErr := command.Run()
	status := ReceiptSucceeded
	reason := "completed"
	afterGeneration := source.Generation + 1
	if runErr != nil {
		status = ReceiptFailed
		reason = "operation_failed"
		afterGeneration = source.Generation
	} else if err = manager.registry.CompareAndSwapGeneration(source.ID, source.Generation, afterGeneration); err != nil {
		status = ReceiptFailed
		reason = "generation_conflict"
		runErr = err
		afterGeneration = source.Generation
	}
	receipt := LifecycleReceipt{
		ID: plan.ID, PlanID: plan.ID, PlanDigest: plan.Digest, SourceID: source.ID, Kind: plan.Kind,
		BeforeGeneration: source.Generation, AfterGeneration: afterGeneration, Status: status,
		ReasonCode: reason, CommandDigest: commandHash, CompletedAt: manager.now().UTC(),
	}
	receipt.Digest, err = lifecycleReceiptDigest(receipt)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	if err = manager.receipts.InsertLifecycleReceipt(ctx, receipt); err != nil {
		return LifecycleReceipt{}, err
	}
	outcome := AuditSucceeded
	if status == ReceiptFailed {
		outcome = AuditFailed
	}
	auditErr := manager.auditor.RecordLogLifecycle(ctx, LifecycleAuditRecord{
		PlanID: plan.ID, PlanDigest: plan.Digest, SourceID: source.ID, Generation: afterGeneration,
		Kind: plan.Kind, ActorID: actor.SubjectID, AuthzEpoch: actor.AuthzEpoch, StepUpGrantID: grant.GrantID,
		Outcome: outcome, ReasonCode: reason, ReceiptDigest: receipt.Digest, RecordedAt: receipt.CompletedAt,
	})
	if runErr != nil {
		return receipt, errors.Join(fmt.Errorf("log lifecycle operation: %w", ErrIntegrity), auditErr)
	}
	if auditErr != nil {
		return receipt, auditErr
	}
	return receipt, nil
}
