package webmaildata

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	maildata "github.com/aonsyed/cyberpanel/platform/internal/mail"
)

type Operation string

const (
	OperationContactInspect Operation = "contact.inspect"
	OperationContactList    Operation = "contact.list"
	OperationContactCreate  Operation = "contact.create"
	OperationContactUpdate  Operation = "contact.update"
	OperationContactMerge   Operation = "contact.merge"
	OperationContactDelete  Operation = "contact.delete"
	OperationContactPurge   Operation = "contact.tombstone.purge"
	OperationContactImport  Operation = "contact.import"
	OperationContactExport  Operation = "contact.export"
	OperationGroupInspect   Operation = "group.inspect"
	OperationGroupList      Operation = "group.list"
	OperationGroupCreate    Operation = "group.create"
	OperationGroupUpdate    Operation = "group.update"
	OperationGroupPopulate  Operation = "group.populate"
	OperationGroupDelete    Operation = "group.delete"
	OperationSettingsRead   Operation = "settings.read"
	OperationSettingsWrite  Operation = "settings.write"
	OperationSieveRead      Operation = "sieve.read"
	OperationSieveWrite     Operation = "sieve.write"
	OperationSieveRedirect  Operation = "sieve.redirect"
	OperationSieveDiscard   Operation = "sieve.discard"
	OperationSieveTest      Operation = "sieve.test"
	OperationBackupExport   Operation = "settings.backup.export"
	OperationBackupRestore  Operation = "settings.backup.restore"
	OperationBackupMigrate  Operation = "settings.backup.migrate"
)

type Call struct {
	ActorID     string
	OperationID string
	Scope       Scope
	StepUpProof string
}

type AuthorizationRequest struct { ActorID string; Operation Operation; Scope Scope; ResourceID string }
type Authorizer interface { AuthorizeWebmailData(context.Context, AuthorizationRequest) error }
type StepUpVerifier interface { VerifyWebmailDataStepUp(context.Context, string, Scope, string) error }

type AuditEvent struct {
	OperationID string    `json:"operation_id"`
	ActorID     string    `json:"actor_id"`
	Operation   Operation `json:"operation"`
	Scope       Scope     `json:"scope"`
	ResourceID  string    `json:"resource_id,omitempty"`
	Before      uint64    `json:"before_revision,omitempty"`
	After       uint64    `json:"after_revision,omitempty"`
	Digest      string    `json:"digest,omitempty"`
	OccurredAt  time.Time `json:"occurred_at"`
}

type AuditSink interface { RecordWebmailData(context.Context, AuditEvent) error }
type ForwardingPolicy interface { AuthorizeSieveRedirect(context.Context, Scope, string) error }
type AutoresponderResolver interface { ResolveAutoresponder(context.Context, Scope, maildata.AutoresponderID, uint64) (maildata.AutoresponderRule, error) }

type Repository interface {
	PutContact(context.Context, Contact, uint64) error
	GetContact(context.Context, Scope, string) (Contact, error)
	FindContactByAddress(context.Context, Scope, string) (Contact, error)
	ListContacts(context.Context, ContactQuery) (ContactPage, error)
	DeleteContact(context.Context, Scope, string, uint64, time.Time, time.Time, string) error
	PurgeExpiredContactTombstones(context.Context, Scope, time.Time, int) (int, error)
	MergeContacts(context.Context, Contact, uint64, string, uint64, time.Time) error
	PutGroup(context.Context, ContactGroup, uint64) error
	GetGroup(context.Context, Scope, string) (ContactGroup, error)
	ListGroups(context.Context, Scope, string, int) ([]ContactGroup, string, error)
	PutPreferences(context.Context, WebmailPreferences, uint64) error
	GetPreferences(context.Context, Scope) (WebmailPreferences, error)
	PutSieveRule(context.Context, SieveRule, uint64) error
	GetSieveRule(context.Context, Scope, string) (SieveRule, error)
	ListSieveRules(context.Context, Scope) ([]SieveRule, error)
	ReplaceSieveRulesCAS(context.Context, Scope, []SieveRule, map[string]uint64) error
	NextSieveGeneration(context.Context, Scope) (uint64, error)
	StageSieveGeneration(context.Context, SieveProgram) error
	GetSieveProgram(context.Context, Scope, uint64) (SieveProgram, error)
	ActiveSieve(context.Context, Scope) (SieveActivation, error)
	ActivateSieveCAS(context.Context, SieveActivation, string) error
}

type Service struct {
	Repository      Repository
	Authorizer      Authorizer
	StepUp          StepUpVerifier
	Audit           AuditSink
	SieveRuntime    ManageSieveRuntime
	Forwarding      ForwardingPolicy
	Autoresponders  AutoresponderResolver
	ExpertParser    ExpertSieveParser
	Now             func() time.Time
}

func (service *Service) CreateContact(ctx context.Context, call Call, contact Contact) (Contact, error) {
	if err := service.ready(call); err != nil { return Contact{}, err }
	if err := service.authorize(ctx, call, OperationContactCreate, contact.ID, false); err != nil { return Contact{}, err }
	now := service.now(); contact.Scope = call.Scope; contact.Revision = 1; contact.Lifecycle = LifecycleActive; contact.CreatedAt = now; contact.UpdatedAt = now
	normalized, err := NormalizeContact(contact)
	if err != nil { return Contact{}, err }
	if err = service.Repository.PutContact(ctx, normalized, 0); err != nil { return Contact{}, err }
	if err = service.audit(ctx, call, OperationContactCreate, normalized.ID, 0, 1, ""); err != nil { return Contact{}, err }
	return normalized, nil
}

func (service *Service) InspectContact(ctx context.Context, call Call, id string) (Contact, error) {
	if err := service.ready(call); err != nil { return Contact{}, err }
	if err := service.authorize(ctx, call, OperationContactInspect, id, false); err != nil { return Contact{}, err }
	return service.Repository.GetContact(ctx, call.Scope, id)
}

func (service *Service) ListContacts(ctx context.Context, call Call, search, cursor string, limit int) (ContactPage, error) {
	if err := service.ready(call); err != nil { return ContactPage{}, err }
	if err := service.authorize(ctx, call, OperationContactList, "", false); err != nil { return ContactPage{}, err }
	return service.Repository.ListContacts(ctx, ContactQuery{Scope: call.Scope, Search: search, Cursor: cursor, Limit: limit})
}

var contactUpdateFields = map[string]bool{"display_name": true, "given_name": true, "family_name": true, "organization": true, "notes": true, "addresses": true, "phones": true, "metadata": true}

func (service *Service) UpdateContact(ctx context.Context, call Call, id string, expected uint64, patch Contact, mask FieldMask) (Contact, error) {
	if err := service.ready(call); err != nil || !mask.Valid(contactUpdateFields) { if err != nil { return Contact{}, err }; return Contact{}, ErrInvalid }
	if err := service.authorize(ctx, call, OperationContactUpdate, id, false); err != nil { return Contact{}, err }
	current, err := service.Repository.GetContact(ctx, call.Scope, id)
	if err != nil { return Contact{}, err }
	if current.Revision != expected || expected >= MaximumRevision { return Contact{}, ErrConflict }
	for _, field := range mask {
		switch field {
		case "display_name": current.DisplayName = patch.DisplayName
		case "given_name": current.GivenName = patch.GivenName
		case "family_name": current.FamilyName = patch.FamilyName
		case "organization": current.Organization = patch.Organization
		case "notes": current.Notes = patch.Notes
		case "addresses": current.Addresses = append([]LabeledAddress(nil), patch.Addresses...)
		case "phones": current.Phones = append([]LabeledPhone(nil), patch.Phones...)
		case "metadata": current.Metadata = append([]MetadataField(nil), patch.Metadata...)
		}
	}
	current.Revision++; current.UpdatedAt = service.now()
	current, err = NormalizeContact(current)
	if err != nil { return Contact{}, err }
	if err = service.Repository.PutContact(ctx, current, expected); err != nil { return Contact{}, err }
	if err = service.audit(ctx, call, OperationContactUpdate, id, expected, current.Revision, ""); err != nil { return Contact{}, err }
	return current, nil
}

type MergeContactRequest struct { TargetID string; TargetRevision uint64; SourceID string; SourceRevision uint64; PreferSource FieldMask; RetainFor time.Duration }

func (service *Service) MergeContacts(ctx context.Context, call Call, request MergeContactRequest) (Contact, error) {
	if err := service.ready(call); err != nil { return Contact{}, err }
	if !request.PreferSource.Valid(contactUpdateFields) || request.RetainFor < 24*time.Hour || request.RetainFor > 10*365*24*time.Hour { return Contact{}, ErrInvalid }
	if err := service.authorize(ctx, call, OperationContactMerge, request.TargetID, false); err != nil { return Contact{}, err }
	target, err := service.Repository.GetContact(ctx, call.Scope, request.TargetID)
	if err != nil { return Contact{}, err }
	source, err := service.Repository.GetContact(ctx, call.Scope, request.SourceID)
	if err != nil { return Contact{}, err }
	if target.Revision != request.TargetRevision || source.Revision != request.SourceRevision { return Contact{}, ErrConflict }
	merged := mergeContactValues(target, source, request.PreferSource)
	merged.Revision++; merged.UpdatedAt = service.now()
	merged, err = NormalizeContact(merged)
	if err != nil { return Contact{}, err }
	if err = service.Repository.MergeContacts(ctx, merged, target.Revision, source.ID, source.Revision, merged.UpdatedAt.Add(request.RetainFor)); err != nil { return Contact{}, err }
	if err = service.audit(ctx, call, OperationContactMerge, target.ID, target.Revision, merged.Revision, addressDigest(source.ID)); err != nil { return Contact{}, err }
	return merged, nil
}

func (service *Service) DeleteContact(ctx context.Context, call Call, id string, expected uint64, retainFor time.Duration) error {
	if err := service.ready(call); err != nil { return err }
	if retainFor < 24*time.Hour || retainFor > 10*365*24*time.Hour { return ErrInvalid }
	if err := service.authorize(ctx, call, OperationContactDelete, id, false); err != nil { return err }
	now := service.now()
	if err := service.Repository.DeleteContact(ctx, call.Scope, id, expected, now.Add(retainFor), now, "privacy_retention"); err != nil { return err }
	return service.audit(ctx, call, OperationContactDelete, id, expected, expected+1, "")
}

func (service *Service) PurgeExpiredContactTombstones(ctx context.Context, call Call, before time.Time, limit int) (int, error) {
	if err := service.ready(call); err != nil { return 0, err }
	if before.After(service.now()) { return 0, ErrInvalid }
	if err := service.authorize(ctx, call, OperationContactPurge, "", false); err != nil { return 0, err }
	count, err := service.Repository.PurgeExpiredContactTombstones(ctx, call.Scope, before, limit)
	if err != nil { return 0, err }
	return count, service.audit(ctx, call, OperationContactPurge, "", 0, uint64(count), digestCounts(count))
}

func (service *Service) ImportContacts(ctx context.Context, call Call, request ImportRequest) (ImportResult, error) {
	if err := service.ready(call); err != nil { return ImportResult{}, err }
	if err := service.authorize(ctx, call, OperationContactImport, "", false); err != nil { return ImportResult{}, err }
	request.Scope = call.Scope
	result, err := StreamImportContacts(ctx, request, func(ctx context.Context, contact Contact, policy DuplicatePolicy) (bool, error) {
		err := service.Repository.PutContact(ctx, contact, 0)
		if !errors.Is(err, ErrDuplicate) { return err == nil, err }
		if policy == DuplicateReject { return false, ErrDuplicate }
		if policy == DuplicateSkip { return false, nil }
		var duplicate Contact
		for _, address := range contact.Addresses { duplicate, err = service.Repository.FindContactByAddress(ctx, call.Scope, address.Normalized); if err == nil { break } }
		if err != nil { return false, err }
		merged := mergeContactValues(duplicate, contact, FieldMask{"display_name", "given_name", "family_name", "organization", "notes", "addresses", "phones", "metadata"})
		merged.ID = duplicate.ID; merged.Scope = duplicate.Scope; merged.CreatedAt = duplicate.CreatedAt; merged.Revision = duplicate.Revision + 1; merged.UpdatedAt = service.now()
		merged, err = NormalizeContact(merged)
		if err != nil { return false, err }
		return true, service.Repository.PutContact(ctx, merged, duplicate.Revision)
	})
	if err != nil { return result, err }
	if !request.PreviewOnly { err = service.audit(ctx, call, OperationContactImport, "", 0, uint64(result.Committed), digestCounts(result.RowsSeen, result.Committed, result.Failed)) }
	return result, err
}

func (service *Service) ExportContacts(ctx context.Context, call Call, format InterchangeFormat, writer io.Writer, limits StreamLimits) (int, int64, error) {
	if err := service.ready(call); err != nil { return 0, 0, err }
	if err := service.authorize(ctx, call, OperationContactExport, "", true); err != nil { return 0, 0, err }
	count, bytes, err := StreamExportContacts(ctx, service.Repository, call.Scope, format, writer, limits)
	if err == nil { err = service.audit(ctx, call, OperationContactExport, "", 0, uint64(count), digestCounts(count, int(bytes), 0)) }
	return count, bytes, err
}

func (service *Service) SaveGroup(ctx context.Context, call Call, group ContactGroup, expected uint64) (ContactGroup, error) {
	if err := service.ready(call); err != nil { return ContactGroup{}, err }
	operation := OperationGroupCreate; if expected != 0 { operation = OperationGroupUpdate }; if len(group.ContactIDs)+len(group.Recipients) > 0 { operation = OperationGroupPopulate }
	if err := service.authorize(ctx, call, operation, group.ID, false); err != nil { return ContactGroup{}, err }
	now := service.now(); group.Scope = call.Scope; group.Revision = expected+1; group.Lifecycle = LifecycleActive; group.UpdatedAt = now; if expected == 0 { group.CreatedAt = now } else { current, err := service.Repository.GetGroup(ctx, call.Scope, group.ID); if err != nil { return ContactGroup{}, err }; if current.Revision != expected { return ContactGroup{}, ErrConflict }; group.CreatedAt = current.CreatedAt }
	normalized, err := NormalizeGroup(group)
	if err != nil { return ContactGroup{}, err }
	if err = service.Repository.PutGroup(ctx, normalized, expected); err != nil { return ContactGroup{}, err }
	if err = service.audit(ctx, call, operation, normalized.ID, expected, normalized.Revision, ""); err != nil { return ContactGroup{}, err }
	return normalized, nil
}

func (service *Service) InspectGroup(ctx context.Context, call Call, id string) (ContactGroup, error) {
	if err := service.ready(call); err != nil { return ContactGroup{}, err }
	if err := service.authorize(ctx, call, OperationGroupInspect, id, false); err != nil { return ContactGroup{}, err }
	return service.Repository.GetGroup(ctx, call.Scope, id)
}

func (service *Service) ListGroups(ctx context.Context, call Call, after string, limit int) ([]ContactGroup, string, error) {
	if err := service.ready(call); err != nil { return nil, "", err }
	if err := service.authorize(ctx, call, OperationGroupList, "", false); err != nil { return nil, "", err }
	return service.Repository.ListGroups(ctx, call.Scope, after, limit)
}

func (service *Service) DeleteGroup(ctx context.Context, call Call, id string, expected uint64) error {
	if err := service.ready(call); err != nil { return err }
	if err := service.authorize(ctx, call, OperationGroupDelete, id, false); err != nil { return err }
	group, err := service.Repository.GetGroup(ctx, call.Scope, id)
	if err != nil { return err }
	if group.Revision != expected { return ErrConflict }
	group.Revision++; group.Lifecycle = LifecycleDeleted; group.Name = "deleted-" + group.ID + "-" + addressDigest(group.Name)[:12]; group.ContactIDs = nil; group.Recipients = nil; group.UpdatedAt = service.now()
	if err = service.Repository.PutGroup(ctx, group, expected); err != nil { return err }
	return service.audit(ctx, call, OperationGroupDelete, id, expected, group.Revision, "")
}

func (service *Service) GetPreferences(ctx context.Context, call Call) (WebmailPreferences, error) {
	if err := service.ready(call); err != nil { return WebmailPreferences{}, err }
	if err := service.authorize(ctx, call, OperationSettingsRead, "preferences", false); err != nil { return WebmailPreferences{}, err }
	return service.Repository.GetPreferences(ctx, call.Scope)
}

func (service *Service) SavePreferences(ctx context.Context, call Call, value WebmailPreferences, expected uint64) (WebmailPreferences, error) {
	if err := service.ready(call); err != nil { return WebmailPreferences{}, err }
	if err := service.authorize(ctx, call, OperationSettingsWrite, "preferences", false); err != nil { return WebmailPreferences{}, err }
	value.Scope = call.Scope; value.Revision = expected+1; value.UpdatedAt = service.now()
	normalized, err := NormalizePreferences(value)
	if err != nil { return WebmailPreferences{}, err }
	if err = service.Repository.PutPreferences(ctx, normalized, expected); err != nil { return WebmailPreferences{}, err }
	if err = service.audit(ctx, call, OperationSettingsWrite, "preferences", expected, normalized.Revision, ""); err != nil { return WebmailPreferences{}, err }
	return normalized, nil
}

func (service *Service) SaveSieveRule(ctx context.Context, call Call, rule SieveRule, expected uint64) (SieveRule, SieveActivation, error) {
	if err := service.sieveReady(call); err != nil { return SieveRule{}, SieveActivation{}, err }
	rule.Scope = call.Scope; rule.Revision = expected+1; rule.UpdatedAt = service.now()
	normalized, err := NormalizeSieveRule(rule)
	if err != nil { return SieveRule{}, SieveActivation{}, err }
	if err = service.authorizeSieveRule(ctx, call, normalized); err != nil { return SieveRule{}, SieveActivation{}, err }
	if err = service.validateVacation(ctx, normalized); err != nil { return SieveRule{}, SieveActivation{}, err }
	prospective, err := service.Repository.ListSieveRules(ctx, call.Scope)
	if err != nil { return SieveRule{}, SieveActivation{}, err }
	replaced := false
	for index := range prospective { if prospective[index].ID == normalized.ID { if prospective[index].Revision != expected { return SieveRule{}, SieveActivation{}, ErrConflict }; prospective[index] = normalized; replaced = true } }
	if !replaced { if expected != 0 { return SieveRule{}, SieveActivation{}, ErrConflict }; prospective = append(prospective, normalized) }
	if _, err = CompileSieveProgram(call.Scope, 1, prospective, service.now()); err != nil { return SieveRule{}, SieveActivation{}, err }
	if err = service.Repository.PutSieveRule(ctx, normalized, expected); err != nil { return SieveRule{}, SieveActivation{}, err }
	activation, err := service.activateSieve(ctx, call)
	if err != nil { return normalized, SieveActivation{}, err }
	if err = service.audit(ctx, call, OperationSieveWrite, normalized.ID, expected, normalized.Revision, activation.Digest); err != nil { return normalized, activation, err }
	return normalized, activation, nil
}

func (service *Service) SubmitExpertSieve(ctx context.Context, call Call, text string, expected map[string]uint64) ([]SieveRule, SieveActivation, error) {
	if err := service.sieveReady(call); err != nil || service.ExpertParser == nil { if err != nil { return nil, SieveActivation{}, err }; return nil, SieveActivation{}, ErrInvalid }
	rules, err := ParseExpertSieve(ctx, service.ExpertParser, call.Scope, text)
	if err != nil { return nil, SieveActivation{}, err }
	now := service.now()
	for index := range rules {
		revision, found := expected[rules[index].ID]
		if !found { return nil, SieveActivation{}, ErrConflict }
		rules[index].Revision = revision+1; rules[index].UpdatedAt = now
		rules[index], err = NormalizeSieveRule(rules[index])
		if err != nil { return nil, SieveActivation{}, err }
		if err = service.authorizeSieveRule(ctx, call, rules[index]); err != nil { return nil, SieveActivation{}, err }
		if err = service.validateVacation(ctx, rules[index]); err != nil { return nil, SieveActivation{}, err }
	}
	if _, err = CompileSieveProgram(call.Scope, 1, rules, now); err != nil { return nil, SieveActivation{}, err }
	if err = service.Repository.ReplaceSieveRulesCAS(ctx, call.Scope, rules, expected); err != nil { return nil, SieveActivation{}, err }
	activation, err := service.activateSieve(ctx, call)
	if err != nil { return rules, SieveActivation{}, err }
	if err = service.audit(ctx, call, OperationSieveWrite, "expert", 0, uint64(len(rules)), activation.Digest); err != nil { return rules, activation, err }
	return rules, activation, nil
}

func (service *Service) DeleteSieveRule(ctx context.Context, call Call, id string, expected uint64) (SieveActivation, error) {
	if err := service.sieveReady(call); err != nil { return SieveActivation{}, err }
	current, err := service.Repository.GetSieveRule(ctx, call.Scope, id)
	if err != nil { return SieveActivation{}, err }
	if current.Revision != expected { return SieveActivation{}, ErrConflict }
	if err = service.authorizeSieveRule(ctx, call, current); err != nil { return SieveActivation{}, err }
	rules, err := service.Repository.ListSieveRules(ctx, call.Scope)
	if err != nil { return SieveActivation{}, err }
	next := make([]SieveRule, 0, len(rules)-1); revisions := make(map[string]uint64, len(rules))
	for _, rule := range rules { revisions[rule.ID] = rule.Revision; if rule.ID != id { rule.Revision++; rule.UpdatedAt = service.now(); next = append(next, rule) } }
	if _, err = CompileSieveProgram(call.Scope, 1, next, service.now()); err != nil { return SieveActivation{}, err }
	if err = service.Repository.ReplaceSieveRulesCAS(ctx, call.Scope, next, revisions); err != nil { return SieveActivation{}, err }
	activation, err := service.activateSieve(ctx, call)
	if err != nil { return SieveActivation{}, err }
	return activation, service.audit(ctx, call, OperationSieveWrite, id, expected, expected+1, activation.Digest)
}

func (service *Service) SetSieveRuleEnabled(ctx context.Context, call Call, id string, expected uint64, enabled bool) (SieveRule, SieveActivation, error) {
	if err := service.sieveReady(call); err != nil { return SieveRule{}, SieveActivation{}, err }
	rule, err := service.Repository.GetSieveRule(ctx, call.Scope, id)
	if err != nil { return SieveRule{}, SieveActivation{}, err }
	if rule.Revision != expected { return SieveRule{}, SieveActivation{}, ErrConflict }
	rule.Enabled = enabled
	return service.SaveSieveRule(ctx, call, rule, expected)
}

func (service *Service) ReorderSieveRules(ctx context.Context, call Call, orderedIDs []string, expected map[string]uint64) (SieveActivation, error) {
	if err := service.sieveReady(call); err != nil { return SieveActivation{}, err }
	rules, err := service.Repository.ListSieveRules(ctx, call.Scope)
	if err != nil { return SieveActivation{}, err }
	if len(orderedIDs) != len(rules) || len(orderedIDs) > MaximumSieveRules { return SieveActivation{}, ErrInvalid }
	byID := make(map[string]SieveRule, len(rules)); for _, rule := range rules { byID[rule.ID] = rule }
	next := make([]SieveRule, 0, len(rules)); now := service.now()
	for order, id := range orderedIDs {
		rule, found := byID[id]; revision, expectedFound := expected[id]
		if !found || !expectedFound || revision != rule.Revision { return SieveActivation{}, ErrConflict }
		if err = service.authorizeSieveRule(ctx, call, rule); err != nil { return SieveActivation{}, err }
		rule.Order = order; rule.Revision++; rule.UpdatedAt = now; next = append(next, rule); delete(byID, id)
	}
	if len(byID) != 0 { return SieveActivation{}, ErrInvalid }
	if _, err = CompileSieveProgram(call.Scope, 1, next, now); err != nil { return SieveActivation{}, err }
	if err = service.Repository.ReplaceSieveRulesCAS(ctx, call.Scope, next, expected); err != nil { return SieveActivation{}, err }
	activation, err := service.activateSieve(ctx, call)
	if err != nil { return SieveActivation{}, err }
	return activation, service.audit(ctx, call, OperationSieveWrite, "order", 0, uint64(len(next)), activation.Digest)
}

func (service *Service) TestSieve(ctx context.Context, call Call, message SieveTestMessage) (SieveEvaluation, error) {
	if err := service.sieveReady(call); err != nil { return SieveEvaluation{}, err }
	if err := service.authorize(ctx, call, OperationSieveTest, "", false); err != nil { return SieveEvaluation{}, err }
	rules, err := service.Repository.ListSieveRules(ctx, call.Scope)
	if err != nil { return SieveEvaluation{}, err }
	program, err := CompileSieveProgram(call.Scope, 1, rules, service.now())
	if err != nil { return SieveEvaluation{}, err }
	expected, err := EvaluateSieve(program, message)
	if err != nil { return SieveEvaluation{}, err }
	actual, err := service.SieveRuntime.Test(ctx, program, message)
	if err != nil { return SieveEvaluation{}, err }
	if !sameEvaluation(expected, actual) { return SieveEvaluation{}, ErrIntegrity }
	return actual, nil
}

func (service *Service) activateSieve(ctx context.Context, call Call) (SieveActivation, error) {
	rules, err := service.Repository.ListSieveRules(ctx, call.Scope)
	if err != nil { return SieveActivation{}, err }
	for _, rule := range rules { if err = service.validateVacation(ctx, rule); err != nil { return SieveActivation{}, err } }
	generation, err := service.Repository.NextSieveGeneration(ctx, call.Scope)
	if err != nil { return SieveActivation{}, err }
	program, err := CompileSieveProgram(call.Scope, generation, rules, service.now())
	if err != nil { return SieveActivation{}, err }
	active, err := service.Repository.ActiveSieve(ctx, call.Scope)
	if err != nil { return SieveActivation{}, err }
	if err = service.Repository.StageSieveGeneration(ctx, program); err != nil { return SieveActivation{}, err }
	stage, err := service.SieveRuntime.Stage(ctx, ManageSieveStageRequest{OperationID: call.OperationID, Program: program})
	if err != nil || !validStageReceipt(stage, call, program) { return SieveActivation{}, errors.Join(ErrActivation, err) }
	validated, err := service.SieveRuntime.ValidateCompile(ctx, ManageSieveValidationRequest{Scope: call.Scope, Generation: program.Generation, Digest: program.Digest})
	if err != nil || !validValidationReceipt(validated, program) { return SieveActivation{}, errors.Join(ErrActivation, err) }
	request := ManageSieveActivationRequest{OperationID: call.OperationID, Scope: call.Scope, ExpectedDigest: active.Digest, Program: program}
	receipt, err := service.SieveRuntime.ActivateCAS(ctx, request)
	if err != nil || !validActivationReceipt(receipt, request) {
		rollbackErr := service.restoreSieveRuntime(ctx, call, active, program.Digest)
		return SieveActivation{}, errors.Join(ErrActivation, err, rollbackErr)
	}
	desired := SieveActivation{Scope: call.Scope, Generation: program.Generation, Digest: program.Digest, UpdatedAt: service.now()}
	if err = service.Repository.ActivateSieveCAS(ctx, desired, active.Digest); err == nil { return desired, nil }
	rollbackErr := service.restoreSieveRuntime(ctx, call, active, program.Digest)
	return SieveActivation{}, errors.Join(ErrActivation, err, rollbackErr)
}

func (service *Service) restoreSieveRuntime(ctx context.Context, call Call, active SieveActivation, expectedDigest string) error {
	rollback := ManageSieveActivationRequest{OperationID: call.OperationID + ".rollback", Scope: call.Scope, ExpectedDigest: expectedDigest, Rollback: true}
	if active.Generation == 0 { rollback.Remove = true } else { previous, err := service.Repository.GetSieveProgram(ctx, call.Scope, active.Generation); if err != nil { return err }; rollback.Program = previous }
	rolledBack, rollbackErr := service.SieveRuntime.ActivateCAS(ctx, rollback)
	if rollbackErr != nil { return rollbackErr }
	if !validActivationReceipt(rolledBack, rollback) { return ErrIntegrity }
	return nil
}

type BackupManifest struct {
	Schema    string         `json:"schema"`
	Scope     Scope          `json:"scope"`
	Counts    map[string]int `json:"counts"`
	Objects   int            `json:"objects"`
	Bytes     int64          `json:"bytes"`
	Digest    string         `json:"digest"`
	CreatedAt time.Time      `json:"created_at"`
}

type backupRecord struct { Kind string `json:"kind"`; Document json.RawMessage `json:"document"` }

func (service *Service) ExportSettingsBackup(ctx context.Context, call Call, writer io.Writer, maximumObjects int, maximumBytes int64) (BackupManifest, error) {
	if err := service.ready(call); err != nil || writer == nil || maximumObjects < 1 || maximumObjects > MaximumBackupObjects || maximumBytes < 1 || maximumBytes > MaximumBackupBytes { if err != nil { return BackupManifest{}, err }; return BackupManifest{}, ErrInvalid }
	if err := service.authorize(ctx, call, OperationBackupExport, "", true); err != nil { return BackupManifest{}, err }
	hasher := sha256.New(); bounded := &boundedWriter{writer: io.MultiWriter(writer, hasher), maximum: maximumBytes}
	manifest := BackupManifest{Schema: "webmail-settings/v1", Scope: call.Scope, Counts: map[string]int{}, CreatedAt: service.now()}
	write := func(kind string, value any) error { if manifest.Objects == maximumObjects { return ErrLimit }; raw, err := json.Marshal(value); if err != nil { return err }; record, err := json.Marshal(backupRecord{Kind: kind, Document: raw}); if err != nil { return err }; record = append(record, '\n'); if _, err = bounded.Write(record); err != nil { return err }; manifest.Counts[kind]++; manifest.Objects++; return nil }
	cursor := ""
	for { page, err := service.Repository.ListContacts(ctx, ContactQuery{Scope: call.Scope, Cursor: cursor, Limit: MaximumPageSize}); if err != nil { return BackupManifest{}, err }; for _, value := range page.Contacts { if err = write("contact", value); err != nil { return BackupManifest{}, err } }; if page.NextCursor == "" { break }; cursor = page.NextCursor }
	after := ""
	for { groups, next, err := service.Repository.ListGroups(ctx, call.Scope, after, MaximumPageSize); if err != nil { return BackupManifest{}, err }; for _, value := range groups { if err = write("group", value); err != nil { return BackupManifest{}, err } }; if next == "" { break }; after = next }
	preferences, err := service.Repository.GetPreferences(ctx, call.Scope)
	if err == nil { if err = write("preferences", preferences); err != nil { return BackupManifest{}, err } } else if !errors.Is(err, ErrNotFound) { return BackupManifest{}, err }
	rules, err := service.Repository.ListSieveRules(ctx, call.Scope)
	if err != nil { return BackupManifest{}, err }
	for _, value := range rules { if err = write("sieve_rule", value); err != nil { return BackupManifest{}, err } }
	manifest.Bytes = bounded.written; manifest.Digest = hex.EncodeToString(hasher.Sum(nil))
	if err = service.audit(ctx, call, OperationBackupExport, "manifest", 0, uint64(manifest.Objects), manifest.Digest); err != nil { return BackupManifest{}, err }
	return manifest, nil
}

type RestoreMode string
const ( RestoreCreateOnly RestoreMode = "create_only"; RestoreReconcile RestoreMode = "reconcile"; RestoreMigrate RestoreMode = "migrate" )
type RestoreRequest struct { Call Call; Reader io.ReadSeeker; Manifest BackupManifest; Mode RestoreMode }

func (service *Service) RestoreSettingsBackup(ctx context.Context, request RestoreRequest) error {
	if err := service.ready(request.Call); err != nil || request.Reader == nil || request.Manifest.Schema != "webmail-settings/v1" || request.Manifest.Scope != request.Call.Scope || request.Manifest.Objects < 0 || request.Manifest.Objects > MaximumBackupObjects || request.Manifest.Bytes < 0 || request.Manifest.Bytes > MaximumBackupBytes || !validDigest(request.Manifest.Digest) || request.Mode != RestoreCreateOnly && request.Mode != RestoreReconcile && request.Mode != RestoreMigrate { if err != nil { return err }; return ErrInvalid }
	operation := OperationBackupRestore; if request.Mode == RestoreMigrate { operation = OperationBackupMigrate }
	if err := service.authorize(ctx, request.Call, operation, "manifest", true); err != nil { return err }
	if err := verifyBackupReader(request.Reader, request.Manifest); err != nil { return err }
	if err := service.validateBackupRecords(ctx, request); err != nil { return err }
	if _, err := request.Reader.Seek(0, io.SeekStart); err != nil { return err }
	scanner := bufio.NewScanner(io.LimitReader(request.Reader, request.Manifest.Bytes+1)); scanner.Buffer(make([]byte, 4096), 4<<20)
	seen := 0; actualCounts := map[string]int{}; sieveExpected := map[string]uint64{}; restoredRules := []SieveRule{}
	currentRules, err := service.Repository.ListSieveRules(ctx, request.Call.Scope)
	if err != nil { return err }
	for _, rule := range currentRules { sieveExpected[rule.ID] = rule.Revision; if request.Mode == RestoreCreateOnly { rule.Revision++; rule.UpdatedAt = service.now(); restoredRules = append(restoredRules, rule) } }
	for scanner.Scan() {
		if err := ctx.Err(); err != nil { return err }
		seen++; if seen > request.Manifest.Objects { return ErrIntegrity }
		var record backupRecord
		if json.Unmarshal(scanner.Bytes(), &record) != nil { return ErrIntegrity }
		actualCounts[record.Kind]++
		switch record.Kind {
		case "contact":
			var value Contact; if json.Unmarshal(record.Document, &value) != nil || value.Scope != request.Call.Scope { return ErrIntegrity }; current, err := service.Repository.GetContact(ctx, value.Scope, value.ID); expected := uint64(0); if err == nil { if request.Mode == RestoreCreateOnly { return ErrConflict }; expected = current.Revision; value.CreatedAt = current.CreatedAt } else if !errors.Is(err, ErrNotFound) { return err }; value.Revision = expected+1; value.UpdatedAt = service.now(); if expected == 0 { value.CreatedAt = value.UpdatedAt }; if request.Mode == RestoreMigrate { value.Provenance = Provenance{Kind: ProvenanceMigrated, SourceDigest: request.Manifest.Digest, ImportedAt: timePointer(value.UpdatedAt)} }; if err = service.Repository.PutContact(ctx, value, expected); err != nil { return err }
		case "group":
			var value ContactGroup; if json.Unmarshal(record.Document, &value) != nil || value.Scope != request.Call.Scope { return ErrIntegrity }; current, err := service.Repository.GetGroup(ctx, value.Scope, value.ID); expected := uint64(0); if err == nil { if request.Mode == RestoreCreateOnly { return ErrConflict }; expected = current.Revision; value.CreatedAt = current.CreatedAt } else if !errors.Is(err, ErrNotFound) { return err }; value.Revision = expected+1; value.UpdatedAt = service.now(); if expected == 0 { value.CreatedAt = value.UpdatedAt }; if err = service.Repository.PutGroup(ctx, value, expected); err != nil { return err }
		case "preferences":
			var value WebmailPreferences; if json.Unmarshal(record.Document, &value) != nil || value.Scope != request.Call.Scope { return ErrIntegrity }; current, err := service.Repository.GetPreferences(ctx, value.Scope); expected := uint64(0); if err == nil { if request.Mode == RestoreCreateOnly { return ErrConflict }; expected = current.Revision } else if !errors.Is(err, ErrNotFound) { return err }; value.Revision = expected+1; value.UpdatedAt = service.now(); if err = service.Repository.PutPreferences(ctx, value, expected); err != nil { return err }
		case "sieve_rule":
			var value SieveRule; if json.Unmarshal(record.Document, &value) != nil || value.Scope != request.Call.Scope { return ErrIntegrity }; current, err := service.Repository.GetSieveRule(ctx, value.Scope, value.ID); expected := uint64(0); if err == nil { if request.Mode == RestoreCreateOnly { return ErrConflict }; expected = current.Revision } else if !errors.Is(err, ErrNotFound) { return err }; value.Revision = expected+1; value.UpdatedAt = service.now(); sieveExpected[value.ID] = expected; restoredRules = append(restoredRules, value)
		default: return ErrIntegrity
		}
	}
	if err := scanner.Err(); err != nil || seen != request.Manifest.Objects || !sameCounts(actualCounts, request.Manifest.Counts) { if err != nil { return err }; return ErrIntegrity }
	if request.Manifest.Counts["sieve_rule"] > 0 || request.Mode != RestoreCreateOnly && len(currentRules) > 0 { if err := service.Repository.ReplaceSieveRulesCAS(ctx, request.Call.Scope, restoredRules, sieveExpected); err != nil { return err }; if _, err := service.activateSieve(ctx, request.Call); err != nil { return err } }
	return service.audit(ctx, request.Call, operation, "manifest", 0, uint64(seen), request.Manifest.Digest)
}

func verifyBackupReader(reader io.ReadSeeker, manifest BackupManifest) error {
	if _, err := reader.Seek(0, io.SeekStart); err != nil { return err }
	hasher := sha256.New(); count, err := io.Copy(hasher, io.LimitReader(reader, manifest.Bytes+1))
	if err != nil { return err }
	if count != manifest.Bytes || hex.EncodeToString(hasher.Sum(nil)) != manifest.Digest { return ErrIntegrity }
	var extra [1]byte; if read, _ := reader.Read(extra[:]); read != 0 { return ErrLimit }
	return nil
}

func (service *Service) validateBackupRecords(ctx context.Context, request RestoreRequest) error {
	if _, err := request.Reader.Seek(0, io.SeekStart); err != nil { return err }
	scanner := bufio.NewScanner(io.LimitReader(request.Reader, request.Manifest.Bytes+1)); scanner.Buffer(make([]byte, 4096), 4<<20)
	counts := map[string]int{}; seen, phase := 0, 0; rules := make([]SieveRule, 0)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil { return err }
		seen++; if seen > request.Manifest.Objects { return ErrIntegrity }
		var record backupRecord
		if json.Unmarshal(scanner.Bytes(), &record) != nil { return ErrIntegrity }
		counts[record.Kind]++
		nextPhase := map[string]int{"contact": 0, "group": 1, "preferences": 2, "sieve_rule": 3}[record.Kind]
		if nextPhase < phase || record.Kind == "preferences" && counts[record.Kind] > 1 { return ErrIntegrity }; phase = nextPhase
		switch record.Kind {
		case "contact":
			var value Contact; if json.Unmarshal(record.Document, &value) != nil || value.Scope != request.Call.Scope { return ErrIntegrity }; if _, err := NormalizeContact(value); err != nil { return ErrIntegrity }
		case "group":
			var value ContactGroup; if json.Unmarshal(record.Document, &value) != nil || value.Scope != request.Call.Scope { return ErrIntegrity }; if _, err := NormalizeGroup(value); err != nil { return ErrIntegrity }
		case "preferences":
			var value WebmailPreferences; if json.Unmarshal(record.Document, &value) != nil || value.Scope != request.Call.Scope { return ErrIntegrity }; if _, err := NormalizePreferences(value); err != nil { return ErrIntegrity }
		case "sieve_rule":
			var value SieveRule; if json.Unmarshal(record.Document, &value) != nil || value.Scope != request.Call.Scope { return ErrIntegrity }; normalized, err := NormalizeSieveRule(value); if err != nil { return ErrIntegrity }; if err = service.authorizeSieveRule(ctx, request.Call, normalized); err != nil { return err }; if err = service.validateVacation(ctx, normalized); err != nil { return err }; rules = append(rules, normalized)
		default: return ErrIntegrity
		}
	}
	if err := scanner.Err(); err != nil { return err }
	if seen != request.Manifest.Objects || !sameCounts(counts, request.Manifest.Counts) { return ErrIntegrity }
	if len(rules) > 0 { if _, err := CompileSieveProgram(request.Call.Scope, 1, rules, service.now()); err != nil { return err } }
	return nil
}

func (service *Service) authorizeSieveRule(ctx context.Context, call Call, rule SieveRule) error {
	if err := service.authorize(ctx, call, OperationSieveWrite, rule.ID, false); err != nil { return err }
	for _, action := range rule.Actions {
		if action.Kind == ActionRedirect {
			if err := service.authorize(ctx, call, OperationSieveRedirect, rule.ID, true); err != nil { return err }
			if service.Forwarding == nil || service.Forwarding.AuthorizeSieveRedirect(ctx, call.Scope, action.Target) != nil { return ErrUnauthorized }
		}
		if action.Kind == ActionDiscard { if err := service.authorize(ctx, call, OperationSieveDiscard, rule.ID, true); err != nil { return err } }
	}
	return nil
}

func (service *Service) validateVacation(ctx context.Context, rule SieveRule) error {
	if rule.CanonicalVacation == nil { return nil }
	if service.Autoresponders == nil { return ErrUnauthorized }
	resolved, err := service.Autoresponders.ResolveAutoresponder(ctx, rule.Scope, rule.CanonicalVacation.RuleID, rule.CanonicalVacation.Generation)
	if err != nil { return err }
	if resolved.TenantID != rule.Scope.TenantID || string(resolved.MailboxID) != rule.Scope.MailboxID || resolved.ID != rule.CanonicalVacation.RuleID || resolved.Generation != rule.CanonicalVacation.Generation || resolved.State == maildata.AutoresponderDeleted { return ErrIntegrity }
	return nil
}

func (service *Service) authorize(ctx context.Context, call Call, operation Operation, resource string, stepUp bool) error {
	if ctx == nil { return ErrInvalid }
	if service.Authorizer.AuthorizeWebmailData(ctx, AuthorizationRequest{ActorID: call.ActorID, Operation: operation, Scope: call.Scope, ResourceID: resource}) != nil { return ErrUnauthorized }
	if stepUp { if service.StepUp == nil || call.StepUpProof == "" || service.StepUp.VerifyWebmailDataStepUp(ctx, call.ActorID, call.Scope, call.StepUpProof) != nil { return ErrStepUp } }
	return nil
}

func (service *Service) ready(call Call) error {
	if service == nil || service.Repository == nil || service.Authorizer == nil || service.Audit == nil || !call.Scope.Valid() || !opaquePattern.MatchString(call.ActorID) || !opaquePattern.MatchString(call.OperationID) { return ErrInvalid }
	return nil
}

func (service *Service) sieveReady(call Call) error { if err := service.ready(call); err != nil { return err }; if service.SieveRuntime == nil { return ErrInvalid }; return nil }
func (service *Service) now() time.Time { if service.Now != nil { return service.Now().UTC().Truncate(time.Second) }; return time.Now().UTC().Truncate(time.Second) }
func (service *Service) audit(ctx context.Context, call Call, operation Operation, resource string, before, after uint64, digest string) error { return service.Audit.RecordWebmailData(ctx, AuditEvent{OperationID: call.OperationID, ActorID: call.ActorID, Operation: operation, Scope: call.Scope, ResourceID: resource, Before: before, After: after, Digest: digest, OccurredAt: service.now()}) }

func mergeContactValues(target, source Contact, prefer FieldMask) Contact {
	fields := map[string]bool{}; for _, field := range prefer { fields[field] = true }
	if fields["display_name"] && source.DisplayName != "" { target.DisplayName = source.DisplayName }
	if fields["given_name"] && source.GivenName != "" { target.GivenName = source.GivenName }
	if fields["family_name"] && source.FamilyName != "" { target.FamilyName = source.FamilyName }
	if fields["organization"] && source.Organization != "" { target.Organization = source.Organization }
	if fields["notes"] && source.Notes != "" { target.Notes = source.Notes }
	if fields["addresses"] { target.Addresses = mergeAddresses(target.Addresses, source.Addresses) }
	if fields["phones"] { target.Phones = mergePhones(target.Phones, source.Phones) }
	if fields["metadata"] { target.Metadata = mergeMetadata(target.Metadata, source.Metadata) }
	return target
}

func mergeAddresses(left, right []LabeledAddress) []LabeledAddress { result := append([]LabeledAddress(nil), left...); seen := map[string]bool{}; for _, value := range result { seen[value.Normalized] = true }; for _, value := range right { if !seen[value.Normalized] { value.Primary = false; result = append(result, value); seen[value.Normalized] = true } }; return result }
func mergePhones(left, right []LabeledPhone) []LabeledPhone { result := append([]LabeledPhone(nil), left...); seen := map[string]bool{}; for _, value := range result { seen[value.Normalized] = true }; for _, value := range right { if !seen[value.Normalized] { value.Primary = false; result = append(result, value); seen[value.Normalized] = true } }; return result }
func mergeMetadata(left, right []MetadataField) []MetadataField { values := map[string]string{}; for _, value := range left { values[value.Key] = value.Value }; for _, value := range right { values[value.Key] = value.Value }; keys := make([]string, 0, len(values)); for key := range values { keys = append(keys, key) }; sort.Strings(keys); result := make([]MetadataField, 0, len(keys)); for _, key := range keys { result = append(result, MetadataField{Key: key, Value: values[key]}) }; return result }

func validStageReceipt(receipt ManageSieveReceipt, call Call, program SieveProgram) bool { return receipt.OperationID == call.OperationID && receipt.Scope == call.Scope && receipt.Generation == program.Generation && receipt.Digest == program.Digest && !receipt.Activated }
func validValidationReceipt(receipt ManageSieveReceipt, program SieveProgram) bool { return receipt.Scope == program.Scope && receipt.Generation == program.Generation && receipt.Digest == program.Digest && receipt.Validated && !receipt.Activated }
func validActivationReceipt(receipt ManageSieveReceipt, request ManageSieveActivationRequest) bool { if request.Remove { return receipt.OperationID == request.OperationID && receipt.Scope == request.Scope && receipt.PreviousDigest == request.ExpectedDigest && receipt.Activated && receipt.Digest == "" }; return receipt.OperationID == request.OperationID && receipt.Scope == request.Scope && receipt.Generation == request.Program.Generation && receipt.Digest == request.Program.Digest && receipt.PreviousDigest == request.ExpectedDigest && receipt.Validated && receipt.Activated }
func sameEvaluation(left, right SieveEvaluation) bool { leftJSON, _ := json.Marshal(left); rightJSON, _ := json.Marshal(right); return string(leftJSON) == string(rightJSON) }
func sameCounts(left, right map[string]int) bool { if len(left) != len(right) { return false }; for key, value := range left { if right[key] != value { return false } }; return true }
func digestCounts(values ...int) string { raw, _ := json.Marshal(values); sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
