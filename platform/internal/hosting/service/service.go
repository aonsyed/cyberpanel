// Package service implements the durable command boundary for hosting sites.
// It owns site intent admission and effect correlation. A node composer consumes
// site projections later and remains solely responsible for node-wide web state.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

var (
	ErrUnauthorized         = errors.New("hosting command is not authorized for tenant")
	ErrIdempotencyConflict  = errors.New("command ID was reused with different payload")
	ErrNotFound             = errors.New("site not found")
	ErrInvalidCommand       = errors.New("invalid hosting command")
	ErrInvalidReceipt       = errors.New("stored command receipt does not match command identity")
	ErrInvalidEffectReceipt = errors.New("site effect receipt does not match accepted effect")
)

// Actor is the tenant-scoped principal that submitted a command.
type Actor struct {
	TenantID site.TenantID
}

// Command is a closed hosting lifecycle request.
type Command interface {
	commandID() string
	commandTenant() site.TenantID
	commandActor() Actor
	commandDigest() string
}

type CreateSite struct {
	CommandID string
	Actor     Actor
	TenantID  site.TenantID
	Site      site.CreateInput
}

func (command CreateSite) commandID() string            { return command.CommandID }
func (command CreateSite) commandTenant() site.TenantID { return command.TenantID }
func (command CreateSite) commandActor() Actor          { return command.Actor }
func (command CreateSite) commandDigest() string {
	return canonicalDigest(commandDigestDTO{
		Version:         1,
		Type:            "CreateSite",
		CommandID:       command.CommandID,
		ActorTenantID:   command.Actor.TenantID.String(),
		TenantID:        command.TenantID.String(),
		SiteID:          command.Site.ID.String(),
		ProjectID:       command.Site.ProjectID.String(),
		PrimaryHostname: command.Site.PrimaryHostname.String(),
		PHPProfile:      command.Site.PHPProfile,
	})
}

type lifecycleRequest struct {
	CommandID          string
	Actor              Actor
	TenantID           site.TenantID
	SiteID             site.SiteID
	ExpectedGeneration uint64
}

type MarkProvisioned lifecycleRequest
type SuspendSite lifecycleRequest
type ResumeSite lifecycleRequest
type BeginDelete lifecycleRequest
type MarkQuarantined lifecycleRequest
type RestoreSite lifecycleRequest
type BeginPurge lifecycleRequest
type MarkDeleted lifecycleRequest

type AttachDomainBinding struct {
	CommandID          string
	Actor              Actor
	TenantID           site.TenantID
	SiteID             site.SiteID
	ExpectedGeneration uint64
	Binding            site.DomainBinding
}

func (command AttachDomainBinding) commandID() string { return command.CommandID }
func (command AttachDomainBinding) commandTenant() site.TenantID { return command.TenantID }
func (command AttachDomainBinding) commandActor() Actor { return command.Actor }
func (command AttachDomainBinding) commandDigest() string {
	return canonicalDigest(struct {
		Version uint32 `json:"version"`
		Type string `json:"type"`
		CommandID string `json:"command_id"`
		ActorTenantID string `json:"actor_tenant_id"`
		TenantID string `json:"tenant_id"`
		SiteID string `json:"site_id"`
		ExpectedGeneration uint64 `json:"expected_generation"`
		Hostname string `json:"hostname"`
		Kind site.BindingKind `json:"kind"`
		RedirectTarget string `json:"redirect_target,omitempty"`
		RedirectStatus site.RedirectStatus `json:"redirect_status,omitempty"`
	}{1,"AttachDomainBinding",command.CommandID,command.Actor.TenantID.String(),command.TenantID.String(),command.SiteID.String(),command.ExpectedGeneration,command.Binding.Hostname.String(),command.Binding.Kind,command.Binding.RedirectTarget.String(),command.Binding.RedirectStatus})
}

type DetachDomainBinding struct {
	CommandID          string
	Actor              Actor
	TenantID           site.TenantID
	SiteID             site.SiteID
	ExpectedGeneration uint64
	Hostname           site.Hostname
}

func (command DetachDomainBinding) commandID() string { return command.CommandID }
func (command DetachDomainBinding) commandTenant() site.TenantID { return command.TenantID }
func (command DetachDomainBinding) commandActor() Actor { return command.Actor }
func (command DetachDomainBinding) commandDigest() string {
	return canonicalDigest(struct {
		Version uint32 `json:"version"`
		Type string `json:"type"`
		CommandID string `json:"command_id"`
		ActorTenantID string `json:"actor_tenant_id"`
		TenantID string `json:"tenant_id"`
		SiteID string `json:"site_id"`
		ExpectedGeneration uint64 `json:"expected_generation"`
		Hostname string `json:"hostname"`
	}{1,"DetachDomainBinding",command.CommandID,command.Actor.TenantID.String(),command.TenantID.String(),command.SiteID.String(),command.ExpectedGeneration,command.Hostname.String()})
}

func lifecycleID(request lifecycleRequest) string            { return request.CommandID }
func lifecycleTenant(request lifecycleRequest) site.TenantID { return request.TenantID }
func lifecycleActor(request lifecycleRequest) Actor          { return request.Actor }
func lifecycleRequestDigest(kind string, request lifecycleRequest) string {
	return canonicalDigest(commandDigestDTO{
		Version:            1,
		Type:               kind,
		CommandID:          request.CommandID,
		ActorTenantID:      request.Actor.TenantID.String(),
		TenantID:           request.TenantID.String(),
		SiteID:             request.SiteID.String(),
		ExpectedGeneration: request.ExpectedGeneration,
	})
}

func (command MarkProvisioned) commandID() string {
	return lifecycleID(lifecycleRequest(command))
}
func (command MarkProvisioned) commandTenant() site.TenantID {
	return lifecycleTenant(lifecycleRequest(command))
}
func (command MarkProvisioned) commandActor() Actor {
	return lifecycleActor(lifecycleRequest(command))
}
func (command MarkProvisioned) commandDigest() string {
	return lifecycleRequestDigest("MarkProvisioned", lifecycleRequest(command))
}
func (command SuspendSite) commandID() string { return lifecycleID(lifecycleRequest(command)) }
func (command SuspendSite) commandTenant() site.TenantID {
	return lifecycleTenant(lifecycleRequest(command))
}
func (command SuspendSite) commandActor() Actor { return lifecycleActor(lifecycleRequest(command)) }
func (command SuspendSite) commandDigest() string {
	return lifecycleRequestDigest("SuspendSite", lifecycleRequest(command))
}
func (command ResumeSite) commandID() string { return lifecycleID(lifecycleRequest(command)) }
func (command ResumeSite) commandTenant() site.TenantID {
	return lifecycleTenant(lifecycleRequest(command))
}
func (command ResumeSite) commandActor() Actor { return lifecycleActor(lifecycleRequest(command)) }
func (command ResumeSite) commandDigest() string {
	return lifecycleRequestDigest("ResumeSite", lifecycleRequest(command))
}
func (command BeginDelete) commandID() string { return lifecycleID(lifecycleRequest(command)) }
func (command BeginDelete) commandTenant() site.TenantID {
	return lifecycleTenant(lifecycleRequest(command))
}
func (command BeginDelete) commandActor() Actor { return lifecycleActor(lifecycleRequest(command)) }
func (command BeginDelete) commandDigest() string {
	return lifecycleRequestDigest("BeginDelete", lifecycleRequest(command))
}
func (command MarkQuarantined) commandID() string { return lifecycleID(lifecycleRequest(command)) }
func (command MarkQuarantined) commandTenant() site.TenantID {
	return lifecycleTenant(lifecycleRequest(command))
}
func (command MarkQuarantined) commandActor() Actor {
	return lifecycleActor(lifecycleRequest(command))
}
func (command MarkQuarantined) commandDigest() string {
	return lifecycleRequestDigest("MarkQuarantined", lifecycleRequest(command))
}
func (command RestoreSite) commandID() string { return lifecycleID(lifecycleRequest(command)) }
func (command RestoreSite) commandTenant() site.TenantID {
	return lifecycleTenant(lifecycleRequest(command))
}
func (command RestoreSite) commandActor() Actor { return lifecycleActor(lifecycleRequest(command)) }
func (command RestoreSite) commandDigest() string {
	return lifecycleRequestDigest("RestoreSite", lifecycleRequest(command))
}
func (command BeginPurge) commandID() string { return lifecycleID(lifecycleRequest(command)) }
func (command BeginPurge) commandTenant() site.TenantID {
	return lifecycleTenant(lifecycleRequest(command))
}
func (command BeginPurge) commandActor() Actor { return lifecycleActor(lifecycleRequest(command)) }
func (command BeginPurge) commandDigest() string {
	return lifecycleRequestDigest("BeginPurge", lifecycleRequest(command))
}
func (command MarkDeleted) commandID() string { return lifecycleID(lifecycleRequest(command)) }
func (command MarkDeleted) commandTenant() site.TenantID {
	return lifecycleTenant(lifecycleRequest(command))
}
func (command MarkDeleted) commandActor() Actor { return lifecycleActor(lifecycleRequest(command)) }
func (command MarkDeleted) commandDigest() string {
	return lifecycleRequestDigest("MarkDeleted", lifecycleRequest(command))
}

type OperationStatus string

const (
	OperationAccepted  OperationStatus = "accepted"
	OperationApplied   OperationStatus = "applied"
	OperationDegraded  OperationStatus = "degraded"
	OperationAmbiguous OperationStatus = "ambiguous"
)

type EffectOutcome string

const (
	EffectConfirmed EffectOutcome = "confirmed"
	EffectRejected  EffectOutcome = "rejected"
	EffectAmbiguous EffectOutcome = "ambiguous"
)

type CommandScope struct {
	TenantID site.TenantID
	SiteID   site.SiteID
}

// SiteProjection is the site-owned contribution to later node composition.
// It deliberately contains no listener, engine-edition, or node-wide state.
type SiteProjection struct {
	Generation uint64
	Lifecycle  site.Lifecycle
	PHPProfile site.PHPProfile
	Bindings   []site.DomainBinding
}

// SiteEffectRequest is the durable outbox payload for a site projection.
type SiteEffectRequest struct {
	EffectID         string
	Scope            CommandScope
	Projection       SiteProjection
	ProjectionDigest string
	Withdraw         bool
}

// SiteEffectReceipt proves the effect driver observed the exact accepted
// projection. Ambiguous receipts are retryable and are never terminal truth.
type SiteEffectReceipt struct {
	EffectID         string
	Scope            CommandScope
	ProjectionDigest string
	Generation       uint64
	Outcome          EffectOutcome
	ProbeDigest      string
}

type OperationReceipt struct {
	CommandID  string
	Digest     string
	Scope      CommandScope
	Status     OperationStatus
	AcceptedAt time.Time
	Request    SiteEffectRequest
	Effect     SiteEffectReceipt
}

// Admission atomically reserves the aggregate CAS and persists both the
// proposed aggregate and its Accepted outbox request.
type Admission struct {
	CommandID          string
	Digest             string
	Actor              Actor
	TenantID           site.TenantID
	Scope              CommandScope
	ExpectedGeneration uint64
	Proposal           site.Site
	AcceptedAt         time.Time
	Request            SiteEffectRequest
}

type AdmissionResultKind string

const (
	AdmissionNew          AdmissionResultKind = "new"
	AdmissionExistingSame AdmissionResultKind = "existing_same"
	AdmissionConflict     AdmissionResultKind = "conflict"
)

type AdmissionResult struct {
	Kind    AdmissionResultKind
	Receipt OperationReceipt
}

// Completion atomically records an outcome. Only an exact confirmed effect may
// commit the admitted proposal as observed aggregate state.
type Completion struct {
	CommandID string
	Digest    string
	Scope     CommandScope
	Status    OperationStatus
	Request   SiteEffectRequest
	Effect    SiteEffectReceipt
}

type SiteRepository interface {
	LookupCommand(context.Context, CommandScope, string, string) (OperationReceipt, bool, error)
	Load(context.Context, site.TenantID, site.SiteID) (site.Site, error)
	Admit(context.Context, Admission) (AdmissionResult, error)
	Complete(context.Context, Completion) (OperationReceipt, error)
}

type SiteEffectDriver interface {
	ObserveOrApply(context.Context, SiteEffectRequest) (SiteEffectReceipt, error)
}

type Clock interface {
	Now() time.Time
}

type Service struct {
	repository SiteRepository
	driver     SiteEffectDriver
	clock      Clock
}

func New(repository SiteRepository, driver SiteEffectDriver, clock Clock) Service {
	return Service{repository: repository, driver: driver, clock: clock}
}

func (service Service) Handle(ctx context.Context, command Command) (OperationReceipt, error) {
	if service.repository == nil || service.driver == nil || service.clock == nil || command == nil || strings.TrimSpace(command.commandID()) == "" {
		return OperationReceipt{}, ErrInvalidCommand
	}
	if command.commandActor().TenantID != command.commandTenant() {
		return OperationReceipt{}, ErrUnauthorized
	}
	if create, ok := command.(CreateSite); ok && create.Site.TenantID != create.TenantID {
		return OperationReceipt{}, ErrUnauthorized
	}

	scope, err := scopeOfCommand(command)
	if err != nil {
		return OperationReceipt{}, err
	}
	digest := command.commandDigest()
	previous, found, err := service.repository.LookupCommand(ctx, scope, command.commandID(), digest)
	if err != nil {
		return OperationReceipt{}, err
	}
	if found {
		if err := validateStoredReceipt(previous, command.commandID(), digest, scope); err != nil {
			return OperationReceipt{}, err
		}
		switch previous.Status {
		case OperationApplied, OperationDegraded:
			return cloneOperationReceipt(previous), nil
		case OperationAccepted, OperationAmbiguous:
			return service.observeAndComplete(ctx, previous)
		default:
			return OperationReceipt{}, ErrInvalidReceipt
		}
	}

	proposal, expectedGeneration, err := applyCommand(ctx, service.repository, command)
	if err != nil {
		return OperationReceipt{}, err
	}
	projection := projectionFromSite(proposal)
	projectionDigest := projectionDigest(projection)
	withdraw := shouldWithdraw(projection.Lifecycle)
	request := SiteEffectRequest{
		EffectID:         stableEffectID(scope, command.commandID(), digest, projectionDigest, withdraw),
		Scope:            scope,
		Projection:       projection,
		ProjectionDigest: projectionDigest,
		Withdraw:         withdraw,
	}
	admission := Admission{
		CommandID:          command.commandID(),
		Digest:             digest,
		Actor:              command.commandActor(),
		TenantID:           command.commandTenant(),
		Scope:              scope,
		ExpectedGeneration: expectedGeneration,
		Proposal:           proposal,
		AcceptedAt:         service.clock.Now().UTC(),
		Request:            cloneRequest(request),
	}
	result, err := service.repository.Admit(ctx, admission)
	if err != nil {
		return OperationReceipt{}, err
	}
	if result.Kind == AdmissionConflict {
		return OperationReceipt{}, ErrIdempotencyConflict
	}
	if result.Kind != AdmissionNew && result.Kind != AdmissionExistingSame {
		return OperationReceipt{}, ErrInvalidReceipt
	}
	accepted := result.Receipt
	if !reflect.DeepEqual(accepted.Request, admission.Request) {
		return OperationReceipt{}, ErrInvalidReceipt
	}
	if err := validateStoredReceipt(accepted, command.commandID(), digest, scope); err != nil {
		return OperationReceipt{}, err
	}
	if accepted.Status == OperationApplied || accepted.Status == OperationDegraded {
		return cloneOperationReceipt(accepted), nil
	}
	if accepted.Status != OperationAccepted && accepted.Status != OperationAmbiguous {
		return OperationReceipt{}, ErrInvalidReceipt
	}
	return service.observeAndComplete(ctx, accepted)
}

func (service Service) observeAndComplete(ctx context.Context, accepted OperationReceipt) (OperationReceipt, error) {
	request := cloneRequest(accepted.Request)
	effect, effectErr := service.driver.ObserveOrApply(ctx, request)
	status, outcomeErr := classifyEffect(request, effect, effectErr)
	completion := Completion{
		CommandID: accepted.CommandID,
		Digest:    accepted.Digest,
		Scope:     accepted.Scope,
		Status:    status,
		Request:   cloneRequest(request),
		Effect:    effect,
	}
	completed, completeErr := service.repository.Complete(ctx, completion)
	if completeErr != nil {
		accepted.Status = OperationAmbiguous
		accepted.Effect = effect
		return cloneOperationReceipt(accepted), completeErr
	}
	if err := validateStoredReceipt(completed, accepted.CommandID, accepted.Digest, accepted.Scope); err != nil {
		return OperationReceipt{}, err
	}
	if outcomeErr != nil {
		return cloneOperationReceipt(completed), outcomeErr
	}
	return cloneOperationReceipt(completed), nil
}

func validateStoredReceipt(receipt OperationReceipt, commandID, digest string, scope CommandScope) error {
	if receipt.CommandID != commandID || receipt.Digest != digest || receipt.Scope != scope {
		return ErrInvalidReceipt
	}
	if !validRequest(receipt.Request, scope, commandID, digest) {
		return ErrInvalidReceipt
	}
	switch receipt.Status {
	case OperationAccepted:
		return nil
	case OperationAmbiguous:
		// The last observation is intentionally not trusted. The immutable,
		// admitted request remains retryable with the same effect identity.
		return nil
	case OperationApplied:
		if !effectReceiptMatchesRequest(receipt.Effect, receipt.Request) || receipt.Effect.Outcome != EffectConfirmed || receipt.Effect.ProbeDigest == "" {
			return ErrInvalidReceipt
		}
		return nil
	case OperationDegraded:
		if !effectReceiptMatchesRequest(receipt.Effect, receipt.Request) || receipt.Effect.Outcome != EffectRejected {
			return ErrInvalidReceipt
		}
		return nil
	default:
		return ErrInvalidReceipt
	}
}

func validRequest(request SiteEffectRequest, scope CommandScope, commandID, digest string) bool {
	if request.Scope != scope || request.EffectID != stableEffectID(scope, commandID, digest, request.ProjectionDigest, request.Withdraw) {
		return false
	}
	if !validProjection(request.Projection) || request.ProjectionDigest != projectionDigest(request.Projection) {
		return false
	}
	return request.Withdraw == shouldWithdraw(request.Projection.Lifecycle)
}

func validProjection(projection SiteProjection) bool {
	if projection.Generation == 0 || !validLifecycle(projection.Lifecycle) || !site.ValidPHPProfile(projection.PHPProfile) || len(projection.Bindings) == 0 {
		return false
	}
	primaryCount := 0
	seen := make(map[string]struct{}, len(projection.Bindings))
	for _, binding := range projection.Bindings {
		hostname := binding.Hostname.String()
		if hostname == "" {
			return false
		}
		if _, exists := seen[hostname]; exists {
			return false
		}
		seen[hostname] = struct{}{}
		switch binding.Kind {
		case site.BindingPrimary:
			primaryCount++
			if binding.RedirectTarget.String() != "" || binding.RedirectStatus != "" {
				return false
			}
		case site.BindingChild, site.BindingAlias, site.BindingPreview:
			if binding.RedirectTarget.String() != "" || binding.RedirectStatus != "" {
				return false
			}
		case site.BindingRedirect:
			if binding.RedirectTarget.String() == "" || (binding.RedirectStatus != site.RedirectStatusPermanent301 && binding.RedirectStatus != site.RedirectStatusTemporary302) {
				return false
			}
		default:
			return false
		}
	}
	return primaryCount == 1
}

func validLifecycle(lifecycle site.Lifecycle) bool {
	switch lifecycle {
	case site.LifecycleProvisioning,
		site.LifecycleActive,
		site.LifecycleDegraded,
		site.LifecycleSuspended,
		site.LifecycleDeleting,
		site.LifecycleQuarantined,
		site.LifecyclePurging,
		site.LifecycleDeleted:
		return true
	default:
		return false
	}
}

func classifyEffect(request SiteEffectRequest, effect SiteEffectReceipt, effectErr error) (OperationStatus, error) {
	if !effectReceiptMatchesRequest(effect, request) {
		return OperationAmbiguous, ErrInvalidEffectReceipt
	}
	switch effect.Outcome {
	case EffectConfirmed:
		if effectErr == nil && effect.ProbeDigest != "" {
			return OperationApplied, nil
		}
		if effectErr != nil {
			return OperationAmbiguous, effectErr
		}
		return OperationAmbiguous, ErrInvalidEffectReceipt
	case EffectRejected:
		return OperationDegraded, effectErr
	case EffectAmbiguous:
		return OperationAmbiguous, effectErr
	default:
		return OperationAmbiguous, ErrInvalidEffectReceipt
	}
}

func effectReceiptMatchesRequest(effect SiteEffectReceipt, request SiteEffectRequest) bool {
	return effect.EffectID == request.EffectID &&
		effect.Scope == request.Scope &&
		effect.ProjectionDigest == request.ProjectionDigest &&
		effect.Generation == request.Projection.Generation
}

func scopeOfCommand(command Command) (CommandScope, error) {
	if create, ok := command.(CreateSite); ok {
		return CommandScope{TenantID: create.TenantID, SiteID: create.Site.ID}, nil
	}
	if attach, ok := command.(AttachDomainBinding); ok {
		return CommandScope{TenantID: attach.TenantID, SiteID: attach.SiteID}, nil
	}
	if detach, ok := command.(DetachDomainBinding); ok {
		return CommandScope{TenantID: detach.TenantID, SiteID: detach.SiteID}, nil
	}
	request, ok := asLifecycleRequest(command)
	if !ok {
		return CommandScope{}, ErrInvalidCommand
	}
	return CommandScope{TenantID: request.TenantID, SiteID: request.SiteID}, nil
}

func applyCommand(ctx context.Context, repository SiteRepository, command Command) (site.Site, uint64, error) {
	if create, ok := command.(CreateSite); ok {
		proposal, err := site.Create(create.Site)
		return proposal, 0, err
	}
	if attach, ok := command.(AttachDomainBinding); ok {
		current, err := repository.Load(ctx, attach.TenantID, attach.SiteID)
		if err != nil { return site.Site{}, 0, err }
		if current.TenantID() != attach.TenantID || current.ID() != attach.SiteID { return site.Site{}, 0, ErrNotFound }
		proposal, err := current.AttachBinding(attach.ExpectedGeneration, attach.Binding)
		return proposal, attach.ExpectedGeneration, err
	}
	if detach, ok := command.(DetachDomainBinding); ok {
		current, err := repository.Load(ctx, detach.TenantID, detach.SiteID)
		if err != nil { return site.Site{}, 0, err }
		if current.TenantID() != detach.TenantID || current.ID() != detach.SiteID { return site.Site{}, 0, ErrNotFound }
		proposal, err := current.DetachBinding(detach.ExpectedGeneration, detach.Hostname)
		return proposal, detach.ExpectedGeneration, err
	}
	request, ok := asLifecycleRequest(command)
	if !ok {
		return site.Site{}, 0, ErrInvalidCommand
	}
	nextLifecycle, ok := lifecycleTarget(command)
	if !ok {
		return site.Site{}, 0, ErrInvalidCommand
	}
	current, err := repository.Load(ctx, command.commandTenant(), request.SiteID)
	if err != nil {
		return site.Site{}, 0, err
	}
	if current.TenantID() != request.TenantID || current.ID() != request.SiteID {
		return site.Site{}, 0, ErrNotFound
	}
	proposal, err := current.Transition(request.ExpectedGeneration, nextLifecycle)
	return proposal, request.ExpectedGeneration, err
}

func asLifecycleRequest(command Command) (lifecycleRequest, bool) {
	switch command := command.(type) {
	case MarkProvisioned:
		return lifecycleRequest(command), true
	case SuspendSite:
		return lifecycleRequest(command), true
	case ResumeSite:
		return lifecycleRequest(command), true
	case BeginDelete:
		return lifecycleRequest(command), true
	case MarkQuarantined:
		return lifecycleRequest(command), true
	case RestoreSite:
		return lifecycleRequest(command), true
	case BeginPurge:
		return lifecycleRequest(command), true
	case MarkDeleted:
		return lifecycleRequest(command), true
	default:
		return lifecycleRequest{}, false
	}
}

func lifecycleTarget(command Command) (site.Lifecycle, bool) {
	switch command.(type) {
	case MarkProvisioned, ResumeSite, RestoreSite:
		return site.LifecycleActive, true
	case SuspendSite:
		return site.LifecycleSuspended, true
	case BeginDelete:
		return site.LifecycleDeleting, true
	case MarkQuarantined:
		return site.LifecycleQuarantined, true
	case BeginPurge:
		return site.LifecyclePurging, true
	case MarkDeleted:
		return site.LifecycleDeleted, true
	default:
		return "", false
	}
}

func projectionFromSite(aggregate site.Site) SiteProjection {
	return SiteProjection{
		Generation: aggregate.Generation(),
		Lifecycle:  aggregate.Lifecycle(),
		PHPProfile: aggregate.PHPProfile(),
		Bindings:   aggregate.Bindings(),
	}
}

func shouldWithdraw(lifecycle site.Lifecycle) bool {
	return lifecycle == site.LifecyclePurging || lifecycle == site.LifecycleDeleted
}

func cloneRequest(request SiteEffectRequest) SiteEffectRequest {
	request.Projection.Bindings = append([]site.DomainBinding(nil), request.Projection.Bindings...)
	return request
}

func cloneOperationReceipt(receipt OperationReceipt) OperationReceipt {
	receipt.Request = cloneRequest(receipt.Request)
	return receipt
}

func stableEffectID(scope CommandScope, commandID, commandDigest, projectionDigest string, withdraw bool) string {
	sum := sha256.Sum256([]byte(
		"cyberpanel:site-effect:v2\x00" +
			scope.TenantID.String() + "\x00" +
			scope.SiteID.String() + "\x00" +
			commandID + "\x00" +
			commandDigest + "\x00" +
			projectionDigest + "\x00" +
			strconv.FormatBool(withdraw),
	))
	return "effect-" + hex.EncodeToString(sum[:])
}

type projectionDigestDTO struct {
	Version    int                `json:"v"`
	Generation uint64             `json:"generation"`
	Lifecycle  site.Lifecycle     `json:"lifecycle"`
	PHPProfile site.PHPProfile    `json:"php_profile"`
	Bindings   []bindingDigestDTO `json:"bindings"`
}

type bindingDigestDTO struct {
	Hostname       string              `json:"hostname"`
	Kind           site.BindingKind    `json:"kind"`
	RedirectTarget string              `json:"redirect_target,omitempty"`
	RedirectStatus site.RedirectStatus `json:"redirect_status,omitempty"`
}

func projectionDigest(projection SiteProjection) string {
	bindings := make([]bindingDigestDTO, 0, len(projection.Bindings))
	for _, binding := range projection.Bindings {
		bindings = append(bindings, bindingDigestDTO{
			Hostname:       binding.Hostname.String(),
			Kind:           binding.Kind,
			RedirectTarget: binding.RedirectTarget.String(),
			RedirectStatus: binding.RedirectStatus,
		})
	}
	sort.Slice(bindings, func(left, right int) bool {
		if bindings[left].Hostname != bindings[right].Hostname {
			return bindings[left].Hostname < bindings[right].Hostname
		}
		return bindings[left].Kind < bindings[right].Kind
	})
	encoded, _ := json.Marshal(projectionDigestDTO{
		Version:    2,
		Generation: projection.Generation,
		Lifecycle:  projection.Lifecycle,
		PHPProfile: projection.PHPProfile,
		Bindings:   bindings,
	})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

type commandDigestDTO struct {
	Version            int    `json:"v"`
	Type               string `json:"type"`
	CommandID          string `json:"command_id"`
	ActorTenantID      string `json:"actor_tenant_id"`
	TenantID           string `json:"tenant_id"`
	SiteID             string `json:"site_id,omitempty"`
	ProjectID          string `json:"project_id,omitempty"`
	PrimaryHostname    string `json:"primary_hostname,omitempty"`
	PHPProfile         site.PHPProfile `json:"php_profile,omitempty"`
	ExpectedGeneration uint64 `json:"expected_generation,omitempty"`
}

func canonicalDigest(value commandDigestDTO) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
