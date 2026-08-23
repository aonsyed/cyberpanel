package mail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidCommand = errors.New("invalid mail command")
	ErrUnauthorized = errors.New("mail command is outside the tenant scope")
	ErrConflict = errors.New("mail resource generation conflict")
	ErrRateLimited = errors.New("mail delivery admission limit reached")
	ErrSuppressed = errors.New("mail recipient is currently suppressed")
	ErrCampaignPaused = fmt.Errorf("%w: campaign is paused", ErrConflict)
	ErrCampaignStopped = fmt.Errorf("%w: campaign is no longer sendable", ErrConflict)
	ErrNotFound = errors.New("mail resource not found")
	ErrAmbiguous = errors.New("mail effect outcome is ambiguous")
	ErrInvalidReceipt = errors.New("invalid mail effect receipt")
)

type ResourceKind string
const (
	ResourceDomain ResourceKind = "mail.domain"
	ResourceMailbox ResourceKind = "mail.mailbox"
	ResourceAlias ResourceKind = "mail.alias"
	ResourcePolicy ResourceKind = "mail.policy"
	ResourceQueue ResourceKind = "mail.queue_message"
	ResourceSieve ResourceKind = "mail.sieve_rule"
	ResourceCampaign ResourceKind = "marketing.campaign"
)

type Action string
const (
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
	ActionSuspend Action = "suspend"
	ActionResume Action = "resume"
	ActionRotateCredential Action = "rotate_credential"
	ActionRetry Action = "retry"
	ActionFlush Action = "flush"
	ActionCancel Action = "cancel"
)

type ResourceState string
const (
	StatePending ResourceState = "pending"
	StateActive ResourceState = "active"
	StateSuspended ResourceState = "suspended"
	StateDeleting ResourceState = "deleting"
	StateDeleted ResourceState = "deleted"
	StateDegraded ResourceState = "degraded"
)

type ResourceEnvelope struct {
	Kind ResourceKind `json:"kind"`
	ID string `json:"id"`
	TenantID string `json:"tenant_id"`
	Generation uint64 `json:"generation"`
	State ResourceState `json:"state"`
	Spec json.RawMessage `json:"spec"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Command struct {
	ID string `json:"id"`
	IdempotencyKey string `json:"idempotency_key"`
	ActorID string `json:"actor_id"`
	TenantID string `json:"tenant_id"`
	Kind ResourceKind `json:"kind"`
	ResourceID string `json:"resource_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	Action Action `json:"action"`
	Domain *Domain `json:"domain,omitempty"`
	Mailbox *Mailbox `json:"mailbox,omitempty"`
	Alias *Alias `json:"alias,omitempty"`
	Policy *Policy `json:"policy,omitempty"`
	Sieve *SieveRule `json:"sieve,omitempty"`
	Campaign *Campaign `json:"campaign,omitempty"`
	Queue *QueueItem `json:"queue,omitempty"`
}

type OperationStatus string
const (
	OperationAccepted OperationStatus = "accepted"
	OperationApplied OperationStatus = "applied"
	OperationDegraded OperationStatus = "degraded"
	OperationAmbiguous OperationStatus = "ambiguous"
	OperationRejected OperationStatus = "rejected"
)

type EffectOutcome string
const (
	EffectConfirmed EffectOutcome = "confirmed"
	EffectRejected EffectOutcome = "rejected"
	EffectUnknown EffectOutcome = "unknown"
)

type EffectRequest struct {
	EffectID string `json:"effect_id"`
	CommandID string `json:"command_id"`
	CommandDigest string `json:"command_digest"`
	TenantID string `json:"tenant_id"`
	Kind ResourceKind `json:"kind"`
	ResourceID string `json:"resource_id"`
	Generation uint64 `json:"generation"`
	Action Action `json:"action"`
	Desired *ResourceEnvelope `json:"desired,omitempty"`
	Previous *ResourceEnvelope `json:"previous,omitempty"`
	DesiredDigest string `json:"desired_digest"`
}

type EffectReceipt struct {
	EffectID string `json:"effect_id"`
	DesiredDigest string `json:"desired_digest"`
	Generation uint64 `json:"generation"`
	Outcome EffectOutcome `json:"outcome"`
	AppliedGeneration string `json:"applied_generation,omitempty"`
	ProbeDigest string `json:"probe_digest,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	Detail string `json:"detail,omitempty"`
}

type OperationReceipt struct {
	CommandID string `json:"command_id"`
	CommandDigest string `json:"command_digest"`
	TenantID string `json:"tenant_id"`
	Kind ResourceKind `json:"kind"`
	ResourceID string `json:"resource_id"`
	Status OperationStatus `json:"status"`
	Request EffectRequest `json:"request"`
	Effect EffectReceipt `json:"effect,omitempty"`
	AcceptedAt time.Time `json:"accepted_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type Admission struct { Command Command; Digest string; Proposal *ResourceEnvelope; Request EffectRequest }
type AdmissionResult struct { New bool; Receipt OperationReceipt }
type Completion struct { CommandID string; CommandDigest string; TenantID string; Request EffectRequest; Effect EffectReceipt; Status OperationStatus; Resource *ResourceEnvelope }

type ControlRepository interface {
	Lookup(context.Context, string, string) (OperationReceipt, bool, error)
	Load(context.Context, string, ResourceKind, string) (ResourceEnvelope, bool, error)
	Admit(context.Context, Admission) (AdmissionResult, error)
	Complete(context.Context, Completion) (OperationReceipt, error)
	List(context.Context, string, ResourceKind, int, string) ([]ResourceEnvelope, string, error)
}

// HostExecutor owns only closed mail effects. It may render and activate daemon
// generations, operate a specific queue ID, or update a registry-bound mailbox;
// it never receives command text or a caller-selected host path.
type HostExecutor interface { ObserveOrApply(context.Context, EffectRequest) (EffectReceipt, error) }
type QueueRuntime interface {
	Queue(context.Context, MailQueueAction, QueueID) (MailQueueReceipt, error)
	ListQueue(context.Context, uint32) ([]MailQueueRecord, string, error)
}

type Coordinator struct { Store ControlRepository; Executor HostExecutor; DKIMRotation *DKIMRotationService; Now func() time.Time }

func (c Coordinator) Handle(ctx context.Context, command Command) (OperationReceipt, error) {
	if ctx == nil || c.Store == nil || c.Executor == nil { return OperationReceipt{}, ErrInvalidCommand }
	digest, err := ValidateCommand(command); if err != nil { return OperationReceipt{}, err }
	if prior, found, err := c.Store.Lookup(ctx, command.ID, digest); err != nil { return OperationReceipt{}, err } else if found {
		if !receiptBound(prior, command, digest) { return OperationReceipt{}, ErrInvalidReceipt }
		if prior.Status != OperationAccepted && prior.Status != OperationAmbiguous { return prior, nil }
		return c.observeAndComplete(ctx, command, digest, prior.Request)
	}
	previous, exists, err := c.Store.Load(ctx, command.TenantID, command.Kind, command.ResourceID); if err != nil { return OperationReceipt{}, err }
	proposal, err := applyCommand(command, previous, exists, c.now()); if err != nil { return OperationReceipt{}, err }
	request, err := effectRequest(command, digest, previous, exists, proposal); if err != nil { return OperationReceipt{}, err }
	admitted, err := c.Store.Admit(ctx, Admission{Command:command,Digest:digest,Proposal:proposal,Request:request}); if err != nil { return OperationReceipt{}, err }
	if !admitted.New {
		if !receiptBound(admitted.Receipt, command, digest) || !requestsEqual(admitted.Receipt.Request, request) { return OperationReceipt{}, ErrInvalidReceipt }
		if admitted.Receipt.Status != OperationAccepted && admitted.Receipt.Status != OperationAmbiguous { return admitted.Receipt, nil }
	}
	return c.observeAndComplete(ctx, command, digest, request)
}

func (c Coordinator) observeAndComplete(ctx context.Context, command Command, digest string, request EffectRequest) (OperationReceipt, error) {
	effect, callErr := c.Executor.ObserveOrApply(ctx, request)
	status := OperationAmbiguous
	if validEffect(effect, request) {
		switch effect.Outcome { case EffectConfirmed: status = OperationApplied; case EffectRejected: status = OperationDegraded }
	}
	if callErr != nil && effect.EffectID == "" { effect = EffectReceipt{EffectID:request.EffectID,DesiredDigest:request.DesiredDigest,Generation:request.Generation,Outcome:EffectUnknown,ObservedAt:c.now(),Detail:callErr.Error()} }
	var resource *ResourceEnvelope
	if status == OperationApplied && request.Desired != nil { next:=*request.Desired;switch request.Action{case ActionSuspend:next.State=StateSuspended;case ActionDelete:next.State=StateDeleted;default:next.State=StateActive};resource=&next }
	receipt, err := c.Store.Complete(ctx, Completion{CommandID:command.ID,CommandDigest:digest,TenantID:command.TenantID,Request:request,Effect:effect,Status:status,Resource:resource})
	if err != nil { return OperationReceipt{}, err }
	if status == OperationAmbiguous { if callErr != nil { return receipt, errors.Join(ErrAmbiguous,callErr) }; return receipt, ErrAmbiguous }
	if callErr != nil { return receipt, callErr }
	return receipt, nil
}

func ValidateCommand(command Command) (string, error) {
	if !validOpaque(command.ID) || !validOpaque(command.IdempotencyKey) || !validOpaque(command.ActorID) || !validOpaque(command.TenantID) || !validOpaque(command.ResourceID) { return "", ErrInvalidCommand }
	if !validKind(command.Kind) || !validAction(command.Action) { return "", ErrInvalidCommand }
	count := 0; for _, present := range []bool{command.Domain!=nil,command.Mailbox!=nil,command.Alias!=nil,command.Policy!=nil,command.Sieve!=nil,command.Campaign!=nil,command.Queue!=nil} { if present { count++ } }
	if command.Action == ActionDelete || command.Action == ActionSuspend || command.Action == ActionResume || command.Action == ActionRetry || command.Action == ActionFlush || command.Action == ActionCancel { if count != 0 { return "", ErrInvalidCommand } } else if count != 1 { return "", ErrInvalidCommand }
	if !payloadMatches(command) { return "", ErrInvalidCommand }
	canonical, err := json.Marshal(struct{Version uint8 `json:"version"`;Command Command `json:"command"`}{1,command}); if err != nil { return "", err }
	sum := sha256.Sum256(canonical); return hex.EncodeToString(sum[:]), nil
}

func applyCommand(command Command, current ResourceEnvelope, exists bool, now time.Time) (*ResourceEnvelope, error) {
	if command.Action == ActionCreate && exists { return nil, ErrConflict }
	if command.Action != ActionCreate && !exists { return nil, ErrNotFound }
	if exists && (current.TenantID != command.TenantID || current.Kind != command.Kind || current.ID != command.ResourceID) { return nil, ErrUnauthorized }
	if exists && current.Generation != command.ExpectedGeneration { return nil, ErrConflict }
	if !exists && command.ExpectedGeneration != 0 { return nil, ErrConflict }
	if command.Action == ActionDelete { deleted:=current;deleted.Generation++;deleted.State=StateDeleted;deleted.UpdatedAt=now;return &deleted,nil }
	next:=current;if !exists { next=ResourceEnvelope{Kind:command.Kind,ID:command.ResourceID,TenantID:command.TenantID,Generation:1,State:StatePending} } else { next.Generation++ }
	switch command.Action { case ActionSuspend: next.State=StateSuspended; case ActionResume: next.State=StateActive; case ActionRetry,ActionFlush,ActionCancel: next.State=StatePending; default: next.State=StatePending;spec,err:=commandSpec(command);if err!=nil{return nil,err};next.Spec=spec }
	next.UpdatedAt=now;return &next,nil
}

func effectRequest(command Command, digest string, previous ResourceEnvelope, exists bool, desired *ResourceEnvelope) (EffectRequest,error) {
	desiredRaw,err:=json.Marshal(desired);if err!=nil{return EffectRequest{},err};sum:=sha256.Sum256(desiredRaw);desiredDigest:=hex.EncodeToString(sum[:]);effectSum:=sha256.Sum256([]byte("mail-effect-v1\x00"+command.TenantID+"\x00"+command.ID+"\x00"+digest+"\x00"+desiredDigest));request:=EffectRequest{EffectID:"mailfx_"+hex.EncodeToString(effectSum[:])[:48],CommandID:command.ID,CommandDigest:digest,TenantID:command.TenantID,Kind:command.Kind,ResourceID:command.ResourceID,Generation:desired.Generation,Action:command.Action,Desired:desired,DesiredDigest:desiredDigest};if exists{copy:=previous;request.Previous=&copy};return request,nil
}

func commandSpec(command Command) (json.RawMessage,error) { var value any;switch command.Kind{case ResourceDomain:value=command.Domain;case ResourceMailbox:value=command.Mailbox;case ResourceAlias:value=command.Alias;case ResourcePolicy:value=command.Policy;case ResourceSieve:value=command.Sieve;case ResourceCampaign:value=command.Campaign;case ResourceQueue:value=command.Queue;default:return nil,ErrInvalidCommand};return json.Marshal(value) }
func payloadMatches(c Command) bool { if c.Action==ActionDelete||c.Action==ActionSuspend||c.Action==ActionResume{return true};switch c.Kind { case ResourceDomain:return c.Domain!=nil;case ResourceMailbox:return c.Mailbox!=nil;case ResourceAlias:return c.Alias!=nil;case ResourcePolicy:return c.Policy!=nil;case ResourceSieve:return c.Sieve!=nil;case ResourceCampaign:return c.Campaign!=nil;case ResourceQueue:return c.Queue!=nil||c.Action==ActionRetry||c.Action==ActionCancel||c.Action==ActionFlush };return false }
func validEffect(effect EffectReceipt, request EffectRequest) bool { return effect.EffectID==request.EffectID&&effect.DesiredDigest==request.DesiredDigest&&effect.Generation==request.Generation&&(effect.Outcome==EffectConfirmed||effect.Outcome==EffectRejected||effect.Outcome==EffectUnknown)&&!effect.ObservedAt.IsZero() }
func receiptBound(receipt OperationReceipt,c Command,digest string)bool{return receipt.CommandID==c.ID&&receipt.CommandDigest==digest&&receipt.TenantID==c.TenantID&&receipt.Kind==c.Kind&&receipt.ResourceID==c.ResourceID&&receipt.Request.CommandID==c.ID&&receipt.Request.CommandDigest==digest}
func requestsEqual(left,right EffectRequest)bool{leftRaw,leftErr:=json.Marshal(left);rightRaw,rightErr:=json.Marshal(right);return leftErr==nil&&rightErr==nil&&string(leftRaw)==string(rightRaw)}
func validKind(k ResourceKind)bool{switch k{case ResourceDomain,ResourceMailbox,ResourceAlias,ResourcePolicy,ResourceQueue,ResourceSieve,ResourceCampaign:return true};return false}
func validAction(a Action)bool{switch a{case ActionCreate,ActionUpdate,ActionDelete,ActionSuspend,ActionResume,ActionRotateCredential,ActionRetry,ActionFlush,ActionCancel:return true};return false}
func validOpaque(value string)bool{if len(value)<1||len(value)>160{return false};for _,r:=range value{if !(r=='-'||r=='_'||r=='.'||r>='0'&&r<='9'||r>='a'&&r<='z'||r>='A'&&r<='Z'){return false}};return true}
func (c Coordinator) now()time.Time{if c.Now!=nil{return c.Now().UTC()};return time.Now().UTC()}

func ValidateAddress(address Address) error { value:=strings.ToLower(strings.TrimSpace(string(address)));if len(value)>254||strings.Count(value,"@")!=1||strings.ContainsAny(value,"\x00\r\n\t"){return fmt.Errorf("%w: address",ErrInvalidCommand)};parts:=strings.SplitN(value,"@",2);if !validLocalPart(parts[0])||!validHostname(parts[1]){return fmt.Errorf("%w: address",ErrInvalidCommand)};return nil }
func NormalizeAddresses(values []Address)([]Address,error){out:=make([]Address,0,len(values));seen:=map[Address]struct{}{};for _,value:=range values{normalized:=Address(strings.ToLower(strings.TrimSpace(string(value))));if err:=ValidateAddress(normalized);err!=nil{return nil,err};if _,ok:=seen[normalized];ok{continue};seen[normalized]=struct{}{};out=append(out,normalized)};sort.Slice(out,func(i,j int)bool{return out[i]<out[j]});return out,nil}
func validHostname(value string)bool{value=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)),".");if len(value)<1||len(value)>253{return false};for _,label:=range strings.Split(value,"."){if len(label)<1||len(label)>63||label[0]=='-'||label[len(label)-1]=='-'{return false};for _,r:=range label{if !(r=='-'||r>='0'&&r<='9'||r>='a'&&r<='z'){return false}}};return strings.Contains(value,".")}
func validLocalPart(value string)bool{if value==""||len(value)>64||value[0]=='.'||value[len(value)-1]=='.'||strings.Contains(value,".."){return false};for _,r:=range value{if !(r>='0'&&r<='9'||r>='a'&&r<='z'||r>='A'&&r<='Z'||strings.ContainsRune(".!#$%&'*+-=?^_`{|}~",r)){return false}};return true}
