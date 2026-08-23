package audit

import(
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var(ErrInvalid=errors.New("audit: invalid value");ErrNotFound=errors.New("audit: not found");ErrConflict=errors.New("audit: conflict");ErrIntegrity=errors.New("audit: integrity failure");ErrCapacity=errors.New("audit: capacity exhausted"))
var idPattern=regexp.MustCompile(`^[a-zA-Z0-9._:-]{8,192}$`)
type EventClass string
const(ClassMutation EventClass="mutation";ClassPrivilegedEffect EventClass="privileged_effect";ClassAuthorization EventClass="authorization";ClassAuthentication EventClass="authentication";ClassSecretDelivery EventClass="secret_delivery";ClassSensitiveRead EventClass="sensitive_read";ClassSecurity EventClass="security";ClassSafetyRecovery EventClass="safety_recovery";ClassSystem EventClass="system")
type Outcome string
const(OutcomeAllowed Outcome="allowed";OutcomeDenied Outcome="denied";OutcomeApplied Outcome="applied";OutcomeRejected Outcome="rejected";OutcomeAmbiguous Outcome="ambiguous";OutcomeFailed Outcome="failed")
type Actor struct{PrincipalID,CredentialID,SessionID,ServiceID string;TenantID string;AuthzEpoch uint64;Assurance string;Origin string;DelegationChain []string}
type Target struct{Kind,ID,TenantID,Generation string}
type Event struct{ID string;Class EventClass;Action string;Actor Actor;Target Target;Outcome Outcome;RequestDigest,DecisionDigest,EffectID,TraceID,ParentID string;Attributes map[string]string;OccurredAt time.Time}
func(e Event)Validate()error{if !idPattern.MatchString(e.ID)||!validClass(e.Class)||strings.TrimSpace(e.Action)==""||!validOutcome(e.Outcome)||len(e.RequestDigest)!=64||e.OccurredAt.IsZero(){return fmt.Errorf("%w: event",ErrInvalid)};if len(e.Attributes)>64{return fmt.Errorf("%w: attributes",ErrInvalid)};for key,value:=range e.Attributes{if len(key)>64||len(value)>4096||strings.ContainsRune(key,0)||strings.ContainsRune(value,0){return fmt.Errorf("%w: attribute",ErrInvalid)}};return nil}
type Record struct{Sequence uint64;Event Event;PreviousHash,Hash string;WrittenAt time.Time}
type Checkpoint struct{Sequence uint64;HeadHash,SegmentID,Signature,KeyID string;CreatedAt time.Time}
type Prepared struct{EventID,EventDigest string;PreparedAt time.Time}
type Query struct{TenantID string `json:"tenant_id,omitempty"`;ActorID string `json:"actor_id,omitempty"`;TargetKind string `json:"target_kind,omitempty"`;TargetID string `json:"target_id,omitempty"`;Action string `json:"action,omitempty"`;EffectID string `json:"effect_id,omitempty"`;TraceID string `json:"trace_id,omitempty"`;Classes []EventClass `json:"classes,omitempty"`;Outcomes []Outcome `json:"outcomes,omitempty"`;From time.Time `json:"from,omitempty"`;To time.Time `json:"to,omitempty"`;AfterSequence uint64 `json:"after_sequence,omitempty"`;Limit uint32 `json:"limit,omitempty"`}
func validClass(v EventClass)bool{switch v{case ClassMutation,ClassPrivilegedEffect,ClassAuthorization,ClassAuthentication,ClassSecretDelivery,ClassSensitiveRead,ClassSecurity,ClassSafetyRecovery,ClassSystem:return true};return false}
func validOutcome(v Outcome)bool{switch v{case OutcomeAllowed,OutcomeDenied,OutcomeApplied,OutcomeRejected,OutcomeAmbiguous,OutcomeFailed:return true};return false}
