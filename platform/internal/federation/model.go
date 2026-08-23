package federation

import(
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)
var(ErrInvalid=errors.New("federation: invalid value");ErrForbidden=errors.New("federation: forbidden");ErrExpired=errors.New("federation: expired");ErrStale=errors.New("federation: stale authority or generation");ErrReplay=errors.New("federation: replay");ErrConflict=errors.New("federation: conflict");ErrOffline=errors.New("federation: offline");ErrAmbiguous=errors.New("federation: ambiguous outcome"))
var idPattern=regexp.MustCompile(`^[a-z][a-z0-9_-]{2,95}$`)
type ID string
func NewID(v string)(ID,error){v=strings.TrimSpace(v);if !idPattern.MatchString(v){return "",ErrInvalid};return ID(v),nil}
func(id ID)Valid()bool{return idPattern.MatchString(string(id))}
func(id ID)String()string{return string(id)}
type Risk string
const(RiskLow Risk="low";RiskModerate Risk="moderate";RiskHigh Risk="high";RiskCritical Risk="critical")
type Origin string
const(OriginLocalUI Origin="local_ui";OriginLocalAPI Origin="local_api";OriginLocalCLI Origin="local_cli";OriginScheduler Origin="scheduler";OriginFederation Origin="federation")
type Capability struct{CommandType,SchemaHash string;Version uint32;RemoteEligible bool;MinimumRisk Risk;Resources []string}
type CapabilitySet struct{NodeID ID;ProtocolVersion uint32;ProductVersion,BuildDigest,OS,Architecture,WebEngineEdition,WebEngineVersion string;AuthorityEpoch uint64;Capabilities []Capability;GeneratedAt time.Time;Digest string}
func(c CapabilitySet)CanonicalDigest()string{copy:=c;copy.Digest="";copy.Capabilities=append([]Capability(nil),c.Capabilities...);sort.Slice(copy.Capabilities,func(i,j int)bool{return copy.Capabilities[i].CommandType<copy.Capabilities[j].CommandType});raw,_:=json.Marshal(copy);sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:])}
type ResourceSelector struct{Kind,TenantID,ResourceID,LabelSelector string;Operations []string}
type MutationGrant struct{ID,PeerID,NodeID ID;AuthorityEpoch uint64;Selectors []ResourceSelector;MaximumRisk Risk;IssuedAt,ExpiresAt time.Time;RevokedAt *time.Time;Digest,SignatureKeyID string;Signature []byte}
func(g MutationGrant)Validate(now time.Time)error{if !g.ID.Valid()||!g.PeerID.Valid()||!g.NodeID.Valid()||g.AuthorityEpoch==0||len(g.Selectors)==0||g.IssuedAt.IsZero()||!g.ExpiresAt.After(g.IssuedAt)||!now.Before(g.ExpiresAt)||len(g.Digest)!=64||len(g.Signature)==0{return ErrInvalid};if g.RevokedAt!=nil{return ErrForbidden};return nil}
type Actor struct{PrincipalID,TenantID,CredentialID,SessionID string;AuthzEpoch uint64;Assurance,Display string}
type Approval struct{AuthorizationID,PlanDigest,DisplayDigest,PolicyVersion,SigningKeyID string;ExpiresAt time.Time;Signature []byte}
type Intent struct{ID,PeerID,NodeID,GrantID ID;AuthorityEpoch uint64;ProtocolVersion uint32;CommandType,SchemaHash string;Payload json.RawMessage;PayloadDigest string;TenantID,ResourceKind,ResourceID string;ExpectedGeneration uint64;IdempotencyKey,EffectID string;Risk Risk;ActorChain []Actor;Approval *Approval;IssuedAt,ExpiresAt time.Time;SigningKeyID string;Signature []byte}
func(i Intent)Validate(now time.Time)error{if !i.ID.Valid()||!i.PeerID.Valid()||!i.NodeID.Valid()||!i.GrantID.Valid()||i.AuthorityEpoch==0||i.ProtocolVersion==0||i.CommandType==""||len(i.SchemaHash)!=64||len(i.Payload)==0||len(i.Payload)>4<<20||len(i.PayloadDigest)!=64||i.TenantID==""||i.ResourceKind==""||i.ResourceID==""||i.IdempotencyKey==""||i.EffectID==""||i.IssuedAt.IsZero()||!i.ExpiresAt.After(i.IssuedAt)||!now.Before(i.ExpiresAt)||i.SigningKeyID==""||len(i.Signature)!=ed25519.SignatureSize{return ErrInvalid};canonical,err:=canonicalJSON(i.Payload);if err!=nil||digest(canonical)!=i.PayloadDigest{return ErrInvalid};return nil}
func(i Intent)SigStructure()[]byte{actors:=append([]Actor(nil),i.ActorChain...);envelope:=struct{Domain string `json:"domain"`;ID,PeerID,NodeID,GrantID ID;AuthorityEpoch uint64;ProtocolVersion uint32;CommandType,SchemaHash,PayloadDigest,TenantID,ResourceKind,ResourceID string;ExpectedGeneration uint64;IdempotencyKey,EffectID string;Risk Risk;ActorChain []Actor;ApprovalDigest string;IssuedAt,ExpiresAt time.Time;SigningKeyID string}{Domain:"cyberpanel-federated-intent-v1",ID:i.ID,PeerID:i.PeerID,NodeID:i.NodeID,GrantID:i.GrantID,AuthorityEpoch:i.AuthorityEpoch,ProtocolVersion:i.ProtocolVersion,CommandType:i.CommandType,SchemaHash:i.SchemaHash,PayloadDigest:i.PayloadDigest,TenantID:i.TenantID,ResourceKind:i.ResourceKind,ResourceID:i.ResourceID,ExpectedGeneration:i.ExpectedGeneration,IdempotencyKey:i.IdempotencyKey,EffectID:i.EffectID,Risk:i.Risk,ActorChain:actors,ApprovalDigest:digestJSON(i.Approval),IssuedAt:i.IssuedAt.UTC(),ExpiresAt:i.ExpiresAt.UTC(),SigningKeyID:i.SigningKeyID};raw,_:=json.Marshal(envelope);return raw}
type IntentStatus string
const(IntentQueued IntentStatus="queued";IntentAccepted IntentStatus="accepted";IntentRunning IntentStatus="running";IntentApplied IntentStatus="applied";IntentRejected IntentStatus="rejected";IntentAmbiguous IntentStatus="ambiguous";IntentExpired IntentStatus="expired")
type Receipt struct{IntentID ID;NodeID ID;EffectID,IdempotencyKey string;Status IntentStatus;OperationID,ResultDigest,ErrorCode,ErrorMessage string;LocalGeneration uint64;AcceptedAt,UpdatedAt time.Time;Terminal bool;SignatureKeyID string;Signature []byte}
func(r Receipt)SigStructure()[]byte{copy:=r;copy.Signature=nil;raw,_:=json.Marshal(struct{Domain string `json:"domain"`;Value Receipt `json:"value"`}{"cyberpanel-federation-receipt-v1",copy});return raw}
type EventPriority uint8
const(PriorityTelemetry EventPriority=1;PriorityState EventPriority=2;PrioritySecurity EventPriority=3;PriorityReceipt EventPriority=4;PriorityRevocation EventPriority=5)
type NodeEvent struct{ID,NodeID ID;Sequence uint64;Priority EventPriority;Kind,TenantID,ResourceID,ResourceKind string;Generation uint64;Payload json.RawMessage;PayloadDigest string;OccurredAt time.Time;SignatureKeyID string;Signature []byte}
func(e NodeEvent)SigStructure()[]byte{copy:=e;copy.Signature=nil;raw,_:=json.Marshal(struct{Domain string `json:"domain"`;Value NodeEvent `json:"value"`}{"cyberpanel-federation-event-v1",copy});return raw}
type ProjectionCursor struct{PeerID,NodeID ID;EventSequence,SnapshotGeneration uint64;LastReceiptAt,UpdatedAt time.Time}
type Revocation struct{PeerID,NodeID ID;NewAuthorityEpoch uint64;GrantIDs []ID;Reason string;IssuedAt time.Time;SigningKeyID string;Signature []byte}
func canonicalJSON(raw []byte)([]byte,error){var value any;decoder:=json.NewDecoder(strings.NewReader(string(raw)));decoder.UseNumber();if err:=decoder.Decode(&value);err!=nil{return nil,err};var extra any;if err:=decoder.Decode(&extra);!errors.Is(err,io.EOF){return nil,ErrInvalid};return json.Marshal(value)}
func digest(raw []byte)string{sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:])}
func digestJSON(v any)string{if v==nil{return strings.Repeat("0",64)};raw,_:=json.Marshal(v);return digest(raw)}
func riskAllows(maximum,requested Risk)bool{rank:=map[Risk]int{RiskLow:1,RiskModerate:2,RiskHigh:3,RiskCritical:4};return rank[requested]>0&&rank[requested]<=rank[maximum]}
func selectorAllows(selector ResourceSelector,intent Intent)bool{if selector.Kind!="*"&&selector.Kind!=intent.ResourceKind{return false};if selector.TenantID!="*"&&selector.TenantID!=intent.TenantID{return false};if selector.ResourceID!="*"&&selector.ResourceID!=intent.ResourceID{return false};for _,operation:=range selector.Operations{if operation=="*"||operation==intent.CommandType{return true}};return false}
var _=fmt.Sprintf
