package controlplane

import(
	"encoding/json"
	"errors"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)
var(ErrInvalid=errors.New("control plane: invalid value");ErrNotFound=errors.New("control plane: not found");ErrForbidden=errors.New("control plane: forbidden");ErrConflict=errors.New("control plane: conflict");ErrStale=errors.New("control plane: stale projection"))
type NodeState string
const(NodeEnrolling NodeState="enrolling";NodeOnline NodeState="online";NodeOffline NodeState="offline";NodeRevoking NodeState="revoking";NodeRevoked NodeState="revoked";NodeDegraded NodeState="degraded")
type Node struct{ID,OwnerTenantID federation.ID;Name string;State NodeState;AuthorityEpoch uint64;Capabilities federation.CapabilitySet;ProjectionSequence,SnapshotGeneration uint64;LastSeenAt,CreatedAt,UpdatedAt time.Time;CertificateFingerprint string}
type Projection struct{NodeID federation.ID;TenantID,ResourceKind,ResourceID string;Generation uint64;Status json.RawMessage;Digest string;ObservedAt time.Time;EventSequence uint64;Stale bool}
type Operator struct{PrincipalID,TenantID string;Permissions []string;Assurance,SessionID string;AuthzEpoch uint64}
type IntentRequest struct{NodeID federation.ID;GrantID federation.ID;CommandType,SchemaHash string;Payload json.RawMessage;TenantID,ResourceKind,ResourceID string;ExpectedGeneration uint64;IdempotencyKey string;Risk federation.Risk;Approval *federation.Approval}
type SagaState string
const(SagaPending SagaState="pending";SagaRunning SagaState="running";SagaPaused SagaState="paused";SagaApplied SagaState="applied";SagaCompensating SagaState="compensating";SagaFailed SagaState="failed")
type Saga struct{ID,OwnerTenantID federation.ID;Kind string;State SagaState;Steps []SagaStep;Current uint32;CreatedAt,UpdatedAt time.Time;ErrorCode string}
type SagaStep struct{ID string;NodeID federation.ID;IntentID federation.ID;CommandType string;Dependencies []string;Compensation *IntentRequest;Status federation.IntentStatus;Receipt *federation.Receipt}
type EncryptedSecret struct{TargetNodeID federation.ID;SecretID string;Version uint64;Purpose,AudienceDigest,KeyID,Algorithm string;EncapsulatedKey,Ciphertext []byte;ExpiresAt time.Time}
