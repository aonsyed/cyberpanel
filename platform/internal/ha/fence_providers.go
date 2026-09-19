package ha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const (
	LocalMariaDBFenceProviderBinding         = "local-mariadb-fence"
	LocalMandatoryLeaseFenceProviderBinding = "local-writer-lease-fence"
	AdministrativeFenceApprovalKind         = "ha-administrative-fence"
	localFenceProofLifetime                  = 2 * time.Minute
	maximumAdministrativeFenceApprovals      = 16
	minimumAdministrativeFenceApprovals      = 2
)

// AdministrativeApprovalVerifier is the cryptographic boundary for manual
// fencing. Implementations must verify that approval.Signature authenticates
// the complete fence and approval, including the challenge and actor identity.
type AdministrativeApprovalVerifier interface {
	VerifyAdministrativeApproval(context.Context, Fence, Approval) error
}

// LocalMariaDBFenceProvider combines the database writer gate with the
// independent lease authority. A read-only observation alone is not accepted
// as proof while the previous writer can still hold write authority.
type LocalMariaDBFenceProvider struct {
	Store       Store
	Database    DatabaseReplicationExecutor
	Leases      LeaseAuthority
	LocalNodeID NodeID
	Now         func() time.Time
}

func NewLocalMariaDBFenceProvider(store Store, database DatabaseReplicationExecutor, leases LeaseAuthority, localNodeID NodeID, now func() time.Time) (*LocalMariaDBFenceProvider, error) {
	if store == nil || database == nil || leases == nil || !validID(string(localNodeID)) {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &LocalMariaDBFenceProvider{Store: store, Database: database, Leases: leases, LocalNodeID: localNodeID, Now: now}, nil
}

func (*LocalMariaDBFenceProvider) Class() FenceClass { return FenceDatabase }

type localMariaDBFenceEvidence struct {
	Version                 uint8         `json:"version"`
	FenceID                 FenceID       `json:"fence_id"`
	GroupID                 NodeGroupID   `json:"group_id"`
	ProviderBindingID       string        `json:"provider_binding_id"`
	ResourceID              string        `json:"resource_id"`
	TargetNodeID            NodeID        `json:"target_node_id"`
	LeaseID                 WriterLeaseID `json:"lease_id"`
	RevokedFencingToken     uint64        `json:"revoked_fencing_token"`
	FenceFencingToken       uint64        `json:"fence_fencing_token"`
	AuthorityEpoch          uint64        `json:"authority_epoch"`
	QuorumDigest            string        `json:"quorum_digest"`
	Challenge               string        `json:"challenge"`
	ProtectedWritePaths     []string      `json:"protected_write_paths"`
	DatabaseReceipt         string        `json:"database_receipt,omitempty"`
	DatabaseReceiptReturned bool          `json:"database_receipt_returned"`
	ObservedSequence        uint64        `json:"observed_sequence"`
	ObservedGTID            string        `json:"observed_gtid"`
	ReadOnly                bool          `json:"read_only"`
	LeaseState              LeaseState    `json:"lease_state"`
	LeaseGeneration         uint64        `json:"lease_generation"`
	ObservedAt              time.Time     `json:"observed_at"`
}

func (provider *LocalMariaDBFenceProvider) Fence(ctx context.Context, request FenceRequest) (FenceReceipt, error) {
	now := provider.current()
	if provider == nil || provider.Store == nil || provider.Database == nil || provider.Leases == nil {
		return FenceReceipt{}, ErrUnsupported
	}
	if err := validateLocalFenceRequest(ctx, request, FenceDatabase, LocalMariaDBFenceProviderBinding, provider.LocalNodeID, now); err != nil {
		return FenceReceipt{}, err
	}
	lease, err := provider.Store.ActiveWriterLeaseByResource(ctx, LocalMariaDBResourceID)
	if err != nil {
		return FenceReceipt{}, errors.Join(err, ErrFenceFailed)
	}
	if err = validateLeaseForFence(lease, request.Fence); err != nil {
		return FenceReceipt{}, err
	}
	cluster, err := localMariaDBCluster(ctx, provider.Store, lease.ResourceID)
	if err != nil || cluster.GroupID != request.Fence.GroupID {
		return FenceReceipt{}, errors.Join(err, ErrFenceFailed)
	}
	databaseReceipt, freezeErr := provider.Database.FreezeDatabaseWrites(ctx, cluster, request.Fence.TargetNodeID, request.Fence.FencingToken)
	if freezeErr != nil || databaseReceipt == "" {
		return FenceReceipt{}, errors.Join(freezeErr, ErrFenceFailed)
	}
	observed, observeErr := provider.Database.ObserveCluster(ctx, cluster)
	member, memberErr := requiredDatabaseMember(observed, request.Fence.TargetNodeID)
	if observeErr != nil || memberErr != nil || !member.ReadOnly {
		return FenceReceipt{}, errors.Join(freezeErr, observeErr, memberErr, ErrFenceFailed)
	}
	terminated, err := revokeAndObserveLease(ctx, provider.Leases, lease)
	if err != nil {
		return FenceReceipt{}, err
	}
	appliedAt := provider.current()
	evidence := localMariaDBFenceEvidence{
		Version: 1, FenceID: request.Fence.ID, GroupID: request.Fence.GroupID, ProviderBindingID: request.Fence.ProviderBindingID,
		ResourceID: lease.ResourceID, TargetNodeID: request.Fence.TargetNodeID, LeaseID: lease.ID,
		RevokedFencingToken: lease.FencingToken, FenceFencingToken: request.Fence.FencingToken,
		AuthorityEpoch: request.Fence.AuthorityEpoch, QuorumDigest: request.Quorum.Digest,
		Challenge: request.Fence.Challenge, ProtectedWritePaths: canonicalWritePaths(request.Fence.ProtectedWritePaths),
		DatabaseReceipt: databaseReceipt, DatabaseReceiptReturned: databaseReceipt != "",
		ObservedSequence: member.Sequence, ObservedGTID: member.GTID, ReadOnly: true,
		LeaseState: terminated.State, LeaseGeneration: terminated.Generation, ObservedAt: appliedAt,
	}
	return newFenceReceipt(request.Fence, evidence, appliedAt, fenceProofDeadline(appliedAt, request.Quorum.ValidUntil))
}

func (provider *LocalMariaDBFenceProvider) Observe(ctx context.Context, request FenceRequest, receipt FenceReceipt) (FenceReceipt, error) {
	now := provider.current()
	if provider == nil || provider.Store == nil || provider.Database == nil || provider.Leases == nil {
		return FenceReceipt{}, ErrUnsupported
	}
	if err := validateLocalFenceRequest(ctx, request, FenceDatabase, LocalMariaDBFenceProviderBinding, provider.LocalNodeID, now); err != nil {
		return FenceReceipt{}, err
	}
	if err := validateLocalFenceReceipt(request.Fence, receipt, now); err != nil {
		return FenceReceipt{}, err
	}
	var evidence localMariaDBFenceEvidence
	if json.Unmarshal([]byte(receipt.ProviderReceipt), &evidence) != nil || !mariaDBEvidenceMatchesRequest(evidence, request) || evidence.ObservedAt.IsZero() || !evidence.ObservedAt.Equal(receipt.AppliedAt) {
		return FenceReceipt{}, ErrFenceFailed
	}
	if fenceEvidenceDigest([]byte(receipt.ProviderReceipt)) != receipt.ProofDigest {
		return FenceReceipt{}, ErrFenceFailed
	}
	lease, err := provider.Leases.ObserveWriterLease(ctx, evidence.LeaseID)
	if err != nil || validateObservedFencedLease(lease, evidence.LeaseID, evidence.GroupID, evidence.ResourceID, evidence.TargetNodeID, evidence.RevokedFencingToken, evidence.AuthorityEpoch, evidence.ProtectedWritePaths) != nil {
		return FenceReceipt{}, errors.Join(err, ErrFenceFailed)
	}
	cluster, err := localMariaDBCluster(ctx, provider.Store, evidence.ResourceID)
	if err != nil {
		return FenceReceipt{}, errors.Join(err, ErrFenceFailed)
	}
	observed, err := provider.Database.ObserveCluster(ctx, cluster)
	member, memberErr := requiredDatabaseMember(observed, evidence.TargetNodeID)
	if err != nil || memberErr != nil || !member.ReadOnly || member.Sequence < evidence.ObservedSequence {
		return FenceReceipt{}, errors.Join(err, memberErr, ErrFenceFailed)
	}
	return receipt, nil
}

func (*LocalMariaDBFenceProvider) Release(context.Context, FenceRequest, FenceReceipt) error {
	return ErrUnsupported
}

func (provider *LocalMariaDBFenceProvider) current() time.Time {
	if provider != nil && provider.Now != nil {
		return provider.Now().UTC()
	}
	return time.Now().UTC()
}

// MandatoryLeaseFenceProvider proves that the exact previous authority has
// ended. It never substitutes a newer token, epoch, holder, or lease.
type MandatoryLeaseFenceProvider struct {
	Store       Store
	Leases      LeaseAuthority
	LocalNodeID NodeID
	Now         func() time.Time
}

func NewMandatoryLeaseFenceProvider(store Store, leases LeaseAuthority, localNodeID NodeID, now func() time.Time) (*MandatoryLeaseFenceProvider, error) {
	if store == nil || leases == nil || !validID(string(localNodeID)) {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &MandatoryLeaseFenceProvider{Store: store, Leases: leases, LocalNodeID: localNodeID, Now: now}, nil
}

func (*MandatoryLeaseFenceProvider) Class() FenceClass { return FenceMandatoryLease }

type mandatoryLeaseFenceEvidence struct {
	Version             uint8         `json:"version"`
	FenceID             FenceID       `json:"fence_id"`
	GroupID             NodeGroupID   `json:"group_id"`
	ProviderBindingID   string        `json:"provider_binding_id"`
	ResourceID          string        `json:"resource_id"`
	TargetNodeID        NodeID        `json:"target_node_id"`
	LeaseID             WriterLeaseID `json:"lease_id"`
	RevokedFencingToken uint64        `json:"revoked_fencing_token"`
	FenceFencingToken   uint64        `json:"fence_fencing_token"`
	AuthorityEpoch      uint64        `json:"authority_epoch"`
	QuorumDigest        string        `json:"quorum_digest"`
	Challenge           string        `json:"challenge"`
	ProtectedWritePaths []string      `json:"protected_write_paths"`
	LeaseState          LeaseState    `json:"lease_state"`
	LeaseGeneration     uint64        `json:"lease_generation"`
	ObservedAt          time.Time     `json:"observed_at"`
}

func (provider *MandatoryLeaseFenceProvider) Fence(ctx context.Context, request FenceRequest) (FenceReceipt, error) {
	now := provider.current()
	if provider == nil || provider.Store == nil || provider.Leases == nil {
		return FenceReceipt{}, ErrUnsupported
	}
	if err := validateLocalFenceRequest(ctx, request, FenceMandatoryLease, LocalMandatoryLeaseFenceProviderBinding, provider.LocalNodeID, now); err != nil {
		return FenceReceipt{}, err
	}
	lease, err := provider.Store.ActiveWriterLeaseByResource(ctx, LocalMariaDBResourceID)
	if err != nil {
		return FenceReceipt{}, errors.Join(err, ErrFenceFailed)
	}
	if err = validateLeaseForFence(lease, request.Fence); err != nil {
		return FenceReceipt{}, err
	}
	terminated, err := revokeAndObserveLease(ctx, provider.Leases, lease)
	if err != nil {
		return FenceReceipt{}, err
	}
	appliedAt := provider.current()
	evidence := mandatoryLeaseFenceEvidence{
		Version: 1, FenceID: request.Fence.ID, GroupID: request.Fence.GroupID, ProviderBindingID: request.Fence.ProviderBindingID,
		ResourceID: lease.ResourceID, TargetNodeID: request.Fence.TargetNodeID, LeaseID: lease.ID,
		RevokedFencingToken: lease.FencingToken, FenceFencingToken: request.Fence.FencingToken,
		AuthorityEpoch: request.Fence.AuthorityEpoch, QuorumDigest: request.Quorum.Digest,
		Challenge: request.Fence.Challenge, ProtectedWritePaths: canonicalWritePaths(request.Fence.ProtectedWritePaths),
		LeaseState: terminated.State, LeaseGeneration: terminated.Generation, ObservedAt: appliedAt,
	}
	return newFenceReceipt(request.Fence, evidence, appliedAt, fenceProofDeadline(appliedAt, request.Quorum.ValidUntil))
}

func (provider *MandatoryLeaseFenceProvider) Observe(ctx context.Context, request FenceRequest, receipt FenceReceipt) (FenceReceipt, error) {
	now := provider.current()
	if provider == nil || provider.Store == nil || provider.Leases == nil {
		return FenceReceipt{}, ErrUnsupported
	}
	if err := validateLocalFenceRequest(ctx, request, FenceMandatoryLease, LocalMandatoryLeaseFenceProviderBinding, provider.LocalNodeID, now); err != nil {
		return FenceReceipt{}, err
	}
	if err := validateLocalFenceReceipt(request.Fence, receipt, now); err != nil {
		return FenceReceipt{}, err
	}
	var evidence mandatoryLeaseFenceEvidence
	if json.Unmarshal([]byte(receipt.ProviderReceipt), &evidence) != nil || !leaseEvidenceMatchesRequest(evidence, request) || evidence.ObservedAt.IsZero() || !evidence.ObservedAt.Equal(receipt.AppliedAt) {
		return FenceReceipt{}, ErrFenceFailed
	}
	if fenceEvidenceDigest([]byte(receipt.ProviderReceipt)) != receipt.ProofDigest {
		return FenceReceipt{}, ErrFenceFailed
	}
	lease, err := provider.Leases.ObserveWriterLease(ctx, evidence.LeaseID)
	if err != nil || validateObservedFencedLease(lease, evidence.LeaseID, evidence.GroupID, evidence.ResourceID, evidence.TargetNodeID, evidence.RevokedFencingToken, evidence.AuthorityEpoch, evidence.ProtectedWritePaths) != nil {
		return FenceReceipt{}, errors.Join(err, ErrFenceFailed)
	}
	return receipt, nil
}

func (*MandatoryLeaseFenceProvider) Release(context.Context, FenceRequest, FenceReceipt) error {
	return ErrUnsupported
}

func (provider *MandatoryLeaseFenceProvider) current() time.Time {
	if provider != nil && provider.Now != nil {
		return provider.Now().UTC()
	}
	return time.Now().UTC()
}

type AdministrativeFenceConfirmer struct {
	Verifier AdministrativeApprovalVerifier
	Now      func() time.Time
}

func NewAdministrativeFenceConfirmer(verifier AdministrativeApprovalVerifier, now func() time.Time) (*AdministrativeFenceConfirmer, error) {
	if verifier == nil {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &AdministrativeFenceConfirmer{Verifier: verifier, Now: now}, nil
}

type administrativeFenceEvidence struct {
	Version             uint8      `json:"version"`
	FenceID             FenceID    `json:"fence_id"`
	GroupID             NodeGroupID `json:"group_id"`
	ProviderBindingID   string     `json:"provider_binding_id,omitempty"`
	TargetNodeID        NodeID     `json:"target_node_id"`
	FencingToken        uint64     `json:"fencing_token"`
	AuthorityEpoch      uint64     `json:"authority_epoch"`
	Challenge           string     `json:"challenge"`
	ProtectedWritePaths []string   `json:"protected_write_paths"`
	Approvals           []Approval `json:"approvals"`
	VerifiedAt          time.Time  `json:"verified_at"`
}

func (confirmer *AdministrativeFenceConfirmer) VerifyAdministrativeFence(ctx context.Context, fence Fence, approvals []Approval) (FenceReceipt, error) {
	now := confirmer.current()
	if confirmer == nil || confirmer.Verifier == nil || ctx == nil || fence.Class != FenceAdministrative || fence.State != FencePlanned || fence.Validate(now) != nil || !validDigest(fence.Challenge) || len(approvals) < minimumAdministrativeFenceApprovals || len(approvals) > maximumAdministrativeFenceApprovals {
		return FenceReceipt{}, ErrFenceFailed
	}
	verified := append([]Approval(nil), approvals...)
	sort.Slice(verified, func(left, right int) bool {
		if verified[left].ActorID == verified[right].ActorID {
			return verified[left].ID < verified[right].ID
		}
		return verified[left].ActorID < verified[right].ActorID
	})
	actors := make(map[string]struct{}, len(verified))
	identifiers := make(map[string]struct{}, len(verified))
	validUntil := now.Add(localFenceProofLifetime)
	for _, approval := range verified {
		if !validID(approval.ID) || !validID(approval.ActorID) || approval.Kind != AdministrativeFenceApprovalKind || approval.PlanDigest != fence.Challenge || !validDigest(approval.PlanDigest) || approval.Signature == "" || approval.IssuedAt.IsZero() || approval.IssuedAt.After(now) || !approval.ExpiresAt.After(approval.IssuedAt) || !now.Before(approval.ExpiresAt) {
			return FenceReceipt{}, ErrFenceFailed
		}
		if _, duplicate := actors[approval.ActorID]; duplicate {
			return FenceReceipt{}, ErrFenceFailed
		}
		if _, duplicate := identifiers[approval.ID]; duplicate {
			return FenceReceipt{}, ErrFenceFailed
		}
		if err := confirmer.Verifier.VerifyAdministrativeApproval(ctx, fence, approval); err != nil {
			return FenceReceipt{}, errors.Join(err, ErrForbidden)
		}
		actors[approval.ActorID] = struct{}{}
		identifiers[approval.ID] = struct{}{}
		if approval.ExpiresAt.Before(validUntil) {
			validUntil = approval.ExpiresAt
		}
	}
	verifiedAt := confirmer.current()
	evidence := administrativeFenceEvidence{
		Version: 1, FenceID: fence.ID, GroupID: fence.GroupID, ProviderBindingID: fence.ProviderBindingID, TargetNodeID: fence.TargetNodeID,
		FencingToken: fence.FencingToken, AuthorityEpoch: fence.AuthorityEpoch,
		Challenge: fence.Challenge, ProtectedWritePaths: canonicalWritePaths(fence.ProtectedWritePaths),
		Approvals: verified, VerifiedAt: verifiedAt,
	}
	return newFenceReceipt(fence, evidence, verifiedAt, validUntil)
}

func (confirmer *AdministrativeFenceConfirmer) current() time.Time {
	if confirmer != nil && confirmer.Now != nil {
		return confirmer.Now().UTC()
	}
	return time.Now().UTC()
}

func validateLocalFenceRequest(ctx context.Context, request FenceRequest, class FenceClass, binding string, localNodeID NodeID, now time.Time) error {
	if ctx == nil || request.Fence.Class != class || request.Fence.State != FencePlanned || request.Fence.ProviderBindingID != binding || request.Fence.TargetNodeID != localNodeID || request.Fence.Validate(now) != nil || request.Quorum.Validate(now) != nil || request.Quorum.GroupID != request.Fence.GroupID || request.Quorum.Epoch != request.Fence.AuthorityEpoch || request.ApprovalDigest != request.Fence.Challenge || !validDigest(request.ApprovalDigest) || request.ExpectedBootID != "" || request.PotentialDataLossAcknowledged {
		return ErrFenceFailed
	}
	return nil
}

func validateLeaseForFence(lease WriterLease, fence Fence) error {
	if !validID(string(lease.ID)) || !validID(string(lease.GroupID)) || !validID(string(lease.HolderNodeID)) || !validDigest(lease.QuorumDigest) || lease.Generation == 0 || lease.IssuedAt.IsZero() || !lease.RenewAfter.After(lease.IssuedAt) || !lease.ExpiresAt.After(lease.RenewAfter) || lease.State != LeaseActive || lease.ResourceID != LocalMariaDBResourceID || lease.GroupID != fence.GroupID || lease.HolderNodeID != fence.TargetNodeID || lease.FencingToken == 0 || fence.FencingToken <= 1 || lease.FencingToken != fence.FencingToken-1 || lease.AuthorityEpoch != fence.AuthorityEpoch || !sameProtectedWritePaths(lease.EnforcedWritePaths, fence.ProtectedWritePaths) {
		return ErrFenceFailed
	}
	return nil
}

func revokeAndObserveLease(ctx context.Context, authority LeaseAuthority, expected WriterLease) (WriterLease, error) {
	revokeErr := authority.RevokeWriterLease(ctx, expected.ID, expected.FencingToken, expected.AuthorityEpoch)
	observed, observeErr := authority.ObserveWriterLease(ctx, expected.ID)
	if observeErr != nil {
		return WriterLease{}, errors.Join(revokeErr, observeErr, ErrFenceFailed)
	}
	if err := validateObservedFencedLease(observed, expected.ID, expected.GroupID, expected.ResourceID, expected.HolderNodeID, expected.FencingToken, expected.AuthorityEpoch, expected.EnforcedWritePaths); err != nil {
		return WriterLease{}, errors.Join(revokeErr, err)
	}
	if revokeErr != nil {
		return WriterLease{}, errors.Join(revokeErr, ErrFenceFailed)
	}
	return observed, nil
}

func validateObservedFencedLease(lease WriterLease, id WriterLeaseID, groupID NodeGroupID, resourceID string, holder NodeID, token, epoch uint64, paths []string) error {
	if lease.ID != id || lease.GroupID != groupID || lease.ResourceID != resourceID || lease.HolderNodeID != holder || lease.FencingToken != token || lease.AuthorityEpoch != epoch || lease.Generation == 0 || lease.State != LeaseRevoked && lease.State != LeaseExpired || !sameProtectedWritePaths(lease.EnforcedWritePaths, paths) {
		return ErrFenceFailed
	}
	return nil
}

func newFenceReceipt(fence Fence, evidence any, appliedAt, validUntil time.Time) (FenceReceipt, error) {
	raw, err := json.Marshal(evidence)
	if err != nil || !validUntil.After(appliedAt) {
		return FenceReceipt{}, errors.Join(err, ErrFenceFailed)
	}
	return FenceReceipt{
		FenceID: fence.ID, TargetNodeID: fence.TargetNodeID, Class: fence.Class,
		FencingToken: fence.FencingToken, ProtectedWritePaths: canonicalWritePaths(fence.ProtectedWritePaths),
		ProofDigest: fenceEvidenceDigest(raw), ProviderReceipt: string(raw), AppliedAt: appliedAt, ValidUntil: validUntil,
	}, nil
}

func validateLocalFenceReceipt(fence Fence, receipt FenceReceipt, now time.Time) error {
	if receipt.FenceID != fence.ID || receipt.TargetNodeID != fence.TargetNodeID || receipt.Class != fence.Class || receipt.FencingToken != fence.FencingToken || !sameProtectedWritePaths(receipt.ProtectedWritePaths, fence.ProtectedWritePaths) || !validDigest(receipt.ProofDigest) || receipt.ProviderReceipt == "" || receipt.AppliedAt.IsZero() || receipt.AppliedAt.After(now) || !receipt.ValidUntil.After(receipt.AppliedAt) || !now.Before(receipt.ValidUntil) {
		return ErrFenceFailed
	}
	return nil
}

func mariaDBEvidenceMatchesRequest(evidence localMariaDBFenceEvidence, request FenceRequest) bool {
	return evidence.Version == 1 && evidence.FenceID == request.Fence.ID && evidence.GroupID == request.Fence.GroupID && evidence.ProviderBindingID == request.Fence.ProviderBindingID && evidence.ResourceID == LocalMariaDBResourceID && evidence.TargetNodeID == request.Fence.TargetNodeID && evidence.LeaseID != "" && evidence.RevokedFencingToken == request.Fence.FencingToken-1 && evidence.FenceFencingToken == request.Fence.FencingToken && evidence.AuthorityEpoch == request.Fence.AuthorityEpoch && evidence.QuorumDigest == request.Quorum.Digest && evidence.Challenge == request.Fence.Challenge && evidence.ReadOnly && evidence.LeaseGeneration > 0 && (evidence.LeaseState == LeaseRevoked || evidence.LeaseState == LeaseExpired) && sameProtectedWritePaths(evidence.ProtectedWritePaths, request.Fence.ProtectedWritePaths) && evidence.DatabaseReceiptReturned == (evidence.DatabaseReceipt != "")
}

func leaseEvidenceMatchesRequest(evidence mandatoryLeaseFenceEvidence, request FenceRequest) bool {
	return evidence.Version == 1 && evidence.FenceID == request.Fence.ID && evidence.GroupID == request.Fence.GroupID && evidence.ProviderBindingID == request.Fence.ProviderBindingID && evidence.ResourceID == LocalMariaDBResourceID && evidence.TargetNodeID == request.Fence.TargetNodeID && evidence.LeaseID != "" && evidence.RevokedFencingToken == request.Fence.FencingToken-1 && evidence.FenceFencingToken == request.Fence.FencingToken && evidence.AuthorityEpoch == request.Fence.AuthorityEpoch && evidence.QuorumDigest == request.Quorum.Digest && evidence.Challenge == request.Fence.Challenge && evidence.LeaseGeneration > 0 && (evidence.LeaseState == LeaseRevoked || evidence.LeaseState == LeaseExpired) && sameProtectedWritePaths(evidence.ProtectedWritePaths, request.Fence.ProtectedWritePaths)
}

func canonicalWritePaths(paths []string) []string {
	result := append([]string(nil), paths...)
	sort.Strings(result)
	return result
}

func fenceProofDeadline(now, quorumUntil time.Time) time.Time {
	deadline := now.Add(localFenceProofLifetime)
	if quorumUntil.Before(deadline) {
		return quorumUntil
	}
	return deadline
}

func fenceEvidenceDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

var _ FenceProvider = (*LocalMariaDBFenceProvider)(nil)
var _ FenceProvider = (*MandatoryLeaseFenceProvider)(nil)
var _ ManualFenceConfirmer = (*AdministrativeFenceConfirmer)(nil)
