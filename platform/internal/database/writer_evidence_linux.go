//go:build linux

package database

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

func writerFenceEvidencePayload(value DatabaseWriterFenceEvidence) []byte {
	value.LocalSeal = ""
	payload, _ := json.Marshal(value)
	return payload
}

func (executor *LinuxMariaDBExecutor) sealWriterFenceEvidence(value DatabaseWriterFenceEvidence) (DatabaseWriterFenceEvidence, error) {
	key, err := executor.localHAPermitKey()
	if err != nil {
		return DatabaseWriterFenceEvidence{}, err
	}
	defer wipeBytes(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("cyberpanel-writer-fence-evidence-v1\x00"))
	_, _ = mac.Write(writerFenceEvidencePayload(value))
	value.LocalSeal = hex.EncodeToString(mac.Sum(nil))
	return value, nil
}

func stableWriterFenceEvidence(value DatabaseWriterFenceEvidence) DatabaseWriterFenceEvidence {
	value.ObservedAt = time.Time{}
	value.ExpiresAt = time.Time{}
	value.LocalSeal = ""
	value.ObservationDigest = ""
	return value
}

func writerFenceEvidenceRequestDigest(authority json.RawMessage, node ha.NodeID) string {
	payload := append([]byte("cyberpanel-writer-fence-evidence-request-v1\x00"+string(node)+"\x00"), authority...)
	return digestBytes(payload)
}

func (executor *LinuxMariaDBExecutor) stableWriterFenceEvidence(record writerFenceEvidenceRecord, requestDigest string, fresh DatabaseWriterFenceEvidence) (DatabaseWriterFenceEvidence, error) {
	if record.RequestDigest != requestDigest || !validDatabaseWriterFenceEvidence(record.Evidence) || !executor.now().UTC().Before(record.Evidence.ExpiresAt) || !sameWriterValue(stableWriterFenceEvidence(record.Evidence), stableWriterFenceEvidence(fresh)) {
		return DatabaseWriterFenceEvidence{}, ErrIdempotency
	}
	sealed, err := executor.sealWriterFenceEvidence(record.Evidence)
	if err != nil || !hmac.Equal([]byte(sealed.LocalSeal), []byte(record.Evidence.LocalSeal)) {
		return DatabaseWriterFenceEvidence{}, ErrIdempotency
	}
	return record.Evidence, nil
}

func verifyWriterAuthority(ctx context.Context, verify func(context.Context, json.RawMessage) error, raw json.RawMessage) error {
	if ctx == nil || verify == nil {
		return ErrUnauthorized
	}
	bounded, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	if err := verify(bounded, append(json.RawMessage(nil), raw...)); err != nil || bounded.Err() != nil {
		return ErrUnauthorized
	}
	return nil
}

func sourceFenceReceiptName(planDigest string) (string, error) {
	if !validSHA256(planDigest) {
		return "", ErrUnauthorized
	}
	return "ha-source-fence-" + planDigest[:48] + ".json", nil
}

func readExactWriterReceipt(path string) (json.RawMessage, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > maximumWriterAuthorityJSON {
		return nil, ErrUnauthorized
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if _, err = decodeDatabaseSourceFenceReceipt(raw); err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

// persistExactSourceFenceReceipt uses an atomic hard-link commit so an existing
// plan receipt can never be overwritten, even by a retry with different bytes.
func persistExactSourceFenceReceipt(planDigest string, raw json.RawMessage) (json.RawMessage, error) {
	name, err := sourceFenceReceiptName(planDigest)
	if err != nil {
		return nil, err
	}
	directory := filepath.Join(mariaDBStateRoot, "effects")
	if err = verifyRootDirectory(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, name)
	stored, readErr := readExactWriterReceipt(path)
	if readErr == nil {
		if !bytes.Equal(stored, raw) {
			return nil, ErrIdempotency
		}
		return stored, nil
	}
	if !errors.Is(readErr, ErrNotFound) {
		return nil, readErr
	}
	temporary, err := os.CreateTemp(directory, ".cyberpanel-source-fence-")
	if err != nil {
		return nil, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0600); err == nil {
		err = temporary.Chown(0, 0)
	}
	if err == nil {
		var written int
		written, err = temporary.Write(raw)
		if err == nil && written != len(raw) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err = os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		stored, err = readExactWriterReceipt(path)
		if err != nil || !bytes.Equal(stored, raw) {
			return nil, errors.Join(err, ErrIdempotency)
		}
		return stored, nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	err = handle.Sync()
	closeErr = handle.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	return append(json.RawMessage(nil), raw...), nil
}

func sourceFenceReceiptJSON(authority DatabaseWriterFenceAuthority, fence localMariaDBHAReceipt) (json.RawMessage, error) {
	if fence.Action != MariaDBHAFreeze || fence.ClusterID != authority.Cluster.ID || fence.NodeID != "local" || fence.FencingToken != authority.FencingToken || !fence.ReadOnly || fence.GTID != authority.Checkpoint.Position || fence.Frontier != authority.Checkpoint.WriteFrontier || !validSHA256(fence.ProofDigest) || fence.AppliedAt.IsZero() {
		return nil, ha.ErrFenceRequired
	}
	receipt := DatabaseSourceFenceReceipt{SchemaVersion: databaseSourceFenceReceiptSchemaVersion, AuthorityEpoch: authority.AuthorityEpoch, ClusterGeneration: authority.Cluster.Generation, PromotionID: authority.PromotionID, PreviousLeaseID: authority.PreviousLeaseID, EffectID: fence.EffectID, Action: databaseSourceFenceAction, ClusterID: authority.Cluster.ID, SourceNodeID: authority.SourceNodeID, FencingToken: authority.FencingToken, ReadOnly: true, Checkpoint: authority.Checkpoint, Outcome: databaseSourceFenceOutcome, ProofDigest: fence.ProofDigest, FencedAt: fence.AppliedAt, ExpiresAt: authority.ExpiresAt}
	if !validDatabaseSourceFenceReceipt(receipt) || !sourceFenceReceiptMatchesAuthority(receipt, authority) {
		return nil, ErrInvalidReceipt
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return persistExactSourceFenceReceipt(authority.PlanDigest, raw)
}

func candidateSourceFenceReceipt(authority DatabaseWriterCandidateAuthority) (json.RawMessage, error) {
	receipt, err := decodeDatabaseSourceFenceReceipt(authority.SourceFenceReceipt)
	base := DatabaseWriterFenceAuthority{SchemaVersion: authority.SchemaVersion, ProposalID: authority.ProposalID, PlanDigest: authority.PlanDigest, PromotionID: authority.PromotionID, PreviousLeaseID: authority.PreviousLeaseID, AuthorityEpoch: authority.AuthorityEpoch, TopologyEpoch: authority.TopologyEpoch, TopologyDigest: authority.TopologyDigest, MembershipDigest: authority.MembershipDigest, DeploymentEpoch: authority.DeploymentEpoch, DeploymentDigest: authority.DeploymentDigest, Cluster: authority.Cluster, SourceNodeID: authority.SourceNodeID, FencingToken: authority.FencingToken, Channel: authority.Channel, Checkpoint: authority.Checkpoint, ExpiresAt: authority.ExpiresAt}
	if err != nil || !sourceFenceReceiptMatchesAuthority(receipt, base) {
		return nil, ha.ErrFenceRequired
	}
	return persistExactSourceFenceReceipt(authority.PlanDigest, authority.SourceFenceReceipt)
}

func (executor *LinuxMariaDBExecutor) observeDatabaseWriterEvidence(ctx context.Context, rawAuthority json.RawMessage, source bool) (DatabaseWriterFenceEvidence, error) {
	if executor == nil || ctx == nil {
		return DatabaseWriterFenceEvidence{}, ErrInvalidCommand
	}
	var authority DatabaseWriterFenceAuthority
	var candidate DatabaseWriterCandidateAuthority
	var verify func(context.Context, json.RawMessage) error
	if source {
		var err error
		authority, err = decodeDatabaseWriterFenceAuthority(rawAuthority)
		if err != nil {
			return DatabaseWriterFenceEvidence{}, err
		}
		verify = executor.VerifyWriterFenceAuthorityJSON
	} else {
		var err error
		candidate, err = decodeDatabaseWriterCandidateAuthority(rawAuthority)
		if err != nil {
			return DatabaseWriterFenceEvidence{}, err
		}
		authority = DatabaseWriterFenceAuthority{SchemaVersion: candidate.SchemaVersion, ProposalID: candidate.ProposalID, PlanDigest: candidate.PlanDigest, PromotionID: candidate.PromotionID, PreviousLeaseID: candidate.PreviousLeaseID, AuthorityEpoch: candidate.AuthorityEpoch, TopologyEpoch: candidate.TopologyEpoch, TopologyDigest: candidate.TopologyDigest, MembershipDigest: candidate.MembershipDigest, DeploymentEpoch: candidate.DeploymentEpoch, DeploymentDigest: candidate.DeploymentDigest, Cluster: candidate.Cluster, SourceNodeID: candidate.SourceNodeID, FencingToken: candidate.FencingToken, Channel: candidate.Channel, Checkpoint: candidate.Checkpoint, ExpiresAt: candidate.ExpiresAt}
		verify = executor.VerifyWriterCandidateAuthorityJSON
	}
	if err := verifyWriterAuthority(ctx, verify, rawAuthority); err != nil {
		return DatabaseWriterFenceEvidence{}, err
	}
	if source {
		// The verified source authority is the only input allowed to initiate
		// this fence. A prior prepare vote or caller-supplied tuple can neither
		// select the token nor reuse an older observation as a fresh receipt.
		if _, err := executor.applyLocalHA(ctx, MariaDBHAFreeze, authority.Cluster, ha.NodeID("local"), authority.FencingToken, "", sqlFreezeHA, true); err != nil {
			return DatabaseWriterFenceEvidence{}, err
		}
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	boundCtx := context.WithValue(ctx, replicationEpochContextKey{}, authority.AuthorityEpoch)
	binding, node, epoch, err := executor.replicationBinding(boundCtx, authority.Channel.ID)
	role := "target"
	expectedNode := authority.Channel.TargetNodeID
	if source {
		role = "source"
		expectedNode = authority.Channel.SourceNodeID
	}
	if err != nil || node != expectedNode || !bindingMatchesChannel(binding, node, authority.Channel, role) || epoch != authority.AuthorityEpoch || binding.DeploymentEpoch != authority.DeploymentEpoch || binding.DeploymentDigest != authority.DeploymentDigest {
		return DatabaseWriterFenceEvidence{}, ErrUnauthorized
	}
	credential, err := executor.replicationCredential(boundCtx, binding, authority.Channel, epoch)
	if err != nil {
		return DatabaseWriterFenceEvidence{}, err
	}
	defer credential.Wipe()
	if !verifyReplicationCheckpoint(authority.Checkpoint, authority.Channel, credential) {
		return DatabaseWriterFenceEvidence{}, ha.ErrCheckpointStale
	}
	fence, err := executor.replicationFence()
	if err != nil || fence.FencingToken != authority.FencingToken {
		return DatabaseWriterFenceEvidence{}, ha.ErrFenceRequired
	}
	var sourceReceipt json.RawMessage
	replicaDigest := ""
	if source {
		identity, _ := json.Marshal(struct {
			Channel    ha.ReplicationChannel
			Generation uint64
		}{authority.Channel, authority.Checkpoint.SourceGeneration})
		var checkpoint localGTIDCheckpoint
		if err = executor.readNamed("effects", "ha-checkpoint-"+digestBytes(identity)[:40]+".json", &checkpoint); err != nil {
			return DatabaseWriterFenceEvidence{}, err
		}
		if !sameWriterValue(checkpoint.Channel, authority.Channel) || !sameWriterValue(checkpoint.Checkpoint, authority.Checkpoint) {
			return DatabaseWriterFenceEvidence{}, ha.ErrCheckpointStale
		}
		sourceReceipt, err = sourceFenceReceiptJSON(authority, fence)
	} else {
		var replica localReplicaJournal
		if err = executor.readNamed("effects", "ha-replica-"+digestBytes([]byte(authority.Channel.ID))[:32]+".json", &replica); err != nil {
			return DatabaseWriterFenceEvidence{}, err
		}
		if replica.State != "applied" || replica.Epoch != epoch || replica.FenceToken != authority.FencingToken || replica.DeploymentDigest != binding.DeploymentDigest || !sameWriterValue(replica.Channel, authority.Channel) || !sameWriterValue(replica.Checkpoint, authority.Checkpoint) || replica.Receipt.Position != authority.Checkpoint.Position || replica.Receipt.TargetReceipt == "" {
			return DatabaseWriterFenceEvidence{}, ha.ErrCheckpointStale
		}
		replicaBytes, _ := json.Marshal(replica.Receipt)
		replicaDigest = digestBytes(replicaBytes)
		sourceReceipt, err = candidateSourceFenceReceipt(candidate)
	}
	if err != nil {
		return DatabaseWriterFenceEvidence{}, err
	}
	executor.writer.transition.Lock()
	defer executor.writer.transition.Unlock()
	member, proof, gate, err := executor.observeWriterCandidateBoundary(boundCtx, authority.Checkpoint)
	if err != nil {
		return DatabaseWriterFenceEvidence{}, err
	}
	if executor.VerifyReplicationAuthority == nil {
		return DatabaseWriterFenceEvidence{}, ErrUnauthorized
	}
	if err = executor.VerifyReplicationAuthority(boundCtx, binding, node, epoch); err != nil {
		return DatabaseWriterFenceEvidence{}, ErrUnauthorized
	}
	if err = verifyWriterAuthority(boundCtx, verify, rawAuthority); err != nil {
		return DatabaseWriterFenceEvidence{}, err
	}
	now := executor.now().UTC()
	if !now.Before(authority.ExpiresAt) {
		return DatabaseWriterFenceEvidence{}, ErrUnauthorized
	}
	evidence := DatabaseWriterFenceEvidence{SchemaVersion: databaseWriterEvidenceSchemaVersion, Channel: authority.Channel, Checkpoint: authority.Checkpoint, NodeID: node, AuthorityEpoch: epoch, DeploymentEpoch: binding.DeploymentEpoch, DeploymentDigest: binding.DeploymentDigest, FencingToken: authority.FencingToken, GTID: member.GTID, Frontier: member.Sequence, SourceFenceReceipt: append(json.RawMessage(nil), sourceReceipt...), CursorDigest: digestBytes(sourceReceipt), SessionFenceDigest: gate.ObservationDigest, ObservationDigest: proof, ReplicaDigest: replicaDigest, ObservedAt: now, ExpiresAt: authority.ExpiresAt}
	evidence, err = executor.sealWriterFenceEvidence(evidence)
	if err != nil {
		return DatabaseWriterFenceEvidence{}, err
	}
	requestDigest := writerFenceEvidenceRequestDigest(rawAuthority, node)
	name := "ha-writer-fence-" + requestDigest[:48] + ".json"
	var prior writerFenceEvidenceRecord
	if err = executor.readNamed("effects", name, &prior); err == nil {
		return executor.stableWriterFenceEvidence(prior, requestDigest, evidence)
	} else if !errors.Is(err, ErrNotFound) {
		return DatabaseWriterFenceEvidence{}, err
	}
	if !validDatabaseWriterFenceEvidence(evidence) {
		return DatabaseWriterFenceEvidence{}, ErrInvalidReceipt
	}
	if err = executor.writeNamed("effects", name, writerFenceEvidenceRecord{RequestDigest: requestDigest, Evidence: evidence}); err != nil {
		return DatabaseWriterFenceEvidence{}, err
	}
	return evidence, nil
}

// ObserveDatabaseWriterFence proves the source's privileged freeze under an
// authenticated HA authority and returns the fixed raw source receipt.
func (executor *LinuxMariaDBExecutor) ObserveDatabaseWriterFence(ctx context.Context, authority json.RawMessage) (DatabaseWriterFenceEvidence, error) {
	return executor.observeDatabaseWriterEvidence(ctx, authority, true)
}

// ObserveDatabaseWriterCandidate proves target replica/session state while
// referencing the source's exact immutable receipt bytes.
func (executor *LinuxMariaDBExecutor) ObserveDatabaseWriterCandidate(ctx context.Context, authority json.RawMessage) (DatabaseWriterFenceEvidence, error) {
	return executor.observeDatabaseWriterEvidence(ctx, authority, false)
}
