package mail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
)

type SpamArtifactIdentity struct {
	TenantID      string
	DomainID      DomainID
	MailboxID     MailboxID
	ItemID        SpamQuarantineID
	ObjectID      SpamObjectID
	ObjectDigest  string
	MessageDigest string
	Size          uint64
}

func (identity SpamArtifactIdentity) Validate() error {
	if !validOpaque(identity.TenantID) || !validOpaque(string(identity.DomainID)) || !validOpaque(string(identity.MailboxID)) || !validSpamID(string(identity.ItemID), "spamq_") || !validSpamID(string(identity.ObjectID), "spamobj_") || !validSpamDigest(identity.ObjectDigest) || !validSpamDigest(identity.MessageDigest) || identity.Size == 0 || identity.Size > SpamMaximumQuarantineBytes {
		return ErrInvalidCommand
	}
	return nil
}

type SpamArtifactMetadata struct {
	Identity SpamArtifactIdentity
	Sealed   bool
}

type SpamArtifactHandle interface {
	io.ReadCloser
	Metadata() SpamArtifactMetadata
}

type SpamArtifactTombstoneReceipt struct {
	ObjectID       SpamObjectID
	EffectKey      string
	ObjectDigest   string
	EvidencePreserved bool
	EffectDigest   string
}

// SpamQuarantineArtifactStore resolves only an exact opaque identity. It must
// not accept caller-selected paths, prefixes, buckets, or search expressions;
// TombstoneExact is idempotent by effect key and never erases a preserved hold.
type SpamQuarantineArtifactStore interface {
	OpenExact(context.Context, SpamArtifactIdentity) (SpamArtifactHandle, error)
	TombstoneExact(context.Context, SpamArtifactIdentity, string, bool) (SpamArtifactTombstoneReceipt, error)
}

type SpamBodyEffectRequest struct {
	EffectKey string
	ActorID   string
	Action    SpamQuarantineAction
	Identity  SpamArtifactIdentity
}

type SpamBodyEffectReceipt struct {
	EffectKey      string
	ObjectID       SpamObjectID
	Action         SpamQuarantineAction
	Bytes          uint64
	ArtifactDigest string
	EffectDigest   string
}

// A stage is not externally visible until Commit. Begin, Commit, and Abort must
// be idempotent by EffectKey and return the same bound receipt on retry. This
// makes digest verification happen before release, delivery, or learning.
type SpamBodyEffectStage interface {
	io.Writer
	Commit(context.Context, string, uint64) (SpamBodyEffectReceipt, error)
	Abort(context.Context) error
}

type SpamQuarantineDelivery interface {
	BeginDelivery(context.Context, SpamBodyEffectRequest) (SpamBodyEffectStage, error)
}

type SpamLearningAttribution struct {
	ActorID       string
	OperationID   string
	ReasonCode    string
	PolicyGeneration uint64
}

type SpamLocalLearner interface {
	BeginFalsePositive(context.Context, SpamBodyEffectRequest, SpamLearningAttribution) (SpamBodyEffectStage, error)
}

func spamArtifactIdentity(item SpamQuarantineItem) SpamArtifactIdentity {
	return SpamArtifactIdentity{TenantID: item.TenantID, DomainID: item.DomainID, MailboxID: item.MailboxID, ItemID: item.ID, ObjectID: item.ObjectID, ObjectDigest: item.ObjectDigest, MessageDigest: item.MessageDigest, Size: item.Size}
}

func openSpamArtifact(ctx context.Context, store SpamQuarantineArtifactStore, item SpamQuarantineItem) (SpamArtifactHandle, error) {
	if ctx == nil || store == nil || item.Validate() != nil {
		return nil, ErrInvalidCommand
	}
	identity := spamArtifactIdentity(item)
	handle, err := store.OpenExact(ctx, identity)
	if err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, ErrInvalidReceipt
	}
	metadata := handle.Metadata()
	if !metadata.Sealed || metadata.Identity != identity {
		handle.Close()
		return nil, ErrUnauthorized
	}
	return handle, nil
}

func streamSpamArtifact(ctx context.Context, handle SpamArtifactHandle, destination io.Writer, identity SpamArtifactIdentity) (uint64, string, error) {
	if ctx == nil || handle == nil || destination == nil || identity.Validate() != nil {
		return 0, "", ErrInvalidCommand
	}
	reader := &spamHashReader{source: io.LimitReader(handle, int64(identity.Size)+1), hasher: sha256.New()}
	written, err := io.Copy(destination, reader)
	if err == nil {
		err = ctx.Err()
	}
	digest := hex.EncodeToString(reader.hasher.Sum(nil))
	if err != nil || written != int64(identity.Size) || reader.bytes != identity.Size || digest != identity.ObjectDigest {
		return reader.bytes, digest, errors.Join(ErrInvalidReceipt, err)
	}
	return reader.bytes, digest, nil
}

func stageSpamArtifact(ctx context.Context, handle SpamArtifactHandle, stage SpamBodyEffectStage, identity SpamArtifactIdentity) (SpamBodyEffectReceipt, error) {
	if stage == nil {
		return SpamBodyEffectReceipt{}, ErrInvalidCommand
	}
	bytesWritten, digest, err := streamSpamArtifact(ctx, handle, stage, identity)
	if err != nil {
		_ = stage.Abort(context.WithoutCancel(ctx))
		return SpamBodyEffectReceipt{}, err
	}
	receipt, err := stage.Commit(ctx, digest, bytesWritten)
	if err != nil {
		_ = stage.Abort(context.WithoutCancel(ctx))
		return SpamBodyEffectReceipt{}, err
	}
	if receipt.ObjectID != identity.ObjectID || receipt.Bytes != identity.Size || receipt.ArtifactDigest != identity.ObjectDigest || !validOpaque(receipt.EffectKey) || !validSpamDigest(receipt.EffectDigest) {
		return SpamBodyEffectReceipt{}, ErrInvalidReceipt
	}
	return receipt, nil
}

type spamHashReader struct {
	source io.Reader
	hasher hash.Hash
	bytes  uint64
}

func (reader *spamHashReader) Read(buffer []byte) (int, error) {
	count, err := reader.source.Read(buffer)
	if count > 0 {
		_, _ = reader.hasher.Write(buffer[:count])
		reader.bytes += uint64(count)
	}
	return count, err
}
