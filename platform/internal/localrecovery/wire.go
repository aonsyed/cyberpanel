package localrecovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"
)

type ErrorCode string

const (
	ErrorInvalidRequest   ErrorCode = "invalid_request"
	ErrorUnauthorized     ErrorCode = "unauthorized"
	ErrorRateLimited      ErrorCode = "rate_limited"
	ErrorAuthorityDenied  ErrorCode = "authority_denied"
	ErrorAuditUnavailable ErrorCode = "audit_unavailable"
	ErrorConflict         ErrorCode = "generation_conflict"
	ErrorRecoveryFailed   ErrorCode = "recovery_failed"
	ErrorDeadlineExceeded ErrorCode = "deadline_exceeded"
)

func (code ErrorCode) valid() bool {
	switch code {
	case ErrorInvalidRequest, ErrorUnauthorized, ErrorRateLimited, ErrorAuthorityDenied, ErrorAuditUnavailable, ErrorConflict, ErrorRecoveryFailed, ErrorDeadlineExceeded:
		return true
	default:
		return false
	}
}

type Response struct {
	Version     uint16           `json:"version"`
	RequestID   string           `json:"request_id"`
	Action      Action           `json:"action"`
	Succeeded   bool             `json:"succeeded"`
	ErrorCode   ErrorCode        `json:"error_code,omitempty"`
	Challenge   *Challenge       `json:"challenge,omitempty"`
	Status      *RecoveryStatus  `json:"status,omitempty"`
	Receipt     *RecoveryReceipt `json:"receipt,omitempty"`
	CompletedAt time.Time        `json:"completed_at"`
}

func (response Response) Validate(request Request, now time.Time) error {
	if response.Version != ProtocolVersion || response.RequestID != request.RequestID || response.Action != request.Action || response.CompletedAt.Location() != time.UTC || response.CompletedAt.After(now) || response.CompletedAt.After(request.Deadline) || response.CompletedAt.Before(now.Add(-MaximumRequestLifetime)) {
		return ErrInvalid
	}
	if !response.Succeeded {
		if !response.ErrorCode.valid() || response.Challenge != nil || response.Status != nil || response.Receipt != nil {
			return ErrInvalid
		}
		return nil
	}
	if response.ErrorCode != "" {
		return ErrInvalid
	}
	switch request.Action {
	case ActionBeginChallenge:
		if response.Challenge == nil || response.Status != nil || response.Receipt != nil || request.Binding == nil || response.Challenge.Validate(*request.Binding, now) != nil {
			return ErrInvalid
		}
	case ActionStatus:
		if response.Challenge != nil || response.Status == nil || response.Receipt != nil || response.Status.Validate(now) != nil {
			return ErrInvalid
		}
	case ActionResetOwnerPassword, ActionResetOwnerMFA, ActionRevokeOwnerAccess, ActionRotateRecoveryAuthority:
		if response.Challenge != nil || response.Status != nil || response.Receipt == nil || response.Receipt.Validate(request, now) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func writeFrame(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > MaximumFrameBytes {
		wipeBytes(encoded)
		return ErrInvalid
	}
	defer wipeBytes(encoded)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
	if err = writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, encoded)
}

func readFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaximumFrameBytes {
		return ErrInvalid
	}
	encoded := make([]byte, size)
	defer wipeBytes(encoded)
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return ErrInvalid
	}
	defer wipeBytes(canonical)
	if !bytes.Equal(encoded, canonical) {
		return ErrInvalid
	}
	return nil
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(content) {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func newAuditRecord(request Request, phase AuditPhase, outcome AuditOutcome, code ErrorCode, generation uint64, at time.Time) AuditRecord {
	reason, host, digest, challengeFor := request.Reason, request.Host, request.RequestDigest, Action("")
	if request.Action == ActionBeginChallenge && request.Binding != nil {
		reason, host, digest, challengeFor = request.Binding.Reason, request.Binding.Host, request.Binding.RequestDigest, request.Binding.Action
	}
	seed := request.RequestID + "\x00" + string(request.Action) + "\x00" + string(phase) + "\x00" + string(outcome) + "\x00" + at.UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte("cyberpanel:local-recovery:audit:v1\x00" + seed))
	return AuditRecord{
		ID: "local-recovery:" + hex.EncodeToString(sum[:]), RequestID: request.RequestID,
		Action: request.Action, ChallengeFor: challengeFor, Phase: phase, Outcome: outcome,
		Reason: reason, Host: host, RequestDigest: digest, PeerUID: 0,
		Generation: generation, ErrorCode: string(code), OccurredAt: at.UTC(),
	}
}
