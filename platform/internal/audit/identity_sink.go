package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

// IdentitySink adapts identity's deliberately small audit boundary to the
// authoritative append-only audit writer. Identity mutations never silently
// fall back to logs or journald.
type IdentitySink struct {
	Service *Service
}

func (sink IdentitySink) Record(ctx context.Context, source identity.AuditEvent) error {
	if sink.Service == nil || source.At.IsZero() || source.Action == "" || len(source.RequestHash) != sha256.Size*2 {
		return ErrInvalid
	}
	outcome := OutcomeFailed
	switch strings.ToLower(source.Outcome) {
	case "prepared":
		outcome = OutcomePrepared
	case "applied", "allowed", "success":
		outcome = OutcomeApplied
	case "denied", "forbidden":
		outcome = OutcomeDenied
	case "rejected":
		outcome = OutcomeRejected
	case "ambiguous":
		outcome = OutcomeAmbiguous
	case "failed", "error":
		outcome = OutcomeFailed
	default:
		return ErrInvalid
	}
	eventID := source.ID
	if !idPattern.MatchString(eventID) {
		sum := sha256.Sum256([]byte("cyberpanel:identity-audit:v1\x00" + source.Action + "\x00" + source.RequestHash + "\x00" + source.At.UTC().String()))
		eventID = "identity:" + hex.EncodeToString(sum[:])
	}
	event := Event{
		ID: eventID,
		Class: ClassMutation,
		Action: source.Action,
		Actor: Actor{PrincipalID: source.ActorID.String(), TenantID: source.TenantID.String(), Origin: "panel-core"},
		Target: Target{Kind: source.TargetKind, ID: source.TargetID.String(), TenantID: source.TenantID.String()},
		Outcome: outcome,
		RequestDigest: source.RequestHash,
		OccurredAt: source.At.UTC(),
	}
	_, err := sink.Service.Writer.Append(ctx, event)
	return err
}

var _ identity.AuditSink = IdentitySink{}
