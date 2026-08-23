package federation

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a locally registered federation resource does
// not exist. It is intentionally distinct from a peer being inactive or a
// grant being forbidden.
var ErrNotFound = errors.New("federation: not found")

// EnrollmentPreparer exposes only the local-owner initiation step. Keeping the
// complete EnrollmentService private prevents an API adapter without key,
// certificate, and central-exchange authorities from claiming full enrollment.
type EnrollmentPreparer struct {
	service *EnrollmentService
}

func NewEnrollmentPreparer(tokens EnrollmentStore) (*EnrollmentPreparer, error) {
	if tokens == nil {
		return nil, ErrInvalid
	}
	return &EnrollmentPreparer{service: &EnrollmentService{tokens: tokens, clock: time.Now}}, nil
}

func (preparer *EnrollmentPreparer) Prepare(ctx context.Context, id, peer, node ID, rawToken []byte, caFingerprint, endpoint string, ttl time.Duration) (EnrollmentToken, error) {
	if preparer == nil || preparer.service == nil || ctx == nil {
		wipe(rawToken)
		return EnrollmentToken{}, ErrInvalid
	}
	return preparer.service.Prepare(ctx, id, peer, node, rawToken, caFingerprint, endpoint, ttl)
}

// LocalAuthority narrows Agent to the one lifecycle command that is safe to
// expose without wiring remote command, policy, schema, or receipt authorities.
type LocalAuthority struct {
	agent *Agent
}

func NewLocalAuthority(store *Store) (*LocalAuthority, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &LocalAuthority{agent: &Agent{store: store, clock: time.Now}}, nil
}

func (authority *LocalAuthority) Revoke(ctx context.Context, reason string) error {
	if authority == nil || authority.agent == nil || ctx == nil {
		return ErrInvalid
	}
	return authority.agent.LocalRevoke(ctx, reason)
}
