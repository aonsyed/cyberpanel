package secrets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

type ConsumerReleaseMove struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// ConsumerReleaseTransition is supplied only by the root release installer after
// verifying both signed manifests and their executable artifacts. It changes
// execution authority, not credential content, version or authenticated audience.
type ConsumerReleaseTransition struct {
	ID    string                `json:"id"`
	Moves []ConsumerReleaseMove `json:"moves"`
}

func (transition ConsumerReleaseTransition) Validate() error {
	if !validConsumerDigest(transition.ID) || len(transition.Moves) == 0 || len(transition.Moves) > 32 {
		return ErrInvalid
	}
	sources := map[string]string{}
	for _, move := range transition.Moves {
		if !validConsumerDigest(move.From) || !validConsumerDigest(move.To) || move.From == move.To || sources[move.From] != "" {
			return ErrInvalid
		}
		sources[move.From] = move.To
	}
	for _, move := range transition.Moves {
		if sources[move.To] != "" {
			return ErrInvalid
		}
	}
	return nil
}

func (client *ManagementClient) AuthorizeRelease(ctx context.Context, transition ConsumerReleaseTransition) error {
	if client == nil || client.transport == nil || ctx == nil || transition.Validate() != nil {
		return ErrInvalid
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	now := client.now().UTC()
	deadline := now.Add(30 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value.UTC()
	}
	request := ManagementRequest{Version: ManagementProtocolVersion, RequestID: "mgt-" + hex.EncodeToString(id), Action: ManagementAuthorizeRelease, ReleaseTransition: &transition, Deadline: deadline}
	if err := request.Validate(now); err != nil {
		return err
	}
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil {
		return err
	}
	if err = response.Validate(request); err != nil {
		return err
	}
	if response.FailureCode != "" {
		return materialFailure(response.FailureCode)
	}
	return nil
}

func (broker *Broker) authorizeRelease(ctx context.Context, transition ConsumerReleaseTransition) error {
	if transition.Validate() != nil {
		return ErrInvalid
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	tx, err := broker.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	want := digestJSON(transition)
	var previous string
	err = tx.QueryRowContext(ctx, "SELECT request_digest FROM secret_consumer_transitions WHERE id=?", transition.ID).Scan(&previous)
	if err == nil {
		var head string
		if err = tx.QueryRowContext(ctx, "SELECT transition_id FROM secret_consumer_transition_head WHERE singleton=1").Scan(&head); err != nil {
			return err
		}
		if previous != want || head != transition.ID {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	moves := map[string]string{}
	for _, move := range transition.Moves {
		moves[move.From] = move.To
	}
	// Validate every source before mutating any alias. A source already advanced
	// elsewhere is rejected unless this same atomic batch advances it to the same
	// destination (bootstrap recovery from two retained signed generations).
	for _, move := range transition.Moves {
		var current string
		err = tx.QueryRowContext(ctx, "SELECT consumer_digest FROM secret_consumer_releases WHERE anchor_digest=?", move.From).Scan(&current)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && current != move.From && current != move.To && moves[current] != move.To {
			return ErrConflict
		}
		err = tx.QueryRowContext(ctx, "SELECT consumer_digest FROM secret_consumer_releases WHERE anchor_digest=?", move.To).Scan(&current)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && current != move.To && moves[current] != move.To {
			return ErrConflict
		}
	}
	for _, move := range transition.Moves {
		if _, err = tx.ExecContext(ctx, "UPDATE secret_consumer_releases SET consumer_digest=? WHERE consumer_digest=?", move.To, move.From); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO secret_consumer_releases(anchor_digest,consumer_digest) VALUES(?,?) ON CONFLICT(anchor_digest) DO UPDATE SET consumer_digest=excluded.consumer_digest", move.From, move.To); err != nil {
			return err
		}
	}
	for _, move := range transition.Moves {
		// The target must be a terminal identity. This also lets a deliberate
		// rollback retire a candidate identity and restore the retained binary.
		if _, err = tx.ExecContext(ctx, "INSERT INTO secret_consumer_releases(anchor_digest,consumer_digest) VALUES(?,?) ON CONFLICT(anchor_digest) DO UPDATE SET consumer_digest=excluded.consumer_digest", move.To, move.To); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO secret_consumer_transitions VALUES(?,?,?)", transition.ID, want, broker.clock().UTC()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO secret_consumer_transition_head VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET transition_id=excluded.transition_id", transition.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (broker *Broker) audienceAllows(ctx context.Context, binding AudienceBinding, consumer ConsumerIdentity, operation Operation) (bool, error) {
	var active string
	err := broker.store.db.QueryRowContext(ctx, "SELECT consumer_digest FROM secret_consumer_releases WHERE anchor_digest=?", binding.ConsumerReleaseDigest).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		active = binding.ConsumerReleaseDigest
	} else if err != nil {
		return false, err
	}
	// Never rewrite the stored binding or consumer identity. Only this local
	// comparison substitutes the root-authorized successor for its anchor.
	binding.ConsumerReleaseDigest = active
	return audienceAllows(binding, consumer, operation), nil
}
