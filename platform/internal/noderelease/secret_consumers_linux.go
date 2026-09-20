//go:build linux

package noderelease

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// Signed artifacts are paired by their installation destination, never by an
// arbitrary caller-supplied hash. Only panel binaries can inherit authority.
func consumerReleaseMoves(sources []Manifest, target Manifest) ([]secrets.ConsumerReleaseMove, error) {
	destinations := map[string]string{}
	for _, artifact := range target.Artifacts {
		if artifact.Kind == ArtifactBinary {
			destinations[artifact.Destination] = artifact.SHA256
		}
	}
	pairs := map[string]string{}
	for _, source := range sources {
		for _, artifact := range source.Artifacts {
			if artifact.Kind != ArtifactBinary {
				continue
			}
			to := destinations[artifact.Destination]
			if to == "" || to == artifact.SHA256 {
				continue
			}
			if previous := pairs[artifact.SHA256]; previous != "" && previous != to {
				return nil, ErrConflict
			}
			pairs[artifact.SHA256] = to
		}
	}
	moves := make([]secrets.ConsumerReleaseMove, 0, len(pairs))
	for from, to := range pairs {
		moves = append(moves, secrets.ConsumerReleaseMove{From: from, To: to})
	}
	sort.Slice(moves, func(i, j int) bool { return moves[i].From < moves[j].From })
	return moves, nil
}

func (installer *Installer) transitionSecretConsumers(ctx context.Context, journal *Journal, trust TrustStore, rollback bool) error {
	if journal.Previous == nil {
		return nil
	}
	kind := "authorize_consumers"
	if rollback {
		started := false
		for _, effect := range journal.Effects {
			if effect.Kind == kind {
				started = true
			}
		}
		if !started {
			return nil
		}
		kind = "restore_consumers"
	}
	// A completed effect must not be replayed after a later transition, notably
	// on recovery after rollback has already switched to the retained broker.
	for _, effect := range journal.Effects {
		if effect.Kind == kind && effect.State == "completed" {
			return nil
		}
	}
	_, candidate, err := loadRetainedEnvelopeWithoutTime(journal.Candidate, trust)
	if err != nil {
		return err
	}
	_, previous, err := loadRetainedEnvelopeWithoutTime(*journal.Previous, trust)
	if err != nil {
		return err
	}
	sources, target := []Manifest{previous}, candidate
	if rollback {
		sources, target = []Manifest{candidate}, previous
	} else if journal.ConsumerPredecessor != nil {
		_, predecessor, loadErr := loadRetainedEnvelopeWithoutTime(*journal.ConsumerPredecessor, trust)
		if loadErr != nil {
			return loadErr
		}
		sources = append(sources, predecessor)
	}
	moves, err := consumerReleaseMoves(sources, target)
	if err != nil || len(moves) == 0 {
		return err
	}
	transition := secrets.ConsumerReleaseTransition{ID: effectID(journal.ManifestDigest, kind, journal.Candidate.ReleaseID), Moves: moves}
	if err = transition.Validate(); err != nil {
		return err
	}
	if _, err = beginEffect(journal, kind, journal.Candidate.ReleaseID, installer.now()); err != nil {
		return err
	}
	// Called after the candidate broker's probe, before consumers start. Rollback
	// calls this while that broker is still running, before switching its link.
	if err = sendConsumerTransition(ctx, transition); err != nil {
		return err
	}
	return completeEffect(journal, kind, journal.Candidate.ReleaseID, digestJSON(transition), installer.now())
}

func sendConsumerTransition(ctx context.Context, transition secrets.ConsumerReleaseTransition) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		client, err := secrets.NewLocalManagementClient()
		if err == nil {
			err = client.AuthorizeRelease(ctx, transition)
		}
		if err == nil {
			return nil
		}
		if errors.Is(err, secrets.ErrConflict) || errors.Is(err, secrets.ErrInvalid) || errors.Is(err, secrets.ErrForbidden) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// ReconcileSecretConsumers bootstraps upgrades predating automatic consumer
// authorization using only the verified current and retained previous release.
func (installer *Installer) ReconcileSecretConsumers(ctx context.Context) error {
	if installer == nil || ctx == nil {
		return ErrInvalid
	}
	return installer.withLock(func() error {
		state, err := loadInstalledState()
		if err != nil {
			return err
		}
		if state.Previous == nil {
			return nil
		}
		active, err := observeActiveRelease()
		if err != nil || active != state.Active.ManifestDigest {
			return ErrIntegrity
		}
		trust, err := LoadTrustStore(TrustRoot)
		if err != nil {
			return err
		}
		_, current, err := loadRetainedEnvelopeWithoutTime(state.Active, trust)
		if err != nil {
			return err
		}
		_, previous, err := loadRetainedEnvelopeWithoutTime(*state.Previous, trust)
		if err != nil {
			return err
		}
		moves, err := consumerReleaseMoves([]Manifest{previous}, current)
		if err != nil || len(moves) == 0 {
			return err
		}
		transition := secrets.ConsumerReleaseTransition{ID: effectID(current.ManifestDigest, "repair_consumers", previous.ManifestDigest), Moves: moves}
		if err = transition.Validate(); err != nil {
			return err
		}
		return sendConsumerTransition(ctx, transition)
	})
}
