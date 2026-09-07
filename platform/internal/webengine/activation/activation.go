package activation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

type Status string

const (
	Applied    Status = "applied"
	RolledBack Status = "rolled_back"
	Ambiguous  Status = "ambiguous"
)

type Receipt struct {
	Edition          webengine.Edition
	Digest           string
	Status           Status
	CandidateDigest  string
	PreviousDigest   string
	ReloadRequested  bool
	CandidateProbed  bool
	Confirmed        bool
	RollbackRestored bool
	RollbackReloaded bool
	PreviousProbed   bool
}

type Store interface {
	Stage(context.Context, native.ConfigGeneration) (Receipt, error)
	Current(context.Context) (Receipt, error)
	SwapMaster(context.Context, Receipt) error
	RestoreMaster(context.Context, Receipt) error
	Confirm(context.Context, Receipt) error
}

type Engine interface {
	Reload(context.Context) error
}

type Probe interface {
	Check(context.Context, Receipt) error
}

type Activator struct {
	Store  Store
	Engine Engine
	Probe  Probe
	mu     sync.Mutex
}

// Configuration changes share one privileged broker process (guarded by the
// siteops registry's exclusive process lock). Management keeps this lease until
// confirmation/rollback so ordinary activation cannot invalidate its baseline.
var configurationLease = make(chan struct{}, 1)

func LockConfiguration(ctx context.Context) (func(), error) {
	if ctx == nil { return nil, errors.New("configuration context is required") }
	select {
	case configurationLease <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-configurationLease }) }, nil
	case <-ctx.Done(): return nil, ctx.Err()
	}
}

func (a *Activator) Apply(ctx context.Context, generation native.ConfigGeneration) (Receipt, error) {
	if err := validGeneration(generation); err != nil {
		return ambiguous(), err
	}
	if a == nil || nilInterface(a.Store) || nilInterface(a.Engine) || nilInterface(a.Probe) {
		return ambiguous(), errors.New("activation dependencies are required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	release, lockErr := LockConfiguration(ctx)
	if lockErr != nil { return ambiguous(), lockErr }
	defer release()

	candidate, err := a.Store.Stage(ctx, generation)
	if err != nil {
		return ambiguous(), fmt.Errorf("stage candidate: %w", err)
	}
	previous, err := a.Store.Current(ctx)
	if err != nil {
		return ambiguousWith(candidate, Receipt{}), fmt.Errorf("read current receipt: %w", err)
	}
	if !matchesGeneration(candidate, generation) || !validCurrent(previous) || previous.Edition != candidate.Edition {
		return ambiguousWith(candidate, previous), errors.New("activation receipt does not match generation")
	}
	if same(candidate, previous) {
		return applied(candidate, previous, false, false), nil
	}

	if err = a.Store.SwapMaster(ctx, candidate); err == nil {
		reloadRequested := true
		if err = a.Engine.Reload(ctx); err == nil {
			candidateProbed := true
			err = a.Probe.Check(ctx, candidate)
			if err == nil {
				if err = a.Store.Confirm(ctx, candidate); err == nil {
					return applied(candidate, previous, reloadRequested, candidateProbed), nil
				}
			}
			return a.rollback(ctx, candidate, previous, err, reloadRequested, candidateProbed)
		}
		return a.rollback(ctx, candidate, previous, err, reloadRequested, false)
	}
	return a.rollback(ctx, candidate, previous, err, false, false)
}

func (a *Activator) rollback(ctx context.Context, candidate, previous Receipt, cause error, reloadRequested, candidateProbed bool) (Receipt, error) {
	if cause == nil {
		cause = errors.New("candidate activation failed")
	}
	if err := a.Store.RestoreMaster(ctx, previous); err != nil {
		return ambiguousWithEvidence(candidate, previous, reloadRequested, candidateProbed, false, false, false), fmt.Errorf("%w: restore previous: %v", cause, err)
	}
	if err := a.Engine.Reload(ctx); err != nil {
		return ambiguousWithEvidence(candidate, previous, reloadRequested, candidateProbed, true, false, false), fmt.Errorf("%w: reload previous: %v", cause, err)
	}
	if err := a.Probe.Check(ctx, previous); err != nil {
		return ambiguousWithEvidence(candidate, previous, reloadRequested, candidateProbed, true, true, false), fmt.Errorf("%w: prove previous: %v", cause, err)
	}
	return rolledBack(candidate, previous, reloadRequested, candidateProbed), nil
}

func validGeneration(g native.ConfigGeneration) error {
	if (g.Edition != webengine.EditionOpenLiteSpeed && g.Edition != webengine.EditionLiteSpeedEnterprise) ||
		g.Kind != native.GenerationCompleteReplacement || g.SnapshotGeneration == 0 || !validDigest(g.ContentDigest) {
		return errors.New("invalid config generation")
	}
	return nil
}

func validStaged(r Receipt) bool {
	return r.Status == "" && r.CandidateDigest == "" && r.PreviousDigest == "" &&
		!r.ReloadRequested && !r.CandidateProbed && !r.Confirmed &&
		!r.RollbackRestored && !r.RollbackReloaded && !r.PreviousProbed &&
		(r.Edition == webengine.EditionOpenLiteSpeed || r.Edition == webengine.EditionLiteSpeedEnterprise) &&
		validDigest(r.Digest)
}

func validCurrent(r Receipt) bool {
	return r.Status == Applied && r.Confirmed &&
		(r.Edition == webengine.EditionOpenLiteSpeed || r.Edition == webengine.EditionLiteSpeedEnterprise) &&
		validDigest(r.Digest)
}

func matchesGeneration(r Receipt, g native.ConfigGeneration) bool {
	return validStaged(r) && r.Edition == g.Edition && r.Digest == g.ContentDigest
}

func same(left, right Receipt) bool {
	return left.Edition == right.Edition && left.Digest == right.Digest
}

func validDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	return strings.Trim(digest, "0123456789abcdef") == ""
}

func applied(candidate, previous Receipt, reloadRequested, candidateProbed bool) Receipt {
	return Receipt{Edition: candidate.Edition, Digest: candidate.Digest, Status: Applied,
		CandidateDigest: candidate.Digest, PreviousDigest: previous.Digest,
		ReloadRequested: reloadRequested, CandidateProbed: candidateProbed, Confirmed: true}
}

func rolledBack(candidate, previous Receipt, reloadRequested, candidateProbed bool) Receipt {
	return Receipt{Edition: previous.Edition, Digest: previous.Digest, Status: RolledBack,
		CandidateDigest: candidate.Digest, PreviousDigest: previous.Digest,
		ReloadRequested: reloadRequested, CandidateProbed: candidateProbed,
		RollbackRestored: true, RollbackReloaded: true, PreviousProbed: true}
}

func ambiguous() Receipt { return Receipt{Status: Ambiguous} }

func ambiguousWith(candidate, previous Receipt) Receipt {
	return ambiguousWithEvidence(candidate, previous, false, false, false, false, false)
}

func ambiguousWithEvidence(candidate, previous Receipt, reloadRequested, candidateProbed, rollbackRestored, rollbackReloaded, previousProbed bool) Receipt {
	return Receipt{Status: Ambiguous, CandidateDigest: candidate.Digest, PreviousDigest: previous.Digest,
		ReloadRequested: reloadRequested, CandidateProbed: candidateProbed,
		RollbackRestored: rollbackRestored, RollbackReloaded: rollbackReloaded, PreviousProbed: previousProbed}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	return (v.Kind() == reflect.Chan || v.Kind() == reflect.Func || v.Kind() == reflect.Interface || v.Kind() == reflect.Map || v.Kind() == reflect.Ptr || v.Kind() == reflect.Slice) && v.IsNil()
}
