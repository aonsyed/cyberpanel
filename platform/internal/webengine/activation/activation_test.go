package activation

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

var errInjected = errors.New("injected failure")

// The fakes deliberately record the public workflow, not implementation detail.
type storeFake struct {
	events                                                *[]string
	staged                                                Receipt
	current                                               Receipt
	stageErr, currentErr, swapErr, restoreErr, confirmErr error
}

func (s *storeFake) Stage(context.Context, native.ConfigGeneration) (Receipt, error) {
	*s.events = append(*s.events, "stage")
	return s.staged, s.stageErr
}

func (s *storeFake) Current(context.Context) (Receipt, error) {
	*s.events = append(*s.events, "current")
	return s.current, s.currentErr
}

func (s *storeFake) SwapMaster(_ context.Context, r Receipt) error {
	*s.events = append(*s.events, "swap:"+r.Digest)
	return s.swapErr
}

func (s *storeFake) RestoreMaster(_ context.Context, r Receipt) error {
	*s.events = append(*s.events, "restore:"+r.Digest)
	return s.restoreErr
}

func (s *storeFake) Confirm(_ context.Context, r Receipt) error {
	*s.events = append(*s.events, "confirm:"+r.Digest)
	return s.confirmErr
}

type engineFake struct {
	events *[]string
	errs   []error
}

func (e *engineFake) Reload(context.Context) error {
	*e.events = append(*e.events, "reload")
	if len(e.errs) == 0 {
		return nil
	}
	err := e.errs[0]
	e.errs = e.errs[1:]
	return err
}

type probeFake struct {
	events *[]string
	errs   []error
}

func (p *probeFake) Check(_ context.Context, r Receipt) error {
	*p.events = append(*p.events, "probe:"+r.Digest)
	if len(p.errs) == 0 {
		return nil
	}
	err := p.errs[0]
	p.errs = p.errs[1:]
	return err
}

func receipt(edition webengine.Edition, digest string) Receipt {
	return Receipt{Edition: edition, Digest: digest}
}

func currentReceipt(edition webengine.Edition, digest string) Receipt {
	return Receipt{Edition: edition, Digest: digest, Status: Applied, Confirmed: true}
}

func generation() native.ConfigGeneration {
	return native.ConfigGeneration{
		Edition:            webengine.EditionOpenLiteSpeed,
		Kind:               native.GenerationCompleteReplacement,
		DesiredDigest:      strings.Repeat("d", 64),
		SnapshotGeneration: 42,
		ContentDigest:      strings.Repeat("c", 64),
	}
}

func activator(events *[]string, staged, current Receipt) (*Activator, *storeFake, *engineFake, *probeFake) {
	store := &storeFake{events: events, staged: staged, current: current}
	engine := &engineFake{events: events}
	probe := &probeFake{events: events}
	return &Activator{Store: store, Engine: engine, Probe: probe}, store, engine, probe
}

func TestApplyPromotesCandidateOnlyAfterItReloadsAndProbes(t *testing.T) {
	events := []string{}
	generation := generation()
	candidate := receipt(generation.Edition, generation.ContentDigest)
	previous := currentReceipt(generation.Edition, strings.Repeat("a", 64))
	a, _, _, _ := activator(&events, candidate, previous)

	got, err := a.Apply(context.Background(), generation)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	wantReceipt := Receipt{Edition: candidate.Edition, Digest: candidate.Digest, Status: Applied,
		CandidateDigest: candidate.Digest, PreviousDigest: previous.Digest,
		ReloadRequested: true, CandidateProbed: true, Confirmed: true}
	if got != wantReceipt {
		t.Fatalf("Apply() receipt = %#v, want applied candidate", got)
	}
	want := []string{"stage", "current", "swap:" + candidate.Digest, "reload", "probe:" + candidate.Digest, "confirm:" + candidate.Digest}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("workflow = %v, want %v", events, want)
	}
}

func TestApplyRollsBackWhenCandidateReloadFailsAndPreviousProvesHealthy(t *testing.T) {
	events := []string{}
	generation := generation()
	candidate, previous := receipt(generation.Edition, generation.ContentDigest), currentReceipt(generation.Edition, strings.Repeat("a", 64))
	a, _, engine, _ := activator(&events, candidate, previous)
	engine.errs = []error{errInjected}

	got, err := a.Apply(context.Background(), generation)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	wantReceipt := Receipt{Edition: previous.Edition, Digest: previous.Digest, Status: RolledBack,
		CandidateDigest: candidate.Digest, PreviousDigest: previous.Digest,
		ReloadRequested: true, RollbackRestored: true, RollbackReloaded: true, PreviousProbed: true}
	if got != wantReceipt {
		t.Fatalf("Apply() receipt = %#v, want rolled-back previous receipt", got)
	}
	want := []string{"stage", "current", "swap:" + candidate.Digest, "reload", "restore:" + previous.Digest, "reload", "probe:" + previous.Digest}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("workflow = %v, want %v", events, want)
	}
}

func TestApplyRollsBackWhenCandidateProbeFailsAndPreviousProvesHealthy(t *testing.T) {
	events := []string{}
	generation := generation()
	candidate, previous := receipt(generation.Edition, generation.ContentDigest), currentReceipt(generation.Edition, strings.Repeat("a", 64))
	a, _, _, probe := activator(&events, candidate, previous)
	probe.errs = []error{errInjected}

	got, err := a.Apply(context.Background(), generation)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	wantReceipt := Receipt{Edition: previous.Edition, Digest: previous.Digest, Status: RolledBack,
		CandidateDigest: candidate.Digest, PreviousDigest: previous.Digest,
		ReloadRequested: true, CandidateProbed: true,
		RollbackRestored: true, RollbackReloaded: true, PreviousProbed: true}
	if got != wantReceipt {
		t.Fatalf("Apply() receipt = %#v, want rolled-back previous receipt", got)
	}
	want := []string{"stage", "current", "swap:" + candidate.Digest, "reload", "probe:" + candidate.Digest, "restore:" + previous.Digest, "reload", "probe:" + previous.Digest}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("workflow = %v, want %v", events, want)
	}
}

func TestApplyIsAmbiguousWhenRollbackCannotBeProven(t *testing.T) {
	events := []string{}
	generation := generation()
	candidate, previous := receipt(generation.Edition, generation.ContentDigest), currentReceipt(generation.Edition, strings.Repeat("a", 64))
	a, _, engine, probe := activator(&events, candidate, previous)
	engine.errs = []error{errInjected}
	probe.errs = []error{errInjected}

	got, err := a.Apply(context.Background(), generation)
	if err == nil {
		t.Fatal("Apply() error = nil, want failed-closed error")
	}
	wantReceipt := Receipt{Status: Ambiguous, CandidateDigest: candidate.Digest, PreviousDigest: previous.Digest,
		ReloadRequested: true, RollbackRestored: true, RollbackReloaded: true}
	if got != wantReceipt {
		t.Fatalf("Apply() receipt = %#v, want ambiguous", got)
	}
	want := []string{"stage", "current", "swap:" + candidate.Digest, "reload", "restore:" + previous.Digest, "reload", "probe:" + previous.Digest}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("workflow = %v, want %v", events, want)
	}
}

func TestApplyReturnsAppliedWithoutSideEffectsForExactCurrentDigest(t *testing.T) {
	events := []string{}
	generation := generation()
	candidate := receipt(generation.Edition, generation.ContentDigest)
	a, _, _, _ := activator(&events, candidate, currentReceipt(candidate.Edition, candidate.Digest))

	got, err := a.Apply(context.Background(), generation)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	wantReceipt := Receipt{Edition: candidate.Edition, Digest: candidate.Digest, Status: Applied,
		CandidateDigest: candidate.Digest, PreviousDigest: candidate.Digest, Confirmed: true}
	if got != wantReceipt {
		t.Fatalf("Apply() receipt = %#v, want applied current receipt", got)
	}
	want := []string{"stage", "current"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("side effects = %v, want %v", events, want)
	}
}

func TestApplyFailsClosedForMismatchedEditionDigestOrReceipt(t *testing.T) {
	cases := []struct {
		name    string
		staged  Receipt
		current Receipt
	}{
		{"edition", receipt(webengine.EditionLiteSpeedEnterprise, strings.Repeat("c", 64)), currentReceipt(webengine.EditionOpenLiteSpeed, strings.Repeat("a", 64))},
		{"digest", receipt(webengine.EditionOpenLiteSpeed, ""), currentReceipt(webengine.EditionOpenLiteSpeed, strings.Repeat("a", 64))},
		{"receipt", Receipt{Edition: webengine.EditionOpenLiteSpeed, Digest: strings.Repeat("c", 64), Status: RolledBack}, currentReceipt(webengine.EditionOpenLiteSpeed, strings.Repeat("a", 64))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := []string{}
			a, _, _, _ := activator(&events, tc.staged, tc.current)

			got, err := a.Apply(context.Background(), generation())
			if err == nil {
				t.Fatal("Apply() error = nil, want failed-closed error")
			}
			if got.Status != Ambiguous {
				t.Fatalf("Apply() receipt = %#v, want ambiguous", got)
			}
			if !reflect.DeepEqual(events, []string{"stage", "current"}) {
				t.Fatalf("side effects = %v, want none after validation", events)
			}
		})
	}
}

func TestApplyStopsWhenStagingFails(t *testing.T) {
	events := []string{}
	generation := generation()
	a, store, _, _ := activator(&events, receipt(generation.Edition, generation.ContentDigest), currentReceipt(generation.Edition, strings.Repeat("a", 64)))
	store.stageErr = errInjected

	if _, err := a.Apply(context.Background(), generation); err == nil {
		t.Fatal("Apply() error = nil, want staging error")
	}
	if !reflect.DeepEqual(events, []string{"stage"}) {
		t.Fatalf("workflow = %v, want only stage", events)
	}
}

func TestApplyIsAmbiguousWhenSwapAndRestoreFail(t *testing.T) {
	events := []string{}
	generation := generation()
	candidate := receipt(generation.Edition, generation.ContentDigest)
	previous := currentReceipt(generation.Edition, strings.Repeat("a", 64))
	a, store, _, _ := activator(&events, candidate, previous)
	swapSentinel := errors.New("swap failed")
	store.swapErr = swapSentinel
	store.restoreErr = errInjected

	got, err := a.Apply(context.Background(), generation)
	if !errors.Is(err, swapSentinel) {
		t.Fatalf("Apply() error = %v, want it to preserve swap error", err)
	}
	wantReceipt := Receipt{Status: Ambiguous, CandidateDigest: candidate.Digest, PreviousDigest: previous.Digest}
	if got != wantReceipt {
		t.Fatalf("Apply() receipt = %#v, want %#v", got, wantReceipt)
	}
	want := []string{"stage", "current", "swap:" + candidate.Digest, "restore:" + previous.Digest}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("workflow = %v, want %v", events, want)
	}
}

func TestApplyRollsBackWhenConfirmFails(t *testing.T) {
	events := []string{}
	generation := generation()
	candidate := receipt(generation.Edition, generation.ContentDigest)
	previous := currentReceipt(generation.Edition, strings.Repeat("a", 64))
	a, store, _, _ := activator(&events, candidate, previous)
	store.confirmErr = errInjected

	got, err := a.Apply(context.Background(), generation)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	wantReceipt := Receipt{Edition: previous.Edition, Digest: previous.Digest, Status: RolledBack,
		CandidateDigest: candidate.Digest, PreviousDigest: previous.Digest,
		ReloadRequested: true, CandidateProbed: true,
		RollbackRestored: true, RollbackReloaded: true, PreviousProbed: true}
	if got != wantReceipt {
		t.Fatalf("Apply() receipt = %#v, want %#v", got, wantReceipt)
	}
	want := []string{"stage", "current", "swap:" + candidate.Digest, "reload", "probe:" + candidate.Digest, "confirm:" + candidate.Digest, "restore:" + previous.Digest, "reload", "probe:" + previous.Digest}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("workflow = %v, want %v", events, want)
	}
}

func TestApplyFailsClosedForNilActivatorAndTypedNilStore(t *testing.T) {
	generation := generation()
	var nilActivator *Activator
	var nilStore *storeFake
	cases := []struct {
		name string
		a    *Activator
	}{
		{"nil activator", nilActivator},
		{"typed nil store", &Activator{Store: nilStore, Engine: &engineFake{}, Probe: &probeFake{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err, panicked := applyWithoutPanic(tc.a, generation)
			if panicked != nil {
				t.Fatalf("Apply() panicked: %v", panicked)
			}
			if err == nil || got != (Receipt{Status: Ambiguous}) {
				t.Fatalf("Apply() = (%#v, %v), want ambiguous receipt and error", got, err)
			}
		})
	}
}

func applyWithoutPanic(a *Activator, generation native.ConfigGeneration) (got Receipt, err error, panicked any) {
	defer func() { panicked = recover() }()
	got, err = a.Apply(context.Background(), generation)
	return
}
