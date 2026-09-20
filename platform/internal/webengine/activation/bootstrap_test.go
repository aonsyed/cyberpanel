package activation

import (
	"context"
	"io/fs"
	"reflect"
	"testing"
)

type bootstrapStoreFake struct{ *storeFake }

func (s *bootstrapStoreFake) PrepareBootstrap(context.Context, Receipt) error {
	*s.events = append(*s.events, "backup")
	return nil
}
func (s *bootstrapStoreFake) RestoreBootstrap(context.Context, Receipt) error {
	*s.events = append(*s.events, "restore-vendor")
	return s.restoreErr
}

type bootstrapEngineFake struct {
	*engineFake
	validationErr, startErr, stopErr error
}

func (e *bootstrapEngineFake) CheckStopped(context.Context) error {
	*e.events = append(*e.events, "check-stopped")
	return nil
}
func (e *bootstrapEngineFake) ValidateInitial(context.Context) error {
	*e.events = append(*e.events, "validate")
	return e.validationErr
}
func (e *bootstrapEngineFake) StartInitial(context.Context) error {
	*e.events = append(*e.events, "start")
	return e.startErr
}
func (e *bootstrapEngineFake) StopInitial(context.Context) error {
	*e.events = append(*e.events, "stop")
	return e.stopErr
}

func TestApplyInitialGenerationRequiresValidationAndLiveProof(t *testing.T) {
	events := []string{}
	g := generation()
	g.SnapshotGeneration = 1
	a, s, e, _ := activator(&events, receipt(g.Edition, g.ContentDigest), Receipt{})
	s.currentErr = fs.ErrNotExist
	a.Store = &bootstrapStoreFake{s}
	a.Engine = &bootstrapEngineFake{engineFake: e}
	got, err := a.Apply(context.Background(), g)
	if err != nil || got.Status != Applied || !got.Confirmed || got.PreviousDigest != "" {
		t.Fatalf("first activation: %#v %v", got, err)
	}
	want := []string{"stage", "current", "check-stopped", "backup", "swap:" + g.ContentDigest, "validate", "start", "probe:" + g.ContentDigest, "confirm:" + g.ContentDigest}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("workflow: %v", events)
	}
}

func TestInitialProbeFailureStopsAndRestoresWithoutClaimingHealthyRollback(t *testing.T) {
	events := []string{}
	g := generation()
	g.SnapshotGeneration = 1
	a, s, e, p := activator(&events, receipt(g.Edition, g.ContentDigest), Receipt{})
	s.currentErr = fs.ErrNotExist
	p.errs = []error{errInjected}
	a.Store = &bootstrapStoreFake{s}
	a.Engine = &bootstrapEngineFake{engineFake: e}
	got, err := a.Apply(context.Background(), g)
	if err == nil || got.Status != Ambiguous || got.Confirmed {
		t.Fatalf("failed bootstrap: %#v %v", got, err)
	}
	if len(events) < 2 || !reflect.DeepEqual(events[len(events)-2:], []string{"stop", "restore-vendor"}) {
		t.Fatalf("restore workflow: %v", events)
	}
}

func TestInitialValidationFailureNeverStartsService(t *testing.T) {
	events := []string{}
	g := generation()
	g.SnapshotGeneration = 1
	a, s, e, _ := activator(&events, receipt(g.Edition, g.ContentDigest), Receipt{})
	s.currentErr = fs.ErrNotExist
	a.Store = &bootstrapStoreFake{s}
	a.Engine = &bootstrapEngineFake{engineFake: e, validationErr: errInjected}
	got, err := a.Apply(context.Background(), g)
	if err == nil || got.Confirmed {
		t.Fatal("invalid configuration accepted")
	}
	for _, event := range events {
		if event == "start" {
			t.Fatal("started invalid configuration")
		}
	}
}

func TestInitialStopFailureDoesNotRestoreUnderRunningProcess(t *testing.T) {
	events := []string{}
	g := generation()
	g.SnapshotGeneration = 1
	a, s, e, p := activator(&events, receipt(g.Edition, g.ContentDigest), Receipt{})
	s.currentErr = fs.ErrNotExist
	p.errs = []error{errInjected}
	a.Store = &bootstrapStoreFake{s}
	a.Engine = &bootstrapEngineFake{engineFake: e, stopErr: errInjected}
	got, err := a.Apply(context.Background(), g)
	if err == nil || got.Confirmed {
		t.Fatal("unproven stop accepted")
	}
	for _, event := range events {
		if event == "restore-vendor" {
			t.Fatal("restored while stop was unproven")
		}
	}
}

func TestLaterSnapshotCannotUseInitialActivation(t *testing.T) {
	events := []string{}
	g := generation()
	a, s, e, _ := activator(&events, receipt(g.Edition, g.ContentDigest), Receipt{})
	s.currentErr = fs.ErrNotExist
	a.Store = &bootstrapStoreFake{s}
	a.Engine = &bootstrapEngineFake{engineFake: e}
	got, err := a.Apply(context.Background(), g)
	if err == nil || got.Confirmed || !reflect.DeepEqual(events, []string{"stage", "current"}) {
		t.Fatal("later generation initialized missing state", events)
	}
}
