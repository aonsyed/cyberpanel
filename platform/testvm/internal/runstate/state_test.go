package runstate

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNewCreatesTheOnlyInitialState(t *testing.T) {
	state, err := New("run-20260812-arm64")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	want := State{
		SchemaVersion: SchemaVersion,
		RunID:         "run-20260812-arm64",
		Phase:         PhaseNew,
		Revision:      1,
	}
	if !reflect.DeepEqual(state, want) {
		t.Fatalf("New() = %#v, want %#v", state, want)
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("New().Validate() error = %v", err)
	}
}

func TestTransitionAcceptsTheClosedSuccessfulLifecycle(t *testing.T) {
	state := mustNew(t, "successful-run")
	for _, next := range []Phase{
		PhaseDoctored,
		PhaseImageVerified,
		PhasePrepared,
		PhaseBooting,
		PhaseSSHReady,
		PhaseGuestReady,
		PhaseTesting,
		PhaseCollecting,
		PhaseShuttingDown,
		PhaseComplete,
	} {
		before := state
		var err error
		state, err = state.Transition(next, nil)
		if err != nil {
			t.Fatalf("Transition(%s) from %s error = %v", next, before.Phase, err)
		}
		if state.RunID != before.RunID {
			t.Fatalf("Transition(%s) changed RunID from %q to %q", next, before.RunID, state.RunID)
		}
		if state.Revision != before.Revision+1 {
			t.Fatalf("Transition(%s) revision = %d, want %d", next, state.Revision, before.Revision+1)
		}
		if state.Phase != next {
			t.Fatalf("Transition(%s) phase = %s", next, state.Phase)
		}
	}

	if !state.IsTerminal() {
		t.Fatal("COMPLETE state is not terminal")
	}
}

func TestEveryNonterminalProgressPhaseMayFail(t *testing.T) {
	for _, failedPhase := range failureEligiblePhases() {
		t.Run(string(failedPhase), func(t *testing.T) {
			state := stateAtPhase(t, failedPhase)
			failure := &Failure{
				Class:       FailureClassInfraFailed,
				FailedPhase: failedPhase,
				Reason:      "guest-readiness-deadline",
			}

			failed, err := state.Transition(PhaseFailed, failure)
			if err != nil {
				t.Fatalf("Transition(FAILED) from %s error = %v", failedPhase, err)
			}
			if failed.Phase != PhaseFailed {
				t.Fatalf("phase = %s, want FAILED", failed.Phase)
			}
			if failed.FailureClass != failure.Class || failed.FailedPhase != failedPhase || failed.Reason != failure.Reason {
				t.Fatalf("failure metadata = %#v", failed)
			}
			if failed.IsTerminal() {
				t.Fatal("FAILED must record a cleanup disposition before becoming terminal")
			}
		})
	}
}

func TestFailedAcceptsOnlyClosedTerminalDispositionsAndRetainsFailure(t *testing.T) {
	for _, disposition := range []Phase{
		PhaseFailedRetained,
		PhaseFailedCleaned,
		PhaseEmergencyManualCleanup,
	} {
		t.Run(string(disposition), func(t *testing.T) {
			state := stateAtPhase(t, PhaseTesting)
			failed, err := state.Transition(PhaseFailed, &Failure{
				Class:       FailureClassTestFailed,
				FailedPhase: PhaseTesting,
				Reason:      "acceptance-suite-failed",
			})
			if err != nil {
				t.Fatalf("create FAILED state: %v", err)
			}

			terminal, err := failed.Transition(disposition, nil)
			if err != nil {
				t.Fatalf("Transition(%s) error = %v", disposition, err)
			}
			if terminal.FailureClass != failed.FailureClass || terminal.FailedPhase != failed.FailedPhase || terminal.Reason != failed.Reason {
				t.Fatalf("Transition(%s) changed failure metadata: got %#v, want %#v", disposition, terminal, failed)
			}
			if !terminal.IsTerminal() {
				t.Fatalf("%s is not terminal", disposition)
			}
		})
	}
}

func TestTransitionRejectsIllegalEdgesAndFailureMetadata(t *testing.T) {
	tests := []struct {
		name    string
		state   func(*testing.T) State
		next    Phase
		failure *Failure
	}{
		{
			name:  "skip a successful phase",
			state: func(t *testing.T) State { return mustNew(t, "run") },
			next:  PhaseImageVerified,
		},
		{
			name:  "move backward",
			state: func(t *testing.T) State { return stateAtPhase(t, PhasePrepared) },
			next:  PhaseDoctored,
		},
		{
			name:  "jump directly to failure disposition",
			state: func(t *testing.T) State { return stateAtPhase(t, PhaseTesting) },
			next:  PhaseFailedCleaned,
		},
		{
			name:  "complete state cannot fail",
			state: func(t *testing.T) State { return stateAtPhase(t, PhaseComplete) },
			next:  PhaseFailed,
			failure: &Failure{
				Class:       FailureClassInfraFailed,
				FailedPhase: PhaseComplete,
				Reason:      "too-late",
			},
		},
		{
			name:  "failed state cannot resume",
			state: failedState,
			next:  PhaseTesting,
		},
		{
			name:  "terminal failure disposition cannot transition",
			state: terminalFailedState,
			next:  PhaseFailedCleaned,
		},
		{
			name:  "ordinary transition rejects failure metadata",
			state: func(t *testing.T) State { return mustNew(t, "run") },
			next:  PhaseDoctored,
			failure: &Failure{
				Class:       FailureClassInfraFailed,
				FailedPhase: PhaseNew,
				Reason:      "not-a-failure-edge",
			},
		},
		{
			name:  "failed transition requires metadata",
			state: func(t *testing.T) State { return mustNew(t, "run") },
			next:  PhaseFailed,
		},
		{
			name:  "failed transition requires closed class",
			state: func(t *testing.T) State { return mustNew(t, "run") },
			next:  PhaseFailed,
			failure: &Failure{
				Class:       FailureClass("UNKNOWN"),
				FailedPhase: PhaseNew,
				Reason:      "unknown-failure-class",
			},
		},
		{
			name:  "failed phase must be current phase",
			state: func(t *testing.T) State { return stateAtPhase(t, PhaseBooting) },
			next:  PhaseFailed,
			failure: &Failure{
				Class:       FailureClassInfraFailed,
				FailedPhase: PhasePrepared,
				Reason:      "incorrect-failed-phase",
			},
		},
		{
			name:  "failure reason cannot be empty",
			state: func(t *testing.T) State { return stateAtPhase(t, PhaseTesting) },
			next:  PhaseFailed,
			failure: &Failure{
				Class:       FailureClassTestFailed,
				FailedPhase: PhaseTesting,
				Reason:      "   ",
			},
		},
		{
			name:  "failure disposition cannot replace metadata",
			state: failedState,
			next:  PhaseFailedRetained,
			failure: &Failure{
				Class:       FailureClassInfraFailed,
				FailedPhase: PhaseTesting,
				Reason:      "replacement",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := tt.state(t)
			got, err := before.Transition(tt.next, tt.failure)
			if !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("Transition() error = %v, want ErrInvalidTransition", err)
			}
			if got != (State{}) {
				t.Fatalf("Transition() state = %#v, want zero state on error", got)
			}
		})
	}
}

func TestNewRejectsUnsafeRunIDs(t *testing.T) {
	valid := []string{"run-1", "RUN_20260812.arm64", "a"}
	for _, runID := range valid {
		t.Run("valid_"+runID, func(t *testing.T) {
			if _, err := New(runID); err != nil {
				t.Fatalf("New(%q) error = %v", runID, err)
			}
		})
	}

	invalid := []string{
		"",
		".",
		"..",
		"../escape",
		"run/child",
		"run with spaces",
		"run\nnewline",
		"café",
		strings.Repeat("r", MaxRunIDBytes+1),
	}
	for _, runID := range invalid {
		t.Run("invalid_"+strings.ReplaceAll(runID, "/", "_"), func(t *testing.T) {
			_, err := New(runID)
			if !errors.Is(err, ErrInvalidState) {
				t.Fatalf("New(%q) error = %v, want ErrInvalidState", runID, err)
			}
		})
	}
}

func TestValidateRejectsCorruptFailureCombinations(t *testing.T) {
	base := mustNew(t, "run")
	tests := []State{
		{SchemaVersion: SchemaVersion, RunID: "run", Phase: Phase("UNKNOWN"), Revision: 1},
		{SchemaVersion: SchemaVersion + 1, RunID: "run", Phase: PhaseNew, Revision: 1},
		{SchemaVersion: SchemaVersion, RunID: "run", Phase: PhaseNew, Revision: 0},
		{
			SchemaVersion: SchemaVersion,
			RunID:         "run",
			Phase:         PhaseFailed,
			Revision:      2,
			FailureClass:  FailureClassInfraFailed,
			FailedPhase:   PhaseNew,
		},
		{
			SchemaVersion: SchemaVersion,
			RunID:         "run",
			Phase:         PhaseFailed,
			Revision:      2,
			FailureClass:  FailureClassInfraFailed,
			FailedPhase:   PhaseComplete,
			Reason:        "invalid-failed-phase",
		},
	}
	withUnexpectedFailure := base
	withUnexpectedFailure.FailureClass = FailureClassInfraFailed
	withUnexpectedFailure.FailedPhase = PhaseNew
	withUnexpectedFailure.Reason = "metadata-on-success"
	tests = append(tests, withUnexpectedFailure)

	for index, state := range tests {
		if err := state.Validate(); !errors.Is(err, ErrInvalidState) {
			t.Errorf("case %d Validate() error = %v, want ErrInvalidState", index, err)
		}
	}
}

func mustNew(t *testing.T, runID string) State {
	t.Helper()
	state, err := New(runID)
	if err != nil {
		t.Fatalf("New(%q): %v", runID, err)
	}
	return state
}

func stateAtPhase(t *testing.T, want Phase) State {
	t.Helper()
	state := mustNew(t, "run")
	if want == PhaseNew {
		return state
	}
	for _, next := range successfulPhases()[1:] {
		var err error
		state, err = state.Transition(next, nil)
		if err != nil {
			t.Fatalf("advance to %s: %v", next, err)
		}
		if next == want {
			return state
		}
	}
	t.Fatalf("test requested unsupported progress phase %s", want)
	return State{}
}

func failedState(t *testing.T) State {
	t.Helper()
	state := stateAtPhase(t, PhaseTesting)
	state, err := state.Transition(PhaseFailed, &Failure{
		Class:       FailureClassTestFailed,
		FailedPhase: PhaseTesting,
		Reason:      "acceptance-suite-failed",
	})
	if err != nil {
		t.Fatalf("create failed state: %v", err)
	}
	return state
}

func terminalFailedState(t *testing.T) State {
	t.Helper()
	state := failedState(t)
	state, err := state.Transition(PhaseFailedRetained, nil)
	if err != nil {
		t.Fatalf("create terminal failed state: %v", err)
	}
	return state
}

func successfulPhases() []Phase {
	return []Phase{
		PhaseNew,
		PhaseDoctored,
		PhaseImageVerified,
		PhasePrepared,
		PhaseBooting,
		PhaseSSHReady,
		PhaseGuestReady,
		PhaseTesting,
		PhaseCollecting,
		PhaseShuttingDown,
		PhaseComplete,
	}
}

func failureEligiblePhases() []Phase {
	phases := successfulPhases()
	return phases[:len(phases)-1]
}
