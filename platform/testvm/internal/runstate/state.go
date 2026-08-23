// Package runstate records the closed, durable lifecycle of one test-VM run.
package runstate

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// SchemaVersion is the only on-disk run-state schema understood by this
	// package. A version change requires an explicit migration.
	SchemaVersion = 1

	// MaxRunIDBytes bounds identifiers before they enter logs or file-backed
	// authority state.
	MaxRunIDBytes = 128

	maxReasonBytes = 512
)

var (
	// ErrInvalidState means a State violates the closed schema or lifecycle
	// invariants.
	ErrInvalidState = errors.New("invalid run state")
	// ErrInvalidTransition means the requested edge is absent from the closed
	// lifecycle graph.
	ErrInvalidTransition = errors.New("invalid run-state transition")
)

// Phase is one node in the closed run lifecycle.
type Phase string

const (
	PhaseNew           Phase = "NEW"
	PhaseDoctored      Phase = "DOCTORED"
	PhaseImageVerified Phase = "IMAGE_VERIFIED"
	PhasePrepared      Phase = "PREPARED"
	PhaseBooting       Phase = "BOOTING"
	PhaseSSHReady      Phase = "SSH_READY"
	PhaseGuestReady    Phase = "GUEST_READY"
	PhaseTesting       Phase = "TESTING"
	PhaseCollecting    Phase = "COLLECTING"
	PhaseShuttingDown  Phase = "SHUTTING_DOWN"
	PhaseComplete      Phase = "COMPLETE"

	PhaseFailed                 Phase = "FAILED"
	PhaseFailedRetained         Phase = "FAILED_RETAINED"
	PhaseFailedCleaned          Phase = "FAILED_CLEANED"
	PhaseEmergencyManualCleanup Phase = "EMERGENCY_MANUAL_CLEANUP"
)

// FailureClass distinguishes a product/test failure from harness or
// infrastructure failure. No unclassified failure is persistable.
type FailureClass string

const (
	FailureClassTestFailed  FailureClass = "TEST_FAILED"
	FailureClassInfraFailed FailureClass = "INFRA_FAILED"
)

// Failure supplies the required metadata for a transition into FAILED.
// FailedPhase must equal the state's current phase; this prevents callers from
// rewriting where the failure occurred.
type Failure struct {
	Class       FailureClass
	FailedPhase Phase
	Reason      string
}

// State is the complete versioned authority record for one run. Failure fields
// are absent until FAILED and remain unchanged through the terminal cleanup
// disposition.
type State struct {
	SchemaVersion int          `json:"schemaVersion"`
	RunID         string       `json:"runId"`
	Phase         Phase        `json:"phase"`
	Revision      uint64       `json:"revision"`
	FailureClass  FailureClass `json:"failureClass,omitempty"`
	FailedPhase   Phase        `json:"failedPhase,omitempty"`
	Reason        string       `json:"reason,omitempty"`
}

var progressPhases = [...]Phase{
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

// New returns the only valid initial state for runID.
func New(runID string) (State, error) {
	state := State{
		SchemaVersion: SchemaVersion,
		RunID:         runID,
		Phase:         PhaseNew,
		Revision:      1,
	}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

// Validate checks both the JSON-level schema and invariants implied by the
// closed transition graph.
func (s State) Validate() error {
	if s.SchemaVersion != SchemaVersion {
		return invalidState("schemaVersion must equal %d", SchemaVersion)
	}
	if !isSafeRunID(s.RunID) {
		return invalidState("runId must contain 1 to %d safe ASCII bytes", MaxRunIDBytes)
	}
	if s.Revision == 0 {
		return invalidState("revision must be positive")
	}

	if index, ok := progressPhaseIndex(s.Phase); ok {
		if s.FailureClass != "" || s.FailedPhase != "" || s.Reason != "" {
			return invalidState("phase %s cannot contain failure metadata", s.Phase)
		}
		wantRevision := uint64(index + 1)
		if s.Revision != wantRevision {
			return invalidState("phase %s requires revision %d", s.Phase, wantRevision)
		}
		return nil
	}

	if !isFailurePhase(s.Phase) {
		return invalidState("unknown phase %q", s.Phase)
	}
	failure := Failure{Class: s.FailureClass, FailedPhase: s.FailedPhase, Reason: s.Reason}
	if err := validateFailure(failure); err != nil {
		return invalidState("%v", err)
	}
	failedIndex, _ := progressPhaseIndex(s.FailedPhase)
	wantRevision := uint64(failedIndex + 2)
	if s.Phase != PhaseFailed {
		wantRevision++
	}
	if s.Revision != wantRevision {
		return invalidState("phase %s failed from %s requires revision %d", s.Phase, s.FailedPhase, wantRevision)
	}
	return nil
}

// Transition applies one legal lifecycle edge and increments Revision. It
// returns a new value; the receiver is never mutated.
func (s State) Transition(next Phase, failure *Failure) (State, error) {
	if err := s.Validate(); err != nil {
		return State{}, err
	}
	if s.IsTerminal() {
		return State{}, invalidTransition("terminal phase %s has no outgoing edge", s.Phase)
	}
	if s.Revision == ^uint64(0) {
		return State{}, invalidTransition("revision overflow")
	}

	updated := s
	updated.Revision++

	if s.Phase == PhaseFailed {
		if failure != nil {
			return State{}, invalidTransition("failure metadata is immutable after FAILED")
		}
		switch next {
		case PhaseFailedRetained, PhaseFailedCleaned, PhaseEmergencyManualCleanup:
			updated.Phase = next
			return updated, nil
		default:
			return State{}, invalidTransition("FAILED cannot transition to %s", next)
		}
	}

	if next == PhaseFailed {
		if failure == nil {
			return State{}, invalidTransition("FAILED requires failure metadata")
		}
		if err := validateFailure(*failure); err != nil {
			return State{}, invalidTransition("%v", err)
		}
		if failure.FailedPhase != s.Phase {
			return State{}, invalidTransition("failedPhase %s must equal current phase %s", failure.FailedPhase, s.Phase)
		}
		updated.Phase = PhaseFailed
		updated.FailureClass = failure.Class
		updated.FailedPhase = failure.FailedPhase
		updated.Reason = failure.Reason
		return updated, nil
	}

	if failure != nil {
		return State{}, invalidTransition("failure metadata is allowed only when entering FAILED")
	}
	want, ok := nextProgressPhase(s.Phase)
	if !ok || next != want {
		return State{}, invalidTransition("%s cannot transition to %s", s.Phase, next)
	}
	updated.Phase = next
	return updated, nil
}

// IsTerminal reports whether no further transition is allowed.
func (s State) IsTerminal() bool {
	switch s.Phase {
	case PhaseComplete, PhaseFailedRetained, PhaseFailedCleaned, PhaseEmergencyManualCleanup:
		return true
	default:
		return false
	}
}

func nextProgressPhase(current Phase) (Phase, bool) {
	index, ok := progressPhaseIndex(current)
	if !ok || index+1 >= len(progressPhases) {
		return "", false
	}
	return progressPhases[index+1], true
}

func progressPhaseIndex(phase Phase) (int, bool) {
	for index, candidate := range progressPhases {
		if candidate == phase {
			return index, true
		}
	}
	return 0, false
}

func isFailureEligiblePhase(phase Phase) bool {
	index, ok := progressPhaseIndex(phase)
	return ok && index < len(progressPhases)-1
}

func isFailurePhase(phase Phase) bool {
	switch phase {
	case PhaseFailed, PhaseFailedRetained, PhaseFailedCleaned, PhaseEmergencyManualCleanup:
		return true
	default:
		return false
	}
}

func validateFailure(failure Failure) error {
	switch failure.Class {
	case FailureClassTestFailed, FailureClassInfraFailed:
	default:
		return fmt.Errorf("failureClass must be TEST_FAILED or INFRA_FAILED")
	}
	if !isFailureEligiblePhase(failure.FailedPhase) {
		return fmt.Errorf("failedPhase %q is not failure-eligible", failure.FailedPhase)
	}
	if !isStableReason(failure.Reason) {
		return fmt.Errorf("reason must be non-empty, trimmed, printable UTF-8 of at most %d bytes", maxReasonBytes)
	}
	return nil
}

func isSafeRunID(runID string) bool {
	if runID == "" || len(runID) > MaxRunIDBytes || runID == "." || runID == ".." {
		return false
	}
	for index := 0; index < len(runID); index++ {
		character := runID[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func isStableReason(reason string) bool {
	if reason == "" || len(reason) > maxReasonBytes || strings.TrimSpace(reason) != reason || !utf8.ValidString(reason) {
		return false
	}
	for _, character := range reason {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func invalidState(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidState, fmt.Sprintf(format, args...))
}

func invalidTransition(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTransition, fmt.Sprintf(format, args...))
}
