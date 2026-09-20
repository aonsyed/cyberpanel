//go:build linux

package webactivation

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
)

func testJournal(t *testing.T, path string) *Journal {
	t.Helper()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	j := &Journal{root: root, state: journalState{Version: ProtocolVersion, Records: make(map[string]journalRecord)}}
	t.Cleanup(func() { _ = j.Close() })
	if err := j.load(); err != nil {
		t.Fatal(err)
	}
	return j
}

func TestInitialJournalRecoveryPersistsAndThenBecomesImmutable(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		t.Run(map[bool]string{false: "ambiguous", true: "pending"}[interrupted], func(t *testing.T) {
			path := t.TempDir()
			j := testJournal(t, path)
			now := time.Now().UTC()
			r := Request{Version: ProtocolVersion, ExpectedDigest: strings.Repeat("a", 64), IssuedAt: now, Deadline: now.Add(time.Minute)}
			r.EffectID = effectIdentity(r.ExpectedDigest)
			r.Render.Snapshot.Generation = 1
			if _, _, err := j.Begin(r, now); err != nil {
				t.Fatal(err)
			}
			response := Response{Version: ProtocolVersion, EffectID: r.EffectID, ExpectedDigest: r.ExpectedDigest, CompletedAt: now, ErrorCode: "outcome_unknown", Receipt: activation.Receipt{Status: activation.Ambiguous, CandidateDigest: r.ExpectedDigest}}
			if !interrupted {
				if err := j.Complete(r, response); err != nil {
					t.Fatal(err)
				}
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			j = testJournal(t, path)
			// A new deadline does not change the canonical operation identity.
			r.IssuedAt = now.Add(time.Second)
			r.Deadline = r.IssuedAt.Add(time.Minute)
			record, existing, err := j.Begin(r, r.IssuedAt)
			if err != nil || !existing || !retryableInitial(r, record) {
				t.Fatalf("retry denied: %#v %v", record, err)
			}
			changed := r
			changed.Render.Snapshot.Generation = 2
			if _, _, err := j.Begin(changed, now); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("changed input accepted: %v", err)
			}
			response.ErrorCode = ""
			response.Receipt = activation.Receipt{Status: activation.Applied, Edition: webengine.EditionOpenLiteSpeed, Digest: r.ExpectedDigest, CandidateDigest: r.ExpectedDigest, Confirmed: true}
			if err := j.Complete(r, response); err != nil {
				t.Fatal(err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			j = testJournal(t, path)
			record, _, err = j.Begin(r, now)
			if err != nil || retryableInitial(r, record) || record.Receipt != response.Receipt {
				t.Fatalf("terminal receipt: %#v %v", record, err)
			}
			response.CompletedAt = now.Add(time.Second)
			if err := j.Complete(r, response); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("terminal receipt mutated: %v", err)
			}
		})
	}
}

func TestInitialRecoveryDoesNotReplayOtherOutcomes(t *testing.T) {
	r := Request{ExpectedDigest: strings.Repeat("a", 64)}
	r.Render.Snapshot.Generation = 1
	base := journalRecord{State: "completed", RequestDigest: r.Digest(), ErrorCode: "outcome_unknown", Receipt: activation.Receipt{Status: activation.Ambiguous}}
	for _, variant := range []string{"later-snapshot", "previous-generation", "rejected", "applied", "different-request"} {
		t.Run(variant, func(t *testing.T) {
			request, record := r, base
			switch variant {
			case "later-snapshot":
				request.Render.Snapshot.Generation = 2
				record.RequestDigest = request.Digest()
			case "previous-generation":
				record.Receipt.PreviousDigest = strings.Repeat("b", 64)
			case "rejected":
				record.ErrorCode = "activation_rejected"
			case "applied":
				record.Receipt.Status = activation.Applied
			case "different-request":
				record.RequestDigest = strings.Repeat("c", 64)
			}
			if retryableInitial(request, record) {
				t.Fatal("unsafe replay permitted")
			}
		})
	}
}
