package webactivation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

type recoveryStore struct {
	activation.Store
	current activation.Receipt
	err     error
}

func (s recoveryStore) Current(context.Context) (activation.Receipt, error) { return s.current, s.err }

type recoveryHTTP struct {
	body   string
	status int
}

func (h recoveryHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: h.status, Body: io.NopCloser(strings.NewReader(h.body)), Request: r}, nil
}

func TestRestoredRecoveryRequiresMatchingMasterAndLiveProof(t *testing.T) {
	previous := strings.Repeat("a", 64)
	request := Request{ExpectedDigest: strings.Repeat("b", 64)}
	request.Render.Snapshot.Generation = 2
	host, _ := webengine.ParseHostname("default.invalid")
	request.Render.Desired.Engine.Listeners = []webengine.Listener{{Ref: "http", Addresses: []string{"127.0.0.1"}, Port: 80, TLSMode: webengine.TLSModeClear}}
	request.Render.Desired.Bindings = []webengine.WebBindingSpec{{Ref: "binding/system-default", Hostnames: []webengine.Hostname{host}, ListenerRefs: []webengine.ResourceRef{"http"}}}
	record := journalRecord{RequestDigest: request.Digest(), State: "completed", ErrorCode: "outcome_unknown", Receipt: activation.Receipt{Status: activation.Ambiguous, CandidateDigest: request.ExpectedDigest, PreviousDigest: previous, RollbackRestored: true}}
	current := activation.Receipt{Edition: webengine.EditionOpenLiteSpeed, Status: activation.Applied, Digest: previous, Confirmed: true}
	for _, name := range []string{"valid", "wrong-master", "unconfirmed", "tampered-files", "wrong-live", "http-error", "not-restored", "running", "changed-request"} {
		t.Run(name, func(t *testing.T) {
			r := record
			c := current
			q := request
			s := recoveryStore{current: c}
			h := recoveryHTTP{status: 200, body: "panel-health-v1 " + previous + "\n"}
			switch name {
			case "wrong-master":
				s.current.Digest = request.ExpectedDigest
			case "unconfirmed":
				s.current.Confirmed = false
			case "tampered-files":
				s.err = errors.New("master mismatch")
			case "wrong-live":
				h.body = "panel-health-v1 " + request.ExpectedDigest + "\n"
			case "http-error":
				h.status = 404
			case "not-restored":
				r.Receipt.RollbackRestored = false
			case "running":
				r.State = "pending"
			case "changed-request":
				q.Render = native.RenderRequest{}
			}
			broker := &Broker{edition: webengine.EditionOpenLiteSpeed, store: s, transport: h}
			proof, err := broker.restoredRecoveryEvidence(context.Background(), q, r)
			if name == "valid" {
				if err != nil || !validDigest(proof) {
					t.Fatal(proof, err)
				}
			} else if err == nil {
				t.Fatal("unsafe recovery accepted")
			}
		})
	}
}
