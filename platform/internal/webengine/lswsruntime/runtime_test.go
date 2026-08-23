package lswsruntime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
)

var (
	_ activation.Engine = (*Engine)(nil)
	_ activation.Probe  = (*HTTPProbe)(nil)
)

var errRunnerExit = errors.New("lswsctrl exited unsuccessfully")

type runnerCall struct {
	ctx     context.Context
	program string
	args    []string
}

type runnerFake struct {
	calls []runnerCall
	run   func(context.Context) error
}

func (runner *runnerFake) Run(ctx context.Context, program string, args ...string) error {
	runner.calls = append(runner.calls, runnerCall{
		ctx:     ctx,
		program: program,
		args:    append([]string(nil), args...),
	})
	if runner.run != nil {
		return runner.run(ctx)
	}
	return nil
}

func TestEngineReloadInvokesOnlyTheFixedLSWSControlArgv(t *testing.T) {
	runner := &runnerFake{}
	engine, err := NewEngine(runner)
	if err != nil {
		t.Fatalf("NewEngine(): %v", err)
	}
	ctx := context.WithValue(context.Background(), struct{}{}, "caller-context")
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload(): %v", err)
	}

	want := []runnerCall{{
		ctx:     ctx,
		program: "/usr/local/lsws/bin/lswsctrl",
		args:    []string{"reload"},
	}}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("runner calls = %#v, want fixed argv %#v", runner.calls, want)
	}
}

func TestEngineReloadPropagatesRunnerExitAndContextErrors(t *testing.T) {
	tests := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		run  func(context.Context) error
		want error
	}{
		{
			name: "exit error",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			run:  func(context.Context) error { return errRunnerExit },
			want: errRunnerExit,
		},
		{
			name: "expired deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Unix(1, 0))
			},
			run:  func(ctx context.Context) error { return ctx.Err() },
			want: context.DeadlineExceeded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.ctx()
			defer cancel()
			runner := &runnerFake{run: test.run}
			engine, err := NewEngine(runner)
			if err != nil {
				t.Fatalf("NewEngine(): %v", err)
			}
			if err := engine.Reload(ctx); !errors.Is(err, test.want) {
				t.Fatalf("Reload() error = %v, want %v", err, test.want)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("runner call count = %d, want 1", len(runner.calls))
			}
		})
	}
}

type roundTripperFake struct {
	calls    []*http.Request
	response func(*http.Request) *http.Response
	err      error
}

func (transport *roundTripperFake) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls = append(transport.calls, request)
	if transport.err != nil {
		return nil, transport.err
	}
	return transport.response(request), nil
}

type trackedBody struct {
	reader io.Reader
	closed bool
}

func (body *trackedBody) Read(buffer []byte) (int, error) { return body.reader.Read(buffer) }
func (body *trackedBody) Close() error {
	body.closed = true
	return nil
}

func TestNewHTTPProbeRejectsUnsafeOrIncompleteInputs(t *testing.T) {
	validHostname := mustWebHostname(t, "tenant.example.test")
	valid := HTTPProbeConfig{
		Port:      8080,
		Hostname:  validHostname,
		PathToken: "probe_A9-z",
	}

	tests := []struct {
		name      string
		transport HTTPRoundTripper
		mutate    func(*HTTPProbeConfig)
	}{
		{name: "nil transport", transport: nil, mutate: func(*HTTPProbeConfig) {}},
		{name: "zero port", transport: &roundTripperFake{}, mutate: func(config *HTTPProbeConfig) { config.Port = 0 }},
		{name: "empty hostname", transport: &roundTripperFake{}, mutate: func(config *HTTPProbeConfig) { config.Hostname = webengine.Hostname{} }},
		{name: "path traversal token", transport: &roundTripperFake{}, mutate: func(config *HTTPProbeConfig) { config.PathToken = "../escape" }},
		{name: "query injection token", transport: &roundTripperFake{}, mutate: func(config *HTTPProbeConfig) { config.PathToken = "probe?admin=1" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if probe, err := NewHTTPProbe(test.transport, config); err == nil || probe != nil {
				t.Fatalf("NewHTTPProbe() = (%#v, %v), want nil and validation error", probe, err)
			}
		})
	}
}

func TestHTTPProbeUsesOnlyLoopbackHealthURLAndExactHost(t *testing.T) {
	receipts := []struct {
		name    string
		receipt activation.Receipt
	}{
		{
			name: "staged candidate",
			receipt: activation.Receipt{
				Edition: webengine.EditionOpenLiteSpeed,
				Digest:  strings.Repeat("a", 64),
			},
		},
		{
			name: "confirmed current",
			receipt: activation.Receipt{
				Edition:   webengine.EditionLiteSpeedEnterprise,
				Digest:    strings.Repeat("b", 64),
				Status:    activation.Applied,
				Confirmed: true,
			},
		},
	}

	for _, test := range receipts {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedBody{reader: strings.NewReader(healthBody(test.receipt))}
			transport := &roundTripperFake{response: func(request *http.Request) *http.Response {
				return &http.Response{StatusCode: http.StatusOK, Body: body, Request: request}
			}}
			probe := mustHTTPProbe(t, transport, HTTPProbeConfig{
				Port:      8080,
				Hostname:  mustWebHostname(t, "Tenant.Example.Test"),
				PathToken: "probe_A9-z",
			})
			ctx := context.WithValue(context.Background(), struct{}{}, "probe-context")
			if err := probe.Check(ctx, test.receipt); err != nil {
				t.Fatalf("Check(): %v", err)
			}
			if len(transport.calls) != 1 {
				t.Fatalf("HTTP calls = %d, want 1", len(transport.calls))
			}
			request := transport.calls[0]
			if request.Method != http.MethodGet {
				t.Fatalf("method = %q, want GET", request.Method)
			}
			if got, want := request.URL.String(), "http://127.0.0.1:8080/.well-known/panel-health/probe_A9-z"; got != want {
				t.Fatalf("URL = %q, want %q", got, want)
			}
			if request.Host != "tenant.example.test" {
				t.Fatalf("Host = %q, want canonical tenant hostname", request.Host)
			}
			if request.Context() != ctx {
				t.Fatal("request did not preserve caller context")
			}
			if !body.closed {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestHTTPProbeRejectsRedirectStatusWrongGenerationAndOversizeBody(t *testing.T) {
	receipt := stagedReceipt()
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "redirect is returned without a second request", status: http.StatusFound, body: healthBody(receipt)},
		{name: "non-200", status: http.StatusServiceUnavailable, body: healthBody(receipt)},
		{name: "old generation body", status: http.StatusOK, body: "panel-health-v1 " + strings.Repeat("b", 64) + "\n"},
		{name: "malformed body", status: http.StatusOK, body: "healthy\n"},
		{name: "body over 4 KiB", status: http.StatusOK, body: strings.Repeat("x", 4097)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedBody{reader: strings.NewReader(test.body)}
			transport := &roundTripperFake{response: func(request *http.Request) *http.Response {
				return &http.Response{StatusCode: test.status, Body: body, Request: request}
			}}
			probe := mustHTTPProbe(t, transport, HTTPProbeConfig{
				Port:      8080,
				Hostname:  mustWebHostname(t, "tenant.example.test"),
				PathToken: "probe_A9-z",
			})
			if err := probe.Check(context.Background(), receipt); err == nil {
				t.Fatal("Check() succeeded for an untrusted response")
			}
			if len(transport.calls) != 1 {
				t.Fatalf("transport calls = %d, want exactly one loopback round trip", len(transport.calls))
			}
			if !body.closed {
				t.Fatal("response body was not closed after rejection")
			}
		})
	}
}

func TestHTTPProbePropagatesCallerCancellationAndTransportErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transport := &roundTripperFake{err: context.Canceled}
	probe := mustHTTPProbe(t, transport, validProbeConfig(t))

	if err := probe.Check(ctx, stagedReceipt()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Check() error = %v, want context cancellation", err)
	}
	if len(transport.calls) != 1 || !errors.Is(transport.calls[0].Context().Err(), context.Canceled) {
		t.Fatalf("transport request did not carry canceled context: %#v", transport.calls)
	}
}

func TestHTTPProbeRejectsInvalidActivationReceiptBeforeNetworkIO(t *testing.T) {
	tests := []activation.Receipt{
		{},
		{Edition: webengine.EditionOpenLiteSpeed, Digest: strings.Repeat("a", 63)},
		{Edition: webengine.EditionOpenLiteSpeed, Digest: strings.Repeat("a", 64), Status: activation.Applied},
		{Edition: webengine.EditionOpenLiteSpeed, Digest: strings.Repeat("a", 64), Status: activation.Ambiguous},
		{
			Edition:         webengine.EditionOpenLiteSpeed,
			Digest:          strings.Repeat("a", 64),
			CandidateDigest: strings.Repeat("a", 64),
		},
	}

	for index, receipt := range tests {
		transport := &roundTripperFake{response: func(request *http.Request) *http.Response {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(healthBody(receipt))), Request: request}
		}}
		probe := mustHTTPProbe(t, transport, validProbeConfig(t))
		if err := probe.Check(context.Background(), receipt); err == nil {
			t.Fatalf("case %d: Check() accepted invalid receipt %#v", index, receipt)
		}
		if len(transport.calls) != 0 {
			t.Fatalf("case %d: invalid receipt caused %d HTTP calls", index, len(transport.calls))
		}
	}
}

type typedNilContext struct{}

func (*typedNilContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*typedNilContext) Done() <-chan struct{}       { return nil }
func (*typedNilContext) Err() error                  { return nil }
func (*typedNilContext) Value(any) any               { return nil }

func TestRuntimeBoundariesRejectTypedNilContextBeforeSideEffects(t *testing.T) {
	var ctx *typedNilContext
	t.Run("engine reload", func(t *testing.T) {
		runner := &runnerFake{}
		engine, err := NewEngine(runner)
		if err != nil {
			t.Fatalf("NewEngine(): %v", err)
		}
		if err := engine.Reload(ctx); err == nil {
			t.Fatal("Reload() accepted a typed-nil context")
		}
		if len(runner.calls) != 0 {
			t.Fatalf("typed-nil context caused %d runner calls", len(runner.calls))
		}
	})
	t.Run("HTTP probe", func(t *testing.T) {
		transport := &roundTripperFake{response: func(request *http.Request) *http.Response {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(healthBody(stagedReceipt()))), Request: request}
		}}
		probe := mustHTTPProbe(t, transport, validProbeConfig(t))
		if err := probe.Check(ctx, stagedReceipt()); err == nil {
			t.Fatal("Check() accepted a typed-nil context")
		}
		if len(transport.calls) != 0 {
			t.Fatalf("typed-nil context caused %d HTTP calls", len(transport.calls))
		}
	})
}

type panicReadCloser struct{}

func (*panicReadCloser) Read([]byte) (int, error) { panic("typed-nil body was read") }
func (*panicReadCloser) Close() error             { panic("typed-nil body was closed") }

func TestHTTPProbeRejectsTypedNilResponseBodyWithoutPanicking(t *testing.T) {
	var body *panicReadCloser
	transport := &roundTripperFake{response: func(request *http.Request) *http.Response {
		return &http.Response{StatusCode: http.StatusOK, Body: body, Request: request}
	}}
	probe := mustHTTPProbe(t, transport, validProbeConfig(t))
	if err := probe.Check(context.Background(), stagedReceipt()); err == nil {
		t.Fatal("Check() accepted a typed-nil response body")
	}
}

func stagedReceipt() activation.Receipt {
	return activation.Receipt{
		Edition: webengine.EditionOpenLiteSpeed,
		Digest:  strings.Repeat("a", 64),
	}
}

func validProbeConfig(t *testing.T) HTTPProbeConfig {
	t.Helper()
	return HTTPProbeConfig{
		Port:      8080,
		Hostname:  mustWebHostname(t, "tenant.example.test"),
		PathToken: "probe_A9-z",
	}
}

func mustHTTPProbe(t *testing.T, transport HTTPRoundTripper, config HTTPProbeConfig) *HTTPProbe {
	t.Helper()
	probe, err := NewHTTPProbe(transport, config)
	if err != nil {
		t.Fatalf("NewHTTPProbe(): %v", err)
	}
	return probe
}

func mustWebHostname(t *testing.T, raw string) webengine.Hostname {
	t.Helper()
	hostname, err := webengine.ParseHostname(raw)
	if err != nil {
		t.Fatalf("ParseHostname(%q): %v", raw, err)
	}
	return hostname
}

func healthBody(receipt activation.Receipt) string {
	return "panel-health-v1 " + receipt.Digest + "\n"
}
