// Package lswsruntime provides the narrow runtime boundary shared by
// OpenLiteSpeed and LiteSpeed Enterprise activation.
package lswsruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
)

const (
	lswsControlPath = "/usr/local/lsws/bin/lswsctrl"
	probeBodyLimit  = 4096
)

// Runner executes a bounded process invocation. Implementations must honor the
// supplied context and must not reinterpret program or args through a shell.
type Runner interface {
	Run(context.Context, string, ...string) error
}

// Engine exposes only the product-owned LiteSpeed reload operation.
type Engine struct {
	runner Runner
}

func NewEngine(runner Runner) (*Engine, error) {
	if nilInterface(runner) {
		return nil, errors.New("runtime runner is required")
	}
	return &Engine{runner: runner}, nil
}

func (engine *Engine) Reload(ctx context.Context) error {
	if engine == nil || nilInterface(engine.runner) {
		return errors.New("runtime runner is required")
	}
	if nilInterface(ctx) {
		return errors.New("reload context is required")
	}
	return engine.runner.Run(ctx, lswsControlPath, "reload")
}

// HTTPRoundTripper performs exactly one HTTP exchange. Unlike http.Client, a
// RoundTripper does not follow redirects, keeping health probes on loopback.
type HTTPRoundTripper interface {
	RoundTrip(*http.Request) (*http.Response, error)
}

type HTTPProbeConfig struct {
	Port      uint16
	Hostname  webengine.Hostname
	PathToken string
}

type HTTPProbe struct {
	transport HTTPRoundTripper
	url       string
	hostname  string
}

func NewHTTPProbe(transport HTTPRoundTripper, config HTTPProbeConfig) (*HTTPProbe, error) {
	if nilInterface(transport) {
		return nil, errors.New("HTTP transport is required")
	}
	if config.Port == 0 {
		return nil, errors.New("probe port must be non-zero")
	}
	hostname := config.Hostname.String()
	parsedHostname, err := webengine.ParseHostname(hostname)
	if err != nil || parsedHostname.String() != hostname {
		return nil, errors.New("probe hostname is invalid")
	}
	if !validPathToken(config.PathToken) {
		return nil, errors.New("probe path token is invalid")
	}

	return &HTTPProbe{
		transport: transport,
		url:       "http://127.0.0.1:" + strconv.FormatUint(uint64(config.Port), 10) + "/.well-known/panel-health/" + config.PathToken,
		hostname:  hostname,
	}, nil
}

func (probe *HTTPProbe) Check(ctx context.Context, receipt activation.Receipt) error {
	if probe == nil || nilInterface(probe.transport) {
		return errors.New("HTTP probe is not configured")
	}
	if nilInterface(ctx) {
		return errors.New("probe context is required")
	}
	if !validProbeReceipt(receipt) {
		return errors.New("activation receipt is invalid for probing")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.url, nil)
	if err != nil {
		return fmt.Errorf("build health request: %w", err)
	}
	request.Host = probe.hostname
	response, err := probe.transport.RoundTrip(request)
	if err != nil {
		return fmt.Errorf("perform health request: %w", err)
	}
	if response == nil || nilInterface(response.Body) {
		return errors.New("health response is incomplete")
	}
	defer response.Body.Close()

	if response.Request == nil || response.Request.URL == nil || response.Request.URL.String() != probe.url || response.Request.Host != probe.hostname {
		return errors.New("health response followed or replaced the loopback request")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health response status is %d, want 200", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, probeBodyLimit+1))
	if err != nil {
		return fmt.Errorf("read health response: %w", err)
	}
	if len(body) > probeBodyLimit {
		return errors.New("health response exceeds 4096 bytes")
	}
	expectedBody := []byte("panel-health-v1 " + receipt.Digest + "\n")
	if !bytes.Equal(body, expectedBody) {
		return errors.New("health response does not attest the activation digest")
	}
	return nil
}

func validProbeReceipt(receipt activation.Receipt) bool {
	if (receipt.Edition != webengine.EditionOpenLiteSpeed && receipt.Edition != webengine.EditionLiteSpeedEnterprise) || !validSHA256(receipt.Digest) {
		return false
	}
	if receipt.CandidateDigest != "" || receipt.PreviousDigest != "" || receipt.ReloadRequested || receipt.CandidateProbed || receipt.RollbackRestored || receipt.RollbackReloaded || receipt.PreviousProbed {
		return false
	}
	if receipt.Status == "" {
		return !receipt.Confirmed
	}
	return receipt.Status == activation.Applied && receipt.Confirmed
}

func validPathToken(token string) bool {
	if token == "" || len(token) > 128 {
		return false
	}
	for _, character := range token {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func validSHA256(digest string) bool {
	return len(digest) == sha256.Size*2 && strings.Trim(digest, "0123456789abcdef") == ""
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
