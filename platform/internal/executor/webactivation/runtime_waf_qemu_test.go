//go:build linux

package webactivation

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/lswsruntime"
)

func runQEMUWAFHTTP(t *testing.T, master, digest string) {
	t.Helper()
	// Bind test-only attestation/challenge material into the private unit.
	// Do not write the live health tree or claim this provisions activation.
	fixtureRoot := t.TempDir()
	if err := os.Chmod(fixtureRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureRoot, "activation"), []byte("panel-health-v1 "+digest+"\n"), 0444); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	healthSource := fixtureRoot
	if os.Getenv("CYBERPANEL_QEMU_PERSISTENT_HEALTH") == "1" {
		healthSource = "/var/lib/cyberpanel/site-health/activation/g1"
	}
	output, err := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
		"--property=PrivateNetwork=yes", "--property=PrivateTmp=yes",
		"--property=TemporaryFileSystem=/run",
		"--property=ReadOnlyPaths=/usr/local/lsws/conf /etc /usr/share/modsecurity-crs",
		"--property=CapabilityBoundingSet=~CAP_SYS_ADMIN", "--property=KillMode=control-group",
		"--property=RuntimeMaxSec=30s", "--property=TimeoutStopSec=5s",
		"--property=BindReadOnlyPaths="+master+":/usr/local/lsws/conf/httpd_config.conf",
		"--property=BindReadOnlyPaths="+healthSource+":/var/lib/cyberpanel/site-health/activation/g1",
		"--property=BindReadOnlyPaths="+fixtureRoot+":/var/lib/cyberpanel/acme/http-01",
		"--setenv=CYBERPANEL_QEMU_WAF_HTTP_CHILD=1",
		"--setenv=CYBERPANEL_QEMU_HEALTH_DIGEST="+digest,
		executable, "-test.run=^TestQEMUWebWAFHTTPChild$", "-test.v").CombinedOutput()
	if err != nil {
		t.Fatalf("isolated native WAF HTTP fixture: %v\n%s", err, output)
	}
	t.Log(string(output))
}

// Re-exec only inside the bounded private-network unit above. This starts the
// real installed server against the actual pending renderer output, without
// changing live master files, bootstrap journals, service holds or receipts.
func TestQEMUWebWAFHTTPChild(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_WAF_HTTP_CHILD") != "1" {
		t.Skip("private QEMU HTTP test unit only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 23*time.Second)
	defer cancel()
	logPath := filepath.Join(t.TempDir(), "native.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	server := exec.CommandContext(ctx, "/usr/local/lsws/bin/lshttpd", "-d")
	server.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	server.Stdout, server.Stderr = log, log
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var exitErr error
	go func() { exitErr = server.Wait(); close(done) }()
	defer func() {
		_ = syscall.Kill(-server.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-server.Process.Pid, syscall.SIGKILL)
			<-done
		}
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			if len(data) > 4096 {
				data = data[len(data)-4096:]
			}
			t.Log(string(data))
		}
	}()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	request := func(method, target, contentType, body string, chunked, boundedChunks bool) (int, string, error) {
		req, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1"+target, strings.NewReader(body))
		if err != nil {
			return 0, "", err
		}
		req.Host = "default.invalid"
		if chunked {
			req.ContentLength = -1
			if boundedChunks {
				req.Body = io.NopCloser(struct{ io.Reader }{strings.NewReader(body)})
			}
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 CyberPanel-QEMU-qualification")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		response, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return response.StatusCode, string(data), err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-done:
			t.Fatalf("native server exited before readiness: %v", exitErr)
		default:
		}
		status, body, err := request("GET", "/", "", "", false, false)
		if err == nil && status == 200 && strings.Contains(body, "maintenance") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("native benign request did not become healthy: status=%d error=%v body=%q", status, err, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Run("production-health-probe", func(t *testing.T) {
		transport := NewLoopbackTransport()
		defer transport.CloseIdleConnections()
		hostname, err := webengine.ParseHostname("default.invalid")
		if err != nil {
			t.Fatal(err)
		}
		probe, err := lswsruntime.NewHTTPProbe(transport, lswsruntime.HTTPProbeConfig{Port: 80, Hostname: hostname, PathToken: "activation"})
		if err != nil {
			t.Fatal(err)
		}
		if err := probe.Check(ctx, activation.Receipt{Edition: webengine.EditionOpenLiteSpeed, Digest: os.Getenv("CYBERPANEL_QEMU_HEALTH_DIGEST")}); err != nil {
			t.Fatal(err)
		}
	})
	oversizedJSON := `{"message":"` + strings.Repeat("a", 13107200) + `"}`
	for _, fixture := range []struct {
		name, method, target, contentType, body string
		want                                    int
	}{
		{"benign-repeat", "GET", "/", "", "", 200},
		{"benign-direct-file", "GET", "/index.html", "", "", 200},
		{"activation-health", "GET", "/.well-known/panel-health/activation", "", "", 200},
		{"acme-challenge", "GET", "/.well-known/acme-challenge/activation", "", "", 200},
		{"health-listing-denied", "GET", "/.well-known/panel-health/", "", "", 404},
		{"acme-listing-denied", "GET", "/.well-known/acme-challenge/", "", "", 404},
		{"benign-query", "GET", "/?q=hello", "", "", 200},
		{"xss-query", "GET", "/?q=" + url.QueryEscape("<script>alert(1)</script>"), "", "", 403},
		{"sqli-query", "GET", "/?q=" + url.QueryEscape("1' OR '1'='1"), "", "", 403},
		{"benign-json", "POST", "/", "application/json", `{"message":"hello"}`, 200},
		{"xss-json", "POST", "/", "application/json", `{"message":"<script>alert(1)</script>"}`, 403},
		{"xss-chunked-json", "POST", "/", "application/json", `{"message":"<script>alert(1)</script>"}`, 403},
		{"late-xss-bounded-chunked-json", "POST", "/", "application/json", `{"padding":"` + strings.Repeat("a", 65536) + `","message":"<script>alert(1)</script>"}`, 403},
		{"xss-json-subtype", "POST", "/", "application/problem+json", `{"message":"<script>alert(1)</script>"}`, 403},
		{"malformed-json", "POST", "/", "application/json", `{"message":`, 400},
		{"benign-xml", "POST", "/", "application/xml", `<message>hello</message>`, 200},
		{"xss-xml-attribute", "POST", "/", "application/xml", `<message value="&lt;script&gt;alert(1)&lt;/script&gt;"/>`, 403},
		{"oversized-body", "POST", "/", "application/json", oversizedJSON, 413},
		{"oversized-chunked-body", "POST", "/", "application/json", oversizedJSON, 413},
		{"oversized-bounded-chunked-body", "POST", "/", "application/json", oversizedJSON, 413},
		{"benign-after-cache-expiry", "GET", "/?q=hello", "", "", 200},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if fixture.name == "benign-after-cache-expiry" {
				time.Sleep(1100 * time.Millisecond)
			}
			status, body, err := request(fixture.method, fixture.target, fixture.contentType, fixture.body, strings.Contains(fixture.name, "chunked"), strings.Contains(fixture.name, "bounded"))
			if err != nil || status != fixture.want {
				t.Fatalf("status=%d want=%d error=%v body=%q", status, fixture.want, err, body)
			}
			if fixture.name == "activation-health" || fixture.name == "acme-challenge" {
				if body != "panel-health-v1 "+os.Getenv("CYBERPANEL_QEMU_HEALTH_DIGEST")+"\n" {
					t.Fatal("native context served incorrect proof bytes")
				}
			}
		})
	}
}
