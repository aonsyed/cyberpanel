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
)

func runQEMUWAFHTTP(t *testing.T, master string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
		"--property=PrivateNetwork=yes", "--property=PrivateTmp=yes",
		"--property=TemporaryFileSystem=/run",
		"--property=ReadOnlyPaths=/usr/local/lsws/conf /etc /usr/share/modsecurity-crs",
		"--property=CapabilityBoundingSet=~CAP_SYS_ADMIN", "--property=KillMode=control-group",
		"--property=RuntimeMaxSec=30s", "--property=TimeoutStopSec=5s",
		"--property=BindReadOnlyPaths="+master+":/usr/local/lsws/conf/httpd_config.conf",
		"--setenv=CYBERPANEL_QEMU_WAF_HTTP_CHILD=1",
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
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	request := func(method, target, contentType, body string) (int, string, error) {
		req, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1"+target, strings.NewReader(body))
		if err != nil {
			return 0, "", err
		}
		req.Host = "default.invalid"
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
		status, body, err := request("GET", "/", "", "")
		if err == nil && status == 200 && strings.Contains(body, "maintenance") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("native benign request did not become healthy: status=%d error=%v body=%q", status, err, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, fixture := range []struct {
		name, method, target, contentType, body string
		want                                    int
	}{
		{"benign-repeat", "GET", "/", "", "", 200},
		{"benign-direct-file", "GET", "/index.html", "", "", 200},
		{"benign-query", "GET", "/?q=hello", "", "", 200},
		{"xss-query", "GET", "/?q=" + url.QueryEscape("<script>alert(1)</script>"), "", "", 403},
		{"sqli-query", "GET", "/?q=" + url.QueryEscape("1' OR '1'='1"), "", "", 403},
		{"benign-json", "POST", "/", "application/json", `{"message":"hello"}`, 200},
		{"xss-json", "POST", "/", "application/json", `{"message":"<script>alert(1)</script>"}`, 403},
		{"xss-json-subtype", "POST", "/", "application/problem+json", `{"message":"<script>alert(1)</script>"}`, 403},
		{"malformed-json", "POST", "/", "application/json", `{"message":`, 400},
		{"benign-xml", "POST", "/", "application/xml", `<message>hello</message>`, 200},
		{"xss-xml-attribute", "POST", "/", "application/xml", `<message value="&lt;script&gt;alert(1)&lt;/script&gt;"/>`, 403},
		{"oversized-body", "POST", "/", "application/json", `{"message":"` + strings.Repeat("a", 13107200) + `"}`, 413},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			status, body, err := request(fixture.method, fixture.target, fixture.contentType, fixture.body)
			if err != nil || status != fixture.want {
				t.Fatalf("status=%d want=%d error=%v body=%q", status, fixture.want, err, body)
			}
		})
	}
}
