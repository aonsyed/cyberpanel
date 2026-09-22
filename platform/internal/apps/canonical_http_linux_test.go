//go:build linux

package apps

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func canonicalManifestFixture() linuxApplicationReleaseManifest {
	digest := strings.Repeat("a", 64)
	return linuxApplicationReleaseManifest{
		Version: 1, InstallationID: "scheme-install", TenantID: "scheme-tenant", SiteID: "scheme-site", DefinitionID: "wordpress", Kind: ApplicationWordPress,
		ProductVersion: "7.1", RecipeDigest: digest, DefinitionDigest: digest, ReleaseID: "scheme-release", RuntimeID: "php83", CreatedAt: time.Now(),
		Artifact: ArtifactReference{URL: "https://example.invalid/wordpress.tar.gz", Digest: digest, Size: 1},
		Database: DatabaseBinding{ID: "scheme-db", InstanceID: "mariadb-local", Placement: "local", Engine: "mariadb", DatabaseName: "scheme_db", PrincipalName: "scheme_user", EndpointRef: "local-mariadb", PasswordRef: "scheme-password"},
		Probes:   []ProbeDefinition{{Name: "http_home", Kind: ProbeHTTP, RelativeEndpoint: "/", ExpectedStatus: []int{200}, Timeout: time.Second}},
	}
}

func TestApplicationHTTPProbeUsesFixedLoopbackAndDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{200, 302} {
		manifest := canonicalManifestFixture()
		manifest.CanonicalURL = "http://site.example.invalid/"
		observed := make(chan string, 1)
		dial := func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "127.0.0.1:80" {
				return nil, fmt.Errorf("unsafe dial %s %s", network, address)
			}
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				request, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					observed <- err.Error()
					return
				}
				observed <- request.Host + request.URL.Path
				fmt.Fprintf(server, "HTTP/1.1 %d Test\r\nContent-Length: 0\r\nLocation: https://outside.example.invalid/\r\n\r\n", status)
			}()
			return client, nil
		}
		digest, err := probeApplicationHTTPWithDial(context.Background(), manifest, manifest.Probes[0], dial)
		if status == 200 && (err != nil || digest == "") {
			t.Fatalf("HTTP probe failed: %v", err)
		}
		if status == 302 && !errors.Is(err, ErrIntegrity) {
			t.Fatalf("redirect accepted/followed: %v", err)
		}
		if got := <-observed; got != "site.example.invalid/" {
			t.Fatalf("wrong request host/path: %s", got)
		}
	}
	manifest := canonicalManifestFixture()
	manifest.CanonicalURL = "https://site.example.invalid/"
	dialFailure := errors.New("fixture dial stop")
	_, err := probeApplicationHTTPWithDial(context.Background(), manifest, manifest.Probes[0], func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:443" {
			t.Errorf("HTTPS dial target: %s %s", network, address)
		}
		return nil, dialFailure
	})
	if !errors.Is(err, dialFailure) {
		t.Fatalf("HTTPS failure hidden: %v", err)
	}
}

func TestApplicationManifestCanonicalSchemes(t *testing.T) {
	for _, value := range []string{"http://site.example.invalid/", "http://site.example.invalid:80/", "https://site.example.invalid/", "https://site.example.invalid:443/"} {
		manifest := canonicalManifestFixture()
		manifest.CanonicalURL = value
		if err := manifest.Validate(); err != nil {
			t.Errorf("valid canonical %s: %v", value, err)
		}
	}
	for _, value := range []string{"http://site.example.invalid:443/", "https://site.example.invalid:80/", "http://site.example.invalid:8080/", "ftp://site.example.invalid/", "http://user:password@site.example.invalid/", "http://site.example.invalid/?secret=x", "http://site.example.invalid/#fragment"} {
		manifest := canonicalManifestFixture()
		manifest.CanonicalURL = value
		if err := manifest.Validate(); err == nil {
			t.Errorf("unsafe canonical accepted: %s", value)
		}
	}
	manifest := canonicalManifestFixture()
	manifest.CanonicalURL = "http://site.example.invalid/"
	manifest.Artifact.URL = "http://example.invalid/wordpress.tar.gz"
	if err := manifest.Validate(); err == nil {
		t.Fatal("HTTP artifact download was accepted")
	}
}
