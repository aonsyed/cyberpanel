package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestQEMUInstalledUIAssets(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_INSTALLED_UI") != "1" {
		t.Skip("requires signed QEMU UI release")
	}
	ui, err := loadInstalledUI("/usr/lib/cyberpanel/ui", 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(ui)
	defer server.Close()
	assets, err := filepath.Glob("/usr/lib/cyberpanel/ui/assets/*")
	if err != nil || len(assets) == 0 {
		t.Fatalf("installed assets missing: %v", err)
	}
	paths := []string{"index.html"}
	for _, asset := range assets {
		paths = append(paths, "assets/"+filepath.Base(asset))
	}
	for _, path := range paths {
		want, err := os.ReadFile("/usr/lib/cyberpanel/ui/" + path)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.Get(server.URL + "/" + path)
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || !bytes.Equal(got, want) {
			t.Fatalf("installed asset HTTP mismatch %s: status=%d error=%v", path, response.StatusCode, readErr)
		}
	}
}
