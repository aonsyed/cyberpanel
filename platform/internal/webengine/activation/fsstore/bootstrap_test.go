package fsstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

func TestBootstrapPreservesVendorMasterAcrossReopen(t *testing.T) {
	for _, edition := range []webengine.Edition{webengine.EditionOpenLiteSpeed, webengine.EditionLiteSpeedEnterprise} {
		t.Run(string(edition), func(t *testing.T) {
			root := privateRoot(t)
			master := "httpd_config.conf"
			if edition == webengine.EditionLiteSpeedEnterprise {
				master = "httpd_config.xml"
			}
			if err := os.WriteFile(filepath.Join(root, master), []byte("vendor"), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := New(root, edition)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			candidate, err := s.Stage(ctx, testGeneration(t, edition, 1, "candidate", "vhost"))
			if err != nil {
				t.Fatal(err)
			}
			if err = s.PrepareBootstrap(ctx, candidate); err != nil {
				t.Fatal(err)
			}
			if err = s.SwapMaster(ctx, candidate); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = New(root, edition)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err = s.PrepareBootstrap(ctx, candidate); err != nil {
				t.Fatal("resume", err)
			}
			if err = s.RestoreBootstrap(ctx, candidate); err != nil {
				t.Fatal(err)
			}
			assertPrivateFile(t, filepath.Join(root, master), "vendor")
			if err = s.SwapMaster(ctx, candidate); err != nil {
				t.Fatal(err)
			}
			if err = s.Confirm(ctx, candidate); err != nil {
				t.Fatal(err)
			}
			if err = s.PrepareBootstrap(ctx, candidate); err == nil {
				t.Fatal("reinitialized adopted node")
			}
		})
	}
}

func TestBootstrapRejectsTamperedBackupOrUnrelatedLiveMaster(t *testing.T) {
	for _, target := range []string{".panel-state/bootstrap-master", "httpd_config.conf"} {
		t.Run(target, func(t *testing.T) {
			root := privateRoot(t)
			if err := os.WriteFile(filepath.Join(root, "httpd_config.conf"), []byte("vendor"), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := New(root, webengine.EditionOpenLiteSpeed)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx := context.Background()
			candidate, err := s.Stage(ctx, testGeneration(t, webengine.EditionOpenLiteSpeed, 1, "candidate", "vhost"))
			if err != nil {
				t.Fatal(err)
			}
			if err = s.PrepareBootstrap(ctx, candidate); err != nil {
				t.Fatal(err)
			}
			if err = s.SwapMaster(ctx, candidate); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(root, target), []byte("unrelated"), 0600); err != nil {
				t.Fatal(err)
			}
			if err = s.RestoreBootstrap(ctx, candidate); err == nil {
				t.Fatal("tamper accepted")
			}
		})
	}
}

func TestBootstrapUpdatedCandidateRequiresRestoredOriginal(t *testing.T) {
	for _, edition := range []webengine.Edition{webengine.EditionOpenLiteSpeed, webengine.EditionLiteSpeedEnterprise} {
		t.Run(string(edition), func(t *testing.T) {
			root := privateRoot(t)
			master := "httpd_config.conf"
			if edition == webengine.EditionLiteSpeedEnterprise {
				master = "httpd_config.xml"
			}
			if err := os.WriteFile(filepath.Join(root, master), []byte("vendor"), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := New(root, edition)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx := context.Background()
			first, err := s.Stage(ctx, testGeneration(t, edition, 1, "first", "vhost"))
			if err != nil {
				t.Fatal(err)
			}
			second, err := s.Stage(ctx, testGeneration(t, edition, 1, "updated", "vhost"))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.PrepareBootstrap(ctx, first); err != nil {
				t.Fatal(err)
			}
			if err := s.SwapMaster(ctx, first); err != nil {
				t.Fatal(err)
			}
			if err := s.PrepareBootstrap(ctx, second); err == nil {
				t.Fatal("replaced unrestored bootstrap")
			}
			if err := s.RestoreBootstrap(ctx, first); err != nil {
				t.Fatal(err)
			}
			if err := s.PrepareBootstrap(ctx, second); err != nil {
				t.Fatal(err)
			}
			if err := s.SwapMaster(ctx, second); err != nil {
				t.Fatal(err)
			}
			if err := s.RestoreBootstrap(ctx, second); err != nil {
				t.Fatal(err)
			}
			assertPrivateFile(t, filepath.Join(root, master), "vendor")
			if err := s.RestoreBootstrap(ctx, first); err == nil {
				t.Fatal("stale candidate regained checkpoint")
			}
		})
	}
}
