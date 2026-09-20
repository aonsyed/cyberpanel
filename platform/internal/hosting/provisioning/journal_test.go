package provisioning

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

func TestFileJournalRetainsRuntimeProfileForResume(t *testing.T) {
	for _, profile := range []site.PHPProfile{site.PHPProfile82, site.PHPProfile83, site.PHPProfile84} {
		t.Run(string(profile), func(t *testing.T) {
			tenant, _ := site.NewTenantID("test_tenant")
			id, _ := site.NewSiteID("test_site")
			projection := service.SiteProjection{Generation: 1, Lifecycle: site.LifecycleProvisioning, PHPProfile: profile}
			request := service.SiteEffectRequest{EffectID: "effect-" + strings.Repeat("a", 64), Scope: service.CommandScope{TenantID: tenant, SiteID: id}, Projection: projection, ProjectionDigest: digestProjection(projection)}
			spec, err := specFromRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			original := newReceipt(spec)
			root := t.TempDir()
			journal, err := NewFileJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			if err = journal.Save(context.Background(), original); err != nil {
				t.Fatal(err)
			}
			reopened, err := NewFileJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			loaded, found, err := reopened.Load(context.Background(), original.EffectKey)
			if err != nil || !found {
				t.Fatalf("found=%t err=%v", found, err)
			}
			if !reflect.DeepEqual(loaded, original) {
				t.Fatalf("receipt lost fields: PHP profile %q, want %q", loaded.PHPProfile, profile)
			}
			if err = validateProvisioningReceipt(loaded, spec); err != nil {
				t.Fatalf("resume rejected persisted receipt: %v", err)
			}
		})
	}
}
