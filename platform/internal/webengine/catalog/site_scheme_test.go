package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	_ "modernc.org/sqlite"
)

func TestSiteSchemeRequiresCurrentOwnedAppliedBinding(t *testing.T) {
	tenant, _ := site.NewTenantID("scheme-tenant")
	siteID, _ := site.NewSiteID("scheme-site")
	hostname, _ := site.ParseHostname("scheme.example.invalid")
	scope := service.CommandScope{TenantID: tenant, SiteID: siteID}
	for _, scenario := range []string{"no_tls", "tls", "unowned_tls", "stale", "unapplied", "unowned_host", "missing_listener"} {
		t.Run(scenario, func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			catalog := &SQLCatalog{db: db, clock: time.Now}
			if err := catalog.Bootstrap(context.Background()); err != nil {
				t.Fatal(err)
			}
			configuration := NodeConfiguration{Revision: 1, Engine: composer.NodeEngine{Listeners: []composer.ListenerInput{
				{Port: 80, TLSMode: webengine.TLSModeClear},
				{Port: 443, TLSMode: webengine.TLSModeTLS},
			}}}
			input := composer.SiteInput{Scope: scope, Projection: service.SiteProjection{Generation: 2, Lifecycle: site.LifecycleActive, Bindings: []site.DomainBinding{{Hostname: hostname, Kind: site.BindingPrimary}}}}
			if scenario == "tls" || scenario == "unowned_tls" {
				input.TLS = []composer.TLSInput{{OwnerScope: scope, Generation: 1, PolicyRef: "tls/scheme", MaterialKey: "scheme"}}
			}
			if scenario == "unowned_tls" {
				input.TLS[0].OwnerScope = service.CommandScope{}
			}
			if scenario == "missing_listener" {
				configuration.Engine.Listeners = nil
			}
			digest := strings.Repeat("a", 64)
			if scenario == "unapplied" {
				digest = ""
			}
			configJSON, _ := json.Marshal(configuration)
			inputJSON, _ := json.Marshal(input)
			if _, err := db.Exec(`INSERT INTO webengine_node_config(singleton_id,revision,snapshot_generation,config_json,applied_digest,updated_at) VALUES(1,1,1,?,?,?)`, configJSON, digest, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO webengine_site_inputs(tenant_id,site_id,projection_generation,projection_digest,effect_id,input_json) VALUES(?,?,2,?,'scheme-effect',?)`, tenant.String(), siteID.String(), strings.Repeat("b", 64), inputJSON); err != nil {
				t.Fatal(err)
			}
			expected, host := uint64(2), hostname.String()
			if scenario == "stale" {
				expected = 3
			}
			if scenario == "unowned_host" {
				host = "other.example.invalid"
			}
			scheme, err := catalog.SiteScheme(context.Background(), scope, host, expected)
			if scenario == "no_tls" || scenario == "tls" {
				want := "http"
				if scenario == "tls" {
					want = "https"
				}
				if err != nil || scheme != want {
					t.Fatalf("scheme=%q error=%v, want %s", scheme, err, want)
				}
			} else if err == nil || scheme != "" {
				t.Fatalf("invalid authority admitted: scheme=%q err=%v", scheme, err)
			}
		})
	}
}
