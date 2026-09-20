//go:build linux

package mail

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type mapProjectionFixture map[ResourceKind][]ResourceEnvelope

func (fixture mapProjectionFixture) ListAll(_ context.Context, kind ResourceKind, _ int, _ string) ([]ResourceEnvelope, string, error) {
	return fixture[kind], "", nil
}

func TestMailMapProjectionOmitsSuspendedResources(t *testing.T) {
	for _, kind := range []ResourceKind{ResourceDomain, ResourceMailbox, ResourceAlias} {
		for _, state := range []ResourceState{StateActive, StateSuspended, StateDeleted} {
			fixture := mapProjectionFixture{}
			for resourceKind, spec := range map[ResourceKind]any{
				ResourceDomain:  Domain{ID: "domain", Name: "qemu-map.example.invalid", Tenant: "tenant", Policy: "policy"},
				ResourcePolicy:  Policy{ID: "policy"},
				ResourceMailbox: Mailbox{ID: "mailbox", Domain: "domain", Local: "owner", Enabled: true},
				ResourceAlias:   Alias{ID: "alias", Domain: "domain", Source: "sales@qemu-map.example.invalid", Targets: []Address{"owner@qemu-map.example.invalid"}},
			} {
				raw, err := json.Marshal(spec)
				if err != nil {
					t.Fatal(err)
				}
				resourceState := StateActive
				if resourceKind == kind {
					resourceState = state
				}
				fixture[resourceKind] = []ResourceEnvelope{{TenantID: "tenant", State: resourceState, Spec: raw}}
			}
			snapshot, err := (RepositorySnapshotProjector{Store: fixture, NodeID: "node", Hostname: "mail.example.invalid", Postmaster: "postmaster@example.invalid", MessageSizeBytes: 1 << 20}).ProjectMail(context.Background(), EffectRequest{TenantID: "tenant", Generation: 1})
			if err != nil {
				t.Fatal(err)
			}
			if kind == ResourceDomain && state != StateActive {
				if len(snapshot.Domains) != 0 {
					t.Fatal("inactive domain published")
				}
				continue
			}
			if len(snapshot.Domains) != 1 {
				t.Fatal("active domain missing")
			}
			projection := snapshot.Domains[0]
			if kind == ResourceMailbox && (len(projection.Mailboxes) == 1) != (state == StateActive) {
				t.Fatal("mailbox suspension ignored")
			}
			if kind == ResourceAlias && (len(projection.Aliases) == 1) != (state == StateActive) {
				t.Fatal("alias suspension ignored")
			}
		}
	}
}

func TestMailMapRejectsRecordWhitespace(t *testing.T) {
	snapshot := ConfigSnapshot{NodeID: "node", Generation: 1, Hostname: "mail.example.invalid", Postmaster: "postmaster@example.invalid", MessageSizeBytes: 1 << 20, Domains: []DomainProjection{{Domain: Domain{ID: "domain", Name: "example.invalid", Tenant: "tenant", Policy: "policy"}, Policy: Policy{ID: "policy"}, TLS: TLSMaterial{Key: "tls", Hostnames: []string{"example.invalid"}}}}}
	if err := validateSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{" owner", "owner ", "owner\nattacker"} {
		snapshot.Domains[0].Mailboxes = []Mailbox{{ID: "mailbox", Domain: "domain", Local: value, QuotaBytes: 1024}}
		if err := validateSnapshot(snapshot); err == nil {
			t.Fatal("unsafe mailbox local accepted")
		}
	}
	snapshot.Domains[0].Mailboxes = nil
	for _, value := range []Address{" owner@example.invalid", "owner@example.invalid\n"} {
		snapshot.Domains[0].Aliases = []Alias{{ID: "alias", Domain: "domain", Source: value, Targets: []Address{"target@example.invalid"}}}
		if err := validateSnapshot(snapshot); err == nil {
			t.Fatal("unsafe alias source accepted")
		}
		snapshot.Domains[0].Aliases = []Alias{{ID: "alias", Domain: "domain", Source: "source@example.invalid", Targets: []Address{value}}}
		if err := validateSnapshot(snapshot); err == nil {
			t.Fatal("unsafe alias target accepted")
		}
	}
}

func TestQEMUPostfixOrdinaryMaps(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_MAPS") != "1" {
		t.Skip("requires native Postfix inside QEMU")
	}
	for _, migrated := range []bool{false, true} {
		snapshot := ConfigSnapshot{Domains: []DomainProjection{{Domain: Domain{ID: "domain", Name: "qemu-map.example.invalid", StaticRoutes: migrated}, Mailboxes: []Mailbox{{Local: "owner", Enabled: true}, {Local: "disabled", Enabled: false}}, Aliases: []Alias{{Source: "sales@qemu-map.example.invalid", Targets: []Address{"owner@qemu-map.example.invalid"}}}}}}
		directory := t.TempDir()
		maps := map[string][]byte{"domains": renderPostfixStaticDomains(snapshot), "mailboxes": renderPostfixStaticMailboxes(snapshot), "aliases": renderPostfixStaticAliases(snapshot)}
		for name, content := range maps {
			if err := os.WriteFile(filepath.Join(directory, name), content, 0600); err != nil {
				t.Fatal(err)
			}
		}
		for _, check := range []struct{ table, key, want string }{
			{"domains", "qemu-map.example.invalid", "OK"},
			{"domains", "other.example.invalid", ""},
			{"mailboxes", "owner@qemu-map.example.invalid", "qemu-map.example.invalid/owner/Maildir/"},
			{"mailboxes", "disabled@qemu-map.example.invalid", ""},
			{"aliases", "sales@qemu-map.example.invalid", "owner@qemu-map.example.invalid"},
			{"aliases", "missing@qemu-map.example.invalid", ""},
		} {
			output, err := exec.Command("/usr/sbin/postmap", "-q", check.key, "texthash:"+filepath.Join(directory, check.table)).Output()
			if strings.TrimSpace(string(output)) != check.want || check.want != "" && err != nil {
				t.Fatalf("migrated=%v %s/%s: got %q, %v", migrated, check.table, check.key, output, err)
			}
			if check.want == "" {
				if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
					t.Fatalf("absent lookup did not return NOTFOUND: %v", err)
				}
			}
		}
	}
	if strings.Contains(string(renderPostfixMain(ConfigSnapshot{})), "socketmap:") {
		t.Fatal("configuration still references unimplemented socketmap")
	}
}
