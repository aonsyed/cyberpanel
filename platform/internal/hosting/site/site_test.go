package site

import (
	"errors"
	"reflect"
	"testing"
)

func TestCreateNormalizesPrimaryHostnameAndStartsProvisioningGenerationOne(t *testing.T) {
	got := mustCreate(t, "Site-01", "Tenant-01", "Project-01", "WWW.Example.COM.")

	if got.ID() != mustSiteID(t, "Site-01") || got.TenantID() != mustTenantID(t, "Tenant-01") || got.ProjectID() != mustProjectID(t, "Project-01") {
		t.Fatalf("Create() ownership = (%v, %v, %v), want immutable supplied identifiers", got.ID(), got.TenantID(), got.ProjectID())
	}
	if got.Lifecycle() != LifecycleProvisioning || got.Generation() != 1 {
		t.Fatalf("Create() lifecycle/generation = (%v, %d), want (Provisioning, 1)", got.Lifecycle(), got.Generation())
	}
	if got.DesiredLifecycle() != LifecycleActive {
		t.Fatalf("Create() desired lifecycle = %v, want Active", got.DesiredLifecycle())
	}
	bindings := got.Bindings()
	if len(bindings) != 1 || bindings[0].Kind != BindingPrimary || bindings[0].Hostname.String() != "www.example.com" {
		t.Fatalf("Create() bindings = %#v, want normalized sole primary", bindings)
	}
}

func TestOpaqueIdentifiersAndHostnameRejectUnsafeOrNonCanonicalInput(t *testing.T) {
	for _, raw := range []string{"", " ", "tenant/project", "tenant\nnext", "ténant"} {
		if _, err := NewTenantID(raw); err == nil {
			t.Fatalf("NewTenantID(%q) error = nil, want validation rejection", raw)
		}
	}
	for _, raw := range []string{"", "example", "https://example.com", "example.com/route", "例子.公司"} {
		if _, err := ParseHostname(raw); err == nil {
			t.Fatalf("ParseHostname(%q) error = nil, want ASCII FQDN rejection", raw)
		}
	}
}

func TestLifecycleAcceptsOnlySpecifiedEdgesAndLeavesReceiverUnmodified(t *testing.T) {
	site := mustCreate(t, "site-1", "tenant-1", "project-1", "example.com")
	before := site
	active := mustTransition(t, site, LifecycleActive)
	if !reflect.DeepEqual(site, before) {
		t.Fatalf("Transition() mutated receiver: got %#v, want %#v", site, before)
	}
	for _, next := range []Lifecycle{LifecycleSuspended, LifecycleActive, LifecycleDeleting, LifecycleQuarantined, LifecycleActive, LifecycleDeleting, LifecycleQuarantined, LifecyclePurging, LifecycleDeleted} {
		active = mustTransition(t, active, next)
	}
	if active.Lifecycle() != LifecycleDeleted || active.Generation() != 11 {
		t.Fatalf("closed lifecycle result = (%v, %d), want (Deleted, 11)", active.Lifecycle(), active.Generation())
	}

	if _, err := site.Transition(site.Generation(), LifecycleDeleted); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Provisioning -> Deleted error = %v, want ErrInvalidTransition", err)
	}
}

func TestProvisioningMayBecomeDegradedAndDegradedMayReconcileToActive(t *testing.T) {
	site := mustCreate(t, "site-1", "tenant-1", "project-1", "example.com")
	degraded := mustTransition(t, site, LifecycleDegraded)
	active := mustTransition(t, degraded, LifecycleActive)
	if active.Lifecycle() != LifecycleActive || active.Generation() != 3 {
		t.Fatalf("reconciled site = (%v, %d), want (Active, 3)", active.Lifecycle(), active.Generation())
	}
}

func TestSuspensionPreservesPriorDesiredStateAndResumeRestoresIt(t *testing.T) {
	site := mustTransition(t, mustCreate(t, "site-1", "tenant-1", "project-1", "example.com"), LifecycleActive)
	suspended := mustTransition(t, site, LifecycleSuspended)
	if suspended.DesiredLifecycle() != LifecycleActive {
		t.Fatalf("suspended desired lifecycle = %v, want prior Active", suspended.DesiredLifecycle())
	}
	resumed := mustTransition(t, suspended, LifecycleActive)
	if resumed.Lifecycle() != LifecycleActive || resumed.DesiredLifecycle() != LifecycleActive {
		t.Fatalf("resume = (%v, desired %v), want active prior generation restored", resumed.Lifecycle(), resumed.DesiredLifecycle())
	}
}

func TestTransitionRejectsStaleGeneration(t *testing.T) {
	site := mustCreate(t, "site-1", "tenant-1", "project-1", "example.com")
	if _, err := site.Transition(site.Generation()+1, LifecycleActive); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("Transition() stale generation error = %v, want ErrStaleGeneration", err)
	}
}

func TestZeroValueSiteRejectsEveryMutationAsInvalidAggregate(t *testing.T) {
	zero := Site{}
	tests := []struct {
		name   string
		mutate func() error
	}{
		{"transition", func() error { _, err := zero.Transition(0, LifecycleActive); return err }},
		{"attach", func() error {
			_, err := zero.AttachBinding(0, DomainBinding{Hostname: mustHostname(t, "alias.example.com"), Kind: BindingAlias})
			return err
		}},
		{"detach", func() error { _, err := zero.DetachBinding(0, mustHostname(t, "alias.example.com")); return err }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.mutate(); !errors.Is(err, ErrInvalidAggregate) {
				t.Fatalf("zero Site mutation error = %v, want ErrInvalidAggregate", err)
			}
		})
	}
}

func TestBindingsAreNormalizedUniqueAcrossKindsAndCannotRemoveSolePrimary(t *testing.T) {
	site := mustCreate(t, "site-1", "tenant-1", "project-1", "Example.COM")
	aliasHost := mustHostname(t, "blog.example.com")
	aliased, err := site.AttachBinding(site.Generation(), DomainBinding{Hostname: aliasHost, Kind: BindingAlias})
	if err != nil {
		t.Fatalf("AttachBinding(alias) error = %v", err)
	}
	if aliased.Generation() != site.Generation()+1 || !reflect.DeepEqual(site.Bindings(), mustCreate(t, "site-1", "tenant-1", "project-1", "example.com").Bindings()) {
		t.Fatal("AttachBinding() must return a new generation without mutating receiver")
	}
	if _, err := aliased.AttachBinding(aliased.Generation(), DomainBinding{
		Hostname:       mustHostname(t, "BLOG.EXAMPLE.COM."),
		Kind:           BindingRedirect,
		RedirectTarget: mustHostname(t, "example.com"),
		RedirectStatus: RedirectStatusPermanent301,
	}); !errors.Is(err, ErrDuplicateBinding) {
		t.Fatalf("duplicate hostname across binding kinds error = %v, want ErrDuplicateBinding", err)
	}
	if _, err := aliased.DetachBinding(aliased.Generation(), mustHostname(t, "example.com")); !errors.Is(err, ErrSolePrimary) {
		t.Fatalf("DetachBinding(sole primary) error = %v, want ErrSolePrimary", err)
	}
}

func TestChildBindingAttachesAndDetachesWithoutRedirectSemantics(t *testing.T) {
	site := mustCreate(t, "site-1", "tenant-1", "project-1", "example.com")
	childHostname := mustHostname(t, "shop.example.com")
	withChild, err := site.AttachBinding(site.Generation(), DomainBinding{Hostname: childHostname, Kind: BindingChild})
	if err != nil {
		t.Fatalf("AttachBinding(child) error = %v", err)
	}
	bindings := withChild.Bindings()
	if len(bindings) != 2 || bindings[1].Kind != BindingChild || bindings[1].Hostname != childHostname {
		t.Fatalf("child bindings = %#v, want attached child relationship", bindings)
	}
	if bindings[1].RedirectTarget != (Hostname{}) || bindings[1].RedirectStatus != RedirectStatus("") {
		t.Fatalf("child redirect fields = (%v, %v), want empty", bindings[1].RedirectTarget, bindings[1].RedirectStatus)
	}

	withoutChild, err := withChild.DetachBinding(withChild.Generation(), childHostname)
	if err != nil {
		t.Fatalf("DetachBinding(child) error = %v", err)
	}
	if len(withoutChild.Bindings()) != 1 || withoutChild.Generation() != withChild.Generation()+1 {
		t.Fatalf("detached child aggregate = %#v, want sole primary in next generation", withoutChild)
	}
}

func TestRedirectBindingsRequireTypedTargetAndStatus(t *testing.T) {
	site := mustCreate(t, "site-1", "tenant-1", "project-1", "example.com")
	for _, test := range []struct {
		hostname string
		status   RedirectStatus
	}{
		{"permanent.example.com", RedirectStatusPermanent301},
		{"temporary.example.com", RedirectStatusTemporary302},
	} {
		binding := DomainBinding{
			Hostname:       mustHostname(t, test.hostname),
			Kind:           BindingRedirect,
			RedirectTarget: mustHostname(t, "target.example.com"),
			RedirectStatus: test.status,
		}
		attached, err := site.AttachBinding(site.Generation(), binding)
		if err != nil {
			t.Fatalf("AttachBinding(redirect %v) error = %v", test.status, err)
		}
		got := attached.Bindings()[1]
		if got.RedirectTarget != binding.RedirectTarget || got.RedirectStatus != test.status {
			t.Fatalf("attached redirect = %#v, want target/status preserved", got)
		}
	}

	invalid := []DomainBinding{
		{Hostname: mustHostname(t, "missing-target.example.com"), Kind: BindingRedirect, RedirectStatus: RedirectStatusPermanent301},
		{Hostname: mustHostname(t, "missing-status.example.com"), Kind: BindingRedirect, RedirectTarget: mustHostname(t, "target.example.com")},
		{Hostname: mustHostname(t, "unknown-status.example.com"), Kind: BindingRedirect, RedirectTarget: mustHostname(t, "target.example.com"), RedirectStatus: RedirectStatus("see_other_303")},
		{Hostname: mustHostname(t, "alias.example.com"), Kind: BindingAlias, RedirectTarget: mustHostname(t, "target.example.com"), RedirectStatus: RedirectStatusTemporary302},
		{Hostname: mustHostname(t, "child.example.com"), Kind: BindingChild, RedirectTarget: mustHostname(t, "target.example.com"), RedirectStatus: RedirectStatusPermanent301},
	}
	for _, binding := range invalid {
		if _, err := site.AttachBinding(site.Generation(), binding); err == nil {
			t.Fatalf("AttachBinding(%#v) error = nil, want redirect semantics rejection", binding)
		}
	}

	if _, err := site.AttachBinding(site.Generation()+1, invalid[0]); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("AttachBinding(stale, invalid redirect) error = %v, want ErrStaleGeneration first", err)
	}
}

func TestRedirectBindingsRejectSelfRedirectsAndCyclesBeforeAdmission(t *testing.T) {
	site := mustCreate(t, "site-1", "tenant-1", "project-1", "example.com")
	self := DomainBinding{
		Hostname:       mustHostname(t, "self.example.com"),
		Kind:           BindingRedirect,
		RedirectTarget: mustHostname(t, "self.example.com"),
		RedirectStatus: RedirectStatusPermanent301,
	}
	if _, err := site.AttachBinding(site.Generation(), self); !errors.Is(err, ErrRedirectCycle) {
		t.Fatalf("AttachBinding(self redirect) error = %v, want ErrRedirectCycle", err)
	}

	first := DomainBinding{
		Hostname:       mustHostname(t, "a.example.com"),
		Kind:           BindingRedirect,
		RedirectTarget: mustHostname(t, "b.example.com"),
		RedirectStatus: RedirectStatusPermanent301,
	}
	withFirst, err := site.AttachBinding(site.Generation(), first)
	if err != nil {
		t.Fatalf("AttachBinding(first redirect) error = %v", err)
	}
	cycle := DomainBinding{
		Hostname:       mustHostname(t, "b.example.com"),
		Kind:           BindingRedirect,
		RedirectTarget: mustHostname(t, "a.example.com"),
		RedirectStatus: RedirectStatusTemporary302,
	}
	if _, err := withFirst.AttachBinding(withFirst.Generation(), cycle); !errors.Is(err, ErrRedirectCycle) {
		t.Fatalf("AttachBinding(cycle) error = %v, want ErrRedirectCycle", err)
	}
	if got := withFirst.Bindings(); len(got) != 2 || got[1] != first {
		t.Fatalf("rejected cycle mutated aggregate bindings: %#v", got)
	}
}

func TestDeletingAndQuarantineNeverPurgeWithoutExplicitLifecycleEdges(t *testing.T) {
	site := mustTransition(t, mustCreate(t, "site-1", "tenant-1", "project-1", "example.com"), LifecycleActive)
	deleting := mustTransition(t, site, LifecycleDeleting)
	quarantined := mustTransition(t, deleting, LifecycleQuarantined)
	if quarantined.Lifecycle() != LifecycleQuarantined {
		t.Fatalf("deletion path lifecycle = %v, want Quarantined", quarantined.Lifecycle())
	}
	if _, err := deleting.Transition(deleting.Generation(), LifecyclePurging); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Deleting -> Purging error = %v, want ErrInvalidTransition", err)
	}
}

func mustCreate(t *testing.T, site, tenant, project, hostname string) Site {
	t.Helper()
	got, err := Create(CreateInput{ID: mustSiteID(t, site), TenantID: mustTenantID(t, tenant), ProjectID: mustProjectID(t, project), PrimaryHostname: mustHostname(t, hostname)})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	return got
}

func mustTransition(t *testing.T, site Site, next Lifecycle) Site {
	t.Helper()
	got, err := site.Transition(site.Generation(), next)
	if err != nil {
		t.Fatalf("Transition(%v -> %v) error = %v", site.Lifecycle(), next, err)
	}
	return got
}

func mustSiteID(t *testing.T, raw string) SiteID {
	t.Helper()
	got, err := NewSiteID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
func mustTenantID(t *testing.T, raw string) TenantID {
	t.Helper()
	got, err := NewTenantID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
func mustProjectID(t *testing.T, raw string) ProjectID {
	t.Helper()
	got, err := NewProjectID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
func mustHostname(t *testing.T, raw string) Hostname {
	t.Helper()
	got, err := ParseHostname(raw)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
