package webactivation

import (
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

func TestProbePrefersPermanentSystemBindingForRollback(t *testing.T) {
	system, _ := webengine.ParseHostname("default.invalid")
	tenant, _ := webengine.ParseHostname("new-site.example.invalid")
	render := native.RenderRequest{}
	render.Desired.Engine.Listeners = []webengine.Listener{{Ref: "listener/http", Addresses: []string{"127.0.0.1"}, Port: 80, TLSMode: webengine.TLSModeClear}}
	render.Desired.Bindings = []webengine.WebBindingSpec{
		{Ref: "binding/new-site", Hostnames: []webengine.Hostname{tenant}, ListenerRefs: []webengine.ResourceRef{"listener/http"}},
		{Ref: "binding/system-default", Hostnames: []webengine.Hostname{system}, ListenerRefs: []webengine.ResourceRef{"listener/http"}},
	}
	config, err := deriveProbeConfiguration(render)
	if err != nil || config.Hostname != system {
		t.Fatalf("probe=%+v err=%v; rollback must not depend on new tenant route", config, err)
	}
	// Standalone renderer consumers without the system binding retain their
	// existing route selection; production composition always provides it.
	render.Desired.Bindings = render.Desired.Bindings[:1]
	config, err = deriveProbeConfiguration(render)
	if err != nil || config.Hostname != tenant {
		t.Fatal(config, err)
	}
}
