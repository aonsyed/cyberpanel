//go:build linux

package noderelease

import (
	"reflect"
	"testing"
)

func TestActivationServiceOrderIncludesShippedFrontends(t *testing.T) {
	manifest := Manifest{Services: []ServiceProbe{{Unit: "panel-providerd.service", TimeoutSeconds: 20}, {Unit: "panel-secretd.service", TimeoutSeconds: 25}, {Unit: "panel-peer-inspectd.service", TimeoutSeconds: 30}, {Unit: "panel-authd.service", TimeoutSeconds: 30}}}
	for _, unit := range []string{"panel-core.service", "panel-execd.service", "panel-gateway.service", "panel-secretd.service"} {
		manifest.Artifacts = append(manifest.Artifacts, Artifact{Kind: ArtifactUnit, Destination: "/etc/systemd/system/" + unit})
	}
	var got []string
	for _, service := range activationServiceOrder(manifest) {
		got = append(got, service.Unit)
		if service.Unit == "panel-secretd.service" && service.TimeoutSeconds != 25 {
			t.Fatal("explicit timeout replaced")
		}
	}
	want := []string{"panel-authd.service", "panel-peer-inspectd.service", "panel-secretd.service", "panel-execd.service", "panel-providerd.service", "panel-core.service", "panel-gateway.service"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("activation order: %v", got)
	}
	if len(manifest.Services) != 4 {
		t.Fatal("changed signed manifest")
	}
	if len(activationServiceOrder(Manifest{})) != 0 {
		t.Fatal("invented unsigned units")
	}
}
