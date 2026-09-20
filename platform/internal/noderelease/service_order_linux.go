//go:build linux

package noderelease

import (
	"context"
	"sort"
)

func activationServiceOrder(manifest Manifest) []ServiceProbe {
	services := append([]ServiceProbe(nil), manifest.Services...)
	seen := map[string]bool{}
	for _, service := range services {
		seen[service.Unit] = true
	}
	// Older manifests shipped these units but omitted their probes. A committed
	// release must not claim success while its signed core/gateway are down.
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind != ArtifactUnit {
			continue
		}
		for _, unit := range []string{"panel-secretd.service", "panel-execd.service", "panel-core.service", "panel-gateway.service"} {
			if artifact.Destination == "/etc/systemd/system/"+unit && !seen[unit] {
				services = append(services, ServiceProbe{Unit: unit, TimeoutSeconds: 30})
				seen[unit] = true
			}
		}
	}
	rank := func(unit string) int {
		switch unit {
		case "panel-authd.service":
			return 0
		case "panel-peer-inspectd.service":
			return 1
		case "panel-secretd.service":
			return 2
		case "panel-execd.service":
			return 3
		case "panel-providerd.service":
			return 4
		case "panel-core.service":
			return 1000
		case "panel-gateway.service":
			return 1001
		}
		return 100
	}
	sort.Slice(services, func(i, j int) bool {
		a, b := rank(services[i].Unit), rank(services[j].Unit)
		if a != b {
			return a < b
		}
		return services[i].Unit < services[j].Unit
	})
	return services
}

func quiescePanelFrontends(ctx context.Context, manifest Manifest) error {
	services := activationServiceOrder(manifest)
	for _, unit := range []string{"panel-gateway.service", "panel-core.service"} {
		for _, service := range services {
			if service.Unit == unit {
				if _, err := runSystemctl(ctx, "stop", unit); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
