package authn

import "testing"

func TestConfiguredHTTPSPanelOriginPorts(t *testing.T) {
	for _, origin := range []string{"https://localhost", "https://localhost:443", "https://localhost:8090"} {
		if _, err := (Config{WebAuthnOrigins: map[string][]string{"localhost": {origin}}}).normalized(); err != nil {
			t.Errorf("configured panel origin %s rejected: %v", origin, err)
		}
	}
	for _, origin := range []string{"http://localhost:8090", "https://other.test:8090", "https://localhost:0", "https://localhost:65536", "https://localhost:", "https://user@localhost:8090", "https://localhost:8090/path", "https://localhost:8090?query=1"} {
		if validOriginForRP(origin, "localhost") {
			t.Errorf("unsafe configured origin accepted: %s", origin)
		}
	}
}
