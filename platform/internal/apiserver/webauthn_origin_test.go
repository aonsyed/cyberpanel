package apiserver

import "testing"

func TestWebAuthnRPWithPanelPort(t *testing.T) {
	for _, tc := range []struct {
		name, host, origin, want string
		tls                      bool
	}{
		{"panel port", "panel.example.test", "https://panel.example.test:8090", "panel.example.test", true},
		{"default port", "panel.example.test", "https://panel.example.test", "panel.example.test", true},
		{"local test RP", "localhost", "https://localhost:8090", "localhost", true},
		{"plaintext", "panel.example.test", "http://panel.example.test:8090", "", true},
		{"no TLS", "panel.example.test", "https://panel.example.test:8090", "", false},
		{"different host", "panel.example.test", "https://other.example.test:8090", "", true},
		{"invalid port", "panel.example.test", "https://panel.example.test:99999", "", true},
		{"IP RP", "127.0.0.1", "https://127.0.0.1:8090", "", true},
		{"path", "panel.example.test", "https://panel.example.test:8090/path", "", true},
		{"userinfo", "panel.example.test", "https://user@panel.example.test:8090", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := webAuthnRP(RequestMeta{Host: tc.host, Origin: tc.origin, TLS: tc.tls})
			if tc.want == "" {
				if err == nil {
					t.Fatalf("accepted forbidden origin, RP=%q", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("RP=%q, err=%v; want %q", got, err, tc.want)
			}
		})
	}
}
