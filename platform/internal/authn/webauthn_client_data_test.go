package authn

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestWebAuthnClientDataExtensions(t *testing.T) {
	challenge := bytes.Repeat([]byte{7}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(challenge)
	for _, kind := range []string{"webauthn.create", "webauthn.get"} {
		base := fmt.Sprintf(`"type":%q,"challenge":%q,"origin":"https://localhost:8090","crossOrigin":false`, kind, encoded)
		for _, tc := range []struct {
			name, raw string
			valid     bool
		}{
			{"standard", `{` + base + `}`, true},
			{"browser extension", `{` + base + `,"other_keys_can_be_added_here":"future fields are permitted"}`, true},
			{"structured extension", `{` + base + `,"future":{"nested":[true,1]}}`, true},
			{"duplicate origin", `{` + base + `,"origin":"https://other.test"}`, false},
			{"duplicate extension", `{` + base + `,"future":1,"future":2}`, false},
			{"top origin", `{` + base + `,"topOrigin":"https://other.test"}`, false},
			{"wrong origin", fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":"https://localhost:8443"}`, kind, encoded), false},
			{"cross origin", fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":"https://localhost:8090","crossOrigin":true}`, kind, encoded), false},
			{"wrong challenge", fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":"https://localhost:8090"}`, kind, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))), false},
			{"trailing JSON", `{` + base + `}{}`, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				err := verifyClientData([]byte(tc.raw), kind, challenge, "localhost", []string{"https://localhost:8090"})
				if (err == nil) != tc.valid {
					t.Fatalf("valid=%t, err=%v", tc.valid, err)
				}
			})
		}
	}
}
