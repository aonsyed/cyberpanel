package mailtelemetry

import (
	"regexp"
	"strings"
	"testing"
)

func TestBoundedMailPatterns(t *testing.T) {
	for _, tc := range []struct {
		name string
		pattern *regexp.Regexp
		prefix, suffix string
		maximum int
	}{
		{"status", postfixStatus, "postfix/smtp[12]: ABCDEF: to=<a@example.com>, relay=mx, delay=1,", " dsn=2.0.0, status=sent", 1024},
		{"reject", postfixReject, "postfix/smtpd[12]: NOQUEUE: reject: ", "; from=<a@example.com> to=<b@example.com>", 1536},
		{"signature", deliveryResult, "delivery: provider=test receipt=test queue_id=ABCDEF recipient=<a@example.com> result=delivered signature=", " key_id=test", 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, length := range []int{1, 999, 1000, tc.maximum, tc.maximum+1} {
				message := tc.prefix + strings.Repeat("x", length) + tc.suffix
				if got, want := tc.pattern.MatchString(message), length <= tc.maximum; got != want {
					t.Fatalf("length %d: match=%v, want %v", length, got, want)
				}
			}
		})
	}
}
