package emailmarketing

import (
	"regexp"
	"strings"
	"testing"
)

func TestAnchorPatternLengthBounds(t *testing.T) {
	for _, tc := range []struct { pattern *regexp.Regexp; suffix string }{
		{anchorPattern, `">`},
		{canonicalAnchorPattern, `" rel="noopener noreferrer">`},
	} {
		for _, length := range []int{0, 1, 1000, 2000, 2048, 2049} {
			matches := tc.pattern.FindStringSubmatch(`<a href="` + strings.Repeat("x", length) + tc.suffix)
			want := length > 0 && length <= 2048
			if (matches != nil) != want { t.Fatalf("length %d: match=%v, want %v", length, matches != nil, want) }
			if want && (len(matches) != 2 || len(matches[1]) != length) { t.Fatalf("lost URL capture at length %d", length) }
		}
	}
}
