//go:build linux

package containers

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagedRecipeExecutableLayouts(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := "/opt/cyberpanel/node-releases/" + digest + "/root/usr/lib/cyberpanel/bin/cyberpanel"
	for _, executable := range []string{valid, "/opt/cyberpanel/slots/release-1/components/panel/cyberpanel"} {
		parent, err := packagedRecipeParent(executable)
		if err != nil || parent != filepath.Dir(executable) {
			t.Fatalf("installed executable %q rejected: %v", executable, err)
		}
	}
	for _, executable := range []string{
		strings.Replace(valid, digest, strings.Repeat("A", 64), 1),
		strings.Replace(valid, digest, strings.Repeat("z", 64), 1),
		strings.Replace(valid, digest, "short", 1),
		strings.Replace(valid, "/root/usr/lib/", "/usr/lib/", 1),
		strings.Replace(valid, "/root/usr/lib/", "/root/usr/local/libexec/", 1),
		strings.Replace(valid, "/node-releases/", "/node-releases-extra/", 1),
		strings.Replace(valid, "/bin/cyberpanel", "/bin/../bin/cyberpanel", 1),
		valid + "/child", valid + "-fake", "/tmp/cyberpanel", "relative/cyberpanel",
	} {
		if _, err := packagedRecipeParent(executable); !errors.Is(err, ErrForbidden) {
			t.Fatalf("untrusted executable %q accepted: %v", executable, err)
		}
	}
}
