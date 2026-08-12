package images

import (
	"os"
	"strings"
	"testing"
)

func TestRepositoryImageLockPinsAllSupportedImages(t *testing.T) {
	data, err := os.ReadFile("../../images.lock.json")
	if err != nil {
		t.Fatalf("read repository image lock: %v", err)
	}

	lock, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() repository image lock: %v", err)
	}
	if got, want := len(lock.Images), 4; got != want {
		t.Fatalf("len(Images) = %d, want %d", got, want)
	}

	wantDigests := map[string]string{
		"ubuntu-24.04-20260801-arm64":  "aa6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476",
		"ubuntu-24.04-20260801-amd64":  "0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe",
		"almalinux-9.8-20260810-arm64": "d5c2c1b1c03c02fe0d2abd774fa7d3bf6c4a86261c746e871a0475d12e74f8ae",
		"almalinux-9.8-20260810-amd64": "6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b",
	}
	for _, image := range lock.Images {
		want, ok := wantDigests[image.StableID]
		if !ok {
			t.Errorf("unexpected image %q", image.StableID)
			continue
		}
		if image.SHA256 != want {
			t.Errorf("image %q SHA256 = %q, want %q", image.StableID, image.SHA256, want)
		}
		delete(wantDigests, image.StableID)
	}
	for stableID := range wantDigests {
		t.Errorf("missing image %q", stableID)
	}
}

const ubuntuImageLockJSON = `{
  "schemaVersion": 1,
  "images": [
    {
      "stableId": "ubuntu-24.04-20260801-arm64",
      "distribution": "ubuntu",
      "resolvedRelease": "24.04-20260801",
      "architecture": "arm64",
      "acquisitionUrl": "https://cloud-images.ubuntu.com/releases/noble/release-20260801/ubuntu-24.04-server-cloudimg-arm64.img",
      "runtimePath": ".work/qemu/images/sha256/aa6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476/base.qcow2",
      "sha256": "aa6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476",
      "format": "qcow2"
    },
    {
      "stableId": "ubuntu-24.04-20260801-amd64",
      "distribution": "ubuntu",
      "resolvedRelease": "24.04-20260801",
      "architecture": "amd64",
      "acquisitionUrl": "https://cloud-images.ubuntu.com/releases/noble/release-20260801/ubuntu-24.04-server-cloudimg-amd64.img",
      "runtimePath": ".work/qemu/images/sha256/0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe/base.qcow2",
      "sha256": "0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe",
      "format": "qcow2"
    }
  ]
}`

func TestParseAcceptsPinnedUbuntuImages(t *testing.T) {
	lock, err := Parse([]byte(ubuntuImageLockJSON))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if lock.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", lock.SchemaVersion)
	}
	if len(lock.Images) != 2 {
		t.Fatalf("len(Images) = %d, want 2", len(lock.Images))
	}

	arm64 := lock.Images[0]
	if arm64.StableID != "ubuntu-24.04-20260801-arm64" {
		t.Errorf("arm64 StableID = %q", arm64.StableID)
	}
	if arm64.Architecture != ArchitectureARM64 {
		t.Errorf("arm64 Architecture = %q", arm64.Architecture)
	}
	if arm64.Format != FormatQCOW2 {
		t.Errorf("arm64 Format = %q", arm64.Format)
	}
	if arm64.SHA256 != "aa6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476" {
		t.Errorf("arm64 SHA256 = %q", arm64.SHA256)
	}

	amd64 := lock.Images[1]
	if amd64.StableID != "ubuntu-24.04-20260801-amd64" {
		t.Errorf("amd64 StableID = %q", amd64.StableID)
	}
	if amd64.Architecture != ArchitectureAMD64 {
		t.Errorf("amd64 Architecture = %q", amd64.Architecture)
	}
	if amd64.Format != FormatQCOW2 {
		t.Errorf("amd64 Format = %q", amd64.Format)
	}
	if amd64.SHA256 != "0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe" {
		t.Errorf("amd64 SHA256 = %q", amd64.SHA256)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	tests := map[string]string{
		"top level": replaceOnce(t, ubuntuImageLockJSON,
			`"schemaVersion": 1,`,
			`"schemaVersion": 1, "unexpected": true,`),
		"image record": replaceOnce(t, ubuntuImageLockJSON,
			`"distribution": "ubuntu",`,
			`"distribution": "ubuntu", "unexpected": true,`),
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			assertParseErrorContains(t, input, "unknown field")
		})
	}
}

func TestParseRejectsTrailingJSONValue(t *testing.T) {
	assertParseErrorContains(t, ubuntuImageLockJSON+"\n{}", "trailing")
}

func TestParseRejectsDuplicateStableIDs(t *testing.T) {
	input := replaceOnce(t, ubuntuImageLockJSON,
		`"stableId": "ubuntu-24.04-20260801-amd64"`,
		`"stableId": "ubuntu-24.04-20260801-arm64"`)

	assertParseErrorContains(t, input, "duplicate stableId")
}

func TestParseRejectsNonCanonicalSHA256(t *testing.T) {
	tests := map[string]string{
		"uppercase": "AA6DA05756E85EA6DDE4836B841FECB10CFD1BA3BCEA320189D9AF945DB70476",
		"non hex":   "ga6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476",
		"too short": "a6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476",
	}

	for name, digest := range tests {
		t.Run(name, func(t *testing.T) {
			input := replaceOnce(t, ubuntuImageLockJSON,
				`"sha256": "aa6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476"`,
				`"sha256": "`+digest+`"`)
			assertParseErrorContains(t, input, "canonical lowercase SHA256")
		})
	}
}

func TestParseRejectsUnsupportedArchitecture(t *testing.T) {
	for _, architecture := range []string{"aarch64", "x86_64", "ARM64", ""} {
		t.Run(architecture, func(t *testing.T) {
			input := replaceOnce(t, ubuntuImageLockJSON,
				`"architecture": "arm64"`,
				`"architecture": "`+architecture+`"`)
			assertParseErrorContains(t, input, "architecture")
		})
	}
}

func TestParseRejectsNonQCOW2Format(t *testing.T) {
	for _, format := range []string{"raw", "QCOW2", "qcow", ""} {
		t.Run(format, func(t *testing.T) {
			input := replaceOnce(t, ubuntuImageLockJSON,
				`"format": "qcow2"`,
				`"format": "`+format+`"`)
			assertParseErrorContains(t, input, "format")
		})
	}
}

func TestParseRejectsMutableResolvedRelease(t *testing.T) {
	for _, release := range []string{"latest", "current", "24.04-latest", "noble/current"} {
		t.Run(release, func(t *testing.T) {
			input := replaceOnce(t, ubuntuImageLockJSON,
				`"resolvedRelease": "24.04-20260801"`,
				`"resolvedRelease": "`+release+`"`)
			assertParseErrorContains(t, input, "immutable resolvedRelease")
		})
	}
}

func TestParseRejectsMutableOrUnboundRuntimePath(t *testing.T) {
	tests := map[string]string{
		"latest":           ".work/qemu/images/latest/base.qcow2",
		"current":          ".work/qemu/images/current/base.qcow2",
		"wrong digest":     ".work/qemu/images/sha256/0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe/base.qcow2",
		"path traversal":   ".work/qemu/images/sha256/aa6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476/../base.qcow2",
		"absolute path":    "/var/lib/vmharness/images/sha256/aa6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476/base.qcow2",
		"mutable filename": ".work/qemu/images/sha256/aa6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476/latest.qcow2",
	}

	for name, runtimePath := range tests {
		t.Run(name, func(t *testing.T) {
			input := replaceOnce(t, ubuntuImageLockJSON,
				`.work/qemu/images/sha256/aa6da05756e85ea6dde4836b841fecb10cfd1ba3bcea320189d9af945db70476/base.qcow2`,
				runtimePath)
			assertParseErrorContains(t, input, "immutable runtimePath")
		})
	}
}

func TestParseAllowsLatestOnlyInAcquisitionURL(t *testing.T) {
	input := replaceOnce(t, ubuntuImageLockJSON,
		"https://cloud-images.ubuntu.com/releases/noble/release-20260801/ubuntu-24.04-server-cloudimg-arm64.img",
		"https://vendor.example/images/product-latest.qcow2")

	if _, err := Parse([]byte(input)); err != nil {
		t.Fatalf("Parse() rejected a mutable acquisition locator with immutable release and runtime authority: %v", err)
	}
}

func assertParseErrorContains(t *testing.T, input, want string) {
	t.Helper()

	_, err := Parse([]byte(input))
	if err == nil {
		t.Fatalf("Parse() error = nil, want error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Parse() error = %q, want substring %q", err, want)
	}
}

func replaceOnce(t *testing.T, input, old, replacement string) string {
	t.Helper()

	if !strings.Contains(input, old) {
		t.Fatalf("fixture does not contain %q", old)
	}
	return strings.Replace(input, old, replacement, 1)
}
