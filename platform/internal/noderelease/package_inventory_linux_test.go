package noderelease

import "testing"

func TestPrivateCertificateDirectoryInventory(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"drwx------ root/root 0 2023-10-01 04:19 ./etc/ssl/private/", true},
		{"drwxr-xr-x root/root 0 2023-10-01 04:19 ./etc/ssl/private/", false},
		{"drwx------ user/root 0 2023-10-01 04:19 ./etc/ssl/private/", false},
		{"-rw------- root/root 0 2023-10-01 04:19 ./etc/ssl/private/", false},
		{"lrwx------ root/root 0 2023-10-01 04:19 ./etc/ssl/private -> /tmp", false},
		{"-rw------- root/root 100 2023-10-01 04:19 ./etc/ssl/private/key.pem", false},
		{"drwx------ root/root 0 2023-10-01 04:19 ./etc/ssl/private/nested/", false},
	} {
		if got := privateCertificateDirectoryInventory(tc.line, PackageDPKG); got != tc.want {
			t.Errorf("line=%q: got %v want %v", tc.line, got, tc.want)
		}
		if privateCertificateDirectoryInventory(tc.line, PackageRPM) {
			t.Fatal("RPM path-only inventory cannot prove directory metadata")
		}
	}
}
