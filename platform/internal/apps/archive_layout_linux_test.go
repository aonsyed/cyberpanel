package apps

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedArchiveStandardDirectoryHeaders(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "product.tar.gz")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	for _, header := range []*tar.Header{
		{Name: "wordpress/", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "wordpress/wp-admin/", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "wordpress/index.php", Typeflag: tar.TypeReg, Mode: 0644, Size: 1},
	} {
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := archive.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validatePinnedApplicationArchive(filename); err != nil {
		t.Fatal(err)
	}
}

func TestQEMURealWordPressArchive(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_REAL_APP_ARCHIVES") != "1" {
		t.Skip("requires verified QEMU release inputs")
	}
	if err := validatePinnedApplicationArchive("/home/harness/wordpress-7.1.tar.gz"); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedArchiveRejectsUnsafeDirectories(t *testing.T) {
	for _, name := range []string{"../escape/", "/absolute/", "wordpress/../escape/", "wordpress//nested/", "other/"} {
		t.Run(name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "unsafe.tar.gz")
			file, err := os.Create(filename)
			if err != nil {
				t.Fatal(err)
			}
			compressed := gzip.NewWriter(file)
			archive := tar.NewWriter(compressed)
			for _, directory := range []string{"wordpress/", name} {
				if err := archive.WriteHeader(&tar.Header{Name: directory, Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
					t.Fatal(err)
				}
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if err := compressed.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if err := validatePinnedApplicationArchive(filename); err == nil {
				t.Fatal("accepted unsafe directory")
			}
		})
	}
}

func TestQEMURealMauticArchive(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_REAL_APP_ARCHIVES") != "1" {
		t.Skip("requires verified QEMU release inputs")
	}
	if err := validatePinnedApplicationArchive("/home/harness/mautic-7.2.0-rooted.tar.gz"); err != nil {
		t.Fatal(err)
	}
}

func TestQEMURealJoomlaArchive(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_REAL_APP_ARCHIVES") != "1" {
		t.Skip("requires verified QEMU release inputs")
	}
	if err := validatePinnedApplicationArchive("/home/harness/joomla-6.1.3-rooted.tar.gz"); err != nil {
		t.Fatal(err)
	}
}
