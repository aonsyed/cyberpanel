//go:build linux

package install

import "testing"

func TestUbuntuSieveIncludesManageSieveServer(t *testing.T) {
	// Ubuntu's managesieved package depends on the exact matching Sieve plugin;
	// sieve alone cannot serve the protocol declared in the mail configuration.
	name, err := nativePackage(DistributionUbuntu, PackageDovecotSieve)
	if err != nil || name != "dovecot-managesieved" {
		t.Fatal(name, err)
	}
}
