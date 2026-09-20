package apps

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestJoomlaRequiresSimpleXML(t *testing.T) {
	contract := CertifiedProductContracts()[ApplicationJoomla]
	definition := DefinitionFromContract(contract, RecipeReference{}, ArtifactReference{}, "")
	if !slices.Contains(definition.Runtime.PHPExtensions, "simplexml") {
		t.Fatal("Joomla installer calls simplexml_load_file before executing any command")
	}
}

func TestQEMURealJoomlaInstallerCLI(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_JOOMLA") != "1" {
		t.Skip("requires verified Joomla 6.1.3 fixture in QEMU")
	}
	command := exec.Command("/usr/bin/php8.3", "installation/joomla.php", "install", "--help")
	command.Dir = "/home/harness/joomla-6.1.3"
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Joomla CLI startup: %v: %s", err, output)
	}
	for _, option := range []string{"--site-name", "--admin-user", "--admin-username", "--admin-password", "--admin-email", "--db-type", "--db-host", "--db-user", "--db-pass", "--db-name", "--db-prefix", "--no-interaction"} {
		if !strings.Contains(string(output), option) {
			t.Errorf("real installer lacks runtime option %s", option)
		}
	}
}
