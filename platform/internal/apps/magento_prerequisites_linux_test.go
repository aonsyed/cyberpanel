package apps

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestQEMUMagentoExtensionContract(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAGENTO_INPUTS") != "1" {
		t.Skip("requires official Magento 2.4.9 source in QEMU")
	}
	payload, err := os.ReadFile("/home/harness/magento-2.4.9-release-source/composer.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Require) == 0 {
		t.Fatal("empty upstream requirements")
	}
	contract := CertifiedProductContracts()[ApplicationMagento]
	for dependency := range document.Require {
		if extension, ok := strings.CutPrefix(dependency, "ext-"); ok && !slices.Contains(contract.PHPExtensions, extension) {
			t.Errorf("Magento upstream requires missing extension %s", extension)
		}
	}
}

func TestMagentoRequiresCoreExtensions(t *testing.T) {
	contract := CertifiedProductContracts()[ApplicationMagento]
	definition := DefinitionFromContract(contract, RecipeReference{}, ArtifactReference{}, "")
	for _, extension := range []string{"ftp", "hash", "iconv"} {
		if !slices.Contains(definition.Runtime.PHPExtensions, extension) {
			t.Errorf("missing required extension %s", extension)
		}
	}
}
