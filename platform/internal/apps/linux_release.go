//go:build linux

package apps

import (
	"fmt"
	"reflect"
	"sort"
	"time"
)

// ValidateCertifiedProductDefinition checks declared capabilities, not empirical
// certification. Each pinned version can narrow PHP compatibility but cannot
// silently drop a required OS, architecture, engine, lifecycle, store, or probe.
func ValidateCertifiedProductDefinition(definition ApplicationDefinition, now time.Time) error {
	if err := definition.Validate(now); err != nil { return err }
	contract, exists := CertifiedProductContracts()[definition.Kind]
	if !exists { return ErrUnsupported }
	expected := DefinitionFromContract(contract, definition.Recipe, definition.Artifact, definition.DefinitionDigest)
	if definition.DisplayName != contract.DisplayName || definition.StorageMode != contract.DefaultStorage || definition.Lifecycle != contract.Lifecycle ||
		!reflect.DeepEqual(definition.MutableStores, expected.MutableStores) || !reflect.DeepEqual(definition.InstallProbes, expected.InstallProbes) ||
		!reflect.DeepEqual(definition.UpdateProbes, expected.UpdateProbes) || !sameReleaseStrings(definition.BackupComponents, expected.BackupComponents) ||
		!sameReleaseStrings(definition.Runtime.PHPExtensions, expected.Runtime.PHPExtensions) || !sameReleaseStrings(definition.Runtime.DatabaseKinds, expected.Runtime.DatabaseKinds) ||
		definition.Runtime.MinMemoryBytes < expected.Runtime.MinMemoryBytes || definition.Runtime.MinDiskBytes < expected.Runtime.MinDiskBytes {
		return fmt.Errorf("%w: %s product contract", ErrUnsupported, definition.Kind)
	}
	if len(definition.OperatingSystems) != 2 || len(definition.Architectures) != 2 || len(definition.WebEngines) != 2 { return ErrUnsupported }
	seenPHP := map[string]bool{}
	for _, php := range definition.Runtime.PHPVersions {
		allowed := false
		for _, candidate := range contract.PHPVersions { allowed = allowed || php == candidate }
		if !allowed || seenPHP[php] { return ErrUnsupported }
		seenPHP[php] = true
		for _, operatingSystem := range []OperatingSystem{OSUbuntuNoble, OSAlmaLinux9} {
			for _, architecture := range []CPUArchitecture{ArchitectureAMD64, ArchitectureARM64} {
				for _, engine := range []WebEngine{EngineOpenLiteSpeed, EngineLiteSpeedEnterprise} {
					target := CatalogTarget{OperatingSystem: operatingSystem, Architecture: architecture, WebEngine: engine, PHPVersion: php}
					if target.Validate() != nil || !definitionSupports(definition, target) { return ErrUnsupported }
				}
			}
		}
	}
	return nil
}

func sameReleaseStrings(left, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	return reflect.DeepEqual(left, right)
}

// ValidateReleaseApplicationArchive uses the installer's archive rules without
// requiring release engineering input files to be root-owned.
func ValidateReleaseApplicationArchive(path string) error { return validatePinnedApplicationArchive(path) }
