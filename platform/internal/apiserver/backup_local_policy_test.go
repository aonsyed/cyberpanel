package apiserver

import (
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"testing"
)

func TestConsoleBackupPolicyUsesNativeCapabilities(t *testing.T) {
	payload := BackupPolicyCreatePayload{Scope: "site", Schedule: "0 2 * * *", RepositoryID: "local", Retention: "7d", Consistency: backup.ConsistencyFuzzy, Components: []backup.ComponentKind{backup.ComponentFiles, backup.ComponentDatabase}}
	if err := validateBackupPolicyCreate(&payload); err != nil {
		t.Fatal(err)
	}
	payload.Consistency = backup.ConsistencyApplication
	if validateBackupPolicyCreate(&payload) == nil {
		t.Fatal("unsupported application consistency accepted")
	}
	payload.Consistency = backup.ConsistencyFuzzy
	for _, components := range [][]backup.ComponentKind{nil, {backup.ComponentDNS}, {backup.ComponentSecrets}, {backup.ComponentFiles, backup.ComponentFiles}} {
		payload.Components = components
		if validateBackupPolicyCreate(&payload) == nil {
			t.Fatalf("unsupported components accepted: %v", components)
		}
	}
}
