//go:build linux

package backup

import (
	"context"
	"testing"
)

func TestNativeRestoreRejectsUnmappedDatabaseScope(t *testing.T) {
	called := false
	host := &LinuxBackupHost{Resolver: LinuxBackupSiteResolverFunc(func(context.Context, string, string) (LinuxBackupSiteBinding, error) {
		called = true
		return LinuxBackupSiteBinding{}, ErrInvalidBackup
	})}
	plan := RestorePlanSpec{ID: "restore", TenantID: "tenant", SourceScope: "source", TargetScope: "target", RecoveryPointID: "point", CollisionPolicy: CollisionReplaceBlueGreen, SecretPolicy: SecretResetRequired, ComponentMapping: map[ComponentKind]string{ComponentDatabase: "target"}}
	_, err := host.CreateScratch(context.Background(), plan, RecoveryPointManifest{RecoveryPointID: "point", Scope: "source"}, "restore")
	if err == nil || called {
		t.Fatal("cross-scope database restore must be rejected before resolving or mutating the target")
	}
	// Previously staged plans must not bypass the boundary on restart.
	_, err = host.Promote(context.Background(), plan, "existing-scratch", "restore")
	if err == nil || called {
		t.Fatal("resumed cross-scope database promotion must be rejected before touching the target")
	}
}

func TestLinuxRestoreScopeSelection(t *testing.T) {
	for _, component := range []ComponentKind{ComponentDatabase, ComponentMail, ComponentFiles} {
		plan := RestorePlanSpec{SourceScope: "source", TargetScope: "source", ComponentMapping: map[ComponentKind]string{component: "source"}}
		manifest := RecoveryPointManifest{Scope: "source"}
		if err := validateLinuxRestoreScope(plan, manifest); err != nil {
			t.Fatalf("same-scope %s: %v", component, err)
		}
		plan.TargetScope = "target"
		err := validateLinuxRestoreScope(plan, manifest)
		if component == ComponentFiles && err != nil || component != ComponentFiles && err == nil {
			t.Fatalf("cross-scope %s: %v", component, err)
		}
		manifest.Scope = "other"
		if validateLinuxRestoreScope(plan, manifest) == nil {
			t.Fatal("manifest scope mismatch accepted")
		}
	}
}
