//go:build linux

package backup

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryRejectsIncompleteAndLegacyJournalWithoutMutation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned journal boundary")
	}
	plan := RestorePlanSpec{ID: "restore", TenantID: "tenant", SourceScope: "site", TargetScope: "site", Generation: 1, ComponentMapping: map[ComponentKind]string{ComponentFiles: "site"}}
	receipt := RestoreReceipt{PlanID: plan.ID, TenantID: plan.TenantID, PlanDigest: nativeRestorePlanDigest(plan), ScratchID: "scratch", PreviousGeneration: "previous", SafetySnapshotID: "safety", RollbackFrontier: 1}
	host := &LinuxBackupHost{Root: t.TempDir(), Resolver: LinuxBackupSiteResolverFunc(func(context.Context, string, string) (LinuxBackupSiteBinding, error) {
		return LinuxBackupSiteBinding{SiteKey: "fixture", SiteID: "site", TenantID: "tenant", Generation: 1, UID: 1000, GID: 1000}, nil
	})}
	root := host.restoreRoot(plan)
	valid := linuxRestoreState{RecoveryVersion: 1, PlanDigest: receipt.PlanDigest, SourceGeneration: 1, PlanID: plan.ID, TenantID: plan.TenantID, TargetScope: plan.TargetScope, ScratchID: receipt.ScratchID, PreviousGeneration: receipt.PreviousGeneration, SafetyID: receipt.SafetySnapshotID, Watermark: 1, Fingerprint: "baseline", Promoted: true, Frozen: true}
	for _, mutation := range []string{"legacy", "mid_effect", "conflicting_completion", "source_generation", "plan", "scratch", "missing_fingerprint"} {
		t.Run(mutation, func(t *testing.T) {
			state := valid
			switch mutation {
			case "legacy":
				state.RecoveryVersion = 0
			case "mid_effect":
				state.Promoted = false
			case "conflicting_completion":
				state.RolledBack = true
			case "source_generation":
				state.SourceGeneration++
			case "plan":
				state.PlanDigest = "foreign"
			case "scratch":
				state.ScratchID = "other"
			case "missing_fingerprint":
				state.Fingerprint = ""
			}
			path := filepath.Join(root, "state.json")
			if err := writeLinuxBackupJSON(path, state); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = host.ReconcileRestore(context.Background(), plan, receipt); err == nil {
				t.Fatal("unsafe journal accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(before) {
				t.Fatal("rejected recovery mutated journal", err)
			}
		})
	}
}

func TestRecoveryClientObservationsNeverReuseEffectIdentity(t *testing.T) {
	var effects []string
	client := &LocalLinuxBackupClient{Dialer: func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var request LinuxBackupRequest
			if err := readLinuxBackupFrame(server, &request); err != nil {
				return
			}
			effects = append(effects, request.EffectID)
			proof := RestoreRecoveryProof{Phase: RestoreActive, TargetGeneration: "generation", Watermark: uint64(len(effects)), Digest: linuxBackupDigest("proof")}
			_ = writeLinuxBackupFrame(server, LinuxBackupResponse{Version: request.Version, RequestID: request.RequestID, Operation: request.Operation, Recovery: &proof})
		}()
		return client, nil
	}}
	for i := 0; i < 2; i++ {
		proof, err := client.ReconcileRestore(context.Background(), RestorePlanSpec{ID: "restore"}, RestoreReceipt{})
		if err != nil || proof.Watermark != uint64(i+1) {
			t.Fatal("fresh observation", err)
		}
	}
	if len(effects) != 2 || effects[0] == effects[1] {
		t.Fatal("recovery could reuse stale broker receipt")
	}
}
