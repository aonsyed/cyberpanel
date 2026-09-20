//go:build linux

package dns

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

type forbiddenStartupAdmission struct{ calls int }

func TestQEMUPowerDNSNativeHealthProbe(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_PDNS_RUNNING") != "1" {
		t.Skip("requires running native PowerDNS in QEMU")
	}
	profile, err := profileForPowerDNS(PowerDNSUbuntuNoble)
	if err != nil {
		t.Fatal(err)
	}
	host := &LinuxPowerDNSHost{profile: profile}
	receipt, err := host.probe(context.Background(), "qemu-native-health")
	if err != nil || !receipt.Success || !receipt.Healthy {
		t.Fatalf("native PowerDNS health probe: %v", err)
	}
}

func (admission *forbiddenStartupAdmission) AdmitExecution(context.Context, rebootcontrol.ExecutionBinding) (rebootcontrol.ExecutionLease, error) {
	admission.calls++
	return rebootcontrol.ExecutionLease{}, errors.New("unexpected execution lease")
}

func TestQEMUPowerDNSUnappliedStartupEvidence(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_NODE_RELEASE") != "1" {
		t.Skip("requires inactive QEMU PowerDNS and recoverable managed store")
	}
	profile, err := profileForPowerDNS(PowerDNSUbuntuNoble)
	if err != nil {
		t.Fatal(err)
	}
	store, err := daemoncfg.OpenStore(PowerDNSConfigurationRoot, PowerDNSConfigurationRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	group, err := user.LookupGroup("pdns")
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	host := &LinuxPowerDNSHost{Store: store, profile: profile, Ownership: PowerDNSOwnership{PDNSGID: uint32(gid)}, ControlDatabaseFingerprint: LocalPowerDNSControlFingerprint()}
	snapshot := LocalPowerDNSConfigSnapshot(1)
	proof, err := host.unappliedStartupEvidence(context.Background(), snapshot)
	if err != nil || !powerDNSSHA256(proof) {
		t.Fatal("actual unapplied state rejected", err)
	}
	entries, err := os.ReadDir(filepath.Join(PowerDNSConfigurationRoot, "generations"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 0 {
		if _, err := host.unappliedStartupEvidence(context.Background(), LocalPowerDNSConfigSnapshot(2)); !errors.Is(err, ErrPowerDNSAmbiguous) {
			t.Fatal("different desired generation was treated as unapplied", err)
		}
	}
	marker, err := os.MkdirTemp(filepath.Join(PowerDNSConfigurationRoot, "staging"), "recovery-proof-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(marker)
	if _, err := host.unappliedStartupEvidence(context.Background(), snapshot); !errors.Is(err, ErrPowerDNSAmbiguous) {
		t.Fatal("staged work was treated as unapplied", err)
	}
}
func (*forbiddenStartupAdmission) FinishExecution(context.Context, rebootcontrol.ExecutionLease, bool, []byte) error {
	return errors.New("unexpected settlement")
}

func TestQEMUPowerDNSUnmanagedConfigDoesNotAcquireLease(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_NODE_RELEASE") != "1" {
		t.Skip("requires QEMU native package configuration")
	}
	profile, err := profileForPowerDNS(PowerDNSUbuntuNoble)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(profile.configuration.link)
	if err != nil || !info.Mode().IsRegular() {
		t.Skip("native regular config no longer present")
	}
	if err := checkPowerDNSBindingBeforeActivation(profile.configuration); !errors.Is(err, daemoncfg.ErrConflict) {
		t.Fatalf("unmanaged config: %v", err)
	}
	admission := &forbiddenStartupAdmission{}
	server := &PowerDNSDaemonServer{
		Host:      &LinuxPowerDNSHost{profile: profile, ControlDatabaseFingerprint: LocalPowerDNSControlFingerprint()},
		Authority: &SecuredPowerDNSAuthority{},
	}
	if err := server.ReconcileStartup(context.Background(), admission, LocalPowerDNSConfigSnapshot(1)); !errors.Is(err, daemoncfg.ErrConflict) {
		t.Fatalf("startup: %v", err)
	}
	if admission.calls != 0 {
		t.Fatal("acquired execution lease before rejecting unmanaged config")
	}
	after, err := os.Lstat(profile.configuration.link)
	if err != nil || !os.SameFile(info, after) || info.Mode() != after.Mode() {
		t.Fatal("preflight mutated native config", err)
	}
}
