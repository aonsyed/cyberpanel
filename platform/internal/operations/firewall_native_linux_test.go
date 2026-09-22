//go:build linux

package operations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	_ "modernc.org/sqlite"
)

// Only observation failure is injected. nft validation, commits, packet
// filtering, and rollback all execute against the actual kernel ruleset.
type firewallNativeRunner struct {
	failAfterApply bool
	pendingFailure bool
}

func (r *firewallNativeRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if r.pendingFailure && binary == "/usr/sbin/nft" && len(args) > 0 && args[0] == "--handle" {
		r.pendingFailure = false
		return nil, errors.New("injected post-commit observation loss")
	}
	out, err := (LinuxFixedCommandRunner{}).Run(ctx, binary, args...)
	if err == nil && r.failAfterApply && binary == "/usr/sbin/nft" && len(args) > 0 && args[0] == "--file" {
		r.pendingFailure = true
		r.failAfterApply = false
	}
	return out, err
}

func TestQEMUFirewallNativeTransaction(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_FIREWALL") != "1" {
		t.Skip("requires disposable network AND mount namespaces")
	}
	for _, kind := range []string{"net", "mnt"} {
		self, err := os.Readlink("/proc/self/ns/" + kind)
		if err != nil {
			t.Fatal(err)
		}
		root, err := os.Readlink("/proc/1/ns/" + kind)
		if err != nil || self == root {
			t.Fatalf("refusing root %s namespace", kind)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(binary string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v %s", binary, args, err, out)
		}
		return string(out)
	}
	run("/usr/bin/mount", "--make-rprivate", "/")
	private := t.TempDir()
	run("/usr/bin/mount", "--bind", private, "/etc/cyberpanel")
	defer exec.Command("/usr/bin/umount", "/etc/cyberpanel").Run()
	run("/usr/sbin/ip", "link", "set", "lo", "up")
	peer := exec.CommandContext(ctx, "/usr/bin/unshare", "--net", "/usr/bin/sleep", "60")
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Process.Kill(); _ = peer.Wait() }()
	pid := strconv.Itoa(peer.Process.Pid)
	self, _ := os.Readlink("/proc/self/ns/net")
	ready := false
	for i := 0; i < 100; i++ {
		ns, err := os.Readlink("/proc/" + pid + "/ns/net")
		if err == nil && ns != self {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("peer namespace unavailable")
	}
	run("/usr/sbin/ip", "link", "add", "fw-server", "type", "veth", "peer", "name", "fw-peer")
	defer exec.Command("/usr/sbin/ip", "link", "del", "fw-server").Run()
	run("/usr/sbin/ip", "link", "set", "fw-peer", "netns", pid)
	run("/usr/sbin/ip", "addr", "add", "192.0.2.1/30", "dev", "fw-server")
	run("/usr/sbin/ip", "link", "set", "fw-server", "up")
	peerRun := func(args ...string) string {
		return run("/usr/bin/nsenter", append([]string{"-t", pid, "-n", "--"}, args...)...)
	}
	peerRun("/usr/sbin/ip", "addr", "add", "192.0.2.2/30", "dev", "fw-peer")
	peerRun("/usr/sbin/ip", "link", "set", "fw-peer", "up")
	peerRun("/usr/sbin/ip", "link", "set", "lo", "up")
	listen := func() uint16 {
		t.Helper()
		listener, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("namespace-firewall-ok")) })}
		go server.Serve(listener)
		t.Cleanup(func() { server.Close() })
		return uint16(listener.Addr().(*net.TCPAddr).Port)
	}
	allowed, denied := listen(), listen()
	packet := func(port uint16, want bool) {
		t.Helper()
		out, err := exec.CommandContext(ctx, "/usr/bin/nsenter", "-t", pid, "-n", "--", "/usr/bin/curl", "--noproxy", "*", "--silent", "--connect-timeout", "1", "--max-time", "2", fmt.Sprintf("http://192.0.2.1:%d/", port)).CombinedOutput()
		if want && (err != nil || string(out) != "namespace-firewall-ok") {
			t.Fatalf("allowed TCP %d: %v %q", port, err, out)
		}
		if !want && err == nil {
			t.Fatalf("denied TCP %d passed", port)
		}
	}
	packet(allowed, true)
	packet(denied, true)
	run("/usr/sbin/nft", "add", "table", "inet", "fixture_unrelated")
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ensureOperationsStateRoot(state); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(state, "admission.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo, err := rebootcontrol.NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = rebootcontrol.NewAdmissionGate(ctx, db, "firewall-native-test", time.Now); err != nil {
		t.Fatal(err)
	}
	runner := &firewallNativeRunner{}
	executor := &LinuxOperationsExecutor{stateRoot: state, runner: runner, clock: SystemClock{}, admission: &rebootcontrol.SQLExecutionAdmission{DB: db, BootID: "firewall-native-test"}}
	id, _ := NewResourceID("native-firewall")
	ruleID, _ := NewResourceID("management")
	secondID, _ := NewResourceID("temporary-port")
	source := netip.MustParsePrefix("192.0.2.2/32")
	policy := FirewallPolicy{Metadata: Metadata{ID: id, Generation: 1}, Backend: FirewallNFTables, DefaultInbound: FirewallDrop, DefaultForward: FirewallDrop, DefaultOutbound: FirewallAccept, ManagementProbe: ManagementProbe{SourceCIDRs: []netip.Prefix{source}, Port: allowed, MinimumSuccesses: 1}, Rules: []FirewallRule{{ID: ruleID, Priority: 10, Family: FamilyIPv4, Protocol: ProtocolTCP, Sources: []netip.Prefix{source}, DestinationPorts: []PortRange{{From: allowed, To: allowed}}, Action: FirewallAccept}}}
	request := func(tag string) EffectRequest {
		return EffectRequest{EffectID: "hostfx-" + digestBytes([]byte(tag)), RequestDigest: digestBytes([]byte("request-" + tag))}
	}
	first := request("first")
	result, err := executor.applyFirewall(ctx, first, FirewallPolicyEffect{Policy: policy})
	if err != nil || result.Activation == nil {
		t.Log(run("/usr/sbin/nft", "--handle", "list", "table", "inet", "cyberpanel"))
		t.Fatal("native generation1", err)
	}
	packet(allowed, true)
	packet(denied, false)
	t.Log("generation1: allowed management TCP succeeds; unallowed fresh TCP denied across private veth")
	before, err := os.ReadFile("/etc/cyberpanel/firewall.nft")
	if err != nil {
		t.Fatal(err)
	}
	policy.Generation = 2
	policy.Rules = append(policy.Rules, FirewallRule{ID: secondID, Priority: 20, Family: FamilyIPv4, Protocol: ProtocolTCP, Sources: []netip.Prefix{source}, DestinationPorts: []PortRange{{From: denied, To: denied}}, Action: FirewallAccept})
	runner.failAfterApply = true
	second := request("second")
	result, err = executor.applyFirewall(ctx, second, FirewallPolicyEffect{Policy: policy})
	if err == nil || !result.MutationObserved {
		t.Fatal("post-commit failure not observed", err)
	}
	packet(denied, true)
	t.Log("generation2 native commit observed before injected confirmation failure")
	if err = executor.rollbackSecurityLease(ctx, second.EffectID); err != nil {
		t.Fatal("native rollback", err)
	}
	packet(allowed, true)
	packet(denied, false)
	after, err := os.ReadFile("/etc/cyberpanel/firewall.nft")
	if err != nil || string(after) != string(before) {
		t.Fatal("configuration snapshot not restored", err)
	}
	active, found, err := executor.loadSecurityActive(KindFirewallPolicy)
	if err != nil || !found || active.Generation != 1 {
		t.Fatal("active generation not restored", err)
	}
	lease, found, err := executor.loadSecurityLease(second.EffectID)
	if err != nil || !found || lease.State != securityLeaseRolledBack || !validSHA256(lease.RollbackProofDigest) {
		t.Fatal("rollback receipt", err)
	}
	if err = executor.rollbackSecurityLease(ctx, second.EffectID); err != nil {
		t.Fatal("rollback receipt replay", err)
	}
	rules := run("/usr/sbin/nft", "list", "table", "inet", "cyberpanel")
	if !strings.Contains(rules, "cyberpanel-generation:1:") || strings.Contains(rules, "cyberpanel:temporary-port") {
		t.Fatal("native generation mismatch")
	}
	run("/usr/sbin/nft", "delete", "table", "inet", "cyberpanel")
	if !strings.Contains(run("/usr/sbin/nft", "list", "tables"), "table inet fixture_unrelated") {
		t.Fatal("unrelated table changed")
	}
	run("/usr/sbin/nft", "delete", "table", "inet", "fixture_unrelated")
	if strings.TrimSpace(run("/usr/sbin/nft", "list", "tables")) != "" {
		t.Fatal("namespace rules remain")
	}
	t.Log("rollback restored generation1, config bytes, real allow/deny packets and durable receipt; namespace rules removed")
}
