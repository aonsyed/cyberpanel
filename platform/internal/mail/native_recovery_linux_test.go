//go:build linux

package mail

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestQEMUCurrentMailGenerationRecovery(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_RECOVERY") != "1" {
		t.Skip("explicit QEMU native mail stop/recovery qualification")
	}
	profile, err := profileForMail(MailUbuntuNoble)
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.Readlink(filepath.Join(MailConfigurationRoot, "current"))
	if err != nil || filepath.Dir(current) != "generations" {
		t.Fatal("managed mail generation required", current, err)
	}
	units := []string{"clamav-daemon", "rspamd", "opendkim", "dovecot", "postfix"}
	t.Cleanup(func() {
		if output, err := exec.Command("/usr/bin/systemctl", append([]string{"start"}, units...)...).CombinedOutput(); err != nil {
			t.Errorf("restore native mail: %v %s", err, output)
		}
	})
	if output, err := exec.Command("/usr/bin/systemctl", append([]string{"stop"}, units...)...).CombinedOutput(); err != nil {
		t.Fatalf("stop mail: %v %s", err, output)
	}
	host := &LinuxMailHost{profile: profile}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := host.reconcileCurrentGeneration(ctx, MailActivationReceipt{GenerationID: "missing-generation"}); err == nil {
		t.Fatal("unvalidated generation accepted")
	}
	if err := exec.Command("/usr/bin/systemctl", "is-active", "--quiet", "postfix").Run(); err == nil {
		t.Fatal("invalid generation started native mail")
	}
	initial := MailActivationReceipt{GenerationID: filepath.Base(current)}
	recovered, err := host.reconcileCurrentGeneration(ctx, initial)
	if err != nil {
		t.Fatalf("unchanged-generation recovery: %v", err)
	}
	if recovered.ValidationDigest == "" || recovered.ReloadDigest == "" || recovered.ProbeDigest == "" {
		t.Fatal("missing recovery evidence")
	}
	assertNativeSMTP(t)
	replayed, err := host.reconcileCurrentGeneration(ctx, initial)
	if err != nil || replayed.ProbeDigest == "" || replayed.ReloadDigest != "" {
		t.Fatal("healthy replay must not restart services", err)
	}
}
