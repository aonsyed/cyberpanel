//go:build linux

package access

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/scheduler"
)

func TestCronCalendarAcceptedByNativeScheduler(t *testing.T) {
	if _, err := exec.LookPath("/usr/bin/systemd-analyze"); err != nil {
		t.Skip("native systemd calendar parser unavailable")
	}
	for _, expression := range []string{"* * * * *", "*/5 * * * *", "0 0 * * 1", "@daily"} {
		calendar, err := renderCalendar(expression)
		if err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command("/usr/bin/systemd-analyze", "calendar", calendar+" UTC").CombinedOutput()
		if err != nil {
			t.Fatalf("%s rejected: %s", expression, output)
		}
	}
}

func TestCronNativeCalendarPreservesDayUnion(t *testing.T) {
	if _, err := exec.LookPath("/usr/bin/systemd-analyze"); err != nil {
		t.Skip("native systemd calendar parser unavailable")
	}
	const expression = "0 0 1 * 1"
	after := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	want, err := scheduler.NextLogicalTime(expression, "UTC", after)
	if err != nil {
		t.Fatal(err)
	}
	calendars, err := renderCalendars(expression)
	if err != nil || len(calendars) != 2 {
		t.Fatalf("expected two OR branches: %v %v", calendars, err)
	}
	var earliest time.Time
	for _, calendar := range calendars {
		command := exec.Command("/usr/bin/systemd-analyze", "calendar", "--base-time="+after.Format("2006-01-02 15:04:05 MST"), calendar+" UTC")
		command.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("native calendar: %v %s", err, output)
		}
		var next time.Time
		for _, line := range strings.Split(string(output), "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line), "Next elapse: "); ok {
				next, err = time.Parse("Mon 2006-01-02 15:04:05 MST", value)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		if next.IsZero() {
			t.Fatalf("missing next occurrence: %s", output)
		}
		if earliest.IsZero() || next.Before(earliest) {
			earliest = next
		}
	}
	if !earliest.Equal(want) {
		t.Fatalf("native OR next=%s, cron contract=%s", earliest, want)
	}
}

func TestQEMUCronPackagedPHPExecutesAsSiteOwner(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_CRON") != "1" {
		t.Skip("isolated QEMU native fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("QEMU root required")
	}
	site, err := os.MkdirTemp(LinuxAccessSitesRoot, "s-cron-qa-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(site) })
	root := filepath.Join(site, "roots/g1/releases/current")
	if err := os.MkdirAll(root, 0750); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(site, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, 1000, 1000)
	}); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "cron.php")
	if err := os.WriteFile(script, []byte("<?php file_put_contents(__DIR__.'/executed', 'scheduled-cli');"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(script, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	binding := LinuxSiteBinding{SiteKey: filepath.Base(site), Username: "harness", UID: 1000, GID: 1000, Generation: 1}
	executor, err := NewLinuxCronExecutor(&LinuxFileExecutor{Resolver: LinuxSiteResolverFunc(func(context.Context, SiteID) (LinuxSiteBinding, error) { return binding, nil })}, nil)
	if err != nil {
		t.Fatal(err)
	}
	expression, _ := ParseCronExpression("* * * * *")
	entry, _ := ParseRelativePath("cron.php")
	job := CronJob{ID: "cron-qa", SiteID: "site-qa", Name: "QEMU owned cron", Schedule: expression, Timezone: "UTC", Invocation: CronInvocation{Kind: InvocationProgram, Program: &ProgramInvocation{Program: ProgramPHP, Entrypoint: entry}}, Concurrency: ConcurrencyForbid, TimeoutSeconds: 10, Output: OutputDiscard, Enabled: true, Generation: 1}
	run, err := executor.RunNow(context.Background(), job)
	if err != nil || run.State != "succeeded" {
		t.Fatalf("native run: %+v %v", run, err)
	}
	value, err := os.ReadFile(filepath.Join(root, "executed"))
	if err != nil || string(value) != "scheduled-cli" {
		t.Fatalf("PHP CLI did not execute: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "executed"))
	if err != nil {
		t.Fatal(err)
	}
	if stat := info.Sys().(*syscall.Stat_t); stat.Uid != 1000 || stat.Gid != 1000 {
		t.Fatal("cron escaped site ownership")
	}
	if os.Getenv("CYBERPANEL_QEMU_CRON_TIMER") != "1" {
		return
	}
	// A far-future timer verifies unit lifecycle without depending on the
	// installed helper or dispatching through the shared access broker.
	job.Schedule, _ = ParseCronExpression("0 0 1 1 *")
	ctx := context.Background()
	token := cronUnitToken(binding, job)
	t.Cleanup(func() {
		if _, err := executor.ApplySchedule(ctx, job.SiteID, 10, nil); err != nil {
			t.Error(err)
		}
		if err := os.Remove(linuxCronStateRoot + "/" + binding.SiteKey + ".json"); err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
	})
	if _, err := executor.ApplySchedule(ctx, job.SiteID, 1, []CronJob{job}); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/systemctl", "is-active", token+".timer").CombinedOutput(); err != nil {
		t.Fatalf("timer inactive: %s", out)
	}
	job.Enabled = false
	if _, err := executor.ApplySchedule(ctx, job.SiteID, 2, []CronJob{job}); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".timer", ".service"} {
		if _, err := os.Lstat("/etc/systemd/system/" + token + suffix); !os.IsNotExist(err) {
			t.Fatalf("disabled unit remains: %s %v", suffix, err)
		}
	}
	if out, err := exec.Command("/usr/bin/systemctl", "is-active", token+".timer").CombinedOutput(); err == nil {
		t.Fatalf("disabled timer remains active: %s", out)
	}
	if _, err := os.Lstat("/etc/systemd/system/timers.target.wants/" + token + ".timer"); !os.IsNotExist(err) {
		t.Fatalf("disabled timer retains enablement: %v", err)
	}
	job.Enabled = true
	if _, err := executor.ApplySchedule(ctx, job.SiteID, 3, []CronJob{job}); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ApplySchedule(ctx, job.SiteID, 4, nil); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/systemctl", "is-active", token+".timer").CombinedOutput(); err == nil {
		t.Fatalf("deleted timer remains active: %s", out)
	}
}
