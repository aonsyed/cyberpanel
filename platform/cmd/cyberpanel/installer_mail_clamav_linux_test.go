//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestQEMUMailClamAVNative(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_CLAM") != "1" {
		t.Skip("explicit QEMU ClamAV service qualification")
	}
	if err := installMailClamAVUnit(); err != nil {
		t.Fatal(err)
	}
	if err := installMailClamAVUnit(); err != nil {
		t.Fatal("unit replay", err)
	}
	for _, unit := range []string{"clamav-daemon.service", "clamav-daemon.socket"} {
		out, err := exec.Command("/usr/bin/systemctl", "is-active", unit).Output()
		if err == nil || strings.TrimSpace(string(out)) != "inactive" {
			t.Fatal("ClamAV must be inactive before fixture", unit)
		}
	}
	entries, err := os.ReadDir("/var/lib/cyberpanel/mail/generations")
	if err != nil || len(entries) == 0 {
		t.Fatal("retained config required", err)
	}
	config := filepath.Join("/var/lib/cyberpanel/mail/generations", entries[0].Name(), "clamav/clamd.conf")
	const directory = "/run/systemd/system/clamav-daemon.service.d"
	if err := os.Mkdir(directory, 0755); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	const override = directory + "/90-qemu-mail.conf"
	f, err := os.OpenFile(override, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = exec.Command("/usr/bin/systemctl", "stop", "clamav-daemon.service", "clamav-daemon.socket").Run()
		if err := os.Remove(override); err != nil {
			t.Error(err)
		}
		_ = exec.Command("/usr/bin/systemctl", "daemon-reload").Run()
	}()
	_, err = f.WriteString("[Service]\nExecStart=\nExecStart=/usr/sbin/clamd --foreground=true --config-file=" + config + "\n")
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	for _, args := range [][]string{{"daemon-reload"}, {"start", "clamav-daemon.service"}} {
		if out, err := exec.Command("/usr/bin/systemctl", args...).CombinedOutput(); err != nil {
			t.Fatalf("start ClamAV: %v %s", err, out)
		}
	}
	const socket = "/run/clamd/cyberpanel.sock"
	deniedProbe := "import socket\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect('/run/clamd/cyberpanel.sock')\nexcept PermissionError:\n raise SystemExit(0)\nraise SystemExit('unexpected scan access')\n"
	if out, err := exec.Command("/usr/sbin/runuser", "-u", "nobody", "--", "/usr/bin/python3", "-c", deniedProbe).CombinedOutput(); err != nil {
		t.Fatalf("unrelated-user socket denial: %v %s", err, out)
	}
	for _, identity := range []string{"cyberpanel", "_rspamd"} {
		probe := `import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect("/run/clamd/cyberpanel.sock"); s.sendall(b"zPING\0"); assert s.recv(128).strip(b"\0\n")==b"PONG"`
		if out, err := exec.Command("/usr/sbin/runuser", "-u", identity, "-G", "clamav", "--", "/usr/bin/python3", "-c", probe).CombinedOutput(); err != nil {
			t.Fatalf("scan socket as %s: %v %s", identity, err, out)
		}
	}
	for _, sample := range []struct {
		data     string
		infected bool
	}{{"plain clean mail fixture", false}, {"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", true}} {
		connection, err := net.DialTimeout("unix", socket, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err = connection.Write([]byte("zINSTREAM\x00")); err == nil {
			err = binary.Write(connection, binary.BigEndian, uint32(len(sample.data)))
		}
		if err == nil {
			_, err = connection.Write([]byte(sample.data))
		}
		if err == nil {
			err = binary.Write(connection, binary.BigEndian, uint32(0))
		}
		if err != nil {
			connection.Close()
			t.Fatal(err)
		}
		response, err := bufio.NewReader(connection).ReadString(0)
		connection.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(response, "FOUND") != sample.infected || (!sample.infected && !strings.Contains(response, "OK")) {
			t.Fatalf("scan verdict: %q", response)
		}
	}
	profiles, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	if err != nil || !strings.Contains(string(profiles), "/usr/sbin/clamd (enforce)") {
		t.Fatal("ClamAV confinement is not enforcing", err)
	}
	pidOutput, err := exec.Command("/usr/bin/systemctl", "show", "clamav-daemon.service", "--property=MainPID", "--value").Output()
	pid := strings.TrimSpace(string(pidOutput))
	number, parseErr := strconv.ParseUint(pid, 10, 32)
	if err != nil || parseErr != nil || number <= 1 {
		t.Fatal("missing ClamAV process", err, parseErr)
	}
	label, err := os.ReadFile("/proc/" + pid + "/attr/current")
	if err != nil || strings.TrimSpace(string(label)) != "/usr/sbin/clamd (enforce)" {
		t.Fatal("running ClamAV process is not confined", err)
	}
}
