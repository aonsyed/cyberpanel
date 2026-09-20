package containers

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// This profile is inherited by the rootless runtime and its container children.
// Mount/userns operations are required by the host-side runtime; workload
// capability, seccomp, mount, UID and network restrictions remain mandatory.
// Executables inherit confinement; no change_profile or unconfined transition
// is granted. Profile generations coexist until their workloads are retired.
const rootlessAppArmorTemplate = `profile PROFILE_NAME flags=(attach_disconnected,mediate_deleted) {
  file,
  /** ix,
  network,
  unix,
  capability,
  mount,
  umount,
  pivot_root,
  userns,
  dbus,
  ptrace (read, trace, readby, tracedby) peer=PROFILE_NAME,
  signal (send, receive) peer=PROFILE_NAME,
  signal (receive) peer=unconfined,
  deny /etc/cyberpanel/** rwklmx,
  deny /var/lib/cyberpanel/{auth,secrets,identity,providers,sites}/** rwklmx,
  deny /run/cyberpanel/** rwklmx,
  deny /sys/kernel/security/** wklmx,
  deny /sys/firmware/** rwklmx,
  deny /proc/{kcore,kmem,mem,sysrq-trigger} rwklmx,
  deny /proc/sys/{kernel,vm,fs}/** wklmx,
  deny /proc/**/attr/{current,exec} w,
}
`

// RootlessAppArmorPolicy provides the immutable policy an installer must load
// before admitting this executable's Ubuntu container runtime generation.
func RootlessAppArmorPolicy() (string, []byte) {
	sum := sha256.Sum256([]byte(rootlessAppArmorTemplate))
	name := fmt.Sprintf("cyberpanel-containers-%x", sum[:16])
	return name, []byte(strings.ReplaceAll(rootlessAppArmorTemplate, "PROFILE_NAME", name))
}

func loadedEnforcingContainerProfile(reader io.Reader, name string) bool {
	scanner := bufio.NewScanner(io.LimitReader(reader, 2<<20))
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == name+" (enforce)" {
			found = true
		}
		if strings.HasPrefix(line, name+" ") && line != name+" (enforce)" {
			return false
		}
	}
	return scanner.Err() == nil && found
}

func containerAppArmorAvailable() bool {
	enabled, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
	return err == nil && strings.TrimSpace(string(enabled)) == "Y"
}

func rootlessContainerProfileReady() error {
	info, err := os.Lstat("/usr/bin/aa-exec")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%w: trusted aa-exec unavailable", ErrPolicy)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("%w: aa-exec ownership", ErrPolicy)
	}
	file, err := os.Open("/sys/kernel/security/apparmor/profiles")
	if err != nil {
		return fmt.Errorf("%w: AppArmor profile inventory", ErrPolicy)
	}
	defer file.Close()
	name, _ := RootlessAppArmorPolicy()
	if !loadedEnforcingContainerProfile(file, name) {
		return fmt.Errorf("%w: required enforcing profile %s not loaded", ErrPolicy, name)
	}
	return nil
}

func confineContainerInvocation(invocation LinuxContainerInvocation) (LinuxContainerInvocation, error) {
	if invocation.UID == 0 {
		return invocation, nil
	}
	if !containerAppArmorAvailable() {
		// Alma's native SELinux path remains supported only while enforcing.
		// Missing/unreadable/disabled MAC is never an unconfined fallback,
		// including exec against a previously admitted workload.
		mode, err := os.ReadFile("/sys/fs/selinux/enforce")
		if err != nil || strings.TrimSpace(string(mode)) != "1" {
			return LinuxContainerInvocation{}, fmt.Errorf("%w: enforcing container MAC unavailable", ErrPolicy)
		}
		return invocation, nil
	}
	if err := rootlessContainerProfileReady(); err != nil {
		return LinuxContainerInvocation{}, err
	}
	name, _ := RootlessAppArmorPolicy()
	invocation.Arguments = append([]string{"--profile", name, "--", invocation.Path}, invocation.Arguments...)
	invocation.Path = "/usr/bin/aa-exec"
	return invocation, nil
}

// Only the native runner can attest to its mandatory fixed-profile launcher;
// arbitrary runner implementations cannot opt into this fallback via JSON.
func (NativeLinuxContainerCommandRunner) inheritedMACReady() bool {
	return containerAppArmorAvailable() && rootlessContainerProfileReady() == nil
}
