package main

import (
	"errors"
	"os"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
)

// Transfer only the fixed native config boundary to panel authority. This is
// root installer work, not a runtime relaxation of the private-store policy.
func reconcileWebEngineAuthority() error {
	if os.Geteuid() != 0 {
		return errors.New("web authority requires root installer")
	}
	edition, err := siteops.LoadEngineEdition()
	if err != nil {
		return err
	}
	if err := reconcileWebWorker(); err != nil {
		return err
	}
	master := "httpd_config.conf"
	if edition == siteops.EditionLiteSpeedEnterprise {
		master = "httpd_config.xml"
	}
	for _, path := range []string{"/usr", "/usr/local", "/usr/local/lsws"} {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe web configuration ancestor")
		}
	}
	dir, err := syscall.Open("/usr/local/lsws/conf", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(dir)
	// Revoking the vendor admin account's write access prevents it from
	// replacing entries while the privileged panel establishes authority.
	if err = syscall.Fchown(dir, 0, 0); err != nil {
		return err
	}
	if err = syscall.Fchmod(dir, 0700); err != nil {
		return err
	}
	// Managed vhosts live beneath this vendor-created parent. Transfer only
	// the parent; never recursively rewrite vendor or tenant configuration.
	if err = syscall.Mkdirat(dir, "vhosts", 0700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	vhosts, err := syscall.Openat(dir, "vhosts", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(vhosts)
	if err = syscall.Fchown(vhosts, 0, 0); err != nil {
		return err
	}
	if err = syscall.Fchmod(vhosts, 0700); err != nil {
		return err
	}
	if err = syscall.Fsync(vhosts); err != nil {
		return err
	}
	fd, err := syscall.Openat(dir, master, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 {
		return errors.New("unsafe web configuration master")
	}
	if err = syscall.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err = syscall.Fchmod(fd, 0600); err != nil {
		return err
	}
	if err = syscall.Fsync(fd); err != nil {
		return err
	}
	return syscall.Fsync(dir)
}
