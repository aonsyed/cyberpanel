package noderelease

import (
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// Run on a disposable locked thread: namespace changes must never leak to the
// caller or another Go task. Go destroys the thread when this goroutine exits;
// deliberately do not UnlockOSThread on either success or failure.
func runInOfflineNetwork(run func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			done <- err
			return
		}
		if err := enablePrivateLoopback(); err != nil {
			done <- err
			return
		}
		done <- run()
	}()
	return <-done
}

func enablePrivateLoopback() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	request, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
		return err
	}
	request.SetUint16(request.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, request)
}
