//go:build linux

package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

func powerDNSNativeUID() (uint32, error) {
	account, err := user.Lookup("pdns")
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return 0, ErrPowerDNSDatabaseOpen
	}
	return uint32(uid), nil
}

// The daemon may traverse the dedicated store but cannot list, create, replace
// or unlink entries. Only the three live SQLite files receive read/write access.
// Root retains ownership; other users and the owning group receive no access.
func powerDNSNativeACL(uid uint32, directory bool) []byte {
	owner, service := uint16(6), uint16(6)
	if directory {
		owner, service = 7, 1
	}
	data := make([]byte, 44)
	binary.LittleEndian.PutUint32(data, 2)
	entries := [][3]uint32{{1, uint32(owner), ^uint32(0)}, {2, uint32(service), uid}, {4, 0, ^uint32(0)}, {16, uint32(service), ^uint32(0)}, {32, 0, ^uint32(0)}}
	for i, entry := range entries {
		offset := 4 + i*8
		binary.LittleEndian.PutUint16(data[offset:], uint16(entry[0]))
		binary.LittleEndian.PutUint16(data[offset+2:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(data[offset+4:], entry[2])
	}
	return data
}

func powerDNSNativeAccessFile(path string, uid uint32, directory, grant bool) error {
	if uid == 0 {
		return ErrPowerDNSDatabaseOpen
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	privateMode, sharedMode, kind := uint32(0600), uint32(0660), uint32(unix.S_IFREG)
	if directory {
		privateMode, sharedMode, kind = 0700, 0710, unix.S_IFDIR
	}
	if stat.Uid != 0 || stat.Gid != 0 || stat.Mode&unix.S_IFMT != kind || (!directory && stat.Nlink != 1) {
		return ErrPowerDNSDatabaseOpen
	}
	want := powerDNSNativeACL(uid, directory)
	var acl [256]byte
	n, aclErr := unix.Fgetxattr(fd, "system.posix_acl_access", acl[:])
	if aclErr == nil {
		if stat.Mode&0777 != sharedMode || !bytes.Equal(acl[:n], want) {
			return ErrPowerDNSDatabaseOpen
		}
	} else {
		// SQLite can recreate root-owned sidecars with the database's mask.
		// The private parent denies root-group traversal; world access is denied.
		mode := stat.Mode & 0777
		if !errors.Is(aclErr, unix.ENODATA) || (mode != privateMode && (directory || (mode != 0640 && mode != 0660))) {
			return ErrPowerDNSDatabaseOpen
		}
	}
	if !grant {
		return nil
	}
	if err = unix.Fsetxattr(fd, "system.posix_acl_access", want, 0); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func preparePowerDNSNativeDatabaseAccess() error {
	uid, err := powerDNSNativeUID()
	if err != nil {
		return err
	}
	// Install file access first; expose directory traversal only when all three
	// existing files have passed validation. Missing sidecars fail closed.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err = powerDNSNativeAccessFile(LocalPowerDNSDatabasePath+suffix, uid, false, true); err != nil {
			return err
		}
	}
	return powerDNSNativeAccessFile(filepath.Dir(LocalPowerDNSDatabasePath), uid, true, true)
}

func validatePowerDNSNativeDatabaseFiles() error {
	for directory := filepath.Dir(LocalPowerDNSDatabasePath); ; directory = filepath.Dir(directory) {
		if err := validateRootOwnedPowerDNSDirectory(directory); err != nil {
			return err
		}
		if filepath.Dir(directory) == directory {
			break
		}
	}
	uid, err := powerDNSNativeUID()
	if err != nil {
		return err
	}
	if err = powerDNSNativeAccessFile(filepath.Dir(LocalPowerDNSDatabasePath), uid, true, false); err != nil {
		return err
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err = powerDNSNativeAccessFile(LocalPowerDNSDatabasePath+suffix, uid, false, false); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
