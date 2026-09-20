//go:build linux

package mail

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"

	"golang.org/x/sys/unix"
)

func mailServiceUID(gid uint32) (uint32, error) {
	if gid == 0 {
		return 0, ErrInvalidCommand
	}
	group, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		return 0, err
	}
	account, err := user.Lookup(group.Name)
	if err != nil || account.Gid != group.Gid {
		return 0, ErrInvalidCommand
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return 0, ErrInvalidCommand
	}
	return uint32(uid), nil
}

// All bytes and ownership remain root-controlled. A daemon can read only its
// own role subtree; top-level access is traverse-only, never create or list.
func (host *LinuxMailHost) prepareNativeConfigAccess(id, digest string) error {
	if host == nil || host.Store == nil || host.Store.Root != MailConfigurationRoot || host.Ownership.Validate() != nil {
		return ErrInvalidCommand
	}
	if _, err := host.Store.Verify(id, digest); err != nil {
		return err
	}
	owners := map[string]uint32{"postfix": host.Ownership.PostfixGID, "dovecot": host.Ownership.DovecotGID, "rspamd": host.Ownership.RspamdGID, "opendkim": host.Ownership.OpenDKIMGID, "redis": host.Ownership.RedisGID, "clamav": host.Ownership.ClamAVGID}
	all := make([]uint32, 0, len(owners))
	for role, gid := range owners {
		uid, err := mailServiceUID(gid)
		if err != nil {
			return err
		}
		all = append(all, uid)
		root := filepath.Join(MailConfigurationRoot, "generations", id, role)
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return ErrInvalidCommand
			}
			if entry.IsDir() {
				return grantMailReadAccess(path, 0550, []uint32{uid}, 5, true)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	postfix, err := mailServiceUID(host.Ownership.PostfixGID)
	if err != nil {
		return err
	}
	if err := prepareMailFallbackAccess(postfix); err != nil {
		return err
	}
	if err := grantMailReadAccess(filepath.Join(MailConfigurationRoot, "generations"), 0750, all, 1, true); err != nil {
		return err
	}
	return grantMailReadAccess(MailConfigurationRoot, 0750, all, 1, true)
}

func mailReadACL(mode uint32, uids []uint32, permission uint32) ([]byte, error) {
	uids = append([]uint32(nil), uids...)
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	entries := [][3]uint32{{1, (mode >> 6) & 7, ^uint32(0)}}
	for index, uid := range uids {
		if uid == 0 || (index > 0 && uid == uids[index-1]) {
			return nil, ErrInvalidCommand
		}
		entries = append(entries, [3]uint32{2, permission, uid})
	}
	entries = append(entries, [3]uint32{4, (mode >> 3) & 7, ^uint32(0)}, [3]uint32{16, ((mode >> 3) & 7) | permission, ^uint32(0)}, [3]uint32{32, mode & 7, ^uint32(0)})
	data := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(data, 2)
	for index, entry := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(data[offset:], uint16(entry[0]))
		binary.LittleEndian.PutUint16(data[offset+2:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(data[offset+4:], entry[2])
	}
	return data, nil
}

func grantMailReadAccess(path string, mode uint32, uids []uint32, permission uint32, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(uids) == 0 || len(uids) > 6 || !(directory && ((mode == 0750 && permission == 1) || (mode == 0550 && permission == 5)) || !directory && mode == 0440 && permission == 4) {
		return ErrInvalidCommand
	}
	want, err := mailReadACL(mode, uids, permission)
	if err != nil {
		return err
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		var metadata unix.Stat_t
		if err := unix.Lstat(parent, &metadata); err != nil {
			return err
		}
		if metadata.Uid != 0 || metadata.Mode&unix.S_IFMT != unix.S_IFDIR || metadata.Mode&0022 != 0 {
			return ErrInvalidCommand
		}
		if parent == "/" {
			break
		}
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
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	kind := uint32(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	actual := stat.Mode & 0777
	if stat.Uid != 0 || stat.Gid != 0 || stat.Mode&unix.S_IFMT != kind || (!directory && stat.Nlink != 1) {
		return ErrInvalidCommand
	}
	// Fresh store directories inherit the process umask. Only their initial
	// root-owned initial forms are normalized; role directories stay immutable.
	if actual != mode && !(directory && mode == 0750 && (actual == 0700 || actual == 0755)) {
		return ErrInvalidCommand
	}
	var acl [256]byte
	n, aclErr := unix.Fgetxattr(fd, "system.posix_acl_access", acl[:])
	if aclErr == nil {
		if actual != mode || !bytes.Equal(acl[:n], want) {
			return ErrInvalidCommand
		}
	} else if !errors.Is(aclErr, unix.ENODATA) {
		return aclErr
	}
	if err := unix.Fsetxattr(fd, "system.posix_acl_access", want, 0); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func prepareMailFallbackAccess(postfix uint32) error {
	const consumer = "/var/lib/cyberpanel/certificates/consumers/mail/default"
	const generations = "/var/lib/cyberpanel/certificates/generations/mail/default"
	var metadata unix.Stat_t
	if err := unix.Lstat(MailConfigurationRoot+"/tls/default", &metadata); err != nil || metadata.Uid != 0 || metadata.Mode&unix.S_IFMT != unix.S_IFLNK {
		return ErrInvalidCommand
	}
	binding, err := os.Readlink(MailConfigurationRoot + "/tls/default")
	if err != nil || binding != consumer+"/current" {
		return ErrInvalidCommand
	}
	if err := unix.Lstat(consumer+"/current", &metadata); err != nil || metadata.Uid != 0 || metadata.Mode&unix.S_IFMT != unix.S_IFLNK {
		return ErrInvalidCommand
	}
	target, err := os.Readlink(consumer + "/current")
	if err != nil || filepath.Clean(target) != target || filepath.Dir(target) != generations {
		return ErrInvalidCommand
	}
	for _, path := range []string{MailConfigurationRoot + "/tls", consumer, target} {
		if err := grantMailReadAccess(path, 0750, []uint32{postfix}, 1, true); err != nil {
			return err
		}
	}
	for _, name := range []string{"fullchain.pem", "private.key"} {
		if err := grantMailReadAccess(filepath.Join(target, name), 0440, []uint32{postfix}, 4, false); err != nil {
			return err
		}
	}
	return nil
}
