//go:build linux

package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	hostOpenPath          = 0x200000
	hostResolveNoXDev     = 0x01
	hostResolveNoMagic    = 0x02
	hostResolveNoSymlinks = 0x04
	hostResolveBeneath    = 0x08
	hostSysOpenat2        = 437
)

type LinuxHostFilesystemRoot struct {
	ID   HostFilesystemRootID
	Path string
}

func DefaultLinuxHostFilesystemRoots() []LinuxHostFilesystemRoot {
	return []LinuxHostFilesystemRoot{
		{ID: HostFilesystemRootSystemConfiguration, Path: "/etc"},
		{ID: HostFilesystemRootSystemLogs, Path: "/var/log"},
	}
}

type linuxHostFilesystemRoot struct {
	path   string
	fd     int
	device uint64
}

type LinuxHostFilesystemBroker struct {
	roots   map[HostFilesystemRootID]linuxHostFilesystemRoot
	ordered []HostFilesystemRootID
}

var deniedHostFilesystemRoots = []string{
	"/boot",
	"/dev",
	"/etc/cyberpanel",
	"/etc/gshadow",
	"/etc/gshadow-",
	"/etc/letsencrypt",
	"/etc/pki/private",
	"/etc/shadow",
	"/etc/shadow-",
	"/etc/ssh",
	"/etc/ssl/private",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/lib",
	"/lib32",
	"/lib64",
	"/opt/cyberpanel",
	"/proc",
	"/root",
	"/run",
	"/sbin",
	"/sys",
	"/usr/bin",
	"/usr/lib",
	"/usr/lib32",
	"/usr/lib64",
	"/usr/libexec",
	"/usr/local/bin",
	"/usr/local/lib",
	"/usr/local/sbin",
	"/usr/sbin",
	"/var/lib/cyberpanel-auth",
	"/var/lib/cyberpanel-secrets",
	"/var/lib/cyberpanel/control/recovery",
	"/var/lib/cyberpanel/control/trust",
	"/var/lib/cyberpanel/sites",
	"/var/run",
}

func hostFilesystemPathWithin(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func deniedHostFilesystemPath(path string) bool {
	clean := filepath.Clean(path)
	for _, root := range deniedHostFilesystemRoots {
		if hostFilesystemPathWithin(clean, root) {
			return true
		}
	}
	return false
}

func NewLinuxHostFilesystemBroker(configured []LinuxHostFilesystemRoot) (*LinuxHostFilesystemBroker, error) {
	if len(configured) == 0 || len(configured) > 32 {
		return nil, ErrInvalidState
	}
	broker := &LinuxHostFilesystemBroker{roots: make(map[HostFilesystemRootID]linuxHostFilesystemRoot, len(configured))}
	for _, configuredRoot := range configured {
		if configuredRoot.ID.Validate() != nil || !filepath.IsAbs(configuredRoot.Path) || filepath.Clean(configuredRoot.Path) != configuredRoot.Path || configuredRoot.Path == "/" || deniedHostFilesystemPath(configuredRoot.Path) {
			broker.Close()
			return nil, ErrUnauthorized
		}
		if _, exists := broker.roots[configuredRoot.ID]; exists {
			broker.Close()
			return nil, ErrConflict
		}
		info, err := os.Lstat(configuredRoot.Path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			broker.Close()
			return nil, ErrInvalidPath
		}
		fd, err := syscall.Open(configuredRoot.Path, hostOpenPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			broker.Close()
			return nil, err
		}
		var stat syscall.Stat_t
		if err = syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			syscall.Close(fd)
			broker.Close()
			return nil, ErrInvalidPath
		}
		broker.roots[configuredRoot.ID] = linuxHostFilesystemRoot{path: configuredRoot.Path, fd: fd, device: uint64(stat.Dev)}
		broker.ordered = append(broker.ordered, configuredRoot.ID)
	}
	sort.Slice(broker.ordered, func(left, right int) bool { return broker.ordered[left] < broker.ordered[right] })
	return broker, nil
}

func (broker *LinuxHostFilesystemBroker) Close() error {
	if broker == nil {
		return nil
	}
	var result error
	for id, root := range broker.roots {
		if err := syscall.Close(root.fd); err != nil {
			result = errors.Join(result, err)
		}
		delete(broker.roots, id)
	}
	broker.ordered = nil
	return result
}

func (broker *LinuxHostFilesystemBroker) AllowedRoots() []HostFilesystemRootID {
	if broker == nil {
		return nil
	}
	return append([]HostFilesystemRootID(nil), broker.ordered...)
}

type hostOpenHow struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

func hostOpenat2(root int, relative string, flags int) (int, error) {
	if relative == "" {
		relative = "."
	}
	pointer, err := syscall.BytePtrFromString(relative)
	if err != nil {
		return -1, ErrInvalidPath
	}
	how := hostOpenHow{
		Flags: uint64(flags | syscall.O_CLOEXEC | syscall.O_NOFOLLOW),
		Resolve: hostResolveNoXDev | hostResolveNoMagic | hostResolveNoSymlinks | hostResolveBeneath,
	}
	fd, _, errno := syscall.Syscall6(hostSysOpenat2, uintptr(root), uintptr(unsafe.Pointer(pointer)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if errno != 0 {
		return -1, hostFilesystemOpenError(errno)
	}
	return int(fd), nil
}

func hostFilesystemOpenError(err error) error {
	switch {
	case errors.Is(err, syscall.ENOENT):
		return ErrNotFound
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.EXDEV), errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES), errors.Is(err, syscall.ENXIO):
		return ErrUnauthorized
	case errors.Is(err, syscall.ENOSYS), errors.Is(err, syscall.E2BIG):
		return ErrInvalidState
	default:
		return err
	}
}

func (broker *LinuxHostFilesystemBroker) resolve(rootID HostFilesystemRootID, path HostFilesystemPath, flags int) (linuxHostFilesystemRoot, int, error) {
	if broker == nil || rootID.Validate() != nil {
		return linuxHostFilesystemRoot{}, -1, ErrUnauthorized
	}
	root, exists := broker.roots[rootID]
	if !exists {
		return linuxHostFilesystemRoot{}, -1, ErrUnauthorized
	}
	canonical, err := ParseHostFilesystemPath(path.String())
	if err != nil || canonical.String() != path.String() {
		return linuxHostFilesystemRoot{}, -1, ErrInvalidPath
	}
	absolute := root.path
	if !path.IsRoot() {
		absolute = filepath.Join(root.path, filepath.FromSlash(path.String()))
	}
	if !hostFilesystemPathWithin(absolute, root.path) || deniedHostFilesystemPath(absolute) {
		return linuxHostFilesystemRoot{}, -1, ErrUnauthorized
	}
	fd, err := hostOpenat2(root.fd, path.String(), flags)
	if err != nil {
		return linuxHostFilesystemRoot{}, -1, err
	}
	return root, fd, nil
}

func hostFilesystemEntryFromStat(root HostFilesystemRootID, path HostFilesystemPath, stat syscall.Stat_t) (HostFilesystemEntry, error) {
	kind := EntryRegular
	switch stat.Mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		if stat.Mode&0111 != 0 || stat.Nlink != 1 {
			return HostFilesystemEntry{}, ErrUnauthorized
		}
	case syscall.S_IFDIR:
		kind = EntryDirectory
	case syscall.S_IFLNK:
		return HostFilesystemEntry{}, ErrUnauthorized
	default:
		return HostFilesystemEntry{}, ErrUnauthorized
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strconv.FormatUint(uint64(stat.Dev), 10), strconv.FormatUint(stat.Ino, 10),
		strconv.FormatInt(stat.Size, 10), strconv.FormatInt(stat.Mtim.Sec, 10),
		strconv.FormatInt(stat.Mtim.Nsec, 10), strconv.FormatUint(uint64(stat.Mode), 10),
	}, ":")))
	return HostFilesystemEntry{
		Root: root, Path: path, Kind: kind, Size: stat.Size, Mode: uint32(stat.Mode & 0777),
		UID: stat.Uid, GID: stat.Gid, ModifiedAt: time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec).UTC(), ETag: hex.EncodeToString(sum[:]),
	}, nil
}

func (broker *LinuxHostFilesystemBroker) Stat(ctx context.Context, rootID HostFilesystemRootID, path HostFilesystemPath) (HostFilesystemEntry, error) {
	if ctx == nil {
		return HostFilesystemEntry{}, ErrInvalidState
	}
	root, fd, err := broker.resolve(rootID, path, hostOpenPath)
	if err != nil {
		return HostFilesystemEntry{}, err
	}
	defer syscall.Close(fd)
	if err = ctx.Err(); err != nil {
		return HostFilesystemEntry{}, err
	}
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil {
		return HostFilesystemEntry{}, err
	}
	if uint64(stat.Dev) != root.device {
		return HostFilesystemEntry{}, ErrUnauthorized
	}
	entry, err := hostFilesystemEntryFromStat(rootID, path, stat)
	if err != nil {
		return HostFilesystemEntry{}, ErrUnauthorized
	}
	return entry, nil
}

func (broker *LinuxHostFilesystemBroker) List(ctx context.Context, rootID HostFilesystemRootID, directory HostFilesystemPath, page HostFilesystemPageRequest) (HostFilesystemPage, error) {
	if ctx == nil {
		return HostFilesystemPage{}, ErrInvalidState
	}
	page, err := page.normalized()
	if err != nil {
		return HostFilesystemPage{}, err
	}
	root, fd, err := broker.resolve(rootID, directory, syscall.O_RDONLY|syscall.O_DIRECTORY)
	if err != nil {
		return HostFilesystemPage{}, err
	}
	file := os.NewFile(uintptr(fd), "host-filesystem-list")
	defer file.Close()
	infos, err := file.Readdir(-1)
	if err != nil {
		return HostFilesystemPage{}, err
	}
	sort.Slice(infos, func(left, right int) bool { return infos[left].Name() < infos[right].Name() })
	entries := make([]HostFilesystemEntry, 0, int(page.Limit)+1)
	for _, info := range infos {
		if err = ctx.Err(); err != nil {
			return HostFilesystemPage{}, err
		}
		if info.Name() <= page.Cursor {
			continue
		}
		child, parseErr := directory.Join(info.Name())
		if parseErr != nil {
			continue
		}
		absolute := filepath.Join(root.path, filepath.FromSlash(child.String()))
		if deniedHostFilesystemPath(absolute) {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint64(stat.Dev) != root.device {
			continue
		}
		entry, entryErr := hostFilesystemEntryFromStat(rootID, child, *stat)
		if entryErr != nil {
			continue
		}
		entries = append(entries, entry)
		if len(entries) > int(page.Limit) {
			break
		}
	}
	result := HostFilesystemPage{Entries: entries}
	if len(result.Entries) > int(page.Limit) {
		result.Entries = result.Entries[:page.Limit]
		result.NextCursor = result.Entries[len(result.Entries)-1].Path.String()
		if slash := strings.LastIndexByte(result.NextCursor, '/'); slash >= 0 {
			result.NextCursor = result.NextCursor[slash+1:]
		}
	}
	return result, nil
}

func (broker *LinuxHostFilesystemBroker) Read(ctx context.Context, rootID HostFilesystemRootID, path HostFilesystemPath, offset, length int64) (HostFilesystemRead, error) {
	if ctx == nil || path.IsRoot() || offset < 0 || length <= 0 || length > MaximumHostFilesystemReadBytes {
		return HostFilesystemRead{}, ErrLimitExceeded
	}
	root, fd, err := broker.resolve(rootID, path, syscall.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return HostFilesystemRead{}, err
	}
	defer syscall.Close(fd)
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil {
		return HostFilesystemRead{}, err
	}
	if uint64(stat.Dev) != root.device || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&0111 != 0 || stat.Nlink != 1 {
		return HostFilesystemRead{}, ErrUnauthorized
	}
	if offset > stat.Size {
		return HostFilesystemRead{}, ErrInvalidState
	}
	if length > stat.Size-offset {
		length = stat.Size - offset
	}
	content := make([]byte, int(length))
	read := 0
	for read < len(content) {
		if err = ctx.Err(); err != nil {
			for index := range content {
				content[index] = 0
			}
			return HostFilesystemRead{}, err
		}
		count, readErr := syscall.Pread(fd, content[read:], offset+int64(read))
		if readErr != nil {
			for index := range content {
				content[index] = 0
			}
			return HostFilesystemRead{}, readErr
		}
		if count == 0 {
			break
		}
		read += count
	}
	content = content[:read]
	entry, err := hostFilesystemEntryFromStat(rootID, path, stat)
	if err != nil {
		return HostFilesystemRead{}, err
	}
	sum := sha256.Sum256(content)
	return HostFilesystemRead{Entry: entry, Offset: offset, Content: content, SHA256: hex.EncodeToString(sum[:]), EOF: offset+int64(read) >= stat.Size}, nil
}

var _ HostFilesystemBroker = (*LinuxHostFilesystemBroker)(nil)
