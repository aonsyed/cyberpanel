//go:build linux

package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeUploadRoundTrip(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_ACCESS") != "1" || os.Geteuid() != 0 {
		t.Skip("requires isolated root QEMU access fixture")
	}
	account, err := user.Lookup("cyberpanel-web")
	if err != nil {
		t.Fatal(err)
	}
	webID, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.MkdirTemp(LinuxAccessSitesRoot, "s-access-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(fixture) })
	generation := filepath.Join(fixture, "roots/g1")
	for _, suffix := range []string{"", "roots", "roots/g1", "roots/g1/releases", "roots/g1/releases/current", "roots/g1/releases/current/public", "roots/g1/private"} {
		path := filepath.Join(fixture, suffix)
		if err = os.MkdirAll(path, 0711); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(path, 0711); err != nil {
			t.Fatal(err)
		}
	}
	public := filepath.Join(generation, "releases/current/public")
	if err = os.Chmod(public, 0750); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(generation, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	acl := make([]byte, 44)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, e := range [][3]uint32{{1, 7, ^uint32(0)}, {2, 5, uint32(webID)}, {4, 0, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		offset := 4 + i*8
		binary.LittleEndian.PutUint16(acl[offset:], uint16(e[0]))
		binary.LittleEndian.PutUint16(acl[offset+2:], uint16(e[1]))
		binary.LittleEndian.PutUint32(acl[offset+4:], e[2])
	}
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		if err = unix.Setxattr(public, name, acl, 0); err != nil {
			t.Fatal(err)
		}
	}
	executor, _ := NewLinuxFileExecutor(LinuxSiteResolverFunc(func(context.Context, SiteID) (LinuxSiteBinding, error) {
		return LinuxSiteBinding{SiteKey: filepath.Base(fixture), Username: "access-test", UID: 61001, GID: 61001, Generation: 1}, nil
	}))
	ctx := context.Background()
	data := []byte("exact\x00bytes\xff\r\npublic upload\n")
	digest := sha256.Sum256(data)
	path, _ := ParseRelativePath("roundtrip.txt")
	destination := FileLocator{Root: SiteRoot{SiteID: "access-proof", Kind: RootPublic}, Path: path}
	upload := func(id UploadID, condition WriteCondition) (FileMutationReceipt, error) {
		session := UploadSession{ID: id, Destination: destination, Integrity: Integrity{Algorithm: "sha256", Digest: hex.EncodeToString(digest[:]), Size: int64(len(data))}, Condition: condition}
		session.Handle, err = executor.BeginUpload(ctx, session)
		if err != nil {
			t.Fatal(err)
		}
		if err = executor.AppendUpload(ctx, session.Handle, UploadChunk{Data: data}); err != nil {
			t.Fatal(err)
		}
		return executor.CommitUpload(ctx, session)
	}
	if _, err = upload("first", WriteCondition{IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	var uploaded syscall.Stat_t
	if err = syscall.Stat(filepath.Join(public, "roundtrip.txt"), &uploaded); err != nil || uploaded.Uid != 61001 || uploaded.Gid != 61001 || uploaded.Mode&0007 != 0 {
		t.Fatalf("upload must be site-owned without world access: %v", err)
	}
	readAs := func(uid uint32, path string) ([]byte, error) {
		cmd := exec.Command("/usr/bin/cat", path)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
		return cmd.Output()
	}
	if got, e := readAs(uint32(webID), filepath.Join(public, "roundtrip.txt")); e != nil || !bytes.Equal(got, data) {
		t.Fatalf("public upload unreadable or changed: %v", e)
	}
	if _, e := readAs(61002, filepath.Join(public, "roundtrip.txt")); e == nil {
		t.Fatal("unrelated tenant read public file")
	}
	if _, err = upload("collision", WriteCondition{IfNoneMatch: true}); !errors.Is(err, ErrConflict) {
		t.Fatalf("existing destination must conflict: %v", err)
	}
	renamed := destination
	renamed.Path, _ = ParseRelativePath("renamed.txt")
	if _, err = executor.Move(ctx, destination, renamed, WriteCondition{IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	lease, err := executor.OpenDownload(ctx, DownloadLease{Source: renamed})
	if err != nil {
		t.Fatal(err)
	}
	got, err := executor.ReadDownload(ctx, lease, 0, int64(len(data)))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("download mismatch: %v", err)
	}
	entry, _, err := executor.MoveToTrash(ctx, renamed, "trash-proof")
	if err != nil {
		t.Fatal(err)
	}
	entry.SiteID = renamed.Root.SiteID
	if _, err = os.Stat(filepath.Join(public, "renamed.txt")); !os.IsNotExist(err) {
		t.Fatal("trashed file remains public")
	}
	if _, e := readAs(uint32(webID), filepath.Join(generation, "private/access-trash/trash-proof")); e == nil {
		t.Fatal("web worker read private trash")
	}
	if _, err = executor.RestoreTrash(ctx, entry, renamed, WriteCondition{IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if got, e := readAs(uint32(webID), filepath.Join(public, "renamed.txt")); e != nil || !bytes.Equal(got, data) {
		t.Fatalf("restored public access changed: %v", e)
	}
	if err = os.Symlink("/etc/passwd", filepath.Join(public, "escape")); err != nil {
		t.Fatal(err)
	}
	escape := destination
	escape.Path, _ = ParseRelativePath("escape")
	if _, _, err = executor.ReadRange(ctx, escape, 0, 32); err == nil {
		t.Fatal("symlink read permitted")
	}
}
