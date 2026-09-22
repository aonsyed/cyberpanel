//go:build linux

package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func (executor *LinuxFileExecutor) CommitUpload(ctx context.Context, session UploadSession) (FileMutationReceipt, error) {
	site, leaf, err := parseUploadHandle(session.Handle)
	if err != nil || site != session.Destination.Root.SiteID {
		return FileMutationReceipt{}, ErrUnauthorized
	}
	directory, _, err := executor.ensurePrivateDir(ctx, site, RootPrivate, "access-uploads")
	if err != nil {
		return FileMutationReceipt{}, err
	}
	defer syscall.Close(directory)
	fd, err := syscall.Openat(directory, leaf, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return FileMutationReceipt{}, err
	}
	source := os.NewFile(uintptr(fd), "access-upload")
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return FileMutationReceipt{}, ErrInvalidPath
	}
	root, binding, err := executor.openRoot(ctx, session.Destination.Root)
	if err != nil {
		return FileMutationReceipt{}, err
	}
	defer syscall.Close(root)
	parent, target, err := parentLinux(root, session.Destination.Path)
	if err != nil {
		return FileMutationReceipt{}, err
	}
	defer syscall.Close(parent)
	existing, statErr := statLinux(parent, target, session.Destination.Path)
	if statErr != nil && !errors.Is(statErr, ErrNotFound) {
		return FileMutationReceipt{}, statErr
	}
	if err = checkCondition(existing, statErr == nil, session.Condition); err != nil {
		return FileMutationReceipt{}, err
	}
	temporary, err := randomLinuxLeaf(".access-upload-")
	if err != nil {
		return FileMutationReceipt{}, err
	}
	// Creation under the destination inherits its default ACL. Renaming the
	// private 0600 staging inode here would bypass public-tree inheritance.
	mode := uint32(0640)
	outputFD, err := syscall.Openat(parent, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return FileMutationReceipt{}, err
	}
	output := os.NewFile(uintptr(outputFD), "access-upload-publish")
	defer output.Close()
	defer unix.Unlinkat(parent, temporary, 0)
	if err = applyOwnership(outputFD, FileMetadata{Mode: mode, Ownership: OwnershipSiteUser}, binding); err != nil {
		return FileMutationReceipt{}, err
	}
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(source, session.Integrity.Size+1))
	if err != nil {
		return FileMutationReceipt{}, err
	}
	if size != session.Integrity.Size || hex.EncodeToString(hash.Sum(nil)) != session.Integrity.Digest {
		return FileMutationReceipt{}, ErrIntegrity
	}
	if err = output.Sync(); err != nil {
		return FileMutationReceipt{}, err
	}
	if err = ctx.Err(); err != nil {
		return FileMutationReceipt{}, err
	}
	if session.Condition.IfNoneMatch {
		err = unix.Renameat2(parent, temporary, parent, target, unix.RENAME_NOREPLACE)
		if errors.Is(err, syscall.EEXIST) {
			err = ErrConflict
		}
	} else {
		err = syscall.Renameat(parent, temporary, parent, target)
	}
	if err != nil {
		return FileMutationReceipt{}, err
	}
	if err = syscall.Fsync(parent); err != nil {
		return FileMutationReceipt{}, err
	}
	if err = unix.Unlinkat(directory, leaf, 0); err != nil {
		return FileMutationReceipt{}, err
	}
	entry, err := statLinux(parent, target, session.Destination.Path)
	return mutationReceipt(entry), err
}
