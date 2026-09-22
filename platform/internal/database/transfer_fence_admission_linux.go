//go:build linux

package database

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Only operations holding the admission lock may issue this capability. It is
// never serialized or accepted from a broker/API request.
type transferFenceMutationAuthority struct{}

func transferFenceAdmissionLock(exclusive bool) (func(), error) {
	root := filepath.Join(mariaDBStateRoot, "transfer-fences")
	if err := ensureRootDirectory(root, 0700); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(root, "admission.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err = syscall.Flock(fd, mode|syscall.LOCK_NB); err != nil {
		syscall.Close(fd)
		return nil, ErrConflict
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = syscall.Close(fd) }, nil
}

// Serialize panel native mutations with fence acquisition and recovery. While
// any local fence is active, conservatively refuse other native management
// mutations; normal application connections are fenced by ACCOUNT LOCK instead.
func (executor *LinuxMariaDBExecutor) guardTransferFenceMutation(ctx context.Context, statement mariaDBStatement) (func(), error) {
	if owned, _ := ctx.Value(transferFenceMutationAuthority{}).(bool); owned {
		return func() {}, nil
	}
	switch statement {
	case sqlObserveTransferPrograms:
		return func() {}, nil
	case sqlObserveStatus, sqlObserveDatabase, sqlObservePrincipal, sqlObserveGrants, sqlObserveTuning, sqlObserveHA, sqlObserveNativePrincipal, sqlObserveDataDirectory, sqlObserveImportTables, sqlObserveImportSchema, sqlObserveImportView, sqlObserveImportViewColumns, sqlCountImportRows, sqlCheckImportTable, sqlTransferFenceIdentity, sqlTransferFenceAudit, sqlTransferFenceAccount, sqlTransferFenceGrants, sqlTransferFenceSessions, sqlTransferFenceReplication:
		return func() {}, nil
	}
	unlock, err := transferFenceAdmissionLock(false)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(mariaDBStateRoot, "transfer-fences"))
	if err != nil {
		unlock()
		return nil, err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var record transferWriterFence
		if err := executor.readNamed("transfer-fences", entry.Name(), &record); err != nil || record.Database.Validate() != nil || record.State != "released" {
			unlock()
			return nil, ErrConflict
		}
	}
	return unlock, nil
}
