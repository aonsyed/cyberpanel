//go:build linux

package database

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Root-only native building blocks. The transfer broker enforces a closed
// command, source-artifact ownership and execution admission before dispatch.
type isolatedTransferRecord struct {
	Views           []transferNativeView     `json:"views,omitempty"`
	PromotionCommit *transferPromotionCommit `json:"promotion_commit,omitempty"`
	Process         *TransferProcessReceipt  `json:"process,omitempty"`
	Promotion       *TransferPromotion       `json:"promotion,omitempty"`
	Verification    *TransferVerification    `json:"verification,omitempty"`
	Job             TransferJob              `json:"job"`
	Target          Database                 `json:"target"`
	Isolated        IsolatedTransferDatabase `json:"isolated"`
	State           string                   `json:"state"`
}

func (executor *LinuxMariaDBExecutor) transferImportSource(job TransferJob) (Database, error) {
	if executor == nil || executor.now == nil || os.Geteuid() != 0 || job.Validate() != nil || job.Direction != TransferImport {
		return Database{}, ErrUnauthorized
	}
	var source Database
	if err := executor.readResource("databases", job.DatabaseID, &source); err != nil {
		return source, err
	}
	if source.Validate() != nil || source.TenantID != job.TenantID || source.SiteID != job.SiteID || source.Generation != job.DatabaseGeneration || source.InstanceID != job.InstanceID || !workspaceExportExecutorRecord(source.Metadata) {
		return source, ErrUnauthorized
	}
	instance, err := executor.instance(source.InstanceID)
	if err != nil || instance.Placement != PlacementLocal || !workspaceReady(instance.Metadata) {
		return source, ErrUnauthorized
	}
	return source, nil
}

func isolatedTransferIdentity(job TransferJob) (ResourceID, SQLIdentifier) {
	token := transferDigest([]byte(job.Digest))[:24]
	id, _ := NewResourceID("import-" + token)
	// No SQL grant-pattern characters in isolated names (not even underscore).
	name, _ := ParseSQLIdentifier("cpimp" + token)
	return id, name
}

func (executor *LinuxMariaDBExecutor) allocateTransferImport(ctx context.Context, job TransferJob) (IsolatedTransferDatabase, error) {
	if executor == nil || ctx == nil {
		return IsolatedTransferDatabase{}, ErrUnauthorized
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	source, err := executor.transferImportSource(job)
	if err != nil {
		return IsolatedTransferDatabase{}, err
	}
	ctx, release, err := executor.beginWriterMutation(ctx)
	if err != nil {
		return IsolatedTransferDatabase{}, err
	}
	defer release()
	if err := ensureRootDirectory(filepath.Join(mariaDBStateRoot, "transfer-imports"), 0700); err != nil {
		return IsolatedTransferDatabase{}, err
	}
	id, name := isolatedTransferIdentity(job)
	var prior isolatedTransferRecord
	if err := executor.readResource("transfer-imports", id, &prior); err == nil {
		if prior.Job.Digest != job.Digest || prior.State != "allocated" || prior.Target.ID != id || prior.Target.Name != name || prior.Isolated.Validate(job) != nil {
			return IsolatedTransferDatabase{}, ErrAmbiguous
		}
		return prior.Isolated, nil
	} else if !errors.Is(err, ErrNotFound) {
		return IsolatedTransferDatabase{}, err
	}
	target := source
	target.ID, target.Name, target.Generation = id, name, 1
	isolated := IsolatedTransferDatabase{Token: id, InstanceID: job.InstanceID, Name: name, SourceDatabaseID: job.DatabaseID, SourceGeneration: job.DatabaseGeneration, CreatedAt: executor.now().UTC()}
	instance, err := executor.instance(job.InstanceID)
	if err != nil {
		return isolated, err
	}
	connection, closeConnection, err := executor.connection(ctx, instance)
	if err != nil {
		return isolated, err
	}
	defer closeConnection()
	dataDirectory, err := connection.query(ctx, sqlObserveDataDirectory)
	if err != nil {
		return isolated, err
	}
	dataPath := strings.TrimSpace(string(dataDirectory))
	if !filepath.IsAbs(dataPath) || strings.ContainsAny(dataPath, "\n\r\t") {
		return isolated, ErrInvalidResource
	}
	var disk syscall.Statfs_t
	if err := syscall.Statfs(dataPath, &disk); err != nil {
		return isolated, err
	}
	if disk.Bavail*uint64(disk.Bsize) < job.Limits.MaximumBytes+(2<<30) {
		return isolated, ErrTransferLimit
	}
	observed, err := connection.query(ctx, sqlObserveDatabase, target)
	if err != nil {
		return isolated, err
	}
	if len(strings.TrimSpace(string(observed))) != 0 {
		return isolated, ErrConflict
	}
	record := isolatedTransferRecord{Job: job, Target: target, Isolated: isolated, State: "creating"}
	if err = executor.writeResource("transfer-imports", id, record); err != nil {
		return isolated, err
	}
	proof, err := connection.query(ctx, sqlCreateDatabase, target)
	if err != nil || len(strings.TrimSpace(string(proof))) == 0 {
		return isolated, ErrAmbiguous
	}
	record.State = "allocated"
	if err = executor.writeResource("transfer-imports", id, record); err != nil {
		return isolated, err
	}
	return isolated, nil
}

func (executor *LinuxMariaDBExecutor) loadTransferImport(job TransferJob, isolated IsolatedTransferDatabase) (isolatedTransferRecord, error) {
	id, name := isolatedTransferIdentity(job)
	var record isolatedTransferRecord
	if job.Validate() != nil || job.Direction != TransferImport || isolated.Validate(job) != nil || isolated.Token != id || isolated.Name != name {
		return record, ErrUnauthorized
	}
	if err := executor.readResource("transfer-imports", id, &record); err != nil {
		return record, err
	}
	if record.Job.Validate() != nil || record.Job.Digest != job.Digest || record.Isolated != isolated || record.Target.Validate() != nil || record.Target.ID != id || record.Target.Name != name || record.Target.Generation != 1 || record.Target.TenantID != job.TenantID || record.Target.SiteID != job.SiteID || record.Target.InstanceID != job.InstanceID {
		return record, ErrUnauthorized
	}
	return record, nil
}

type isolatedImportConfigs struct {
	executor *LinuxMariaDBExecutor
	isolated IsolatedTransferDatabase
}

func (configs isolatedImportConfigs) TransferClientConfig(ctx context.Context, job TransferJob, name SQLIdentifier) (TransferClientConfigDescriptor, error) {
	executor := configs.executor
	if executor == nil || ctx == nil || name != configs.isolated.Name {
		return TransferClientConfigDescriptor{}, ErrUnauthorized
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if _, err := executor.transferImportSource(job); err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	record, err := executor.loadTransferImport(job, configs.isolated)
	if err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	if record.State != "allocated" {
		return TransferClientConfigDescriptor{}, ErrConflict
	}
	bounded, cancel := context.WithDeadline(ctx, job.Source.ExpiresAt)
	bounded, releaseGate, err := executor.beginWriterMutation(bounded)
	if err != nil {
		cancel()
		return TransferClientConfigDescriptor{}, err
	}
	keep := false
	defer func() {
		if !keep {
			releaseGate()
			cancel()
		}
	}()
	// Persist claim before issuing credentials: concurrent/replayed imports must
	// never share or replace an in-use loader. A crash requires qualified
	// recovery before reuse; ambiguous creation is never silently adopted.
	record.State = "loading"
	if err = executor.writeResource("transfer-imports", record.Target.ID, record); err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	principal, password, err := executor.createScopedMigrationLoader(bounded, record.Target, true)
	defer wipeBytes(password)
	if err != nil {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		cleanupErr := executor.cleanupMigrationLoader(cleanup, record.Target.ID)
		if cleanupErr == nil {
			record.State = "closed"
			cleanupErr = executor.writeResource("transfer-imports", record.Target.ID, record)
		}
		return TransferClientConfigDescriptor{}, errors.Join(err, cleanupErr)
	}
	var once sync.Once
	var releaseErr error
	path := ""
	release := func() error {
		once.Do(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			executor.mu.Lock()
			defer executor.mu.Unlock()
			if path != "" {
				releaseErr = os.Remove(path)
				if os.IsNotExist(releaseErr) {
					releaseErr = nil
				}
			}
			releaseErr = errors.Join(releaseErr, executor.cleanupMigrationLoader(cleanup, record.Target.ID))
			if releaseErr == nil {
				record.State = "closed"
				releaseErr = executor.writeResource("transfer-imports", record.Target.ID, record)
			}
			releaseGate()
			cancel()
		})
		return releaseErr
	}
	// Error cleanup runs while this method already holds the executor mutex.
	cleanupFailed := func() error {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		cleanupErr := executor.cleanupMigrationLoader(cleanup, record.Target.ID)
		if path != "" {
			removeErr := os.Remove(path)
			if !os.IsNotExist(removeErr) {
				cleanupErr = errors.Join(cleanupErr, removeErr)
			}
		}
		if cleanupErr == nil {
			record.State = "closed"
			cleanupErr = executor.writeResource("transfer-imports", record.Target.ID, record)
		}
		return cleanupErr
	}
	if err = ensureRootDirectory(strings.TrimSuffix(transferConfigDirectory, "/"), 0700); err != nil {
		return TransferClientConfigDescriptor{}, errors.Join(err, cleanupFailed())
	}
	value, err := optionFileValue(password)
	if err != nil {
		return TransferClientConfigDescriptor{}, errors.Join(err, cleanupFailed())
	}
	file, err := os.CreateTemp(transferConfigDirectory, "import-*.cnf")
	if err != nil {
		return TransferClientConfigDescriptor{}, errors.Join(err, cleanupFailed())
	}
	path = file.Name()
	payload := []byte("[client]\nuser=" + principal.Name.String() + "\npassword=\"" + value + "\"\nlocal-infile=0\n")
	_, err = file.Write(payload)
	wipeBytes(payload)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return TransferClientConfigDescriptor{}, errors.Join(err, cleanupFailed())
	}
	keep = true
	expires := executor.now().UTC().Add(job.Limits.MaximumDuration)
	if job.Source.ExpiresAt.Before(expires) {
		expires = job.Source.ExpiresAt
	}
	return TransferClientConfigDescriptor{Path: path, Token: principal.ID, Database: name, Direction: TransferImport, ExpiresAt: expires, Context: bounded, Release: release}, nil
}

func (executor *LinuxMariaDBExecutor) discardTransferImport(ctx context.Context, job TransferJob, isolated IsolatedTransferDatabase) error {
	if executor == nil || ctx == nil || os.Geteuid() != 0 {
		return ErrUnauthorized
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	record, err := executor.loadTransferImport(job, isolated)
	if err != nil {
		return err
	}
	if record.State == "creating" {
		return ErrAmbiguous
	}
	if record.State != "allocated" && record.State != "closed" && record.State != "verified" && record.State != "discarding" {
		return ErrConflict
	}
	ctx, release, err := executor.beginWriterMutation(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err = executor.cleanupMigrationLoader(ctx, record.Target.ID); err != nil {
		return err
	}
	record.State = "discarding"
	if err = executor.writeResource("transfer-imports", record.Target.ID, record); err != nil {
		return err
	}
	instance, err := executor.instance(job.InstanceID)
	if err != nil {
		return err
	}
	connection, closeConnection, err := executor.connection(ctx, instance)
	if err != nil {
		return err
	}
	defer closeConnection()
	observed, err := connection.query(ctx, sqlObserveDatabase, record.Target)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(observed))) != 0 {
		proof, err := connection.query(ctx, sqlDropDatabase, record.Target)
		if err != nil || len(strings.TrimSpace(string(proof))) != 0 {
			return ErrAmbiguous
		}
	}
	return executor.removeResource("transfer-imports", record.Target.ID)
}
