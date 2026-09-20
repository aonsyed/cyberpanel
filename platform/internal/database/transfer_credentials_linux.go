//go:build linux

package database

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// LinuxWorkspaceExportConfigs resolves credentials through an existing,
// generation-bound workspace session. It never supplies an administrator
// credential. Import into an isolated database requires its own authority and
// is deliberately not authorized by a read-only workspace session.
type LinuxWorkspaceExportConfigs struct {
	executor *LinuxMariaDBExecutor
	access   WorkspaceAccess
}

func NewLinuxWorkspaceExportConfigs(executor *LinuxMariaDBExecutor, access WorkspaceAccess) (*LinuxWorkspaceExportConfigs, error) {
	if executor == nil || executor.now == nil || executor.secrets == nil || os.Geteuid() != 0 || access.validate(executor.now().UTC()) != nil {
		return nil, ErrUnauthorized
	}
	return &LinuxWorkspaceExportConfigs{executor: executor, access: access}, nil
}

func (configs *LinuxWorkspaceExportConfigs) TransferClientConfig(ctx context.Context, job TransferJob, name SQLIdentifier) (TransferClientConfigDescriptor, error) {
	if configs == nil || configs.executor == nil || configs.executor.now == nil || configs.executor.secrets == nil || ctx == nil || job.Validate() != nil || job.Direction != TransferExport || name.IsZero() {
		return TransferClientConfigDescriptor{}, ErrUnauthorized
	}
	executor, access := configs.executor, configs.access
	session, database, principal, err := executor.authorizeWorkspaceExport(ctx, access, job)
	if err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	if database.Name != name {
		return TransferClientConfigDescriptor{}, ErrUnauthorized
	}
	releaseSlot, err := executor.acquireWorkspace(session)
	if err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	return configs.writeClientConfig(ctx, job, session, principal, name, releaseSlot)
}

func (executor *LinuxMariaDBExecutor) authorizeWorkspaceExport(ctx context.Context, access WorkspaceAccess, job TransferJob) (DatabaseWorkspaceSession, Database, DatabasePrincipal, error) {
	if executor == nil || executor.now == nil || os.Geteuid() != 0 || ctx == nil || job.Validate() != nil || job.Direction != TransferExport {
		return DatabaseWorkspaceSession{}, Database{}, DatabasePrincipal{}, ErrUnauthorized
	}
	if access.validate(executor.now().UTC()) != nil || job.TenantID != access.TenantID || job.SiteID != access.SiteID || job.DatabaseID != access.DatabaseID || job.DatabaseGeneration != access.DatabaseGeneration || job.Limits.MaximumBytes > access.Limits.MaxResultBytes || job.Limits.MaximumRows > uint64(access.Limits.MaxRows) || job.Limits.MaximumDuration > access.Limits.StatementTimeout {
		return DatabaseWorkspaceSession{}, Database{}, DatabasePrincipal{}, ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return DatabaseWorkspaceSession{}, Database{}, DatabasePrincipal{}, err
	}
	// Join protected resources under the same lock as executor mutations.
	executor.mu.Lock()
	session, database, principal, instance, err := executor.workspaceResources(ctx, access)
	executor.mu.Unlock()
	if err != nil {
		return session, database, principal, err
	}
	if database.InstanceID != job.InstanceID || !workspaceExportExecutorRecord(session.Metadata) || !workspaceExportExecutorRecord(database.Metadata) || !workspaceExportExecutorRecord(principal.Metadata) || !workspaceReady(instance.Metadata) {
		return session, database, principal, ErrUnauthorized
	}
	return session, database, principal, nil
}

// Applied executor records retain effect input metadata. Only the coordinator
// projects the successful receipt to Ready/InSync in its separate repository.
// Presence here follows native proof, but terminal/revoking states still deny
// access. Generation, tenant, expiry and disabled checks remain in workspaceResources.
func workspaceExportExecutorRecord(metadata Metadata) bool {
	if workspaceReady(metadata) {
		return true
	}
	if metadata.Status.Reconciliation != ReconciliationPending {
		return false
	}
	switch metadata.Status.Lifecycle {
	case LifecycleProvisioning, LifecycleUpdating, LifecycleReady:
		return true
	default:
		return false
	}
}

func (configs *LinuxWorkspaceExportConfigs) writeClientConfig(ctx context.Context, job TransferJob, session DatabaseWorkspaceSession, principal DatabasePrincipal, name SQLIdentifier, releaseSlot func()) (TransferClientConfigDescriptor, error) {
	keep := false
	defer func() {
		if !keep {
			releaseSlot()
		}
	}()
	executor, access := configs.executor, configs.access
	bounded, cancel := context.WithDeadline(ctx, access.ExpiresAt)
	defer cancel()
	password, err := executor.secrets.PrincipalPassword(bounded, session.SessionSecretRef, principal.ID, session.TenantID.String(), session.SiteID.String())
	defer wipeBytes(password)
	if err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	if len(password) == 0 || len(password) > maximumSecretBytes {
		return TransferClientConfigDescriptor{}, ErrUnauthorized
	}
	value, err := optionFileValue(password)
	if err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	if err = bounded.Err(); err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	root := strings.TrimSuffix(transferConfigDirectory, "/")
	if err = ensureRootDirectory(root, 0700); err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	if err = verifyPrivateTransferDirectory(root); err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	directory, err := os.MkdirTemp(root, "export-")
	if err != nil {
		return TransferClientConfigDescriptor{}, err
	}
	executor.mu.Lock()
	instance, err := executor.instance(job.InstanceID)
	executor.mu.Unlock()
	if err != nil || !workspaceReady(instance.Metadata) {
		_ = os.RemoveAll(directory)
		return TransferClientConfigDescriptor{}, ErrUnauthorized
	}
	transport, err := executor.workspaceTransportArguments(bounded, instance, directory)
	if err != nil {
		_ = os.RemoveAll(directory)
		return TransferClientConfigDescriptor{}, err
	}
	credential := []byte("[client]\nuser=" + principal.Name.String() + "\npassword=\"" + value + "\"\n")
	defer wipeBytes(credential)
	path := filepath.Join(directory, "client.cnf")
	if err = atomicRootFile(path, credential, 0600); err != nil {
		_ = os.RemoveAll(directory)
		return TransferClientConfigDescriptor{}, err
	}
	var once sync.Once
	var releaseErr error
	release := func() error {
		once.Do(func() { releaseErr = os.RemoveAll(directory); releaseSlot() })
		return releaseErr
	}
	keep = true
	expires := executor.now().UTC().Add(job.Limits.MaximumDuration)
	if access.ExpiresAt.Before(expires) {
		expires = access.ExpiresAt
	}
	return TransferClientConfigDescriptor{Path: path, Token: session.ID, Database: name, Direction: TransferExport, ReadOnly: true, ExpiresAt: expires, Release: release, transportArguments: transport}, nil
}

var _ MariaDBTransferClientConfigs = (*LinuxWorkspaceExportConfigs)(nil)
