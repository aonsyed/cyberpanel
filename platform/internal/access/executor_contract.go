package access

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ExecutorProtocolVersion is bumped whenever an executor operation or receipt
// changes incompatibly. Control and privileged processes reject mismatches.
const ExecutorProtocolVersion uint16 = 2

type ExecutorOperation string

const (
	ExecutorFileList                     ExecutorOperation = "access.file.list"
	ExecutorFileStat                     ExecutorOperation = "access.file.stat"
	ExecutorFileRead                     ExecutorOperation = "access.file.read"
	ExecutorFileCreate                   ExecutorOperation = "access.file.create"
	ExecutorFileReplace                  ExecutorOperation = "access.file.replace"
	ExecutorFileMove                     ExecutorOperation = "access.file.move"
	ExecutorFileCopy                     ExecutorOperation = "access.file.copy"
	ExecutorFileMetadata                 ExecutorOperation = "access.file.metadata"
	ExecutorFileSymlink                  ExecutorOperation = "access.file.symlink"
	ExecutorFileTrash                    ExecutorOperation = "access.file.trash"
	ExecutorFileRestore                  ExecutorOperation = "access.file.restore"
	ExecutorFilePurge                    ExecutorOperation = "access.file.purge"
	ExecutorFileArchive                  ExecutorOperation = "access.file.archive"
	ExecutorFileExtract                  ExecutorOperation = "access.file.extract"
	ExecutorUpload                       ExecutorOperation = "access.file.upload"
	ExecutorUploadAppend                 ExecutorOperation = "access.file.upload.append"
	ExecutorUploadCommit                 ExecutorOperation = "access.file.upload.commit"
	ExecutorUploadAbort                  ExecutorOperation = "access.file.upload.abort"
	ExecutorDownload                     ExecutorOperation = "access.file.download"
	ExecutorDownloadRead                 ExecutorOperation = "access.file.download.read"
	ExecutorDownloadClose                ExecutorOperation = "access.file.download.close"
	ExecutorFTPS                         ExecutorOperation = "access.ftps.apply"
	ExecutorFTPSRotate                   ExecutorOperation = "access.ftps.rotate"
	ExecutorFTPSEnable                   ExecutorOperation = "access.ftps.enable"
	ExecutorFTPSDelete                   ExecutorOperation = "access.ftps.delete"
	ExecutorSSHKey                       ExecutorOperation = "access.ssh.key"
	ExecutorSSHKeyRemove                 ExecutorOperation = "access.ssh.key.remove"
	ExecutorSSHGrant                     ExecutorOperation = "access.ssh.grant"
	ExecutorSSHGrantRemove               ExecutorOperation = "access.ssh.grant.remove"
	ExecutorMigrationPrincipalStage      ExecutorOperation = "access.migration.principal.stage"
	ExecutorMigrationPrincipalObserve    ExecutorOperation = "access.migration.principal.observe"
	ExecutorMigrationPrincipalsActivate  ExecutorOperation = "access.migration.principals.activate"
	ExecutorMigrationPrincipalCompensate ExecutorOperation = "access.migration.principal.compensate"
	ExecutorTerminalIssue                ExecutorOperation = "access.terminal.issue"
	ExecutorTerminalRevoke               ExecutorOperation = "access.terminal.revoke"
	ExecutorCronApply                    ExecutorOperation = "access.cron.apply"
	ExecutorCronRun                      ExecutorOperation = "access.cron.run"
	ExecutorCronCancel                   ExecutorOperation = "access.cron.cancel"
	ExecutorGitKey                       ExecutorOperation = "access.git.key"
	ExecutorGitKeyDelete                 ExecutorOperation = "access.git.key.delete"
	ExecutorGitRepository                ExecutorOperation = "access.git.repository"
	ExecutorGitInitialize                ExecutorOperation = "access.git.initialize"
	ExecutorGitDetach                    ExecutorOperation = "access.git.detach"
	ExecutorGitStatus                    ExecutorOperation = "access.git.status"
	ExecutorGitFetch                     ExecutorOperation = "access.git.fetch"
	ExecutorGitCheckout                  ExecutorOperation = "access.git.checkout"
	ExecutorGitPull                      ExecutorOperation = "access.git.pull"
	ExecutorGitCommit                    ExecutorOperation = "access.git.commit"
	ExecutorGitPush                      ExecutorOperation = "access.git.push"
	ExecutorGitLog                       ExecutorOperation = "access.git.log"
	ExecutorGitIgnore                    ExecutorOperation = "access.git.ignore"
	ExecutorGitDeployment                ExecutorOperation = "access.git.deployment"
	ExecutorGitPromote                   ExecutorOperation = "access.git.deployment.promote"
	ExecutorGitVerify                    ExecutorOperation = "access.git.deployment.verify"
	ExecutorGitRollback                  ExecutorOperation = "access.git.deployment.rollback"
	ExecutorGitDiscard                   ExecutorOperation = "access.git.deployment.discard"
	ExecutorStagingSync                  ExecutorOperation = "access.staging.sync"
	ExecutorStagingApply                 ExecutorOperation = "access.staging.apply"
	ExecutorStagingVerify                ExecutorOperation = "access.staging.verify"
	ExecutorStagingPromote               ExecutorOperation = "access.staging.promote"
	ExecutorStagingRollback              ExecutorOperation = "access.staging.rollback"
	ExecutorStagingRelease               ExecutorOperation = "access.staging.release"
)

func validAccessBrokerOperation(operation ExecutorOperation) bool {
	switch operation {
	case ExecutorFileList, ExecutorFileStat, ExecutorFileRead, ExecutorFileCreate, ExecutorFileReplace, ExecutorFileMove, ExecutorFileCopy, ExecutorFileMetadata, ExecutorFileSymlink, ExecutorFileTrash, ExecutorFileRestore, ExecutorFilePurge, ExecutorFileArchive, ExecutorFileExtract, ExecutorUpload, ExecutorUploadAppend, ExecutorUploadCommit, ExecutorUploadAbort, ExecutorDownload, ExecutorDownloadRead, ExecutorDownloadClose, ExecutorFTPS, ExecutorFTPSRotate, ExecutorFTPSEnable, ExecutorFTPSDelete, ExecutorSSHKey, ExecutorSSHKeyRemove, ExecutorSSHGrant, ExecutorSSHGrantRemove, ExecutorMigrationPrincipalStage, ExecutorMigrationPrincipalObserve, ExecutorMigrationPrincipalsActivate, ExecutorMigrationPrincipalCompensate, ExecutorTerminalIssue, ExecutorTerminalRevoke, ExecutorCronApply, ExecutorCronRun, ExecutorCronCancel, ExecutorGitKey, ExecutorGitKeyDelete, ExecutorGitRepository, ExecutorGitInitialize, ExecutorGitDetach, ExecutorGitStatus, ExecutorGitFetch, ExecutorGitCheckout, ExecutorGitPull, ExecutorGitCommit, ExecutorGitPush, ExecutorGitLog, ExecutorGitIgnore, ExecutorGitDeployment, ExecutorGitPromote, ExecutorGitVerify, ExecutorGitRollback, ExecutorGitDiscard, ExecutorStagingSync, ExecutorStagingApply, ExecutorStagingVerify, ExecutorStagingPromote, ExecutorStagingRollback, ExecutorStagingRelease:
		return true
	default:
		return false
	}
}

type ExecutorEnvelope struct {
	Version     uint16            `json:"version"`
	RequestID   string            `json:"request_id"`
	Operation   ExecutorOperation `json:"operation"`
	SiteID      SiteID            `json:"site_id"`
	Deadline    time.Time         `json:"deadline"`
	Payload     []byte            `json:"payload"`
	PayloadHash string            `json:"payload_hash"`
}

func (envelope ExecutorEnvelope) Validate(now time.Time) error {
	if envelope.Version != ExecutorProtocolVersion || !validID(envelope.RequestID) || envelope.Operation == "" || len(envelope.Payload) > 64<<20 || envelope.Deadline.Before(now) || envelope.Deadline.After(now.Add(10*time.Minute)) {
		return fmt.Errorf("invalid executor envelope")
	}
	if envelope.SiteID != "" {
		if err := requireID("site", string(envelope.SiteID)); err != nil {
			return err
		}
	}
	if deploymentPayloadDigest(envelope.Payload) != envelope.PayloadHash {
		return ErrIntegrity
	}
	return nil
}

type ExecutorResult struct {
	Version     uint16            `json:"version"`
	RequestID   string            `json:"request_id"`
	Operation   ExecutorOperation `json:"operation"`
	Succeeded   bool              `json:"succeeded"`
	Payload     []byte            `json:"payload,omitempty"`
	PayloadHash string            `json:"payload_hash,omitempty"`
	ErrorCode   string            `json:"error_code,omitempty"`
	Receipt     string            `json:"receipt"`
	CompletedAt time.Time         `json:"completed_at"`
}

func (result ExecutorResult) Validate(request ExecutorEnvelope, now time.Time) error {
	if result.Version != ExecutorProtocolVersion || result.RequestID != request.RequestID || result.Operation != request.Operation || result.Receipt == "" || result.CompletedAt.After(now.Add(time.Minute)) || result.CompletedAt.Before(request.Deadline.Add(-10*time.Minute)) {
		return ErrIntegrity
	}
	if result.Succeeded == (result.ErrorCode != "") {
		return ErrIntegrity
	}
	if result.Succeeded && deploymentPayloadDigest(result.Payload) != result.PayloadHash {
		return ErrIntegrity
	}
	if len(result.Payload) > 64<<20 {
		return ErrLimitExceeded
	}
	return nil
}

// ExecutorTransport is implemented by authenticated local RPC over a
// root-owned Unix socket. Implementations must authenticate peer credentials,
// cap request sizes, and bind each request to its deadline.
type ExecutorTransport interface {
	Execute(context.Context, ExecutorEnvelope) (ExecutorResult, error)
}

type ExecutorAuthorizer interface {
	Authorize(context.Context, ExecutorEnvelope) error
}

type ExecutorHandler interface {
	Handle(context.Context, ExecutorEnvelope) (ExecutorResult, error)
}

type ExecutorServer struct {
	Authorizer ExecutorAuthorizer
	Handler    ExecutorHandler
	Now        func() time.Time
}

func (server ExecutorServer) Dispatch(ctx context.Context, envelope ExecutorEnvelope) (ExecutorResult, error) {
	if server.Authorizer == nil || server.Handler == nil {
		return ExecutorResult{}, errors.New("executor authorizer and handler are required")
	}
	now := time.Now().UTC()
	if server.Now != nil {
		now = server.Now().UTC()
	}
	if err := envelope.Validate(now); err != nil {
		return ExecutorResult{}, err
	}
	if err := server.Authorizer.Authorize(ctx, envelope); err != nil {
		return ExecutorResult{}, ErrUnauthorized
	}
	result, err := server.Handler.Handle(ctx, envelope)
	if err != nil {
		return ExecutorResult{}, err
	}
	if err = result.Validate(envelope, now); err != nil {
		return ExecutorResult{}, err
	}
	return result, nil
}
