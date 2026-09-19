package access

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
)

type AccessExecutorSet struct {
	Files       FileExecutor
	Credentials CredentialExecutor
	Migration   MigrationPrincipalExecutor
	Terminal    TerminalBroker
	Cron        CronExecutor
	Git         GitExecutor
	Staging     StagingExecutor
}

func NewAccessExecutorHandler(executors AccessExecutorSet) (*AccessExecutorHandler, error) {
	if executors.Files == nil || executors.Credentials == nil || executors.Migration == nil || executors.Terminal == nil || executors.Cron == nil || executors.Git == nil || executors.Staging == nil {
		return nil, ErrAccessBrokerProtocol
	}
	return &AccessExecutorHandler{executors: executors}, nil
}

type AccessExecutorHandler struct{ executors AccessExecutorSet }

func decodeAccessPayload(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrAccessBrokerProtocol
	}
	return nil
}
func (handler *AccessExecutorHandler) Handle(ctx context.Context, request ExecutorEnvelope) (ExecutorResult, error) {
	var value any
	switch request.Operation {
	case ExecutorFileList:
		var in listInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.List(ctx, in.Root, in.Directory, in.Page)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorFileStat:
		var in statInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.Stat(ctx, in.Locator)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorFileRead:
		var in readRangeInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		content, integrity, err := handler.executors.Files.ReadRange(ctx, in.Locator, in.Offset, in.Length)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = readRangeOutput{content, integrity}
	case ExecutorFileCreate:
		var in createInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		var out FileMutationReceipt
		var err error
		if in.Content == nil {
			out, err = handler.executors.Files.CreateDirectory(ctx, in.Locator, in.Metadata)
		} else {
			out, err = handler.executors.Files.CreateFile(ctx, in.Locator, in.Content, in.Metadata, in.Condition)
		}
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorFileReplace:
		var in createInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.ReplaceFile(ctx, in.Locator, in.Content, in.Metadata, in.Condition)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorFileMove, ExecutorFileCopy:
		var in transferInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		var out FileMutationReceipt
		var err error
		if request.Operation == ExecutorFileMove {
			out, err = handler.executors.Files.Move(ctx, in.Source, in.Destination, in.Condition)
		} else {
			out, err = handler.executors.Files.Copy(ctx, in.Source, in.Destination, in.Condition)
		}
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorFileMetadata:
		var in metadataInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.SetMetadata(ctx, in.Locator, in.Metadata, in.Condition)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorFileSymlink:
		var in symlinkInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.CreateSymlink(ctx, in.Locator, in.Target, in.Condition)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorFileTrash:
		var in trashInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		entry, receipt, err := handler.executors.Files.MoveToTrash(ctx, in.Locator, in.TrashID)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = trashOutput{entry, receipt}
	case ExecutorFileRestore:
		var in restoreInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.RestoreTrash(ctx, in.Entry, in.Destination, in.Condition)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorFilePurge:
		var in TrashEntry
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.PurgeTrash(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorUpload:
		var in UploadSession
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.BeginUpload(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorUploadAppend:
		var in uploadAppendInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		if err := handler.executors.Files.AppendUpload(ctx, in.Handle, in.Chunk); err != nil {
			return ExecutorResult{}, err
		}
		value = nil
	case ExecutorUploadCommit:
		var in UploadSession
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.CommitUpload(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorUploadAbort:
		var in uploadAbortInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		if err := handler.executors.Files.AbortUpload(ctx, in.Handle); err != nil {
			return ExecutorResult{}, err
		}
		value = nil
	case ExecutorDownload:
		var in DownloadLease
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.OpenDownload(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorDownloadRead:
		var in downloadReadInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.ReadDownload(ctx, in.Lease, in.Offset, in.Length)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorDownloadClose:
		var in DownloadLease
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		if err := handler.executors.Files.CloseDownload(ctx, in); err != nil {
			return ExecutorResult{}, err
		}
		value = nil
	case ExecutorFileArchive:
		var in Archive
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.CreateArchive(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorFileExtract:
		var in extractInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Files.ExtractArchive(ctx, in.Archive, in.Destination, in.Policy)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorFTPS, ExecutorFTPSRotate, ExecutorFTPSEnable, ExecutorFTPSDelete:
		var in ftpsInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		var out string
		var err error
		switch request.Operation {
		case ExecutorFTPS:
			secret, se := NewSecretMaterial(in.Password)
			if se != nil {
				return ExecutorResult{}, se
			}
			defer secret.Destroy()
			out, err = handler.executors.Credentials.ApplyFTPSAccount(ctx, in.Account, secret)
		case ExecutorFTPSRotate:
			secret, se := NewSecretMaterial(in.Password)
			if se != nil {
				return ExecutorResult{}, se
			}
			defer secret.Destroy()
			out, err = handler.executors.Credentials.RotateFTPSPassword(ctx, in.Account, secret)
		case ExecutorFTPSEnable:
			if in.Enabled == nil {
				return ExecutorResult{}, ErrAccessBrokerProtocol
			}
			out, err = handler.executors.Credentials.SetFTPSAccountEnabled(ctx, in.Account, *in.Enabled)
		case ExecutorFTPSDelete:
			out, err = handler.executors.Credentials.DeleteFTPSAccount(ctx, in.Account)
		}
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorSSHKey, ExecutorSSHKeyRemove:
		var in SSHKey
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		var out string
		var err error
		if request.Operation == ExecutorSSHKey {
			out, err = handler.executors.Credentials.ApplySSHKey(ctx, in)
		} else {
			out, err = handler.executors.Credentials.RemoveSSHKey(ctx, in)
		}
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorSSHGrant:
		var in sshGrantInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Credentials.ApplyAccessGrant(ctx, in.Grant, in.Key)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorSSHGrantRemove:
		var in AccessGrant
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Credentials.RemoveAccessGrant(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorMigrationPrincipalStage:
		var in migrationPrincipalMutationInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Migration.StageMigrationPrincipal(ctx, in.Principal, in.Attempt)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorMigrationPrincipalObserve:
		var in MigrationPrincipal
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Migration.ObserveMigrationPrincipal(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorMigrationPrincipalsActivate:
		var in MigrationPrincipalBatch
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Migration.ActivateMigrationPrincipals(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorMigrationPrincipalCompensate:
		var in migrationPrincipalMutationInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Migration.CompensateMigrationPrincipal(ctx, in.Principal, in.Attempt)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorTerminalIssue:
		var in struct {
			Grant   AccessGrant     `json:"grant"`
			Request TerminalRequest `json:"request"`
		}
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Terminal.Issue(ctx, in.Grant, in.Request)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorTerminalRevoke:
		var in TerminalSession
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		if err := handler.executors.Terminal.Revoke(ctx, in); err != nil {
			return ExecutorResult{}, err
		}
		value = nil
	case ExecutorCronApply:
		var in struct {
			SiteID     SiteID    `json:"site_id"`
			Generation uint64    `json:"generation"`
			Jobs       []CronJob `json:"jobs"`
		}
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Cron.ApplySchedule(ctx, in.SiteID, in.Generation, in.Jobs)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorCronRun:
		var in CronJob
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Cron.RunNow(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorCronCancel:
		var in CronRun
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		if err := handler.executors.Cron.CancelRun(ctx, in); err != nil {
			return ExecutorResult{}, err
		}
		value = nil
	case ExecutorGitKey:
		var in DeployKey
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Git.GenerateDeployKey(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorGitKeyDelete:
		var in DeployKey
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		if err := handler.executors.Git.DeleteDeployKey(ctx, in); err != nil {
			return ExecutorResult{}, err
		}
		value = nil
	case ExecutorGitRepository:
		var in repositoryKeyInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		a, b, err := handler.executors.Git.Attach(ctx, in.Repository, in.Key)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = pairOutput{a, b}
	case ExecutorGitInitialize:
		var in GitRepository
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Git.Initialize(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorGitDetach:
		var in struct {
			Repository GitRepository `json:"repository"`
			Retain     bool          `json:"retain"`
		}
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Git.Detach(ctx, in.Repository, in.Retain)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorGitStatus, ExecutorGitPull:
		var in GitRepository
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		var out GitStatus
		var err error
		if request.Operation == ExecutorGitStatus {
			out, err = handler.executors.Git.Status(ctx, in)
		} else {
			out, err = handler.executors.Git.Pull(ctx, in)
		}
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorGitFetch:
		var in struct {
			Repository GitRepository `json:"repository"`
			Prune      bool          `json:"prune"`
		}
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Git.Fetch(ctx, in.Repository, in.Prune)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorGitCheckout:
		var in struct {
			Repository GitRepository `json:"repository"`
			Branch     string        `json:"branch"`
			Force      bool          `json:"force"`
		}
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Git.Checkout(ctx, in.Repository, in.Branch, in.Force)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorGitCommit:
		var in struct {
			Repository GitRepository `json:"repository"`
			Changes    GitChangeSet  `json:"changes"`
		}
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Git.Commit(ctx, in.Repository, in.Changes)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorGitPush:
		var in struct {
			Repository GitRepository `json:"repository"`
			Ref        string        `json:"ref"`
		}
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Git.Push(ctx, in.Repository, in.Ref)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorGitLog:
		var in struct {
			Repository GitRepository `json:"repository"`
			Page       PageRequest   `json:"page"`
		}
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Git.Log(ctx, in.Repository, in.Page)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorGitIgnore:
		var in struct {
			Repository GitRepository `json:"repository"`
			Patterns   []string      `json:"patterns"`
		}
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Git.WriteIgnore(ctx, in.Repository, in.Patterns)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorGitDeployment, ExecutorGitPromote, ExecutorGitVerify, ExecutorGitRollback, ExecutorGitDiscard:
		var in deploymentInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		switch request.Operation {
		case ExecutorGitDeployment:
			out, err := handler.executors.Git.PrepareDeployment(ctx, in.Repository, in.Deployment)
			if err != nil {
				return ExecutorResult{}, err
			}
			value = out
		case ExecutorGitPromote:
			out, err := handler.executors.Git.PromoteDeployment(ctx, in.Repository, in.Deployment)
			if err != nil {
				return ExecutorResult{}, err
			}
			value = out
		case ExecutorGitVerify:
			out, err := handler.executors.Git.VerifyDeployment(ctx, in.Repository, in.Deployment)
			if err != nil {
				return ExecutorResult{}, err
			}
			value = out
		case ExecutorGitRollback:
			out, err := handler.executors.Git.RollbackDeployment(ctx, in.Repository, in.Deployment)
			if err != nil {
				return ExecutorResult{}, err
			}
			value = out
		case ExecutorGitDiscard:
			if err := handler.executors.Git.DiscardDeployment(ctx, in.Repository, in.Deployment); err != nil {
				return ExecutorResult{}, err
			}
			value = nil
		}
	case ExecutorStagingSync:
		var in StagingSync
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		if err := in.Validate(); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Staging.SnapshotSyncSource(ctx, in)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorStagingApply:
		var in syncSnapshotInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		if err := in.Sync.Validate(); err != nil {
			return ExecutorResult{}, err
		}
		out, err := handler.executors.Staging.ApplyStagingSync(ctx, in.Sync, in.Snapshot)
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorStagingVerify, ExecutorStagingPromote, ExecutorStagingRollback:
		var in syncApplicationInput
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		if err := in.Sync.Validate(); err != nil {
			return ExecutorResult{}, err
		}
		var out string
		var err error
		switch request.Operation {
		case ExecutorStagingVerify:
			out, err = handler.executors.Staging.VerifyStagingSync(ctx, in.Sync, in.Application)
		case ExecutorStagingPromote:
			out, err = handler.executors.Staging.PromoteStagingSync(ctx, in.Sync, in.Application)
		case ExecutorStagingRollback:
			out, err = handler.executors.Staging.RollbackStagingSync(ctx, in.Sync, in.Application)
		}
		if err != nil {
			return ExecutorResult{}, err
		}
		value = out
	case ExecutorStagingRelease:
		var in SyncSnapshot
		if err := decodeAccessPayload(request.Payload, &in); err != nil {
			return ExecutorResult{}, err
		}
		if err := handler.executors.Staging.ReleaseSyncSnapshot(ctx, in); err != nil {
			return ExecutorResult{}, err
		}
		value = nil
	default:
		return ExecutorResult{}, ErrAccessBrokerProtocol
	}
	return succeededExecutorResult(request, value)
}
