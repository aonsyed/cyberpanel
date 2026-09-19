package apps

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type IdentityRewrite struct {
	SourceURL string `json:"source_url"`
	TargetURL string `json:"target_url"`
	Application ApplicationKind `json:"application"`
	SerializedDataAware bool `json:"serialized_data_aware"`
	RewriteFiles bool `json:"rewrite_files"`
	RewriteDatabase bool `json:"rewrite_database"`
	PreserveGUIDs bool `json:"preserve_guids"`
}

type CloneRequest struct {
	CommandID            CommandID `json:"command_id"`
	RelationID           StagingRelationID `json:"relation_id"`
	TenantID             TenantID `json:"tenant_id"`
	Source               ApplicationInstallation `json:"source"`
	TargetSiteID         SiteID `json:"target_site_id"`
	TargetProjectID      ProjectID `json:"target_project_id"`
	TargetSiteUID        SiteUID `json:"target_site_uid"`
	TargetInstallationID InstallationID `json:"target_installation_id"`
	TargetDatabaseInstanceID DatabaseInstanceID `json:"target_database_instance_id"`
	TargetDatabaseClientIdentityRef SecretRef `json:"target_database_client_identity_ref,omitempty"`
	TargetRoot           RelativePath `json:"target_root"`
	SourceURL            string `json:"source_url"`
	TargetURL            string `json:"target_url"`
	TargetRuntimeID      string `json:"target_runtime_id"`
	Selection            Selection `json:"selection"`
	CreateDatabase       bool `json:"create_database"`
	MailSuppressed       bool `json:"mail_suppressed"`
	ExternalActionsDenied bool `json:"external_actions_denied"`
	AccessPolicyID       string `json:"access_policy_id"`
}

func (request CloneRequest) Validate(now time.Time) error {
	if err := requireID("command", string(request.CommandID)); err != nil { return err }
	if err := requireID("staging relation", string(request.RelationID)); err != nil { return err }
	if err := requireID("tenant", string(request.TenantID)); err != nil { return err }
	if err := request.Source.Validate(now); err != nil { return err }
	if err := requireID("target site", string(request.TargetSiteID)); err != nil { return err }
	if err := requireID("target project", string(request.TargetProjectID)); err != nil { return err }
	if err := requireID("target installation", string(request.TargetInstallationID)); err != nil { return err }
	if request.TargetDatabaseClientIdentityRef!="" && request.TargetDatabaseClientIdentityRef!=SecretRef(ApplicationManagedSecretID("database_tls",request.TargetInstallationID).String()) { return ErrPolicyDenied }
	if err := requireID("target database instance", string(request.TargetDatabaseInstanceID)); err != nil { return err }
	if request.TargetSiteUID < 1000 || request.TargetSiteID == request.Source.SiteID || request.TargetInstallationID == request.Source.ID || request.SourceURL == "" || request.TargetURL == "" || request.TargetRuntimeID == "" || !request.CreateDatabase || !request.MailSuppressed || !request.ExternalActionsDenied || request.AccessPolicyID == "" {
		return fmt.Errorf("%w: clone request", ErrInvalid)
	}
	return nil
}

type CloneExecution struct {
	SourceScope          SiteExecutionScope `json:"source_scope"`
	TargetScope          SiteExecutionScope `json:"target_scope"`
	SourceInstallationID InstallationID `json:"source_installation_id"`
	TargetInstallationID InstallationID `json:"target_installation_id"`
	SourceSnapshot       Snapshot `json:"source_snapshot"`
	TargetDatabase       DatabaseBinding `json:"target_database"`
	Selection            Selection `json:"selection"`
	Rewrite              IdentityRewrite `json:"rewrite"`
	SuppressMail         bool `json:"suppress_mail"`
	DenyExternalActions  bool `json:"deny_external_actions"`
}

type SyncExecution struct {
	SourceScope  SiteExecutionScope `json:"source_scope"`
	TargetScope  SiteExecutionScope `json:"target_scope"`
	Sync         StagingSync `json:"sync"`
	SourceSnapshot Snapshot `json:"source_snapshot"`
	TargetSnapshot Snapshot `json:"target_snapshot"`
	Rewrite      IdentityRewrite `json:"rewrite"`
	WriteFence   bool `json:"write_fence"`
}

type StagingDeleteExecution struct {
	SourceScope       SiteExecutionScope `json:"source_scope"`
	TargetScope       SiteExecutionScope `json:"target_scope"`
	RelationID        StagingRelationID `json:"relation_id"`
	TargetInstallation InstallationID `json:"target_installation_id"`
	RecoveryPointID   RecoveryPointID `json:"recovery_point_id"`
}

type StagingExecutor interface {
	CreateClone(context.Context, CloneExecution) (ExecutionReceipt, error)
	ProbeClone(context.Context, CloneExecution) (HealthObservation, ExecutionReceipt, error)
	ApplySync(context.Context, SyncExecution) (ExecutionReceipt, error)
	RewriteApplicationIdentity(context.Context, SyncExecution) (ExecutionReceipt, error)
	ProbeSynchronizedApplication(context.Context, SyncExecution) (HealthObservation, ExecutionReceipt, error)
	RollbackSync(context.Context, SyncExecution) (ExecutionReceipt, error)
	DeleteClone(context.Context, StagingDeleteExecution) (ExecutionReceipt, error)
}

type StagingStore interface {
	CreateStagingRelation(context.Context, StagingRelation) error
	LoadStagingRelation(context.Context, StagingRelationID) (StagingRelation, error)
	DeleteStagingRelation(context.Context, StagingRelationID, uint64) error
	CreateStagingSync(context.Context, StagingSync) error
	UpdateStagingSync(context.Context, StagingSync) error
	LoadStagingSync(context.Context, SyncID) (StagingSync, error)
}

type StagingRequest struct {
	ID                       SyncID `json:"id"`
	CommandID                CommandID `json:"command_id"`
	RelationID               StagingRelationID `json:"relation_id"`
	Direction                SyncDirection `json:"direction"`
	Scope                    SyncScope `json:"scope"`
	Selection                Selection `json:"selection"`
	ExpectedSourceGeneration uint64 `json:"expected_source_generation"`
	ExpectedTargetGeneration uint64 `json:"expected_target_generation"`
	SourceURL                string `json:"source_url"`
	TargetURL                string `json:"target_url"`
	Application              ApplicationKind `json:"application"`
}

func (request StagingRequest) Validate() error {
	if err := requireID("sync", string(request.ID)); err != nil { return err }
	if err := requireID("command", string(request.CommandID)); err != nil { return err }
	if err := requireID("staging relation", string(request.RelationID)); err != nil { return err }
	if request.Direction != SyncPushToTarget && request.Direction != SyncPullToSource || request.ExpectedSourceGeneration == 0 || request.ExpectedTargetGeneration == 0 || request.SourceURL == "" || request.TargetURL == "" || !request.Application.Valid() {
		return fmt.Errorf("%w: staging sync request", ErrInvalid)
	}
	switch request.Scope {
	case SyncEverything, SyncFiles, SyncDatabase, SyncUploads:
	case SyncSelected:
		if len(request.Selection.Paths) == 0 && len(request.Selection.DatabaseTables) == 0 && len(request.Selection.Components) == 0 && !request.Selection.IncludeUploads {
			return fmt.Errorf("%w: empty selective sync", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: staging sync scope", ErrInvalid)
	}
	for _, table := range request.Selection.DatabaseTables {
		if !componentNamePattern.MatchString(strings.ToLower(table)) { return fmt.Errorf("%w: database table selection", ErrInvalid) }
	}
	return nil
}
