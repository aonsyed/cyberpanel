package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/preview"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/maildelivery"
	"github.com/aonsyed/cyberpanel/platform/internal/maintenance"
	"github.com/aonsyed/cyberpanel/platform/internal/malwarescan"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/packagemaint"
	"github.com/aonsyed/cyberpanel/platform/internal/productupdate"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"github.com/aonsyed/cyberpanel/platform/internal/sitepreview"
	"github.com/aonsyed/cyberpanel/platform/internal/webmaildata"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/accesspolicy"
	management "github.com/aonsyed/cyberpanel/platform/internal/webengine/management"
)

type HostingCommandService interface { Handle(context.Context, service.Command) (service.OperationReceipt,error) }
type HostingQueryService interface {
	Load(context.Context, site.TenantID, site.SiteID) (site.Site, error)
	List(context.Context, site.TenantID, string, int) ([]site.Site, string, uint64, error)
}
type DatabaseCommandService interface { Handle(context.Context, database.Command) (database.OperationReceipt,error) }
type OperationsCommandService interface { Handle(context.Context, operations.Command) (operations.OperationReceipt,error) }
type CertificateMaterialUploadBroker interface { OpenCertificateMaterialUpload(context.Context,string,string,string,uint64) (certificates.OneUseCertificateMaterial,error) }

// RebootRequiredReasonProjection binds a controlled reboot to durable package
// or recovery evidence. It is not a free-form operator reason.
type RebootRequiredReasonProjection struct {
	Code rebootcontrol.PlanReason `json:"code"`
	Source string `json:"source"`
	Reference string `json:"reference"`
	EvidenceDigest string `json:"evidence_digest"`
	ObservedAt time.Time `json:"observed_at"`
}

type RebootControlProjection struct {
	ID string `json:"id"`
	Type string `json:"type"`
	NodeID string `json:"node_id"`
	Required bool `json:"required"`
	Reasons []RebootRequiredReasonProjection `json:"reasons"`
	MaintenanceOccurrenceID string `json:"maintenance_occurrence_id,omitempty"`
	MaintenanceStartsAt time.Time `json:"maintenance_starts_at,omitempty"`
	MaintenanceEndsAt time.Time `json:"maintenance_ends_at,omitempty"`
	MaintenanceStatus string `json:"maintenance_status"`
	Phase string `json:"phase"`
	Outcome string `json:"outcome,omitempty"`
	DrainStatus string `json:"drain_status"`
	DrainReady bool `json:"drain_ready"`
	QuiesceStatus string `json:"quiesce_status"`
	QuiesceReady bool `json:"quiesce_ready"`
	ApprovalStatus string `json:"approval_status"`
	ApprovalRef string `json:"approval_ref,omitempty"`
	IndependentApprover string `json:"independent_approver,omitempty"`
	SourceBootID string `json:"source_boot_id,omitempty"`
	ObservedBootID string `json:"observed_boot_id,omitempty"`
	BootConfirmationStatus string `json:"boot_confirmation_status"`
	CurrentKernel string `json:"current_kernel,omitempty"`
	ExpectedKernel string `json:"expected_kernel,omitempty"`
	ObservedKernel string `json:"observed_kernel,omitempty"`
	Ambiguous bool `json:"ambiguous"`
	CanExecute bool `json:"can_execute"`
	CanCancel bool `json:"can_cancel"`
	CanReconcile bool `json:"can_reconcile"`
	Generation uint64 `json:"generation"`
	Fence uint64 `json:"fence"`
	RecoverySteps []string `json:"recovery_steps,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RebootControlSchedulePayload struct {
	Reason rebootcontrol.PlanReason `json:"reason"`
	RequirementReference string `json:"requirement_reference"`
	MaintenanceOccurrence string `json:"maintenance_occurrence_id"`
	ApprovalRef string `json:"approval_ref"`
	IndependentApprover string `json:"independent_approver"`
	DrainMode rebootcontrol.DrainMode `json:"drain_mode"`
	ExpectedReturnSeconds uint32 `json:"expected_return_seconds,omitempty"`
}

type RebootControlEdgeService interface {
	ListRebootControls(context.Context, EdgeCall, EdgePagePayload) (EdgePage[RebootControlProjection], error)
	ScheduleReboot(context.Context, EdgeCall, RebootControlSchedulePayload) (EdgeMutation[RebootControlProjection], error)
	ExecuteReboot(context.Context, EdgeCall) (EdgeMutation[RebootControlProjection], error)
	CancelReboot(context.Context, EdgeCall) (EdgeMutation[RebootControlProjection], error)
	ReconcileReboot(context.Context, EdgeCall) (EdgeMutation[RebootControlProjection], error)
}

// Capabilities keep partial assembly from advertising a reboot effect without
// its protected approval, HA, and recovery authority.
type RebootControlEdgeCapabilities struct { List, Schedule, Execute, Cancel, Reconcile bool }
type RebootControlEdgeCapabilityProvider interface { RebootControlCapabilities() RebootControlEdgeCapabilities }

func registerRebootControlContracts(registry *Registry) error {
	definitions:=[]Operation{
		consoleOperation("reboot_control.status.list","operations:observe",identity.AssurancePassword,false,func()any{return &EdgePagePayload{}},validateEdgePage,edgeInstallationListScope),
		consoleOperation("reboot_control.schedule","operations:manage",identity.AssuranceMFA,true,func()any{return &RebootControlSchedulePayload{}},validateRebootControlSchedule,edgeInstallationCreateScope),
		consoleOperation("reboot_control.execute","operations:manage",identity.AssurancePhishingResistant,true,func()any{return &EmptyPayload{}},nil,edgeInstallationExistingMutationScope),
		consoleOperation("reboot_control.cancel","operations:manage",identity.AssurancePhishingResistant,true,func()any{return &EmptyPayload{}},nil,edgeInstallationExistingMutationScope),
		consoleOperation("reboot_control.reconcile","operations:manage",identity.AssurancePhishingResistant,true,func()any{return &EmptyPayload{}},nil,edgeInstallationExistingMutationScope),
	}
	for _,definition:=range definitions{if err:=register(registry,definition);err!=nil{return err}}
	return nil
}

func validateRebootControlSchedule(value any) error {
	payload:=value.(*RebootControlSchedulePayload)
	switch payload.Reason {
	case rebootcontrol.ReasonKernelUpdate,rebootcontrol.ReasonPackageUpdate,rebootcontrol.ReasonSecurityResponse,rebootcontrol.ReasonRecovery:
	default:return invalid("controlled reboot reason")
	}
	if !validEdgeID(payload.RequirementReference)||!validEdgeID(payload.MaintenanceOccurrence)||!validEdgeID(payload.ApprovalRef)||!validEdgeID(payload.IndependentApprover)||payload.DrainMode!=rebootcontrol.DrainGraceful&&payload.DrainMode!=rebootcontrol.DrainRequired{return invalid("controlled reboot schedule")}
	if payload.ExpectedReturnSeconds==0{payload.ExpectedReturnSeconds=1800}
	if payload.ExpectedReturnSeconds<60||payload.ExpectedReturnSeconds>86400{return invalid("controlled reboot return window")}
	return nil
}

func bindRebootControlContracts(registry *Registry,services DomainServices) error {
	if services.RebootControl==nil{return nil}
	capabilities:=RebootControlEdgeCapabilities{List:true,Schedule:true,Execute:true,Cancel:true,Reconcile:true}
	if provider,ok:=services.RebootControl.(RebootControlEdgeCapabilityProvider);ok{capabilities=provider.RebootControlCapabilities()}
	if capabilities.List {
		if err:=registry.Bind("reboot_control.status.list",func(ctx context.Context,invocation Invocation,value any)(OperationResult,error){
			result,err:=services.RebootControl.ListRebootControls(ctx,edgeCall(invocation),*value.(*EdgePagePayload));if err!=nil{return OperationResult{},mapDomainError(err)}
			return OperationResult{Status:http.StatusOK,Value:result},nil
		});err!=nil{return err}
	}
	bindings:=[]struct{name string;available bool;invoke func(context.Context,EdgeCall,any)(EdgeMutation[RebootControlProjection],error)}{
		{"reboot_control.schedule",capabilities.Schedule,func(ctx context.Context,call EdgeCall,value any)(EdgeMutation[RebootControlProjection],error){return services.RebootControl.ScheduleReboot(ctx,call,*value.(*RebootControlSchedulePayload))}},
		{"reboot_control.execute",capabilities.Execute,func(ctx context.Context,call EdgeCall,_ any)(EdgeMutation[RebootControlProjection],error){return services.RebootControl.ExecuteReboot(ctx,call)}},
		{"reboot_control.cancel",capabilities.Cancel,func(ctx context.Context,call EdgeCall,_ any)(EdgeMutation[RebootControlProjection],error){return services.RebootControl.CancelReboot(ctx,call)}},
		{"reboot_control.reconcile",capabilities.Reconcile,func(ctx context.Context,call EdgeCall,_ any)(EdgeMutation[RebootControlProjection],error){return services.RebootControl.ReconcileReboot(ctx,call)}},
	}
	for _,binding:=range bindings{
		if !binding.available{continue};invoke:=binding.invoke
		if err:=registry.Bind(binding.name,func(ctx context.Context,invocation Invocation,value any)(OperationResult,error){result,err:=invoke(ctx,edgeCall(invocation),value);if err!=nil{return OperationResult{},mapDomainError(err)};return edgeOperationResult(http.StatusAccepted,result),nil});err!=nil{return err}
	}
	return nil
}

type DomainServices struct {
	Identity *identity.Service
	Hosting HostingCommandService
	HostingQuery HostingQueryService
	HostingPreviews *preview.Service
	SitePreviews *sitepreview.Service
	SiteScreenshots *sitepreview.ScreenshotService
	Database DatabaseCommandService
	Operations OperationsCommandService
	ProductUpdates ProductUpdateEdgeService
	PackageMaintenance PackageMaintenanceEdgeService
	MaintenanceWindows MaintenanceWindowEdgeService
	RebootControl RebootControlEdgeService
	DNSRepository *dns.Repository
	DNSProvider dns.Provider
	DNSAuthority DNSAuthorityService
	DNSSEC *dns.DNSSECCoordinator
	HTTP01 certificates.HTTP01Presenter
	DNS01 certificates.DNS01Presenter
	CertificateStore *certificates.IssuanceStore
	CertificateIssuance *certificates.IssuanceCoordinator
	CertificateDeployment *certificates.DeploymentCoordinator
	CertificateMaterials *certificates.MaterialService
	CertificateMaterialUploads CertificateMaterialUploadBroker
	Mail *mail.Service
	MailDelivery *maildelivery.Service
	MailControl *mail.Coordinator
	MailQueue mail.QueueRuntime
	Webmail *mail.WebmailService
	MailSessions *mail.MailSessionAuthority
	WebmailData *webmaildata.Service
	WebmailDataBlobs WebmailDataBlobStore
	Marketing *mail.MarketingStore
	Campaigns *mail.CampaignCoordinator
	Unsubscribe *mail.UnsubscribeService
	EmailMarketing *EmailMarketingOperations
	Backup *backup.Coordinator
	BackupPromoter backup.Promoter
	BackupMover backup.Mover
	BackupCatalog *backup.BackupCatalog
	BackupWorkflow *backup.BackupCoordinator
	RestoreWorkflow *backup.RestoreCoordinator
	Retention *backup.RetentionCoordinator
	Files *access.FileService
	Credentials *access.CredentialService
	Cron *access.CronService
	Git *access.GitService
	Staging *access.StagingService
	Applications *apps.ApplicationService
	ApplicationLifecycle *apps.LifecycleCoordinator
	ApplicationStaging *apps.StagingCoordinator
	ApplicationAccessProtection *apps.AccessProtectionService
	WordPress *apps.WordPressManager
	ApplicationAutologin *apps.AutologinService
	ApplicationAutologinBridge *apps.AutologinBridgeManager
	Containers *containers.Service
	ContainerApplications *containers.ApplicationService
	N8N *integrations.N8NRuntime
	Hermes *integrations.HermesRuntime
	WebEngine *management.Service
	Audit *audit.Service
	DashboardEdge DashboardEdgeService
	HostingEdge HostingEdgeService
	HostingCloneEdge HostingCloneEdgeService
	HostingPreviewEdge HostingPreviewEdgeService
	HostingAccessPolicyEdge HostingAccessPolicyEdgeService
	DatabaseEdge DatabaseEdgeService
	AccessEdge AccessEdgeService
	ApplicationEdge ApplicationEdgeService
	BackupEdge BackupEdgeService
	DNSEdge DNSEdgeService
	CertificateEdge CertificateEdgeService
	MailEdge MailEdgeService
	WebmailEdge WebmailEdgeService
	ContainerEdge ContainerEdgeService
	OperationsEdge OperationsEdgeService
	SecurityEdge SecurityEdgeService
	Malware *malwarescan.OperationalService
	FleetEdge FleetEdgeService
	HAEdge HAEdgeService
	MigrationEdge MigrationEdgeService
	IdentityEdge IdentityEdgeService
	WebEngineEdge WebEngineEdgeService
	IntegrationEdge IntegrationEdgeService
	SecretEnrollment SecretEnrollmentService
}

func NewDomainRegistry() (*Registry,error) {
	registry:=NewRegistry()
	for _,register:=range []func(*Registry)error{registerIdentityContracts,registerHostingContracts,registerDatabaseContracts,registerFoundationContracts,registerCertificateContracts,registerBackupContracts,registerDNSContracts,registerMailContracts,registerMailDeliveryContracts,registerWebmailDataContracts,registerMarketingContracts,registerAccessContracts,registerAccessFileContracts,registerAccessDeveloperContracts,registerApplicationContracts,registerContainerContracts,registerOperationsContracts,registerWebEngineContracts,registerSitePreviewContracts,registerAuditContracts,registerConsoleEdgeContracts,registerObservabilityContracts,registerMalwareContracts,registerNotificationContracts,registerSecretEnrollmentContracts,registerProductUpdateContracts,registerPackageMaintenanceContracts,registerMaintenanceWindowContracts,registerRebootControlContracts}{if err:=register(registry);err!=nil{return nil,err}}
	return registry,nil
}

func (services DomainServices) Bind(registry *Registry) error {
	if registry==nil{return invalid("domain registry")}
	for _,bind:=range []func(*Registry,DomainServices)error{bindIdentity,bindHosting,bindDatabase,bindFoundation,bindCertificates,bindBackup,bindDNS,bindMail,bindMailDelivery,bindWebmailDataContracts,bindMarketing,bindAccess,bindAccessFileDomains,bindAccessDeveloper,bindApplications,bindContainers,bindOperations,bindWebEngine,bindSitePreviewContracts,bindAudit,bindConsoleEdgeContracts,bindObservabilityContracts,bindMalwareContracts,bindNotificationContracts,bindSecretEnrollmentContracts,bindProductUpdateContracts,bindPackageMaintenanceContracts,bindMaintenanceWindowContracts,bindRebootControlContracts}{if err:=bind(registry,services);err!=nil{return err}}
	return nil
}

func commandID(invocation Invocation) string { sum:=sha256.Sum256([]byte(invocation.Request.Operation+"\x00"+invocation.IdempotencyKey));return "api_"+hex.EncodeToString(sum[:])[:48] }
func effectID(invocation Invocation) string { sum:=sha256.Sum256([]byte(invocation.Request.RequestID+"\x00"+invocation.IdempotencyKey));return "effect_"+hex.EncodeToString(sum[:])[:48] }

func register(registry *Registry,operation Operation)error{return registry.Register(operation)}
func bindIf(registry *Registry,name string,available bool,handler OperationHandler)error{if !available{return nil};return registry.Bind(name,handler)}

func mapDomainError(err error)error{
	if err==nil{return nil}
	switch{
	case errors.Is(err,database.ErrInvalidResource),errors.Is(err,database.ErrInvalidCommand),errors.Is(err,containers.ErrInvalid),errors.Is(err,apps.ErrInvalid),errors.Is(err,access.ErrInvalidID),errors.Is(err,access.ErrInvalidPath),errors.Is(err,access.ErrInvalidState),errors.Is(err,accesspolicy.ErrInvalid),errors.Is(err,preview.ErrInvalid),errors.Is(err,sitepreview.ErrInvalid),errors.Is(err,management.ErrInvalid),errors.Is(err,mail.ErrInvalidCommand),errors.Is(err,integrations.ErrInvalid),errors.Is(err,migration.ErrInvalid),errors.Is(err,ha.ErrInvalid),errors.Is(err,productupdate.ErrInvalid),errors.Is(err,packagemaint.ErrInvalid),errors.Is(err,maintenance.ErrInvalid),errors.Is(err,rebootcontrol.ErrInvalid),errors.Is(err,identity.ErrInvalid),errors.Is(err,malwarescan.ErrInvalid):return ErrInvalidRequest
	case errors.Is(err,identity.ErrUnauthenticated),errors.Is(err,identity.ErrExpired),errors.Is(err,identity.ErrCredentialCompromised):return ErrUnauthenticated
	case errors.Is(err,identity.ErrAssuranceRequired):return ErrAssuranceRequired
	case errors.Is(err,database.ErrUnauthorized),errors.Is(err,containers.ErrForbidden),errors.Is(err,apps.ErrPolicyDenied),errors.Is(err,mail.ErrUnauthorized),errors.Is(err,access.ErrUnauthorized),errors.Is(err,accesspolicy.ErrForbidden),errors.Is(err,sitepreview.ErrPolicyDenied),errors.Is(err,integrations.ErrUnauthorized),errors.Is(err,integrations.ErrPolicyDenied),errors.Is(err,ha.ErrForbidden),errors.Is(err,productupdate.ErrUnauthorized),errors.Is(err,packagemaint.ErrUnauthorized),errors.Is(err,rebootcontrol.ErrUnauthorized),errors.Is(err,identity.ErrForbidden),errors.Is(err,identity.ErrDelegationExceeded),errors.Is(err,identity.ErrSuspended),errors.Is(err,malwarescan.ErrUnauthorized),errors.Is(err,malwarescan.ErrProtected):return ErrForbidden
	case errors.Is(err,database.ErrNotFound),errors.Is(err,containers.ErrNotFound),errors.Is(err,apps.ErrNotFound),errors.Is(err,access.ErrNotFound),errors.Is(err,accesspolicy.ErrNotFound),errors.Is(err,preview.ErrNotFound),errors.Is(err,sitepreview.ErrNotFound),errors.Is(err,sitepreview.ErrUnauthorized),errors.Is(err,management.ErrNotFound),errors.Is(err,mail.ErrNotFound),errors.Is(err,integrations.ErrNotFound),errors.Is(err,migration.ErrNotFound),errors.Is(err,ha.ErrNotFound),errors.Is(err,productupdate.ErrNotFound),errors.Is(err,packagemaint.ErrNotFound),errors.Is(err,maintenance.ErrNotFound),errors.Is(err,rebootcontrol.ErrNotFound),errors.Is(err,identity.ErrNotFound),errors.Is(err,malwarescan.ErrNotFound):return ErrNotFound
	case errors.Is(err,database.ErrConflict),errors.Is(err,database.ErrIdempotency),errors.Is(err,containers.ErrConflict),errors.Is(err,containers.ErrStale),errors.Is(err,apps.ErrConflict),errors.Is(err,apps.ErrStaleGeneration),errors.Is(err,access.ErrConflict),errors.Is(err,access.ErrStaleGeneration),errors.Is(err,access.ErrInvalidTransition),errors.Is(err,accesspolicy.ErrConflict),errors.Is(err,preview.ErrConflict),errors.Is(err,preview.ErrExpired),errors.Is(err,preview.ErrBudgetExhausted),errors.Is(err,sitepreview.ErrConflict),errors.Is(err,sitepreview.ErrStaleGeneration),errors.Is(err,sitepreview.ErrExpired),errors.Is(err,sitepreview.ErrRevoked),errors.Is(err,sitepreview.ErrBudgetExhausted),errors.Is(err,management.ErrConflict),errors.Is(err,mail.ErrConflict),errors.Is(err,integrations.ErrConflict),errors.Is(err,integrations.ErrStaleGeneration),errors.Is(err,migration.ErrConflict),errors.Is(err,migration.ErrWriteFrontier),errors.Is(err,ha.ErrConflict),errors.Is(err,ha.ErrStaleGeneration),errors.Is(err,ha.ErrExpired),errors.Is(err,productupdate.ErrConflict),errors.Is(err,productupdate.ErrExpired),errors.Is(err,productupdate.ErrIncompatible),errors.Is(err,productupdate.ErrRollback),errors.Is(err,packagemaint.ErrConflict),errors.Is(err,packagemaint.ErrStaleInventory),errors.Is(err,packagemaint.ErrStalePlan),errors.Is(err,packagemaint.ErrLocked),errors.Is(err,maintenance.ErrConflict),errors.Is(err,maintenance.ErrClockPolicy),errors.Is(err,rebootcontrol.ErrConflict),errors.Is(err,rebootcontrol.ErrStaleBoot),errors.Is(err,identity.ErrConflict),errors.Is(err,identity.ErrStaleGeneration),errors.Is(err,identity.ErrQuotaExceeded),errors.Is(err,malwarescan.ErrConflict),errors.Is(err,malwarescan.ErrApproval),errors.Is(err,malwarescan.ErrAmbiguous):return ErrConflict
	case errors.Is(err,mail.ErrRateLimited):return ErrRateLimited
	case errors.Is(err,migration.ErrBlocked),errors.Is(err,migration.ErrCapacity),errors.Is(err,sitepreview.ErrProviderNotInvoked),errors.Is(err,management.ErrUnsupported),errors.Is(err,management.ErrLicense),errors.Is(err,productupdate.ErrCapacity),errors.Is(err,packagemaint.ErrUnsupported),errors.Is(err,maintenance.ErrCapacity),errors.Is(err,malwarescan.ErrUnavailable),errors.Is(err,malwarescan.ErrStale),errors.Is(err,malwarescan.ErrLimit),errors.Is(err,malwarescan.ErrIntegrity):return ErrOperationUnavailable
	case errors.Is(err,containers.ErrAmbiguous),errors.Is(err,accesspolicy.ErrAmbiguous),errors.Is(err,preview.ErrRecoveryRequired),errors.Is(err,sitepreview.ErrAmbiguous),errors.Is(err,sitepreview.ErrIntegrity),errors.Is(err,management.ErrAmbiguous),errors.Is(err,apps.ErrRecoveryRequired),errors.Is(err,apps.ErrUnsupported),errors.Is(err,mail.ErrAmbiguous),errors.Is(err,mail.ErrInvalidReceipt),errors.Is(err,integrations.ErrUnavailable),errors.Is(err,integrations.ErrRateLimited),errors.Is(err,integrations.ErrPartial),errors.Is(err,integrations.ErrAmbiguous),errors.Is(err,integrations.ErrUnsupported),errors.Is(err,ha.ErrUnsupported),errors.Is(err,ha.ErrProviderAmbiguous),errors.Is(err,ha.ErrNoQuorum),errors.Is(err,ha.ErrFenceRequired),errors.Is(err,ha.ErrUnsafePromotion),errors.Is(err,productupdate.ErrIntegrity),errors.Is(err,productupdate.ErrUnsafeArchive),errors.Is(err,packagemaint.ErrRecoveryRequired),errors.Is(err,packagemaint.ErrAmbiguous),errors.Is(err,maintenance.ErrIntegrity),errors.Is(err,maintenance.ErrAuditRequired),errors.Is(err,rebootcontrol.ErrIntegrity),errors.Is(err,rebootcontrol.ErrPartialArm),errors.Is(err,rebootcontrol.ErrUnproven),errors.Is(err,rebootcontrol.ErrCapacity):return ErrUnavailable
	default:return err
	}
}
