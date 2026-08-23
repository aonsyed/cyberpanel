package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

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
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
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

type DomainServices struct {
	Identity *identity.Service
	Hosting HostingCommandService
	HostingQuery HostingQueryService
	HostingPreviews *preview.Service
	Database DatabaseCommandService
	Operations OperationsCommandService
	DNSRepository *dns.Repository
	DNSProvider dns.Provider
	DNSAuthority DNSAuthorityService
	DNSSEC *dns.DNSSECCoordinator
	HTTP01 certificates.HTTP01Presenter
	DNS01 certificates.DNS01Presenter
	CertificateStore *certificates.IssuanceStore
	CertificateIssuance *certificates.IssuanceCoordinator
	CertificateDeployment *certificates.DeploymentCoordinator
	Mail *mail.Service
	MailControl *mail.Coordinator
	MailQueue mail.QueueRuntime
	Webmail *mail.WebmailService
	MailSessions *mail.MailSessionAuthority
	Marketing *mail.MarketingStore
	Campaigns *mail.CampaignCoordinator
	Unsubscribe *mail.UnsubscribeService
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
	for _,register:=range []func(*Registry)error{registerIdentityContracts,registerHostingContracts,registerDatabaseContracts,registerFoundationContracts,registerCertificateContracts,registerBackupContracts,registerDNSContracts,registerMailContracts,registerMarketingContracts,registerAccessContracts,registerAccessFileContracts,registerAccessDeveloperContracts,registerApplicationContracts,registerContainerContracts,registerOperationsContracts,registerWebEngineContracts,registerAuditContracts,registerConsoleEdgeContracts,registerSecretEnrollmentContracts}{if err:=register(registry);err!=nil{return nil,err}}
	return registry,nil
}

func (services DomainServices) Bind(registry *Registry) error {
	if registry==nil{return invalid("domain registry")}
	for _,bind:=range []func(*Registry,DomainServices)error{bindIdentity,bindHosting,bindDatabase,bindFoundation,bindCertificates,bindBackup,bindDNS,bindMail,bindMarketing,bindAccess,bindAccessFileDomains,bindAccessDeveloper,bindApplications,bindContainers,bindOperations,bindWebEngine,bindAudit,bindConsoleEdgeContracts,bindSecretEnrollmentContracts}{if err:=bind(registry,services);err!=nil{return err}}
	return nil
}

func commandID(invocation Invocation) string { sum:=sha256.Sum256([]byte(invocation.Request.Operation+"\x00"+invocation.IdempotencyKey));return "api_"+hex.EncodeToString(sum[:])[:48] }
func effectID(invocation Invocation) string { sum:=sha256.Sum256([]byte(invocation.Request.RequestID+"\x00"+invocation.IdempotencyKey));return "effect_"+hex.EncodeToString(sum[:])[:48] }

func register(registry *Registry,operation Operation)error{return registry.Register(operation)}
func bindIf(registry *Registry,name string,available bool,handler OperationHandler)error{if !available{return nil};return registry.Bind(name,handler)}

func mapDomainError(err error)error{
	if err==nil{return nil}
	switch{
	case errors.Is(err,database.ErrInvalidResource),errors.Is(err,database.ErrInvalidCommand),errors.Is(err,containers.ErrInvalid),errors.Is(err,apps.ErrInvalid),errors.Is(err,access.ErrInvalidID),errors.Is(err,access.ErrInvalidPath),errors.Is(err,access.ErrInvalidState),errors.Is(err,accesspolicy.ErrInvalid),errors.Is(err,preview.ErrInvalid),errors.Is(err,management.ErrInvalid),errors.Is(err,mail.ErrInvalidCommand),errors.Is(err,integrations.ErrInvalid),errors.Is(err,migration.ErrInvalid),errors.Is(err,ha.ErrInvalid),errors.Is(err,identity.ErrInvalid):return ErrInvalidRequest
	case errors.Is(err,identity.ErrUnauthenticated),errors.Is(err,identity.ErrExpired),errors.Is(err,identity.ErrCredentialCompromised):return ErrUnauthenticated
	case errors.Is(err,identity.ErrAssuranceRequired):return ErrAssuranceRequired
	case errors.Is(err,database.ErrUnauthorized),errors.Is(err,containers.ErrForbidden),errors.Is(err,apps.ErrPolicyDenied),errors.Is(err,mail.ErrUnauthorized),errors.Is(err,access.ErrUnauthorized),errors.Is(err,accesspolicy.ErrForbidden),errors.Is(err,integrations.ErrUnauthorized),errors.Is(err,integrations.ErrPolicyDenied),errors.Is(err,ha.ErrForbidden),errors.Is(err,identity.ErrForbidden),errors.Is(err,identity.ErrDelegationExceeded),errors.Is(err,identity.ErrSuspended):return ErrForbidden
	case errors.Is(err,database.ErrNotFound),errors.Is(err,containers.ErrNotFound),errors.Is(err,apps.ErrNotFound),errors.Is(err,access.ErrNotFound),errors.Is(err,accesspolicy.ErrNotFound),errors.Is(err,preview.ErrNotFound),errors.Is(err,management.ErrNotFound),errors.Is(err,mail.ErrNotFound),errors.Is(err,integrations.ErrNotFound),errors.Is(err,migration.ErrNotFound),errors.Is(err,ha.ErrNotFound),errors.Is(err,identity.ErrNotFound):return ErrNotFound
	case errors.Is(err,database.ErrConflict),errors.Is(err,database.ErrIdempotency),errors.Is(err,containers.ErrConflict),errors.Is(err,containers.ErrStale),errors.Is(err,apps.ErrConflict),errors.Is(err,apps.ErrStaleGeneration),errors.Is(err,access.ErrConflict),errors.Is(err,access.ErrStaleGeneration),errors.Is(err,access.ErrInvalidTransition),errors.Is(err,accesspolicy.ErrConflict),errors.Is(err,preview.ErrConflict),errors.Is(err,preview.ErrExpired),errors.Is(err,preview.ErrBudgetExhausted),errors.Is(err,management.ErrConflict),errors.Is(err,mail.ErrConflict),errors.Is(err,integrations.ErrConflict),errors.Is(err,integrations.ErrStaleGeneration),errors.Is(err,migration.ErrConflict),errors.Is(err,migration.ErrWriteFrontier),errors.Is(err,ha.ErrConflict),errors.Is(err,ha.ErrStaleGeneration),errors.Is(err,ha.ErrExpired),errors.Is(err,identity.ErrConflict),errors.Is(err,identity.ErrStaleGeneration),errors.Is(err,identity.ErrQuotaExceeded):return ErrConflict
	case errors.Is(err,mail.ErrRateLimited):return ErrRateLimited
	case errors.Is(err,migration.ErrBlocked),errors.Is(err,migration.ErrCapacity),errors.Is(err,management.ErrUnsupported),errors.Is(err,management.ErrLicense):return ErrOperationUnavailable
	case errors.Is(err,containers.ErrAmbiguous),errors.Is(err,accesspolicy.ErrAmbiguous),errors.Is(err,preview.ErrRecoveryRequired),errors.Is(err,management.ErrAmbiguous),errors.Is(err,apps.ErrRecoveryRequired),errors.Is(err,apps.ErrUnsupported),errors.Is(err,mail.ErrAmbiguous),errors.Is(err,mail.ErrInvalidReceipt),errors.Is(err,integrations.ErrUnavailable),errors.Is(err,integrations.ErrRateLimited),errors.Is(err,integrations.ErrPartial),errors.Is(err,integrations.ErrAmbiguous),errors.Is(err,integrations.ErrUnsupported),errors.Is(err,ha.ErrUnsupported),errors.Is(err,ha.ErrProviderAmbiguous),errors.Is(err,ha.ErrNoQuorum),errors.Is(err,ha.ErrFenceRequired),errors.Is(err,ha.ErrUnsafePromotion):return ErrUnavailable
	default:return err
	}
}
