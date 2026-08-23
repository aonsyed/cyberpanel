//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	backupproviders "github.com/aonsyed/cyberpanel/platform/internal/backup/providers"
	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/webactivation"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/preview"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
	hostingservice "github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/maildelivery"
	localmigration "github.com/aonsyed/cyberpanel/platform/internal/migration/localruntime"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/accesspolicy"
	webcatalog "github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	webcontroller "github.com/aonsyed/cyberpanel/platform/internal/webengine/controller"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/containerproxy"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/enterprise"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/management"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
)

// assembleDomainServices exposes only services whose complete runtime
// dependencies are present. Repository-backed catalogs are immediately
// useful; mutation coordinators are attached by the concrete-runtime
// assembler only after their local broker connection and protected secret
// audience are established. An operation is never advertised by the gateway
// merely because a schema exists.
func assembleDomainServices(ctx context.Context, repositories controlRepositories, identityService *identity.Service, identityStore *identity.Store, auditService *audit.Service, mailHostname, panelRegistrableDomain, previewRegistrableDomain string) (apiserver.DomainServices, error) {
	if ctx == nil || repositories.ControlDB == nil || repositories.MailDelivery == nil || identityService == nil || identityStore == nil ||
		auditService == nil || auditService.Writer == nil {
		return apiserver.DomainServices{}, fmt.Errorf("domain service assembly requires control authority")
	}
	identityConsoleEdge,err:=newIdentityEdge(identityService,identityStore);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize identity console edge: %w",err)}
	dashboardConsoleEdge,err:=newDashboardEdge(repositories.ControlDB,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize dashboard console edge: %w",err)}
	databaseExecutor, err := database.NewLocalMariaDBClient()
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("connect database executor: %w", err)
	}
	databaseCoordinator := database.NewCoordinator(repositories.Database, databaseExecutor, runtimeClock{})
	databaseConsoleEdge, err := newDatabaseEdge(repositories.Database)
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("initialize database console edge: %w", err)
	}
	operationsExecutor, err := operations.NewLocalOperationsClient()
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("connect operations executor: %w", err)
	}
	operationsCoordinator := operations.NewCoordinator(repositories.Operations, operationsExecutor, runtimeClock{})
	operationsConsoleEdge, err := newOperationsEdge(operationsCoordinator, repositories.Operations, "local")
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("initialize operations console edge: %w", err)
	}
	mailClient := mail.NewLocalMailDaemonClient()
	mailProjector := mail.RepositorySnapshotProjector{Store:repositories.MailControl,NodeID:"local",Hostname:mailHostname,Postmaster:mail.Address("postmaster@"+mailHostname),MessageSizeBytes:128<<20}
	mailCoordinator := &mail.Coordinator{Store:repositories.MailControl,Executor:mail.GenerationExecutor{Projector:mailProjector,Activator:mailClient},Now:runtimeClock{}.Now}
	mailConsoleEdge,err:=newMailEdge(repositories.MailControl,mailClient);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize mail console edge: %w",err)}
	mailTelemetryReady:=true
	if telemetryErr:=mailConsoleEdge.enableTelemetry(ctx,repositories.Operations,operationsCoordinator,auditService);telemetryErr!=nil{mailConsoleEdge.setTelemetryUnavailable("telemetry_initialization_failed");mailTelemetryReady=false}
	webmailKey,err:=mail.LoadMailSessionCredential(mail.MailSessionCredentialPath);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("load webmail session authority: %w",err)};defer func(){for index:=range webmailKey{webmailKey[index]=0}}()
	webmailService,mailSessions,err:=mail.NewLocalWebmailService(webmailKey,"cyberpanel-webmail",mailHostname,repositories.Webmail,repositories.MailControl);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize webmail runtime: %w",err)}
	webmailConsoleEdge,err:=newWebmailEdge(webmailService,repositories.Webmail);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize webmail console edge: %w",err)}
	repositories.MailDeliveryPolicy.ResolveLimit=mail.ControlDeliveryLimitResolver(repositories.MailControl,mail.DeliveryLimit{HourlyMessages:500,MonthlyMessages:100000,HourlyRecipients:500,MonthlyRecipients:100000,MaxMessageBytes:16<<20,MaxRecipientsPerMessage:1})
	unsubscribeKey,err:=mail.LoadCampaignUnsubscribeCredential(mail.CampaignUnsubscribeCredentialPath);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("load campaign unsubscribe authority: %w",err)};defer func(){for index:=range unsubscribeKey{unsubscribeKey[index]=0}}()
	campaignSender,err:=mail.NewLocalCampaignSender(repositories.Marketing,repositories.MailControl,repositories.MailDeliveryPolicy,mailHostname,unsubscribeKey,"https://"+panelRegistrableDomain+"/unsubscribe");if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize campaign delivery runtime: %w",err)}
	campaignCoordinator:=&mail.CampaignCoordinator{Store:repositories.Marketing,Sender:campaignSender,Now:runtimeClock{}.Now}
	unsubscribeService:=&mail.UnsubscribeService{Store:repositories.Marketing,Signer:campaignSender.Signer,Now:runtimeClock{}.Now}
	emailMarketingOperations,err:=apiserver.NewEmailMarketingOperations(ctx,repositories.ControlDB,identityService,auditService,unsubscribeKey,"/var/lib/cyberpanel/control/emailmarketing-archives");if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize email marketing operations: %w",err)}
	dnsAuthority := dns.NewLocalPowerDNSControlClient()
	dnssecCoordinator:=&dns.DNSSECCoordinator{Store:repositories.DNSSEC,Executor:dnsAuthority,Observer:dnsAuthority,Now:runtimeClock{}.Now}
	dnsConsoleEdge,err:=newDNSEdge(dnsAuthority,dnssecCoordinator);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize DNS console edge: %w",err)}
	certificateRuntime,err:=certificates.NewLocalLinuxClientRuntimeForCurrentExecutable(nil,false,dnsAuthority);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize certificate runtime: %w",err)}
	var certificateMaterials *certificates.MaterialService
	if auditService!=nil&&auditService.Writer!=nil{
		materialRepository:=certificates.MaterialRepository{DB:repositories.ControlDB};if err=materialRepository.Bootstrap(ctx);err!=nil{return apiserver.DomainServices{},fmt.Errorf("bootstrap certificate material catalog: %w",err)}
		trustRoots,rootErr:=x509.SystemCertPool();if rootErr!=nil{return apiserver.DomainServices{},fmt.Errorf("load certificate material trust roots: %w",rootErr)};if trustRoots==nil{return apiserver.DomainServices{},fmt.Errorf("certificate material trust roots unavailable")}
		policy:=certificateMaterialPolicy{trustRoots:trustRoots}
		certificateMaterials=&certificates.MaterialService{Repository:materialRepository,Secrets:certificateRuntime.Secrets,ImportPolicies:policy,SelfSignedPolicy:policy,Audit:certificateMaterialAuditSink{service:auditService},Now:runtimeClock{}.Now}
	}
	certificateIssuance:=certificateRuntime.Issuance(repositories.CertificateIssuance)
	certificateDeployment:=certificateRuntime.Deployment(repositories.Certificates)
	certificateRenewal:=&certificates.RenewalCoordinator{Store:repositories.CertificateIssuance,Deployments:repositories.Certificates,Issuance:certificateIssuance,Deployment:certificateDeployment,Now:runtimeClock{}.Now}
	if err=certificateRenewal.Bootstrap(ctx);err!=nil{return apiserver.DomainServices{},fmt.Errorf("bootstrap certificate renewal: %w",err)}
	certificateConsoleEdge,err:=newCertificateEdge(certificateRuntime,certificateIssuance,certificateDeployment);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize certificate console edge: %w",err)}
	accessClient,err:=access.NewLocalAccessClient();if err!=nil{return apiserver.DomainServices{},fmt.Errorf("connect access executor: %w",err)}
	fileService:=&access.FileService{Executor:accessClient,Store:repositories.Access,Now:runtimeClock{}.Now}
	credentialService:=&access.CredentialService{Executor:accessClient,Terminal:accessClient,Store:repositories.Access,Now:runtimeClock{}.Now}
	cronService:=&access.CronService{Executor:accessClient,Store:repositories.Access,Now:runtimeClock{}.Now}
	gitService:=&access.GitService{Executor:accessClient,Store:repositories.Access,Now:runtimeClock{}.Now}
	stagingService:=&access.StagingService{Executor:accessClient,Store:repositories.Access,Now:runtimeClock{}.Now}
	accessConsoleEdge,err:=newAccessEdge(credentialService,fileService,repositories.Access,repositories.Hosting);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize access console edge: %w",err)}
	siteExecutor, err := siteops.NewLocalClient()
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("connect site executor: %w", err)
	}
	provisioningJournal, err := provisioning.NewFileJournal("/var/lib/cyberpanel/control/provisioning")
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("open site provisioning journal: %w", err)
	}
	provisioner, err := provisioning.New(siteExecutor, provisioningJournal)
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("initialize site provisioner: %w", err)
	}
	catalog, err := webcatalog.New(repositories.ControlDB, provisioner)
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("open web-engine catalog: %w", err)
	}
	if err = catalog.Bootstrap(ctx); err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("bootstrap web-engine catalog: %w", err)
	}
	installedEdition, err := siteops.LoadEngineEdition()
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("load installed web-engine edition: %w", err)
	}
	defaultWebTuning:=management.DefaultGlobalTuning()
	desiredWebTuning,err:=management.DesiredTuning(defaultWebTuning);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("construct default web-engine tuning: %w",err)}
	configuration := webcatalog.NodeConfiguration{
		Revision: 3,
		Engine: composer.NodeEngine{
			Edition: webengine.Edition(installedEdition),
			PreviewProxyPort: 8090,
			Tuning: desiredWebTuning,
			Listeners: []composer.ListenerInput{{
				Ref:       webengine.ResourceRef("listener/http"),
				Addresses: []string{"0.0.0.0", "::"},
				Port:      80,
				TLSMode:   webengine.TLSModeClear,
				Protocols: []webengine.Protocol{webengine.ProtocolHTTP1},
			},{
				Ref:       webengine.ResourceRef("listener/https"),
				Addresses: []string{"0.0.0.0", "::"},
				Port:      443,
				TLSMode:   webengine.TLSModeTLS,
				Protocols: []webengine.Protocol{webengine.ProtocolHTTP1,webengine.ProtocolHTTP2},
			},{
				Ref:       webengine.ResourceRef("listener/preview-internal"),
				Addresses: []string{"127.0.0.1"},
				Port:      8088,
				TLSMode:   webengine.TLSModeClear,
				Protocols: []webengine.Protocol{webengine.ProtocolHTTP1},
			}},
		},
		DefaultTLS: &composer.TLSInput{PolicyRef:webengine.ResourceRef("tls/preview-default"),MaterialKey:"preview-default",Generation:1},
	}
	if err = catalog.EnsureConfigured(ctx, configuration); err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("configure web-engine catalog: %w", err)
	}
	activationClient, err := webactivation.NewLocalClient()
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("connect web-engine activation broker: %w", err)
	}
	webManagementRuntime,err:=management.NewRuntime(catalog,activationClient,ols.New(),enterprise.New());if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize web-engine management runtime: %w",err)}
	webManagement,err:=management.New(repositories.WebEngine,webManagementRuntime,webManagementRuntime,webManagementRuntime);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize web-engine management service: %w",err)}
	nodeState,err:=catalog.NodeState(ctx);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("inspect web-engine node state: %w",err)}
	observedTuning:=management.ManagementTuning(nodeState.Configuration.Engine.Tuning)
	if _,err=repositories.WebEngine.EnsureGlobalTuning(ctx,observedTuning);err!=nil{return apiserver.DomainServices{},fmt.Errorf("reconcile web-engine tuning projection: %w",err)}
	observedInstallation,err:=webManagementRuntime.Inspect(ctx,webengine.Edition(installedEdition));if err!=nil{return apiserver.DomainServices{},fmt.Errorf("inspect web-engine installation: %w",err)}
	if _,err=repositories.WebEngine.EnsureInstallation(ctx,observedInstallation);err!=nil{return apiserver.DomainServices{},fmt.Errorf("reconcile web-engine installation projection: %w",err)}
	webEngineConsoleEdge,err:=newWebEngineEdge(webManagement,webengine.Edition(installedEdition));if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize web-engine console edge: %w",err)}
	webAccessCredentials,err:=accesspolicy.NewLocalCredentialSource();if err!=nil{return apiserver.DomainServices{},fmt.Errorf("connect web access credential broker: %w",err)}
	webAccessPolicies,err:=accesspolicy.New(catalog,activationClient,webAccessCredentials,ols.New(),enterprise.New());if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize web access policy authority: %w",err)}
	controller, err := webcontroller.New(catalog, activationClient, provisioner, ols.New(), enterprise.New())
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("initialize web-engine controller: %w", err)
	}
	containerBroker,err:=containers.NewLocalContainerBrokerClient();if err!=nil{return apiserver.DomainServices{},fmt.Errorf("connect container broker: %w",err)}
	containerPolicy,err:=containers.NewDefaultPolicy();if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize container policy: %w",err)}
	containerRoutes,err:=containerproxy.New(catalog,activationClient,ols.New(),enterprise.New());if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize container route authority: %w",err)}
	containerBackups,err:=containers.NewBrokerVolumeBackupCoordinator(repositories.Containers,containerBroker);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize container volume backup coordinator: %w",err)}
	containerService,err:=containers.NewService(repositories.Containers,containerBroker,containerPolicy,containerRoutes,containerBackups);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize container service: %w",err)}
	recipeVerifier,err:=containers.LoadDefaultLinuxRecipeVerifier();if err!=nil{return apiserver.DomainServices{},fmt.Errorf("load container recipe trust: %w",err)}
	containerIDs,err:=containers.NewDeterministicIDAllocator("local");if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize container id allocator: %w",err)}
	containerApplications,err:=containers.NewApplicationService(containerService,repositories.Containers,recipeVerifier,containerIDs);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize container applications: %w",err)}
	containerConsoleEdge,err:=newContainerEdge(containerService,repositories.Containers,containerBroker);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize container console edge: %w",err)}
	secretEnrollment, err := newSecretEnrollmentClient()
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("connect secret management broker: %w", err)
	}
	mailDeliveryMaterial,err:=secrets.NewLocalMaterialClient();if err!=nil{return apiserver.DomainServices{},fmt.Errorf("connect mail-delivery material broker: %w",err)}
	mailDeliveryConsumerDigest,err:=certificates.CurrentExecutableDigest();if err!=nil{return apiserver.DomainServices{},fmt.Errorf("digest mail-delivery consumer: %w",err)}
	mailDeliveryRuntime,err:=maildelivery.NewCyberMailLocalRuntimeV1(maildelivery.CyberMailLocalRuntimeV1Options{Repository:repositories.MailDelivery,Material:mailDeliveryMaterial,Management:secretEnrollment.client,HelloName:mailHostname,ConsumerReleaseDigest:mailDeliveryConsumerDigest,Now:runtimeClock{}.Now});if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize CyberMail adapter: %w",err)}
	mailDeliveryAuthorizer,err:=identity.NewAuthorizer(identityStore);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize mail-delivery authorization: %w",err)}
	mailDeliveryService,err:=maildelivery.NewService(maildelivery.ServiceConfig{Repository:repositories.MailDelivery,Authorizer:cyberMailAuthorization{authorizer:mailDeliveryAuthorizer,now:runtimeClock{}.Now},StepUp:cyberMailAuthorization{authorizer:mailDeliveryAuthorizer,now:runtimeClock{}.Now},Consent:cyberMailConsent{},Audit:cyberMailAudit{writer:auditService.Writer},Providers:mailDeliveryRuntime.Registry,ProviderConsumerReleaseDigest:mailDeliveryConsumerDigest,Now:runtimeClock{}.Now});if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize mail-delivery service: %w",err)}
	mailConsumerDigest,err:=webEngineExecutableDigest("/usr/local/libexec/cyberpanel/panel-execd");if err!=nil{return apiserver.DomainServices{},fmt.Errorf("digest OpenDKIM material consumer: %w",err)}
	mailRotation,err:=mail.NewDKIMRotationService(repositories.MailControl,mailProjector,cyberpanelDKIMRuntime{client:mailClient},secretEnrollment.client,mail.SystemDKIMTXTObserver{},mailConsumerDigest,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize DKIM rotation: %w",err)}
	mailCoordinator.DKIMRotation=mailRotation
	providerDigest,err:=integrations.ProviderWorkerReleaseDigest("");if err!=nil{return apiserver.DomainServices{},fmt.Errorf("digest provider worker: %w",err)}
	providerClients:=map[integrations.ProviderKind]integrations.Provider{};for _,kind:=range []integrations.ProviderKind{integrations.ProviderCloudflare,integrations.ProviderAWSS3,integrations.ProviderWasabi,integrations.ProviderBackblaze}{client,clientErr:=integrations.NewLocalProviderWorkerClient(kind);if clientErr!=nil{return apiserver.DomainServices{},fmt.Errorf("connect %s provider worker: %w",kind,clientErr)};providerClients[kind]=client}
	providerRegistrations,err:=integrations.DefaultProviderWorkerRegistrations(providerDigest,providerClients);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("register provider workers: %w",err)}
	integrationRuntime,err:=integrations.NewRuntime(repositories.Integrations,secretEnrollment.client,providerRegistrations,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize integration runtime: %w",err)}
	integrationProfiles:=map[string]integrationEdgeProfile{};for _,registration:=range providerRegistrations{integrationProfiles[registration.PublicName]=integrationEdgeProfile{Kind:registration.Kind,Purpose:registration.Purpose,Endpoint:registration.Endpoint}}
	integrationConsoleEdge,err:=newIntegrationEdge(repositories.Integrations,integrationRuntime.Bindings,integrationProfiles);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize integration console edge: %w",err)}
	applicationClient,err:=apps.NewLocalLinuxApplicationClient();if err!=nil{return apiserver.DomainServices{},fmt.Errorf("connect application executor: %w",err)}
	applicationCatalog,applicationCatalogAuthority,err:=apps.NewLinuxPinnedApplicationCatalog("");if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize application catalog: %w",err)}
	releaseDigest,err:=apps.LinuxApplicationExecutorDigest();if err!=nil{return apiserver.DomainServices{},fmt.Errorf("digest application consumer: %w",err)}
	applicationSecrets,err:=apps.NewApplicationSecretIssuer(secretEnrollment.client,repositories.Applications,releaseDigest);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize application secret issuer: %w",err)}
	applicationDatabases,err:=apps.NewApplicationDatabaseProvisioner(databaseCoordinator,repositories.Database,secretEnrollment.client,releaseDigest);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize application database provisioner: %w",err)}
	applicationRecovery:=&apps.LinuxApplicationRecoveryProvider{Client:applicationClient,Store:repositories.Applications}
	securityConsoleEdge,err:=newSecurityEdge(repositories.Applications,applicationClient,applicationRecovery,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize security console edge: %w",err)}
	applicationService:=&apps.ApplicationService{Store:repositories.Applications,Catalog:applicationCatalog,Databases:applicationDatabases,Secrets:applicationSecrets,Executor:applicationClient,Snapshots:applicationClient,Recovery:applicationRecovery,Routes:applicationClient,Now:runtimeClock{}.Now}
	applicationLifecycle:=&apps.LifecycleCoordinator{Store:repositories.Applications,Catalog:applicationCatalog,Executor:applicationClient,Recovery:applicationRecovery,Databases:applicationDatabases,Secrets:applicationSecrets,Now:runtimeClock{}.Now}
	applicationStaging:=&apps.StagingCoordinator{Store:repositories.Applications,Snapshots:applicationClient,Recovery:applicationRecovery,Databases:applicationDatabases,Executor:applicationClient,Now:runtimeClock{}.Now}
	applicationAccessProtection:=&apps.AccessProtectionService{Store:repositories.Applications,Policies:applicationAccessPolicyBridge{authority:webAccessPolicies},Now:runtimeClock{}.Now}
	wordpressManager:=&apps.WordPressManager{Store:repositories.Applications,Executor:applicationClient,Recovery:applicationRecovery,Now:runtimeClock{}.Now}
	applicationAutologin:=&apps.AutologinService{Store:repositories.Applications,Tokens:apps.CryptoRandomTokenSource{},Now:runtimeClock{}.Now,Endpoint:"/api/v1/applications/wordpress/autologin/exchange"}
	applicationAutologinBridge:=&apps.AutologinBridgeManager{Store:repositories.Applications,Executor:applicationClient,Verifier:applicationCatalogAuthority,Now:runtimeClock{}.Now}
	applicationConsoleEdge,err:=newApplicationEdge(applicationService,applicationLifecycle,wordpressManager,applicationAutologin,applicationAutologinBridge,repositories.Applications,repositories.Hosting,applicationClient,applicationCatalog,applicationCatalogAuthority,applicationSecrets,installedEdition,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize application console edge: %w",err)}
	hostingCoordinator := hostingservice.New(repositories.Hosting, controller, runtimeClock{})
	hostingConsoleEdge,err:=newHostingEdge(hostingCoordinator,repositories.Hosting,webAccessPolicies,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize hosting console edge: %w",err)}
	hostingCloneConsoleEdge,err:=newHostingCloneEdge(hostingCoordinator,repositories.Hosting,repositories.Applications,applicationStaging,applicationAccessProtection,applicationClient,webAccessPolicies,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize hosting clone edge: %w",err)}
	previewRepository,err:=preview.NewRepository(repositories.ControlDB,previewRegistrableDomain);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("open preview session authority: %w",err)}
	if err=previewRepository.Bootstrap(ctx);err!=nil{return apiserver.DomainServices{},fmt.Errorf("bootstrap preview session authority: %w",err)}
	previewSessions,err:=preview.NewService(previewRepository,repositories.Hosting,hostingCoordinator,panelRegistrableDomain,previewRegistrableDomain);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize preview session authority: %w",err)}
	hostingPreviewConsoleEdge,err:=newHostingPreviewEdge(previewSessions);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize hosting preview edge: %w",err)}
	backupClient,err:=backup.NewLocalLinuxBackupClient()
	if err!=nil{return apiserver.DomainServices{},fmt.Errorf("connect backup executor: %w",err)}
	backupRuntime, err := backupproviders.NewLocalRuntimeWithSource(repositories.ControlDB,backupClient,runtimeClock{}.Now)
	if err != nil {
		return apiserver.DomainServices{}, fmt.Errorf("initialize local backup provider: %w", err)
	}
	if err = backupRuntime.Bootstrap(ctx); err != nil {
		_ = backupRuntime.Close()
		return apiserver.DomainServices{}, fmt.Errorf("bootstrap backup provider runtime: %w", err)
	}
	if err = backupRuntime.ValidateLocalRepositories(ctx); err != nil {
		_ = backupRuntime.Close()
		return apiserver.DomainServices{}, fmt.Errorf("validate local backup repositories: %w", err)
	}
	backupRetention := backupRuntime.RetentionCoordinator(nil)
	backupWorkflow:=backupRuntime.BackupCoordinator(backupClient,backupClient)
	restoreWorkflow:=backup.RestoreCoordinator{Store:backupRuntime.Restores,Capacity:backupClient,Source:backupRuntime.RestoreSource(),Scanner:backup.IntegrityRestoreScanner{},Target:backupClient,Safety:backupClient,Now:runtimeClock{}.Now}
	backupConsoleEdge,err:=newBackupEdge(backupRuntime.Catalog,&restoreWorkflow,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize backup console edge: %w",err)}
	migrationRuntime,err:=localmigration.New(ctx,repositories.ControlDB,repositories.Migrations);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize migration runtime: %w",err)}
	migrationConsoleEdge,err:=newMigrationEdge(migrationRuntime,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize migration console edge: %w",err)}
	fleetHAConsoleEdge,err:=newFleetHAEdge(&repositories.HA,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize fleet and HA console edge: %w",err)}
	repositories.WebCatalog = catalog
	go certificateRenewal.RunQueue(ctx,15*time.Minute,4)
	if mailTelemetryReady{go mailConsoleEdge.RunMailTelemetry(ctx,15*time.Second)}
	return apiserver.DomainServices{
		DashboardEdge:     dashboardConsoleEdge,
		Hosting:          hostingCoordinator,
		HostingQuery:     repositories.Hosting,
		HostingPreviews:  previewSessions,
		HostingEdge:      hostingConsoleEdge,
		HostingCloneEdge: hostingCloneConsoleEdge,
		HostingPreviewEdge: hostingPreviewConsoleEdge,
		HostingAccessPolicyEdge: hostingConsoleEdge,
		Database:         databaseCoordinator,
		DatabaseEdge:     databaseConsoleEdge,
		Operations:       operationsCoordinator,
		OperationsEdge:   operationsConsoleEdge,
		MailControl:      mailCoordinator,
		MailQueue:        mailClient,
		MailEdge:         mailConsoleEdge,
		Webmail:          webmailService,
		MailSessions:     mailSessions,
		MailDelivery:     mailDeliveryService,
		WebmailEdge:      webmailConsoleEdge,
		DNSAuthority:     dnsAuthority,
		DNSSEC:           dnssecCoordinator,
		DNSEdge:          dnsConsoleEdge,
		HTTP01:           certificateRuntime.HTTP01,
		DNS01:            certificateRuntime.DNS01,
		CertificateIssuance: certificateIssuance,
		CertificateDeployment: certificateDeployment,
		CertificateMaterials: certificateMaterials,
		CertificateMaterialUploads: certificateRuntime.Secrets,
		CertificateEdge:  certificateConsoleEdge,
		Files:            fileService,
		Credentials:      credentialService,
		Cron:             cronService,
		Git:              gitService,
		Staging:          stagingService,
		AccessEdge:       accessConsoleEdge,
		Applications:     applicationService,
		ApplicationLifecycle: applicationLifecycle,
		ApplicationStaging: applicationStaging,
		ApplicationAccessProtection: applicationAccessProtection,
		WordPress:        wordpressManager,
		ApplicationAutologin: applicationAutologin,
		ApplicationAutologinBridge: applicationAutologinBridge,
		ApplicationEdge:    applicationConsoleEdge,
		SecurityEdge:     securityConsoleEdge,
		Containers:       containerService,
		ContainerApplications: containerApplications,
		ContainerEdge:    containerConsoleEdge,
		DNSRepository:    &repositories.DNS,
		CertificateStore: &repositories.CertificateIssuance,
		BackupCatalog:     &backupRuntime.Catalog,
		BackupWorkflow:    &backupWorkflow,
		RestoreWorkflow:   &restoreWorkflow,
		Retention:         &backupRetention,
		BackupEdge:        backupConsoleEdge,
		FleetEdge:         fleetHAConsoleEdge,
		HAEdge:            fleetHAConsoleEdge,
		MigrationEdge:     migrationConsoleEdge,
		IdentityEdge:      identityConsoleEdge,
		WebEngine:        webManagement,
		WebEngineEdge:    webEngineConsoleEdge,
		IntegrationEdge:   integrationConsoleEdge,
		Marketing:         &repositories.Marketing,
		Campaigns:         campaignCoordinator,
		Unsubscribe:       unsubscribeService,
		EmailMarketing:    emailMarketingOperations,
		Audit:             auditService,
		SecretEnrollment:  secretEnrollment,
	}, nil
}

type certificateMaterialPolicy struct{trustRoots *x509.CertPool}

func(policy certificateMaterialPolicy)ResolveMaterialImportPolicy(ctx context.Context,principal certificates.MaterialPrincipal,scope certificates.MaterialScope)(certificates.MaterialImportPolicy,error){
	if ctx==nil||policy.trustRoots==nil||principal.TenantID==""||principal.SubjectID==""||principal.TenantID!=scope.TenantID||scope.ResourceID==""{return certificates.MaterialImportPolicy{},certificates.ErrMaterialUnauthorized}
	return certificates.MaterialImportPolicy{TrustRoots:policy.trustRoots,TrustLabel:certificates.MaterialTrustPublicValidated,Names:certificates.MaterialNamePolicy{AllowWildcards:true},AllowedKeyAlgorithms:[]certificates.MaterialKeyAlgorithm{certificates.MaterialKeyECDSA,certificates.MaterialKeyRSA,certificates.MaterialKeyEd25519},MinimumRSAKeyBits:2048,MinimumRemainingLifetime:time.Hour,MaximumLifetime:398*24*time.Hour,MaximumFutureSkew:5*time.Minute},nil
}

func(policy certificateMaterialPolicy)ResolveSelfSignedMaterialPolicy(ctx context.Context,principal certificates.MaterialPrincipal,scope certificates.MaterialScope)(certificates.SelfSignedMaterialPolicy,error){
	if ctx==nil||policy.trustRoots==nil||principal.TenantID==""||principal.SubjectID==""||principal.TenantID!=scope.TenantID||scope.ResourceID==""{return certificates.SelfSignedMaterialPolicy{},certificates.ErrMaterialUnauthorized}
	return certificates.SelfSignedMaterialPolicy{DevelopmentEnabled:true,RecoveryEnabled:true,MinimumLifetime:time.Hour,MaximumDevelopmentTTL:7*24*time.Hour,MaximumRecoveryTTL:24*time.Hour,Backdate:5*time.Minute,AllowedKeyAlgorithms:[]certificates.MaterialKeyAlgorithm{certificates.MaterialKeyECDSA,certificates.MaterialKeyRSA},MinimumRSAKeyBits:3072,AllowWildcards:true},nil
}

type certificateMaterialAuditSink struct{service *audit.Service}

func(sink certificateMaterialAuditSink)RecordMaterialAudit(ctx context.Context,source certificates.MaterialAuditEvent)error{
	if ctx==nil||sink.service==nil||sink.service.Writer==nil||source.EventID==""||source.TenantID==""||source.SubjectID==""||source.Action==""||source.ResourceID==""||source.OccurredAt.IsZero(){return audit.ErrInvalid}
	class,outcome:=audit.ClassMutation,audit.OutcomeFailed
	switch source.Outcome{case "admitted":class,outcome=audit.ClassAuthorization,audit.OutcomeAllowed;case "denied":class,outcome=audit.ClassAuthorization,audit.OutcomeDenied;case "succeeded":outcome=audit.OutcomeApplied;if source.Action==certificates.MaterialActionInspect||source.Action==certificates.MaterialActionList{class=audit.ClassSensitiveRead};case "failed":if source.Action==certificates.MaterialActionInspect||source.Action==certificates.MaterialActionList{class=audit.ClassSensitiveRead};default:return audit.ErrInvalid}
	targetID:=source.MaterialID;if targetID==""{targetID=source.ResourceID};attributes:=map[string]string{};if source.ReasonCode!=""{attributes["reason_code"]=source.ReasonCode};if source.CertificateFingerprint!=""{attributes["certificate_fingerprint_sha256"]=source.CertificateFingerprint}
	digest:=sha256.Sum256([]byte("certificate-material-audit-v1\x00"+source.TenantID+"\x00"+source.SubjectID+"\x00"+string(source.Action)+"\x00"+source.ResourceID+"\x00"+source.MaterialID+"\x00"+source.CertificateFingerprint+"\x00"+source.Outcome+"\x00"+source.ReasonCode+"\x00"+source.OccurredAt.UTC().Format(time.RFC3339Nano)))
	_,err:=sink.service.Writer.Append(ctx,audit.Event{ID:source.EventID,Class:class,Action:string(source.Action),Actor:audit.Actor{PrincipalID:source.SubjectID,TenantID:source.TenantID,Origin:"panel-core"},Target:audit.Target{Kind:"certificate_material",ID:targetID,TenantID:source.TenantID},Outcome:outcome,RequestDigest:hex.EncodeToString(digest[:]),Attributes:attributes,OccurredAt:source.OccurredAt.UTC()});return err
}

var _ certificates.MaterialImportPolicyResolver = certificateMaterialPolicy{}
var _ certificates.SelfSignedMaterialPolicyResolver = certificateMaterialPolicy{}
var _ certificates.MaterialAuditSink = certificateMaterialAuditSink{}

type cyberMailAuthorization struct {
	authorizer *identity.Authorizer
	now        func() time.Time
}

func (authority cyberMailAuthorization) AuthorizeMailDelivery(ctx context.Context, request maildelivery.AuthorizationRequest) error {
	assurance := identity.AssurancePassword
	if request.HighRisk {
		assurance = identity.AssuranceMFA
	}
	return authority.authorize(ctx, request, assurance)
}

func (authority cyberMailAuthorization) VerifyMailDeliveryStepUp(ctx context.Context, request maildelivery.AuthorizationRequest, proofDigest string, operationAt time.Time) error {
	if !request.HighRisk || len(proofDigest) != 64 || operationAt.IsZero() {
		return identity.ErrAssuranceRequired
	}
	if _, err := hex.DecodeString(proofDigest); err != nil {
		return identity.ErrAssuranceRequired
	}
	now := authority.now().UTC()
	if operationAt.After(now.Add(time.Minute)) || now.Sub(operationAt) > 5*time.Minute {
		return identity.ErrAssuranceRequired
	}
	return authority.authorize(ctx, request, identity.AssuranceMFA)
}

func (authority cyberMailAuthorization) authorize(ctx context.Context, request maildelivery.AuthorizationRequest, assurance identity.AssuranceLevel) error {
	if authority.authorizer == nil || authority.now == nil || request.Validate() != nil {
		return identity.ErrForbidden
	}
	principalID, err := identity.NewID(string(request.Actor))
	if err != nil {
		return identity.ErrForbidden
	}
	tenantID, err := identity.NewID(string(request.TenantID))
	if err != nil {
		return identity.ErrForbidden
	}
	decision, err := authority.authorizer.Decide(ctx, identity.AuthorizationRequest{PrincipalID: principalID,
		Permission: identity.MustPermission("mail:manage"), Scope: identity.Scope{Kind: identity.ScopeTenant, TenantID: tenantID},
		At: authority.now().UTC(), Assurance: assurance})
	if err != nil || !decision.Allowed || decision.PrincipalEpoch != request.AuthorizationEpoch {
		return identity.ErrForbidden
	}
	return nil
}

type cyberMailConsent struct{}

func (cyberMailConsent) VerifyMailDeliveryConsent(_ context.Context, request maildelivery.ConsentRequest) error {
	expected := []string{"delivery_metadata", "mail_content", "recipient_address", "sender_address"}
	if request.Validate() != nil || request.Destination != maildelivery.CyberMailAPIBaseURL || len(request.DataClasses) != len(expected) {
		return maildelivery.ErrDenied
	}
	for index := range expected {
		if request.DataClasses[index] != expected[index] {
			return maildelivery.ErrDenied
		}
	}
	return nil
}

type cyberMailAudit struct {
	writer *audit.Writer
}

func (sink cyberMailAudit) RecordMailDelivery(ctx context.Context, record maildelivery.AuditRecord) error {
	if sink.writer == nil || record.Validate() != nil {
		return audit.ErrInvalid
	}
	outcome := audit.OutcomeApplied
	switch record.Outcome {
	case "ambiguous":
		outcome = audit.OutcomeAmbiguous
	case "failed":
		outcome = audit.OutcomeFailed
	case "rejected":
		outcome = audit.OutcomeRejected
	}
	event := audit.Event{ID: "maildelivery." + record.IntentDigest[:48], Class: audit.ClassMutation,
		Action: "maildelivery." + string(record.Action), Actor: audit.Actor{PrincipalID: string(record.Actor), TenantID: string(record.TenantID),
			AuthzEpoch: record.AuthorizationEpoch, Assurance: "gateway"},
		Target: audit.Target{Kind: "maildelivery_binding", ID: string(record.BindingID), TenantID: string(record.TenantID),
			Generation: strconv.FormatUint(record.Generation, 10)}, Outcome: outcome, RequestDigest: record.IntentDigest,
		EffectID: record.ResourceID, Attributes: map[string]string{"boundary": "maildelivery"}, OccurredAt: record.OccurredAt}
	_, err := sink.writer.Append(ctx, event)
	return err
}

type cyberpanelDKIMRuntime struct{client *mail.MailDaemonClient}

func(runtime cyberpanelDKIMRuntime)ApplyDKIMGeneration(ctx context.Context,effect mail.EffectRequest,generation mail.ConfigGeneration)(mail.DKIMRuntimeReceipt,error){receipt:=mail.DKIMRuntimeReceipt{};if runtime.client==nil{return receipt,mail.ErrInvalidCommand};applied,activation,err:=runtime.client.ApplyGeneration(ctx,effect,generation);receipt.Effect=applied;receipt.GenerationDigest=activation.GenerationDigest;receipt.RolledBack=activation.RolledBack;if err!=nil{return receipt,err};reload,reloadErr:=runtime.client.ControlService(ctx,mail.ServiceOpenDKIM,mail.ServiceReload);receipt.OpenDKIMReloadDigest=reload.EvidenceDigest;probe,probeErr:=runtime.client.ControlService(ctx,mail.ServiceOpenDKIM,mail.ServiceProbe);receipt.OpenDKIMProbeDigest=probe.EvidenceDigest;receipt.OpenDKIMActive=probe.Active;if reloadErr!=nil{return receipt,reloadErr};if probeErr!=nil{return receipt,probeErr};if !probe.Active{return receipt,mail.ErrInvalidReceipt};return receipt,nil}
