//go:build linux

package main

import (
	"context"
	"fmt"

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
	localmigration "github.com/aonsyed/cyberpanel/platform/internal/migration/localruntime"
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
	if ctx == nil || repositories.ControlDB == nil || identityService == nil || identityStore == nil {
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
	webmailKey,err:=mail.LoadMailSessionCredential(mail.MailSessionCredentialPath);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("load webmail session authority: %w",err)};defer func(){for index:=range webmailKey{webmailKey[index]=0}}()
	webmailService,mailSessions,err:=mail.NewLocalWebmailService(webmailKey,"cyberpanel-webmail",mailHostname,repositories.Webmail,repositories.MailControl);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize webmail runtime: %w",err)}
	webmailConsoleEdge,err:=newWebmailEdge(webmailService,repositories.Webmail);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize webmail console edge: %w",err)}
	repositories.MailDeliveryPolicy.ResolveLimit=mail.ControlDeliveryLimitResolver(repositories.MailControl,mail.DeliveryLimit{HourlyMessages:500,MonthlyMessages:100000,HourlyRecipients:500,MonthlyRecipients:100000,MaxMessageBytes:16<<20,MaxRecipientsPerMessage:1})
	unsubscribeKey,err:=mail.LoadCampaignUnsubscribeCredential(mail.CampaignUnsubscribeCredentialPath);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("load campaign unsubscribe authority: %w",err)};defer func(){for index:=range unsubscribeKey{unsubscribeKey[index]=0}}()
	campaignSender,err:=mail.NewLocalCampaignSender(repositories.Marketing,repositories.MailControl,repositories.MailDeliveryPolicy,mailHostname,unsubscribeKey,"https://"+panelRegistrableDomain+"/unsubscribe");if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize campaign delivery runtime: %w",err)}
	campaignCoordinator:=&mail.CampaignCoordinator{Store:repositories.Marketing,Sender:campaignSender,Now:runtimeClock{}.Now}
	unsubscribeService:=&mail.UnsubscribeService{Store:repositories.Marketing,Signer:campaignSender.Signer,Now:runtimeClock{}.Now}
	dnsAuthority := dns.NewLocalPowerDNSControlClient()
	dnssecCoordinator:=&dns.DNSSECCoordinator{Store:repositories.DNSSEC,Executor:dnsAuthority,Observer:dnsAuthority,Now:runtimeClock{}.Now}
	dnsConsoleEdge,err:=newDNSEdge(dnsAuthority,dnssecCoordinator);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize DNS console edge: %w",err)}
	certificateRuntime,err:=certificates.NewLocalLinuxClientRuntimeForCurrentExecutable(nil,false,dnsAuthority);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize certificate runtime: %w",err)}
	certificateIssuance:=certificateRuntime.Issuance(repositories.CertificateIssuance)
	certificateDeployment:=certificateRuntime.Deployment(repositories.Certificates)
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
	applicationConsoleEdge,err:=newApplicationEdge(applicationService,applicationLifecycle,wordpressManager,repositories.Applications,repositories.Hosting,applicationClient,applicationCatalog,applicationCatalogAuthority,applicationSecrets,installedEdition,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize application console edge: %w",err)}
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
	backupRetention := backupRuntime.RetentionCoordinator(nil)
	backupWorkflow:=backupRuntime.BackupCoordinator(backupClient,backupClient)
	restoreWorkflow:=backup.RestoreCoordinator{Store:backupRuntime.Restores,Capacity:backupClient,Source:backupRuntime.RestoreSource(),Scanner:backup.IntegrityRestoreScanner{},Target:backupClient,Safety:backupClient,Now:runtimeClock{}.Now}
	backupConsoleEdge,err:=newBackupEdge(backupRuntime.Catalog,backupRuntime.Restores,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize backup console edge: %w",err)}
	migrationRuntime,err:=localmigration.New(ctx,repositories.ControlDB,repositories.Migrations);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize migration runtime: %w",err)}
	migrationConsoleEdge,err:=newMigrationEdge(migrationRuntime,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize migration console edge: %w",err)}
	fleetHAConsoleEdge,err:=newFleetHAEdge(&repositories.HA,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize fleet and HA console edge: %w",err)}
	repositories.WebCatalog = catalog
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
		WebmailEdge:      webmailConsoleEdge,
		DNSAuthority:     dnsAuthority,
		DNSSEC:           dnssecCoordinator,
		DNSEdge:          dnsConsoleEdge,
		HTTP01:           certificateRuntime.HTTP01,
		DNS01:            certificateRuntime.DNS01,
		CertificateIssuance: certificateIssuance,
		CertificateDeployment: certificateDeployment,
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
		Audit:             auditService,
		SecretEnrollment:  secretEnrollment,
	}, nil
}
