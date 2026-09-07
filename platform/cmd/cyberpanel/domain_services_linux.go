//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	stdmail "net/mail"
	"net/textproto"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	backupproviders "github.com/aonsyed/cyberpanel/platform/internal/backup/providers"
	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	marketing "github.com/aonsyed/cyberpanel/platform/internal/emailmarketing"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/webactivation"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/preview"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	hostingservice "github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/maildelivery"
	"github.com/aonsyed/cyberpanel/platform/internal/maintenance"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	localmigration "github.com/aonsyed/cyberpanel/platform/internal/migration/localruntime"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/redisservice"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	securewebmail "github.com/aonsyed/cyberpanel/platform/internal/webmail"
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

type localEmailMarketingDeliveryProvider struct {
	client             *mail.MailDaemonClient
	unsubscribeBaseURL string
}

type migrationChunkMaintenanceAudit struct{ service *audit.Service }

func (sink migrationChunkMaintenanceAudit) RecordMigrationChunkMaintenance(ctx context.Context, evidence migration.ChunkMaintenanceEvidence) error {
	if sink.service == nil || sink.service.Writer == nil || len(evidence.EvidenceDigest) != sha256.Size*2 {
		return audit.ErrInvalid
	}
	outcome := audit.OutcomeApplied
	if evidence.State == migration.ChunkMaintenanceNeedsReconciliation {
		outcome = audit.OutcomeAmbiguous
	} else if evidence.State != migration.ChunkMaintenanceHealthy {
		outcome = audit.OutcomeFailed
	}
	_, err := sink.service.Writer.Append(ctx, audit.Event{
		ID:            "migration-chunk-maintenance-" + evidence.EvidenceDigest[:32],
		Class:         audit.ClassSystem,
		Action:        "migration.chunk_maintenance.cycle",
		Actor:         audit.Actor{ServiceID: "panel-core", Origin: "local_scheduler"},
		Target:        audit.Target{Kind: "migration_chunk_store", ID: "local"},
		Outcome:       outcome,
		RequestDigest: evidence.EvidenceDigest,
		Attributes: map[string]string{
			"evidence_digest":     evidence.EvidenceDigest,
			"failure_code":        evidence.FailureCode,
			"lease_fence":         strconv.FormatUint(evidence.LeaseFence, 10),
			"release_cursor":      evidence.ReleaseCursor,
			"gc_cursor":           evidence.GarbageCursor,
			"released_migrations": strconv.FormatUint(uint64(evidence.ReleasedMigrations), 10),
			"gc_receipts":         strconv.FormatUint(uint64(evidence.GarbageReceipts), 10),
		},
		OccurredAt: evidence.CompletedAt.UTC(),
	})
	return err
}

func (provider *localEmailMarketingDeliveryProvider) Availability(context.Context, marketing.TenantID, string) (marketing.ProviderAvailability, error) {
	if provider == nil || provider.client == nil {
		return marketing.ProviderAvailability{}, marketing.ErrInvalid
	}
	evidence := sha256.Sum256([]byte("local_mail_daemon_configured"))
	return marketing.ProviderAvailability{Online: true, EvidenceDigest: hex.EncodeToString(evidence[:])}, nil
}

func (provider *localEmailMarketingDeliveryProvider) Send(ctx context.Context, envelope marketing.DeliveryEnvelope) (marketing.ProviderResult, error) {
	if provider == nil || provider.client == nil || !envelope.Test || envelope.TextBody == "" || len(envelope.Subject)+len("[TEST] ") > 998 {
		return marketing.ProviderResult{}, marketing.ErrInvalid
	}
	sender, err := stdmail.ParseAddress(envelope.From)
	if err != nil || mail.ValidateAddress(mail.Address(strings.ToLower(sender.Address))) != nil {
		return marketing.ProviderResult{}, marketing.ErrInvalid
	}
	parts := strings.SplitN(strings.ToLower(sender.Address), "@", 2)
	if len(parts) != 2 {
		return marketing.ProviderResult{}, marketing.ErrInvalid
	}
	replyTo := mail.Address("")
	if envelope.ReplyTo != "" {
		parsed, parseErr := stdmail.ParseAddress(envelope.ReplyTo)
		if parseErr != nil || mail.ValidateAddress(mail.Address(strings.ToLower(parsed.Address))) != nil {
			return marketing.ProviderResult{}, marketing.ErrInvalid
		}
		replyTo = mail.Address(strings.ToLower(parsed.Address))
	}
	sum := sha256.Sum256([]byte(envelope.IdempotencyKey))
	binding := mail.WebmailBinding{TenantID: string(envelope.TenantID), MailboxID: mail.MailboxID("test_" + hex.EncodeToString(sum[:16])), Address: mail.Address(strings.ToLower(sender.Address)), ServerName: parts[1]}
	submission := mail.CampaignSubmission{CampaignID: mail.CampaignID("test_" + hex.EncodeToString(sum[16:])), Sender: binding, Recipient: mail.Address(envelope.Recipient), ReplyTo: replyTo, Subject: "[TEST] " + envelope.Subject, Text: envelope.TextBody, SanitizedHTML: envelope.HTMLBody, UnsubscribeURL: provider.unsubscribeBaseURL, IdempotencyKey: envelope.IdempotencyKey}
	queueID, err := provider.client.SubmitCampaign(ctx, submission)
	if errors.Is(err, mail.ErrRateLimited) {
		return marketing.ProviderResult{Disposition: marketing.ProviderDeferred, Reason: "local_rate_limited", RetryAfter: time.Minute, Definitive: true}, nil
	}
	if err != nil {
		return marketing.ProviderResult{Disposition: marketing.ProviderUnknown, Reason: "local_submission_unavailable", Definitive: false}, err
	}
	return marketing.ProviderResult{Disposition: marketing.ProviderAccepted, ProviderMessageID: string(queueID), Definitive: true}, nil
}

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
	malwareService,err:=newMalwareOperationalService(ctx,repositories.ControlDB,identityStore,auditService);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize malware operations: %w",err)}
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
	redisRepository,err:=redisservice.NewSQLiteRepository(repositories.ControlDB)
	if err!=nil{return apiserver.DomainServices{},fmt.Errorf("open managed Redis repository: %w",err)}
	if err=redisRepository.Init(ctx);err!=nil{return apiserver.DomainServices{},fmt.Errorf("bootstrap managed Redis repository: %w",err)}
	operationsConsoleEdge, err := newOperationsEdge(operationsCoordinator, repositories.Operations, redisRepository, "local")
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
	legacyWebmailEdge,err:=newWebmailEdge(webmailService,repositories.Webmail);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize webmail console edge: %w",err)}
	if auditService==nil{return apiserver.DomainServices{},fmt.Errorf("initialize webmail runtime: audit authority is unavailable")}
	webmailRepository,err:=securewebmail.NewSQLiteRepository(repositories.ControlDB);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("open secure webmail repository: %w",err)}
	webmailBackend,err:=securewebmail.NewDovecotBackend(securewebmail.Endpoint{TLSAddress:"127.0.0.1:993",TLSServerName:mailHostname,DialTimeout:5*time.Second,CommandTimeout:20*time.Second});if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize Dovecot OAuth backend: %w",err)}
	secureWebmailService,err:=securewebmail.NewService(webmailRepository,secureWebmailDirectory{store:repositories.MailControl},secureWebmailAudit{service:auditService},webmailBackend,"cyberpanel-webmail",90*time.Second);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize secure webmail service: %w",err)}
	const webmailBlobRoot="/var/lib/cyberpanel/webmail/blobs"
	if err=os.MkdirAll(webmailBlobRoot,0700);err!=nil{return apiserver.DomainServices{},fmt.Errorf("create webmail blob store: %w",err)}
	webmailBlobs,err:=securewebmail.NewLocalBlobStore(webmailBlobRoot);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("open webmail blob store: %w",err)}
	webmailImages,err:=securewebmail.NewHTTPRemoteImageProxy(net.DefaultResolver,&net.Dialer{Timeout:5*time.Second},64<<20);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize webmail image proxy: %w",err)}
	if err=secureWebmailService.ConfigureContent(securewebmail.ContentDependencies{Blobs:webmailBlobs,Scanner:localClamScanner{socket:"/run/clamd/cyberpanel.sock"},Images:webmailImages,Submitter:localWebmailSubmitter{address:"127.0.0.1:25"},Spam:failClosedSpamReporter{}});err!=nil{return apiserver.DomainServices{},fmt.Errorf("configure secure webmail content: %w",err)}
	if err=secureWebmailService.Bootstrap(ctx);err!=nil{return apiserver.DomainServices{},fmt.Errorf("bootstrap secure webmail: %w",err)}
	if err=bootstrapWebmailDovecotTokens(ctx,repositories.ControlDB);err!=nil{return apiserver.DomainServices{},fmt.Errorf("bootstrap Dovecot token bridge: %w",err)}
	if err=serveWebmailTokenInfo(ctx,repositories.ControlDB,repositories.MailControl);err!=nil{return apiserver.DomainServices{},fmt.Errorf("start Dovecot token introspection: %w",err)}
	if err=activateWebmailDovecotOAuth(ctx,mailProjector,mailClient);err!=nil{return apiserver.DomainServices{},fmt.Errorf("activate Dovecot OAuth passdb: %w",err)}
	webmailConsoleEdge:=integratedWebmailEdge{secure:secureWebmailService,legacy:legacyWebmailEdge}
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
	localMarketingDelivery:=&localEmailMarketingDeliveryProvider{client:campaignSender.Client,unsubscribeBaseURL:campaignSender.Signer.BaseURL}
	if err=emailMarketingOperations.ConfigureContentRuntime(fileService,localMarketingDelivery,unsubscribeKey);err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize email marketing content runtime: %w",err)}
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
	packagedN8N,err:=containers.ReadPackagedN8NRecipe(ctx,recipeVerifier);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("load packaged n8n recipe: %w",err)}
	if err=integrations.ValidateN8NApplicationRecipe(packagedN8N);err!=nil{return apiserver.DomainServices{},fmt.Errorf("validate packaged n8n contract: %w",err)}
	if err=containerApplications.RegisterRecipe(ctx,packagedN8N);err!=nil{return apiserver.DomainServices{},fmt.Errorf("register packaged n8n recipe: %w",err)}
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
	var migrationSecrets *migrationSecretTarget
	migrationSecretFactory:=func(ctx context.Context,db *sql.DB,scopes *migration.RuntimeScopeStore)(migration.MigrationSecretGateway,error){
		value,createErr:=newMigrationSecretTarget(ctx,db,scopes);if createErr!=nil{return nil,createErr};migrationSecrets=value;return value,nil
	}
	migrationDatabaseFactory:=func(ctx context.Context,db *sql.DB,chunks *migration.ChunkStore,scopes *migration.RuntimeScopeStore)(migration.CanonicalImportHandler,error){
		if migrationSecrets==nil{return nil,migration.ErrBlocked}
		resolveSecret:=func(ctx context.Context,id migration.ID,envelope string)(migration.DatabaseImportCredential,error){metadata,resolveErr:=migrationSecrets.Resolve(ctx,id,envelope);if resolveErr!=nil{return migration.DatabaseImportCredential{},resolveErr};ref,resolveErr:=database.NewSecretRef(metadata.ID.String());if resolveErr!=nil{return migration.DatabaseImportCredential{},resolveErr};credential:=migration.DatabaseImportCredential{SecretRef:ref};switch metadata.Audience.ResourceKind{case "database_principal":case "database_principal_native_hash":credential.Format=database.CredentialFormatNativeHash;default:return migration.DatabaseImportCredential{},migration.ErrBlocked};return credential,nil}
		resolveSite:=func(ctx context.Context,id,source migration.ID)(site.SiteID,error){value,loadErr:=repositories.Migrations.Migration(ctx,id);if loadErr!=nil{return site.SiteID{},loadErr};plan,loadErr:=repositories.Migrations.Plan(ctx,value.PlanDigest);if loadErr!=nil{return site.SiteID{},loadErr};if plan.ApprovedAt==nil||plan.ApprovalDigest==""||plan.MigrationID!=id{return site.SiteID{},migration.ErrBlocked};for _,mapping:=range plan.Mappings{if mapping.SourceKind==string(migration.ImportSite)&&mapping.SourceID==source&&mapping.Disposition==migration.DispositionCreate{return site.NewSiteID(mapping.TargetID.String())}};return site.SiteID{},migration.ErrBlocked}
		return migration.NewDatabaseImportHandler(ctx,db,chunks,scopes,databaseCoordinator,repositories.Database,databaseExecutor,resolveSecret,resolveSite)
	}
	migrationScopes,err:=migration.NewRuntimeScopeStore(repositories.ControlDB);if err!=nil{return apiserver.DomainServices{},err}
	migrationProbe:=&migrationApplicationProbe{catalog:catalog,runtime:webManagementRuntime,installations:repositories.WebEngine,scopes:migrationScopes}
	migrationFactory:=migrationTargetFactory(hostingCoordinator,repositories.Hosting,fileService,dnsAuthority,repositories.Migrations,migrationProbe,migrationSecretFactory,migrationDatabaseFactory)
	migrationRuntime,err:=localmigration.New(ctx,repositories.ControlDB,repositories.Migrations,migrationFactory);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize migration runtime: %w",err)}
	migrationConsoleEdge,err:=newMigrationEdge(migrationRuntime,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize migration console edge: %w",err)}
	haApprovalAuthority,_:=newHAPromotionApprovalAuthority(&repositories.HA,identityStore,runtimeClock{}.Now)
	haRemoteSender,err:=newHAFederatedSender(ctx,repositories.ControlDB,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize federated HA sender: %w",err)}
	localHAProviders,err:=newLocalMariaDBHAProviders(ctx,&repositories.HA,databaseExecutor,databaseExecutor,catalog,activationClient,configuration.Engine.Listeners,haApprovalAuthority,haRemoteSender,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize local MariaDB HA providers: %w",err)}
	fleetHAConsoleEdge,err:=newFleetHAEdge(&repositories.HA,localHAProviders,haApprovalAuthority,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize fleet and HA console edge: %w",err)}
	federationConsoleEdge,err:=newFederationEdge(ctx,repositories.ControlDB,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize federation console edge: %w",err)}
	maintenanceRepository,err:=maintenance.NewRepository(repositories.ControlDB);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("open maintenance-window repository: %w",err)}
	if err=maintenanceRepository.Bootstrap(ctx);err!=nil{return apiserver.DomainServices{},fmt.Errorf("bootstrap maintenance-window repository: %w",err)}
	maintenanceEvaluator,err:=maintenance.NewEvaluator(maintenanceRepository,maintenance.EvaluatorConfig{});if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize maintenance-window evaluator: %w",err)}
	maintenanceWindows,err:=maintenance.NewWindowService(maintenanceRepository,maintenanceEvaluator,maintenance.WindowServiceConfig{Now:runtimeClock{}.Now});if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize maintenance-window service: %w",err)}
	productUpdateEdge,err:=assembleProductUpdateEdge(ctx,repositories.ControlDB,auditService,runtimeClock{});if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize product-update catalog: %w",err)}
	packageMaintenanceEdge,err:=assemblePackageMaintenanceEdge(ctx,repositories.ControlDB,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize package-maintenance runtime: %w",err)}
	if err=migrationRuntime.StartChunkMaintenance(ctx,migrationChunkMaintenanceAudit{service:auditService});err!=nil{_=migrationRuntime.Close();return apiserver.DomainServices{},fmt.Errorf("start migration chunk maintenance: %w",err)}
	rebootControlEdge,err:=assembleRebootControlLinuxEdge(ctx,repositories.ControlDB,operationsExecutor,repositories.HA,runtimeClock{}.Now);if err!=nil{return apiserver.DomainServices{},fmt.Errorf("initialize reboot-control runtime: %w",err)}
	repositories.WebCatalog = catalog
	go certificateRenewal.RunQueue(ctx,15*time.Minute,4)
	if err = startFederationRuntime(ctx,repositories.ControlDB,localHAProviders); err != nil { return apiserver.DomainServices{},fmt.Errorf("initialize federation runtime: %w",err) }
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
		ProductUpdates:   productUpdateEdge,
		PackageMaintenance: packageMaintenanceEdge,
		MaintenanceWindows: maintenanceWindows,
		RebootControl:    rebootControlEdge,
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
		Malware:          malwareService,
		Containers:       containerService,
		ContainerApplications: containerApplications,
		N8N: &integrations.N8NRuntime{Applications:containerApplications,Containers:containerService,Repository:repositories.Containers,Store:repositories.Integrations,Verifier:recipeVerifier,Allocator:containerIDs,AuthorizeSite:func(ctx context.Context,tenantID,siteID string)error{tenant,err:=site.NewTenantID(tenantID);if err!=nil{return err};resource,err:=site.NewSiteID(siteID);if err!=nil{return err};_,err=repositories.Hosting.Load(ctx,tenant,resource);return err}},
		ContainerEdge:    containerConsoleEdge,
		DNSRepository:    &repositories.DNS,
		CertificateStore: &repositories.CertificateIssuance,
		BackupCatalog:     &backupRuntime.Catalog,
		BackupWorkflow:    &backupWorkflow,
		RestoreWorkflow:   &restoreWorkflow,
		Retention:         &backupRetention,
		BackupEdge:        backupConsoleEdge,
		FleetEdge:         federationConsoleEdge,
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

type integratedWebmailEdge struct{secure *securewebmail.Service;legacy apiserver.WebmailEdgeService}
func(edge integratedWebmailEdge)SecureWebmail()*securewebmail.Service{return edge.secure}
func(edge integratedWebmailEdge)ListContacts(ctx context.Context,call apiserver.EdgeCall,session mail.MailSession,page apiserver.EdgePagePayload)(apiserver.EdgePage[mail.Contact],error){if edge.legacy==nil{return apiserver.EdgePage[mail.Contact]{},mail.ErrUnauthorized};return edge.legacy.ListContacts(ctx,call,session,page)}
func(edge integratedWebmailEdge)ListSieveRules(ctx context.Context,call apiserver.EdgeCall,session mail.MailSession,page apiserver.EdgePagePayload)(apiserver.EdgePage[mail.SieveRule],error){if edge.legacy==nil{return apiserver.EdgePage[mail.SieveRule]{},mail.ErrUnauthorized};return edge.legacy.ListSieveRules(ctx,call,session,page)}

type secureWebmailDirectory struct{store mail.SQLControlRepository}

func(directory secureWebmailDirectory)ListMailAccounts(ctx context.Context,_ securewebmail.Principal,tenant string)([]securewebmail.AuthorizedMailAccount,error){
	mailboxes,next,err:=directory.store.List(ctx,tenant,mail.ResourceMailbox,500,"");if err!=nil{return nil,err};if next!=""{return nil,securewebmail.ErrLimit}
	domains,next,err:=directory.store.List(ctx,tenant,mail.ResourceDomain,500,"");if err!=nil{return nil,err};if next!=""{return nil,securewebmail.ErrLimit}
	domainNames:=make(map[mail.DomainID]string,len(domains));for _,resource:=range domains{if resource.State!=mail.StateActive{continue};var domain mail.Domain;if json.Unmarshal(resource.Spec,&domain)!=nil||domain.ID==""||domain.Tenant!=tenant||domain.Name==""{return nil,securewebmail.ErrProtocol};domainNames[domain.ID]=domain.Name}
	accounts:=make([]securewebmail.AuthorizedMailAccount,0,len(mailboxes));for _,resource:=range mailboxes{if resource.State!=mail.StateActive{continue};var mailbox mail.Mailbox;if json.Unmarshal(resource.Spec,&mailbox)!=nil||string(mailbox.ID)!=resource.ID||!mailbox.Enabled||resource.Generation==0{continue};domain:=domainNames[mailbox.Domain];if domain==""{continue};address:=strings.ToLower(mailbox.Local+"@"+domain);accounts=append(accounts,securewebmail.AuthorizedMailAccount{TenantID:tenant,MailboxID:resource.ID,DisplayLabel:address,AddressLabel:address,AuthorizationEpoch:resource.Generation,Enabled:true})}
	return accounts,nil
}

func(directory secureWebmailDirectory)AuthorizeMailbox(ctx context.Context,_ securewebmail.Principal,tenant,mailboxID string)(securewebmail.AuthorizedMailAccount,error){
	resource,found,err:=directory.store.Load(ctx,tenant,mail.ResourceMailbox,mailboxID);if err!=nil{return securewebmail.AuthorizedMailAccount{},err};if !found||resource.State!=mail.StateActive||resource.Generation==0{return securewebmail.AuthorizedMailAccount{},securewebmail.ErrNotFound}
	var mailbox mail.Mailbox;if json.Unmarshal(resource.Spec,&mailbox)!=nil||string(mailbox.ID)!=mailboxID||!mailbox.Enabled{return securewebmail.AuthorizedMailAccount{},securewebmail.ErrNotFound}
	domainResource,found,err:=directory.store.Load(ctx,tenant,mail.ResourceDomain,string(mailbox.Domain));if err!=nil{return securewebmail.AuthorizedMailAccount{},err};if !found||domainResource.State!=mail.StateActive{return securewebmail.AuthorizedMailAccount{},securewebmail.ErrNotFound}
	var domain mail.Domain;if json.Unmarshal(domainResource.Spec,&domain)!=nil||domain.ID!=mailbox.Domain||domain.Tenant!=tenant||domain.Name==""{return securewebmail.AuthorizedMailAccount{},securewebmail.ErrProtocol}
	address:=strings.ToLower(mailbox.Local+"@"+domain.Name);return securewebmail.AuthorizedMailAccount{TenantID:tenant,MailboxID:mailboxID,DisplayLabel:address,AddressLabel:address,AuthorizationEpoch:resource.Generation,Enabled:true},nil
}

type secureWebmailAudit struct{service *audit.Service}

func(sink secureWebmailAudit)RecordWebmailSecurity(ctx context.Context,event securewebmail.AuditEvent)error{
	if sink.service==nil{return securewebmail.ErrUnavailable};sum:=sha256.Sum256([]byte(event.RequestID+"\x00"+event.Operation+"\x00"+event.MailboxDigest+"\x00"+event.OccurredAt.UTC().Format(time.RFC3339Nano)));request:=sha256.Sum256([]byte(event.RequestID));outcome:=audit.OutcomeAllowed;switch event.Outcome{case"denied":outcome=audit.OutcomeDenied;case"failed":outcome=audit.OutcomeFailed}
	_,err:=sink.service.RecordDecision(ctx,audit.Event{ID:"webmail-"+hex.EncodeToString(sum[:24]),Class:audit.ClassSecurity,Action:"webmail."+event.Operation,Actor:audit.Actor{PrincipalID:event.UserDigest,SessionID:event.SessionDigest,TenantID:event.TenantID},Target:audit.Target{Kind:"mailbox",ID:event.MailboxDigest,TenantID:event.TenantID},Outcome:outcome,RequestDigest:hex.EncodeToString(request[:]),OccurredAt:event.OccurredAt},nil);return err
}

type localWebmailSubmitter struct{address string}
var postfixQueuePattern=regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func(submitter localWebmailSubmitter)Submit(ctx context.Context,envelope securewebmail.SubmissionEnvelope,source io.Reader,maximum uint64)(string,error){
	if ctx==nil||source==nil||submitter.address!="127.0.0.1:25"||maximum==0||maximum>securewebmail.MaximumComposeBytes{return "",securewebmail.ErrInvalid}
	connection,err:=(&net.Dialer{Timeout:5*time.Second}).DialContext(ctx,"tcp",submitter.address);if err!=nil{return "",errors.Join(securewebmail.ErrUnavailable,err)};defer connection.Close();stop:=context.AfterFunc(ctx,func(){_=connection.SetDeadline(time.Now())});defer stop();_=connection.SetDeadline(time.Now().Add(30*time.Second));protocol:=textproto.NewConn(connection)
	if _,_,err=protocol.ReadResponse(220);err!=nil{return "",errors.Join(securewebmail.ErrUnavailable,err)};if err=webmailSMTPCommand(protocol,250,"EHLO localhost");err!=nil{return "",errors.Join(securewebmail.ErrUnavailable,err)};if err=webmailSMTPCommand(protocol,250,"MAIL FROM:<"+envelope.From+">");err!=nil{return "",errors.Join(securewebmail.ErrUnavailable,err)}
	for _,recipient:=range envelope.Recipients{if err=webmailSMTPCommand(protocol,250,"RCPT TO:<"+recipient+">");err!=nil{return "",errors.Join(securewebmail.ErrUnavailable,err)}};if err=webmailSMTPCommand(protocol,354,"DATA");err!=nil{return "",errors.Join(securewebmail.ErrUnavailable,err)}
	writer:=protocol.DotWriter();written,copyErr:=io.Copy(writer,io.LimitReader(source,int64(maximum)+1));if copyErr!=nil||uint64(written)>maximum{if uint64(written)>maximum{return "",securewebmail.ErrLimit};return "",errors.Join(securewebmail.ErrUnavailable,copyErr)};if err=writer.Close();err!=nil{return "",errors.Join(securewebmail.ErrPartial,err)}
	_,reply,err:=protocol.ReadResponse(250);if err!=nil{var protocolError *textproto.Error;if errors.As(err,&protocolError){return "",errors.Join(securewebmail.ErrUnavailable,err)};return "",errors.Join(securewebmail.ErrPartial,err)};_,_=protocol.Cmd("QUIT")
	marker:="queued as ";index:=strings.LastIndex(strings.ToLower(reply),marker);if index<0{return "",errors.Join(securewebmail.ErrPartial,securewebmail.ErrProtocol)};fields:=strings.Fields(reply[index+len(marker):]);if len(fields)==0{return "",errors.Join(securewebmail.ErrPartial,securewebmail.ErrProtocol)};queue:=strings.Trim(fields[0],".[]()");if !postfixQueuePattern.MatchString(queue){return "",errors.Join(securewebmail.ErrPartial,securewebmail.ErrProtocol)};return queue,nil
}

func webmailSMTPCommand(connection *textproto.Conn,code int,command string)error{id,err:=connection.Cmd("%s",command);if err!=nil{return err};connection.StartResponse(id);defer connection.EndResponse(id);_,_,err=connection.ReadResponse(code);return err}

type localClamScanner struct{socket string}

func(scanner localClamScanner)Scan(ctx context.Context,source io.Reader,maximum uint64)(string,error){
	if ctx==nil||source==nil||scanner.socket!="/run/clamd/cyberpanel.sock"||maximum==0||maximum>securewebmail.MaximumAttachmentBytes{return "",securewebmail.ErrInvalid};connection,err:=(&net.Dialer{Timeout:5*time.Second}).DialContext(ctx,"unix",scanner.socket);if err!=nil{return "",errors.Join(securewebmail.ErrUnavailable,err)};defer connection.Close();stop:=context.AfterFunc(ctx,func(){_=connection.SetDeadline(time.Now())});defer stop();_=connection.SetDeadline(time.Now().Add(60*time.Second));if _,err=connection.Write([]byte("zINSTREAM\x00"));err!=nil{return "",errors.Join(securewebmail.ErrUnavailable,err)}
	buffer:=make([]byte,32<<10);limited:=io.LimitReader(source,int64(maximum)+1);var total uint64;for{read,readErr:=limited.Read(buffer);if read>0{total+=uint64(read);if total>maximum{return "",securewebmail.ErrLimit};var length [4]byte;binary.BigEndian.PutUint32(length[:],uint32(read));if _,err=connection.Write(length[:]);err==nil{_,err=connection.Write(buffer[:read])};if err!=nil{return "",errors.Join(securewebmail.ErrUnavailable,err)}};if errors.Is(readErr,io.EOF){break};if readErr!=nil{return "",readErr}}
	if _,err=connection.Write([]byte{0,0,0,0});err!=nil{return "",errors.Join(securewebmail.ErrUnavailable,err)};reply,err:=bufio.NewReaderSize(connection,4096).ReadString(0);if err!=nil||len(reply)>4096{return "",errors.Join(securewebmail.ErrUnavailable,err)};reply=strings.TrimSuffix(reply,"\x00");if strings.HasSuffix(reply,": OK"){return "clean",nil};if strings.HasSuffix(reply," FOUND"){return "infected",nil};return "",securewebmail.ErrUnavailable
}

type failClosedSpamReporter struct{}
func(failClosedSpamReporter)Report(context.Context,securewebmail.BlobOwner,[]securewebmail.MessageIdentity,bool)error{return securewebmail.ErrUnavailable}

type webmailTokenInfo struct{database *sql.DB;directory secureWebmailDirectory}

func activateWebmailDovecotOAuth(ctx context.Context,projector mail.RepositorySnapshotProjector,client *mail.MailDaemonClient)error{
	if ctx==nil||client==nil{return mail.ErrInvalidCommand};request:=mail.EffectRequest{CommandID:"startup-webmail-dovecot-oauth",TenantID:"system",Kind:mail.ResourcePolicy,ResourceID:"webmail-dovecot-oauth",Generation:1,Action:mail.ActionUpdate}
	snapshot,err:=projector.ProjectMail(ctx,request);if err!=nil{return err};generation,err:=(mail.ConfigRenderer{}).Render(snapshot);if err!=nil{return err};binding:=sha256.Sum256([]byte("webmail-dovecot-oauth-activation-v1\x00"+generation.Digest));request.EffectID="mailfx_"+hex.EncodeToString(binding[:])[:48];request.CommandDigest=generation.Digest;request.DesiredDigest=generation.Digest
	effect,activation,err:=client.ApplyGeneration(ctx,request,generation);if err!=nil{return err};if effect.Outcome!=mail.EffectConfirmed||effect.AppliedGeneration!=activation.GenerationDigest||effect.ProbeDigest==""{return mail.ErrInvalidReceipt};return nil
}

func bootstrapWebmailDovecotTokens(ctx context.Context,database *sql.DB)error{if ctx==nil||database==nil{return securewebmail.ErrInvalid};_,err:=database.ExecContext(ctx,`CREATE TABLE IF NOT EXISTS webmail_dovecot_tokens_v1(token_digest TEXT PRIMARY KEY CHECK(length(token_digest)=64),tenant_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,authz_epoch INTEGER NOT NULL,expires_at INTEGER NOT NULL,consumed_at INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS webmail_dovecot_grant_consumed_v1 AFTER UPDATE OF consumed_at ON webmail_grants_v1 WHEN NEW.consumed_at IS NOT NULL AND OLD.consumed_at IS NULL BEGIN INSERT OR REPLACE INTO webmail_dovecot_tokens_v1(token_digest,tenant_id,mailbox_id,authz_epoch,expires_at,consumed_at) VALUES(NEW.token_digest,NEW.tenant_id,NEW.mailbox_id,NEW.authz_epoch,NEW.expires_at,NEW.consumed_at); END;`);if err!=nil{return err};_,err=database.ExecContext(ctx,`DELETE FROM webmail_dovecot_tokens_v1 WHERE expires_at<=?`,time.Now().UTC().UnixNano());return err}

func serveWebmailTokenInfo(ctx context.Context,database *sql.DB,store mail.SQLControlRepository)error{
	if ctx==nil||database==nil||store.DB==nil{return securewebmail.ErrInvalid};listener,err:=net.Listen("tcp","127.0.0.1:18090");if err!=nil{return err};server:=&http.Server{Handler:webmailTokenInfo{database:database,directory:secureWebmailDirectory{store:store}},ReadHeaderTimeout:3*time.Second,ReadTimeout:5*time.Second,WriteTimeout:5*time.Second,IdleTimeout:5*time.Second,MaxHeaderBytes:8<<10};go func(){ticker:=time.NewTicker(time.Minute);defer ticker.Stop();for{select{case<-ctx.Done():shutdown,cancel:=context.WithTimeout(context.Background(),3*time.Second);_=server.Shutdown(shutdown);cancel();return;case now:=<-ticker.C:_,_=database.ExecContext(ctx,`DELETE FROM webmail_dovecot_tokens_v1 WHERE expires_at<=?`,now.UTC().UnixNano())}}}();go func(){_=server.Serve(listener)}();return nil
}

func(handler webmailTokenInfo)ServeHTTP(writer http.ResponseWriter,request *http.Request){
	writer.Header().Set("Cache-Control","no-store");writer.Header().Set("Content-Type","application/json");active:=func(){writer.WriteHeader(http.StatusUnauthorized);_,_=writer.Write([]byte(`{"active":false}`))};if request.Method!=http.MethodGet&&request.Method!=http.MethodPost{active();return};token:="";authorization:=strings.TrimSpace(request.Header.Get("Authorization"));if strings.HasPrefix(authorization,"Bearer "){token=strings.TrimSpace(strings.TrimPrefix(authorization,"Bearer "))};if token==""{token=request.URL.Query().Get("access_token")};if token==""&&request.Method==http.MethodPost{request.Body=http.MaxBytesReader(writer,request.Body,4<<10);if request.ParseForm()==nil{token=request.Form.Get("token")}};if len(token)<32||len(token)>256||strings.ContainsAny(token,"\x00\r\n\t "){active();return};digest:=sha256.Sum256([]byte(token));digestString:=hex.EncodeToString(digest[:]);now:=time.Now().UTC();var tenant,mailbox string;var epoch uint64;var expires,consumed int64;err:=handler.database.QueryRowContext(request.Context(),`SELECT tenant_id,mailbox_id,authz_epoch,expires_at,consumed_at FROM webmail_dovecot_tokens_v1 WHERE token_digest=? AND expires_at>?`,digestString,now.UnixNano()).Scan(&tenant,&mailbox,&epoch,&expires,&consumed);if err!=nil||consumed<=0||expires<=now.UnixNano(){active();return};account,err:=handler.directory.AuthorizeMailbox(request.Context(),securewebmail.Principal{UserID:"dovecot",SessionID:"introspection"},tenant,mailbox);if err!=nil||account.AuthorizationEpoch!=epoch{active();return};result,err:=handler.database.ExecContext(request.Context(),`DELETE FROM webmail_dovecot_tokens_v1 WHERE token_digest=? AND consumed_at=? AND expires_at>?`,digestString,consumed,now.UnixNano());if err!=nil{active();return};rows,err:=result.RowsAffected();if err!=nil||rows!=1{active();return};_,_=handler.database.ExecContext(request.Context(),`UPDATE webmail_grants_v1 SET revoked_at=? WHERE token_digest=? AND consumed_at=? AND revoked_at IS NULL`,now.UnixNano(),digestString,consumed);writer.WriteHeader(http.StatusOK);_=json.NewEncoder(writer).Encode(map[string]any{"active":true,"email":account.AddressLabel,"username":account.AddressLabel,"scope":"imap"})
}
