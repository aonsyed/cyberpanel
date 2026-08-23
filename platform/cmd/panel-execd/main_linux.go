//go:build linux

package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/webactivation"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation/fsstore"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/lswsruntime"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/management"
)

const webEngineConfigurationRoot = "/usr/local/lsws/conf"

type serveResult struct { name string; err error }

func main() {
	if os.Geteuid() != 0 { log.Fatal("panel-execd must run as root") }
	edition, err := siteops.LoadEngineEdition(); if err != nil { log.Fatalf("load web-engine edition: %v", err) }
	controlUID, controlGID, err := siteops.LookupControlIdentity(); if err != nil { log.Fatalf("resolve control-plane identity: %v", err) }
	backend, err := siteops.NewLinuxStateBackend(); if err != nil { log.Fatalf("open durable registry backend: %v", err) }; defer backend.Close()
	registry, err := siteops.NewDurableRegistryWithUIDAvailability(backend, siteops.DefaultUIDMinimum, siteops.DefaultUIDMaximum, siteops.LinuxUIDAvailable); if err != nil { log.Fatalf("open durable site registry: %v", err) }
	host, err := siteops.NewLinuxHost(); if err != nil { log.Fatalf("initialize privileged host: %v", err) }; defer host.Close()
	executor, err := siteops.NewExecutor(registry, host, siteops.InstalledPHPResolver{}, siteops.Config{Edition: edition, Retention: siteops.DefaultRetention}); if err != nil { log.Fatalf("initialize site executor: %v", err) }
	policy, err := siteops.NewPeerPolicy(controlUID); if err != nil { log.Fatalf("initialize peer policy: %v", err) }
	listener, err := siteops.ListenDefault(controlGID); if err != nil { log.Fatalf("listen on privileged siteops socket: %v", err) }; defer listener.Close()
	server := &siteops.Server{Authorizer: policy, Handler: executor, MaximumConcurrent: 128}
	installedEdition := webengine.Edition(edition)
	configurationStore, err := fsstore.New(webEngineConfigurationRoot, installedEdition); if err != nil { log.Fatalf("open web-engine configuration store: %v", err) }
	journal, err := webactivation.NewJournal(webactivation.DefaultJournalRoot); if err != nil { log.Fatalf("open web-engine activation journal: %v", err) }; defer journal.Close()
	runtimeEngine, err := lswsruntime.NewEngine(webactivation.FixedRunner{}); if err != nil { log.Fatalf("initialize web-engine runtime: %v", err) }
	probeTransport := webactivation.NewLoopbackTransport(); defer probeTransport.CloseIdleConnections()
	activationBroker, err := webactivation.NewBroker(installedEdition, configurationStore, runtimeEngine, probeTransport, journal); if err != nil { log.Fatalf("initialize web-engine activation broker: %v", err) }
	activationPolicy, err := webactivation.NewPeerPolicy(controlUID); if err != nil { log.Fatalf("initialize web-engine activation peer policy: %v", err) }
	activationListener, err := webactivation.ListenDefault(controlGID); if err != nil { log.Fatalf("listen on web-engine activation socket: %v", err) }; defer activationListener.Close()
	activationServer := &webactivation.Server{Authorizer: activationPolicy, Handler: activationBroker, MaximumConcurrent: 32}
	managementHost,err:=management.NewLinuxLifecycleHost();if err!=nil{log.Fatalf("initialize web-engine management host: %v",err)}
	managementPolicy,err:=management.NewLinuxManagementPeerPolicy(controlUID);if err!=nil{log.Fatalf("initialize web-engine management peer policy: %v",err)}
	managementListener,err:=management.ListenLinuxManagementBroker(controlGID);if err!=nil{log.Fatalf("listen on web-engine management socket: %v",err)};defer managementListener.Close()
	managementServer:=&management.LinuxManagementBrokerServer{Authorizer:managementPolicy,Handler:managementHost,MaximumConcurrent:8}
	materialClient, err := secrets.NewLocalMaterialClient(); if err != nil { log.Fatalf("connect protected secret broker: %v", err) }
	installationOwner, err := secrets.NewID("installation"); if err != nil { log.Fatalf("construct installation secret owner: %v", err) }
	databaseSecrets, err := database.NewLinuxSecretBrokerSource(materialClient, installationOwner); if err != nil { log.Fatalf("initialize database secret source: %v", err) }
	distribution, err := database.DetectLinuxMariaDBDistribution(); if err != nil { log.Fatalf("detect MariaDB distribution: %v", err) }
	localDatabase, err := database.DefaultLocalInstance(); if err != nil { log.Fatalf("construct local database instance: %v", err) }
	databaseExecutor, err := database.NewLinuxMariaDBExecutor(databaseSecrets, distribution, []database.DatabaseInstance{localDatabase}); if err != nil { log.Fatalf("initialize MariaDB executor: %v", err) }
	databasePolicy, err := database.NewDatabaseBrokerPeerPolicy(controlUID); if err != nil { log.Fatalf("initialize database peer policy: %v", err) }
	databaseListener, err := database.ListenDatabaseBroker(controlGID); if err != nil { log.Fatalf("listen on database broker socket: %v", err) }; defer databaseListener.Close()
	databaseServer := &database.DatabaseBrokerServer{Authorizer:databasePolicy,Executor:databaseExecutor,MaximumConcurrent:64}
	operationsSecrets, err := operations.NewLinuxOperationsSecretBrokerSource(materialClient, installationOwner); if err != nil { log.Fatalf("initialize operations secret source: %v", err) }
	operationsConfig := operations.DefaultLinuxOperationsConfig(); operationsConfig.Secrets = operationsSecrets
	operationsExecutor, err := operations.NewLinuxOperationsExecutor(operationsConfig); if err != nil { log.Fatalf("initialize operations executor: %v", err) }
	if err = operationsExecutor.ResumeSecurityWatchdogs(context.Background()); err != nil { log.Fatalf("recover unconfirmed firewall/SSH transaction: %v", err) }
	operationsPolicy, err := operations.NewOperationsBrokerPeerPolicy(controlUID); if err != nil { log.Fatalf("initialize operations peer policy: %v", err) }
	operationsListener, err := operations.ListenOperationsBroker(controlGID); if err != nil { log.Fatalf("listen on operations broker socket: %v", err) }; defer operationsListener.Close()
	operationsServer := &operations.OperationsBrokerServer{Authorizer:operationsPolicy,Handler:operationsExecutor,MaximumConcurrent:64}
	managementClient, err := secrets.NewLocalManagementClient(); if err != nil { log.Fatalf("connect protected secret management broker: %v", err) }
	accessSecrets, err := access.NewLinuxAccessSecretSourceWithManagement(materialClient, managementClient, installationOwner); if err != nil { log.Fatalf("initialize access secret source: %v", err) }
	accessResolver := access.LinuxSiteResolverFunc(func(ctx context.Context, siteID access.SiteID) (access.LinuxSiteBinding, error) {
		binding, found, resolveErr := registry.BindingForSite(string(siteID)); if resolveErr != nil { return access.LinuxSiteBinding{}, resolveErr }; if !found { return access.LinuxSiteBinding{}, access.ErrNotFound }
		generation := binding.RootGeneration; if generation == 0 { generation = binding.Fence }
		return access.LinuxSiteBinding{SiteKey:binding.SiteKey,Username:binding.Username,UID:binding.UID,GID:binding.GID,Generation:generation},nil
	})
	accessRuntime, err := access.NewLinuxAccessRuntime(accessResolver, accessSecrets, controlGID); if err != nil { log.Fatalf("initialize access executor: %v", err) }
	accessPolicy, err := access.NewAccessBrokerPeerPolicy(controlUID); if err != nil { log.Fatalf("initialize access peer policy: %v", err) }
	accessListener, err := access.ListenAccessBroker(controlGID); if err != nil { log.Fatalf("listen on access broker socket: %v", err) }; defer accessListener.Close()
	accessJournal, err := access.NewLinuxAccessReceiptJournal(access.DefaultAccessJournalRoot); if err != nil { log.Fatalf("open access receipt journal: %v", err) }; defer accessJournal.Close()
	accessServer := &access.AccessBrokerServer{Authorizer:accessPolicy,Handler:accessRuntime.Handler,Journal:accessJournal,MaximumConcurrent:64}
	applicationResolver:=apps.LinuxApplicationSiteResolverFunc(func(ctx context.Context,siteID apps.SiteID)(apps.LinuxApplicationSiteBinding,error){binding,found,resolveErr:=registry.BindingForSite(string(siteID));if resolveErr!=nil{return apps.LinuxApplicationSiteBinding{},resolveErr};if !found{return apps.LinuxApplicationSiteBinding{},apps.ErrNotFound};generation:=binding.RootGeneration;if generation==0{generation=binding.Fence};return apps.LinuxApplicationSiteBinding{SiteKey:binding.SiteKey,UID:binding.UID,GID:binding.GID,Generation:generation},nil})
	applicationSecrets,err:=apps.NewLinuxApplicationMaterialSource(materialClient);if err!=nil{log.Fatalf("initialize application secret source: %v",err)}
	applicationRuntime,err:=apps.NewLinuxApplicationRuntime(applicationResolver,applicationSecrets);if err!=nil{log.Fatalf("initialize application runtime: %v",err)}
	applicationPolicy,err:=apps.NewLinuxApplicationBrokerPeerPolicy(controlUID);if err!=nil{log.Fatalf("initialize application peer policy: %v",err)}
	applicationListener,err:=apps.ListenLinuxApplicationBroker(controlGID);if err!=nil{log.Fatalf("listen on application broker socket: %v",err)};defer applicationListener.Close()
	applicationServer:=&apps.LinuxApplicationBrokerServer{Authorizer:applicationPolicy,Runtime:applicationRuntime,MaximumConcurrent:32}
	mailPlatform, err := detectMailPlatform(); if err != nil { log.Fatalf("detect mail platform: %v", err) }
	mailOwnership, err := resolveMailOwnership(); if err != nil { log.Fatalf("resolve mail daemon ownership: %v", err) }
	mailHost, err := mail.OpenLinuxMailHost(mailPlatform,mailOwnership); if err != nil { log.Fatalf("initialize mail host: %v", err) }; defer mailHost.Close()
	mailPolicy, err := mail.NewMailDaemonPeerPolicy(controlUID); if err != nil { log.Fatalf("initialize mail peer policy: %v", err) }
	mailListener, err := mail.ListenMailDaemon(controlGID); if err != nil { log.Fatalf("listen on mail daemon socket: %v", err) }; defer mailListener.Close()
	mailServer, err := mail.NewMailDaemonServer(mailHost,mailPolicy); if err != nil { log.Fatalf("initialize mail daemon server: %v", err) }; mailServer.MaximumConcurrent=32;mailServer.MaximumCampaignConcurrent=4
	pdnsPlatform:=dns.PowerDNSUbuntuNoble;if mailPlatform==mail.MailAlma9{pdnsPlatform=dns.PowerDNSAlma9};pdnsGID,err:=lookupFirstGroup("pdns");if err!=nil{log.Fatalf("resolve PowerDNS ownership: %v",err)}
	pdnsMaterial,err:=dns.NewPowerDNSMaterialResolver(materialClient,installationOwner);if err!=nil{log.Fatalf("initialize PowerDNS material source: %v",err)}
	pdnsHost,err:=dns.OpenLinuxPowerDNSHost(pdnsPlatform,dns.PowerDNSOwnership{PDNSGID:pdnsGID},pdnsMaterial,dns.LocalPowerDNSControlFingerprint());if err!=nil{log.Fatalf("initialize PowerDNS host: %v",err)};defer pdnsHost.Close()
	startupContext,cancelStartup:=context.WithTimeout(context.Background(),2*time.Minute)
	pdnsDatabase,pdnsAuthority,err:=dns.OpenLocalSQLitePowerDNSAuthority(startupContext,pdnsMaterial);if err!=nil{cancelStartup();log.Fatalf("open PowerDNS authority: %v",err)};defer pdnsDatabase.Close()
	if _,err=pdnsHost.ApplyConfiguration(startupContext,dns.LocalPowerDNSConfigSnapshot(1));err!=nil{cancelStartup();log.Fatalf("activate PowerDNS configuration: %v",err)}
	cancelStartup()
	pdnsPolicy,err:=dns.NewPowerDNSDaemonPeerPolicy(controlUID);if err!=nil{log.Fatalf("initialize PowerDNS peer policy: %v",err)}
	pdnsListener,err:=dns.ListenPowerDNSDaemon(controlGID);if err!=nil{log.Fatalf("listen on PowerDNS socket: %v",err)};defer pdnsListener.Close()
	pdnsServer,err:=dns.NewPowerDNSDaemonServer(pdnsHost,pdnsAuthority,pdnsPolicy);if err!=nil{log.Fatalf("initialize PowerDNS daemon server: %v",err)};pdnsServer.MaximumConcurrent=16
	containerConfig,err:=containers.DefaultLinuxContainerConfig(materialClient);if err!=nil{log.Fatalf("construct container runtime configuration: %v",err)}
	containerRuntime,err:=containers.NewLinuxContainerRuntime(containerConfig);if err!=nil{log.Fatalf("initialize container runtime: %v",err)}
	containerJournal,err:=containers.NewFileContainerReceiptJournal(containers.DefaultContainerReceiptRoot);if err!=nil{log.Fatalf("open container receipt journal: %v",err)}
	containerPolicy,err:=containers.NewLinuxContainerBrokerPeerPolicy(controlUID);if err!=nil{log.Fatalf("initialize container peer policy: %v",err)}
	containerListener,err:=containers.ListenContainerBroker(controlGID);if err!=nil{log.Fatalf("listen on container broker socket: %v",err)};defer containerListener.Close()
	containerServer:=&containers.ContainerBrokerServer{Authorizer:containerPolicy,Broker:containerRuntime,Journal:containerJournal,MaximumConcurrent:64}
	certificateHost,err:=certificates.NewLinuxCertificateHost();if err!=nil{log.Fatalf("initialize certificate host: %v",err)}
	certificatePolicy,err:=secrets.NewLinuxMaterialPeerAuthorizer(uint32(controlUID));if err!=nil{log.Fatalf("initialize certificate peer policy: %v",err)}
	certificateListener,err:=certificates.ListenCertificateBroker(0,controlGID);if err!=nil{log.Fatalf("listen on certificate broker socket: %v",err)};defer certificateListener.Close()
	certificateServer:=&certificates.CertificateBrokerServer{Authorizer:certificatePolicy,Host:certificateHost,MaximumConcurrent:16}
	backupResolver:=backup.LinuxBackupSiteResolverFunc(func(ctx context.Context,tenantID,siteID string)(backup.LinuxBackupSiteBinding,error){binding,found,resolveErr:=registry.BindingForSite(siteID);if resolveErr!=nil{return backup.LinuxBackupSiteBinding{},resolveErr};if !found{return backup.LinuxBackupSiteBinding{},backup.ErrInvalidBackup};if tenantID!=""&&binding.TenantID!=tenantID{return backup.LinuxBackupSiteBinding{},backup.ErrInvalidBackup};generation:=binding.RootGeneration;if generation==0{generation=binding.Fence};return backup.LinuxBackupSiteBinding{SiteKey:binding.SiteKey,TenantID:binding.TenantID,SiteID:binding.SiteID,UID:binding.UID,GID:binding.GID,Generation:generation},nil})
	backupHost,err:=backup.NewLinuxBackupHost(backupResolver);if err!=nil{log.Fatalf("initialize backup host: %v",err)}
	backupPolicy,err:=backup.NewLinuxBackupPeerPolicy(controlUID);if err!=nil{log.Fatalf("initialize backup peer policy: %v",err)}
	backupListener,err:=backup.ListenLinuxBackupBroker(controlGID);if err!=nil{log.Fatalf("listen on backup broker socket: %v",err)};defer backupListener.Close()
	backupServer:=&backup.LinuxBackupBrokerServer{Authorizer:backupPolicy,Executor:backupHost,MaximumConcurrent:16}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM); defer cancel()
	serveErrors := make(chan serveResult, 12)
	go func() { serveErrors <- serveResult{name: "siteops", err: server.Serve(listener)} }()
	go func() { serveErrors <- serveResult{name: "web-engine activation", err: activationServer.Serve(activationListener)} }()
	go func() { serveErrors <- serveResult{name: "web-engine management", err: managementServer.Serve(managementListener)} }()
	go func() { serveErrors <- serveResult{name: "database", err: databaseServer.Serve(databaseListener)} }()
	go func() { serveErrors <- serveResult{name: "operations", err: operationsServer.Serve(operationsListener)} }()
	go func() { serveErrors <- serveResult{name: "access", err: accessServer.Serve(accessListener)} }()
	go func() { serveErrors <- serveResult{name: "mail", err: mailServer.Serve(mailListener)} }()
	go func() { serveErrors <- serveResult{name: "powerdns", err: pdnsServer.Serve(pdnsListener)} }()
	go func() { serveErrors <- serveResult{name: "containers", err: containerServer.Serve(containerListener)} }()
	go func() { serveErrors <- serveResult{name: "certificates", err: certificateServer.Serve(certificateListener)} }()
	go func() { serveErrors <- serveResult{name: "applications", err: applicationServer.Serve(applicationListener)} }()
	go func() { serveErrors <- serveResult{name: "backup", err: backupServer.Serve(backupListener)} }()
	go collectTombstones(ctx, executor)
	select {
	case <-ctx.Done():
		_ = listener.Close()
		_ = activationListener.Close()
		_ = managementListener.Close()
		_ = databaseListener.Close()
		_ = operationsListener.Close()
		_ = accessListener.Close()
		_ = mailListener.Close()
		_ = pdnsListener.Close()
		_ = containerListener.Close()
		_ = certificateListener.Close()
		_ = applicationListener.Close()
		_ = backupListener.Close()
		for count := 0; count < 12; count++ { result := <-serveErrors; if result.err != nil && !errors.Is(result.err, net.ErrClosed) { log.Printf("%s server stopped: %v", result.name, result.err) } }
	case result := <-serveErrors:
		_ = listener.Close()
		_ = activationListener.Close()
		_ = managementListener.Close()
		_ = databaseListener.Close()
		_ = operationsListener.Close()
		_ = accessListener.Close()
		_ = mailListener.Close()
		_ = pdnsListener.Close()
		_ = containerListener.Close()
		_ = certificateListener.Close()
		_ = applicationListener.Close()
		_ = backupListener.Close()
		if result.err != nil && !errors.Is(result.err, net.ErrClosed) { log.Fatalf("%s server failed: %v", result.name, result.err) }
		log.Fatalf("%s server stopped unexpectedly", result.name)
	}
}

func collectTombstones(ctx context.Context, executor *siteops.Executor) {
	ticker := time.NewTicker(time.Hour); defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-ticker.C:
			collected, err := executor.CollectExpired(ctx, 64); if err != nil { log.Printf("collect expired site tombstones: %v", err) } else if collected > 0 { log.Printf("collected %d expired site tombstones", collected) }
		}
	}
}
