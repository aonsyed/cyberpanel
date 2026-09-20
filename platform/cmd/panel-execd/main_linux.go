//go:build linux

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/webactivation"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/malwarescan"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/packagemaint"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation/fsstore"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/lswsruntime"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/management"
	_ "modernc.org/sqlite"
)

const webEngineConfigurationRoot = "/usr/local/lsws/conf"

type serveResult struct {
	name string
	err  error
}

type startupMutationAdmission struct {
	delegate rebootcontrol.ExecutionAdmission
	mu       sync.RWMutex
	ready    bool
}

func (admission *startupMutationAdmission) AdmitExecution(ctx context.Context, binding rebootcontrol.ExecutionBinding) (rebootcontrol.ExecutionLease, error) {
	if admission == nil || admission.delegate == nil {
		return rebootcontrol.ExecutionLease{}, rebootcontrol.ErrConflict
	}
	admission.mu.RLock()
	ready := admission.ready
	admission.mu.RUnlock()
	if !ready {
		return rebootcontrol.ExecutionLease{}, rebootcontrol.ErrConflict
	}
	return admission.delegate.AdmitExecution(ctx, binding)
}

func (admission *startupMutationAdmission) FinishExecution(ctx context.Context, lease rebootcontrol.ExecutionLease, terminal bool, response []byte) error {
	if admission == nil || admission.delegate == nil {
		return rebootcontrol.ErrConflict
	}
	return admission.delegate.FinishExecution(ctx, lease, terminal, response)
}

func (admission *startupMutationAdmission) markReady() {
	admission.mu.Lock()
	admission.ready = true
	admission.mu.Unlock()
}

type startupRecoveryIdentity struct {
	Version   uint32                     `json:"version"`
	BootID    string                     `json:"boot_id"`
	PID       int                        `json:"pid"`
	StartedAt time.Time                  `json:"started_at"`
	PowerDNS  dns.PowerDNSConfigSnapshot `json:"powerdns"`
}

type startupRecoveryReceipt struct {
	IdentityDigest string    `json:"identity_digest"`
	CompletedAt    time.Time `json:"completed_at"`
}

type writerAuthorityRecovery interface {
	VerifyDatabaseWriterFenceAuthority(context.Context, json.RawMessage) error
	VerifyDatabaseWriterCandidateAuthority(context.Context, json.RawMessage) error
	LoadWriterActivation(context.Context, ha.WriterLease) (json.RawMessage, error)
	AdmitWriterActivation(context.Context, json.RawMessage) error
	VerifyActiveWriterAuthority(context.Context, json.RawMessage) error
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == webactivation.StoppedProofMode {
		if err := webactivation.RunStoppedProof(); err != nil {
			log.Fatalf("native web stopped proof failed: %v", err)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "--mail-milter-access" {
		if err := mail.PrepareNativeMilterAccess(os.Args[2]); err != nil {
			log.Fatal("mail milter socket access failed")
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--mariadb-writer-supervisor" {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		if err := database.RunMariaDBWriterSupervisor(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatal("MariaDB independent writer supervisor failed")
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == management.LinuxLifecycleWorkerMode {
		if err := management.RunLinuxLifecycleWorker(); err != nil {
			log.Fatalf("run private web-engine candidate: %v", err)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "--provision-mariadb-replication" {
		if err := provisionMariaDBReplication(os.Args[2]); err != nil {
			log.Fatal("MariaDB replication provisioning failed")
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == malwarescan.LinuxMalwareWorkerMode {
		if err := malwarescan.RunLinuxMalwareSiteWorker(); err != nil {
			log.Fatalf("run site malware worker: %v", err)
		}
		return
	}
	if len(os.Args) != 1 {
		log.Fatal("panel-execd received unsupported arguments")
	}
	if os.Geteuid() != 0 {
		log.Fatal("panel-execd must run as root")
	}
	edition, err := siteops.LoadEngineEdition()
	if err != nil {
		log.Fatalf("load web-engine edition: %v", err)
	}
	controlUID, controlGID, err := siteops.LookupControlIdentity()
	if err != nil {
		log.Fatalf("resolve control-plane identity: %v", err)
	}
	executionAdmission, err := openExecutionAdmission(controlUID)
	if err != nil {
		log.Fatalf("configure reboot execution admission: %v", err)
	}
	defer executionAdmission.DB.Close()
	mutationAdmission := &startupMutationAdmission{delegate: executionAdmission}
	startupBegan := time.Now().UTC()
	backend, err := siteops.NewLinuxStateBackend()
	if err != nil {
		log.Fatalf("open durable registry backend: %v", err)
	}
	defer backend.Close()
	registry, err := siteops.NewDurableRegistryWithUIDAvailability(backend, siteops.DefaultUIDMinimum, siteops.DefaultUIDMaximum, siteops.LinuxUIDAvailable)
	if err != nil {
		log.Fatalf("open durable site registry: %v", err)
	}
	malwareResolver := malwarescan.LinuxMalwareSiteResolverFunc(func(_ context.Context, target malwarescan.TargetLocator) (malwarescan.LinuxMalwareSiteRegistration, error) {
		binding, found, resolveErr := registry.BindingForSite(string(target.Site))
		if resolveErr != nil {
			return malwarescan.LinuxMalwareSiteRegistration{}, resolveErr
		}
		if !found {
			return malwarescan.LinuxMalwareSiteRegistration{}, malwarescan.ErrNotFound
		}
		if binding.TenantID != string(target.Tenant) || binding.SiteID != string(target.Site) || binding.SiteKey != string(target.Root) || binding.RootGeneration == 0 || binding.RootGeneration != target.RootGeneration || binding.UID < siteops.DefaultUIDMinimum || binding.GID != binding.UID {
			return malwarescan.LinuxMalwareSiteRegistration{}, malwarescan.ErrProtected
		}
		switch binding.State {
		case siteops.BindingActive, siteops.BindingSuspended, siteops.BindingQuarantined:
		default:
			return malwarescan.LinuxMalwareSiteRegistration{}, malwarescan.ErrProtected
		}
		return malwarescan.LinuxMalwareSiteRegistration{Tenant: target.Tenant, Site: target.Site, Root: target.Root, RootGeneration: binding.RootGeneration, SiteKey: binding.SiteKey, UID: binding.UID, GID: binding.GID}, nil
	})
	malwareWorker, err := malwarescan.NewLinuxMalwareWorkerServer(malwareResolver, controlUID, mutationAdmission)
	if err != nil {
		log.Fatalf("initialize malware worker: %v", err)
	}
	defer malwareWorker.Close()
	host, err := siteops.NewLinuxHost()
	if err != nil {
		log.Fatalf("initialize privileged host: %v", err)
	}
	defer host.Close()
	executor, err := siteops.NewExecutor(registry, host, siteops.InstalledPHPResolver{}, siteops.Config{Admission: mutationAdmission, Edition: edition, Retention: siteops.DefaultRetention})
	if err != nil {
		log.Fatalf("initialize site executor: %v", err)
	}
	policy, err := siteops.NewPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize peer policy: %v", err)
	}
	listener, err := siteops.ListenDefault(controlGID)
	if err != nil {
		log.Fatalf("listen on privileged siteops socket: %v", err)
	}
	defer listener.Close()
	// ListenDefault establishes the shared runtime directory's root/control
	// ownership before the malware listener enforces that exact boundary.
	malwareListener, err := malwarescan.ListenLinuxMalwareWorker(controlGID)
	if err != nil {
		log.Fatalf("listen on malware worker socket: %v", err)
	}
	defer malwareListener.Close()
	server := &siteops.Server{Authorizer: policy, Handler: executor, Admission: mutationAdmission, MaximumConcurrent: 128}
	installedEdition := webengine.Edition(edition)
	configurationStore, err := fsstore.NewWithHealth(webEngineConfigurationRoot, installedEdition, "/var/lib/cyberpanel/site-health/activation")
	if err != nil {
		log.Fatalf("open web-engine configuration store: %v", err)
	}
	journal, err := webactivation.NewJournal(webactivation.DefaultJournalRoot)
	if err != nil {
		log.Fatalf("open web-engine activation journal: %v", err)
	}
	defer journal.Close()
	runtimeEngine, err := lswsruntime.NewEngine(webactivation.FixedRunner{})
	if err != nil {
		log.Fatalf("initialize web-engine runtime: %v", err)
	}
	probeTransport := webactivation.NewLoopbackTransport()
	defer probeTransport.CloseIdleConnections()
	activationBroker, err := webactivation.NewBroker(installedEdition, configurationStore, runtimeEngine, probeTransport, journal)
	if err != nil {
		log.Fatalf("initialize web-engine activation broker: %v", err)
	}
	activationPolicy, err := webactivation.NewPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize web-engine activation peer policy: %v", err)
	}
	activationListener, err := webactivation.ListenDefault(controlGID)
	if err != nil {
		log.Fatalf("listen on web-engine activation socket: %v", err)
	}
	defer activationListener.Close()
	activationServer := &webactivation.Server{Authorizer: activationPolicy, Handler: activationBroker, Admission: mutationAdmission, MaximumConcurrent: 32}
	managementHost, err := management.NewLinuxLifecycleHost(executionAdmission)
	if err != nil {
		log.Fatalf("initialize web-engine management host: %v", err)
	}
	managementPolicy, err := management.NewLinuxManagementPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize web-engine management peer policy: %v", err)
	}
	managementListener, err := management.ListenLinuxManagementBroker(controlGID)
	if err != nil {
		log.Fatalf("listen on web-engine management socket: %v", err)
	}
	defer managementListener.Close()
	managementServer := &management.LinuxManagementBrokerServer{Authorizer: managementPolicy, Handler: managementHost, Admission: mutationAdmission, MaximumConcurrent: 8}
	materialClient, err := secrets.NewLocalMaterialClient()
	if err != nil {
		log.Fatalf("connect protected secret broker: %v", err)
	}
	installationOwner, err := secrets.NewID("installation")
	if err != nil {
		log.Fatalf("construct installation secret owner: %v", err)
	}
	databaseSecrets, err := database.NewLinuxSecretBrokerSource(materialClient, installationOwner)
	if err != nil {
		log.Fatalf("initialize database secret source: %v", err)
	}
	distribution, err := database.DetectLinuxMariaDBDistribution()
	if err != nil {
		log.Fatalf("detect MariaDB distribution: %v", err)
	}
	localDatabase, err := database.DefaultLocalInstance()
	if err != nil {
		log.Fatalf("construct local database instance: %v", err)
	}
	databaseExecutor, err := database.NewLinuxMariaDBExecutor(databaseSecrets, distribution, []database.DatabaseInstance{localDatabase})
	if err != nil {
		log.Fatalf("initialize MariaDB executor: %v", err)
	}
	replicationAuthority, err := apiserver.NewRecoveryClient("/run/cyberpanel-core/recovery.sock")
	if err != nil {
		log.Fatalf("initialize database replication authority: %v", err)
	}
	databaseExecutor.VerifyReplicationAuthority = replicationAuthority.VerifyStaticHAReplication
	if authority, ok := any(replicationAuthority).(writerAuthorityRecovery); ok {
		databaseExecutor.LoadWriterTransferJSON = authority.LoadWriterActivation
		databaseExecutor.ConfigureWriterAuthorityVerifiers(authority.VerifyDatabaseWriterFenceAuthority, authority.VerifyDatabaseWriterCandidateAuthority, authority.AdmitWriterActivation, authority.VerifyActiveWriterAuthority)
	}
	// Missing recovery methods leave every writer-authority callback nil and
	// closed. Start fencing before the database broker begins serving.
	writerContext, writerCancel := context.WithCancel(context.Background())
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if databaseExecutor.ShutdownWriterGate(shutdown) != nil {
			log.Printf("MariaDB shutdown fence unconfirmed")
		}
		writerCancel()
	}()
	if err = databaseExecutor.StartWriterWatchdog(writerContext); err != nil {
		shutdown, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		_ = databaseExecutor.ShutdownWriterGate(shutdown)
		cancel()
		writerCancel()
		log.Fatal("MariaDB writer gate failed closed")
	}
	databasePolicy, err := database.NewDatabaseBrokerPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize database peer policy: %v", err)
	}
	databaseListener, err := database.ListenDatabaseBroker(controlGID)
	if err != nil {
		log.Fatalf("listen on database broker socket: %v", err)
	}
	defer databaseListener.Close()
	databaseServer := &database.DatabaseBrokerServer{Authorizer: databasePolicy, Executor: databaseExecutor, Admission: mutationAdmission, MaximumConcurrent: 64}
	operationsSecrets, err := operations.NewLinuxOperationsSecretBrokerSource(materialClient, installationOwner)
	if err != nil {
		log.Fatalf("initialize operations secret source: %v", err)
	}
	operationsConfig := operations.DefaultLinuxOperationsConfig()
	operationsConfig.Secrets = operationsSecrets
	operationsConfig.Admission = executionAdmission
	productUpdates, productUpdateErr := operations.NewLocalProductUpdateClient()
	if productUpdateErr != nil {
		log.Printf("product updater unavailable: %v", productUpdateErr)
	} else {
		operationsConfig.ProductUpdates = productUpdates
	}
	operationsConfig.Sites = operations.LinuxOperationsSiteResolverFunc(func(ctx context.Context, siteID string) (operations.LinuxOperationsSiteBinding, error) {
		binding, found, resolveErr := registry.BindingForSite(siteID)
		if resolveErr != nil {
			return operations.LinuxOperationsSiteBinding{}, resolveErr
		}
		if !found {
			return operations.LinuxOperationsSiteBinding{}, operations.ErrNotFound
		}
		generation := binding.RootGeneration
		if generation == 0 {
			generation = binding.Fence
		}
		return operations.LinuxOperationsSiteBinding{TenantID: binding.TenantID, SiteID: binding.SiteID, SiteKey: binding.SiteKey, UID: binding.UID, GID: binding.GID, Generation: generation}, nil
	})
	operationsExecutor, err := operations.NewLinuxOperationsExecutor(operationsConfig)
	if err != nil {
		log.Fatalf("initialize operations executor: %v", err)
	}
	operationsPolicy, err := operations.NewOperationsBrokerPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize operations peer policy: %v", err)
	}
	operationsListener, err := operations.ListenOperationsBroker(controlGID)
	if err != nil {
		log.Fatalf("listen on operations broker socket: %v", err)
	}
	defer operationsListener.Close()
	operationsServer := &operations.OperationsBrokerServer{Authorizer: operationsPolicy, Handler: operationsExecutor, Admission: mutationAdmission, MaximumConcurrent: 64}
	managementClient, err := secrets.NewLocalManagementClient()
	if err != nil {
		log.Fatalf("connect protected secret management broker: %v", err)
	}
	accessSecrets, err := access.NewLinuxAccessSecretSourceWithManagement(materialClient, managementClient, installationOwner)
	if err != nil {
		log.Fatalf("initialize access secret source: %v", err)
	}
	accessResolver := access.LinuxSiteResolverFunc(func(ctx context.Context, siteID access.SiteID) (access.LinuxSiteBinding, error) {
		binding, found, resolveErr := registry.BindingForSite(string(siteID))
		if resolveErr != nil {
			return access.LinuxSiteBinding{}, resolveErr
		}
		if !found {
			return access.LinuxSiteBinding{}, access.ErrNotFound
		}
		generation := binding.RootGeneration
		if generation == 0 {
			generation = binding.Fence
		}
		return access.LinuxSiteBinding{SiteKey: binding.SiteKey, Username: binding.Username, UID: binding.UID, GID: binding.GID, Generation: generation}, nil
	})
	accessRuntime, err := access.NewLinuxAccessRuntime(accessResolver, accessSecrets, controlGID)
	if err != nil {
		log.Fatalf("initialize access executor: %v", err)
	}
	accessPolicy, err := access.NewAccessBrokerPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize access peer policy: %v", err)
	}
	accessListener, err := access.ListenAccessBroker(controlGID)
	if err != nil {
		log.Fatalf("listen on access broker socket: %v", err)
	}
	defer accessListener.Close()
	accessJournal, err := access.NewLinuxAccessReceiptJournal(access.DefaultAccessJournalRoot)
	if err != nil {
		log.Fatalf("open access receipt journal: %v", err)
	}
	defer accessJournal.Close()
	accessServer := &access.AccessBrokerServer{Authorizer: accessPolicy, Handler: accessRuntime.Handler, Journal: accessJournal, Admission: mutationAdmission, MaximumConcurrent: 64}
	applicationResolver := apps.LinuxApplicationSiteResolverFunc(func(ctx context.Context, siteID apps.SiteID) (apps.LinuxApplicationSiteBinding, error) {
		binding, found, resolveErr := registry.BindingForSite(string(siteID))
		if resolveErr != nil {
			return apps.LinuxApplicationSiteBinding{}, resolveErr
		}
		if !found {
			return apps.LinuxApplicationSiteBinding{}, apps.ErrNotFound
		}
		generation := binding.RootGeneration
		if generation == 0 {
			generation = binding.Fence
		}
		return apps.LinuxApplicationSiteBinding{SiteKey: binding.SiteKey, UID: binding.UID, GID: binding.GID, Generation: generation}, nil
	})
	applicationSecrets, err := apps.NewLinuxApplicationMaterialSource(materialClient)
	if err != nil {
		log.Fatalf("initialize application secret source: %v", err)
	}
	applicationRuntime, err := apps.NewLinuxApplicationRuntime(applicationResolver, applicationSecrets)
	if err != nil {
		log.Fatalf("initialize application runtime: %v", err)
	}
	applicationRuntime.DatabaseConnections = databaseExecutor
	applicationPolicy, err := apps.NewLinuxApplicationBrokerPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize application peer policy: %v", err)
	}
	applicationListener, err := apps.ListenLinuxApplicationBroker(controlGID)
	if err != nil {
		log.Fatalf("listen on application broker socket: %v", err)
	}
	defer applicationListener.Close()
	applicationServer := &apps.LinuxApplicationBrokerServer{Authorizer: applicationPolicy, Runtime: applicationRuntime, Admission: mutationAdmission, MaximumConcurrent: 32}
	mailPlatform, err := detectMailPlatform()
	if err != nil {
		log.Fatalf("detect mail platform: %v", err)
	}
	mailOwnership, err := resolveMailOwnership()
	if err != nil {
		log.Fatalf("resolve mail daemon ownership: %v", err)
	}
	mailHost, err := mail.OpenLinuxMailHost(mailPlatform, mailOwnership)
	if err != nil {
		log.Fatalf("initialize mail host: %v", err)
	}
	defer mailHost.Close()
	mailHost.SiteRegistry = registry
	mailPolicy, err := mail.NewMailDaemonPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize mail peer policy: %v", err)
	}
	mailListener, err := mail.ListenMailDaemon(controlGID)
	if err != nil {
		log.Fatalf("listen on mail daemon socket: %v", err)
	}
	defer mailListener.Close()
	mailServer, err := mail.NewMailDaemonServer(mailHost, mailPolicy)
	if err != nil {
		log.Fatalf("initialize mail daemon server: %v", err)
	}
	mailServer.MaximumConcurrent = 32
	mailServer.MaximumCampaignConcurrent = 4
	pdnsPlatform := dns.PowerDNSUbuntuNoble
	if mailPlatform == mail.MailAlma9 {
		pdnsPlatform = dns.PowerDNSAlma9
	}
	pdnsGID, err := lookupFirstGroup("pdns")
	if err != nil {
		log.Fatalf("resolve PowerDNS ownership: %v", err)
	}
	pdnsMaterial, err := dns.NewPowerDNSMaterialResolver(materialClient, installationOwner)
	if err != nil {
		log.Fatalf("initialize PowerDNS material source: %v", err)
	}
	pdnsHost, err := dns.OpenLinuxPowerDNSHost(pdnsPlatform, dns.PowerDNSOwnership{PDNSGID: pdnsGID}, pdnsMaterial, dns.LocalPowerDNSControlFingerprint())
	if err != nil {
		log.Fatalf("initialize PowerDNS host: %v", err)
	}
	defer pdnsHost.Close()
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 2*time.Minute)
	pdnsDatabase, pdnsAuthority, err := dns.OpenLocalSQLitePowerDNSAuthority(startupContext, pdnsMaterial)
	if err != nil {
		cancelStartup()
		log.Fatalf("open PowerDNS authority: %v", err)
	}
	defer pdnsDatabase.Close()
	pdnsSnapshot := dns.LocalPowerDNSConfigSnapshot(1)
	cancelStartup()
	pdnsPolicy, err := dns.NewPowerDNSDaemonPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize PowerDNS peer policy: %v", err)
	}
	pdnsListener, err := dns.ListenPowerDNSDaemon(controlGID)
	if err != nil {
		log.Fatalf("listen on PowerDNS socket: %v", err)
	}
	defer pdnsListener.Close()
	pdnsServer, err := dns.NewPowerDNSDaemonServer(pdnsHost, pdnsAuthority, pdnsPolicy)
	if err != nil {
		log.Fatalf("initialize PowerDNS daemon server: %v", err)
	}
	pdnsServer.Admission = mutationAdmission
	pdnsServer.MaximumConcurrent = 16
	containerConfig, err := containers.DefaultLinuxContainerConfig(materialClient)
	if err != nil {
		log.Fatalf("construct container runtime configuration: %v", err)
	}
	containerRuntime, err := containers.NewLinuxContainerRuntime(containerConfig)
	if err != nil {
		log.Fatalf("initialize container runtime: %v", err)
	}
	containerJournal, err := containers.NewFileContainerReceiptJournal(containers.DefaultContainerReceiptRoot)
	if err != nil {
		log.Fatalf("open container receipt journal: %v", err)
	}
	containerPolicy, err := containers.NewLinuxContainerBrokerPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize container peer policy: %v", err)
	}
	containerListener, err := containers.ListenContainerBroker(controlGID)
	if err != nil {
		log.Fatalf("listen on container broker socket: %v", err)
	}
	defer containerListener.Close()
	containerServer := &containers.ContainerBrokerServer{Authorizer: containerPolicy, Broker: containerRuntime, Journal: containerJournal, MaximumConcurrent: 64}
	certificateHost, err := certificates.NewLinuxCertificateHost()
	if err != nil {
		log.Fatalf("initialize certificate host: %v", err)
	}
	certificatePolicy, err := secrets.NewLinuxMaterialPeerAuthorizer(uint32(controlUID))
	if err != nil {
		log.Fatalf("initialize certificate peer policy: %v", err)
	}
	if uint64(controlGID) > uint64(^uint(0)>>1) {
		log.Fatalf("certificate broker control GID overflows platform int")
	}
	certificateListener, err := certificates.ListenCertificateBroker(0, int(controlGID))
	if err != nil {
		log.Fatalf("listen on certificate broker socket: %v", err)
	}
	defer certificateListener.Close()
	certificateServer := &certificates.CertificateBrokerServer{Authorizer: certificatePolicy, Host: certificateHost, MaximumConcurrent: 16}
	backupResolver := backup.LinuxBackupSiteResolverFunc(func(ctx context.Context, tenantID, siteID string) (backup.LinuxBackupSiteBinding, error) {
		binding, found, resolveErr := registry.BindingForSite(siteID)
		if resolveErr != nil {
			return backup.LinuxBackupSiteBinding{}, resolveErr
		}
		if !found {
			return backup.LinuxBackupSiteBinding{}, backup.ErrInvalidBackup
		}
		if tenantID != "" && binding.TenantID != tenantID {
			return backup.LinuxBackupSiteBinding{}, backup.ErrInvalidBackup
		}
		generation := binding.RootGeneration
		if generation == 0 {
			generation = binding.Fence
		}
		return backup.LinuxBackupSiteBinding{SiteKey: binding.SiteKey, TenantID: binding.TenantID, SiteID: binding.SiteID, UID: binding.UID, GID: binding.GID, Generation: generation}, nil
	})
	backupHost, err := backup.NewLinuxBackupHost(backupResolver)
	if err != nil {
		log.Fatalf("initialize backup host: %v", err)
	}
	backupPolicy, err := backup.NewLinuxBackupPeerPolicy(controlUID)
	if err != nil {
		log.Fatalf("initialize backup peer policy: %v", err)
	}
	backupListener, err := backup.ListenLinuxBackupBroker(controlGID)
	if err != nil {
		log.Fatalf("listen on backup broker socket: %v", err)
	}
	defer backupListener.Close()
	backupServer := &backup.LinuxBackupBrokerServer{Authorizer: backupPolicy, Executor: backupHost, Admission: mutationAdmission, MaximumConcurrent: 16}
	var packageMaintenanceListener *net.UnixListener
	var packageMaintenanceServer *packagemaint.LinuxBrokerServer
	packageMaintenanceConfigured, err := packagemaint.LinuxRuntimeConfigured()
	if err != nil {
		log.Fatalf("inspect package-maintenance deployment: %v", err)
	}
	if packageMaintenanceConfigured {
		packageCatalog, loadErr := packagemaint.LoadDefaultLinuxRuntimeCatalog(time.Now().UTC())
		if loadErr != nil {
			log.Fatalf("load signed package-maintenance catalog: %v", loadErr)
		}
		packageRuntime, runtimeErr := packagemaint.NewLinuxSignedRuntime(packageCatalog, nil, time.Now)
		if runtimeErr != nil {
			log.Fatalf("initialize package-maintenance runtime: %v", runtimeErr)
		}
		packageJournal, journalErr := packagemaint.NewLinuxJournal(packagemaint.DefaultLinuxJournalRoot)
		if journalErr != nil {
			log.Fatalf("open package-maintenance effect journal: %v", journalErr)
		}
		packageBroker, brokerErr := packagemaint.NewLinuxBroker(packageRuntime, packageJournal, time.Now)
		if brokerErr != nil {
			log.Fatalf("initialize package-maintenance broker: %v", brokerErr)
		}
		packagePolicy, policyErr := secrets.NewLinuxMaterialPeerAuthorizer(controlUID)
		if policyErr != nil {
			log.Fatalf("initialize package-maintenance peer policy: %v", policyErr)
		}
		packageMaintenanceListener, err = packagemaint.ListenLinuxBroker(controlGID)
		if err != nil {
			log.Fatalf("listen on package-maintenance socket: %v", err)
		}
		defer packageMaintenanceListener.Close()
		packageMaintenanceServer = &packagemaint.LinuxBrokerServer{Authorizer: packagePolicy, Broker: packageBroker, Admission: mutationAdmission, MaximumConcurrent: 8}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	serverCount := 13
	if packageMaintenanceServer != nil {
		serverCount++
	}
	serveErrors := make(chan serveResult, serverCount)
	go func() { serveErrors <- serveResult{name: "siteops", err: server.Serve(listener)} }()
	go func() {
		serveErrors <- serveResult{name: "web-engine activation", err: activationServer.Serve(activationListener)}
	}()
	go func() {
		serveErrors <- serveResult{name: "web-engine management", err: managementServer.Serve(managementListener)}
	}()
	go func() { serveErrors <- serveResult{name: "database", err: databaseServer.Serve(databaseListener)} }()
	go func() {
		serveErrors <- serveResult{name: "operations", err: operationsServer.Serve(operationsListener)}
	}()
	go func() { serveErrors <- serveResult{name: "access", err: accessServer.Serve(accessListener)} }()
	go func() { serveErrors <- serveResult{name: "mail", err: mailServer.Serve(mailListener)} }()
	go func() { serveErrors <- serveResult{name: "powerdns", err: pdnsServer.Serve(pdnsListener)} }()
	go func() { serveErrors <- serveResult{name: "containers", err: containerServer.Serve(containerListener)} }()
	go func() {
		serveErrors <- serveResult{name: "certificates", err: certificateServer.Serve(certificateListener)}
	}()
	go func() {
		serveErrors <- serveResult{name: "applications", err: applicationServer.Serve(applicationListener)}
	}()
	go func() { serveErrors <- serveResult{name: "backup", err: backupServer.Serve(backupListener)} }()
	go func() { serveErrors <- serveResult{name: "malware worker", err: malwareWorker.Serve(malwareListener)} }()
	if packageMaintenanceServer != nil {
		go func() {
			serveErrors <- serveResult{name: "package maintenance", err: packageMaintenanceServer.Serve(packageMaintenanceListener)}
		}()
	}
	startupIdentity := startupRecoveryIdentity{Version: 1, BootID: executionAdmission.BootID, PID: os.Getpid(), StartedAt: startupBegan, PowerDNS: pdnsSnapshot}
	go reconcileStartupMutations(ctx, executionAdmission, mutationAdmission, managementHost, operationsExecutor, pdnsServer, startupIdentity)
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
		_ = malwareListener.Close()
		if packageMaintenanceListener != nil {
			_ = packageMaintenanceListener.Close()
		}
		for count := 0; count < serverCount; count++ {
			result := <-serveErrors
			if result.err != nil && !errors.Is(result.err, net.ErrClosed) {
				log.Printf("%s server stopped: %v", result.name, result.err)
			}
		}
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
		_ = malwareListener.Close()
		if packageMaintenanceListener != nil {
			_ = packageMaintenanceListener.Close()
		}
		if result.err != nil && !errors.Is(result.err, net.ErrClosed) {
			log.Fatalf("%s server failed: %v", result.name, result.err)
		}
		log.Fatalf("%s server stopped unexpectedly", result.name)
	}
}

func reconcileStartupMutations(ctx context.Context, raw *rebootcontrol.SQLExecutionAdmission, admission *startupMutationAdmission, managementHost *management.LinuxLifecycleHost, operationsExecutor *operations.LinuxOperationsExecutor, pdnsServer *dns.PowerDNSDaemonServer, identity startupRecoveryIdentity) {
	waitingForDrain := false
	for {
		err := startupAdmissionSchemaReady(ctx, raw)
		if err == nil {
			err = completeStartupMutationRecovery(ctx, raw, managementHost, operationsExecutor, pdnsServer, identity)
		}
		if err == nil {
			admission.markReady()
			log.Printf("privileged mutation admission is ready")
			return
		}
		if ctx.Err() != nil {
			return
		}
		if !errors.Is(err, rebootcontrol.ErrConflict) {
			log.Printf("privileged mutation admission remains closed after startup recovery failure: %v", err)
			return
		}
		if !waitingForDrain {
			log.Printf("privileged mutation admission remains closed while core admission bootstrap or reboot drain is pending")
			waitingForDrain = true
		}
		timer := time.NewTimer(15 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func completeStartupMutationRecovery(ctx context.Context, raw rebootcontrol.ExecutionAdmission, managementHost *management.LinuxLifecycleHost, operationsExecutor *operations.LinuxOperationsExecutor, pdnsServer *dns.PowerDNSDaemonServer, identity startupRecoveryIdentity) error {
	if ctx == nil || raw == nil || managementHost == nil || operationsExecutor == nil || pdnsServer == nil {
		return rebootcontrol.ErrIntegrity
	}
	if err := managementHost.ResumeStartup(ctx); err != nil {
		return fmt.Errorf("recover web-engine management: %w", err)
	}
	if err := operationsExecutor.ResumeSecurityWatchdogs(ctx); err != nil {
		return fmt.Errorf("recover firewall/SSH transaction: %w", err)
	}
	if err := operationsExecutor.ResumeWAFTransactions(ctx); err != nil {
		return fmt.Errorf("recover WAF transaction: %w", err)
	}
	if err := pdnsServer.ReconcileStartup(ctx, raw, identity.PowerDNS); err != nil {
		return fmt.Errorf("recover PowerDNS configuration: %w", err)
	}
	digest := rebootcontrol.ExecutionDigest(identity)
	if digest == "" {
		return rebootcontrol.ErrIntegrity
	}
	lease, err := raw.AdmitExecution(ctx, rebootcontrol.ExecutionBinding{Boundary: "panel-execd-startup", Method: "mutation_ready", EffectID: "startup-ready-" + digest, RequestDigest: digest, Caller: "panel-execd-startup", Resource: rebootcontrol.ExecutionResource(struct {
		Boot     string `json:"boot"`
		PID      int    `json:"pid"`
		Version  uint32 `json:"version"`
		Identity string `json:"identity"`
	}{identity.BootID, identity.PID, identity.Version, digest})})
	if err != nil {
		return err
	}
	if len(lease.Cached) != 0 {
		var receipt startupRecoveryReceipt
		if json.Unmarshal(lease.Cached, &receipt) != nil || !validStartupRecoveryReceipt(receipt, identity, digest, time.Now().UTC()) {
			return rebootcontrol.ErrIntegrity
		}
		return nil
	}
	defer func() { _ = rebootcontrol.SettleExecution(raw, lease, false, nil) }()
	receipt := startupRecoveryReceipt{IdentityDigest: digest, CompletedAt: time.Now().UTC()}
	if !validStartupRecoveryReceipt(receipt, identity, digest, time.Now().UTC()) {
		return rebootcontrol.ErrIntegrity
	}
	return rebootcontrol.SettleExecution(raw, lease, true, receipt)
}

func validStartupRecoveryReceipt(receipt startupRecoveryReceipt, identity startupRecoveryIdentity, digest string, now time.Time) bool {
	return identity.Version == 1 && identity.BootID != "" && identity.PID > 1 && !identity.StartedAt.IsZero() && rebootcontrol.ExecutionDigest(identity) == digest && receipt.IdentityDigest == digest && !receipt.CompletedAt.Before(identity.StartedAt) && !receipt.CompletedAt.After(now.Add(time.Minute))
}

// The root daemon must never initialize, migrate, or repair the core database.
// sql.Open is lazy: before core bootstrap, fixed observations remain available
// but every mutation fails its store validation/schema query closed.
func openExecutionAdmission(controlUID uint32) (*rebootcontrol.SQLExecutionAdmission, error) {
	const controlPath = "/var/lib/cyberpanel/control/control.db"
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	dsn := "file:" + controlPath + "?mode=rw&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=trusted_schema(0)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	var identity os.FileInfo
	var identityMu sync.Mutex
	validate := func() error {
		identityMu.Lock()
		defer identityMu.Unlock()
		parent, err := os.Lstat("/var/lib/cyberpanel/control")
		if err != nil {
			return err
		}
		parentStat, ok := parent.Sys().(*syscall.Stat_t)
		if !ok || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parentStat.Uid != controlUID || parent.Mode().Perm()&0022 != 0 {
			return rebootcontrol.ErrIntegrity
		}
		info, err := os.Lstat(controlPath)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || stat.Uid != controlUID || stat.Nlink != 1 {
			return rebootcontrol.ErrIntegrity
		}
		if identity != nil && !os.SameFile(identity, info) {
			return rebootcontrol.ErrIntegrity
		}
		identity = info
		return nil
	}
	return &rebootcontrol.SQLExecutionAdmission{DB: db, BootID: strings.TrimSpace(string(boot)), ValidateStore: validate}, nil
}

func collectTombstones(ctx context.Context, executor *siteops.Executor) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collected, err := executor.CollectExpired(ctx, 64)
			if err != nil {
				log.Printf("collect expired site tombstones: %v", err)
			} else if collected > 0 {
				log.Printf("collected %d expired site tombstones", collected)
			}
		}
	}
}
