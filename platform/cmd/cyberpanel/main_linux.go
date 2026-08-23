//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/authn"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

const (
	coreConfigPath = "/etc/cyberpanel/panel-core.json"
	auditCredentialPath = "/run/credentials/panel-core.service/audit-signing.key"
)

type coreConfiguration struct {
	DatabasePath string `json:"database_path"`
	StateRoot string `json:"state_root"`
	TrustPath string `json:"trust_path"`
	SignerPath string `json:"signer_path"`
	ClaimTokenPath string `json:"claim_token_path"`
	AuditRoot string `json:"audit_root"`
	EmergencyAuditRoot string `json:"emergency_audit_root"`
	CoreSocket string `json:"core_socket"`
	RecoverySocket string `json:"recovery_socket"`
	GatewayAccount string `json:"gateway_account"`
	MailHostname string `json:"mail_hostname"`
	PanelRegistrableDomain string `json:"panel_registrable_domain"`
	PreviewRegistrableDomain string `json:"preview_registrable_domain"`
	MaximumDatabaseConnections int `json:"maximum_database_connections"`
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "installer-hook" {
		if err := runInstallerHook(os.Args[2:]); err != nil { log.Fatal(err) }
		return
	}
	arguments := os.Args[1:]
	if len(arguments) > 0 && arguments[0] == "serve" { arguments = arguments[1:] }
	flags := flag.NewFlagSet("cyberpanel serve", flag.ExitOnError)
	configPath := flags.String("config", coreConfigPath, "panel-core configuration")
	_ = flags.Parse(arguments)
	if flags.NArg() != 0 { log.Fatal("cyberpanel serve accepts no positional arguments") }
	configuration, err := loadCoreConfiguration(*configPath)
	if err != nil { log.Fatalf("load panel-core configuration: %v", err) }
	if err = runCore(configuration); err != nil { log.Fatal(err) }
}

func runCore(configuration coreConfiguration) error {
	if os.Geteuid() == 0 { return errors.New("panel-core refuses to run as root") }
	database, err := openControlDatabase(configuration)
	if err != nil { return fmt.Errorf("open control database: %w", err) }
	defer database.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	identityStore, err := identity.NewStore(database)
	if err != nil { return err }
	if err = identityStore.Bootstrap(ctx); err != nil { return fmt.Errorf("bootstrap identity authority: %w", err) }
	repositories, err := bootstrapControlRepositories(ctx, database)
	if err != nil { return err }
	auditIndex, err := audit.NewSQLIndex(database)
	if err != nil { return err }
	if err = auditIndex.Bootstrap(ctx); err != nil { return fmt.Errorf("bootstrap audit index: %w", err) }
	auditSigner, err := loadAuditSigner(auditCredentialPath)
	if err != nil { return err }
	auditWriter, err := audit.NewWriter(configuration.AuditRoot, auditIndex, auditSigner)
	if err != nil { return fmt.Errorf("open audit segments: %w", err) }
	emergencyWriter, err := audit.NewEmergencyWriter(configuration.EmergencyAuditRoot, os.Geteuid())
	if err != nil { return fmt.Errorf("open emergency audit lane: %w", err) }
	auditService, err := audit.NewService(auditWriter, emergencyWriter)
	if err != nil { return err }
	authClient, err := authn.NewLocalClient()
	if err != nil { return fmt.Errorf("initialize protected authentication client: %w", err) }
	identityService, err := identity.NewService(identityStore, authClient, audit.IdentitySink{Service:auditService})
	if err != nil { return fmt.Errorf("initialize identity authority: %w", err) }
	domainServices, err := assembleDomainServices(ctx,repositories,identityService,identityStore,auditService,configuration.MailHostname,configuration.PanelRegistrableDomain,configuration.PreviewRegistrableDomain)
	if err != nil { return fmt.Errorf("assemble domain services: %w", err) }
	if migrationService, ok := domainServices.MigrationEdge.(*migrationEdge); ok { defer migrationService.runtime.Close() }
	core, err := apiserver.AssembleCore(apiserver.CoreAssemblyConfig{StateRoot:configuration.StateRoot,TrustPath:configuration.TrustPath},identityService,domainServices)
	if err != nil { return fmt.Errorf("assemble panel core: %w", err) }
	gatewayUID, controlGID, err := resolveRuntimeIdentities(configuration.GatewayAccount)
	if err != nil { return err }
	coreTransport, err := apiserver.NewUnixCoreTransport(configuration.CoreSocket)
	if err != nil { return err }
	claimStore, err := apiserver.NewFileClaimTokenStore(configuration.ClaimTokenPath)
	if err != nil { return err }
	recovery := &apiserver.RecoveryServer{Controller:&apiserver.RecoveryController{Identity:identityService,Claims:claimStore,Core:coreTransport,TrustPaths:apiserver.TrustPaths{SignerPath:configuration.SignerPath,TrustPath:configuration.TrustPath}},MaximumBodyBytes:1<<20}
	process := &apiserver.CoreProcess{Core:core,Recovery:recovery,Config:apiserver.CoreProcessConfig{
		CoreSocket:apiserver.SocketOptions{Path:configuration.CoreSocket,DirectoryMode:0750,SocketMode:0660,UID:-1,GID:controlGID},
		RecoverySocket:apiserver.SocketOptions{Path:configuration.RecoverySocket,DirectoryMode:0750,SocketMode:0600,UID:-1,GID:-1},
		GatewayUIDs:[]uint32{gatewayUID},EnableRecovery:true,ShutdownTimeout:30*time.Second,
	}}
	malwareSchedules, err := newMalwareScheduleRunner(domainServices.Malware)
	if err != nil { return fmt.Errorf("initialize malware scheduler: %w", err) }
	if domainServices.HostingPreviews != nil { go domainServices.HostingPreviews.RunJanitor(ctx, 30*time.Second) }
	if domainServices.Campaigns != nil { go domainServices.Campaigns.RunDispatchQueue(ctx, time.Second, 4) }
	malwareScheduleContext, stopMalwareSchedules := context.WithCancel(ctx)
	malwareScheduleDone := make(chan error, 1)
	go func() { malwareScheduleDone <- malwareSchedules.Run(malwareScheduleContext) }()
	processErr := process.Run(ctx)
	stopMalwareSchedules()
	malwareScheduleErr := <-malwareScheduleDone
	if malwareScheduleErr != nil && !errors.Is(malwareScheduleErr, context.Canceled) {
		processErr = errors.Join(processErr, fmt.Errorf("malware scheduler stopped: %w", malwareScheduleErr))
	}
	return processErr
}

func loadCoreConfiguration(path string) (coreConfiguration, error) {
	var configuration coreConfiguration
	if path != coreConfigPath { return configuration, errors.New("panel-core configuration path is not registered") }
	content, err := readCoreFile(path, 1<<20, false)
	if err != nil { return configuration, err }
	decoder := json.NewDecoder(&sliceReader{value:content})
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&configuration); err != nil { return configuration, err }
	if err = decoder.Decode(&struct{}{}); err != io.EOF { return configuration, errors.New("trailing panel-core configuration data") }
	registered := coreConfiguration{
		DatabasePath:"/var/lib/cyberpanel/control/control.db",StateRoot:"/var/lib/cyberpanel/control/runtime",
		TrustPath:"/var/lib/cyberpanel/control/trust/gateway-public.json",SignerPath:"/var/lib/cyberpanel/control/trust/gateway-signer.json",
		ClaimTokenPath:"/var/lib/cyberpanel/control/recovery/claim.token",AuditRoot:"/var/lib/cyberpanel/audit/segments",
		EmergencyAuditRoot:"/var/lib/cyberpanel/audit/emergency",CoreSocket:"/run/cyberpanel-core/core.sock",
		RecoverySocket:"/run/cyberpanel-core/recovery.sock",GatewayAccount:"cyberpanel-gateway",
		MailHostname:configuration.MailHostname,PanelRegistrableDomain:configuration.PanelRegistrableDomain,PreviewRegistrableDomain:configuration.PreviewRegistrableDomain,
	}
	if configuration.DatabasePath!=registered.DatabasePath||configuration.StateRoot!=registered.StateRoot||configuration.TrustPath!=registered.TrustPath||configuration.SignerPath!=registered.SignerPath||configuration.ClaimTokenPath!=registered.ClaimTokenPath||configuration.AuditRoot!=registered.AuditRoot||configuration.EmergencyAuditRoot!=registered.EmergencyAuditRoot||configuration.CoreSocket!=registered.CoreSocket||configuration.RecoverySocket!=registered.RecoverySocket||configuration.GatewayAccount!=registered.GatewayAccount {
		return coreConfiguration{}, errors.New("panel-core configuration contains an unregistered authority path")
	}
	if _, err = site.ParseHostname(configuration.MailHostname); err != nil { return coreConfiguration{}, errors.New("invalid mail hostname") }
	panelDomain, panelErr := site.ParseHostname(configuration.PanelRegistrableDomain)
	previewDomain, previewErr := site.ParseHostname(configuration.PreviewRegistrableDomain)
	if panelErr != nil || previewErr != nil || panelDomain == previewDomain || strings.HasSuffix(panelDomain.String(), "."+previewDomain.String()) || strings.HasSuffix(previewDomain.String(), "."+panelDomain.String()) { return coreConfiguration{}, errors.New("panel and preview require separate registrable domains") }
	if configuration.MaximumDatabaseConnections == 0 { configuration.MaximumDatabaseConnections = 1 }
	if configuration.MaximumDatabaseConnections < 1 || configuration.MaximumDatabaseConnections > 8 { return coreConfiguration{}, errors.New("invalid database connection bound") }
	return configuration, nil
}

func openControlDatabase(configuration coreConfiguration) (*sql.DB, error) {
	info, err := os.Lstat(configuration.DatabasePath)
	if err != nil { return nil, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()!=0600 { return nil, errors.New("unsafe control database") }
	dsn := "file:"+configuration.DatabasePath+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=trusted_schema(0)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil { return nil, err }
	database.SetMaxOpenConns(configuration.MaximumDatabaseConnections)
	database.SetMaxIdleConns(configuration.MaximumDatabaseConnections)
	database.SetConnMaxLifetime(0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = database.PingContext(ctx); err != nil { _=database.Close(); return nil, err }
	opened, err := os.Stat(configuration.DatabasePath)
	if err != nil || !os.SameFile(info, opened) { _=database.Close(); return nil, errors.New("control database changed while opening") }
	return database, nil
}

func loadAuditSigner(path string) (*audit.Ed25519Signer, error) {
	content, err := readCoreFile(path, ed25519.PrivateKeySize, true)
	if err != nil { return nil, fmt.Errorf("load audit signing key: %w", err) }
	defer wipeBytes(content)
	if len(content)!=ed25519.PrivateKeySize { return nil, errors.New("audit signing key has invalid size") }
	private := ed25519.PrivateKey(append([]byte(nil),content...))
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok { return nil, errors.New("invalid audit signing key") }
	digest := sha256.Sum256(public)
	keyID := "audit_"+hex.EncodeToString(digest[:])[:32]
	return audit.NewEd25519Signer(keyID,private,map[string]ed25519.PublicKey{keyID:public})
}

func resolveRuntimeIdentities(gatewayName string) (uint32, int, error) {
	gateway, err := user.Lookup(gatewayName)
	if err != nil { return 0,0,err }
	gatewayUID, err := strconv.ParseUint(gateway.Uid,10,32)
	if err != nil || gatewayUID==0 { return 0,0,errors.New("invalid gateway UID") }
	control, err := user.Lookup("cyberpanel")
	if err != nil { return 0,0,err }
	controlGID, err := strconv.Atoi(control.Gid)
	if err != nil || controlGID<=0 { return 0,0,errors.New("invalid control GID") }
	return uint32(gatewayUID),controlGID,nil
}

func readCoreFile(path string, maximum int64, secret bool) ([]byte,error) {
	if !filepath.IsAbs(path)||filepath.Clean(path)!=path||maximum<=0{return nil,errors.New("unsafe core file path")}
	before,err:=os.Lstat(path);if err!=nil{return nil,err}
	if !before.Mode().IsRegular()||before.Mode()&os.ModeSymlink!=0||before.Size()<=0||before.Size()>maximum||before.Mode().Perm()&0002!=0{return nil,errors.New("unsafe core file")}
	if secret&&before.Mode().Perm()&0077!=0{return nil,errors.New("core secret is accessible to another account")}
	file,err:=os.Open(path);if err!=nil{return nil,err};defer file.Close();opened,err:=file.Stat();if err!=nil||!os.SameFile(before,opened){return nil,errors.New("core file changed while opening")}
	content,err:=io.ReadAll(io.LimitReader(file,maximum+1));if err!=nil||int64(len(content))>maximum{wipeBytes(content);return nil,errors.New("core file exceeds limit")};return content,nil
}

type sliceReader struct{value []byte;offset int}
func(reader *sliceReader)Read(target []byte)(int,error){if reader.offset==len(reader.value){return 0,io.EOF};count:=copy(target,reader.value[reader.offset:]);reader.offset+=count;return count,nil}
func wipeBytes(value []byte){for index:=range value{value[index]=0}}
