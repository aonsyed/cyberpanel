//go:build linux

package main

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanel"
)

const extractConfigPath = "/etc/cyberpanel/migration/cyberpanel-extract.json"
const extractPlanDirectory = "/var/lib/cyberpanel-migration/source-plans"
const extractGrantDirectory = "/var/lib/cyberpanel-migration/source-grants"
const extractArtifactDirectory = "/var/lib/cyberpanel-migration/artifacts"
const extractChunkDirectory = "/var/lib/cyberpanel-migration/chunks"
const extractTLSCertificate = "/etc/cyberpanel/migration/source-agent.crt"
const extractTLSPrivateKey = "/run/credentials/cyberpanel-extract.service/source-agent.key"
const extractTargetClientCA = "/etc/cyberpanel/migration/target-client-ca.pem"
const extractManifestKey = "/run/credentials/cyberpanel-extract.service/manifest-signing.key"
const extractCutoverSocket = "/run/cyberpanel-migration/cutover.sock"

func main() {
	log.SetFlags(0)
	if err := run(); err != nil { log.Fatal(err) }
}

func run() (result error) {
	if len(os.Args) != 1 || os.Geteuid() == 0 { return errors.New("cyberpanel-extract accepts no arguments and must run as the source account") }
	config, err := loadFixedSourceConfig()
	if err != nil { return errors.Join(errors.New("load protected source configuration"), err) }
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	startup, startupCancel := context.WithTimeout(ctx, 30*time.Second)
	database, err := openBatchDatabase(startup)
	startupCancel()
	if err != nil { return errors.Join(errors.New("open read-only CyberPanel database transport"), err) }
	defer func() { result = errors.Join(result, database.Close()) }()
	collector, err := cyberpanel.NewSQLCollector(cyberpanel.SQLCollectorConfig{Database: database, InstallationID: config.SourceInstallationID})
	if err != nil { return errors.Join(errors.New("initialize CyberPanel collector"), err) }
	if err = cyberpanel.RunSourceAgent(ctx, config, collector); err != nil && !errors.Is(err, context.Canceled) { return errors.Join(errors.New("run CyberPanel source agent"), err) }
	return nil
}

func loadFixedSourceConfig() (cyberpanel.SourceAgentConfig, error) {
	before, err := fixedReadableFile(extractConfigPath, 1<<20)
	if err != nil { return cyberpanel.SourceAgentConfig{}, err }
	config, err := cyberpanel.LoadSourceAgentConfig(extractConfigPath)
	if err != nil { return cyberpanel.SourceAgentConfig{}, err }
	after, err := fixedReadableFile(extractConfigPath, 1<<20)
	if err != nil || !os.SameFile(before, after) { return cyberpanel.SourceAgentConfig{}, errors.Join(err, errBatchProtocol) }
	address, err := netip.ParseAddrPort(config.ListenAddress)
	if err != nil || address.Port() < 1024 { return cyberpanel.SourceAgentConfig{}, errBatchProtocol }
	if config.PlanDirectory != extractPlanDirectory || config.GrantDirectory != extractGrantDirectory || config.SessionDirectory != extractSessionDirectory || config.ArtifactDirectory != extractArtifactDirectory || config.ChunkDirectory != extractChunkDirectory || config.HomeRoot != "/home" || config.MailRoot != "/home/vmail" || config.CertificateRoot != "/etc/letsencrypt/live" || config.DKIMRoot != "/etc/opendkim/keys" || config.CronRoot != "/var/spool/cron" || config.DebianCronRoot != "/var/spool/cron/crontabs" || config.TLSCertificatePath != extractTLSCertificate || config.TLSPrivateKeyPath != extractTLSPrivateKey || config.TargetClientCAPath != extractTargetClientCA || config.ManifestSigningPrivateKeyPath != extractManifestKey || config.CutoverHelperSocket != extractCutoverSocket { return cyberpanel.SourceAgentConfig{}, errBatchProtocol }
	return config, nil
}
