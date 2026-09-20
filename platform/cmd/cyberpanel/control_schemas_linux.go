//go:build linux

package main

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	backupproviders "github.com/aonsyed/cyberpanel/platform/internal/backup/providers"
	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/preview"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/sqlrepo"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/maildelivery"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	webmanagement "github.com/aonsyed/cyberpanel/platform/internal/webengine/management"
	webcatalog "github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
)

// controlRepositories owns the panel-core projections and durable operation
// journals that are allowed to share control.db. Secret, authenticator,
// privileged-executor, container-broker, and watchdog authority are
// intentionally absent: those stores have separate writers and processes.
type controlRepositories struct {
	ControlDB           *sql.DB
	Hosting             *sqlrepo.Repository
	HostingPreviews     *preview.Repository
	Database            *database.SQLRepository
	Operations          *operations.SQLRepository
	DNS                 dns.Repository
	DNSSEC              dns.DNSSECRepository
	Certificates        certificates.Repository
	CertificateIssuance certificates.IssuanceStore
	Mail                mail.Repository
	MailControl         mail.SQLControlRepository
	MailDeliveryPolicy  mail.DeliveryPolicyStore
	MailDelivery        *maildelivery.SQLiteRepository
	Webmail             *mail.WebmailStore
	Marketing           mail.MarketingStore
	Backup              backup.SQLRepository
	BackupCatalog       backup.BackupCatalog
	BackupRestore       backup.RestoreStore
	BackupRetention     backup.SQLRetentionCatalog
	BackupUploads       backupproviders.SQLUploadJournal
	BackupLifecycle     backupproviders.RepositoryLifecycle
	Access              access.SQLStore
	Applications        apps.SQLRepository
	Containers          *containers.SQLStore
	WebEngine           *webmanagement.SQLRepository
	WebCatalog          *webcatalog.SQLCatalog
	HA                  ha.SQLRepository
	Integrations        integrations.SQLRepository
	Migrations          *migration.SQLRepository
}

func bootstrapControlRepositories(ctx context.Context, handle *sql.DB) (controlRepositories, error) {
	var repositories controlRepositories
	if ctx == nil || handle == nil {
		return repositories, fmt.Errorf("control repository bootstrap requires context and database")
	}
	repositories.ControlDB = handle

	var err error
	if repositories.Hosting, err = sqlrepo.New(handle); err != nil {
		return repositories, fmt.Errorf("open hosting repository: %w", err)
	}
	// The preview repository is opened after the operator-declared domain is
	// supplied during service assembly. Its schema is bootstrapped there.
	if repositories.Database, err = database.NewSQLRepository(handle); err != nil {
		return repositories, fmt.Errorf("open database repository: %w", err)
	}
	if repositories.Operations, err = operations.NewSQLRepository(handle); err != nil {
		return repositories, fmt.Errorf("open operations repository: %w", err)
	}
	if repositories.Containers, err = containers.NewSQLStore(handle); err != nil {
		return repositories, fmt.Errorf("open container repository: %w", err)
	}
	if repositories.WebEngine, err = webmanagement.NewSQLRepository(handle); err != nil {
		return repositories, fmt.Errorf("open web-engine repository: %w", err)
	}
	if repositories.Migrations, err = migration.NewSQLRepository(handle); err != nil {
		return repositories, fmt.Errorf("open migration repository: %w", err)
	}
	if repositories.MailDelivery, err = maildelivery.NewSQLiteRepository(handle); err != nil {
		return repositories, fmt.Errorf("open mail-delivery repository: %w", err)
	}

	repositories.DNS = dns.Repository{DB: handle}
	repositories.DNSSEC = dns.DNSSECRepository{DB: handle}
	repositories.Certificates = certificates.Repository{DB: handle}
	repositories.CertificateIssuance = certificates.IssuanceStore{DB: handle}
	repositories.Mail = mail.Repository{DB: handle}
	repositories.MailControl = mail.SQLControlRepository{DB: handle}
	repositories.MailDeliveryPolicy = mail.DeliveryPolicyStore{DB: handle}
	repositories.Webmail = &mail.WebmailStore{DB: handle}
	repositories.Marketing = mail.MarketingStore{DB: handle}
	repositories.Backup = backup.SQLRepository{DB: handle}
	repositories.BackupCatalog = backup.BackupCatalog{DB: handle}
	repositories.BackupRestore = backup.RestoreStore{DB: handle}
	repositories.BackupRetention = backup.SQLRetentionCatalog{DB: handle}
	repositories.BackupUploads = backupproviders.SQLUploadJournal{DB: handle}
	repositories.BackupLifecycle = backupproviders.RepositoryLifecycle{DB: handle}
	repositories.Access = access.SQLStore{DB: handle}
	repositories.Applications = apps.SQLRepository{DB: handle}
	repositories.HA = ha.SQLRepository{DB: handle}
	repositories.Integrations = integrations.SQLRepository{DB: handle}

	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"hosting", repositories.Hosting.Bootstrap},
		{"database", repositories.Database.Bootstrap},
		{"operations", repositories.Operations.Bootstrap},
		{"dns", repositories.DNS.Bootstrap},
		{"dnssec", repositories.DNSSEC.Bootstrap},
		{"certificates", repositories.Certificates.Bootstrap},
		{"certificate issuance", repositories.CertificateIssuance.Bootstrap},
		{"mail", repositories.Mail.Bootstrap},
		{"mail control", repositories.MailControl.Bootstrap},
		{"mail delivery policy", repositories.MailDeliveryPolicy.Bootstrap},
		{"mail delivery", repositories.MailDelivery.Bootstrap},
		{"webmail", repositories.Webmail.Bootstrap},
		{"marketing", repositories.Marketing.Bootstrap},
		{"backup resources", repositories.Backup.Bootstrap},
		{"backup catalog", repositories.BackupCatalog.Bootstrap},
		{"backup restore", repositories.BackupRestore.Bootstrap},
		{"backup retention", repositories.BackupRetention.Bootstrap},
		{"backup uploads", repositories.BackupUploads.Bootstrap},
		{"backup lifecycle", repositories.BackupLifecycle.Bootstrap},
		{"access", repositories.Access.Bootstrap},
		{"applications", repositories.Applications.Bootstrap},
		{"containers", repositories.Containers.Bootstrap},
		{"web engine", repositories.WebEngine.Bootstrap},
		{"high availability", repositories.HA.Bootstrap},
		{"integrations", repositories.Integrations.Bootstrap},
		{"migrations", repositories.Migrations.Bootstrap},
	}
	for _, step := range steps {
		if err = step.run(ctx); err != nil {
			return controlRepositories{}, fmt.Errorf("bootstrap %s authority: %w", step.name, err)
		}
	}
	localInstance, err := database.DefaultLocalInstance()
	if err != nil { return controlRepositories{}, fmt.Errorf("construct local database instance: %w", err) }
	localNetworkPolicy, err := database.DefaultLocalNetworkPolicy()
	if err != nil { return controlRepositories{}, fmt.Errorf("construct local database policy: %w", err) }
	if err = repositories.Database.EnsureBootstrapResources(ctx, localInstance, localNetworkPolicy); err != nil {
		return controlRepositories{}, fmt.Errorf("bootstrap local database resources: %w", err)
	}
	if err = bootstrapExecutionAdmission(ctx, handle); err != nil {
		return controlRepositories{}, fmt.Errorf("bootstrap execution admission: %w", err)
	}
	return repositories, nil
}
