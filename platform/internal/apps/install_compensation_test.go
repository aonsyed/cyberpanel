package apps

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type compensationJournal struct {
	ApplicationStore
	failState OperationState
	failure   error
	writes    []OperationState
	deadline  time.Time
}

type installFailureStore struct{ compensationJournal }

func (store *installFailureStore) AdmitOperation(_ context.Context, operation Operation) (Operation, bool, error) {
	return operation, true, nil
}
func (store *installFailureStore) CreateInstallation(context.Context, ApplicationInstallation) error {
	return nil
}
func (store *installFailureStore) UpdateInstallation(context.Context, ApplicationInstallation, uint64) error {
	return nil
}

type installFailureCatalog struct{}

func (installFailureCatalog) Resolve(_ context.Context, recipe RecipeReference, _ CatalogTarget) (ApplicationDefinition, error) {
	return ApplicationDefinition{ID: recipe.DefinitionID, Recipe: recipe, Kind: ApplicationWordPress}, nil
}

type installFailureSecrets struct {
	compensationSecrets
	failure error
}

func (secrets *installFailureSecrets) IssueApplicationSecret(context.Context, TenantID, SiteID, InstallationID, string) (SecretRef, error) {
	return "", secrets.failure
}

func (database *compensationDatabase) ProvisionApplicationDatabase(context.Context, TenantID, SiteID, InstallationID, ApplicationKind, DatabaseInstanceID) (DatabaseBinding, error) {
	return DatabaseBinding{ID: "appdb-1"}, nil
}

type unusedInstallExecutor struct{ SiteApplicationExecutor }

func TestInstallSecretFailureCleansProvisionedResources(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(fmtBool(cleanupFails), func(t *testing.T) {
			now := time.Now().UTC()
			issueFailure := errors.New("configuration secret unavailable")
			cleanupFailure := errors.New("database cleanup unavailable")
			store := &installFailureStore{}
			secrets := &installFailureSecrets{failure: issueFailure}
			database := &compensationDatabase{}
			if cleanupFails {
				database.failure = cleanupFailure
			}
			service := ApplicationService{Store: store, Catalog: installFailureCatalog{}, Databases: database, Secrets: secrets, Executor: unusedInstallExecutor{}, Now: func() time.Time { return now }}
			request := InstallRequest{
				CommandID: "install-1", TenantID: "tenant-1", SiteID: "site-1", SiteUID: 1001, SiteGeneration: 1,
				IsolationProfile: "isolated", InstallationID: "app-1", DatabaseInstanceID: "mariadb-local", RuntimeID: "php-83",
				CanonicalURL: "https://example.test", Locale: "en_US", Timezone: "UTC", ReleaseID: "release-1",
				Administrator: AdministratorBootstrap{Username: "admin", Email: "admin@example.test", DisplayName: "Admin", PasswordRef: "admin-1"},
				Recipe:        RecipeReference{ID: "recipe-1", DefinitionID: "wordpress", ProductVersion: "6.8.0", RecipeDigest: strings.Repeat("a", 64), Signature: "fixture", SigningKeyID: "key-1", CatalogEpoch: 1, PublishedAt: now.Add(-time.Hour)},
				CatalogTarget: CatalogTarget{OperatingSystem: OSUbuntuNoble, Architecture: ArchitectureARM64, WebEngine: EngineOpenLiteSpeed, PHPVersion: "8.3.0"},
			}
			request.DatabaseClientIdentityRef = SecretRef(ApplicationManagedSecretID("database_tls", request.InstallationID).String())
			_, err := service.Install(context.Background(), request)
			if !errors.Is(err, issueFailure) {
				t.Fatalf("lost issue failure: %v", err)
			}
			if len(secrets.revoked) != 2 || secrets.revoked[0] != "admin-1" || secrets.revoked[1] != request.DatabaseClientIdentityRef || len(database.revoked) != 1 {
				t.Fatalf("resources leaked: secrets=%v databases=%v", secrets.revoked, database.revoked)
			}
			wantState := OperationCompensated
			if cleanupFails {
				wantState = OperationRecoveryRequired
				if !errors.Is(err, cleanupFailure) || !errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("cleanup failure hidden: %v", err)
				}
			}
			if store.writes[len(store.writes)-1] != wantState {
				t.Fatalf("operation states=%v, want final %s", store.writes, wantState)
			}
		})
	}
}

func fmtBool(value bool) string {
	if value {
		return "cleanup fails"
	}
	return "cleanup succeeds"
}

func (journal *compensationJournal) UpdateOperation(ctx context.Context, operation Operation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	journal.deadline, _ = ctx.Deadline()
	journal.writes = append(journal.writes, operation.State)
	if operation.State == journal.failState {
		return journal.failure
	}
	return nil
}

type compensationSecrets struct {
	SecretIssuer
	revoked []SecretRef
}

func (secrets *compensationSecrets) RevokeApplicationSecret(ctx context.Context, ref SecretRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	secrets.revoked = append(secrets.revoked, ref)
	return nil
}

type compensationDatabase struct {
	DatabaseProvisioner
	revoked []DatabaseBindingID
	failure error
}

func (database *compensationDatabase) RevokeApplicationDatabase(ctx context.Context, id DatabaseBindingID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	database.revoked = append(database.revoked, id)
	return database.failure
}

func TestInstallCompensationSurvivesRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	journal := &compensationJournal{}
	secrets := &compensationSecrets{}
	database := &compensationDatabase{}
	service := ApplicationService{Store: journal, Secrets: secrets, Databases: database}
	err := service.compensateInstall(ctx, Operation{CommandID: "canceled-install"}, "appdb-1", []SecretRef{"admin-1", "config-1"}, context.Canceled)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("cleanup outcome: %v", err)
	}
	if len(secrets.revoked) != 2 || len(database.revoked) != 1 {
		t.Fatalf("canceled request prevented cleanup: secrets=%v database=%v", secrets.revoked, database.revoked)
	}
	if len(journal.writes) != 2 || journal.writes[1] != OperationCompensated {
		t.Fatalf("missing durable cleanup: %v", journal.writes)
	}
	if journal.deadline.IsZero() || !journal.deadline.After(time.Now()) || time.Until(journal.deadline) > 2*time.Minute {
		t.Fatalf("cleanup must have a bounded independent deadline: %v", journal.deadline)
	}
}

func TestInstallCompensationPreservesRecoveryFailures(t *testing.T) {
	for _, state := range []OperationState{"", OperationCompensating, OperationCompensated, OperationRecoveryRequired} {
		t.Run(string(state), func(t *testing.T) {
			persistenceFailure := errors.New("journal unavailable")
			cleanupFailure := errors.New("database revoke failed")
			cause := errors.New("install failed")
			journal := &compensationJournal{failState: state, failure: persistenceFailure}
			secrets := &compensationSecrets{}
			database := &compensationDatabase{}
			if state == OperationRecoveryRequired {
				database.failure = cleanupFailure
			}
			service := ApplicationService{Store: journal, Secrets: secrets, Databases: database}
			err := service.compensateInstall(context.Background(), Operation{CommandID: "install-1"}, "appdb-1", []SecretRef{"admin-1", "config-1"}, cause)
			if !errors.Is(err, cause) {
				t.Fatalf("lost original failure: %v", err)
			}
			if len(secrets.revoked) != 2 || len(database.revoked) != 1 {
				t.Fatalf("cleanup not attempted: secrets=%v databases=%v", secrets.revoked, database.revoked)
			}
			if state == "" {
				if errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("successful cleanup needs no recovery: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrRecoveryRequired) || !errors.Is(err, persistenceFailure) {
				t.Fatalf("must expose recovery and persistence failure: %v", err)
			}
			if journal.writes[len(journal.writes)-1] != OperationRecoveryRequired {
				t.Fatalf("missing recovery journal attempt: %v", journal.writes)
			}
			if state == OperationRecoveryRequired && !errors.Is(err, cleanupFailure) {
				t.Fatalf("lost cleanup failure: %v", err)
			}
		})
	}
}
