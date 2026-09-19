package apps

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCloneClientIdentityBelongsToTarget(t *testing.T) {
	now := time.Now().UTC()
	request := cloneRequestFixture(now)
	source := request.Source
	request.TargetDatabaseClientIdentityRef = SecretRef(ApplicationManagedSecretID("database_tls", request.TargetInstallationID).String())
	if err := request.Validate(now); err != nil {
		t.Fatal(err)
	}
	request.TargetDatabaseClientIdentityRef = SecretRef(ApplicationManagedSecretID("database_tls", source.ID).String())
	if err := request.Validate(now); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("clone accepted source client identity: %v", err)
	}
	request.TargetDatabaseClientIdentityRef = "arbitrary-identity"
	if err := request.Validate(now); !errors.Is(err, ErrPolicyDenied) {
		t.Fatal("clone accepted unrelated identity")
	}
}

func cloneRequestFixture(now time.Time) CloneRequest {
	source := ApplicationInstallation{ID: "source-app", TenantID: "tenant-test", SiteID: "source-site", SiteUID: 1001, DefinitionID: "wordpress", Kind: ApplicationWordPress, RuntimeID: "php83", Generation: 1, StorageMode: StorageMutableTree, State: InstallationActive, CreatedAt: now, UpdatedAt: now, Recipe: RecipeReference{ID: "recipe-test", DefinitionID: "wordpress", ProductVersion: "7.1.0", RecipeDigest: strings.Repeat("a", 64), Signature: "fixture", SigningKeyID: "key-test", CatalogEpoch: 1, PublishedAt: now.Add(-time.Hour)}}
	request := CloneRequest{CommandID: "clone-test", RelationID: "relation-test", TenantID: "tenant-test", Source: source, TargetSiteID: "target-site", TargetProjectID: "project-test", TargetSiteUID: 1002, TargetInstallationID: "target-app", TargetDatabaseInstanceID: "external-test", SourceURL: "https://source.example.test", TargetURL: "https://target.example.test", TargetRuntimeID: "php83", CreateDatabase: true, MailSuppressed: true, ExternalActionsDenied: true, AccessPolicyID: "policy-test"}
	return request
}
