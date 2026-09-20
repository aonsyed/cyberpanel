package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type rebindTestConsumers struct{}

func (rebindTestConsumers) Verify(context.Context, ConsumerIdentity) (bool, error) { return true, nil }

type rebindTestPeer struct{ uid uint32 }

func (p rebindTestPeer) Authorize(net.Conn) (VerifiedPeer, error) {
	return VerifiedPeer{UID: p.uid, PID: 123}, nil
}

type rebindTestTransport struct{ server *ManagementServer }

func (p rebindTestTransport) RoundTrip(_ context.Context, request ManagementRequest) (ManagementResponse, error) {
	client, server := net.Pipe()
	defer client.Close()
	go func() { defer server.Close(); p.server.serve(server) }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeManagementFrame(client, request); err != nil {
		return ManagementResponse{}, err
	}
	var response ManagementResponse
	err := readManagementFrame(client, &response)
	return response, err
}

func rebindFixture(t *testing.T) (*Broker, Metadata, *ManagementClient) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, key, 0400); err != nil {
		t.Fatal(err)
	}
	wipe(key)
	kek, err := NewFileKEK(keyPath, 1, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	broker, err := NewBroker(store, kek, rebindTestConsumers{})
	if err != nil {
		t.Fatal(err)
	}
	audience := AudienceBinding{AdapterID: "database.mariadb", AdapterVersion: "linux-mariadb-v1", Account: "test-user", Origin: "local://panel-execd/mariadb", ResourceKind: "database_principal", ResourceID: "principal-test", ResourceGeneration: 1, Operations: []Operation{OperationAuthenticate}, ConsumerReleaseDigest: strings.Repeat("a", 64)}
	head, err := broker.Put(ctx, PutRequest{ID: "credential-test", OwnerTenantID: "tenant-test", Purpose: PurposeDatabase, Audience: audience, Plaintext: []byte("test-only-password")})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewManagementClient(rebindTestTransport{&ManagementServer{Authorizer: rebindTestPeer{}, Broker: broker}})
	if err != nil {
		t.Fatal(err)
	}
	return broker, head, client
}

func TestConsumerRebindPreservesMaterialAndRejectsOldConsumer(t *testing.T) {
	broker, old, client := rebindFixture(t)
	ctx := context.Background()
	consumer := ConsumerIdentity{ID: "consumer-test", PID: 123, ProcessStart: 1, ExecutableDigest: strings.Repeat("b", 64), ReleaseDigest: strings.Repeat("b", 64), TenantID: old.OwnerTenantID, AdapterID: old.Audience.AdapterID, AdapterVersion: old.Audience.AdapterVersion}
	grant := GrantRequest{ID: "before-upgrade", SecretID: old.ID, TenantID: old.OwnerTenantID, Version: old.Version, Operation: OperationAuthenticate, Consumer: consumer, RequestDigest: strings.Repeat("c", 64), TTL: time.Minute}
	if _, err := broker.Grant(ctx, grant); !errors.Is(err, ErrForbidden) {
		t.Fatalf("new binary before authorization: %v", err)
	}
	head, err := client.RebindConsumer(ctx, old, consumer.ReleaseDigest)
	if err != nil {
		t.Fatal(err)
	}
	if head.Version != 2 || head.BindingDigest == old.BindingDigest {
		t.Fatal("transition did not create new authenticated version")
	}
	replayed, err := client.RebindConsumer(ctx, old, consumer.ReleaseDigest)
	if err != nil || replayed.BindingDigest != head.BindingDigest {
		t.Fatalf("lost-response replay: %v", err)
	}
	grant.ID, grant.Version = "after-upgrade", head.Version
	issued, err := broker.Grant(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := broker.Deliver(ctx, issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	material, err := io.ReadAll(reader)
	reader.Close()
	defer wipe(material)
	if err != nil || !bytes.Equal(material, []byte("test-only-password")) {
		t.Fatal("upgrade changed credential material")
	}
	grant.ID = "old-consumer"
	grant.Consumer.ReleaseDigest, grant.Consumer.ExecutableDigest = old.Audience.ConsumerReleaseDigest, old.Audience.ConsumerReleaseDigest
	if _, err := broker.Grant(ctx, grant); !errors.Is(err, ErrForbidden) {
		t.Fatalf("old binary accepted for current version: %v", err)
	}
	rolled, err := client.RebindConsumer(ctx, head, old.Audience.ConsumerReleaseDigest)
	if err != nil || rolled.Version != 3 {
		t.Fatalf("rollback must advance secret version: %v", err)
	}
	if _, err := client.RebindConsumer(ctx, old, consumer.ReleaseDigest); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale transition replay: %v", err)
	}
}

func TestConsumerRebindRejectsAuthorityChanges(t *testing.T) {
	for _, change := range []string{"non-root", "tenant", "account", "origin", "resource", "generation", "operations", "adapter", "purpose", "binding", "revoked", "tampered", "same-digest", "invalid-digest"} {
		t.Run(change, func(t *testing.T) {
			broker, old, client := rebindFixture(t)
			ctx := context.Background()
			destination := strings.Repeat("b", 64)
			switch change {
			case "non-root":
				client, _ = NewManagementClient(rebindTestTransport{&ManagementServer{Authorizer: rebindTestPeer{uid: 1001}, Broker: broker}})
			case "tenant":
				old.OwnerTenantID = "another-tenant"
			case "account":
				old.Audience.Account = "other"
			case "origin":
				old.Audience.Origin = "https://other.invalid"
			case "resource":
				old.Audience.ResourceID = "other-resource"
			case "generation":
				old.Audience.ResourceGeneration++
			case "operations":
				old.Audience.Operations = []Operation{OperationWrite}
			case "adapter":
				old.Audience.AdapterVersion = "v2"
			case "purpose":
				old.Purpose = PurposeAuthentication
			case "binding":
				old.BindingDigest = strings.Repeat("f", 64)
			case "revoked":
				if err := broker.Revoke(ctx, old.ID, old.Version, false); err != nil {
					t.Fatal(err)
				}
			case "tampered":
				if _, err := broker.store.db.Exec("UPDATE secret_records SET ciphertext=? WHERE secret_id=?", []byte("corrupt"), old.ID); err != nil {
					t.Fatal(err)
				}
			case "same-digest":
				destination = old.Audience.ConsumerReleaseDigest
			case "invalid-digest":
				destination = strings.Repeat("z", 64)
			}
			if _, err := client.RebindConsumer(ctx, old, destination); err == nil {
				t.Fatal("invalid transition accepted")
			}
			var version uint64
			if err := broker.store.db.QueryRow("SELECT current_version FROM secret_heads WHERE secret_id=?", old.ID).Scan(&version); err != nil || version != 1 {
				t.Fatalf("failed transition mutated head: %d %v", version, err)
			}
		})
	}
}
