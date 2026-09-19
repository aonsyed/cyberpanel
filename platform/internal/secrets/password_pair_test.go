package secrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type pairDenyConsumers struct{}

func (pairDenyConsumers) Verify(context.Context, ConsumerIdentity) (bool, error) { return false, nil }

func TestPasswordPairAtomicReplay(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "key")
	if err := os.WriteFile(keyPath, key, 0400); err != nil {
		t.Fatal(err)
	}
	wipe(key)
	kek, err := NewFileKEK(keyPath, 1, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	open := func() (*sql.DB, *Broker) {
		t.Helper()
		db, err := sql.Open("sqlite", filepath.Join(directory, "secrets.db"))
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { db.Close() })
		store, err := NewStore(db)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Bootstrap(ctx); err != nil {
			t.Fatal(err)
		}
		broker, err := NewBroker(store, kek, pairDenyConsumers{})
		if err != nil {
			t.Fatal(err)
		}
		return db, broker
	}
	db, broker := open()
	audience := AudienceBinding{AdapterID: "database.mariadb", AdapterVersion: "v1", Account: "application", Origin: "local", ResourceKind: "database_principal", ResourceID: "principal-1", ResourceGeneration: 1, Operations: []Operation{OperationAuthenticate}, ConsumerReleaseDigest: strings.Repeat("a", 64)}
	replicaAudience := audience
	replicaAudience.AdapterID, replicaAudience.ResourceKind, replicaAudience.ResourceID = "applications.wordpress", "application_installation", "installation-1"
	request := ManagementRequest{Version: ManagementProtocolVersion, RequestID: "mgt-" + strings.Repeat("a", 32), Action: ManagementProvisionPasswordPair, SecretID: "database-secret", OwnerTenantID: "database-tenant", Purpose: PurposeDatabase, Audience: audience, Deadline: time.Now().Add(time.Minute), PasswordReplica: &PasswordBinding{ID: "application-secret", OwnerTenantID: "application-tenant", Audience: replicaAudience}}
	// Failure after the first envelope must roll back both records and pair intent.
	if _, err := db.Exec(`CREATE TRIGGER fail_replica BEFORE INSERT ON secret_records WHEN NEW.secret_id='application-secret' BEGIN SELECT RAISE(ABORT,'injected replica failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := broker.provisionPasswordPair(ctx, request); err == nil {
		t.Fatal("injected failure not observed")
	}
	for _, table := range []string{"secret_heads", "secret_records", "secret_password_pairs"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("partial pair in %s: count=%d err=%v", table, count, err)
		}
	}
	if _, err := db.Exec(`DROP TRIGGER fail_replica`); err != nil {
		t.Fatal(err)
	}
	primary, replica, err := broker.provisionPasswordPair(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	decrypt := func(head Metadata) []byte {
		t.Helper()
		record, err := broker.store.Record(ctx, head.ID, head.Version)
		if err != nil {
			t.Fatal(err)
		}
		dek, err := kek.Unwrap(ctx, head.KeyEpoch, record.WrappedDEK, record.AAD)
		if err != nil {
			t.Fatal(err)
		}
		defer wipe(dek)
		block, err := aes.NewCipher(dek)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		material, err := aead.Open(nil, record.Nonce, record.Ciphertext, record.AAD)
		if err != nil {
			t.Fatal(err)
		}
		return material
	}
	first, second := decrypt(primary), decrypt(replica)
	defer wipe(first)
	defer wipe(second)
	if len(first) != 43 || !bytes.Equal(first, second) {
		t.Fatal("consumers did not receive the same generated password")
	}
	if primary.CiphertextDigest == replica.CiphertextDigest {
		t.Fatal("consumer envelopes not independently encrypted")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, broker = open()
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			p, r, err := broker.provisionPasswordPair(ctx, request)
			if err != nil || p.CiphertextDigest != primary.CiphertextDigest || r.CiphertextDigest != replica.CiphertextDigest {
				t.Errorf("reopened concurrent replay changed pair: %v", err)
			}
		}()
	}
	workers.Wait()
	response := ManagementResponse{Version: request.Version, RequestID: request.RequestID, SecretID: request.SecretID, Metadata: primary, ReplicaMetadata: &replica}
	if err := response.Validate(request); err != nil {
		t.Fatal(err)
	}
	wrongReplica := replica
	wrongReplica.Audience.AdapterID = "other-adapter"
	response.ReplicaMetadata = &wrongReplica
	if err := response.Validate(request); err == nil {
		t.Fatal("client accepted a different replica audience")
	}
	for _, change := range []string{"material", "missing replica", "same id", "purpose", "rotation", "release mismatch"} {
		t.Run("invalid/"+change, func(t *testing.T) {
			changed := request
			copyReplica := *request.PasswordReplica
			changed.PasswordReplica = &copyReplica
			switch change {
			case "material":
				changed.Material = []byte("caller password")
			case "missing replica":
				changed.PasswordReplica = nil
			case "same id":
				copyReplica.ID = changed.SecretID
			case "purpose":
				changed.Purpose = PurposeAuthentication
			case "rotation":
				changed.ExpectedVersion = 1
			case "release mismatch":
				copyReplica.Audience.ConsumerReleaseDigest = strings.Repeat("b", 64)
			}
			if err := changed.Validate(time.Now()); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid request accepted: %v", err)
			}
		})
	}
	for _, change := range []string{"owner", "replica owner", "replica id", "adapter", "release"} {
		t.Run(change, func(t *testing.T) {
			changed := request
			copyReplica := *request.PasswordReplica
			changed.PasswordReplica = &copyReplica
			switch change {
			case "owner":
				changed.OwnerTenantID = "other-owner"
			case "replica owner":
				copyReplica.OwnerTenantID = "other-owner"
			case "replica id":
				copyReplica.ID = "other-secret"
			case "adapter":
				copyReplica.Audience.AdapterID = "other-adapter"
			case "release":
				changed.Audience.ConsumerReleaseDigest = strings.Repeat("b", 64)
				copyReplica.Audience.ConsumerReleaseDigest = strings.Repeat("b", 64)
			}
			if _, _, err := broker.provisionPasswordPair(ctx, changed); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed authority accepted: %v", err)
			}
		})
	}
	preexisting := request
	preexisting.SecretID = "preexisting-secret"
	preexistingReplica := *request.PasswordReplica
	preexistingReplica.ID = "new-replica"
	preexisting.PasswordReplica = &preexistingReplica
	if _, err := broker.Put(ctx, PutRequest{ID: preexisting.SecretID, OwnerTenantID: preexisting.OwnerTenantID, Purpose: PurposeDatabase, Audience: preexisting.Audience, Plaintext: []byte("independent credential")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := broker.provisionPasswordPair(ctx, preexisting); !errors.Is(err, ErrConflict) {
		t.Fatalf("independent secret adopted into pair: %v", err)
	}
	if _, err := broker.store.Head(ctx, preexistingReplica.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("conflict created orphan replica: %v", err)
	}
	if err := broker.Revoke(ctx, replica.ID, 1, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := broker.provisionPasswordPair(ctx, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked replica resurrected: %v", err)
	}
}
