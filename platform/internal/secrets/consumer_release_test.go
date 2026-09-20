package secrets

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestConsumerReleasePreservesCredentialIdentity(t *testing.T) {
	b, head, client := rebindFixture(t)
	ctx := context.Background()
	a, bb, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	transition := ConsumerReleaseTransition{ID: strings.Repeat("1", 64), Moves: []ConsumerReleaseMove{{a, bb}}}
	grant := GrantRequest{ID: "grant-old-before-upgrade", SecretID: head.ID, TenantID: head.OwnerTenantID, Version: head.Version, Operation: OperationAuthenticate, RequestDigest: strings.Repeat("d", 64), TTL: time.Minute, Consumer: ConsumerIdentity{ID: "consumer-test", PID: 123, ProcessStart: 1, ExecutableDigest: a, ReleaseDigest: a, TenantID: head.OwnerTenantID, AdapterID: head.Audience.AdapterID, AdapterVersion: head.Audience.AdapterVersion}}
	if _, err := b.Grant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if err := client.AuthorizeRelease(ctx, transition); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Deliver(ctx, grant.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("pre-upgrade grant survived retirement: %v", err)
	}
	if err := client.AuthorizeRelease(ctx, transition); err != nil {
		t.Fatalf("replay: %v", err)
	}
	for _, change := range []string{"old", "unrelated", "tenant", "operation", "adapter", "good"} {
		request := grant
		request.ID = ID("grant-" + change)
		request.Consumer.ReleaseDigest, request.Consumer.ExecutableDigest = bb, bb
		switch change {
		case "old":
			request.Consumer.ReleaseDigest, request.Consumer.ExecutableDigest = a, a
		case "unrelated":
			request.Consumer.ReleaseDigest, request.Consumer.ExecutableDigest = c, c
		case "tenant":
			request.TenantID = "other-tenant"
		case "operation":
			request.Operation = OperationWrite
		case "adapter":
			request.Consumer.AdapterID = "other-adapter"
		}
		issued, err := b.Grant(ctx, request)
		if change != "good" {
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("%s: %v", change, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		reader, metadata, err := b.Deliver(ctx, issued.ID)
		if err != nil {
			t.Fatal(err)
		}
		material, err := io.ReadAll(reader)
		reader.Close()
		defer wipe(material)
		if err != nil || !bytes.Equal(material, []byte("test-only-password")) || digestJSON(metadata) != digestJSON(head) {
			t.Fatal("release changed credential or its version/binding")
		}
	}
	second := ConsumerReleaseTransition{ID: strings.Repeat("2", 64), Moves: []ConsumerReleaseMove{{bb, c}}}
	if err := client.AuthorizeRelease(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := client.AuthorizeRelease(ctx, transition); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale replay: %v", err)
	}
	rollback := ConsumerReleaseTransition{ID: strings.Repeat("3", 64), Moves: []ConsumerReleaseMove{{c, bb}}}
	if err := client.AuthorizeRelease(ctx, rollback); err != nil {
		t.Fatal(err)
	}
	current, err := b.store.Head(ctx, head.ID)
	if err != nil || digestJSON(current) != digestJSON(head) {
		t.Fatal("rollback mutated credential identity")
	}
	grant.ID = "after-rollback"
	grant.Consumer.ReleaseDigest, grant.Consumer.ExecutableDigest = bb, bb
	if _, err := b.Grant(ctx, grant); err != nil {
		t.Fatalf("original credential after chained upgrade/rollback: %v", err)
	}
}

func TestConsumerReleaseRootAndAtomicity(t *testing.T) {
	b, _, client := rebindFixture(t)
	ctx := context.Background()
	transition := ConsumerReleaseTransition{ID: strings.Repeat("1", 64), Moves: []ConsumerReleaseMove{{strings.Repeat("a", 64), strings.Repeat("b", 64)}}}
	nonroot, _ := NewManagementClient(rebindTestTransport{&ManagementServer{Authorizer: rebindTestPeer{uid: 1001}, Broker: b}})
	if err := nonroot.AuthorizeRelease(ctx, transition); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-root: %v", err)
	}
	if _, err := b.store.db.Exec("CREATE TRIGGER fail_release_head BEFORE INSERT ON secret_consumer_transition_head BEGIN SELECT RAISE(ABORT,'injected'); END"); err != nil {
		t.Fatal(err)
	}
	if err := client.AuthorizeRelease(ctx, transition); err == nil {
		t.Fatal("injected failure ignored")
	}
	for _, table := range []string{"secret_consumer_releases", "secret_consumer_transitions", "secret_consumer_transition_head"} {
		var n int
		if err := b.store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("partial transition %s: %d %v", table, n, err)
		}
	}
	if _, err := b.store.db.Exec("DROP TRIGGER fail_release_head"); err != nil {
		t.Fatal(err)
	}
	if err := client.AuthorizeRelease(ctx, transition); err != nil {
		t.Fatal(err)
	}
	changed := transition
	changed.Moves = []ConsumerReleaseMove{{strings.Repeat("a", 64), strings.Repeat("c", 64)}}
	if err := client.AuthorizeRelease(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused id with changed target: %v", err)
	}
	changed.ID = strings.Repeat("2", 64)
	if err := client.AuthorizeRelease(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale source: %v", err)
	}
}
