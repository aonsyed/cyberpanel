//go:build linux

package apps

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// Records metadata only, so fixture cleanup never reads or retains credentials.
type provisionManagementTransport struct {
	secrets.ManagementTransport
	heads    map[secrets.ID]secrets.Metadata
	loseNext bool
}

func (transport *provisionManagementTransport) RoundTrip(ctx context.Context, request secrets.ManagementRequest) (secrets.ManagementResponse, error) {
	response, err := transport.ManagementTransport.RoundTrip(ctx, request)
	if err == nil && response.FailureCode == "" {
		transport.heads[response.Metadata.ID] = response.Metadata
		if response.ReplicaMetadata != nil {
			transport.heads[response.ReplicaMetadata.ID] = *response.ReplicaMetadata
		}
		if transport.loseNext {
			transport.loseNext = false
			return secrets.ManagementResponse{}, errors.New("injected lost response")
		}
	}
	return response, err
}

func TestQEMULiveApplicationDatabaseProvisionReplay(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_APP_DATABASE") != "1" {
		t.Skip("requires installed QEMU secret-management broker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	transport := &provisionManagementTransport{
		ManagementTransport: secrets.FramedManagementTransport{Dialer: secrets.LocalManagementDialer{}},
		heads:               make(map[secrets.ID]secrets.Metadata),
	}
	if os.Getenv("CYBERPANEL_QEMU_APP_DATABASE_ISOLATED") == "1" {
		transport.ManagementTransport = isolatedProvisionBroker(t, ctx)
		transport.loseNext = true
	}
	client, err := secrets.NewManagementClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		for _, head := range transport.heads {
			if _, err := client.Revoke(cleanup, secrets.RevokeRequest{ID: head.ID, OwnerTenantID: head.OwnerTenantID, Purpose: head.Purpose, Audience: head.Audience, ExpectedVersion: head.Version, ExpectedBindingDigest: head.BindingDigest}); err != nil {
				t.Errorf("revoke fixture metadata: %v", err)
			}
		}
	})
	handle, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "database.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	repository, err := database.NewSQLRepository(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	instance, err := database.DefaultLocalInstance()
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.EnsureBootstrapResources(ctx, instance); err != nil {
		t.Fatal(err)
	}
	// SQL side effects are controlled here; real MariaDB has separate live coverage.
	commands := &cleanupCommands{statuses: []database.OperationStatus{
		database.OperationApplied, database.OperationApplied, database.OperationApplied,
		database.OperationApplied, database.OperationApplied, database.OperationApplied,
	}}
	provisioner, err := NewApplicationDatabaseProvisioner(commands, repository, client, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	installation := InstallationID(fmt.Sprintf("qemu-provision-%x", time.Now().UnixNano()))
	if transport.loseNext {
		if _, err := provisioner.ProvisionApplicationDatabase(ctx, "qemu-tenant", "qemu-site", installation, ApplicationWordPress); err == nil {
			t.Fatal("lost response was not injected")
		}
		if commands.calls != 0 {
			t.Fatal("database commands ran before credential acknowledgement")
		}
	}
	first, err := provisioner.ProvisionApplicationDatabase(ctx, "qemu-tenant", "qemu-site", installation, ApplicationWordPress)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if len(transport.heads) != 2 {
		t.Fatalf("expected two audience-bound credentials, got %d", len(transport.heads))
	}
	replayed, err := provisioner.ProvisionApplicationDatabase(ctx, "qemu-tenant", "qemu-site", installation, ApplicationWordPress)
	if err != nil {
		t.Fatalf("identical provisioning replay must preserve credentials: %v", err)
	}
	if replayed != first {
		t.Fatal("replay changed database binding")
	}
	for _, head := range transport.heads {
		if head.Version != 1 {
			t.Fatal("replay rotated credential")
		}
	}
}

type provisionDialer string

func (path provisionDialer) DialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", string(path))
}

type noProvisionConsumers struct{}

func (noProvisionConsumers) Verify(context.Context, secrets.ConsumerIdentity) (bool, error) {
	return false, nil
}

// Runs the current broker over an actual Unix socket and encrypted SQLite store.
// It does not replace or relax the installed broker or allow material delivery.
func isolatedProvisionBroker(t *testing.T, ctx context.Context) secrets.ManagementTransport {
	t.Helper()
	directory, err := os.MkdirTemp("/var/tmp", "app-pair-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "key")
	if err := os.WriteFile(keyPath, key, 0400); err != nil {
		t.Fatal(err)
	}
	wipeLinuxApplicationBytes(key)
	handle, err := sql.Open("sqlite", filepath.Join(directory, "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { handle.Close() })
	store, err := secrets.NewStore(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	kek, err := secrets.NewFileKEK(keyPath, 1, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secrets.NewBroker(store, kek, noProvisionConsumers{})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := secrets.NewLinuxManagementPeerAuthorizer(uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "manage.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	server := &secrets.ManagementServer{Broker: broker, Authorizer: authorizer}
	go func() { defer close(stopped); _ = server.Serve(listener) }()
	t.Cleanup(func() { listener.Close(); <-stopped })
	return secrets.FramedManagementTransport{Dialer: provisionDialer(path)}
}
