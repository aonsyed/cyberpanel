package webmaildata

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type oauthFixtureCredentials struct{}

func (oauthFixtureCredentials) CredentialsForManageSieve(context.Context, Scope) (ManageSieveCredentials, error) {
	return ManageSieveCredentials{Username: "qa=tag,user@example.invalid", Secret: []byte("one-use-fixture-token"), OAuthBearer: true}, nil
}

func TestSieveInitialActivationRollbackCAS(t *testing.T) {
	repository, err := OpenSQLiteRepository(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.db.Close()
	ctx := context.Background()
	if err = repository.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	scope := Scope{TenantID: "tenant", UserID: "owner", MailboxID: "mailbox"}
	active := SieveActivation{Scope: scope, Generation: 1, Digest: strings.Repeat("a", 64), UpdatedAt: time.Now().UTC()}
	if err = repository.ActivateSieveCAS(ctx, active, ""); err != nil {
		t.Fatal(err)
	}
	if err = repository.ActivateSieveCAS(ctx, SieveActivation{Scope: scope}, strings.Repeat("b", 64)); err == nil {
		t.Fatal("stale rollback accepted")
	}
	if err = repository.ActivateSieveCAS(ctx, SieveActivation{Scope: scope}, active.Digest); err != nil {
		t.Fatal(err)
	}
	rolled, err := repository.ActiveSieve(ctx, scope)
	if err != nil || rolled.Generation != 0 || rolled.Digest != "" {
		t.Fatal("initial active pointer not restored", err)
	}
}

func TestSieveMutationLockSharedAcrossMailboxUsers(t *testing.T) {
	service := &Service{}
	unlock := service.LockSieveMailbox(Scope{TenantID: "tenant", UserID: "first", MailboxID: "mailbox"})
	started, acquired := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		release := service.LockSieveMailbox(Scope{TenantID: "tenant", UserID: "second", MailboxID: "mailbox"})
		close(acquired)
		release()
	}()
	<-started
	select {
	case <-acquired:
		t.Fatal("same mailbox activation raced retirement")
	case <-time.After(30 * time.Millisecond):
	}
	unlock()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("mailbox mutation lock was not released")
	}
}

func TestManageSieveOAuthNativeShape(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprint(denied), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sieve.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			completed := make(chan error, 1)
			go func() {
				conn, e := listener.Accept()
				if e != nil {
					completed <- e
					return
				}
				defer conn.Close()
				r := bufio.NewReader(conn)
				fmt.Fprint(conn, "OK ready\r\n")
				command, e := r.ReadString('\n')
				if e != nil || command != "CAPABILITY\r\n" {
					completed <- fmt.Errorf("capability: %q %v", command, e)
					return
				}
				fmt.Fprint(conn, "\"SIEVE\" \"vacation include\"\r\n\"SASL\" \"OAUTHBEARER\"\r\nOK\r\n")
				command, e = r.ReadString('\n')
				if e != nil {
					completed <- e
					return
				}
				expected := "n,a=qa=3Dtag=2Cuser@example.invalid,\x01auth=Bearer one-use-fixture-token\x01\x01"
				if command != "AUTHENTICATE \"OAUTHBEARER\" \""+base64.StdEncoding.EncodeToString([]byte(expected))+"\"\r\n" {
					completed <- fmt.Errorf("unexpected SASL shape")
					return
				}
				if denied {
					fmt.Fprint(conn, "NO denied\r\n")
				} else {
					fmt.Fprint(conn, "OK authenticated\r\n")
				}
				completed <- nil
			}()
			adapter := LocalManageSieveAdapter{UnixSocket: path, Credentials: oauthFixtureCredentials{}}
			client, err := adapter.connect(context.Background(), Scope{TenantID: "tenant", UserID: "user", MailboxID: "mailbox"})
			if denied {
				if err != ErrUnauthorized {
					t.Fatalf("denied: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				client.close()
			}
			if err := <-completed; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManageSieveOAuthNoPlaintextMaster(t *testing.T) {
	credentials, _ := (oauthFixtureCredentials{}).CredentialsForManageSieve(context.Background(), Scope{})
	if !credentials.OAuthBearer || strings.Contains(credentials.Username, "*") {
		t.Fatal("master credential selected")
	}
}

func TestManageSieveStatusLiteral(t *testing.T) {
	for _, status := range []string{"OK (WARNINGS)", "NO"} {
		literal := "native compiler diagnostic\r\n"
		client := manageSieveClient{reader: bufio.NewReader(strings.NewReader(fmt.Sprintf("%s {%d}\r\n%s\r\nOK next\r\n", status, len(literal), literal)))}
		_, err := client.readResponse()
		if status == "NO" && err != ErrConflict || status != "NO" && err != nil {
			t.Fatalf("status lost: %v", err)
		}
		lines, err := client.readResponse()
		if err != nil || len(lines) != 0 {
			t.Fatalf("literal desynchronized next command: %v %q", err, lines)
		}
	}
}
