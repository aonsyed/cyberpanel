package webmaildata

import (
	"context"
	"errors"
	"fmt"
	maildata "github.com/aonsyed/cyberpanel/platform/internal/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type vacationFixtureAuthority struct{}

func (vacationFixtureAuthority) AuthorizeWebmailData(_ context.Context, r AuthorizationRequest) error {
	if r.Scope.TenantID != "tenant" || r.Scope.UserID != "owner" || r.Scope.MailboxID != "mailbox" {
		return ErrUnauthorized
	}
	return nil
}

type vacationFixtureCredentials struct{}

func (vacationFixtureCredentials) CredentialsForManageSieve(_ context.Context, s Scope) (ManageSieveCredentials, error) {
	if s.TenantID != "tenant" || s.UserID != "owner" {
		return ManageSieveCredentials{}, ErrUnauthorized
	}
	return ManageSieveCredentials{Username: "qa@fixture.invalid", Secret: []byte("disposable-fixture")}, nil
}

func TestVacationNativeComposition(t *testing.T) {
	if os.Getenv("CYBERPANEL_VACATION_NATIVE") != "1" {
		t.Skip("isolated QEMU native fixture only")
	}
	root, err := os.MkdirTemp("/tmp", "cp-vacation-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(home, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	passdb := filepath.Join(root, "users")
	if err = os.WriteFile(passdb, []byte("qa@fixture.invalid:{PLAIN}disposable-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "sieve.sock")
	config := fmt.Sprintf(`base_dir = %s/run
state_dir = %s/state
instance_name = vacation-fixture
protocols = sieve
listen = 127.0.0.1
ssl = no
disable_plaintext_auth = no
auth_mechanisms = plain
service auth {
 user = root
}
log_path = %s/native.log
mail_location = maildir:~/Maildir
passdb {
 driver = passwd-file
 args = %s
}
userdb {
 driver = static
 args = uid=65534 gid=65534 home=%s
}
service managesieve-login {
 inet_listener sieve {
  port = 0
 }
 unix_listener %s {
  mode = 0600
  user = root
 }
}
plugin {
 sieve = file:~/sieve;active=~/.dovecot.sieve
 sieve_extensions = +vacation-seconds
 sieve_vacation_min_period = 1h
}
`, root, root, root, passdb, home, socket)
	configPath := filepath.Join(root, "dovecot.conf")
	if err = os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/sbin/dovecot", "-F", "-c", configPath)
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		command.Process.Signal(os.Interrupt)
		command.Wait()
		if t.Failed() {
			raw, _ := os.ReadFile(filepath.Join(root, "native.log"))
			t.Log(string(raw))
		}
	}()
	for i := 0; i < 100; i++ {
		if _, err = os.Stat(socket); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	ctx := context.Background()
	repository, err := OpenSQLiteRepository(filepath.Join(root, "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.db.Close()
	if err = repository.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	native := &LocalManageSieveAdapter{UnixSocket: socket, Credentials: vacationFixtureCredentials{}}
	service := &Service{Repository: repository, SieveRuntime: native, Authorizer: vacationFixtureAuthority{}, Now: time.Now}
	scope := Scope{TenantID: "tenant", UserID: "owner", MailboxID: "mailbox"}
	now := time.Now().UTC().Truncate(time.Second)
	probe, err := native.connect(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if err = probe.checkScript("require [\"cyberpanel-missing-extension\"];\nkeep;\n"); err == nil {
		t.Fatal("unsupported native program accepted")
	}
	probe.close()
	filter := SieveRule{Scope: scope, ID: "filter", Name: "Keep tagged messages", Enabled: true, Order: 0, Revision: 1, UpdatedAt: now, MatchAll: true, Conditions: []SieveCondition{{Kind: ConditionHeader, Operator: MatchContains, Field: "Subject", Values: []string{"tagged"}}}, Actions: []SieveAction{{Kind: ActionKeep}}}
	if err = repository.PutSieveRule(ctx, filter, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = service.activateSieve(ctx, Call{ActorID: "owner", OperationID: "initial", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	rule := maildata.AutoresponderRule{ID: "vacation", TenantID: "tenant", DomainID: "domain", MailboxID: "mailbox", MailboxAddress: "qa@fixture.invalid", MailboxGeneration: 1, Settings: maildata.AutoresponderSettings{Subject: "Away", Body: "Local fixture reply", Timezone: "UTC", RepeatInterval: time.Hour}, Enabled: true, State: maildata.AutoresponderActive, Generation: 1, CreatedAt: now, UpdatedAt: now}
	enabled, err := maildata.CompileAutoresponderSieve(rule)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := maildata.RemovedAutoresponderSieveProgram("tenant", "domain", "mailbox", "vacation", 0)
	if err != nil {
		t.Fatal(err)
	}
	runtime := VacationRuntime{Service: service, Native: native, ActorID: "owner"}
	request := maildata.AutoresponderSieveRequest{OperationID: "enable", TenantID: "tenant", DomainID: "domain", MailboxID: "mailbox", MailboxGeneration: 1, ExpectedDigest: removed.Digest, Program: enabled}
	if _, err = runtime.ApplyAutoresponder(ctx, request); err != nil {
		t.Fatal(err)
	}
	inspect := func(included bool) {
		t.Helper()
		active, e := repository.ActiveSieve(ctx, scope)
		if e != nil {
			t.Fatal(e)
		}
		program, e := repository.GetSieveProgram(ctx, scope, active.Generation)
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(program.Script, "tagged") || strings.Contains(program.Script, "include :personal") != included {
			t.Fatalf("filter/vacation composition mismatch: %s", program.Script)
		}
		client, e := native.connect(ctx, scope)
		if e != nil {
			t.Fatal(e)
		}
		defer client.close()
		_, name, e := client.listScripts()
		if e != nil {
			t.Fatal(e)
		}
		raw, e := client.getScript(name)
		if e != nil || raw != program.Script {
			t.Fatal("native active script differs", e)
		}
	}
	inspect(true)
	if _, err = runtime.ApplyAutoresponder(ctx, request); !errors.Is(err, maildata.ErrConflict) {
		t.Fatalf("stale digest: %v", err)
	}
	foreign := runtime
	foreign.ActorID = "foreign"
	if _, err = foreign.ApplyAutoresponder(ctx, request); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign actor: %v", err)
	}
	foreignRequest := request
	foreignRequest.TenantID = "foreign"
	if _, err = runtime.ApplyAutoresponder(ctx, foreignRequest); err == nil {
		t.Fatal("foreign tenant accepted")
	}
	rule.Generation = 2
	rule.Enabled = false
	rule.State = maildata.AutoresponderSuspended
	disabled, err := maildata.CompileAutoresponderSieve(rule)
	if err != nil {
		t.Fatal(err)
	}
	request.OperationID = "disable"
	request.ExpectedDigest = enabled.Digest
	request.Program = disabled
	if _, err = runtime.ApplyAutoresponder(ctx, request); err != nil {
		t.Fatal(err)
	}
	inspect(false)
	retained := []CanonicalVacationReference{{RuleID: enabled.RuleID, Generation: enabled.Generation, ProgramDigest: enabled.Digest}, {RuleID: disabled.RuleID, Generation: disabled.Generation, ProgramDigest: disabled.Digest}}
	if err = runtime.Retire(ctx, scope, enabled.RuleID, retained); err != nil {
		t.Fatal(err)
	}
	assertOwned := func(want int) {
		t.Helper()
		client, e := native.connect(ctx, scope)
		if e != nil {
			t.Fatal(e)
		}
		defer client.close()
		scripts, _, e := client.listScripts()
		if e != nil {
			t.Fatal(e)
		}
		count := 0
		for name := range scripts {
			if strings.HasPrefix(name, vacationScriptPrefix(scope, enabled.RuleID)) {
				count++
			}
		}
		if count != want {
			t.Fatalf("owned named scripts: got %d want %d", count, want)
		}
	}
	assertOwned(2)
	request.OperationID = "rollback"
	request.ExpectedDigest = disabled.Digest
	request.Program = enabled
	request.Rollback = true
	if _, err = runtime.ApplyAutoresponder(ctx, request); err != nil {
		t.Fatal(err)
	}
	inspect(true)
	// A committed cleanup cannot retire a program referenced by the active script.
	if err = runtime.Retire(ctx, scope, enabled.RuleID, nil); err != nil {
		t.Fatal(err)
	}
	assertOwned(1)
	request.OperationID = "remove"
	request.ExpectedDigest = enabled.Digest
	request.Program = removed
	request.Rollback = false
	if _, err = runtime.ApplyAutoresponder(ctx, request); err != nil {
		t.Fatal(err)
	}
	inspect(false)
	if err = runtime.Retire(ctx, scope, enabled.RuleID, nil); err != nil {
		t.Fatal(err)
	}
	assertOwned(0)
	t.Log("native CHECKSCRIPT/PUTSCRIPT/SETACTIVE: filter preserved; vacation enabled, disabled, rolled back, removed; stale digest and foreign actor denied")
}
