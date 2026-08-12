package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

func TestCreateAdmitsSiteProjectionAndOutboxBeforeApplyingEffect(t *testing.T) {
	repository := newMemoryRepository(site.Site{})
	driver := &recordingEffectDriver{events: &repository.events}
	command := createCommand(t, "cmd-create", "site-1", "tenant-a")
	driver.observe = func(request SiteEffectRequest) {
		if !repository.hasStored || repository.stored.Status != OperationAccepted {
			t.Fatalf("effect ran before accepted command was durable: %#v", repository.stored)
		}
		if repository.proposal.ID() != command.Site.ID {
			t.Fatalf("effect ran before proposal was durable: proposal = %#v", repository.proposal)
		}
		if !reflect.DeepEqual(repository.stored.Request, request) {
			t.Fatalf("durable outbox request = %#v, applied request = %#v", repository.stored.Request, request)
		}
	}

	receipt, err := New(repository, driver, fixedClock{}).Handle(context.Background(), command)
	if err != nil {
		t.Fatalf("Handle(create): %v", err)
	}
	if receipt.Status != OperationApplied || repository.current.Lifecycle() != site.LifecycleProvisioning {
		t.Fatalf("receipt/current = %q/%q, want applied/provisioning", receipt.Status, repository.current.Lifecycle())
	}
	if got, want := repository.events, []string{"lookup:cmd-create", "admit:cmd-create", "effect:provisioning", "complete:applied"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("durable boundary order = %#v, want %#v", got, want)
	}
	if repository.admission.ExpectedGeneration != 0 {
		t.Fatalf("create expected generation = %d, want 0", repository.admission.ExpectedGeneration)
	}
	if len(driver.requests) != 1 {
		t.Fatalf("effect requests = %d, want 1", len(driver.requests))
	}
	request := driver.requests[0]
	if request.EffectID == "" || request.ProjectionDigest == "" {
		t.Fatalf("request is not durably identifiable: %#v", request)
	}
	wantEffectID := expectedEffectID(request.Scope, command.CommandID, command.commandDigest(), request.ProjectionDigest, request.Withdraw)
	if request.EffectID != wantEffectID {
		t.Fatalf("effect ID = %q, want projection-and-withdrawal-bound %q", request.EffectID, wantEffectID)
	}
	if request.Scope != commandScope(command) {
		t.Fatalf("request scope = %#v, want %#v", request.Scope, commandScope(command))
	}
	if request.Withdraw {
		t.Fatal("new provisioning site was emitted as a withdrawal")
	}
	if request.Projection.Generation != 1 || request.Projection.Lifecycle != site.LifecycleProvisioning {
		t.Fatalf("projection generation/lifecycle = %d/%q, want 1/provisioning", request.Projection.Generation, request.Projection.Lifecycle)
	}
	wantBindings := []site.DomainBinding{{Hostname: mustHostname(t, "example.test"), Kind: site.BindingPrimary}}
	if !reflect.DeepEqual(request.Projection.Bindings, wantBindings) {
		t.Fatalf("projection bindings = %#v, want %#v", request.Projection.Bindings, wantBindings)
	}
	if !effectMatchesRequest(receipt.Effect, request) || receipt.Effect.Outcome != EffectConfirmed {
		t.Fatalf("terminal effect = %#v, want exact confirmed binding to %#v", receipt.Effect, request)
	}
}

func TestLifecycleLoadRejectsAggregateOutsideRequestedIdentity(t *testing.T) {
	requested := mustSiteAt(t, "site-1", "tenant-a", site.LifecycleActive)
	command := SuspendSite{
		CommandID:          "cmd-suspend",
		Actor:              Actor{TenantID: requested.TenantID()},
		TenantID:           requested.TenantID(),
		SiteID:             requested.ID(),
		ExpectedGeneration: requested.Generation(),
	}

	for _, test := range []struct {
		name   string
		loaded site.Site
	}{
		{name: "wrong tenant", loaded: mustSiteAt(t, "site-1", "tenant-b", site.LifecycleActive)},
		{name: "wrong site", loaded: mustSiteAt(t, "site-2", "tenant-a", site.LifecycleActive)},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newMemoryRepository(requested)
			repository.loadOverride = func(site.TenantID, site.SiteID) (site.Site, error) {
				return test.loaded, nil
			}
			driver := &recordingEffectDriver{events: &repository.events}

			receipt, err := New(repository, driver, fixedClock{}).Handle(context.Background(), command)
			if err == nil {
				t.Fatalf("Handle() accepted repository aggregate %#v outside requested scope %#v", test.loaded, scopeFor(requested))
			}
			if !reflect.DeepEqual(receipt, OperationReceipt{}) {
				t.Fatalf("receipt = %#v, want zero", receipt)
			}
			if repository.admitCalls != 0 || len(driver.requests) != 0 {
				t.Fatalf("wrong-identity load reached admission/effect: admits=%d requests=%#v", repository.admitCalls, driver.requests)
			}
			if got, want := repository.events, []string{"lookup:cmd-suspend", "load:site-1"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("events = %#v, want fail-closed %#v", got, want)
			}
		})
	}
}

func TestAdmissionResultCannotSubstituteSelfConsistentEffectRequest(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(SiteEffectRequest) SiteEffectRequest
	}{
		{
			name: "different valid projection",
			mutate: func(request SiteEffectRequest) SiteEffectRequest {
				request.Projection.Bindings = []site.DomainBinding{{Hostname: mustHostname(t, "substituted.test"), Kind: site.BindingPrimary}}
				return request
			},
		},
		{
			name: "different valid withdrawal",
			mutate: func(request SiteEffectRequest) SiteEffectRequest {
				request.Projection.Lifecycle = site.LifecyclePurging
				request.Withdraw = true
				return request
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := createCommand(t, "cmd-create", "site-1", "tenant-a")
			repository := newMemoryRepository(site.Site{})
			repository.admitReceiptMutator = func(admission Admission, receipt OperationReceipt) OperationReceipt {
				receipt.Request = test.mutate(receipt.Request)
				receipt.Request.ProjectionDigest = projectionDigest(receipt.Request.Projection)
				receipt.Request.EffectID = expectedEffectID(
					receipt.Request.Scope,
					admission.CommandID,
					admission.Digest,
					receipt.Request.ProjectionDigest,
					receipt.Request.Withdraw,
				)
				return receipt
			}
			driver := &recordingEffectDriver{events: &repository.events}

			receipt, err := New(repository, driver, fixedClock{}).Handle(context.Background(), command)
			if !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("error = %v, want ErrInvalidReceipt", err)
			}
			if !reflect.DeepEqual(receipt, OperationReceipt{}) {
				t.Fatalf("receipt = %#v, want zero", receipt)
			}
			if len(driver.requests) != 0 {
				t.Fatalf("substituted admission request reached effect driver: %#v", driver.requests)
			}
			if got, want := repository.events, []string{"lookup:cmd-create", "admit:cmd-create"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("events = %#v, want %#v", got, want)
			}
		})
	}
}

func TestCompetingAdmissionCASConflictDoesNotCreateOutboxOrEffect(t *testing.T) {
	current := mustSiteAt(t, "site-1", "tenant-a", site.LifecycleActive)
	repository := newMemoryRepository(current)
	repository.beforeAdmit = func(repository *memoryRepository, _ Admission) {
		competing, err := repository.current.Transition(repository.current.Generation(), site.LifecycleSuspended)
		if err != nil {
			t.Fatalf("build competing commit: %v", err)
		}
		repository.current = competing
	}
	driver := &recordingEffectDriver{events: &repository.events}
	command := SuspendSite{
		CommandID:          "cmd-lost-cas",
		Actor:              Actor{TenantID: current.TenantID()},
		TenantID:           current.TenantID(),
		SiteID:             current.ID(),
		ExpectedGeneration: current.Generation(),
	}

	receipt, err := New(repository, driver, fixedClock{}).Handle(context.Background(), command)
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("error = %v, want ErrIdempotencyConflict", err)
	}
	if !reflect.DeepEqual(receipt, OperationReceipt{}) {
		t.Fatalf("receipt = %#v, want zero", receipt)
	}
	if repository.hasStored || len(driver.requests) != 0 {
		t.Fatalf("lost CAS created outbox/effect: stored=%t requests=%#v", repository.hasStored, driver.requests)
	}
	if got, want := repository.events, []string{"lookup:cmd-lost-cas", "load:site-1", "admit:cmd-lost-cas"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
}

func TestLifecycleRetryReturnsTerminalReceiptBeforeStaleAggregateLoad(t *testing.T) {
	current := mustSiteAt(t, "site-1", "tenant-a", site.LifecycleActive)
	repository := newMemoryRepository(current)
	driver := &recordingEffectDriver{events: &repository.events}
	command := SuspendSite{
		CommandID:          "cmd-suspend",
		Actor:              Actor{TenantID: current.TenantID()},
		TenantID:           current.TenantID(),
		SiteID:             current.ID(),
		ExpectedGeneration: current.Generation(),
	}
	service := New(repository, driver, fixedClock{})

	first, err := service.Handle(context.Background(), command)
	if err != nil {
		t.Fatalf("first Handle(suspend): %v", err)
	}
	beforeRetry := len(repository.events)
	second, err := service.Handle(context.Background(), command)
	if err != nil {
		t.Fatalf("retry Handle(suspend): %v", err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("retry receipt = %#v, want durable first receipt %#v", second, first)
	}
	if got, want := repository.events[beforeRetry:], []string{"lookup:cmd-suspend"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retry events = %#v, want %#v", got, want)
	}
	if len(driver.requests) != 1 {
		t.Fatalf("effect requests after terminal retry = %d, want 1", len(driver.requests))
	}
}

func TestLookupConflictStopsBeforeLifecycleLoad(t *testing.T) {
	current := mustSiteAt(t, "site-1", "tenant-a", site.LifecycleActive)
	command := SuspendSite{
		CommandID:          "cmd-conflict",
		Actor:              Actor{TenantID: current.TenantID()},
		TenantID:           current.TenantID(),
		SiteID:             current.ID(),
		ExpectedGeneration: current.Generation(),
	}
	repository := newMemoryRepository(current)
	repository.hasStored = true
	repository.stored = OperationReceipt{
		CommandID: command.CommandID,
		Digest:    "digest-for-another-payload",
		Scope:     scopeFor(current),
		Status:    OperationApplied,
	}

	receipt, err := New(repository, &recordingEffectDriver{events: &repository.events}, fixedClock{}).Handle(context.Background(), command)
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("error = %v, want ErrIdempotencyConflict", err)
	}
	if !reflect.DeepEqual(receipt, OperationReceipt{}) {
		t.Fatalf("receipt = %#v, want zero", receipt)
	}
	if got, want := repository.events, []string{"lookup:cmd-conflict"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
}

func TestAmbiguousLifecycleRetryUsesOriginalProposalAndEffectIdentity(t *testing.T) {
	current := mustSiteAt(t, "site-1", "tenant-a", site.LifecycleProvisioning)
	repository := newMemoryRepository(current)
	driver := &recordingEffectDriver{
		events: &repository.events,
		responses: []effectResponse{
			{outcome: EffectAmbiguous, err: context.DeadlineExceeded},
			{outcome: EffectConfirmed},
		},
	}
	command := MarkProvisioned{
		CommandID:          "cmd-activate",
		Actor:              Actor{TenantID: current.TenantID()},
		TenantID:           current.TenantID(),
		SiteID:             current.ID(),
		ExpectedGeneration: current.Generation(),
	}
	service := New(repository, driver, fixedClock{})

	first, err := service.Handle(context.Background(), command)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first error = %v, want deadline exceeded", err)
	}
	if first.Status != OperationAmbiguous || repository.current.Lifecycle() != site.LifecycleProvisioning {
		t.Fatalf("first status/current = %q/%q, want ambiguous/provisioning", first.Status, repository.current.Lifecycle())
	}
	beforeRetry := len(repository.events)
	second, err := service.Handle(context.Background(), command)
	if err != nil {
		t.Fatalf("retry Handle(activate): %v", err)
	}
	if second.Status != OperationApplied || repository.current.Lifecycle() != site.LifecycleActive {
		t.Fatalf("retry status/current = %q/%q, want applied/active", second.Status, repository.current.Lifecycle())
	}
	if got, want := repository.events[beforeRetry:], []string{"lookup:cmd-activate", "effect:active", "complete:applied"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retry events = %#v, want %#v", got, want)
	}
	if len(driver.requests) != 2 || !reflect.DeepEqual(driver.requests[1], driver.requests[0]) {
		t.Fatalf("retry requests = %#v, want byte-for-byte stable request", driver.requests)
	}
	if repository.admitCalls != 1 || repository.loadCalls != 1 {
		t.Fatalf("admit/load calls = %d/%d, want 1/1", repository.admitCalls, repository.loadCalls)
	}
}

func TestConfirmedEffectIsNotReportedAppliedUntilCompletionIsDurable(t *testing.T) {
	current := mustSiteAt(t, "site-1", "tenant-a", site.LifecycleProvisioning)
	repository := newMemoryRepository(current)
	durableErr := errors.New("database commit failed")
	repository.completeErr = durableErr
	driver := &recordingEffectDriver{events: &repository.events}
	command := MarkProvisioned{
		CommandID:          "cmd-activate",
		Actor:              Actor{TenantID: current.TenantID()},
		TenantID:           current.TenantID(),
		SiteID:             current.ID(),
		ExpectedGeneration: current.Generation(),
	}

	receipt, err := New(repository, driver, fixedClock{}).Handle(context.Background(), command)
	if !errors.Is(err, durableErr) {
		t.Fatalf("error = %v, want durable commit error", err)
	}
	if receipt.Status != OperationAmbiguous {
		t.Fatalf("status = %q, want ambiguous", receipt.Status)
	}
	if repository.current.Lifecycle() != site.LifecycleProvisioning {
		t.Fatalf("observed lifecycle = %q, want provisioning", repository.current.Lifecycle())
	}
	if repository.stored.Status != OperationAccepted {
		t.Fatalf("durable command status = %q, want accepted after failed atomic completion", repository.stored.Status)
	}
}

func TestPurgingAndDeletedProjectionsExplicitlyWithdrawTheirScopedSite(t *testing.T) {
	for _, test := range []struct {
		name    string
		current site.Site
		command func(site.Site) Command
		want    site.Lifecycle
	}{
		{
			name:    "purging",
			current: mustSiteAt(t, "site-1", "tenant-a", site.LifecycleQuarantined),
			command: func(current site.Site) Command {
				return BeginPurge{CommandID: "cmd-purge", Actor: Actor{TenantID: current.TenantID()}, TenantID: current.TenantID(), SiteID: current.ID(), ExpectedGeneration: current.Generation()}
			},
			want: site.LifecyclePurging,
		},
		{
			name:    "deleted",
			current: mustSiteAt(t, "site-1", "tenant-a", site.LifecyclePurging),
			command: func(current site.Site) Command {
				return MarkDeleted{CommandID: "cmd-deleted", Actor: Actor{TenantID: current.TenantID()}, TenantID: current.TenantID(), SiteID: current.ID(), ExpectedGeneration: current.Generation()}
			},
			want: site.LifecycleDeleted,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newMemoryRepository(test.current)
			driver := &recordingEffectDriver{events: &repository.events}

			receipt, err := New(repository, driver, fixedClock{}).Handle(context.Background(), test.command(test.current))
			if err != nil {
				t.Fatalf("Handle(%s): %v", test.name, err)
			}
			if receipt.Status != OperationApplied || len(driver.requests) != 1 {
				t.Fatalf("status/requests = %q/%d, want applied/1", receipt.Status, len(driver.requests))
			}
			request := driver.requests[0]
			if !request.Withdraw {
				t.Fatalf("%s projection was not an explicit withdrawal", test.want)
			}
			if request.Scope != scopeFor(test.current) || request.Projection.Lifecycle != test.want {
				t.Fatalf("withdrawal target = %#v/%q, want %#v/%q", request.Scope, request.Projection.Lifecycle, scopeFor(test.current), test.want)
			}
			if request.Projection.Generation != test.current.Generation()+1 || !reflect.DeepEqual(request.Projection.Bindings, test.current.Bindings()) {
				t.Fatalf("withdrawal projection lost exact proposed generation/bindings: %#v", request.Projection)
			}
		})
	}
}

func TestTenantIsolationCoversAuthorizationScopeAndEffectIdentity(t *testing.T) {
	t.Run("cross-tenant actor", func(t *testing.T) {
		current := mustSiteAt(t, "site-1", "tenant-a", site.LifecycleActive)
		repository := newMemoryRepository(current)
		command := SuspendSite{
			CommandID:          "cmd-cross-tenant",
			Actor:              Actor{TenantID: mustTenantID(t, "tenant-b")},
			TenantID:           current.TenantID(),
			SiteID:             current.ID(),
			ExpectedGeneration: current.Generation(),
		}

		receipt, err := New(repository, &recordingEffectDriver{events: &repository.events}, fixedClock{}).Handle(context.Background(), command)
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("error = %v, want ErrUnauthorized", err)
		}
		if !reflect.DeepEqual(receipt, OperationReceipt{}) || len(repository.events) != 0 {
			t.Fatalf("unauthorized command produced receipt/events: %#v/%#v", receipt, repository.events)
		}
	})

	t.Run("same local IDs in different tenants", func(t *testing.T) {
		requests := make([]SiteEffectRequest, 0, 2)
		for _, tenant := range []string{"tenant-a", "tenant-b"} {
			repository := newMemoryRepository(site.Site{})
			driver := &recordingEffectDriver{events: &repository.events}
			_, err := New(repository, driver, fixedClock{}).Handle(context.Background(), createCommand(t, "cmd-create", "site-1", tenant))
			if err != nil {
				t.Fatalf("Handle(create %s): %v", tenant, err)
			}
			requests = append(requests, driver.requests[0])
		}
		if requests[0].Scope.TenantID == requests[1].Scope.TenantID || requests[0].EffectID == requests[1].EffectID {
			t.Fatalf("tenant-scoped requests collided: %#v", requests)
		}
	})
}

func TestRejectedAndAmbiguousEffectsRemainDistinctDurableOutcomes(t *testing.T) {
	for _, test := range []struct {
		name         string
		outcome      EffectOutcome
		effectErr    error
		wantStatus   OperationStatus
		wantTerminal bool
	}{
		{name: "rejected", outcome: EffectRejected, effectErr: errors.New("configuration rejected"), wantStatus: OperationDegraded, wantTerminal: true},
		{name: "ambiguous", outcome: EffectAmbiguous, effectErr: context.DeadlineExceeded, wantStatus: OperationAmbiguous, wantTerminal: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newMemoryRepository(site.Site{})
			driver := &recordingEffectDriver{events: &repository.events, responses: []effectResponse{{outcome: test.outcome, err: test.effectErr}}}
			command := createCommand(t, "cmd-"+test.name, "site-1", "tenant-a")

			receipt, err := New(repository, driver, fixedClock{}).Handle(context.Background(), command)
			if !errors.Is(err, test.effectErr) {
				t.Fatalf("error = %v, want %v", err, test.effectErr)
			}
			if receipt.Status != test.wantStatus || repository.stored.Status != test.wantStatus {
				t.Fatalf("receipt/durable status = %q/%q, want %q", receipt.Status, repository.stored.Status, test.wantStatus)
			}
			if repository.hasCurrent {
				t.Fatalf("%s create committed an unconfirmed proposal: %#v", test.name, repository.current)
			}

			beforeRetry := len(driver.requests)
			if test.wantTerminal {
				retry, retryErr := New(repository, driver, fixedClock{}).Handle(context.Background(), command)
				if retryErr != nil || retry.Status != OperationDegraded {
					t.Fatalf("rejected retry = %#v, %v; want durable degraded receipt", retry, retryErr)
				}
				if len(driver.requests) != beforeRetry {
					t.Fatal("definitive rejection was applied again")
				}
			}
		})
	}
}

func TestCorruptTerminalReceiptIsRejectedBeforeEffectExecution(t *testing.T) {
	for _, test := range []struct {
		name    string
		outcome EffectOutcome
		mutate  func(*OperationReceipt)
	}{
		{
			name:    "request scope",
			outcome: EffectConfirmed,
			mutate: func(receipt *OperationReceipt) {
				receipt.Request.Scope.TenantID = mustTenantID(t, "tenant-b")
			},
		},
		{
			name:    "projection content",
			outcome: EffectConfirmed,
			mutate: func(receipt *OperationReceipt) {
				receipt.Request.Projection.Lifecycle = site.LifecycleDeleted
			},
		},
		{
			name:    "applied effect digest",
			outcome: EffectConfirmed,
			mutate: func(receipt *OperationReceipt) {
				receipt.Effect.ProjectionDigest = "digest-for-another-projection"
			},
		},
		{
			name:    "degraded effect outcome",
			outcome: EffectRejected,
			mutate: func(receipt *OperationReceipt) {
				receipt.Effect.Outcome = EffectAmbiguous
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newMemoryRepository(site.Site{})
			driver := &recordingEffectDriver{events: &repository.events, responses: []effectResponse{{outcome: test.outcome}}}
			if test.outcome == EffectRejected {
				driver.responses[0].err = errors.New("configuration rejected")
			}
			command := createCommand(t, "cmd-corrupt", "site-1", "tenant-a")
			_, _ = New(repository, driver, fixedClock{}).Handle(context.Background(), command)
			test.mutate(&repository.stored)
			beforeRetry := len(driver.requests)

			receipt, err := New(repository, driver, fixedClock{}).Handle(context.Background(), command)
			if !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("error = %v, want ErrInvalidReceipt", err)
			}
			if !reflect.DeepEqual(receipt, OperationReceipt{}) {
				t.Fatalf("receipt = %#v, want zero", receipt)
			}
			if len(driver.requests) != beforeRetry {
				t.Fatal("corrupt durable receipt reached effect driver")
			}
		})
	}
}

func TestMismatchedConfirmedEffectStaysRecoverableAsAmbiguous(t *testing.T) {
	current := mustSiteAt(t, "site-1", "tenant-a", site.LifecycleProvisioning)
	repository := newMemoryRepository(current)
	driver := &recordingEffectDriver{events: &repository.events}
	driver.respond = func(call int, request SiteEffectRequest) (SiteEffectReceipt, error) {
		receipt := confirmedEffect(request)
		if call == 0 {
			receipt.ProjectionDigest = "digest-for-another-projection"
		}
		return receipt, nil
	}
	command := MarkProvisioned{
		CommandID:          "cmd-activate",
		Actor:              Actor{TenantID: current.TenantID()},
		TenantID:           current.TenantID(),
		SiteID:             current.ID(),
		ExpectedGeneration: current.Generation(),
	}
	service := New(repository, driver, fixedClock{})

	first, err := service.Handle(context.Background(), command)
	if !errors.Is(err, ErrInvalidEffectReceipt) {
		t.Fatalf("first error = %v, want ErrInvalidEffectReceipt", err)
	}
	if first.Status != OperationAmbiguous || repository.current.Lifecycle() != site.LifecycleProvisioning {
		t.Fatalf("first status/current = %q/%q, want ambiguous/provisioning", first.Status, repository.current.Lifecycle())
	}
	second, err := service.Handle(context.Background(), command)
	if err != nil {
		t.Fatalf("retry Handle(): %v", err)
	}
	if second.Status != OperationApplied || repository.current.Lifecycle() != site.LifecycleActive {
		t.Fatalf("retry status/current = %q/%q, want applied/active", second.Status, repository.current.Lifecycle())
	}
	if len(driver.requests) != 2 || !reflect.DeepEqual(driver.requests[0], driver.requests[1]) {
		t.Fatalf("recoverable request identity changed: %#v", driver.requests)
	}
}

func createCommand(t *testing.T, commandID, id, tenant string) CreateSite {
	t.Helper()
	return CreateSite{
		CommandID: commandID,
		Actor:     Actor{TenantID: mustTenantID(t, tenant)},
		TenantID:  mustTenantID(t, tenant),
		Site: site.CreateInput{
			ID:              mustSiteID(t, id),
			TenantID:        mustTenantID(t, tenant),
			ProjectID:       mustProjectID(t, "project-1"),
			PrimaryHostname: mustHostname(t, "example.test"),
		},
	}
}

func commandScope(command CreateSite) CommandScope {
	return CommandScope{TenantID: command.TenantID, SiteID: command.Site.ID}
}

func scopeFor(aggregate site.Site) CommandScope {
	return CommandScope{TenantID: aggregate.TenantID(), SiteID: aggregate.ID()}
}

func confirmedEffect(request SiteEffectRequest) SiteEffectReceipt {
	return SiteEffectReceipt{
		EffectID:         request.EffectID,
		Scope:            request.Scope,
		ProjectionDigest: request.ProjectionDigest,
		Generation:       request.Projection.Generation,
		Outcome:          EffectConfirmed,
		ProbeDigest:      "probe/" + request.EffectID,
	}
}

func effectMatchesRequest(receipt SiteEffectReceipt, request SiteEffectRequest) bool {
	return receipt.EffectID == request.EffectID &&
		receipt.Scope == request.Scope &&
		receipt.ProjectionDigest == request.ProjectionDigest &&
		receipt.Generation == request.Projection.Generation
}

func expectedEffectID(scope CommandScope, commandID, commandDigest, projectionDigest string, withdraw bool) string {
	sum := sha256.Sum256([]byte(
		"cyberpanel:site-effect:v2\x00" +
			scope.TenantID.String() + "\x00" +
			scope.SiteID.String() + "\x00" +
			commandID + "\x00" +
			commandDigest + "\x00" +
			projectionDigest + "\x00" +
			strconv.FormatBool(withdraw),
	))
	return "effect-" + hex.EncodeToString(sum[:])
}

func mustHostname(t *testing.T, value string) site.Hostname {
	t.Helper()
	parsed, err := site.ParseHostname(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func mustSiteID(t *testing.T, value string) site.SiteID {
	t.Helper()
	parsed, err := site.NewSiteID(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func mustTenantID(t *testing.T, value string) site.TenantID {
	t.Helper()
	parsed, err := site.NewTenantID(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func mustProjectID(t *testing.T, value string) site.ProjectID {
	t.Helper()
	parsed, err := site.NewProjectID(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func mustSiteAt(t *testing.T, id, tenant string, lifecycle site.Lifecycle) site.Site {
	t.Helper()
	aggregate, err := site.Create(site.CreateInput{
		ID:              mustSiteID(t, id),
		TenantID:        mustTenantID(t, tenant),
		ProjectID:       mustProjectID(t, "project-1"),
		PrimaryHostname: mustHostname(t, "example.test"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for aggregate.Lifecycle() != lifecycle {
		var next site.Lifecycle
		switch aggregate.Lifecycle() {
		case site.LifecycleProvisioning:
			next = site.LifecycleActive
		case site.LifecycleActive:
			if lifecycle == site.LifecycleSuspended {
				next = site.LifecycleSuspended
			} else {
				next = site.LifecycleDeleting
			}
		case site.LifecycleDeleting:
			next = site.LifecycleQuarantined
		case site.LifecycleQuarantined:
			next = site.LifecyclePurging
		case site.LifecyclePurging:
			next = site.LifecycleDeleted
		default:
			t.Fatalf("cannot build lifecycle %q from %q", lifecycle, aggregate.Lifecycle())
		}
		aggregate, err = aggregate.Transition(aggregate.Generation(), next)
		if err != nil {
			t.Fatal(err)
		}
	}
	return aggregate
}

type fixedClock struct{}

func (fixedClock) Now() time.Time {
	return time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
}

type memoryRepository struct {
	current             site.Site
	hasCurrent          bool
	proposal            site.Site
	stored              OperationReceipt
	hasStored           bool
	admission           Admission
	completion          Completion
	completeErr         error
	loadOverride        func(site.TenantID, site.SiteID) (site.Site, error)
	beforeAdmit         func(*memoryRepository, Admission)
	admitReceiptMutator func(Admission, OperationReceipt) OperationReceipt
	events              []string
	loadCalls           int
	admitCalls          int
	completeCalls       int
}

func newMemoryRepository(current site.Site) *memoryRepository {
	return &memoryRepository{current: current, hasCurrent: current.ID().String() != ""}
}

func (repository *memoryRepository) LookupCommand(_ context.Context, _ CommandScope, commandID, digest string) (OperationReceipt, bool, error) {
	repository.events = append(repository.events, "lookup:"+commandID)
	if !repository.hasStored || repository.stored.CommandID != commandID {
		return OperationReceipt{}, false, nil
	}
	if repository.stored.Digest != digest {
		return OperationReceipt{}, false, ErrIdempotencyConflict
	}
	return repository.stored, true, nil
}

func (repository *memoryRepository) Load(_ context.Context, tenant site.TenantID, id site.SiteID) (site.Site, error) {
	repository.loadCalls++
	repository.events = append(repository.events, "load:"+id.String())
	if repository.loadOverride != nil {
		return repository.loadOverride(tenant, id)
	}
	if repository.hasCurrent && repository.current.ID() == id && repository.current.TenantID() == tenant {
		return repository.current, nil
	}
	return site.Site{}, ErrNotFound
}

func (repository *memoryRepository) Admit(_ context.Context, admission Admission) (AdmissionResult, error) {
	repository.admitCalls++
	repository.events = append(repository.events, "admit:"+admission.CommandID)
	if repository.hasStored {
		if repository.stored.CommandID == admission.CommandID && repository.stored.Digest == admission.Digest && repository.stored.Scope == admission.Scope {
			return AdmissionResult{Kind: AdmissionExistingSame, Receipt: repository.stored}, nil
		}
		return AdmissionResult{Kind: AdmissionConflict}, nil
	}
	if repository.beforeAdmit != nil {
		beforeAdmit := repository.beforeAdmit
		repository.beforeAdmit = nil
		beforeAdmit(repository, admission)
	}
	observedGeneration := uint64(0)
	if repository.hasCurrent {
		observedGeneration = repository.current.Generation()
	}
	if observedGeneration != admission.ExpectedGeneration || admission.Proposal.Generation() != admission.ExpectedGeneration+1 {
		return AdmissionResult{Kind: AdmissionConflict}, nil
	}
	repository.admission = admission
	repository.proposal = admission.Proposal
	repository.stored = OperationReceipt{
		CommandID:  admission.CommandID,
		Digest:     admission.Digest,
		Scope:      admission.Scope,
		Status:     OperationAccepted,
		AcceptedAt: admission.AcceptedAt,
		Request:    admission.Request,
	}
	repository.hasStored = true
	resultReceipt := repository.stored
	if repository.admitReceiptMutator != nil {
		resultReceipt = repository.admitReceiptMutator(admission, resultReceipt)
	}
	return AdmissionResult{Kind: AdmissionNew, Receipt: resultReceipt}, nil
}

func (repository *memoryRepository) Complete(_ context.Context, completion Completion) (OperationReceipt, error) {
	repository.completeCalls++
	repository.events = append(repository.events, "complete:"+string(completion.Status))
	repository.completion = completion
	if repository.completeErr != nil {
		return OperationReceipt{}, repository.completeErr
	}
	if !repository.hasStored || completion.CommandID != repository.stored.CommandID || completion.Digest != repository.stored.Digest || completion.Scope != repository.stored.Scope || !reflect.DeepEqual(completion.Request, repository.stored.Request) {
		return OperationReceipt{}, errors.New("completion did not bind to admitted command")
	}
	if completion.Status == OperationApplied {
		if completion.Effect.Outcome != EffectConfirmed || !effectMatchesRequest(completion.Effect, repository.stored.Request) {
			return OperationReceipt{}, errors.New("applied completion did not contain exact confirmed effect")
		}
		repository.current = repository.proposal
		repository.hasCurrent = true
	}
	if completion.Status == OperationDegraded && (completion.Effect.Outcome != EffectRejected || !effectMatchesRequest(completion.Effect, repository.stored.Request)) {
		return OperationReceipt{}, errors.New("degraded completion did not contain exact rejected effect")
	}
	repository.stored.Status = completion.Status
	repository.stored.Effect = completion.Effect
	return repository.stored, nil
}

type effectResponse struct {
	outcome EffectOutcome
	err     error
}

type recordingEffectDriver struct {
	events    *[]string
	requests  []SiteEffectRequest
	responses []effectResponse
	respond   func(int, SiteEffectRequest) (SiteEffectReceipt, error)
	observe   func(SiteEffectRequest)
}

func (driver *recordingEffectDriver) ObserveOrApply(_ context.Context, request SiteEffectRequest) (SiteEffectReceipt, error) {
	call := len(driver.requests)
	driver.requests = append(driver.requests, request)
	*driver.events = append(*driver.events, "effect:"+string(request.Projection.Lifecycle))
	if driver.observe != nil {
		driver.observe(request)
	}
	if driver.respond != nil {
		return driver.respond(call, request)
	}
	receipt := confirmedEffect(request)
	if call < len(driver.responses) {
		receipt.Outcome = driver.responses[call].outcome
		return receipt, driver.responses[call].err
	}
	return receipt, nil
}
