package webmaildata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	maildata "github.com/aonsyed/cyberpanel/platform/internal/mail"
)

func vacationScriptName(scope Scope, reference CanonicalVacationReference) string {
	return vacationScriptPrefix(scope, reference.RuleID) + reference.ProgramDigest
}

func vacationScriptPrefix(scope Scope, id maildata.AutoresponderID) string {
	sum := sha256.Sum256([]byte(scope.TenantID + "\x00" + scope.UserID + "\x00" + scope.MailboxID + "\x00" + string(id)))
	return "cp-vacation-" + hex.EncodeToString(sum[:16]) + "-"
}

// Retire is called only after canonical persistence succeeds. Current and
// immediate rollback programs, and every actual active reference, are retained.
func (runtime VacationRuntime) Retire(ctx context.Context, scope Scope, id maildata.AutoresponderID, retained []CanonicalVacationReference) error {
	if runtime.Service == nil || runtime.Native == nil || scope.UserID != runtime.ActorID || !scope.Valid() {
		return ErrInvalid
	}
	if err := runtime.Service.Authorizer.AuthorizeWebmailData(ctx, AuthorizationRequest{ActorID: runtime.ActorID, Scope: scope, Operation: OperationSieveWrite}); err != nil {
		return ErrUnauthorized
	}
	client, err := runtime.Native.connect(ctx, scope)
	if err != nil {
		return err
	}
	defer client.close()
	scripts, activeName, err := client.listScripts()
	if err != nil {
		return err
	}
	generation, digest, recognized := manageSieveGeneration(activeName)
	if !recognized {
		return ErrConflict
	}
	keep := map[string]bool{activeName: true}
	if generation != 0 {
		program, e := runtime.Service.Repository.GetSieveProgram(ctx, scope, generation)
		if e != nil || program.Digest != digest {
			return ErrConflict
		}
		for _, reference := range program.VacationReferences {
			keep[vacationScriptName(scope, reference)] = true
		}
	}
	for _, reference := range retained {
		if reference.RuleID != id || !validDigest(reference.ProgramDigest) {
			return ErrInvalid
		}
		keep[vacationScriptName(scope, reference)] = true
	}
	prefix := vacationScriptPrefix(scope, id)
	for name := range scripts {
		if !strings.HasPrefix(name, prefix) || !validDigest(strings.TrimPrefix(name, prefix)) || keep[name] {
			continue
		}
		// Fail closed if the native active pointer changed while collecting.
		_, observed, e := client.listScripts()
		if e != nil {
			return e
		}
		if observed != activeName {
			return ErrConflict
		}
		if _, err = client.command(`DELETESCRIPT "` + quoteManageSieve(name) + `"`); err != nil {
			return err
		}
	}
	return nil
}

// VacationRuntime composes the canonical program with the same actor-scoped
// filter rules and the existing active-script CAS. It never replaces filters
// with a standalone vacation script.
type VacationRuntime struct {
	Service *Service
	Native  *LocalManageSieveAdapter
	ActorID string
}

// LockSieveMailbox spans rule validation, activation, rollback and retirement.
// Bounded stripes avoid an unbounded lock registry. Users of the same native
// mailbox share a lock even though their desired-state records are user scoped.
func (service *Service) LockSieveMailbox(scope Scope) func() {
	sum := sha256.Sum256([]byte(scope.TenantID + "\x00" + scope.MailboxID))
	lock := &service.sieveLocks[int(sum[0])%len(service.sieveLocks)]
	lock.Lock()
	return lock.Unlock
}

func (runtime VacationRuntime) ApplyAutoresponder(ctx context.Context, request maildata.AutoresponderSieveRequest) (maildata.AutoresponderSieveReceipt, error) {
	receipt := maildata.AutoresponderSieveReceipt{}
	scope := Scope{TenantID: request.TenantID, UserID: runtime.ActorID, MailboxID: string(request.MailboxID)}
	if runtime.Service == nil || runtime.Native == nil || !scope.Valid() || request.Program.Validate(request.TenantID, request.DomainID, request.MailboxID) != nil {
		return receipt, ErrInvalid
	}
	call := Call{ActorID: runtime.ActorID, OperationID: request.OperationID, Scope: scope}
	if err := runtime.Service.Authorizer.AuthorizeWebmailData(ctx, AuthorizationRequest{ActorID: runtime.ActorID, Scope: scope, Operation: OperationSieveWrite}); err != nil {
		return receipt, ErrUnauthorized
	}
	rules, err := runtime.Service.Repository.ListSieveRules(ctx, scope)
	if err != nil {
		return receipt, err
	}
	active, err := runtime.Service.Repository.ActiveSieve(ctx, scope)
	if err != nil {
		return receipt, err
	}
	expected := map[string]uint64{}
	next := make([]SieveRule, 0, len(rules)+1)
	found := false
	used := map[int]bool{}
	for _, rule := range rules {
		expected[rule.ID] = rule.Revision
		if rule.CanonicalVacation != nil && rule.CanonicalVacation.RuleID == request.Program.RuleID {
			if found || rule.CanonicalVacation.ProgramDigest != request.ExpectedDigest && !(request.Rollback && rule.CanonicalVacation.ProgramDigest == request.Program.Digest) {
				return receipt, maildata.ErrConflict
			}
			found = true
			if request.Program.Mode == maildata.AutoresponderProgramRemove {
				continue
			}
			rule.CanonicalVacation = &CanonicalVacationReference{RuleID: request.Program.RuleID, Generation: request.Program.Generation, ProgramDigest: request.Program.Digest}
			rule.Enabled = request.Program.Enabled
		}
		rule.Revision++
		rule.UpdatedAt = time.Now().UTC()
		used[rule.Order] = true
		next = append(next, rule)
	}
	if !found {
		removed, e := maildata.RemovedAutoresponderSieveProgram(request.TenantID, request.DomainID, request.MailboxID, request.Program.RuleID, 0)
		if e != nil || request.ExpectedDigest != removed.Digest && !request.Rollback {
			return receipt, maildata.ErrConflict
		}
		if request.Program.Mode != maildata.AutoresponderProgramRemove {
			order := 0
			for used[order] {
				order++
			}
			if order >= MaximumSieveRules {
				return receipt, ErrLimit
			}
			sum := sha256.Sum256([]byte(string(request.Program.RuleID)))
			id := "vacation-" + hex.EncodeToString(sum[:16])
			if _, exists := expected[id]; exists {
				return receipt, ErrConflict
			}
			expected[id] = 0
			next = append(next, SieveRule{Scope: scope, ID: id, Name: "Vacation", Enabled: request.Program.Enabled, Order: order, Revision: 1, UpdatedAt: time.Now().UTC(), CanonicalVacation: &CanonicalVacationReference{RuleID: request.Program.RuleID, Generation: request.Program.Generation, ProgramDigest: request.Program.Digest}})
		}
	}
	if request.Program.Mode != maildata.AutoresponderProgramRemove {
		if err = runtime.Native.publishVacation(ctx, scope, request.Program); err != nil {
			return receipt, err
		}
	}
	generation, err := runtime.Service.Repository.NextSieveGeneration(ctx, scope)
	if err != nil {
		return receipt, err
	}
	program, err := CompileSieveProgram(scope, generation, next, time.Now().UTC())
	if err != nil {
		return receipt, err
	}
	desired, err := runtime.Service.activateSieveProgram(ctx, call, program, active)
	if err != nil {
		return receipt, err
	}
	if len(next) > 0 || len(expected) > 0 {
		err = runtime.Service.Repository.ReplaceSieveRulesCAS(ctx, scope, next, expected)
	}
	if err != nil {
		nativeErr := runtime.Service.restoreSieveRuntime(ctx, call, active, desired.Generation, desired.Digest)
		var databaseErr error
		if nativeErr == nil {
			databaseErr = runtime.Service.Repository.ActivateSieveCAS(ctx, active, desired.Digest)
		}
		return receipt, errors.Join(err, nativeErr, databaseErr)
	}
	return maildata.AutoresponderSieveReceipt{OperationID: request.OperationID, TenantID: request.TenantID, DomainID: request.DomainID, RuleID: request.Program.RuleID, MailboxID: request.MailboxID, MailboxGeneration: request.MailboxGeneration, RuleGeneration: request.Program.Generation, Mode: request.Program.Mode, PriorDigest: request.ExpectedDigest, AppliedDigest: request.Program.Digest, ObservedDigest: request.Program.Digest, Confirmed: true, ObservedAt: time.Now().UTC()}, nil
}

func (adapter *LocalManageSieveAdapter) publishVacation(ctx context.Context, scope Scope, program maildata.AutoresponderSieveProgram) error {
	client, err := adapter.connect(ctx, scope)
	if err != nil {
		return err
	}
	defer client.close()
	// CHECKSCRIPT is authoritative for include/vacation-seconds support.
	if err = client.checkScript(program.Script); err != nil {
		return fmt.Errorf("vacation compile: %w", err)
	}
	name := vacationScriptName(scope, CanonicalVacationReference{RuleID: program.RuleID, Generation: program.Generation, ProgramDigest: program.Digest})
	scripts, _, err := client.listScripts()
	if err != nil {
		return fmt.Errorf("vacation list: %w", err)
	}
	if scripts[name] {
		stored, e := client.getScript(name)
		if e != nil {
			return e
		}
		if stored != program.Script {
			return fmt.Errorf("%w: vacation script differs", ErrIntegrity)
		}
		return nil
	}
	return client.putScript(name, program.Script)
}
