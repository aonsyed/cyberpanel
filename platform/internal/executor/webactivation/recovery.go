package webactivation

import (
	"context"
	"errors"
	"io/fs"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
)

// InitialRecoveryEvidence observes only; re-admission never bypasses the
// activator's immutable candidate, vendor-backup and stopped-service checks.
func (broker *Broker) InitialRecoveryEvidence(ctx context.Context, request Request) (string, error) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.journal.mu.Lock()
	record, found := broker.journal.state.Records[request.EffectID]
	broker.journal.mu.Unlock()
	if !found || !retryableInitial(request, record) {
		return "", ErrOutcomeUnknown
	}
	engine, ok := broker.engine.(activation.BootstrapEngine)
	if !ok {
		return "", ErrOutcomeUnknown
	}
	if err := engine.CheckStopped(ctx); err != nil {
		return "", err
	}
	if _, err := broker.store.Current(ctx); !errors.Is(err, fs.ErrNotExist) {
		return "", ErrOutcomeUnknown
	}
	return rebootcontrol.ExecutionDigest(struct {
		Record                journalRecord
		StoppedWithoutCurrent bool
	}{record, true}), nil
}

func (server *Server) admitActivation(ctx context.Context, request Request, binding rebootcontrol.ExecutionBinding) (rebootcontrol.ExecutionLease, error) {
	lease, err := server.Admission.AdmitExecution(ctx, binding)
	if !errors.Is(err, rebootcontrol.ErrUnproven) || request.Render.Snapshot.Generation != 1 {
		return lease, err
	}
	observer, ok := server.Handler.(interface {
		InitialRecoveryEvidence(context.Context, Request) (string, error)
	})
	recovery, supported := server.Admission.(rebootcontrol.InitialWebActivationRecovery)
	if !ok || !supported {
		return lease, err
	}
	evidence, observeErr := observer.InitialRecoveryEvidence(ctx, request)
	if observeErr != nil {
		return lease, errors.Join(err, observeErr)
	}
	return recovery.RecoverInitialWebActivation(ctx, binding, evidence)
}
