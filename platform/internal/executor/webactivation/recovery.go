package webactivation

import (
	"context"
	"errors"
	"io/fs"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/lswsruntime"
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
	if !errors.Is(err, rebootcontrol.ErrUnproven) {
		return lease, err
	}
	if request.Render.Snapshot.Generation != 1 {
		observer, ok := server.Handler.(interface {
			RestoredRecoveryEvidence(context.Context, Request) (string, error)
		})
		recovery, supported := server.Admission.(rebootcontrol.RestoredWebActivationRecovery)
		if !ok || !supported {
			return lease, err
		}
		proof, observeErr := observer.RestoredRecoveryEvidence(ctx, request)
		if observeErr != nil {
			return lease, errors.Join(err, observeErr)
		}
		return recovery.RecoverRestoredWebActivation(ctx, binding, proof)
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

func retryableRestored(request Request, record journalRecord) bool {
	return request.Render.Snapshot.Generation > 1 && record.RequestDigest == request.Digest() && record.State == "completed" && record.ErrorCode == "outcome_unknown" && record.Receipt.Status == activation.Ambiguous && record.Receipt.CandidateDigest == request.ExpectedDigest && validDigest(record.Receipt.PreviousDigest) && record.Receipt.RollbackRestored && !record.Receipt.Confirmed
}

func (broker *Broker) RestoredRecoveryEvidence(ctx context.Context, request Request) (string, error) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.journal.mu.Lock()
	record, found := broker.journal.state.Records[request.EffectID]
	broker.journal.mu.Unlock()
	if !found {
		return "", ErrOutcomeUnknown
	}
	return broker.restoredRecoveryEvidence(ctx, request, record)
}

func (broker *Broker) restoredRecoveryEvidence(ctx context.Context, request Request, record journalRecord) (string, error) {
	if !retryableRestored(request, record) {
		return "", ErrOutcomeUnknown
	}
	current, err := broker.store.Current(ctx)
	if err != nil {
		return "", err
	}
	if !current.Confirmed || current.Status != activation.Applied || current.Edition != broker.edition || current.Digest != record.Receipt.PreviousDigest {
		return "", ErrOutcomeUnknown
	}
	config, err := deriveProbeConfiguration(request.Render)
	if err != nil {
		return "", err
	}
	probe, err := lswsruntime.NewHTTPProbe(broker.transport, config)
	if err != nil {
		return "", err
	}
	if err = probe.Check(ctx, current); err != nil {
		return "", err
	}
	return rebootcontrol.ExecutionDigest(struct {
		Record  journalRecord
		Current activation.Receipt
	}{record, current}), nil
}
