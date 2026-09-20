package webactivation

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/enterprise"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/lswsruntime"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
)

const healthPathToken = "activation"

type Broker struct {
	edition webengine.Edition
	renderer native.Renderer
	store activation.Store
	engine activation.Engine
	transport lswsruntime.HTTPRoundTripper
	journal *Journal
	now func() time.Time
	mu sync.Mutex
}

func NewBroker(edition webengine.Edition, store activation.Store, engine activation.Engine, transport lswsruntime.HTTPRoundTripper, journal *Journal) (*Broker, error) {
	if !validEdition(edition) || store == nil || engine == nil || transport == nil || journal == nil { return nil, errors.New("web-engine activation broker dependencies are required") }
	var renderer native.Renderer
	switch edition {
	case webengine.EditionOpenLiteSpeed: renderer = ols.New()
	case webengine.EditionLiteSpeedEnterprise: renderer = enterprise.New()
	}
	return &Broker{edition: edition, renderer: renderer, store: store, engine: engine, transport: transport, journal: journal}, nil
}

func (broker *Broker) Execute(ctx context.Context, request Request) (Response, error) {
	if broker == nil || broker.renderer == nil || broker.store == nil || broker.engine == nil || broker.transport == nil || broker.journal == nil || ctx == nil { return Response{}, ErrInvalidRequest }
	now := time.Now().UTC()
	if broker.now != nil { now = broker.now().UTC() }
	if err := request.Validate(now); err != nil { return Response{}, err }
	broker.mu.Lock()
	defer broker.mu.Unlock()

	record, existing, err := broker.journal.Begin(request, now)
	if err != nil { return Response{}, err }
	restored := existing && retryableRestored(request,record)
	if restored {
		if _,err = broker.restoredRecoveryEvidence(ctx,request,record); err != nil { return Response{},err }
		if err = broker.journal.archiveAttempt(record); err != nil { return Response{},err }
	}
	if existing && !retryableInitial(request, record) && !restored {
		if record.State == "completed" {
			return Response{Version: ProtocolVersion, EffectID: record.EffectID, ExpectedDigest: request.ExpectedDigest, Receipt: record.Receipt, ErrorCode: record.ErrorCode, CompletedAt: record.CompletedAt}, nil
		}
		response := broker.failure(request, activation.Receipt{Status: activation.Ambiguous, CandidateDigest: request.ExpectedDigest}, "outcome_unknown")
		if err = broker.journal.Complete(request, response); err != nil { return Response{}, err }
		return response, nil
	}

	response := broker.apply(ctx, request)
	if err = broker.journal.Complete(request, response); err != nil { return Response{}, err }
	return response, nil
}

// Only first activation can re-enter its stopped-engine/backup guards after an
// interrupted attempt. Never replay ordinary ambiguous replacements or a
// terminal receipt. The request digest binds retries to exactly the same input.
func retryableInitial(request Request, record journalRecord) bool {
	return request.Render.Snapshot.Generation == 1 && record.RequestDigest == request.Digest() &&
		(record.State == "pending" || (record.State == "completed" && record.ErrorCode == "outcome_unknown" &&
			record.Receipt.Status == activation.Ambiguous && record.Receipt.PreviousDigest == ""))
}

func (broker *Broker) apply(ctx context.Context, request Request) Response {
	if request.Render.Desired.Engine.Edition != broker.edition {
		return broker.failure(request, activation.Receipt{Status: activation.Ambiguous, CandidateDigest: request.ExpectedDigest}, "edition_mismatch")
	}
	if err := native.ValidateRequest(request.Render, broker.edition); err != nil {
		return broker.failure(request, activation.Receipt{Status: activation.Ambiguous, CandidateDigest: request.ExpectedDigest}, "invalid_request")
	}
	generation, err := broker.renderer.Render(ctx, request.Render)
	if err != nil {
		return broker.failure(request, activation.Receipt{Status: activation.Ambiguous, CandidateDigest: request.ExpectedDigest}, "invalid_request")
	}
	if generation.ContentDigest != request.ExpectedDigest {
		return broker.failure(request, activation.Receipt{Status: activation.Ambiguous, CandidateDigest: request.ExpectedDigest}, "digest_mismatch")
	}
	probeConfiguration, err := deriveProbeConfiguration(request.Render)
	if err != nil {
		return broker.failure(request, activation.Receipt{Status: activation.Ambiguous, CandidateDigest: request.ExpectedDigest}, "invalid_request")
	}
	probe, err := lswsruntime.NewHTTPProbe(broker.transport, probeConfiguration)
	if err != nil {
		return broker.failure(request, activation.Receipt{Status: activation.Ambiguous, CandidateDigest: request.ExpectedDigest}, "internal_error")
	}
	activator := &activation.Activator{Store: broker.store, Engine: broker.engine, Probe: probe}
	receipt, activationErr := activator.Apply(ctx, generation)
	switch receipt.Status {
	case activation.Applied:
		if activationErr == nil && receipt.Digest == request.ExpectedDigest && receipt.Confirmed {
			return broker.response(request, receipt, "")
		}
		return broker.failure(request, receipt, "outcome_unknown")
	case activation.RolledBack:
		return broker.failure(request, receipt, "activation_rejected")
	default:
		return broker.failure(request, receipt, "outcome_unknown")
	}
}

func (broker *Broker) response(request Request, receipt activation.Receipt, errorCode string) Response {
	now := time.Now().UTC()
	if broker.now != nil { now = broker.now().UTC() }
	return Response{Version: ProtocolVersion, EffectID: request.EffectID, ExpectedDigest: request.ExpectedDigest, Receipt: receipt, ErrorCode: errorCode, CompletedAt: now}
}

func (broker *Broker) failure(request Request, receipt activation.Receipt, errorCode string) Response {
	if receipt.Status != activation.RolledBack && receipt.Status != activation.Ambiguous {
		receipt = activation.Receipt{Status: activation.Ambiguous, CandidateDigest: request.ExpectedDigest}
	}
	if receipt.Status == activation.Ambiguous && receipt.CandidateDigest == "" { receipt.CandidateDigest = request.ExpectedDigest }
	return broker.response(request, receipt, errorCode)
}

func deriveProbeConfiguration(render native.RenderRequest) (lswsruntime.HTTPProbeConfig, error) {
	listeners := append([]webengine.Listener(nil), render.Desired.Engine.Listeners...)
	sort.Slice(listeners, func(left, right int) bool { return listeners[left].Ref < listeners[right].Ref })
	bindings := append([]webengine.WebBindingSpec(nil), render.Desired.Bindings...)
	// Composition retains this binding across generations. A newly added
	// tenant hostname cannot prove the previous generation during rollback.
	sort.Slice(bindings, func(left, right int) bool {
		if bindings[left].Ref == "binding/system-default" { return bindings[right].Ref != "binding/system-default" }
		if bindings[right].Ref == "binding/system-default" { return false }
		return bindings[left].Ref < bindings[right].Ref
	})
	for _, listener := range listeners {
		if listener.TLSMode != webengine.TLSModeClear || !hasLoopbackReachableIPv4(listener.Addresses) { continue }
		for _, binding := range bindings {
			if !containsListener(binding.ListenerRefs, listener.Ref) || len(binding.Hostnames) == 0 { continue }
			hostnames := append([]webengine.Hostname(nil), binding.Hostnames...)
			sort.Slice(hostnames, func(left, right int) bool { return hostnames[left].String() < hostnames[right].String() })
			return lswsruntime.HTTPProbeConfig{Port: listener.Port, Hostname: hostnames[0], PathToken: healthPathToken}, nil
		}
	}
	return lswsruntime.HTTPProbeConfig{}, errors.New("desired state has no loopback-reachable cleartext health listener")
}

func hasLoopbackReachableIPv4(addresses []string) bool {
	for _, address := range addresses {
		parsed, err := netip.ParseAddr(address)
		if err == nil && parsed.Is4() && (parsed.IsUnspecified() || parsed.IsLoopback()) { return true }
	}
	return false
}

func containsListener(values []webengine.ResourceRef, wanted webengine.ResourceRef) bool {
	for _, value := range values { if value == wanted { return true } }
	return false
}
