package containerproxy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

var (
	ErrTenantRouteInvalid   = errors.New("tenant workload route is invalid")
	ErrTenantRouteNotFound  = errors.New("tenant workload route does not exist")
	ErrTenantRouteConflict  = errors.New("tenant workload route conflicts with existing authority")
	ErrTenantRouteClosed    = errors.New("tenant workload route is closed")
	ErrTenantRouteAmbiguous = errors.New("tenant workload route outcome is ambiguous")
	// The rendered proxy configuration is node-global, so all authority
	// instances in the broker process share one mutation critical section.
	tenantWorkloadRouteOperations sync.Mutex
)

type TenantWorkloadRouteState string

const (
	TenantWorkloadRouteReserved   TenantWorkloadRouteState = "reserved"
	TenantWorkloadRouteActivating TenantWorkloadRouteState = "activating"
	TenantWorkloadRouteAmbiguous  TenantWorkloadRouteState = "ambiguous"
	TenantWorkloadRouteActive     TenantWorkloadRouteState = "active"
	TenantWorkloadRouteDiscarded  TenantWorkloadRouteState = "discarded"
)

// TenantWorkloadRouteSpec is the complete immutable ownership and runtime
// binding. Reserve normalizes Hostname and rejects any non-loopback endpoint;
// neither later activation nor observation accepts replacement values.
type TenantWorkloadRouteSpec struct {
	TenantID                  containers.ID             `json:"tenant_id"`
	SiteID                    containers.ID             `json:"site_id"`
	DomainID                  containers.ID             `json:"domain_id"`
	Hostname                  string                    `json:"hostname"`
	ListenerRef               webengine.ResourceRef     `json:"listener_ref"`
	WorkloadID                containers.ID             `json:"workload_id"`
	RecipeDigest              string                    `json:"recipe_digest"`
	ImageDigest               string                    `json:"image_digest"`
	Generation                uint64                    `json:"generation"`
	TargetEndpoint            netip.AddrPort            `json:"target_endpoint"`
	ActivationAuthorityDigest string                    `json:"activation_authority_digest"`
	SiteHandoff               TenantWorkloadSiteHandoff `json:"site_handoff"`
}

// TenantWorkloadSiteHandoff fixes the exact non-serving site projection that
// owns the hostname before it is atomically replaced by the workload route.
// It is not a generic route takeover token: all four values are compared with
// the current tenant/site catalog row and node generation.
type TenantWorkloadSiteHandoff struct {
	ProjectionGeneration    uint64 `json:"projection_generation"`
	ProjectionDigest        string `json:"projection_digest"`
	ConfigurationGeneration uint64 `json:"configuration_generation"`
	ConfigurationDigest     string `json:"configuration_digest"`
}

type TenantWorkloadRouteReference struct {
	TenantID           containers.ID `json:"tenant_id"`
	ReservationID      string        `json:"reservation_id"`
	ExpectedGeneration uint64        `json:"expected_generation"`
	ReservationDigest  string        `json:"reservation_digest"`
}

type TenantWorkloadRouteActivation struct {
	TenantWorkloadRouteReference
	ActivationAuthorityDigest string `json:"activation_authority_digest"`
}

type TenantWorkloadRouteReceipt struct {
	ReservationID             string                   `json:"reservation_id"`
	ReservationDigest         string                   `json:"reservation_digest"`
	TenantID                  containers.ID            `json:"tenant_id"`
	Generation                uint64                   `json:"generation"`
	State                     TenantWorkloadRouteState `json:"state"`
	TargetEndpoint            netip.AddrPort           `json:"target_endpoint"`
	ActivationAuthorityDigest string                   `json:"activation_authority_digest"`
	ConfigurationGeneration   uint64                   `json:"configuration_generation"`
	ConfigurationDigest       string                   `json:"configuration_digest,omitempty"`
	ObservationDigest         string                   `json:"observation_digest,omitempty"`
	Bound                     bool                     `json:"bound"`
	Reason                    string                   `json:"reason"`
	ObservedAt                time.Time                `json:"observed_at"`
	EvidenceDigest            string                   `json:"evidence_digest"`
}

type TenantWorkloadRouteReservation struct {
	ID                   string                     `json:"id"`
	Digest               string                     `json:"digest"`
	Spec                 TenantWorkloadRouteSpec    `json:"spec"`
	RouteRef             webengine.ResourceRef      `json:"route_ref"`
	ActivationEffectID   string                     `json:"activation_effect_id"`
	State                TenantWorkloadRouteState   `json:"state"`
	ActivationGeneration uint64                     `json:"activation_generation"`
	CandidateDigest      string                     `json:"candidate_digest,omitempty"`
	ObservationDigest    string                     `json:"observation_digest,omitempty"`
	Receipt              TenantWorkloadRouteReceipt `json:"receipt"`
	ActivatedAt          *time.Time                 `json:"activated_at,omitempty"`
	CreatedAt            time.Time                  `json:"created_at"`
	UpdatedAt            time.Time                  `json:"updated_at"`
	DiscardedAt          *time.Time                 `json:"discarded_at,omitempty"`
}

type TenantWorkloadRouteExpectation struct {
	ReservationID           string                `json:"reservation_id"`
	ReservationDigest       string                `json:"reservation_digest"`
	TenantID                containers.ID         `json:"tenant_id"`
	SiteID                  containers.ID         `json:"site_id"`
	DomainID                containers.ID         `json:"domain_id"`
	Hostname                string                `json:"hostname"`
	ListenerRef             webengine.ResourceRef `json:"listener_ref"`
	WorkloadID              containers.ID         `json:"workload_id"`
	TargetEndpoint          netip.AddrPort        `json:"target_endpoint"`
	ConfigurationGeneration uint64                `json:"configuration_generation"`
	ConfigurationDigest     string                `json:"configuration_digest,omitempty"`
}

type TenantWorkloadRouteObservation struct {
	TenantWorkloadRouteExpectation
	Occupied       bool      `json:"occupied"`
	Bound          bool      `json:"bound"`
	EvidenceDigest string    `json:"evidence_digest"`
	ObservedAt     time.Time `json:"observed_at"`
}

// TenantWorkloadRouteAuthorityVerifier must revalidate the currently live
// source fence or equivalent activation authority before reservation and again
// before every activation/finalization. A stored digest alone is never enough.
type TenantWorkloadRouteAuthorityVerifier interface {
	VerifyCurrentTenantWorkloadRouteAuthority(context.Context, TenantWorkloadRouteReservation) error
}

// TenantWorkloadRouteObserver is a protected live proxy probe. Occupied means
// some binding owns the hostname/listener. When a configuration generation is
// expected, Bound additionally proves that exact endpoint, generation, and
// digest; absence checks must leave Bound false.
type TenantWorkloadRouteObserver interface {
	ObserveTenantWorkloadRoute(context.Context, TenantWorkloadRouteExpectation) (TenantWorkloadRouteObservation, error)
}

// TenantWorkloadRouteBroker is the narrow interface consumed by a staged
// container target. It exposes no renderer text, filesystem path, or arbitrary
// proxy directive.
type TenantWorkloadRouteBroker interface {
	ReserveTenantWorkloadRoute(context.Context, TenantWorkloadRouteSpec) (TenantWorkloadRouteReservation, error)
	ActivateTenantWorkloadRoute(context.Context, TenantWorkloadRouteActivation) (TenantWorkloadRouteReservation, error)
	ObserveTenantWorkloadRoute(context.Context, TenantWorkloadRouteReference) (TenantWorkloadRouteReservation, error)
	DiscardTenantWorkloadRoute(context.Context, TenantWorkloadRouteReference) (TenantWorkloadRouteReservation, error)
}

type TenantRouteAuthority struct {
	database  *sql.DB
	catalog   *catalog.SQLCatalog
	activator VerifiedActivator
	verifier  TenantWorkloadRouteAuthorityVerifier
	observer  TenantWorkloadRouteObserver
	renderers map[webengine.Edition]native.Renderer
	clock     func() time.Time
}

func NewTenantRouteAuthority(database *sql.DB, catalogValue *catalog.SQLCatalog, activator VerifiedActivator, verifier TenantWorkloadRouteAuthorityVerifier, observer TenantWorkloadRouteObserver, renderers ...native.Renderer) (*TenantRouteAuthority, error) {
	if database == nil || catalogValue == nil || nilAuthority(activator) || nilAuthority(verifier) || nilAuthority(observer) {
		return nil, ErrTenantRouteInvalid
	}
	byEdition := make(map[webengine.Edition]native.Renderer, len(renderers))
	for _, renderer := range renderers {
		if nilAuthority(renderer) {
			return nil, ErrTenantRouteInvalid
		}
		byEdition[renderer.Edition()] = renderer
	}
	if len(byEdition) != 2 || byEdition[webengine.EditionOpenLiteSpeed] == nil || byEdition[webengine.EditionLiteSpeedEnterprise] == nil {
		return nil, ErrTenantRouteInvalid
	}
	return &TenantRouteAuthority{database: database, catalog: catalogValue, activator: activator, verifier: verifier, observer: observer, renderers: byEdition, clock: time.Now}, nil
}

func (authority *TenantRouteAuthority) ReserveTenantWorkloadRoute(ctx context.Context, supplied TenantWorkloadRouteSpec) (TenantWorkloadRouteReservation, error) {
	if authority == nil || authority.database == nil || authority.catalog == nil || ctx == nil {
		return TenantWorkloadRouteReservation{}, ErrTenantRouteInvalid
	}
	spec, err := normalizeTenantWorkloadRouteSpec(supplied)
	if err != nil {
		return TenantWorkloadRouteReservation{}, err
	}
	reservation := newTenantWorkloadRouteReservation(spec)
	tenantWorkloadRouteOperations.Lock()
	defer tenantWorkloadRouteOperations.Unlock()
	if existing, loadErr := authority.load(ctx, spec.TenantID, reservation.ID); loadErr == nil {
		if existing.Digest != reservation.Digest || existing.Spec != spec {
			return TenantWorkloadRouteReservation{}, ErrTenantRouteConflict
		}
		return existing, nil
	} else if !errors.Is(loadErr, ErrTenantRouteNotFound) {
		return TenantWorkloadRouteReservation{}, loadErr
	}
	now := authority.now()
	reservation.State = TenantWorkloadRouteReserved
	reservation.CreatedAt = now
	reservation.UpdatedAt = now
	reservation.Receipt = tenantWorkloadRouteReceipt(reservation, TenantWorkloadRouteReserved, 0, "", "", false, "reservation_requested", now)
	if err = validateStoredTenantWorkloadRoute(reservation); err != nil {
		return TenantWorkloadRouteReservation{}, err
	}
	if err = authority.verifier.VerifyCurrentTenantWorkloadRouteAuthority(ctx, reservation); err != nil {
		return TenantWorkloadRouteReservation{}, err
	}
	observation, err := authority.observe(ctx, reservation, 0, "")
	if err != nil {
		return TenantWorkloadRouteReservation{}, err
	}
	if observation.Occupied || observation.Bound {
		return TenantWorkloadRouteReservation{}, ErrTenantRouteConflict
	}
	reservation.ObservationDigest = observation.EvidenceDigest
	reservation.Receipt = tenantWorkloadRouteReceipt(reservation, TenantWorkloadRouteReserved, 0, "", observation.EvidenceDigest, false, "reserved", now)
	if err = validateStoredTenantWorkloadRoute(reservation); err != nil {
		return TenantWorkloadRouteReservation{}, err
	}
	receiptJSON, err := json.Marshal(reservation.Receipt)
	if err != nil {
		return TenantWorkloadRouteReservation{}, err
	}
	tx, err := authority.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return TenantWorkloadRouteReservation{}, err
	}
	defer tx.Rollback()
	if err = ensureTenantWorkloadRouteAvailable(ctx, tx, reservation); err != nil {
		_ = tx.Rollback()
		if existing, retryErr := authority.load(ctx, spec.TenantID, reservation.ID); retryErr == nil && existing.Digest == reservation.Digest && existing.Spec == spec {
			return existing, nil
		}
		return TenantWorkloadRouteReservation{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webengine_tenant_workload_routes_v1(reservation_id,tenant_id,site_id,domain_id,hostname,listener_ref,workload_id,recipe_digest,image_digest,generation,target_endpoint,activation_authority_digest,site_projection_generation,site_projection_digest,site_configuration_generation,site_configuration_digest,reservation_digest,route_ref,activation_effect_id,state,activation_generation,candidate_digest,observation_digest,receipt_json,activated_at,created_at,updated_at,discarded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'reserved',0,'',?,?,NULL,?,?,NULL)`,
		reservation.ID, spec.TenantID, spec.SiteID, spec.DomainID, spec.Hostname, spec.ListenerRef, spec.WorkloadID, spec.RecipeDigest, spec.ImageDigest, spec.Generation, spec.TargetEndpoint.String(), spec.ActivationAuthorityDigest, spec.SiteHandoff.ProjectionGeneration, spec.SiteHandoff.ProjectionDigest, spec.SiteHandoff.ConfigurationGeneration, spec.SiteHandoff.ConfigurationDigest, reservation.Digest, reservation.RouteRef, reservation.ActivationEffectID, observation.EvidenceDigest, receiptJSON, now, now)
	if err != nil {
		_ = tx.Rollback()
		if existing, retryErr := authority.load(ctx, spec.TenantID, reservation.ID); retryErr == nil && existing.Digest == reservation.Digest && existing.Spec == spec {
			return existing, nil
		}
		return TenantWorkloadRouteReservation{}, errors.Join(ErrTenantRouteConflict, err)
	}
	if err = tx.Commit(); err != nil {
		_ = tx.Rollback()
		if existing, retryErr := authority.load(ctx, spec.TenantID, reservation.ID); retryErr == nil && existing.Digest == reservation.Digest && existing.Spec == spec {
			return existing, nil
		}
		return TenantWorkloadRouteReservation{}, err
	}
	return authority.load(ctx, spec.TenantID, reservation.ID)
}

func (authority *TenantRouteAuthority) ActivateTenantWorkloadRoute(ctx context.Context, request TenantWorkloadRouteActivation) (TenantWorkloadRouteReservation, error) {
	if authority == nil || ctx == nil || validateTenantWorkloadRouteReference(request.TenantWorkloadRouteReference) != nil || !validRouteDigest(request.ActivationAuthorityDigest) {
		return TenantWorkloadRouteReservation{}, ErrTenantRouteInvalid
	}
	tenantWorkloadRouteOperations.Lock()
	defer tenantWorkloadRouteOperations.Unlock()
	current, err := authority.loadReference(ctx, request.TenantWorkloadRouteReference)
	if err != nil {
		return current, err
	}
	if request.ActivationAuthorityDigest != current.Spec.ActivationAuthorityDigest {
		return TenantWorkloadRouteReservation{}, ErrTenantRouteNotFound
	}
	if current.State == TenantWorkloadRouteDiscarded {
		return current, ErrTenantRouteClosed
	}
	if current.State == TenantWorkloadRouteActive || current.ActivatedAt != nil || current.State == TenantWorkloadRouteAmbiguous {
		return authority.observeLocked(ctx, current)
	}
	if err = authority.verifier.VerifyCurrentTenantWorkloadRouteAuthority(ctx, current); err != nil {
		return current, err
	}
	if current.State == TenantWorkloadRouteReserved {
		receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteActivating, 0, "", current.ObservationDigest, false, "activation_started", authority.now())
		current, err = authority.transition(ctx, current, TenantWorkloadRouteActivating, 0, "", current.ObservationDigest, false, false, receipt)
		if err != nil {
			return current, err
		}
	}
	if current.State != TenantWorkloadRouteActivating {
		return current, ErrTenantRouteAmbiguous
	}
	prepared, renderRequest, candidateDigest, err := authority.prepare(ctx, current)
	if err != nil {
		if prepared.Token != "" {
			return current, errors.Join(err, authority.rejectPending(ctx, current))
		}
		return current, err
	}
	if current.CandidateDigest != "" && (current.CandidateDigest != candidateDigest || current.ActivationGeneration != prepared.Plan.SnapshotGeneration) {
		return current, ErrTenantRouteConflict
	}
	if current.CandidateDigest == "" {
		receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteActivating, prepared.Plan.SnapshotGeneration, candidateDigest, current.ObservationDigest, false, "candidate_recorded", authority.now())
		current, err = authority.transition(ctx, current, TenantWorkloadRouteActivating, prepared.Plan.SnapshotGeneration, candidateDigest, current.ObservationDigest, false, false, receipt)
		if err != nil {
			return current, err
		}
	}
	observation, err := authority.observe(ctx, current, current.ActivationGeneration, candidateDigest)
	if err != nil {
		return current, err
	}
	if observation.Occupied {
		if !observation.Bound {
			receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteAmbiguous, current.ActivationGeneration, candidateDigest, observation.EvidenceDigest, false, "binding_conflict", authority.now())
			current, err = authority.transition(ctx, current, TenantWorkloadRouteAmbiguous, current.ActivationGeneration, candidateDigest, observation.EvidenceDigest, false, false, receipt)
			return current, errors.Join(ErrTenantRouteConflict, err)
		}
		receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteAmbiguous, current.ActivationGeneration, candidateDigest, observation.EvidenceDigest, true, "candidate_found_live", authority.now())
		current, err = authority.transition(ctx, current, TenantWorkloadRouteAmbiguous, current.ActivationGeneration, candidateDigest, observation.EvidenceDigest, true, false, receipt)
		if err != nil {
			return current, err
		}
		if err = authority.verifier.VerifyCurrentTenantWorkloadRouteAuthority(ctx, current); err != nil {
			return current, errors.Join(ErrTenantRouteAmbiguous, err)
		}
		if err = authority.catalog.FinalizeProxyRoute(ctx, prepared, candidateDigest); err != nil {
			return current, errors.Join(ErrTenantRouteAmbiguous, err)
		}
		return authority.observeLocked(ctx, current)
	}
	if err = authority.verifier.VerifyCurrentTenantWorkloadRouteAuthority(ctx, current); err != nil {
		return current, err
	}
	activationReceipt, activationErr := authority.activator.ApplyVerified(ctx, renderRequest, candidateDigest)
	applied := activationReceipt.Status == activation.Applied && activationReceipt.Confirmed && activationReceipt.Digest == candidateDigest
	reason := "activation_outcome_unknown"
	if activationReceipt.Status == activation.RolledBack {
		reason = "activation_rolled_back"
	}
	receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteAmbiguous, current.ActivationGeneration, candidateDigest, "", false, reason, authority.now())
	current, persistErr := authority.transition(ctx, current, TenantWorkloadRouteAmbiguous, current.ActivationGeneration, candidateDigest, "", applied, false, receipt)
	if persistErr != nil {
		return current, errors.Join(ErrTenantRouteAmbiguous, activationErr, persistErr)
	}
	if !applied || activationErr != nil {
		return current, errors.Join(ErrTenantRouteAmbiguous, activationErr)
	}
	if err = authority.verifier.VerifyCurrentTenantWorkloadRouteAuthority(ctx, current); err != nil {
		return current, errors.Join(ErrTenantRouteAmbiguous, err)
	}
	if err = authority.catalog.FinalizeProxyRoute(ctx, prepared, candidateDigest); err != nil {
		return current, errors.Join(ErrTenantRouteAmbiguous, err)
	}
	return authority.observeLocked(ctx, current)
}

func (authority *TenantRouteAuthority) ObserveTenantWorkloadRoute(ctx context.Context, reference TenantWorkloadRouteReference) (TenantWorkloadRouteReservation, error) {
	if authority == nil || ctx == nil || validateTenantWorkloadRouteReference(reference) != nil {
		return TenantWorkloadRouteReservation{}, ErrTenantRouteInvalid
	}
	tenantWorkloadRouteOperations.Lock()
	defer tenantWorkloadRouteOperations.Unlock()
	current, err := authority.loadReference(ctx, reference)
	if err != nil {
		return current, err
	}
	return authority.observeLocked(ctx, current)
}

func (authority *TenantRouteAuthority) DiscardTenantWorkloadRoute(ctx context.Context, reference TenantWorkloadRouteReference) (TenantWorkloadRouteReservation, error) {
	if authority == nil || ctx == nil || validateTenantWorkloadRouteReference(reference) != nil {
		return TenantWorkloadRouteReservation{}, ErrTenantRouteInvalid
	}
	tenantWorkloadRouteOperations.Lock()
	defer tenantWorkloadRouteOperations.Unlock()
	current, err := authority.loadReference(ctx, reference)
	if err != nil {
		return current, err
	}
	if current.State == TenantWorkloadRouteDiscarded {
		return current, nil
	}
	if current.State == TenantWorkloadRouteActive || current.ActivatedAt != nil {
		return current, ErrTenantRouteClosed
	}
	observation, err := authority.observe(ctx, current, current.ActivationGeneration, current.CandidateDigest)
	if err != nil {
		return current, err
	}
	if observation.Occupied || observation.Bound {
		receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteAmbiguous, current.ActivationGeneration, current.CandidateDigest, observation.EvidenceDigest, observation.Bound, "discard_binding_present", authority.now())
		current, err = authority.transition(ctx, current, TenantWorkloadRouteAmbiguous, current.ActivationGeneration, current.CandidateDigest, observation.EvidenceDigest, observation.Bound, false, receipt)
		return current, errors.Join(ErrTenantRouteClosed, err)
	}
	if _, stateErr := authority.catalog.ProxyRouteState(ctx, current.RouteRef); stateErr == nil {
		return current, ErrTenantRouteClosed
	} else if !errors.Is(stateErr, catalog.ErrChangeMissing) {
		return current, stateErr
	}
	if err = authority.rejectPending(ctx, current); err != nil {
		return current, err
	}
	receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteDiscarded, current.ActivationGeneration, current.CandidateDigest, observation.EvidenceDigest, false, "discarded_before_publication", authority.now())
	return authority.transition(ctx, current, TenantWorkloadRouteDiscarded, current.ActivationGeneration, current.CandidateDigest, observation.EvidenceDigest, false, true, receipt)
}

func (authority *TenantRouteAuthority) observeLocked(ctx context.Context, current TenantWorkloadRouteReservation) (TenantWorkloadRouteReservation, error) {
	if current.State == TenantWorkloadRouteDiscarded {
		return current, ErrTenantRouteClosed
	}
	configurationGeneration := current.ActivationGeneration
	configurationDigest := current.CandidateDigest
	recorded := false
	proxyState, stateErr := authority.catalog.ProxyRouteState(ctx, current.RouteRef)
	if stateErr == nil {
		if !sameTenantWorkloadProxyRoute(proxyState.Route, current) {
			return current, ErrTenantRouteConflict
		}
		recorded = true
		configurationGeneration = proxyState.SnapshotGeneration
		configurationDigest = proxyState.AppliedDigest
	} else if !errors.Is(stateErr, catalog.ErrChangeMissing) {
		return current, stateErr
	}
	observation, err := authority.observe(ctx, current, configurationGeneration, configurationDigest)
	if err != nil {
		if current.State == TenantWorkloadRouteActive || current.ActivatedAt != nil {
			receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteAmbiguous, configurationGeneration, configurationDigest, "", false, "live_observation_failed", authority.now())
			var transitionErr error
			current, transitionErr = authority.transition(ctx, current, TenantWorkloadRouteAmbiguous, configurationGeneration, configurationDigest, "", true, false, receipt)
			return current, errors.Join(err, transitionErr)
		}
		return current, err
	}
	if observation.Occupied && observation.Bound {
		if !recorded {
			if current.CandidateDigest == "" || current.ActivationGeneration == 0 {
				receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteAmbiguous, configurationGeneration, configurationDigest, observation.EvidenceDigest, true, "unowned_live_binding", authority.now())
				current, err = authority.transition(ctx, current, TenantWorkloadRouteAmbiguous, configurationGeneration, configurationDigest, observation.EvidenceDigest, true, false, receipt)
				return current, errors.Join(ErrTenantRouteConflict, err)
			}
			if err = authority.verifier.VerifyCurrentTenantWorkloadRouteAuthority(ctx, current); err != nil {
				return current, errors.Join(ErrTenantRouteAmbiguous, err)
			}
			prepared, pendingErr := authority.catalog.PendingProxyRoute(ctx, current.ActivationEffectID, current.ActivationGeneration)
			if pendingErr != nil || !sameTenantWorkloadProxyRoute(prepared.Route, current) {
				return current, errors.Join(ErrTenantRouteAmbiguous, pendingErr)
			}
			if err = authority.catalog.FinalizeProxyRoute(ctx, prepared, current.CandidateDigest); err != nil {
				return current, errors.Join(ErrTenantRouteAmbiguous, err)
			}
			proxyState, err = authority.catalog.ProxyRouteState(ctx, current.RouteRef)
			if err != nil || !sameTenantWorkloadProxyRoute(proxyState.Route, current) {
				return current, errors.Join(ErrTenantRouteAmbiguous, err)
			}
			configurationGeneration = proxyState.SnapshotGeneration
			configurationDigest = proxyState.AppliedDigest
			observation, err = authority.observe(ctx, current, configurationGeneration, configurationDigest)
			if err != nil || !observation.Occupied || !observation.Bound {
				return current, errors.Join(ErrTenantRouteAmbiguous, err)
			}
		}
		if current.State != TenantWorkloadRouteActive {
			if err = authority.verifier.VerifyCurrentTenantWorkloadRouteAuthority(ctx, current); err != nil {
				return current, errors.Join(ErrTenantRouteAmbiguous, err)
			}
		}
		receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteActive, configurationGeneration, configurationDigest, observation.EvidenceDigest, true, "live_binding_verified", authority.now())
		return authority.transition(ctx, current, TenantWorkloadRouteActive, configurationGeneration, configurationDigest, observation.EvidenceDigest, true, false, receipt)
	}
	if observation.Occupied {
		receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteAmbiguous, configurationGeneration, configurationDigest, observation.EvidenceDigest, false, "different_binding_present", authority.now())
		current, err = authority.transition(ctx, current, TenantWorkloadRouteAmbiguous, configurationGeneration, configurationDigest, observation.EvidenceDigest, current.ActivatedAt != nil, false, receipt)
		return current, errors.Join(ErrTenantRouteConflict, err)
	}
	if recorded || current.ActivatedAt != nil {
		receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteAmbiguous, configurationGeneration, configurationDigest, observation.EvidenceDigest, false, "live_binding_missing", authority.now())
		current, err = authority.transition(ctx, current, TenantWorkloadRouteAmbiguous, configurationGeneration, configurationDigest, observation.EvidenceDigest, true, false, receipt)
		return current, errors.Join(ErrTenantRouteAmbiguous, err)
	}
	if current.State == TenantWorkloadRouteReserved {
		receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteReserved, 0, "", observation.EvidenceDigest, false, "reserved_not_public", authority.now())
		return authority.transition(ctx, current, TenantWorkloadRouteReserved, 0, "", observation.EvidenceDigest, false, false, receipt)
	}
	receipt := tenantWorkloadRouteReceipt(current, TenantWorkloadRouteAmbiguous, configurationGeneration, configurationDigest, observation.EvidenceDigest, false, "candidate_not_live", authority.now())
	current, err = authority.transition(ctx, current, TenantWorkloadRouteAmbiguous, configurationGeneration, configurationDigest, observation.EvidenceDigest, false, false, receipt)
	return current, errors.Join(ErrTenantRouteAmbiguous, err)
}

func (authority *TenantRouteAuthority) prepare(ctx context.Context, reservation TenantWorkloadRouteReservation) (catalog.PreparedProxyRoute, native.RenderRequest, string, error) {
	route := tenantWorkloadProxyRoute(reservation)
	prepared, err := authority.catalog.PrepareProxyRoute(ctx, reservation.ActivationEffectID, route, false)
	if err != nil {
		return catalog.PreparedProxyRoute{}, native.RenderRequest{}, "", err
	}
	composed, err := composer.Compose(prepared.Plan)
	if err != nil {
		return prepared, native.RenderRequest{}, "", err
	}
	renderer := authority.renderers[composed.Desired.Engine.Edition]
	if renderer == nil {
		return prepared, native.RenderRequest{}, "", ErrTenantRouteInvalid
	}
	request := native.RenderRequest{Desired: composed.Desired, Snapshot: composed.Snapshot}
	rendered, err := renderer.Render(ctx, request)
	if err != nil || !validRouteDigest(rendered.ContentDigest) {
		return prepared, native.RenderRequest{}, "", errors.Join(ErrTenantRouteInvalid, err)
	}
	return prepared, request, rendered.ContentDigest, nil
}

func (authority *TenantRouteAuthority) rejectPending(ctx context.Context, reservation TenantWorkloadRouteReservation) error {
	var token, status string
	var planJSON, proposal []byte
	err := authority.database.QueryRowContext(ctx, `SELECT change_token,status,plan_json,proposed_json FROM webengine_proxy_changes WHERE effect_id=?`, reservation.ActivationEffectID).Scan(&token, &status, &planJSON, &proposal)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var route composer.ProxyRouteInput
	var plan composer.Plan
	if json.Unmarshal(proposal, &route) != nil || json.Unmarshal(planJSON, &plan) != nil || plan.SnapshotGeneration == 0 || !sameTenantWorkloadProxyRoute(route, reservation) {
		return ErrTenantRouteConflict
	}
	switch status {
	case "rejected":
		return nil
	case "pending":
		prepared := catalog.PreparedProxyRoute{Token: token, EffectID: reservation.ActivationEffectID, Route: route, Plan: plan}
		return authority.catalog.RejectProxyRoute(ctx, prepared)
	default:
		return ErrTenantRouteClosed
	}
}

func (authority *TenantRouteAuthority) observe(ctx context.Context, reservation TenantWorkloadRouteReservation, configurationGeneration uint64, configurationDigest string) (TenantWorkloadRouteObservation, error) {
	expectation := TenantWorkloadRouteExpectation{
		ReservationID: reservation.ID, ReservationDigest: reservation.Digest, TenantID: reservation.Spec.TenantID,
		SiteID: reservation.Spec.SiteID, DomainID: reservation.Spec.DomainID, Hostname: reservation.Spec.Hostname,
		ListenerRef: reservation.Spec.ListenerRef, WorkloadID: reservation.Spec.WorkloadID,
		TargetEndpoint: reservation.Spec.TargetEndpoint, ConfigurationGeneration: configurationGeneration, ConfigurationDigest: configurationDigest,
	}
	observation, err := authority.observer.ObserveTenantWorkloadRoute(ctx, expectation)
	if err != nil {
		return observation, err
	}
	now := authority.now()
	if observation.TenantWorkloadRouteExpectation != expectation || observation.Bound && !observation.Occupied || !validRouteDigest(observation.EvidenceDigest) || observation.ObservedAt.IsZero() || observation.ObservedAt.After(now.Add(time.Minute)) || observation.ObservedAt.Before(now.Add(-5*time.Minute)) {
		return TenantWorkloadRouteObservation{}, ErrTenantRouteInvalid
	}
	if configurationGeneration == 0 {
		if configurationDigest != "" || observation.Bound {
			return TenantWorkloadRouteObservation{}, ErrTenantRouteInvalid
		}
	} else if !validRouteDigest(configurationDigest) {
		return TenantWorkloadRouteObservation{}, ErrTenantRouteInvalid
	}
	return observation, nil
}

func (authority *TenantRouteAuthority) transition(ctx context.Context, current TenantWorkloadRouteReservation, next TenantWorkloadRouteState, activationGeneration uint64, candidateDigest, observationDigest string, activated, discarded bool, receipt TenantWorkloadRouteReceipt) (TenantWorkloadRouteReservation, error) {
	if !tenantWorkloadRouteTransitionAllowed(current.State, next) || activated && discarded || discarded && current.ActivatedAt != nil || receipt.State != next || receipt.ReservationID != current.ID || receipt.ReservationDigest != current.Digest {
		return current, ErrTenantRouteConflict
	}
	if candidateDigest != "" && !validRouteDigest(candidateDigest) || observationDigest != "" && !validRouteDigest(observationDigest) || (activationGeneration == 0) != (candidateDigest == "") {
		return current, ErrTenantRouteInvalid
	}
	now := authority.now()
	activatedAt := current.ActivatedAt
	if activated && activatedAt == nil {
		value := now
		activatedAt = &value
	}
	discardedAt := current.DiscardedAt
	if discarded && discardedAt == nil {
		value := now
		discardedAt = &value
	}
	proposed := current
	proposed.State = next
	proposed.ActivationGeneration = activationGeneration
	proposed.CandidateDigest = candidateDigest
	proposed.ObservationDigest = observationDigest
	proposed.Receipt = receipt
	proposed.ActivatedAt = activatedAt
	proposed.UpdatedAt = now
	proposed.DiscardedAt = discardedAt
	if err := validateStoredTenantWorkloadRoute(proposed); err != nil {
		return current, err
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		return current, err
	}
	result, err := authority.database.ExecContext(ctx, `UPDATE webengine_tenant_workload_routes_v1 SET state=?,activation_generation=?,candidate_digest=?,observation_digest=?,receipt_json=?,activated_at=?,updated_at=?,discarded_at=? WHERE reservation_id=? AND tenant_id=? AND reservation_digest=? AND generation=? AND state=? AND activation_generation=? AND candidate_digest=? AND observation_digest=?`,
		next, activationGeneration, candidateDigest, observationDigest, receiptJSON, activatedAt, now, discardedAt, current.ID, current.Spec.TenantID, current.Digest, current.Spec.Generation, current.State, current.ActivationGeneration, current.CandidateDigest, current.ObservationDigest)
	if err != nil {
		return current, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return current, errors.Join(ErrTenantRouteConflict, err)
	}
	return authority.load(ctx, current.Spec.TenantID, current.ID)
}

func (authority *TenantRouteAuthority) loadReference(ctx context.Context, reference TenantWorkloadRouteReference) (TenantWorkloadRouteReservation, error) {
	reservation, err := authority.load(ctx, reference.TenantID, reference.ReservationID)
	if err != nil {
		return reservation, err
	}
	if reservation.Spec.Generation != reference.ExpectedGeneration || reservation.Digest != reference.ReservationDigest {
		return TenantWorkloadRouteReservation{}, ErrTenantRouteNotFound
	}
	return reservation, nil
}

func (authority *TenantRouteAuthority) load(ctx context.Context, tenantID containers.ID, reservationID string) (TenantWorkloadRouteReservation, error) {
	var reservation TenantWorkloadRouteReservation
	var endpoint string
	var receiptJSON []byte
	var activatedAt, discardedAt sql.NullTime
	row := authority.database.QueryRowContext(ctx, `SELECT reservation_id,tenant_id,site_id,domain_id,hostname,listener_ref,workload_id,recipe_digest,image_digest,generation,target_endpoint,activation_authority_digest,site_projection_generation,site_projection_digest,site_configuration_generation,site_configuration_digest,reservation_digest,route_ref,activation_effect_id,state,activation_generation,candidate_digest,observation_digest,receipt_json,activated_at,created_at,updated_at,discarded_at FROM webengine_tenant_workload_routes_v1 WHERE reservation_id=? AND tenant_id=?`, reservationID, tenantID)
	err := row.Scan(&reservation.ID, &reservation.Spec.TenantID, &reservation.Spec.SiteID, &reservation.Spec.DomainID, &reservation.Spec.Hostname, &reservation.Spec.ListenerRef, &reservation.Spec.WorkloadID, &reservation.Spec.RecipeDigest, &reservation.Spec.ImageDigest, &reservation.Spec.Generation, &endpoint, &reservation.Spec.ActivationAuthorityDigest, &reservation.Spec.SiteHandoff.ProjectionGeneration, &reservation.Spec.SiteHandoff.ProjectionDigest, &reservation.Spec.SiteHandoff.ConfigurationGeneration, &reservation.Spec.SiteHandoff.ConfigurationDigest, &reservation.Digest, &reservation.RouteRef, &reservation.ActivationEffectID, &reservation.State, &reservation.ActivationGeneration, &reservation.CandidateDigest, &reservation.ObservationDigest, &receiptJSON, &activatedAt, &reservation.CreatedAt, &reservation.UpdatedAt, &discardedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return reservation, ErrTenantRouteNotFound
	}
	if err != nil {
		return reservation, err
	}
	reservation.Spec.TargetEndpoint, err = netip.ParseAddrPort(endpoint)
	if err != nil || json.Unmarshal(receiptJSON, &reservation.Receipt) != nil {
		return TenantWorkloadRouteReservation{}, ErrTenantRouteConflict
	}
	if activatedAt.Valid {
		value := activatedAt.Time.UTC()
		reservation.ActivatedAt = &value
	}
	if discardedAt.Valid {
		value := discardedAt.Time.UTC()
		reservation.DiscardedAt = &value
	}
	if err = validateStoredTenantWorkloadRoute(reservation); err != nil {
		return TenantWorkloadRouteReservation{}, err
	}
	return reservation, nil
}

func (authority *TenantRouteAuthority) now() time.Time {
	if authority.clock == nil {
		return time.Now().UTC()
	}
	return authority.clock().UTC()
}

func normalizeTenantWorkloadRouteSpec(spec TenantWorkloadRouteSpec) (TenantWorkloadRouteSpec, error) {
	hostname, err := webengine.ParseHostname(spec.Hostname)
	if err != nil || !spec.TenantID.Valid() || !spec.SiteID.Valid() || !spec.DomainID.Valid() || !spec.WorkloadID.Valid() || !safeRouteRef(spec.ListenerRef) || !validRouteDigest(spec.RecipeDigest) || !strings.HasPrefix(spec.ImageDigest, "sha256:") || !validRouteDigest(strings.TrimPrefix(spec.ImageDigest, "sha256:")) || spec.Generation == 0 || !spec.TargetEndpoint.IsValid() || spec.TargetEndpoint.Addr() != netip.MustParseAddr("127.0.0.1") || spec.TargetEndpoint.Port() < 1024 || !validRouteDigest(spec.ActivationAuthorityDigest) || spec.SiteHandoff.ProjectionGeneration == 0 || !validRouteDigest(spec.SiteHandoff.ProjectionDigest) || spec.SiteHandoff.ConfigurationGeneration == 0 || !validRouteDigest(spec.SiteHandoff.ConfigurationDigest) {
		return TenantWorkloadRouteSpec{}, ErrTenantRouteInvalid
	}
	spec.Hostname = hostname.String()
	return spec, nil
}

func newTenantWorkloadRouteReservation(spec TenantWorkloadRouteSpec) TenantWorkloadRouteReservation {
	raw, _ := json.Marshal(struct {
		Domain string                  `json:"domain"`
		Spec   TenantWorkloadRouteSpec `json:"spec"`
	}{"cyberpanel:tenant-workload-route-reservation:v1", spec})
	digest := routeDigest(raw)
	return TenantWorkloadRouteReservation{
		ID: "twr-" + digest[:48], Digest: digest, Spec: spec,
		RouteRef:           webengine.ResourceRef("tenant-workload/" + digest[:48]),
		ActivationEffectID: "tenant-workload-route-" + digest,
	}
}

// TenantWorkloadRouteReferenceForSpec exposes only the deterministic identity
// needed to journal a route before Reserve performs its first live observation.
func TenantWorkloadRouteReferenceForSpec(spec TenantWorkloadRouteSpec) (TenantWorkloadRouteReference, error) {
	normalized, err := normalizeTenantWorkloadRouteSpec(spec)
	if err != nil {
		return TenantWorkloadRouteReference{}, err
	}
	reservation := newTenantWorkloadRouteReservation(normalized)
	return TenantWorkloadRouteReference{TenantID: normalized.TenantID, ReservationID: reservation.ID, ExpectedGeneration: normalized.Generation, ReservationDigest: reservation.Digest}, nil
}

func validateTenantWorkloadRouteReference(reference TenantWorkloadRouteReference) error {
	if !reference.TenantID.Valid() || !strings.HasPrefix(reference.ReservationID, "twr-") || len(reference.ReservationID) != 52 || reference.ExpectedGeneration == 0 || !validRouteDigest(reference.ReservationDigest) {
		return ErrTenantRouteInvalid
	}
	return nil
}

func validateStoredTenantWorkloadRoute(reservation TenantWorkloadRouteReservation) error {
	normalized, err := normalizeTenantWorkloadRouteSpec(reservation.Spec)
	if err != nil || normalized != reservation.Spec {
		return ErrTenantRouteConflict
	}
	expected := newTenantWorkloadRouteReservation(normalized)
	if reservation.ID != expected.ID || reservation.Digest != expected.Digest || reservation.RouteRef != expected.RouteRef || reservation.ActivationEffectID != expected.ActivationEffectID || reservation.CreatedAt.IsZero() || reservation.UpdatedAt.Before(reservation.CreatedAt) || reservation.ActivatedAt != nil && (reservation.ActivatedAt.Before(reservation.CreatedAt) || reservation.ActivatedAt.After(reservation.UpdatedAt)) || reservation.DiscardedAt != nil && (reservation.DiscardedAt.Before(reservation.CreatedAt) || reservation.DiscardedAt.After(reservation.UpdatedAt)) || reservation.CandidateDigest != "" && !validRouteDigest(reservation.CandidateDigest) || reservation.ObservationDigest != "" && !validRouteDigest(reservation.ObservationDigest) || (reservation.ActivationGeneration == 0) != (reservation.CandidateDigest == "") {
		return ErrTenantRouteConflict
	}
	switch reservation.State {
	case TenantWorkloadRouteReserved:
		if reservation.ActivatedAt != nil || reservation.DiscardedAt != nil || reservation.ActivationGeneration != 0 || reservation.CandidateDigest != "" {
			return ErrTenantRouteConflict
		}
	case TenantWorkloadRouteActivating, TenantWorkloadRouteAmbiguous:
		if reservation.DiscardedAt != nil {
			return ErrTenantRouteConflict
		}
	case TenantWorkloadRouteActive:
		if reservation.ActivatedAt == nil || reservation.DiscardedAt != nil || reservation.ActivationGeneration == 0 || !validRouteDigest(reservation.CandidateDigest) || !validRouteDigest(reservation.ObservationDigest) {
			return ErrTenantRouteConflict
		}
	case TenantWorkloadRouteDiscarded:
		if reservation.ActivatedAt != nil || reservation.DiscardedAt == nil {
			return ErrTenantRouteConflict
		}
	default:
		return ErrTenantRouteConflict
	}
	if validateTenantWorkloadRouteReceipt(reservation.Receipt, reservation) != nil {
		return ErrTenantRouteConflict
	}
	return nil
}

func tenantWorkloadRouteReceipt(reservation TenantWorkloadRouteReservation, state TenantWorkloadRouteState, generation uint64, configurationDigest, observationDigest string, bound bool, reason string, now time.Time) TenantWorkloadRouteReceipt {
	receipt := TenantWorkloadRouteReceipt{
		ReservationID: reservation.ID, ReservationDigest: reservation.Digest, TenantID: reservation.Spec.TenantID,
		Generation: reservation.Spec.Generation, State: state, TargetEndpoint: reservation.Spec.TargetEndpoint,
		ActivationAuthorityDigest: reservation.Spec.ActivationAuthorityDigest, ConfigurationGeneration: generation,
		ConfigurationDigest: configurationDigest, ObservationDigest: observationDigest, Bound: bound, Reason: reason, ObservedAt: now.UTC(),
	}
	receipt.EvidenceDigest = tenantWorkloadRouteReceiptDigest(receipt)
	return receipt
}

func validateTenantWorkloadRouteReceipt(receipt TenantWorkloadRouteReceipt, reservation TenantWorkloadRouteReservation) error {
	if receipt.ReservationID != reservation.ID || receipt.ReservationDigest != reservation.Digest || receipt.TenantID != reservation.Spec.TenantID || receipt.Generation != reservation.Spec.Generation || receipt.State != reservation.State || receipt.TargetEndpoint != reservation.Spec.TargetEndpoint || receipt.ActivationAuthorityDigest != reservation.Spec.ActivationAuthorityDigest || receipt.ConfigurationGeneration != reservation.ActivationGeneration || receipt.ConfigurationDigest != reservation.CandidateDigest || receipt.ObservationDigest != reservation.ObservationDigest || receipt.Reason == "" || len(receipt.Reason) > 96 || receipt.ObservedAt.IsZero() || receipt.EvidenceDigest != tenantWorkloadRouteReceiptDigest(receipt) {
		return ErrTenantRouteInvalid
	}
	if receipt.Bound != (reservation.State == TenantWorkloadRouteActive) && reservation.State != TenantWorkloadRouteAmbiguous {
		return ErrTenantRouteInvalid
	}
	return nil
}

func tenantWorkloadRouteReceiptDigest(receipt TenantWorkloadRouteReceipt) string {
	receipt.EvidenceDigest = ""
	raw, _ := json.Marshal(struct {
		Domain  string                     `json:"domain"`
		Receipt TenantWorkloadRouteReceipt `json:"receipt"`
	}{"cyberpanel:tenant-workload-route-receipt:v1", receipt})
	return routeDigest(raw)
}

func tenantWorkloadProxyRoute(reservation TenantWorkloadRouteReservation) composer.ProxyRouteInput {
	hostname, _ := webengine.ParseHostname(reservation.Spec.Hostname)
	return composer.ProxyRouteInput{Ref: reservation.RouteRef, Hostname: hostname, ListenerRef: reservation.Spec.ListenerRef, UpstreamPort: reservation.Spec.TargetEndpoint.Port(), Generation: reservation.Spec.Generation}
}

func sameTenantWorkloadProxyRoute(route composer.ProxyRouteInput, reservation TenantWorkloadRouteReservation) bool {
	return reflect.DeepEqual(route, tenantWorkloadProxyRoute(reservation))
}

func ensureTenantWorkloadRouteAvailable(ctx context.Context, tx *sql.Tx, reservation TenantWorkloadRouteReservation) error {
	var existing string
	err := tx.QueryRowContext(ctx, `SELECT reservation_id FROM webengine_tenant_workload_routes_v1 WHERE hostname=? AND listener_ref=? AND state<>'discarded' LIMIT 1`, reservation.Spec.Hostname, reservation.Spec.ListenerRef).Scan(&existing)
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		return errors.Join(ErrTenantRouteConflict, err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT input_json FROM webengine_proxy_routes`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var raw []byte
		var route composer.ProxyRouteInput
		if err = rows.Scan(&raw); err != nil || json.Unmarshal(raw, &route) != nil {
			_ = rows.Close()
			return errors.Join(ErrTenantRouteConflict, err)
		}
		if route.Ref == reservation.RouteRef || route.Hostname.String() == reservation.Spec.Hostname && route.ListenerRef == reservation.Spec.ListenerRef {
			_ = rows.Close()
			return ErrTenantRouteConflict
		}
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	rows, err = tx.QueryContext(ctx, `SELECT tenant_id,site_id,projection_generation,projection_digest,input_json FROM webengine_site_inputs`)
	if err != nil {
		return err
	}
	handoffMatched := false
	for rows.Next() {
		var tenantID, siteID, projectionDigest string
		var projectionGeneration uint64
		var raw []byte
		var input composer.SiteInput
		if err = rows.Scan(&tenantID, &siteID, &projectionGeneration, &projectionDigest, &raw); err != nil || json.Unmarshal(raw, &input) != nil {
			_ = rows.Close()
			return errors.Join(ErrTenantRouteConflict, err)
		}
		for _, binding := range input.Projection.Bindings {
			if binding.Hostname.String() != reservation.Spec.Hostname {
				continue
			}
			if tenantID == reservation.Spec.TenantID.String() && siteID == reservation.Spec.SiteID.String() && input.Scope.TenantID.String() == tenantID && input.Scope.SiteID.String() == siteID && !input.Withdraw && input.Projection.Lifecycle == site.LifecycleProvisioning && len(input.Projection.Bindings) == 1 && binding.Kind == site.BindingPrimary && projectionGeneration == reservation.Spec.SiteHandoff.ProjectionGeneration && projectionDigest == reservation.Spec.SiteHandoff.ProjectionDigest {
				if handoffMatched {
					_ = rows.Close()
					return ErrTenantRouteConflict
				}
				handoffMatched = true
				continue
			}
			_ = rows.Close()
			return ErrTenantRouteConflict
		}
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	if !handoffMatched {
		return ErrTenantRouteConflict
	}
	var policies int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM webengine_access_policies WHERE tenant_id=? AND site_id=?`, reservation.Spec.TenantID, reservation.Spec.SiteID).Scan(&policies); err != nil || policies != 0 {
		return errors.Join(ErrTenantRouteConflict, err)
	}
	var priorChange string
	err = tx.QueryRowContext(ctx, `SELECT effect_id FROM webengine_proxy_changes WHERE effect_id=? OR route_ref=? LIMIT 1`, reservation.ActivationEffectID, reservation.RouteRef).Scan(&priorChange)
	if err == nil {
		return ErrTenantRouteConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var pending string
	err = tx.QueryRowContext(ctx, `SELECT effect_id FROM webengine_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_proxy_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_access_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_node_changes WHERE status='pending' LIMIT 1`).Scan(&pending)
	if err == nil {
		return ErrTenantRouteConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var configurationJSON []byte
	var configurationGeneration uint64
	var configurationDigest string
	if err = tx.QueryRowContext(ctx, `SELECT snapshot_generation,applied_digest,config_json FROM webengine_node_config WHERE singleton_id=1`).Scan(&configurationGeneration, &configurationDigest, &configurationJSON); err != nil {
		return err
	}
	var configuration catalog.NodeConfiguration
	if json.Unmarshal(configurationJSON, &configuration) != nil || configurationGeneration != reservation.Spec.SiteHandoff.ConfigurationGeneration || configurationDigest != reservation.Spec.SiteHandoff.ConfigurationDigest {
		return ErrTenantRouteConflict
	}
	matched := false
	for _, listener := range configuration.Engine.Listeners {
		if listener.Ref == reservation.Spec.ListenerRef {
			if matched || listener.TLSMode != webengine.TLSModeClear || listener.Port == 0 || len(listener.Protocols) != 1 || listener.Protocols[0] != webengine.ProtocolHTTP1 {
				return ErrTenantRouteConflict
			}
			matched = true
		}
	}
	if !matched {
		return ErrTenantRouteConflict
	}
	return nil
}

func tenantWorkloadRouteTransitionAllowed(current, next TenantWorkloadRouteState) bool {
	switch current {
	case TenantWorkloadRouteReserved:
		return next == TenantWorkloadRouteReserved || next == TenantWorkloadRouteActivating || next == TenantWorkloadRouteAmbiguous || next == TenantWorkloadRouteDiscarded
	case TenantWorkloadRouteActivating:
		return next == TenantWorkloadRouteActivating || next == TenantWorkloadRouteAmbiguous || next == TenantWorkloadRouteActive || next == TenantWorkloadRouteDiscarded
	case TenantWorkloadRouteAmbiguous:
		return next == TenantWorkloadRouteAmbiguous || next == TenantWorkloadRouteActive || next == TenantWorkloadRouteDiscarded
	case TenantWorkloadRouteActive:
		return next == TenantWorkloadRouteActive || next == TenantWorkloadRouteAmbiguous
	case TenantWorkloadRouteDiscarded:
		return next == TenantWorkloadRouteDiscarded
	default:
		return false
	}
}

func validRouteDigest(value string) bool {
	return len(value) == sha256.Size*2 && strings.Trim(value, "0123456789abcdef") == ""
}

func routeDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

var _ TenantWorkloadRouteBroker = (*TenantRouteAuthority)(nil)
