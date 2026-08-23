package diagnosticsrepair

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

type Clock interface { Now() time.Time }

type ProbeRequest struct {
	RunID              string         `json:"run_id"`
	Kind               DiagnosticKind `json:"kind"`
	Scope              Scope          `json:"scope"`
	ExpectedGeneration uint64         `json:"expected_generation"`
	Deadline           time.Time      `json:"deadline"`
	Digest             string         `json:"digest"`
}

type ReadOnlyProbe interface { Observe(context.Context, ProbeRequest) (ProbeObservation, error) }

type RegisteredProbe struct {
	Kind  DiagnosticKind
	Probe ReadOnlyProbe
}

type RunnerLimits struct {
	MaximumDuration       time.Duration
	MaximumTotalFindings  int
	MaximumEvidenceItems  int
	MaximumExportBytes    int
}

type Runner struct {
	registry *Registry
	probes   map[DiagnosticKind]ReadOnlyProbe
	limits   RunnerLimits
	clock    Clock
}

func NewRunner(registry *Registry, probes []RegisteredProbe, limits RunnerLimits, clock Clock) (*Runner, error) {
	if registry == nil || clock == nil || limits.MaximumDuration < time.Second || limits.MaximumDuration > 30*time.Minute ||
		limits.MaximumTotalFindings <= 0 || limits.MaximumTotalFindings > 2304 || limits.MaximumEvidenceItems <= 0 ||
		limits.MaximumEvidenceItems > 32 || limits.MaximumExportBytes < 1024 || limits.MaximumExportBytes > 16<<20 || len(probes) > 9 {
		return nil, ErrInvalid
	}
	runner := &Runner{registry: registry, probes: make(map[DiagnosticKind]ReadOnlyProbe), limits: limits, clock: clock}
	for _, registered := range probes {
		if !registered.Kind.Valid() || registered.Probe == nil { return nil, ErrInvalid }
		if _, duplicate := runner.probes[registered.Kind]; duplicate { return nil, ErrInvalid }
		runner.probes[registered.Kind] = registered.Probe
	}
	return runner, nil
}

type RunRequest struct {
	ID                 string
	Scope              Scope
	Kinds              []DiagnosticKind
	ExpectedGeneration uint64
	RequestedAt        time.Time
}

func (runner *Runner) Run(ctx context.Context, request RunRequest) (DiagnosticRun, error) {
	if runner == nil || !identifierPattern.MatchString(request.ID) || request.Scope.Validate() != nil || !validTime(request.RequestedAt) ||
		request.ExpectedGeneration > maxGeneration || len(request.Kinds) > 9 { return DiagnosticRun{}, ErrInvalid }
	now := runner.clock.Now().UTC()
	if !validTime(now) || absoluteDuration(now.Sub(request.RequestedAt.UTC())) > 5*time.Minute { return DiagnosticRun{}, ErrInvalid }
	selected, err := runner.selection(request.Kinds)
	if err != nil { return DiagnosticRun{}, err }
	deadline := now.Add(runner.limits.MaximumDuration)
	runContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	observations := make(map[DiagnosticKind]ProbeObservation, len(selected))
	totalFindings := 0
	for _, kind := range runner.registry.Order() {
		if !selected[kind] { continue }
		definition, _ := runner.registry.Definition(kind)
		if dependency, blocked := blockedDependency(definition.Dependencies, observations); blocked {
			dependencyDigest := dependency.Digest
			if !validDigest(dependencyDigest) { dependencyDigest = digestParts("dependency-absent", request.ID, string(kind)) }
			observation, buildErr := syntheticObservation(kind, request.Scope, request.ExpectedGeneration,
				ProbeUncertain, FindingDependencyUnknown, EvidenceDependency, dependencyDigest, now, definition)
			if buildErr != nil { return DiagnosticRun{}, buildErr }
			observations[kind], totalFindings = observation, totalFindings+1
			continue
		}
		probe := runner.probes[kind]
		if probe == nil {
			observation, buildErr := syntheticObservation(kind, request.Scope, request.ExpectedGeneration,
				ProbeUnsupported, FindingProbeUnsupported, EvidenceUnsupported, digestParts("unsupported", string(kind)), now, definition)
			if buildErr != nil { return DiagnosticRun{}, buildErr }
			observations[kind], totalFindings = observation, totalFindings+1
			continue
		}
		probeRequest := ProbeRequest{RunID: request.ID, Kind: kind, Scope: request.Scope,
			ExpectedGeneration: request.ExpectedGeneration, Deadline: deadline.UTC()}
		probeRequest.Digest, _ = digestJSON(probeRequest)
		observation, observeErr := probe.Observe(runContext, probeRequest)
		if observeErr != nil {
			observation, err = syntheticObservation(kind, request.Scope, request.ExpectedGeneration, ProbeUncertain,
				FindingProbeUncertain, EvidenceAmbiguous, digestParts("probe-error", request.ID, string(kind)), runner.clock.Now().UTC(), definition)
		} else {
			rawObservation := observation
			observation, err = canonicalObservation(observation, definition, runner.clock.Now().UTC())
			if err == ErrStale {
				observation, err = syntheticObservation(kind, request.Scope, rawObservation.ObservedGeneration, ProbeUncertain,
					FindingStaleObservation, EvidenceStale, digestParts("stale", rawObservation.EvidenceDigest), runner.clock.Now().UTC(), definition)
			}
		}
		if err != nil { return DiagnosticRun{}, err }
		if observation.Scope != request.Scope { return DiagnosticRun{}, ErrIntegrity }
		if request.ExpectedGeneration != 0 && observation.ObservedGeneration != request.ExpectedGeneration {
			observation, err = syntheticObservation(kind, request.Scope, observation.ObservedGeneration, ProbeUncertain,
				FindingStaleObservation, EvidenceObservedGeneration,
				digestParts("generation-mismatch", uintString(request.ExpectedGeneration), uintString(observation.ObservedGeneration)), runner.clock.Now().UTC(), definition)
			if err != nil { return DiagnosticRun{}, err }
		}
		for _, finding := range observation.Findings {
			if len(finding.Evidence) > runner.limits.MaximumEvidenceItems { return DiagnosticRun{}, ErrCapacity }
		}
		totalFindings += len(observation.Findings)
		if totalFindings > runner.limits.MaximumTotalFindings { return DiagnosticRun{}, ErrCapacity }
		observations[kind] = observation
	}
	ordered := make([]ProbeObservation, 0, len(observations))
	state := RunHealthy
	for _, kind := range runner.registry.Order() {
		observation, found := observations[kind]
		if !found { continue }
		ordered = append(ordered, observation)
		switch observation.State {
		case ProbeUncertain: state = RunUncertain
		case ProbeUnsupported:
			if state != RunUncertain { state = RunUnsupported }
		case ProbeFindings:
			if state == RunHealthy { state = RunFindings }
		}
	}
	completed := runner.clock.Now().UTC()
	if !validTime(completed) || completed.Before(request.RequestedAt.UTC()) || completed.After(deadline.Add(time.Second)) { return DiagnosticRun{}, ErrIntegrity }
	run := DiagnosticRun{ID: request.ID, Scope: request.Scope, RegistryDigest: runner.registry.Digest(),
		RequestedAt: request.RequestedAt.UTC(), CompletedAt: completed, State: state, Observations: ordered}
	return CanonicalRun(run)
}

func (runner *Runner) selection(requested []DiagnosticKind) (map[DiagnosticKind]bool, error) {
	selected := make(map[DiagnosticKind]bool)
	if len(requested) == 0 {
		for _, kind := range runner.registry.Order() { selected[kind] = true }
		return selected, nil
	}
	requested = append([]DiagnosticKind(nil), requested...)
	sort.Slice(requested, func(i, j int) bool { return requested[i] < requested[j] })
	for index, kind := range requested {
		if !kind.Valid() || index > 0 && requested[index-1] == kind { return nil, ErrInvalid }
		var add func(DiagnosticKind)
		add = func(current DiagnosticKind) {
			if selected[current] { return }
			selected[current] = true
			definition, _ := runner.registry.Definition(current)
			for _, dependency := range definition.Dependencies { add(dependency) }
		}
		add(kind)
	}
	return selected, nil
}

func blockedDependency(dependencies []DiagnosticKind, observations map[DiagnosticKind]ProbeObservation) (ProbeObservation, bool) {
	for _, dependency := range dependencies {
		observation, found := observations[dependency]
		if !found || observation.State != ProbeHealthy { return observation, true }
	}
	return ProbeObservation{}, false
}

func syntheticObservation(kind DiagnosticKind, scope Scope, generation uint64, state ProbeState, findingCode FindingCode,
	evidenceCode EvidenceCode, evidenceDigest string, at time.Time, definition DiagnosticDefinition) (ProbeObservation, error) {
	if !validTime(at) { return ProbeObservation{}, ErrInvalid }
	at = at.UTC()
	finding := Finding{Kind: kind, Scope: scope, Code: findingCode, Severity: SeverityWarning,
		ObservedGeneration: generation, ServiceID: definition.ServiceID, RepairEligible: false,
		Evidence: []Evidence{{Code: evidenceCode, Digest: evidenceDigest, ObservedAt: at}}}
	finding, err := canonicalFinding(finding, 32)
	if err != nil { return ProbeObservation{}, err }
	observation := ProbeObservation{Kind: kind, Scope: scope, State: state, ObservedGeneration: generation,
		ObservedAt: at, FreshUntil: at.Add(definition.Freshness), Findings: []Finding{finding},
		EvidenceDigest: evidenceDigest}
	return canonicalObservation(observation, definition, at)
}

type FindingProof struct {
	Code     FindingCode `json:"code"`
	Severity Severity    `json:"severity"`
	Digest   string      `json:"digest"`
}

type ObservationProof struct {
	Kind               DiagnosticKind `json:"kind"`
	State              ProbeState     `json:"state"`
	ObservedGeneration uint64         `json:"observed_generation"`
	Findings           []FindingProof `json:"findings"`
	Digest             string         `json:"digest"`
}

type RunProofManifest struct {
	RunID          string             `json:"run_id"`
	Scope          Scope              `json:"scope"`
	RegistryDigest string             `json:"registry_digest"`
	State          RunState           `json:"state"`
	CompletedAt    time.Time          `json:"completed_at"`
	Observations   []ObservationProof `json:"observations"`
	Digest         string             `json:"digest"`
}

func (runner *Runner) Export(run DiagnosticRun) (RunProofManifest, []byte, error) {
	run, err := CanonicalRun(run)
	if err != nil || runner == nil || run.RegistryDigest != runner.registry.Digest() { return RunProofManifest{}, nil, ErrIntegrity }
	manifest := RunProofManifest{RunID: run.ID, Scope: run.Scope, RegistryDigest: run.RegistryDigest,
		State: run.State, CompletedAt: run.CompletedAt}
	for _, observation := range run.Observations {
		proof := ObservationProof{Kind: observation.Kind, State: observation.State,
			ObservedGeneration: observation.ObservedGeneration, Digest: observation.Digest}
		for _, finding := range observation.Findings {
			proof.Findings = append(proof.Findings, FindingProof{finding.Code, finding.Severity, finding.Digest})
		}
		manifest.Observations = append(manifest.Observations, proof)
	}
	manifest.Digest, err = digestJSON(manifest)
	if err != nil { return RunProofManifest{}, nil, err }
	raw, err := json.Marshal(manifest)
	if err != nil || len(raw) > runner.limits.MaximumExportBytes { return RunProofManifest{}, nil, ErrCapacity }
	return manifest, raw, nil
}

func absoluteDuration(duration time.Duration) time.Duration { if duration < 0 { return -duration }; return duration }
