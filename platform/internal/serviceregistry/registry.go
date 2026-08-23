package serviceregistry

import (
	"fmt"
	"sort"
	"time"
)

type Registry struct {
	definitions   map[ServiceID]ServiceDefinition
	ordered       []ServiceID
	support       SupportContext
	digest        string
	supportDigest string
}

type PlanRequest struct {
	ID                         string
	NodeID                     string
	Target                     ServiceID
	Action                     Action
	Generation                 uint64
	ExpectedDesiredGeneration  uint64
	ExpectedObservedGeneration uint64
	ExpectedConfigGeneration   uint64
	Observations               map[ServiceID]ServiceObservation
	ConsumerSnapshot           ConsumerSnapshot
	CreatedAt                  time.Time
	TTL                        time.Duration
}

func requiresConsumerSnapshot(action Action) bool {
	return action == ActionStop || action == ActionRestart || action == ActionReload || action == ActionRemove || action == ActionRepair
}

func NewRegistry(support SupportContext) (*Registry, error) {
	if support.OSFamily == "" || support.OSVersion == "" || support.Architecture == "" || support.ReleaseChannel == "" {
		return nil, fmt.Errorf("%w: incomplete support context", ErrInvalid)
	}
	if !closedSupportContext(support) {
		return nil, fmt.Errorf("%w: unqualified support context", ErrUnsupported)
	}
	tuple, err := qualifiedTuple(support)
	if err != nil {
		return nil, err
	}
	defs := closedDefinitions(tuple)
	if len(defs) > MaxServices {
		return nil, fmt.Errorf("%w: registry exceeds service bound", ErrInvalid)
	}
	r := &Registry{
		definitions: make(map[ServiceID]ServiceDefinition, len(defs)),
		support:     support,
	}
	for _, definition := range defs {
		if err := validateDefinition(definition, support); err != nil {
			return nil, err
		}
		if _, exists := r.definitions[definition.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate service %s", ErrInvalid, definition.ID)
		}
		definition.Dependencies = copyAndSortServiceIDs(definition.Dependencies)
		definition.Conflicts = copyAndSortServiceIDs(definition.Conflicts)
		definition.AllowedActions = copyAndSortActions(definition.AllowedActions)
		r.definitions[definition.ID] = definition
		r.ordered = append(r.ordered, definition.ID)
	}
	sort.Slice(r.ordered, func(i, j int) bool { return r.ordered[i] < r.ordered[j] })
	for _, consumerID := range r.ordered {
		for _, dependencyID := range r.definitions[consumerID].Dependencies {
			dependency, ok := r.definitions[dependencyID]
			if !ok {
				return nil, fmt.Errorf("%w: unknown dependency %s", ErrInvalid, dependencyID)
			}
			dependency.Consumers = append(dependency.Consumers, consumerID)
			if len(dependency.Consumers) > MaxDependencies {
				return nil, fmt.Errorf("%w: consumer bound exceeded for %s", ErrInvalid, dependencyID)
			}
			dependency.Consumers = copyAndSortServiceIDs(dependency.Consumers)
			r.definitions[dependencyID] = dependency
		}
	}
	if err := r.validateGraph(); err != nil {
		return nil, err
	}
	canonical := make([]ServiceDefinition, 0, len(r.ordered))
	for _, id := range r.ordered {
		canonical = append(canonical, r.definitions[id])
	}
	r.digest, err = digestValue(canonical)
	if err != nil {
		return nil, err
	}
	r.supportDigest, err = digestValue(tuple)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func closedSupportContext(s SupportContext) bool {
	if s.ReleaseChannel != "stable" || (s.Architecture != "amd64" && s.Architecture != "arm64") {
		return false
	}
	switch s.OSFamily {
	case "ubuntu":
		return s.OSVersion == "22.04" || s.OSVersion == "24.04"
	case "almalinux":
		return s.OSVersion == "8" || s.OSVersion == "9"
	default:
		return false
	}
}

func qualifiedTuple(s SupportContext) (SupportTuple, error) {
	t := SupportTuple{
		OSFamily:       s.OSFamily,
		OSVersion:      s.OSVersion,
		Architecture:   s.Architecture,
		ReleaseChannel: s.ReleaseChannel,
	}
	d, err := digestValue(t)
	if err != nil {
		return SupportTuple{}, err
	}
	t.QualificationDigest = d
	return t, nil
}

func actions(c Capabilities) []Action {
	a := []Action{ActionInspect}
	if c.Lifecycle {
		a = append(a, ActionStart, ActionStop, ActionRestart)
	}
	if c.Reload {
		a = append(a, ActionReload)
	}
	if c.Enable {
		a = append(a, ActionEnable, ActionDisable)
	}
	if c.Install {
		a = append(a, ActionInstall)
	}
	if c.Remove {
		a = append(a, ActionRemove)
	}
	if c.Repair {
		a = append(a, ActionRepair)
	}
	return a
}

func closedDefinitions(support SupportTuple) []ServiceDefinition {
	stateful := Capabilities{Lifecycle: true, Reload: true, Enable: true, Install: true, Remove: true, Repair: true, Stateful: true, Critical: true}
	statefulNoReload := stateful
	statefulNoReload.Reload = false
	standard := Capabilities{Lifecycle: true, Reload: true, Enable: true, Install: true, Remove: true, Repair: true}
	standardNoReload := standard
	standardNoReload.Reload = false
	critical := standard
	critical.Critical = true
	php := standard
	php.Reload = false
	panel := Capabilities{Lifecycle: true, Reload: true, Enable: true, Install: false, Remove: false, Repair: true, Critical: true}
	makeDefinition := func(id ServiceID, name, profile string, capability Capabilities, owner OwnershipKind, dependencies, conflicts []ServiceID) ServiceDefinition {
		return ServiceDefinition{
			ID:               id,
			DisplayName:      name,
			Capabilities:     capability,
			Dependencies:     dependencies,
			Conflicts:        conflicts,
			Ownership:        Ownership{Kind: owner, Scope: "node", ManagedConfig: owner == OwnershipPanel},
			ConfigGeneration: true,
			PackageProfile:   profile,
			AllowedActions:   actions(capability),
			Support:          []SupportTuple{support},
		}
	}
	return []ServiceDefinition{
		makeDefinition(ServiceOpenLiteSpeed, "OpenLiteSpeed", "service-openlitespeed", critical, OwnershipPanel, nil, []ServiceID{ServiceLiteSpeed}),
		makeDefinition(ServiceLiteSpeed, "LiteSpeed Enterprise", "service-litespeed-enterprise", critical, OwnershipVendor, nil, []ServiceID{ServiceOpenLiteSpeed}),
		makeDefinition(ServicePowerDNS, "PowerDNS Authoritative", "service-powerdns", stateful, OwnershipPanel, nil, nil),
		makeDefinition(ServiceMariaDB, "MariaDB", "service-mariadb", statefulNoReload, OwnershipOS, nil, nil),
		makeDefinition(ServicePostfix, "Postfix", "service-postfix", stateful, OwnershipPanel, nil, nil),
		makeDefinition(ServiceDovecot, "Dovecot", "service-dovecot", stateful, OwnershipPanel, nil, nil),
		makeDefinition(ServiceRspamd, "Rspamd", "service-rspamd", standard, OwnershipPanel, []ServiceID{ServiceRedis}, nil),
		makeDefinition(ServiceClamAV, "ClamAV", "service-clamav", standard, OwnershipOS, nil, nil),
		makeDefinition(ServiceFTPS, "Pure-FTPd FTPS", "service-ftps", standardNoReload, OwnershipPanel, nil, nil),
		makeDefinition(ServicePHP74, "PHP 7.4 Runtime", "service-php74", php, OwnershipPanel, nil, nil),
		makeDefinition(ServicePHP80, "PHP 8.0 Runtime", "service-php80", php, OwnershipPanel, nil, nil),
		makeDefinition(ServicePHP81, "PHP 8.1 Runtime", "service-php81", php, OwnershipPanel, nil, nil),
		makeDefinition(ServicePHP82, "PHP 8.2 Runtime", "service-php82", php, OwnershipPanel, nil, nil),
		makeDefinition(ServicePHP83, "PHP 8.3 Runtime", "service-php83", php, OwnershipPanel, nil, nil),
		makeDefinition(ServicePHP84, "PHP 8.4 Runtime", "service-php84", php, OwnershipPanel, nil, nil),
		makeDefinition(ServiceRedis, "Redis", "service-redis", statefulNoReload, OwnershipOS, nil, nil),
		makeDefinition(ServiceSearch, "Search", "service-search", statefulNoReload, OwnershipPanel, nil, nil),
		makeDefinition(ServiceContainers, "Container Runtime", "service-containers", statefulNoReload, OwnershipOS, nil, nil),
		makeDefinition(ServicePanelCore, "Panel Core", "", panel, OwnershipPanel, []ServiceID{ServiceMariaDB}, nil),
		makeDefinition(ServicePanelGateway, "Panel Gateway", "", panel, OwnershipPanel, []ServiceID{ServicePanelCore}, nil),
		makeDefinition(ServiceScheduler, "Panel Scheduler", "", panel, OwnershipPanel, []ServiceID{ServicePanelCore}, nil),
		makeDefinition(ServiceNodeAgent, "Panel Node Agent", "", panel, OwnershipPanel, []ServiceID{ServicePanelCore}, nil),
	}
}

func validateDefinition(d ServiceDefinition, support SupportContext) error {
	if validateServiceID(d.ID) != nil || d.DisplayName == "" || len(d.Dependencies) > MaxDependencies || len(d.Conflicts) > MaxDependencies {
		return fmt.Errorf("%w: invalid service definition %q", ErrInvalid, d.ID)
	}
	if len(d.AllowedActions) == 0 || len(d.Support) == 0 || d.Ownership.Scope != "node" {
		return fmt.Errorf("%w: incomplete service definition %s", ErrInvalid, d.ID)
	}
	matched := false
	for _, tuple := range d.Support {
		if tuple.OSFamily == support.OSFamily && tuple.OSVersion == support.OSVersion && tuple.Architecture == support.Architecture && tuple.ReleaseChannel == support.ReleaseChannel && tuple.QualificationDigest != "" {
			matched = true
		}
	}
	if !matched {
		return fmt.Errorf("%w: service %s has no exact support tuple", ErrUnsupported, d.ID)
	}
	return nil
}

func (r *Registry) validateGraph() error {
	visiting := make(map[ServiceID]bool)
	visited := make(map[ServiceID]bool)
	var visit func(ServiceID) error
	visit = func(id ServiceID) error {
		if visiting[id] {
			return fmt.Errorf("%w: dependency cycle at %s", ErrInvalid, id)
		}
		if visited[id] {
			return nil
		}
		definition, ok := r.definitions[id]
		if !ok {
			return fmt.Errorf("%w: unknown dependency %s", ErrInvalid, id)
		}
		visiting[id] = true
		for _, dependency := range definition.Dependencies {
			if _, ok := r.definitions[dependency]; !ok {
				return fmt.Errorf("%w: %s depends on unknown %s", ErrInvalid, id, dependency)
			}
			if err := visit(dependency); err != nil {
				return err
			}
		}
		for _, conflict := range definition.Conflicts {
			if _, ok := r.definitions[conflict]; !ok || conflict == id {
				return fmt.Errorf("%w: invalid conflict on %s", ErrInvalid, id)
			}
		}
		visiting[id] = false
		visited[id] = true
		return nil
	}
	for _, id := range r.ordered {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) Digest() string { return r.digest }

func (r *Registry) SupportDigest() string { return r.supportDigest }

func (r *Registry) Definition(id ServiceID) (ServiceDefinition, bool) {
	d, ok := r.definitions[id]
	if !ok {
		return ServiceDefinition{}, false
	}
	d.Dependencies = append([]ServiceID(nil), d.Dependencies...)
	d.Consumers = append([]ServiceID(nil), d.Consumers...)
	d.Conflicts = append([]ServiceID(nil), d.Conflicts...)
	d.AllowedActions = append([]Action(nil), d.AllowedActions...)
	d.Support = append([]SupportTuple(nil), d.Support...)
	return d, true
}

func (r *Registry) Definitions() []ServiceDefinition {
	out := make([]ServiceDefinition, 0, len(r.ordered))
	for _, id := range r.ordered {
		d, _ := r.Definition(id)
		out = append(out, d)
	}
	return out
}

func (r *Registry) actionAllowed(id ServiceID, action Action) bool {
	d, ok := r.definitions[id]
	if !ok {
		return false
	}
	for _, candidate := range d.AllowedActions {
		if candidate == action {
			return true
		}
	}
	return false
}

func (r *Registry) consumersOf(id ServiceID) []ServiceID {
	return append([]ServiceID(nil), r.definitions[id].Consumers...)
}

func (r *Registry) dependencyOrder(id ServiceID) ([]ServiceID, error) {
	seen := make(map[ServiceID]bool)
	var order []ServiceID
	var visit func(ServiceID) error
	visit = func(current ServiceID) error {
		if seen[current] {
			return nil
		}
		definition, ok := r.definitions[current]
		if !ok {
			return fmt.Errorf("%w: service %s", ErrNotFound, current)
		}
		for _, dependency := range definition.Dependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		seen[current] = true
		order = append(order, current)
		return nil
	}
	if err := visit(id); err != nil {
		return nil, err
	}
	if len(order) > MaxPlanSteps {
		return nil, fmt.Errorf("%w: dependency expansion exceeds bound", ErrInvalid)
	}
	return order, nil
}

func (r *Registry) BuildPlan(request PlanRequest) (LifecyclePlan, error) {
	if !validID(request.ID) || !validID(request.NodeID) || !validGeneration(request.Generation) || request.ExpectedDesiredGeneration > MaxGeneration || !validGeneration(request.ExpectedObservedGeneration) || request.ExpectedConfigGeneration > MaxGeneration || request.CreatedAt.IsZero() {
		return LifecyclePlan{}, fmt.Errorf("%w: incomplete plan request", ErrInvalid)
	}
	if request.TTL <= 0 || request.TTL > 30*time.Minute {
		return LifecyclePlan{}, fmt.Errorf("%w: plan TTL must be within 30 minutes", ErrInvalid)
	}
	definition, ok := r.definitions[request.Target]
	if !ok {
		return LifecyclePlan{}, fmt.Errorf("%w: service %s", ErrNotFound, request.Target)
	}
	if !r.actionAllowed(request.Target, request.Action) {
		return LifecyclePlan{}, fmt.Errorf("%w: %s on %s", ErrUnsupported, request.Action, request.Target)
	}
	if len(request.Observations) > MaxServices || len(request.ConsumerSnapshot.Consumers) > MaxConsumers {
		return LifecyclePlan{}, fmt.Errorf("%w: planner inputs exceed bounds", ErrInvalid)
	}
	for id, observation := range request.Observations {
		if _, known := r.definitions[id]; !known || observation.ServiceID != id || observation.NodeID != request.NodeID || observation.DefinitionDigest != r.digest {
			return LifecyclePlan{}, fmt.Errorf("%w: observation registry binding", ErrInvalid)
		}
		if err := ValidateObservation(observation); err != nil {
			return LifecyclePlan{}, err
		}
	}
	targetObservation, ok := request.Observations[request.Target]
	if !ok || targetObservation.NodeID != request.NodeID || targetObservation.Generation != request.ExpectedObservedGeneration || targetObservation.ConfigGeneration != request.ExpectedConfigGeneration {
		return LifecyclePlan{}, fmt.Errorf("%w: target observation generation", ErrStale)
	}
	conflictSensitive := request.Action == ActionStart || request.Action == ActionRestart || request.Action == ActionReload || request.Action == ActionEnable || request.Action == ActionInstall || request.Action == ActionRepair
	if conflictSensitive {
		for _, conflict := range definition.Conflicts {
			observed, present := request.Observations[conflict]
			if !present {
				return LifecyclePlan{}, fmt.Errorf("%w: conflict observation missing", ErrStale)
			}
			if observed.Install == InstallInstalled {
				return LifecyclePlan{}, fmt.Errorf("%w: %s conflicts with installed %s", ErrConflict, request.Target, conflict)
			}
		}
	}

	plan := LifecyclePlan{
		ID:                         request.ID,
		NodeID:                     request.NodeID,
		Target:                     request.Target,
		Action:                     request.Action,
		Generation:                 request.Generation,
		ExpectedDesiredGeneration:  request.ExpectedDesiredGeneration,
		ExpectedObservedGeneration: request.ExpectedObservedGeneration,
		ExpectedConfigGeneration:   request.ExpectedConfigGeneration,
		RegistryDigest:             r.digest,
		SupportDigest:              r.supportDigest,
		CreatedAt:                  request.CreatedAt.UTC(),
		ExpiresAt:                  request.CreatedAt.UTC().Add(request.TTL),
		IrreversibleFrontier:       -1,
	}
	disruptive := request.Action == ActionStop || request.Action == ActionRemove
	consumerAware := requiresConsumerSnapshot(request.Action)
	if consumerAware {
		sealedSnapshot, err := SealConsumerSnapshot(request.ConsumerSnapshot)
		if err != nil || sealedSnapshot.EvidenceDigest != request.ConsumerSnapshot.EvidenceDigest || request.ConsumerSnapshot.NodeID != request.NodeID || request.ConsumerSnapshot.ServiceID != request.Target || request.ConsumerSnapshot.ObservedAt.After(request.CreatedAt) || request.CreatedAt.Sub(request.ConsumerSnapshot.ObservedAt) > 5*time.Minute {
			return LifecyclePlan{}, fmt.Errorf("%w: recent complete consumer snapshot required", ErrStale)
		}
		plan.ConsumerSnapshotGeneration = request.ConsumerSnapshot.Generation
		plan.ConsumerSnapshotDigest = request.ConsumerSnapshot.EvidenceDigest
	} else if request.ConsumerSnapshot.Generation != 0 || len(request.ConsumerSnapshot.Consumers) != 0 || request.ConsumerSnapshot.EvidenceDigest != "" {
		return LifecyclePlan{}, fmt.Errorf("%w: consumer snapshot is not used by this action", ErrInvalid)
	}
	for _, consumer := range request.ConsumerSnapshot.Consumers {
		if !validID(consumer.ID) || consumer.Kind == "" || consumer.EvidenceRef == "" {
			return LifecyclePlan{}, fmt.Errorf("%w: invalid consumer binding", ErrInvalid)
		}
		if consumer.ServiceID != "" {
			if _, known := r.definitions[consumer.ServiceID]; !known {
				return LifecyclePlan{}, fmt.Errorf("%w: unknown consumer service %s", ErrInvalid, consumer.ServiceID)
			}
		}
		if consumer.Active || request.Action == ActionRemove {
			plan.Consumers = append(plan.Consumers, consumer)
		}
	}

	if consumerAware {
		for _, consumerID := range r.consumersOf(request.Target) {
			observed, present := request.Observations[consumerID]
			if !present {
				return LifecyclePlan{}, fmt.Errorf("%w: registered consumer observation missing", ErrStale)
			}
			if observed.Active == ActiveActive || (request.Action == ActionRemove && observed.Install == InstallInstalled) {
				plan.Consumers = append(plan.Consumers, ConsumerBinding{
					ID:          "service:" + string(consumerID),
					ServiceID:   consumerID,
					Kind:        "registered_service",
					Active:      observed.Active == ActiveActive,
					EvidenceRef: observed.EvidenceDigest,
				})
			}
		}
		if disruptive && len(plan.Consumers) != 0 {
			return LifecyclePlan{}, fmt.Errorf("%w: %s has %d consumers", ErrConsumersPresent, request.Target, len(plan.Consumers))
		}
	}
	sort.Slice(plan.Consumers, func(i, j int) bool { return plan.Consumers[i].ID < plan.Consumers[j].ID })
	for i := 1; i < len(plan.Consumers); i++ {
		if plan.Consumers[i-1].ID == plan.Consumers[i].ID {
			return LifecyclePlan{}, fmt.Errorf("%w: duplicate effective consumer", ErrInvalid)
		}
	}

	appendStep := func(id ServiceID, action Action, reason string, irreversible bool) error {
		if len(plan.Steps) >= MaxPlanSteps {
			return fmt.Errorf("%w: plan step bound", ErrInvalid)
		}
		if !r.actionAllowed(id, action) {
			return fmt.Errorf("%w: %s on dependency %s", ErrUnsupported, action, id)
		}
		observed, present := request.Observations[id]
		if !present || observed.NodeID != request.NodeID {
			return fmt.Errorf("%w: missing observation for %s", ErrStale, id)
		}
		compensate := Action("")
		switch action {
		case ActionStart:
			compensate = ActionStop
		case ActionStop:
			compensate = ActionStart
		case ActionEnable:
			compensate = ActionDisable
		case ActionDisable:
			compensate = ActionEnable
		}
		step := PlanStep{
			Index:                      len(plan.Steps),
			ServiceID:                  id,
			Action:                     action,
			ExpectedObservedGeneration: observed.Generation,
			ExpectedConfigGeneration:   observed.ConfigGeneration,
			Compensate:                 compensate,
			Irreversible:               irreversible,
			Reason:                     reason,
		}
		if irreversible && plan.IrreversibleFrontier < 0 {
			plan.IrreversibleFrontier = step.Index
		}
		plan.Steps = append(plan.Steps, step)
		return nil
	}

	dependencyOrder, err := r.dependencyOrder(request.Target)
	if err != nil {
		return LifecyclePlan{}, err
	}
	switch request.Action {
	case ActionStart:
		for _, id := range dependencyOrder {
			observed, present := request.Observations[id]
			if !present || observed.Install != InstallInstalled {
				return LifecyclePlan{}, fmt.Errorf("%w: dependency %s is not installed", ErrStale, id)
			}
			if observed.Active != ActiveActive {
				if err := appendStep(id, ActionStart, "start target dependency in topological order", false); err != nil {
					return LifecyclePlan{}, err
				}
			}
		}
	case ActionEnable:
		for _, id := range dependencyOrder {
			observed, present := request.Observations[id]
			if !present || observed.Install != InstallInstalled {
				return LifecyclePlan{}, fmt.Errorf("%w: dependency %s is not installed", ErrStale, id)
			}
			if observed.Enable != EnableEnabled && observed.Enable != EnableStatic {
				if err := appendStep(id, ActionEnable, "enable target dependency in topological order", false); err != nil {
					return LifecyclePlan{}, err
				}
			}
		}
	case ActionInstall:
		for _, id := range dependencyOrder {
			observed, present := request.Observations[id]
			if !present {
				return LifecyclePlan{}, fmt.Errorf("%w: missing dependency observation %s", ErrStale, id)
			}
			if observed.Install != InstallInstalled {
				if err := appendStep(id, ActionInstall, "install exact registered dependency profile", true); err != nil {
					return LifecyclePlan{}, err
				}
			}
		}
	case ActionRemove:
		if targetObservation.Install == InstallAbsent {
			break
		}
		if targetObservation.Active != ActiveInactive {
			if err := appendStep(request.Target, ActionStop, "stop service before destructive removal", false); err != nil {
				return LifecyclePlan{}, err
			}
		}
		if targetObservation.Enable == EnableEnabled {
			if err := appendStep(request.Target, ActionDisable, "disable service before destructive removal", false); err != nil {
				return LifecyclePlan{}, err
			}
		}
		if err := appendStep(request.Target, ActionRemove, "remove exact registered package profile", true); err != nil {
			return LifecyclePlan{}, err
		}
	case ActionRestart, ActionReload:
		if targetObservation.Install != InstallInstalled || targetObservation.Active != ActiveActive {
			return LifecyclePlan{}, fmt.Errorf("%w: target is not active", ErrStale)
		}
		for _, dependency := range definition.Dependencies {
			observed, present := request.Observations[dependency]
			if !present || observed.Install != InstallInstalled || observed.Active != ActiveActive || !observed.InternallyHealthy {
				return LifecyclePlan{}, fmt.Errorf("%w: dependency %s is not ready", ErrStale, dependency)
			}
		}
		if err := appendStep(request.Target, request.Action, "operate only on selected service", false); err != nil {
			return LifecyclePlan{}, err
		}
	case ActionRepair:
		if targetObservation.Install != InstallInstalled {
			return LifecyclePlan{}, fmt.Errorf("%w: target is not installed", ErrStale)
		}
		for _, dependency := range definition.Dependencies {
			observed, present := request.Observations[dependency]
			if !present || observed.Install != InstallInstalled || observed.Active != ActiveActive || !observed.InternallyHealthy {
				return LifecyclePlan{}, fmt.Errorf("%w: dependency %s is not ready", ErrStale, dependency)
			}
		}
		if err := appendStep(request.Target, ActionRepair, "repair exact registered package profile", true); err != nil {
			return LifecyclePlan{}, err
		}
	case ActionStop:
		if targetObservation.Install == InstallInstalled && targetObservation.Active != ActiveInactive {
			if err := appendStep(request.Target, ActionStop, "stop only the selected service", false); err != nil {
				return LifecyclePlan{}, err
			}
		}
	case ActionDisable:
		if targetObservation.Install == InstallInstalled && targetObservation.Enable != EnableDisabled && targetObservation.Enable != EnableStatic && targetObservation.Enable != EnableMasked {
			if err := appendStep(request.Target, ActionDisable, "disable only the selected service", false); err != nil {
				return LifecyclePlan{}, err
			}
		}
	case ActionInspect:
		if err := appendStep(request.Target, ActionInspect, "inspect selected service", false); err != nil {
			return LifecyclePlan{}, err
		}
	default:
		return LifecyclePlan{}, fmt.Errorf("%w: unrecognized action", ErrUnsupported)
	}
	if len(plan.Steps) == 0 {
		if err := appendStep(request.Target, ActionInspect, "target already satisfies requested state", false); err != nil {
			return LifecyclePlan{}, err
		}
	}
	for _, step := range plan.Steps {
		relationship := "self"
		if step.ServiceID != request.Target {
			relationship = "dependency"
		}
		availability := "none"
		if step.Action == ActionStop || step.Action == ActionRestart || step.Action == ActionReload || step.Action == ActionRemove || step.Action == ActionRepair {
			availability = "bounded interruption"
		}
		plan.Impacts = append(plan.Impacts, Impact{
			ServiceID:       step.ServiceID,
			Relationship:    relationship,
			Availability:    availability,
			WorkloadRestart: step.Action == ActionRestart,
			Reason:          step.Reason,
		})
	}
	for _, consumer := range plan.Consumers {
		impactService := consumer.ServiceID
		if impactService == "" {
			impactService = request.Target
		}
		plan.Impacts = append(plan.Impacts, Impact{
			ServiceID:       impactService,
			ConsumerID:      consumer.ID,
			Relationship:    "consumer",
			Availability:    "bounded degradation",
			WorkloadRestart: false,
			Reason:          "active consumer may observe selected service interruption",
		})
	}
	plan.RequiresStepUp = request.Action != ActionInspect
	plan.RequiresMaintenance = request.Action == ActionStop || request.Action == ActionRestart || request.Action == ActionReload || request.Action == ActionInstall || request.Action == ActionRemove || request.Action == ActionRepair
	return SealPlan(plan)
}

func (r *Registry) ValidateExecutablePlan(plan LifecyclePlan, now time.Time) error {
	if err := ValidatePlan(plan); err != nil {
		return err
	}
	if plan.RegistryDigest != r.digest || plan.SupportDigest != r.supportDigest || now.Before(plan.CreatedAt) || !now.Before(plan.ExpiresAt) {
		return fmt.Errorf("%w: plan registry, support, or time binding", ErrStale)
	}
	if !r.actionAllowed(plan.Target, plan.Action) {
		return fmt.Errorf("%w: %s on %s", ErrUnsupported, plan.Action, plan.Target)
	}
	sealed, err := SealPlan(plan)
	if err != nil || sealed.Digest != plan.Digest {
		return fmt.Errorf("%w: plan digest", ErrStale)
	}
	for _, step := range plan.Steps {
		if !r.actionAllowed(step.ServiceID, step.Action) {
			return fmt.Errorf("%w: %s on %s", ErrUnsupported, step.Action, step.ServiceID)
		}
	}
	if err := r.validateStepOrder(plan); err != nil {
		return err
	}
	return nil
}

func (r *Registry) validateStepOrder(plan LifecyclePlan) error {
	if len(plan.Impacts) != len(plan.Steps)+len(plan.Consumers) {
		return fmt.Errorf("%w: plan impact cardinality", ErrInvalid)
	}
	expectedIrreversible := -1
	positions := make(map[ServiceID]int)
	for i, step := range plan.Steps {
		if _, duplicate := positions[step.ServiceID]; duplicate && plan.Action != ActionRemove {
			return fmt.Errorf("%w: repeated service step", ErrInvalid)
		}
		positions[step.ServiceID] = i
		shouldBeIrreversible := step.Action == ActionInstall || step.Action == ActionRemove || step.Action == ActionRepair
		if step.Irreversible != shouldBeIrreversible {
			return fmt.Errorf("%w: incorrect irreversible boundary", ErrInvalid)
		}
		if step.Irreversible && expectedIrreversible < 0 {
			expectedIrreversible = i
		}
		expectedCompensation := Action("")
		switch step.Action {
		case ActionStart:
			expectedCompensation = ActionStop
		case ActionStop:
			expectedCompensation = ActionStart
		case ActionEnable:
			expectedCompensation = ActionDisable
		case ActionDisable:
			expectedCompensation = ActionEnable
		}
		if step.Compensate != expectedCompensation {
			return fmt.Errorf("%w: invalid compensation action", ErrInvalid)
		}
		impact := plan.Impacts[i]
		if impact.ServiceID != step.ServiceID || impact.WorkloadRestart != (step.Action == ActionRestart) {
			return fmt.Errorf("%w: impact does not match step", ErrInvalid)
		}
	}
	for i, consumer := range plan.Consumers {
		impact := plan.Impacts[len(plan.Steps)+i]
		if impact.Relationship != "consumer" || impact.ConsumerID != consumer.ID || impact.WorkloadRestart {
			return fmt.Errorf("%w: consumer impact does not match snapshot", ErrInvalid)
		}
	}
	if plan.IrreversibleFrontier != expectedIrreversible {
		return fmt.Errorf("%w: irreversible frontier mismatch", ErrInvalid)
	}
	if (plan.Action == ActionStop || plan.Action == ActionRemove) && len(plan.Consumers) != 0 {
		return ErrConsumersPresent
	}
	if requiresConsumerSnapshot(plan.Action) && (plan.ConsumerSnapshotGeneration == 0 || plan.ConsumerSnapshotDigest == "") {
		return fmt.Errorf("%w: consumer snapshot binding missing", ErrInvalid)
	}
	if plan.RequiresStepUp != (plan.Action != ActionInspect) {
		return fmt.Errorf("%w: step-up boundary mismatch", ErrInvalid)
	}
	expectedMaintenance := plan.Action == ActionStop || plan.Action == ActionRestart || plan.Action == ActionReload || plan.Action == ActionInstall || plan.Action == ActionRemove || plan.Action == ActionRepair
	if plan.RequiresMaintenance != expectedMaintenance {
		return fmt.Errorf("%w: maintenance boundary mismatch", ErrInvalid)
	}
	if len(plan.Steps) == 1 && plan.Steps[0].Action == ActionInspect {
		if plan.Steps[0].ServiceID != plan.Target {
			return fmt.Errorf("%w: no-op inspection target mismatch", ErrInvalid)
		}
		return nil
	}
	switch plan.Action {
	case ActionStart, ActionEnable, ActionInstall:
		order, err := r.dependencyOrder(plan.Target)
		if err != nil {
			return err
		}
		allowed := make(map[ServiceID]bool, len(order))
		for _, id := range order {
			allowed[id] = true
		}
		for _, step := range plan.Steps {
			if !allowed[step.ServiceID] || step.Action != plan.Action {
				return fmt.Errorf("%w: step expands beyond dependency closure", ErrInvalid)
			}
			definition := r.definitions[step.ServiceID]
			for _, dependency := range definition.Dependencies {
				if dependencyPosition, included := positions[dependency]; included && dependencyPosition >= step.Index {
					return fmt.Errorf("%w: dependency follows consumer", ErrInvalid)
				}
			}
		}
		if _, included := positions[plan.Target]; !included {
			return fmt.Errorf("%w: target action missing", ErrInvalid)
		}
	case ActionRemove:
		if len(plan.Steps) > 3 || plan.Steps[len(plan.Steps)-1].Action != ActionRemove {
			return fmt.Errorf("%w: invalid removal order", ErrInvalid)
		}
		stage := 0
		for _, step := range plan.Steps {
			if step.ServiceID != plan.Target {
				return fmt.Errorf("%w: removal expands beyond target", ErrInvalid)
			}
			switch step.Action {
			case ActionStop:
				if stage != 0 {
					return fmt.Errorf("%w: invalid removal stop order", ErrInvalid)
				}
				stage = 1
			case ActionDisable:
				if stage > 1 {
					return fmt.Errorf("%w: invalid removal disable order", ErrInvalid)
				}
				stage = 2
			case ActionRemove:
				stage = 3
			default:
				return fmt.Errorf("%w: invalid removal step", ErrInvalid)
			}
		}
	default:
		if len(plan.Steps) != 1 || plan.Steps[0].ServiceID != plan.Target || plan.Steps[0].Action != plan.Action {
			return fmt.Errorf("%w: action expands beyond selected service", ErrInvalid)
		}
	}
	return nil
}
