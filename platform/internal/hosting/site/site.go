// Package site defines the immutable site aggregate and its closed lifecycle.
package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidTransition = errors.New("invalid site lifecycle transition")
	ErrStaleGeneration   = errors.New("stale site generation")
	ErrInvalidAggregate  = errors.New("invalid site aggregate")
	ErrDuplicateBinding  = errors.New("duplicate domain binding hostname")
	ErrSolePrimary       = errors.New("cannot detach the sole primary domain binding")
	ErrRedirectCycle     = errors.New("redirect binding cycle")
)

// SiteID identifies one site. Its representation is deliberately private.
type SiteID struct{ value string }

// TenantID identifies a site owner. Its representation is deliberately private.
type TenantID struct{ value string }

// ProjectID identifies the owning project. Its representation is deliberately private.
type ProjectID struct{ value string }

func NewSiteID(raw string) (SiteID, error) {
	value, err := parseIdentifier(raw)
	return SiteID{value: value}, err
}

func NewTenantID(raw string) (TenantID, error) {
	value, err := parseIdentifier(raw)
	return TenantID{value: value}, err
}

func NewProjectID(raw string) (ProjectID, error) {
	value, err := parseIdentifier(raw)
	return ProjectID{value: value}, err
}

func parseIdentifier(raw string) (string, error) {
	if raw == "" || len(raw) > 128 {
		return "", fmt.Errorf("identifier must contain 1 through 128 ASCII characters")
	}
	if !asciiLetterOrDigit(raw[0]) || !asciiLetterOrDigit(raw[len(raw)-1]) {
		return "", fmt.Errorf("identifier must start and end with an ASCII letter or digit")
	}
	for _, character := range raw {
		if character > 127 || !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return "", fmt.Errorf("identifier contains an unsafe character")
		}
	}
	return raw, nil
}

func asciiLetterOrDigit(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
}

// Hostname is a normalized ASCII fully-qualified domain name.
type Hostname struct{ value string }

func ParseHostname(raw string) (Hostname, error) {
	if raw == "" || strings.HasPrefix(raw, ".") {
		return Hostname{}, fmt.Errorf("hostname must be an ASCII FQDN")
	}
	if strings.HasSuffix(raw, ".") {
		raw = raw[:len(raw)-1]
	}
	if raw == "" || len(raw) > 253 || !strings.Contains(raw, ".") {
		return Hostname{}, fmt.Errorf("hostname must be an ASCII FQDN")
	}
	for _, label := range strings.Split(raw, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Hostname{}, fmt.Errorf("hostname contains an invalid label")
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-') {
				return Hostname{}, fmt.Errorf("hostname contains a non-ASCII DNS character")
			}
		}
	}
	return Hostname{value: strings.ToLower(raw)}, nil
}

func (hostname Hostname) String() string { return hostname.value }

func (id SiteID) MarshalJSON() ([]byte, error) { return json.Marshal(id.value) }
func (id *SiteID) UnmarshalJSON(data []byte) error { var raw string; if err := json.Unmarshal(data, &raw); err != nil { return err }; if raw == "" { *id = SiteID{}; return nil }; parsed, err := NewSiteID(raw); if err == nil { *id = parsed }; return err }
func (id TenantID) MarshalJSON() ([]byte, error) { return json.Marshal(id.value) }
func (id *TenantID) UnmarshalJSON(data []byte) error { var raw string; if err := json.Unmarshal(data, &raw); err != nil { return err }; if raw == "" { *id = TenantID{}; return nil }; parsed, err := NewTenantID(raw); if err == nil { *id = parsed }; return err }
func (id ProjectID) MarshalJSON() ([]byte, error) { return json.Marshal(id.value) }
func (id *ProjectID) UnmarshalJSON(data []byte) error { var raw string; if err := json.Unmarshal(data, &raw); err != nil { return err }; if raw == "" { *id = ProjectID{}; return nil }; parsed, err := NewProjectID(raw); if err == nil { *id = parsed }; return err }
func (hostname Hostname) MarshalJSON() ([]byte, error) { return json.Marshal(hostname.value) }
func (hostname *Hostname) UnmarshalJSON(data []byte) error { var raw string; if err := json.Unmarshal(data, &raw); err != nil { return err }; if raw == "" { *hostname = Hostname{}; return nil }; parsed, err := ParseHostname(raw); if err == nil { *hostname = parsed }; return err }

type Lifecycle string

const (
	LifecycleProvisioning Lifecycle = "provisioning"
	LifecycleActive       Lifecycle = "active"
	LifecycleDegraded     Lifecycle = "degraded"
	LifecycleSuspended    Lifecycle = "suspended"
	LifecycleDeleting     Lifecycle = "deleting"
	LifecycleQuarantined  Lifecycle = "quarantined"
	LifecyclePurging      Lifecycle = "purging"
	LifecycleDeleted      Lifecycle = "deleted"
)

type BindingKind string

const (
	BindingPrimary  BindingKind = "primary"
	BindingChild    BindingKind = "child"
	BindingAlias    BindingKind = "alias"
	BindingRedirect BindingKind = "redirect"
	BindingPreview  BindingKind = "preview"
)

type RedirectStatus string

const (
	RedirectStatusPermanent301 RedirectStatus = "permanent_301"
	RedirectStatusTemporary302 RedirectStatus = "temporary_302"
)

// PHPProfile is a closed product runtime selection, never a package name or
// executable path supplied by a caller.
type PHPProfile string

const (
	PHPProfile82 PHPProfile = "php82"
	PHPProfile83 PHPProfile = "php83"
	PHPProfile84 PHPProfile = "php84"
)

func ValidPHPProfile(profile PHPProfile) bool {
	return profile == PHPProfile82 || profile == PHPProfile83 || profile == PHPProfile84
}

// DomainBinding gives one hostname its site-local routing relationship.
type DomainBinding struct {
	Hostname       Hostname
	Kind           BindingKind
	RedirectTarget Hostname
	RedirectStatus RedirectStatus
}

type CreateInput struct {
	ID              SiteID
	TenantID        TenantID
	ProjectID       ProjectID
	PrimaryHostname Hostname
	PHPProfile      PHPProfile
}

// Site is an immutable value aggregate. Its accessors and mutators never expose
// or reuse mutable binding storage.
type Site struct {
	id               SiteID
	tenantID         TenantID
	projectID        ProjectID
	phpProfile       PHPProfile
	lifecycle        Lifecycle
	desiredLifecycle Lifecycle
	generation       uint64
	bindings         []DomainBinding
}

// Snapshot is the canonical, self-validating persistence representation of a
// Site. It exposes no mutable aggregate state to callers.
func (site Site) Snapshot() ([]byte, error) {
	if err := site.validate(); err != nil {
		return nil, err
	}
	bindings := make([]bindingSnapshot, 0, len(site.bindings))
	for _, binding := range site.bindings { bindings = append(bindings, bindingSnapshot{Hostname: binding.Hostname.String(), Kind: binding.Kind, RedirectTarget: binding.RedirectTarget.String(), RedirectStatus: binding.RedirectStatus}) }
	return json.Marshal(siteSnapshot{Version: 2, ID: site.id.value, TenantID: site.tenantID.value, ProjectID: site.projectID.value, PHPProfile: site.phpProfile,
		Lifecycle: site.lifecycle, DesiredLifecycle: site.desiredLifecycle, Generation: site.generation, Bindings: bindings})
}

// Restore reconstitutes a Site only from its canonical snapshot and repeats
// every aggregate invariant before returning it.
func Restore(snapshot []byte) (Site, error) {
	var stored siteSnapshot
	if err := json.Unmarshal(snapshot, &stored); err != nil || (stored.Version != 1 && stored.Version != 2) {
		return Site{}, ErrInvalidAggregate
	}
	id, err := NewSiteID(stored.ID); if err != nil { return Site{}, ErrInvalidAggregate }
	tenant, err := NewTenantID(stored.TenantID); if err != nil { return Site{}, ErrInvalidAggregate }
	project, err := NewProjectID(stored.ProjectID); if err != nil { return Site{}, ErrInvalidAggregate }
	bindings := make([]DomainBinding, 0, len(stored.Bindings))
	for _, binding := range stored.Bindings {
		hostname, err := ParseHostname(binding.Hostname); if err != nil { return Site{}, ErrInvalidAggregate }
		var target Hostname
		if binding.RedirectTarget != "" { target, err = ParseHostname(binding.RedirectTarget); if err != nil { return Site{}, ErrInvalidAggregate } }
		bindings = append(bindings, DomainBinding{Hostname: hostname, Kind: binding.Kind, RedirectTarget: target, RedirectStatus: binding.RedirectStatus})
	}
	profile := stored.PHPProfile
	if stored.Version == 1 && profile == "" { profile = PHPProfile83 }
	aggregate := Site{id: id, tenantID: tenant, projectID: project, phpProfile: profile, lifecycle: stored.Lifecycle, desiredLifecycle: stored.DesiredLifecycle,
		generation: stored.Generation, bindings: bindings}
	if err := aggregate.validate(); err != nil { return Site{}, err }
	return aggregate, nil
}

type siteSnapshot struct {
	Version          int             `json:"v"`
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	ProjectID        string          `json:"project_id"`
	PHPProfile       PHPProfile      `json:"php_profile,omitempty"`
	Lifecycle        Lifecycle       `json:"lifecycle"`
	DesiredLifecycle Lifecycle       `json:"desired_lifecycle"`
	Generation       uint64          `json:"generation"`
	Bindings         []bindingSnapshot `json:"bindings"`
}

type bindingSnapshot struct {
	Hostname string `json:"hostname"`
	Kind BindingKind `json:"kind"`
	RedirectTarget string `json:"redirect_target,omitempty"`
	RedirectStatus RedirectStatus `json:"redirect_status,omitempty"`
}

func Create(input CreateInput) (Site, error) {
	if input.ID.value == "" || input.TenantID.value == "" || input.ProjectID.value == "" || input.PrimaryHostname.value == "" || !ValidPHPProfile(input.PHPProfile) {
		return Site{}, fmt.Errorf("site identity and primary hostname are required")
	}
	return Site{
		id:               input.ID,
		tenantID:         input.TenantID,
		projectID:        input.ProjectID,
		phpProfile:       input.PHPProfile,
		lifecycle:        LifecycleProvisioning,
		desiredLifecycle: LifecycleActive,
		generation:       1,
		bindings: []DomainBinding{{
			Hostname: input.PrimaryHostname,
			Kind:     BindingPrimary,
		}},
	}, nil
}

func (site Site) ID() SiteID                  { return site.id }
func (site Site) TenantID() TenantID          { return site.tenantID }
func (site Site) ProjectID() ProjectID        { return site.projectID }
func (site Site) PHPProfile() PHPProfile      { return site.phpProfile }
func (site Site) Lifecycle() Lifecycle        { return site.lifecycle }
func (site Site) DesiredLifecycle() Lifecycle { return site.desiredLifecycle }
func (site Site) Generation() uint64          { return site.generation }

// String returns the validated canonical identifier value.
func (id SiteID) String() string { return id.value }

// String returns the validated canonical identifier value.
func (id TenantID) String() string { return id.value }

// String returns the validated canonical identifier value.
func (id ProjectID) String() string { return id.value }

func (site Site) Bindings() []DomainBinding {
	return append([]DomainBinding(nil), site.bindings...)
}

func (site Site) Transition(expectedGeneration uint64, next Lifecycle) (Site, error) {
	if expectedGeneration != site.generation {
		return Site{}, ErrStaleGeneration
	}
	if err := site.validate(); err != nil {
		return Site{}, err
	}
	if !allowedTransition(site.lifecycle, next) {
		return Site{}, ErrInvalidTransition
	}
	nextSite := site.nextGeneration()
	nextSite.lifecycle = next
	return nextSite, nil
}

func allowedTransition(current, next Lifecycle) bool {
	switch current {
	case LifecycleProvisioning:
		return next == LifecycleActive || next == LifecycleDegraded
	case LifecycleActive:
		return next == LifecycleSuspended || next == LifecycleDegraded || next == LifecycleDeleting
	case LifecycleSuspended:
		return next == LifecycleActive || next == LifecycleDeleting
	case LifecycleDegraded:
		return next == LifecycleActive
	case LifecycleDeleting:
		return next == LifecycleQuarantined
	case LifecycleQuarantined:
		return next == LifecycleActive || next == LifecyclePurging
	case LifecyclePurging:
		return next == LifecycleDeleted
	default:
		return false
	}
}

func (site Site) AttachBinding(expectedGeneration uint64, binding DomainBinding) (Site, error) {
	if expectedGeneration != site.generation {
		return Site{}, ErrStaleGeneration
	}
	if err := site.validate(); err != nil {
		return Site{}, err
	}
	if err := validateDomainBinding(binding); err != nil {
		return Site{}, err
	}
	for _, existing := range site.bindings {
		if existing.Hostname == binding.Hostname {
			return Site{}, ErrDuplicateBinding
		}
		if binding.Kind == BindingPrimary && existing.Kind == BindingPrimary {
			return Site{}, fmt.Errorf("site already has a primary domain binding")
		}
	}
	prospectiveBindings := append([]DomainBinding(nil), site.bindings...)
	prospectiveBindings = append(prospectiveBindings, binding)
	if hasRedirectCycle(prospectiveBindings) {
		return Site{}, ErrRedirectCycle
	}
	nextSite := site.nextGeneration()
	nextSite.bindings = append(nextSite.bindings, binding)
	return nextSite, nil
}

func (site Site) DetachBinding(expectedGeneration uint64, hostname Hostname) (Site, error) {
	if expectedGeneration != site.generation {
		return Site{}, ErrStaleGeneration
	}
	if err := site.validate(); err != nil {
		return Site{}, err
	}
	for index, binding := range site.bindings {
		if binding.Hostname != hostname {
			continue
		}
		if binding.Kind == BindingPrimary {
			return Site{}, ErrSolePrimary
		}
		nextSite := site.nextGeneration()
		nextSite.bindings = append(nextSite.bindings[:index:index], nextSite.bindings[index+1:]...)
		return nextSite, nil
	}
	return Site{}, fmt.Errorf("domain binding not found")
}

func validBindingKind(kind BindingKind) bool {
	return kind == BindingPrimary || kind == BindingChild || kind == BindingAlias || kind == BindingRedirect || kind == BindingPreview
}

func validateDomainBinding(binding DomainBinding) error {
	if binding.Hostname.value == "" || !validBindingKind(binding.Kind) {
		return fmt.Errorf("invalid domain binding")
	}
	if binding.Kind == BindingRedirect {
		if binding.RedirectTarget.value == "" || !validRedirectStatus(binding.RedirectStatus) {
			return fmt.Errorf("redirect binding requires a target and supported status")
		}
		if binding.RedirectTarget == binding.Hostname {
			return ErrRedirectCycle
		}
		return nil
	}
	if binding.RedirectTarget != (Hostname{}) || binding.RedirectStatus != "" {
		return fmt.Errorf("non-redirect binding cannot contain redirect metadata")
	}
	return nil
}

func validRedirectStatus(status RedirectStatus) bool {
	return status == RedirectStatusPermanent301 || status == RedirectStatusTemporary302
}

func (site Site) validate() error {
	if site.id.value == "" || site.tenantID.value == "" || site.projectID.value == "" || !ValidPHPProfile(site.phpProfile) || site.generation == 0 || !validLifecycle(site.lifecycle) || site.desiredLifecycle != LifecycleActive || len(site.bindings) == 0 {
		return ErrInvalidAggregate
	}
	primaryCount := 0
	seenHostnames := make(map[Hostname]struct{}, len(site.bindings))
	for _, binding := range site.bindings {
		if err := validateDomainBinding(binding); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidAggregate, err)
		}
		if _, exists := seenHostnames[binding.Hostname]; exists {
			return fmt.Errorf("%w: duplicate binding hostname", ErrInvalidAggregate)
		}
		seenHostnames[binding.Hostname] = struct{}{}
		if binding.Kind == BindingPrimary {
			primaryCount++
		}
	}
	if primaryCount != 1 {
		return fmt.Errorf("%w: site must have exactly one primary binding", ErrInvalidAggregate)
	}
	if hasRedirectCycle(site.bindings) {
		return fmt.Errorf("%w: %v", ErrInvalidAggregate, ErrRedirectCycle)
	}
	return nil
}

func hasRedirectCycle(bindings []DomainBinding) bool {
	edges := make(map[Hostname]Hostname)
	for _, binding := range bindings {
		if binding.Kind == BindingRedirect {
			edges[binding.Hostname] = binding.RedirectTarget
		}
	}
	const (
		visiting = 1
		visited  = 2
	)
	marks := make(map[Hostname]uint8, len(edges))
	var visit func(Hostname) bool
	visit = func(hostname Hostname) bool {
		switch marks[hostname] {
		case visiting:
			return true
		case visited:
			return false
		}
		target, exists := edges[hostname]
		if !exists {
			return false
		}
		marks[hostname] = visiting
		if visit(target) {
			return true
		}
		marks[hostname] = visited
		return false
	}
	for hostname := range edges {
		if visit(hostname) {
			return true
		}
	}
	return false
}

func validLifecycle(lifecycle Lifecycle) bool {
	switch lifecycle {
	case LifecycleProvisioning, LifecycleActive, LifecycleDegraded, LifecycleSuspended, LifecycleDeleting, LifecycleQuarantined, LifecyclePurging, LifecycleDeleted:
		return true
	default:
		return false
	}
}

func (site Site) nextGeneration() Site {
	nextSite := site
	nextSite.generation++
	nextSite.bindings = append([]DomainBinding(nil), site.bindings...)
	return nextSite
}
