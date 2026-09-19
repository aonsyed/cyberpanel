package integrations

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// HermesDefinition binds the one-click Hermes product to a signed, digest-
// pinned container recipe. Tenant requests cannot supply Compose or image tags.
type HermesDefinition struct {
	RecipeID            ID           `json:"recipe_id"`
	RecipeDigest        string       `json:"recipe_digest"`
	RecipeSignature     string       `json:"recipe_signature"`
	SigningKeyID        string       `json:"signing_key_id"`
	CatalogEpoch        uint64       `json:"catalog_epoch"`
	Version             string       `json:"version"`
	Image               OCIReference `json:"image"`
	ResolvedImageDigest string       `json:"resolved_image_digest"`
	Architectures       []string     `json:"architectures"`
	InternalPort        uint16       `json:"internal_port"`
	MinimumMemory       uint64       `json:"minimum_memory"`
	MinimumCPU          uint32       `json:"minimum_cpu"`
	DefinitionDigest    string       `json:"definition_digest"`
}

func (definition HermesDefinition) Validate() error {
	if !validID(string(definition.RecipeID)) || !validDigest(definition.RecipeDigest) || definition.RecipeSignature == "" || !validID(definition.SigningKeyID) || definition.CatalogEpoch == 0 || definition.Version == "" || definition.Image.Validate() != nil || !validDigest(definition.ResolvedImageDigest) || len(definition.Architectures) == 0 || len(definition.Architectures) > 2 || definition.InternalPort != 9119 || definition.MinimumMemory < 2<<30 || definition.MinimumCPU == 0 || !validDigest(definition.DefinitionDigest) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, architecture := range definition.Architectures {
		if architecture != "amd64" && architecture != "arm64" && architecture != "linux/amd64" && architecture != "linux/arm64" || seen[architecture] {
			return ErrInvalid
		}
		seen[architecture] = true
	}
	return nil
}

type HermesInstallation struct {
	ID                     ID               `json:"id"`
	TenantID               TenantID         `json:"tenant_id"`
	SiteID                 string           `json:"site_id"`
	Definition             HermesDefinition `json:"definition"`
	DashboardUsernameRef   SecretRef        `json:"dashboard_username_ref"`
	DashboardPasswordRef   SecretRef        `json:"dashboard_password_ref"`
	DashboardSessionRef    SecretRef        `json:"dashboard_session_ref"`
	VolumeID               string           `json:"volume_id"`
	ResourceProfileID      string           `json:"resource_profile_id"`
	PrivateServiceBinding  string           `json:"private_service_binding"`
	PublicRouteBinding     string           `json:"public_route_binding"`
	State                  string           `json:"state"`
	Generation             uint64           `json:"generation"`
	CreatedAt              time.Time        `json:"created_at"`
	UpdatedAt              time.Time        `json:"updated_at"`
}

func (installation HermesInstallation) Validate() error {
	if !validID(string(installation.ID)) || !validID(string(installation.TenantID)) || !validID(installation.SiteID) || installation.Definition.Validate() != nil || !validID(string(installation.DashboardUsernameRef)) || !validID(string(installation.DashboardPasswordRef)) || !validID(string(installation.DashboardSessionRef)) || !validID(installation.VolumeID) || !validID(installation.ResourceProfileID) || installation.PrivateServiceBinding == "" || installation.PublicRouteBinding == "" || installation.Generation == 0 || installation.CreatedAt.IsZero() || installation.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	if installation.State != "" {
		switch installation.State {
		case "reconciling", "active", "starting", "degraded", "suspended", "removed":
		default:
			return ErrInvalid
		}
	}
	return nil
}

type HermesWorkloadIntent struct {
	InstallationID       ID       `json:"installation_id"`
	Action               string   `json:"action"`
	ExpectedGeneration   uint64   `json:"expected_generation"`
	ImageDigest          string   `json:"image_digest"`
	SecretGrantRefs      []string `json:"secret_grant_refs"`
	VolumeID             string   `json:"volume_id"`
	ResourceProfileID    string   `json:"resource_profile_id"`
	InternalPort         uint16   `json:"internal_port"`
	PrivateServiceBinding string  `json:"private_service_binding"`
}

func (intent HermesWorkloadIntent) Validate() error {
	if !validID(string(intent.InstallationID)) || intent.ExpectedGeneration == 0 || !validDigest(intent.ImageDigest) || len(intent.SecretGrantRefs) != 3 || !validID(intent.VolumeID) || !validID(intent.ResourceProfileID) || intent.InternalPort != 9119 || intent.PrivateServiceBinding == "" {
		return ErrInvalid
	}
	for _, reference := range intent.SecretGrantRefs {
		if !validID(reference) {
			return ErrInvalid
		}
	}
	switch intent.Action {
	case "install", "update", "suspend", "resume", "remove":
		return nil
	default:
		return ErrUnsupported
	}
}

type HermesReceipt struct {
	State              string    `json:"state"`
	InstallationID     ID        `json:"installation_id"`
	Action             string    `json:"action"`
	ObservedGeneration uint64    `json:"observed_generation"`
	ImageDigest        string    `json:"image_digest"`
	WorkloadDigest     string    `json:"workload_digest"`
	PrivateEndpoint    string    `json:"private_endpoint"`
	HealthDigest       string    `json:"health_digest"`
	Receipt            string    `json:"receipt"`
	CompletedAt        time.Time `json:"completed_at"`
}

type HermesContainerFederation interface {
	ApplyHermesIntent(context.Context, HermesWorkloadIntent) (HermesReceipt, error)
	ObserveHermes(context.Context, ID) (HermesReceipt, error)
}

type HermesStore interface {
	SaveHermesInstallation(context.Context, HermesInstallation, uint64) error
	LoadHermesInstallation(context.Context, ID) (HermesInstallation, error)
}

type HermesCoordinator struct {
	Federation HermesContainerFederation
	Store      HermesStore
}

func (coordinator HermesCoordinator) Apply(ctx context.Context, installation HermesInstallation, action string) (HermesReceipt, error) {
	if coordinator.Federation == nil || coordinator.Store == nil {
		return HermesReceipt{}, ErrInvalid
	}
	if err := installation.Validate(); err != nil {
		return HermesReceipt{}, err
	}
	expected := uint64(0)
	if action != "install" {
		persisted, err := coordinator.Store.LoadHermesInstallation(ctx, installation.ID)
		if err != nil {
			return HermesReceipt{}, err
		}
		if persisted.TenantID != installation.TenantID {
			return HermesReceipt{}, ErrNotFound
		}
		if persisted.Generation != installation.Generation {
			return HermesReceipt{}, ErrStaleGeneration
		}
		expected = persisted.Generation
	} else if _, err := coordinator.Store.LoadHermesInstallation(ctx, installation.ID); err == nil {
		return HermesReceipt{}, ErrStaleGeneration
	} else if !errors.Is(err, ErrNotFound) {
		return HermesReceipt{}, err
	}
	intent := HermesWorkloadIntent{
		InstallationID:       installation.ID,
		Action:               action,
		ExpectedGeneration:   installation.Generation,
		ImageDigest:          installation.Definition.ResolvedImageDigest,
		SecretGrantRefs:      []string{string(installation.DashboardUsernameRef), string(installation.DashboardPasswordRef), string(installation.DashboardSessionRef)},
		VolumeID:             installation.VolumeID,
		ResourceProfileID:    installation.ResourceProfileID,
		InternalPort:         9119,
		PrivateServiceBinding: installation.PrivateServiceBinding,
	}
	if err := intent.Validate(); err != nil {
		return HermesReceipt{}, err
	}
	installation.State = "reconciling"
	installation.Generation = expected + 1
	installation.UpdatedAt = time.Now().UTC()
	if err := coordinator.Store.SaveHermesInstallation(ctx, installation, expected); err != nil {
		return HermesReceipt{}, err
	}
	receipt, err := coordinator.Federation.ApplyHermesIntent(ctx, intent)
	if err != nil {
		return HermesReceipt{}, err
	}
	if receipt.InstallationID != installation.ID || receipt.Action != action || receipt.ImageDigest != installation.Definition.ResolvedImageDigest || !validDigest(receipt.WorkloadDigest) || !validDigest(receipt.HealthDigest) || receipt.Receipt == "" || receipt.CompletedAt.IsZero() {
		return HermesReceipt{}, fmt.Errorf("%w: hermes receipt", ErrIntegrity)
	}
	switch receipt.State {
	case "active", "starting", "degraded", "suspended", "removed":
	default:
		return HermesReceipt{}, ErrIntegrity
	}
	expected = installation.Generation
	installation.Generation++
	installation.State = receipt.State
	installation.UpdatedAt = receipt.CompletedAt
	receipt.ObservedGeneration = installation.Generation
	if err := coordinator.Store.SaveHermesInstallation(ctx, installation, expected); err != nil {
		return HermesReceipt{}, err
	}
	return receipt, nil
}
