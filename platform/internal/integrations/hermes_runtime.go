package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/containers"
)

// HermesRuntime connects the certified Hermes recipe to the local rootless
// container broker. Standalone admission never depends on a central service.
type HermesRuntime struct {
	Applications  *containers.ApplicationService
	Containers    *containers.Service
	Repository    containers.Repository
	Store         HermesStore
	Verifier      containers.RecipeVerifier
	Allocator     containers.IDAllocator
	AuthorizeSite func(context.Context, string, string) error
}

var ErrHermesRecipeUnavailable = errors.New("hermes signed recipe unavailable")
var ErrHermesRecipeTrust = errors.New("hermes release trust rejected")

func (service *HermesRuntime) Apply(ctx context.Context, meta containers.CommandMeta, installation HermesInstallation, action string) (HermesReceipt, error) {
	if service == nil || service.Applications == nil || service.Containers == nil || service.Repository == nil || service.Store == nil || service.Verifier == nil || service.Allocator == nil || service.AuthorizeSite == nil {
		return HermesReceipt{}, ErrInvalid
	}
	switch action {
	case "install", "update", "suspend", "resume", "remove":
	default:
		return HermesReceipt{}, ErrUnsupported
	}
	if string(installation.TenantID) != meta.Grant.TenantID.String() {
		return HermesReceipt{}, ErrNotFound
	}
	if action == "install" {
		if meta.ExpectedGeneration != 0 {
			return HermesReceipt{}, ErrStaleGeneration
		}
		if err := service.AuthorizeSite(ctx, string(installation.TenantID), installation.SiteID); err != nil {
			return HermesReceipt{}, err
		}
		now := time.Now().UTC()
		installation.Generation = 1
		installation.CreatedAt, installation.UpdatedAt = now, now
	} else {
		current, err := service.Store.LoadHermesInstallation(ctx, installation.ID)
		if err != nil {
			return HermesReceipt{}, err
		}
		if current.TenantID != installation.TenantID {
			return HermesReceipt{}, ErrNotFound
		}
		if current.Generation != meta.ExpectedGeneration {
			return HermesReceipt{}, ErrStaleGeneration
		}
		if err = service.AuthorizeSite(ctx, string(current.TenantID), current.SiteID); err != nil {
			return HermesReceipt{}, err
		}
		if current.State == "removed" {
			return HermesReceipt{}, fmt.Errorf("%w: installation removed", ErrInvalid)
		}
		if action == "update" {
			if current.State != "active" && current.State != "starting" {
				return HermesReceipt{}, fmt.Errorf("%w: update requires reconciled installation", ErrInvalid)
			}
			current.Definition = installation.Definition
		}
		installation = current
	}
	if err := installation.Definition.Validate(); err != nil {
		return HermesReceipt{}, err
	}
	if _, err := hermesPublicURL(installation.PublicRouteBinding); err != nil {
		return HermesReceipt{}, err
	}
	recipeID, err := containers.NewID(string(installation.Definition.RecipeID))
	if err != nil {
		return HermesReceipt{}, err
	}
	recipe, err := service.Repository.Recipe(ctx, recipeID, installation.Definition.Version)
	if err != nil {
		return HermesReceipt{}, fmt.Errorf("%w: %s/%s: %v", ErrHermesRecipeUnavailable, recipeID, installation.Definition.Version, err)
	}
	if err = service.Verifier.Verify(ctx, recipe); err != nil {
		return HermesReceipt{}, fmt.Errorf("%w: %v", ErrHermesRecipeTrust, err)
	}
	if err = validateHermesRecipe(recipe, installation); err != nil {
		return HermesReceipt{}, err
	}
	applicationID, err := containers.NewID(string(installation.ID))
	if err != nil {
		return HermesReceipt{}, err
	}
	volumeID, err := service.Allocator.For(ctx, applicationID, "volume", "hermes_data")
	if err != nil {
		return HermesReceipt{}, err
	}
	installation.VolumeID, installation.ResourceProfileID = volumeID.String(), recipe.ID.String()
	if err = installation.Validate(); err != nil {
		return HermesReceipt{}, err
	}
	federation := &localHermesFederation{service: service, meta: meta, installation: installation, recipe: recipe}
	return (HermesCoordinator{Federation: federation, Store: service.Store}).Apply(ctx, installation, action)
}

func (service *HermesRuntime) Observe(ctx context.Context, meta containers.CommandMeta, id ID) (HermesReceipt, error) {
	if service == nil || service.Store == nil || service.AuthorizeSite == nil {
		return HermesReceipt{}, ErrInvalid
	}
	installation, err := service.Store.LoadHermesInstallation(ctx, id)
	if err != nil {
		return HermesReceipt{}, err
	}
	if string(installation.TenantID) != meta.Grant.TenantID.String() {
		return HermesReceipt{}, ErrNotFound
	}
	if err = service.AuthorizeSite(ctx, string(installation.TenantID), installation.SiteID); err != nil {
		return HermesReceipt{}, err
	}
	federation := &localHermesFederation{service: service, meta: meta, installation: installation}
	return federation.ObserveHermes(ctx, id)
}

func hermesSecretBindings(installation HermesInstallation) map[string]string {
	return map[string]string{
		"secret_hermes_username": string(installation.DashboardUsernameRef),
		"secret_hermes_password": string(installation.DashboardPasswordRef),
		"secret_hermes_session":  string(installation.DashboardSessionRef),
	}
}

func hermesValueBindings(installation HermesInstallation) (map[string]string, error) {
	publicURL, err := hermesPublicURL(installation.PublicRouteBinding)
	if err != nil {
		return nil, err
	}
	return map[string]string{"binding_hermes_public_url": publicURL}, nil
}

func hermesPublicURL(domain string) (string, error) {
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, "/@ \t\r\n") {
		return "", ErrInvalid
	}
	publicURL := "https://" + domain
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != domain || parsed.Hostname() == "" || parsed.Port() != "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrInvalid
	}
	return publicURL, nil
}

// ValidateHermesApplicationRecipe is shared by release assembly, installer
// admission, and runtime deployment. Dynamic data is limited to declared slots.
func ValidateHermesApplicationRecipe(recipe containers.ApplicationRecipe) error {
	if recipe.Name != "hermes" || len(recipe.Workloads) != 1 || len(recipe.Volumes) != 1 || len(recipe.Networks) != 1 {
		return ErrInvalid
	}
	volume := recipe.Volumes[0]
	if volume.Name != "hermes_data" || volume.MountTarget != "/opt/data" || volume.QuotaBytes == 0 || volume.InodeLimit == 0 || !volume.Backup {
		return fmt.Errorf("%w: one backed-up hermes data volume is required", ErrInvalid)
	}
	network := recipe.Networks[0]
	if network.Name == "" || !network.Internal {
		return fmt.Errorf("%w: hermes network must be private", ErrInvalid)
	}
	workload := recipe.Workloads[0]
	if workload.Name != "gateway" || len(workload.DependsOn) != 0 || workload.RoutePortName != "dashboard" || workload.Spec.Validate(containers.TierTenantRootless) != nil {
		return ErrInvalid
	}
	if workload.Spec.Image.Registry != "docker.io" && workload.Spec.Image.Registry != "registry-1.docker.io" || workload.Spec.Image.Repository != "nousresearch/hermes-agent" {
		return fmt.Errorf("%w: Hermes must use the official image repository", ErrInvalid)
	}
	if len(workload.Spec.Arguments) != 2 || workload.Spec.Arguments[0] != "gateway" || workload.Spec.Arguments[1] != "run" || len(workload.Spec.Volumes) != 1 || len(workload.Spec.Networks) != 1 || !workload.Spec.Security.ReadOnlyRoot || !workload.Spec.Security.AllowPublicEgress || workload.Spec.Limits.MemoryMaxBytes < 2<<30 {
		return ErrInvalid
	}
	mount := workload.Spec.Volumes[0]
	if strings.TrimPrefix(mount.VolumeID.String(), "vol_") != volume.Name || mount.Target != "/opt/data" || mount.ReadOnly {
		return ErrInvalid
	}
	attachment := workload.Spec.Networks[0]
	if strings.TrimPrefix(attachment.NetworkID.String(), "net_") != network.Name {
		return ErrInvalid
	}
	if workload.Spec.Health.Kind != "tcp" || workload.Spec.Health.PortName != "dashboard" {
		return fmt.Errorf("%w: hermes dashboard health contract missing", ErrInvalid)
	}
	portFound := false
	for _, port := range workload.Spec.Ports {
		if port.Name == "dashboard" && port.ContainerPort == 9119 && port.Protocol == containers.ProtocolTCP {
			portFound = true
		}
	}
	if !portFound || len(workload.Spec.Ports) != 1 {
		return ErrInvalid
	}
	expectedValues := map[string]string{
		"HERMES_DASHBOARD":            "1",
		"HERMES_DASHBOARD_HOST":       "0.0.0.0",
		"HERMES_DASHBOARD_PORT":       "9119",
		"HERMES_DASHBOARD_PUBLIC_URL": "binding_hermes_public_url",
	}
	expectedSecrets := map[string]string{
		"HERMES_DASHBOARD_BASIC_AUTH_USERNAME": "secret_hermes_username",
		"HERMES_DASHBOARD_BASIC_AUTH_PASSWORD": "secret_hermes_password",
		"HERMES_DASHBOARD_BASIC_AUTH_SECRET":   "secret_hermes_session",
	}
	seen := map[string]bool{}
	for _, entry := range workload.Spec.Environment {
		if seen[entry.Name] {
			return ErrInvalid
		}
		seen[entry.Name] = true
		if value, ok := expectedValues[entry.Name]; ok {
			if entry.Value != value || entry.SecretRef != "" {
				return ErrInvalid
			}
			continue
		}
		if reference, ok := expectedSecrets[entry.Name]; ok {
			if entry.SecretRef != reference || entry.Value != "" {
				return ErrInvalid
			}
			continue
		}
		return fmt.Errorf("%w: undeclared hermes environment", ErrInvalid)
	}
	if len(seen) != len(expectedValues)+len(expectedSecrets) {
		return ErrInvalid
	}
	return nil
}

func validateHermesRecipe(recipe containers.ApplicationRecipe, installation HermesInstallation) error {
	if err := ValidateHermesApplicationRecipe(recipe); err != nil {
		return err
	}
	definition := installation.Definition
	if recipe.ID.String() != string(definition.RecipeID) || recipe.Version != definition.Version || recipe.Digest != definition.RecipeDigest || recipe.Signature != definition.RecipeSignature || recipe.SigningKeyID != definition.SigningKeyID || recipe.Digest != definition.DefinitionDigest {
		return fmt.Errorf("%w: hermes definition does not match the signed recipe", ErrIntegrity)
	}
	compatible := false
	for _, architecture := range definition.Architectures {
		if architecture == runtime.GOARCH || architecture == "linux/"+runtime.GOARCH {
			compatible = true
		}
	}
	if !compatible {
		return fmt.Errorf("%w: hermes definition excludes node architecture", ErrUnsupported)
	}
	workload := recipe.Workloads[0]
	if workload.Spec.Image.Platform != "linux/"+runtime.GOARCH {
		return fmt.Errorf("%w: signed hermes workload architecture differs from node", ErrUnsupported)
	}
	if workload.Spec.Image.Digest != "sha256:"+definition.ResolvedImageDigest || workload.Spec.Image.Registry != definition.Image.Registry || workload.Spec.Image.Repository != definition.Image.Repository {
		return fmt.Errorf("%w: hermes workload image differs from signed definition", ErrIntegrity)
	}
	if workload.Spec.Limits.MemoryMaxBytes < definition.MinimumMemory || workload.Spec.Limits.CPUQuotaMicros < uint64(definition.MinimumCPU) {
		return ErrInvalid
	}
	return nil
}

type localHermesFederation struct {
	service      *HermesRuntime
	meta         containers.CommandMeta
	installation HermesInstallation
	recipe       containers.ApplicationRecipe
}

func (federation *localHermesFederation) metaFor(operation string, id containers.ID, generation uint64) containers.CommandMeta {
	meta := federation.meta
	meta.CommandID = "hermes-" + hermesDigest(struct {
		Parent, Operation, Resource string
		Generation                  uint64
	}{meta.CommandID, operation, id.String(), generation})[:48]
	meta.Grant.Operation, meta.Grant.ResourceID = operation, id
	meta.Grant.Digest = hermesDigest(struct{ Parent, Operation, Resource string }{meta.CommandID, operation, id.String()})
	meta.ExpectedGeneration, meta.Fence = generation, containers.FenceToken(generation+1)
	return meta
}

func (federation *localHermesFederation) ApplyHermesIntent(ctx context.Context, intent HermesWorkloadIntent) (HermesReceipt, error) {
	if err := intent.Validate(); err != nil {
		return HermesReceipt{}, err
	}
	installation := federation.installation
	if intent.InstallationID != installation.ID || intent.ImageDigest != installation.Definition.ResolvedImageDigest {
		return HermesReceipt{}, ErrIntegrity
	}
	id, err := containers.NewID(string(installation.ID))
	if err != nil {
		return HermesReceipt{}, err
	}
	tenant := federation.meta.Grant.TenantID
	valueBindings, err := hermesValueBindings(installation)
	if err != nil {
		return HermesReceipt{}, err
	}
	var application containers.ContainerApplication
	switch intent.Action {
	case "install":
		siteID, conversionErr := containers.NewID(installation.SiteID)
		if conversionErr != nil {
			return HermesReceipt{}, conversionErr
		}
		application, _, err = federation.service.Applications.Deploy(ctx, containers.DeployApplicationCommand{Meta: federation.metaFor("application.deploy", id, 0), ApplicationID: id, SiteID: siteID, RecipeID: federation.recipe.ID, RecipeVersion: federation.recipe.Version, SecretBindings: hermesSecretBindings(installation), ValueBindings: valueBindings})
	case "update":
		current, loadErr := federation.service.Repository.Application(ctx, tenant, id)
		if loadErr != nil {
			return HermesReceipt{}, loadErr
		}
		application, _, err = federation.service.Applications.Update(ctx, containers.UpdateApplicationCommand{Meta: federation.metaFor("application.deploy", id, current.ActiveGeneration), ApplicationID: id, RecipeID: federation.recipe.ID, RecipeVersion: federation.recipe.Version, SecretBindings: hermesSecretBindings(installation), ValueBindings: valueBindings})
	case "suspend", "resume", "remove":
		application, err = federation.service.Repository.Application(ctx, tenant, id)
		if err != nil {
			return HermesReceipt{}, err
		}
		if intent.Action != "resume" {
			if err = federation.withdraw(ctx, id); err != nil {
				return HermesReceipt{}, err
			}
		}
		for _, workloadID := range application.WorkloadIDs {
			workload, loadErr := federation.service.Repository.Workload(ctx, tenant, workloadID)
			if loadErr != nil {
				return HermesReceipt{}, loadErr
			}
			lifecycle := containers.LifecycleStopped
			if intent.Action == "resume" {
				lifecycle = containers.LifecycleRunning
			} else if intent.Action == "remove" {
				lifecycle = containers.LifecycleDeleting
			}
			if workload.ObservedLifecycle == containers.LifecycleDeleted && intent.Action == "remove" {
				continue
			}
			_, _, err = federation.service.Containers.SetLifecycle(ctx, containers.LifecycleCommand{Meta: federation.metaFor("workload.lifecycle", workloadID, workload.Generation), WorkloadID: workloadID, Lifecycle: lifecycle})
			if err != nil {
				return HermesReceipt{}, err
			}
		}
	default:
		return HermesReceipt{}, ErrUnsupported
	}
	if err != nil {
		return HermesReceipt{}, err
	}
	if intent.Action == "install" || intent.Action == "resume" || intent.Action == "update" {
		if err = federation.expose(ctx, application); err != nil {
			return HermesReceipt{}, err
		}
	}
	receipt, err := federation.ObserveHermes(ctx, installation.ID)
	if err != nil {
		return HermesReceipt{}, err
	}
	receipt.Action = intent.Action
	if intent.Action == "suspend" && receipt.State != "suspended" || intent.Action == "remove" && receipt.State != "removed" {
		return HermesReceipt{}, fmt.Errorf("%w: hermes lifecycle observation does not confirm request", ErrIntegrity)
	}
	return receipt, nil
}

func (federation *localHermesFederation) exposureID(ctx context.Context, id containers.ID) (containers.ID, error) {
	return federation.service.Allocator.For(ctx, id, "exposure", "hermes")
}

func (federation *localHermesFederation) withdraw(ctx context.Context, id containers.ID) error {
	exposureID, err := federation.exposureID(ctx, id)
	if err != nil {
		return err
	}
	exposure, err := federation.service.Repository.Exposure(ctx, federation.meta.Grant.TenantID, exposureID)
	if errors.Is(err, containers.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if exposure.State == "deleted" {
		return nil
	}
	_, _, err = federation.service.Containers.DeleteExposure(ctx, containers.DeleteExposureCommand{Meta: federation.metaFor("exposure.delete", exposureID, exposure.Generation), ExposureID: exposureID})
	return err
}

func (federation *localHermesFederation) expose(ctx context.Context, application containers.ContainerApplication) error {
	id, err := federation.exposureID(ctx, application.ID)
	if err != nil {
		return err
	}
	generation := uint64(0)
	if current, loadErr := federation.service.Repository.Exposure(ctx, application.TenantID, id); loadErr == nil {
		if current.State == "active" {
			return nil
		}
		generation = current.Generation
	} else if !errors.Is(loadErr, containers.ErrNotFound) {
		return loadErr
	}
	workload := federation.recipe.Workloads[0]
	workloadID, err := federation.service.Allocator.For(ctx, application.ID, "workload", workload.Name)
	if err != nil {
		return err
	}
	_, _, err = federation.service.Containers.ApplyExposure(ctx, containers.ApplyExposureCommand{Meta: federation.metaFor("exposure.apply", id, generation), Exposure: containers.Exposure{ID: id, WorkloadID: workloadID, PortName: workload.RoutePortName, Public: true, ListenerRef: federation.installation.PrivateServiceBinding, DomainBindingRef: federation.installation.PublicRouteBinding}})
	return err
}

func (federation *localHermesFederation) ObserveHermes(ctx context.Context, id ID) (HermesReceipt, error) {
	if id != federation.installation.ID {
		return HermesReceipt{}, ErrNotFound
	}
	applicationID, err := containers.NewID(string(id))
	if err != nil {
		return HermesReceipt{}, err
	}
	application, err := federation.service.Repository.Application(ctx, federation.meta.Grant.TenantID, applicationID)
	if err != nil {
		return HermesReceipt{}, err
	}
	if len(application.WorkloadIDs) != 1 {
		return HermesReceipt{}, fmt.Errorf("%w: hermes requires one admitted workload", ErrIntegrity)
	}
	workloadID := application.WorkloadIDs[0]
	stored, err := federation.service.Repository.Workload(ctx, application.TenantID, workloadID)
	if err != nil {
		return HermesReceipt{}, err
	}
	observed := stored
	if stored.ObservedLifecycle != containers.LifecycleDeleted {
		observed, err = federation.service.Containers.Reconcile(ctx, application.TenantID, workloadID, federation.metaFor("workload.reconcile", workloadID, stored.Generation).Grant)
		if err != nil {
			return HermesReceipt{}, err
		}
	}
	state := "active"
	switch {
	case observed.ObservedLifecycle == containers.LifecycleDeleted:
		state = "removed"
	case observed.ObservedLifecycle == containers.LifecycleStopped:
		state = "suspended"
	case observed.ObservedHealth == containers.HealthUnhealthy:
		state = "degraded"
	case observed.ObservedLifecycle != containers.LifecycleRunning || observed.ObservedHealth != containers.HealthHealthy:
		state = "starting"
	}
	imageDigest := strings.TrimPrefix(observed.Spec.Image.Digest, "sha256:")
	if imageDigest != federation.installation.Definition.ResolvedImageDigest {
		state = "degraded"
	}
	endpoint := ""
	if exposureID, exposureErr := federation.exposureID(ctx, applicationID); exposureErr == nil {
		if exposure, loadErr := federation.service.Repository.Exposure(ctx, application.TenantID, exposureID); loadErr == nil && exposure.State == "active" {
			endpoint = fmt.Sprintf("127.0.0.1:%d", containers.LoopbackExposurePort(exposure.WorkloadID, exposure.PortName))
		}
	}
	healthDigest := hermesDigest(observed)
	return HermesReceipt{InstallationID: id, Action: "observe", ObservedGeneration: federation.installation.Generation, ImageDigest: imageDigest, WorkloadDigest: hermesDigest(application), PrivateEndpoint: endpoint, HealthDigest: healthDigest, Receipt: healthDigest, CompletedAt: observed.UpdatedAt, State: state}, nil
}

func hermesDigest(value any) string {
	payload, _ := json.Marshal(value)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

var _ HermesContainerFederation = (*localHermesFederation)(nil)
