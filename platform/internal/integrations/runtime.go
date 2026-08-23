package integrations

import (
	"errors"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// ProviderRegistration is supplied by a concrete provider-worker adapter.
// Registration is deliberately all-or-nothing: the public contract, provider
// implementation, immutable endpoint, and secret audience must agree.
type ProviderRegistration struct {
	PublicName string
	Kind       ProviderKind
	Purpose    CredentialPurpose
	Endpoint   EndpointPolicy
	Provider   Provider
	Secret     SecretConsumerProfile
}

type Runtime struct {
	Bindings     *BindingService
	Registrations map[string]ProviderRegistration
}

func NewRuntime(store Store, management *secrets.ManagementClient, registrations []ProviderRegistration, now func() time.Time) (*Runtime, error) {
	if store == nil || management == nil || len(registrations) == 0 {
		return nil, ErrInvalid
	}
	providers := make(map[ProviderKind]Provider, len(registrations))
	secretProfiles := make(map[ProviderKind]SecretConsumerProfile, len(registrations))
	registered := make(map[string]ProviderRegistration, len(registrations))
	for _, registration := range registrations {
		registration.PublicName = strings.TrimSpace(registration.PublicName)
		if !validPublicProviderName(registration.PublicName) || !registration.Kind.Valid() || !purposeMatches(registration.Kind, registration.Purpose) || registration.Provider == nil || registration.Endpoint.Validate() != nil || validateProviderEndpoint(registration.Kind, registration.Endpoint) != nil || registration.Secret.validate() != nil || registration.Secret.Origin != registration.Endpoint.URL {
			return nil, ErrInvalid
		}
		if _, exists := registered[registration.PublicName]; exists {
			return nil, ErrConflict
		}
		if prior, exists := providers[registration.Kind]; exists && prior != registration.Provider {
			return nil, ErrConflict
		}
		providers[registration.Kind] = registration.Provider
		secretProfiles[registration.Kind] = registration.Secret
		registered[registration.PublicName] = registration
	}
	secretManager, err := NewBrokerSecretManager(management, secretProfiles)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Runtime{Bindings:&BindingService{Store:store, Secrets:secretManager, Providers:providers, Now:now}, Registrations:registered}, nil
}

func validPublicProviderName(value string) bool {
	switch value {
	case "cloudflare", "aws_s3", "wasabi_s3", "backblaze_b2_s3", "google_drive", "sftp", "notification_smtp", "notification_webhook", "container_registry", "security_scanner":
		return true
	default:
		return false
	}
}

var _ = errors.Is
