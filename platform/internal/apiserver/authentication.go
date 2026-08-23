package apiserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type Authenticator interface {
	Authenticate(context.Context, AuthMaterial, RequestMeta) (Actor, error)
	Authorize(context.Context, Actor, identity.Permission, identity.Scope, identity.AssuranceLevel) error
}

// IdentityAuthenticator keeps all credential verification in panel-core. The
// network-facing gateway carries opaque material only over its authenticated
// Unix connection and never opens the identity database.
type IdentityAuthenticator struct { Service *identity.Service }

func (authenticator IdentityAuthenticator) Authenticate(ctx context.Context, material AuthMaterial, meta RequestMeta) (Actor, error) {
	if authenticator.Service == nil || material.Validate() != nil || meta.Validate() != nil { return Actor{}, ErrUnauthenticated }
	switch material.Kind {
	case CredentialSession:
		id, err := identity.NewID(material.SessionID); if err != nil { return Actor{}, ErrUnauthenticated }
		raw, err := decodeCredential(material.SessionToken); if err != nil { return Actor{}, ErrUnauthenticated }
		var csrf []byte
		if material.CSRFToken != "" { csrf, err = decodeCredential(material.CSRFToken); if err != nil { clearSecret(raw); return Actor{}, ErrUnauthenticated } }
		session, principal, err := authenticator.Service.ValidateSession(ctx, id, raw, csrf, meta.ClientIP, meta.UserAgentDigest)
		clearSecret(raw); clearSecret(csrf)
		if err != nil { return Actor{}, mapIdentityError(err) }
		return Actor{PrincipalID: principal.ID, CredentialID: session.CredentialID, SessionID: session.ID, AuthzEpoch: principal.AuthzEpoch, Assurance: session.Assurance, CredentialKind: CredentialSession}, nil
	case CredentialAPIKey:
		raw := []byte(material.APIKey)
		var actor identity.ActorContext
		var principal identity.Principal
		var err error
		if strings.HasPrefix(material.APIKey, "spk.") {
			if !meta.TLS { clearSecret(raw); return Actor{}, ErrUnauthenticated }
			actor, principal, err = authenticator.Service.AuthenticateServiceAPIKey(ctx, raw, meta.ClientIP, meta.Host)
		} else {
			actor, principal, err = authenticator.Service.AuthenticateAPIKey(ctx, raw)
		}
		if err != nil { return Actor{}, mapIdentityError(err) }
		return Actor{PrincipalID: principal.ID, CredentialID: actor.CredentialID, AuthzEpoch: actor.AuthzEpoch, Assurance: actor.Assurance, CredentialKind: CredentialAPIKey}, nil
	default:
		return Actor{}, ErrUnauthenticated
	}
}

func (authenticator IdentityAuthenticator) Authorize(ctx context.Context, actor Actor, permission identity.Permission, scope identity.Scope, minimum identity.AssuranceLevel) error {
	if authenticator.Service == nil { return ErrUnavailable }
	_, err := authenticator.Service.AuthorizeActor(ctx, actor.IdentityContext(), permission, scope, minimum)
	return mapIdentityError(err)
}

func decodeCredential(value string) ([]byte, error) {
	if len(value) < 16 || len(value) > 8192 || strings.ContainsAny(value, "\r\n\t ") { return nil, ErrUnauthenticated }
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < 16 || len(decoded) > 4096 { clearSecret(decoded); return nil, ErrUnauthenticated }
	return decoded, nil
}

func clearSecret(value []byte) { for index := range value { value[index] = 0 } }

func mapIdentityError(err error) error {
	if err == nil { return nil }
	switch {
	case errors.Is(err, identity.ErrUnauthenticated), errors.Is(err, identity.ErrExpired), errors.Is(err, identity.ErrCredentialCompromised): return ErrUnauthenticated
	case errors.Is(err, identity.ErrForbidden), errors.Is(err, identity.ErrDelegationExceeded), errors.Is(err, identity.ErrSuspended): return ErrForbidden
	case errors.Is(err, identity.ErrAssuranceRequired): return ErrAssuranceRequired
	case errors.Is(err, identity.ErrNotFound): return ErrNotFound
	case errors.Is(err, identity.ErrConflict), errors.Is(err, identity.ErrStaleGeneration): return ErrConflict
	case errors.Is(err, identity.ErrInvalid): return ErrInvalidRequest
	default: return fmt.Errorf("%w: identity service", ErrUnavailable)
	}
}
