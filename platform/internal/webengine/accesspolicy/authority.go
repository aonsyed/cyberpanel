// Package accesspolicy owns engine-neutral HTTP password protection and its
// immutable OLS/LiteSpeed Enterprise activation lifecycle.
package accesspolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

var (
	ErrInvalid   = errors.New("invalid web access policy")
	ErrNotFound  = errors.New("web access policy not found")
	ErrConflict  = errors.New("web access policy conflict")
	ErrAmbiguous = errors.New("web access policy activation outcome is ambiguous")
	ErrForbidden = errors.New("web access policy ownership mismatch")
)

const bcryptCost = 12

const (
	SecretAdapterID      = "webaccess.litespeed"
	SecretAdapterVersion = "web-access-v1"
	SecretResourceKind   = "web_access_policy"
	MaximumMaterialBytes = 8 << 10
)

var allHTTPMethods = []string{"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"}

type CredentialMaterial struct {
	username string
	password []byte
}

func newCredentialMaterial(username string, password []byte) (CredentialMaterial, error) {
	if !validUsername(username) || len(password) < 12 || len(password) > 1024 || bytes.IndexByte(password, 0) >= 0 || bytes.IndexAny(password, "\r\n") >= 0 {
		wipe(password)
		return CredentialMaterial{}, ErrInvalid
	}
	return CredentialMaterial{username: username, password: append([]byte(nil), password...)}, nil
}

func (material *CredentialMaterial) Destroy() {
	if material == nil { return }
	wipe(material.password)
	material.password = nil
	material.username = ""
}

type CredentialSource interface {
	Resolve(context.Context, string, string, string) (CredentialMaterial, error)
}

type VerifiedActivator interface {
	ApplyVerified(context.Context, native.RenderRequest, string) (activation.Receipt, error)
}

type Authority struct {
	Catalog    *catalog.SQLCatalog
	Activator  VerifiedActivator
	Credentials CredentialSource
	renderers  map[webengine.Edition]native.Renderer
	now        func() time.Time
	activation sync.Mutex
}

func New(catalogValue *catalog.SQLCatalog, activator VerifiedActivator, credentials CredentialSource, renderers ...native.Renderer) (*Authority, error) {
	if catalogValue == nil || activator == nil || credentials == nil {
		return nil, ErrInvalid
	}
	byEdition := make(map[webengine.Edition]native.Renderer, len(renderers))
	for _, renderer := range renderers {
		if renderer == nil || renderer.Edition() != webengine.EditionOpenLiteSpeed && renderer.Edition() != webengine.EditionLiteSpeedEnterprise || byEdition[renderer.Edition()] != nil {
			return nil, ErrInvalid
		}
		byEdition[renderer.Edition()] = renderer
	}
	if len(byEdition) != 2 {
		return nil, ErrInvalid
	}
	return &Authority{Catalog: catalogValue, Activator: activator, Credentials: credentials, renderers: byEdition, now: time.Now}, nil
}

type ConfigureBindingRequest struct {
	EffectID      string
	Scope         service.CommandScope
	Hostname      webengine.Hostname
	ResourceID    string
	Enabled       bool
	CredentialRef string
	Realm         string
	Route         string
	ExpiresAt     time.Time
}

func (authority *Authority) ConfigureBinding(ctx context.Context, request ConfigureBindingRequest) (composer.AccessPolicyInput, error) {
	if authority == nil || authority.Catalog == nil || authority.Activator == nil || authority.Credentials == nil || request.EffectID == "" || request.Scope.TenantID.String() == "" || request.Scope.SiteID.String() == "" || request.Hostname.String() == "" || request.ResourceID == "" {
		return composer.AccessPolicyInput{}, ErrInvalid
	}
	if existing, err := authority.Catalog.AccessPolicyChange(ctx, request.EffectID); err == nil {
		if existing.Policy.Scope != request.Scope || existing.Policy.Hostname != request.Hostname {
			return composer.AccessPolicyInput{}, ErrConflict
		}
		return authority.apply(ctx, existing)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return composer.AccessPolicyInput{}, err
	}
	policyRef := PolicyRef(request.Scope, request.Hostname, request.Route)
	current, loadErr := authority.Catalog.AccessPolicy(ctx, string(policyRef))
	if loadErr != nil && !errors.Is(loadErr, sql.ErrNoRows) {
		return composer.AccessPolicyInput{}, loadErr
	}
	if loadErr == nil && (current.Scope != request.Scope || current.Hostname != request.Hostname) {
		return composer.AccessPolicyInput{}, ErrForbidden
	}
	if request.Realm == "" { request.Realm = "Protected site" }
	if request.Route == "" { request.Route = "/" }
	next := current
	if errors.Is(loadErr, sql.ErrNoRows) {
		next = composer.AccessPolicyInput{Scope: request.Scope, PolicyRef: policyRef, Hostname: request.Hostname, Realm: request.Realm, Route: request.Route, Methods: append([]string(nil), allHTTPMethods...), MaximumFailures: 10, FailureWindowSeconds: 300, FailurePolicy: webengine.AccessFailureDeny, Generation: 1}
	} else {
		next.Generation++
		next.Realm = request.Realm
		next.Route = request.Route
	}
	if !request.ExpiresAt.IsZero() {
		now := authority.now().UTC()
		if !request.ExpiresAt.After(now.Add(time.Minute)) || request.ExpiresAt.After(now.Add(365*24*time.Hour)) {
			return composer.AccessPolicyInput{}, ErrInvalid
		}
		next.ExpiresAtUnix = uint64(request.ExpiresAt.UTC().Unix())
	}
	if request.Enabled {
		if request.CredentialRef == "" {
			return composer.AccessPolicyInput{}, ErrInvalid
		}
		material, err := authority.Credentials.Resolve(ctx, request.CredentialRef, request.Scope.TenantID.String(), request.ResourceID)
		if err != nil {
			return composer.AccessPolicyInput{}, err
		}
		defer material.Destroy()
		digest, err := bcrypt.GenerateFromPassword(material.password, bcryptCost)
		if err != nil {
			return composer.AccessPolicyInput{}, err
		}
		principalRef := webengine.ResourceRef("principal/" + shortHash(string(policyRef)+"\x00"+material.username))
		next.Principals = []composer.AccessPrincipalInput{{Ref: principalRef, Username: material.username, Digest: string(digest)}}
		wipe(digest)
		next.CredentialRef = request.CredentialRef
		next.State = webengine.AccessPolicyEnabled
	} else {
		if errors.Is(loadErr, sql.ErrNoRows) {
			return composer.AccessPolicyInput{}, ErrNotFound
		}
		next.State = webengine.AccessPolicyDisabled
	}
	prepared, err := authority.Catalog.PrepareAccessPolicy(ctx, request.EffectID, next, false)
	if err != nil {
		return composer.AccessPolicyInput{}, err
	}
	return authority.apply(ctx, prepared)
}

func (authority *Authority) SetState(ctx context.Context, policyRef string, enabled bool) (composer.AccessPolicyInput, error) {
	current, err := authority.Catalog.AccessPolicy(ctx, policyRef)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) { return composer.AccessPolicyInput{}, ErrNotFound }
		return composer.AccessPolicyInput{}, err
	}
	if enabled && current.ExpiresAtUnix != 0 && uint64(authority.now().UTC().Unix()) >= current.ExpiresAtUnix {
		return composer.AccessPolicyInput{}, ErrForbidden
	}
	target := webengine.AccessPolicyDisabled
	if enabled { target = webengine.AccessPolicyEnabled }
	if current.State == target { return current, nil }
	current.State = target
	current.Generation++
	effect := "access-state-" + shortHash(policyRef+"\x00"+string(target)+"\x00"+fmt.Sprint(current.Generation))
	if existing, lookupErr := authority.Catalog.AccessPolicyChange(ctx, effect); lookupErr == nil { return authority.apply(ctx, existing) } else if !errors.Is(lookupErr, sql.ErrNoRows) { return composer.AccessPolicyInput{}, lookupErr }
	prepared, err := authority.Catalog.PrepareAccessPolicy(ctx, effect, current, false)
	if err != nil { return composer.AccessPolicyInput{}, err }
	return authority.apply(ctx, prepared)
}

func (authority *Authority) Delete(ctx context.Context, effectID, policyRef string) error {
	if authority == nil || effectID == "" || policyRef == "" { return ErrInvalid }
	if existing, err := authority.Catalog.AccessPolicyChange(ctx, effectID); err == nil { _, err = authority.apply(ctx, existing); return err } else if !errors.Is(err, sql.ErrNoRows) { return err }
	current, err := authority.Catalog.AccessPolicy(ctx, policyRef)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) { return nil }
		return err
	}
	current.Generation++
	prepared, err := authority.Catalog.PrepareAccessPolicy(ctx, effectID, current, true)
	if err != nil { return err }
	_, err = authority.apply(ctx, prepared)
	return err
}

func (authority *Authority) VerifyBinding(ctx context.Context, tenantID, siteID, policyRef, route string) error {
	policy, err := authority.Catalog.AccessPolicy(ctx, policyRef)
	if err != nil { return err }
	if policy.Scope.TenantID.String() != tenantID || policy.Scope.SiteID.String() != siteID || policy.Route != route || policy.State != webengine.AccessPolicyEnabled {
		return ErrForbidden
	}
	if policy.ExpiresAtUnix != 0 && uint64(authority.now().UTC().Unix()) >= policy.ExpiresAtUnix { return ErrForbidden }
	return nil
}

func (authority *Authority) Policy(ctx context.Context, policyRef string) (composer.AccessPolicyInput, error) {
	if authority == nil || authority.Catalog == nil || policyRef == "" { return composer.AccessPolicyInput{}, ErrInvalid }
	policy, err := authority.Catalog.AccessPolicy(ctx, policyRef)
	if errors.Is(err, sql.ErrNoRows) { return composer.AccessPolicyInput{}, ErrNotFound }
	return policy, err
}

func (authority *Authority) apply(ctx context.Context, prepared catalog.PreparedAccessPolicy) (composer.AccessPolicyInput, error) {
	if prepared.Finalized { return prepared.Policy, nil }
	authority.activation.Lock()
	defer authority.activation.Unlock()
	composed, err := composer.Compose(prepared.Plan)
	if err != nil {
		_ = authority.Catalog.RejectAccessPolicy(ctx, prepared)
		return composer.AccessPolicyInput{}, err
	}
	renderer := authority.renderers[composed.Desired.Engine.Edition]
	if renderer == nil {
		_ = authority.Catalog.RejectAccessPolicy(ctx, prepared)
		return composer.AccessPolicyInput{}, ErrInvalid
	}
	renderRequest := native.RenderRequest{Desired: composed.Desired, Snapshot: composed.Snapshot}
	generation, err := renderer.Render(ctx, renderRequest)
	if err != nil {
		_ = authority.Catalog.RejectAccessPolicy(ctx, prepared)
		return composer.AccessPolicyInput{}, err
	}
	receipt, activationErr := authority.Activator.ApplyVerified(ctx, renderRequest, generation.ContentDigest)
	if activationErr != nil || receipt.Status != activation.Applied || !receipt.Confirmed || receipt.Digest != generation.ContentDigest {
		if receipt.Status == activation.RolledBack { _ = authority.Catalog.RejectAccessPolicy(ctx, prepared) }
		return composer.AccessPolicyInput{}, errors.Join(ErrAmbiguous, activationErr)
	}
	if err = authority.Catalog.FinalizeAccessPolicy(ctx, prepared, receipt.Digest); err != nil {
		return composer.AccessPolicyInput{}, errors.Join(ErrAmbiguous, err)
	}
	return prepared.Policy, nil
}

func PolicyRef(scope service.CommandScope, hostname webengine.Hostname, route string) webengine.ResourceRef {
	if route == "" { route = "/" }
	return webengine.ResourceRef("access/" + shortHash(scope.TenantID.String()+"\x00"+scope.SiteID.String()+"\x00"+hostname.String()+"\x00"+route))
}

func Scope(tenantID, siteID string) (service.CommandScope, error) {
	tenant, err := site.NewTenantID(tenantID)
	if err != nil { return service.CommandScope{}, err }
	identifier, err := site.NewSiteID(siteID)
	if err != nil { return service.CommandScope{}, err }
	return service.CommandScope{TenantID: tenant, SiteID: identifier}, nil
}

func shortHash(value string) string { sum := sha256.Sum256([]byte(value)); return hex.EncodeToString(sum[:])[:48] }
func validUsername(value string) bool { if value==""||len(value)>64||value[0]=='-'||value[0]=='.'{return false};for index:=range value{character:=value[index];if !((character>='a'&&character<='z')||(character>='A'&&character<='Z')||(character>='0'&&character<='9')||character=='_'||character=='-'||character=='.'||character=='@'){return false}};return true }
func wipe(values ...[]byte) { for _, value := range values { for index := range value { value[index] = 0 } } }

func SortedHTTPMethods() []string { result:=append([]string(nil),allHTTPMethods...);sort.Strings(result);return result }
