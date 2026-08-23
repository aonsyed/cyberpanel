package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/accesspolicy"
)

// SecretEnrollmentService is the only API-facing secret management boundary.
// Material is caller-owned, valid only for the duration of the call, and is
// wiped by the API handler immediately afterward. Implementations return only
// an opaque reference and must never return plaintext or ciphertext. Rotate
// must atomically compare the current owner, purpose, resource, version, and
// binding digest before replacing material; it must not rebind an existing
// secret to a different audience resource.
type SecretEnrollmentService interface {
	Enroll(context.Context, SecretEnrollmentRequest) (SecretReference, error)
	Rotate(context.Context, SecretRotationRequest) (SecretReference, error)
}

type SecretBindingPayload struct {
	MaterialBase64        string              `json:"material_base64"`
	AdapterID             string              `json:"adapter_id"`
	AdapterVersion        string              `json:"adapter_version"`
	Account               string              `json:"account"`
	Origin                string              `json:"origin"`
	Operations            []secrets.Operation `json:"operations"`
	ConsumerReleaseDigest string              `json:"consumer_release_digest"`
}

type SecretRotationPayload struct {
	SecretID              secrets.ID          `json:"secret_id"`
	ExpectedSecretVersion uint64              `json:"expected_secret_version"`
	ExpectedBindingDigest string              `json:"expected_binding_digest"`
	MaterialBase64        string              `json:"material_base64"`
	AdapterID             string              `json:"adapter_id"`
	AdapterVersion        string              `json:"adapter_version"`
	Account               string              `json:"account"`
	Origin                string              `json:"origin"`
	Operations            []secrets.Operation `json:"operations"`
	ConsumerReleaseDigest string              `json:"consumer_release_digest"`
}

type SecretEnrollmentRequest struct {
	Call       EdgeCall
	SecretID   secrets.ID
	OwnerID    secrets.ID
	Purpose    secrets.Purpose
	Audience   secrets.AudienceBinding
	Material   []byte
}

type SecretRotationRequest struct {
	Call            EdgeCall
	SecretID        secrets.ID
	OwnerID         secrets.ID
	Purpose         secrets.Purpose
	Audience        secrets.AudienceBinding
	ExpectedVersion uint64
	ExpectedBindingDigest string
	Material        []byte
}

type SecretReference struct {
	ID            secrets.ID      `json:"id"`
	Purpose       secrets.Purpose `json:"purpose"`
	ResourceKind  string          `json:"resource_kind"`
	ResourceID    secrets.ID      `json:"resource_id"`
	Version       uint64          `json:"version"`
	BindingDigest string          `json:"binding_digest"`
	State         secrets.State   `json:"state"`
	CreatedAt     time.Time       `json:"created_at"`
}

type secretOperationSpec struct {
	Name         string
	Permission   string
	Purpose      secrets.Purpose
	ResourceKind string
	Allowed      map[secrets.Operation]bool
}

var secretOperationSpecs = []secretOperationSpec{
	{Name:"secret.database_principal", Permission:"database:manage", Purpose:secrets.PurposeDatabase, ResourceKind:"database_principal", Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationRotate)},
	{Name:"secret.database_admin", Permission:"database:admin", Purpose:secrets.PurposeDatabase, ResourceKind:"database_admin", Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationRotate)},
	{Name:"secret.tls_private_key", Permission:"certificate:manage", Purpose:secrets.PurposeTLSKey, ResourceKind:"tls_private_key", Allowed:secretOperations(secrets.OperationRead, secrets.OperationSign, secrets.OperationRotate)},
	{Name:"secret.acme_account", Permission:"certificate:manage", Purpose:secrets.PurposeACME, ResourceKind:"acme_account", Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationSign, secrets.OperationRotate)},
	{Name:"secret.mail_relay", Permission:"mail:manage", Purpose:secrets.PurposeMailRelay, ResourceKind:"mail_relay", Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationRotate)},
	{Name:"secret.dkim_private_key", Permission:"mail:manage", Purpose:secrets.PurposeDKIMKey, ResourceKind:"dkim_private_key", Allowed:secretOperations(secrets.OperationSign, secrets.OperationRotate)},
	{Name:"secret.dns_provider", Permission:"dns:manage", Purpose:secrets.PurposeDNSProvider, ResourceKind:"dns_provider", Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationRotate)},
	{Name:"secret.dns_tsig", Permission:"dns:manage", Purpose:secrets.PurposeDNSProvider, ResourceKind:"dns_tsig", Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationSign, secrets.OperationRotate)},
	{Name:"secret.backup_repository", Permission:"backup:manage", Purpose:secrets.PurposeBackupRepository, ResourceKind:"backup_repository", Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationEncrypt, secrets.OperationDecrypt, secrets.OperationRotate)},
	{Name:"secret.git", Permission:"access:manage", Purpose:secrets.PurposeGit, ResourceKind:"git_credential", Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationSign, secrets.OperationRotate)},
	{Name:"secret.registry", Permission:"container:manage", Purpose:secrets.PurposeRegistry, ResourceKind:"registry_credential", Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationRotate)},
	{Name:"secret.application_administrator", Permission:"application:install", Purpose:secrets.PurposeAuthentication, ResourceKind:"application_administrator", Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationRotate)},
	{Name:"secret.web_access", Permission:"site:manage", Purpose:secrets.PurposeAuthentication, ResourceKind:accesspolicy.SecretResourceKind, Allowed:secretOperations(secrets.OperationAuthenticate, secrets.OperationRotate)},
}

func registerSecretEnrollmentContracts(registry *Registry) error {
	for _, spec := range secretOperationSpecs {
		spec := spec
		if err := register(registry, Operation{Name:spec.Name+".enroll", Permission:identity.MustPermission(spec.Permission), Assurance:identity.AssuranceMFA, Auth:AuthRequired, Mutating:true, MaximumBodyBytes:12<<20, NewPayload:func() any { return &SecretBindingPayload{} }, ValidatePayload:func(value any) error { return validateSecretBinding(value.(*SecretBindingPayload), spec) }, ResolveScope:edgeTenantOrInstallationExistingMutationScope}); err != nil { return err }
		if err := register(registry, Operation{Name:spec.Name+".rotate", Permission:identity.MustPermission(spec.Permission), Assurance:identity.AssuranceMFA, Auth:AuthRequired, Mutating:true, MaximumBodyBytes:12<<20, NewPayload:func() any { return &SecretRotationPayload{} }, ValidatePayload:func(value any) error { payload:=value.(*SecretRotationPayload); payload.ExpectedBindingDigest=strings.ToLower(payload.ExpectedBindingDigest); if !payload.SecretID.Valid() || payload.ExpectedSecretVersion==0 || payload.ExpectedSecretVersion == ^uint64(0) || !validDigestReference(payload.ExpectedBindingDigest) { return invalid("secret rotation") }; return validateSecretBinding(&SecretBindingPayload{MaterialBase64:payload.MaterialBase64, AdapterID:payload.AdapterID, AdapterVersion:payload.AdapterVersion, Account:payload.Account, Origin:payload.Origin, Operations:payload.Operations, ConsumerReleaseDigest:payload.ConsumerReleaseDigest}, spec) }, ResolveScope:edgeTenantOrInstallationExistingMutationScope}); err != nil { return err }
	}
	return nil
}

func bindSecretEnrollmentContracts(registry *Registry, services DomainServices) error {
	if services.SecretEnrollment == nil { return nil }
	for _, spec := range secretOperationSpecs {
		spec := spec
		if err := registry.Bind(spec.Name+".enroll", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*SecretBindingPayload)
			material, err := decodeSecretMaterial(payload.MaterialBase64); payload.MaterialBase64=""; if err != nil { return OperationResult{}, err }; defer clearSecret(material)
			owner, resource, err := secretScopeIDs(inv); if err != nil { return OperationResult{}, err }
			audience := secretAudience(payload.AdapterID, payload.AdapterVersion, payload.Account, payload.Origin, spec.ResourceKind, resource, inv.Request.ExpectedGeneration, payload.Operations, payload.ConsumerReleaseDigest)
			request := SecretEnrollmentRequest{Call:edgeCall(inv), SecretID:secrets.ID(effectID(inv)), OwnerID:owner, Purpose:spec.Purpose, Audience:audience, Material:material}
			result, err := services.SecretEnrollment.Enroll(ctx, request); if err != nil { return OperationResult{}, mapSecretError(err) }
			if err=validateSecretReference(result, request.SecretID, spec, resource, 1);err!=nil{return OperationResult{},err}
			return OperationResult{Status:http.StatusCreated, Value:result, Generation:result.Version}, nil
		}); err != nil { return err }
		if err := registry.Bind(spec.Name+".rotate", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*SecretRotationPayload)
			material, err := decodeSecretMaterial(payload.MaterialBase64); payload.MaterialBase64=""; if err != nil { return OperationResult{}, err }; defer clearSecret(material)
			owner, resource, err := secretScopeIDs(inv); if err != nil { return OperationResult{}, err }
			audience := secretAudience(payload.AdapterID, payload.AdapterVersion, payload.Account, payload.Origin, spec.ResourceKind, resource, inv.Request.ExpectedGeneration, payload.Operations, payload.ConsumerReleaseDigest)
			request := SecretRotationRequest{Call:edgeCall(inv), SecretID:payload.SecretID, OwnerID:owner, Purpose:spec.Purpose, Audience:audience, ExpectedVersion:payload.ExpectedSecretVersion, ExpectedBindingDigest:payload.ExpectedBindingDigest, Material:material}
			result, err := services.SecretEnrollment.Rotate(ctx, request); if err != nil { return OperationResult{}, mapSecretError(err) }
			if err=validateSecretReference(result, request.SecretID, spec, resource, request.ExpectedVersion+1);err!=nil{return OperationResult{},err}
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Version}, nil
		}); err != nil { return err }
	}
	return nil
}

func validateSecretBinding(payload *SecretBindingPayload, spec secretOperationSpec) error {
	if payload == nil || len(payload.MaterialBase64) < 16 || len(payload.MaterialBase64) > 12<<20 || !validAdapterComponent(payload.AdapterID) || !validAdapterComponent(payload.AdapterVersion) || !safeEdgeText(payload.Account, 512) || !validApprovedEndpoint(payload.Origin) || len(payload.ConsumerReleaseDigest)!=64 || !validDigestReference(strings.ToLower(payload.ConsumerReleaseDigest)) || len(payload.Operations)==0 || len(payload.Operations)>8 { return invalid("secret enrollment") }
	seen := map[secrets.Operation]bool{}
	for _, operation := range payload.Operations { if !spec.Allowed[operation] || seen[operation] { return invalid("secret audience operation") }; seen[operation]=true }
	decoded, err := base64.StdEncoding.Strict().DecodeString(payload.MaterialBase64); if err != nil || len(decoded)==0 || len(decoded)>8<<20 { clearSecret(decoded); return invalid("secret material") }; clearSecret(decoded)
	return nil
}

func decodeSecretMaterial(value string) ([]byte, error) {
	material, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(material)==0 || len(material)>8<<20 { clearSecret(material); return nil, invalid("secret material") }
	return material, nil
}

func secretScopeIDs(inv Invocation) (secrets.ID, secrets.ID, error) {
	ownerRaw := inv.Request.TenantID; if ownerRaw=="" { ownerRaw="installation" }
	if inv.Request.ResourceID == "" { return "", "", ErrInvalidRequest }
	return secretScopeID("tenant", ownerRaw), secretScopeID("resource", inv.Request.ResourceID), nil
}

// Secret broker identifiers are deliberately narrower than public API IDs.
// Keep already-compatible IDs readable and deterministically map every other
// authenticated scope value into the broker namespace. The original identity
// remains present in EdgeCall; no caller can choose the mapped owner/resource.
func secretScopeID(namespace, value string) secrets.ID {
	if id, err := secrets.NewID(value); err == nil { return id }
	digest := sha256.Sum256([]byte(namespace + "\x00" + value))
	return secrets.ID(namespace + "_" + hex.EncodeToString(digest[:])[:48])
}

func secretAudience(adapterID, adapterVersion, account, origin, resourceKind string, resourceID secrets.ID, generation uint64, operations []secrets.Operation, releaseDigest string) secrets.AudienceBinding {
	return secrets.AudienceBinding{AdapterID:adapterID, AdapterVersion:adapterVersion, Account:account, Origin:origin, ResourceKind:resourceKind, ResourceID:resourceID, ResourceGeneration:generation, Operations:append([]secrets.Operation(nil), operations...), ConsumerReleaseDigest:strings.ToLower(releaseDigest)}
}

func validateSecretReference(reference SecretReference, expected secrets.ID, spec secretOperationSpec, resource secrets.ID, version uint64) error {
	if reference.ID!=expected || reference.Purpose!=spec.Purpose || reference.ResourceKind!=spec.ResourceKind || reference.ResourceID!=resource || reference.Version!=version || !validDigestReference(reference.BindingDigest) || reference.State!=secrets.StateActive || reference.CreatedAt.IsZero() { return ErrUnavailable }
	return nil
}

func secretOperations(values ...secrets.Operation) map[secrets.Operation]bool { result:=make(map[secrets.Operation]bool,len(values));for _,value:=range values{result[value]=true};return result }

func validAdapterComponent(value string) bool { return value!="" && len(value)<=128 && !strings.ContainsAny(value,"\x00\r\n\t /\\;|&$`") }

func mapSecretError(err error) error {
	switch {
	case err==nil:return nil
	case errors.Is(err,secrets.ErrInvalid):return ErrInvalidRequest
	case errors.Is(err,secrets.ErrForbidden):return ErrForbidden
	case errors.Is(err,secrets.ErrNotFound):return ErrNotFound
	case errors.Is(err,secrets.ErrConflict),errors.Is(err,secrets.ErrRollback),errors.Is(err,secrets.ErrExpired),errors.Is(err,secrets.ErrRevoked):return ErrConflict
	default:return err
	}
}
