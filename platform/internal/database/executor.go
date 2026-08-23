package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type MutationKind string

const MutationUpsert MutationKind = "upsert"

// ResourceMutation is a compare-and-swap proposal for control.db. The SQL
// repository applies it atomically with operation acceptance, before any
// MariaDB effect is attempted.
type ResourceMutation struct {
	Kind               MutationKind    `json:"kind"`
	ExpectedGeneration uint64          `json:"expected_generation"`
	Resource           ResourceEnvelope `json:"resource"`
}

type ObservedResource struct {
	Kind       ResourceKind   `json:"kind"`
	ID         ResourceID     `json:"id"`
	Generation uint64         `json:"generation"`
	Status     ResourceStatus `json:"status"`
}

type CreateDatabaseEffect struct { Database Database `json:"database"` }
type DeleteDatabaseEffect struct {
	Database           Database   `json:"database"`
	RecoveryPointRef   ResourceID `json:"recovery_point_ref,omitempty"`
	WaiveRecovery      bool       `json:"waive_recovery"`
	ApprovalRef        ResourceID `json:"approval_ref,omitempty"`
}
type CreatePrincipalEffect struct { Principal DatabasePrincipal `json:"principal"` }
type DeletePrincipalEffect struct { Principal DatabasePrincipal `json:"principal"` }
type RotatePasswordEffect struct {
	Principal   DatabasePrincipal `json:"principal"`
	NewSecretRef SecretRef        `json:"new_secret_ref"`
}
type ReplaceGrantsEffect struct { GrantSet GrantSet `json:"grant_set"` }
type ApplyNetworkPolicyEffect struct { Policy NetworkAccessPolicy `json:"policy"` }
type BindExternalInstanceEffect struct { Instance DatabaseInstance `json:"instance"` }
type OpenConsoleSessionEffect struct { Session DatabaseWorkspaceSession `json:"session"` }
type ApplyTuningEffect struct { Profile TuningProfile `json:"profile"` }
type UpgradeDatabaseEffect struct { Upgrade DatabaseUpgrade `json:"upgrade"` }

type EffectKind string

const (
	EffectCreateDatabase       EffectKind = "create_database"
	EffectDeleteDatabase       EffectKind = "delete_database"
	EffectCreatePrincipal      EffectKind = "create_principal"
	EffectDeletePrincipal      EffectKind = "delete_principal"
	EffectRotatePassword       EffectKind = "rotate_password"
	EffectReplaceGrants        EffectKind = "replace_grants"
	EffectApplyNetworkPolicy   EffectKind = "apply_network_policy"
	EffectBindExternalInstance EffectKind = "bind_external_instance"
	EffectOpenConsoleSession   EffectKind = "open_console_session"
	EffectApplyTuning          EffectKind = "apply_tuning"
	EffectUpgradeDatabase      EffectKind = "upgrade_database"
)

// EffectRequest is a closed sum type. Exactly one member matching Kind must be
// populated, so neither tenant SQL nor a shell command can cross this boundary.
type EffectRequest struct {
	EffectID     string         `json:"effect_id"`
	Scope        OperationScope `json:"scope"`
	Kind         EffectKind     `json:"kind"`
	RequestDigest string        `json:"request_digest"`

	CreateDatabase       *CreateDatabaseEffect       `json:"create_database,omitempty"`
	DeleteDatabase       *DeleteDatabaseEffect       `json:"delete_database,omitempty"`
	CreatePrincipal      *CreatePrincipalEffect      `json:"create_principal,omitempty"`
	DeletePrincipal      *DeletePrincipalEffect      `json:"delete_principal,omitempty"`
	RotatePassword       *RotatePasswordEffect       `json:"rotate_password,omitempty"`
	ReplaceGrants        *ReplaceGrantsEffect        `json:"replace_grants,omitempty"`
	ApplyNetworkPolicy   *ApplyNetworkPolicyEffect   `json:"apply_network_policy,omitempty"`
	BindExternalInstance *BindExternalInstanceEffect `json:"bind_external_instance,omitempty"`
	OpenConsoleSession   *OpenConsoleSessionEffect   `json:"open_console_session,omitempty"`
	ApplyTuning          *ApplyTuningEffect          `json:"apply_tuning,omitempty"`
	UpgradeDatabase      *UpgradeDatabaseEffect      `json:"upgrade_database,omitempty"`
}

type EffectOutcome string

const (
	EffectConfirmed EffectOutcome = "confirmed"
	EffectRejected  EffectOutcome = "rejected"
	EffectAmbiguous EffectOutcome = "ambiguous"
)

type EffectReceipt struct {
	EffectID          string        `json:"effect_id"`
	RequestDigest     string        `json:"request_digest"`
	Outcome           EffectOutcome `json:"outcome"`
	ProofDigest       string        `json:"proof_digest,omitempty"`
	MutationObserved  bool          `json:"mutation_observed"`
	CompensationToken ResourceID    `json:"compensation_token,omitempty"`
	FailureCode       string        `json:"failure_code,omitempty"`
}

type CompensationRequest struct {
	EffectID          string         `json:"effect_id"`
	RequestDigest     string         `json:"request_digest"`
	Scope             OperationScope `json:"scope"`
	CompensationToken ResourceID     `json:"compensation_token"`
	FailureCode       string         `json:"failure_code"`
}

type CompensationReceipt struct {
	EffectID          string      `json:"effect_id"`
	RequestDigest     string      `json:"request_digest"`
	CompensationToken ResourceID  `json:"compensation_token"`
	Outcome           EffectOutcome `json:"outcome"`
	ProofDigest       string      `json:"proof_digest,omitempty"`
}

// MariaDBExecutor is implemented by the narrowly privileged MariaDB broker.
// It resolves protected secret references internally and never accepts raw
// credential bytes, SQL, executable names, arguments, or filesystem paths.
type MariaDBExecutor interface {
	ObserveOrApply(context.Context, EffectRequest) (EffectReceipt, error)
	Compensate(context.Context, CompensationRequest) (CompensationReceipt, error)
}

func finalizeEffect(request EffectRequest) (EffectRequest, error) {
	request.EffectID = ""
	request.RequestDigest = ""
	if err := validateEffectShape(request); err != nil { return EffectRequest{}, err }
	encoded, err := json.Marshal(request)
	if err != nil { return EffectRequest{}, err }
	digest := sha256.Sum256(encoded)
	request.RequestDigest = hex.EncodeToString(digest[:])
	effectID := sha256.Sum256([]byte("cyberpanel:mariadb-effect:v1\x00" + request.Scope.TenantID.String() + "\x00" +
		string(request.Scope.Kind) + "\x00" + request.Scope.ID.String() + "\x00" + request.RequestDigest))
	request.EffectID = "effect-" + hex.EncodeToString(effectID[:])
	return request, nil
}

func validateEffectRequest(request EffectRequest) error {
	want, err := finalizeEffect(request)
	if err != nil || want.EffectID != request.EffectID || want.RequestDigest != request.RequestDigest {
		return ErrInvalidCommand
	}
	return nil
}

func validateEffectShape(request EffectRequest) error {
	if request.Scope.ID.IsZero() { return ErrInvalidCommand }
	count := 0
	if request.CreateDatabase != nil { count++ }
	if request.DeleteDatabase != nil { count++ }
	if request.CreatePrincipal != nil { count++ }
	if request.DeletePrincipal != nil { count++ }
	if request.RotatePassword != nil { count++ }
	if request.ReplaceGrants != nil { count++ }
	if request.ApplyNetworkPolicy != nil { count++ }
	if request.BindExternalInstance != nil { count++ }
	if request.OpenConsoleSession != nil { count++ }
	if request.ApplyTuning != nil { count++ }
	if request.UpgradeDatabase != nil { count++ }
	if count != 1 { return ErrInvalidCommand }
	switch request.Kind {
	case EffectCreateDatabase:
		if request.CreateDatabase == nil || request.CreateDatabase.Database.Validate() != nil { return ErrInvalidCommand }
	case EffectDeleteDatabase:
		if request.DeleteDatabase == nil || request.DeleteDatabase.Database.Validate() != nil { return ErrInvalidCommand }
	case EffectCreatePrincipal:
		if request.CreatePrincipal == nil || request.CreatePrincipal.Principal.Validate() != nil { return ErrInvalidCommand }
	case EffectDeletePrincipal:
		if request.DeletePrincipal == nil || request.DeletePrincipal.Principal.Validate() != nil { return ErrInvalidCommand }
	case EffectRotatePassword:
		if request.RotatePassword == nil || request.RotatePassword.Principal.Validate() != nil || request.RotatePassword.NewSecretRef.IsZero() { return ErrInvalidCommand }
	case EffectReplaceGrants:
		if request.ReplaceGrants == nil || request.ReplaceGrants.GrantSet.Validate() != nil { return ErrInvalidCommand }
	case EffectApplyNetworkPolicy:
		if request.ApplyNetworkPolicy == nil || request.ApplyNetworkPolicy.Policy.Validate() != nil { return ErrInvalidCommand }
	case EffectBindExternalInstance:
		if request.BindExternalInstance == nil || request.BindExternalInstance.Instance.Validate() != nil || request.BindExternalInstance.Instance.Placement != PlacementExternal { return ErrInvalidCommand }
	case EffectOpenConsoleSession:
		if request.OpenConsoleSession == nil || request.OpenConsoleSession.Session.Validate() != nil { return ErrInvalidCommand }
	case EffectApplyTuning:
		if request.ApplyTuning == nil || request.ApplyTuning.Profile.Validate() != nil { return ErrInvalidCommand }
	case EffectUpgradeDatabase:
		if request.UpgradeDatabase == nil || request.UpgradeDatabase.Upgrade.Validate() != nil { return ErrInvalidCommand }
	default:
		return ErrInvalidCommand
	}
	return nil
}

func effectReceiptMatches(request EffectRequest, receipt EffectReceipt) bool {
	if receipt.EffectID != request.EffectID || receipt.RequestDigest != request.RequestDigest { return false }
	switch receipt.Outcome {
	case EffectConfirmed:
		return receipt.ProofDigest != "" && validSHA256(receipt.ProofDigest) && receipt.MutationObserved && receipt.CompensationToken.IsZero()
	case EffectRejected:
		return receipt.FailureCode != "" && (!receipt.MutationObserved || !receipt.CompensationToken.IsZero())
	case EffectAmbiguous:
		return true
	default:
		return false
	}
}

func compensationReceiptMatches(request CompensationRequest, receipt CompensationReceipt) bool {
	return receipt.EffectID == request.EffectID && receipt.RequestDigest == request.RequestDigest &&
		receipt.CompensationToken == request.CompensationToken &&
		((receipt.Outcome == EffectConfirmed && validSHA256(receipt.ProofDigest)) || receipt.Outcome == EffectRejected || receipt.Outcome == EffectAmbiguous)
}
