package database

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

type Capability string

const (
	CapabilityTenantManage Capability = "tenant_database_manage"
	CapabilityTenantConsole Capability = "tenant_database_console"
	CapabilityNodeAdmin    Capability = "node_database_admin"
)

type Actor struct {
	TenantID   site.TenantID `json:"tenant_id,omitempty"`
	Capability Capability    `json:"capability"`
	ApprovalRef ResourceID   `json:"approval_ref,omitempty"`
}

type CommandHeader struct {
	CommandID string        `json:"command_id"`
	Actor     Actor         `json:"actor"`
	TenantID  site.TenantID `json:"tenant_id,omitempty"`
}

type OperationScope struct {
	TenantID site.TenantID `json:"tenant_id,omitempty"`
	Kind     ResourceKind  `json:"kind"`
	ID       ResourceID    `json:"id"`
}

type Command interface {
	commandKind() string
	commandHeader() CommandHeader
	commandScope() OperationScope
	commandPayload() any
}

type CreateDatabase struct {
	Header   CommandHeader `json:"header"`
	Database Database      `json:"database"`
}
func (command CreateDatabase) commandKind() string { return "create_database" }
func (command CreateDatabase) commandHeader() CommandHeader { return command.Header }
func (command CreateDatabase) commandScope() OperationScope { return scope(command.Header.TenantID, KindDatabase, command.Database.ID) }
func (command CreateDatabase) commandPayload() any { return command }

type DeleteDatabase struct {
	Header             CommandHeader `json:"header"`
	DatabaseID         ResourceID    `json:"database_id"`
	ExpectedGeneration uint64        `json:"expected_generation"`
	RecoveryPointRef   ResourceID    `json:"recovery_point_ref,omitempty"`
	WaiveRecovery      bool          `json:"waive_recovery"`
	ApprovalRef        ResourceID    `json:"approval_ref,omitempty"`
}
func (command DeleteDatabase) commandKind() string { return "delete_database" }
func (command DeleteDatabase) commandHeader() CommandHeader { return command.Header }
func (command DeleteDatabase) commandScope() OperationScope { return scope(command.Header.TenantID, KindDatabase, command.DatabaseID) }
func (command DeleteDatabase) commandPayload() any { return command }

type CreatePrincipal struct {
	Header    CommandHeader     `json:"header"`
	Principal DatabasePrincipal `json:"principal"`
}
func (command CreatePrincipal) commandKind() string { return "create_principal" }
func (command CreatePrincipal) commandHeader() CommandHeader { return command.Header }
func (command CreatePrincipal) commandScope() OperationScope { return scope(command.Header.TenantID, KindPrincipal, command.Principal.ID) }
func (command CreatePrincipal) commandPayload() any { return command }

type DeletePrincipal struct {
	Header             CommandHeader `json:"header"`
	PrincipalID        ResourceID    `json:"principal_id"`
	ExpectedGeneration uint64        `json:"expected_generation"`
}
func (command DeletePrincipal) commandKind() string { return "delete_principal" }
func (command DeletePrincipal) commandHeader() CommandHeader { return command.Header }
func (command DeletePrincipal) commandScope() OperationScope { return scope(command.Header.TenantID, KindPrincipal, command.PrincipalID) }
func (command DeletePrincipal) commandPayload() any { return command }

type RotatePrincipalPassword struct {
	Header             CommandHeader `json:"header"`
	PrincipalID        ResourceID    `json:"principal_id"`
	ExpectedGeneration uint64        `json:"expected_generation"`
	NewSecretRef       SecretRef     `json:"new_secret_ref"`
}
func (command RotatePrincipalPassword) commandKind() string { return "rotate_principal_password" }
func (command RotatePrincipalPassword) commandHeader() CommandHeader { return command.Header }
func (command RotatePrincipalPassword) commandScope() OperationScope { return scope(command.Header.TenantID, KindPrincipal, command.PrincipalID) }
func (command RotatePrincipalPassword) commandPayload() any { return command }

type ReplaceGrantSet struct {
	Header   CommandHeader `json:"header"`
	GrantSet GrantSet      `json:"grant_set"`
}
func (command ReplaceGrantSet) commandKind() string { return "replace_grant_set" }
func (command ReplaceGrantSet) commandHeader() CommandHeader { return command.Header }
func (command ReplaceGrantSet) commandScope() OperationScope { return scope(command.Header.TenantID, KindGrantSet, command.GrantSet.ID) }
func (command ReplaceGrantSet) commandPayload() any { return command }

type ReplaceRemoteCIDRs struct {
	Header CommandHeader       `json:"header"`
	Policy NetworkAccessPolicy `json:"policy"`
}
func (command ReplaceRemoteCIDRs) commandKind() string { return "replace_remote_cidrs" }
func (command ReplaceRemoteCIDRs) commandHeader() CommandHeader { return command.Header }
func (command ReplaceRemoteCIDRs) commandScope() OperationScope { return scope(command.Header.TenantID, KindNetworkPolicy, command.Policy.ID) }
func (command ReplaceRemoteCIDRs) commandPayload() any { return command }

type BindExternalInstance struct {
	Header   CommandHeader   `json:"header"`
	Instance DatabaseInstance `json:"instance"`
}
func (command BindExternalInstance) commandKind() string { return "bind_external_instance" }
func (command BindExternalInstance) commandHeader() CommandHeader { return command.Header }
func (command BindExternalInstance) commandScope() OperationScope { return scope(site.TenantID{}, KindDatabaseInstance, command.Instance.ID) }
func (command BindExternalInstance) commandPayload() any { return command }

type OpenConsoleSession struct {
	Header  CommandHeader             `json:"header"`
	Session DatabaseWorkspaceSession `json:"session"`
}
func (command OpenConsoleSession) commandKind() string { return "open_console_session" }
func (command OpenConsoleSession) commandHeader() CommandHeader { return command.Header }
func (command OpenConsoleSession) commandScope() OperationScope { return scope(command.Header.TenantID, KindConsoleSession, command.Session.ID) }
func (command OpenConsoleSession) commandPayload() any { return command }

type RequestTuning struct {
	Header  CommandHeader `json:"header"`
	Profile TuningProfile `json:"profile"`
}
func (command RequestTuning) commandKind() string { return "request_tuning" }
func (command RequestTuning) commandHeader() CommandHeader { return command.Header }
func (command RequestTuning) commandScope() OperationScope { return scope(site.TenantID{}, KindTuningProfile, command.Profile.ID) }
func (command RequestTuning) commandPayload() any { return command }

type RequestUpgrade struct {
	Header  CommandHeader  `json:"header"`
	Upgrade DatabaseUpgrade `json:"upgrade"`
}
func (command RequestUpgrade) commandKind() string { return "request_upgrade" }
func (command RequestUpgrade) commandHeader() CommandHeader { return command.Header }
func (command RequestUpgrade) commandScope() OperationScope { return scope(site.TenantID{}, KindDatabaseUpgrade, command.Upgrade.ID) }
func (command RequestUpgrade) commandPayload() any { return command }

func scope(tenantID site.TenantID, kind ResourceKind, id ResourceID) OperationScope {
	return OperationScope{TenantID: tenantID, Kind: kind, ID: id}
}

func commandDigest(command Command) string {
	encoded, _ := json.Marshal(struct {
		Version int `json:"v"`
		Kind string `json:"kind"`
		Payload any `json:"payload"`
	}{Version: 1, Kind: command.commandKind(), Payload: command.commandPayload()})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validateHeader(header CommandHeader, nodeScoped bool) error {
	if _, err := parseOpaqueID(header.CommandID); err != nil { return ErrInvalidCommand }
	if nodeScoped {
		if header.Actor.Capability != CapabilityNodeAdmin || header.Actor.TenantID.String() != "" || header.TenantID.String() != "" || header.Actor.ApprovalRef.IsZero() {
			return ErrUnauthorized
		}
		return nil
	}
	if header.TenantID.String() == "" || header.Actor.TenantID != header.TenantID { return ErrUnauthorized }
	if header.Actor.Capability != CapabilityTenantManage && header.Actor.Capability != CapabilityTenantConsole { return ErrUnauthorized }
	return nil
}

func validateCommand(command Command, now time.Time) error {
	if command == nil || command.commandScope().ID.IsZero() { return ErrInvalidCommand }
	nodeScoped := command.commandScope().TenantID.String() == ""
	if err := validateHeader(command.commandHeader(), nodeScoped); err != nil { return err }
	switch value := command.(type) {
	case CreateDatabase:
		if value.Database.Validate() != nil || value.Database.TenantID != value.Header.TenantID || value.Database.Generation != 1 { return ErrInvalidCommand }
	case DeleteDatabase:
		if value.ExpectedGeneration == 0 || !value.WaiveRecovery && value.RecoveryPointRef.IsZero() || value.WaiveRecovery && value.ApprovalRef.IsZero() { return ErrInvalidCommand }
	case CreatePrincipal:
		if value.Principal.Validate() != nil || value.Principal.TenantID != value.Header.TenantID || value.Principal.Generation != 1 { return ErrInvalidCommand }
	case DeletePrincipal:
		if value.ExpectedGeneration == 0 { return ErrInvalidCommand }
	case RotatePrincipalPassword:
		if value.ExpectedGeneration == 0 || value.NewSecretRef.IsZero() { return ErrInvalidCommand }
	case ReplaceGrantSet:
		if value.GrantSet.Validate() != nil || value.GrantSet.TenantID != value.Header.TenantID { return ErrInvalidCommand }
	case ReplaceRemoteCIDRs:
		if value.Policy.Validate() != nil { return ErrInvalidCommand }
		if value.Policy.TenantID != value.Header.TenantID { return ErrUnauthorized }
	case BindExternalInstance:
		if value.Instance.Validate() != nil || value.Instance.Placement != PlacementExternal || value.Instance.Generation != 1 || value.Instance.TenantID.String() != "" { return ErrInvalidCommand }
	case OpenConsoleSession:
		if value.Header.Actor.Capability != CapabilityTenantConsole || value.Session.Validate() != nil || value.Session.TenantID != value.Header.TenantID ||
			!value.Session.ExpiresAt.After(now) || value.Session.ExpiresAt.After(now.Add(30*time.Minute)) { return ErrInvalidCommand }
	case RequestTuning:
		if value.Profile.Validate() != nil || value.Profile.TenantID.String() != "" { return ErrInvalidCommand }
	case RequestUpgrade:
		if value.Upgrade.Validate() != nil || value.Upgrade.TenantID.String() != "" { return ErrInvalidCommand }
	default:
		return ErrInvalidCommand
	}
	return nil
}
