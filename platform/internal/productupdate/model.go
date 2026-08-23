// Package productupdate implements the signed, durable product-update core.
// It exposes typed operations only and never downloads artifacts or invokes a shell.
package productupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid       = errors.New("invalid product-update resource")
	ErrNotFound      = errors.New("product-update resource not found")
	ErrConflict      = errors.New("product-update generation, fence, or admission conflict")
	ErrIntegrity     = errors.New("product-update integrity failure")
	ErrUnauthorized  = errors.New("product-update authorization rejected")
	ErrIncompatible  = errors.New("product-update compatibility rejected")
	ErrExpired       = errors.New("product-update manifest expired")
	ErrRollback      = errors.New("product-update rollback is not proven")
	ErrCapacity      = errors.New("product-update bound exceeded")
	ErrUnsafeArchive = errors.New("product-update archive contains an unsafe entry")
)

const (
	MaxPageSize  = 500
	maxGeneration = uint64(1<<63 - 1)
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type OperatingSystem string

const OSLinux OperatingSystem = "linux"

type Architecture string

const (
	ArchAMD64 Architecture = "amd64"
	ArchARM64 Architecture = "arm64"
)

type Channel string

const (
	ChannelStable    Channel = "stable"
	ChannelCandidate Channel = "candidate"
	ChannelEdge      Channel = "edge"
)

type PlatformTuple struct {
	OS      OperatingSystem `json:"os"`
	Arch    Architecture    `json:"arch"`
	Channel Channel         `json:"channel"`
}

func (tuple PlatformTuple) Validate() error {
	if tuple.OS != OSLinux || tuple.Arch != ArchAMD64 && tuple.Arch != ArchARM64 ||
		tuple.Channel != ChannelStable && tuple.Channel != ChannelCandidate && tuple.Channel != ChannelEdge {
		return ErrInvalid
	}
	return nil
}

func (tuple PlatformTuple) key() string {
	return string(tuple.OS) + "/" + string(tuple.Arch) + "/" + string(tuple.Channel)
}

type Version struct {
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
	Patch uint32 `json:"patch"`
}

func (version Version) Compare(other Version) int {
	if version.Major != other.Major {
		if version.Major < other.Major { return -1 }
		return 1
	}
	if version.Minor != other.Minor {
		if version.Minor < other.Minor { return -1 }
		return 1
	}
	if version.Patch < other.Patch { return -1 }
	if version.Patch > other.Patch { return 1 }
	return 0
}

func (version Version) String() string {
	return fmt.Sprintf("%d.%d.%d", version.Major, version.Minor, version.Patch)
}

type VersionRange struct {
	Minimum Version `json:"minimum"`
	Maximum Version `json:"maximum"`
}

func (versionRange VersionRange) Includes(version Version) bool {
	return version.Compare(versionRange.Minimum) >= 0 && version.Compare(versionRange.Maximum) <= 0
}

func (versionRange VersionRange) Validate() error {
	if versionRange.Minimum.Compare(versionRange.Maximum) > 0 { return ErrInvalid }
	return nil
}

type SchemaRange struct {
	Minimum uint64 `json:"minimum"`
	Maximum uint64 `json:"maximum"`
}

func (schemaRange SchemaRange) Validate() error {
	if schemaRange.Maximum < schemaRange.Minimum { return ErrInvalid }
	return nil
}

type InstalledComponent struct {
	ID             string  `json:"id"`
	Version        Version `json:"version"`
	ArtifactDigest string  `json:"artifact_digest"`
}

type InstalledInventory struct {
	NodeID        string               `json:"node_id"`
	Platform      PlatformTuple        `json:"platform"`
	Runtime       Version              `json:"runtime"`
	SchemaVersion uint64               `json:"schema_version"`
	Components    []InstalledComponent `json:"components"`
	Capabilities  []string             `json:"capabilities"`
	ObservedAt    time.Time            `json:"observed_at"`
	Digest        string               `json:"digest"`
}

func CanonicalInventory(inventory InstalledInventory) (InstalledInventory, error) {
	if !identifierPattern.MatchString(inventory.NodeID) || inventory.Platform.Validate() != nil || !validTime(inventory.ObservedAt) ||
		len(inventory.Components) == 0 || len(inventory.Components) > 4096 || len(inventory.Capabilities) > 4096 {
		return InstalledInventory{}, ErrInvalid
	}
	inventory.ObservedAt = inventory.ObservedAt.UTC()
	inventory.Components = append([]InstalledComponent(nil), inventory.Components...)
	sort.Slice(inventory.Components, func(i, j int) bool { return inventory.Components[i].ID < inventory.Components[j].ID })
	for index, component := range inventory.Components {
		if !identifierPattern.MatchString(component.ID) || !validDigest(component.ArtifactDigest) ||
			index > 0 && inventory.Components[index-1].ID == component.ID { return InstalledInventory{}, ErrInvalid }
	}
	inventory.Capabilities = append([]string(nil), inventory.Capabilities...)
	sort.Strings(inventory.Capabilities)
	for index, capability := range inventory.Capabilities {
		if !identifierPattern.MatchString(capability) || index > 0 && inventory.Capabilities[index-1] == capability { return InstalledInventory{}, ErrInvalid }
	}
	claimed := inventory.Digest
	if claimed != "" && !validDigest(claimed) { return InstalledInventory{}, ErrIntegrity }
	inventory.Digest = ""
	digest, err := digestJSON(inventory)
	if err != nil || claimed != "" && claimed != digest { return InstalledInventory{}, ErrIntegrity }
	inventory.Digest = digest
	return inventory, nil
}

type ArtifactKind string

const (
	ArtifactReleaseBundle ArtifactKind = "release_bundle"
	ArtifactMigration     ArtifactKind = "migration"
)

type ArtifactFormat string

const ArtifactTar ArtifactFormat = "tar"

type Artifact struct {
	ID        string         `json:"id"`
	Component string         `json:"component"`
	Kind      ArtifactKind   `json:"kind"`
	Format    ArtifactFormat `json:"format"`
	Digest    string         `json:"digest"`
	Size      int64          `json:"size"`
}

type RolloutClass string

const (
	RolloutImmediate RolloutClass = "immediate"
	RolloutPhased    RolloutClass = "phased"
	RolloutManual    RolloutClass = "manual"
)

type RollbackClass string

const (
	RollbackFull       RollbackClass = "fully_reversible"
	RollbackBinaryOnly RollbackClass = "binary_only"
	RollbackNone       RollbackClass = "none"
)

type MigrationStep struct {
	ID             string `json:"id"`
	Order          uint32 `json:"order"`
	FromSchema     uint64 `json:"from_schema"`
	ToSchema       uint64 `json:"to_schema"`
	ArtifactID     string `json:"artifact_id"`
	ArtifactDigest string `json:"artifact_digest"`
	BackupRequired bool   `json:"backup_required"`
	ForwardOnly    bool   `json:"forward_only"`
}

type IrreversibleFrontier struct {
	StepID        string `json:"step_id,omitempty"`
	SchemaVersion uint64 `json:"schema_version,omitempty"`
}

func (frontier IrreversibleFrontier) Declared() bool { return frontier.StepID != "" }

type ManifestSignature struct {
	KeyID string `json:"key_id"`
	Epoch uint64 `json:"epoch"`
	Value []byte `json:"value"`
}

type RotationProof struct {
	FromEpoch uint64              `json:"from_epoch"`
	ToEpoch   uint64              `json:"to_epoch"`
	NewKeyIDs []string            `json:"new_key_ids"`
	Digest    string              `json:"digest"`
	Signatures []ManifestSignature `json:"signatures"`
}

type ReleaseManifest struct {
	ID                    string                 `json:"id"`
	Sequence              uint64                 `json:"sequence"`
	ReleaseVersion        Version                `json:"release_version"`
	Platform              PlatformTuple          `json:"platform"`
	SchemaCompatibility   SchemaRange            `json:"schema_compatibility"`
	RuntimeCompatibility  VersionRange           `json:"runtime_compatibility"`
	RequiredCapabilities  []string               `json:"required_capabilities"`
	Artifacts             []Artifact             `json:"artifacts"`
	ReleaseRootDigest     string                 `json:"release_root_digest"`
	Migrations            []MigrationStep        `json:"migrations"`
	SignerEpoch           uint64                 `json:"signer_epoch"`
	SignatureThreshold    uint16                 `json:"signature_threshold"`
	Rollout               RolloutClass           `json:"rollout"`
	Rollback              RollbackClass          `json:"rollback"`
	Irreversible          IrreversibleFrontier   `json:"irreversible_frontier"`
	IssuedAt              time.Time              `json:"issued_at"`
	ExpiresAt             time.Time              `json:"expires_at"`
	Digest                string                 `json:"digest"`
	Signatures            []ManifestSignature    `json:"signatures"`
	Rotation              *RotationProof         `json:"rotation,omitempty"`
}

type manifestPayload struct {
	ID                   string               `json:"id"`
	Sequence             uint64               `json:"sequence"`
	ReleaseVersion       Version              `json:"release_version"`
	Platform             PlatformTuple        `json:"platform"`
	SchemaCompatibility  SchemaRange          `json:"schema_compatibility"`
	RuntimeCompatibility VersionRange         `json:"runtime_compatibility"`
	RequiredCapabilities []string             `json:"required_capabilities"`
	Artifacts            []Artifact           `json:"artifacts"`
	ReleaseRootDigest    string               `json:"release_root_digest"`
	Migrations           []MigrationStep      `json:"migrations"`
	SignerEpoch          uint64               `json:"signer_epoch"`
	SignatureThreshold   uint16               `json:"signature_threshold"`
	Rollout              RolloutClass         `json:"rollout"`
	Rollback             RollbackClass        `json:"rollback"`
	Irreversible         IrreversibleFrontier `json:"irreversible_frontier"`
	IssuedAt             time.Time            `json:"issued_at"`
	ExpiresAt            time.Time            `json:"expires_at"`
}

func CanonicalManifest(manifest ReleaseManifest) (ReleaseManifest, error) {
	if !identifierPattern.MatchString(manifest.ID) || manifest.Sequence == 0 || manifest.Sequence > maxGeneration || manifest.Platform.Validate() != nil ||
		manifest.SchemaCompatibility.Validate() != nil || manifest.RuntimeCompatibility.Validate() != nil ||
		!validDigest(manifest.ReleaseRootDigest) || !validTime(manifest.IssuedAt) || !validTime(manifest.ExpiresAt) ||
		!manifest.ExpiresAt.After(manifest.IssuedAt) || manifest.SignerEpoch == 0 || manifest.SignatureThreshold == 0 ||
		len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > 256 || len(manifest.Migrations) > 256 || len(manifest.RequiredCapabilities) > 4096 {
		return ReleaseManifest{}, ErrInvalid
	}
	if manifest.Rollout != RolloutImmediate && manifest.Rollout != RolloutPhased && manifest.Rollout != RolloutManual ||
		manifest.Rollback != RollbackFull && manifest.Rollback != RollbackBinaryOnly && manifest.Rollback != RollbackNone {
		return ReleaseManifest{}, ErrInvalid
	}
	manifest.IssuedAt, manifest.ExpiresAt = manifest.IssuedAt.UTC(), manifest.ExpiresAt.UTC()
	manifest.RequiredCapabilities = append([]string(nil), manifest.RequiredCapabilities...)
	sort.Strings(manifest.RequiredCapabilities)
	for index, capability := range manifest.RequiredCapabilities {
		if !identifierPattern.MatchString(capability) || index > 0 && manifest.RequiredCapabilities[index-1] == capability { return ReleaseManifest{}, ErrInvalid }
	}
	manifest.Artifacts = append([]Artifact(nil), manifest.Artifacts...)
	sort.Slice(manifest.Artifacts, func(i, j int) bool { return manifest.Artifacts[i].ID < manifest.Artifacts[j].ID })
	artifactDigests := make(map[string]string, len(manifest.Artifacts))
	artifactKinds := make(map[string]ArtifactKind, len(manifest.Artifacts))
	releaseBundles := 0
	for index, artifact := range manifest.Artifacts {
		if !identifierPattern.MatchString(artifact.ID) || !identifierPattern.MatchString(artifact.Component) ||
			artifact.Kind != ArtifactReleaseBundle && artifact.Kind != ArtifactMigration || artifact.Format != ArtifactTar ||
			!validDigest(artifact.Digest) || artifact.Size <= 0 || index > 0 && manifest.Artifacts[index-1].ID == artifact.ID {
			return ReleaseManifest{}, ErrInvalid
		}
		artifactDigests[artifact.ID] = artifact.Digest
		artifactKinds[artifact.ID] = artifact.Kind
		if artifact.Kind == ArtifactReleaseBundle { releaseBundles++ }
	}
	if releaseBundles == 0 { return ReleaseManifest{}, ErrInvalid }
	manifest.Migrations = append([]MigrationStep(nil), manifest.Migrations...)
	sort.Slice(manifest.Migrations, func(i, j int) bool { return manifest.Migrations[i].Order < manifest.Migrations[j].Order })
	firstForwardOnly := ""
	var firstForwardSchema uint64
	migrationIDs := make(map[string]struct{}, len(manifest.Migrations))
	for index, step := range manifest.Migrations {
		if !identifierPattern.MatchString(step.ID) || step.Order != uint32(index+1) || step.ToSchema <= step.FromSchema ||
			artifactDigests[step.ArtifactID] != step.ArtifactDigest || artifactKinds[step.ArtifactID] != ArtifactMigration ||
			index > 0 && manifest.Migrations[index-1].ToSchema != step.FromSchema {
			return ReleaseManifest{}, ErrInvalid
		}
		if _, duplicate := migrationIDs[step.ID]; duplicate { return ReleaseManifest{}, ErrInvalid }
		migrationIDs[step.ID] = struct{}{}
		if step.ForwardOnly && firstForwardOnly == "" { firstForwardOnly, firstForwardSchema = step.ID, step.ToSchema }
		if manifest.Rollback == RollbackFull && (!step.BackupRequired || step.ForwardOnly) { return ReleaseManifest{}, ErrInvalid }
	}
	if manifest.Rollback == RollbackBinaryOnly && len(manifest.Migrations) != 0 { return ReleaseManifest{}, ErrInvalid }
	if firstForwardOnly == "" {
		if manifest.Rollback == RollbackNone {
			if manifest.Irreversible.StepID != "release_switch" || manifest.Irreversible.SchemaVersion != 0 { return ReleaseManifest{}, ErrInvalid }
		} else if manifest.Irreversible.Declared() { return ReleaseManifest{}, ErrInvalid }
	} else if manifest.Irreversible.StepID != firstForwardOnly || manifest.Irreversible.SchemaVersion != firstForwardSchema || manifest.Rollback != RollbackNone {
		return ReleaseManifest{}, ErrInvalid
	}
	manifest.Signatures = append([]ManifestSignature(nil), manifest.Signatures...)
	sort.Slice(manifest.Signatures, func(i, j int) bool { return manifest.Signatures[i].KeyID < manifest.Signatures[j].KeyID })
	if len(manifest.Signatures) < int(manifest.SignatureThreshold) || len(manifest.Signatures) > 128 { return ReleaseManifest{}, ErrInvalid }
	for index, signature := range manifest.Signatures {
		if !identifierPattern.MatchString(signature.KeyID) || signature.Epoch != manifest.SignerEpoch || len(signature.Value) != 64 ||
			index > 0 && manifest.Signatures[index-1].KeyID == signature.KeyID { return ReleaseManifest{}, ErrInvalid }
		manifest.Signatures[index].Value = append([]byte(nil), signature.Value...)
	}
	if manifest.Rotation != nil {
		rotation := *manifest.Rotation
		rotation.NewKeyIDs = append([]string(nil), rotation.NewKeyIDs...)
		sort.Strings(rotation.NewKeyIDs)
		rotation.Signatures = append([]ManifestSignature(nil), rotation.Signatures...)
		sort.Slice(rotation.Signatures, func(i, j int) bool { return rotation.Signatures[i].KeyID < rotation.Signatures[j].KeyID })
		if rotation.FromEpoch == 0 || rotation.ToEpoch != rotation.FromEpoch+1 || !validDigest(rotation.Digest) ||
			len(rotation.NewKeyIDs) == 0 || len(rotation.NewKeyIDs) > 128 || len(rotation.Signatures) == 0 || len(rotation.Signatures) > 128 { return ReleaseManifest{}, ErrInvalid }
		for index, keyID := range rotation.NewKeyIDs {
			if !identifierPattern.MatchString(keyID) || index > 0 && rotation.NewKeyIDs[index-1] == keyID { return ReleaseManifest{}, ErrInvalid }
		}
		for index, signature := range rotation.Signatures {
			if !identifierPattern.MatchString(signature.KeyID) || signature.Epoch != rotation.FromEpoch || len(signature.Value) != 64 ||
				index > 0 && rotation.Signatures[index-1].KeyID == signature.KeyID { return ReleaseManifest{}, ErrInvalid }
			rotation.Signatures[index].Value = append([]byte(nil), signature.Value...)
		}
		manifest.Rotation = &rotation
	}
	claimed := manifest.Digest
	if claimed != "" && !validDigest(claimed) { return ReleaseManifest{}, ErrIntegrity }
	payload := manifest.payload()
	digest, err := digestJSON(payload)
	if err != nil || claimed != "" && claimed != digest { return ReleaseManifest{}, ErrIntegrity }
	manifest.Digest = digest
	return manifest, nil
}

func (manifest ReleaseManifest) payload() manifestPayload {
	return manifestPayload{manifest.ID, manifest.Sequence, manifest.ReleaseVersion, manifest.Platform,
		manifest.SchemaCompatibility, manifest.RuntimeCompatibility, manifest.RequiredCapabilities,
		manifest.Artifacts, manifest.ReleaseRootDigest, manifest.Migrations, manifest.SignerEpoch,
		manifest.SignatureThreshold, manifest.Rollout, manifest.Rollback, manifest.Irreversible,
		manifest.IssuedAt, manifest.ExpiresAt}
}

type Phase string

const (
	PhaseDiscovered  Phase = "discovered"
	PhaseVerified    Phase = "verified"
	PhaseStaged      Phase = "staged"
	PhasePreflighted Phase = "preflighted"
	PhaseSwitched    Phase = "switched"
	PhaseProbing     Phase = "probing"
	PhaseCommitted   Phase = "committed"
	PhaseRolledBack  Phase = "rolled_back"
	PhaseFailed      Phase = "failed"
	PhaseUncertain   Phase = "uncertain"
)

func (phase Phase) terminal() bool { return phase == PhaseCommitted || phase == PhaseRolledBack || phase == PhaseFailed }

func validTransition(from, to Phase) bool {
	switch from {
	case PhaseDiscovered: return to == PhaseVerified || to == PhaseFailed
	case PhaseVerified: return to == PhaseStaged || to == PhaseFailed
	case PhaseStaged: return to == PhasePreflighted || to == PhaseFailed || to == PhaseUncertain
	case PhasePreflighted: return to == PhaseSwitched || to == PhaseFailed || to == PhaseUncertain
	case PhaseSwitched: return to == PhaseProbing || to == PhaseUncertain
	case PhaseProbing: return to == PhaseCommitted || to == PhaseRolledBack || to == PhaseFailed || to == PhaseUncertain
	default: return false
	}
}

type ReasonCode string

const (
	ReasonNone                 ReasonCode = "none"
	ReasonVerified             ReasonCode = "signature_and_compatibility_verified"
	ReasonStaged               ReasonCode = "artifact_staged"
	ReasonPreflighted          ReasonCode = "preflight_completed"
	ReasonSwitched             ReasonCode = "release_switched"
	ReasonHealthy              ReasonCode = "health_non_regression_proven"
	ReasonHealthRegression     ReasonCode = "health_regression"
	ReasonRolledBack           ReasonCode = "rollback_completed"
	ReasonUnprovenRollback     ReasonCode = "rollback_unproven"
	ReasonExternalUncertain    ReasonCode = "external_effect_uncertain"
	ReasonRejected             ReasonCode = "update_rejected"
)

type UpdateState struct {
	ManifestID          string     `json:"manifest_id"`
	ManifestDigest      string     `json:"manifest_digest"`
	NodeID              string     `json:"node_id"`
	Phase               Phase      `json:"phase"`
	Generation          uint64     `json:"generation"`
	Fence               uint64     `json:"fence"`
	ControllerID        string     `json:"controller_id"`
	StagedRootID        string     `json:"staged_root_id,omitempty"`
	StagedRootDigest    string     `json:"staged_root_digest,omitempty"`
	PreviousReleaseID   string     `json:"previous_release_id,omitempty"`
	PreviousReleaseDigest string   `json:"previous_release_digest,omitempty"`
	BaselineDigest      string     `json:"baseline_digest,omitempty"`
	MigrationEvidence   string     `json:"migration_evidence,omitempty"`
	MigrationProofs     []MigrationProof `json:"migration_proofs,omitempty"`
	RollbackProven      bool       `json:"rollback_proven"`
	RollbackEvidence    string     `json:"rollback_evidence,omitempty"`
	RecoveryEvidence    string     `json:"recovery_evidence,omitempty"`
	RecoverySteps       []string   `json:"recovery_steps,omitempty"`
	Reason              ReasonCode `json:"reason"`
	LastReceiptDigest   string     `json:"last_receipt_digest"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type Receipt struct {
	ID               string     `json:"id"`
	ManifestID       string     `json:"manifest_id"`
	NodeID            string     `json:"node_id"`
	From              Phase      `json:"from"`
	To                Phase      `json:"to"`
	Generation        uint64     `json:"generation"`
	Fence             uint64     `json:"fence"`
	IdempotencyKey    string     `json:"idempotency_key"`
	CommandDigest     string     `json:"command_digest"`
	EvidenceDigest    string     `json:"evidence_digest"`
	Reason            ReasonCode `json:"reason"`
	CreatedAt         time.Time  `json:"created_at"`
	Digest            string     `json:"digest"`
}

type Transition struct {
	ManifestID        string
	NodeID            string
	ExpectedGeneration uint64
	Fence              uint64
	ControllerID       string
	IdempotencyKey     string
	From               Phase
	To                 Phase
	Reason             ReasonCode
	EvidenceDigest     string
	StagedRootID       string
	StagedRootDigest   string
	PreviousReleaseID  string
	PreviousReleaseDigest string
	BaselineDigest     string
	MigrationEvidence  string
	MigrationProofs    []MigrationProof
	RollbackProven     bool
	RollbackEvidence   string
	RecoveryEvidence   string
	RecoverySteps      []string
	At                  time.Time
}

type MigrationProof struct {
	StepID            string `json:"step_id"`
	OperationDigest   string `json:"operation_digest"`
	AssessmentDigest  string `json:"assessment_digest"`
	BackupEvidence    string `json:"backup_evidence,omitempty"`
	ApplyReceiptDigest string `json:"apply_receipt_digest"`
}

type VersionProjection struct {
	NodeID        string                `json:"node_id"`
	Runtime       string                `json:"runtime"`
	SchemaVersion uint64                `json:"schema_version"`
	Components    []ComponentProjection `json:"components"`
	Capabilities  []string              `json:"capabilities"`
	ObservedAt    time.Time             `json:"observed_at"`
}

type ComponentProjection struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

func RedactedVersion(inventory InstalledInventory) (VersionProjection, error) {
	canonical, err := CanonicalInventory(inventory)
	if err != nil { return VersionProjection{}, err }
	components := make([]ComponentProjection, 0, len(canonical.Components))
	for _, component := range canonical.Components { components = append(components, ComponentProjection{component.ID, component.Version.String()}) }
	return VersionProjection{canonical.NodeID, canonical.Runtime.String(), canonical.SchemaVersion,
		components, append([]string(nil), canonical.Capabilities...), canonical.ObservedAt}, nil
}

type UpdateProjection struct {
	ManifestID string     `json:"manifest_id"`
	NodeID     string     `json:"node_id"`
	Version    string     `json:"version"`
	Channel    Channel    `json:"channel"`
	Sequence   uint64     `json:"sequence"`
	Phase      Phase      `json:"phase"`
	Generation uint64     `json:"generation"`
	Reason     ReasonCode `json:"reason"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func RedactedUpdate(manifest ReleaseManifest, state UpdateState) (UpdateProjection, error) {
	canonical, err := CanonicalManifest(manifest)
	if err != nil || state.ManifestID != canonical.ID || state.ManifestDigest != canonical.Digest { return UpdateProjection{}, ErrIntegrity }
	return UpdateProjection{canonical.ID, state.NodeID, canonical.ReleaseVersion.String(), canonical.Platform.Channel,
		canonical.Sequence, state.Phase, state.Generation, state.Reason, state.UpdatedAt}, nil
}

func digestJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil { return "", err }
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func digestParts(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		fmt.Fprintf(hash, "%d:%s\n", len(part), part)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) { return false }
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 2000 && value.Year() <= 9999
}
