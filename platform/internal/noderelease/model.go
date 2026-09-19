// Package noderelease defines the closed, signed contract used to assemble and
// install a CyberPanel node release without network access.
package noderelease

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const ManifestSchema uint16 = 1

var (
	ErrInvalid     = errors.New("node release: invalid resource")
	ErrIntegrity   = errors.New("node release: integrity verification failed")
	ErrUntrusted   = errors.New("node release: signature is not trusted")
	ErrExpired     = errors.New("node release: manifest is not currently valid")
	ErrUnsupported = errors.New("node release: unsupported target")
	ErrRollback    = errors.New("node release: rollback or source frontier rejected")
	ErrConflict    = errors.New("node release: conflicting durable operation")
	ErrNotFound    = errors.New("node release: resource not found")
	ErrRecovery    = errors.New("node release: manual recovery required")
	identifier     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	packageName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:-]{0,191}$`)
	packageVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+.:~_-]{0,191}$`)
	unitName       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,191}\.(service|socket|timer|path)$`)
)

type Version struct {
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
	Patch uint32 `json:"patch"`
}

func (version Version) Compare(other Version) int {
	if version.Major != other.Major {
		if version.Major < other.Major {
			return -1
		}
		return 1
	}
	if version.Minor != other.Minor {
		if version.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if version.Patch < other.Patch {
		return -1
	}
	if version.Patch > other.Patch {
		return 1
	}
	return 0
}

func (version Version) String() string {
	return fmt.Sprintf("%d.%d.%d", version.Major, version.Minor, version.Patch)
}

func (version Version) zero() bool {
	return version == (Version{})
}

type VersionRange struct {
	Minimum Version `json:"minimum"`
	Maximum Version `json:"maximum"`
}

func (value VersionRange) Includes(version Version) bool {
	return version.Compare(value.Minimum) >= 0 && version.Compare(value.Maximum) <= 0
}

func (value VersionRange) validate() error {
	if value.Minimum.Compare(value.Maximum) > 0 {
		return ErrInvalid
	}
	return nil
}

type SchemaRange struct {
	Minimum uint64 `json:"minimum"`
	Maximum uint64 `json:"maximum"`
}

func (value SchemaRange) Includes(schema uint64) bool {
	return schema >= value.Minimum && schema <= value.Maximum
}

func (value SchemaRange) validate() error {
	if value.Maximum < value.Minimum {
		return ErrInvalid
	}
	return nil
}

type Distribution string

const (
	DistributionUbuntu Distribution = "ubuntu"
	DistributionAlma   Distribution = "almalinux"
)

type Architecture string

const (
	ArchitectureAMD64 Architecture = "amd64"
	ArchitectureARM64 Architecture = "arm64"
)

type Target struct {
	Distribution Distribution `json:"distribution"`
	Release      string       `json:"release"`
	Codename     string       `json:"codename"`
	Architecture Architecture `json:"architecture"`
}

func (target Target) Validate() error {
	if target.Architecture != ArchitectureAMD64 && target.Architecture != ArchitectureARM64 {
		return ErrUnsupported
	}
	switch target.Distribution {
	case DistributionUbuntu:
		if target.Release != "24.04" || target.Codename != "noble" {
			return ErrUnsupported
		}
	case DistributionAlma:
		if target.Release != "9" || target.Codename != "el9" {
			return ErrUnsupported
		}
	default:
		return ErrUnsupported
	}
	return nil
}

func (target Target) Key() string {
	return strings.Join([]string{string(target.Distribution), target.Release, target.Codename, string(target.Architecture)}, "/")
}

type ArtifactKind string

const (
	ArtifactBinary  ArtifactKind = "binary"
	ArtifactConfig  ArtifactKind = "config"
	ArtifactUnit    ArtifactKind = "systemd_unit"
	ArtifactPackage ArtifactKind = "os_package"
)

type PackageManager string

const (
	PackageDPKG PackageManager = "dpkg"
	PackageRPM  PackageManager = "rpm"
)

type PackageMetadata struct {
	Manager      PackageManager `json:"manager"`
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Architecture string         `json:"architecture"`
}

func (metadata PackageMetadata) validate(target Target) error {
	if !packageName.MatchString(metadata.Name) || !packageVersion.MatchString(metadata.Version) {
		return ErrInvalid
	}
	expectedManager := PackageDPKG
	expectedArchitecture := string(target.Architecture)
	if target.Distribution == DistributionAlma {
		expectedManager = PackageRPM
		if target.Architecture == ArchitectureAMD64 {
			expectedArchitecture = "x86_64"
		} else {
			expectedArchitecture = "aarch64"
		}
	}
	if metadata.Manager != expectedManager || metadata.Architecture != expectedArchitecture {
		return ErrUnsupported
	}
	return nil
}

type Artifact struct {
	ID          string           `json:"id"`
	Kind        ArtifactKind     `json:"kind"`
	SHA256      string           `json:"sha256"`
	Size        int64            `json:"size"`
	Destination string           `json:"destination,omitempty"`
	UID         uint32           `json:"uid"`
	GID         uint32           `json:"gid"`
	Mode        string           `json:"mode"`
	Package     *PackageMetadata `json:"package,omitempty"`
}

func (artifact Artifact) PayloadPath() string {
	return "payload/" + artifact.ID
}

func (artifact Artifact) FileMode() (uint32, error) {
	if len(artifact.Mode) != 4 || artifact.Mode[0] != '0' {
		return 0, ErrInvalid
	}
	value, err := strconv.ParseUint(artifact.Mode, 8, 32)
	if err != nil || value > 0777 {
		return 0, ErrInvalid
	}
	return uint32(value), nil
}

func (artifact Artifact) validate(target Target) error {
	if !identifier.MatchString(artifact.ID) || !validDigest(artifact.SHA256) || artifact.Size <= 0 || artifact.Size > 4<<30 {
		return ErrInvalid
	}
	mode, err := artifact.FileMode()
	if err != nil || artifact.UID != 0 || artifact.GID != 0 {
		return ErrInvalid
	}
	if artifact.Kind == ArtifactPackage {
		if artifact.Destination != "" || mode != 0600 || artifact.Package == nil {
			return ErrInvalid
		}
		return artifact.Package.validate(target)
	}
	if artifact.Kind == ArtifactConfig || artifact.Kind == ArtifactUnit {
		if artifact.Size > 16<<20 {
			return ErrInvalid
		}
	} else if artifact.Kind == ArtifactBinary && artifact.Size > 1<<30 {
		return ErrInvalid
	}
	if artifact.Package != nil || !allowedDestination(artifact.Kind, artifact.Destination) || forbiddenReleasePath(artifact.Destination) {
		return ErrInvalid
	}
	switch artifact.Kind {
	case ArtifactBinary:
		if mode != 0555 && mode != 0755 {
			return ErrInvalid
		}
	case ArtifactConfig:
		if mode != 0444 && mode != 0644 {
			return ErrInvalid
		}
	case ArtifactUnit:
		if mode != 0644 || !unitName.MatchString(filepath.Base(artifact.Destination)) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type ServiceProbe struct {
	Unit           string `json:"unit"`
	TimeoutSeconds uint16 `json:"timeout_seconds"`
}

func (probe ServiceProbe) validate() error {
	if !unitName.MatchString(probe.Unit) || probe.TimeoutSeconds < 1 || probe.TimeoutSeconds > 600 {
		return ErrInvalid
	}
	return nil
}

type RollbackMetadata struct {
	Strategy              string `json:"strategy"`
	RetainPrevious        bool   `json:"retain_previous"`
	ReinstallPackages     bool   `json:"reinstall_packages"`
	MinimumRetained       uint8  `json:"minimum_retained"`
	ActivationProbeWindow uint16 `json:"activation_probe_window_seconds"`
}

func (metadata RollbackMetadata) validate() error {
	if metadata.Strategy != "retain_previous_release" || !metadata.RetainPrevious || !metadata.ReinstallPackages ||
		metadata.MinimumRetained < 1 || metadata.ActivationProbeWindow < 10 || metadata.ActivationProbeWindow > 1800 {
		return ErrInvalid
	}
	return nil
}

type Manifest struct {
	SchemaVersion  uint16           `json:"schema_version"`
	ReleaseID      string           `json:"release_id"`
	Sequence       uint64           `json:"sequence"`
	ProductVersion Version          `json:"product_version"`
	ProductSchema  uint64           `json:"product_schema"`
	Target         Target           `json:"target"`
	FreshInstall   bool             `json:"fresh_install"`
	UpgradeSource  VersionRange     `json:"upgrade_source"`
	SourceSchema   SchemaRange      `json:"source_schema"`
	Artifacts      []Artifact       `json:"artifacts"`
	InstallOrder   []string         `json:"install_order"`
	Services       []ServiceProbe   `json:"services"`
	Rollback       RollbackMetadata `json:"rollback"`
	IssuedAt       time.Time        `json:"issued_at"`
	ExpiresAt      time.Time        `json:"expires_at"`
	ManifestDigest string           `json:"manifest_digest"`
}

type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	KeyID     string   `json:"key_id"`
	Signature string   `json:"signature"`
}

func CanonicalManifest(manifest Manifest) (Manifest, error) {
	if manifest.SchemaVersion != ManifestSchema || !identifier.MatchString(manifest.ReleaseID) || manifest.Sequence == 0 ||
		manifest.ProductVersion.zero() || manifest.ProductSchema == 0 || manifest.Target.Validate() != nil ||
		manifest.UpgradeSource.validate() != nil || manifest.SourceSchema.validate() != nil || manifest.Rollback.validate() != nil ||
		len(manifest.Artifacts) < 4 || len(manifest.Artifacts) > 4096 || len(manifest.InstallOrder) != len(manifest.Artifacts) ||
		len(manifest.Services) == 0 || len(manifest.Services) > 256 || !canonicalTime(manifest.IssuedAt) ||
		!canonicalTime(manifest.ExpiresAt) || !manifest.ExpiresAt.After(manifest.IssuedAt) ||
		manifest.ExpiresAt.Sub(manifest.IssuedAt) > 30*24*time.Hour {
		return Manifest{}, ErrInvalid
	}
	manifest.Artifacts = append([]Artifact(nil), manifest.Artifacts...)
	sort.Slice(manifest.Artifacts, func(i, j int) bool { return manifest.Artifacts[i].ID < manifest.Artifacts[j].ID })
	byID := make(map[string]Artifact, len(manifest.Artifacts))
	destinations := make(map[string]bool, len(manifest.Artifacts))
	kinds := map[ArtifactKind]int{}
	var total int64
	for index, artifact := range manifest.Artifacts {
		if artifact.validate(manifest.Target) != nil || index > 0 && manifest.Artifacts[index-1].ID == artifact.ID ||
			total > 16<<30-artifact.Size {
			return Manifest{}, ErrInvalid
		}
		total += artifact.Size
		if artifact.Destination != "" {
			if destinations[artifact.Destination] {
				return Manifest{}, ErrInvalid
			}
			destinations[artifact.Destination] = true
		}
		byID[artifact.ID] = artifact
		kinds[artifact.Kind]++
	}
	for _, kind := range []ArtifactKind{ArtifactBinary, ArtifactConfig, ArtifactUnit, ArtifactPackage} {
		if kinds[kind] == 0 {
			return Manifest{}, ErrInvalid
		}
	}
	manifest.InstallOrder = append([]string(nil), manifest.InstallOrder...)
	ordered := make(map[string]bool, len(manifest.InstallOrder))
	seenNonPackage := false
	for _, id := range manifest.InstallOrder {
		artifact, exists := byID[id]
		if !exists || ordered[id] {
			return Manifest{}, ErrInvalid
		}
		if artifact.Kind == ArtifactPackage && seenNonPackage {
			return Manifest{}, ErrInvalid
		}
		if artifact.Kind != ArtifactPackage {
			seenNonPackage = true
		}
		ordered[id] = true
	}
	manifest.Services = append([]ServiceProbe(nil), manifest.Services...)
	sort.Slice(manifest.Services, func(i, j int) bool { return manifest.Services[i].Unit < manifest.Services[j].Unit })
	units := make(map[string]bool, len(manifest.Services))
	var probeSeconds uint64
	for index, service := range manifest.Services {
		if service.validate() != nil || index > 0 && manifest.Services[index-1].Unit == service.Unit {
			return Manifest{}, ErrInvalid
		}
		units[service.Unit] = false
		probeSeconds += uint64(service.TimeoutSeconds)
	}
	if probeSeconds > uint64(manifest.Rollback.ActivationProbeWindow) {
		return Manifest{}, ErrInvalid
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind == ArtifactUnit {
			if _, exists := units[filepath.Base(artifact.Destination)]; exists {
				units[filepath.Base(artifact.Destination)] = true
			}
		}
	}
	for _, present := range units {
		if !present {
			return Manifest{}, ErrInvalid
		}
	}
	claimed := manifest.ManifestDigest
	if claimed != "" && !validDigest(claimed) {
		return Manifest{}, ErrIntegrity
	}
	manifest.ManifestDigest = ""
	payload, err := json.Marshal(manifest)
	if err != nil {
		return Manifest{}, err
	}
	sum := sha256.Sum256(payload)
	manifest.ManifestDigest = hex.EncodeToString(sum[:])
	if claimed != "" && claimed != manifest.ManifestDigest {
		return Manifest{}, ErrIntegrity
	}
	return manifest, nil
}

func (manifest Manifest) SignedBytes() ([]byte, error) {
	canonical, err := CanonicalManifest(manifest)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

func (manifest Manifest) Artifact(id string) (Artifact, bool) {
	for _, artifact := range manifest.Artifacts {
		if artifact.ID == id {
			return artifact, true
		}
	}
	return Artifact{}, false
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func allowedDestination(kind ArtifactKind, destination string) bool {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || strings.Contains(destination, "\x00") {
		return false
	}
	switch kind {
	case ArtifactBinary:
		return pathBelow(destination, "/usr/local/bin") || pathBelow(destination, "/usr/local/sbin") || pathBelow(destination, "/usr/local/libexec/cyberpanel")
	case ArtifactConfig:
		return pathBelow(destination, "/etc/cyberpanel")
	case ArtifactUnit:
		return filepath.Dir(destination) == "/etc/systemd/system"
	default:
		return false
	}
}

func pathBelow(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func forbiddenReleasePath(path string) bool {
	if path == "/usr/local/sbin/panel-node-install" || path == "/etc/systemd/system/panel-node-release-reconcile.service" {
		return true
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, protected := range []string{
		"/etc/cyberpanel/node-release", "/etc/cyberpanel/secrets", "/etc/cyberpanel/credentials",
		"/etc/cyberpanel/node-identity", "/etc/cyberpanel/host-identity", "/etc/cyberpanel/identity",
	} {
		if lower == protected || strings.HasPrefix(lower, protected+"/") {
			return true
		}
	}
	for _, fragment := range []string{
		"/secrets/", "/secret/", "/credentials/", "/private/", "/machine-id", "/hostname", "/ssh_host_",
		"/shadow", "/gshadow", "/passwd", "/token", "/identity/", "/node-id", "/node_id",
	} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}
