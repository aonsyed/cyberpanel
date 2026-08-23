package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

const (
	localArtifactCatalogPath = "/etc/cyberpanel/webengine/catalog.json"
	localArtifactCatalogLimit = 8 << 20
	localPHPArtifactCatalogPath = "/etc/cyberpanel/webengine/php-catalog.json"
	localPHPArtifactTrustRoot = "/etc/cyberpanel/webengine/php-trust.d"
	localPHPArtifactCatalogLimit = 8 << 20
)

type localArtifactCatalog struct {
	SchemaVersion uint32 `json:"schema_version"`
	Digest string `json:"digest"`
	Entries []localArtifactCatalogEntry `json:"entries"`
}

type localArtifactCatalogEntry struct {
	OS string `json:"os"`
	OSVersion string `json:"os_version"`
	Architecture string `json:"architecture"`
	Channel Channel `json:"channel"`
	Plan ArtifactPlan `json:"plan"`
}

type localPHPCatalogPayload struct {
	SchemaVersion uint32 `json:"schema_version"`
	Sequence uint64 `json:"sequence"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	KeyID string `json:"key_id"`
	Entries []localPHPCatalogEntry `json:"entries"`
}

type signedLocalPHPCatalog struct {
	SchemaVersion uint32 `json:"schema_version"`
	Sequence uint64 `json:"sequence"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	KeyID string `json:"key_id"`
	Entries []localPHPCatalogEntry `json:"entries"`
	Signature string `json:"signature"`
}

type localPHPCatalogEntry struct {
	OS string `json:"os"`
	OSVersion string `json:"os_version"`
	Architecture string `json:"architecture"`
	Version string `json:"version"`
	RepositorySnapshotDigest string `json:"repository_snapshot_digest"`
	BinaryPathID string `json:"binary_path_id"`
	Packages []PackageArtifact `json:"packages"`
	Extensions []string `json:"extensions"`
}

func (runtime *Runtime) ResolvePHP(ctx context.Context, version string, extensions []string) (PHPArtifactPlan, error) {
	if runtime == nil || runtime.lifecycle == nil {
		return PHPArtifactPlan{}, ErrInvalid
	}
	return resolveLocalPHPArtifact(ctx, version, extensions, false)
}

func resolveLocalPHPArtifact(ctx context.Context, version string, extensions []string, requireRoot bool) (PHPArtifactPlan, error) {
	if ctx == nil || ctx.Err() != nil || !validPHPVersion(version) {
		return PHPArtifactPlan{}, ErrInvalid
	}
	wantedExtensions := canonicalExtensions(extensions)
	if len(extensions) != len(wantedExtensions) || !equalStrings(wantedExtensions, wantedExtensions) {
		return PHPArtifactPlan{}, ErrInvalid
	}
	osName, osVersion, architecture, err := localPlatformTuple()
	if err != nil {
		return PHPArtifactPlan{}, err
	}
	payload, digest, err := readSignedLocalPHPCatalog(requireRoot, time.Now().UTC())
	if err != nil {
		return PHPArtifactPlan{}, err
	}
	var selected PHPArtifactPlan
	for _, entry := range payload.Entries {
		if validateLocalPHPEntry(entry) != nil {
			return PHPArtifactPlan{}, ErrInvalid
		}
		if entry.OS != osName || entry.OSVersion != osVersion || entry.Architecture != architecture || entry.Version != version || !equalStrings(entry.Extensions, wantedExtensions) {
			continue
		}
		if selected.Version != "" {
			return PHPArtifactPlan{}, ErrConflict
		}
		selected = PHPArtifactPlan{Version: entry.Version, RepositorySnapshotDigest: entry.RepositorySnapshotDigest,
			BinaryPathID: entry.BinaryPathID, CatalogDigest: digest, CatalogSequence: payload.Sequence,
			Packages: append([]PackageArtifact(nil), entry.Packages...), Extensions: append([]string(nil), entry.Extensions...)}
	}
	if selected.Version == "" {
		return PHPArtifactPlan{}, ErrUnsupported
	}
	return selected, nil
}

func readSignedLocalPHPCatalog(requireRoot bool, now time.Time) (localPHPCatalogPayload, string, error) {
	info, err := os.Lstat(localPHPArtifactCatalogPath)
	if err != nil {
		return localPHPCatalogPayload{}, "", err
	}
	if !safeLocalCatalogFile(info, localPHPArtifactCatalogLimit, requireRoot) {
		return localPHPCatalogPayload{}, "", ErrInvalid
	}
	content, err := os.ReadFile(localPHPArtifactCatalogPath)
	if err != nil {
		return localPHPCatalogPayload{}, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var signed signedLocalPHPCatalog
	if decoder.Decode(&signed) != nil || decoder.Decode(&struct{}{}) != io.EOF || signed.SchemaVersion != 1 || signed.Sequence == 0 ||
		signed.IssuedAt.IsZero() || signed.ExpiresAt.IsZero() || signed.IssuedAt.After(now.Add(5*time.Minute)) || !signed.ExpiresAt.After(now) ||
		!signed.ExpiresAt.After(signed.IssuedAt) || signed.ExpiresAt.Sub(signed.IssuedAt) > 370*24*time.Hour || !safeLifecycleToken(signed.KeyID) ||
		len(signed.Entries) == 0 || len(signed.Entries) > 4096 {
		return localPHPCatalogPayload{}, "", ErrInvalid
	}
	payload := localPHPCatalogPayload{SchemaVersion: signed.SchemaVersion, Sequence: signed.Sequence, IssuedAt: signed.IssuedAt,
		ExpiresAt: signed.ExpiresAt, KeyID: signed.KeyID, Entries: signed.Entries}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return localPHPCatalogPayload{}, "", err
	}
	key, err := readLocalPHPTrustKey(signed.KeyID, requireRoot)
	if err != nil {
		return localPHPCatalogPayload{}, "", err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, canonical, signature) {
		return localPHPCatalogPayload{}, "", ErrConflict
	}
	for _, entry := range payload.Entries {
		if validateLocalPHPEntry(entry) != nil {
			return localPHPCatalogPayload{}, "", ErrInvalid
		}
	}
	return payload, linuxManagementDigest(canonical), nil
}

func readLocalPHPTrustKey(keyID string, requireRoot bool) (ed25519.PublicKey, error) {
	path := filepath.Join(localPHPArtifactTrustRoot, keyID+".pub")
	if filepath.Dir(path) != localPHPArtifactTrustRoot {
		return nil, ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !safeLocalCatalogFile(info, 4096, requireRoot) {
		return nil, ErrInvalid
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(content)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	return ed25519.PublicKey(decoded), nil
}

func safeLocalCatalogFile(info os.FileInfo, limit int64, requireRoot bool) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0 &&
		info.Size() > 0 && info.Size() <= limit && (!requireRoot || rootOwnedFile(info))
}

func validateLocalPHPEntry(entry localPHPCatalogEntry) error {
	if !validLifecycleTuple(entry.OS, entry.OSVersion, entry.Architecture) || !validPHPVersion(entry.Version) ||
		!validSHA256(entry.RepositorySnapshotDigest) || entry.BinaryPathID != "lsphp"+strings.ReplaceAll(entry.Version, ".", "") ||
		len(entry.Packages) == 0 || len(entry.Packages) > 64 || len(entry.Extensions) > 32 ||
		!equalStrings(entry.Extensions, canonicalExtensions(entry.Extensions)) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, item := range entry.Packages {
		if !safeLifecycleToken(item.Name) || !safeLifecycleVersion(item.Version) || !validSHA256(item.Digest) ||
			!safeLifecycleToken(item.RepositoryID) || seen[item.Name] || item.Name != entry.BinaryPathID && !strings.HasPrefix(item.Name, entry.BinaryPathID+"-") {
			return ErrInvalid
		}
		seen[item.Name] = true
	}
	return nil
}

func resolveLocalArtifact(ctx context.Context, request ArtifactRequest, requireRoot bool) (ArtifactPlan, error) {
	if ctx == nil || ctx.Err() != nil || request.Edition != webengine.EditionOpenLiteSpeed && request.Edition != webengine.EditionLiteSpeedEnterprise || !validChannel(request.Channel) || !safeLifecycleVersion(request.Version) {
		return ArtifactPlan{}, ErrInvalid
	}
	if request.OS == "" || request.OSVersion == "" || request.Architecture == "" {
		osName, osVersion, architecture, err := localPlatformTuple()
		if err != nil { return ArtifactPlan{}, err }
		if request.OS == "" { request.OS = osName }
		if request.OSVersion == "" { request.OSVersion = osVersion }
		if request.Architecture == "" { request.Architecture = architecture }
	}
	if !validLifecycleTuple(request.OS, request.OSVersion, request.Architecture) { return ArtifactPlan{}, ErrUnsupported }
	catalog, err := readLocalArtifactCatalog(requireRoot)
	if err != nil { return ArtifactPlan{}, err }
	var selected ArtifactPlan
	for _, entry := range catalog.Entries {
		if !validLifecycleTuple(entry.OS, entry.OSVersion, entry.Architecture) || !validChannel(entry.Channel) || validateArtifactPlan(entry.Plan) != nil { return ArtifactPlan{}, ErrInvalid }
		if entry.OS != request.OS || entry.OSVersion != request.OSVersion || entry.Architecture != request.Architecture || entry.Channel != request.Channel || entry.Plan.Edition != request.Edition || entry.Plan.Version != request.Version { continue }
		if selected.Version != "" { return ArtifactPlan{}, ErrConflict }
		selected = entry.Plan
	}
	if selected.Version == "" { return ArtifactPlan{}, ErrUnsupported }
	return selected, nil
}

func readLocalArtifactCatalog(requireRoot bool)(localArtifactCatalog,error){info,err:=os.Lstat(localArtifactCatalogPath);if err!=nil{return localArtifactCatalog{},err};if !info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0o022!=0||info.Size()<=0||info.Size()>localArtifactCatalogLimit||requireRoot&&!rootOwnedFile(info){return localArtifactCatalog{},ErrInvalid};content,err:=os.ReadFile(localArtifactCatalogPath);if err!=nil{return localArtifactCatalog{},err};if len(content)==0||len(content)>localArtifactCatalogLimit{return localArtifactCatalog{},ErrInvalid};decoder:=json.NewDecoder(bytes.NewReader(content));decoder.DisallowUnknownFields();var catalog localArtifactCatalog;if err=decoder.Decode(&catalog);err!=nil||decoder.Decode(&struct{}{})!=io.EOF||catalog.SchemaVersion!=1||!validSHA256(catalog.Digest)||len(catalog.Entries)==0||len(catalog.Entries)>1024{return localArtifactCatalog{},ErrInvalid};if digestJSON(catalog.Entries)!=catalog.Digest{return localArtifactCatalog{},ErrConflict};for _,entry:=range catalog.Entries{if !validLifecycleTuple(entry.OS,entry.OSVersion,entry.Architecture)||!validChannel(entry.Channel)||validateArtifactPlan(entry.Plan)!=nil{return localArtifactCatalog{},ErrInvalid}};return catalog,nil}

func validateArtifactPlan(plan ArtifactPlan) error {
	if plan.Edition != webengine.EditionOpenLiteSpeed && plan.Edition != webengine.EditionLiteSpeedEnterprise || !safeLifecycleVersion(plan.Version) || !validSHA256(plan.ArtifactDigest) || !validSHA256(plan.RepositorySnapshotDigest) || len(plan.Packages) == 0 || len(plan.Packages) > 32 || plan.ServiceProfileID != "systemd-lsws-v1" { return ErrInvalid }
	if plan.Edition == webengine.EditionOpenLiteSpeed && plan.NativeConfigFormat != "ols-text-v1" || plan.Edition == webengine.EditionLiteSpeedEnterprise && plan.NativeConfigFormat != "lse-xml-v1" { return ErrInvalid }
	seen := map[string]bool{}
	for _, item := range plan.Packages {
		if !safeLifecycleToken(item.Name) || !safeLifecycleVersion(item.Version) || !validSHA256(item.Digest) || !safeLifecycleToken(item.RepositoryID) || seen[item.Name] { return ErrInvalid }
		if plan.Edition == webengine.EditionOpenLiteSpeed && item.Name != "openlitespeed" || plan.Edition == webengine.EditionLiteSpeedEnterprise && item.Name != "lsws" { return ErrUnsupported }
		seen[item.Name] = true
	}
	return nil
}

func localPlatformTuple() (string, string, string, error) {
	architecture := runtime.GOARCH
	if architecture != "amd64" && architecture != "arm64" { return "", "", "", ErrUnsupported }
	content, err := os.ReadFile("/etc/os-release")
	if err != nil || len(content) == 0 || len(content) > 64<<10 { return "", "", "", ErrUnsupported }
	values := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") { key, value, found := strings.Cut(line, "="); if found { values[key] = strings.Trim(strings.TrimSpace(value), "\"") } }
	switch values["ID"] {
	case "ubuntu": if values["VERSION_ID"] != "24.04" { return "", "", "", ErrUnsupported }; return "ubuntu", "24.04", architecture, nil
	case "almalinux": if !strings.HasPrefix(values["VERSION_ID"], "9") { return "", "", "", ErrUnsupported }; return "almalinux", "9", architecture, nil
	default: return "", "", "", ErrUnsupported
	}
}

func validLifecycleTuple(osName, version, architecture string) bool { return (osName == "ubuntu" && version == "24.04" || osName == "almalinux" && version == "9") && (architecture == "amd64" || architecture == "arm64") }
func validChannel(value Channel) bool { return value == ChannelStable || value == ChannelPinned || value == ChannelLTS }
func safeLifecycleToken(value string) bool { if value == "" || len(value) > 128 { return false }; for index := range value { character:=value[index]; if character>127 || !(character>='a'&&character<='z'||character>='A'&&character<='Z'||character>='0'&&character<='9'||character=='-'||character=='_'||character=='.') { return false } }; return true }
func safeLifecycleVersion(value string) bool { return safeLifecycleToken(value) && !strings.Contains(value, "..") }

// rootOwnedFile is overridden by the Linux host's metadata check. Keeping the
// catalog reader portable lets API-side resolution fail closed on non-Linux.
var rootOwnedFile = func(os.FileInfo) bool { return true }
