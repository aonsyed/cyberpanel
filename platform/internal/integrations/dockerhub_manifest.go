//go:build linux

package integrations

import (
	"sort"
	"strings"
	"time"
)

const (
	dockerManifestV2     = "application/vnd.docker.distribution.manifest.v2+json"
	dockerManifestListV2 = "application/vnd.docker.distribution.manifest.list.v2+json"
	ociImageManifestV1   = "application/vnd.oci.image.manifest.v1+json"
	ociImageIndexV1      = "application/vnd.oci.image.index.v1+json"
	dockerHubManifestAccept = dockerManifestListV2 + ", " + ociImageIndexV1 + ", " + dockerManifestV2 + ", " + ociImageManifestV1
)

type dockerHubManifestDocument struct {
	SchemaVersion int                    `json:"schemaVersion"`
	MediaType     string                 `json:"mediaType"`
	ArtifactType  string                 `json:"artifactType,omitempty"`
	Config        *dockerHubDescriptor   `json:"config,omitempty"`
	Layers        []dockerHubDescriptor  `json:"layers,omitempty"`
	Manifests     []dockerHubDescriptor  `json:"manifests,omitempty"`
	Subject       *dockerHubDescriptor   `json:"subject,omitempty"`
	Annotations   map[string]string      `json:"annotations,omitempty"`
}

type dockerHubDescriptor struct {
	MediaType    string                     `json:"mediaType"`
	Digest       string                     `json:"digest"`
	Size         int64                      `json:"size"`
	URLs         []string                   `json:"urls,omitempty"`
	Annotations  map[string]string          `json:"annotations,omitempty"`
	Data         string                     `json:"data,omitempty"`
	ArtifactType string                     `json:"artifactType,omitempty"`
	Platform     *dockerHubPlatform         `json:"platform,omitempty"`
}

type dockerHubPlatform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	Variant      string   `json:"variant,omitempty"`
	OSVersion    string   `json:"os.version,omitempty"`
	OSFeatures   []string `json:"os.features,omitempty"`
	Features     []string `json:"features,omitempty"`
}

func normalizeDockerHubManifest(reference OCIReference, mediaType string, body []byte, digest string, observedAt time.Time) (OCIManifest, error) {
	if !validDockerHubReference(reference) || !validDockerHubManifestMediaType(mediaType) || !validDockerHubDigest(digest) ||
		len(body) == 0 || len(body) > dockerHubMaximumManifestBytes || observedAt.IsZero() {
		return OCIManifest{}, dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "invalid_manifest", ErrIntegrity, 0)
	}
	var document dockerHubManifestDocument
	if dockerHubDecodeJSON(body, &document) != nil || document.SchemaVersion != 2 || document.MediaType != mediaType ||
		document.ArtifactType != "" || document.Subject != nil || !validDockerHubAnnotations(document.Annotations) {
		return OCIManifest{}, dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "invalid_manifest", ErrIntegrity, 0)
	}
	platforms := make([]string, 0)
	switch mediaType {
	case dockerManifestV2, ociImageManifestV1:
		if document.Config == nil || document.Manifests != nil || len(document.Layers) > 2048 || validateDockerHubDescriptor(*document.Config, false) != nil ||
			!validDockerHubConfigMediaType(mediaType, document.Config.MediaType) {
			return OCIManifest{}, dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "invalid_image_manifest", ErrIntegrity, 0)
		}
		for _, layer := range document.Layers {
			if validateDockerHubDescriptor(layer, false) != nil || !validDockerHubLayerMediaType(layer.MediaType) {
				return OCIManifest{}, dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "invalid_layer", ErrIntegrity, 0)
			}
		}
	case dockerManifestListV2, ociImageIndexV1:
		if document.Config != nil || document.Layers != nil || len(document.Manifests) == 0 || len(document.Manifests) > 1024 {
			return OCIManifest{}, dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "invalid_image_index", ErrIntegrity, 0)
		}
		seen := make(map[string]struct{}, len(document.Manifests))
		for _, descriptor := range document.Manifests {
			if validateDockerHubDescriptor(descriptor, true) != nil {
				return OCIManifest{}, dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "invalid_image_index", ErrIntegrity, 0)
			}
			platform, include, err := normalizeDockerHubPlatform(descriptor)
			if err != nil {
				return OCIManifest{}, err
			}
			if !include {
				continue
			}
			if _, duplicate := seen[platform]; duplicate {
				return OCIManifest{}, dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "duplicate_platform", ErrIntegrity, 0)
			}
			seen[platform] = struct{}{}
			platforms = append(platforms, platform)
		}
		if len(platforms) == 0 {
			return OCIManifest{}, dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "missing_platforms", ErrIntegrity, 0)
		}
		sort.Strings(platforms)
	default:
		return OCIManifest{}, ErrUnsupported
	}
	reference.Registry = "registry-1.docker.io"
	return OCIManifest{Reference: reference, ResolvedDigest: digest, MediaType: mediaType, Platforms: platforms, Size: int64(len(body)),
		SignatureState: "not_evaluated", ObservedAt: observedAt.UTC()}, nil
}

func validateDockerHubDescriptor(descriptor dockerHubDescriptor, indexed bool) error {
	if !validDockerHubDigest(descriptor.Digest) || descriptor.Size <= 0 || descriptor.Size > 1<<50 || len(descriptor.MediaType) == 0 ||
		len(descriptor.MediaType) > 256 || strings.ContainsAny(descriptor.MediaType, "\x00\r\n\t ") || len(descriptor.URLs) != 0 ||
		descriptor.Data != "" || descriptor.ArtifactType != "" || !validDockerHubAnnotations(descriptor.Annotations) {
		return ErrIntegrity
	}
	if indexed {
		if descriptor.MediaType != dockerManifestV2 && descriptor.MediaType != ociImageManifestV1 || descriptor.Platform == nil {
			return ErrIntegrity
		}
	} else if descriptor.Platform != nil {
		return ErrIntegrity
	}
	return nil
}

func normalizeDockerHubPlatform(descriptor dockerHubDescriptor) (string, bool, error) {
	platform := descriptor.Platform
	if platform == nil {
		return "", false, ErrIntegrity
	}
	if platform.OS == "unknown" && platform.Architecture == "unknown" {
		return "", false, nil
	}
	if !validDockerHubPlatformToken(platform.OS) || !validDockerHubPlatformToken(platform.Architecture) ||
		platform.Variant != "" && !validDockerHubPlatformToken(platform.Variant) || len(platform.OSVersion) > 128 ||
		strings.ContainsAny(platform.OSVersion, "\x00\r\n\t") || !validDockerHubPlatformFeatures(platform.OSFeatures) || !validDockerHubPlatformFeatures(platform.Features) {
		return "", false, dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "invalid_platform", ErrIntegrity, 0)
	}
	normalized := platform.OS + "/" + platform.Architecture
	if platform.Variant != "" {
		normalized += "/" + platform.Variant
	}
	return normalized, true, nil
}

func validDockerHubPlatformToken(value string) bool {
	if value == "" || len(value) > 64 || strings.ToLower(value) != value {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '_' && character != '-' && character != '.' {
					return false
				}
			}
		}
	}
	return true
}

func validDockerHubPlatformFeatures(features []string) bool {
	if len(features) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(features))
	for _, feature := range features {
		if !validDockerHubPlatformToken(feature) {
			return false
		}
		if _, duplicate := seen[feature]; duplicate {
			return false
		}
		seen[feature] = struct{}{}
	}
	return true
}

func validDockerHubAnnotations(annotations map[string]string) bool {
	if len(annotations) > 256 {
		return false
	}
	for key, value := range annotations {
		if key == "" || len(key) > 256 || len(value) > 4096 || strings.ContainsAny(key, "\x00\r\n\t") || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	return true
}

func validDockerHubManifestMediaType(mediaType string) bool {
	switch mediaType {
	case dockerManifestV2, dockerManifestListV2, ociImageManifestV1, ociImageIndexV1:
		return true
	default:
		return false
	}
}

func validDockerHubConfigMediaType(manifestMediaType, configMediaType string) bool {
	if manifestMediaType == dockerManifestV2 {
		return configMediaType == "application/vnd.docker.container.image.v1+json"
	}
	return manifestMediaType == ociImageManifestV1 && configMediaType == "application/vnd.oci.image.config.v1+json"
}

func validDockerHubLayerMediaType(mediaType string) bool {
	switch mediaType {
	case "application/vnd.docker.image.rootfs.diff.tar", "application/vnd.docker.image.rootfs.diff.tar.gzip",
		"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd",
		"application/vnd.oci.image.layer.nondistributable.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd":
		return true
	default:
		return false
	}
}

func validDockerHubManifestEvidence(manifest OCIManifest, now time.Time) bool {
	if !validDockerHubReference(manifest.Reference) || !validDockerHubDigest(manifest.ResolvedDigest) || !validDockerHubManifestMediaType(manifest.MediaType) ||
		manifest.Size <= 0 || manifest.Size > dockerHubMaximumManifestBytes || manifest.SignatureState != "not_evaluated" || manifest.SBOMRef != "" ||
		manifest.VulnerabilityRef != "" || manifest.ObservedAt.IsZero() || manifest.ObservedAt.After(now.Add(time.Minute)) || manifest.ObservedAt.Before(now.Add(-10*time.Minute)) ||
		manifest.Reference.Digest != "" && manifest.Reference.Digest != manifest.ResolvedDigest {
		return false
	}
	isIndex := manifest.MediaType == dockerManifestListV2 || manifest.MediaType == ociImageIndexV1
	if isIndex != (len(manifest.Platforms) > 0) {
		return false
	}
	previous := ""
	for _, platform := range manifest.Platforms {
		parts := strings.Split(platform, "/")
		if len(parts) < 2 || len(parts) > 3 || !validDockerHubPlatformToken(parts[0]) || !validDockerHubPlatformToken(parts[1]) ||
			len(parts) == 3 && !validDockerHubPlatformToken(parts[2]) || platform <= previous {
			return false
		}
		previous = platform
	}
	return true
}
