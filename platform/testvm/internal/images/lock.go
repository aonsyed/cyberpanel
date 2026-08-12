// Package images parses and validates immutable virtual-machine image locks.
package images

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const (
	currentSchemaVersion = 1
	runtimePathPrefix    = ".work/qemu/images/sha256/"
	runtimeImageName     = "base.qcow2"
)

// Architecture is a supported guest CPU architecture.
type Architecture string

const (
	ArchitectureARM64 Architecture = "arm64"
	ArchitectureAMD64 Architecture = "amd64"
)

// Format is a supported virtual-machine disk format.
type Format string

const FormatQCOW2 Format = "qcow2"

// Lock is the closed, versioned image-lock document.
type Lock struct {
	SchemaVersion int     `json:"schemaVersion"`
	Images        []Image `json:"images"`
}

// Image identifies one release-pinned, content-addressed guest image.
type Image struct {
	StableID        string       `json:"stableId"`
	Distribution    string       `json:"distribution"`
	ResolvedRelease string       `json:"resolvedRelease"`
	Architecture    Architecture `json:"architecture"`
	AcquisitionURL  string       `json:"acquisitionUrl"`
	RuntimePath     string       `json:"runtimePath"`
	SHA256          string       `json:"sha256"`
	Format          Format       `json:"format"`
}

// ValidationError identifies the field whose semantic lock contract failed.
type ValidationError struct {
	Path    string
	Problem string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("image lock %s: %s", e.Path, e.Problem)
}

// Parse decodes exactly one closed JSON value and validates all lock semantics.
func Parse(data []byte) (Lock, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var lock Lock
	if err := decoder.Decode(&lock); err != nil {
		return Lock{}, fmt.Errorf("decode image lock: %w", err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Lock{}, fmt.Errorf("decode image lock: trailing JSON value")
		}
		return Lock{}, fmt.Errorf("decode image lock trailing data: %w", err)
	}

	if err := lock.Validate(); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

// Validate enforces the semantic rules that cannot be represented by Go's JSON
// decoder alone.
func (l Lock) Validate() error {
	if l.SchemaVersion != currentSchemaVersion {
		return invalid("schemaVersion", "must equal 1")
	}
	if len(l.Images) == 0 {
		return invalid("images", "must contain at least one image")
	}

	stableIDs := make(map[string]struct{}, len(l.Images))
	for index, image := range l.Images {
		path := fmt.Sprintf("images[%d]", index)
		if err := image.validate(path); err != nil {
			return err
		}
		if _, exists := stableIDs[image.StableID]; exists {
			return invalid(path+".stableId", fmt.Sprintf("duplicate stableId %q", image.StableID))
		}
		stableIDs[image.StableID] = struct{}{}
	}
	return nil
}

func (image Image) validate(recordPath string) error {
	if !isStableID(image.StableID) {
		return invalid(recordPath+".stableId", "must be a non-empty lowercase stable identifier")
	}
	if !isStableID(image.Distribution) {
		return invalid(recordPath+".distribution", "must be a non-empty lowercase stable identifier")
	}
	if !isImmutableRelease(image.ResolvedRelease) {
		return invalid(recordPath+".resolvedRelease", "must be an immutable resolvedRelease without latest or current authority")
	}

	switch image.Architecture {
	case ArchitectureARM64, ArchitectureAMD64:
	default:
		return invalid(recordPath+".architecture", "architecture must be arm64 or amd64")
	}

	if err := validateAcquisitionURL(image.AcquisitionURL); err != nil {
		return invalid(recordPath+".acquisitionUrl", err.Error())
	}
	if !isCanonicalSHA256(image.SHA256) {
		return invalid(recordPath+".sha256", "must be a 64-character canonical lowercase SHA256")
	}
	if image.Format != FormatQCOW2 {
		return invalid(recordPath+".format", "format must be qcow2")
	}

	wantRuntimePath := runtimePathPrefix + image.SHA256 + "/" + runtimeImageName
	if image.RuntimePath != wantRuntimePath {
		return invalid(recordPath+".runtimePath", "must be the immutable runtimePath bound to this SHA256")
	}
	return nil
}

func invalid(path, problem string) error {
	return &ValidationError{Path: path, Problem: problem}
}

func isStableID(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' {
			continue
		}
		if character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '-', '.', '_':
			continue
		default:
			return false
		}
	}
	return true
}

func isImmutableRelease(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' {
			continue
		}
		if character >= 'A' && character <= 'Z' {
			continue
		}
		if character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '-', '.', '_', '+':
			continue
		default:
			return false
		}
	}

	for _, token := range authorityTokens(value) {
		if token == "latest" || token == "current" {
			return false
		}
	}
	return true
}

func authorityTokens(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(character rune) bool {
		return !(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9')
	})
}

func isCanonicalSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' {
			continue
		}
		if character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func validateAcquisitionURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("must be a valid HTTPS URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("must not contain user information or a fragment")
	}
	return nil
}
