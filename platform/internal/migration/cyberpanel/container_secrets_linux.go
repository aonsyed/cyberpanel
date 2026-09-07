//go:build linux

package cyberpanel

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

// Only source identities and observed state are retained between discovery and
// sealing. Plaintext is freshly read under the same authority and then wiped.
type legacyContainerBinding struct {
	owner legacyContainerOwner
	digest [32]byte
	migrationID migration.ID
}

type legacyEnvironmentSecret struct {
	Schema string `json:"schema"`
	SecretRef SecretRef `json:"secret_ref"`
	SourceID string `json:"source_id"`
	SiteSourceID string `json:"site_source_id"`
	Service string `json:"service"`
	RuntimeID string `json:"runtime_id"`
	Environment map[string]string `json:"environment"`
}

func legacyEnvironmentRef(owner legacyContainerOwner, volume string) SecretRef {
	return SecretRef("container-environment:"+strconv.FormatInt(owner.ID, 10)+":"+strconv.FormatInt(owner.WebsiteID, 10)+":"+volume)
}

func (snapshot *legacyRuntimeSnapshot) clearSecrets() {
	for ref, value := range snapshot.environments {
		wipe(value)
		delete(snapshot.environments, ref)
	}
}

// This wrapper runs before HostSource registers artifacts, so Extractor's
// ordinary inventory includes these refs in generation hashes and encrypted
// container-secret envelopes. It does not widen the selected SQL inventory.
type legacyContainerSecretCollector struct {
	collector Collector
	snapshotter *SQLContainerSnapshotter
}

func (c *legacyContainerSecretCollector) Collect(ctx context.Context, request CollectRequest) (Snapshot, error) {
	if c == nil || c.collector == nil || c.snapshotter == nil || ctx == nil { return Snapshot{}, ErrInvalid }
	c.snapshotter.mu.Lock()
	c.snapshotter.bindings = nil
	c.snapshotter.mu.Unlock()
	snapshot, err := c.collector.Collect(ctx, request)
	if err != nil { return Snapshot{}, err }
	if !request.Selection.Containers { return snapshot, nil }
	if len(snapshot.Containers) > maximumContainerMetadataFiles { return Snapshot{}, migration.ErrCapacity }
	bindings := make(map[string]legacyContainerBinding, len(snapshot.Containers))
	for index := range snapshot.Containers {
		container := &snapshot.Containers[index]
		if len(container.Secrets) != 0 { return Snapshot{}, ErrDenied }
		artifactRequest := ContainerArtifactRequest{SourceID: container.SourceID, SiteSourceID: container.SiteSourceID,
			ArtifactID: container.DescriptorArtifact, Kind: "descriptor"}
		owner, runtime, err := c.snapshotter.checkedRuntime(ctx, artifactRequest)
		if err != nil { return Snapshot{}, err }
		for _, service := range runtime.descriptor.Services {
			container.Secrets = append(container.Secrets, service.EnvironmentSecretRef)
		}
		bindings[container.SourceID] = legacyContainerBinding{owner: owner, digest: runtime.digest, migrationID: request.MigrationID}
		runtime.clearSecrets()
	}
	c.snapshotter.mu.Lock()
	c.snapshotter.bindings = bindings
	c.snapshotter.mu.Unlock()
	return snapshot, nil
}

func (s *SQLContainerSnapshotter) binding(request ContainerArtifactRequest) (legacyContainerBinding, error) {
	if s == nil { return legacyContainerBinding{}, ErrInvalid }
	s.mu.RLock()
	binding, ok := s.bindings[request.SourceID]
	s.mu.RUnlock()
	if !ok || request.SiteSourceID != "website:"+strconv.FormatInt(binding.owner.WebsiteID, 10) { return legacyContainerBinding{}, ErrDenied }
	return binding, nil
}

// checkedRuntime brackets discovery with a second complete runtime scan and
// SQL ownership read. Caller owns and must wipe the returned secret buffers.
func (s *SQLContainerSnapshotter) checkedRuntime(ctx context.Context, request ContainerArtifactRequest) (owner legacyContainerOwner, snapshot legacyRuntimeSnapshot, resultErr error) {
	defer func() { if resultErr != nil { snapshot.clearSecrets() } }()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	owner, err := s.owner(ctx, request)
	if err != nil { return owner, snapshot, err }
	root, err := openLegacyFixedRoot(legacyDockerRoot)
	if err != nil { return owner, snapshot, err }
	defer root.Close()
	snapshot, err = readLegacyRuntime(ctx, root, owner, request)
	if err != nil { return owner, snapshot, err }
	after, err := readLegacyRuntime(ctx, root, owner, request)
	defer after.clearSecrets()
	if err != nil || after.digest != snapshot.digest { return owner, snapshot, errors.Join(ErrChanged, err) }
	afterOwner, err := s.owner(ctx, request)
	if err != nil || afterOwner != owner { return owner, snapshot, errors.Join(ErrChanged, err) }
	return owner, snapshot, nil
}

func (s *SQLContainerSnapshotter) ReadSecret(ctx context.Context, ref SecretRef) ([]byte, error) {
	if s == nil || ctx == nil || !ref.Valid() { return nil, ErrInvalid }
	// An arbitrary ref cannot turn this reader into a metadata query surface:
	// it must have been generated from the current approved SQL selection.
	var sourceID string
	var binding legacyContainerBinding
	s.mu.RLock()
	for id, candidate := range s.bindings {
		if ref == legacyEnvironmentRef(candidate.owner, "data") || ref == legacyEnvironmentRef(candidate.owner, "db") {
			sourceID, binding = id, candidate
			break
		}
	}
	s.mu.RUnlock()
	if sourceID == "" { return nil, migration.ErrNotFound }
	request := ContainerArtifactRequest{SourceID: sourceID, SiteSourceID: "website:"+strconv.FormatInt(binding.owner.WebsiteID, 10),
		ArtifactID: ArtifactID("container-descriptor:"+strconv.FormatInt(binding.owner.ID, 10)), Kind: "descriptor"}
	owner, snapshot, err := s.checkedRuntime(ctx, request)
	defer snapshot.clearSecrets()
	if err != nil { return nil, err }
	if owner != binding.owner || snapshot.digest != binding.digest { return nil, ErrChanged }
	value, ok := snapshot.environments[ref]
	if !ok || len(value) == 0 || len(value) > maximumMigrationSecretBytes { return nil, ErrDenied }
	return append([]byte(nil), value...), nil
}

var _ Collector = (*legacyContainerSecretCollector)(nil)
var _ SecretSource = (*SQLContainerSnapshotter)(nil)
