//go:build linux

package cyberpanel

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

const (
	legacyDockerRoot = "/var/lib/docker"
	legacyDockerHome = "/home/docker/"
	maximumContainerMetadataBytes = 32 << 20
	maximumContainerMetadataFiles = 4096
	maximumContainerTreeEntries = 1000000
	maximumContainerTreeDepth = 128
)

// SQLContainerSnapshotter supports only DockerSites.py's two-service bind
// layout. Neither the request nor SQL path columns confer filesystem authority.
// Docker's privileged socket and compose/shell executables are never used.
type SQLContainerSnapshotter struct {
	database *sql.DB
	maximumBytes uint64
}

func NewSQLContainerSnapshotter(database *sql.DB, maximumBytes uint64) (*SQLContainerSnapshotter, error) {
	if database == nil || maximumBytes < 1<<20 || maximumBytes > maximumSourceAgentStoredBytes {
		return nil, ErrInvalid
	}
	return &SQLContainerSnapshotter{database: database, maximumBytes: maximumBytes}, nil
}

type legacyContainerOwner struct {
	ID, WebsiteID int64
	SiteType int
	Name, Domain, FinalURL, ComposePath, SitePath, MySQLPath string
}

func (s *SQLContainerSnapshotter) owner(ctx context.Context, request ContainerArtifactRequest) (legacyContainerOwner, error) {
	var owner legacyContainerOwner
	id, err := legacyContainerNumericID(request.SourceID, "container:")
	if err != nil { return owner, err }
	websiteID, err := legacyContainerNumericID(request.SiteSourceID, "website:")
	if err != nil { return owner, err }
	prefix := "container-descriptor:"
	if request.Kind == "volume" { prefix = "container-volumes:" } else if request.Kind != "descriptor" { return owner, ErrDenied }
	if string(request.ArtifactID) != prefix+strconv.FormatInt(id, 10) { return owner, ErrDenied }
	err = s.database.QueryRowContext(ctx, `SELECT d.id,d.admin_id,d.SiteType,d.SiteName,w.domain,d.finalURL,d.ComposePath,d.SitePath,d.MySQLPath
		FROM websiteFunctions_dockersites d JOIN websiteFunctions_websites w ON w.id=d.admin_id WHERE d.id=? AND w.id=?`, id, websiteID).
		Scan(&owner.ID, &owner.WebsiteID, &owner.SiteType, &owner.Name, &owner.Domain, &owner.FinalURL, &owner.ComposePath, &owner.SitePath, &owner.MySQLPath)
	if err != nil { return owner, errors.Join(ErrDenied, err) }
	// Wordpress=1 in DockerSites.py; old model rows defaulted to 0. n8n
	// also stores 1, so actual application identity comes from runtime images.
	if owner.ID != id || owner.WebsiteID != websiteID || (owner.SiteType != 0 && owner.SiteType != 1) ||
		!validHostname(owner.Domain) || owner.Domain != normalizeHostname(owner.Domain) || owner.FinalURL != owner.Domain ||
		!validSafeToken(strings.ReplaceAll(owner.Name, " ", "-")) || len(owner.Name) > 128 {
		return owner, ErrDenied
	}
	// The producer stores an obsolete ComposePath, although deployment writes
	// /home/docker/<domain>/docker-compose.yml. Accept exactly those two values.
	if (owner.ComposePath != "/home/"+owner.Domain+"/docker-compose.yml" && owner.ComposePath != legacyDockerHome+owner.Domain+"/docker-compose.yml") ||
		owner.SitePath != "/home/"+owner.Domain+"/public_html/wpdocker" || owner.MySQLPath != "/home/"+owner.Domain+"/public_html/sqldocker" {
		return owner, ErrDenied
	}
	return owner, nil
}

func legacyContainerNumericID(value, prefix string) (int64, error) {
	if !strings.HasPrefix(value, prefix) { return 0, ErrDenied }
	text := strings.TrimPrefix(value, prefix)
	id, err := strconv.ParseInt(text, 10, 64)
	if err != nil || id < 1 || strconv.FormatInt(id, 10) != text { return 0, ErrDenied }
	return id, nil
}

type legacyDockerConfig struct {
	ID string
	Image string
	State *struct {
		Running *bool
		Paused, Restarting, RemovalInProgress, Dead bool
	}
	Config *struct {
		Image, User, WorkingDir string
		Entrypoint, Cmd, Env []string
		Labels map[string]string
	}
	MountPoints map[string]struct {
		Type, Source, Destination, Name, Driver string
		RW bool
	}
}

type legacyContainerService struct {
	Service string `json:"service"`
	RuntimeID string `json:"runtime_id"`
	Image string `json:"image"`
	ImageID string `json:"image_id"`
	User string `json:"user"`
	WorkingDirectory string `json:"working_directory"`
	Entrypoint []string `json:"entrypoint"`
	Command []string `json:"command"`
	Volume string `json:"volume"`
	Destination string `json:"destination"`
	EnvironmentKeys []string `json:"environment_keys"`
}

type legacyContainerDescriptor struct {
	Schema string `json:"schema"`
	SourceID string `json:"source_id"`
	SiteSourceID string `json:"site_source_id"`
	Domain string `json:"domain"`
	Application string `json:"application"`
	Layout string `json:"layout"`
	Stopped bool `json:"stopped"`
	VolumeArtifact ArtifactID `json:"volume_artifact"`
	Services []legacyContainerService `json:"services"`
	RestoreBlockers []string `json:"restore_blockers"`
}

type legacyRuntimeSnapshot struct {
	descriptor legacyContainerDescriptor
	digest [32]byte
}

func (s *SQLContainerSnapshotter) WriteContainerArtifact(ctx context.Context, request ContainerArtifactRequest, destination io.Writer) (uint64, error) {
	if s == nil || s.database == nil || ctx == nil || destination == nil { return 0, ErrInvalid }
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	owner, err := s.owner(ctx, request)
	if err != nil { return 0, err }
	docker, err := openLegacyFixedRoot(legacyDockerRoot)
	if err != nil { return 0, err }
	defer docker.Close()
	runtime, err := readLegacyRuntime(ctx, docker, owner, request)
	if err != nil { return 0, err }
	limited := &boundedWriter{destination: destination, remaining: s.maximumBytes}
	objects := uint64(1)
	if request.Kind == "descriptor" {
		err = json.NewEncoder(limited).Encode(runtime.descriptor)
	} else {
		home, openErr := openLegacyFixedRoot("/home")
		if openErr != nil { return 0, openErr }
		defer home.Close()
		root, openErr := legacyOpenChild(home, "docker/"+owner.Domain, syscall.O_RDONLY|syscall.O_DIRECTORY)
		if openErr != nil { return 0, openErr }
		defer root.Close()
		before, statErr := root.Stat()
		if statErr != nil { return 0, statErr }
		archive := tar.NewWriter(limited)
		budget := legacyTreeBudget{remainingEntries: maximumContainerTreeEntries, remainingScans: maximumContainerTreeEntries, remainingBytes: s.maximumBytes}
		for _, volume := range []string{"data", "db"} {
			if err = writeLegacyVolume(ctx, archive, root, volume, volume, 0, &budget); err != nil { break }
		}
		err = errors.Join(err, archive.Close())
		objects = maximumContainerTreeEntries-budget.remainingEntries
		if err == nil { err = legacyVerifyHandle(root, before) }
		if err == nil { err = legacyVerifyChild(home, "docker/"+owner.Domain, before) }
	}
	if err != nil { return 0, err }
	// Re-read SQL ownership and all runtime metadata, including unrelated
	// containers, to detect a new shared mount or concurrent runtime change.
	afterOwner, err := s.owner(ctx, request)
	if err != nil || afterOwner != owner { return 0, errors.Join(ErrChanged, err) }
	afterRuntime, err := readLegacyRuntime(ctx, docker, owner, request)
	if err != nil || afterRuntime.digest != runtime.digest { return 0, errors.Join(ErrChanged, err) }
	return objects, nil
}

func readLegacyRuntime(ctx context.Context, root *os.File, owner legacyContainerOwner, request ContainerArtifactRequest) (legacyRuntimeSnapshot, error) {
	var result legacyRuntimeSnapshot
	directory, err := legacyOpenChild(root, "containers", syscall.O_RDONLY|syscall.O_DIRECTORY)
	if err != nil { return result, err }
	defer directory.Close()
	before, err := directory.Stat()
	if err != nil || !legacyTrustedMetadata(before) { return result, errors.Join(ErrDenied, err) }
	entries, err := directory.ReadDir(maximumContainerMetadataFiles+1)
	if err != nil && !errors.Is(err, io.EOF) { return result, err }
	if len(entries) > maximumContainerMetadataFiles { return result, migration.ErrCapacity }
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	result.descriptor = legacyContainerDescriptor{
		Schema: "cyberpanel.legacy-container-descriptor/v1", SourceID: request.SourceID, SiteSourceID: request.SiteSourceID,
		Domain: owner.Domain, Layout: "docker-sites-bind-data-db/v1", Stopped: true,
		VolumeArtifact: ArtifactID("container-volumes:"+strconv.FormatInt(owner.ID, 10)),
		RestoreBlockers: []string{"target must bind an approved recipe; legacy runtime settings are inventory, not execution authority"},
	}
	hash := sha256.New()
	remaining := int64(maximumContainerMetadataBytes)
	serviceName := strings.ReplaceAll(owner.Name, " ", "-")
	path := legacyDockerHome+owner.Domain
	project := ""
	seen := map[string]bool{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil { return result, err }
		id := entry.Name()
		if !legacyDockerID(id) || !entry.IsDir() { return result, ErrDenied }
		containerRoot, err := legacyOpenChild(directory, id, syscall.O_RDONLY|syscall.O_DIRECTORY)
		if err != nil { return result, err }
		containerInfo, err := containerRoot.Stat()
		if err != nil || !legacyTrustedMetadata(containerInfo) { containerRoot.Close(); return result, errors.Join(ErrDenied, err) }
		raw, err := readLegacyMetadata(ctx, containerRoot, "config.v2.json", &remaining)
		if err == nil { err = legacyVerifyHandle(containerRoot, containerInfo) }
		containerRoot.Close()
		if err == nil { err = legacyVerifyChild(directory, id, containerInfo) }
		if err != nil { wipe(raw); return result, err }
		hash.Write([]byte(id))
		digest := sha256.Sum256(raw)
		hash.Write(digest[:])
		var config legacyDockerConfig
		err = json.Unmarshal(raw, &config)
		wipe(raw)
		if err != nil || config.ID != id || config.Config == nil || config.State == nil || config.State.Running == nil { return result, ErrDenied }
		labels := config.Config.Labels
		owned := labels["com.docker.compose.project.config_files"] == path+"/docker-compose.yml" && labels["com.docker.compose.project.working_dir"] == path
		// No second container may consume these data, including an ancestor bind
		// such as /home. Named volumes and non-bind mounts cannot prove this layout.
		for _, mount := range config.MountPoints {
			if legacyPathsOverlap(mount.Source, path) && !owned { return result, ErrDenied }
		}
		if !owned { continue }
		service := labels["com.docker.compose.service"]
		if (service != serviceName && service != serviceName+"-db") || seen[service] ||
			*config.State.Running || config.State.Paused || config.State.Restarting || config.State.RemovalInProgress || config.State.Dead ||
			labels["com.docker.compose.oneoff"] != "False" || labels["com.docker.compose.container-number"] != "1" || len(config.MountPoints) != 1 {
			return result, ErrDenied
		}
		if labels["com.docker.compose.project"] == "" { return result, ErrDenied }
		if project == "" { project = labels["com.docker.compose.project"] } else if project != labels["com.docker.compose.project"] { return result, ErrDenied }
		volume := "data"
		if service == serviceName+"-db" { volume = "db" }
		value := legacyContainerService{Service: service, RuntimeID: id, Image: config.Config.Image, ImageID: config.Image,
			User: config.Config.User, WorkingDirectory: config.Config.WorkingDir, Entrypoint: config.Config.Entrypoint, Command: config.Config.Cmd,
			Volume: volume, EnvironmentKeys: []string{}}
		if !strings.HasPrefix(value.ImageID, "sha256:") || !legacyDockerID(strings.TrimPrefix(value.ImageID, "sha256:")) { return result, ErrDenied }
		for key, mount := range config.MountPoints {
			if mount.Type != "bind" || mount.Source != path+"/"+volume || !mount.RW || mount.Name != "" || mount.Driver != "" || key != mount.Destination { return result, ErrDenied }
			value.Destination = mount.Destination
		}
		// Environment values are credentials in both legacy producers. They are
		// not copied into plaintext descriptor JSON or silently called portable.
		keys := map[string]bool{}
		for _, environment := range config.Config.Env {
			key, _, ok := strings.Cut(environment, "=")
			if !ok || !validSafeToken(key) || keys[key] { return result, ErrDenied }
			keys[key] = true
			value.EnvironmentKeys = append(value.EnvironmentKeys, key)
		}
		sort.Strings(value.EnvironmentKeys)
		if len(value.EnvironmentKeys) > 0 {
			result.descriptor.RestoreBlockers = append(result.descriptor.RestoreBlockers,
				"rebind environment for service "+service+" through target secret authority; values intentionally omitted: "+strings.Join(value.EnvironmentKeys, ","))
		}
		seen[service] = true
		result.descriptor.Services = append(result.descriptor.Services, value)
	}
	if len(seen) != 2 { return result, ErrDenied }
	sort.Slice(result.descriptor.Services, func(i, j int) bool { return result.descriptor.Services[i].Volume < result.descriptor.Services[j].Volume })
	app, database := result.descriptor.Services[0], result.descriptor.Services[1]
	switch {
	case legacyImageName(app.Image) == "cyberpanel/openlitespeed" && legacyImageName(database.Image) == "mariadb" && app.Destination == "/usr/local/lsws/Example/html" && database.Destination == "/var/lib/mysql":
		result.descriptor.Application = "wordpress"
	case legacyImageName(app.Image) == "docker.n8n.io/n8nio/n8n" && legacyImageName(database.Image) == "postgres" && app.Destination == "/home/node/.n8n" && database.Destination == "/var/lib/postgresql/data":
		result.descriptor.Application = "n8n"
	default:
		return result, ErrDenied
	}
	if err := legacyVerifyHandle(directory, before); err != nil { return result, err }
	if err := legacyVerifyChild(root, "containers", before); err != nil { return result, err }
	copy(result.digest[:], hash.Sum(nil))
	return result, nil
}

func legacyImageName(value string) string {
	if index := strings.IndexByte(value, '@'); index >= 0 { value = value[:index] }
	if index := strings.LastIndexByte(value, ':'); index > strings.LastIndexByte(value, '/') { value = value[:index] }
	return strings.TrimPrefix(strings.TrimPrefix(value, "docker.io/"), "library/")
}

func legacyDockerID(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value { return false }
	_, err := hex.DecodeString(value)
	return err == nil
}

func legacyPathsOverlap(left, right string) bool {
	if left == "" { return false }
	return left == "/" || left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, strings.TrimSuffix(left, "/")+"/")
}

// Fixed roots may themselves reside on a dedicated filesystem. Everything
// below them uses NO_XDEV, including bind mounts on the same device. A kernel
// without openat2 fails closed; there is no weaker pathname fallback.
func openLegacyFixedRoot(path string) (*os.File, error) {
	if path != "/home" && path != legacyDockerRoot { return nil, ErrDenied }
	root, err := os.Open("/")
	if err != nil { return nil, err }
	defer root.Close()
	file, err := legacyOpenat2(root, strings.TrimPrefix(path, "/"), syscall.O_RDONLY|syscall.O_DIRECTORY, false)
	if err != nil { return nil, err }
	info, err := file.Stat()
	if err != nil || !legacyTrustedMetadata(info) { file.Close(); return nil, errors.Join(ErrDenied, err) }
	return file, nil
}

func legacyOpenChild(root *os.File, relative string, flags int) (*os.File, error) {
	return legacyOpenat2(root, relative, flags, true)
}

func legacyOpenat2(root *os.File, relative string, flags int, noMounts bool) (*os.File, error) {
	if root == nil || !safeRelativeName(relative) { return nil, ErrDenied }
	name, err := syscall.BytePtrFromString(relative)
	if err != nil { return nil, ErrDenied }
	// RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS.
	how := struct { Flags, Mode, Resolve uint64 }{Flags: uint64(flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK), Resolve: 0x08|0x04|0x02}
	if noMounts { how.Resolve |= 0x01 }
	fd, _, errno := syscall.Syscall6(437, root.Fd(), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if errno != 0 { return nil, errors.Join(ErrDenied, errno) }
	return os.NewFile(fd, relative), nil
}

func legacyTrustedMetadata(info os.FileInfo) bool {
	if info == nil || info.Mode().Perm()&0o022 != 0 { return false }
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && (info.IsDir() || (info.Mode().IsRegular() && stat.Nlink == 1))
}

func legacyStableState(left, right os.FileInfo) bool {
	if !sameFileState(left, right) || left.Mode() != right.Mode() { return false }
	a, aOK := left.Sys().(*syscall.Stat_t)
	b, bOK := right.Sys().(*syscall.Stat_t)
	return aOK && bOK && a.Ctim == b.Ctim && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink
}

func legacyVerifyHandle(file *os.File, before os.FileInfo) error {
	after, err := file.Stat()
	if err != nil || !legacyStableState(before, after) { return errors.Join(ErrChanged, err) }
	return nil
}

func legacyVerifyChild(parent *os.File, name string, before os.FileInfo) error {
	flags := syscall.O_RDONLY
	if before.IsDir() { flags |= syscall.O_DIRECTORY }
	file, err := legacyOpenChild(parent, name, flags)
	if err != nil { return errors.Join(ErrChanged, err) }
	defer file.Close()
	return legacyVerifyHandle(file, before)
}

func readLegacyMetadata(ctx context.Context, root *os.File, name string, remaining *int64) ([]byte, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	file, err := legacyOpenChild(root, name, syscall.O_RDONLY)
	if err != nil { return nil, err }
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || !legacyTrustedMetadata(before) || before.Size() < 1 || before.Size() > 2<<20 || before.Size() > *remaining {
		return nil, errors.Join(ErrDenied, err)
	}
	var buffer bytes.Buffer
	_, err = copyWithContext(ctx, &buffer, io.LimitReader(file, before.Size()+1))
	raw := buffer.Bytes()
	if err != nil || int64(len(raw)) != before.Size() { wipe(raw); return nil, errors.Join(ErrChanged, err) }
	if err = legacyVerifyHandle(file, before); err == nil { err = legacyVerifyChild(root, name, before) }
	if err != nil { wipe(raw); return nil, err }
	*remaining -= int64(len(raw))
	return raw, nil
}

type legacyTreeBudget struct {
	remainingEntries uint64
	remainingScans uint64
	remainingBytes uint64
}

func writeLegacyVolume(ctx context.Context, archive *tar.Writer, parent *os.File, name, archiveName string, depth int, budget *legacyTreeBudget) error {
	if err := ctx.Err(); err != nil { return err }
	if depth > maximumContainerTreeDepth || budget.remainingEntries == 0 { return migration.ErrCapacity }
	file, err := legacyOpenChild(parent, name, syscall.O_RDONLY)
	if err != nil { return err }
	defer file.Close()
	before, err := file.Stat()
	if err != nil { return err }
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || (!before.IsDir() && !before.Mode().IsRegular()) || (before.Mode().IsRegular() && stat.Nlink != 1) { return ErrDenied }
	if depth == 0 && !before.IsDir() { return ErrDenied }
	budget.remainingEntries--
	header := &tar.Header{Name: archiveName, Mode: int64(before.Mode().Perm()), Uid: int(stat.Uid), Gid: int(stat.Gid), ModTime: before.ModTime()}
	if before.IsDir() {
		header.Typeflag = tar.TypeDir
		header.Name += "/"
		if err := archive.WriteHeader(header); err != nil { return err }
		// ReadDir is bounded globally; never load an unbounded directory list.
		entries, err := file.ReadDir(int(budget.remainingScans)+1)
		if err != nil && !errors.Is(err, io.EOF) { return err }
		if uint64(len(entries)) > budget.remainingScans { return migration.ErrCapacity }
		budget.remainingScans -= uint64(len(entries))
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			child := entry.Name()
			if child == "" || child == "." || child == ".." || strings.ContainsAny(child, "/\\\x00") { return ErrDenied }
			if err := writeLegacyVolume(ctx, archive, file, child, archiveName+"/"+child, depth+1, budget); err != nil { return err }
		}
	} else {
		if before.Size() < 0 || uint64(before.Size()) > budget.remainingBytes { return migration.ErrCapacity }
		budget.remainingBytes -= uint64(before.Size())
		header.Typeflag = tar.TypeReg
		header.Size = before.Size()
		if err := archive.WriteHeader(header); err != nil { return err }
		count, err := copyWithContext(ctx, archive, io.LimitReader(file, before.Size()+1))
		if err != nil || count != before.Size() { return errors.Join(ErrChanged, err) }
	}
	if err := legacyVerifyHandle(file, before); err != nil { return err }
	return legacyVerifyChild(parent, name, before)
}

var _ ContainerSnapshotter = (*SQLContainerSnapshotter)(nil)
