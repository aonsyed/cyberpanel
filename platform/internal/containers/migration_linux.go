//go:build linux

package containers

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type migrationVolumeJournal struct {
	Plan       MigrationVolumePlan
	State      string
	Received   uint64
	Files      uint64
	TreeDigest string
	Workload   linuxRuntimeResource
}

// This journal intentionally lives outside the generic broker effect cache:
// observe must read the actual volume/container, and an interrupted chunk is
// reconciled against its durable byte offset, never a cached success response.
func (runtime *LinuxContainerRuntime) MigrationContainer(ctx context.Context, request MigrationContainerRequest) (MigrationContainerReceipt, error) {
	if err := request.Validate(runtime.clock().UTC()); err != nil {
		return MigrationContainerReceipt{}, err
	}
	verifier, err := LoadDefaultLinuxRecipeVerifier()
	if err != nil {
		return MigrationContainerReceipt{}, err
	}
	if err = verifier.Verify(ctx, request.Plan.Recipe); err != nil {
		return MigrationContainerReceipt{}, err
	}
	if request.Action == "stage" {
		capability, inspectErr := runtime.InspectRuntime(ctx)
		if inspectErr != nil || !capability.Rootless || !capability.UserNamespaces || !capability.CgroupV2 || !capability.Seccomp || !capability.MAC {
			return MigrationContainerReceipt{}, errors.Join(ErrPolicy, inspectErr)
		}
	}

	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	root := filepath.Join(runtime.config.StateRoot, "migration-inbound")
	if err = ensureContainerDirectory(root, 0o700, 0, 0); err != nil {
		return MigrationContainerReceipt{}, err
	}
	// The resource key, unlike the plan digest, prevents a changed plan from
	// claiming an already allocated volume under a second ingress journal.
	key := digestContainerValue(struct{ Tenant, Volume ID }{request.Plan.TenantID, request.Plan.VolumeID})
	directory := filepath.Join(root, key)
	if err = ensureContainerDirectory(directory, 0o700, 0, 0); err != nil {
		return MigrationContainerReceipt{}, err
	}
	journalPath := filepath.Join(directory, "receipt.json")
	journal := migrationVolumeJournal{Plan: request.Plan, State: "receiving"}
	raw, readErr := readBoundedContainerFile(journalPath, 16<<20)
	if readErr == nil {
		if json.Unmarshal(raw, &journal) != nil || digestContainerValue(journal.Plan) != digestContainerValue(request.Plan) {
			return MigrationContainerReceipt{}, ErrConflict
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return MigrationContainerReceipt{}, readErr
	} else {
		if request.Action != "begin" {
			return MigrationContainerReceipt{}, ErrNotFound
		}
		if _, exists := runtime.state.Workloads[request.Plan.WorkloadID]; exists {
			return MigrationContainerReceipt{}, ErrConflict
		}
		if _, exists := runtime.state.MigrationWorkloads[request.Plan.WorkloadID]; exists {
			return MigrationContainerReceipt{}, ErrConflict
		}
		volume, exists := runtime.state.Volumes[request.Plan.VolumeID]
		if !exists || volume.TenantID != request.Plan.TenantID || volume.Generation != 1 || volume.QuotaBytes != request.Plan.Recipe.Volumes[0].QuotaBytes || volume.InodeLimit != request.Plan.Recipe.Volumes[0].InodeLimit {
			return MigrationContainerReceipt{}, ErrConflict
		}
		if err = runtime.migrationUnusedVolume(ctx, volume, ""); err != nil {
			return MigrationContainerReceipt{}, err
		}
		mount, mountErr := runtime.migrationMount(ctx, volume)
		if mountErr != nil {
			return MigrationContainerReceipt{}, mountErr
		}
		entries, entriesErr := os.ReadDir(mount)
		if entriesErr != nil || len(entries) != 0 {
			return MigrationContainerReceipt{}, errors.Join(ErrConflict, entriesErr)
		}
		if err = saveMigrationVolume(journalPath, journal); err != nil {
			return MigrationContainerReceipt{}, err
		}
	}
	if journal.State == "discarded" {
		if request.Action != "discard" {
			return MigrationContainerReceipt{}, ErrConflict
		}
		return runtime.migrationReceipt(journal), nil
	}
	if journal.State == "discarding" && request.Action != "discard" {
		return MigrationContainerReceipt{}, ErrConflict
	}
	volume, exists := runtime.state.Volumes[request.Plan.VolumeID]
	if !exists || volume.TenantID != request.Plan.TenantID || volume.Generation != 1 || volume.QuotaBytes != request.Plan.Recipe.Volumes[0].QuotaBytes || volume.InodeLimit != request.Plan.Recipe.Volumes[0].InodeLimit {
		return MigrationContainerReceipt{}, ErrConflict
	}
	if err = runtime.migrationUnusedVolume(ctx, volume, journal.Workload.RuntimeObjectID); err != nil {
		return MigrationContainerReceipt{}, err
	}

	switch request.Action {
	case "begin":
	case "chunk":
		if journal.State != "receiving" {
			return MigrationContainerReceipt{}, ErrConflict
		}
		if err = receiveMigrationVolume(directory, &journal, request); err != nil {
			return MigrationContainerReceipt{}, err
		}
		if err = saveMigrationVolume(journalPath, journal); err != nil {
			return MigrationContainerReceipt{}, err
		}
	case "seal":
		if journal.State == "receiving" || journal.State == "sealing" {
			if err = runtime.sealMigrationVolume(ctx, directory, journalPath, volume, &journal); err != nil {
				return MigrationContainerReceipt{}, err
			}
		}
		if journal.State != "sealed" && journal.State != "staged" {
			return MigrationContainerReceipt{}, ErrConflict
		}
		if err = runtime.observeMigrationVolume(ctx, volume, journal); err != nil {
			return MigrationContainerReceipt{}, err
		}
	case "observe":
		if journal.State != "sealed" && journal.State != "staged" {
			return MigrationContainerReceipt{}, ErrAmbiguous
		}
		if err = runtime.observeMigrationVolume(ctx, volume, journal); err != nil {
			return MigrationContainerReceipt{}, err
		}
	case "stage":
		if journal.State != "sealed" && journal.State != "creating" && journal.State != "staged" {
			return MigrationContainerReceipt{}, ErrConflict
		}
		if err = runtime.observeMigrationVolume(ctx, volume, journal); err != nil {
			return MigrationContainerReceipt{}, err
		}
		if err = runtime.stageMigrationWorkload(ctx, journalPath, request.Grant, &journal); err != nil {
			return MigrationContainerReceipt{}, err
		}
	case "discard":
		if err = runtime.discardMigrationVolume(ctx, directory, journalPath, volume, &journal); err != nil {
			return MigrationContainerReceipt{}, err
		}
	default:
		return MigrationContainerReceipt{}, ErrPolicy
	}
	if journal.State == "staged" {
		if err = runtime.observeStagedMigration(ctx, journal); err != nil {
			return MigrationContainerReceipt{}, err
		}
	}
	return runtime.migrationReceipt(journal), nil
}

func (runtime *LinuxContainerRuntime) migrationReceipt(journal migrationVolumeJournal) MigrationContainerReceipt {
	plan := journal.Plan
	receipt := MigrationContainerReceipt{EffectID: plan.EffectID(), PlanDigest: digestContainerValue(plan), State: journal.State, ArchiveDigest: plan.Digest, TreeDigest: journal.TreeDigest, RuntimeObjectID: journal.Workload.RuntimeObjectID, MigrationID: plan.MigrationID, ApplicationID: plan.ApplicationID, VolumeID: plan.VolumeID, WorkloadID: plan.WorkloadID, Received: journal.Received, Bytes: plan.Bytes, Files: journal.Files, ObservedAt: runtime.clock().UTC()}
	evidence := receipt
	// Evidence is stable across observation retries; freshness stays in ObservedAt.
	evidence.ObservedAt = time.Time{}
	evidence.EvidenceDigest = ""
	receipt.EvidenceDigest = digestContainerValue(evidence)
	return receipt
}

func saveMigrationVolume(filename string, journal migrationVolumeJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return atomicContainerFile(filename, raw, 0o600)
}

func removeMigrationArchive(directory string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = root.Remove("archive.tar"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func receiveMigrationVolume(directory string, journal *migrationVolumeJournal, request MigrationContainerRequest) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile("archive.tar", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) < journal.Received {
		return errors.Join(ErrAmbiguous, err)
	}
	if uint64(info.Size()) != journal.Received {
		if err = file.Truncate(int64(journal.Received)); err != nil {
			return err
		}
	}
	data := request.Data
	offset := request.Offset
	if offset < journal.Received {
		confirmed := uint64(len(data))
		if confirmed > journal.Received-offset {
			confirmed = journal.Received - offset
		}
		prior := make([]byte, confirmed)
		if _, err = file.ReadAt(prior, int64(offset)); err != nil {
			return err
		}
		if !bytes.Equal(prior, data[:confirmed]) {
			return ErrConflict
		}
		data = data[confirmed:]
		offset += confirmed
		if len(data) == 0 {
			return nil
		}
	}
	if offset != journal.Received {
		return ErrConflict
	}
	written, err := file.WriteAt(data, int64(journal.Received))
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	journal.Received += uint64(written)
	return nil
}

func (runtime *LinuxContainerRuntime) migrationUnusedVolume(ctx context.Context, record linuxRuntimeResource, allowed string) error {
	if err := runtime.inspectManagedVolume(ctx, record); err != nil {
		return err
	}
	output, _, err := runtime.run(ctx, TierTenantRootless, runtime.config.PodmanPath, []string{"ps", "--all", "--filter", "volume=" + record.RuntimeObjectID, "--format", "json"}, nil)
	if err != nil {
		return err
	}
	var rows []struct {
		Names []string
		State string
	}
	if json.Unmarshal(output, &rows) != nil {
		return ErrInvalid
	}
	for _, row := range rows {
		if allowed == "" || len(row.Names) != 1 || row.Names[0] != allowed || (row.State != "created" && row.State != "configured") {
			return ErrInUse
		}
	}
	return nil
}

func (runtime *LinuxContainerRuntime) migrationMount(ctx context.Context, record linuxRuntimeResource) (string, error) {
	if err := runtime.inspectManagedVolume(ctx, record); err != nil {
		return "", err
	}
	output, _, err := runtime.run(ctx, TierTenantRootless, runtime.config.PodmanPath, []string{"volume", "inspect", "--format", "json", "--", record.RuntimeObjectID}, nil)
	if err != nil {
		return "", err
	}
	var rows []struct{ Mountpoint string }
	if json.Unmarshal(output, &rows) != nil || len(rows) != 1 {
		return "", ErrInvalid
	}
	// The normal named-volume layout is mandatory. Do not accept plugin mount
	// points or caller-selected roots even if they fall under rootless storage.
	expected := filepath.Join(runtime.config.RootlessHome, ".local", "share", "containers", "storage", "volumes", record.RuntimeObjectID, "_data")
	if rows[0].Mountpoint != expected {
		return "", ErrPolicy
	}
	return expected, nil
}

func (runtime *LinuxContainerRuntime) sealMigrationVolume(ctx context.Context, directory, journalPath string, volume linuxRuntimeResource, journal *migrationVolumeJournal) error {
	if journal.Received != journal.Plan.Bytes {
		return ErrConflict
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	archive, err := root.OpenFile("archive.tar", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer archive.Close()
	if err = verifyMigrationArchive(ctx, archive, journal.Plan); err != nil {
		return err
	}
	mount, err := runtime.migrationMount(ctx, volume)
	if err != nil {
		return err
	}
	parent, err := os.OpenRoot(filepath.Dir(mount))
	if err != nil {
		return err
	}
	defer parent.Close()
	staging := ".migration-" + digestContainerValue(journal.Plan)
	if journal.State == "sealing" && journal.TreeDigest != "" {
		digest, files, observeErr := runtime.migrationTree(ctx, mount, journal.Plan)
		if observeErr == nil && digest == journal.TreeDigest && files == journal.Files {
			journal.State = "sealed"
			return saveMigrationVolume(journalPath, *journal)
		}
	}
	// Recovery deletes only the exact private tree reserved by this journal.
	if err = parent.RemoveAll(staging); err != nil {
		return err
	}
	if err = parent.Mkdir(staging, 0o700); err != nil {
		return err
	}
	journal.State = "sealing"
	if err = saveMigrationVolume(journalPath, *journal); err != nil {
		return err
	}
	stage, err := parent.OpenRoot(staging)
	if err != nil {
		return err
	}
	defer stage.Close()
	if _, err = archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err = runtime.extractMigrationTar(ctx, archive, stage, journal.Plan); err != nil {
		return err
	}
	stagePath := filepath.Join(filepath.Dir(mount), staging)
	digest, files, err := runtime.migrationTree(ctx, stagePath, journal.Plan)
	if err != nil {
		return err
	}
	journal.TreeDigest = digest
	journal.Files = files
	if err = saveMigrationVolume(journalPath, *journal); err != nil {
		return err
	}
	if err = runtime.migrationUnusedVolume(ctx, volume, ""); err != nil {
		return err
	}
	current, err := parent.OpenRoot("_data")
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(current.FS(), ".")
	current.Close()
	if err != nil || len(entries) != 0 {
		return errors.Join(ErrConflict, err)
	}
	if err = parent.Rename(staging, "_data"); err != nil {
		return err
	}
	directoryFile, err := os.Open(filepath.Dir(mount))
	if err != nil {
		return err
	}
	err = directoryFile.Sync()
	directoryFile.Close()
	if err != nil {
		return err
	}
	journal.State = "sealed"
	return saveMigrationVolume(journalPath, *journal)
}

func verifyMigrationArchive(ctx context.Context, file *os.File, plan MigrationVolumePlan) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	whole := sha256.New()
	buffer := make([]byte, 128<<10)
	for _, piece := range plan.Pieces {
		if err := ctx.Err(); err != nil {
			return err
		}
		part := sha256.New()
		count, err := io.CopyBuffer(io.MultiWriter(whole, part), io.LimitReader(file, int64(piece.Bytes)), buffer)
		if err != nil || uint64(count) != piece.Bytes || hex.EncodeToString(part.Sum(nil)) != piece.Digest {
			return errors.Join(ErrConflict, err)
		}
	}
	var extra [1]byte
	n, err := file.Read(extra[:])
	if n != 0 || err != io.EOF || hex.EncodeToString(whole.Sum(nil)) != plan.Digest {
		return ErrConflict
	}
	return nil
}

func (runtime *LinuxContainerRuntime) extractMigrationTar(ctx context.Context, archive io.Reader, root *os.Root, plan MigrationVolumePlan) error {
	reader := tar.NewReader(archive)
	seen := map[string]bool{}
	var total uint64
	buffer := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		directoryName := strings.HasSuffix(header.Name, "/")
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || name == "." || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.IndexFunc(name, func(character rune) bool { return character < ' ' || character == '\u007f' }) >= 0 || name == ".." || strings.HasPrefix(name, "../") || len(name) > 4096 || strings.Count(name, "/") > 64 || seen[name] || len(seen) >= int(plan.Recipe.Volumes[0].InodeLimit) || header.Size < 0 || header.Mode&0o7002 != 0 || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 || header.Linkname != "" {
			return ErrPolicy
		}
		seen[name] = true
		parent := path.Dir(name)
		if parent != "." {
			info, statErr := root.Lstat(parent)
			if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return ErrPolicy
			}
		}
		mode := os.FileMode(header.Mode) & os.ModePerm
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 || mode&0o700 != 0o700 {
				return ErrInvalid
			}
			if err = root.Mkdir(name, 0o700); err != nil {
				return err
			}
			if err = root.Chown(name, int(runtime.config.RootlessUID), int(runtime.config.RootlessGID)); err != nil {
				return err
			}
			if err = root.Chmod(name, mode); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if directoryName {
				return ErrPolicy
			}
			if uint64(header.Size) > plan.Recipe.Volumes[0].QuotaBytes-total {
				return ErrPolicy
			}
			total += uint64(header.Size)
			file, openErr := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
			if openErr != nil {
				return openErr
			}
			count, copyErr := io.CopyBuffer(file, reader, buffer)
			if copyErr == nil && count != header.Size {
				copyErr = io.ErrUnexpectedEOF
			}
			if copyErr == nil {
				copyErr = file.Chown(int(runtime.config.RootlessUID), int(runtime.config.RootlessGID))
			}
			if copyErr == nil {
				copyErr = file.Chmod(mode)
			}
			if copyErr == nil {
				copyErr = file.Sync()
			}
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return ErrPolicy
		}
	}
	// A tar reader stops at its end marker; only canonical zero padding may
	// follow. Hidden concatenated archives or nonzero trailers are rejected.
	for {
		count, err := archive.Read(buffer)
		for _, value := range buffer[:count] {
			if value != 0 {
				return ErrPolicy
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
	if len(seen) == 0 {
		return ErrInvalid
	}
	if err := root.Chown(".", int(runtime.config.RootlessUID), int(runtime.config.RootlessGID)); err != nil {
		return err
	}
	return root.Chmod(".", 0o750)
}

func (runtime *LinuxContainerRuntime) migrationTree(ctx context.Context, directory string, plan MigrationVolumePlan) (string, uint64, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", 0, err
	}
	defer root.Close()
	hash := sha256.New()
	var files, total uint64
	buffer := make([]byte, 128<<10)
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != runtime.config.RootlessUID || stat.Gid != runtime.config.RootlessGID || info.Mode()&0o7000 != 0 {
			return ErrForbidden
		}
		if name == "." {
			if !info.IsDir() {
				return ErrPolicy
			}
			return nil
		}
		files++
		if files > plan.Recipe.Volumes[0].InodeLimit || entry.Type()&os.ModeSymlink != 0 {
			return ErrPolicy
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return ErrPolicy
		}
		fmt.Fprintf(hash, "%s\x00%d\x00%d\x00", name, info.Mode(), info.Size())
		if info.IsDir() {
			return nil
		}
		if info.Size() < 0 || uint64(info.Size()) > plan.Recipe.Volumes[0].QuotaBytes-total {
			return ErrPolicy
		}
		total += uint64(info.Size())
		file, openErr := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return openErr
		}
		count, copyErr := io.CopyBuffer(hash, io.LimitReader(file, info.Size()+1), buffer)
		file.Close()
		if copyErr != nil {
			return copyErr
		}
		if count != info.Size() {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return "", files, err
	}
	return hex.EncodeToString(hash.Sum(nil)), files, nil
}

func (runtime *LinuxContainerRuntime) observeMigrationVolume(ctx context.Context, volume linuxRuntimeResource, journal migrationVolumeJournal) error {
	mount, err := runtime.migrationMount(ctx, volume)
	if err != nil {
		return err
	}
	digest, files, err := runtime.migrationTree(ctx, mount, journal.Plan)
	if err != nil {
		return err
	}
	if journal.TreeDigest == "" || digest != journal.TreeDigest || files != journal.Files {
		return ErrConflict
	}
	return nil
}

func sameMigrationRuntimeResource(left, right linuxRuntimeResource) bool {
	return left.TenantID == right.TenantID && left.ResourceID == right.ResourceID && left.RuntimeObjectID == right.RuntimeObjectID && left.Tier == right.Tier && left.Generation == right.Generation && left.Fence == right.Fence && left.SpecDigest == right.SpecDigest && left.Lifecycle == right.Lifecycle
}

func (runtime *LinuxContainerRuntime) observeStagedMigration(ctx context.Context, journal migrationVolumeJournal) error {
	reserved, exists := runtime.state.MigrationWorkloads[journal.Plan.WorkloadID]
	if !exists || !sameMigrationRuntimeResource(reserved, journal.Workload) {
		return ErrConflict
	}
	lifecycle, digest, image, _, err := runtime.inspectWorkload(ctx, journal.Workload)
	if err != nil || lifecycle != LifecycleCreating || digest != journal.Workload.SpecDigest || image != journal.Plan.WorkloadSpec().Image.Digest {
		return errors.Join(ErrAmbiguous, err)
	}
	return runtime.observeStagedMigrationConfiguration(ctx, journal)
}

func (runtime *LinuxContainerRuntime) observeStagedMigrationConfiguration(ctx context.Context, journal migrationVolumeJournal) error {
	output, _, err := runtime.run(ctx, TierTenantRootless, runtime.config.PodmanPath, []string{"inspect", "--format", "json", "--", journal.Workload.RuntimeObjectID}, nil)
	if err != nil {
		return err
	}
	var rows []struct {
		Config struct {
			User string `json:"User"`
		} `json:"Config"`
		HostConfig struct {
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
			PortBindings map[string]json.RawMessage `json:"PortBindings"`
			NetworkMode  string                     `json:"NetworkMode"`
		} `json:"HostConfig"`
		NetworkSettings struct {
			Networks map[string]json.RawMessage `json:"Networks"`
		} `json:"NetworkSettings"`
		Mounts []struct {
			Type        string `json:"Type"`
			Name        string `json:"Name"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
	}
	if json.Unmarshal(output, &rows) != nil || len(rows) != 1 {
		return ErrInvalid
	}
	spec := journal.Plan.WorkloadSpec()
	expectedUser := strconv.FormatUint(uint64(spec.User.UID), 10) + ":" + strconv.FormatUint(uint64(spec.User.GID), 10)
	if rows[0].Config.User != expectedUser || (rows[0].HostConfig.RestartPolicy.Name != "" && rows[0].HostConfig.RestartPolicy.Name != "no") || len(rows[0].HostConfig.PortBindings) != 0 {
		return ErrPolicy
	}
	volume := runtime.state.Volumes[journal.Plan.VolumeID]
	volumeMounts := 0
	for _, mount := range rows[0].Mounts {
		switch mount.Type {
		case "volume":
			volumeMounts++
			if mount.Name != volume.RuntimeObjectID || mount.Destination != journal.Plan.Recipe.Volumes[0].MountTarget || !mount.RW {
				return ErrConflict
			}
		case "tmpfs":
			if mount.Destination != "/tmp" || !mount.RW || !spec.Security.ReadOnlyRoot {
				return ErrPolicy
			}
		default:
			return ErrPolicy
		}
	}
	if volumeMounts != 1 {
		return ErrConflict
	}
	if journal.Plan.NetworkID == "" {
		if rows[0].HostConfig.NetworkMode != "none" || len(rows[0].NetworkSettings.Networks) != 0 {
			return ErrPolicy
		}
		return nil
	}
	network := runtime.state.Networks[journal.Plan.NetworkID]
	if err := runtime.inspectPrivateNetworkRecord(ctx, network); err != nil {
		return err
	}
	if len(rows[0].NetworkSettings.Networks) != 1 {
		return ErrPolicy
	}
	if _, exists := rows[0].NetworkSettings.Networks[network.RuntimeObjectID]; !exists {
		return ErrConflict
	}
	return nil
}

func (runtime *LinuxContainerRuntime) stageMigrationWorkload(ctx context.Context, journalPath string, grant Grant, journal *migrationVolumeJournal) error {
	plan := journal.Plan
	spec := plan.WorkloadSpec()
	if err := runtime.inspectLocalImage(ctx, spec.Image); err != nil {
		return err
	}
	if _, exists := runtime.state.Workloads[plan.WorkloadID]; exists {
		return ErrConflict
	}
	if journal.State == "staged" {
		return runtime.observeStagedMigration(ctx, *journal)
	}
	if journal.State == "creating" {
		lifecycle, digest, image, _, err := runtime.inspectWorkload(ctx, journal.Workload)
		if err != nil || lifecycle != LifecycleCreating || digest != digestContainerValue(spec) || image != spec.Image.Digest {
			return errors.Join(ErrAmbiguous, err)
		}
		if reserved, exists := runtime.state.MigrationWorkloads[plan.WorkloadID]; exists {
			if !sameMigrationRuntimeResource(reserved, journal.Workload) {
				return ErrConflict
			}
		} else {
			runtime.state.MigrationWorkloads[plan.WorkloadID] = journal.Workload
			if err = runtime.saveLocked(); err != nil {
				return errors.Join(ErrAmbiguous, err)
			}
		}
		journal.State = "staged"
		return saveMigrationVolume(journalPath, *journal)
	}
	if _, exists := runtime.state.MigrationWorkloads[plan.WorkloadID]; exists {
		return ErrConflict
	}
	name := runtimeName("cpm", plan.TenantID, plan.WorkloadID)
	grant.ResourceID = plan.WorkloadID
	grant.Operation = "workload.apply"
	request := WorkloadMutationRequest{EffectID: plan.EffectID(), Grant: grant, WorkloadID: plan.WorkloadID, Tier: TierTenantRootless, Spec: spec, SpecDigest: digestContainerValue(spec), Fence: FenceToken(plan.SourceGeneration)}
	arguments, cleanup, err := runtime.workloadArguments(ctx, request, name)
	if err != nil {
		return err
	}
	defer cleanup()
	// A staged object has no host port binding. Route preparation and the
	// loopback publish are part of the deliberately unimplemented activation
	// transaction, not an attribute of protected staging.
	stagedArguments := make([]string, 0, len(arguments))
	options := true
	for index := 0; index < len(arguments); index++ {
		if options && arguments[index] == "--publish" {
			if index+1 >= len(arguments) {
				return ErrPolicy
			}
			index++
			continue
		}
		stagedArguments = append(stagedArguments, arguments[index])
		if options && arguments[index] == "--" {
			options = false
		}
	}
	arguments = stagedArguments
	userNamespace, restart := 0, 0
	for index := range arguments {
		if arguments[index] == "--" {
			break
		}
		if arguments[index] == "--userns" && index+1 < len(arguments) {
			arguments[index+1] = "keep-id:uid=" + strconv.FormatUint(uint64(spec.User.UID), 10) + ",gid=" + strconv.FormatUint(uint64(spec.User.GID), 10)
			userNamespace++
		}
		if arguments[index] == "--restart" && index+1 < len(arguments) {
			arguments[index+1] = "no"
			restart++
		}
	}
	if userNamespace != 1 || restart != 1 {
		return ErrPolicy
	}
	journal.Workload = linuxRuntimeResource{TenantID: plan.TenantID, ResourceID: plan.WorkloadID, RuntimeObjectID: name, Tier: TierTenantRootless, Generation: 1, Fence: FenceToken(plan.SourceGeneration), SpecDigest: request.SpecDigest, Lifecycle: LifecycleCreating, UpdatedAt: runtime.clock().UTC()}
	journal.State = "creating"
	if err = saveMigrationVolume(journalPath, *journal); err != nil {
		return err
	}
	// Create only. The migration reservation is disjoint from the ordinary
	// lifecycle map, so SetLifecycle/Restart/Exposure cannot reach this object.
	if _, _, err = runtime.run(ctx, TierTenantRootless, runtime.config.PodmanPath, arguments, nil); err != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	lifecycle, digest, image, _, err := runtime.inspectWorkload(ctx, journal.Workload)
	if err != nil || lifecycle != LifecycleCreating || digest != request.SpecDigest || image != spec.Image.Digest {
		return errors.Join(ErrAmbiguous, err)
	}
	runtime.state.MigrationWorkloads[plan.WorkloadID] = journal.Workload
	if err = runtime.saveLocked(); err != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	journal.State = "staged"
	return saveMigrationVolume(journalPath, *journal)
}

func (runtime *LinuxContainerRuntime) migrationWorkloadAbsent(ctx context.Context, name string) (bool, error) {
	output, _, err := runtime.run(ctx, TierTenantRootless, runtime.config.PodmanPath, []string{"ps", "--all", "--filter", "name=" + name, "--format", "json"}, nil)
	if err != nil {
		return false, err
	}
	var rows []struct{ Names []string }
	if json.Unmarshal(output, &rows) != nil {
		return false, ErrInvalid
	}
	for _, row := range rows {
		for _, candidate := range row.Names {
			if candidate == name {
				return false, nil
			}
		}
	}
	return true, nil
}

func (runtime *LinuxContainerRuntime) clearMigrationVolume(ctx context.Context, volume linuxRuntimeResource, plan MigrationVolumePlan) error {
	if err := runtime.migrationUnusedVolume(ctx, volume, ""); err != nil {
		return err
	}
	mount, err := runtime.migrationMount(ctx, volume)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(mount)
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		root.Close()
		return err
	}
	for _, entry := range entries {
		if err = root.RemoveAll(entry.Name()); err != nil {
			root.Close()
			return err
		}
	}
	if err = root.Chown(".", int(runtime.config.RootlessUID), int(runtime.config.RootlessGID)); err == nil {
		err = root.Chmod(".", 0o750)
	}
	root.Close()
	if err != nil {
		return err
	}
	parent, err := os.OpenRoot(filepath.Dir(mount))
	if err != nil {
		return err
	}
	err = parent.RemoveAll(".migration-" + digestContainerValue(plan))
	parent.Close()
	if err != nil {
		return err
	}
	directory, err := os.Open(mount)
	if err != nil {
		return err
	}
	err = directory.Sync()
	directory.Close()
	return err
}

func (runtime *LinuxContainerRuntime) discardMigrationVolume(ctx context.Context, directory, journalPath string, volume linuxRuntimeResource, journal *migrationVolumeJournal) error {
	if journal.State != "discarding" {
		switch journal.State {
		case "receiving", "sealing":
		case "sealed", "creating", "staged":
			if err := runtime.observeMigrationVolume(ctx, volume, *journal); err != nil {
				return err
			}
		default:
			return ErrConflict
		}
		if journal.Workload.RuntimeObjectID != "" {
			lifecycle, _, _, _, err := runtime.inspectWorkload(ctx, journal.Workload)
			if err != nil || lifecycle != LifecycleCreating {
				return errors.Join(ErrInUse, err)
			}
		}
		journal.State = "discarding"
		if err := saveMigrationVolume(journalPath, *journal); err != nil {
			return err
		}
	}
	if journal.Workload.RuntimeObjectID != "" {
		lifecycle, _, _, _, inspectErr := runtime.inspectWorkload(ctx, journal.Workload)
		if inspectErr == nil {
			if lifecycle != LifecycleCreating {
				return ErrInUse
			}
			if _, _, err := runtime.run(ctx, TierTenantRootless, runtime.config.PodmanPath, []string{"rm", "--", journal.Workload.RuntimeObjectID}, nil); err != nil {
				return err
			}
		} else {
			absent, err := runtime.migrationWorkloadAbsent(ctx, journal.Workload.RuntimeObjectID)
			if err != nil || !absent {
				return errors.Join(ErrAmbiguous, inspectErr, err)
			}
		}
		if reserved, exists := runtime.state.MigrationWorkloads[journal.Plan.WorkloadID]; exists {
			if !sameMigrationRuntimeResource(reserved, journal.Workload) {
				return ErrConflict
			}
			delete(runtime.state.MigrationWorkloads, journal.Plan.WorkloadID)
			if err := runtime.saveLocked(); err != nil {
				return errors.Join(ErrAmbiguous, err)
			}
		}
		journal.Workload = linuxRuntimeResource{}
		if err := saveMigrationVolume(journalPath, *journal); err != nil {
			return err
		}
	}
	if err := runtime.clearMigrationVolume(ctx, volume, journal.Plan); err != nil {
		return err
	}
	if err := removeMigrationArchive(directory); err != nil {
		return err
	}
	journal.State = "discarded"
	return saveMigrationVolume(journalPath, *journal)
}

var _ MigrationContainerBroker = (*LinuxContainerRuntime)(nil)
