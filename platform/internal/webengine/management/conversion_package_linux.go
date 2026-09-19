//go:build linux

package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation/fsstore"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

func conversionDirectory(effect string) string {
	return filepath.Join(lifecycleStateRoot, "conversion-"+linuxManagementDigest([]byte(effect)))
}

func privateConversionDirectory(path string) error {
	if !strings.HasPrefix(path, lifecycleStateRoot+"/conversion-") || filepath.Clean(path) != path {
		return ErrInvalid
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || !rootOwnedFile(info) {
		return ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return ErrInvalid
	}
	return nil
}

func pinConversionPlan(ctx context.Context, catalogValue localArtifactCatalog, plan ArtifactPlan, expectedChannel Channel) ([]conversionPackage, Channel, error) {
	osName, osVersion, architecture, err := localPlatformTuple()
	if err != nil {
		return nil, "", err
	}
	if expectedChannel != "" && !validChannel(expectedChannel) {
		return nil, "", ErrInvalid
	}
	var channel Channel
	matches := 0
	for _, entry := range catalogValue.Entries {
		if entry.OS == osName && entry.OSVersion == osVersion && entry.Architecture == architecture && (expectedChannel == "" || entry.Channel == expectedChannel) && digestJSON(entry.Plan) == digestJSON(plan) {
			matches++
			channel = entry.Channel
		}
	}
	if matches != 1 || catalogValue.Sequence == 0 || !validSHA256(catalogValue.Digest) {
		return nil, "", ErrConflict
	}
	result := make([]conversionPackage, 0, len(plan.Packages))
	for _, artifact := range plan.Packages {
		path, resolveErr := resolveLifecyclePackage(ctx, artifact, plan.RepositorySnapshotDigest, osName, architecture)
		if resolveErr != nil {
			return nil, "", resolveErr
		}
		result = append(result, conversionPackage{Artifact: artifact, Path: path})
	}
	return result, channel, nil
}

// The root-only journal pins a previously signature-verified plan and its
// exact package files for rollback, even after the current catalog advances.
func conversionAuthority(effect string) (*lifecycleConversionRecord, error) {
	if !validEffectToken(effect) {
		return nil, ErrInvalid
	}
	path := filepath.Join(lifecycleStateRoot, lifecycleStateFile)
	info, err := os.Lstat(path)
	if err != nil || !safeLocalCatalogFile(info, lifecycleMaximumStateBytes, true) || info.Mode().Perm() != 0o600 {
		return nil, ErrInvalid
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var journal lifecycleJournal
	if decodeLifecyclePayload(content, &journal) != nil || journal.Version != 1 || journal.Conversion == nil {
		return nil, ErrInvalid
	}
	record := journal.Conversion
	selection := conversionSelection(record.Input.Request, record.Input.Plan.Edition)
	if record.Input.Request.EffectID != effect || !validConversionRecord(record) || record.CatalogSequence == 0 ||
		record.CatalogSequence != journal.EngineCatalogSequence || record.CatalogDigest != journal.EngineCatalogDigest ||
		!validSHA256(record.CatalogDigest) || record.Input.Request.PlanDigest != ConversionPlanDigest(selection, record.Input.Plan, record.Input.Generation.ContentDigest, record.Input.License, record.Input.RollbackWindow) {
		return nil, ErrConflict
	}
	return record, nil
}

func verifyConversionPackages(ctx context.Context, plan ArtifactPlan, packages []conversionPackage) ([]string, error) {
	if validateArtifactPlan(plan) != nil || len(packages) != len(plan.Packages) {
		return nil, ErrInvalid
	}
	osName, _, architecture, err := localPlatformTuple()
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(packages))
	for index, item := range packages {
		if item.Artifact != plan.Packages[index] || !strings.HasPrefix(item.Path, lifecyclePackageRoot+"/") || filepath.Clean(item.Path) != item.Path {
			return nil, ErrConflict
		}
		resolved, resolveErr := filepath.EvalSymlinks(item.Path)
		if resolveErr != nil || resolved != item.Path {
			return nil, ErrInvalid
		}
		before, statErr := os.Lstat(item.Path)
		if statErr != nil || !safeLocalCatalogFile(before, 16<<30, true) {
			return nil, ErrInvalid
		}
		file, openErr := os.Open(item.Path)
		if openErr != nil {
			return nil, openErr
		}
		opened, openStatErr := file.Stat()
		hash := sha256.New()
		size, copyErr := io.Copy(hash, io.LimitReader(file, (16<<30)+1))
		closeErr := file.Close()
		if openStatErr != nil || !os.SameFile(before, opened) || copyErr != nil || closeErr != nil || size != before.Size() || hex.EncodeToString(hash.Sum(nil)) != item.Artifact.Digest {
			return nil, ErrConflict
		}
		if err = verifyLifecyclePackageMetadata(ctx, item.Path, item.Artifact, osName, architecture); err != nil {
			return nil, err
		}
		paths = append(paths, item.Path)
	}
	sort.Strings(paths)
	return paths, nil
}

func stageConversionImage(ctx context.Context, record *lifecycleConversionRecord, generation native.ConfigGeneration) (string, error) {
	root := conversionDirectory(record.Input.Request.EffectID)
	if err := privateConversionDirectory(root); err != nil {
		return "", err
	}
	imageRoot := filepath.Join(root, "image")
	if info, err := os.Lstat(imageRoot); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || !rootOwnedFile(info) {
			return "", ErrInvalid
		}
		digest, digestErr := conversionImageDigest(ctx, imageRoot)
		if digestErr != nil || record.ImageDigest != "" && digest != record.ImageDigest {
			return "", errors.Join(ErrConflict, digestErr)
		}
		return digest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := privateConversionDirectory(imageRoot); err != nil {
		return "", err
	}
	paths, err := verifyConversionPackages(ctx, record.Input.Plan, record.TargetPackages)
	if err != nil {
		return "", err
	}
	osName, _, _, err := localPlatformTuple()
	if err != nil {
		return "", err
	}
	for _, path := range paths {
		// Archive extraction only: no package install, scriptlet, or maintainer
		// script can run while the source runtime serves public traffic.
		if osName == "ubuntu" {
			_, err = fixedConversionCommand(ctx, "/usr/bin/dpkg-deb", "--extract", path, imageRoot)
		} else {
			_, err = fixedConversionCommand(ctx, "/usr/bin/bsdtar", "-xf", path, "-C", imageRoot, "--no-same-owner", "--no-same-permissions")
		}
		if err != nil {
			return "", err
		}
	}
	if err = normalizeConversionImage(imageRoot); err != nil {
		return "", err
	}
	engineRoot := filepath.Join(imageRoot, "usr/local/lsws")
	resolved, err := filepath.EvalSymlinks(engineRoot)
	if err != nil || resolved != engineRoot {
		return "", ErrInvalid
	}
	for _, suffix := range []string{"conf", "logs", "admin", "admin/logs", "admin/tmp"} {
		path := filepath.Join(engineRoot, suffix)
		if info, statErr := os.Lstat(path); statErr == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return "", ErrInvalid
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		if err = os.MkdirAll(path, 0o700); err != nil {
			return "", err
		}
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil || resolved != path {
			return "", ErrInvalid
		}
	}
	configRoot := filepath.Join(engineRoot, "conf")
	if err = os.Chown(configRoot, 0, 0); err == nil {
		err = os.Chmod(configRoot, 0o700)
	}
	if err != nil {
		return "", err
	}
	master := "httpd_config.conf"
	if generation.Edition == webengine.EditionLiteSpeedEnterprise {
		master = "httpd_config.xml"
	}
	if info, statErr := os.Lstat(filepath.Join(configRoot, master)); statErr == nil {
		if !info.Mode().IsRegular() || !rootOwnedFile(info) {
			return "", ErrInvalid
		}
		if err = os.Chmod(filepath.Join(configRoot, master), 0o600); err != nil {
			return "", err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	store, err := fsstore.New(configRoot, generation.Edition)
	if err != nil {
		return "", err
	}
	staged, err := store.Stage(ctx, generation)
	if err == nil {
		err = store.SwapMaster(ctx, staged)
	}
	closeErr := store.Close()
	if err != nil || closeErr != nil {
		return "", errors.Join(err, closeErr)
	}
	return conversionImageDigest(ctx, imageRoot)
}

func conversionImageDigest(ctx context.Context, root string) (string, error) {
	type entry struct {
		Name         string
		Mode         uint32
		Size         int64
		Digest, Link string
	}
	var entries []entry
	var total int64
	err := filepath.WalkDir(root, func(path string, value fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := value.Info()
		if err != nil {
			return err
		}
		if len(entries) >= 131072 || !rootOwnedFile(info) || info.Mode()&os.ModeSymlink == 0 && info.Mode()&0o022 != 0 {
			return ErrInvalid
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		item := entry{Name: name, Mode: uint32(info.Mode()), Size: info.Size()}
		switch {
		case info.IsDir():
		case info.Mode()&os.ModeSymlink != 0:
			item.Link, err = os.Readlink(path)
			if err != nil {
				return err
			}
			if filepath.IsAbs(item.Link) {
				if !strings.HasPrefix(item.Link, "/usr/local/lsws/") {
					return ErrInvalid
				}
			} else {
				resolved := filepath.Clean(filepath.Join(filepath.Dir(path), item.Link))
				if !strings.HasPrefix(resolved, root+"/") {
					return ErrInvalid
				}
			}
		case info.Mode().IsRegular():
			total += info.Size()
			if info.Size() > 2<<30 || total > 16<<30 {
				return ErrInvalid
			}
			file, openErr := os.Open(path)
			if openErr != nil {
				return openErr
			}
			hash := sha256.New()
			size, copyErr := io.Copy(hash, io.LimitReader(file, (2<<30)+1))
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || size != info.Size() {
				return ErrInvalid
			}
			item.Digest = hex.EncodeToString(hash.Sum(nil))
		default:
			return ErrInvalid
		}
		entries = append(entries, item)
		return nil
	})
	if err != nil {
		return "", err
	}
	return digestJSON(entries), nil
}

func normalizeConversionImage(root string) error {
	count := 0
	var total int64
	return filepath.WalkDir(root, func(path string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > 131072 {
			return ErrInvalid
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return ErrInvalid
		}
		if info.Mode().IsRegular() {
			total += info.Size()
			if info.Size() > 2<<30 || total > 16<<30 {
				return ErrInvalid
			}
		}
		if err = os.Lchown(path, 0, 0); err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return os.Chmod(path, info.Mode().Perm()&^0o022)
		}
		return nil
	})
}

func fixedConversionCommand(ctx context.Context, program string, arguments ...string) ([]byte, error) {
	allowed := program == "/usr/bin/dpkg-deb" && len(arguments) == 3 && arguments[0] == "--extract" ||
		program == "/usr/bin/bsdtar" && len(arguments) == 6 && arguments[0] == "-xf" && arguments[2] == "-C" && arguments[4] == "--no-same-owner" && arguments[5] == "--no-same-permissions"
	if !allowed {
		return nil, ErrInvalid
	}
	if err := trustedLifecycleProgram(program); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, program, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	output := &lifecycleBoundedOutput{maximum: 1 << 20}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	return output.Bytes(), err
}

func runConversionCandidate(ctx context.Context, input lifecycleGenerationInput, record *lifecycleConversionRecord) (lifecycleWorkerResult, error) {
	plan := record.Input.Plan
	return runLifecycleWorker(ctx, lifecycleWorkerInput{Candidate: input, Mode: "validate", ConversionEffectID: record.Input.Request.EffectID, TargetPlan: &plan})
}

func conversionPackageActionDigest(effect, action, hostDigest string) string {
	return digestJSON(struct{ Effect, Action, HostDigest string }{effect, action, hostDigest})
}

func runConversionPackages(ctx context.Context, record *lifecycleConversionRecord, action string) error {
	result, err := runLifecycleWorker(ctx, lifecycleWorkerInput{Mode: "packages", ConversionEffectID: record.Input.Request.EffectID, PackageAction: action})
	if err != nil {
		return err
	}
	if result.PackageDigest != conversionPackageActionDigest(record.Input.Request.EffectID, action, record.HostDigest) {
		return ErrAmbiguous
	}
	return nil
}

func executeConversionPackages(ctx context.Context, input lifecycleWorkerInput) (lifecycleWorkerResult, error) {
	record, err := conversionAuthority(input.ConversionEffectID)
	if err != nil {
		return lifecycleWorkerResult{}, err
	}
	var plan, other ArtifactPlan
	var packages []conversionPackage
	install := false
	switch input.PackageAction {
	case "install_target":
		if record.Phase != conversionPhaseInstallTarget {
			return lifecycleWorkerResult{}, ErrConflict
		}
		plan, packages, install = record.Input.Plan, record.TargetPackages, true
	case "install_previous":
		if record.Phase != conversionPhaseRollbackInstallPrior {
			return lifecycleWorkerResult{}, ErrConflict
		}
		plan, packages, install = record.Previous.Plan, record.PreviousPackages, true
	case "remove_previous":
		if record.Phase != conversionPhaseRemovePrevious {
			return lifecycleWorkerResult{}, ErrConflict
		}
		plan, other, packages = record.Previous.Plan, record.Input.Plan, record.PreviousPackages
	case "remove_target":
		if record.Phase != conversionPhaseRollbackRemoveTarget {
			return lifecycleWorkerResult{}, ErrConflict
		}
		plan, other, packages = record.Input.Plan, record.Previous.Plan, record.TargetPackages
	default:
		return lifecycleWorkerResult{}, ErrInvalid
	}
	paths, err := verifyConversionPackages(ctx, plan, packages)
	if err != nil {
		return lifecycleWorkerResult{}, err
	}
	if err = isolateConversionPackageProcess(); err != nil {
		return lifecycleWorkerResult{}, err
	}
	if install {
		installed, inspectErr := exactConversionPlanInstalled(ctx, plan)
		if inspectErr != nil {
			return lifecycleWorkerResult{}, inspectErr
		}
		if !installed {
			err = installLifecyclePackages(ctx, paths)
		}
		if err == nil {
			err = installedLifecyclePlan(ctx, plan)
		}
	} else {
		keep := map[string]bool{}
		for _, item := range other.Packages {
			keep[item.Name] = true
		}
		for _, item := range plan.Packages {
			if keep[item.Name] {
				continue
			}
			if err = removeConversionPackage(ctx, item); err != nil {
				break
			}
		}
	}
	if err != nil {
		return lifecycleWorkerResult{}, err
	}
	return lifecycleWorkerResult{PackageDigest: conversionPackageActionDigest(input.ConversionEffectID, input.PackageAction, record.HostDigest)}, nil
}

func exactConversionPlanInstalled(ctx context.Context, plan ArtifactPlan) (bool, error) {
	osName, _, architecture, err := localPlatformTuple()
	if err != nil {
		return false, err
	}
	for _, item := range plan.Packages {
		if osName == "ubuntu" {
			output, queryErr := runLifecycleOutput(ctx, "/usr/bin/dpkg-query", "-W", "-f=${Status}\n${Version}\n${Architecture}\n", item.Name)
			if queryErr != nil {
				if strings.Contains(output, "no packages found matching") {
					return false, nil
				}
				return false, queryErr
			}
			lines := strings.Split(strings.TrimSpace(output), "\n")
			if len(lines) != 3 || lines[0] != "install ok installed" || lines[1] != item.Version || lines[2] != architecture {
				return false, nil
			}
			continue
		}
		output, queryErr := runLifecycleOutput(ctx, "/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n%{ARCH}\n", item.Name)
		if queryErr != nil {
			if strings.Contains(output, "is not installed") {
				return false, nil
			}
			return false, queryErr
		}
		expectedArchitecture := "x86_64"
		if architecture == "arm64" {
			expectedArchitecture = "aarch64"
		}
		lines := strings.Split(strings.TrimSpace(output), "\n")
		if len(lines) != 2 || lines[0] != item.Version || lines[1] != expectedArchitecture {
			return false, nil
		}
	}
	return true, nil
}

func removeConversionPackage(ctx context.Context, item PackageArtifact) error {
	osName, _, architecture, err := localPlatformTuple()
	if err != nil {
		return err
	}
	if osName == "ubuntu" {
		output, queryErr := runLifecycleOutput(ctx, "/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}\n${Version}\n${Architecture}\n", item.Name)
		if queryErr != nil {
			if strings.Contains(output, "no packages found matching") {
				return nil
			}
			return queryErr
		}
		lines := strings.Split(strings.TrimSpace(output), "\n")
		if len(lines) == 3 && (strings.HasPrefix(lines[0], "un") || strings.HasPrefix(lines[0], "rc")) {
			return nil
		}
		if len(lines) != 3 || lines[0] != "ii " || lines[1] != item.Version || lines[2] != architecture {
			return ErrConflict
		}
		return runLifecycle(ctx, "/usr/bin/dpkg", "--remove", item.Name)
	}
	output, queryErr := runLifecycleOutput(ctx, "/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n%{ARCH}\n", item.Name)
	if queryErr != nil {
		if strings.Contains(output, "is not installed") {
			return nil
		}
		return queryErr
	}
	expectedArchitecture := "x86_64"
	if architecture == "arm64" {
		expectedArchitecture = "aarch64"
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 || lines[0] != item.Version || lines[1] != expectedArchitecture {
		return ErrConflict
	}
	return runLifecycle(ctx, "/usr/bin/rpm", "-e", item.Name)
}

func isolateConversionPackageProcess() error {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return err
	}
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return err
	}
	for _, directory := range []string{"/tmp", "/run", "/dev/shm"} {
		if err := lifecycleTmpfs(directory, "mode=1777,size=128m"); err != nil {
			return err
		}
	}
	return nil
}

func captureConversionService(ctx context.Context) (conversionServiceState, error) {
	enablement, err := conversionServiceEnablement(ctx)
	if err != nil || !validConversionEnablement(enablement) {
		return conversionServiceState{}, errors.Join(ErrConflict, err)
	}
	activity, err := conversionServiceActivity(ctx)
	if err != nil || activity != "active" {
		return conversionServiceState{}, errors.Join(ErrConflict, err)
	}
	return conversionServiceState{Enablement: enablement, Active: true}, nil
}

func validConversionEnablement(value string) bool {
	switch value {
	case "enabled", "enabled-runtime", "disabled", "static", "indirect":
		return true
	default:
		return false
	}
}

func conversionServiceEnablement(ctx context.Context) (string, error) {
	output, commandErr := runLifecycleOutput(ctx, "/usr/bin/systemctl", "is-enabled", lifecycleService)
	value := strings.TrimSpace(output)
	if validConversionEnablement(value) || value == "masked" || value == "masked-runtime" {
		if commandErr != nil && (value == "enabled" || value == "enabled-runtime") {
			return "", commandErr
		}
		return value, nil
	}
	return "", errors.Join(ErrAmbiguous, commandErr)
}

func conversionServiceActivity(ctx context.Context) (string, error) {
	output, commandErr := runLifecycleOutput(ctx, "/usr/bin/systemctl", "is-active", lifecycleService)
	value := strings.TrimSpace(output)
	switch value {
	case "active", "activating", "reloading":
		if commandErr != nil {
			return "", commandErr
		}
		return value, nil
	case "inactive", "deactivating", "failed":
		return value, nil
	default:
		return "", errors.Join(ErrAmbiguous, commandErr)
	}
}

func stopConversionService(ctx context.Context) error {
	enablement, err := conversionServiceEnablement(ctx)
	if err != nil {
		return err
	}
	if enablement == "enabled-runtime" {
		if err = runLifecycle(ctx, "/usr/bin/systemctl", "disable", "--runtime", lifecycleService); err != nil {
			return err
		}
		enablement = "disabled"
	}
	if enablement != "masked-runtime" && enablement != "masked" {
		if err = runLifecycle(ctx, "/usr/bin/systemctl", "mask", "--runtime", lifecycleService); err != nil {
			return err
		}
	}
	activity, err := conversionServiceActivity(ctx)
	if err != nil {
		return err
	}
	if activity != "inactive" && activity != "failed" {
		if err = runLifecycle(ctx, "/usr/bin/systemctl", "stop", lifecycleService); err != nil {
			return err
		}
	}
	activity, err = conversionServiceActivity(ctx)
	if err != nil || activity != "inactive" && activity != "failed" {
		return ErrAmbiguous
	}
	return nil
}

func restoreConversionService(ctx context.Context, state conversionServiceState) error {
	if !state.Active || !validConversionEnablement(state.Enablement) {
		return ErrInvalid
	}
	if err := runLifecycle(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	current, err := conversionServiceEnablement(ctx)
	if err != nil {
		return err
	}
	if current == "masked-runtime" {
		if err := runLifecycle(ctx, "/usr/bin/systemctl", "unmask", "--runtime", lifecycleService); err != nil {
			return err
		}
	} else if current == "masked" {
		if err := runLifecycle(ctx, "/usr/bin/systemctl", "unmask", lifecycleService); err != nil {
			return err
		}
	}
	current, err = conversionServiceEnablement(ctx)
	if err != nil {
		return err
	}
	if current != state.Enablement {
		var err error
		switch state.Enablement {
		case "enabled":
			err = runLifecycle(ctx, "/usr/bin/systemctl", "enable", lifecycleService)
		case "enabled-runtime":
			err = runLifecycle(ctx, "/usr/bin/systemctl", "enable", "--runtime", lifecycleService)
		default:
			err = runLifecycle(ctx, "/usr/bin/systemctl", "disable", lifecycleService)
		}
		if err != nil {
			return err
		}
	}
	activity, err := conversionServiceActivity(ctx)
	if err != nil {
		return err
	}
	if activity != "active" {
		if err := runLifecycle(ctx, "/usr/bin/systemctl", "start", lifecycleService); err != nil {
			return err
		}
	}
	return verifyConversionService(ctx, state)
}

func verifyConversionService(ctx context.Context, expected conversionServiceState) error {
	observed, err := captureConversionService(ctx)
	if err != nil || observed != expected {
		return errors.Join(ErrAmbiguous, err)
	}
	return nil
}

func prepareConversionConfigRoot() error {
	info, err := os.Lstat(lifecycleConfigurationRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !rootOwnedFile(info) {
		return ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(lifecycleConfigurationRoot)
	if err != nil || resolved != lifecycleConfigurationRoot {
		return ErrInvalid
	}
	if err = os.Chmod(lifecycleConfigurationRoot, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"httpd_config.conf", "httpd_config.xml"} {
		path := filepath.Join(lifecycleConfigurationRoot, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || !rootOwnedFile(info) {
			return ErrInvalid
		}
		if err = os.Chmod(path, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// fsstore replacement is rename-based. A crash before the rename can leave
// only its root-owned temporary file; removing that verified residue makes the
// same journal phase retryable without repeating package or license effects.
func recoverConversionConfigResidue(edition webengine.Edition) error {
	master := "httpd_config.conf"
	if edition == webengine.EditionLiteSpeedEnterprise {
		master = "httpd_config.xml"
	} else if edition != webengine.EditionOpenLiteSpeed {
		return ErrInvalid
	}
	paths := []string{
		filepath.Join(lifecycleConfigurationRoot, ".tmp-"+master),
		filepath.Join(lifecycleConfigurationRoot, ".panel-state", ".tmp-current"),
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || !rootOwnedFile(info) || info.Size() < 0 || info.Size() > 16<<20 {
			return ErrInvalid
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		directory, openErr := os.Open(filepath.Dir(path))
		if openErr != nil {
			return openErr
		}
		if err = errors.Join(directory.Sync(), directory.Close()); err != nil {
			return err
		}
	}
	return nil
}

func backupConversionLicense(record *lifecycleConversionRecord) ([]conversionLicenseFile, error) {
	directory := conversionDirectory(record.Input.Request.EffectID)
	if err := privateConversionDirectory(directory); err != nil {
		return nil, err
	}
	files := make([]conversionLicenseFile, 0, 2)
	for _, name := range []string{"license.key", "serial.no"} {
		path := filepath.Join(lifecycleConfigurationRoot, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			if _, backupErr := os.Lstat(filepath.Join(directory, "previous-"+name)); backupErr == nil || !errors.Is(backupErr, os.ErrNotExist) {
				return nil, ErrConflict
			}
			files = append(files, conversionLicenseFile{Name: name})
			continue
		}
		if err != nil || !safeLocalCatalogFile(info, 1<<20, true) || info.Mode().Perm() != 0o600 {
			return nil, ErrLicense
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		digest := linuxManagementDigest(content)
		err = ensureConversionFile(filepath.Join(directory, "previous-"+name), content, 0o600)
		wipeLicenseMaterial(content)
		if err != nil {
			return nil, err
		}
		files = append(files, conversionLicenseFile{Name: name, Digest: digest, Present: true})
	}
	return files, nil
}

func restoreConversionLicense(record *lifecycleConversionRecord) error {
	if len(record.PreviousFiles) != 2 {
		return ErrAmbiguous
	}
	matches, err := conversionLicenseFilesMatch(record)
	if err != nil {
		return err
	}
	if matches {
		return nil
	}
	if err = disableConversionLicense(); err != nil {
		return err
	}
	for _, item := range record.PreviousFiles {
		if item.Name != "license.key" && item.Name != "serial.no" {
			return ErrInvalid
		}
		if !item.Present {
			continue
		}
		path := filepath.Join(conversionDirectory(record.Input.Request.EffectID), "previous-"+item.Name)
		info, err := os.Lstat(path)
		if err != nil || !safeLocalCatalogFile(info, 1<<20, true) || info.Mode().Perm() != 0o600 {
			return ErrLicense
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if linuxManagementDigest(content) != item.Digest {
			wipeLicenseMaterial(content)
			return ErrConflict
		}
		err = ensureConversionFile(filepath.Join(lifecycleConfigurationRoot, item.Name), content, 0o600)
		wipeLicenseMaterial(content)
		if err != nil {
			return err
		}
	}
	matches, err = conversionLicenseFilesMatch(record)
	if err != nil || !matches {
		return errors.Join(ErrAmbiguous, err)
	}
	return nil
}

func conversionLicenseFilesMatch(record *lifecycleConversionRecord) (bool, error) {
	if len(record.PreviousFiles) != 2 {
		return false, ErrInvalid
	}
	for _, item := range record.PreviousFiles {
		path := filepath.Join(lifecycleConfigurationRoot, item.Name)
		info, err := os.Lstat(path)
		if !item.Present {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return false, err
			}
			return false, nil
		}
		if err != nil || !safeLocalCatalogFile(info, 1<<20, true) || info.Mode().Perm() != 0o600 {
			return false, nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return false, readErr
		}
		matches := linuxManagementDigest(content) == item.Digest
		wipeLicenseMaterial(content)
		if !matches {
			return false, nil
		}
	}
	return true, nil
}

func disableConversionLicense() error {
	for _, name := range []string{"license.key", "serial.no"} {
		path := filepath.Join(lifecycleConfigurationRoot, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || !rootOwnedFile(info) {
			return ErrLicense
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	directory, err := os.Open(lifecycleConfigurationRoot)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func ensureConversionFile(path string, content []byte, mode fs.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if !safeLocalCatalogFile(info, 1<<20, true) || info.Mode().Perm() != mode.Perm() {
			return ErrInvalid
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		matches := linuxManagementDigest(existing) == linuxManagementDigest(content)
		wipeLicenseMaterial(existing)
		if !matches {
			return ErrConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeConversionFile(path, content, mode)
}

func writeConversionFile(path string, content []byte, mode fs.FileMode) error {
	if len(content) == 0 || len(content) > 1<<20 {
		return ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(content) {
		return errors.Join(ErrAmbiguous, writeErr, syncErr, closeErr)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
