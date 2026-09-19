//go:build linux

package apps

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	linuxApplicationStagingMaximumFiles = 1_000_000
	linuxApplicationStagingMaximumBytes = uint64(256 << 30)
)

var wordpressTablePrefixPattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

const wordpressStagingGuard = `<?php
/* CyberPanel managed staging guard. */
add_filter('pre_wp_mail', static function () { return false; }, PHP_INT_MAX, 2);
add_filter('pre_http_request', static function ($preempt, $arguments, $request_url) {
    $request_host = strtolower((string) wp_parse_url($request_url, PHP_URL_HOST));
    $site_host = strtolower((string) wp_parse_url(home_url('/'), PHP_URL_HOST));
    if ($request_host !== '' && hash_equals($site_host, $request_host)) {
        return $preempt;
    }
    return new WP_Error('cyberpanel_staging_egress_denied', 'Outbound requests are disabled for this staging clone.');
}, PHP_INT_MAX, 3);
`

func (runtime *LinuxApplicationRuntime) CreateClone(ctx context.Context, execution CloneExecution) (ExecutionReceipt, error) {
	if err := validateLinuxCloneExecution(execution); err != nil {
		return ExecutionReceipt{}, err
	}
	target, err := runtime.resolve(ctx, execution.TargetScope)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	workspace, err := runtime.extractStagingSnapshot(ctx, execution.SourceSnapshot, target.binding)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	defer os.RemoveAll(workspace)

	dumpName := linuxSnapshotDatabaseName(execution.SourceSnapshot)
	if err = runtime.replaceApplicationTree(ctx, target, workspace, dumpName, false); err != nil {
		return ExecutionReceipt{}, err
	}
	if err = runtime.configureClonedWordPress(ctx, target, execution, filepath.Join(workspace, dumpName)); err != nil {
		return ExecutionReceipt{}, err
	}
	if execution.SuppressMail || execution.DenyExternalActions {
		if err = installWordPressStagingGuard(target); err != nil {
			return ExecutionReceipt{}, err
		}
	}
	if err = runtime.rewriteWordPressIdentity(ctx, target, execution.Rewrite); err != nil {
		return ExecutionReceipt{}, err
	}
	return receiptForApplication("create_clone", execution.TargetScope, execution.TargetInstallationID, execution, execution.SourceSnapshot.ManifestDigest, "", execution.SourceSnapshot.ID, true), nil
}

func (runtime *LinuxApplicationRuntime) ProbeClone(ctx context.Context, execution CloneExecution) (HealthObservation, ExecutionReceipt, error) {
	if err := validateLinuxCloneExecution(execution); err != nil {
		return HealthObservation{}, ExecutionReceipt{}, err
	}
	target, err := runtime.resolve(ctx, execution.TargetScope)
	if err != nil {
		return HealthObservation{}, ExecutionReceipt{}, err
	}
	health, err := runtime.probeStagedWordPress(ctx, target, execution.TargetInstallationID, execution.Rewrite.TargetURL, execution.SourceSnapshot.ManifestDigest)
	if err != nil {
		return HealthObservation{}, ExecutionReceipt{}, err
	}
	receipt := receiptForApplication("probe_clone", execution.TargetScope, execution.TargetInstallationID, execution, health, "", execution.SourceSnapshot.ID, false)
	return health, receipt, nil
}

func (runtime *LinuxApplicationRuntime) ApplySync(ctx context.Context, execution SyncExecution) (ExecutionReceipt, error) {
	if err := validateLinuxSyncExecution(execution); err != nil {
		return ExecutionReceipt{}, err
	}
	target, err := runtime.resolve(ctx, execution.TargetScope)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	workspace, err := runtime.extractStagingSnapshot(ctx, execution.SourceSnapshot, target.binding)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	defer os.RemoveAll(workspace)

	dumpName := linuxSnapshotDatabaseName(execution.SourceSnapshot)
	if syncCopiesFiles(execution.Sync.Scope) {
		if err = runtime.syncWordPressFiles(ctx, target, workspace, dumpName, execution.Sync); err != nil {
			return ExecutionReceipt{}, err
		}
	}
	if syncCopiesDatabase(execution.Sync.Scope, execution.Sync.Selection) {
		if len(execution.Sync.Selection.DatabaseTables) != 0 {
			return ExecutionReceipt{}, ErrUnsupported
		}
		if err = runtime.importWordPressSnapshot(ctx, target, execution.SourceSnapshot, filepath.Join(workspace, dumpName)); err != nil {
			return ExecutionReceipt{}, err
		}
	}
	return receiptForApplication("staging_sync", execution.TargetScope, stagedTargetInstallation(execution), execution, execution.SourceSnapshot.ManifestDigest, "", execution.SourceSnapshot.ID, true), nil
}

func (runtime *LinuxApplicationRuntime) RewriteApplicationIdentity(ctx context.Context, execution SyncExecution) (ExecutionReceipt, error) {
	if err := validateLinuxSyncExecution(execution); err != nil {
		return ExecutionReceipt{}, err
	}
	target, err := runtime.resolve(ctx, execution.TargetScope)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	if execution.Sync.Selection.RewriteIdentity || execution.Rewrite.RewriteDatabase {
		if err = runtime.rewriteWordPressIdentity(ctx, target, execution.Rewrite); err != nil {
			return ExecutionReceipt{}, err
		}
	}
	return receiptForApplication("rewrite_staging_identity", execution.TargetScope, stagedTargetInstallation(execution), execution, execution.Rewrite.TargetURL, "", execution.SourceSnapshot.ID, true), nil
}

func (runtime *LinuxApplicationRuntime) ProbeSynchronizedApplication(ctx context.Context, execution SyncExecution) (HealthObservation, ExecutionReceipt, error) {
	if err := validateLinuxSyncExecution(execution); err != nil {
		return HealthObservation{}, ExecutionReceipt{}, err
	}
	target, err := runtime.resolve(ctx, execution.TargetScope)
	if err != nil {
		return HealthObservation{}, ExecutionReceipt{}, err
	}
	installation := stagedTargetInstallation(execution)
	health, err := runtime.probeStagedWordPress(ctx, target, installation, execution.Rewrite.TargetURL, execution.SourceSnapshot.ManifestDigest)
	if err != nil {
		return HealthObservation{}, ExecutionReceipt{}, err
	}
	return health, receiptForApplication("probe_staging_sync", execution.TargetScope, installation, execution, health, "", execution.SourceSnapshot.ID, false), nil
}

func (runtime *LinuxApplicationRuntime) RollbackSync(ctx context.Context, execution SyncExecution) (ExecutionReceipt, error) {
	if err := validateLinuxSyncExecution(execution); err != nil {
		return ExecutionReceipt{}, err
	}
	target, err := runtime.resolve(ctx, execution.TargetScope)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	workspace, err := runtime.extractStagingSnapshot(ctx, execution.TargetSnapshot, target.binding)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	defer os.RemoveAll(workspace)
	dumpName := linuxSnapshotDatabaseName(execution.TargetSnapshot)
	if err = runtime.replaceApplicationTree(ctx, target, workspace, dumpName, true); err != nil {
		return ExecutionReceipt{}, err
	}
	if execution.TargetSnapshot.DatabaseDigest != "" {
		if err = runtime.importWordPressSnapshot(ctx, target, execution.TargetSnapshot, filepath.Join(workspace, dumpName)); err != nil {
			return ExecutionReceipt{}, err
		}
	}
	return receiptForApplication("rollback_staging_sync", execution.TargetScope, stagedTargetInstallation(execution), execution, execution.TargetSnapshot.ManifestDigest, "", execution.TargetSnapshot.ID, true), nil
}

func (runtime *LinuxApplicationRuntime) DeleteClone(ctx context.Context, execution StagingDeleteExecution) (ExecutionReceipt, error) {
	if execution.SourceScope.Validate() != nil || execution.TargetScope.Validate() != nil || execution.SourceScope.TenantID != execution.TargetScope.TenantID || execution.SourceScope.SiteID == execution.TargetScope.SiteID || !validID(string(execution.RelationID)) || !validID(string(execution.TargetInstallation)) || !validID(string(execution.RecoveryPointID)) {
		return ExecutionReceipt{}, ErrInvalid
	}
	target, err := runtime.resolve(ctx, execution.TargetScope)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	if err = removeWordPressTLSMaterial(target, execution.TargetInstallation); err != nil {
		return ExecutionReceipt{}, err
	}
	if err = clearLinuxApplicationRoot(target.root); err != nil {
		return ExecutionReceipt{}, err
	}
	return receiptForApplication("delete_clone", execution.TargetScope, execution.TargetInstallation, execution, "deleted", "", SnapshotID(execution.RecoveryPointID), true), nil
}

func validateLinuxCloneExecution(execution CloneExecution) error {
	if execution.SourceScope.Validate() != nil || execution.TargetScope.Validate() != nil || execution.SourceScope.TenantID != execution.TargetScope.TenantID || execution.SourceScope.SiteID == execution.TargetScope.SiteID || !validID(string(execution.SourceInstallationID)) || !validID(string(execution.TargetInstallationID)) || execution.SourceInstallationID == execution.TargetInstallationID || execution.TargetDatabase.Validate() != nil || !execution.SuppressMail || !execution.DenyExternalActions || validateLinuxIdentityRewrite(execution.Rewrite) != nil {
		return ErrInvalid
	}
	return validateLinuxStagingSnapshot(execution.SourceSnapshot)
}

func validateLinuxSyncExecution(execution SyncExecution) error {
	if execution.SourceScope.Validate() != nil || execution.TargetScope.Validate() != nil || execution.SourceScope.TenantID != execution.TargetScope.TenantID || execution.SourceScope.SiteID == execution.TargetScope.SiteID || execution.Sync.Validate() != nil || execution.Sync.State == "" || validateLinuxIdentityRewrite(execution.Rewrite) != nil || validateLinuxStagingSnapshot(execution.SourceSnapshot) != nil || validateLinuxStagingSnapshot(execution.TargetSnapshot) != nil {
		return ErrInvalid
	}
	return nil
}

func validateLinuxIdentityRewrite(rewrite IdentityRewrite) error {
	if rewrite.Application != ApplicationWordPress || !validStagingApplicationURL(rewrite.SourceURL) || !validStagingApplicationURL(rewrite.TargetURL) || sameStagingURL(rewrite.SourceURL, rewrite.TargetURL) {
		return ErrInvalid
	}
	return nil
}

func validStagingApplicationURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Opaque != "" {
		return false
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return true
	}
	return strings.HasPrefix(parsed.Path, "/") && !strings.Contains(parsed.Path, "//") && path.Clean(parsed.Path) == parsed.Path && len(parsed.Path) <= 2048
}

func sameStagingURL(left, right string) bool {
	return strings.EqualFold(strings.TrimRight(left, "/"), strings.TrimRight(right, "/"))
}

func validateLinuxStagingSnapshot(snapshot Snapshot) error {
	if !validID(string(snapshot.ID)) || !validID(string(snapshot.InstallationID)) || !validDigest(snapshot.ManifestDigest) || snapshot.Size == 0 || snapshot.Size > linuxApplicationStagingMaximumBytes || snapshot.CreatedAt.IsZero() {
		return ErrInvalid
	}
	if snapshot.DatabaseDigest != "" && !validDigest(snapshot.DatabaseDigest) {
		return ErrInvalid
	}
	return nil
}

func (runtime *LinuxApplicationRuntime) extractStagingSnapshot(ctx context.Context, snapshot Snapshot, binding LinuxApplicationSiteBinding) (string, error) {
	if err := validateLinuxStagingSnapshot(snapshot); err != nil || binding.UID < 1000 || binding.GID != binding.UID {
		return "", ErrInvalid
	}
	if err := runtime.VerifyApplicationSnapshot(ctx, snapshot.ID); err != nil {
		return "", err
	}
	archivePath := filepath.Join(linuxApplicationSnapshotRoot, string(snapshot.ID), "snapshot.tar.gz")
	archive, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	compressed, err := gzip.NewReader(io.LimitReader(archive, int64(snapshot.Size)+1))
	if err != nil {
		return "", err
	}
	defer compressed.Close()
	workspace, err := os.MkdirTemp(linuxApplicationSnapshotRoot, ".extract-")
	if err != nil {
		return "", err
	}
	if err = os.Chmod(workspace, 0700); err != nil {
		os.RemoveAll(workspace)
		return "", err
	}
	reader := tar.NewReader(compressed)
	var files uint64
	var expanded uint64
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			os.RemoveAll(workspace)
			return "", nextErr
		}
		files++
		if files > linuxApplicationStagingMaximumFiles || header.Size < 0 || uint64(header.Size) > linuxApplicationStagingMaximumBytes-expanded {
			os.RemoveAll(workspace)
			return "", ErrPolicyDenied
		}
		expanded += uint64(header.Size)
		relative, pathErr := safeLinuxSnapshotMember(header.Name)
		if pathErr != nil {
			os.RemoveAll(workspace)
			return "", pathErr
		}
		if relative == "" {
			continue
		}
		target := filepath.Join(workspace, filepath.FromSlash(relative))
		if !strings.HasPrefix(target, workspace+string(os.PathSeparator)) {
			os.RemoveAll(workspace)
			return "", ErrPolicyDenied
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(target, boundedSnapshotDirectoryMode(header.Mode)); err != nil {
				os.RemoveAll(workspace)
				return "", err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err = os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				os.RemoveAll(workspace)
				return "", err
			}
			file, openErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, boundedSnapshotFileMode(header.Mode))
			if openErr != nil {
				os.RemoveAll(workspace)
				return "", openErr
			}
			written, copyErr := io.CopyN(file, reader, header.Size)
			syncErr := file.Sync()
			closeErr := file.Close()
			if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
				os.RemoveAll(workspace)
				return "", errors.Join(ErrIntegrity, copyErr, syncErr, closeErr)
			}
		default:
			os.RemoveAll(workspace)
			return "", ErrPolicyDenied
		}
	}
	if err = chownLinuxSnapshotTree(workspace, int(binding.UID), int(binding.GID)); err != nil {
		os.RemoveAll(workspace)
		return "", err
	}
	return workspace, nil
}

func safeLinuxSnapshotMember(raw string) (string, error) {
	if raw == "" || strings.IndexByte(raw, 0) >= 0 || strings.HasPrefix(raw, "/") || strings.Contains(raw, `\`) {
		return "", ErrPolicyDenied
	}
	trimmed := strings.TrimPrefix(raw, "./")
	clean := path.Clean(trimmed)
	if clean == "." || clean == "" {
		return "", nil
	}
	if clean != trimmed || clean == ".." || strings.HasPrefix(clean, "../") || len(clean) > 4096 {
		return "", ErrPolicyDenied
	}
	for _, component := range strings.Split(clean, "/") {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return "", ErrPolicyDenied
		}
	}
	return clean, nil
}

func boundedSnapshotDirectoryMode(raw int64) os.FileMode {
	mode := os.FileMode(raw) & 0770 &^ 0002
	if mode&0700 == 0 {
		mode |= 0700
	}
	return mode
}

func boundedSnapshotFileMode(raw int64) os.FileMode {
	mode := os.FileMode(raw) & 0770 &^ 0002
	if mode&0400 == 0 {
		mode |= 0400
	}
	return mode
}

func chownLinuxSnapshotTree(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return ErrIntegrity
		}
		return os.Chown(name, uid, gid)
	})
}

func (runtime *LinuxApplicationRuntime) replaceApplicationTree(ctx context.Context, target linuxApplicationScope, workspace, dumpName string, preserveConfig bool) error {
	args := []string{"--archive", "--delete", "--safe-links", "--one-file-system", "--exclude=/" + dumpName}
	if preserveConfig {
		args = append(args, "--exclude=/wp-config.php")
	}
	args = append(args, "--", workspace+"/", target.root+"/")
	_, stderr, _, err := runtime.command(ctx, target, "/usr/bin/rsync", nil, 4<<20, args...)
	if err != nil {
		return fmt.Errorf("copy application snapshot: %w: %s", err, stderr)
	}
	return nil
}

func (runtime *LinuxApplicationRuntime) syncWordPressFiles(ctx context.Context, target linuxApplicationScope, workspace, dumpName string, sync StagingSync) error {
	base := []string{"--archive", "--safe-links", "--one-file-system", "--exclude=/" + dumpName, "--exclude=/wp-config.php", "--exclude=/wp-content/mu-plugins/cyberpanel-staging-guard.php"}
	switch sync.Scope {
	case SyncEverything:
		base = append(base, "--delete", "--", workspace+"/", target.root+"/")
		_, stderr, _, err := runtime.command(ctx, target, "/usr/bin/rsync", nil, 4<<20, base...)
		if err != nil {
			return fmt.Errorf("synchronize application files: %w: %s", err, stderr)
		}
		return nil
	case SyncFiles:
		base = append(base, "--delete", "--exclude=/wp-content/uploads/", "--", workspace+"/", target.root+"/")
		_, stderr, _, err := runtime.command(ctx, target, "/usr/bin/rsync", nil, 4<<20, base...)
		if err != nil {
			return fmt.Errorf("synchronize application files: %w: %s", err, stderr)
		}
		return nil
	case SyncUploads:
		return runtime.syncWordPressRelativePath(ctx, target, workspace, MustRelativePath("wp-content/uploads"), true)
	case SyncSelected:
		for _, selected := range sync.Selection.Paths {
			if selected.IsRoot() || selected.String() == "wp-config.php" || strings.HasPrefix(selected.String(), "wp-config.php/") {
				return ErrPolicyDenied
			}
			if err := runtime.syncWordPressRelativePath(ctx, target, workspace, selected, false); err != nil {
				return err
			}
		}
		for _, component := range sync.Selection.Components {
			var selected RelativePath
			switch component {
			case "plugins":
				selected = MustRelativePath("wp-content/plugins")
			case "themes":
				selected = MustRelativePath("wp-content/themes")
			case "languages":
				selected = MustRelativePath("wp-content/languages")
			default:
				return ErrUnsupported
			}
			if err := runtime.syncWordPressRelativePath(ctx, target, workspace, selected, false); err != nil {
				return err
			}
		}
		if sync.Selection.IncludeUploads {
			return runtime.syncWordPressRelativePath(ctx, target, workspace, MustRelativePath("wp-content/uploads"), false)
		}
		return nil
	default:
		return nil
	}
}

func (runtime *LinuxApplicationRuntime) syncWordPressRelativePath(ctx context.Context, target linuxApplicationScope, workspace string, selected RelativePath, deleteExtraneous bool) error {
	source := filepath.Join(workspace, filepath.FromSlash(selected.String()))
	destination := filepath.Join(target.root, filepath.FromSlash(selected.String()))
	if !strings.HasPrefix(source, workspace+string(os.PathSeparator)) || !strings.HasPrefix(destination, target.root+string(os.PathSeparator)) {
		return ErrPolicyDenied
	}
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrNotFound, err)
	}
	if info.IsDir() {
		if err = os.MkdirAll(destination, 0750); err != nil {
			return err
		}
		if err = os.Chown(destination, int(target.binding.UID), int(target.binding.GID)); err != nil {
			return err
		}
		args := []string{"--archive", "--safe-links", "--one-file-system"}
		if deleteExtraneous {
			args = append(args, "--delete")
		}
		args = append(args, "--", source+"/", destination+"/")
		_, stderr, _, runErr := runtime.command(ctx, target, "/usr/bin/rsync", nil, 4<<20, args...)
		if runErr != nil {
			return fmt.Errorf("synchronize selected directory: %w: %s", runErr, stderr)
		}
		return nil
	}
	if err = os.MkdirAll(filepath.Dir(destination), 0750); err != nil {
		return err
	}
	_, stderr, _, runErr := runtime.command(ctx, target, "/usr/bin/rsync", nil, 4<<20, "--archive", "--safe-links", "--", source, destination)
	if runErr != nil {
		return fmt.Errorf("synchronize selected file: %w: %s", runErr, stderr)
	}
	return nil
}

func (runtime *LinuxApplicationRuntime) configureClonedWordPress(ctx context.Context, target linuxApplicationScope, execution CloneExecution, dumpPath string) error {
	prefixOutput, _, _, prefixErr := runtime.wp(ctx, target, nil, 1<<20, "config", "get", "table_prefix")
	prefix := strings.TrimSpace(string(prefixOutput))
	if prefixErr != nil || !wordpressTablePrefixPattern.MatchString(prefix) {
		prefix = "wp_"
	}
	configPath := filepath.Join(target.root, "wp-config.php")
	if err := os.Remove(configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	password, err := runtime.Secrets.ApplicationSecret(ctx, execution.TargetDatabase.PasswordRef, execution.TargetScope.TenantID, execution.TargetScope.SiteID, execution.TargetInstallationID, "database")
	if err != nil {
		return err
	}
	defer wipeLinuxApplicationBytes(password)
	host := execution.TargetDatabase.EndpointRef
	if host == "local-mariadb" {
		host = "127.0.0.1:3306"
	}
	stdin := append(append([]byte(nil), password...), '\n')
	defer wipeLinuxApplicationBytes(stdin)
	_, stderr, _, err := runtime.wp(ctx, target, stdin, 1<<20, "config", "create", "--dbname="+execution.TargetDatabase.DatabaseName, "--dbuser="+execution.TargetDatabase.PrincipalName, "--dbhost="+host, "--dbcharset=utf8mb4", "--dbprefix="+prefix, "--skip-check", "--skip-salts", "--force", "--prompt=dbpass")
	if err != nil {
		return fmt.Errorf("create cloned WordPress config: %w: %s", err, stderr)
	}
	if err = injectWordPressCloneConstants(configPath, target.binding); err != nil {
		return err
	}
	if err = runtime.configureWordPressDatabaseTLS(ctx, target, execution.TargetScope, execution.TargetInstallationID, execution.TargetDatabase); err != nil {
		return err
	}
	return runtime.importWordPressSnapshot(ctx, target, execution.SourceSnapshot, dumpPath)
}

func injectWordPressCloneConstants(configPath string, binding LinuxApplicationSiteBinding) error {
	info, err := os.Lstat(configPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 2<<20 {
		return ErrIntegrity
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	marker := []byte("/* That's all, stop editing!")
	position := strings.Index(string(content), string(marker))
	if position < 0 {
		return ErrIntegrity
	}
	keys := []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"}
	var constants strings.Builder
	constants.WriteString("define( 'WP_ENVIRONMENT_TYPE', 'staging' );\n")
	constants.WriteString("define( 'DISABLE_WP_CRON', true );\n")
	for _, key := range keys {
		material := make([]byte, 48)
		if _, err = rand.Read(material); err != nil {
			wipeLinuxApplicationBytes(material)
			return err
		}
		encoded := base64.RawStdEncoding.EncodeToString(material)
		wipeLinuxApplicationBytes(material)
		constants.WriteString("define( '")
		constants.WriteString(key)
		constants.WriteString("', '")
		constants.WriteString(encoded)
		constants.WriteString("' );\n")
	}
	rewritten := make([]byte, 0, len(content)+constants.Len())
	rewritten = append(rewritten, content[:position]...)
	rewritten = append(rewritten, constants.String()...)
	rewritten = append(rewritten, content[position:]...)
	temporary, err := os.CreateTemp(filepath.Dir(configPath), ".wp-config-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0640); err == nil {
		err = temporary.Chown(int(binding.UID), int(binding.GID))
	}
	if err == nil {
		_, err = temporary.Write(rewritten)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, configPath)
}

func installWordPressStagingGuard(target linuxApplicationScope) error {
	directory := filepath.Join(target.root, "wp-content", "mu-plugins")
	if err := os.MkdirAll(directory, 0750); err != nil {
		return err
	}
	if err := os.Chown(directory, int(target.binding.UID), int(target.binding.GID)); err != nil {
		return err
	}
	guardPath := filepath.Join(directory, "cyberpanel-staging-guard.php")
	if err := os.WriteFile(guardPath, []byte(wordpressStagingGuard), 0640); err != nil {
		return err
	}
	return os.Chown(guardPath, int(target.binding.UID), int(target.binding.GID))
}

func (runtime *LinuxApplicationRuntime) importWordPressSnapshot(ctx context.Context, target linuxApplicationScope, snapshot Snapshot, dumpPath string) error {
	if snapshot.DatabaseDigest == "" {
		return ErrInvalid
	}
	fd, err := syscall.Open(dumpPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.Join(ErrIntegrity, err)
	}
	dump := os.NewFile(uintptr(fd), dumpPath)
	defer dump.Close()
	info, err := dump.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || uint64(info.Size()) > linuxApplicationStagingMaximumBytes {
		return ErrIntegrity
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(dump, info.Size()+1))
	if err != nil || n != info.Size() || hex.EncodeToString(hash.Sum(nil)) != snapshot.DatabaseDigest {
		return errors.Join(ErrIntegrity, err)
	}
	if _, err := dump.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// WP-CLI 2.12's file import opens an extra SQL-mode connection without
	// forwarding TLS options. Stream the verified snapshot instead; exported
	// SQL carries its own session modes, and no insecure probe is necessary.
	_, stderr, _, err := runtime.wpReader(ctx, target, io.LimitReader(dump, info.Size()), 4<<20, "db", "import", "-")
	if err != nil {
		return fmt.Errorf("import staged WordPress database: %w: %s", err, stderr)
	}
	return nil
}

func (runtime *LinuxApplicationRuntime) rewriteWordPressIdentity(ctx context.Context, target linuxApplicationScope, rewrite IdentityRewrite) error {
	if err := validateLinuxIdentityRewrite(rewrite); err != nil {
		return err
	}
	args := []string{"search-replace", strings.TrimRight(rewrite.SourceURL, "/"), strings.TrimRight(rewrite.TargetURL, "/"), "--all-tables-with-prefix", "--precise"}
	if rewrite.PreserveGUIDs {
		args = append(args, "--skip-columns=guid")
	}
	if _, stderr, _, err := runtime.wp(ctx, target, nil, 4<<20, args...); err != nil {
		return fmt.Errorf("rewrite staged WordPress identity: %w: %s", err, stderr)
	}
	for _, option := range []string{"home", "siteurl"} {
		if _, stderr, _, err := runtime.wp(ctx, target, nil, 1<<20, "option", "update", option, strings.TrimRight(rewrite.TargetURL, "/")); err != nil {
			return fmt.Errorf("set staged WordPress URL: %w: %s", err, stderr)
		}
	}
	_, _, _, _ = runtime.wp(ctx, target, nil, 1<<20, "cache", "flush")
	return nil
}

func (runtime *LinuxApplicationRuntime) probeStagedWordPress(ctx context.Context, target linuxApplicationScope, installation InstallationID, targetURL, definitionDigest string) (HealthObservation, error) {
	started := time.Now().UTC()
	if _, stderr, _, err := runtime.wp(ctx, target, nil, 1<<20, "core", "is-installed"); err != nil {
		return HealthObservation{}, fmt.Errorf("probe staged WordPress: %w: %s", err, stderr)
	}
	observedURL, stderr, _, err := runtime.wp(ctx, target, nil, 1<<20, "option", "get", "siteurl")
	if err != nil {
		return HealthObservation{}, fmt.Errorf("read staged WordPress URL: %w: %s", err, stderr)
	}
	if !sameStagingURL(strings.TrimSpace(string(observedURL)), targetURL) {
		return HealthObservation{}, ErrIntegrity
	}
	version, stderr, _, err := runtime.wp(ctx, target, nil, 1<<20, "core", "version")
	if err != nil {
		return HealthObservation{}, fmt.Errorf("read staged WordPress version: %w: %s", err, stderr)
	}
	now := time.Now().UTC()
	probeDigest := linuxApplicationDigest([]byte(string(installation) + "\x00" + strings.TrimSpace(string(version)) + "\x00" + strings.TrimRight(targetURL, "/")))
	return HealthObservation{State: HealthHealthy, CheckedAt: now, DefinitionDigest: definitionDigest, ReleaseDigest: probeDigest, ProbeReceipts: []ProbeReceipt{{Name: "wordpress_staging", Passed: true, Digest: probeDigest, Duration: now.Sub(started), ObservedAt: now}}}, nil
}

func clearLinuxApplicationRoot(root string) error {
	if root == "" || root == "/" || !strings.HasPrefix(root, linuxApplicationSitesRoot+"/") {
		return ErrPolicyDenied
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err = os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func linuxSnapshotDatabaseName(snapshot Snapshot) string {
	return "." + string(snapshot.ID) + ".sql"
}

func syncCopiesFiles(scope SyncScope) bool {
	return scope == SyncEverything || scope == SyncFiles || scope == SyncUploads || scope == SyncSelected
}

func syncCopiesDatabase(scope SyncScope, selection Selection) bool {
	return scope == SyncEverything || scope == SyncDatabase || scope == SyncSelected && len(selection.DatabaseTables) != 0
}

func stagedTargetInstallation(execution SyncExecution) InstallationID {
	return execution.TargetSnapshot.InstallationID
}

var _ StagingExecutor = (*LinuxApplicationRuntime)(nil)
