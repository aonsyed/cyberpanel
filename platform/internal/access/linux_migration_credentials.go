//go:build linux

package access

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const linuxMigrationAccessRoot = DefaultAccessJournalRoot + "/migrations"

var linuxMigrationAccessMu sync.Mutex

type linuxMigrationPrincipalState struct {
	Version       uint32             `json:"version"`
	Principal     MigrationPrincipal `json:"principal"`
	DesiredDigest string             `json:"desired_digest"`
	Phase         string             `json:"phase"`
	Attempt       uint32             `json:"attempt"`
	ManagedGroup  string             `json:"managed_group,omitempty"`
	Evidence      string             `json:"evidence,omitempty"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

type linuxMigrationBatchState struct {
	Version       uint32                  `json:"version"`
	Batch         MigrationPrincipalBatch `json:"batch"`
	DesiredDigest string                  `json:"desired_digest"`
	Phase         string                  `json:"phase"`
	Evidence      string                  `json:"evidence,omitempty"`
	UpdatedAt     time.Time               `json:"updated_at"`
}

type linuxAccount struct{ Username, Password, UID, GID, Comment, Home, Shell string }

type linuxGroup struct {
	Name    string
	GID     uint32
	Members map[string]struct{}
}

type linuxMigrationHomeObservation struct {
	Path       string
	Device     uint64
	Inode      uint64
	OwnerUID   uint32
	OwnerGID   uint32
	Mode       uint32
	Generation uint64
}

func migrationPrincipalDigest(principal MigrationPrincipal) string {
	raw, _ := json.Marshal(principal)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func migrationBatchDigest(batch MigrationPrincipalBatch) string {
	copy := batch
	copy.Attempt = 0
	copy.Action = ""
	raw, _ := json.Marshal(copy)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func migrationBatchAdmissionEvidence(batch MigrationPrincipalBatch, digest string) string {
	raw, _ := json.Marshal(struct {
		Batch string
		Fence MigrationFenceBinding
	}{digest, batch.Fence})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func migrationBatchEvidence(batch MigrationPrincipalBatch, digest string, proofs []string) string {
	raw, _ := json.Marshal(struct {
		Batch  string
		Fence  MigrationFenceBinding
		Proofs []string
	}{digest, batch.Fence, proofs})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func migrationPrincipalPath(effect string) string {
	return linuxMigrationAccessRoot + "/principal-" + effect + ".json"
}
func migrationBatchPath(effect string) string {
	return linuxMigrationAccessRoot + "/batch-" + effect + ".json"
}
func migrationKeyStagePath(effect string) string {
	return linuxAuthorizedKeysRoot + "/.migration-" + effect + ".staged"
}
func migrationKeyActivePath(username string) string {
	return linuxAuthorizedKeysRoot + "/cyberpanel-" + username
}
func migrationAccountMarker(effect string) string { return "cyberpanel-migration=" + effect }
func migrationManagedGroup(migrationID string, gid uint32) string {
	sum := sha256.Sum256([]byte("migration-access-group\x00" + migrationID + "\x00" + strconv.FormatUint(uint64(gid), 10)))
	return "cpm-" + hex.EncodeToString(sum[:8])
}

func migrationManagedGroupOwned(migrationID, group string, gid uint32) (bool, error) {
	entries, err := os.ReadDir(linuxMigrationAccessRoot)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "principal-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		effectID := strings.TrimSuffix(strings.TrimPrefix(name, "principal-"), ".json")
		if !migrationAccessDigest(effectID) {
			return false, ErrIntegrity
		}
		var state linuxMigrationPrincipalState
		found, readErr := decodeLinuxState(linuxMigrationAccessRoot+"/"+name, &state)
		if readErr != nil || !found || state.Version != 1 || state.Principal.EffectID != effectID || state.DesiredDigest != migrationPrincipalDigest(state.Principal) {
			return false, errors.Join(readErr, ErrIntegrity)
		}
		if state.Principal.MigrationID == migrationID && state.Principal.GID == gid && state.ManagedGroup == group {
			return true, nil
		}
	}
	return false, nil
}

func readLinuxProtectedFile(path string, maximum int64) ([]byte, error) {
	return readLinuxProtectedFileMode(path, maximum, false)
}

func readLinuxPrivateFile(path string, maximum int64) ([]byte, error) {
	return readLinuxProtectedFileMode(path, maximum, true)
}

func readLinuxProtectedFileMode(path string, maximum int64, private bool) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return nil, errors.Join(err, ErrIntegrity)
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || info.Mode().Perm() != 0600 {
			return nil, ErrIntegrity
		}
	}
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) != info.Size() {
		return nil, errors.Join(err, ErrIntegrity)
	}
	return value, nil
}

func decodeLinuxState(path string, target any) (bool, error) {
	raw, err := readLinuxPrivateFile(path, 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false, ErrIntegrity
	}
	return true, nil
}
func storeLinuxState(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 4<<20 {
		return errors.Join(err, ErrIntegrity)
	}
	if err = ensureAccessDirectory(linuxMigrationAccessRoot, 0700, 0, 0); err != nil {
		return err
	}
	temporary := path + ".new"
	fd, err := syscall.Open(temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(temporary, 0600)
	}
	if err == nil {
		err = os.Rename(temporary, path)
	}
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	directory, err := os.Open(linuxMigrationAccessRoot)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func linuxAccounts() (map[string]linuxAccount, map[uint32]string, error) {
	passwd, err := readLinuxProtectedFile("/etc/passwd", 8<<20)
	if err != nil {
		return nil, nil, err
	}
	shadow, err := readLinuxProtectedFile("/etc/shadow", 8<<20)
	if err != nil {
		return nil, nil, err
	}
	defer wipeAccess(shadow)
	shadowConfirmation, err := readLinuxProtectedFile("/etc/shadow", 8<<20)
	if err != nil {
		return nil, nil, err
	}
	defer wipeAccess(shadowConfirmation)
	passwdConfirmation, err := readLinuxProtectedFile("/etc/passwd", 8<<20)
	if err != nil || !bytes.Equal(passwd, passwdConfirmation) || !bytes.Equal(shadow, shadowConfirmation) {
		return nil, nil, errors.Join(err, ErrIntegrity)
	}
	passwords := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(shadow))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 2 || fields[0] == "" {
			return nil, nil, ErrIntegrity
		}
		if _, duplicate := passwords[fields[0]]; duplicate {
			return nil, nil, ErrIntegrity
		}
		passwords[fields[0]] = fields[1]
	}
	if err = scanner.Err(); err != nil {
		return nil, nil, err
	}
	accounts := map[string]linuxAccount{}
	uids := map[uint32]string{}
	scanner = bufio.NewScanner(bytes.NewReader(passwd))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 7 || fields[0] == "" {
			return nil, nil, ErrIntegrity
		}
		uid, uidErr := strconv.ParseUint(fields[2], 10, 32)
		gid, gidErr := strconv.ParseUint(fields[3], 10, 32)
		if uidErr != nil || gidErr != nil {
			return nil, nil, ErrIntegrity
		}
		password, hasShadow := passwords[fields[0]]
		if !hasShadow {
			return nil, nil, ErrIntegrity
		}
		if _, duplicate := accounts[fields[0]]; duplicate {
			return nil, nil, ErrIntegrity
		}
		if _, duplicate := uids[uint32(uid)]; duplicate {
			return nil, nil, ErrIntegrity
		}
		account := linuxAccount{fields[0], password, fields[2], fields[3], fields[4], fields[5], fields[6]}
		accounts[account.Username] = account
		uids[uint32(uid)] = account.Username
	}
	if err = scanner.Err(); err != nil {
		return nil, nil, err
	}
	return accounts, uids, nil
}

func linuxGroups() (map[string]linuxGroup, map[uint32][]linuxGroup, error) {
	raw, err := readLinuxProtectedFile("/etc/group", 8<<20)
	if err != nil {
		return nil, nil, err
	}
	byName := map[string]linuxGroup{}
	byGID := map[uint32][]linuxGroup{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 4 || fields[0] == "" {
			return nil, nil, ErrIntegrity
		}
		gid, parseErr := strconv.ParseUint(fields[2], 10, 32)
		if parseErr != nil {
			return nil, nil, ErrIntegrity
		}
		group := linuxGroup{Name: fields[0], GID: uint32(gid), Members: map[string]struct{}{}}
		if fields[3] != "" {
			for _, member := range strings.Split(fields[3], ",") {
				if member == "" {
					return nil, nil, ErrIntegrity
				}
				group.Members[member] = struct{}{}
			}
		}
		if _, duplicate := byName[group.Name]; duplicate {
			return nil, nil, ErrIntegrity
		}
		byName[group.Name] = group
		byGID[group.GID] = append(byGID[group.GID], group)
	}
	if err = scanner.Err(); err != nil {
		return nil, nil, err
	}
	return byName, byGID, nil
}

func migrationAccountGroupIDs(username string, primary uint32) ([]uint32, error) {
	_, groups, err := linuxGroups()
	if err != nil {
		return nil, err
	}
	seen := map[uint32]struct{}{primary: {}}
	for gid, candidates := range groups {
		for _, candidate := range candidates {
			if _, member := candidate.Members[username]; member {
				seen[gid] = struct{}{}
			}
		}
	}
	values := make([]uint32, 0, len(seen))
	for gid := range seen {
		values = append(values, gid)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values, nil
}

func containsGID(values []uint32, wanted uint32) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func migrationObservation(principal MigrationPrincipal, status MigrationAccessStatus, state, evidence, code string) MigrationAccessObservation {
	return MigrationAccessObservation{EffectID: principal.EffectID, PrincipalID: principal.PrincipalID, Status: status, State: state, EvidenceDigest: evidence, ErrorCode: code, ObservedAt: time.Now().UTC()}
}
func migrationBatchObservation(batch MigrationPrincipalBatch, status MigrationAccessStatus, state, evidence, code string) MigrationAccessObservation {
	return MigrationAccessObservation{EffectID: batch.EffectID, Status: status, State: state, EvidenceDigest: evidence, ErrorCode: code, ObservedAt: time.Now().UTC()}
}
func terminalMigrationError(err error) bool {
	return errors.Is(err, ErrInvalidID) || errors.Is(err, ErrInvalidPath) || errors.Is(err, ErrInvalidState) || errors.Is(err, ErrConflict) || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrIntegrity)
}
func migrationErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrConflict):
		return "identity_collision"
	case errors.Is(err, ErrUnauthorized):
		return "fence_or_scope_rejected"
	case errors.Is(err, ErrIntegrity):
		return "observation_mismatch"
	case errors.Is(err, ErrInvalidID), errors.Is(err, ErrInvalidPath), errors.Is(err, ErrInvalidState):
		return "invalid_principal"
	default:
		return "executor_ambiguous"
	}
}

func (executor *LinuxCredentialExecutor) migrationFailure(principal MigrationPrincipal, err error) MigrationAccessObservation {
	status := MigrationAccessAmbiguous
	if terminalMigrationError(err) {
		status = MigrationAccessTerminal
	}
	return migrationObservation(principal, status, "unknown", "", migrationErrorCode(err))
}
func (executor *LinuxCredentialExecutor) batchFailure(batch MigrationPrincipalBatch, err error) MigrationAccessObservation {
	status := MigrationAccessAmbiguous
	if terminalMigrationError(err) {
		status = MigrationAccessTerminal
	}
	return migrationBatchObservation(batch, status, "unknown", "", migrationErrorCode(err))
}

func (executor *LinuxCredentialExecutor) claimMigrationPrincipal(ctx context.Context, principal MigrationPrincipal, attempt uint32) (linuxMigrationPrincipalState, error) {
	if executor == nil || executor.Files == nil || attempt == 0 || principal.Validate() != nil {
		return linuxMigrationPrincipalState{}, ErrInvalidState
	}
	if _, err := executor.binding(ctx, principal.SiteID); err != nil {
		return linuxMigrationPrincipalState{}, err
	}
	digest := migrationPrincipalDigest(principal)
	path := migrationPrincipalPath(principal.EffectID)
	var state linuxMigrationPrincipalState
	found, err := decodeLinuxState(path, &state)
	if err != nil {
		return state, err
	}
	if found {
		validPhase := state.Phase == "claimed" || state.Phase == "account_created" || state.Phase == "credential_staged" || state.Phase == "dark" || state.Phase == "activating" || state.Phase == "active"
		if state.Version != 1 || state.DesiredDigest != digest || migrationPrincipalDigest(state.Principal) != digest || !validPhase || state.ManagedGroup != "" && state.ManagedGroup != migrationManagedGroup(principal.MigrationID, principal.GID) {
			return state, ErrConflict
		}
		if attempt > state.Attempt {
			state.Attempt = attempt
			state.UpdatedAt = time.Now().UTC()
			err = storeLinuxState(path, state)
		}
		return state, err
	}
	accounts, uids, err := linuxAccounts()
	if err != nil {
		return state, err
	}
	if _, exists := accounts[principal.Username]; exists {
		return state, ErrConflict
	}
	if owner, exists := uids[principal.UID]; exists && owner != principal.Username {
		return state, ErrConflict
	}
	groupsByName, groupsByGID, err := linuxGroups()
	if err != nil {
		return state, err
	}
	managedGroup := migrationManagedGroup(principal.MigrationID, principal.GID)
	if named, present := groupsByName[managedGroup]; present && named.GID != principal.GID {
		return state, ErrConflict
	}
	if len(groupsByGID[principal.GID]) == 0 {
		state.ManagedGroup = managedGroup
	} else if named, present := groupsByName[managedGroup]; present && named.GID == principal.GID {
		owned, ownershipErr := migrationManagedGroupOwned(principal.MigrationID, managedGroup, principal.GID)
		if ownershipErr != nil {
			return state, ownershipErr
		}
		if owned {
			state.ManagedGroup = managedGroup
		}
	}
	state.Version = 1
	state.Principal = principal
	state.DesiredDigest = digest
	state.Phase = "claimed"
	state.Attempt = attempt
	state.UpdatedAt = time.Now().UTC()
	return state, storeLinuxState(path, state)
}

func migrationPrincipalShell(principal MigrationPrincipal, active bool) string {
	if !active || principal.Kind == MigrationPrincipalFTPS {
		return "/usr/sbin/nologin"
	}
	return "/bin/bash"
}
func migrationKeyLine(principal MigrationPrincipal, key MigrationAuthorizedKey) string {
	options := "no-agent-forwarding,no-port-forwarding,no-X11-forwarding"
	switch principal.Policy {
	case MigrationPolicySFTPReadWrite:
		options += `,command="internal-sftp"`
	case MigrationPolicySFTPReadOnly:
		options += `,command="internal-sftp -R"`
	}
	return options + " " + key.PublicKey.AuthorizedKey() + " cyberpanel-migration principal=" + string(principal.PrincipalID) + " key=" + string(key.ID)
}
func migrationKeys(principal MigrationPrincipal) []byte {
	lines := make([]string, 0, len(principal.AuthorizedKeys))
	for _, key := range principal.AuthorizedKeys {
		lines = append(lines, migrationKeyLine(principal, key))
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func (executor *LinuxCredentialExecutor) migrationHome(ctx context.Context, principal MigrationPrincipal) (linuxMigrationHomeObservation, LinuxSiteBinding, error) {
	root, binding, err := executor.Files.openRoot(ctx, SiteRoot{SiteID: principal.SiteID, Kind: RootSite})
	if err != nil {
		return linuxMigrationHomeObservation{}, binding, err
	}
	defer syscall.Close(root)
	components, err := splitRelative(principal.Home)
	if err != nil {
		return linuxMigrationHomeObservation{}, binding, err
	}
	homeFD, err := descendLinux(root, components)
	if err != nil {
		return linuxMigrationHomeObservation{}, binding, err
	}
	defer syscall.Close(homeFD)
	var stat syscall.Stat_t
	if err = syscall.Fstat(homeFD, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || stat.Uid != binding.UID || stat.Gid != binding.GID || stat.Mode&0002 != 0 {
		return linuxMigrationHomeObservation{}, binding, errors.Join(err, ErrInvalidPath)
	}
	home := accessRootPath(binding, SiteRoot{SiteID: principal.SiteID, Kind: RootSite}, principal.Home)
	return linuxMigrationHomeObservation{
		Path:       home,
		Device:     uint64(stat.Dev),
		Inode:      stat.Ino,
		OwnerUID:   stat.Uid,
		OwnerGID:   stat.Gid,
		Mode:       stat.Mode & 07777,
		Generation: binding.Generation,
	}, binding, nil
}

func (executor *LinuxCredentialExecutor) ensureMigrationGroup(ctx context.Context, state *linuxMigrationPrincipalState) error {
	principal := state.Principal
	byName, byGID, err := linuxGroups()
	if err != nil {
		return err
	}
	if state.ManagedGroup == "" {
		if len(byGID[principal.GID]) == 0 {
			return ErrConflict
		}
		return nil
	}
	if state.ManagedGroup != migrationManagedGroup(principal.MigrationID, principal.GID) {
		return ErrConflict
	}
	if named, present := byName[state.ManagedGroup]; present {
		if named.GID != principal.GID {
			return ErrConflict
		}
		return nil
	}
	if len(byGID[principal.GID]) != 0 {
		return ErrConflict
	}
	if _, err = runFixedAccess(ctx, "/usr/sbin/groupadd", nil, "--gid", strconv.FormatUint(uint64(principal.GID), 10), state.ManagedGroup); err != nil {
		return err
	}
	byName, _, err = linuxGroups()
	if err != nil {
		return err
	}
	if created, present := byName[state.ManagedGroup]; !present || created.GID != principal.GID {
		return ErrConflict
	}
	return nil
}

func (executor *LinuxCredentialExecutor) ensureMigrationAccount(ctx context.Context, state *linuxMigrationPrincipalState) error {
	principal := state.Principal
	if err := executor.ensureMigrationGroup(ctx, state); err != nil {
		return err
	}
	homeObservation, binding, err := executor.migrationHome(ctx, principal)
	if err != nil {
		return err
	}
	accounts, uids, err := linuxAccounts()
	if err != nil {
		return err
	}
	account, present := accounts[principal.Username]
	if !present {
		if owner, exists := uids[principal.UID]; exists && owner != principal.Username {
			return ErrConflict
		}
		args := []string{"--uid", strconv.FormatUint(uint64(principal.UID), 10), "--gid", strconv.FormatUint(uint64(principal.GID), 10), "--home-dir", homeObservation.Path, "--no-create-home", "--shell", "/usr/sbin/nologin", "--comment", migrationAccountMarker(principal.EffectID), "--no-user-group"}
		if principal.GID != binding.GID {
			args = append(args, "--groups", strconv.FormatUint(uint64(binding.GID), 10))
		}
		args = append(args, principal.Username)
		if _, err = runFixedAccess(ctx, "/usr/sbin/useradd", nil, args...); err != nil {
			return err
		}
		accounts, _, err = linuxAccounts()
		if err != nil {
			return err
		}
		account, present = accounts[principal.Username]
	}
	if !present || account.UID != strconv.FormatUint(uint64(principal.UID), 10) || account.GID != strconv.FormatUint(uint64(principal.GID), 10) || account.Comment != migrationAccountMarker(principal.EffectID) || account.Home != homeObservation.Path {
		return ErrConflict
	}
	groups, err := migrationAccountGroupIDs(principal.Username, principal.GID)
	if err != nil {
		return err
	}
	if principal.GID != binding.GID && !containsGID(groups, binding.GID) {
		return ErrConflict
	}
	if state.Phase == "claimed" {
		state.Phase = "account_created"
		state.UpdatedAt = time.Now().UTC()
		return storeLinuxState(migrationPrincipalPath(principal.EffectID), *state)
	}
	return nil
}

func (executor *LinuxCredentialExecutor) installMigrationCredential(ctx context.Context, state *linuxMigrationPrincipalState) error {
	principal := state.Principal
	if principal.Kind == MigrationPrincipalFTPS && state.Phase == "account_created" {
		if executor.Secrets == nil {
			return ErrInvalidState
		}
		hash, err := executor.Secrets.ReadMigrationHash(ctx, principal.Credential.Reference, string(principal.TenantID), string(principal.PrincipalID))
		if err != nil {
			return err
		}
		defer wipeAccess(hash)
		input := append([]byte(principal.Username+":"), hash...)
		input = append(input, '\n')
		if _, err = runFixedAccess(ctx, "/usr/sbin/chpasswd", input, "-e"); err != nil {
			return err
		}
		if _, err = runFixedAccess(ctx, "/usr/sbin/usermod", nil, "--lock", principal.Username); err != nil {
			return err
		}
		state.Phase = "credential_staged"
		state.UpdatedAt = time.Now().UTC()
		return storeLinuxState(migrationPrincipalPath(principal.EffectID), *state)
	}
	if principal.Kind == MigrationPrincipalSSH && state.Phase == "account_created" {
		if _, err := runFixedAccess(ctx, "/usr/sbin/usermod", nil, "--password", "x", "--lock", principal.Username); err != nil {
			return err
		}
		state.Phase = "credential_staged"
		state.UpdatedAt = time.Now().UTC()
		return storeLinuxState(migrationPrincipalPath(principal.EffectID), *state)
	}
	return nil
}

func (executor *LinuxCredentialExecutor) stageMigrationKeys(state *linuxMigrationPrincipalState) error {
	principal := state.Principal
	if state.Phase != "credential_staged" {
		return nil
	}
	if principal.Kind == MigrationPrincipalSSH {
		if err := ensureAuthorizedKeysRoot(); err != nil {
			return err
		}
		active := migrationKeyActivePath(principal.Username)
		if _, err := os.Lstat(active); err == nil {
			return ErrConflict
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := atomicRootFile(migrationKeyStagePath(principal.EffectID), migrationKeys(principal), 0600); err != nil {
			return err
		}
	}
	state.Phase = "dark"
	state.UpdatedAt = time.Now().UTC()
	return storeLinuxState(migrationPrincipalPath(principal.EffectID), *state)
}

func (executor *LinuxCredentialExecutor) StageMigrationPrincipal(ctx context.Context, principal MigrationPrincipal, attempt uint32) (MigrationAccessObservation, error) {
	linuxMigrationAccessMu.Lock()
	defer linuxMigrationAccessMu.Unlock()
	state, err := executor.claimMigrationPrincipal(ctx, principal, attempt)
	if err == nil {
		err = executor.ensureMigrationAccount(ctx, &state)
	}
	if err == nil {
		err = executor.installMigrationCredential(ctx, &state)
	}
	if err == nil {
		err = executor.stageMigrationKeys(&state)
	}
	if err != nil {
		return executor.migrationFailure(principal, err), nil
	}
	return executor.ObserveMigrationPrincipal(ctx, principal)
}

func (executor *LinuxCredentialExecutor) ObserveMigrationPrincipal(ctx context.Context, principal MigrationPrincipal) (MigrationAccessObservation, error) {
	if executor == nil || executor.Files == nil || principal.Validate() != nil {
		return executor.migrationFailure(principal, ErrInvalidState), nil
	}
	var state linuxMigrationPrincipalState
	found, err := decodeLinuxState(migrationPrincipalPath(principal.EffectID), &state)
	if err != nil {
		return executor.migrationFailure(principal, err), nil
	}
	if !found {
		return migrationObservation(principal, MigrationAccessTerminal, "absent", "", "not_staged"), nil
	}
	if state.DesiredDigest != migrationPrincipalDigest(principal) || migrationPrincipalDigest(state.Principal) != state.DesiredDigest {
		return executor.migrationFailure(principal, ErrConflict), nil
	}
	if state.Phase == "compensated" {
		return migrationObservation(principal, MigrationAccessCompensated, "absent", state.Evidence, ""), nil
	}
	home, binding, err := executor.migrationHome(ctx, principal)
	if err != nil {
		return executor.migrationFailure(principal, err), nil
	}
	accounts, _, err := linuxAccounts()
	if err != nil {
		return executor.migrationFailure(principal, err), nil
	}
	account, present := accounts[principal.Username]
	if !present || account.UID != strconv.FormatUint(uint64(principal.UID), 10) || account.GID != strconv.FormatUint(uint64(principal.GID), 10) || account.Comment != migrationAccountMarker(principal.EffectID) || account.Home != home.Path {
		return executor.migrationFailure(principal, ErrConflict), nil
	}
	groups, err := migrationAccountGroupIDs(principal.Username, principal.GID)
	if err != nil || principal.GID != binding.GID && !containsGID(groups, binding.GID) {
		return executor.migrationFailure(principal, errors.Join(ErrConflict, err)), nil
	}
	active := state.Phase == "active"
	enabled := active && principal.Enabled
	locked := strings.HasPrefix(account.Password, "!") || strings.HasPrefix(account.Password, "*")
	if enabled == locked {
		return executor.migrationFailure(principal, ErrConflict), nil
	}
	if account.Shell != migrationPrincipalShell(principal, enabled) {
		return executor.migrationFailure(principal, ErrConflict), nil
	}
	keyDigest := ""
	if principal.Kind == MigrationPrincipalSSH {
		wanted := migrationKeys(principal)
		path := migrationKeyStagePath(principal.EffectID)
		if active && principal.Enabled {
			path = migrationKeyActivePath(principal.Username)
		}
		raw, readErr := readLinuxPrivateFile(path, 1<<20)
		if readErr != nil || !bytes.Equal(raw, wanted) {
			return executor.migrationFailure(principal, errors.Join(ErrConflict, readErr)), nil
		}
		other := migrationKeyActivePath(principal.Username)
		if active && principal.Enabled {
			other = migrationKeyStagePath(principal.EffectID)
		}
		if _, statErr := os.Lstat(other); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
			return executor.migrationFailure(principal, ErrConflict), nil
		}
		sum := sha256.Sum256(raw)
		keyDigest = hex.EncodeToString(sum[:])
	}
	credentialDigest := ""
	if principal.Kind == MigrationPrincipalFTPS {
		hash := strings.TrimPrefix(account.Password, "!")
		if ValidateUnixCryptHash([]byte(hash)) != nil || executor.Secrets == nil {
			return executor.migrationFailure(principal, ErrIntegrity), nil
		}
		expected, readErr := executor.Secrets.ReadMigrationHash(ctx, principal.Credential.Reference, string(principal.TenantID), string(principal.PrincipalID))
		if readErr != nil {
			return executor.migrationFailure(principal, readErr), nil
		}
		matches := subtle.ConstantTimeCompare([]byte(hash), expected) == 1
		wipeAccess(expected)
		if !matches {
			return executor.migrationFailure(principal, ErrIntegrity), nil
		}
		sum := sha256.Sum256([]byte(hash))
		credentialDigest = hex.EncodeToString(sum[:])
	}
	evidenceRaw, _ := json.Marshal(struct {
		Principal                                 MigrationPrincipal
		Home                                      linuxMigrationHomeObservation
		PrimaryGID                                uint32
		SupplementaryGIDs                         []uint32
		Shell, KeyDigest, CredentialDigest, Phase string
		Enabled                                   bool
	}{principal, home, principal.GID, groups, account.Shell, keyDigest, credentialDigest, state.Phase, enabled})
	sum := sha256.Sum256(evidenceRaw)
	evidence := hex.EncodeToString(sum[:])
	status := MigrationAccessApplied
	visible := "dark"
	if active {
		visible = "active"
	}
	return migrationObservation(principal, status, visible, evidence, ""), nil
}

func (executor *LinuxCredentialExecutor) activateMigrationPrincipal(ctx context.Context, principal MigrationPrincipal) error {
	var state linuxMigrationPrincipalState
	found, err := decodeLinuxState(migrationPrincipalPath(principal.EffectID), &state)
	if err != nil || !found {
		return errors.Join(err, ErrConflict)
	}
	if state.DesiredDigest != migrationPrincipalDigest(principal) || state.Phase != "dark" && state.Phase != "activating" && state.Phase != "active" {
		return ErrConflict
	}
	if state.Phase == "active" {
		observation, _ := executor.ObserveMigrationPrincipal(ctx, principal)
		if observation.Status != MigrationAccessApplied || observation.State != "active" {
			return ErrConflict
		}
		return nil
	}
	state.Phase = "activating"
	state.UpdatedAt = time.Now().UTC()
	if err = storeLinuxState(migrationPrincipalPath(principal.EffectID), state); err != nil {
		return err
	}
	if principal.Enabled {
		if principal.Kind == MigrationPrincipalSSH {
			staged, active := migrationKeyStagePath(principal.EffectID), migrationKeyActivePath(principal.Username)
			if _, statErr := os.Lstat(active); errors.Is(statErr, os.ErrNotExist) {
				if err = os.Rename(staged, active); err != nil {
					return err
				}
			} else if statErr != nil {
				return statErr
			}
			if raw, readErr := readLinuxPrivateFile(active, 1<<20); readErr != nil || !bytes.Equal(raw, migrationKeys(principal)) {
				return errors.Join(readErr, ErrConflict)
			}
		}
		if _, err = runFixedAccess(ctx, "/usr/sbin/usermod", nil, "--shell", migrationPrincipalShell(principal, true), "--unlock", principal.Username); err != nil {
			return err
		}
	}
	state.Phase = "active"
	state.UpdatedAt = time.Now().UTC()
	if err = storeLinuxState(migrationPrincipalPath(principal.EffectID), state); err != nil {
		return err
	}
	observation, _ := executor.ObserveMigrationPrincipal(ctx, principal)
	if observation.Status != MigrationAccessApplied || observation.State != "active" {
		return ErrConflict
	}
	state.Evidence = observation.EvidenceDigest
	state.UpdatedAt = time.Now().UTC()
	return storeLinuxState(migrationPrincipalPath(principal.EffectID), state)
}

func (executor *LinuxCredentialExecutor) ActivateMigrationPrincipals(ctx context.Context, batch MigrationPrincipalBatch) (MigrationAccessObservation, error) {
	linuxMigrationAccessMu.Lock()
	defer linuxMigrationAccessMu.Unlock()
	if executor == nil || batch.validateRecorded() != nil {
		return executor.batchFailure(batch, ErrUnauthorized), nil
	}
	digest := migrationBatchDigest(batch)
	var state linuxMigrationBatchState
	found, err := decodeLinuxState(migrationBatchPath(batch.EffectID), &state)
	if err != nil {
		return executor.batchFailure(batch, err), nil
	}
	if found {
		if state.Version != 1 || state.DesiredDigest != digest || migrationBatchDigest(state.Batch) != digest || state.Phase != "admitted" && state.Phase != "activating" && state.Phase != "active" {
			return executor.batchFailure(batch, ErrConflict), nil
		}
		if state.Phase == "active" {
			proofs := make([]string, 0, len(batch.Principals))
			for _, principal := range batch.Principals {
				observation, _ := executor.ObserveMigrationPrincipal(ctx, principal)
				if observation.Status != MigrationAccessApplied || observation.State != "active" {
					return executor.batchFailure(batch, ErrConflict), nil
				}
				proofs = append(proofs, observation.EvidenceDigest)
			}
			if evidence := migrationBatchEvidence(batch, digest, proofs); evidence != state.Evidence {
				return executor.batchFailure(batch, ErrIntegrity), nil
			}
			return migrationBatchObservation(batch, MigrationAccessApplied, "active", state.Evidence, ""), nil
		}
	} else {
		if batch.Action != MigrationActivationAdmit || batch.Validate(time.Now().UTC()) != nil {
			return executor.batchFailure(batch, ErrUnauthorized), nil
		}
		for _, principal := range batch.Principals {
			observation, _ := executor.ObserveMigrationPrincipal(ctx, principal)
			if observation.Status != MigrationAccessApplied || observation.State != "dark" {
				return executor.batchFailure(batch, ErrConflict), nil
			}
		}
		state = linuxMigrationBatchState{Version: 1, Batch: batch, DesiredDigest: digest, Phase: "admitted", UpdatedAt: time.Now().UTC()}
		if err = storeLinuxState(migrationBatchPath(batch.EffectID), state); err != nil {
			return executor.batchFailure(batch, err), nil
		}
		return migrationBatchObservation(batch, MigrationAccessApplied, "admitted", migrationBatchAdmissionEvidence(batch, digest), ""), nil
	}
	if batch.Action == MigrationActivationAdmit || batch.Action == MigrationActivationObserveAdmission {
		return migrationBatchObservation(batch, MigrationAccessApplied, state.Phase, migrationBatchAdmissionEvidence(batch, digest), ""), nil
	}
	if batch.Action != MigrationActivationCommit {
		return executor.batchFailure(batch, ErrUnauthorized), nil
	}
	if state.Phase == "admitted" {
		// A live source fence admitted this exact batch in the durable step
		// above. Commit may therefore resume after lease expiry, but a commit
		// without that root-owned admission record is always rejected.
		state.Phase = "activating"
		state.UpdatedAt = time.Now().UTC()
		if err = storeLinuxState(migrationBatchPath(batch.EffectID), state); err != nil {
			return executor.batchFailure(batch, err), nil
		}
	}
	proofs := make([]string, 0, len(batch.Principals))
	for _, principal := range batch.Principals {
		if err = executor.activateMigrationPrincipal(ctx, principal); err != nil {
			return executor.batchFailure(batch, err), nil
		}
		observation, _ := executor.ObserveMigrationPrincipal(ctx, principal)
		if observation.Status != MigrationAccessApplied || observation.State != "active" {
			return executor.batchFailure(batch, ErrConflict), nil
		}
		proofs = append(proofs, observation.EvidenceDigest)
	}
	state.Phase = "active"
	state.Evidence = migrationBatchEvidence(batch, digest, proofs)
	state.UpdatedAt = time.Now().UTC()
	if err = storeLinuxState(migrationBatchPath(batch.EffectID), state); err != nil {
		return executor.batchFailure(batch, err), nil
	}
	return migrationBatchObservation(batch, MigrationAccessApplied, "active", state.Evidence, ""), nil
}

func (executor *LinuxCredentialExecutor) cleanupMigrationGroup(ctx context.Context, state linuxMigrationPrincipalState) error {
	if state.ManagedGroup == "" {
		return nil
	}
	principal := state.Principal
	if state.ManagedGroup != migrationManagedGroup(principal.MigrationID, principal.GID) {
		return ErrConflict
	}
	accounts, _, err := linuxAccounts()
	if err != nil {
		return err
	}
	wantedGID := strconv.FormatUint(uint64(principal.GID), 10)
	for _, account := range accounts {
		if account.GID == wantedGID {
			// Another staged principal still owns the shared migration group. Its
			// compensation will remove the group after the last account is gone.
			return nil
		}
	}
	byName, _, err := linuxGroups()
	if err != nil {
		return err
	}
	group, present := byName[state.ManagedGroup]
	if !present {
		return nil
	}
	if group.GID != principal.GID || len(group.Members) != 0 {
		return ErrConflict
	}
	if _, err = runFixedAccess(ctx, "/usr/sbin/groupdel", nil, state.ManagedGroup); err != nil {
		return err
	}
	byName, _, err = linuxGroups()
	if err != nil {
		return err
	}
	if _, present = byName[state.ManagedGroup]; present {
		return ErrConflict
	}
	return nil
}

func migrationPrincipalPastPublicFrontier(effectID string) (bool, error) {
	entries, err := os.ReadDir(linuxMigrationAccessRoot)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "batch-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		batchID := strings.TrimSuffix(strings.TrimPrefix(name, "batch-"), ".json")
		if !migrationAccessDigest(batchID) {
			return false, ErrIntegrity
		}
		var state linuxMigrationBatchState
		found, readErr := decodeLinuxState(linuxMigrationAccessRoot+"/"+name, &state)
		validPhase := state.Phase == "admitted" || state.Phase == "activating" || state.Phase == "active"
		if readErr != nil || !found || state.Version != 1 || state.Batch.EffectID != batchID || state.DesiredDigest != migrationBatchDigest(state.Batch) || !validPhase {
			return false, errors.Join(readErr, ErrIntegrity)
		}
		if state.Phase != "activating" && state.Phase != "active" {
			continue
		}
		for _, principal := range state.Batch.Principals {
			if principal.EffectID == effectID {
				return true, nil
			}
		}
	}
	return false, nil
}

func (executor *LinuxCredentialExecutor) CompensateMigrationPrincipal(ctx context.Context, principal MigrationPrincipal, attempt uint32) (MigrationAccessObservation, error) {
	linuxMigrationAccessMu.Lock()
	defer linuxMigrationAccessMu.Unlock()
	if executor == nil || attempt == 0 || principal.Validate() != nil {
		return executor.migrationFailure(principal, ErrInvalidState), nil
	}
	var state linuxMigrationPrincipalState
	found, err := decodeLinuxState(migrationPrincipalPath(principal.EffectID), &state)
	if err != nil {
		return executor.migrationFailure(principal, err), nil
	}
	if !found {
		sum := sha256.Sum256([]byte("migration-principal-absent\x00" + principal.EffectID))
		return migrationObservation(principal, MigrationAccessCompensated, "absent", hex.EncodeToString(sum[:]), ""), nil
	}
	if state.DesiredDigest != migrationPrincipalDigest(principal) {
		return executor.migrationFailure(principal, ErrConflict), nil
	}
	if state.Phase == "active" || state.Phase == "activating" {
		return executor.migrationFailure(principal, ErrUnauthorized), nil
	}
	published, err := migrationPrincipalPastPublicFrontier(principal.EffectID)
	if err != nil {
		return executor.migrationFailure(principal, err), nil
	}
	if published {
		return executor.migrationFailure(principal, ErrUnauthorized), nil
	}
	if state.Phase == "compensated" {
		return migrationObservation(principal, MigrationAccessCompensated, "absent", state.Evidence, ""), nil
	}
	state.Phase = "compensating"
	state.Attempt = attempt
	state.UpdatedAt = time.Now().UTC()
	if err = storeLinuxState(migrationPrincipalPath(principal.EffectID), state); err != nil {
		return executor.migrationFailure(principal, err), nil
	}
	if removeErr := os.Remove(migrationKeyStagePath(principal.EffectID)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return executor.migrationFailure(principal, removeErr), nil
	}
	if _, statErr := os.Lstat(migrationKeyActivePath(principal.Username)); statErr == nil {
		return executor.migrationFailure(principal, ErrUnauthorized), nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return executor.migrationFailure(principal, statErr), nil
	}
	accounts, _, err := linuxAccounts()
	if err != nil {
		return executor.migrationFailure(principal, err), nil
	}
	if account, present := accounts[principal.Username]; present {
		if account.Comment != migrationAccountMarker(principal.EffectID) {
			return executor.migrationFailure(principal, ErrConflict), nil
		}
		if _, err = runFixedAccess(ctx, "/usr/sbin/userdel", nil, principal.Username); err != nil {
			return executor.migrationFailure(principal, err), nil
		}
	}
	if err = executor.cleanupMigrationGroup(ctx, state); err != nil {
		return executor.migrationFailure(principal, err), nil
	}
	sum := sha256.Sum256([]byte("migration-principal-compensated\x00" + state.DesiredDigest))
	state.Phase = "compensated"
	state.Evidence = hex.EncodeToString(sum[:])
	state.UpdatedAt = time.Now().UTC()
	if err = storeLinuxState(migrationPrincipalPath(principal.EffectID), state); err != nil {
		return executor.migrationFailure(principal, err), nil
	}
	return migrationObservation(principal, MigrationAccessCompensated, "absent", state.Evidence, ""), nil
}

var _ MigrationPrincipalExecutor = (*LinuxCredentialExecutor)(nil)
