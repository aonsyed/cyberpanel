package themes

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	storeStateFile = "state.json"
	storeLockFile  = ".lock"
)

type StoreConfig struct {
	Root              string
	RequiredRoot      string
	MaximumStateBytes int64
	Clock             func() time.Time
}

type Store struct {
	root              *os.Root
	rootPath          string
	maximumStateBytes int64
	clock             func() time.Time
}

type diskState struct {
	Version    uint8             `json:"version"`
	Generation uint64            `json:"generation"`
	Packages   []InstalledTheme  `json:"packages"`
	Scopes     []ActivationState `json:"scopes"`
	Digest     string            `json:"digest"`
}

func OpenStore(config StoreConfig) (*Store, error) {
	if config.Root == "" || config.Root != config.RequiredRoot || !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root {
		return nil, ErrInvalid
	}
	if config.MaximumStateBytes == 0 {
		config.MaximumStateBytes = DefaultMaximumStateBytes
	}
	if config.MaximumStateBytes < 4096 || config.MaximumStateBytes > 64<<20 {
		return nil, ErrInvalid
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	before, err := os.Lstat(config.Root)
	if err != nil || validateDirectory(before) != nil {
		return nil, errors.Join(ErrDenied, err)
	}
	real, err := filepath.EvalSymlinks(config.Root)
	if err != nil || real != config.Root {
		return nil, ErrDenied
	}
	opened, err := os.OpenRoot(config.Root)
	if err != nil {
		return nil, err
	}
	after, err := opened.Stat(".")
	if err != nil || !os.SameFile(before, after) || validateDirectory(after) != nil {
		opened.Close()
		return nil, ErrDenied
	}
	store := &Store{root: opened, rootPath: config.Root, maximumStateBytes: config.MaximumStateBytes, clock: config.Clock}
	for _, directory := range []string{"packages", "staging"} {
		if err = store.ensureDirectory(directory); err != nil {
			store.Close()
			return nil, err
		}
	}
	if err = store.ensureLockFile(); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) Close() error {
	if store == nil || store.root == nil {
		return nil
	}
	err := store.root.Close()
	store.root = nil
	return err
}

func (store *Store) ensureLockFile() error {
	info, err := store.root.Lstat(storeLockFile)
	if errors.Is(err, fs.ErrNotExist) {
		file, createErr := store.root.OpenFile(storeLockFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			return createErr
		}
		if syncErr := file.Sync(); syncErr != nil {
			file.Close()
			return syncErr
		}
		if closeErr := file.Close(); closeErr != nil {
			return closeErr
		}
		return store.syncDirectory(".")
	}
	if err != nil || validateRegular(info) != nil {
		return errors.Join(ErrDenied, err)
	}
	return nil
}

func (store *Store) withLock(ctx context.Context, operation func() error) error {
	if store == nil || store.root == nil || ctx == nil || operation == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := store.root.OpenFile(storeLockFile, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if err = ctx.Err(); err != nil {
		return err
	}
	return operation()
}

func (store *Store) install(ctx context.Context, candidate VerifiedPackage, expected uint64) (Receipt, error) {
	var receipt Receipt
	err := store.withLock(ctx, func() error {
		state, err := store.loadState()
		if err != nil {
			return err
		}
		if state.Generation != expected {
			return ErrConflict
		}
		for _, installed := range state.Packages {
			if installed.Reference.ThemeID == candidate.Manifest.ThemeID && installed.Reference.Version == candidate.Manifest.Version {
				if installed.Reference.Digest != candidate.Manifest.Digest {
					return ErrConflict
				}
				probe, verifyErr := store.probePackage(installed)
				if verifyErr != nil {
					return verifyErr
				}
				reference := installed.Reference
				receipt = newReceipt("install", nil, &reference, nil, state.Generation, state.Generation, "", state.Digest, store.clock(), []Probe{probe})
				return nil
			}
		}
		if err = store.stagePackage(candidate); err != nil {
			return err
		}
		now := store.clock().UTC()
		reference := referenceFor(candidate.Manifest)
		installed := InstalledTheme{Reference: reference, Manifest: candidate.Manifest, InstalledAt: now}
		state.Packages = append(state.Packages, installed)
		state.Generation++
		if err = store.saveState(&state); err != nil {
			return err
		}
		probe, err := store.probePackage(installed)
		if err != nil {
			return err
		}
		receipt = newReceipt("install", nil, &reference, nil, state.Generation, state.Generation, "", state.Digest, now, []Probe{probe})
		return nil
	})
	return receipt, err
}

func (store *Store) list(ctx context.Context, limit int, cursor string) (Inventory, error) {
	if limit < 1 || limit > 200 || len(cursor) > 256 {
		return Inventory{}, ErrInvalid
	}
	var inventory Inventory
	err := store.withLock(ctx, func() error {
		state, err := store.loadState()
		if err != nil {
			return err
		}
		inventory.Generation = state.Generation
		for _, installed := range state.Packages {
			key := packageKey(installed.Reference)
			if key <= cursor {
				continue
			}
			inventory.Items = append(inventory.Items, installed)
			if len(inventory.Items) > limit {
				inventory.NextCursor = packageKey(inventory.Items[limit-1].Reference)
				inventory.Items = inventory.Items[:limit]
				break
			}
		}
		return nil
	})
	return inventory, err
}

func (store *Store) inspect(ctx context.Context, themeID, version string) (Inspection, error) {
	if !themeIDPattern.MatchString(themeID) || !validVersion(version) {
		return Inspection{}, ErrInvalid
	}
	var inspection Inspection
	err := store.withLock(ctx, func() error {
		state, err := store.loadState()
		if err != nil {
			return err
		}
		installed, found := findInstalled(state.Packages, themeID, version)
		if !found {
			return ErrNotFound
		}
		probe, err := store.probePackage(installed)
		if err != nil {
			return err
		}
		inspection = Inspection{Theme: installed, Probe: probe}
		return nil
	})
	return inspection, err
}

func (store *Store) activate(ctx context.Context, scope Scope, reference ThemeReference, expected uint64) (Receipt, error) {
	if scope.Validate() != nil || reference.Validate() != nil {
		return Receipt{}, ErrInvalid
	}
	var receipt Receipt
	err := store.withLock(ctx, func() error {
		state, err := store.loadState()
		if err != nil {
			return err
		}
		installed, found := findReference(state.Packages, reference)
		if !found {
			return ErrNotFound
		}
		probe, err := store.probePackage(installed)
		if err != nil {
			return err
		}
		index, existing := findScope(state.Scopes, scope)
		activation := ActivationState{Scope: scope}
		if existing {
			activation = state.Scopes[index]
		}
		if activation.Generation != expected {
			return ErrConflict
		}
		previous := activation.ActiveReference()
		if previous != nil && sameReference(*previous, reference) {
			receipt = newReceipt("activate", &scope, &reference, previous, activation.Generation, state.Generation, activation.Active, state.Digest, store.clock(), []Probe{probe})
			return nil
		}
		if activation.Active == SlotA {
			activation.B = cloneReference(&reference)
			activation.Active = SlotB
		} else {
			activation.A = cloneReference(&reference)
			activation.Active = SlotA
		}
		activation.Generation++
		activation.UpdatedAt = store.clock().UTC()
		if existing {
			state.Scopes[index] = activation
		} else {
			state.Scopes = append(state.Scopes, activation)
		}
		state.Generation++
		if err = store.saveState(&state); err != nil {
			return err
		}
		receipt = newReceipt("activate", &scope, &reference, previous, activation.Generation, state.Generation, activation.Active, state.Digest, activation.UpdatedAt, []Probe{probe, stateProbe(state, activation.UpdatedAt)})
		return nil
	})
	return receipt, err
}

func (store *Store) rollback(ctx context.Context, scope Scope, expected uint64) (Receipt, error) {
	if scope.Validate() != nil {
		return Receipt{}, ErrInvalid
	}
	var receipt Receipt
	err := store.withLock(ctx, func() error {
		state, err := store.loadState()
		if err != nil {
			return err
		}
		index, found := findScope(state.Scopes, scope)
		if !found || state.Scopes[index].Generation != expected {
			return ErrConflict
		}
		activation := state.Scopes[index]
		previous := activation.ActiveReference()
		var target *ThemeReference
		if activation.Active == SlotA {
			target = cloneReference(activation.B)
			activation.Active = SlotB
		} else {
			target = cloneReference(activation.A)
			activation.Active = SlotA
		}
		if target == nil || target.Validate() != nil {
			return ErrNotFound
		}
		installed, exists := findReference(state.Packages, *target)
		if !exists {
			return ErrIntegrity
		}
		probe, err := store.probePackage(installed)
		if err != nil {
			return err
		}
		activation.Generation++
		activation.UpdatedAt = store.clock().UTC()
		state.Scopes[index] = activation
		state.Generation++
		if err = store.saveState(&state); err != nil {
			return err
		}
		receipt = newReceipt("rollback", &scope, target, previous, activation.Generation, state.Generation, activation.Active, state.Digest, activation.UpdatedAt, []Probe{probe, stateProbe(state, activation.UpdatedAt)})
		return nil
	})
	return receipt, err
}

func (store *Store) delete(ctx context.Context, themeID, version string, expected uint64) (Receipt, error) {
	if !themeIDPattern.MatchString(themeID) || !validVersion(version) {
		return Receipt{}, ErrInvalid
	}
	var receipt Receipt
	err := store.withLock(ctx, func() error {
		state, err := store.loadState()
		if err != nil {
			return err
		}
		if state.Generation != expected {
			return ErrConflict
		}
		installed, found := findInstalled(state.Packages, themeID, version)
		if !found {
			return ErrNotFound
		}
		for _, activation := range state.Scopes {
			if referenceMatches(activation.A, installed.Reference) || referenceMatches(activation.B, installed.Reference) {
				return ErrConflict
			}
		}
		filtered := state.Packages[:0]
		for _, candidate := range state.Packages {
			if !sameReference(candidate.Reference, installed.Reference) {
				filtered = append(filtered, candidate)
			}
		}
		state.Packages = filtered
		state.Generation++
		if err = store.saveState(&state); err != nil {
			return err
		}
		if err = store.removeTree(packageRoot(installed.Reference)); err != nil {
			return errors.Join(ErrIntegrity, err)
		}
		now := store.clock().UTC()
		probe := Probe{Name: "package_removed", Passed: true, Digest: installed.Reference.Digest, ObservedAt: now}
		reference := installed.Reference
		receipt = newReceipt("delete", nil, &reference, nil, state.Generation, state.Generation, "", state.Digest, now, []Probe{probe})
		return nil
	})
	return receipt, err
}

func (store *Store) snapshot(ctx context.Context) (diskState, error) {
	var result diskState
	err := store.withLock(ctx, func() error {
		state, err := store.loadState()
		if err == nil {
			result = state
		}
		return err
	})
	return result, err
}

func (store *Store) stagePackage(candidate VerifiedPackage) error {
	final := packageRoot(referenceFor(candidate.Manifest))
	if err := store.ensureDirectory(path.Dir(final)); err != nil {
		return err
	}
	if info, err := store.root.Lstat(final); err == nil {
		if validateDirectory(info) != nil {
			return ErrDenied
		}
		installed := InstalledTheme{Reference: referenceFor(candidate.Manifest), Manifest: candidate.Manifest}
		_, verifyErr := store.probePackage(installed)
		return verifyErr
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	stageName, err := randomName("theme")
	if err != nil {
		return err
	}
	stage := path.Join("staging", stageName)
	if err = store.root.Mkdir(stage, 0o700); err != nil {
		return err
	}
	keep := false
	defer func() { if !keep { _ = store.removeTree(stage) } }()
	manifestRaw, err := json.Marshal(candidate.Manifest)
	if err != nil || int64(len(manifestRaw)) > store.maximumStateBytes {
		return ErrCapacity
	}
	if err = store.writeNew(path.Join(stage, "manifest.json"), manifestRaw); err != nil {
		return err
	}
	for _, asset := range candidate.assets {
		name := path.Join(stage, "assets", asset.Path)
		if err = store.ensureDirectory(path.Dir(name)); err != nil {
			return err
		}
		if err = store.writeNew(name, asset.Content); err != nil {
			return err
		}
	}
	if err = store.syncDirectory(stage); err != nil {
		return err
	}
	if err = store.root.Rename(stage, final); err != nil {
		return err
	}
	keep = true
	if err = store.syncDirectory(path.Dir(final)); err != nil {
		return err
	}
	installed := InstalledTheme{Reference: referenceFor(candidate.Manifest), Manifest: candidate.Manifest}
	_, err = store.probePackage(installed)
	return err
}

func (store *Store) probePackage(installed InstalledTheme) (Probe, error) {
	if installed.Reference.Validate() != nil || installed.Manifest.ThemeID != installed.Reference.ThemeID || installed.Manifest.Version != installed.Reference.Version || installed.Manifest.Digest != installed.Reference.Digest {
		return Probe{}, ErrIntegrity
	}
	root := packageRoot(installed.Reference)
	manifestRaw, err := store.readRegular(path.Join(root, "manifest.json"), store.maximumStateBytes)
	if err != nil {
		return Probe{}, err
	}
	expectedManifest, err := json.Marshal(installed.Manifest)
	if err != nil || !bytes.Equal(manifestRaw, expectedManifest) {
		return Probe{}, ErrIntegrity
	}
	expected := make(map[string]AssetDescriptor, len(installed.Manifest.Assets))
	for _, descriptor := range installed.Manifest.Assets {
		expected[descriptor.Path] = descriptor
		content, readErr := store.readRegular(path.Join(root, "assets", descriptor.Path), int64(descriptor.Size))
		if readErr != nil || uint64(len(content)) != descriptor.Size {
			return Probe{}, errors.Join(ErrIntegrity, readErr)
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != descriptor.SHA256 || !validMagic(descriptor.MIME, content) {
			return Probe{}, ErrIntegrity
		}
	}
	observed, err := store.listTree(path.Join(root, "assets"), DefaultMaximumAssets*4)
	if err != nil || len(observed) != len(expected) {
		return Probe{}, errors.Join(ErrIntegrity, err)
	}
	for _, name := range observed {
		if _, exists := expected[name]; !exists {
			return Probe{}, ErrIntegrity
		}
	}
	now := store.clock().UTC()
	return Probe{Name: "package_integrity", Passed: true, Digest: installed.Reference.Digest, ObservedAt: now}, nil
}

func (store *Store) loadState() (diskState, error) {
	raw, err := store.readRegular(storeStateFile, store.maximumStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		state := diskState{Version: 1, Packages: []InstalledTheme{}, Scopes: []ActivationState{}}
		state.Digest = stateDigest(state)
		return state, nil
	}
	if err != nil {
		return diskState{}, err
	}
	var state diskState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return diskState{}, ErrIntegrity
	}
	canonical, marshalErr := json.Marshal(state)
	if marshalErr != nil || !bytes.Equal(raw, canonical) || state.Version != 1 || !validDigest(state.Digest) || state.Digest != stateDigest(state) {
		return diskState{}, ErrIntegrity
	}
	for index, installed := range state.Packages {
		if installed.Reference.Validate() != nil || installed.InstalledAt.IsZero() || installed.Manifest.Digest != installed.Reference.Digest || index > 0 && packageKey(state.Packages[index-1].Reference) >= packageKey(installed.Reference) {
			return diskState{}, ErrIntegrity
		}
	}
	for index, activation := range state.Scopes {
		if activation.Scope.Validate() != nil || activation.Generation == 0 || activation.UpdatedAt.IsZero() || activation.Active != SlotA && activation.Active != SlotB || activation.ActiveReference() == nil || index > 0 && scopeKey(state.Scopes[index-1].Scope) >= scopeKey(activation.Scope) {
			return diskState{}, ErrIntegrity
		}
		for _, reference := range []*ThemeReference{activation.A, activation.B} {
			if reference != nil && reference.Validate() != nil {
				return diskState{}, ErrIntegrity
			}
		}
	}
	return state, nil
}

func (store *Store) saveState(state *diskState) error {
	if state == nil || state.Version != 1 {
		return ErrInvalid
	}
	sort.Slice(state.Packages, func(i, j int) bool { return packageKey(state.Packages[i].Reference) < packageKey(state.Packages[j].Reference) })
	sort.Slice(state.Scopes, func(i, j int) bool { return scopeKey(state.Scopes[i].Scope) < scopeKey(state.Scopes[j].Scope) })
	state.Digest = stateDigest(*state)
	raw, err := json.Marshal(state)
	if err != nil || int64(len(raw)) > store.maximumStateBytes {
		return ErrCapacity
	}
	if info, statErr := store.root.Lstat(storeStateFile); statErr == nil {
		if validateRegular(info) != nil {
			return ErrDenied
		}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}
	temporary, err := randomName("state")
	if err != nil {
		return err
	}
	if err = store.writeNew(temporary, raw); err != nil {
		return err
	}
	if err = store.root.Rename(temporary, storeStateFile); err != nil {
		_ = store.root.Remove(temporary)
		return err
	}
	if err = store.syncDirectory("."); err != nil {
		return err
	}
	published, err := store.readRegular(storeStateFile, store.maximumStateBytes)
	if err != nil || !bytes.Equal(published, raw) {
		return ErrIntegrity
	}
	return nil
}

func stateDigest(state diskState) string {
	state.Digest = ""
	raw, _ := json.Marshal(state)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func stateProbe(state diskState, now time.Time) Probe {
	return Probe{Name: "activation_state", Passed: true, Digest: state.Digest, ObservedAt: now.UTC()}
}

func newReceipt(operation string, scope *Scope, reference, previous *ThemeReference, generation, storeGeneration uint64, slot Slot, stateDigest string, now time.Time, probes []Probe) Receipt {
	receipt := Receipt{Operation: operation, Scope: cloneScope(scope), Reference: cloneReference(reference), Previous: cloneReference(previous), Generation: generation, StoreGeneration: storeGeneration, ActiveSlot: slot, StateDigest: stateDigest, CompletedAt: now.UTC(), Probes: append([]Probe(nil), probes...)}
	raw, _ := json.Marshal(receipt)
	sum := sha256.Sum256(raw)
	receipt.ReceiptDigest = hex.EncodeToString(sum[:])
	return receipt
}

func referenceFor(manifest Manifest) ThemeReference {
	return ThemeReference{ThemeID: manifest.ThemeID, Version: manifest.Version, Digest: manifest.Digest, AssetRoot: packageAssetRoot(manifest.ThemeID, manifest.Version, manifest.Digest)}
}

func packageRoot(reference ThemeReference) string {
	return path.Join("packages", reference.ThemeID, reference.Version, reference.Digest)
}

func packageAssetRoot(themeID, version, digest string) string {
	return path.Join("packages", themeID, version, digest, "assets")
}

func packageKey(reference ThemeReference) string {
	return reference.ThemeID + "\x00" + reference.Version
}

func scopeKey(scope Scope) string {
	raw, _ := json.Marshal(scope)
	sum := sha256.Sum256(raw)
	return string(scope.Kind) + "-" + hex.EncodeToString(sum[:16])
}

func findInstalled(values []InstalledTheme, themeID, version string) (InstalledTheme, bool) {
	for _, value := range values {
		if value.Reference.ThemeID == themeID && value.Reference.Version == version {
			return value, true
		}
	}
	return InstalledTheme{}, false
}

func findReference(values []InstalledTheme, reference ThemeReference) (InstalledTheme, bool) {
	for _, value := range values {
		if sameReference(value.Reference, reference) {
			return value, true
		}
	}
	return InstalledTheme{}, false
}

func findScope(values []ActivationState, scope Scope) (int, bool) {
	target := scopeKey(scope)
	for index, value := range values {
		if scopeKey(value.Scope) == target {
			if value.Scope != scope {
				return -1, false
			}
			return index, true
		}
	}
	return -1, false
}

func sameReference(left, right ThemeReference) bool {
	return left.ThemeID == right.ThemeID && left.Version == right.Version && left.Digest == right.Digest && left.AssetRoot == right.AssetRoot
}

func referenceMatches(value *ThemeReference, target ThemeReference) bool {
	return value != nil && sameReference(*value, target)
}

func cloneReference(value *ThemeReference) *ThemeReference {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneScope(value *Scope) *Scope {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func randomName(prefix string) (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return "." + prefix + "-" + hex.EncodeToString(entropy[:]), nil
}

func (store *Store) writeNew(name string, content []byte) error {
	if !safeManagedPath(name) {
		return ErrDenied
	}
	if err := store.ensureDirectory(path.Dir(name)); err != nil {
		return err
	}
	file, err := store.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if written != len(content) {
		return io.ErrShortWrite
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return store.syncDirectory(path.Dir(name))
}

func (store *Store) readRegular(name string, limit int64) ([]byte, error) {
	if !safeManagedPath(name) || limit < 0 {
		return nil, ErrDenied
	}
	if err := store.validateParents(name); err != nil {
		return nil, err
	}
	before, err := store.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if validateRegular(before) != nil || before.Size() < 0 || before.Size() > limit {
		return nil, ErrDenied
	}
	file, err := store.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || validateRegular(opened) != nil || !os.SameFile(before, opened) {
		return nil, ErrIntegrity
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != opened.Size() || int64(len(raw)) > limit {
		return nil, errors.Join(ErrIntegrity, err)
	}
	after, err := store.root.Lstat(name)
	if err != nil || !os.SameFile(opened, after) {
		return nil, ErrIntegrity
	}
	return raw, nil
}

func (store *Store) ensureDirectory(name string) error {
	if name == "." {
		info, err := store.root.Lstat(".")
		if err != nil || validateDirectory(info) != nil {
			return errors.Join(ErrDenied, err)
		}
		return nil
	}
	if !safeManagedPath(name) {
		return ErrDenied
	}
	current := ""
	for _, component := range strings.Split(name, "/") {
		parent := "."
		if current != "" {
			parent = current
		}
		current = path.Join(current, component)
		info, err := store.root.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if err = store.root.Mkdir(current, 0o700); err != nil {
				return err
			}
			if err = store.syncDirectory(parent); err != nil {
				return err
			}
			info, err = store.root.Lstat(current)
		}
		if err != nil || validateDirectory(info) != nil {
			return errors.Join(ErrDenied, err)
		}
	}
	return nil
}

func (store *Store) syncDirectory(name string) error {
	directory, err := store.root.Open(name)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func (store *Store) listTree(root string, maximum int) ([]string, error) {
	if !safeManagedPath(root) || maximum < 1 {
		return nil, ErrInvalid
	}
	if err := store.validateParents(root); err != nil {
		return nil, err
	}
	rootInfo, err := store.root.Lstat(root)
	if err != nil || validateDirectory(rootInfo) != nil {
		return nil, errors.Join(ErrDenied, err)
	}
	result := []string{}
	var walk func(string, string) error
	walk = func(current, relative string) error {
		file, err := store.root.Open(current)
		if err != nil {
			return err
		}
		entries, readErr := file.ReadDir(maximum + 1)
		file.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if len(entries) > maximum || len(result) > maximum-len(entries) {
			return ErrCapacity
		}
		for _, entry := range entries {
			name := path.Join(current, entry.Name())
			child := entry.Name()
			if relative != "" {
				child = path.Join(relative, entry.Name())
			}
			info, err := store.root.Lstat(name)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return ErrDenied
			}
			if info.IsDir() {
				if validateDirectory(info) != nil {
					return ErrDenied
				}
				if err = walk(name, child); err != nil {
					return err
				}
			} else {
				if validateRegular(info) != nil {
					return ErrDenied
				}
				result = append(result, child)
			}
		}
		return nil
	}
	if err := walk(root, ""); err != nil {
		return nil, err
	}
	sort.Strings(result)
	return result, nil
}

func (store *Store) removeTree(name string) error {
	if !safeManagedPath(name) || name == "packages" || name == "staging" {
		return ErrDenied
	}
	if err := store.validateParents(name); err != nil {
		return err
	}
	info, err := store.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return store.root.Remove(name)
	}
	directory, err := store.root.Open(name)
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(DefaultMaximumAssets*8 + 32)
	directory.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > DefaultMaximumAssets*8 {
		return errors.Join(ErrCapacity, err)
	}
	for _, entry := range entries {
		if err = store.removeTree(path.Join(name, entry.Name())); err != nil {
			return err
		}
	}
	if err = store.root.Remove(name); err != nil {
		return err
	}
	return store.syncDirectory(path.Dir(name))
}

func safeManagedPath(value string) bool {
	return value != "" && value != "." && fs.ValidPath(value) && path.Clean(value) == value && !strings.ContainsAny(value, "\\\x00")
}

func (store *Store) validateParents(name string) error {
	if !safeManagedPath(name) {
		return ErrDenied
	}
	parent := path.Dir(name)
	if parent == "." {
		info, err := store.root.Lstat(".")
		if err != nil || validateDirectory(info) != nil {
			return errors.Join(ErrDenied, err)
		}
		return nil
	}
	current := ""
	for _, component := range strings.Split(parent, "/") {
		current = path.Join(current, component)
		info, err := store.root.Lstat(current)
		if err != nil || validateDirectory(info) != nil {
			return errors.Join(ErrDenied, err)
		}
	}
	return nil
}

func validateDirectory(info fs.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrDenied
	}
	return nil
}

func validateRegular(info fs.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return ErrDenied
	}
	return nil
}
