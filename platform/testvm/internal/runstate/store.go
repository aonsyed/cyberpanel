package runstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	temporarySuffix = ".tmp"
	intentSuffix    = ".intent"
	maxStateBytes   = 4096
	intentContents  = "run-state-write-v1\n"
)

var (
	// ErrAlreadyExists prevents reuse of any persisted run ID, including a
	// completed or failed run.
	ErrAlreadyExists = errors.New("run state already exists")
	// ErrTemporaryExists indicates crash residue predating the intent-marker
	// protocol. It is never silently discarded.
	ErrTemporaryExists = errors.New("run-state temporary file exists")
	// ErrUncertainState indicates that a durable write intent exists. The state
	// must be reconciled explicitly before any future operation.
	ErrUncertainState = errors.New("run-state write outcome is uncertain")
	// ErrCleanupUncertain means the new state was durably published, but cleanup
	// could not itself be proven durable. The returned State is committed.
	ErrCleanupUncertain = errors.New("run-state cleanup outcome is uncertain")
	// ErrUnsafePath indicates an untrusted directory, symlink, non-regular file,
	// wrong permissions, or an entry identity change.
	ErrUnsafePath = errors.New("unsafe run-state path")
	// ErrCorruptState indicates unreadable, non-closed, noncanonical, or invalid
	// persisted JSON.
	ErrCorruptState = errors.New("corrupt run state")
	// ErrStaleRevision indicates compare-and-swap rejection.
	ErrStaleRevision = errors.New("stale run-state revision")
)

// RevisionConflictError records both sides of a rejected compare-and-swap.
type RevisionConflictError struct {
	Expected uint64
	Actual   uint64
}

func (e *RevisionConflictError) Error() string {
	return fmt.Sprintf("%v: expected %d, actual %d", ErrStaleRevision, e.Expected, e.Actual)
}

func (e *RevisionConflictError) Unwrap() error { return ErrStaleRevision }

// rootDirectory is the Go 1.26 os.Root surface used by Store. Keeping this
// narrow makes security races and filesystem failures deterministic in tests.
type rootDirectory interface {
	Close() error
	Open(name string) (*os.File, error)
	OpenFile(name string, flag int, perm os.FileMode) (*os.File, error)
	Lstat(name string) (os.FileInfo, error)
	Link(oldname, newname string) error
	Rename(oldname, newname string) error
	Remove(name string) error
	Symlink(oldname, newname string) error
}

type storeOperations struct {
	openRoot func(string) (rootDirectory, error)
	syncFile func(*os.File) error
}

func defaultStoreOperations() storeOperations {
	return storeOperations{
		openRoot: func(path string) (rootDirectory, error) {
			return os.OpenRoot(path)
		},
		syncFile: func(file *os.File) error {
			return file.Sync()
		},
	}
}

// Store persists exactly one run state at Path. Path's parent must be a
// private 0700 directory. Every artifact access after opening the parent is a
// fixed-name, directory-relative os.Root operation.
type Store struct {
	Path       string
	operations *storeOperations
}

// Create atomically persists a NEW run. Hard-link publication supplies
// no-replace semantics: an existing final entry is never overwritten.
func (s Store) Create(runID string) (State, error) {
	state, err := New(runID)
	if err != nil {
		return State{}, err
	}
	root, names, operations, err := s.open()
	if err != nil {
		return State{}, err
	}
	defer root.Close()

	if err := rejectResidue(root, names); err != nil {
		return State{}, err
	}
	if err := rejectExistingState(root, names.state); err != nil {
		return State{}, err
	}
	if err := createIntent(root, names.intent, operations); err != nil {
		return State{}, err
	}

	temporaryInfo, err := writeExclusive(root, names.temporary, canonicalState(state), operations)
	if err != nil {
		return State{}, err
	}
	if err := verifyEntry(root, names.temporary, temporaryInfo, "temporary state"); err != nil {
		return State{}, err
	}
	if err := root.Link(names.temporary, names.state); err != nil {
		if errors.Is(err, os.ErrExist) {
			return State{}, ErrAlreadyExists
		}
		return State{}, fmt.Errorf("publish run state without replacement: %w", err)
	}
	if err := verifyEntry(root, names.state, temporaryInfo, "published state"); err != nil {
		return State{}, err
	}
	if err := syncRoot(root, operations); err != nil {
		return State{}, fmt.Errorf("sync published run state: %w", err)
	}

	if err := removeAndSync(root, names.temporary, operations); err != nil {
		return state, cleanupUncertain("temporary state", err)
	}
	if err := removeAndSync(root, names.intent, operations); err != nil {
		return state, cleanupUncertain("intent marker", err)
	}
	return state, nil
}

// Load reads one strict, canonical state document. Intent or temporary residue
// blocks the read so an interrupted write is never mistaken for clean state.
func (s Store) Load() (State, error) {
	root, names, _, err := s.open()
	if err != nil {
		return State{}, err
	}
	defer root.Close()

	if err := rejectResidue(root, names); err != nil {
		return State{}, err
	}
	state, _, err := loadCurrent(root, names.state)
	if err != nil {
		return State{}, err
	}
	if err := rejectResidue(root, names); err != nil {
		return State{}, err
	}
	return state, nil
}

// Transition atomically applies a legal transition iff expectedRevision still
// matches. A durable intent excludes cooperating writers; entry identity is
// rechecked immediately before anchored replacement.
func (s Store) Transition(expectedRevision uint64, next Phase, failure *Failure) (State, error) {
	root, names, operations, err := s.open()
	if err != nil {
		return State{}, err
	}
	defer root.Close()

	if err := rejectResidue(root, names); err != nil {
		return State{}, err
	}
	current, _, err := loadCurrent(root, names.state)
	if err != nil {
		return State{}, err
	}
	if current.Revision != expectedRevision {
		return State{}, &RevisionConflictError{Expected: expectedRevision, Actual: current.Revision}
	}
	updated, err := current.Transition(next, failure)
	if err != nil {
		return State{}, err
	}
	if err := createIntent(root, names.intent, operations); err != nil {
		return State{}, err
	}

	// Reload after acquiring the durable intent. This closes the race between
	// the optimistic read and writer exclusion.
	locked, lockedInfo, err := loadCurrent(root, names.state)
	if err != nil {
		return State{}, err
	}
	if locked.RunID != current.RunID || locked.Revision != expectedRevision {
		return State{}, fmt.Errorf("%w: state changed while acquiring write intent", ErrUnsafePath)
	}
	temporaryInfo, err := writeExclusive(root, names.temporary, canonicalState(updated), operations)
	if err != nil {
		return State{}, err
	}
	if err := verifyEntry(root, names.temporary, temporaryInfo, "temporary state"); err != nil {
		return State{}, err
	}
	if err := verifyEntry(root, names.state, lockedInfo, "current state"); err != nil {
		return State{}, err
	}
	if err := root.Rename(names.temporary, names.state); err != nil {
		return State{}, fmt.Errorf("replace run state: %w", err)
	}
	if err := verifyEntry(root, names.state, temporaryInfo, "published state"); err != nil {
		return State{}, err
	}
	if err := syncRoot(root, operations); err != nil {
		return State{}, fmt.Errorf("sync published run state: %w", err)
	}

	if err := removeAndSync(root, names.intent, operations); err != nil {
		return updated, cleanupUncertain("intent marker", err)
	}
	return updated, nil
}

// Parse accepts only the exact canonical encoding emitted by Store. Comparing
// a validated round trip rejects duplicate keys and semantically equivalent
// alternate encodings without a second open-ended JSON representation.
func Parse(data []byte) (State, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, fmt.Errorf("%w: decode: %v", ErrCorruptState, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return State{}, fmt.Errorf("%w: trailing JSON value", ErrCorruptState)
		}
		return State{}, fmt.Errorf("%w: trailing data: %v", ErrCorruptState, err)
	}
	if err := state.Validate(); err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrCorruptState, err)
	}
	if !bytes.Equal(data, canonicalState(state)) {
		return State{}, fmt.Errorf("%w: state is not canonically encoded", ErrCorruptState)
	}
	return state, nil
}

type storeNames struct {
	state     string
	temporary string
	intent    string
}

func (s Store) open() (rootDirectory, storeNames, storeOperations, error) {
	var empty storeNames
	if s.Path == "" || !filepath.IsAbs(s.Path) || filepath.Clean(s.Path) != s.Path {
		return nil, empty, storeOperations{}, fmt.Errorf("%w: state path must be absolute and canonical", ErrUnsafePath)
	}
	parent := filepath.Dir(s.Path)
	base := filepath.Base(s.Path)
	if parent == s.Path || !isSafeRunID(base) {
		return nil, empty, storeOperations{}, fmt.Errorf("%w: state path must end in one fixed safe filename", ErrUnsafePath)
	}

	// This pathname check authenticates the directory name only. All artifact
	// operations use the single descriptor-backed Root opened immediately below.
	before, err := os.Lstat(parent)
	if err != nil {
		return nil, empty, storeOperations{}, fmt.Errorf("%w: inspect state directory: %v", ErrUnsafePath, err)
	}
	if err := validatePrivateDirectory(before); err != nil {
		return nil, empty, storeOperations{}, err
	}

	operations := defaultStoreOperations()
	if s.operations != nil {
		operations = *s.operations
	}
	if operations.openRoot == nil || operations.syncFile == nil {
		return nil, empty, storeOperations{}, fmt.Errorf("%w: incomplete store operations", ErrUnsafePath)
	}
	root, err := operations.openRoot(parent)
	if err != nil {
		return nil, empty, storeOperations{}, fmt.Errorf("open state directory root: %w", err)
	}
	directory, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, empty, storeOperations{}, fmt.Errorf("open anchored state directory: %w", err)
	}
	opened, statErr := directory.Stat()
	closeErr := directory.Close()
	if statErr != nil {
		root.Close()
		return nil, empty, storeOperations{}, fmt.Errorf("stat anchored state directory: %w", statErr)
	}
	if closeErr != nil {
		root.Close()
		return nil, empty, storeOperations{}, fmt.Errorf("close anchored state directory: %w", closeErr)
	}
	if err := validatePrivateDirectory(opened); err != nil {
		root.Close()
		return nil, empty, storeOperations{}, err
	}
	if !os.SameFile(before, opened) {
		root.Close()
		return nil, empty, storeOperations{}, fmt.Errorf("%w: state directory changed while opening", ErrUnsafePath)
	}

	names := storeNames{
		state:     base,
		temporary: base + temporarySuffix,
		intent:    base + intentSuffix,
	}
	return root, names, operations, nil
}

func validatePrivateDirectory(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: state parent is not a real directory", ErrUnsafePath)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: state directory permissions are %#o, want 0700", ErrUnsafePath, info.Mode().Perm())
	}
	return nil
}

func rejectResidue(root rootDirectory, names storeNames) error {
	if err := classifyExisting(root, names.intent, ErrUncertainState, "intent marker"); err != nil {
		return err
	}
	return classifyExisting(root, names.temporary, ErrTemporaryExists, "temporary state")
}

func rejectExistingState(root rootDirectory, name string) error {
	return classifyExisting(root, name, ErrAlreadyExists, "state")
}

func classifyExisting(root rootDirectory, name string, existsError error, kind string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", kind, err)
	}
	if err := validatePrivateRegular(info, kind); err != nil {
		return err
	}
	return existsError
}

func createIntent(root rootDirectory, name string, operations storeOperations) error {
	_, err := writeExclusive(root, name, []byte(intentContents), operations)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if classifyErr := classifyExisting(root, name, ErrUncertainState, "intent marker"); classifyErr != nil {
				return classifyErr
			}
			return ErrUncertainState
		}
		return err
	}
	if err := syncRoot(root, operations); err != nil {
		return fmt.Errorf("sync intent marker directory entry: %w", err)
	}
	return nil
}

func writeExclusive(root rootDirectory, name string, data []byte, operations storeOperations) (os.FileInfo, error) {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return nil, fmt.Errorf("write %s: %w", name, err)
	}
	if err := operations.syncFile(file); err != nil {
		file.Close()
		return nil, fmt.Errorf("sync %s: %w", name, err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat %s: %w", name, err)
	}
	if err := validatePrivateRegular(info, name); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close %s: %w", name, err)
	}
	return info, nil
}

func loadCurrent(root rootDirectory, name string) (State, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil, fmt.Errorf("%w: state file does not exist", ErrCorruptState)
		}
		return State{}, nil, fmt.Errorf("inspect run state: %w", err)
	}
	if err := validatePrivateRegular(before, "state"); err != nil {
		return State{}, nil, err
	}
	file, err := root.Open(name)
	if err != nil {
		return State{}, nil, fmt.Errorf("open run state: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return State{}, nil, fmt.Errorf("stat opened run state: %w", err)
	}
	if err := validatePrivateRegular(opened, "opened state"); err != nil {
		return State{}, nil, err
	}
	if !os.SameFile(before, opened) {
		return State{}, nil, fmt.Errorf("%w: state changed while opening", ErrUnsafePath)
	}
	if err := verifyEntry(root, name, opened, "opened state"); err != nil {
		return State{}, nil, err
	}

	data, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return State{}, nil, fmt.Errorf("read run state: %w", err)
	}
	if len(data) > maxStateBytes {
		return State{}, nil, fmt.Errorf("%w: state exceeds %d bytes", ErrCorruptState, maxStateBytes)
	}
	state, err := Parse(data)
	if err != nil {
		return State{}, nil, err
	}
	return state, opened, nil
}

func verifyEntry(root rootDirectory, name string, want os.FileInfo, kind string) error {
	current, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("verify %s: %w", kind, err)
	}
	if err := validatePrivateRegular(current, kind); err != nil {
		return err
	}
	if !os.SameFile(want, current) {
		return fmt.Errorf("%w: %s identity changed", ErrUnsafePath, kind)
	}
	return nil
}

func validatePrivateRegular(info os.FileInfo, kind string) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is a symlink or non-regular file", ErrUnsafePath, kind)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: %s permissions are %#o, want 0600", ErrUnsafePath, kind, info.Mode().Perm())
	}
	return nil
}

func syncRoot(root rootDirectory, operations storeOperations) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := operations.syncFile(directory); err != nil {
		directory.Close()
		return err
	}
	return directory.Close()
}

func removeAndSync(root rootDirectory, name string, operations storeOperations) error {
	if err := root.Remove(name); err != nil {
		return err
	}
	return syncRoot(root, operations)
}

func canonicalState(state State) []byte {
	// State contains only JSON-native scalar fields, so Marshal cannot fail.
	data, _ := json.Marshal(state)
	return append(data, '\n')
}

func cleanupUncertain(kind string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrCleanupUncertain, kind, err)
}
