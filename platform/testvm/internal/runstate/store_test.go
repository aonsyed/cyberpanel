package runstate

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStoreCreateLoadRoundTripIsCanonicalAndPrivate(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "state.json")
	store := Store{Path: path}

	created, err := store.Create("run-20260812-arm64")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(loaded, created) {
		t.Fatalf("Load() = %#v, want %#v", loaded, created)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	wantJSON := "{\"schemaVersion\":1,\"runId\":\"run-20260812-arm64\",\"phase\":\"NEW\",\"revision\":1}\n"
	if string(data) != wantJSON {
		t.Fatalf("state JSON = %q, want %q", data, wantJSON)
	}
	assertPrivateRegularFile(t, path)
	if _, err := os.Lstat(path + temporarySuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary file after Create() error = %v, want not exist", err)
	}
}

func TestStoreTransitionPersistsRevisionAndFailureMetadata(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "state.json")
	store := Store{Path: path}
	state, err := store.Create("failure-run")
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}

	state, err = store.Transition(state.Revision, PhaseDoctored, nil)
	if err != nil {
		t.Fatalf("Transition(DOCTORED): %v", err)
	}
	state, err = store.Transition(state.Revision, PhaseFailed, &Failure{
		Class:       FailureClassInfraFailed,
		FailedPhase: PhaseDoctored,
		Reason:      "image-doctor-unavailable",
	})
	if err != nil {
		t.Fatalf("Transition(FAILED): %v", err)
	}
	state, err = store.Transition(state.Revision, PhaseFailedRetained, nil)
	if err != nil {
		t.Fatalf("Transition(FAILED_RETAINED): %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Fatalf("Load() = %#v, want %#v", loaded, state)
	}
	if loaded.Revision != 4 {
		t.Fatalf("Revision = %d, want 4", loaded.Revision)
	}
	wantJSON := "{\"schemaVersion\":1,\"runId\":\"failure-run\",\"phase\":\"FAILED_RETAINED\",\"revision\":4,\"failureClass\":\"INFRA_FAILED\",\"failedPhase\":\"DOCTORED\",\"reason\":\"image-doctor-unavailable\"}\n"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	if string(data) != wantJSON {
		t.Fatalf("state JSON = %q, want %q", data, wantJSON)
	}
	assertPrivateRegularFile(t, path)
}

func TestStoreTransitionRejectsStaleRevisionWithoutChangingState(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "state.json")
	store := Store{Path: path}
	state, err := store.Create("cas-run")
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}
	state, err = store.Transition(state.Revision, PhaseDoctored, nil)
	if err != nil {
		t.Fatalf("Transition(DOCTORED): %v", err)
	}

	_, err = store.Transition(1, PhaseImageVerified, nil)
	if !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale Transition() error = %v, want ErrStaleRevision", err)
	}
	var conflict *RevisionConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("stale Transition() error type = %T, want *RevisionConflictError", err)
	}
	if conflict.Expected != 1 || conflict.Actual != 2 {
		t.Fatalf("revision conflict = %#v, want expected 1 actual 2", conflict)
	}

	loaded, loadErr := store.Load()
	if loadErr != nil {
		t.Fatalf("Load(): %v", loadErr)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Fatalf("state changed after stale transition: got %#v, want %#v", loaded, state)
	}
	if _, statErr := os.Lstat(path + temporarySuffix); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("temporary file after stale transition error = %v, want not exist", statErr)
	}
}

func TestStoreRejectsPreexistingCrashTemporaryFile(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "state.json")
	store := Store{Path: path}
	created, err := store.Create("crash-run")
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}

	tempPath := path + temporarySuffix
	const residue = "incomplete-crash-write"
	if err := os.WriteFile(tempPath, []byte(residue), 0o600); err != nil {
		t.Fatalf("WriteFile(temp): %v", err)
	}

	if _, err := store.Load(); !errors.Is(err, ErrTemporaryExists) {
		t.Fatalf("Load() with crash residue error = %v, want ErrTemporaryExists", err)
	}
	if _, err := store.Transition(created.Revision, PhaseDoctored, nil); !errors.Is(err, ErrTemporaryExists) {
		t.Fatalf("Transition() with crash residue error = %v, want ErrTemporaryExists", err)
	}
	if _, err := store.Create("crash-run"); !errors.Is(err, ErrTemporaryExists) {
		t.Fatalf("Create() with crash residue error = %v, want ErrTemporaryExists", err)
	}

	data, err := os.ReadFile(tempPath)
	if err != nil {
		t.Fatalf("ReadFile(temp): %v", err)
	}
	if string(data) != residue {
		t.Fatalf("crash residue = %q, want %q", data, residue)
	}
	stateData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(state): %v", err)
	}
	if !strings.Contains(string(stateData), `"phase":"NEW"`) {
		t.Fatalf("state changed despite crash residue: %s", stateData)
	}
}

func TestStoreNeverReusesACompletedOrFailedRunState(t *testing.T) {
	for _, terminal := range []Phase{PhaseComplete, PhaseFailedCleaned} {
		t.Run(string(terminal), func(t *testing.T) {
			path := filepath.Join(privateTempDir(t), "state.json")
			store := Store{Path: path}
			state, err := store.Create("immutable-run-id")
			if err != nil {
				t.Fatalf("Create(): %v", err)
			}

			if terminal == PhaseComplete {
				for _, next := range successfulPhases()[1:] {
					state, err = store.Transition(state.Revision, next, nil)
					if err != nil {
						t.Fatalf("Transition(%s): %v", next, err)
					}
				}
			} else {
				state, err = store.Transition(state.Revision, PhaseFailed, &Failure{
					Class:       FailureClassInfraFailed,
					FailedPhase: PhaseNew,
					Reason:      "preparation-failed",
				})
				if err != nil {
					t.Fatalf("Transition(FAILED): %v", err)
				}
				state, err = store.Transition(state.Revision, PhaseFailedCleaned, nil)
				if err != nil {
					t.Fatalf("Transition(FAILED_CLEANED): %v", err)
				}
			}

			if _, err := store.Create("immutable-run-id"); !errors.Is(err, ErrAlreadyExists) {
				t.Fatalf("Create() reused %s run error = %v, want ErrAlreadyExists", terminal, err)
			}
			loaded, err := store.Load()
			if err != nil {
				t.Fatalf("Load(): %v", err)
			}
			if !reflect.DeepEqual(loaded, state) {
				t.Fatalf("terminal state changed: got %#v, want %#v", loaded, state)
			}
		})
	}
}

func TestStoreRejectsCorruptAndUnknownJSON(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"truncated", `{"schemaVersion":1`},
		{"unknown field", `{"schemaVersion":1,"runId":"run","phase":"NEW","revision":1,"extra":true}`},
		{"trailing value", `{"schemaVersion":1,"runId":"run","phase":"NEW","revision":1} {}`},
		{"unknown phase", `{"schemaVersion":1,"runId":"run","phase":"MAYBE","revision":1}`},
		{"zero revision", `{"schemaVersion":1,"runId":"run","phase":"NEW","revision":0}`},
		{"incomplete failure", `{"schemaVersion":1,"runId":"run","phase":"FAILED","revision":2,"failureClass":"INFRA_FAILED","failedPhase":"NEW"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(privateTempDir(t), "state.json")
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatalf("WriteFile(): %v", err)
			}
			_, err := (Store{Path: path}).Load()
			if !errors.Is(err, ErrCorruptState) {
				t.Fatalf("Load() error = %v, want ErrCorruptState", err)
			}
		})
	}
}

func TestParseRejectsEveryNoncanonicalEncoding(t *testing.T) {
	canonical := "{\"schemaVersion\":1,\"runId\":\"run\",\"phase\":\"NEW\",\"revision\":1}\n"
	if _, err := Parse([]byte(canonical)); err != nil {
		t.Fatalf("Parse(canonical) error = %v", err)
	}

	tests := []struct {
		name string
		data string
	}{
		{
			name: "duplicate phase",
			data: "{\"schemaVersion\":1,\"runId\":\"run\",\"phase\":\"NEW\",\"phase\":\"NEW\",\"revision\":1}\n",
		},
		{
			name: "reordered fields",
			data: "{\"runId\":\"run\",\"schemaVersion\":1,\"phase\":\"NEW\",\"revision\":1}\n",
		},
		{
			name: "insignificant whitespace",
			data: "{ \"schemaVersion\": 1, \"runId\": \"run\", \"phase\": \"NEW\", \"revision\": 1 }\n",
		},
		{
			name: "escaped equivalent run ID",
			data: "{\"schemaVersion\":1,\"runId\":\"r\\u0075n\",\"phase\":\"NEW\",\"revision\":1}\n",
		},
		{
			name: "explicit empty failure fields",
			data: "{\"schemaVersion\":1,\"runId\":\"run\",\"phase\":\"NEW\",\"revision\":1,\"failureClass\":\"\",\"failedPhase\":\"\",\"reason\":\"\"}\n",
		},
		{
			name: "missing final newline",
			data: "{\"schemaVersion\":1,\"runId\":\"run\",\"phase\":\"NEW\",\"revision\":1}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.data))
			if !errors.Is(err, ErrCorruptState) {
				t.Fatalf("Parse() error = %v, want ErrCorruptState", err)
			}
		})
	}
}

func TestStoreRejectsSymlinksNonregularFilesAndWrongPermissions(t *testing.T) {
	t.Run("state symlink", func(t *testing.T) {
		dir := privateTempDir(t)
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte("do-not-follow"), 0o600); err != nil {
			t.Fatalf("WriteFile(target): %v", err)
		}
		path := filepath.Join(dir, "state.json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("Symlink(): %v", err)
		}
		if _, err := (Store{Path: path}).Load(); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Load(symlink) error = %v, want ErrUnsafePath", err)
		}
	})

	t.Run("state directory", func(t *testing.T) {
		path := filepath.Join(privateTempDir(t), "state.json")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(): %v", err)
		}
		if _, err := (Store{Path: path}).Load(); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Load(directory) error = %v, want ErrUnsafePath", err)
		}
	})

	t.Run("temporary symlink", func(t *testing.T) {
		dir := privateTempDir(t)
		path := filepath.Join(dir, "state.json")
		store := Store{Path: path}
		state, err := store.Create("run")
		if err != nil {
			t.Fatalf("Create(): %v", err)
		}
		if err := os.Symlink(path, path+temporarySuffix); err != nil {
			t.Fatalf("Symlink(temp): %v", err)
		}
		if _, err := store.Transition(state.Revision, PhaseDoctored, nil); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Transition(temp symlink) error = %v, want ErrUnsafePath", err)
		}
	})

	t.Run("world readable state", func(t *testing.T) {
		path := filepath.Join(privateTempDir(t), "state.json")
		store := Store{Path: path}
		if _, err := store.Create("run"); err != nil {
			t.Fatalf("Create(): %v", err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("Chmod(): %v", err)
		}
		if _, err := store.Load(); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Load(0644) error = %v, want ErrUnsafePath", err)
		}
	})

	t.Run("non-private parent", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatalf("Chmod(parent): %v", err)
		}
		path := filepath.Join(dir, "state.json")
		if _, err := (Store{Path: path}).Create("run"); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Create(non-private parent) error = %v, want ErrUnsafePath", err)
		}
	})
}

func TestStoreRootRemainsAnchoredWhenParentPathIsReplaced(t *testing.T) {
	outer := t.TempDir()
	live := filepath.Join(outer, "live")
	anchored := filepath.Join(outer, "anchored")
	if err := os.Mkdir(live, 0o700); err != nil {
		t.Fatalf("Mkdir(live): %v", err)
	}

	operations := defaultStoreOperations()
	openRoot := operations.openRoot
	operations.openRoot = func(path string) (rootDirectory, error) {
		root, err := openRoot(path)
		if err != nil {
			return nil, err
		}
		if err := os.Rename(live, anchored); err != nil {
			root.Close()
			return nil, err
		}
		if err := os.Mkdir(live, 0o700); err != nil {
			root.Close()
			return nil, err
		}
		return root, nil
	}

	store := Store{Path: filepath.Join(live, "state.json"), operations: &operations}
	if _, err := store.Create("anchored-run"); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(live, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement parent state error = %v, want not exist", err)
	}
	data, err := os.ReadFile(filepath.Join(anchored, "state.json"))
	if err != nil {
		t.Fatalf("ReadFile(anchored state): %v", err)
	}
	if !strings.Contains(string(data), `"runId":"anchored-run"`) {
		t.Fatalf("anchored state = %q", data)
	}
}

func TestStoreCreateCannotOverwriteEntryAppearingAtPublication(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "state.json")
	operations := defaultStoreOperations()
	openRoot := operations.openRoot
	const adversarial = "adversarial-existing-state"
	operations.openRoot = func(path string) (rootDirectory, error) {
		root, err := openRoot(path)
		if err != nil {
			return nil, err
		}
		return &hookRoot{
			rootDirectory: root,
			beforeLink: func(oldname, newname string) {
				file, createErr := root.OpenFile(newname, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if createErr != nil {
					t.Fatalf("adversarial create: %v", createErr)
				}
				if _, writeErr := file.Write([]byte(adversarial)); writeErr != nil {
					t.Fatalf("adversarial write: %v", writeErr)
				}
				if closeErr := file.Close(); closeErr != nil {
					t.Fatalf("adversarial close: %v", closeErr)
				}
			},
		}, nil
	}

	store := Store{Path: path, operations: &operations}
	if _, err := store.Create("must-not-overwrite"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Create() error = %v, want ErrAlreadyExists", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(adversarial state): %v", err)
	}
	if string(data) != adversarial {
		t.Fatalf("existing state = %q, want %q", data, adversarial)
	}
	if _, err := os.Lstat(path + intentSuffix); err != nil {
		t.Fatalf("intent marker missing after uncertain publication: %v", err)
	}
}

func TestStoreLoadRejectsEntryReplacedBySymlinkDuringOpen(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "state.json")
	store := Store{Path: path}
	if _, err := store.Create("original-run"); err != nil {
		t.Fatalf("Create(): %v", err)
	}
	target := filepath.Join(dir, "other.json")
	if err := os.WriteFile(target, []byte("{\"schemaVersion\":1,\"runId\":\"followed-run\",\"phase\":\"NEW\",\"revision\":1}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(target): %v", err)
	}

	operations := defaultStoreOperations()
	openRoot := operations.openRoot
	operations.openRoot = func(path string) (rootDirectory, error) {
		root, err := openRoot(path)
		if err != nil {
			return nil, err
		}
		return &hookRoot{
			rootDirectory: root,
			beforeOpen: func(name string) {
				if name != "state.json" {
					return
				}
				if removeErr := root.Remove(name); removeErr != nil {
					t.Fatalf("adversarial remove: %v", removeErr)
				}
				if symlinkErr := root.Symlink("other.json", name); symlinkErr != nil {
					t.Fatalf("adversarial symlink: %v", symlinkErr)
				}
			},
		}, nil
	}

	store.operations = &operations
	loaded, err := store.Load()
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Load() error = %v, want ErrUnsafePath", err)
	}
	if loaded != (State{}) {
		t.Fatalf("Load() followed replacement and returned %#v", loaded)
	}
}

func TestStoreTransitionDoesNotOverwriteAReplacedFinalEntry(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "state.json")
	store := Store{Path: path}
	state, err := store.Create("transition-race")
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}

	operations := defaultStoreOperations()
	openRoot := operations.openRoot
	const adversarial = "replacement-before-publication"
	operations.openRoot = func(path string) (rootDirectory, error) {
		root, openErr := openRoot(path)
		if openErr != nil {
			return nil, openErr
		}
		stateLstats := 0
		return &hookRoot{
			rootDirectory: root,
			beforeLstat: func(name string) {
				if name != "state.json" {
					return
				}
				stateLstats++
				// Two checked reads bracket the intent acquisition. The fifth
				// state lookup is the final identity check before Rename.
				if stateLstats != 5 {
					return
				}
				if removeErr := root.Remove(name); removeErr != nil {
					t.Fatalf("adversarial remove: %v", removeErr)
				}
				file, createErr := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if createErr != nil {
					t.Fatalf("adversarial create: %v", createErr)
				}
				if _, writeErr := file.Write([]byte(adversarial)); writeErr != nil {
					t.Fatalf("adversarial write: %v", writeErr)
				}
				if closeErr := file.Close(); closeErr != nil {
					t.Fatalf("adversarial close: %v", closeErr)
				}
			},
		}, nil
	}

	store.operations = &operations
	if _, err := store.Transition(state.Revision, PhaseDoctored, nil); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Transition() error = %v, want ErrUnsafePath", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(replacement): %v", err)
	}
	if string(data) != adversarial {
		t.Fatalf("replacement was overwritten: got %q, want %q", data, adversarial)
	}
	if _, err := os.Lstat(path + intentSuffix); err != nil {
		t.Fatalf("intent marker missing after replacement: %v", err)
	}
}

func TestStoreLeavesDurableIntentOnPrecommitSyncFailure(t *testing.T) {
	tests := []struct {
		name     string
		failSync int
	}{
		{name: "intent file", failSync: 1},
		{name: "intent directory entry", failSync: 2},
		{name: "state temporary file", failSync: 3},
		{name: "state publication", failSync: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := privateTempDir(t)
			path := filepath.Join(dir, "state.json")
			operations := defaultStoreOperations()
			calls := 0
			operations.syncFile = func(file *os.File) error {
				calls++
				if calls == tt.failSync {
					return errors.New("injected sync failure")
				}
				return file.Sync()
			}
			store := Store{Path: path, operations: &operations}

			if _, err := store.Create("sync-failure-run"); err == nil {
				t.Fatal("Create() error = nil, want injected failure")
			}
			assertPrivateRegularFile(t, path+intentSuffix)
			if _, err := store.Load(); !errors.Is(err, ErrUncertainState) {
				t.Fatalf("Load() after sync failure error = %v, want ErrUncertainState", err)
			}
		})
	}
}

func TestStoreReportsCleanupSyncFailureAfterStateIsDurable(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "state.json")
	operations := defaultStoreOperations()
	calls := 0
	operations.syncFile = func(file *os.File) error {
		calls++
		// Create sync order: intent, directory, temporary state,
		// publication directory, temporary cleanup directory, intent cleanup directory.
		if calls == 6 {
			return errors.New("injected final cleanup sync failure")
		}
		return file.Sync()
	}
	store := Store{Path: path, operations: &operations}

	state, err := store.Create("durable-despite-cleanup")
	if !errors.Is(err, ErrCleanupUncertain) {
		t.Fatalf("Create() error = %v, want ErrCleanupUncertain", err)
	}
	if state.RunID != "durable-despite-cleanup" {
		t.Fatalf("Create() state = %#v, want committed state", state)
	}
	loaded, loadErr := (Store{Path: path}).Load()
	if loadErr != nil {
		t.Fatalf("Load() committed state: %v", loadErr)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Fatalf("Load() = %#v, want %#v", loaded, state)
	}
}

func TestStoreCreateRejectsAnExistingRegularStateWithoutOverwritingIt(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "state.json")
	const existing = "historical-terminal-state"
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}

	_, err := (Store{Path: path}).Create("same-run-id")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Create() error = %v, want ErrAlreadyExists", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile(): %v", readErr)
	}
	if string(data) != existing {
		t.Fatalf("existing state overwritten: got %q, want %q", data, existing)
	}
}

func assertPrivateRegularFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", path, err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%q mode = %v, want regular", path, info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("%q permissions = %#o, want 0600", path, got)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir(private store directory): %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod(private store directory): %v", err)
	}
	return dir
}

type hookRoot struct {
	rootDirectory
	beforeLink  func(oldname, newname string)
	beforeOpen  func(name string)
	beforeLstat func(name string)
}

func (r *hookRoot) Link(oldname, newname string) error {
	if r.beforeLink != nil {
		hook := r.beforeLink
		r.beforeLink = nil
		hook(oldname, newname)
	}
	return r.rootDirectory.Link(oldname, newname)
}

func (r *hookRoot) Open(name string) (*os.File, error) {
	if r.beforeOpen != nil && name != "." {
		hook := r.beforeOpen
		r.beforeOpen = nil
		hook(name)
	}
	return r.rootDirectory.Open(name)
}

func (r *hookRoot) Lstat(name string) (os.FileInfo, error) {
	if r.beforeLstat != nil {
		r.beforeLstat(name)
	}
	return r.rootDirectory.Lstat(name)
}
