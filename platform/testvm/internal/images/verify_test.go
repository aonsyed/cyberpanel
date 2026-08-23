package images

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

const testQEMUImgPath = "/opt/qemu/11.0.3/bin/qemu-img"

func TestVerifyAcceptsLockedStandaloneQCOW2AndUsesClosedCommands(t *testing.T) {
	image := testImage()
	sourcePath := writeTestImage(t, "image name;$(touch ignored).qcow2", testImageContents())
	request := newAdmitRequest(t, image, sourcePath)
	admittedPath := admittedPath(request)
	runner := successfulVerifyRunner(t, validInfoJSON(admittedPath))
	request.Runner = runner

	gotPath, err := AdmitAndVerify(context.Background(), request)
	if err != nil {
		t.Fatalf("AdmitAndVerify() error = %v", err)
	}
	if gotPath != admittedPath {
		t.Fatalf("AdmitAndVerify() path = %q, want %q", gotPath, admittedPath)
	}

	wantCalls := []runnerCall{
		{
			path:           testQEMUImgPath,
			args:           []string{"info", "--output=json", "--backing-chain", admittedPath},
			maxOutputBytes: MaxCommandOutputBytes,
		},
		{
			path:           testQEMUImgPath,
			args:           []string{"check", "--output=json", admittedPath},
			maxOutputBytes: MaxCommandOutputBytes,
		},
	}
	if len(runner.calls) != len(wantCalls) {
		t.Fatalf("Runner calls = %d, want %d", len(runner.calls), len(wantCalls))
	}
	for index := range wantCalls {
		got := runner.calls[index]
		want := wantCalls[index]
		if got.path != want.path || !slices.Equal(got.args, want.args) || got.maxOutputBytes != want.maxOutputBytes {
			t.Errorf("Runner call %d = %#v, want %#v", index, got, want)
		}
	}
	if slices.Contains(runner.calls[0].args, sourcePath) || slices.Contains(runner.calls[1].args, sourcePath) {
		t.Fatal("Runner received the caller-controlled source path")
	}
	assertFileMode(t, admittedPath, 0o400)
	assertFileMode(t, filepath.Dir(admittedPath), 0o500)
}

func TestVerifyRejectsDigestMismatchBeforeQEMUImg(t *testing.T) {
	contents := testImageContents()
	contents[88] = 1
	sourcePath := writeTestImage(t, "base.qcow2", contents)
	runner := &fakeRunner{t: t}
	request := newAdmitRequest(t, testImage(), sourcePath)
	request.Runner = runner

	_, err := AdmitAndVerify(context.Background(), request)
	assertVerifyErrorContains(t, err, "sha256")
	if len(runner.calls) != 0 {
		t.Fatalf("Runner calls = %d, want 0 after digest mismatch", len(runner.calls))
	}
	assertNoPublishedOrPartialImage(t, request)
}

func TestVerifyRejectsSymlinkAndNonRegularImagePaths(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		targetPath := writeTestImage(t, "target.qcow2", testImageContents())
		linkPath := filepath.Join(filepath.Dir(targetPath), "base.qcow2")
		if err := os.Symlink(targetPath, linkPath); err != nil {
			t.Fatalf("create image symlink: %v", err)
		}

		runner := &fakeRunner{t: t}
		request := newAdmitRequest(t, testImage(), linkPath)
		request.Runner = runner
		_, err := AdmitAndVerify(context.Background(), request)
		assertVerifyErrorContains(t, err, "regular file")
		if len(runner.calls) != 0 {
			t.Fatalf("Runner calls = %d, want 0 for symlink", len(runner.calls))
		}
	})

	t.Run("directory", func(t *testing.T) {
		runner := &fakeRunner{t: t}
		request := newAdmitRequest(t, testImage(), t.TempDir())
		request.Runner = runner
		_, err := AdmitAndVerify(context.Background(), request)
		assertVerifyErrorContains(t, err, "regular file")
		if len(runner.calls) != 0 {
			t.Fatalf("Runner calls = %d, want 0 for directory", len(runner.calls))
		}
	})
}

func TestVerifyRejectsImageLargerThanHashingBudget(t *testing.T) {
	actualPath := filepath.Join(t.TempDir(), "oversized.qcow2")
	file, err := os.Create(actualPath)
	if err != nil {
		t.Fatalf("create sparse image: %v", err)
	}
	if err := file.Truncate(MaxImageBytes + 1); err != nil {
		file.Close()
		t.Fatalf("truncate sparse image: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close sparse image: %v", err)
	}

	runner := &fakeRunner{t: t}
	request := newAdmitRequest(t, testImage(), actualPath)
	request.Runner = runner
	_, err = AdmitAndVerify(context.Background(), request)
	assertVerifyErrorContains(t, err, "size limit")
	if len(runner.calls) != 0 {
		t.Fatalf("Runner calls = %d, want 0 for oversized image", len(runner.calls))
	}
}

func TestVerifyHonorsCanceledContextBeforeReadingImage(t *testing.T) {
	actualPath := writeTestImage(t, "base.qcow2", testImageContents())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &fakeRunner{t: t}
	request := newAdmitRequest(t, testImage(), actualPath)
	request.Runner = runner

	_, err := AdmitAndVerify(ctx, request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify() error = %v, want context.Canceled", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("Runner calls = %d, want 0 after cancellation", len(runner.calls))
	}
}

func TestVerifyRejectsUnsafeQCOW2HeaderBeforeQEMUImg(t *testing.T) {
	tests := []struct {
		name     string
		contents func() []byte
		wantErr  string
	}{
		{
			name: "truncated base header",
			contents: func() []byte {
				return testImageContents()[:71]
			},
			wantErr: "truncated",
		},
		{
			name: "truncated version 3 header",
			contents: func() []byte {
				return testImageContents()[:103]
			},
			wantErr: "truncated",
		},
		{
			name: "wrong magic",
			contents: func() []byte {
				contents := testImageContents()
				binary.BigEndian.PutUint32(contents[0:4], 0)
				return contents
			},
			wantErr: "magic",
		},
		{
			name: "unsupported version",
			contents: func() []byte {
				contents := testImageContents()
				binary.BigEndian.PutUint32(contents[4:8], 1)
				return contents
			},
			wantErr: "version",
		},
		{
			name: "short v3 header length",
			contents: func() []byte {
				contents := testImageContents()
				binary.BigEndian.PutUint32(contents[100:104], 96)
				return contents
			},
			wantErr: "header length",
		},
		{
			name: "v3 header length beyond file",
			contents: func() []byte {
				contents := testImageContents()
				binary.BigEndian.PutUint32(contents[100:104], 112)
				return contents
			},
			wantErr: "header length",
		},
		{
			name: "backing file offset",
			contents: func() []byte {
				contents := testImageContents()
				binary.BigEndian.PutUint64(contents[8:16], 104)
				return contents
			},
			wantErr: "backing file",
		},
		{
			name: "backing file size",
			contents: func() []byte {
				contents := testImageContents()
				binary.BigEndian.PutUint32(contents[16:20], 8)
				return contents
			},
			wantErr: "backing file",
		},
		{
			name: "external data file incompatible feature",
			contents: func() []byte {
				contents := testImageContents()
				binary.BigEndian.PutUint64(contents[72:80], 1<<2)
				return contents
			},
			wantErr: "external data file",
		},
	}

	for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
			contents := tt.contents()
			sourcePath := writeTestImage(t, "base.qcow2", contents)
			runner := &fakeRunner{t: t}
			request := newAdmitRequest(t, testImageFor(contents), sourcePath)
			request.Runner = runner

			_, err := AdmitAndVerify(context.Background(), request)
			assertVerifyErrorContains(t, err, tt.wantErr)
			if len(runner.calls) != 0 {
				t.Fatalf("Runner calls = %d, want 0 for unsafe qcow2 header", len(runner.calls))
			}
			assertNoPublishedOrPartialImage(t, request)
		})
	}
}

func TestVerifyStrictlyRejectsMalformedInfoJSON(t *testing.T) {
	sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
	request := newAdmitRequest(t, testImage(), sourcePath)
	valid := string(validInfoJSON(admittedPath(request)))
	tests := []struct {
		name string
		info string
	}{
		{name: "truncated", info: `[{"format":"qcow2"}`},
		{name: "object instead of backing chain array", info: `{}`},
		{name: "trailing JSON value", info: valid + `{}`},
		{name: "unknown image field", info: replaceInfo(t, valid, `"filename":`, `"unexpected":true,"filename":`)},
		{name: "unknown qcow2 field", info: replaceInfo(t, valid, `"compat":"1.1"`, `"compat":"1.1","unexpected":true`)},
		{name: "string virtual size", info: replaceInfo(t, valid, `"virtual-size":10737418240`, `"virtual-size":"10737418240"`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := successfulVerifyRunner(t, []byte(tt.info))
			request := newAdmitRequest(t, testImage(), sourcePath)
			request.Runner = runner
			_, err := AdmitAndVerify(context.Background(), request)
			assertVerifyErrorContains(t, err, "info JSON")
			if len(runner.calls) != 1 {
				t.Fatalf("Runner calls = %d, want only info command", len(runner.calls))
			}
		})
	}
}

func TestVerifyAcceptsQEMU1103BlockGraphChildren(t *testing.T) {
	sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
	request := newAdmitRequest(t, testImage(), sourcePath)
	cachePath := admittedPath(request)
	info := []byte(fmt.Sprintf(`[{
		"children":[{"name":"file","info":{"children":[],"virtual-size":3,"filename":%q,"format":"file","actual-size":3,"format-specific":{"type":"file","data":{}},"dirty-flag":false}}],
		"virtual-size":10737418240,"filename":%q,"cluster-size":65536,"format":"qcow2","actual-size":3,
		"format-specific":{"type":"qcow2","data":{"compat":"1.1","compression-type":"zlib","lazy-refcounts":false,"refcount-bits":16,"corrupt":false,"extended-l2":false}},"dirty-flag":false
	}]`, cachePath, cachePath))
	runner := successfulVerifyRunner(t, info)
	request.Runner = runner

	if _, err := AdmitAndVerify(context.Background(), request); err != nil {
		t.Fatalf("AdmitAndVerify() rejected QEMU 11.0.3 block graph metadata: %v", err)
	}
}

func TestVerifyRejectsUnsafeImageInfo(t *testing.T) {
	sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
	request := newAdmitRequest(t, testImage(), sourcePath)
	valid := string(validInfoJSON(admittedPath(request)))
	record := valid[1 : len(valid)-1]
	tests := []struct {
		name    string
		info    string
		wantErr string
	}{
		{
			name:    "non qcow2 format",
			info:    replaceInfo(t, valid, `"format":"qcow2"`, `"format":"raw"`),
			wantErr: "qcow2",
		},
		{
			name:    "backing chain",
			info:    "[" + record + "," + record + "]",
			wantErr: "backing chain",
		},
		{
			name:    "backing filename",
			info:    replaceInfo(t, valid, `"filename":`, `"backing-filename":"base.raw","filename":`),
			wantErr: "backing",
		},
		{
			name:    "nested backing image",
			info:    replaceInfo(t, valid, `"filename":`, `"backing-image":`+record+`,"filename":`),
			wantErr: "backing",
		},
		{
			name:    "external data file",
			info:    replaceInfo(t, valid, `"compat":"1.1"`, `"compat":"1.1","data-file":"payload.raw"`),
			wantErr: "external data file",
		},
		{
			name:    "corrupt",
			info:    replaceInfo(t, valid, `"corrupt":false`, `"corrupt":true`),
			wantErr: "corrupt",
		},
		{
			name:    "corrupt state omitted",
			info:    replaceInfo(t, valid, `,"corrupt":false`, ``),
			wantErr: "corrupt",
		},
		{
			name:    "dirty",
			info:    replaceInfo(t, valid, `"dirty-flag":false`, `"dirty-flag":true`),
			wantErr: "dirty",
		},
		{
			name:    "dirty state omitted",
			info:    replaceInfo(t, valid, `,"dirty-flag":false`, ``),
			wantErr: "dirty",
		},
		{
			name:    "zero virtual size",
			info:    replaceInfo(t, valid, `"virtual-size":10737418240`, `"virtual-size":0`),
			wantErr: "virtual size",
		},
		{
			name: "virtual size above limit",
			info: replaceInfo(t, valid, `"virtual-size":10737418240`,
				fmt.Sprintf(`"virtual-size":%d`, MaxVirtualSizeBytes+1)),
			wantErr: "virtual size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := successfulVerifyRunner(t, []byte(tt.info))
			request := newAdmitRequest(t, testImage(), sourcePath)
			request.Runner = runner
			_, err := AdmitAndVerify(context.Background(), request)
			assertVerifyErrorContains(t, err, tt.wantErr)
			if len(runner.calls) != 1 {
				t.Fatalf("Runner calls = %d, want only info command", len(runner.calls))
			}
		})
	}
}

func TestVerifyRejectsOversizedCommandOutput(t *testing.T) {
	sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
	request := newAdmitRequest(t, testImage(), sourcePath)
	tests := []struct {
		name   string
		runner *fakeRunner
	}{
		{
			name: "info output",
			runner: &fakeRunner{
				t: t,
				results: []CommandResult{
					{Stdout: bytes.Repeat([]byte("x"), int(MaxCommandOutputBytes)+1)},
				},
			},
		},
		{
			name: "check output",
				runner: &fakeRunner{
					t: t,
					results: []CommandResult{
						{Stdout: validInfoJSON(admittedPath(request))},
					{Stderr: bytes.Repeat([]byte("x"), int(MaxCommandOutputBytes)+1)},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.runner.t = t
			request := newAdmitRequest(t, testImage(), sourcePath)
			request.Runner = tt.runner
			_, err := AdmitAndVerify(context.Background(), request)
			assertVerifyErrorContains(t, err, "output limit")
		})
	}
}

func TestVerifyRejectsNonzeroQEMUImgCheck(t *testing.T) {
	sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
	request := newAdmitRequest(t, testImage(), sourcePath)
	runner := &fakeRunner{
		t: t,
		results: []CommandResult{
			{Stdout: validInfoJSON(admittedPath(request))},
			{Stdout: []byte(`{"filename":"base.qcow2","format":"qcow2","check-errors":0,"corruptions":1}`), ExitCode: 2},
		},
	}
	request.Runner = runner

	_, err := AdmitAndVerify(context.Background(), request)
	assertVerifyErrorContains(t, err, "check exited with status 2")
}

func TestAdmitAndVerifySourcePathSwapCannotAffectInspectedBytes(t *testing.T) {
	contents := testImageContents()
	sourcePath := writeTestImage(t, "base.qcow2", contents)
	request := newAdmitRequest(t, testImage(), sourcePath)
	cachePath := admittedPath(request)
	runner := successfulVerifyRunner(t, validInfoJSON(cachePath))
	runner.beforeRun = func(call int) {
		if call != 0 {
			return
		}
		oldPath := sourcePath + ".admitted"
		if err := os.Rename(sourcePath, oldPath); err != nil {
			t.Fatalf("move admitted source: %v", err)
		}
		malicious := slices.Clone(contents)
		binary.BigEndian.PutUint64(malicious[8:16], 104)
		if err := os.WriteFile(sourcePath, malicious, 0o600); err != nil {
			t.Fatalf("replace caller source path: %v", err)
		}
	}
	request.Runner = runner

	gotPath, err := AdmitAndVerify(context.Background(), request)
	if err != nil {
		t.Fatalf("AdmitAndVerify() error after source path swap = %v", err)
	}
	if gotPath != cachePath {
		t.Fatalf("AdmitAndVerify() path = %q, want admitted path %q", gotPath, cachePath)
	}
	gotContents, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read admitted image: %v", err)
	}
	if !bytes.Equal(gotContents, contents) {
		t.Fatal("admitted image bytes changed after caller source path swap")
	}
	for _, call := range runner.calls {
		if slices.Contains(call.args, sourcePath) {
			t.Fatal("Runner received swapped caller source path")
		}
	}
}

func TestAdmitAndVerifyRejectsAdmittedBytesChangedWhileQEMUImgRuns(t *testing.T) {
	sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
	request := newAdmitRequest(t, testImage(), sourcePath)
	cachePath := admittedPath(request)
	runner := &fakeRunner{
		t:       t,
		results: []CommandResult{{Stdout: validInfoJSON(cachePath)}},
		beforeRun: func(call int) {
			if call != 0 {
				return
			}
			if err := os.Chmod(cachePath, 0o600); err != nil {
				t.Fatalf("make admitted image writable: %v", err)
			}
			if err := os.WriteFile(cachePath, append(testImageContents(), 0), 0o600); err != nil {
				t.Fatalf("change admitted image during verification: %v", err)
			}
		},
	}
	request.Runner = runner

	_, err := AdmitAndVerify(context.Background(), request)
	assertVerifyErrorContains(t, err, "changed during verification")
	var changed *ImageChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("Verify() error type = %T, want *ImageChangedError", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("Runner calls = %d, want no check after image mutation", len(runner.calls))
	}
}

func TestAdmitAndVerifyRehashRejectsSameLengthAdmittedMutationWithRestoredMtime(t *testing.T) {
	contents := testImageContents()
	sourcePath := writeTestImage(t, "base.qcow2", contents)
	request := newAdmitRequest(t, testImage(), sourcePath)
	cachePath := admittedPath(request)
	runner := successfulVerifyRunner(t, validInfoJSON(cachePath))
	runner.beforeRun = func(call int) {
		if call != 1 {
			return
		}
		initialInfo, err := os.Stat(cachePath)
		if err != nil {
			t.Fatalf("stat admitted image: %v", err)
		}
		mutated := slices.Clone(contents)
		mutated[88] = 1
		if err := os.Chmod(cachePath, 0o600); err != nil {
			t.Fatalf("make admitted image writable: %v", err)
		}
		if err := os.WriteFile(cachePath, mutated, 0o600); err != nil {
			t.Fatalf("mutate admitted image with same length: %v", err)
		}
		if err := os.Chtimes(cachePath, initialInfo.ModTime(), initialInfo.ModTime()); err != nil {
			t.Fatalf("restore admitted image mtime: %v", err)
		}
		if err := os.Chmod(cachePath, 0o400); err != nil {
			t.Fatalf("restore admitted image mode: %v", err)
		}
	}
	request.Runner = runner

	_, err := AdmitAndVerify(context.Background(), request)
	var changed *ImageChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("Verify() error = %v (type %T), want *ImageChangedError", err, err)
	}
	assertVerifyErrorContains(t, err, "sha256")
	if len(runner.calls) != 2 {
		t.Fatalf("Runner calls = %d, want both qemu-img commands before post-command rehash", len(runner.calls))
	}
}

func TestVerifyPropagatesRunnerCancellation(t *testing.T) {
	sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
	ctx, cancel := context.WithCancel(context.Background())
	runner := &fakeRunner{
		t: t,
		run: func(ctx context.Context, _ string, _ []string, _ int64) (CommandResult, error) {
			cancel()
			return CommandResult{}, ctx.Err()
		},
	}
	request := newAdmitRequest(t, testImage(), sourcePath)
	request.Runner = runner

	_, err := AdmitAndVerify(ctx, request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify() error = %v, want context.Canceled", err)
	}
}

func TestAdmitAndVerifyUsesValidPreexistingObjectWithoutSource(t *testing.T) {
	image := testImage()
	request := newAdmitRequest(t, image, filepath.Join(t.TempDir(), "missing-source.qcow2"))
	cachePath := installPreexistingImage(t, request, testImageContents(), 0o400)
	runner := successfulVerifyRunner(t, validInfoJSON(cachePath))
	request.Runner = runner

	gotPath, err := AdmitAndVerify(context.Background(), request)
	if err != nil {
		t.Fatalf("AdmitAndVerify() preexisting object error = %v", err)
	}
	if gotPath != cachePath {
		t.Fatalf("AdmitAndVerify() path = %q, want %q", gotPath, cachePath)
	}
}

func TestAdmitAndVerifyRejectsUnprotectedCacheState(t *testing.T) {
	t.Run("cache root mode", func(t *testing.T) {
		sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
		request := newAdmitRequest(t, testImage(), sourcePath)
		if err := os.Chmod(request.CacheRoot, 0o755); err != nil {
			t.Fatalf("make cache root unprotected: %v", err)
		}
		request.Runner = &fakeRunner{t: t}

		_, err := AdmitAndVerify(context.Background(), request)
		assertVerifyErrorContains(t, err, "0700")
	})

	t.Run("intermediate symlink", func(t *testing.T) {
		sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
		request := newAdmitRequest(t, testImage(), sourcePath)
		target := t.TempDir()
		if err := os.Symlink(target, filepath.Join(request.CacheRoot, ".work")); err != nil {
			t.Fatalf("create intermediate cache symlink: %v", err)
		}
		request.Runner = &fakeRunner{t: t}

		_, err := AdmitAndVerify(context.Background(), request)
		assertVerifyErrorContains(t, err, "directory")
	})

	t.Run("final symlink", func(t *testing.T) {
		sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
		request := newAdmitRequest(t, testImage(), sourcePath)
		cachePath := admittedPath(request)
		if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
			t.Fatalf("create cache directories: %v", err)
		}
		if err := os.Symlink(sourcePath, cachePath); err != nil {
			t.Fatalf("create final cache symlink: %v", err)
		}
		if err := os.Chmod(filepath.Dir(cachePath), 0o500); err != nil {
			t.Fatalf("protect digest directory: %v", err)
		}
		request.Runner = &fakeRunner{t: t}

		_, err := AdmitAndVerify(context.Background(), request)
		assertVerifyErrorContains(t, err, "regular file")
	})

	t.Run("writable final", func(t *testing.T) {
		sourcePath := writeTestImage(t, "base.qcow2", testImageContents())
		request := newAdmitRequest(t, testImage(), sourcePath)
		installPreexistingImage(t, request, testImageContents(), 0o600)
		request.Runner = &fakeRunner{t: t}

		_, err := AdmitAndVerify(context.Background(), request)
		assertVerifyErrorContains(t, err, "0400")
	})
}

func TestProtectedCacheOwnershipRejectsDifferentUID(t *testing.T) {
	rootInfo, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat fixture directory: %v", err)
	}
	otherUID := uint32(os.Geteuid() + 1)
	info := fileInfoWithSys{FileInfo: rootInfo, sys: &syscall.Stat_t{Uid: otherUID}}

	err = requireProtectedOwner("cache root", info)
	assertVerifyErrorContains(t, err, "current uid")
}

func TestAdmitAndVerifyCollisionNeverOverwritesExistingFinal(t *testing.T) {
	sourceContents := testImageContents()
	request := newAdmitRequest(t, testImage(), writeTestImage(t, "base.qcow2", sourceContents))
	collision := slices.Clone(sourceContents)
	collision[88] = 1
	cachePath := installPreexistingImage(t, request, collision, 0o400)
	request.Runner = &fakeRunner{t: t}

	_, err := AdmitAndVerify(context.Background(), request)
	assertVerifyErrorContains(t, err, "sha256")
	got, readErr := os.ReadFile(cachePath)
	if readErr != nil {
		t.Fatalf("read collision object: %v", readErr)
	}
	if !bytes.Equal(got, collision) {
		t.Fatal("preexisting collision object was overwritten")
	}
	if len(request.Runner.(*fakeRunner).calls) != 0 {
		t.Fatal("Runner called for invalid preexisting collision")
	}
}

func testImage() Image {
	return testImageFor(testImageContents())
}

func testImageFor(contents []byte) Image {
	digestBytes := sha256.Sum256(contents)
	digest := hex.EncodeToString(digestBytes[:])
	return Image{
		StableID:        "test-1.0-arm64",
		Distribution:    "test",
		ResolvedRelease: "1.0-20260812",
		Architecture:    ArchitectureARM64,
		AcquisitionURL:  "https://images.example/test-1.0-arm64.qcow2",
		RuntimePath:     runtimePathPrefix + digest + "/" + runtimeImageName,
		SHA256:          digest,
		Format:          FormatQCOW2,
	}
}

func testImageContents() []byte {
	contents := make([]byte, 104)
	binary.BigEndian.PutUint32(contents[0:4], 0x514649fb)
	binary.BigEndian.PutUint32(contents[4:8], 3)
	binary.BigEndian.PutUint32(contents[20:24], 16)
	binary.BigEndian.PutUint64(contents[24:32], 10<<30)
	binary.BigEndian.PutUint32(contents[96:100], 4)
	binary.BigEndian.PutUint32(contents[100:104], uint32(len(contents)))
	return contents
}

func validInfoJSON(actualPath string) []byte {
	return []byte(fmt.Sprintf(`[{"filename":%q,"format":"qcow2","virtual-size":10737418240,"actual-size":3,"cluster-size":65536,"dirty-flag":false,"encrypted":false,"compressed":false,"format-specific":{"type":"qcow2","data":{"compat":"1.1","lazy-refcounts":false,"refcount-bits":16,"corrupt":false,"extended-l2":false,"compression-type":"zlib"}}}]`, actualPath))
}

func successfulVerifyRunner(t *testing.T, info []byte) *fakeRunner {
	return &fakeRunner{
		t: t,
		results: []CommandResult{
			{Stdout: info},
			{Stdout: []byte(`{"filename":"base.qcow2","format":"qcow2","check-errors":0}`)},
		},
	}
}

func newAdmitRequest(t *testing.T, image Image, sourcePath string) AdmitRequest {
	t.Helper()

	cacheRoot := t.TempDir()
	if err := os.Chmod(cacheRoot, 0o700); err != nil {
		t.Fatalf("protect cache root: %v", err)
	}
	return AdmitRequest{
		Image:       image,
		SourcePath:  sourcePath,
		CacheRoot:   cacheRoot,
		QEMUImgPath: testQEMUImgPath,
	}
}

func admittedPath(request AdmitRequest) string {
	return filepath.Join(request.CacheRoot, filepath.FromSlash(request.Image.RuntimePath))
}

func installPreexistingImage(t *testing.T, request AdmitRequest, contents []byte, mode os.FileMode) string {
	t.Helper()

	path := admittedPath(request)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create preexisting cache directories: %v", err)
	}
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("write preexisting cache image: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("set preexisting image mode: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o500); err != nil {
		t.Fatalf("protect preexisting digest directory: %v", err)
	}
	return path
}

func assertNoPublishedOrPartialImage(t *testing.T, request AdmitRequest) {
	t.Helper()

	path := admittedPath(request)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published image state after failed admission: %v", err)
	}
	digestDir := filepath.Dir(path)
	entries, err := os.ReadDir(digestDir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatalf("read failed-admission digest directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed admission left %d partial entries", len(entries))
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %q: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%q) = %#o, want %#o", path, got, want)
	}
}

type fileInfoWithSys struct {
	os.FileInfo
	sys any
}

func (info fileInfoWithSys) Sys() any {
	return info.sys
}

func writeTestImage(t *testing.T, name string, contents []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write test image: %v", err)
	}
	return path
}

func replaceInfo(t *testing.T, input, old, replacement string) string {
	t.Helper()

	if !strings.Contains(input, old) {
		t.Fatalf("info fixture does not contain %q", old)
	}
	return strings.Replace(input, old, replacement, 1)
}

func assertVerifyErrorContains(t *testing.T, err error, want string) {
	t.Helper()

	if err == nil {
		t.Fatalf("Verify() error = nil, want substring %q", want)
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
		t.Fatalf("Verify() error = %q, want substring %q", err, want)
	}
}

type runnerCall struct {
	path           string
	args           []string
	maxOutputBytes int64
}

type fakeRunner struct {
	t         *testing.T
	results   []CommandResult
	errors    []error
	calls     []runnerCall
	beforeRun func(call int)
	run       func(context.Context, string, []string, int64) (CommandResult, error)
}

func (runner *fakeRunner) Run(
	ctx context.Context,
	path string,
	args []string,
	maxOutputBytes int64,
) (CommandResult, error) {
	if runner.t == nil {
		panic("fakeRunner requires a test")
	}

	call := len(runner.calls)
	runner.calls = append(runner.calls, runnerCall{
		path:           path,
		args:           slices.Clone(args),
		maxOutputBytes: maxOutputBytes,
	})
	if runner.beforeRun != nil {
		runner.beforeRun(call)
	}
	if runner.run != nil {
		return runner.run(ctx, path, args, maxOutputBytes)
	}
	if call >= len(runner.results) {
		runner.t.Fatalf("unexpected Runner call %d: %s %#v", call, path, args)
	}

	var err error
	if call < len(runner.errors) {
		err = runner.errors[call]
	}
	return runner.results[call], err
}
