package images

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// MaxImageBytes bounds work spent hashing one acquired base image.
	MaxImageBytes int64 = 16 << 30
	// MaxVirtualSizeBytes bounds the guest-visible capacity accepted from qcow2 metadata.
	MaxVirtualSizeBytes int64 = 1 << 40
	// MaxCommandOutputBytes bounds stdout and stderr retained for each qemu-img command.
	MaxCommandOutputBytes int64 = 64 << 10

	qcow2Magic                               uint32 = 0x514649fb
	qcow2Version2HeaderBytes                        = 72
	qcow2Version3HeaderBytes                        = 104
	maxQCOW2HeaderBytes                      uint32 = 1 << 20
	qcow2IncompatibleExternalDataFileFeature uint64 = 1 << 2
)

// ImageChangedError reports that the path, inode, size, timestamp, or bytes
// changed after verification began.
type ImageChangedError struct {
	Path    string
	Problem string
	Err     error
}

func (e *ImageChangedError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("image %q changed during verification: %s: %v", e.Path, e.Problem, e.Err)
	}
	return fmt.Sprintf("image %q changed during verification: %s", e.Path, e.Problem)
}

func (e *ImageChangedError) Unwrap() error {
	return e.Err
}

// CommandResult is the bounded result of one directly executed process.
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner directly executes path with args and retains at most maxOutputBytes
// bytes across stdout and stderr. Implementations must not invoke a shell.
type Runner interface {
	Run(ctx context.Context, path string, args []string, maxOutputBytes int64) (CommandResult, error)
}

// Verify authenticates an acquired image and proves that it is a clean,
// standalone qcow2 image at the end of verification. This point-in-time proof
// does not make a caller-controlled path immutable: before reuse, the caller
// must admit the verified bytes into a protected, read-only,
// content-addressed cache keyed by image.SHA256.
func Verify(ctx context.Context, image Image, actualPath, qemuImgPath string, runner Runner) error {
	if ctx == nil {
		return fmt.Errorf("verify image: context is nil")
	}
	if runner == nil {
		return fmt.Errorf("verify image: runner is nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verify image: %w", err)
	}
	if err := image.validate("image"); err != nil {
		return fmt.Errorf("verify image lock record: %w", err)
	}
	if err := validateVerificationPath("image path", actualPath, ""); err != nil {
		return err
	}
	if err := validateVerificationPath("qemu-img path", qemuImgPath, "qemu-img"); err != nil {
		return err
	}

	pathInfo, err := os.Lstat(actualPath)
	if err != nil {
		return fmt.Errorf("inspect image path: %w", err)
	}
	if !pathInfo.Mode().IsRegular() {
		return fmt.Errorf("image path must name a regular file without symlinks")
	}
	if pathInfo.Size() < 0 || pathInfo.Size() > MaxImageBytes {
		return fmt.Errorf("image exceeds hashing size limit of %d bytes", MaxImageBytes)
	}

	file, err := os.Open(actualPath)
	if err != nil {
		return fmt.Errorf("open image: %w", err)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened image: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return imageChanged(actualPath, "path no longer identifies the opened regular file", nil)
	}
	if err := preflightQCOW2Header(file, openedInfo.Size()); err != nil {
		return err
	}

	digest, bytesRead, err := hashImage(ctx, file)
	if err != nil {
		return err
	}
	if bytesRead != openedInfo.Size() {
		return imageChanged(actualPath, "size changed while hashing", nil)
	}
	if err := requireUnchangedImage(actualPath, file, openedInfo); err != nil {
		return err
	}
	if digest != image.SHA256 {
		return fmt.Errorf("image SHA256 %s does not match locked SHA256 %s", digest, image.SHA256)
	}

	infoResult, err := runBounded(ctx, runner, qemuImgPath,
		[]string{"info", "--output=json", "--backing-chain", actualPath})
	if err != nil {
		return fmt.Errorf("qemu-img info: %w", err)
	}
	if err := requireUnchangedImage(actualPath, file, openedInfo); err != nil {
		return err
	}
	if infoResult.ExitCode != 0 {
		return fmt.Errorf("qemu-img info exited with status %d", infoResult.ExitCode)
	}
	if err := validateInfoJSON(infoResult.Stdout, actualPath); err != nil {
		return err
	}

	checkResult, err := runBounded(ctx, runner, qemuImgPath,
		[]string{"check", "--output=json", actualPath})
	if err != nil {
		return fmt.Errorf("qemu-img check: %w", err)
	}
	if err := requireUnchangedImage(actualPath, file, openedInfo); err != nil {
		return err
	}
	if checkResult.ExitCode != 0 {
		return fmt.Errorf("qemu-img check exited with status %d", checkResult.ExitCode)
	}
	if err := requireLockedDigest(ctx, actualPath, file, openedInfo, image.SHA256); err != nil {
		return err
	}
	return nil
}

func validateVerificationPath(name, value, requiredBase string) error {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return fmt.Errorf("%s must be an absolute canonical path", name)
	}
	if requiredBase != "" && filepath.Base(value) != requiredBase {
		return fmt.Errorf("%s must name %s", name, requiredBase)
	}
	return nil
}

func hashImage(ctx context.Context, file *os.File) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, fmt.Errorf("rewind image for hashing: %w", err)
	}
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	var total int64

	for {
		if err := ctx.Err(); err != nil {
			return "", total, fmt.Errorf("hash image: %w", err)
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			total += int64(count)
			if total > MaxImageBytes {
				return "", total, fmt.Errorf("image exceeds hashing size limit of %d bytes", MaxImageBytes)
			}
			_, _ = hash.Write(buffer[:count])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", total, fmt.Errorf("hash image: %w", readErr)
		}
	}
	if err := ctx.Err(); err != nil {
		return "", total, fmt.Errorf("hash image: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), total, nil
}

func preflightQCOW2Header(file *os.File, fileSize int64) error {
	var header [qcow2Version3HeaderBytes]byte
	if _, err := file.ReadAt(header[:qcow2Version2HeaderBytes], 0); err != nil {
		return fmt.Errorf("qcow2 header is malformed or truncated: %w", err)
	}
	if magic := binary.BigEndian.Uint32(header[0:4]); magic != qcow2Magic {
		return fmt.Errorf("qcow2 header has invalid magic 0x%08x", magic)
	}

	version := binary.BigEndian.Uint32(header[4:8])
	if version != 2 && version != 3 {
		return fmt.Errorf("qcow2 header version %d is unsupported", version)
	}
	backingOffset := binary.BigEndian.Uint64(header[8:16])
	backingSize := binary.BigEndian.Uint32(header[16:20])
	if backingOffset != 0 || backingSize != 0 {
		return fmt.Errorf("qcow2 header declares a backing file")
	}
	if version == 2 {
		return nil
	}

	if _, err := file.ReadAt(header[qcow2Version2HeaderBytes:qcow2Version3HeaderBytes], qcow2Version2HeaderBytes); err != nil {
		return fmt.Errorf("qcow2 version 3 header is malformed or truncated: %w", err)
	}
	incompatibleFeatures := binary.BigEndian.Uint64(header[72:80])
	if incompatibleFeatures&qcow2IncompatibleExternalDataFileFeature != 0 {
		return fmt.Errorf("qcow2 header declares an external data file")
	}
	headerLength := binary.BigEndian.Uint32(header[100:104])
	if headerLength < qcow2Version3HeaderBytes ||
		headerLength%8 != 0 ||
		headerLength > maxQCOW2HeaderBytes ||
		int64(headerLength) > fileSize {
		return fmt.Errorf("qcow2 header length %d is invalid for a %d-byte file", headerLength, fileSize)
	}
	return nil
}

func requireLockedDigest(
	ctx context.Context,
	actualPath string,
	file *os.File,
	initial os.FileInfo,
	lockedDigest string,
) error {
	if err := requireUnchangedImage(actualPath, file, initial); err != nil {
		return err
	}
	digest, bytesRead, err := hashImage(ctx, file)
	if err != nil {
		return err
	}
	if bytesRead != initial.Size() {
		return imageChanged(actualPath, "size changed during final SHA256", nil)
	}
	if err := requireUnchangedImage(actualPath, file, initial); err != nil {
		return err
	}
	if digest != lockedDigest {
		return imageChanged(actualPath,
			fmt.Sprintf("final SHA256 %s does not match locked SHA256 %s", digest, lockedDigest), nil)
	}
	return nil
}

func requireUnchangedImage(actualPath string, file *os.File, initial os.FileInfo) error {
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect image during verification: %w", err)
	}
	current, err := os.Lstat(actualPath)
	if err != nil {
		return imageChanged(actualPath, "path cannot be inspected", err)
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() ||
		!os.SameFile(initial, opened) || !os.SameFile(initial, current) ||
		opened.Size() != initial.Size() || current.Size() != initial.Size() ||
		!opened.ModTime().Equal(initial.ModTime()) || !current.ModTime().Equal(initial.ModTime()) {
		return imageChanged(actualPath, "identity, size, or modification time differs", nil)
	}
	return nil
}

func imageChanged(path, problem string, err error) error {
	return &ImageChangedError{Path: path, Problem: problem, Err: err}
}

func runBounded(
	ctx context.Context,
	runner Runner,
	path string,
	args []string,
) (CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return CommandResult{}, err
	}
	result, err := runner.Run(ctx, path, args, MaxCommandOutputBytes)
	stdoutBytes := int64(len(result.Stdout))
	stderrBytes := int64(len(result.Stderr))
	if stdoutBytes > MaxCommandOutputBytes || stderrBytes > MaxCommandOutputBytes-stdoutBytes {
		return CommandResult{}, fmt.Errorf("command output limit of %d bytes exceeded", MaxCommandOutputBytes)
	}
	if err != nil {
		return CommandResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return CommandResult{}, err
	}
	return result, nil
}

type qemuImageInfo struct {
	// Children is QEMU 11.0.3 block-graph diagnostic metadata. Backing and
	// external-data authority is validated from the typed image fields below;
	// the bounded child descriptions are retained only so strict decoding can
	// accept the pinned QEMU wire format.
	Children              []json.RawMessage       `json:"children,omitempty"`
	Filename              string                  `json:"filename"`
	Format                string                  `json:"format"`
	VirtualSize           int64                   `json:"virtual-size"`
	ActualSize            *int64                  `json:"actual-size,omitempty"`
	Dirty                 *bool                   `json:"dirty-flag,omitempty"`
	ClusterSize           *int64                  `json:"cluster-size,omitempty"`
	Encrypted             *bool                   `json:"encrypted,omitempty"`
	Compressed            *bool                   `json:"compressed,omitempty"`
	BackingFilename       *string                 `json:"backing-filename,omitempty"`
	FullBackingFilename   *string                 `json:"full-backing-filename,omitempty"`
	BackingFilenameFormat *string                 `json:"backing-filename-format,omitempty"`
	BackingImage          *qemuImageInfo          `json:"backing-image,omitempty"`
	Snapshots             []json.RawMessage       `json:"snapshots,omitempty"`
	Limits                json.RawMessage         `json:"limits,omitempty"`
	FormatSpecific        *qemuInfoFormatSpecific `json:"format-specific,omitempty"`
}

type qemuInfoFormatSpecific struct {
	Type string        `json:"type"`
	Data qemuQCOW2Info `json:"data"`
}

type qemuQCOW2Info struct {
	Compat          string            `json:"compat"`
	DataFile        *string           `json:"data-file,omitempty"`
	DataFileRaw     *bool             `json:"data-file-raw,omitempty"`
	ExtendedL2      *bool             `json:"extended-l2,omitempty"`
	LazyRefcounts   *bool             `json:"lazy-refcounts,omitempty"`
	Corrupt         *bool             `json:"corrupt,omitempty"`
	RefcountBits    int64             `json:"refcount-bits"`
	Encrypt         json.RawMessage   `json:"encrypt,omitempty"`
	Bitmaps         []json.RawMessage `json:"bitmaps,omitempty"`
	CompressionType string            `json:"compression-type"`
}

func validateInfoJSON(data []byte, actualPath string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var chain []qemuImageInfo
	if err := decoder.Decode(&chain); err != nil {
		return fmt.Errorf("decode qemu-img info JSON: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode qemu-img info JSON: trailing JSON value")
		}
		return fmt.Errorf("decode qemu-img info JSON trailing data: %w", err)
	}
	if len(chain) != 1 {
		return fmt.Errorf("qemu-img info reports a backing chain of %d images", len(chain))
	}

	info := chain[0]
	if info.Filename != actualPath {
		return fmt.Errorf("qemu-img info filename does not match verified image path")
	}
	if info.Format != string(FormatQCOW2) {
		return fmt.Errorf("qemu-img info format must be qcow2")
	}
	if info.VirtualSize <= 0 || info.VirtualSize > MaxVirtualSizeBytes {
		return fmt.Errorf("qemu-img info virtual size must be between 1 and %d bytes", MaxVirtualSizeBytes)
	}
	if info.BackingFilename != nil || info.FullBackingFilename != nil ||
		info.BackingFilenameFormat != nil || info.BackingImage != nil {
		return fmt.Errorf("qemu-img info reports backing image metadata")
	}
	if info.Dirty == nil || *info.Dirty {
		return fmt.Errorf("qemu-img info must explicitly report dirty=false")
	}
	if info.FormatSpecific == nil || info.FormatSpecific.Type != string(FormatQCOW2) {
		return fmt.Errorf("qemu-img format-specific info must describe qcow2")
	}
	qcow2 := info.FormatSpecific.Data
	if qcow2.DataFile != nil || (qcow2.DataFileRaw != nil && *qcow2.DataFileRaw) {
		return fmt.Errorf("qemu-img info reports an external data file")
	}
	if qcow2.Corrupt == nil || *qcow2.Corrupt {
		return fmt.Errorf("qemu-img info must explicitly report corrupt=false")
	}
	return nil
}
