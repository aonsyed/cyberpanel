//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
)

// Native archives use the existing ordered object inventory. Each object fits
// the repository AEAD envelope; archive consumers still receive one verified file.
const LinuxBackupChunkBytes = 8 << 20

func commitLinuxBackupChunks(ctx context.Context, temporary, objectsRoot, key string) ([]ObjectDescriptor, uint64, string, error) {
	defer os.Remove(temporary)
	source, err := openLinuxBackupRegular(temporary)
	if err != nil {
		return nil, 0, "", err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return nil, 0, "", err
	}
	var objects []ObjectDescriptor
	var total uint64
	root := sha256.New()
	for index := 0; total < uint64(info.Size()) || index == 0; index++ {
		if err = ctx.Err(); err != nil {
			return nil, 0, "", err
		}
		partial := temporary + ".chunk"
		_ = os.Remove(partial)
		file, createErr := createLinuxBackupFile(partial)
		if createErr != nil {
			return nil, 0, "", createErr
		}
		remaining := uint64(info.Size()) - total
		if remaining > LinuxBackupChunkBytes {
			remaining = LinuxBackupChunkBytes
		}
		_, copyErr := io.CopyN(file, source, int64(remaining))
		err = errors.Join(copyErr, file.Sync(), file.Close())
		if err != nil {
			_ = os.Remove(partial)
			return nil, 0, "", err
		}
		objectKey := key
		if info.Size() > LinuxBackupChunkBytes {
			objectKey = fmt.Sprintf("%s/chunk-%08d", key, index)
		}
		descriptor, commitErr := commitLinuxBackupObject(partial, objectsRoot, objectKey)
		if commitErr != nil {
			_ = os.Remove(partial)
			return nil, 0, "", commitErr
		}
		objects = append(objects, descriptor)
		total += descriptor.Size
		_, _ = io.WriteString(root, descriptor.Key+"\x00"+descriptor.Digest+"\x00")
	}
	return objects, total, hex.EncodeToString(root.Sum(nil)), nil
}

func expectedLinuxBackupArtifact(root string, artifact ArtifactManifest) error {
	var manifest RecoveryPointManifest
	if err := readLinuxBackupJSON(filepath.Join(root, "manifest.json"), &manifest); err != nil {
		return err
	}
	if err := ValidateRecoveryPointManifest(manifest); err != nil {
		return err
	}
	for _, expected := range manifest.Artifacts {
		if expected.Component == artifact.Component && reflect.DeepEqual(expected, artifact) {
			return nil
		}
	}
	return ErrInvalidBackup
}

// Reassemble only after validating every chunk against the authoritative ordered
// manifest. The partial is never consumed and is removed on every failed attempt.
func assembleLinuxBackupArtifact(ctx context.Context, componentRoot string, artifact ArtifactManifest) error {
	if err := validateArtifact(artifact, ReadView{Component: artifact.Component, Consistency: artifact.Consistency}); err != nil {
		return err
	}
	partial := filepath.Join(componentRoot, "assembled.partial")
	target := filepath.Join(componentRoot, "assembled")
	_ = os.Remove(partial)
	// A failed retry must not leave an earlier assembled archive consumable.
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	defer os.Remove(partial)
	file, err := createLinuxBackupFile(partial)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			file.Close()
		}
	}()
	for index, descriptor := range artifact.Objects {
		if err = ctx.Err(); err != nil {
			return err
		}
		input, openErr := openLinuxBackupRegular(filepath.Join(componentRoot, "object-"+strconv.Itoa(index)))
		if openErr != nil {
			return openErr
		}
		hash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(input, int64(descriptor.Size)+1))
		closeErr := input.Close()
		if copyErr != nil || closeErr != nil || uint64(written) != descriptor.Size || hex.EncodeToString(hash.Sum(nil)) != descriptor.Digest {
			return errors.Join(ErrInvalidBackup, copyErr, closeErr)
		}
	}
	err = errors.Join(file.Sync(), file.Close())
	closed = true
	if err != nil {
		return err
	}
	if err = os.Rename(partial, target); err != nil {
		return err
	}
	directory, err := os.Open(componentRoot)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func verifyLinuxBackupComponents(ctx context.Context, root, scratch string, plan RestorePlanSpec) error {
	var manifest RecoveryPointManifest
	if err := readLinuxBackupJSON(filepath.Join(root, "manifest.json"), &manifest); err != nil {
		return err
	}
	if err := ValidateRecoveryPointManifest(manifest); err != nil {
		return err
	}
	for _, artifact := range manifest.Artifacts {
		if _, required := plan.ComponentMapping[artifact.Component]; !required {
			continue
		}
		componentRoot := filepath.Join(root, scratch, string(artifact.Component))
		var staged ArtifactManifest
		if err := readLinuxBackupJSON(filepath.Join(componentRoot, "artifact.json"), &staged); err != nil {
			return err
		}
		if !reflect.DeepEqual(staged, artifact) {
			return ErrInvalidBackup
		}
		if err := assembleLinuxBackupArtifact(ctx, componentRoot, artifact); err != nil {
			return err
		}
	}
	return nil
}
