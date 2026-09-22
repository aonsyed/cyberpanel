//go:build linux

package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"io"
	"path/filepath"
	"sync"
	"syscall"
)

const MaximumEncryptedObjectBytes = secrets.MaterialMaximumBytes

var ErrEncryptedObjectTooLarge = fmt.Errorf("%w: encrypted object exceeds %d-byte whole-object limit", backup.ErrInvalidBackup, MaximumEncryptedObjectBytes)

// The envelope is whole-object. Serialize buffered encryption/decryption in
// this process so caller concurrency cannot multiply the memory bound.
var localEnvelopeSlot = make(chan struct{}, 1)

func acquireLocalEnvelope(ctx context.Context) (func(), error) {
	select {
	case localEnvelopeSlot <- struct{}{}:
		return func() { <-localEnvelopeSlot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type localObjectBinding struct {
	Format           string                  `json:"format"`
	TenantID         string                  `json:"tenant_id"`
	RepositoryID     backup.RepositoryID     `json:"repository_id"`
	EncryptionDomain string                  `json:"encryption_domain"`
	KeyVersion       uint64                  `json:"key_version"`
	Object           backup.ObjectDescriptor `json:"object"`
}
type localObjectEnvelope struct {
	Algorithm  string `json:"algorithm"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func encryptedObjectBinding(spec backup.RepositorySpec, object backup.ObjectDescriptor) ([]byte, error) {
	return json.Marshal(localObjectBinding{LocalEncryptedFormat, spec.TenantID, spec.Repository.ID, spec.EncryptionDomain, 1, object})
}
func encryptedObjectPath(spec backup.RepositorySpec, object backup.ObjectDescriptor) string {
	aad, _ := encryptedObjectBinding(spec, object)
	return "blobs/aes256gcm-v1/" + hashBytes(aad)
}

func (provider LocalProvider) stageEncryptedObject(ctx context.Context, spec backup.RepositorySpec, staging string, object backup.ObjectDescriptor, effect string) (string, error) {
	if object.Size > MaximumEncryptedObjectBytes {
		return "", ErrEncryptedObjectTooLarge
	}
	release, err := acquireLocalEnvelope(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	repository, err := provider.repository(spec)
	if err != nil {
		return "", err
	}
	manifest, metadata, err := loadLocalStage(repository, staging)
	if err != nil || provider.Source == nil || provider.Keys == nil || metadata.EffectID != effect || metadata.TenantID != spec.TenantID || !objectInManifest(manifest, object) || staging != stageToken(spec.Repository.ID, manifest.RecoveryPointID, effect) {
		return "", ErrInvalid
	}
	relative := encryptedObjectPath(spec, object)
	existing, err := provider.decryptEncryptedObject(ctx, spec, repository, object)
	if err == nil {
		existing.Close()
		return relative, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	key, err := provider.Keys.ReadKey(ctx, spec, secrets.OperationEncrypt)
	if err != nil {
		return "", err
	}
	defer wipeKey(key)
	reader, err := provider.Source.OpenObject(ctx, object, effect, 0)
	if err != nil {
		return "", err
	}
	plain, readErr := io.ReadAll(io.LimitReader(reader, MaximumEncryptedObjectBytes+1))
	closeErr := reader.Close()
	defer wipeKey(plain)
	if readErr != nil || closeErr != nil || uint64(len(plain)) != object.Size || hashBytes(plain) != object.Digest {
		return "", ErrIntegrity
	}
	aad, err := encryptedObjectBinding(spec, object)
	if err != nil {
		return "", err
	}
	nonce, ciphertext, err := secrets.SealAEADEnvelope(key, plain, aad)
	if err != nil {
		return "", ErrIntegrity
	}
	encoded, err := json.Marshal(localObjectEnvelope{"AES-256-GCM", nonce, ciphertext})
	if err != nil {
		return "", err
	}
	directory, err := repository.openDir(filepath.Dir(relative), true)
	if err != nil {
		return "", err
	}
	defer syscall.Close(directory)
	// Publish only authenticated ciphertext; never create a plaintext partial file.
	leaf := filepath.Base(relative)
	partial := leaf + ".partial." + hashText(effect)[:20]
	if err = unlinkAt(directory, partial, false); err != nil && !errors.Is(err, ErrNotFound) {
		return "", err
	}
	if err = writeExclusiveOrEqual(directory, partial, encoded, 0600); err != nil {
		return "", err
	}
	err = renameNoReplace(directory, partial, directory, leaf)
	if err != nil {
		_ = unlinkAt(directory, partial, false)
	}
	if err != nil && !errors.Is(err, ErrConflict) {
		return "", err
	}
	if err = syscall.Fsync(directory); err != nil {
		return "", err
	}
	verified, err := provider.decryptEncryptedObject(ctx, spec, repository, object)
	if err != nil {
		return "", err
	}
	verified.Close()
	return relative, nil
}

func (provider LocalProvider) openEncryptedObject(ctx context.Context, spec backup.RepositorySpec, repository *LocalRepository, object backup.ObjectDescriptor) (backup.ReadCloser, error) {
	release, err := acquireLocalEnvelope(ctx)
	if err != nil {
		return nil, err
	}
	reader, err := provider.decryptEncryptedObject(ctx, spec, repository, object)
	if err != nil {
		release()
		return nil, err
	}
	return &leasedObjectReader{ReadCloser: reader, release: release}, nil
}

type leasedObjectReader struct {
	backup.ReadCloser
	release func()
	once    sync.Once
}

func (reader *leasedObjectReader) Close() error {
	err := reader.ReadCloser.Close()
	reader.once.Do(reader.release)
	return err
}

func (provider LocalProvider) decryptEncryptedObject(ctx context.Context, spec backup.RepositorySpec, repository *LocalRepository, object backup.ObjectDescriptor) (backup.ReadCloser, error) {
	if object.Size > MaximumEncryptedObjectBytes {
		return nil, ErrEncryptedObjectTooLarge
	}
	if provider.Keys == nil {
		return nil, ErrCredential
	}
	relative := encryptedObjectPath(spec, object)
	directory, err := repository.openDir(filepath.Dir(relative), false)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(directory)
	encoded, err := readRegularAt(directory, filepath.Base(relative), MaximumEncryptedObjectBytes*2)
	if err != nil {
		return nil, err
	}
	var envelope localObjectEnvelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF || envelope.Algorithm != "AES-256-GCM" {
		return nil, ErrIntegrity
	}
	key, err := provider.Keys.ReadKey(ctx, spec, secrets.OperationDecrypt)
	if err != nil {
		return nil, err
	}
	defer wipeKey(key)
	aad, err := encryptedObjectBinding(spec, object)
	if err != nil {
		return nil, err
	}
	plain, err := secrets.OpenAEADEnvelope(key, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil || uint64(len(plain)) != object.Size || hashBytes(plain) != object.Digest {
		wipeKey(plain)
		return nil, ErrIntegrity
	}
	return &wipingObjectReader{Reader: bytes.NewReader(plain), plain: plain}, nil
}

type wipingObjectReader struct {
	*bytes.Reader
	plain []byte
}

func (reader *wipingObjectReader) Close() error {
	wipeKey(reader.plain)
	reader.plain = nil
	reader.Reader.Reset(nil)
	return nil
}

func (provider LocalProvider) verifyStoredObject(ctx context.Context, spec backup.RepositorySpec, repository *LocalRepository, object backup.ObjectDescriptor) error {
	format, err := localObjectFormat(spec)
	if err != nil {
		return err
	}
	if format == LocalEncryptedFormat {
		reader, err := provider.openEncryptedObject(ctx, spec, repository, object)
		if err != nil {
			return err
		}
		return reader.Close()
	}
	relative := objectPath(object)
	directory, err := repository.openDir(filepath.Dir(relative), false)
	if err != nil {
		return err
	}
	defer syscall.Close(directory)
	valid, err := verifyRegularAt(directory, filepath.Base(relative), object.Digest, object.Size)
	if err != nil || !valid {
		return errors.Join(ErrIntegrity, err)
	}
	return nil
}
