//go:build linux

package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"syscall"
)

func (provider LocalProvider) ProbeRepository(ctx context.Context, spec backup.RepositorySpec, effect string) (RepositoryProbe, error) {
	probe, err := provider.plainProbeRepository(ctx, spec, effect)
	if err != nil {
		return probe, err
	}
	format, err := localObjectFormat(spec)
	if err == nil && format == LocalEncryptedFormat {
		if provider.Keys == nil {
			err = ErrCredential
		} else {
			for _, operation := range []secrets.Operation{secrets.OperationEncrypt, secrets.OperationDecrypt} {
				var key []byte
				key, err = provider.Keys.ReadKey(ctx, spec, operation)
				wipeKey(key)
				if err != nil {
					break
				}
			}
		}
		if err == nil {
			probe.Capabilities = append(probe.Capabilities, "aes256gcm_v1", "maximum_object_bytes_16777216")
		}
	}
	if err != nil {
		probe.Health = RepositoryUnavailable
		probe.DetailDigest = hashText(err.Error())
		return probe, err
	}
	return probe, nil
}

func (provider LocalProvider) StageManifest(ctx context.Context, spec backup.RepositorySpec, manifest backup.RecoveryPointManifest, effect string) (string, error) {
	if spec.ObjectFormat == "" {
		return "", fmt.Errorf("%w: legacy repository requires explicit plaintext-v1 acknowledgement before new capture", backup.ErrInvalidBackup)
	}
	format, err := localObjectFormat(spec)
	if err != nil {
		return "", err
	}
	if format == LocalEncryptedFormat {
		if provider.Keys == nil {
			return "", ErrCredential
		}
		for _, artifact := range manifest.Artifacts {
			for _, object := range artifact.Objects {
				if object.Size > MaximumEncryptedObjectBytes {
					return "", ErrEncryptedObjectTooLarge
				}
			}
		}
	}
	return provider.plainStageManifest(ctx, spec, manifest, effect)
}
func (provider LocalProvider) StageObject(ctx context.Context, spec backup.RepositorySpec, staging string, object backup.ObjectDescriptor, effect string) (string, error) {
	if spec.ObjectFormat == "" {
		return "", backup.ErrInvalidBackup
	}
	format, err := localObjectFormat(spec)
	if err != nil {
		return "", err
	}
	if format == LocalPlaintextFormat {
		return provider.plainStageObject(ctx, spec, staging, object, effect)
	}
	return provider.stageEncryptedObject(ctx, spec, staging, object, effect)
}
func (provider LocalProvider) Commit(ctx context.Context, spec backup.RepositorySpec, manifest backup.RecoveryPointManifest, staging, effect string) (backup.CopyReceipt, error) {
	if spec.ObjectFormat == "" {
		return backup.CopyReceipt{}, backup.ErrInvalidBackup
	}
	format, err := localObjectFormat(spec)
	if err != nil {
		return backup.CopyReceipt{}, err
	}
	if format == LocalPlaintextFormat {
		return provider.plainCommit(ctx, spec, manifest, staging, effect)
	}
	repository, err := provider.repository(spec)
	if err != nil {
		return backup.CopyReceipt{}, err
	}
	if staging != stageToken(spec.Repository.ID, manifest.RecoveryPointID, effect) || effect == "" || manifest.TenantID != spec.TenantID || validateManifest(manifest) != nil {
		return backup.CopyReceipt{}, ErrInvalid
	}
	staged, metadata, err := loadLocalStage(repository, staging)
	if err != nil || metadata.EffectID != effect || metadata.TenantID != spec.TenantID || metadata.RecoveryPointID != manifest.RecoveryPointID || metadata.ManifestDigest != manifest.ManifestDigest {
		return backup.CopyReceipt{}, ErrIntegrity
	}
	raw, err := manifestBytes(manifest)
	if err != nil {
		return backup.CopyReceipt{}, err
	}
	prior, err := manifestBytes(staged)
	if err != nil || !equalBytes(raw, prior) {
		return backup.CopyReceipt{}, ErrIntegrity
	}
	for _, artifact := range manifest.Artifacts {
		for _, object := range artifact.Objects {
			if err = provider.verifyStoredObject(ctx, spec, repository, object); err != nil {
				return backup.CopyReceipt{}, err
			}
		}
	}
	point, err := repository.openDir("points/"+string(manifest.RecoveryPointID), true)
	if err != nil {
		return backup.CopyReceipt{}, err
	}
	defer syscall.Close(point)
	if err = writeExclusiveOrEqual(point, "manifest.json", raw, 0600); err != nil {
		return backup.CopyReceipt{}, err
	}
	payload, _, err := commitBytes(manifest, spec.Repository.ID, effect, provider.now())
	if err != nil {
		return backup.CopyReceipt{}, err
	}
	var marker commitMarker
	if json.Unmarshal(payload, &marker) != nil {
		return backup.CopyReceipt{}, ErrIntegrity
	}
	marker.Version = 2
	marker.ObjectFormat = LocalEncryptedFormat
	marker.EncryptionDomain = spec.EncryptionDomain
	marker.KeyVersion = 1
	payload, err = json.Marshal(marker)
	if err != nil {
		return backup.CopyReceipt{}, err
	}
	if err = writeExclusiveOrEqual(point, "COMMITTED", payload, 0600); err != nil {
		return backup.CopyReceipt{}, err
	}
	if err = syscall.Fsync(point); err != nil {
		return backup.CopyReceipt{}, err
	}
	objects, size := manifestTotals(manifest)
	return backup.CopyReceipt{ID: copyID(spec.Repository.ID, manifest.RecoveryPointID), RecoveryPointID: manifest.RecoveryPointID, RepositoryID: spec.Repository.ID, FailureDomain: spec.FailureDomain, Status: backup.CopyCommitted, CommitMarker: hashBytes(payload), ManifestDigest: manifest.ManifestDigest, Objects: objects, Bytes: size}, nil
}
func (provider LocalProvider) Verify(ctx context.Context, spec backup.RepositorySpec, manifest backup.RecoveryPointManifest, receipt backup.CopyReceipt) (backup.CopyReceipt, error) {
	format, err := localObjectFormat(spec)
	if err != nil {
		return receipt, err
	}
	if format == LocalPlaintextFormat {
		return provider.plainVerify(ctx, spec, manifest, receipt)
	}
	repository, err := provider.repository(spec)
	if err != nil {
		return receipt, err
	}
	if receipt.RecoveryPointID != manifest.RecoveryPointID || receipt.RepositoryID != spec.Repository.ID || receipt.ManifestDigest != manifest.ManifestDigest || manifest.TenantID != spec.TenantID || validateManifest(manifest) != nil {
		return receipt, ErrIntegrity
	}
	point, err := repository.openDir("points/"+string(manifest.RecoveryPointID), false)
	if err != nil {
		return receipt, err
	}
	err = verifyLocalCommit(point, spec, manifest, receipt)
	syscall.Close(point)
	if err != nil {
		return receipt, err
	}
	for _, artifact := range manifest.Artifacts {
		for _, object := range artifact.Objects {
			if err = provider.verifyStoredObject(ctx, spec, repository, object); err != nil {
				return receipt, err
			}
		}
	}
	receipt.Status = backup.CopyVerified
	receipt.VerifiedAt = provider.now()
	return receipt, nil
}
func (provider LocalProvider) OpenCommittedObject(ctx context.Context, spec backup.RepositorySpec, manifest backup.RecoveryPointManifest, receipt backup.CopyReceipt, object backup.ObjectDescriptor) (backup.ReadCloser, error) {
	format, err := localObjectFormat(spec)
	if err != nil {
		return nil, err
	}
	if format == LocalPlaintextFormat {
		return provider.plainOpenCommittedObject(ctx, spec, manifest, receipt, object)
	}
	repository, err := provider.repository(spec)
	if err != nil {
		return nil, err
	}
	if manifest.TenantID != spec.TenantID || validateManifest(manifest) != nil || !receiptMatches(spec, manifest, receipt) || !objectInManifest(manifest, object) {
		return nil, ErrInvalid
	}
	point, err := repository.openDir("points/"+string(manifest.RecoveryPointID), false)
	if err != nil {
		return nil, err
	}
	err = verifyLocalCommit(point, spec, manifest, receipt)
	syscall.Close(point)
	if err != nil {
		return nil, err
	}
	return provider.openEncryptedObject(ctx, spec, repository, object)
}
