package management

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// EnsureInstallation creates the projection for the installer-owned engine or
// advances it to a newer catalog-observed tuning generation after recovery.
// Edition changes require the broker's exact terminal conversion receipt and
// the matching admitted control operation; observation alone cannot authorize one.
func (repository *SQLRepository) EnsureInstallation(ctx context.Context, observed Installation) (Installation, error) {
	if repository == nil || repository.db == nil || observed.ID != "node-webengine" || observed.Generation == 0 ||
		observed.Edition != "openlitespeed" && observed.Edition != "litespeed_enterprise" ||
		observed.State != StateActive || observed.UpdatedAt.IsZero() {
		return Installation{}, ErrInvalid
	}
	if observed.InstalledAt.IsZero() {
		observed.InstalledAt = observed.UpdatedAt
	}
	if observed.Transition != nil && !conversionInstallationMatches(observed, *observed.Transition) { return Installation{}, ErrConflict }
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Installation{}, err
	}
	defer tx.Rollback()
	var raw []byte
	var generation uint64
	err = tx.QueryRowContext(ctx, `SELECT generation,value_json FROM webengine_installation WHERE singleton_id=1`).Scan(&generation, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		if observed.Transition != nil { return Installation{}, ErrConflict }
		encoded, encodeErr := json.Marshal(observed)
		if encodeErr != nil {
			return Installation{}, encodeErr
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO webengine_installation(singleton_id,generation,state,value_json,updated_at) VALUES(1,?,?,?,?)`,
			observed.Generation, observed.State, encoded, repository.clock().UTC())
		if err != nil {
			return Installation{}, err
		}
		return observed, tx.Commit()
	}
	if err != nil {
		return Installation{}, err
	}
	var current Installation
	if json.Unmarshal(raw, &current) != nil || current.Generation != generation || current.ID != observed.ID {
		return Installation{}, ErrConflict
	}
	if observed.Transition != nil {
		receipt := *observed.Transition
		if !conversionInstallationMatches(observed, receipt) || current.Generation != receipt.Fence && current.Generation+1 != receipt.Fence {
			return Installation{}, ErrConflict
		}
		var kind, requestDigest string
		var expected uint64
		if err = tx.QueryRowContext(ctx, `SELECT kind,request_digest,expected_generation FROM webengine_management_operations WHERE id=?`, receipt.EffectID).Scan(&kind, &requestDigest, &expected); err != nil {
			return Installation{}, errors.Join(ErrConflict, err)
		}
		if kind != "convert" || requestDigest != receipt.ConversionDigest || expected+1 != receipt.Fence ||
			current.Edition != receipt.Previous && current.Edition != receipt.Target ||
			current.Generation == expected && (current.Edition != receipt.Previous || current.ActiveConfigDigest != receipt.PreviousConfigDigest) {
			return Installation{}, ErrConflict
		}
		var tuningRaw []byte
		var tuningGeneration uint64
		if err = tx.QueryRowContext(ctx, `SELECT generation,value_json FROM webengine_global_tuning WHERE singleton_id=1`).Scan(&tuningGeneration, &tuningRaw); err != nil {
			return Installation{}, errors.Join(ErrConflict, err)
		}
		var tuning GlobalTuning
		if json.Unmarshal(tuningRaw, &tuning) != nil || tuning.Generation != tuningGeneration || tuningGeneration != expected && tuningGeneration != receipt.Fence {
			return Installation{}, ErrConflict
		}
		if tuningGeneration == expected {
			tuning.Generation = receipt.Fence
			tuningRaw, err = json.Marshal(tuning)
			if err != nil { return Installation{}, err }
			result, updateErr := tx.ExecContext(ctx, `UPDATE webengine_global_tuning SET generation=?,value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`, receipt.Fence, tuningRaw, repository.clock().UTC(), expected)
			if updateErr != nil { return Installation{}, updateErr }
			changed, rowsErr := result.RowsAffected()
			if rowsErr != nil || changed != 1 { return Installation{}, errors.Join(ErrConflict, rowsErr) }
		}
		observed.InstalledAt = current.InstalledAt
		observed.PreviousConfigDigest = receipt.PreviousConfigDigest
		encoded, encodeErr := json.Marshal(observed)
		if encodeErr != nil { return Installation{}, encodeErr }
		result, updateErr := tx.ExecContext(ctx, `UPDATE webengine_installation SET generation=?,state=?,value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`, observed.Generation, observed.State, encoded, repository.clock().UTC(), current.Generation)
		if updateErr != nil { return Installation{}, updateErr }
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil || changed != 1 { return Installation{}, errors.Join(ErrConflict, rowsErr) }
		status := "applied"; if receipt.Restored { status = "rolled_back" }
		receiptJSON, encodeErr := json.Marshal(receipt); if encodeErr != nil { return Installation{}, encodeErr }
		operationResult, operationErr := tx.ExecContext(ctx, `UPDATE webengine_management_operations SET status=?,installation_json=?,receipt_json=?,updated_at=? WHERE id=? AND request_digest=?`, status, encoded, receiptJSON, repository.clock().UTC(), receipt.EffectID, receipt.ConversionDigest)
		if operationErr != nil { return Installation{}, operationErr }
		operationChanged, rowsErr := operationResult.RowsAffected()
		if rowsErr != nil || operationChanged != 1 { return Installation{}, errors.Join(ErrConflict, rowsErr) }
		return observed, tx.Commit()
	}
	if current.Edition != observed.Edition { return Installation{}, ErrConflict }
	if observed.Generation < current.Generation {
		return Installation{}, ErrConflict
	}
	if observed.Generation == current.Generation {
		if observed.ActiveConfigDigest != current.ActiveConfigDigest {
			current.PreviousConfigDigest = current.ActiveConfigDigest
			current.ActiveConfigDigest = observed.ActiveConfigDigest
			current.UpdatedAt = observed.UpdatedAt
			encoded, encodeErr := json.Marshal(current)
			if encodeErr != nil {
				return Installation{}, encodeErr
			}
			result, updateErr := tx.ExecContext(ctx, `UPDATE webengine_installation SET value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`,
				encoded, repository.clock().UTC(), current.Generation)
			if updateErr != nil {
				return Installation{}, updateErr
			}
			changed, rowsErr := result.RowsAffected()
			if rowsErr != nil {
				return Installation{}, rowsErr
			}
			if changed != 1 {
				return Installation{}, ErrConflict
			}
		}
		return current, tx.Commit()
	}
	if observed.Version == "" {
		observed.Version = current.Version
	}
	if observed.ArtifactDigest == "" {
		observed.ArtifactDigest = current.ArtifactDigest
	}
	if observed.RepositorySnapshotDigest == "" {
		observed.RepositorySnapshotDigest = current.RepositorySnapshotDigest
	}
	if observed.Channel == "" {
		observed.Channel = current.Channel
	}
	if observed.License.State == "" {
		observed.License = current.License
	}
	observed.InstalledAt = current.InstalledAt
	observed.PreviousConfigDigest = current.ActiveConfigDigest
	encoded, err := json.Marshal(observed)
	if err != nil {
		return Installation{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE webengine_installation SET generation=?,state=?,value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`,
		observed.Generation, observed.State, encoded, repository.clock().UTC(), current.Generation)
	if err != nil {
		return Installation{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return Installation{}, err
	}
	if changed != 1 {
		return Installation{}, ErrConflict
	}
	return observed, tx.Commit()
}

func conversionInstallationMatches(observed Installation, receipt SwitchReceipt) bool {
	if !validConversionReceipt(receipt) || observed.Generation != receipt.Fence || receipt.LicenseDigest != digestJSON(observed.License) || receipt.LicenseDigest != digestJSON(receipt.License) { return false }
	plan, config, channel := receipt.TargetPlan, receipt.TargetConfigDigest, receipt.TargetChannel
	if receipt.Restored { plan, config, channel = receipt.PreviousPlan, receipt.PreviousConfigDigest, receipt.PreviousChannel }
	return observed.Edition == plan.Edition && observed.Version == plan.Version && observed.ArtifactDigest == plan.ArtifactDigest && observed.RepositorySnapshotDigest == plan.RepositorySnapshotDigest && observed.Channel == channel && observed.ActiveConfigDigest == config
}

// EnsureGlobalTuning seeds the typed tuning projection or reconciles it from a
// newer canonical catalog generation after an ambiguous control-db commit.
func (repository *SQLRepository) EnsureGlobalTuning(ctx context.Context, observed GlobalTuning) (GlobalTuning, error) {
	if repository == nil || repository.db == nil {
		return GlobalTuning{}, ErrInvalid
	}
	if _, err := canonicalTuning(observed); err != nil {
		return GlobalTuning{}, err
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return GlobalTuning{}, err
	}
	defer tx.Rollback()
	var generation uint64
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT generation,value_json FROM webengine_global_tuning WHERE singleton_id=1`).Scan(&generation, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		encoded, encodeErr := json.Marshal(observed)
		if encodeErr != nil {
			return GlobalTuning{}, encodeErr
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO webengine_global_tuning(singleton_id,generation,value_json,updated_at) VALUES(1,?,?,?)`,
			observed.Generation, encoded, repository.clock().UTC())
		if err != nil {
			return GlobalTuning{}, err
		}
		return observed, tx.Commit()
	}
	if err != nil {
		return GlobalTuning{}, err
	}
	var current GlobalTuning
	if json.Unmarshal(raw, &current) != nil || current.Generation != generation {
		return GlobalTuning{}, ErrConflict
	}
	if observed.Generation < current.Generation {
		rolledBack := observed.Generation+1 == current.Generation
		left, right := observed, current
		left.Generation, right.Generation = 0, 0
		if rolledBack && left == right {
			var count uint64
			if queryErr := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM webengine_management_operations WHERE kind='convert' AND status='rolled_back' AND expected_generation=?`, observed.Generation).Scan(&count); queryErr == nil && count == 1 {
				return current, tx.Commit()
			}
		}
		return GlobalTuning{}, ErrConflict
	}
	if observed.Generation == current.Generation {
		currentRaw, _ := json.Marshal(current)
		observedRaw, _ := json.Marshal(observed)
		if string(currentRaw) != string(observedRaw) {
			return GlobalTuning{}, ErrConflict
		}
		return current, tx.Commit()
	}
	encoded, err := json.Marshal(observed)
	if err != nil {
		return GlobalTuning{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE webengine_global_tuning SET generation=?,value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`,
		observed.Generation, encoded, repository.clock().UTC(), current.Generation)
	if err != nil {
		return GlobalTuning{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return GlobalTuning{}, err
	}
	if changed != 1 {
		return GlobalTuning{}, ErrConflict
	}
	return observed, tx.Commit()
}

// CommitTuning advances the aggregate and tuning projection in one serializable
// transaction after the immutable native generation has been confirmed.
func (repository *SQLRepository) CommitTuning(ctx context.Context, installation Installation, tuning GlobalTuning, expected uint64) error {
	if repository == nil || repository.db == nil || installation.ID != "node-webengine" ||
		installation.Generation != expected+1 || tuning.Generation != expected+1 || installation.Generation != tuning.Generation ||
		installation.State != StateActive || !validSHA256(installation.ActiveConfigDigest) {
		return ErrInvalid
	}
	if _, err := canonicalTuning(tuning); err != nil {
		return err
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var installationGeneration, tuningGeneration uint64
	if err = tx.QueryRowContext(ctx, `SELECT generation FROM webengine_installation WHERE singleton_id=1`).Scan(&installationGeneration); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT generation FROM webengine_global_tuning WHERE singleton_id=1`).Scan(&tuningGeneration); err != nil {
		return err
	}
	if installationGeneration != expected || tuningGeneration != expected {
		return ErrConflict
	}
	installationRaw, err := json.Marshal(installation)
	if err != nil {
		return err
	}
	tuningRaw, err := json.Marshal(tuning)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE webengine_global_tuning SET generation=?,value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`,
		tuning.Generation, tuningRaw, repository.clock().UTC(), expected)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	result, err = tx.ExecContext(ctx, `UPDATE webengine_installation SET generation=?,state=?,value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`,
		installation.Generation, installation.State, installationRaw, repository.clock().UTC(), expected)
	if err != nil {
		return err
	}
	changed, err = result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	return tx.Commit()
}
