package management

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// EnsureInstallation creates the projection for the installer-owned engine or
// advances it to a newer catalog-observed tuning generation after recovery.
// It never changes the installed edition or invents artifact/license facts.
func (repository *SQLRepository) EnsureInstallation(ctx context.Context, observed Installation) (Installation, error) {
	if repository == nil || repository.db == nil || observed.ID != "node-webengine" || observed.Generation == 0 ||
		observed.Edition != "openlitespeed" && observed.Edition != "litespeed_enterprise" ||
		observed.State != StateActive || observed.UpdatedAt.IsZero() {
		return Installation{}, ErrInvalid
	}
	if observed.InstalledAt.IsZero() {
		observed.InstalledAt = observed.UpdatedAt
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Installation{}, err
	}
	defer tx.Rollback()
	var raw []byte
	var generation uint64
	err = tx.QueryRowContext(ctx, `SELECT generation,value_json FROM webengine_installation WHERE singleton_id=1`).Scan(&generation, &raw)
	if errors.Is(err, sql.ErrNoRows) {
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
	if json.Unmarshal(raw, &current) != nil || current.Generation != generation || current.ID != observed.ID || current.Edition != observed.Edition {
		return Installation{}, ErrConflict
	}
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
