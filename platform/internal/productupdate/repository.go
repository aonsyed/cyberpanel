package productupdate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

type Repository struct { db *sql.DB }

func NewRepository(db *sql.DB) (*Repository, error) {
	if db == nil { return nil, ErrInvalid }
	return &Repository{db: db}, nil
}

func (repository *Repository) Bootstrap(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS product_update_manifests (
			id TEXT PRIMARY KEY, manifest_digest TEXT NOT NULL UNIQUE, tuple_key TEXT NOT NULL,
			sequence INTEGER NOT NULL CHECK (sequence > 0), storage_digest TEXT NOT NULL, manifest_json BLOB NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS product_update_manifests_sequence_idx ON product_update_manifests (tuple_key, sequence, id)`,
		`CREATE TABLE IF NOT EXISTS product_update_states (
			manifest_id TEXT NOT NULL, node_id TEXT NOT NULL, phase TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0), fence INTEGER NOT NULL CHECK (fence > 0),
			controller_id TEXT NOT NULL, storage_digest TEXT NOT NULL, state_json BLOB NOT NULL,
			updated_unix_nano INTEGER NOT NULL, PRIMARY KEY (manifest_id, node_id),
			FOREIGN KEY (manifest_id) REFERENCES product_update_manifests(id))`,
		`CREATE INDEX IF NOT EXISTS product_update_states_due_idx ON product_update_states (phase, updated_unix_nano, manifest_id, node_id)`,
		`CREATE TABLE IF NOT EXISTS product_update_node_locks (
			node_id TEXT PRIMARY KEY, manifest_id TEXT NOT NULL, fence INTEGER NOT NULL CHECK (fence > 0))`,
		`CREATE TABLE IF NOT EXISTS product_update_sequences (
			node_id TEXT NOT NULL, tuple_key TEXT NOT NULL, sequence INTEGER NOT NULL CHECK (sequence > 0),
			manifest_digest TEXT NOT NULL, PRIMARY KEY (node_id, tuple_key))`,
		`CREATE TABLE IF NOT EXISTS product_update_receipts (
			id TEXT PRIMARY KEY, manifest_id TEXT NOT NULL, node_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
			command_digest TEXT NOT NULL, storage_digest TEXT NOT NULL, receipt_json BLOB NOT NULL,
			created_unix_nano INTEGER NOT NULL, UNIQUE (manifest_id, node_id, idempotency_key),
			FOREIGN KEY (manifest_id) REFERENCES product_update_manifests(id))`,
		`CREATE INDEX IF NOT EXISTS product_update_receipts_update_idx ON product_update_receipts (manifest_id, node_id, id)`,
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	for _, statement := range statements { if _, err := tx.ExecContext(ctx, statement); err != nil { return err } }
	return tx.Commit()
}

func (repository *Repository) CreateDiscovered(ctx context.Context, manifest ReleaseManifest, nodeID, controllerID, idempotencyKey string, at time.Time) (UpdateState, Receipt, error) {
	manifest, err := CanonicalManifest(manifest)
	if err != nil { return UpdateState{}, Receipt{}, err }
	if !identifierPattern.MatchString(nodeID) || !identifierPattern.MatchString(controllerID) ||
		!identifierPattern.MatchString(idempotencyKey) || !validTime(at) { return UpdateState{}, Receipt{}, ErrInvalid }
	at = at.UTC()
	commandDigest := digestParts("discover", manifest.Digest, nodeID, controllerID, idempotencyKey)
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return UpdateState{}, Receipt{}, err }
	defer tx.Rollback()
	if receipt, found, err := loadReceipt(ctx, tx, manifest.ID, nodeID, idempotencyKey); err != nil {
		return UpdateState{}, Receipt{}, err
	} else if found {
		if receipt.CommandDigest != commandDigest { return UpdateState{}, Receipt{}, ErrIntegrity }
		state, err := loadState(ctx, tx, manifest.ID, nodeID)
		if err != nil { return UpdateState{}, Receipt{}, err }
		if state.ManifestDigest != manifest.Digest { return UpdateState{}, Receipt{}, ErrIntegrity }
		if err := tx.Commit(); err != nil { return UpdateState{}, Receipt{}, err }
		return state, receipt, nil
	}
	raw, storageDigest, err := encodeStored(manifest)
	if err != nil { return UpdateState{}, Receipt{}, err }
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO product_update_manifests
		(id, manifest_digest, tuple_key, sequence, storage_digest, manifest_json) VALUES (?, ?, ?, ?, ?, ?)`,
		manifest.ID, manifest.Digest, manifest.Platform.key(), manifest.Sequence, storageDigest, raw)
	if err != nil { return UpdateState{}, Receipt{}, err }
	if !oneRow(result) {
		stored, err := loadManifest(ctx, tx, manifest.ID)
		if err != nil || stored.Digest != manifest.Digest { return UpdateState{}, Receipt{}, ErrConflict }
	}
	receipt, err := buildReceipt(manifest.ID, nodeID, PhaseDiscovered, PhaseDiscovered, 1, 1,
		idempotencyKey, commandDigest, manifest.Digest, ReasonNone, at)
	if err != nil { return UpdateState{}, Receipt{}, err }
	state := UpdateState{ManifestID: manifest.ID, ManifestDigest: manifest.Digest, NodeID: nodeID,
		Phase: PhaseDiscovered, Generation: 1, Fence: 1, ControllerID: controllerID, Reason: ReasonNone,
		LastReceiptDigest: receipt.Digest, UpdatedAt: at}
	if err := insertState(ctx, tx, state); err != nil { return UpdateState{}, Receipt{}, err }
	if err := insertReceipt(ctx, tx, receipt); err != nil { return UpdateState{}, Receipt{}, err }
	if err := tx.Commit(); err != nil { return UpdateState{}, Receipt{}, err }
	return state, receipt, nil
}

func (repository *Repository) transition(ctx context.Context, command Transition) (UpdateState, Receipt, error) {
	command, commandDigest, err := canonicalTransition(command)
	if err != nil { return UpdateState{}, Receipt{}, err }
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return UpdateState{}, Receipt{}, err }
	defer tx.Rollback()
	state, manifest, receipt, replay, err := loadTransitionContext(ctx, tx, command, commandDigest)
	if err != nil { return UpdateState{}, Receipt{}, err }
	if replay {
		if err := tx.Commit(); err != nil { return UpdateState{}, Receipt{}, err }
		return state, receipt, nil
	}
	if state.ManifestID != manifest.ID || state.ManifestDigest != manifest.Digest || state.NodeID != command.NodeID { return UpdateState{}, Receipt{}, ErrIntegrity }
	if state.Generation != command.ExpectedGeneration || state.Fence != command.Fence || state.ControllerID != command.ControllerID || state.Phase != command.From ||
		!validTransition(command.From, command.To) || state.Generation >= maxGeneration { return UpdateState{}, Receipt{}, ErrConflict }
	if command.To == PhaseVerified {
		if err := admitUpdate(ctx, tx, state.NodeID, manifest, state.Fence); err != nil { return UpdateState{}, Receipt{}, err }
	}
	next := state
	next.Phase, next.Generation, next.Reason, next.UpdatedAt = command.To, state.Generation+1, command.Reason, command.At
	if command.StagedRootID != "" {
		next.StagedRootID, next.StagedRootDigest = command.StagedRootID, command.StagedRootDigest
	}
	if command.PreviousReleaseID != "" {
		next.PreviousReleaseID, next.PreviousReleaseDigest = command.PreviousReleaseID, command.PreviousReleaseDigest
	}
	if command.BaselineDigest != "" { next.BaselineDigest = command.BaselineDigest }
	if command.MigrationEvidence != "" {
		next.MigrationEvidence = command.MigrationEvidence
		next.MigrationProofs = append([]MigrationProof(nil), command.MigrationProofs...)
	}
	if command.RollbackEvidence != "" {
		next.RollbackProven, next.RollbackEvidence = command.RollbackProven, command.RollbackEvidence
	}
	if command.RecoveryEvidence != "" {
		next.RecoveryEvidence = command.RecoveryEvidence
		next.RecoverySteps = append([]string(nil), command.RecoverySteps...)
	}
	receipt, err = buildReceipt(command.ManifestID, state.NodeID, state.Phase, next.Phase, next.Generation,
		next.Fence, command.IdempotencyKey, commandDigest, command.EvidenceDigest, command.Reason, command.At)
	if err != nil { return UpdateState{}, Receipt{}, err }
	next.LastReceiptDigest = receipt.Digest
	if err := updateState(ctx, tx, state, next); err != nil { return UpdateState{}, Receipt{}, err }
	if err := insertReceipt(ctx, tx, receipt); err != nil { return UpdateState{}, Receipt{}, err }
	if next.Phase.terminal() && state.Phase != PhaseDiscovered {
		result, err := tx.ExecContext(ctx, `DELETE FROM product_update_node_locks WHERE node_id = ? AND manifest_id = ? AND fence = ?`, next.NodeID, next.ManifestID, next.Fence)
		if err != nil || !oneRow(result) { return UpdateState{}, Receipt{}, ErrIntegrity }
	}
	if err := tx.Commit(); err != nil { return UpdateState{}, Receipt{}, err }
	return next, receipt, nil
}

func (repository *Repository) fence(ctx context.Context, manifestID, nodeID, fromController, toController, idempotencyKey string, expectedGeneration, expectedFence uint64, at time.Time) (UpdateState, Receipt, error) {
	if !identifierPattern.MatchString(manifestID) || !identifierPattern.MatchString(nodeID) || !identifierPattern.MatchString(fromController) ||
		!identifierPattern.MatchString(toController) || !identifierPattern.MatchString(idempotencyKey) || expectedGeneration == 0 || expectedFence == 0 ||
		expectedGeneration >= maxGeneration || expectedFence >= maxGeneration || !validTime(at) {
		return UpdateState{}, Receipt{}, ErrInvalid
	}
	at = at.UTC()
	commandDigest := digestParts("fence", manifestID, nodeID, fromController, toController, idempotencyKey,
		fmtUint(expectedGeneration), fmtUint(expectedFence), at.Format(time.RFC3339Nano))
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return UpdateState{}, Receipt{}, err }
	defer tx.Rollback()
	if receipt, found, err := loadReceipt(ctx, tx, manifestID, nodeID, idempotencyKey); err != nil {
		return UpdateState{}, Receipt{}, err
	} else if found {
		if receipt.CommandDigest != commandDigest { return UpdateState{}, Receipt{}, ErrIntegrity }
		state, err := loadState(ctx, tx, manifestID, nodeID)
		if err != nil { return UpdateState{}, Receipt{}, err }
		if err := tx.Commit(); err != nil { return UpdateState{}, Receipt{}, err }
		return state, receipt, nil
	}
	state, err := loadState(ctx, tx, manifestID, nodeID)
	if err != nil { return UpdateState{}, Receipt{}, err }
	if state.Generation != expectedGeneration || state.Fence != expectedFence || state.ControllerID != fromController ||
		state.Phase != PhaseDiscovered && state.Phase != PhaseVerified && state.Phase != PhaseStaged && state.Phase != PhasePreflighted {
		return UpdateState{}, Receipt{}, ErrConflict
	}
	next := state
	next.Generation, next.Fence, next.ControllerID, next.UpdatedAt = state.Generation+1, state.Fence+1, toController, at
	if state.Phase != PhaseDiscovered {
		result, err := tx.ExecContext(ctx, `UPDATE product_update_node_locks SET fence = ? WHERE node_id = ? AND manifest_id = ? AND fence = ?`,
			next.Fence, nodeID, manifestID, state.Fence)
		if err != nil || !oneRow(result) { return UpdateState{}, Receipt{}, ErrConflict }
	}
	receipt, err := buildReceipt(manifestID, nodeID, state.Phase, state.Phase, next.Generation, next.Fence,
		idempotencyKey, commandDigest, state.LastReceiptDigest, state.Reason, at)
	if err != nil { return UpdateState{}, Receipt{}, err }
	next.LastReceiptDigest = receipt.Digest
	if err := updateState(ctx, tx, state, next); err != nil { return UpdateState{}, Receipt{}, err }
	if err := insertReceipt(ctx, tx, receipt); err != nil { return UpdateState{}, Receipt{}, err }
	if err := tx.Commit(); err != nil { return UpdateState{}, Receipt{}, err }
	return next, receipt, nil
}

func (repository *Repository) Get(ctx context.Context, manifestID, nodeID string) (ReleaseManifest, UpdateState, error) {
	if !identifierPattern.MatchString(manifestID) || !identifierPattern.MatchString(nodeID) { return ReleaseManifest{}, UpdateState{}, ErrInvalid }
	manifest, err := loadManifest(ctx, repository.db, manifestID)
	if err != nil { return ReleaseManifest{}, UpdateState{}, err }
	state, err := loadState(ctx, repository.db, manifestID, nodeID)
	if err == nil && (state.ManifestID != manifest.ID || state.ManifestDigest != manifest.Digest) { return ReleaseManifest{}, UpdateState{}, ErrIntegrity }
	return manifest, state, err
}

func (repository *Repository) AcceptedSequence(ctx context.Context, nodeID string, tuple PlatformTuple) (uint64, string, error) {
	if !identifierPattern.MatchString(nodeID) || tuple.Validate() != nil { return 0, "", ErrInvalid }
	var sequence uint64
	var digest string
	err := repository.db.QueryRowContext(ctx, `SELECT sequence, manifest_digest FROM product_update_sequences WHERE node_id = ? AND tuple_key = ?`, nodeID, tuple.key()).Scan(&sequence, &digest)
	if errors.Is(err, sql.ErrNoRows) { return 0, "", nil }
	if err != nil || sequence == 0 || !validDigest(digest) { if err != nil { return 0, "", err }; return 0, "", ErrIntegrity }
	return sequence, digest, nil
}

func (repository *Repository) List(ctx context.Context, phase Phase, afterManifest, afterNode string, limit int) ([]UpdateState, error) {
	if limit <= 0 || limit > MaxPageSize || phase != "" && !validPhase(phase) ||
		afterManifest != "" && !identifierPattern.MatchString(afterManifest) || afterNode != "" && !identifierPattern.MatchString(afterNode) ||
		afterManifest == "" && afterNode != "" { return nil, ErrInvalid }
	rows, err := repository.db.QueryContext(ctx, `SELECT storage_digest, state_json FROM product_update_states
		WHERE (? = '' OR phase = ?) AND (manifest_id > ? OR (manifest_id = ? AND node_id > ?))
		ORDER BY manifest_id, node_id LIMIT ?`, string(phase), string(phase), afterManifest, afterManifest, afterNode, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	states := make([]UpdateState, 0, limit)
	for rows.Next() {
		var storage string
		var raw []byte
		if err := rows.Scan(&storage, &raw); err != nil { return nil, err }
		state, err := decodeState(raw, storage)
		if err != nil { return nil, err }
		states = append(states, state)
	}
	return states, rows.Err()
}

func (repository *Repository) ListReceipts(ctx context.Context, manifestID, nodeID, afterID string, limit int) ([]Receipt, error) {
	if !identifierPattern.MatchString(manifestID) || !identifierPattern.MatchString(nodeID) ||
		afterID != "" && !validDigest(afterID) || limit <= 0 || limit > MaxPageSize { return nil, ErrInvalid }
	rows, err := repository.db.QueryContext(ctx, `SELECT storage_digest, receipt_json FROM product_update_receipts
		WHERE manifest_id = ? AND node_id = ? AND id > ? ORDER BY id LIMIT ?`, manifestID, nodeID, afterID, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	receipts := make([]Receipt, 0, limit)
	for rows.Next() {
		var storage string
		var raw []byte
		if err := rows.Scan(&storage, &raw); err != nil { return nil, err }
		receipt, err := decodeReceipt(raw, storage)
		if err != nil { return nil, err }
		receipts = append(receipts, receipt)
	}
	return receipts, rows.Err()
}

func (repository *Repository) replay(ctx context.Context, manifestID, nodeID, idempotencyKey string) (UpdateState, Receipt, bool, error) {
	receipt, found, err := loadReceipt(ctx, repository.db, manifestID, nodeID, idempotencyKey)
	if err != nil || !found { return UpdateState{}, Receipt{}, found, err }
	manifest, state, err := repository.Get(ctx, manifestID, nodeID)
	if err != nil { return UpdateState{}, Receipt{}, false, err }
	if state.ManifestDigest != manifest.Digest || receipt.ManifestID != manifestID || receipt.NodeID != nodeID { return UpdateState{}, Receipt{}, false, ErrIntegrity }
	return state, receipt, true, nil
}

type queryer interface { QueryRowContext(context.Context, string, ...any) *sql.Row }

func loadTransitionContext(ctx context.Context, tx *sql.Tx, command Transition, commandDigest string) (UpdateState, ReleaseManifest, Receipt, bool, error) {
	if receipt, found, err := loadReceipt(ctx, tx, command.ManifestID, command.NodeID, command.IdempotencyKey); err != nil {
		return UpdateState{}, ReleaseManifest{}, Receipt{}, false, err
	} else if found {
		if receipt.CommandDigest != commandDigest { return UpdateState{}, ReleaseManifest{}, Receipt{}, false, ErrIntegrity }
		state, err := loadState(ctx, tx, command.ManifestID, command.NodeID)
		if err != nil { return UpdateState{}, ReleaseManifest{}, Receipt{}, false, err }
		manifest, err := loadManifest(ctx, tx, command.ManifestID)
		if err != nil || state.ManifestDigest != manifest.Digest { if err != nil { return UpdateState{}, ReleaseManifest{}, Receipt{}, false, err }; return UpdateState{}, ReleaseManifest{}, Receipt{}, false, ErrIntegrity }
		return state, manifest, receipt, true, nil
	}
	manifest, err := loadManifest(ctx, tx, command.ManifestID)
	if err != nil { return UpdateState{}, ReleaseManifest{}, Receipt{}, false, err }
	state, err := loadState(ctx, tx, command.ManifestID, command.NodeID)
	return state, manifest, Receipt{}, false, err
}

func admitUpdate(ctx context.Context, tx *sql.Tx, nodeID string, manifest ReleaseManifest, fence uint64) error {
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO product_update_node_locks (node_id, manifest_id, fence) VALUES (?, ?, ?)`, nodeID, manifest.ID, fence)
	if err != nil { return err }
	if !oneRow(result) {
		var owner string
		var storedFence uint64
		if err := tx.QueryRowContext(ctx, `SELECT manifest_id, fence FROM product_update_node_locks WHERE node_id = ?`, nodeID).Scan(&owner, &storedFence); err != nil { return err }
		if owner != manifest.ID || storedFence != fence { return ErrConflict }
	}
	var sequence uint64
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT sequence, manifest_digest FROM product_update_sequences WHERE node_id = ? AND tuple_key = ?`, nodeID, manifest.Platform.key()).Scan(&sequence, &digest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) { return err }
	if err == nil && (manifest.Sequence < sequence || manifest.Sequence == sequence && manifest.Digest != digest) { return ErrConflict }
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `INSERT INTO product_update_sequences (node_id, tuple_key, sequence, manifest_digest) VALUES (?, ?, ?, ?)`, nodeID, manifest.Platform.key(), manifest.Sequence, manifest.Digest)
		return err
	}
	if manifest.Sequence > sequence {
		result, err = tx.ExecContext(ctx, `UPDATE product_update_sequences SET sequence = ?, manifest_digest = ? WHERE node_id = ? AND tuple_key = ? AND sequence = ?`,
			manifest.Sequence, manifest.Digest, nodeID, manifest.Platform.key(), sequence)
		if err != nil || !oneRow(result) { return ErrConflict }
	}
	return nil
}

func canonicalTransition(command Transition) (Transition, string, error) {
	if !identifierPattern.MatchString(command.ManifestID) || !identifierPattern.MatchString(command.NodeID) ||
		!identifierPattern.MatchString(command.ControllerID) || !identifierPattern.MatchString(command.IdempotencyKey) ||
		command.ExpectedGeneration == 0 || command.ExpectedGeneration > maxGeneration || command.Fence == 0 || command.Fence > maxGeneration || !validTransition(command.From, command.To) ||
		!validReason(command.Reason) || !validDigest(command.EvidenceDigest) || !validTime(command.At) || len(command.RecoverySteps) > 32 {
		return Transition{}, "", ErrInvalid
	}
	if command.StagedRootID != "" && (!identifierPattern.MatchString(command.StagedRootID) || !validDigest(command.StagedRootDigest)) { return Transition{}, "", ErrInvalid }
	if command.PreviousReleaseID != "" && (!identifierPattern.MatchString(command.PreviousReleaseID) || !validDigest(command.PreviousReleaseDigest)) { return Transition{}, "", ErrInvalid }
	if command.BaselineDigest != "" && !validDigest(command.BaselineDigest) || command.MigrationEvidence != "" && !validDigest(command.MigrationEvidence) { return Transition{}, "", ErrInvalid }
	if len(command.MigrationProofs) > 256 { return Transition{}, "", ErrInvalid }
	for index, proof := range command.MigrationProofs {
		if !identifierPattern.MatchString(proof.StepID) || !validDigest(proof.OperationDigest) || !validDigest(proof.AssessmentDigest) ||
			proof.BackupEvidence != "" && !validDigest(proof.BackupEvidence) || !validDigest(proof.ApplyReceiptDigest) ||
			index > 0 && command.MigrationProofs[index-1].StepID >= proof.StepID { return Transition{}, "", ErrInvalid }
	}
	if command.RollbackEvidence != "" && !validDigest(command.RollbackEvidence) || command.RecoveryEvidence != "" && !validDigest(command.RecoveryEvidence) { return Transition{}, "", ErrInvalid }
	command.RecoverySteps = append([]string(nil), command.RecoverySteps...)
	sort.Strings(command.RecoverySteps)
	for index, step := range command.RecoverySteps {
		if !identifierPattern.MatchString(step) || index > 0 && command.RecoverySteps[index-1] == step { return Transition{}, "", ErrInvalid }
	}
	command.At = command.At.UTC()
	digest, err := digestJSON(command)
	return command, digest, err
}

func validReason(reason ReasonCode) bool {
	switch reason {
	case ReasonNone, ReasonVerified, ReasonStaged, ReasonPreflighted, ReasonSwitched, ReasonHealthy,
		ReasonHealthRegression, ReasonRolledBack, ReasonUnprovenRollback, ReasonExternalUncertain, ReasonRejected:
		return true
	default: return false
	}
}

func validPhase(phase Phase) bool {
	switch phase {
	case PhaseDiscovered, PhaseVerified, PhaseStaged, PhasePreflighted, PhaseSwitched, PhaseProbing,
		PhaseCommitted, PhaseRolledBack, PhaseFailed, PhaseUncertain:
		return true
	default: return false
	}
}

func buildReceipt(manifestID, nodeID string, from, to Phase, generation, fence uint64, key, commandDigest, evidence string, reason ReasonCode, at time.Time) (Receipt, error) {
	receipt := Receipt{ManifestID: manifestID, NodeID: nodeID, From: from, To: to, Generation: generation,
		Fence: fence, IdempotencyKey: key, CommandDigest: commandDigest, EvidenceDigest: evidence, Reason: reason, CreatedAt: at.UTC()}
	receipt.ID = digestParts("product-update-receipt", manifestID, nodeID, key, commandDigest)
	digest, err := digestJSON(receipt)
	if err != nil { return Receipt{}, err }
	receipt.Digest = digest
	return receipt, nil
}

func loadManifest(ctx context.Context, query queryer, id string) (ReleaseManifest, error) {
	var claimedDigest, storage string
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT manifest_digest, storage_digest, manifest_json FROM product_update_manifests WHERE id = ?`, id).Scan(&claimedDigest, &storage, &raw)
	if errors.Is(err, sql.ErrNoRows) { return ReleaseManifest{}, ErrNotFound }
	if err != nil { return ReleaseManifest{}, err }
	if digestBytes(raw) != storage { return ReleaseManifest{}, ErrIntegrity }
	var manifest ReleaseManifest
	if json.Unmarshal(raw, &manifest) != nil { return ReleaseManifest{}, ErrIntegrity }
	manifest, err = CanonicalManifest(manifest)
	if err != nil || manifest.Digest != claimedDigest { return ReleaseManifest{}, ErrIntegrity }
	return manifest, nil
}

func loadState(ctx context.Context, query queryer, manifestID, nodeID string) (UpdateState, error) {
	var storage string
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT storage_digest, state_json FROM product_update_states WHERE manifest_id = ? AND node_id = ?`, manifestID, nodeID).Scan(&storage, &raw)
	if errors.Is(err, sql.ErrNoRows) { return UpdateState{}, ErrNotFound }
	if err != nil { return UpdateState{}, err }
	return decodeState(raw, storage)
}

func decodeState(raw []byte, storage string) (UpdateState, error) {
	if digestBytes(raw) != storage { return UpdateState{}, ErrIntegrity }
	var state UpdateState
	if json.Unmarshal(raw, &state) != nil || !identifierPattern.MatchString(state.ManifestID) || !validDigest(state.ManifestDigest) ||
		!identifierPattern.MatchString(state.NodeID) || state.Generation == 0 || state.Generation > maxGeneration || state.Fence == 0 || state.Fence > maxGeneration || !identifierPattern.MatchString(state.ControllerID) ||
		!validDigest(state.LastReceiptDigest) || !validTime(state.UpdatedAt) { return UpdateState{}, ErrIntegrity }
	if state.StagedRootID != "" && (!identifierPattern.MatchString(state.StagedRootID) || !validDigest(state.StagedRootDigest)) ||
		state.PreviousReleaseID != "" && (!identifierPattern.MatchString(state.PreviousReleaseID) || !validDigest(state.PreviousReleaseDigest)) ||
		state.BaselineDigest != "" && !validDigest(state.BaselineDigest) || state.MigrationEvidence != "" && !validDigest(state.MigrationEvidence) ||
		state.RollbackEvidence != "" && !validDigest(state.RollbackEvidence) || state.RecoveryEvidence != "" && !validDigest(state.RecoveryEvidence) {
		return UpdateState{}, ErrIntegrity
	}
	if len(state.MigrationProofs) > 256 { return UpdateState{}, ErrIntegrity }
	for index, proof := range state.MigrationProofs {
		if !identifierPattern.MatchString(proof.StepID) || !validDigest(proof.OperationDigest) || !validDigest(proof.AssessmentDigest) ||
			proof.BackupEvidence != "" && !validDigest(proof.BackupEvidence) || !validDigest(proof.ApplyReceiptDigest) ||
			index > 0 && state.MigrationProofs[index-1].StepID >= proof.StepID { return UpdateState{}, ErrIntegrity }
	}
	return state, nil
}

func loadReceipt(ctx context.Context, query queryer, manifestID, nodeID, key string) (Receipt, bool, error) {
	var storage string
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT storage_digest, receipt_json FROM product_update_receipts WHERE manifest_id = ? AND node_id = ? AND idempotency_key = ?`, manifestID, nodeID, key).Scan(&storage, &raw)
	if errors.Is(err, sql.ErrNoRows) { return Receipt{}, false, nil }
	if err != nil { return Receipt{}, false, err }
	receipt, err := decodeReceipt(raw, storage)
	return receipt, true, err
}

func decodeReceipt(raw []byte, storage string) (Receipt, error) {
	if digestBytes(raw) != storage { return Receipt{}, ErrIntegrity }
	var receipt Receipt
	if json.Unmarshal(raw, &receipt) != nil { return Receipt{}, ErrIntegrity }
	claimed := receipt.Digest
	receipt.Digest = ""
	digest, err := digestJSON(receipt)
	receipt.Digest = claimed
	if err != nil || claimed != digest || !validDigest(receipt.ID) || !identifierPattern.MatchString(receipt.ManifestID) ||
		!identifierPattern.MatchString(receipt.NodeID) || !validPhase(receipt.From) || !validPhase(receipt.To) || receipt.Generation == 0 ||
		receipt.Fence == 0 || !identifierPattern.MatchString(receipt.IdempotencyKey) || !validDigest(receipt.CommandDigest) ||
		!validDigest(receipt.EvidenceDigest) || !validReason(receipt.Reason) || !validTime(receipt.CreatedAt) { return Receipt{}, ErrIntegrity }
	return receipt, nil
}

func insertState(ctx context.Context, tx *sql.Tx, state UpdateState) error {
	raw, storage, err := encodeStored(state)
	if err != nil { return err }
	_, err = tx.ExecContext(ctx, `INSERT INTO product_update_states
		(manifest_id, node_id, phase, generation, fence, controller_id, storage_digest, state_json, updated_unix_nano)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, state.ManifestID, state.NodeID, state.Phase, state.Generation,
		state.Fence, state.ControllerID, storage, raw, state.UpdatedAt.UnixNano())
	return err
}

func updateState(ctx context.Context, tx *sql.Tx, prior, next UpdateState) error {
	raw, storage, err := encodeStored(next)
	if err != nil { return err }
	result, err := tx.ExecContext(ctx, `UPDATE product_update_states SET phase = ?, generation = ?, fence = ?, controller_id = ?,
		storage_digest = ?, state_json = ?, updated_unix_nano = ? WHERE manifest_id = ? AND node_id = ? AND generation = ? AND fence = ?`,
		next.Phase, next.Generation, next.Fence, next.ControllerID, storage, raw, next.UpdatedAt.UnixNano(),
		next.ManifestID, next.NodeID, prior.Generation, prior.Fence)
	if err != nil { return err }
	if !oneRow(result) { return ErrConflict }
	return nil
}

func insertReceipt(ctx context.Context, tx *sql.Tx, receipt Receipt) error {
	raw, storage, err := encodeStored(receipt)
	if err != nil { return err }
	_, err = tx.ExecContext(ctx, `INSERT INTO product_update_receipts
		(id, manifest_id, node_id, idempotency_key, command_digest, storage_digest, receipt_json, created_unix_nano)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, receipt.ID, receipt.ManifestID, receipt.NodeID, receipt.IdempotencyKey,
		receipt.CommandDigest, storage, raw, receipt.CreatedAt.UnixNano())
	return err
}

func encodeStored(value any) ([]byte, string, error) {
	raw, err := json.Marshal(value)
	if err != nil { return nil, "", err }
	return raw, digestBytes(raw), nil
}

func digestBytes(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func oneRow(result sql.Result) bool {
	rows, err := result.RowsAffected()
	return err == nil && rows == 1
}

func fmtUint(value uint64) string {
	if value == 0 { return "0" }
	buffer := make([]byte, 20)
	index := len(buffer)
	for value > 0 { index--; buffer[index] = byte('0' + value%10); value /= 10 }
	return string(buffer[index:])
}
