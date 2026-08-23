package redisservice

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type OperationState string

const (
	OperationAdmitted    OperationState = "admitted"
	OperationRunning     OperationState = "running"
	OperationSucceeded   OperationState = "succeeded"
	OperationFailed      OperationState = "failed"
	OperationCompensated OperationState = "compensated"
	OperationAmbiguous   OperationState = "ambiguous"
)

type Operation struct {
	ID            string                `json:"id"`
	PlanID        string                `json:"plan_id"`
	PlanDigest    string                `json:"plan_digest"`
	State         OperationState        `json:"state"`
	Version       uint64                `json:"version"`
	Authorization AuthorizationEvidence `json:"authorization"`
	Maintenance   *MaintenanceEvidence  `json:"maintenance,omitempty"`
	ReceiptID     string                `json:"receipt_id,omitempty"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

type ListFilter struct {
	NodeID   string
	TenantID string
	Scope    Scope
	AfterID  InstanceID
	Limit    int
}

type InstanceRecord struct {
	Spec     InstanceSpec         `json:"spec"`
	Observed *InstanceObservation `json:"observed,omitempty"`
}

type Repository interface {
	PutSpec(context.Context, InstanceSpec, uint64) error
	Spec(context.Context, InstanceID) (InstanceSpec, error)
	List(context.Context, ListFilter) ([]InstanceRecord, error)
	Inspect(context.Context, InstanceID) (InstanceRecord, error)
	PutObservation(context.Context, InstanceObservation, uint64) error
	Observation(context.Context, InstanceID) (InstanceObservation, error)
	Status(context.Context, InstanceID) (InstanceObservation, error)
	PutConsumerSnapshot(context.Context, ConsumerSnapshot, uint64) error
	ConsumerSnapshot(context.Context, InstanceID) (ConsumerSnapshot, error)
	PutPlan(context.Context, LifecyclePlan) error
	Plan(context.Context, string) (LifecyclePlan, error)
	PutArtifact(context.Context, ArtifactDescriptor) error
	Artifact(context.Context, string) (ArtifactDescriptor, error)
	AdmitOperation(context.Context, Operation, AuditEvent) error
	Operation(context.Context, string) (Operation, error)
	TransitionOperation(context.Context, string, OperationState, uint64, OperationState, string, AuditEvent) (Operation, error)
	PutReceipt(context.Context, LifecycleReceipt, AuditEvent) error
	Receipt(context.Context, string) (LifecycleReceipt, error)
}

type SQLiteRepository struct {
	db *sql.DB
}

func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: nil database", ErrInvalid)
	}
	return &SQLiteRepository{db: db}, nil
}

func (r *SQLiteRepository) Init(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS redis_instance_specs (
			instance_id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			scope TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			config_generation INTEGER NOT NULL,
			digest TEXT NOT NULL,
			payload BLOB NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS redis_instance_observed (
			instance_id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			config_generation INTEGER NOT NULL,
			evidence_digest TEXT NOT NULL,
			payload BLOB NOT NULL,
			observed_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS redis_consumer_snapshots (
			instance_id TEXT PRIMARY KEY,
			generation INTEGER NOT NULL CHECK (generation > 0),
			evidence_digest TEXT NOT NULL,
			payload BLOB NOT NULL,
			observed_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS redis_plan_heads (
			instance_id TEXT PRIMARY KEY,
			generation INTEGER NOT NULL CHECK (generation > 0),
			plan_id TEXT NOT NULL,
			plan_digest TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS redis_plans (
			plan_id TEXT PRIMARY KEY,
			instance_id TEXT NOT NULL,
			generation INTEGER NOT NULL,
			digest TEXT NOT NULL UNIQUE,
			payload BLOB NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS redis_artifacts (
			artifact_id TEXT PRIMARY KEY,
			group_id TEXT NOT NULL,
			instance_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			sha256 TEXT NOT NULL,
			payload BLOB NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS redis_operations (
			operation_id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL,
			plan_digest TEXT NOT NULL,
			state TEXT NOT NULL,
			version INTEGER NOT NULL CHECK (version > 0),
			authorization_payload BLOB NOT NULL,
			maintenance_payload BLOB,
			receipt_id TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY (plan_id) REFERENCES redis_plans(plan_id)
		)`,
		`CREATE TABLE IF NOT EXISTS redis_receipts (
			receipt_id TEXT PRIMARY KEY,
			operation_id TEXT NOT NULL UNIQUE,
			plan_id TEXT NOT NULL,
			plan_digest TEXT NOT NULL,
			outcome TEXT NOT NULL,
			evidence_digest TEXT NOT NULL,
			payload BLOB NOT NULL,
			completed_at TEXT NOT NULL,
			FOREIGN KEY (operation_id) REFERENCES redis_operations(operation_id)
		)`,
		`CREATE TABLE IF NOT EXISTS redis_audit (
			event_id TEXT PRIMARY KEY,
			operation_id TEXT NOT NULL,
			actor_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			resource TEXT NOT NULL,
			request_digest TEXT NOT NULL,
			evidence_digest TEXT NOT NULL,
			occurred_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS redis_specs_list_idx ON redis_instance_specs(node_id, tenant_id, scope, instance_id)`,
		`CREATE INDEX IF NOT EXISTS redis_artifacts_group_idx ON redis_artifacts(group_id, instance_id)`,
	}
	for _, statement := range statements {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize Redis repository: %w", err)
		}
	}
	return nil
}

func boundedJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode repository payload: %v", ErrInvalid, err)
	}
	if len(encoded) == 0 || len(encoded) > MaxRepositoryBytes {
		return nil, fmt.Errorf("%w: repository payload exceeds bounds", ErrInvalid)
	}
	return encoded, nil
}

func decodeBounded(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxRepositoryBytes {
		return fmt.Errorf("%w: stored payload exceeds bounds", ErrInvalid)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%w: decode stored payload: %v", ErrInvalid, err)
	}
	return nil
}

func (r *SQLiteRepository) PutSpec(ctx context.Context, spec InstanceSpec, expectedGeneration uint64) error {
	sealed, err := SealInstanceSpec(spec)
	if err != nil || sealed.Digest != spec.Digest || expectedGeneration > MaxGeneration || spec.Generation != expectedGeneration+1 {
		return fmt.Errorf("%w: spec generation or digest", ErrStale)
	}
	payload, err := boundedJSON(spec)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current uint64
	err = tx.QueryRowContext(ctx, `SELECT generation FROM redis_instance_specs WHERE instance_id = ?`, spec.ID).Scan(&current)
	exists := true
	if err == sql.ErrNoRows {
		exists = false
		current = 0
	} else if err != nil {
		return err
	}
	if current != expectedGeneration || exists != (expectedGeneration != 0) {
		return ErrConflict
	}
	var result sql.Result
	if exists {
		result, err = tx.ExecContext(ctx,
			`UPDATE redis_instance_specs SET node_id = ?, tenant_id = ?, scope = ?, generation = ?, config_generation = ?, digest = ?, payload = ?, updated_at = ? WHERE instance_id = ? AND generation = ?`,
			spec.NodeID, spec.TenantID, spec.Scope, spec.Generation, spec.ConfigGeneration, spec.Digest, payload, spec.UpdatedAt.UTC().Format(time.RFC3339Nano), spec.ID, expectedGeneration)
	} else {
		result, err = tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO redis_instance_specs(instance_id, node_id, tenant_id, scope, generation, config_generation, digest, payload, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			spec.ID, spec.NodeID, spec.TenantID, spec.Scope, spec.Generation, spec.ConfigGeneration, spec.Digest, payload, spec.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (r *SQLiteRepository) Spec(ctx context.Context, id InstanceID) (InstanceSpec, error) {
	if !instanceIDPattern.MatchString(string(id)) {
		return InstanceSpec{}, fmt.Errorf("%w: instance id", ErrInvalid)
	}
	var payload []byte
	if err := r.db.QueryRowContext(ctx, `SELECT payload FROM redis_instance_specs WHERE instance_id = ?`, id).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return InstanceSpec{}, ErrNotFound
		}
		return InstanceSpec{}, err
	}
	var spec InstanceSpec
	if err := decodeBounded(payload, &spec); err != nil {
		return InstanceSpec{}, err
	}
	sealed, err := SealInstanceSpec(spec)
	if err != nil || sealed.Digest != spec.Digest {
		return InstanceSpec{}, fmt.Errorf("%w: stored spec digest", ErrInvalid)
	}
	return spec, nil
}

func validateListFilter(filter ListFilter) error {
	if filter.Limit <= 0 || filter.Limit > MaxInstances {
		return fmt.Errorf("%w: list limit", ErrInvalid)
	}
	if filter.NodeID != "" && !validID(filter.NodeID) {
		return fmt.Errorf("%w: list node", ErrInvalid)
	}
	if filter.TenantID != "" && !validID(filter.TenantID) {
		return fmt.Errorf("%w: list tenant", ErrInvalid)
	}
	if filter.Scope != "" && filter.Scope != ScopeTenant && filter.Scope != ScopeNode {
		return fmt.Errorf("%w: list scope", ErrInvalid)
	}
	if filter.AfterID != "" && !validID(string(filter.AfterID)) {
		return fmt.Errorf("%w: list cursor", ErrInvalid)
	}
	return nil
}

func (r *SQLiteRepository) List(ctx context.Context, filter ListFilter) ([]InstanceRecord, error) {
	if err := validateListFilter(filter); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT payload FROM redis_instance_specs
		 WHERE (? = '' OR node_id = ?) AND (? = '' OR tenant_id = ?) AND (? = '' OR scope = ?) AND instance_id > ?
		 ORDER BY instance_id ASC LIMIT ?`,
		filter.NodeID, filter.NodeID, filter.TenantID, filter.TenantID, filter.Scope, filter.Scope, filter.AfterID, filter.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]InstanceRecord, 0, filter.Limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var spec InstanceSpec
		if err := decodeBounded(payload, &spec); err != nil {
			return nil, err
		}
		sealed, err := SealInstanceSpec(spec)
		if err != nil || sealed.Digest != spec.Digest {
			return nil, fmt.Errorf("%w: listed spec digest", ErrInvalid)
		}
		records = append(records, InstanceRecord{Spec: spec})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range records {
		observation, observationErr := r.Observation(ctx, records[index].Spec.ID)
		if observationErr == nil {
			records[index].Observed = &observation
		} else if observationErr != ErrNotFound {
			return nil, observationErr
		}
	}
	return records, nil
}

func (r *SQLiteRepository) Inspect(ctx context.Context, id InstanceID) (InstanceRecord, error) {
	spec, err := r.Spec(ctx, id)
	if err != nil {
		return InstanceRecord{}, err
	}
	record := InstanceRecord{Spec: spec}
	observed, observedErr := r.Observation(ctx, id)
	if observedErr == nil {
		record.Observed = &observed
	} else if observedErr != ErrNotFound {
		return InstanceRecord{}, observedErr
	}
	return record, nil
}

func (r *SQLiteRepository) PutObservation(ctx context.Context, observation InstanceObservation, expectedGeneration uint64) error {
	sealed, err := SealObservation(observation)
	if err != nil || sealed.EvidenceDigest != observation.EvidenceDigest || expectedGeneration > MaxGeneration || observation.Generation != expectedGeneration+1 {
		return fmt.Errorf("%w: observation generation or digest", ErrStale)
	}
	payload, err := boundedJSON(observation)
	if err != nil {
		return err
	}
	return r.putCASPayload(ctx, "observation", string(observation.InstanceID), observation.NodeID, observation.ConfigGeneration, observation.Generation, expectedGeneration, observation.EvidenceDigest, payload, observation.ObservedAt)
}

func (r *SQLiteRepository) Observation(ctx context.Context, id InstanceID) (InstanceObservation, error) {
	if !instanceIDPattern.MatchString(string(id)) {
		return InstanceObservation{}, fmt.Errorf("%w: instance id", ErrInvalid)
	}
	var payload []byte
	if err := r.db.QueryRowContext(ctx, `SELECT payload FROM redis_instance_observed WHERE instance_id = ?`, id).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return InstanceObservation{}, ErrNotFound
		}
		return InstanceObservation{}, err
	}
	var observation InstanceObservation
	if err := decodeBounded(payload, &observation); err != nil {
		return InstanceObservation{}, err
	}
	sealed, err := SealObservation(observation)
	if err != nil || sealed.EvidenceDigest != observation.EvidenceDigest {
		return InstanceObservation{}, fmt.Errorf("%w: stored observation digest", ErrInvalid)
	}
	return observation, nil
}

func (r *SQLiteRepository) Status(ctx context.Context, id InstanceID) (InstanceObservation, error) {
	return r.Observation(ctx, id)
}

func (r *SQLiteRepository) PutConsumerSnapshot(ctx context.Context, snapshot ConsumerSnapshot, expectedGeneration uint64) error {
	sealed, err := SealConsumerSnapshot(snapshot)
	if err != nil || sealed.EvidenceDigest != snapshot.EvidenceDigest || expectedGeneration > MaxGeneration || snapshot.Generation != expectedGeneration+1 {
		return fmt.Errorf("%w: consumer snapshot generation or digest", ErrStale)
	}
	payload, err := boundedJSON(snapshot)
	if err != nil {
		return err
	}
	return r.putCASPayload(ctx, "consumers", string(snapshot.InstanceID), "", 0, snapshot.Generation, expectedGeneration, snapshot.EvidenceDigest, payload, snapshot.ObservedAt)
}

func (r *SQLiteRepository) ConsumerSnapshot(ctx context.Context, id InstanceID) (ConsumerSnapshot, error) {
	if !instanceIDPattern.MatchString(string(id)) {
		return ConsumerSnapshot{}, fmt.Errorf("%w: instance id", ErrInvalid)
	}
	var payload []byte
	if err := r.db.QueryRowContext(ctx, `SELECT payload FROM redis_consumer_snapshots WHERE instance_id = ?`, id).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return ConsumerSnapshot{}, ErrNotFound
		}
		return ConsumerSnapshot{}, err
	}
	var snapshot ConsumerSnapshot
	if err := decodeBounded(payload, &snapshot); err != nil {
		return ConsumerSnapshot{}, err
	}
	sealed, err := SealConsumerSnapshot(snapshot)
	if err != nil || sealed.EvidenceDigest != snapshot.EvidenceDigest {
		return ConsumerSnapshot{}, fmt.Errorf("%w: stored consumer snapshot digest", ErrInvalid)
	}
	return snapshot, nil
}

func (r *SQLiteRepository) putCASPayload(ctx context.Context, kind, id, nodeID string, configGeneration, generation, expected uint64, evidence string, payload []byte, observedAt time.Time) error {
	var table string
	switch kind {
	case "observation":
		table = "redis_instance_observed"
	case "consumers":
		table = "redis_consumer_snapshots"
	default:
		return fmt.Errorf("%w: CAS payload kind", ErrInvalid)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current uint64
	err = tx.QueryRowContext(ctx, `SELECT generation FROM `+table+` WHERE instance_id = ?`, id).Scan(&current)
	exists := true
	if err == sql.ErrNoRows {
		exists = false
		current = 0
	} else if err != nil {
		return err
	}
	if current != expected || exists != (expected != 0) {
		return ErrConflict
	}
	var result sql.Result
	if kind == "observation" && exists {
		result, err = tx.ExecContext(ctx, `UPDATE redis_instance_observed SET node_id = ?, generation = ?, config_generation = ?, evidence_digest = ?, payload = ?, observed_at = ? WHERE instance_id = ? AND generation = ?`, nodeID, generation, configGeneration, evidence, payload, observedAt.UTC().Format(time.RFC3339Nano), id, expected)
	} else if kind == "observation" {
		result, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO redis_instance_observed(instance_id, node_id, generation, config_generation, evidence_digest, payload, observed_at) VALUES(?, ?, ?, ?, ?, ?, ?)`, id, nodeID, generation, configGeneration, evidence, payload, observedAt.UTC().Format(time.RFC3339Nano))
	} else if exists {
		result, err = tx.ExecContext(ctx, `UPDATE redis_consumer_snapshots SET generation = ?, evidence_digest = ?, payload = ?, observed_at = ? WHERE instance_id = ? AND generation = ?`, generation, evidence, payload, observedAt.UTC().Format(time.RFC3339Nano), id, expected)
	} else {
		result, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO redis_consumer_snapshots(instance_id, generation, evidence_digest, payload, observed_at) VALUES(?, ?, ?, ?, ?)`, id, generation, evidence, payload, observedAt.UTC().Format(time.RFC3339Nano))
	}
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (r *SQLiteRepository) PutPlan(ctx context.Context, plan LifecyclePlan) error {
	sealed, err := SealLifecyclePlan(plan)
	if err != nil || sealed.Digest != plan.Digest {
		return fmt.Errorf("%w: lifecycle plan digest", ErrInvalid)
	}
	payload, err := boundedJSON(plan)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var specGeneration uint64
	var specDigest string
	if err := tx.QueryRowContext(ctx, `SELECT generation, digest FROM redis_instance_specs WHERE instance_id = ?`, plan.InstanceID).Scan(&specGeneration, &specDigest); err != nil {
		if err == sql.ErrNoRows {
			return ErrStale
		}
		return err
	}
	var observedGeneration, configGeneration uint64
	var observedPayload []byte
	if err := tx.QueryRowContext(ctx, `SELECT generation, config_generation, payload FROM redis_instance_observed WHERE instance_id = ?`, plan.InstanceID).Scan(&observedGeneration, &configGeneration, &observedPayload); err != nil {
		if err == sql.ErrNoRows {
			return ErrStale
		}
		return err
	}
	if specGeneration != plan.ExpectedSpecGeneration || specDigest != plan.TargetSpecDigest || observedGeneration != plan.ExpectedObservedGeneration || configGeneration != plan.ExpectedConfigGeneration {
		return ErrStale
	}
	var observed InstanceObservation
	if err := decodeBounded(observedPayload, &observed); err != nil {
		return ErrStale
	}
	sealedObserved, observedErr := SealObservation(observed)
	if observedErr != nil || sealedObserved.EvidenceDigest != observed.EvidenceDigest || plan.Recovery.PriorConfigGeneration != observed.ConfigGeneration || plan.Recovery.PriorConfigDigest != observed.ActualConfigDigest {
		return ErrStale
	}
	if plan.ConsumerSnapshotGeneration != 0 {
		var generation uint64
		var digest string
		if err := tx.QueryRowContext(ctx, `SELECT generation, evidence_digest FROM redis_consumer_snapshots WHERE instance_id = ?`, plan.InstanceID).Scan(&generation, &digest); err != nil {
			return ErrStale
		}
		if generation != plan.ConsumerSnapshotGeneration || digest != plan.ConsumerSnapshotDigest {
			return ErrStale
		}
	}
	if plan.Artifact != nil {
		var artifactPayload []byte
		if err := tx.QueryRowContext(ctx, `SELECT payload FROM redis_artifacts WHERE artifact_id = ?`, plan.Artifact.ID).Scan(&artifactPayload); err != nil {
			return ErrStale
		}
		var artifact ArtifactDescriptor
		if err := decodeBounded(artifactPayload, &artifact); err != nil {
			return err
		}
		storedDigest, digestErr := digestValue(artifact)
		plannedDigest, plannedErr := digestValue(*plan.Artifact)
		if digestErr != nil || plannedErr != nil || storedDigest != plannedDigest {
			return ErrStale
		}
	}
	if plan.Recovery.RecoveryArtifactRef != "" {
		var recoveryPayload []byte
		if err := tx.QueryRowContext(ctx, `SELECT payload FROM redis_artifacts WHERE artifact_id = ?`, plan.Recovery.RecoveryArtifactRef).Scan(&recoveryPayload); err != nil {
			return ErrStale
		}
		var recovery ArtifactDescriptor
		if err := decodeBounded(recoveryPayload, &recovery); err != nil || validateArtifact(recovery) != nil || recovery.ID != plan.Recovery.RecoveryArtifactRef || recovery.InstanceID != plan.InstanceID || recovery.ConfigGeneration != plan.ExpectedConfigGeneration || (plan.Artifact != nil && recovery.ID == plan.Artifact.ID) {
			return ErrStale
		}
	}
	var head uint64
	err = tx.QueryRowContext(ctx, `SELECT generation FROM redis_plan_heads WHERE instance_id = ?`, plan.InstanceID).Scan(&head)
	headExists := true
	if err == sql.ErrNoRows {
		headExists = false
		head = 0
	} else if err != nil {
		return err
	}
	if plan.Generation != head+1 {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO redis_plans(plan_id, instance_id, generation, digest, payload, created_at, expires_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		plan.ID, plan.InstanceID, plan.Generation, plan.Digest, payload, plan.CreatedAt.UTC().Format(time.RFC3339Nano), plan.ExpiresAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("persist immutable Redis plan: %w", err)
	}
	var result sql.Result
	if headExists {
		result, err = tx.ExecContext(ctx, `UPDATE redis_plan_heads SET generation = ?, plan_id = ?, plan_digest = ? WHERE instance_id = ? AND generation = ?`, plan.Generation, plan.ID, plan.Digest, plan.InstanceID, head)
	} else {
		result, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO redis_plan_heads(instance_id, generation, plan_id, plan_digest) VALUES(?, ?, ?, ?)`, plan.InstanceID, plan.Generation, plan.ID, plan.Digest)
	}
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (r *SQLiteRepository) Plan(ctx context.Context, id string) (LifecyclePlan, error) {
	if !validID(id) {
		return LifecyclePlan{}, fmt.Errorf("%w: plan id", ErrInvalid)
	}
	var payload []byte
	if err := r.db.QueryRowContext(ctx, `SELECT payload FROM redis_plans WHERE plan_id = ?`, id).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return LifecyclePlan{}, ErrNotFound
		}
		return LifecyclePlan{}, err
	}
	var plan LifecyclePlan
	if err := decodeBounded(payload, &plan); err != nil {
		return LifecyclePlan{}, err
	}
	sealed, err := SealLifecyclePlan(plan)
	if err != nil || sealed.Digest != plan.Digest {
		return LifecyclePlan{}, fmt.Errorf("%w: stored plan digest", ErrInvalid)
	}
	return plan, nil
}

func (r *SQLiteRepository) PutArtifact(ctx context.Context, artifact ArtifactDescriptor) error {
	if err := validateArtifact(artifact); err != nil {
		return err
	}
	payload, err := boundedJSON(artifact)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		`INSERT INTO redis_artifacts(artifact_id, group_id, instance_id, kind, sha256, payload, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		artifact.ID, artifact.GroupID, artifact.InstanceID, artifact.Kind, artifact.SHA256, payload, artifact.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("persist immutable Redis artifact: %w", err)
	}
	return nil
}

func (r *SQLiteRepository) Artifact(ctx context.Context, id string) (ArtifactDescriptor, error) {
	if !validID(id) {
		return ArtifactDescriptor{}, fmt.Errorf("%w: artifact id", ErrInvalid)
	}
	var payload []byte
	if err := r.db.QueryRowContext(ctx, `SELECT payload FROM redis_artifacts WHERE artifact_id = ?`, id).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return ArtifactDescriptor{}, ErrNotFound
		}
		return ArtifactDescriptor{}, err
	}
	var artifact ArtifactDescriptor
	if err := decodeBounded(payload, &artifact); err != nil {
		return ArtifactDescriptor{}, err
	}
	if err := validateArtifact(artifact); err != nil {
		return ArtifactDescriptor{}, err
	}
	return artifact, nil
}

func validateAudit(event AuditEvent) error {
	if !validID(event.ID) || !validID(event.OperationID) || !validID(event.ActorID) || !validID(event.Kind) || len(event.Resource) == 0 || len(event.Resource) > 256 || !validSHA256(event.RequestDigest) || !validSHA256(event.EvidenceDigest) || event.OccurredAt.IsZero() {
		return fmt.Errorf("%w: incomplete audit event", ErrInvalid)
	}
	return nil
}

func insertAudit(ctx context.Context, tx *sql.Tx, event AuditEvent) error {
	if err := validateAudit(event); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO redis_audit(event_id, operation_id, actor_id, kind, resource, request_digest, evidence_digest, occurred_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.OperationID, event.ActorID, event.Kind, event.Resource, event.RequestDigest, event.EvidenceDigest, event.OccurredAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (r *SQLiteRepository) AdmitOperation(ctx context.Context, operation Operation, audit AuditEvent) error {
	if !validID(operation.ID) || !validID(operation.PlanID) || operation.PlanDigest == "" || operation.State != OperationAdmitted || operation.Version != 1 || operation.CreatedAt.IsZero() || operation.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: admitted operation", ErrInvalid)
	}
	sealedAuthorization, authorizationErr := SealAuthorization(operation.Authorization)
	if authorizationErr != nil || sealedAuthorization.Digest != operation.Authorization.Digest || operation.Authorization.PlanID != operation.PlanID || operation.Authorization.PlanDigest != operation.PlanDigest || audit.OperationID != operation.ID || audit.ActorID != operation.Authorization.ActorID || audit.RequestDigest != operation.PlanDigest {
		return fmt.Errorf("%w: admitted operation evidence", ErrInvalid)
	}
	if operation.Maintenance != nil {
		sealedMaintenance, maintenanceErr := SealMaintenance(*operation.Maintenance)
		if maintenanceErr != nil || sealedMaintenance.Digest != operation.Maintenance.Digest || operation.Maintenance.PlanID != operation.PlanID || operation.Maintenance.PlanDigest != operation.PlanDigest {
			return fmt.Errorf("%w: admitted maintenance evidence", ErrInvalid)
		}
	}
	authorization, err := boundedJSON(operation.Authorization)
	if err != nil {
		return err
	}
	var maintenance []byte
	if operation.Maintenance != nil {
		maintenance, err = boundedJSON(operation.Maintenance)
		if err != nil {
			return err
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var planDigest string
	if err := tx.QueryRowContext(ctx, `SELECT digest FROM redis_plans WHERE plan_id = ?`, operation.PlanID).Scan(&planDigest); err != nil {
		return ErrNotFound
	}
	if planDigest != operation.PlanDigest {
		return ErrStale
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO redis_operations(operation_id, plan_id, plan_digest, state, version, authorization_payload, maintenance_payload, receipt_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, '', ?, ?)`,
		operation.ID, operation.PlanID, operation.PlanDigest, operation.State, operation.Version, authorization, maintenance, operation.CreatedAt.UTC().Format(time.RFC3339Nano), operation.UpdatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("persist admitted Redis operation: %w", err)
	}
	if err := insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *SQLiteRepository) Operation(ctx context.Context, id string) (Operation, error) {
	if !validID(id) {
		return Operation{}, fmt.Errorf("%w: operation id", ErrInvalid)
	}
	var operation Operation
	var authorization, maintenance []byte
	var state, createdAt, updatedAt string
	if err := r.db.QueryRowContext(ctx,
		`SELECT plan_id, plan_digest, state, version, authorization_payload, maintenance_payload, receipt_id, created_at, updated_at FROM redis_operations WHERE operation_id = ?`, id,
	).Scan(&operation.PlanID, &operation.PlanDigest, &state, &operation.Version, &authorization, &maintenance, &operation.ReceiptID, &createdAt, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return Operation{}, ErrNotFound
		}
		return Operation{}, err
	}
	operation.ID = id
	operation.State = OperationState(state)
	if err := decodeBounded(authorization, &operation.Authorization); err != nil {
		return Operation{}, err
	}
	if len(maintenance) != 0 {
		var evidence MaintenanceEvidence
		if err := decodeBounded(maintenance, &evidence); err != nil {
			return Operation{}, err
		}
		operation.Maintenance = &evidence
	}
	var err error
	operation.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Operation{}, fmt.Errorf("%w: operation created timestamp", ErrInvalid)
	}
	operation.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil || !validGeneration(operation.Version) {
		return Operation{}, fmt.Errorf("%w: operation update metadata", ErrInvalid)
	}
	validState := operation.State == OperationAdmitted || operation.State == OperationRunning || operation.State == OperationSucceeded || operation.State == OperationFailed || operation.State == OperationCompensated || operation.State == OperationAmbiguous
	sealedAuthorization, authorizationErr := SealAuthorization(operation.Authorization)
	if !validState || !validSHA256(operation.PlanDigest) || authorizationErr != nil || sealedAuthorization.Digest != operation.Authorization.Digest || operation.Authorization.PlanID != operation.PlanID || operation.Authorization.PlanDigest != operation.PlanDigest {
		return Operation{}, fmt.Errorf("%w: stored operation binding", ErrInvalid)
	}
	if operation.Maintenance != nil {
		sealedMaintenance, maintenanceErr := SealMaintenance(*operation.Maintenance)
		if maintenanceErr != nil || sealedMaintenance.Digest != operation.Maintenance.Digest || operation.Maintenance.PlanID != operation.PlanID || operation.Maintenance.PlanDigest != operation.PlanDigest {
			return Operation{}, fmt.Errorf("%w: stored maintenance binding", ErrInvalid)
		}
	}
	receiptRequired := operation.State == OperationSucceeded || operation.State == OperationFailed || operation.State == OperationCompensated
	if (operation.ReceiptID != "" && !validID(operation.ReceiptID)) || (receiptRequired && operation.ReceiptID == "") {
		return Operation{}, fmt.Errorf("%w: stored operation receipt binding", ErrInvalid)
	}
	return operation, nil
}

func validOperationTransition(current, next OperationState) bool {
	if current == OperationAdmitted {
		return next == OperationRunning || next == OperationFailed
	}
	if current == OperationRunning {
		return next == OperationSucceeded || next == OperationFailed || next == OperationCompensated || next == OperationAmbiguous
	}
	return false
}

func (r *SQLiteRepository) TransitionOperation(ctx context.Context, id string, expected OperationState, expectedVersion uint64, next OperationState, receiptID string, audit AuditEvent) (Operation, error) {
	receiptRequired := next == OperationSucceeded || next == OperationFailed || next == OperationCompensated
	if !validID(id) || !validOperationTransition(expected, next) || !validGeneration(expectedVersion) || expectedVersion == MaxGeneration || (receiptID != "" && !validID(receiptID)) || (receiptRequired && receiptID == "") || validateAudit(audit) != nil || audit.OperationID != id {
		return Operation{}, fmt.Errorf("%w: operation transition", ErrInvalid)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx,
		`UPDATE redis_operations SET state = ?, version = ?, receipt_id = ?, updated_at = ? WHERE operation_id = ? AND state = ? AND version = ?`,
		next, expectedVersion+1, receiptID, audit.OccurredAt.UTC().Format(time.RFC3339Nano), id, expected, expectedVersion)
	if err != nil {
		return Operation{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return Operation{}, ErrConflict
	}
	if err := insertAudit(ctx, tx, audit); err != nil {
		return Operation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, err
	}
	return r.Operation(ctx, id)
}

func (r *SQLiteRepository) PutReceipt(ctx context.Context, receipt LifecycleReceipt, audit AuditEvent) error {
	sealed, err := SealLifecycleReceipt(receipt)
	if err != nil || sealed.EvidenceDigest != receipt.EvidenceDigest || validateAudit(audit) != nil || audit.OperationID != receipt.OperationID || audit.RequestDigest != receipt.PlanDigest || audit.EvidenceDigest != receipt.EvidenceDigest {
		return fmt.Errorf("%w: receipt digest", ErrInvalid)
	}
	payload, err := boundedJSON(receipt)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var planID, planDigest, operationState string
	if err := tx.QueryRowContext(ctx, `SELECT plan_id, plan_digest, state FROM redis_operations WHERE operation_id = ?`, receipt.OperationID).Scan(&planID, &planDigest, &operationState); err != nil {
		return ErrNotFound
	}
	if planID != receipt.PlanID || planDigest != receipt.PlanDigest || OperationState(operationState) != OperationRunning {
		return ErrStale
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO redis_receipts(receipt_id, operation_id, plan_id, plan_digest, outcome, evidence_digest, payload, completed_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		receipt.ID, receipt.OperationID, receipt.PlanID, receipt.PlanDigest, receipt.Outcome, receipt.EvidenceDigest, payload, receipt.CompletedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("persist immutable Redis receipt: %w", err)
	}
	if err := insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *SQLiteRepository) Receipt(ctx context.Context, id string) (LifecycleReceipt, error) {
	if !validID(id) {
		return LifecycleReceipt{}, fmt.Errorf("%w: receipt id", ErrInvalid)
	}
	var payload []byte
	if err := r.db.QueryRowContext(ctx, `SELECT payload FROM redis_receipts WHERE receipt_id = ?`, id).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return LifecycleReceipt{}, ErrNotFound
		}
		return LifecycleReceipt{}, err
	}
	var receipt LifecycleReceipt
	if err := decodeBounded(payload, &receipt); err != nil {
		return LifecycleReceipt{}, err
	}
	sealed, err := SealLifecycleReceipt(receipt)
	if err != nil || sealed.EvidenceDigest != receipt.EvidenceDigest {
		return LifecycleReceipt{}, fmt.Errorf("%w: stored receipt digest", ErrInvalid)
	}
	return receipt, nil
}
