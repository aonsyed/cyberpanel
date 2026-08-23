package maildelivery

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const databaseTimeFormat = "2006-01-02T15:04:05.000000000Z"

type Repository interface {
	Bootstrap(context.Context) error
	PutBinding(context.Context, ProviderBinding, uint64) error
	LoadBinding(context.Context, TenantID, BindingID) (ProviderBinding, error)
	LoadBindingGeneration(context.Context, TenantID, BindingID, uint64) (ProviderBinding, error)
	AppendDNSPlan(context.Context, DNSPlan) error
	LoadDNSPlan(context.Context, TenantID, PlanID) (DNSPlan, error)
	AppendCredentialRotation(context.Context, CredentialRotation) error
	AppendCredentialRevocation(context.Context, CredentialRevocation) error
	PutMessageIdentity(context.Context, MessageIdentity, uint64) error
	LoadMessageIdentity(context.Context, TenantID, MessageID) (MessageIdentity, error)
	EnqueueReconciliation(context.Context, ReconciliationItem, uint32) error
	ClaimReconciliation(context.Context, string, time.Time, time.Duration) (ReconciliationItem, error)
	PutReconciliation(context.Context, ReconciliationItem, uint64) error
	PruneReconciliation(context.Context, time.Time, uint32) (uint32, error)
	ClaimWebhookReplay(context.Context, TenantID, BindingID, DeliveryID, time.Time, time.Time, uint32) error
	AppendProviderEvent(context.Context, NormalizedProviderEvent) error
}

type SQLiteRepository struct {
	db *sql.DB
}

func OpenSQLiteRepository(path string) (*SQLiteRepository, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	return &SQLiteRepository{db: database}, nil
}

func NewSQLiteRepository(database *sql.DB) (*SQLiteRepository, error) {
	if database == nil {
		return nil, ErrInvalid
	}
	database.SetMaxOpenConns(1)
	return &SQLiteRepository{db: database}, nil
}

func (repository *SQLiteRepository) Close() error {
	if repository == nil || repository.db == nil {
		return nil
	}
	return repository.db.Close()
}

func (repository *SQLiteRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil {
		return ErrInvalid
	}
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = FULL`,
		`CREATE TABLE IF NOT EXISTS maildelivery_bindings_v1 (
			binding_id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			adapter_kind TEXT NOT NULL,
			credential_version INTEGER NOT NULL CHECK (credential_version > 0),
			lifecycle TEXT NOT NULL CHECK (lifecycle IN ('disabled','pending_verification','enabled','rotating','revoked')),
			document BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(tenant_id, binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS maildelivery_bindings_tenant_v1 ON maildelivery_bindings_v1(tenant_id, binding_id)`,
		`CREATE TABLE IF NOT EXISTS maildelivery_binding_versions_v1 (
			binding_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			adapter_kind TEXT NOT NULL,
			credential_version INTEGER NOT NULL CHECK (credential_version > 0),
			document BLOB NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY(binding_id, generation),
			FOREIGN KEY(binding_id) REFERENCES maildelivery_bindings_v1(binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS maildelivery_binding_versions_tenant_v1 ON maildelivery_binding_versions_v1(tenant_id, binding_id, generation DESC)`,
		`CREATE TRIGGER IF NOT EXISTS maildelivery_binding_versions_no_update_v1 BEFORE UPDATE ON maildelivery_binding_versions_v1 BEGIN SELECT RAISE(ABORT, 'binding versions are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS maildelivery_binding_versions_no_delete_v1 BEFORE DELETE ON maildelivery_binding_versions_v1 BEGIN SELECT RAISE(ABORT, 'binding versions are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS maildelivery_dns_plans_v1 (
			plan_id TEXT PRIMARY KEY,
			binding_id TEXT NOT NULL,
			binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
			tenant_id TEXT NOT NULL,
			domain_id TEXT NOT NULL,
			revision INTEGER NOT NULL CHECK (revision > 0),
			state TEXT NOT NULL CHECK (state IN ('pending','verified','drifted','failed')),
			document BLOB NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE(binding_id, domain_id, revision),
			FOREIGN KEY(binding_id) REFERENCES maildelivery_bindings_v1(binding_id),
			FOREIGN KEY(binding_id, binding_generation) REFERENCES maildelivery_binding_versions_v1(binding_id, generation)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS maildelivery_dns_plans_domain_v1 ON maildelivery_dns_plans_v1(tenant_id, binding_id, domain_id, revision DESC)`,
		`CREATE TRIGGER IF NOT EXISTS maildelivery_dns_plans_no_update_v1 BEFORE UPDATE ON maildelivery_dns_plans_v1 BEGIN SELECT RAISE(ABORT, 'DNS plans are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS maildelivery_dns_plans_no_delete_v1 BEFORE DELETE ON maildelivery_dns_plans_v1 BEGIN SELECT RAISE(ABORT, 'DNS plans are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS maildelivery_rotations_v1 (
			rotation_id TEXT PRIMARY KEY,
			binding_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			sequence INTEGER NOT NULL CHECK (sequence > 0),
			old_version INTEGER NOT NULL CHECK (old_version > 0),
			new_version INTEGER NOT NULL CHECK (new_version > old_version),
			state TEXT NOT NULL,
			document BLOB NOT NULL,
			occurred_at TEXT NOT NULL,
			UNIQUE(binding_id, sequence),
			FOREIGN KEY(binding_id) REFERENCES maildelivery_bindings_v1(binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS maildelivery_rotations_binding_v1 ON maildelivery_rotations_v1(tenant_id, binding_id, sequence DESC)`,
		`CREATE TRIGGER IF NOT EXISTS maildelivery_rotations_no_update_v1 BEFORE UPDATE ON maildelivery_rotations_v1 BEGIN SELECT RAISE(ABORT, 'credential rotation history is immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS maildelivery_rotations_no_delete_v1 BEFORE DELETE ON maildelivery_rotations_v1 BEGIN SELECT RAISE(ABORT, 'credential rotation history is immutable'); END`,
		`CREATE TABLE IF NOT EXISTS maildelivery_revocations_v1 (
			revocation_id TEXT PRIMARY KEY,
			binding_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			credential_version INTEGER NOT NULL CHECK (credential_version > 0),
			document BLOB NOT NULL,
			revoked_at TEXT NOT NULL,
			UNIQUE(binding_id, credential_version),
			FOREIGN KEY(binding_id) REFERENCES maildelivery_bindings_v1(binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS maildelivery_revocations_binding_v1 ON maildelivery_revocations_v1(tenant_id, binding_id, revoked_at DESC)`,
		`CREATE TRIGGER IF NOT EXISTS maildelivery_revocations_no_update_v1 BEFORE UPDATE ON maildelivery_revocations_v1 BEGIN SELECT RAISE(ABORT, 'credential revocations are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS maildelivery_revocations_no_delete_v1 BEFORE DELETE ON maildelivery_revocations_v1 BEGIN SELECT RAISE(ABORT, 'credential revocations are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS maildelivery_message_identity_v1 (
			tenant_id TEXT NOT NULL,
			message_id TEXT NOT NULL,
			idempotency_key TEXT NOT NULL,
			binding_id TEXT NOT NULL,
			binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
			provider_message_id TEXT NOT NULL,
			state TEXT NOT NULL CHECK (state IN ('pending','accepted','ambiguous','authoritatively_absent','failed')),
			suppression_generation INTEGER NOT NULL CHECK (suppression_generation > 0),
			generation INTEGER NOT NULL CHECK (generation > 0),
			document BLOB NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(tenant_id, message_id),
			UNIQUE(tenant_id, idempotency_key),
			FOREIGN KEY(binding_id) REFERENCES maildelivery_bindings_v1(binding_id),
			FOREIGN KEY(binding_id, binding_generation) REFERENCES maildelivery_binding_versions_v1(binding_id, generation)
		) STRICT`,
		`CREATE UNIQUE INDEX IF NOT EXISTS maildelivery_provider_identity_v1 ON maildelivery_message_identity_v1(binding_id, provider_message_id) WHERE provider_message_id <> ''`,
		`CREATE TABLE IF NOT EXISTS maildelivery_reconciliation_v1 (
			queue_id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			message_id TEXT NOT NULL,
			binding_id TEXT NOT NULL,
			stream TEXT NOT NULL CHECK (stream IN ('transactional','campaign')),
			state TEXT NOT NULL CHECK (state IN ('waiting','claimed','done','expired')),
			generation INTEGER NOT NULL CHECK (generation > 0),
			not_before TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			lease_expires TEXT NOT NULL,
			document BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(tenant_id, message_id),
			FOREIGN KEY(tenant_id, message_id) REFERENCES maildelivery_message_identity_v1(tenant_id, message_id),
			FOREIGN KEY(binding_id) REFERENCES maildelivery_bindings_v1(binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS maildelivery_reconciliation_claim_v1 ON maildelivery_reconciliation_v1(tenant_id, stream, state, not_before, expires_at)`,
		`CREATE TABLE IF NOT EXISTS maildelivery_webhook_replay_v1 (
			delivery_id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			binding_id TEXT NOT NULL,
			received_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			FOREIGN KEY(binding_id) REFERENCES maildelivery_bindings_v1(binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS maildelivery_webhook_replay_expiry_v1 ON maildelivery_webhook_replay_v1(expires_at)`,
		`CREATE TABLE IF NOT EXISTS maildelivery_provider_events_v1 (
			binding_id TEXT NOT NULL,
			provider_event_id TEXT NOT NULL,
			delivery_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			domain_id TEXT NOT NULL,
			message_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			payload_digest TEXT NOT NULL,
			document BLOB NOT NULL,
			occurred_at TEXT NOT NULL,
			received_at TEXT NOT NULL,
			PRIMARY KEY(binding_id, provider_event_id),
			FOREIGN KEY(binding_id) REFERENCES maildelivery_bindings_v1(binding_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS maildelivery_provider_events_tenant_v1 ON maildelivery_provider_events_v1(tenant_id, domain_id, occurred_at DESC)`,
		`CREATE TRIGGER IF NOT EXISTS maildelivery_provider_events_no_update_v1 BEFORE UPDATE ON maildelivery_provider_events_v1 BEGIN SELECT RAISE(ABORT, 'provider events are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS maildelivery_provider_events_no_delete_v1 BEFORE DELETE ON maildelivery_provider_events_v1 BEGIN SELECT RAISE(ABORT, 'provider events are immutable'); END`,
	}
	for _, statement := range statements {
		if _, err := repository.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (repository *SQLiteRepository) PutBinding(ctx context.Context, binding ProviderBinding, expectedGeneration uint64) error {
	if binding.Validate() != nil || binding.Generation != expectedGeneration+1 || expectedGeneration > uint64(^uint64(0)>>1) {
		return ErrInvalid
	}
	if binding.Lifecycle == BindingEnabled {
		for _, domain := range binding.Domains {
			if domain.Verification != VerificationVerified {
				return ErrDenied
			}
		}
	}
	document, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if binding.Lifecycle == BindingEnabled {
		if binding.Observation.Health != ProviderHealthy && binding.Observation.Health != ProviderDegraded || binding.UpdatedAt.After(binding.Observation.StaleAfter) {
			return ErrDenied
		}
		for _, domain := range binding.Domains {
			var planDocument []byte
			if err = transaction.QueryRowContext(ctx, `SELECT document FROM maildelivery_dns_plans_v1 WHERE tenant_id=? AND binding_id=? AND domain_id=? AND plan_id=?`,
				binding.TenantID, binding.ID, domain.ID, domain.ActiveDNSPlanID).Scan(&planDocument); err != nil {
				return ErrDenied
			}
			var plan DNSPlan
			if decodeStrict(planDocument, &plan) != nil || plan.Validate() != nil || plan.State != VerificationVerified ||
				plan.EvidenceDigest != domain.VerificationDigest || plan.ObservedAt != domain.VerifiedAt {
				return ErrDenied
			}
		}
	}
	if expectedGeneration == 0 {
		if binding.Generation != 1 {
			return ErrInvalid
		}
		_, err = transaction.ExecContext(ctx, `INSERT INTO maildelivery_bindings_v1(binding_id,tenant_id,generation,adapter_kind,credential_version,lifecycle,document,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			binding.ID, binding.TenantID, binding.Generation, binding.Adapter.Kind, binding.Credential.Version, binding.Lifecycle, document,
			formatDatabaseTime(binding.CreatedAt), formatDatabaseTime(binding.UpdatedAt))
		if err != nil {
			return ErrConflict
		}
		if _, err = transaction.ExecContext(ctx, `INSERT INTO maildelivery_binding_versions_v1(binding_id,tenant_id,generation,adapter_kind,credential_version,document,created_at) VALUES(?,?,?,?,?,?,?)`,
			binding.ID, binding.TenantID, binding.Generation, binding.Adapter.Kind, binding.Credential.Version, document, formatDatabaseTime(binding.UpdatedAt)); err != nil {
			return ErrConflict
		}
		return transaction.Commit()
	}
	var currentDocument []byte
	if err = transaction.QueryRowContext(ctx, `SELECT document FROM maildelivery_bindings_v1 WHERE tenant_id=? AND binding_id=? AND generation=?`,
		binding.TenantID, binding.ID, expectedGeneration).Scan(&currentDocument); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStale
		}
		return err
	}
	var current ProviderBinding
	if decodeStrict(currentDocument, &current) != nil || current.Validate() != nil || current.ID != binding.ID ||
		current.TenantID != binding.TenantID || current.CreatedAt != binding.CreatedAt || binding.Credential.Version < current.Credential.Version {
		return ErrInvalid
	}
	if current.Lifecycle == BindingRevoked && binding.Lifecycle != BindingRevoked {
		return ErrDenied
	}
	result, err := transaction.ExecContext(ctx, `UPDATE maildelivery_bindings_v1 SET generation=?,adapter_kind=?,credential_version=?,lifecycle=?,document=?,updated_at=? WHERE tenant_id=? AND binding_id=? AND generation=?`,
		binding.Generation, binding.Adapter.Kind, binding.Credential.Version, binding.Lifecycle, document, formatDatabaseTime(binding.UpdatedAt),
		binding.TenantID, binding.ID, expectedGeneration)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrStale
	}
	if _, err = transaction.ExecContext(ctx, `INSERT INTO maildelivery_binding_versions_v1(binding_id,tenant_id,generation,adapter_kind,credential_version,document,created_at) VALUES(?,?,?,?,?,?,?)`,
		binding.ID, binding.TenantID, binding.Generation, binding.Adapter.Kind, binding.Credential.Version, document, formatDatabaseTime(binding.UpdatedAt)); err != nil {
		return ErrConflict
	}
	return transaction.Commit()
}

func (repository *SQLiteRepository) LoadBinding(ctx context.Context, tenantID TenantID, bindingID BindingID) (ProviderBinding, error) {
	if !validID(string(tenantID)) || !validID(string(bindingID)) {
		return ProviderBinding{}, ErrInvalid
	}
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM maildelivery_bindings_v1 WHERE tenant_id=? AND binding_id=?`, tenantID, bindingID).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return ProviderBinding{}, ErrNotFound
	}
	if err != nil {
		return ProviderBinding{}, err
	}
	var binding ProviderBinding
	if decodeStrict(document, &binding) != nil || binding.Validate() != nil || binding.TenantID != tenantID || binding.ID != bindingID {
		return ProviderBinding{}, ErrConflict
	}
	return binding, nil
}

func (repository *SQLiteRepository) LoadBindingGeneration(ctx context.Context, tenantID TenantID, bindingID BindingID, generation uint64) (ProviderBinding, error) {
	if !validID(string(tenantID)) || !validID(string(bindingID)) || generation == 0 {
		return ProviderBinding{}, ErrInvalid
	}
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM maildelivery_binding_versions_v1 WHERE tenant_id=? AND binding_id=? AND generation=?`,
		tenantID, bindingID, generation).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return ProviderBinding{}, ErrNotFound
	}
	if err != nil {
		return ProviderBinding{}, err
	}
	var binding ProviderBinding
	if decodeStrict(document, &binding) != nil || binding.Validate() != nil || binding.TenantID != tenantID || binding.ID != bindingID || binding.Generation != generation {
		return ProviderBinding{}, ErrConflict
	}
	return binding, nil
}

func (repository *SQLiteRepository) AppendDNSPlan(ctx context.Context, plan DNSPlan) error {
	if plan.Validate() != nil {
		return ErrInvalid
	}
	document, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	result, err := repository.db.ExecContext(ctx, `INSERT INTO maildelivery_dns_plans_v1(plan_id,binding_id,binding_generation,tenant_id,domain_id,revision,state,document,created_at)
		SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM maildelivery_binding_versions_v1 WHERE binding_id=? AND tenant_id=? AND generation=?)`,
		plan.ID, plan.BindingID, plan.BindingGeneration, plan.TenantID, plan.DomainID, plan.Revision, plan.State, document,
		formatDatabaseTime(plan.CreatedAt), plan.BindingID, plan.TenantID, plan.BindingGeneration)
	if err != nil {
		return ErrConflict
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrNotFound
	}
	return nil
}

func (repository *SQLiteRepository) LoadDNSPlan(ctx context.Context, tenantID TenantID, planID PlanID) (DNSPlan, error) {
	if !validID(string(tenantID)) || !validID(string(planID)) {
		return DNSPlan{}, ErrInvalid
	}
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM maildelivery_dns_plans_v1 WHERE tenant_id=? AND plan_id=?`, tenantID, planID).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return DNSPlan{}, ErrNotFound
	}
	if err != nil {
		return DNSPlan{}, err
	}
	var plan DNSPlan
	if decodeStrict(document, &plan) != nil || plan.Validate() != nil || plan.TenantID != tenantID || plan.ID != planID {
		return DNSPlan{}, ErrConflict
	}
	return plan, nil
}

func (repository *SQLiteRepository) AppendCredentialRotation(ctx context.Context, rotation CredentialRotation) error {
	if rotation.Validate() != nil {
		return ErrInvalid
	}
	document, err := json.Marshal(rotation)
	if err != nil {
		return err
	}
	result, err := repository.db.ExecContext(ctx, `INSERT INTO maildelivery_rotations_v1(rotation_id,binding_id,tenant_id,sequence,old_version,new_version,state,document,occurred_at)
		SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM maildelivery_binding_versions_v1 WHERE binding_id=? AND tenant_id=? AND credential_version=?)`,
		rotation.ID, rotation.BindingID, rotation.TenantID, rotation.Sequence, rotation.OldVersion, rotation.NewVersion, rotation.State, document,
		formatDatabaseTime(rotation.OccurredAt), rotation.BindingID, rotation.TenantID, rotation.OldVersion)
	if err != nil {
		return ErrConflict
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrNotFound
	}
	return nil
}

func (repository *SQLiteRepository) AppendCredentialRevocation(ctx context.Context, revocation CredentialRevocation) error {
	if revocation.Validate() != nil {
		return ErrInvalid
	}
	document, err := json.Marshal(revocation)
	if err != nil {
		return err
	}
	result, err := repository.db.ExecContext(ctx, `INSERT INTO maildelivery_revocations_v1(revocation_id,binding_id,tenant_id,credential_version,document,revoked_at)
		SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM maildelivery_binding_versions_v1 WHERE binding_id=? AND tenant_id=? AND credential_version=?)`,
		revocation.ID, revocation.BindingID, revocation.TenantID, revocation.CredentialVersion, document,
		formatDatabaseTime(revocation.RevokedAt), revocation.BindingID, revocation.TenantID, revocation.CredentialVersion)
	if err != nil {
		return ErrConflict
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrNotFound
	}
	return nil
}

func (repository *SQLiteRepository) PutMessageIdentity(ctx context.Context, identity MessageIdentity, expectedGeneration uint64) error {
	if identity.Validate() != nil || identity.Generation != expectedGeneration+1 {
		return ErrInvalid
	}
	document, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	if expectedGeneration == 0 {
		_, err = repository.db.ExecContext(ctx, `INSERT INTO maildelivery_message_identity_v1(tenant_id,message_id,idempotency_key,binding_id,binding_generation,provider_message_id,state,suppression_generation,generation,document,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			identity.TenantID, identity.MessageID, identity.IdempotencyKey, identity.BindingID, identity.BindingGeneration, identity.ProviderMessageID,
			identity.State, identity.SuppressionGeneration, identity.Generation, document, formatDatabaseTime(identity.UpdatedAt))
		if err != nil {
			return ErrConflict
		}
		return nil
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var currentDocument []byte
	if err = transaction.QueryRowContext(ctx, `SELECT document FROM maildelivery_message_identity_v1 WHERE tenant_id=? AND message_id=? AND generation=?`,
		identity.TenantID, identity.MessageID, expectedGeneration).Scan(&currentDocument); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStale
		}
		return err
	}
	var current MessageIdentity
	if decodeStrict(currentDocument, &current) != nil || current.Validate() != nil || current.IdempotencyKey != identity.IdempotencyKey ||
		current.BindingID != identity.BindingID || current.BindingGeneration != identity.BindingGeneration ||
		current.SuppressionGeneration != identity.SuppressionGeneration ||
		current.ProviderMessageID != "" && identity.ProviderMessageID != current.ProviderMessageID {
		return ErrConflict
	}
	result, err := transaction.ExecContext(ctx, `UPDATE maildelivery_message_identity_v1 SET provider_message_id=?,state=?,generation=?,document=?,updated_at=? WHERE tenant_id=? AND message_id=? AND generation=?`,
		identity.ProviderMessageID, identity.State, identity.Generation, document, formatDatabaseTime(identity.UpdatedAt), identity.TenantID, identity.MessageID, expectedGeneration)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrStale
	}
	return transaction.Commit()
}

func (repository *SQLiteRepository) LoadMessageIdentity(ctx context.Context, tenantID TenantID, messageID MessageID) (MessageIdentity, error) {
	if !validID(string(tenantID)) || !validID(string(messageID)) {
		return MessageIdentity{}, ErrInvalid
	}
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM maildelivery_message_identity_v1 WHERE tenant_id=? AND message_id=?`, tenantID, messageID).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return MessageIdentity{}, ErrNotFound
	}
	if err != nil {
		return MessageIdentity{}, err
	}
	var identity MessageIdentity
	if decodeStrict(document, &identity) != nil || identity.Validate() != nil || identity.TenantID != tenantID || identity.MessageID != messageID {
		return MessageIdentity{}, ErrConflict
	}
	return identity, nil
}

func (repository *SQLiteRepository) EnqueueReconciliation(ctx context.Context, item ReconciliationItem, maximumDepth uint32) error {
	if item.Validate() != nil || item.State != QueueWaiting || maximumDepth == 0 || maximumDepth > 1000000 {
		return ErrInvalid
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var depth uint32
	if err = transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM maildelivery_reconciliation_v1 WHERE tenant_id=? AND stream=? AND state IN ('waiting','claimed') AND expires_at>?`,
		item.TenantID, item.Stream, formatDatabaseTime(item.CreatedAt)).Scan(&depth); err != nil {
		return err
	}
	if depth >= maximumDepth {
		return ErrBackpressure
	}
	document, err := json.Marshal(item)
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO maildelivery_reconciliation_v1(queue_id,tenant_id,message_id,binding_id,stream,state,generation,not_before,expires_at,lease_expires,document,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		item.ID, item.TenantID, item.MessageID, item.BindingID, item.Stream, item.State, item.Generation,
		formatDatabaseTime(item.NotBefore), formatDatabaseTime(item.ExpiresAt), formatDatabaseTime(item.LeaseExpires), document,
		formatDatabaseTime(item.CreatedAt), formatDatabaseTime(item.UpdatedAt))
	if err != nil {
		return ErrConflict
	}
	return transaction.Commit()
}

func (repository *SQLiteRepository) ClaimReconciliation(ctx context.Context, worker string, now time.Time, lease time.Duration) (ReconciliationItem, error) {
	if !validID(worker) || now.IsZero() || lease < time.Second || lease > 10*time.Minute {
		return ReconciliationItem{}, ErrInvalid
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return ReconciliationItem{}, err
	}
	defer transaction.Rollback()
	var document []byte
	err = transaction.QueryRowContext(ctx, `SELECT document FROM maildelivery_reconciliation_v1
		WHERE expires_at>? AND not_before<=? AND (state='waiting' OR (state='claimed' AND lease_expires<=?))
		ORDER BY CASE stream WHEN 'transactional' THEN 0 ELSE 1 END, created_at, queue_id LIMIT 1`,
		formatDatabaseTime(now), formatDatabaseTime(now), formatDatabaseTime(now)).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return ReconciliationItem{}, ErrNotFound
	}
	if err != nil {
		return ReconciliationItem{}, err
	}
	var item ReconciliationItem
	if decodeStrict(document, &item) != nil || item.Validate() != nil {
		return ReconciliationItem{}, ErrConflict
	}
	expectedGeneration := item.Generation
	item.State = QueueClaimed
	item.Generation++
	item.LeaseOwner = worker
	item.LeaseExpires = now.UTC().Add(lease)
	item.UpdatedAt = now.UTC()
	document, err = json.Marshal(item)
	if err != nil {
		return ReconciliationItem{}, err
	}
	result, err := transaction.ExecContext(ctx, `UPDATE maildelivery_reconciliation_v1 SET state=?,generation=?,lease_expires=?,document=?,updated_at=? WHERE queue_id=? AND generation=? AND expires_at>?`,
		item.State, item.Generation, formatDatabaseTime(item.LeaseExpires), document, formatDatabaseTime(item.UpdatedAt), item.ID, expectedGeneration, formatDatabaseTime(now))
	if err != nil {
		return ReconciliationItem{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ReconciliationItem{}, err
	}
	if affected != 1 {
		return ReconciliationItem{}, ErrStale
	}
	if err = transaction.Commit(); err != nil {
		return ReconciliationItem{}, err
	}
	return item, nil
}

func (repository *SQLiteRepository) PutReconciliation(ctx context.Context, item ReconciliationItem, expectedGeneration uint64) error {
	if item.Validate() != nil || item.Generation != expectedGeneration+1 {
		return ErrInvalid
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var currentDocument []byte
	if err = transaction.QueryRowContext(ctx, `SELECT document FROM maildelivery_reconciliation_v1 WHERE queue_id=? AND tenant_id=? AND message_id=? AND generation=?`,
		item.ID, item.TenantID, item.MessageID, expectedGeneration).Scan(&currentDocument); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStale
		}
		return err
	}
	var current ReconciliationItem
	if decodeStrict(currentDocument, &current) != nil || current.Validate() != nil || current.ID != item.ID || current.TenantID != item.TenantID ||
		current.MessageID != item.MessageID || current.BindingID != item.BindingID || current.Stream != item.Stream || current.CreatedAt != item.CreatedAt ||
		current.ExpiresAt != item.ExpiresAt || current.State == QueueDone || current.State == QueueExpired ||
		current.State == QueueWaiting && item.State != QueueWaiting && item.State != QueueExpired ||
		current.State == QueueClaimed && item.State == QueueClaimed && current.LeaseOwner != item.LeaseOwner {
		return ErrConflict
	}
	document, err := json.Marshal(item)
	if err != nil {
		return err
	}
	result, err := transaction.ExecContext(ctx, `UPDATE maildelivery_reconciliation_v1 SET state=?,generation=?,not_before=?,expires_at=?,lease_expires=?,document=?,updated_at=? WHERE queue_id=? AND tenant_id=? AND message_id=? AND generation=?`,
		item.State, item.Generation, formatDatabaseTime(item.NotBefore), formatDatabaseTime(item.ExpiresAt), formatDatabaseTime(item.LeaseExpires), document,
		formatDatabaseTime(item.UpdatedAt), item.ID, item.TenantID, item.MessageID, expectedGeneration)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrStale
	}
	return transaction.Commit()
}

func (repository *SQLiteRepository) PruneReconciliation(ctx context.Context, before time.Time, maximum uint32) (uint32, error) {
	if before.IsZero() || maximum == 0 || maximum > 10000 {
		return 0, ErrInvalid
	}
	result, err := repository.db.ExecContext(ctx, `DELETE FROM maildelivery_reconciliation_v1 WHERE queue_id IN (
		SELECT queue_id FROM maildelivery_reconciliation_v1 WHERE expires_at<=? ORDER BY expires_at,queue_id LIMIT ?)`,
		formatDatabaseTime(before), maximum)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected < 0 || affected > int64(maximum) {
		return 0, ErrConflict
	}
	return uint32(affected), nil
}

func (repository *SQLiteRepository) ClaimWebhookReplay(ctx context.Context, tenantID TenantID, bindingID BindingID, deliveryID DeliveryID, receivedAt, expiresAt time.Time, maximumEntries uint32) error {
	if !validID(string(tenantID)) || !validID(string(bindingID)) || !validID(string(deliveryID)) || receivedAt.IsZero() ||
		!expiresAt.After(receivedAt) || expiresAt.After(receivedAt.Add(24*time.Hour)) || maximumEntries == 0 || maximumEntries > 1000000 {
		return ErrInvalid
	}
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err = transaction.ExecContext(ctx, `DELETE FROM maildelivery_webhook_replay_v1 WHERE expires_at<=?`, formatDatabaseTime(receivedAt)); err != nil {
		return err
	}
	var count uint32
	if err = transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM maildelivery_webhook_replay_v1`).Scan(&count); err != nil {
		return err
	}
	if count >= maximumEntries {
		return ErrBackpressure
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO maildelivery_webhook_replay_v1(delivery_id,tenant_id,binding_id,received_at,expires_at)
		SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM maildelivery_bindings_v1 WHERE binding_id=? AND tenant_id=?)`,
		deliveryID, tenantID, bindingID, formatDatabaseTime(receivedAt), formatDatabaseTime(expiresAt), bindingID, tenantID)
	if err != nil {
		return ErrConflict
	}
	return transaction.Commit()
}

func (repository *SQLiteRepository) AppendProviderEvent(ctx context.Context, event NormalizedProviderEvent) error {
	if event.Validate() != nil {
		return ErrInvalid
	}
	document, err := json.Marshal(event)
	if err != nil {
		return err
	}
	result, err := repository.db.ExecContext(ctx, `INSERT INTO maildelivery_provider_events_v1(binding_id,provider_event_id,delivery_id,tenant_id,domain_id,message_id,event_type,payload_digest,document,occurred_at,received_at)
		SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM maildelivery_bindings_v1 WHERE binding_id=? AND tenant_id=?)`,
		event.BindingID, event.ProviderEventID, event.DeliveryID, event.TenantID, event.DomainID, event.MessageID, event.Type,
		event.PayloadDigest, document, formatDatabaseTime(event.OccurredAt), formatDatabaseTime(event.ReceivedAt), event.BindingID, event.TenantID)
	if err != nil {
		return ErrConflict
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrNotFound
	}
	return nil
}

func decodeStrict(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func formatDatabaseTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(databaseTimeFormat)
}
