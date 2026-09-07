package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

const operatorSessionPrefix = "mtls:"

const operatorSchema = `
CREATE TABLE IF NOT EXISTS fleet_operator_grants(
 id TEXT PRIMARY KEY,
 certificate_fingerprint TEXT NOT NULL UNIQUE,
 tenant_id TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 permissions_json BYTEA NOT NULL,
 assurance TEXT NOT NULL,
 authz_epoch BIGINT NOT NULL CHECK(authz_epoch>0),
 state TEXT NOT NULL,
 issued_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 revoked_at TIMESTAMPTZ,
 updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS fleet_operator_grants_active
 ON fleet_operator_grants(certificate_fingerprint,state,expires_at);
CREATE TABLE IF NOT EXISTS fleet_operator_audit(
 sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 event_id TEXT NOT NULL UNIQUE,
 occurred_at TIMESTAMPTZ NOT NULL,
 certificate_fingerprint TEXT NOT NULL,
 tenant_id TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 action TEXT NOT NULL,
 target_kind TEXT NOT NULL,
 target_id TEXT NOT NULL,
 outcome TEXT NOT NULL,
 detail_digest TEXT NOT NULL,
 previous_digest TEXT NOT NULL UNIQUE,
 event_digest TEXT NOT NULL UNIQUE
);
`

var operatorPermissions = map[string]struct{}{
	"node.list": {}, "node.inspect": {}, "node.intent.create": {},
	"intent.inspect": {}, "grant.inspect": {}, "node.revoke": {},
	"saga.inspect": {}, "saga.advance": {},
}

type OperatorGrant struct {
	ID                         federation.ID `json:"id"`
	CertificateFingerprintSHA256 string       `json:"certificate_fingerprint_sha256"`
	TenantID                   string        `json:"tenant_id"`
	PrincipalID                string        `json:"principal_id"`
	Permissions                []string      `json:"permissions"`
	Assurance                  string        `json:"assurance"`
	AuthzEpoch                 uint64        `json:"authz_epoch"`
	IssuedAt                   time.Time     `json:"issued_at"`
	ExpiresAt                  time.Time     `json:"expires_at"`
}

type IntentRecord struct {
	OwnerTenantID  federation.ID              `json:"owner_tenant_id"`
	Status         string                     `json:"status"`
	Intent         federation.Intent          `json:"intent"`
	Receipt        *federation.Receipt        `json:"receipt,omitempty"`
	ReceiptEvidence *NodeReceiptEvidenceRecord `json:"receipt_evidence,omitempty"`
}

type NodeReceiptEvidenceRecord struct {
	NodeID     federation.ID `json:"node_id"`
	KeyID      string        `json:"key_id"`
	PublicKey  []byte        `json:"public_key"`
	State      string        `json:"state"`
	NotBefore  time.Time     `json:"not_before"`
	ExpiresAt  time.Time     `json:"expires_at"`
}

type MutationGrantRecord struct {
	ID             federation.ID             `json:"id"`
	NodeID         federation.ID             `json:"node_id"`
	OwnerTenantID  federation.ID             `json:"owner_tenant_id"`
	PeerID         federation.ID             `json:"peer_id"`
	AuthorityEpoch uint64                    `json:"authority_epoch"`
	State          string                    `json:"state"`
	Grant          *federation.MutationGrant `json:"grant,omitempty"`
	ExpiresAt      time.Time                 `json:"expires_at"`
	UpdatedAt      time.Time                 `json:"updated_at"`
}

func (grant OperatorGrant) validate(now time.Time) error {
	if !grant.ID.Valid() || !validSHA256(grant.CertificateFingerprintSHA256) || grant.AuthzEpoch == 0 || grant.Assurance != "phishing_resistant" && grant.Assurance != "hardware_bound" || grant.IssuedAt.IsZero() || grant.IssuedAt.After(now.Add(5*time.Minute)) || !grant.ExpiresAt.After(grant.IssuedAt) || !now.Before(grant.ExpiresAt) || len(grant.Permissions) == 0 || len(grant.Permissions) > len(operatorPermissions) {
		return ErrInvalid
	}
	if _, err := federation.NewID(grant.TenantID); err != nil {
		return ErrInvalid
	}
	if _, err := federation.NewID(grant.PrincipalID); err != nil {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(grant.Permissions))
	for _, permission := range grant.Permissions {
		if _, allowed := operatorPermissions[permission]; !allowed {
			return ErrForbidden
		}
		if _, duplicate := seen[permission]; duplicate {
			return ErrConflict
		}
		seen[permission] = struct{}{}
	}
	return nil
}

func (s *Store) BootstrapOperator(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalid
	}
	return s.bootstrapPostgreSQL(ctx)
}

func (s *Store) ProvisionOperatorGrants(ctx context.Context, grants []OperatorGrant) error {
	if s == nil || s.db == nil || ctx == nil || len(grants) == 0 || len(grants) > 1024 {
		return ErrInvalid
	}
	now := s.clock().UTC()
	identifiers := make(map[federation.ID]struct{}, len(grants))
	fingerprints := make(map[string]struct{}, len(grants))
	for index := range grants {
		if err := grants[index].validate(now); err != nil {
			return err
		}
		if _, duplicate := identifiers[grants[index].ID]; duplicate {
			return ErrConflict
		}
		if _, duplicate := fingerprints[grants[index].CertificateFingerprintSHA256]; duplicate {
			return ErrConflict
		}
		identifiers[grants[index].ID] = struct{}{}
		fingerprints[grants[index].CertificateFingerprintSHA256] = struct{}{}
		grants[index].Permissions = append([]string(nil), grants[index].Permissions...)
		sort.Strings(grants[index].Permissions)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE fleet_operator_grants SET state='staged',updated_at=? WHERE state='active'`, now); err != nil {
		return err
	}
	for _, grant := range grants {
		permissions, marshalErr := json.Marshal(grant.Permissions)
		if marshalErr != nil {
			return marshalErr
		}
		result, execErr := tx.ExecContext(ctx, `INSERT INTO fleet_operator_grants(id,certificate_fingerprint,tenant_id,principal_id,permissions_json,assurance,authz_epoch,state,issued_at,expires_at,revoked_at,updated_at) VALUES(?,?,?,?,?,?,?,'active',?,?,NULL,?) ON CONFLICT(id) DO UPDATE SET permissions_json=excluded.permissions_json,assurance=excluded.assurance,authz_epoch=excluded.authz_epoch,state='active',issued_at=excluded.issued_at,expires_at=excluded.expires_at,revoked_at=NULL,updated_at=excluded.updated_at WHERE fleet_operator_grants.certificate_fingerprint=excluded.certificate_fingerprint AND fleet_operator_grants.tenant_id=excluded.tenant_id AND fleet_operator_grants.principal_id=excluded.principal_id AND fleet_operator_grants.state IN ('active','staged') AND fleet_operator_grants.authz_epoch<=excluded.authz_epoch`, grant.ID, grant.CertificateFingerprintSHA256, grant.TenantID, grant.PrincipalID, permissions, grant.Assurance, grant.AuthzEpoch, grant.IssuedAt.UTC(), grant.ExpiresAt.UTC(), now)
		if execErr != nil {
			return execErr
		}
		if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
			return ErrStale
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE fleet_operator_grants SET state='revoked',revoked_at=?,updated_at=? WHERE state='staged'`, now, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) operatorGrantByFingerprint(ctx context.Context, fingerprint string) (OperatorGrant, error) {
	var grant OperatorGrant
	var permissions []byte
	var state string
	err := s.db.QueryRowContext(ctx, `SELECT id,certificate_fingerprint,tenant_id,principal_id,permissions_json,assurance,authz_epoch,state,issued_at,expires_at FROM fleet_operator_grants WHERE certificate_fingerprint=?`, fingerprint).Scan(&grant.ID, &grant.CertificateFingerprintSHA256, &grant.TenantID, &grant.PrincipalID, &permissions, &grant.Assurance, &grant.AuthzEpoch, &state, &grant.IssuedAt, &grant.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return grant, ErrNotFound
	}
	if err != nil {
		return grant, err
	}
	if state != "active" || json.Unmarshal(permissions, &grant.Permissions) != nil || grant.validate(s.clock().UTC()) != nil {
		return OperatorGrant{}, ErrForbidden
	}
	return grant, nil
}

func (s *Store) NodesForTenant(ctx context.Context, tenant, after string, limit uint32) ([]Node, error) {
	if s == nil || ctx == nil || limit == 0 || limit > 100 || after != "" && !federation.ID(after).Valid() {
		return nil, ErrInvalid
	}
	if _, err := federation.NewID(tenant); err != nil {
		return nil, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,owner_tenant_id,name,state,authority_epoch,capabilities_json,projection_sequence,snapshot_generation,last_seen_at,created_at,updated_at,certificate_fingerprint FROM fleet_nodes WHERE owner_tenant_id=? AND id>? ORDER BY id LIMIT ?`, tenant, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := make([]Node, 0, limit)
	for rows.Next() {
		var node Node
		var capabilities []byte
		if err = rows.Scan(&node.ID, &node.OwnerTenantID, &node.Name, &node.State, &node.AuthorityEpoch, &capabilities, &node.ProjectionSequence, &node.SnapshotGeneration, &node.LastSeenAt, &node.CreatedAt, &node.UpdatedAt, &node.CertificateFingerprint); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(capabilities, &node.Capabilities); err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func (s *Store) InspectIntent(ctx context.Context, id federation.ID) (IntentRecord, error) {
	var record IntentRecord
	var intentJSON, receiptJSON []byte
	err := s.db.QueryRowContext(ctx, `SELECT owner_tenant_id,status,intent_json,receipt_json FROM fleet_intents WHERE id=?`, id).Scan(&record.OwnerTenantID, &record.Status, &intentJSON, &receiptJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return record, ErrNotFound
	}
	if err != nil || json.Unmarshal(intentJSON, &record.Intent) != nil {
		return record, firstStoreError(err)
	}
	if len(receiptJSON) != 0 && !bytes.Equal(bytes.TrimSpace(receiptJSON), []byte(`{}`)) {
		var receipt federation.Receipt
		if err = json.Unmarshal(receiptJSON, &receipt); err != nil {
			return IntentRecord{}, err
		}
		record.Receipt = &receipt
		evidence, evidenceErr := s.inspectNodeReceiptEvidence(ctx, receipt.NodeID, receipt.SignatureKeyID)
		if evidenceErr != nil {
			return IntentRecord{}, evidenceErr
		}
		record.ReceiptEvidence = &evidence
	}
	return record, nil
}

func (s *Store) inspectNodeReceiptEvidence(ctx context.Context, nodeID federation.ID, keyID string) (NodeReceiptEvidenceRecord, error) {
	var evidence NodeReceiptEvidenceRecord
	if s == nil || s.db == nil || ctx == nil || !nodeID.Valid() {
		return evidence, ErrInvalid
	}
	if _, err := federation.NewID(keyID); err != nil {
		return evidence, ErrInvalid
	}
	err := s.db.QueryRowContext(ctx, `SELECT node_id,key_id,public_key,state,not_before,expires_at FROM fleet_node_evidence_keys WHERE node_id=? AND key_id=?`, nodeID, keyID).Scan(&evidence.NodeID, &evidence.KeyID, &evidence.PublicKey, &evidence.State, &evidence.NotBefore, &evidence.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return evidence, ErrNotFound
	}
	if err != nil {
		return evidence, err
	}
	now := s.clock().UTC()
	if evidence.NodeID != nodeID || evidence.KeyID != keyID || len(evidence.PublicKey) != ed25519.PublicKeySize || evidence.State != "current" && evidence.State != "historical" || evidence.NotBefore.IsZero() || evidence.ExpiresAt.IsZero() || now.Before(evidence.NotBefore) || !now.Before(evidence.ExpiresAt) {
		return NodeReceiptEvidenceRecord{}, ErrForbidden
	}
	return evidence, nil
}

func (s *Store) InspectMutationGrant(ctx context.Context, id federation.ID) (MutationGrantRecord, error) {
	var record MutationGrantRecord
	var grantJSON []byte
	err := s.db.QueryRowContext(ctx, `SELECT g.id,g.node_id,n.owner_tenant_id,g.peer_id,g.authority_epoch,g.state,g.grant_json,g.expires_at,g.updated_at FROM fleet_grants g JOIN fleet_nodes n ON n.id=g.node_id WHERE g.id=?`, id).Scan(&record.ID, &record.NodeID, &record.OwnerTenantID, &record.PeerID, &record.AuthorityEpoch, &record.State, &grantJSON, &record.ExpiresAt, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return record, ErrNotFound
	}
	if err != nil {
		return record, err
	}
	var grant federation.MutationGrant
	if json.Unmarshal(grantJSON, &grant) == nil && grant.ID.Valid() {
		record.Grant = &grant
	}
	return record, nil
}

func firstStoreError(err error) error {
	if err != nil {
		return err
	}
	return ErrConflict
}

type OperatorAuthority struct{ store *Store }

func NewOperatorAuthority(store *Store) (*OperatorAuthority, error) {
	if store == nil || store.db == nil {
		return nil, ErrInvalid
	}
	return &OperatorAuthority{store: store}, nil
}

func (authority *OperatorAuthority) OperatorForFingerprint(ctx context.Context, fingerprint string) (Operator, error) {
	if authority == nil || authority.store == nil || ctx == nil || !validSHA256(fingerprint) {
		return Operator{}, ErrInvalid
	}
	grant, err := authority.store.operatorGrantByFingerprint(ctx, fingerprint)
	if err != nil {
		return Operator{}, err
	}
	return Operator{PrincipalID: grant.PrincipalID, TenantID: grant.TenantID, Permissions: append([]string(nil), grant.Permissions...), Assurance: grant.Assurance, SessionID: operatorSessionPrefix + fingerprint, AuthzEpoch: grant.AuthzEpoch}, nil
}

func (authority *OperatorAuthority) authorizePermission(ctx context.Context, operator Operator, permission string) error {
	if authority == nil || authority.store == nil || ctx == nil || !strings.HasPrefix(operator.SessionID, operatorSessionPrefix) {
		return ErrForbidden
	}
	fingerprint := strings.TrimPrefix(operator.SessionID, operatorSessionPrefix)
	grant, err := authority.store.operatorGrantByFingerprint(ctx, fingerprint)
	if errors.Is(err, ErrAuthorityUnavailable) { return err }
	if err != nil || grant.PrincipalID != operator.PrincipalID || grant.TenantID != operator.TenantID || grant.Assurance != operator.Assurance || grant.AuthzEpoch != operator.AuthzEpoch {
		return ErrForbidden
	}
	for _, allowed := range grant.Permissions {
		if allowed == permission {
			return nil
		}
	}
	return ErrForbidden
}

func (authority *OperatorAuthority) Authorize(ctx context.Context, operator Operator, permission string, target federation.ID, _, _ string) error {
	if err := authority.authorizePermission(ctx, operator, permission); err != nil {
		return err
	}
	switch permission {
	case "node.intent.create", "node.revoke":
		node, err := authority.store.Node(ctx, target)
		if errors.Is(err, ErrAuthorityUnavailable) { return err }
		if err != nil || node.OwnerTenantID.String() != operator.TenantID {
			return ErrForbidden
		}
	case "saga.advance":
		saga, err := authority.store.Saga(ctx, target)
		if errors.Is(err, ErrAuthorityUnavailable) { return err }
		if err != nil || saga.OwnerTenantID.String() != operator.TenantID {
			return ErrForbidden
		}
	default:
		return ErrForbidden
	}
	return nil
}

type OperatorAudit struct{ store *Store }

func NewOperatorAudit(store *Store) (*OperatorAudit, error) {
	if store == nil || store.db == nil {
		return nil, ErrInvalid
	}
	return &OperatorAudit{store: store}, nil
}

func (audit *OperatorAudit) Record(ctx context.Context, action string, operator Operator, target federation.ID, targetKind, targetID, detail string) error {
	if targetID == "" {
		targetID = target.String()
	}
	return audit.Append(ctx, operator, action, targetKind, targetID, "service", detail)
}

func (audit *OperatorAudit) Append(ctx context.Context, operator Operator, action, targetKind, targetID, outcome, detail string) error {
	if audit == nil || audit.store == nil || ctx == nil || !strings.HasPrefix(operator.SessionID, operatorSessionPrefix) || action == "" || len(action) > 128 || targetKind == "" || len(targetKind) > 128 || len(targetID) > 256 || outcome == "" || len(outcome) > 32 || strings.ContainsAny(action+targetKind+targetID+outcome, "\x00\r\n") {
		return ErrInvalid
	}
	fingerprint := strings.TrimPrefix(operator.SessionID, operatorSessionPrefix)
	if !validSHA256(fingerprint) {
		return ErrForbidden
	}
	now := audit.store.clock().UTC()
	tx, err := audit.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	previous := strings.Repeat("0", 64)
	err = tx.QueryRowContext(ctx, `SELECT event_digest FROM fleet_operator_audit ORDER BY sequence DESC LIMIT 1`).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	canonical, err := json.Marshal(struct {
		Domain, Fingerprint, TenantID, PrincipalID, Action, TargetKind, TargetID, Outcome, DetailDigest, PreviousDigest string
		OccurredAt time.Time
	}{"cyberpanel-central-operator-audit-v1", fingerprint, operator.TenantID, operator.PrincipalID, action, targetKind, targetID, outcome, digest([]byte(detail)), previous, now})
	if err != nil {
		return err
	}
	eventDigest := digest(canonical)
	eventID := "op_" + eventDigest[:48]
	if _, err = tx.ExecContext(ctx, `INSERT INTO fleet_operator_audit(event_id,occurred_at,certificate_fingerprint,tenant_id,principal_id,action,target_kind,target_id,outcome,detail_digest,previous_digest,event_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, eventID, now, fingerprint, operator.TenantID, operator.PrincipalID, action, targetKind, targetID, outcome, digest([]byte(detail)), previous, eventDigest); err != nil {
		return err
	}
	return tx.Commit()
}
