package dns

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	zoneOwnershipQuarantined = "quarantined"
	zoneOwnershipPending     = "pending"
	zoneOwnershipOwned       = "owned"
	zoneOwnershipDeleted     = "deleted"
)

// ZoneOwnership is the stable canonical ownership field consumed by inventory
// and federation projections. OwnerTenantID is assigned only from an explicit
// authenticated tenant or a completed privileged adoption; it is never derived
// from a zone name, record payload, DNSSEC state, or backend account string.
type ZoneOwnership struct {
	ZoneID        ZoneID  `json:"zone_id"`
	OwnerTenantID string  `json:"owner_tenant_id"`
	Name          DNSName `json:"name"`
	Generation    uint64  `json:"generation"`
	State         string  `json:"state"`
}

type ZoneOwnershipReceipt struct {
	EffectID           string           `json:"effect_id"`
	ZoneID             ZoneID           `json:"zone_id"`
	OwnerTenantID      string           `json:"owner_tenant_id"`
	Generation         uint64           `json:"generation"`
	State              string           `json:"state"`
	ObservedZoneDigest string           `json:"observed_zone_digest"`
	Authority          AuthorityReceipt `json:"authority"`
	ObservedAt         time.Time        `json:"observed_at"`
}

// TenantZoneBackend is the privileged PowerDNS broker surface needed by the
// canonical ownership coordinator. ConfirmZoneAbsent must check both the zone
// ID metadata and the reserved name without disclosing any conflicting owner.
type TenantZoneBackend interface {
	ApplyZone(context.Context, string, ZoneSpec, []RecordSet, []TransferPeerSpec) (AuthorityReceipt, error)
	DeleteZone(context.Context, string, ZoneSpec) (AuthorityReceipt, error)
	Zone(context.Context, string, ZoneID) (ZoneSpec, error)
	ObserveZone(context.Context, string, ZoneID, string) (ZoneSpec, AuthorityReceipt, error)
	ConfirmZoneAbsent(context.Context, ZoneID, DNSName) error
	ListRecordSets(context.Context, ZoneSpec, int, string) ([]RecordSet, string, error)
	ImportRecordSets(context.Context, string, ZoneSpec, []RecordSet, bool) (AuthorityReceipt, error)
	AdoptZone(context.Context, string, int64, ZoneSpec) (AuthorityReceipt, error)
	PresentACMETXT(context.Context, string, string, string, string) error
	RemoveACMETXT(context.Context, string, string, string, string) error
	GenerateAndPublish(context.Context, ZoneSpec, DNSSECPolicy, string) (KeyActivationReceipt, error)
	Retire(context.Context, ZoneSpec, []DNSSECKeyDescriptor, string) error
	Remove(context.Context, ZoneSpec, string) error
	Prove(context.Context, ZoneSpec, []DNSSECKeyDescriptor, []DSRecord) (DNSSECProof, error)
}

// TenantZoneAuthority binds every operation to the authenticated tenant before
// it crosses the PowerDNS broker boundary.
type TenantZoneAuthority struct {
	Repository Repository
	Backend    TenantZoneBackend
}

func NewTenantZoneAuthority(repository Repository, backend TenantZoneBackend) (*TenantZoneAuthority, error) {
	if repository.DB == nil || backend == nil {
		return nil, ErrInvalidDNS
	}
	return &TenantZoneAuthority{Repository: repository, Backend: backend}, nil
}

// Ownership is not reconstructed from legacy JSON. Empty pre-migration owners
// remain quarantined. Pending and deleted rows retain their name reservation so
// a crash or deletion cannot permit implicit reparenting.
func (r Repository) bootstrapOwnership(ctx context.Context) error {
	if r.DB == nil {
		return errors.New("dns db required")
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, Schema); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info(dns_zones)")
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var ordinal, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err = rows.Scan(&ordinal, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		columns[name] = true
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, column := range []struct{ name, ddl string }{
		{"tenant_id", "TEXT NOT NULL DEFAULT ''"},
		{"ownership_state", "TEXT NOT NULL DEFAULT 'quarantined'"},
		{"generation", "BIGINT NOT NULL DEFAULT 0"},
		{"zone_name", "TEXT NOT NULL DEFAULT ''"},
		{"zone_spec_json", "TEXT NOT NULL DEFAULT '{}'"},
		{"pending_effect", "TEXT NOT NULL DEFAULT ''"},
	} {
		if !columns[column.name] {
			if _, err = tx.ExecContext(ctx, "ALTER TABLE dns_zones ADD COLUMN "+column.name+" "+column.ddl); err != nil {
				return err
			}
		}
	}
	for _, statement := range []string{
		"CREATE INDEX IF NOT EXISTS dns_zones_tenant_page_v1 ON dns_zones(tenant_id,ownership_state,zone_name,id)",
		"CREATE UNIQUE INDEX IF NOT EXISTS dns_zones_reserved_name_v1 ON dns_zones(zone_name) WHERE zone_name<>''",
		"DROP TRIGGER IF EXISTS dns_zones_owner_immutable_v1",
		"DROP TRIGGER IF EXISTS dns_zones_owned_insert_v1",
		"DROP TRIGGER IF EXISTS dns_zones_owner_state_v1",
		"DROP TRIGGER IF EXISTS dns_zones_no_reparent_delete_v1",
		"CREATE TRIGGER dns_zones_owner_immutable_v1 BEFORE UPDATE OF tenant_id ON dns_zones WHEN OLD.tenant_id<>'' AND NEW.tenant_id<>OLD.tenant_id BEGIN SELECT RAISE(ABORT,'immutable DNS tenant'); END",
		"CREATE TRIGGER dns_zones_owned_insert_v1 BEFORE INSERT ON dns_zones WHEN NEW.ownership_state NOT IN ('quarantined','pending','owned') OR (NEW.ownership_state='quarantined' AND NEW.tenant_id<>'') OR (NEW.ownership_state<>'quarantined' AND NEW.tenant_id='') BEGIN SELECT RAISE(ABORT,'DNS owner required'); END",
		"CREATE TRIGGER dns_zones_owner_state_v1 BEFORE UPDATE ON dns_zones WHEN NEW.ownership_state NOT IN ('quarantined','pending','owned','deleted') OR (NEW.ownership_state='quarantined' AND NEW.tenant_id<>'') OR (NEW.ownership_state<>'quarantined' AND NEW.tenant_id='') BEGIN SELECT RAISE(ABORT,'invalid DNS owner state'); END",
		"CREATE TRIGGER dns_zones_no_reparent_delete_v1 BEFORE DELETE ON dns_zones BEGIN SELECT RAISE(ABORT,'DNS ownership must be tombstoned'); END",
		"CREATE TABLE IF NOT EXISTS dns_zone_operations_v1(effect_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,zone_id TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL,state TEXT NOT NULL,response_json BLOB,created_at TIMESTAMP NOT NULL,completed_at TIMESTAMP)",
		"CREATE TABLE IF NOT EXISTS dns_zone_adoptions_v1(effect_id TEXT PRIMARY KEY,actor_id TEXT NOT NULL,tenant_id TEXT NOT NULL,zone_id TEXT NOT NULL,backend_domain_id BIGINT NOT NULL,legacy_digest TEXT NOT NULL,reason TEXT NOT NULL,request_digest TEXT NOT NULL,state TEXT NOT NULL,observed_json BLOB,created_at TIMESTAMP NOT NULL,completed_at TIMESTAMP)",
	} {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func dnsOwnershipDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func LegacyZoneDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validZoneTenant(value string) bool {
	return value != "" && len(value) <= 512 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func sameZoneSpec(left, right ZoneSpec) bool {
	leftDigest, leftErr := dnsOwnershipDigest(left)
	rightDigest, rightErr := dnsOwnershipDigest(right)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

func (r Repository) OwnedZone(ctx context.Context, tenant string, id ZoneID) (ZoneSpec, error) {
	if r.DB == nil || !validZoneTenant(tenant) || id == "" {
		return ZoneSpec{}, ErrInvalidDNS
	}
	var raw []byte
	err := r.DB.QueryRowContext(ctx, "SELECT zone_spec_json FROM dns_zones WHERE id=? AND tenant_id=? AND ownership_state='owned' AND pending_effect=''", id, tenant).Scan(&raw)
	if err != nil {
		return ZoneSpec{}, err
	}
	var zone ZoneSpec
	if json.Unmarshal(raw, &zone) != nil || zone.ID != id || zone.TenantID != tenant || validateZoneSpec(zone, nil, nil) != nil {
		return ZoneSpec{}, ErrDNSConflict
	}
	return zone, nil
}

func (r Repository) ZoneOwnership(ctx context.Context, tenant string, id ZoneID) (ZoneOwnership, error) {
	if r.DB == nil || !validZoneTenant(tenant) || id == "" {
		return ZoneOwnership{}, ErrInvalidDNS
	}
	var name, state string
	var generation uint64
	err := r.DB.QueryRowContext(ctx, "SELECT zone_name,generation,ownership_state FROM dns_zones WHERE id=? AND tenant_id=? AND ownership_state IN ('owned','deleted') AND pending_effect=''", id, tenant).Scan(&name, &generation, &state)
	if err != nil {
		return ZoneOwnership{}, err
	}
	parsed, err := ParseName(name)
	if err != nil || parsed.String() == "@" || generation == 0 {
		return ZoneOwnership{}, ErrDNSConflict
	}
	return ZoneOwnership{ZoneID: id, OwnerTenantID: tenant, Name: parsed, Generation: generation, State: state}, nil
}

func (r Repository) listOwnedZones(ctx context.Context, tenant string, limit int, after string) ([]ZoneSpec, string, error) {
	if r.DB == nil || !validZoneTenant(tenant) || limit < 1 || limit > 500 || len(after) > 253 {
		return nil, "", ErrInvalidDNS
	}
	if after != "" {
		name, err := ParseName(after)
		if err != nil || name.String() != after || name.String() == "@" {
			return nil, "", ErrInvalidDNS
		}
	}
	rows, err := r.DB.QueryContext(ctx, "SELECT id,zone_name,zone_spec_json FROM dns_zones WHERE tenant_id=? AND ownership_state='owned' AND pending_effect='' AND zone_name>? ORDER BY zone_name,id LIMIT ?", tenant, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]ZoneSpec, 0, limit+1)
	for rows.Next() {
		var id ZoneID
		var name string
		var raw []byte
		if err = rows.Scan(&id, &name, &raw); err != nil {
			return nil, "", err
		}
		var zone ZoneSpec
		if json.Unmarshal(raw, &zone) != nil || zone.ID != id || zone.TenantID != tenant || zone.Name.String() != name || validateZoneSpec(zone, nil, nil) != nil {
			return nil, "", ErrDNSConflict
		}
		items = append(items, zone)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > limit {
		next = items[limit-1].Name.String()
		items = items[:limit]
	}
	return items, next, nil
}

func requireDNSTenant(ctx context.Context, tx *sql.Tx, tenant string) error {
	if !validZoneTenant(tenant) {
		return ErrInvalidDNS
	}
	var id string
	return tx.QueryRowContext(ctx, "SELECT id FROM identity_tenants WHERE id=? AND state='active'", tenant).Scan(&id)
}

func (r Repository) reservedNameConflict(ctx context.Context, tx *sql.Tx, spec ZoneSpec) error {
	rows, err := tx.QueryContext(ctx, "SELECT tenant_id,ownership_state FROM dns_zones WHERE zone_name=? AND id<>? LIMIT 2", spec.Name.String(), spec.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var owner, state string
		if err = rows.Scan(&owner, &state); err != nil {
			return err
		}
		if owner != "" && owner != spec.TenantID {
			return sql.ErrNoRows
		}
		return ErrDNSConflict
	}
	return rows.Err()
}

func (r Repository) zoneOperationExists(ctx context.Context, effect, operation, digest string, spec ZoneSpec) (bool, error) {
	var tenant, zone, storedOperation, storedDigest string
	err := r.DB.QueryRowContext(ctx, "SELECT tenant_id,zone_id,operation,request_digest FROM dns_zone_operations_v1 WHERE effect_id=?", effect).Scan(&tenant, &zone, &storedOperation, &storedDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if tenant != spec.TenantID {
		return false, sql.ErrNoRows
	}
	if zone != string(spec.ID) || storedOperation != operation || storedDigest != digest {
		return false, ErrDNSConflict
	}
	return true, nil
}

func (r Repository) newZoneCandidate(ctx context.Context, spec ZoneSpec) (bool, error) {
	var activeTenant string
	if err := r.DB.QueryRowContext(ctx, "SELECT id FROM identity_tenants WHERE id=? AND state='active'", spec.TenantID).Scan(&activeTenant); err != nil {
		return false, err
	}
	var owner string
	err := r.DB.QueryRowContext(ctx, "SELECT tenant_id FROM dns_zones WHERE id=?", spec.ID).Scan(&owner)
	if err == nil {
		if owner != "" && owner != spec.TenantID {
			return false, sql.ErrNoRows
		}
		if owner == "" {
			return false, sql.ErrNoRows
		}
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	err = r.DB.QueryRowContext(ctx, "SELECT tenant_id FROM dns_zones WHERE zone_name=? LIMIT 1", spec.Name.String()).Scan(&owner)
	if err == nil {
		if owner != "" && owner != spec.TenantID {
			return false, sql.ErrNoRows
		}
		return false, ErrDNSConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	return true, nil
}

// reserveZone commits the exact request before crossing into the separate
// authoritative database. A pending row is deliberately not readable inventory.
func (r Repository) reserveZone(ctx context.Context, effect, operation, digest string, spec ZoneSpec) (AuthorityReceipt, bool, error) {
	if r.DB == nil || !validPowerDNSEffectID(effect) || !validZoneTenant(spec.TenantID) || spec.ID == "" || spec.Generation == 0 {
		return AuthorityReceipt{}, false, ErrInvalidDNS
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return AuthorityReceipt{}, false, err
	}
	defer tx.Rollback()
	var oldTenant, oldZone, oldOperation, oldDigest, state string
	var response []byte
	err = tx.QueryRowContext(ctx, "SELECT tenant_id,zone_id,operation,request_digest,state,response_json FROM dns_zone_operations_v1 WHERE effect_id=?", effect).Scan(&oldTenant, &oldZone, &oldOperation, &oldDigest, &state, &response)
	if err == nil {
		if oldTenant != spec.TenantID {
			return AuthorityReceipt{}, false, sql.ErrNoRows
		}
		if oldZone != string(spec.ID) || oldOperation != operation || oldDigest != digest {
			return AuthorityReceipt{}, false, ErrDNSConflict
		}
		if state == "complete" {
			var completed ZoneOwnershipReceipt
			if json.Unmarshal(response, &completed) != nil || completed.ZoneID != spec.ID || completed.OwnerTenantID != spec.TenantID || completed.EffectID != effect || completed.Authority.EffectID != effect || completed.Authority.ZoneID != spec.ID {
				return AuthorityReceipt{}, false, ErrDNSConflict
			}
			return completed.Authority, true, tx.Commit()
		}
		if state != "pending" {
			return AuthorityReceipt{}, false, ErrDNSConflict
		}
		return AuthorityReceipt{}, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuthorityReceipt{}, false, err
	}
	if err = requireDNSTenant(ctx, tx, spec.TenantID); err != nil {
		return AuthorityReceipt{}, false, err
	}
	if err = r.reservedNameConflict(ctx, tx, spec); err != nil {
		return AuthorityReceipt{}, false, err
	}
	var owner, name, pending string
	var generation uint64
	err = tx.QueryRowContext(ctx, "SELECT tenant_id,ownership_state,generation,zone_name,pending_effect FROM dns_zones WHERE id=?", spec.ID).Scan(&owner, &state, &generation, &name, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		if operation != "apply" || spec.Generation != 1 {
			return AuthorityReceipt{}, false, sql.ErrNoRows
		}
		// Legacy JSON reserves an existing name but never supplies its owner. A
		// malformed legacy row blocks creation until a privileged reconciliation.
		var collisions int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM dns_zones WHERE ownership_state='quarantined' AND (NOT json_valid(zone_json) OR lower(rtrim(json_extract(zone_json,'$.name'),'.'))=?)", spec.Name.String()).Scan(&collisions); err != nil {
			return AuthorityReceipt{}, false, err
		}
		if collisions != 0 {
			return AuthorityReceipt{}, false, ErrDNSConflict
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO dns_zones(id,zone_json,tenant_id,ownership_state,generation,zone_name,pending_effect) VALUES(?,'{}',?,'pending',0,?,?)", spec.ID, spec.TenantID, spec.Name.String(), effect)
	} else if err == nil {
		if owner != spec.TenantID {
			return AuthorityReceipt{}, false, sql.ErrNoRows
		}
		if state == zoneOwnershipQuarantined || state == zoneOwnershipDeleted {
			return AuthorityReceipt{}, false, sql.ErrNoRows
		}
		if pending != "" || state != zoneOwnershipOwned || name != spec.Name.String() || operation == "delete" && generation != spec.Generation || operation != "delete" && generation+1 != spec.Generation {
			return AuthorityReceipt{}, false, ErrDNSConflict
		}
		result, updateErr := tx.ExecContext(ctx, "UPDATE dns_zones SET ownership_state='pending',pending_effect=? WHERE id=? AND tenant_id=? AND ownership_state='owned' AND pending_effect=''", effect, spec.ID, spec.TenantID)
		if updateErr != nil {
			return AuthorityReceipt{}, false, updateErr
		}
		affected, affectedErr := result.RowsAffected()
		if affectedErr != nil || affected != 1 {
			return AuthorityReceipt{}, false, errors.Join(ErrDNSConflict, affectedErr)
		}
	}
	if err != nil {
		return AuthorityReceipt{}, false, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO dns_zone_operations_v1(effect_id,tenant_id,zone_id,operation,request_digest,state,created_at) VALUES(?,?,?,?,?,'pending',?)", effect, spec.TenantID, spec.ID, operation, digest, time.Now().UTC())
	if err != nil {
		return AuthorityReceipt{}, false, err
	}
	return AuthorityReceipt{}, false, tx.Commit()
}

func (r Repository) finishZone(ctx context.Context, effect string, spec, observed ZoneSpec, receipt AuthorityReceipt, deleted bool) (AuthorityReceipt, error) {
	if receipt.EffectID != effect || receipt.ZoneID != spec.ID || receipt.ObservedAt.IsZero() || spec.TenantID == "" {
		return AuthorityReceipt{}, ErrDNSConflict
	}
	observedDigest := LegacyZoneDigest([]byte("absent"))
	if !deleted {
		if !sameZoneSpec(spec, observed) {
			return AuthorityReceipt{}, ErrDNSConflict
		}
		var err error
		observedDigest, err = dnsOwnershipDigest(observed)
		if err != nil {
			return AuthorityReceipt{}, err
		}
	}
	specRaw, err := json.Marshal(spec)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	role := Primary
	if spec.Mode == ZoneSecondary {
		role = Secondary
	}
	zoneRaw, err := json.Marshal(Zone{ID: spec.ID, TenantID: spec.TenantID, Name: spec.Name.String(), Role: role, Provider: "powerdns", Serial: receipt.Serial})
	if err != nil {
		return AuthorityReceipt{}, err
	}
	state := zoneOwnershipOwned
	if deleted {
		state = zoneOwnershipDeleted
	}
	completed := ZoneOwnershipReceipt{EffectID: effect, ZoneID: spec.ID, OwnerTenantID: spec.TenantID, Generation: spec.Generation, State: state, ObservedZoneDigest: observedDigest, Authority: receipt, ObservedAt: time.Now().UTC()}
	response, err := json.Marshal(completed)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return AuthorityReceipt{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE dns_zones SET zone_json=?,zone_spec_json=?,generation=?,ownership_state=?,pending_effect='' WHERE id=? AND tenant_id=? AND pending_effect=? AND ownership_state='pending'", zoneRaw, specRaw, spec.Generation, state, spec.ID, spec.TenantID, effect)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return AuthorityReceipt{}, errors.Join(ErrDNSConflict, err)
	}
	result, err = tx.ExecContext(ctx, "UPDATE dns_zone_operations_v1 SET state='complete',response_json=?,completed_at=? WHERE effect_id=? AND tenant_id=? AND zone_id=? AND state='pending'", response, completed.ObservedAt, effect, spec.TenantID, spec.ID)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	affected, err = result.RowsAffected()
	if err != nil || affected != 1 {
		return AuthorityReceipt{}, errors.Join(ErrDNSConflict, err)
	}
	if err = tx.Commit(); err != nil {
		return AuthorityReceipt{}, err
	}
	return receipt, nil
}

func bindAuthenticatedZone(tenant string, spec ZoneSpec) (ZoneSpec, error) {
	if !validZoneTenant(tenant) || spec.TenantID != tenant || validateZoneSpec(spec, nil, nil) != nil {
		if validZoneTenant(tenant) && spec.TenantID != "" && spec.TenantID != tenant {
			return ZoneSpec{}, sql.ErrNoRows
		}
		return ZoneSpec{}, ErrInvalidDNS
	}
	return spec, nil
}

func validObservedReceipt(receipt AuthorityReceipt, effect string, zone ZoneID) bool {
	return receipt.EffectID == effect && receipt.ZoneID == zone && receipt.Serial > 0 && !receipt.ObservedAt.IsZero()
}

func chooseObservedReceipt(returned, observed AuthorityReceipt, effect string, zone ZoneID) AuthorityReceipt {
	if validObservedReceipt(returned, effect, zone) && (returned.Serial == 0 || observed.Serial == 0 || returned.Serial == observed.Serial) {
		returned.ObservedAt = observed.ObservedAt
		if returned.Serial == 0 {
			returned.Serial = observed.Serial
		}
		return returned
	}
	return observed
}

func (authority *TenantZoneAuthority) mutateZone(ctx context.Context, tenant, effect, operation string, spec ZoneSpec, request any, invoke func() (AuthorityReceipt, error)) (AuthorityReceipt, error) {
	if authority == nil || authority.Backend == nil || authority.Repository.DB == nil || ctx == nil {
		return AuthorityReceipt{}, ErrInvalidDNS
	}
	var err error
	spec, err = bindAuthenticatedZone(tenant, spec)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	digest, err := dnsOwnershipDigest(request)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	replay, err := authority.Repository.zoneOperationExists(ctx, effect, operation, digest, spec)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	if !replay && operation == "apply" && spec.Generation == 1 {
		candidate, candidateErr := authority.Repository.newZoneCandidate(ctx, spec)
		if candidateErr != nil {
			return AuthorityReceipt{}, candidateErr
		}
		if candidate {
			if err = authority.Backend.ConfirmZoneAbsent(ctx, spec.ID, spec.Name); err != nil {
				return AuthorityReceipt{}, err
			}
		}
	}
	completed, done, err := authority.Repository.reserveZone(ctx, effect, operation, digest, spec)
	if err != nil || done {
		return completed, err
	}
	current, observedReceipt, observeErr := authority.Backend.ObserveZone(ctx, tenant, spec.ID, effect)
	if observeErr == nil && sameZoneSpec(current, spec) {
		return authority.Repository.finishZone(ctx, effect, spec, current, observedReceipt, false)
	}
	if observeErr != nil && !errors.Is(observeErr, sql.ErrNoRows) {
		return AuthorityReceipt{}, observeErr
	}
	returned, mutationErr := invoke()
	observed, afterReceipt, afterErr := authority.Backend.ObserveZone(ctx, tenant, spec.ID, effect)
	if afterErr != nil {
		if mutationErr != nil {
			return returned, errors.Join(mutationErr, afterErr)
		}
		return returned, afterErr
	}
	if !sameZoneSpec(observed, spec) || !validObservedReceipt(afterReceipt, effect, spec.ID) {
		return returned, ErrDNSConflict
	}
	finalReceipt := chooseObservedReceipt(returned, afterReceipt, effect, spec.ID)
	finalReceipt, finishErr := authority.Repository.finishZone(ctx, effect, spec, observed, finalReceipt, false)
	if finishErr != nil {
		return finalReceipt, errors.Join(mutationErr, finishErr)
	}
	return finalReceipt, mutationErr
}

func (authority *TenantZoneAuthority) ApplyZoneForTenant(ctx context.Context, tenant, effect string, spec ZoneSpec, sets []RecordSet, peers []TransferPeerSpec) (AuthorityReceipt, error) {
	normalizedPeers, err := normalizePowerDNSTransferPeers(peers)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	for _, set := range sets {
		if set.ZoneID != spec.ID {
			return AuthorityReceipt{}, ErrInvalidDNS
		}
	}
	if err = validateZoneSpec(spec, sets, normalizedPeers); err != nil {
		return AuthorityReceipt{}, err
	}
	request := struct {
		Operation string             `json:"operation"`
		Zone      ZoneSpec           `json:"zone"`
		Sets      []RecordSet        `json:"record_sets"`
		Peers     []TransferPeerSpec `json:"transfer_peers"`
	}{"apply", spec, sets, normalizedPeers}
	return authority.mutateZone(ctx, tenant, effect, "apply", spec, request, func() (AuthorityReceipt, error) {
		return authority.Backend.ApplyZone(ctx, effect, spec, sets, normalizedPeers)
	})
}

func (authority *TenantZoneAuthority) ImportRecordSetsForTenant(ctx context.Context, tenant, effect string, spec ZoneSpec, sets []RecordSet, replace bool) (AuthorityReceipt, error) {
	if len(sets) == 0 && !replace || len(sets) > 10000 {
		return AuthorityReceipt{}, ErrInvalidDNS
	}
	for _, set := range sets {
		if set.ZoneID != spec.ID {
			return AuthorityReceipt{}, ErrInvalidDNS
		}
	}
	if err := validateZoneSpec(spec, sets, nil); err != nil {
		return AuthorityReceipt{}, err
	}
	request := struct {
		Operation string      `json:"operation"`
		Zone      ZoneSpec    `json:"zone"`
		Sets      []RecordSet `json:"record_sets"`
		Replace   bool        `json:"replace"`
	}{"import", spec, sets, replace}
	return authority.mutateZone(ctx, tenant, effect, "import", spec, request, func() (AuthorityReceipt, error) {
		return authority.Backend.ImportRecordSets(ctx, effect, spec, sets, replace)
	})
}

func (authority *TenantZoneAuthority) DeleteZoneForTenant(ctx context.Context, tenant, effect string, spec ZoneSpec) (AuthorityReceipt, error) {
	if authority == nil || authority.Backend == nil || authority.Repository.DB == nil || ctx == nil {
		return AuthorityReceipt{}, ErrInvalidDNS
	}
	var err error
	spec, err = bindAuthenticatedZone(tenant, spec)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	request := struct {
		Operation string   `json:"operation"`
		Zone      ZoneSpec `json:"zone"`
	}{"delete", spec}
	digest, err := dnsOwnershipDigest(request)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	completed, done, err := authority.Repository.reserveZone(ctx, effect, "delete", digest, spec)
	if err != nil || done {
		return completed, err
	}
	current, _, observeErr := authority.Backend.ObserveZone(ctx, tenant, spec.ID, effect)
	if errors.Is(observeErr, sql.ErrNoRows) {
		if absentErr := authority.Backend.ConfirmZoneAbsent(ctx, spec.ID, spec.Name); absentErr != nil {
			return AuthorityReceipt{}, absentErr
		}
		receipt := AuthorityReceipt{EffectID: effect, ZoneID: spec.ID, ObservedAt: time.Now().UTC()}
		return authority.Repository.finishZone(ctx, effect, spec, ZoneSpec{}, receipt, true)
	}
	if observeErr != nil {
		return AuthorityReceipt{}, observeErr
	}
	if !sameZoneSpec(current, spec) {
		return AuthorityReceipt{}, ErrDNSConflict
	}
	returned, deleteErr := authority.Backend.DeleteZone(ctx, effect, spec)
	if absentErr := authority.Backend.ConfirmZoneAbsent(ctx, spec.ID, spec.Name); absentErr != nil {
		return returned, errors.Join(deleteErr, absentErr)
	}
	if !validObservedReceipt(returned, effect, spec.ID) {
		returned = AuthorityReceipt{EffectID: effect, ZoneID: spec.ID, ObservedAt: time.Now().UTC()}
	}
	returned, finishErr := authority.Repository.finishZone(ctx, effect, spec, ZoneSpec{}, returned, true)
	if finishErr != nil {
		return returned, errors.Join(deleteErr, finishErr)
	}
	return returned, deleteErr
}

func (authority *TenantZoneAuthority) Zone(ctx context.Context, tenant string, id ZoneID) (ZoneSpec, error) {
	if authority == nil || authority.Backend == nil || ctx == nil {
		return ZoneSpec{}, ErrInvalidDNS
	}
	canonical, err := authority.Repository.OwnedZone(ctx, tenant, id)
	if err != nil {
		return ZoneSpec{}, err
	}
	observed, err := authority.Backend.Zone(ctx, tenant, id)
	if err != nil {
		return ZoneSpec{}, err
	}
	if !sameZoneSpec(canonical, observed) {
		return ZoneSpec{}, ErrDNSConflict
	}
	return canonical, nil
}

func (authority *TenantZoneAuthority) ListZones(ctx context.Context, tenant string, limit int, cursor string) ([]ZoneSpec, string, error) {
	if authority == nil || authority.Backend == nil || ctx == nil {
		return nil, "", ErrInvalidDNS
	}
	if limit < 1 || limit > 500 {
		limit = 100
	}
	items, next, err := authority.Repository.listOwnedZones(ctx, tenant, limit, cursor)
	if err != nil {
		return nil, "", err
	}
	for _, canonical := range items {
		observed, observeErr := authority.Backend.Zone(ctx, tenant, canonical.ID)
		if observeErr != nil {
			return nil, "", observeErr
		}
		if !sameZoneSpec(canonical, observed) {
			return nil, "", ErrDNSConflict
		}
	}
	return items, next, nil
}

func (authority *TenantZoneAuthority) ListRecordSetsForTenant(ctx context.Context, tenant string, spec ZoneSpec, limit int, cursor string) ([]RecordSet, string, error) {
	if authority == nil || authority.Backend == nil || ctx == nil {
		return nil, "", ErrInvalidDNS
	}
	bound, err := bindAuthenticatedZone(tenant, spec)
	if err != nil {
		return nil, "", err
	}
	canonical, err := authority.Zone(ctx, tenant, bound.ID)
	if err != nil {
		return nil, "", err
	}
	if !sameZoneSpec(canonical, bound) {
		return nil, "", ErrDNSConflict
	}
	return authority.Backend.ListRecordSets(ctx, canonical, limit, cursor)
}

func (authority *TenantZoneAuthority) ownedZoneForName(ctx context.Context, tenant, owner string) (ZoneSpec, error) {
	name, err := ParseName(owner)
	if err != nil || name.String() == "@" {
		return ZoneSpec{}, ErrInvalidDNS
	}
	cursor := ""
	var matched ZoneSpec
	for {
		zones, next, listErr := authority.Repository.listOwnedZones(ctx, tenant, 500, cursor)
		if listErr != nil {
			return ZoneSpec{}, listErr
		}
		for _, zone := range zones {
			zoneName := zone.Name.String()
			if name.String() == zoneName || strings.HasSuffix(name.String(), "."+zoneName) {
				if len(zoneName) > len(matched.Name.String()) {
					matched = zone
				}
			}
		}
		if next == "" {
			break
		}
		if next == cursor {
			return ZoneSpec{}, ErrDNSConflict
		}
		cursor = next
	}
	if matched.ID == "" {
		return ZoneSpec{}, sql.ErrNoRows
	}
	return authority.Zone(ctx, tenant, matched.ID)
}

func (authority *TenantZoneAuthority) mutateACMETXT(ctx context.Context, tenant, owner, value, effect string, remove bool) error {
	if authority == nil || authority.Backend == nil || ctx == nil || !validZoneTenant(tenant) {
		return ErrInvalidDNS
	}
	zone, err := authority.ownedZoneForName(ctx, tenant, owner)
	if err != nil {
		return err
	}
	if remove {
		err = authority.Backend.RemoveACMETXT(ctx, tenant, owner, value, effect)
	} else {
		err = authority.Backend.PresentACMETXT(ctx, tenant, owner, value, effect)
	}
	observed, observeErr := authority.Backend.Zone(ctx, tenant, zone.ID)
	if observeErr != nil || !sameZoneSpec(zone, observed) {
		return errors.Join(err, observeErr, ErrDNSConflict)
	}
	return err
}

func (authority *TenantZoneAuthority) PresentACMETXT(ctx context.Context, tenant, owner, value, effect string) error {
	return authority.mutateACMETXT(ctx, tenant, owner, value, effect, false)
}

func (authority *TenantZoneAuthority) RemoveACMETXT(ctx context.Context, tenant, owner, value, effect string) error {
	return authority.mutateACMETXT(ctx, tenant, owner, value, effect, true)
}

func (authority *TenantZoneAuthority) canonicalDNSSECZone(ctx context.Context, zone ZoneSpec) (ZoneSpec, error) {
	if authority == nil || authority.Backend == nil || ctx == nil || zone.TenantID == "" || zone.ID == "" {
		return ZoneSpec{}, ErrInvalidDNS
	}
	canonical, err := authority.Zone(ctx, zone.TenantID, zone.ID)
	if err != nil {
		return ZoneSpec{}, err
	}
	if !sameZoneSpec(canonical, zone) {
		return ZoneSpec{}, ErrDNSConflict
	}
	return canonical, nil
}

func (authority *TenantZoneAuthority) confirmDNSSECOwner(ctx context.Context, zone ZoneSpec, operationErr error) error {
	observed, err := authority.Zone(ctx, zone.TenantID, zone.ID)
	if err != nil || !sameZoneSpec(observed, zone) {
		return errors.Join(operationErr, err, ErrDNSConflict)
	}
	return operationErr
}

func (authority *TenantZoneAuthority) GenerateAndPublish(ctx context.Context, zone ZoneSpec, policy DNSSECPolicy, effect string) (KeyActivationReceipt, error) {
	canonical, err := authority.canonicalDNSSECZone(ctx, zone)
	if err != nil {
		return KeyActivationReceipt{}, err
	}
	receipt, operationErr := authority.Backend.GenerateAndPublish(ctx, canonical, policy, effect)
	return receipt, authority.confirmDNSSECOwner(ctx, canonical, operationErr)
}

func (authority *TenantZoneAuthority) Retire(ctx context.Context, zone ZoneSpec, keys []DNSSECKeyDescriptor, effect string) error {
	canonical, err := authority.canonicalDNSSECZone(ctx, zone)
	if err != nil {
		return err
	}
	return authority.confirmDNSSECOwner(ctx, canonical, authority.Backend.Retire(ctx, canonical, keys, effect))
}

func (authority *TenantZoneAuthority) Remove(ctx context.Context, zone ZoneSpec, effect string) error {
	canonical, err := authority.canonicalDNSSECZone(ctx, zone)
	if err != nil {
		return err
	}
	return authority.confirmDNSSECOwner(ctx, canonical, authority.Backend.Remove(ctx, canonical, effect))
}

func (authority *TenantZoneAuthority) Prove(ctx context.Context, zone ZoneSpec, keys []DNSSECKeyDescriptor, records []DSRecord) (DNSSECProof, error) {
	canonical, err := authority.canonicalDNSSECZone(ctx, zone)
	if err != nil {
		return DNSSECProof{}, err
	}
	return authority.Backend.Prove(ctx, canonical, keys, records)
}

// ZoneAdoption is an explicit privileged instruction, not an ordinary zone
// mutation. LegacyDigest covers the exact pre-migration zone_json bytes; "-" is
// allowed only for a backend-only zone with no canonical ID/name reservation.
type ZoneAdoption struct {
	Zone            ZoneSpec `json:"zone"`
	BackendDomainID int64    `json:"backend_domain_id"`
	LegacyDigest    string   `json:"legacy_digest"`
	Reason          string   `json:"reason"`
}

type ZoneAdoptionReceipt struct {
	EffectID        string           `json:"effect_id"`
	ActorID         string           `json:"actor_id"`
	Reason          string           `json:"reason"`
	OwnerTenantID   string           `json:"owner_tenant_id"`
	ZoneID          ZoneID           `json:"zone_id"`
	BackendDomainID int64            `json:"backend_domain_id"`
	LegacyDigest    string           `json:"legacy_digest"`
	MetadataDigest  string           `json:"metadata_digest"`
	Authority       AuthorityReceipt `json:"authority"`
	ObservedAt      time.Time        `json:"observed_at"`
}

func validLegacyDigest(value string) bool {
	if value == "-" {
		return true
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func (r Repository) reserveAdoption(ctx context.Context, effect, actor string, request ZoneAdoption) (ZoneAdoptionReceipt, bool, error) {
	if r.DB == nil || actor == "" || len(actor) > 512 || strings.TrimSpace(actor) != actor || strings.ContainsAny(actor, "\x00\r\n\t") || request.BackendDomainID < 1 || len(request.Reason) < 8 || len(request.Reason) > 1024 || strings.TrimSpace(request.Reason) != request.Reason || strings.ContainsAny(request.Reason, "\x00\r\n") || request.Zone.Generation != 1 || validateZoneSpec(request.Zone, nil, nil) != nil || !validPowerDNSEffectID(effect) || !validLegacyDigest(request.LegacyDigest) {
		return ZoneAdoptionReceipt{}, false, ErrInvalidDNS
	}
	digest, err := dnsOwnershipDigest(struct {
		Actor   string       `json:"actor"`
		Request ZoneAdoption `json:"request"`
	}{actor, request})
	if err != nil {
		return ZoneAdoptionReceipt{}, false, err
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ZoneAdoptionReceipt{}, false, err
	}
	defer tx.Rollback()
	var oldTenant, oldDigest, state string
	var observed []byte
	err = tx.QueryRowContext(ctx, "SELECT tenant_id,request_digest,state,observed_json FROM dns_zone_adoptions_v1 WHERE effect_id=?", effect).Scan(&oldTenant, &oldDigest, &state, &observed)
	if err == nil {
		if oldTenant != request.Zone.TenantID {
			return ZoneAdoptionReceipt{}, false, sql.ErrNoRows
		}
		if oldDigest != digest {
			return ZoneAdoptionReceipt{}, false, ErrDNSConflict
		}
		if state == "complete" {
			var receipt ZoneAdoptionReceipt
			if json.Unmarshal(observed, &receipt) != nil || receipt.EffectID != effect || receipt.ActorID != actor || receipt.Reason != request.Reason || receipt.ZoneID != request.Zone.ID || receipt.OwnerTenantID != request.Zone.TenantID || receipt.BackendDomainID != request.BackendDomainID || receipt.LegacyDigest != request.LegacyDigest {
				return ZoneAdoptionReceipt{}, false, ErrDNSConflict
			}
			return receipt, true, tx.Commit()
		}
		if state != "pending" {
			return ZoneAdoptionReceipt{}, false, ErrDNSConflict
		}
		return ZoneAdoptionReceipt{}, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ZoneAdoptionReceipt{}, false, err
	}
	if err = requireDNSTenant(ctx, tx, request.Zone.TenantID); err != nil {
		return ZoneAdoptionReceipt{}, false, err
	}
	if err = r.reservedNameConflict(ctx, tx, request.Zone); err != nil {
		return ZoneAdoptionReceipt{}, false, err
	}
	var owner, pending string
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT tenant_id,ownership_state,pending_effect,zone_json FROM dns_zones WHERE id=?", request.Zone.ID).Scan(&owner, &state, &pending, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		if request.LegacyDigest != "-" {
			return ZoneAdoptionReceipt{}, false, sql.ErrNoRows
		}
		var collisions int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM dns_zones WHERE zone_name=? OR (ownership_state='quarantined' AND (NOT json_valid(zone_json) OR lower(rtrim(json_extract(zone_json,'$.name'),'.'))=?)", request.Zone.Name.String(), request.Zone.Name.String()).Scan(&collisions); err != nil {
			return ZoneAdoptionReceipt{}, false, err
		}
		if collisions != 0 {
			return ZoneAdoptionReceipt{}, false, ErrDNSConflict
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO dns_zones(id,zone_json,tenant_id,ownership_state,zone_name,pending_effect) VALUES(?,'{}','','quarantined',?,?)", request.Zone.ID, request.Zone.Name.String(), effect)
	} else if err == nil {
		if owner != "" || state != zoneOwnershipQuarantined || pending != "" || LegacyZoneDigest(raw) != request.LegacyDigest {
			return ZoneAdoptionReceipt{}, false, ErrDNSConflict
		}
		var legacy Zone
		if json.Unmarshal(raw, &legacy) != nil || legacy.ID != request.Zone.ID {
			return ZoneAdoptionReceipt{}, false, ErrDNSConflict
		}
		name, parseErr := ParseName(legacy.Name)
		if parseErr != nil || name.String() != request.Zone.Name.String() {
			return ZoneAdoptionReceipt{}, false, ErrDNSConflict
		}
		var collisions int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM dns_zones WHERE id<>? AND ownership_state='quarantined' AND (NOT json_valid(zone_json) OR lower(rtrim(json_extract(zone_json,'$.name'),'.'))=?)", request.Zone.ID, request.Zone.Name.String()).Scan(&collisions); err != nil {
			return ZoneAdoptionReceipt{}, false, err
		}
		if collisions != 0 {
			return ZoneAdoptionReceipt{}, false, ErrDNSConflict
		}
		result, updateErr := tx.ExecContext(ctx, "UPDATE dns_zones SET zone_name=?,pending_effect=? WHERE id=? AND tenant_id='' AND ownership_state='quarantined' AND pending_effect=''", request.Zone.Name.String(), effect, request.Zone.ID)
		if updateErr != nil {
			return ZoneAdoptionReceipt{}, false, updateErr
		}
		affected, affectedErr := result.RowsAffected()
		if affectedErr != nil || affected != 1 {
			return ZoneAdoptionReceipt{}, false, errors.Join(ErrDNSConflict, affectedErr)
		}
	}
	if err != nil {
		return ZoneAdoptionReceipt{}, false, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO dns_zone_adoptions_v1(effect_id,actor_id,tenant_id,zone_id,backend_domain_id,legacy_digest,reason,request_digest,state,created_at) VALUES(?,?,?,?,?,?,?,?,'pending',?)", effect, actor, request.Zone.TenantID, request.Zone.ID, request.BackendDomainID, request.LegacyDigest, request.Reason, digest, time.Now().UTC())
	if err != nil {
		return ZoneAdoptionReceipt{}, false, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO dns_zone_operations_v1(effect_id,tenant_id,zone_id,operation,request_digest,state,created_at) VALUES(?,?,?,'adopt',?,'pending',?)", effect, request.Zone.TenantID, request.Zone.ID, digest, time.Now().UTC())
	if err != nil {
		return ZoneAdoptionReceipt{}, false, err
	}
	return ZoneAdoptionReceipt{}, false, tx.Commit()
}

func (r Repository) finishAdoption(ctx context.Context, effect, actor string, request ZoneAdoption, observed ZoneSpec, authority AuthorityReceipt) (ZoneAdoptionReceipt, error) {
	if !sameZoneSpec(request.Zone, observed) || !validObservedReceipt(authority, effect, request.Zone.ID) {
		return ZoneAdoptionReceipt{}, ErrDNSConflict
	}
	metadataDigest, err := dnsOwnershipDigest(struct {
		DomainID   int64  `json:"domain_id"`
		ZoneID     ZoneID `json:"zone_id"`
		TenantID   string `json:"tenant_id"`
		Generation uint64 `json:"generation"`
	}{request.BackendDomainID, observed.ID, observed.TenantID, observed.Generation})
	if err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	observedZoneDigest, err := dnsOwnershipDigest(observed)
	if err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	receipt := ZoneAdoptionReceipt{EffectID: effect, ActorID: actor, Reason: request.Reason, OwnerTenantID: observed.TenantID, ZoneID: observed.ID, BackendDomainID: request.BackendDomainID, LegacyDigest: request.LegacyDigest, MetadataDigest: metadataDigest, Authority: authority, ObservedAt: time.Now().UTC()}
	observedRaw, err := json.Marshal(receipt)
	if err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	specRaw, err := json.Marshal(observed)
	if err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	role := Primary
	if observed.Mode == ZoneSecondary {
		role = Secondary
	}
	zoneRaw, err := json.Marshal(Zone{ID: observed.ID, TenantID: observed.TenantID, Name: observed.Name.String(), Role: role, Provider: "powerdns", Serial: authority.Serial})
	if err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	ownership := ZoneOwnershipReceipt{EffectID: effect, ZoneID: observed.ID, OwnerTenantID: observed.TenantID, Generation: observed.Generation, State: zoneOwnershipOwned, ObservedZoneDigest: observedZoneDigest, Authority: authority, ObservedAt: receipt.ObservedAt}
	operationRaw, err := json.Marshal(ownership)
	if err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE dns_zones SET zone_json=?,zone_spec_json=?,tenant_id=?,generation=?,ownership_state='owned',pending_effect='' WHERE id=? AND tenant_id='' AND ownership_state='quarantined' AND pending_effect=?", zoneRaw, specRaw, observed.TenantID, observed.Generation, observed.ID, effect)
	if err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return ZoneAdoptionReceipt{}, errors.Join(ErrDNSConflict, err)
	}
	result, err = tx.ExecContext(ctx, "UPDATE dns_zone_adoptions_v1 SET state='complete',observed_json=?,completed_at=? WHERE effect_id=? AND actor_id=? AND tenant_id=? AND zone_id=? AND state='pending'", observedRaw, receipt.ObservedAt, effect, actor, observed.TenantID, observed.ID)
	if err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	affected, err = result.RowsAffected()
	if err != nil || affected != 1 {
		return ZoneAdoptionReceipt{}, errors.Join(ErrDNSConflict, err)
	}
	result, err = tx.ExecContext(ctx, "UPDATE dns_zone_operations_v1 SET state='complete',response_json=?,completed_at=? WHERE effect_id=? AND tenant_id=? AND zone_id=? AND operation='adopt' AND state='pending'", operationRaw, receipt.ObservedAt, effect, observed.TenantID, observed.ID)
	if err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	affected, err = result.RowsAffected()
	if err != nil || affected != 1 {
		return ZoneAdoptionReceipt{}, errors.Join(ErrDNSConflict, err)
	}
	if err = tx.Commit(); err != nil {
		return ZoneAdoptionReceipt{}, err
	}
	return receipt, nil
}

// AdoptLegacyZoneForTenant is intentionally separate from ordinary CRUD. Only
// privileged operator wiring should expose it; actor and reason are committed
// to the immutable adoption receipt. The backend operation refuses any existing
// owner metadata and is safe to reconcile after an indeterminate response.
func (authority *TenantZoneAuthority) AdoptLegacyZoneForTenant(ctx context.Context, tenant, actor, effect string, request ZoneAdoption) (ZoneAdoptionReceipt, error) {
	if authority == nil || authority.Backend == nil || authority.Repository.DB == nil || ctx == nil {
		return ZoneAdoptionReceipt{}, ErrInvalidDNS
	}
	if request.Zone.TenantID != tenant {
		if validZoneTenant(tenant) && request.Zone.TenantID != "" {
			return ZoneAdoptionReceipt{}, sql.ErrNoRows
		}
		return ZoneAdoptionReceipt{}, ErrInvalidDNS
	}
	completed, done, err := authority.Repository.reserveAdoption(ctx, effect, actor, request)
	if err != nil || done {
		return completed, err
	}
	returned, adoptErr := authority.Backend.AdoptZone(ctx, effect, request.BackendDomainID, request.Zone)
	observed, observedReceipt, observeErr := authority.Backend.ObserveZone(ctx, tenant, request.Zone.ID, effect)
	if observeErr != nil {
		return ZoneAdoptionReceipt{}, errors.Join(adoptErr, observeErr)
	}
	if !sameZoneSpec(observed, request.Zone) {
		return ZoneAdoptionReceipt{}, ErrDNSConflict
	}
	finalReceipt := chooseObservedReceipt(returned, observedReceipt, effect, request.Zone.ID)
	completed, finishErr := authority.Repository.finishAdoption(ctx, effect, actor, request, observed, finalReceipt)
	if finishErr != nil {
		return completed, errors.Join(adoptErr, finishErr)
	}
	return completed, adoptErr
}
