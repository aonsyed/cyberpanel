// Package dns defines durable, provider-neutral DNS control state.
package dns

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type ZoneID string
type ProviderID string
type PeerID string
type RecordType string
const ( A RecordType = "A"; AAAA RecordType = "AAAA"; CNAME RecordType = "CNAME"; TXT RecordType = "TXT"; MX RecordType = "MX"; NS RecordType = "NS"; CAA RecordType = "CAA" )
type Role string
const ( Primary Role = "primary"; Secondary Role = "secondary" )
type Zone struct { ID ZoneID `json:"id"`; TenantID string `json:"tenant_id"`; Name string `json:"name"`; Role Role `json:"role"`; Provider ProviderID `json:"provider"`; Serial uint64 `json:"serial"`; Peers []PeerID `json:"peers"` }
type RRSet struct { ZoneID ZoneID `json:"zone_id"`; Name string `json:"name"`; Type RecordType `json:"type"`; TTL uint32 `json:"ttl"`; Values []string `json:"values"` }
type ProviderBinding struct { ID ProviderID `json:"id"`; Kind string `json:"kind"`; CredentialRef string `json:"credential_ref"` }
type TransferPeer struct { ID PeerID `json:"id"`; Address string `json:"address"`; TSIGKeyRef string `json:"tsig_key_ref"` }
type Change struct { ID string `json:"id"`; Zone ZoneID `json:"zone"`; Key string `json:"key"`; RRSet RRSet `json:"rrset"`; Delete bool `json:"delete"`; At time.Time `json:"at"` }
type Provider interface { Apply(context.Context, Zone, Change) error; Delete(context.Context, Zone, Change) error }
type PowerDNS interface { EnsureZone(context.Context, Zone) error; ReplaceRRSet(context.Context, RRSet) error; DeleteRRSet(context.Context, ZoneID, string, RecordType) error }
type Cloudflare interface { EnsureZone(context.Context, Zone) error; ReplaceRRSet(context.Context, RRSet) error; DeleteRRSet(context.Context, ZoneID, string, RecordType) error }

const Schema = `CREATE TABLE IF NOT EXISTS dns_zones (id TEXT PRIMARY KEY, zone_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS dns_changes (id TEXT PRIMARY KEY, zone_id TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, change_json TEXT NOT NULL, applied_at TIMESTAMP NULL);`
type Repository struct { DB *sql.DB }
func (r Repository) Bootstrap(ctx context.Context) error { return r.bootstrapOwnership(ctx) }

// Apply cannot derive authority from the Zone payload. Older unbound callers
// must migrate to ApplyForTenant using their authenticated tenant context.
func (r Repository) Apply(context.Context, Provider, Zone, Change) error { return ErrInvalidDNS }
func (r Repository) ApplyForTenant(ctx context.Context, tenant string, provider Provider, zone Zone, change Change) error {
	if r.DB == nil || provider == nil || tenant == "" || change.ID == "" || change.Key == "" || zone.ID != change.Zone || change.RRSet.ZoneID != zone.ID { return ErrInvalidDNS }
	stored, err := r.OwnedZone(ctx, tenant, zone.ID)
	if err != nil { return err }
	if zone.TenantID != "" && zone.TenantID != tenant || zone.Name != stored.Name.String() { return sql.ErrNoRows }
	zone.TenantID = tenant
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return err }; defer tx.Rollback()
	var owner string
	if err = tx.QueryRowContext(ctx, "SELECT tenant_id FROM dns_zones WHERE id=? AND tenant_id=? AND ownership_state='owned' AND pending_effect=''", zone.ID, tenant).Scan(&owner); err != nil { return err }
	raw, err := json.Marshal(change); if err != nil { return err }
	var previous []byte; var zoneID string; var applied sql.NullTime
	err = tx.QueryRowContext(ctx, "SELECT zone_id,change_json,applied_at FROM dns_changes WHERE idempotency_key=?", change.Key).Scan(&zoneID, &previous, &applied)
	if err == nil {
		if zoneID != string(zone.ID) || string(previous) != string(raw) { return ErrDNSConflict }
		if applied.Valid { return tx.Commit() }
	} else if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, "INSERT INTO dns_changes(id,zone_id,idempotency_key,change_json) VALUES(?,?,?,?)", change.ID, zone.ID, change.Key, raw)
	}
	if err != nil { return err }
	if err = tx.Commit(); err != nil { return err }
	if change.Delete { err = provider.Delete(ctx,zone,change) } else { err = provider.Apply(ctx,zone,change) }
	if err != nil { return err }
	_, err = r.DB.ExecContext(ctx, "UPDATE dns_changes SET applied_at=? WHERE idempotency_key=? AND zone_id=?", time.Now().UTC(), change.Key, zone.ID); return err
}

// PowerDNSSQL is retained for source compatibility only. Its historic numeric
// domain-ID interface has no tenant authority and must never bypass the owned
// PowerDNS broker. Production uses PowerDNSControlClient instead.
type PowerDNSSQL struct { DB *sql.DB }
func (PowerDNSSQL) EnsureZone(context.Context, Zone) error { return ErrInvalidDNS }
func (PowerDNSSQL) ReplaceRRSet(context.Context, RRSet) error { return ErrInvalidDNS }
func (PowerDNSSQL) DeleteRRSet(context.Context, ZoneID, string, RecordType) error { return ErrInvalidDNS }
func (PowerDNSSQL) Apply(context.Context, Zone, Change) error { return ErrInvalidDNS }
func (PowerDNSSQL) Delete(context.Context, Zone, Change) error { return ErrInvalidDNS }
var _ Provider = PowerDNSSQL{}
