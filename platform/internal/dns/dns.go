// Package dns defines durable, provider-neutral DNS control state.
package dns

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type ZoneID string
type ProviderID string
type PeerID string
type RecordType string
const ( A RecordType = "A"; AAAA RecordType = "AAAA"; CNAME RecordType = "CNAME"; TXT RecordType = "TXT"; MX RecordType = "MX"; NS RecordType = "NS"; CAA RecordType = "CAA" )
type Role string
const ( Primary Role = "primary"; Secondary Role = "secondary" )
type Zone struct { ID ZoneID `json:"id"`; Name string `json:"name"`; Role Role `json:"role"`; Provider ProviderID `json:"provider"`; Serial uint64 `json:"serial"`; Peers []PeerID `json:"peers"` }
type RRSet struct { ZoneID ZoneID `json:"zone_id"`; Name string `json:"name"`; Type RecordType `json:"type"`; TTL uint32 `json:"ttl"`; Values []string `json:"values"` }
type ProviderBinding struct { ID ProviderID `json:"id"`; Kind string `json:"kind"`; CredentialRef string `json:"credential_ref"` }
type TransferPeer struct { ID PeerID `json:"id"`; Address string `json:"address"`; TSIGKeyRef string `json:"tsig_key_ref"` }
type Change struct { ID string `json:"id"`; Zone ZoneID `json:"zone"`; Key string `json:"key"`; RRSet RRSet `json:"rrset"`; Delete bool `json:"delete"`; At time.Time `json:"at"` }
type Provider interface { Apply(context.Context, Zone, Change) error; Delete(context.Context, Zone, Change) error }
type PowerDNS interface { EnsureZone(context.Context, Zone) error; ReplaceRRSet(context.Context, RRSet) error; DeleteRRSet(context.Context, ZoneID, string, RecordType) error }
type Cloudflare interface { EnsureZone(context.Context, Zone) error; ReplaceRRSet(context.Context, RRSet) error; DeleteRRSet(context.Context, ZoneID, string, RecordType) error }

const Schema = `CREATE TABLE IF NOT EXISTS dns_zones (id TEXT PRIMARY KEY, zone_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS dns_changes (id TEXT PRIMARY KEY, zone_id TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, change_json TEXT NOT NULL, applied_at TIMESTAMP NULL);`
type Repository struct { DB *sql.DB }
func (r Repository) Bootstrap(ctx context.Context) error { if r.DB == nil { return errors.New("dns db required") }; _, err := r.DB.ExecContext(ctx, Schema); return err }
func (r Repository) Apply(ctx context.Context, provider Provider, zone Zone, change Change) error {
	if r.DB == nil || provider == nil || change.ID == "" || change.Key == "" || zone.ID != change.Zone { return errors.New("invalid dns change") }
	tx, err := r.DB.BeginTx(ctx, nil); if err != nil { return err }; defer tx.Rollback()
	var applied sql.NullTime; err = tx.QueryRowContext(ctx, `SELECT applied_at FROM dns_changes WHERE idempotency_key = ?`, change.Key).Scan(&applied)
	if err == nil { return tx.Commit() }; if !errors.Is(err, sql.ErrNoRows) { return err }
	b, err := json.Marshal(change); if err != nil { return err }
	if _, err = tx.ExecContext(ctx, `INSERT INTO dns_changes (id, zone_id, idempotency_key, change_json) VALUES (?, ?, ?, ?)`, change.ID, zone.ID, change.Key, b); err != nil { return err }
	if err = tx.Commit(); err != nil { return err }
	if change.Delete { err = provider.Delete(ctx, zone, change) } else { err = provider.Apply(ctx, zone, change) }
	if err != nil { return err }
	_, err = r.DB.ExecContext(ctx, `UPDATE dns_changes SET applied_at = ? WHERE id = ? AND applied_at IS NULL`, time.Now().UTC(), change.ID); return err
}

// PowerDNSSQL writes the authoritative PowerDNS schema without embedding a
// PowerDNS HTTP client or credentials in the domain service.
type PowerDNSSQL struct { DB *sql.DB }
func (p PowerDNSSQL) EnsureZone(ctx context.Context, zone Zone) error { if p.DB == nil { return errors.New("powerdns db required") }; _, err := p.DB.ExecContext(ctx, `INSERT INTO domains (name, type) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM domains WHERE name = ?)`, zone.Name, string(zone.Role), zone.Name); return err }
func (p PowerDNSSQL) ReplaceRRSet(ctx context.Context, set RRSet) error { if p.DB == nil { return errors.New("powerdns db required") }; tx, err := p.DB.BeginTx(ctx, nil); if err != nil { return err }; defer tx.Rollback(); if _, err = tx.ExecContext(ctx, `DELETE FROM records WHERE domain_id = ? AND name = ? AND type = ?`, set.ZoneID, set.Name, set.Type); err != nil { return err }; for _, value := range set.Values { if _, err = tx.ExecContext(ctx, `INSERT INTO records (domain_id, name, type, content, ttl) VALUES (?, ?, ?, ?, ?)`, set.ZoneID, set.Name, set.Type, value, set.TTL); err != nil { return err } }; return tx.Commit() }
func (p PowerDNSSQL) DeleteRRSet(ctx context.Context, zone ZoneID, name string, kind RecordType) error { _, err := p.DB.ExecContext(ctx, `DELETE FROM records WHERE domain_id = ? AND name = ? AND type = ?`, zone, name, kind); return err }
func (p PowerDNSSQL) Apply(ctx context.Context, zone Zone, change Change) error { if err := p.EnsureZone(ctx, zone); err != nil { return err }; return p.ReplaceRRSet(ctx, change.RRSet) }
func (p PowerDNSSQL) Delete(ctx context.Context, _ Zone, change Change) error { return p.DeleteRRSet(ctx, change.Zone, change.RRSet.Name, change.RRSet.Type) }
var _ Provider = PowerDNSSQL{}
var _ = fmt.Sprintf
