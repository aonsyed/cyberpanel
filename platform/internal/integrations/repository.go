package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const SQLSchema = `
CREATE TABLE IF NOT EXISTS integration_bindings (
 id TEXT PRIMARY KEY, tenant_id TEXT, kind TEXT NOT NULL, purpose TEXT NOT NULL,
 state TEXT NOT NULL, generation INTEGER NOT NULL, binding_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS integration_binding_tombstones (
 binding_id TEXT PRIMARY KEY, tenant_id TEXT, generation INTEGER NOT NULL,
 secret_version INTEGER NOT NULL, binding_digest TEXT NOT NULL,
 provider_revoked_at TIMESTAMP NOT NULL, secret_revoked_at TIMESTAMP,
 binding_json BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS integration_bindings_scope ON integration_bindings(tenant_id, kind, state, id);
CREATE TABLE IF NOT EXISTS integration_health (
 binding_id TEXT PRIMARY KEY, state TEXT NOT NULL, health_json BLOB NOT NULL,
 observed_at TIMESTAMP NOT NULL, FOREIGN KEY(binding_id) REFERENCES integration_bindings(id)
);
CREATE TABLE IF NOT EXISTS integration_effects (
 id TEXT PRIMARY KEY, command_id TEXT NOT NULL UNIQUE, binding_id TEXT NOT NULL,
 kind TEXT NOT NULL, resource TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 request_digest TEXT NOT NULL, state TEXT NOT NULL, effect_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL, UNIQUE(binding_id, idempotency_key),
 FOREIGN KEY(binding_id) REFERENCES integration_bindings(id)
);
CREATE INDEX IF NOT EXISTS integration_effects_binding ON integration_effects(binding_id, state, updated_at);
CREATE TABLE IF NOT EXISTS integration_notification_routes (
 id TEXT PRIMARY KEY, binding_id TEXT NOT NULL, enabled INTEGER NOT NULL,
 generation INTEGER NOT NULL, route_json BLOB NOT NULL,
 FOREIGN KEY(binding_id) REFERENCES integration_bindings(id)
);
CREATE TABLE IF NOT EXISTS integration_notifications (
 id TEXT PRIMARY KEY, tenant_id TEXT, kind TEXT NOT NULL, severity TEXT NOT NULL,
 dedupe_key TEXT NOT NULL, notification_json BLOB NOT NULL, occurred_at TIMESTAMP NOT NULL,
 UNIQUE(tenant_id, dedupe_key)
);
CREATE TABLE IF NOT EXISTS integration_notification_inbox (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL,
 notification_id TEXT NOT NULL, unread INTEGER NOT NULL, generation INTEGER NOT NULL,
 dismissed_at TIMESTAMP, item_json BLOB NOT NULL, created_at TIMESTAMP NOT NULL,
 updated_at TIMESTAMP NOT NULL, UNIQUE(tenant_id, principal_id, notification_id),
 FOREIGN KEY(notification_id) REFERENCES integration_notifications(id)
);
CREATE INDEX IF NOT EXISTS integration_notification_inbox_scope ON integration_notification_inbox(tenant_id, principal_id, dismissed_at, id);
CREATE TABLE IF NOT EXISTS integration_notification_attempts (
 id TEXT PRIMARY KEY, notification_id TEXT NOT NULL, route_id TEXT NOT NULL,
 binding_id TEXT NOT NULL, state TEXT NOT NULL, attempt INTEGER NOT NULL,
 next_attempt_at TIMESTAMP, attempt_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL,
 UNIQUE(notification_id, route_id), FOREIGN KEY(notification_id) REFERENCES integration_notifications(id)
);
CREATE INDEX IF NOT EXISTS integration_notification_attempts_due ON integration_notification_attempts(state, next_attempt_at);
CREATE TABLE IF NOT EXISTS integration_n8n_installations (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, site_id TEXT NOT NULL,
 state TEXT NOT NULL, generation INTEGER NOT NULL, installation_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL, UNIQUE(site_id)
);
`

type Store interface {
	CreateBinding(context.Context, ProviderBinding) error
	LoadBinding(context.Context, BindingID) (ProviderBinding, error)
	UpdateBinding(context.Context, ProviderBinding, uint64) error
	ListBindings(context.Context, TenantID, ProviderKind, uint16, string) ([]ProviderBinding, string, error)
	SaveHealth(context.Context, ProviderHealth) error
	LoadHealth(context.Context, BindingID) (ProviderHealth, error)
	AdmitEffect(context.Context, ProviderEffect) (ProviderEffect, bool, error)
	LoadEffect(context.Context, EffectID) (ProviderEffect, error)
	UpdateEffect(context.Context, ProviderEffect) error
	SaveNotificationRoute(context.Context, NotificationRoute, uint64) error
	LoadNotificationRoute(context.Context, ID) (NotificationRoute, error)
	CreateNotification(context.Context, Notification) (Notification, bool, error)
	CreateNotificationAttempt(context.Context, NotificationAttempt) error
	LoadNotificationAttempt(context.Context, DeliveryID) (NotificationAttempt, error)
	UpdateNotificationAttempt(context.Context, NotificationAttempt) error
	SaveN8NInstallation(context.Context, N8NInstallation, uint64) error
	LoadN8NInstallation(context.Context, ID) (N8NInstallation, error)
}

type BindingTombstone struct {
	Binding          ProviderBinding `json:"binding"`
	ProviderRevokedAt time.Time      `json:"provider_revoked_at"`
	SecretRevokedAt   time.Time      `json:"secret_revoked_at"`
}

type SQLRepository struct{ DB *sql.DB }
func (repository SQLRepository) Bootstrap(ctx context.Context) error { if repository.DB == nil { return errors.New("integration database required") }; _, err := repository.DB.ExecContext(ctx, SQLSchema); return err }
func marshal(value any) ([]byte, error) { return json.Marshal(value) }
func unmarshal(data []byte, value any) error { if len(data) == 0 { return ErrIntegrity }; if err := json.Unmarshal(data, value); err != nil { return ErrIntegrity }; return nil }

func (repository SQLRepository) CreateBinding(ctx context.Context, binding ProviderBinding) error { if err := binding.Validate(); err != nil { return err }; payload, err := marshal(binding); if err != nil { return err }; _, err = repository.DB.ExecContext(ctx, `INSERT INTO integration_bindings (id, tenant_id, kind, purpose, state, generation, binding_json, updated_at) VALUES (?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?)`, binding.ID, binding.TenantID, binding.Kind, binding.Purpose, binding.State, binding.Generation, payload, binding.UpdatedAt); return err }
func (repository SQLRepository) LoadBinding(ctx context.Context, id BindingID) (ProviderBinding, error) { var payload []byte; err := repository.DB.QueryRowContext(ctx, `SELECT binding_json FROM integration_bindings WHERE id = ?`, id).Scan(&payload); if errors.Is(err, sql.ErrNoRows) { return ProviderBinding{}, ErrNotFound }; if err != nil { return ProviderBinding{}, err }; var binding ProviderBinding; if err := unmarshal(payload, &binding); err != nil { return ProviderBinding{}, err }; return binding, binding.Validate() }
func (repository SQLRepository) UpdateBinding(ctx context.Context, binding ProviderBinding, expected uint64) error { if err := binding.Validate(); err != nil { return err }; if binding.Generation != expected+1 { return ErrStaleGeneration }; payload, err := marshal(binding); if err != nil { return err }; result, err := repository.DB.ExecContext(ctx, `UPDATE integration_bindings SET state = ?, generation = ?, binding_json = ?, updated_at = ? WHERE id = ? AND generation = ?`, binding.State, binding.Generation, payload, binding.UpdatedAt, binding.ID, expected); if err != nil { return err }; return requireGeneration(result) }
func (repository SQLRepository) SaveBindingTombstone(ctx context.Context, tombstone BindingTombstone) error { if tombstone.Binding.State!=BindingDeleting&&tombstone.Binding.State!=BindingDeleted||tombstone.Binding.Validate()!=nil||tombstone.ProviderRevokedAt.IsZero(){return ErrInvalid};payload,err:=marshal(tombstone.Binding);if err!=nil{return err};_,err=repository.DB.ExecContext(ctx,`INSERT INTO integration_binding_tombstones (binding_id,tenant_id,generation,secret_version,binding_digest,provider_revoked_at,secret_revoked_at,binding_json) VALUES (?,NULLIF(?,''),?,?,?,?,?,?) ON CONFLICT(binding_id) DO UPDATE SET generation=excluded.generation,secret_version=excluded.secret_version,binding_digest=excluded.binding_digest,provider_revoked_at=excluded.provider_revoked_at,secret_revoked_at=excluded.secret_revoked_at,binding_json=excluded.binding_json WHERE integration_binding_tombstones.generation<=excluded.generation`,tombstone.Binding.ID,tombstone.Binding.TenantID,tombstone.Binding.Generation,tombstone.Binding.SecretVersion,tombstone.Binding.SecretBindingDigest,tombstone.ProviderRevokedAt,nullableTime(tombstone.SecretRevokedAt),payload);return err }
func (repository SQLRepository) ListBindings(ctx context.Context, tenant TenantID, kind ProviderKind, limit uint16, cursor string) ([]ProviderBinding, string, error) { if limit == 0 { limit = 100 }; if limit > 500 || len(cursor) > 128 { return nil, "", ErrInvalid }; rows, err := repository.DB.QueryContext(ctx, `SELECT binding_json FROM integration_bindings WHERE (? = '' OR tenant_id = ?) AND (? = '' OR kind = ?) AND id > ? ORDER BY id LIMIT ?`, tenant, tenant, kind, kind, cursor, limit+1); if err != nil { return nil, "", err }; defer rows.Close(); items := make([]ProviderBinding, 0, limit); for rows.Next() { var payload []byte; if err := rows.Scan(&payload); err != nil { return nil, "", err }; var item ProviderBinding; if err := unmarshal(payload, &item); err != nil { return nil, "", err }; items = append(items, item) }; if err := rows.Err(); err != nil { return nil, "", err }; next := ""; if len(items) > int(limit) { next = string(items[limit-1].ID); items = items[:limit] }; return items, next, nil }
func (repository SQLRepository) SaveHealth(ctx context.Context, health ProviderHealth) error { if !validID(string(health.BindingID)) || health.ObservedAt.IsZero() || !validDigest(health.CapabilitiesDigest) { return ErrInvalid }; payload, err := marshal(health); if err != nil { return err }; _, err = repository.DB.ExecContext(ctx, `INSERT INTO integration_health (binding_id, state, health_json, observed_at) VALUES (?, ?, ?, ?) ON CONFLICT(binding_id) DO UPDATE SET state = excluded.state, health_json = excluded.health_json, observed_at = excluded.observed_at WHERE integration_health.observed_at < excluded.observed_at`, health.BindingID, health.State, payload, health.ObservedAt); return err }
func (repository SQLRepository) LoadHealth(ctx context.Context, id BindingID) (ProviderHealth, error) { var payload []byte; err := repository.DB.QueryRowContext(ctx, `SELECT health_json FROM integration_health WHERE binding_id = ?`, id).Scan(&payload); if errors.Is(err, sql.ErrNoRows) { return ProviderHealth{}, ErrNotFound }; if err != nil { return ProviderHealth{}, err }; var health ProviderHealth; return health, unmarshal(payload, &health) }

func (repository SQLRepository) AdmitEffect(ctx context.Context, effect ProviderEffect) (ProviderEffect, bool, error) { if err := effect.Validate(); err != nil { return ProviderEffect{}, false, err }; existing, err := repository.LoadEffect(ctx, effect.ID); if err == nil { if existing.BindingID != effect.BindingID || existing.RequestDigest != effect.RequestDigest || existing.Kind != effect.Kind || existing.Resource != effect.Resource || existing.IdempotencyKey != effect.IdempotencyKey { return ProviderEffect{}, false, ErrConflict }; return existing, false, nil }; if !errors.Is(err, ErrNotFound) { return ProviderEffect{}, false, err }; payload, err := marshal(effect); if err != nil { return ProviderEffect{}, false, err }; _, err = repository.DB.ExecContext(ctx, `INSERT INTO integration_effects (id, command_id, binding_id, kind, resource, idempotency_key, request_digest, state, effect_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, effect.ID, effect.CommandID, effect.BindingID, effect.Kind, effect.Resource, effect.IdempotencyKey, effect.RequestDigest, effect.State, payload, effect.UpdatedAt); if err == nil { return effect, true, nil }; existing, loadErr := repository.LoadEffect(ctx, effect.ID); if loadErr == nil && existing.BindingID == effect.BindingID && existing.RequestDigest == effect.RequestDigest { return existing, false, nil }; return ProviderEffect{}, false, err }
func (repository SQLRepository) LoadEffect(ctx context.Context, id EffectID) (ProviderEffect, error) { var payload []byte; err := repository.DB.QueryRowContext(ctx, `SELECT effect_json FROM integration_effects WHERE id = ?`, id).Scan(&payload); if errors.Is(err, sql.ErrNoRows) { return ProviderEffect{}, ErrNotFound }; if err != nil { return ProviderEffect{}, err }; var effect ProviderEffect; if err := unmarshal(payload, &effect); err != nil { return ProviderEffect{}, err }; return effect, effect.Validate() }
func (repository SQLRepository) UpdateEffect(ctx context.Context, effect ProviderEffect) error { if err := effect.Validate(); err != nil { return err }; payload, err := marshal(effect); if err != nil { return err }; result, err := repository.DB.ExecContext(ctx, `UPDATE integration_effects SET state = ?, effect_json = ?, updated_at = ? WHERE id = ?`, effect.State, payload, effect.UpdatedAt, effect.ID); if err != nil { return err }; return requireOne(result) }

func (repository SQLRepository) SaveNotificationRoute(ctx context.Context, route NotificationRoute, expected uint64) error { if !validID(string(route.ID)) || !validID(string(route.BindingID)) || route.Generation != expected+1 || route.RatePerHour == 0 || len(route.RecipientRefs) == 0 { return ErrInvalid }; payload, err := marshal(route); if err != nil { return err }; if expected == 0 { _, err = repository.DB.ExecContext(ctx, `INSERT INTO integration_notification_routes (id, binding_id, enabled, generation, route_json) VALUES (?, ?, ?, ?, ?)`, route.ID, route.BindingID, route.Enabled, route.Generation, payload); return err }; result, err := repository.DB.ExecContext(ctx, `UPDATE integration_notification_routes SET binding_id = ?, enabled = ?, generation = ?, route_json = ? WHERE id = ? AND generation = ?`, route.BindingID, route.Enabled, route.Generation, payload, route.ID, expected); if err != nil { return err }; return requireGeneration(result) }
func (repository SQLRepository) LoadNotificationRoute(ctx context.Context, id ID) (NotificationRoute, error) { var payload []byte; err := repository.DB.QueryRowContext(ctx, `SELECT route_json FROM integration_notification_routes WHERE id = ?`, id).Scan(&payload); if errors.Is(err, sql.ErrNoRows) { return NotificationRoute{}, ErrNotFound }; if err != nil { return NotificationRoute{}, err }; var route NotificationRoute; return route, unmarshal(payload, &route) }
func (repository SQLRepository) CreateNotification(ctx context.Context, notification Notification) (Notification, bool, error) { if err := notification.Validate(); err != nil { return Notification{}, false, err }; payload, err := marshal(notification); if err != nil { return Notification{}, false, err }; _, err = repository.DB.ExecContext(ctx, `INSERT INTO integration_notifications (id, tenant_id, kind, severity, dedupe_key, notification_json, occurred_at) VALUES (?, NULLIF(?, ''), ?, ?, ?, ?, ?)`, notification.ID, notification.TenantID, notification.Kind, notification.Severity, notification.DedupeKey, payload, notification.OccurredAt); if err == nil { return notification, true, nil }; var existingPayload []byte; loadErr := repository.DB.QueryRowContext(ctx, `SELECT notification_json FROM integration_notifications WHERE tenant_id IS ? AND dedupe_key = ?`, nullString(notification.TenantID), notification.DedupeKey).Scan(&existingPayload); if loadErr != nil { return Notification{}, false, err }; var existing Notification; if unmarshal(existingPayload, &existing) != nil || existing.DataDigest != notification.DataDigest { return Notification{}, false, ErrConflict }; return existing, false, nil }
func (repository SQLRepository) LoadNotification(ctx context.Context,tenant TenantID,id ID)(Notification,error){if repository.DB==nil||ctx==nil||!validID(string(tenant))||!validID(string(id)){return Notification{},ErrInvalid};var payload []byte;err:=repository.DB.QueryRowContext(ctx,`SELECT notification_json FROM integration_notifications WHERE id=? AND (tenant_id=? OR tenant_id IS NULL)`,id,tenant).Scan(&payload);if errors.Is(err,sql.ErrNoRows){return Notification{},ErrNotFound};if err!=nil{return Notification{},err};var notification Notification;if unmarshal(payload,&notification)!=nil||notification.Validate()!=nil||notification.ID!=id||notification.TenantID!=""&&notification.TenantID!=tenant{return Notification{},ErrIntegrity};return notification,nil}
func (repository SQLRepository) CreateInboxItem(ctx context.Context,item InboxItem)(InboxItem,bool,error){if repository.DB==nil||ctx==nil||item.Validate()!=nil{return InboxItem{},false,ErrInvalid};payload,err:=marshal(item);if err!=nil{return InboxItem{},false,err};_,err=repository.DB.ExecContext(ctx,`INSERT INTO integration_notification_inbox(id,tenant_id,principal_id,notification_id,unread,generation,dismissed_at,item_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,item.ID,item.TenantID,item.PrincipalID,item.NotificationID,item.Unread,item.Generation,nullableTime(item.DismissedAt),payload,item.CreatedAt,item.UpdatedAt);if err==nil{return item,true,nil};var existingPayload []byte;loadErr:=repository.DB.QueryRowContext(ctx,`SELECT item_json FROM integration_notification_inbox WHERE id=? OR (tenant_id=? AND principal_id=? AND notification_id=?) LIMIT 1`,item.ID,item.TenantID,item.PrincipalID,item.NotificationID).Scan(&existingPayload);if loadErr!=nil{return InboxItem{},false,err};var existing InboxItem;if unmarshal(existingPayload,&existing)!=nil||existing.Validate()!=nil||!sameInboxSource(existing,item){return InboxItem{},false,ErrConflict};return existing,false,nil}
func (repository SQLRepository) LoadInboxItem(ctx context.Context,tenant TenantID,principal string,id ID)(InboxItem,error){if repository.DB==nil||ctx==nil||!validID(string(tenant))||!validID(principal)||!validID(string(id)){return InboxItem{},ErrInvalid};var payload []byte;err:=repository.DB.QueryRowContext(ctx,`SELECT item_json FROM integration_notification_inbox WHERE id=? AND tenant_id=? AND principal_id=?`,id,tenant,principal).Scan(&payload);if errors.Is(err,sql.ErrNoRows){return InboxItem{},ErrNotFound};if err!=nil{return InboxItem{},err};var item InboxItem;if unmarshal(payload,&item)!=nil||item.Validate()!=nil||item.ID!=id||item.TenantID!=tenant||item.PrincipalID!=principal{return InboxItem{},ErrIntegrity};return item,nil}
func (repository SQLRepository) ListInboxItems(ctx context.Context,tenant TenantID,principal string,limit uint16,cursor string)([]InboxItem,string,error){if repository.DB==nil||ctx==nil||!validID(string(tenant))||!validID(principal)||cursor!=""&&!validID(cursor){return nil,"",ErrInvalid};if limit==0{limit=100};if limit>500{return nil,"",ErrInvalid};rows,err:=repository.DB.QueryContext(ctx,`SELECT item_json FROM integration_notification_inbox WHERE tenant_id=? AND principal_id=? AND dismissed_at IS NULL AND (?='' OR id<?) ORDER BY id DESC LIMIT ?`,tenant,principal,cursor,cursor,limit+1);if err!=nil{return nil,"",err};defer rows.Close();items:=make([]InboxItem,0,limit);for rows.Next(){var payload []byte;if err=rows.Scan(&payload);err!=nil{return nil,"",err};var item InboxItem;if unmarshal(payload,&item)!=nil||item.Validate()!=nil||item.TenantID!=tenant||item.PrincipalID!=principal||!item.DismissedAt.IsZero(){return nil,"",ErrIntegrity};items=append(items,item)};if err=rows.Err();err!=nil{return nil,"",err};next:="";if len(items)>int(limit){next=string(items[limit-1].ID);items=items[:limit]};return items,next,nil}
func (repository SQLRepository) UpdateInboxItem(ctx context.Context,item InboxItem,expected uint64)error{if repository.DB==nil||ctx==nil||item.Validate()!=nil{return ErrInvalid};if expected==0||item.Generation!=expected+1{return ErrStaleGeneration};payload,err:=marshal(item);if err!=nil{return err};result,err:=repository.DB.ExecContext(ctx,`UPDATE integration_notification_inbox SET unread=?,generation=?,dismissed_at=?,item_json=?,updated_at=? WHERE id=? AND tenant_id=? AND principal_id=? AND notification_id=? AND generation=?`,item.Unread,item.Generation,nullableTime(item.DismissedAt),payload,item.UpdatedAt,item.ID,item.TenantID,item.PrincipalID,item.NotificationID,expected);if err!=nil{return err};return requireGeneration(result)}
func (repository SQLRepository) CreateNotificationAttempt(ctx context.Context, attempt NotificationAttempt) error { payload, err := marshal(attempt); if err != nil { return err }; _, err = repository.DB.ExecContext(ctx, `INSERT INTO integration_notification_attempts (id, notification_id, route_id, binding_id, state, attempt, next_attempt_at, attempt_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, attempt.ID, attempt.NotificationID, attempt.RouteID, attempt.BindingID, attempt.State, attempt.Attempt, nullableTime(attempt.NextAttemptAt), payload, attempt.UpdatedAt); return err }
func (repository SQLRepository) LoadNotificationAttempt(ctx context.Context, id DeliveryID) (NotificationAttempt, error) { var payload []byte; err := repository.DB.QueryRowContext(ctx, `SELECT attempt_json FROM integration_notification_attempts WHERE id = ?`, id).Scan(&payload); if errors.Is(err, sql.ErrNoRows) { return NotificationAttempt{}, ErrNotFound }; if err != nil { return NotificationAttempt{}, err }; var attempt NotificationAttempt; return attempt, unmarshal(payload, &attempt) }
func (repository SQLRepository) UpdateNotificationAttempt(ctx context.Context, attempt NotificationAttempt) error { payload, err := marshal(attempt); if err != nil { return err }; result, err := repository.DB.ExecContext(ctx, `UPDATE integration_notification_attempts SET state = ?, attempt = ?, next_attempt_at = ?, attempt_json = ?, updated_at = ? WHERE id = ?`, attempt.State, attempt.Attempt, nullableTime(attempt.NextAttemptAt), payload, attempt.UpdatedAt, attempt.ID); if err != nil { return err }; return requireOne(result) }
func (repository SQLRepository) SaveN8NInstallation(ctx context.Context, installation N8NInstallation, expected uint64) error { if err:=installation.Validate();err!=nil{return err};payload,err:=marshal(installation);if err!=nil{return err};if expected==0{_,err=repository.DB.ExecContext(ctx,`INSERT INTO integration_n8n_installations (id,tenant_id,site_id,state,generation,installation_json,updated_at) VALUES (?,?,?,?,?,?,?)`,installation.ID,installation.TenantID,installation.SiteID,installation.State,installation.Generation,payload,installation.UpdatedAt);return err};if installation.Generation!=expected+1{return ErrStaleGeneration};result,err:=repository.DB.ExecContext(ctx,`UPDATE integration_n8n_installations SET state=?,generation=?,installation_json=?,updated_at=? WHERE id=? AND generation=?`,installation.State,installation.Generation,payload,installation.UpdatedAt,installation.ID,expected);if err!=nil{return err};return requireGeneration(result)}
func (repository SQLRepository) LoadN8NInstallation(ctx context.Context,id ID)(N8NInstallation,error){var payload []byte;err:=repository.DB.QueryRowContext(ctx,`SELECT installation_json FROM integration_n8n_installations WHERE id=?`,id).Scan(&payload);if errors.Is(err,sql.ErrNoRows){return N8NInstallation{},ErrNotFound};if err!=nil{return N8NInstallation{},err};var installation N8NInstallation;if err:=unmarshal(payload,&installation);err!=nil{return N8NInstallation{},err};return installation,installation.Validate()}

func requireOne(result sql.Result) error { count, err := result.RowsAffected(); if err != nil { return err }; if count != 1 { return ErrNotFound }; return nil }
func requireGeneration(result sql.Result) error { count, err := result.RowsAffected(); if err != nil { return err }; if count != 1 { return ErrStaleGeneration }; return nil }
func nullableTime(value time.Time) any { if value.IsZero() { return nil }; return value }
func nullString(value TenantID) any { if value == "" { return nil }; return value }
