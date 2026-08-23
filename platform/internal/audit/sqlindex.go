package audit

import(
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)
const Schema=`
CREATE TABLE IF NOT EXISTS audit_prepared(event_id TEXT PRIMARY KEY,event_digest TEXT NOT NULL,prepared_at TIMESTAMP NOT NULL,sequence BIGINT,record_hash TEXT);
CREATE TABLE IF NOT EXISTS audit_checkpoints(sequence BIGINT PRIMARY KEY,head_hash TEXT NOT NULL,segment_id TEXT NOT NULL,signature TEXT NOT NULL,key_id TEXT NOT NULL,created_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS audit_projection(sequence BIGINT PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,class TEXT NOT NULL,action TEXT NOT NULL,actor_id TEXT NOT NULL,tenant_id TEXT NOT NULL,target_kind TEXT NOT NULL,target_id TEXT NOT NULL,outcome TEXT NOT NULL,effect_id TEXT NOT NULL,trace_id TEXT NOT NULL,occurred_at TIMESTAMP NOT NULL,event_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_projection_tenant_time ON audit_projection(tenant_id,occurred_at);
CREATE INDEX IF NOT EXISTS audit_projection_target ON audit_projection(target_kind,target_id,occurred_at);
`
type SQLIndex struct{db *sql.DB}
func NewSQLIndex(db *sql.DB)(*SQLIndex,error){if db==nil{return nil,ErrInvalid};return &SQLIndex{db:db},nil}
func(i *SQLIndex)Bootstrap(ctx context.Context)error{_,err:=i.db.ExecContext(ctx,Schema);return err}
func(i *SQLIndex)Prepared(ctx context.Context,id string)(Prepared,bool,error){var p Prepared;err:=i.db.QueryRowContext(ctx,`SELECT event_id,event_digest,prepared_at FROM audit_prepared WHERE event_id=?`,id).Scan(&p.EventID,&p.EventDigest,&p.PreparedAt);if errors.Is(err,sql.ErrNoRows){return p,false,nil};return p,err==nil,err}
func(i *SQLIndex)Prepare(ctx context.Context,p Prepared)error{_,err:=i.db.ExecContext(ctx,`INSERT INTO audit_prepared VALUES(?,?,?,NULL,NULL) ON CONFLICT(event_id) DO NOTHING`,p.EventID,p.EventDigest,p.PreparedAt);return err}
func(i *SQLIndex)Finalize(ctx context.Context,id string,sequence uint64,hash string)error{result,err:=i.db.ExecContext(ctx,`UPDATE audit_prepared SET sequence=?,record_hash=? WHERE event_id=? AND sequence IS NULL`,sequence,hash,id);if err!=nil{return err};count,_:=result.RowsAffected();if count==0{var existing uint64;var existingHash string;if err=i.db.QueryRowContext(ctx,`SELECT sequence,record_hash FROM audit_prepared WHERE event_id=?`,id).Scan(&existing,&existingHash);err!=nil{return err};if existing!=sequence||existingHash!=hash{return ErrConflict}};return nil}
func(i *SQLIndex)Lookup(ctx context.Context,id string)(uint64,string,bool,error){var sequence uint64;var hash sql.NullString;err:=i.db.QueryRowContext(ctx,`SELECT sequence,record_hash FROM audit_prepared WHERE event_id=? AND sequence IS NOT NULL`,id).Scan(&sequence,&hash);if errors.Is(err,sql.ErrNoRows){return 0,"",false,nil};return sequence,hash.String,err==nil,err}
func(i *SQLIndex)Checkpoint(ctx context.Context,c Checkpoint)error{_,err:=i.db.ExecContext(ctx,`INSERT INTO audit_checkpoints VALUES(?,?,?,?,?,?) ON CONFLICT(sequence) DO NOTHING`,c.Sequence,c.HeadHash,c.SegmentID,c.Signature,c.KeyID,c.CreatedAt);return err}
func(i *SQLIndex)LastCheckpoint(ctx context.Context)(Checkpoint,bool,error){var c Checkpoint;err:=i.db.QueryRowContext(ctx,`SELECT sequence,head_hash,segment_id,signature,key_id,created_at FROM audit_checkpoints ORDER BY sequence DESC LIMIT 1`).Scan(&c.Sequence,&c.HeadHash,&c.SegmentID,&c.Signature,&c.KeyID,&c.CreatedAt);if errors.Is(err,sql.ErrNoRows){return c,false,nil};return c,err==nil,err}
func(i *SQLIndex)Project(ctx context.Context,record Record)error{raw,_:=json.Marshal(record.Event);_,err:=i.db.ExecContext(ctx,`INSERT INTO audit_projection VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(sequence) DO NOTHING`,record.Sequence,record.Event.ID,record.Event.Class,record.Event.Action,record.Event.Actor.PrincipalID,record.Event.Actor.TenantID,record.Event.Target.Kind,record.Event.Target.ID,record.Event.Outcome,record.Event.EffectID,record.Event.TraceID,record.Event.OccurredAt,raw);return err}
func(i *SQLIndex)Query(ctx context.Context,q Query)([]Record,error){if q.Limit==0||q.Limit>1000{q.Limit=100};rows,err:=i.db.QueryContext(ctx,`SELECT sequence,event_json FROM audit_projection WHERE sequence>? AND (?='' OR tenant_id=?) AND (?='' OR actor_id=?) AND (?='' OR target_kind=?) AND (?='' OR target_id=?) AND (?='' OR action=?) AND (?='' OR effect_id=?) AND (?='' OR trace_id=?) ORDER BY sequence LIMIT ?`,q.AfterSequence,q.TenantID,q.TenantID,q.ActorID,q.ActorID,q.TargetKind,q.TargetKind,q.TargetID,q.TargetID,q.Action,q.Action,q.EffectID,q.EffectID,q.TraceID,q.TraceID,q.Limit);if err!=nil{return nil,err};defer rows.Close();var out []Record;for rows.Next(){var record Record;var raw []byte;if err=rows.Scan(&record.Sequence,&raw);err!=nil{return nil,err};if err=json.Unmarshal(raw,&record.Event);err!=nil{return nil,err};out=append(out,record)};return out,rows.Err()}
