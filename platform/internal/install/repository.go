package install

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

const SQLSchema=`
CREATE TABLE IF NOT EXISTS installer_transactions (
 id TEXT PRIMARY KEY, command_id TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
 state TEXT NOT NULL, generation INTEGER NOT NULL, catalog_sequence INTEGER NOT NULL,
 plan_json BLOB NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS installer_active_transaction ON installer_transactions((1)) WHERE state NOT IN ('committed','rolled_back','failed');
CREATE TABLE IF NOT EXISTS installer_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation INTEGER NOT NULL,
 release_id TEXT NOT NULL, active_slot TEXT NOT NULL, state_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS installer_tombstones (
 id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL UNIQUE, export_digest TEXT NOT NULL,
 tombstone_json BLOB NOT NULL, purge_after TIMESTAMP NOT NULL, created_at TIMESTAMP NOT NULL
);
`
type SQLRepository struct{DB *sql.DB}
func (repository SQLRepository)Bootstrap(ctx context.Context)error{if repository.DB==nil{return ErrInvalid};_,err:=repository.DB.ExecContext(ctx,SQLSchema);return err}
func encode(value any)([]byte,error){return json.Marshal(value)}
func decode(payload []byte,value any)error{if len(payload)==0||json.Unmarshal(payload,value)!=nil{return ErrIntegrity};return nil}
func changed(result sql.Result,stale bool)error{count,err:=result.RowsAffected();if err!=nil{return err};if count!=1{if stale{return ErrStaleGeneration};return ErrNotFound};return nil}
func (repository SQLRepository)Admit(ctx context.Context,plan TransactionPlan)(TransactionPlan,bool,error){if err:=plan.Validate();err!=nil{return TransactionPlan{},false,err};var highest uint64;if err:=repository.DB.QueryRowContext(ctx,`SELECT COALESCE(MAX(catalog_sequence),0) FROM installer_transactions`).Scan(&highest);err!=nil{return TransactionPlan{},false,err};if plan.CatalogSequence<highest{return TransactionPlan{},false,ErrIntegrity};payload,err:=encode(plan);if err!=nil{return TransactionPlan{},false,err};_,err=repository.DB.ExecContext(ctx,`INSERT INTO installer_transactions (id,command_id,kind,state,generation,catalog_sequence,plan_json,updated_at) VALUES (?,?,?,?,?,?,?,?)`,plan.ID,plan.CommandID,plan.Kind,plan.State,plan.Generation,plan.CatalogSequence,payload,plan.UpdatedAt);if err==nil{return plan,true,nil};existing,loadErr:=repository.LoadPlan(ctx,plan.ID);if loadErr==nil{if existing.CommandID==plan.CommandID&&existing.RequestDigest==plan.RequestDigest&&existing.CatalogDigest==plan.CatalogDigest&&existing.Kind==plan.Kind{return existing,false,nil};return TransactionPlan{},false,ErrConflict};return TransactionPlan{},false,err}
func (repository SQLRepository)LoadPlan(ctx context.Context,id string)(TransactionPlan,error){var payload []byte;err:=repository.DB.QueryRowContext(ctx,`SELECT plan_json FROM installer_transactions WHERE id=?`,id).Scan(&payload);if errors.Is(err,sql.ErrNoRows){return TransactionPlan{},ErrNotFound};if err!=nil{return TransactionPlan{},err};var plan TransactionPlan;if err:=decode(payload,&plan);err!=nil{return TransactionPlan{},err};return plan,plan.Validate()}
func (repository SQLRepository)UpdatePlan(ctx context.Context,plan TransactionPlan,expected uint64)error{if plan.Generation!=expected+1{return ErrStaleGeneration};if err:=plan.Validate();err!=nil{return err};payload,err:=encode(plan);if err!=nil{return err};result,err:=repository.DB.ExecContext(ctx,`UPDATE installer_transactions SET state=?,generation=?,plan_json=?,updated_at=? WHERE id=? AND generation=?`,plan.State,plan.Generation,payload,plan.UpdatedAt,plan.ID,expected);if err!=nil{return err};return changed(result,true)}
func (repository SQLRepository)SaveInstalled(ctx context.Context,state InstalledState,expected uint64)error{if state.Generation!=expected+1{return ErrStaleGeneration};if err:=state.Validate();err!=nil{return err};payload,err:=encode(state);if err!=nil{return err};if expected==0{_,err=repository.DB.ExecContext(ctx,`INSERT INTO installer_state (singleton,generation,release_id,active_slot,state_json,updated_at) VALUES (1,?,?,?,?,?)`,state.Generation,state.ReleaseID,state.ActiveSlot,payload,state.UpdatedAt);return err};result,err:=repository.DB.ExecContext(ctx,`UPDATE installer_state SET generation=?,release_id=?,active_slot=?,state_json=?,updated_at=? WHERE singleton=1 AND generation=?`,state.Generation,state.ReleaseID,state.ActiveSlot,payload,state.UpdatedAt,expected);if err!=nil{return err};return changed(result,true)}
func (repository SQLRepository)LoadInstalled(ctx context.Context)(InstalledState,error){var payload []byte;err:=repository.DB.QueryRowContext(ctx,`SELECT state_json FROM installer_state WHERE singleton=1`).Scan(&payload);if errors.Is(err,sql.ErrNoRows){return InstalledState{},ErrNotFound};if err!=nil{return InstalledState{},err};var state InstalledState;if err:=decode(payload,&state);err!=nil{return InstalledState{},err};return state,state.Validate()}
func (repository SQLRepository)DeleteInstalled(ctx context.Context,expected uint64)error{result,err:=repository.DB.ExecContext(ctx,`DELETE FROM installer_state WHERE singleton=1 AND generation=?`,expected);if err!=nil{return err};return changed(result,true)}
func (repository SQLRepository)SaveTombstone(ctx context.Context,tombstone UninstallTombstone)error{if !safeID.MatchString(tombstone.ID)||!safeID.MatchString(tombstone.TransactionID)||!validDigest(tombstone.ExportDigest)||tombstone.ExportPath==""||tombstone.PurgeAfter.IsZero()||tombstone.CreatedAt.IsZero()||tombstone.Generation!=1{return ErrInvalid};payload,err:=encode(tombstone);if err!=nil{return err};_,err=repository.DB.ExecContext(ctx,`INSERT INTO installer_tombstones (id,transaction_id,export_digest,tombstone_json,purge_after,created_at) VALUES (?,?,?,?,?,?)`,tombstone.ID,tombstone.TransactionID,tombstone.ExportDigest,payload,tombstone.PurgeAfter,tombstone.CreatedAt);if err==nil{return nil};existing,loadErr:=repository.LoadTombstone(ctx,tombstone.ID);if loadErr==nil&&existing.TransactionID==tombstone.TransactionID&&existing.ExportDigest==tombstone.ExportDigest&&existing.PurgeAfter.Equal(tombstone.PurgeAfter){return nil};return err}
func (repository SQLRepository)LoadTombstone(ctx context.Context,id string)(UninstallTombstone,error){var payload []byte;err:=repository.DB.QueryRowContext(ctx,`SELECT tombstone_json FROM installer_tombstones WHERE id=?`,id).Scan(&payload);if errors.Is(err,sql.ErrNoRows){return UninstallTombstone{},ErrNotFound};if err!=nil{return UninstallTombstone{},err};var tombstone UninstallTombstone;return tombstone,decode(payload,&tombstone)}
