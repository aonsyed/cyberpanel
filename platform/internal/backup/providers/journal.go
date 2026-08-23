package providers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// SQLUploadJournal makes every remote multipart checkpoint durable. Generation
// is a compare-and-swap fence so two workers cannot complete the same upload.
type SQLUploadJournal struct{DB *sql.DB}
const uploadJournalSchema=`CREATE TABLE IF NOT EXISTS backup_provider_uploads_v2(id TEXT PRIMARY KEY,repository_id TEXT NOT NULL,effect_id TEXT NOT NULL,object_key TEXT NOT NULL,state TEXT NOT NULL,generation INTEGER NOT NULL,session_json BLOB NOT NULL,updated_at TIMESTAMP NOT NULL,UNIQUE(repository_id,effect_id,object_key));`
func (journal SQLUploadJournal)Bootstrap(ctx context.Context)error{if journal.DB==nil{return errors.New("backup upload journal database required")};_,err:=journal.DB.ExecContext(ctx,uploadJournalSchema);return err}
func (journal SQLUploadJournal)LoadUpload(ctx context.Context,id string)(UploadSession,error){if journal.DB==nil||!safeID(id){return UploadSession{},ErrInvalid};var raw []byte;if err:=journal.DB.QueryRowContext(ctx,`SELECT session_json FROM backup_provider_uploads_v2 WHERE id=?`,id).Scan(&raw);err!=nil{if errors.Is(err,sql.ErrNoRows){return UploadSession{},ErrNotFound};return UploadSession{},err};var session UploadSession;if err:=json.Unmarshal(raw,&session);err!=nil{return UploadSession{},errors.Join(ErrIntegrity,err)};if err:=session.Validate();err!=nil{return UploadSession{},err};return session,nil}
func (journal SQLUploadJournal)CreateUpload(ctx context.Context,session UploadSession)error{if journal.DB==nil{return ErrInvalid};if err:=session.Validate();err!=nil{return err};raw,err:=json.Marshal(session);if err!=nil{return err};_,err=journal.DB.ExecContext(ctx,`INSERT INTO backup_provider_uploads_v2(id,repository_id,effect_id,object_key,state,generation,session_json,updated_at) VALUES(?,?,?,?,?,?,?,?)`,session.ID,session.RepositoryID,session.EffectID,session.ObjectKey,session.State,session.Generation,raw,session.UpdatedAt);return err}
func (journal SQLUploadJournal)SaveUpload(ctx context.Context,session UploadSession,expected uint64)error{if journal.DB==nil||session.Generation!=expected+1{return ErrInvalid};if err:=session.Validate();err!=nil{return err};raw,err:=json.Marshal(session);if err!=nil{return err};result,err:=journal.DB.ExecContext(ctx,`UPDATE backup_provider_uploads_v2 SET state=?,generation=?,session_json=?,updated_at=? WHERE id=? AND generation=?`,session.State,session.Generation,raw,session.UpdatedAt,session.ID,expected);if err!=nil{return err};affected,err:=result.RowsAffected();if err!=nil{return err};if affected!=1{return ErrConflict};return nil}
func (journal SQLUploadJournal)DeleteUpload(ctx context.Context,id string,generation uint64)error{if journal.DB==nil||!safeID(id)||generation==0{return ErrInvalid};result,err:=journal.DB.ExecContext(ctx,`DELETE FROM backup_provider_uploads_v2 WHERE id=? AND generation=?`,id,generation);if err!=nil{return err};affected,err:=result.RowsAffected();if err!=nil{return err};if affected==0{return ErrConflict};return nil}
