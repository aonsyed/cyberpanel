//go:build linux

package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

type DatabaseImportCommands interface { Handle(context.Context,database.Command)(database.OperationReceipt,error) }

type DatabaseImportCredential struct {
	SecretRef database.SecretRef
	Format database.PrincipalCredentialFormat
}

type DatabaseImportHandler struct {
	db *sql.DB
	chunks *ChunkStore
	scopes *RuntimeScopeStore
	commands DatabaseImportCommands
	repository database.Repository
	broker database.MigrationRestoreExecutor
	secret func(context.Context,ID,string)(DatabaseImportCredential,error)
	siteTarget func(context.Context,ID,ID)(site.SiteID,error)
	mu sync.Mutex
}

func NewDatabaseImportHandler(ctx context.Context,db *sql.DB,chunks *ChunkStore,scopes *RuntimeScopeStore,commands DatabaseImportCommands,repository database.Repository,broker database.MigrationRestoreExecutor,secret func(context.Context,ID,string)(DatabaseImportCredential,error),siteTarget func(context.Context,ID,ID)(site.SiteID,error))(*DatabaseImportHandler,error) {
	if db==nil || chunks==nil || scopes==nil || commands==nil || repository==nil || broker==nil || secret==nil || siteTarget==nil { return nil,ErrInvalid }
	_,err:=db.ExecContext(ctx,`CREATE TABLE IF NOT EXISTS panel_migration_database_imports(migration_id TEXT NOT NULL,target_id TEXT NOT NULL,effect_id TEXT NOT NULL,input_digest TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(migration_id,target_id),UNIQUE(effect_id))`)
	if err!=nil { return nil,err }
	return &DatabaseImportHandler{db:db,chunks:chunks,scopes:scopes,commands:commands,repository:repository,broker:broker,secret:secret,siteTarget:siteTarget},nil
}

func DatabaseImportPrincipalID(migrationID,targetID ID,name string)string {
	sum:=sha256.Sum256([]byte(migrationID.String()+"\x00"+targetID.String()+"\x00"+name))
	return "migp-"+hex.EncodeToString(sum[:])[:32]
}

type databaseImportPlan struct {
	target database.Database
	principal database.DatabasePrincipal
	grants database.GrantSet
	header database.CommandHeader
	restore database.MigrationRestoreRequest
	chunk Chunk
}

func (handler *DatabaseImportHandler) plan(ctx context.Context,intent ImportIntent)(databaseImportPlan,error) {
	if _,err:=validateCanonicalIntent(intent); err!=nil { return databaseImportPlan{},err }
	if intent.Kind!=ImportDatabase || intent.Disposition!=DispositionCreate || !intent.Dark || len(intent.Chunks)!=1 { return databaseImportPlan{},ErrBlocked }
	var payload Database
	if err:=strictDecode(intent.Payload,&payload,8<<20); err!=nil { return databaseImportPlan{},err }
	if len(payload.Principals)!=1 || len(payload.Dump)!=1 || payload.Dump[0]!=intent.Chunks[0] { return databaseImportPlan{},ErrBlocked }
	credential:=payload.Principals[0]
	if credential.CredentialDisposition!=CredentialPreserved || len(credential.GrantSets)!=1 || strings.ToUpper(strings.TrimSpace(credential.GrantSets[0]))!="ALL PRIVILEGES" { return databaseImportPlan{},ErrBlocked }
	chunk:=intent.Chunks[0]
	if chunk.Size==0 || chunk.Size>64<<30 || chunk.Compression!="" && chunk.Compression!="none" { return databaseImportPlan{},ErrBlocked }
	scope,err:=handler.scopes.LoadByMigration(ctx,intent.MigrationID); if err!=nil { return databaseImportPlan{},err }
	tenant,err:=site.NewTenantID(scope.TenantID); if err!=nil { return databaseImportPlan{},err }
	siteID,err:=handler.siteTarget(ctx,intent.MigrationID,payload.SiteID); if err!=nil { return databaseImportPlan{},err }
	material,err:=handler.secret(ctx,intent.MigrationID,credential.SecretID); if err!=nil || material.SecretRef.IsZero() || material.Format!="" && material.Format!=database.CredentialFormatNativeHash { return databaseImportPlan{},ErrBlocked }
	sum:=sha256.Sum256([]byte(intent.MigrationID.String()+"\x00"+intent.TargetID.String())); token:=hex.EncodeToString(sum[:])[:32]
	databaseID,_:=database.NewResourceID("migdb-"+token)
	principalID,_:=database.NewResourceID(DatabaseImportPrincipalID(intent.MigrationID,intent.TargetID,credential.Name))
	grantID,_:=database.NewResourceID("migg-"+token)
	restoreID,_:=database.NewResourceID("migr-"+intent.EffectID[:32])
	name,err:=database.ParseSQLIdentifier(payload.Name); if err!=nil { return databaseImportPlan{},ErrBlocked }
	principalName,err:=database.ParseSQLIdentifier(credential.Name); if err!=nil { return databaseImportPlan{},ErrBlocked }
	charset,err:=database.ParseSQLIdentifier(payload.Charset); if err!=nil { return databaseImportPlan{},ErrBlocked }
	collation,err:=database.ParseSQLIdentifier(payload.Collation); if err!=nil { return databaseImportPlan{},ErrBlocked }
	instance,err:=database.DefaultLocalInstance(); if err!=nil { return databaseImportPlan{},err }
	status:=database.ResourceStatus{Lifecycle:database.LifecycleProvisioning,Health:database.HealthUnknown,Reconciliation:database.ReconciliationPending}
	meta:=database.Metadata{ID:databaseID,TenantID:tenant,SiteID:siteID,Generation:1,Status:status}
	target:=database.Database{Metadata:meta,InstanceID:instance.ID,Name:name,Charset:charset,Collation:collation,QuotaBytes:64<<30}
	meta.ID=principalID
	principal:=database.DatabasePrincipal{Metadata:meta,InstanceID:instance.ID,Name:principalName,HostScope:database.HostScopeLoopback,CredentialSecretRef:material.SecretRef,CredentialFormat:material.Format}
	meta.ID=grantID
	grants:=database.GrantSet{Metadata:meta,InstanceID:instance.ID,DatabaseID:databaseID,PrincipalID:principalID,Grants:[]database.Grant{{Scope:database.GrantScopeDatabase,Privileges:[]database.Privilege{database.PrivilegeSelect,database.PrivilegeInsert,database.PrivilegeUpdate,database.PrivilegeDelete,database.PrivilegeCreate,database.PrivilegeAlter,database.PrivilegeIndex,database.PrivilegeDrop,database.PrivilegeCreateTemporary,database.PrivilegeExecute,database.PrivilegeCreateView,database.PrivilegeShowView,database.PrivilegeTrigger,database.PrivilegeEvent}}}}
	header:=database.CommandHeader{Actor:database.Actor{TenantID:tenant,Capability:database.CapabilityTenantManage},TenantID:tenant}
	restore:=database.MigrationRestoreRequest{ID:restoreID,TenantID:tenant,SiteID:siteID,DatabaseID:databaseID,PrincipalID:principalID,GrantSetID:grantID,SourceName:name,InputDigest:intent.InputDigest,DumpDigest:chunk.Digest,DumpBytes:chunk.Size}
	return databaseImportPlan{target,principal,grants,header,restore,chunk},nil
}

func (handler *DatabaseImportHandler) admit(ctx context.Context,intent ImportIntent)(string,error) {
	_,err:=handler.db.ExecContext(ctx,`INSERT INTO panel_migration_database_imports(migration_id,target_id,effect_id,input_digest,state) VALUES(?,?,?,?,'pending') ON CONFLICT(migration_id,target_id) DO NOTHING`,intent.MigrationID.String(),intent.TargetID.String(),intent.EffectID,intent.InputDigest)
	if err!=nil { return "",err }
	return handler.state(ctx,intent)
}

func (handler *DatabaseImportHandler) state(ctx context.Context,intent ImportIntent)(string,error) {
	var effect,digest,state string
	err:=handler.db.QueryRowContext(ctx,`SELECT effect_id,input_digest,state FROM panel_migration_database_imports WHERE migration_id=? AND target_id=?`,intent.MigrationID.String(),intent.TargetID.String()).Scan(&effect,&digest,&state)
	if errors.Is(err,sql.ErrNoRows) { return "",ErrNotFound }; if err!=nil { return "",err }
	if effect!=intent.EffectID || digest!=intent.InputDigest { return "",ErrConflict }; return state,nil
}

func (handler *DatabaseImportHandler) Apply(ctx context.Context,intent ImportIntent)(ImportEffect,error) {
	handler.mu.Lock(); defer handler.mu.Unlock()
	plan,err:=handler.plan(ctx,intent); if err!=nil { return rejectedImportEffect(intent,"DATABASE_IMPORT_UNSUPPORTED",time.Now().UTC()),err }
	if err=handler.chunks.Verify(ctx,plan.chunk); err!=nil { return rejectedImportEffect(intent,"DATABASE_DUMP_NOT_VERIFIED",time.Now().UTC()),err }
	state,err:=handler.admit(ctx,intent); if err!=nil { return ImportEffect{},err }; if state=="compensated" || state=="compensating" { return ImportEffect{},ErrBlocked }
	commands:=plan.createCommands(intent)
	for _,command:=range commands { receipt,commandErr:=handler.commands.Handle(ctx,command); if commandErr!=nil || receipt.Status!=database.OperationApplied || receipt.Effect.Outcome!=database.EffectConfirmed { return ambiguousImportEffect(intent,"DATABASE_PROVISIONING_UNPROVEN",time.Now().UTC()),errors.Join(ErrBlocked,commandErr) } }
	request:=plan.restore; request.Action="begin"
	receipt,err:=handler.broker.RestoreMigrationDatabase(ctx,request); if err!=nil { return ambiguousImportEffect(intent,"DATABASE_RESTORE_UNOBSERVED",time.Now().UTC()),err }
	if receipt.State=="uploading" {
		for offset:=receipt.Bytes; offset<plan.chunk.Size; {
			length:=uint64(256<<10); if length>plan.chunk.Size-offset { length=plan.chunk.Size-offset }
			content,readErr:=handler.chunks.ReadRange(ctx,plan.chunk.Digest,offset,length); if readErr!=nil { return ImportEffect{},readErr }
			request.Action="chunk"; request.Offset=offset; request.Data=content
			if _,err=handler.broker.RestoreMigrationDatabase(ctx,request); err!=nil { return ambiguousImportEffect(intent,"DATABASE_UPLOAD_UNCERTAIN",time.Now().UTC()),err }; offset+=length
		}
		request.Action="apply"; request.Offset=0; request.Data=nil
		receipt,err=handler.broker.RestoreMigrationDatabase(ctx,request); if err!=nil { return ambiguousImportEffect(intent,"DATABASE_RESTORE_UNCERTAIN",time.Now().UTC()),err }
	}
	return databaseImportEffect(intent,receipt)
}

func (plan databaseImportPlan) createCommands(intent ImportIntent)[]database.Command {
	header:=plan.header; header.CommandID="mig-db-create-"+intent.EffectID
	create:=database.CreateDatabase{Header:header,Database:plan.target}
	header.CommandID="mig-db-principal-"+intent.EffectID
	principal:=database.CreatePrincipal{Header:header,Principal:plan.principal}
	header.CommandID="mig-db-grants-"+intent.EffectID
	return []database.Command{create,principal,database.ReplaceGrantSet{Header:header,GrantSet:plan.grants}}
}

func (handler *DatabaseImportHandler) Observe(ctx context.Context,intent ImportIntent)(ImportEffect,error) {
	handler.mu.Lock(); defer handler.mu.Unlock()
	plan,err:=handler.plan(ctx,intent); if err!=nil { return ImportEffect{},err }
	state,err:=handler.state(ctx,intent); if err!=nil { return ImportEffect{},err }
	if state=="compensated" { return ImportEffect{EffectID:intent.EffectID,InputDigest:intent.InputDigest,Status:ImportEffectCompensated,AppliedAt:time.Now().UTC()},nil }
	if state=="compensating" { return ambiguousImportEffect(intent,"DATABASE_COMPENSATING",time.Now().UTC()),ErrBlocked }
	request:=plan.restore; request.Action="observe"
	receipt,err:=handler.broker.RestoreMigrationDatabase(ctx,request); if err!=nil { return ambiguousImportEffect(intent,"DATABASE_PROBE_FAILED",time.Now().UTC()),err }
	return databaseImportEffect(intent,receipt)
}

func databaseImportEffect(intent ImportIntent,receipt database.MigrationRestoreReceipt)(ImportEffect,error) {
	if receipt.State!="applied" || receipt.Process==nil || !receipt.Process.InputVerified || receipt.Process.Partial || receipt.Process.ExitCode!=0 || !isDigest(receipt.ProofDigest) { return ambiguousImportEffect(intent,"DATABASE_RESTORE_INCOMPLETE",time.Now().UTC()),ErrBlocked }
	return ImportEffect{EffectID:intent.EffectID,InputDigest:intent.InputDigest,Status:ImportEffectApplied,TargetGeneration:1,BytesWritten:receipt.Bytes,OutputDigest:receipt.Process.Digest,EvidenceDigest:receipt.ProofDigest,AppliedAt:receipt.ObservedAt},nil
}

// Compensation is permitted only after the exact create command is confirmed
// applied in the durable coordinator ledger. Existing or uncertain resources
// are never inferred to be owned from their name or from a failed create.
func (handler *DatabaseImportHandler) Compensate(ctx context.Context,intent ImportIntent,effect ImportEffect)(ImportEffect,error) {
	handler.mu.Lock(); defer handler.mu.Unlock()
	if !effectMatches(effect,intent) { return ImportEffect{},ErrInvalid }
	plan,err:=handler.plan(ctx,intent); if err!=nil { return ImportEffect{},err }
	state,err:=handler.state(ctx,intent); if err!=nil { return ImportEffect{},err }
	if state!="compensated" {
		if _,err=handler.db.ExecContext(ctx,`UPDATE panel_migration_database_imports SET state='compensating' WHERE migration_id=? AND target_id=? AND input_digest=?`,intent.MigrationID.String(),intent.TargetID.String(),intent.InputDigest); err!=nil { return ImportEffect{},err }
		request:=plan.restore; request.Action="discard"
		if _,discardErr:=handler.broker.RestoreMigrationDatabase(ctx,request); discardErr!=nil && !errors.Is(discardErr,database.ErrNotFound) { return ambiguousImportEffect(intent,"DATABASE_RESTORE_CLEANUP_UNCERTAIN",time.Now().UTC()),discardErr }
		for _,item:=range []struct{kind database.ResourceKind; id database.ResourceID; command string}{{database.KindPrincipal,plan.principal.ID,"mig-db-principal-"},{database.KindDatabase,plan.target.ID,"mig-db-create-"}} {
			scope:=database.OperationScope{TenantID:plan.target.TenantID,Kind:item.kind,ID:item.id}
			created,found,loadErr:=handler.repository.LookupOperation(ctx,scope,item.command+intent.EffectID)
			if loadErr!=nil { return ImportEffect{},loadErr }; if !found || created.Status==database.OperationRejected || created.Status==database.OperationCompensated { continue }
			if created.Status!=database.OperationApplied { return ambiguousImportEffect(intent,"DATABASE_OWNERSHIP_UNCERTAIN",time.Now().UTC()),ErrBlocked }
			header:=plan.header; header.CommandID="mig-db-remove-"+item.id.String()+"-"+intent.EffectID[:16]
			var command database.Command
			if item.kind==database.KindPrincipal { command=database.DeletePrincipal{Header:header,PrincipalID:item.id,ExpectedGeneration:1} } else { approval,_:=database.NewResourceID("migration-cancel-"+intent.EffectID[:32]); command=database.DeleteDatabase{Header:header,DatabaseID:item.id,ExpectedGeneration:1,WaiveRecovery:true,ApprovalRef:approval} }
			removed,removeErr:=handler.commands.Handle(ctx,command); if removeErr!=nil || removed.Status!=database.OperationApplied { return ambiguousImportEffect(intent,"DATABASE_CLEANUP_UNPROVEN",time.Now().UTC()),errors.Join(ErrBlocked,removeErr) }
		}
		if _,err=handler.db.ExecContext(ctx,`UPDATE panel_migration_database_imports SET state='compensated' WHERE migration_id=? AND target_id=? AND input_digest=?`,intent.MigrationID.String(),intent.TargetID.String(),intent.InputDigest); err!=nil { return ImportEffect{},err }
	}
	return ImportEffect{EffectID:intent.EffectID,InputDigest:intent.InputDigest,Status:ImportEffectCompensated,AppliedAt:time.Now().UTC()},nil
}

var _ CanonicalImportHandler=(*DatabaseImportHandler)(nil)
