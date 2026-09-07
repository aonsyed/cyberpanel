package rebootcontrol

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ExecutionBinding is constructed by an authenticated, closed-method broker,
// never decoded from caller input. Observations do not need a mutation lease.
type ExecutionBinding struct {
	Boundary string
	Method string
	EffectID string
	RequestDigest string
	Caller string
	Resource string
	Control *ExecutionControl
}

// Only the reboot FSM may cross its own closed epoch, and only for these three
// marker-bound transitions. These effects are reconciled by that FSM, not by
// the domain drain manifest which must already be sealed before marker arm.
type ExecutionControl struct { Action string; PlanID string; Fence uint64; MarkerDigest string }
type ExecutionLease struct { ID string; Epoch uint64; Token string; Cached []byte }
type ExecutionAdmission interface {
	AdmitExecution(context.Context, ExecutionBinding) (ExecutionLease, error)
	FinishExecution(context.Context, ExecutionLease, bool, []byte) error
}

// SQLExecutionAdmission opens no files and creates no schema. The core owns
// schema initialization; missing/malformed schema is an admission error.
type SQLExecutionAdmission struct { DB *sql.DB; BootID string; ValidateStore func() error }

func ExecutionDigest(value any) string {
	encoded, err := json.Marshal(value); if err != nil { return "" }
	return digestBytes(encoded)
}

func ExecutionResource(value any) string {
	encoded, err := json.Marshal(value); if err != nil { return "" }; return string(encoded)
}

const executionSchema = `CREATE TABLE IF NOT EXISTS reboot_execution_effects(
 id TEXT PRIMARY KEY,boundary TEXT NOT NULL,method TEXT NOT NULL,effect_id TEXT NOT NULL,
 request_digest TEXT NOT NULL,caller TEXT NOT NULL,resource TEXT NOT NULL,binding_digest TEXT NOT NULL,
 classification TEXT NOT NULL CHECK(classification IN ('mutation','reboot_control')),
 boot_id TEXT NOT NULL,epoch INTEGER NOT NULL,token TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('active','completed','ambiguous')),
 admitted_at TEXT NOT NULL,completed_at TEXT NOT NULL,response BLOB NOT NULL,response_digest TEXT NOT NULL)`

func (store *SQLExecutionAdmission) AdmitExecution(ctx context.Context, binding ExecutionBinding) (ExecutionLease, error) {
	if store == nil || store.DB == nil || ctx == nil || !identifierPattern.MatchString(store.BootID) ||
		binding.Boundary == "" || len(binding.Boundary)>64 || binding.Method=="" || len(binding.Method)>128 ||
		binding.EffectID=="" || len(binding.EffectID)>512 || !validDigest(binding.RequestDigest) ||
		binding.Caller=="" || len(binding.Caller)>256 || binding.Resource=="" || len(binding.Resource)>2048 { return ExecutionLease{}, ErrInvalid }
	if store.ValidateStore != nil { if err := store.ValidateStore(); err != nil { return ExecutionLease{}, err } }
	tx, err := store.DB.BeginTx(ctx, nil); if err != nil { return ExecutionLease{}, err }; defer tx.Rollback()
	// Obtain the same SQLite writer lock as Close, before checking receipts or
	// epoch. A crash at any later point leaves either no effect or an active row.
	if _, err = tx.ExecContext(ctx, `UPDATE reboot_admission_gate SET epoch=epoch WHERE singleton=1`); err != nil { return ExecutionLease{}, err }
	var epoch uint64; var closed int; var plan, boot string; var fence uint64
	if err = tx.QueryRowContext(ctx, `SELECT epoch,closed,plan_id,fence,boot_id FROM reboot_admission_gate WHERE singleton=1`).Scan(&epoch,&closed,&plan,&fence,&boot); err != nil { return ExecutionLease{}, err }
	if epoch>maxGeneration || closed<0 || closed>1 ||
		(epoch==0 && (closed!=0 || plan!="" || fence!=0 || boot!="")) ||
		(epoch>0 && (!identifierPattern.MatchString(plan) || fence==0 || fence>maxGeneration || !identifierPattern.MatchString(boot))) { return ExecutionLease{}, ErrIntegrity }
	id := digestStrings(binding.Boundary,binding.Method,binding.EffectID)
	bound := ExecutionDigest(binding)
	var oldBinding, state, responseDigest string; var cached []byte; var oldEpoch uint64
	err = tx.QueryRowContext(ctx, `SELECT binding_digest,status,epoch,response,response_digest FROM reboot_execution_effects WHERE id=?`,id).Scan(&oldBinding,&state,&oldEpoch,&cached,&responseDigest)
	if err==nil {
		if oldBinding!=bound || oldEpoch>epoch { return ExecutionLease{}, ErrIntegrity }
		if state!="completed" { return ExecutionLease{}, ErrUnproven }
		if len(cached)==0 || len(cached)>1<<20 || digestBytes(cached)!=responseDigest { return ExecutionLease{}, ErrIntegrity }
		// Returning an exact terminal receipt never invokes the handler again.
		return ExecutionLease{ID:id,Epoch:oldEpoch,Cached:cached},nil
	}
	if !errors.Is(err,sql.ErrNoRows) { return ExecutionLease{}, err }
	var blocked bool
	if err=tx.QueryRowContext(ctx, `SELECT `+admissionClosedSQL).Scan(&blocked); err!=nil { return ExecutionLease{},err }
	classification := "mutation"
	if binding.Control!=nil {
		if binding.Boundary!="operations" || binding.Method!="observe_or_apply" || closed!=1 { return ExecutionLease{},ErrConflict }
		var sealed uint64;var manifest string
		if err=tx.QueryRowContext(ctx,`SELECT epoch,digest FROM reboot_admission_manifests WHERE plan_id=? AND fence=?`,plan,fence).Scan(&sealed,&manifest);err!=nil{return ExecutionLease{},err}
		if sealed!=epoch || !validDigest(manifest){return ExecutionLease{},ErrIntegrity}
		control:=binding.Control
		var phase,marker string
		if err=tx.QueryRowContext(ctx,`SELECT phase,COALESCE(json_extract(state_json,'$.marker_digest'),'') FROM reboot_states WHERE node_id='local' AND plan_id=? AND fence=?`,plan,fence).Scan(&phase,&marker);err!=nil{return ExecutionLease{},err}
		if !validDigest(control.MarkerDigest) { return ExecutionLease{},ErrInvalid }
		switch control.Action {
		case "arm":
			if control.PlanID!=plan || control.Fence!=fence || phase!="checkpointed" || marker!="" || boot!=store.BootID { return ExecutionLease{},ErrConflict }
		case "dispatch":
			if control.PlanID!=plan || control.Fence!=fence || phase!="armed" || marker!=control.MarkerDigest || boot!=store.BootID { return ExecutionLease{},ErrConflict }
		case "clear":
			if control.PlanID!="" || control.Fence!=0 || phase!="reconciling" || marker!=control.MarkerDigest || boot==store.BootID { return ExecutionLease{},ErrConflict }
		default: return ExecutionLease{},ErrInvalid
		}
		classification="reboot_control"
	} else if blocked { return ExecutionLease{},ErrConflict }
	var token [32]byte; if _,err=rand.Read(token[:]);err!=nil{return ExecutionLease{},err}
	lease:=ExecutionLease{ID:id,Epoch:epoch,Token:digestBytes(token[:])}
	_,err=tx.ExecContext(ctx,`INSERT INTO reboot_execution_effects(id,boundary,method,effect_id,request_digest,caller,resource,binding_digest,classification,boot_id,epoch,token,status,admitted_at,completed_at,response,response_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'active',?,'',X'','')`,id,binding.Boundary,binding.Method,binding.EffectID,binding.RequestDigest,binding.Caller,binding.Resource,bound,classification,store.BootID,epoch,lease.Token,time.Now().UTC().Format(time.RFC3339Nano))
	if err!=nil{return ExecutionLease{},err}
	if store.ValidateStore!=nil{if err=store.ValidateStore();err!=nil{return ExecutionLease{},err}}
	if err=tx.Commit();err!=nil{return ExecutionLease{},err}
	return lease,nil
}

func (store *SQLExecutionAdmission) FinishExecution(ctx context.Context, lease ExecutionLease, terminal bool, response []byte) error {
	if store==nil || store.DB==nil || ctx==nil || !validDigest(lease.ID) || !validDigest(lease.Token) || len(lease.Cached)!=0 { return ErrInvalid }
	if store.ValidateStore!=nil{if err:=store.ValidateStore();err!=nil{return err}}
	state:="ambiguous"; content:=[]byte{}; proof:=""
	if terminal && len(response)>0 && len(response)<=1<<20 { state="completed";content=response;proof=digestBytes(response) }
	result,err:=store.DB.ExecContext(ctx,`UPDATE reboot_execution_effects SET status=?,completed_at=?,response=?,response_digest=? WHERE id=? AND epoch=? AND token=? AND boot_id=? AND status='active'`,state,time.Now().UTC().Format(time.RFC3339Nano),content,proof,lease.ID,lease.Epoch,lease.Token,store.BootID)
	if err!=nil{return err};count,err:=result.RowsAffected();if err!=nil||count!=1{return ErrIntegrity}
	// An explicit ambiguous receipt may still be returned to its caller. It
	// stays nonterminal in the drain catalog and is never replayed by admission.
	if terminal && state!="completed"{return ErrUnproven};return nil
}

// SettleExecution uses a bounded independent context so client cancellation
// cannot erase the outcome. A persistence failure never returns success.
func SettleExecution(store ExecutionAdmission, lease ExecutionLease, terminal bool, response any) error {
	if store==nil{return ErrConflict};encoded,err:=json.Marshal(response);if err!=nil{terminal=false}
	ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
	return store.FinishExecution(ctx,lease,terminal,encoded)
}
